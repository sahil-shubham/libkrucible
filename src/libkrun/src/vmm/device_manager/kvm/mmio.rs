// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::{fmt, io};

#[cfg(checkpoint)]
use crate::vmm::checkpoint::format::DeviceId;
use devices::DeviceType;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
use devices::fdt::DeviceInfoForFDT;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
use devices::legacy::IrqChip;
#[cfg(checkpoint)]
use devices::virtio::persist::{VmDevicesState, restore_device, snapshot_device};
#[cfg(checkpoint)]
use devices::virtio::{MmioTransport, VirtioDevice};
use kernel::cmdline as kernel_cmdline;
use kvm_ioctls::{IoEventAddress, VmFd};
#[cfg(target_arch = "aarch64")]
use utils::eventfd::EventFd;

/// Errors for MMIO device manager.
#[allow(clippy::enum_variant_names)]
#[allow(unused)]
#[derive(Debug)]
pub enum Error {
    /// Failed to create MmioTransport
    CreateMmioTransport(devices::virtio::CreateMmioTransportError),
    /// Failed to perform an operation on the bus.
    BusError(devices::BusError),
    /// Appending to kernel command line failed.
    Cmdline(kernel_cmdline::Error),
    /// Failure in creating or cloning an event fd.
    EventFd(io::Error),
    /// No more IRQs are available.
    IrqsExhausted,
    /// Registering an IO Event failed.
    RegisterIoEvent(kvm_ioctls::Error),
    /// Registering an IRQ FD failed.
    RegisterIrqFd(kvm_ioctls::Error),
    /// Failed to create vhost-user device.
    #[cfg(all(feature = "vhost-user", target_os = "linux"))]
    VhostUserDevice(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::CreateMmioTransport(ref e) => {
                write!(f, "failed to create mmio transport for the device {e}")
            }
            Error::BusError(ref e) => write!(f, "failed to perform bus operation: {e}"),
            Error::Cmdline(ref e) => {
                write!(f, "unable to add device to kernel command line: {e}")
            }
            Error::EventFd(ref e) => write!(f, "failed to create or clone event descriptor: {e}"),
            Error::IrqsExhausted => write!(f, "no more IRQs are available"),
            Error::RegisterIoEvent(ref e) => write!(f, "failed to register IO event: {e}"),
            Error::RegisterIrqFd(ref e) => write!(f, "failed to register irqfd: {e}"),
            #[cfg(all(feature = "vhost-user", target_os = "linux"))]
            Error::VhostUserDevice(ref e) => write!(f, "failed to create vhost-user device: {e}"),
        }
    }
}

impl From<devices::virtio::CreateMmioTransportError> for Error {
    fn from(e: devices::virtio::CreateMmioTransportError) -> Self {
        Self::CreateMmioTransport(e)
    }
}

type Result<T> = ::std::result::Result<T, Error>;

/// This represents the size of the mmio device specified to the kernel as a cmdline option
/// It has to be larger than 0x100 (the offset where the configuration space starts from
/// the beginning of the memory mapped device registers) + the size of the configuration space
/// Currently hardcoded to 4K.
const MMIO_LEN: u64 = 0x1000;

/// Manages the complexities of registering a MMIO device.
pub struct MMIODeviceManager {
    pub bus: devices::Bus,
    mmio_base: u64,
    irq: u32,
    last_irq: u32,
    id_to_dev_info: HashMap<(DeviceType, String), MMIODeviceInfo>,
    /// The virtio devices in registration order, which is how a checkpoint
    /// lists them and how a restore matches them up.
    #[cfg(checkpoint)]
    virtio_devices: Vec<VirtioEntry>,
    /// A userspace IOAPIC (split IRQ chip) is on the bus: its state isn't in
    /// KVM, where a checkpoint reads the interrupt controllers from.
    #[cfg(checkpoint)]
    userspace_ioapic: bool,
    /// arm64's RTC and UARTs: a checkpoint holds their state too.
    #[cfg(all(checkpoint, target_arch = "aarch64"))]
    rtc: Option<Arc<Mutex<devices::legacy::RTC>>>,
    #[cfg(all(checkpoint, target_arch = "aarch64"))]
    serials: Vec<Arc<Mutex<devices::legacy::Serial>>>,
}

#[cfg(checkpoint)]
struct VirtioEntry {
    id: DeviceId,
    transport: Arc<Mutex<MmioTransport>>,
    device: Arc<Mutex<dyn VirtioDevice>>,
}

impl MMIODeviceManager {
    /// Create a new DeviceManager handling mmio devices (virtio net, block).
    pub fn new(mmio_base: &mut u64, irq_interval: (u32, u32)) -> MMIODeviceManager {
        if cfg!(any(target_arch = "aarch64", target_arch = "riscv64")) {
            *mmio_base += MMIO_LEN;
        }
        MMIODeviceManager {
            mmio_base: *mmio_base,
            irq: irq_interval.0,
            last_irq: irq_interval.1,
            bus: devices::Bus::new(),
            id_to_dev_info: HashMap::new(),
            #[cfg(checkpoint)]
            virtio_devices: Vec::new(),
            #[cfg(checkpoint)]
            userspace_ioapic: false,
            #[cfg(all(checkpoint, target_arch = "aarch64"))]
            rtc: None,
            #[cfg(all(checkpoint, target_arch = "aarch64"))]
            serials: Vec::new(),
        }
    }

    /// Register a MMIO IOAPIC device.
    #[cfg(target_arch = "x86_64")]
    pub fn register_mmio_ioapic(
        &mut self,
        intc: Option<Arc<Mutex<devices::legacy::IrqChipDevice>>>,
    ) -> Result<()> {
        if let Some(intc) = intc {
            let (addr, size) = {
                let intc = intc.lock().unwrap();
                (intc.get_mmio_addr(), intc.get_mmio_size())
            };
            self.bus.insert(intc, addr, size).map_err(Error::BusError)?;
            #[cfg(checkpoint)]
            {
                self.userspace_ioapic = true;
            }
        }

        Ok(())
    }

    /// Register an already created MMIO device to be used via MMIO transport.
    pub fn register_mmio_device(
        &mut self,
        vm: &VmFd,
        mut mmio_device: devices::virtio::MmioTransport,
        type_id: u32,
        device_id: String,
    ) -> Result<(u64, u32)> {
        if self.irq > self.last_irq {
            return Err(Error::IrqsExhausted);
        }

        for (i, queue_evt) in mmio_device.queue_evts().iter().enumerate() {
            let io_addr = IoEventAddress::Mmio(
                self.mmio_base + u64::from(devices::virtio::NOTIFY_REG_OFFSET),
            );

            vm.register_ioevent(queue_evt, &io_addr, i as u32)
                .map_err(Error::RegisterIoEvent)?;
        }

        vm.register_irqfd(mmio_device.interrupt_evt(), self.irq)
            .map_err(Error::RegisterIrqFd)?;

        mmio_device.set_irq_line(self.irq);

        #[cfg(checkpoint)]
        let device = mmio_device.device();
        let transport = Arc::new(Mutex::new(mmio_device));
        #[cfg(checkpoint)]
        let kept = transport.clone();
        self.bus
            .insert(transport, self.mmio_base, MMIO_LEN)
            .map_err(Error::BusError)?;
        #[cfg(checkpoint)]
        self.virtio_devices.push(VirtioEntry {
            id: DeviceId {
                type_id,
                id: device_id.clone(),
            },
            transport: kept,
            device,
        });
        let ret = (self.mmio_base, self.irq);
        self.id_to_dev_info.insert(
            (DeviceType::Virtio(type_id), device_id),
            MMIODeviceInfo {
                addr: self.mmio_base,
                _len: MMIO_LEN,
                _irq: self.irq,
            },
        );
        self.mmio_base += MMIO_LEN;
        self.irq += 1;

        Ok(ret)
    }

    /// Append a registered MMIO device to the kernel cmdline.
    #[cfg(target_arch = "x86_64")]
    pub fn add_device_to_cmdline(
        &mut self,
        cmdline: &mut kernel_cmdline::Cmdline,
        mmio_base: u64,
        irq: u32,
    ) -> Result<()> {
        // as per doc, [virtio_mmio.]device=<size>@<baseaddr>:<irq> needs to be appended
        // to kernel commandline for virtio mmio devices to get recognized
        // the size parameter has to be transformed to KiB, so dividing hexadecimal value in
        // bytes to 1024; further, the '{}' formatting rust construct will automatically
        // transform it to decimal
        cmdline
            .insert(
                "virtio_mmio.device",
                &format!("{}K@0x{:08x}:{}", MMIO_LEN / 1024, mmio_base, irq),
            )
            .map_err(Error::Cmdline)
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    /// Register an early console at some MMIO address.
    pub fn register_mmio_serial(
        &mut self,
        vm: &VmFd,
        cmdline: &mut kernel_cmdline::Cmdline,
        intc: IrqChip,
        serial: Arc<Mutex<devices::legacy::Serial>>,
    ) -> Result<()> {
        if self.irq > self.last_irq {
            return Err(Error::IrqsExhausted);
        }

        vm.register_irqfd(serial.lock().unwrap().interrupt_evt(), self.irq)
            .map_err(Error::RegisterIrqFd)?;

        {
            let mut serial = serial.lock().unwrap();
            serial.set_intc(intc);
            serial.set_irq_line(self.irq);
        }

        #[cfg(all(checkpoint, target_arch = "aarch64"))]
        self.serials.push(serial.clone());
        self.bus
            .insert(serial, self.mmio_base, MMIO_LEN)
            .map_err(Error::BusError)?;

        cmdline
            .insert(
                "earlycon",
                #[cfg(target_arch = "aarch64")]
                &format!("pl011,mmio32,0x{:08x}", self.mmio_base),
                #[cfg(target_arch = "riscv64")]
                &format!("uart,mmio,0x{:08x}", self.mmio_base),
            )
            .map_err(Error::Cmdline)?;

        let ret = self.mmio_base;
        self.id_to_dev_info.insert(
            (DeviceType::Serial, DeviceType::Serial.to_string()),
            MMIODeviceInfo {
                addr: ret,
                _len: MMIO_LEN,
                _irq: self.irq,
            },
        );

        self.mmio_base += MMIO_LEN;
        self.irq += 1;

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    /// Register a MMIO RTC device.
    pub fn register_mmio_rtc(&mut self, vm: &VmFd) -> Result<()> {
        if self.irq > self.last_irq {
            return Err(Error::IrqsExhausted);
        }

        // Attaching the RTC device.
        let rtc_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(Error::EventFd)?;
        let device = devices::legacy::RTC::new(rtc_evt.try_clone().map_err(Error::EventFd)?);
        vm.register_irqfd(&rtc_evt, self.irq)
            .map_err(Error::RegisterIrqFd)?;

        let device = Arc::new(Mutex::new(device));
        #[cfg(all(checkpoint, target_arch = "aarch64"))]
        {
            self.rtc = Some(device.clone());
        }
        self.bus
            .insert(device, self.mmio_base, MMIO_LEN)
            .map_err(Error::BusError)?;

        let ret = self.mmio_base;
        self.id_to_dev_info.insert(
            (DeviceType::RTC, "rtc".to_string()),
            MMIODeviceInfo {
                addr: ret,
                _len: MMIO_LEN,
                _irq: self.irq,
            },
        );

        self.mmio_base += MMIO_LEN;
        self.irq += 1;

        Ok(())
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    /// Gets the information of the devices registered up to some point in time.
    pub fn get_device_info(&self) -> &HashMap<(DeviceType, String), MMIODeviceInfo> {
        &self.id_to_dev_info
    }

    /// Gets the MMIO base address and IRQ for all registered virtio devices.
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    pub fn virtio_mmio_devices(&self) -> Vec<(u64, u32)> {
        let mut devices: Vec<(u64, u32)> = self
            .id_to_dev_info
            .iter()
            .filter_map(|((device_type, _), info)| {
                if matches!(device_type, DeviceType::Virtio(_)) {
                    Some((info.addr, info._irq))
                } else {
                    None
                }
            })
            .collect();
        devices.sort_unstable_by_key(|(base, _)| *base);
        devices
    }
}

/// Checkpoints: capturing the virtio devices' state, and bringing a VM rebuilt
/// from a checkpoint back to it.
#[cfg(checkpoint)]
impl MMIODeviceManager {
    /// The virtio devices, in registration order.
    pub(crate) fn device_ids(&self) -> Vec<DeviceId> {
        self.virtio_devices.iter().map(|d| d.id.clone()).collect()
    }

    /// Why this VM's devices can't be checkpointed, if they can't.
    pub(crate) fn checkpoint_refusal(&self) -> Option<String> {
        if self.userspace_ioapic {
            return Some("its IOAPIC is emulated in userspace (split IRQ chip)".into());
        }
        self.virtio_devices.iter().find_map(|d| {
            let device = d.device.lock().expect("poisoned virtio device lock");
            snapshot_device(&*device)
                .is_none()
                .then(|| format!("{} device {} can't be saved", device.device_name(), d.id.id))
        })
    }

    /// Stops every device's I/O at a clean boundary (the vCPUs must be
    /// paused), failing if a device couldn't get there. Undone by
    /// [`Self::rearm_devices`].
    pub(crate) fn quiesce_devices(&self) -> std::result::Result<(), String> {
        for d in &self.virtio_devices {
            d.device
                .lock()
                .expect("poisoned virtio device lock")
                .quiesce_for_snapshot();
        }
        for d in &self.virtio_devices {
            let device = d.device.lock().expect("poisoned virtio device lock");
            if let Some(e) = device.snapshot_error() {
                return Err(format!("{}: {e}", d.id));
            }
        }
        Ok(())
    }

    /// Restarts the I/O [`Self::quiesce_devices`] stopped.
    pub(crate) fn rearm_devices(&self) {
        for d in &self.virtio_devices {
            d.device
                .lock()
                .expect("poisoned virtio device lock")
                .rearm_after_snapshot();
        }
    }

    /// Every device's state and pending interrupts; the devices must be
    /// quiesced.
    pub(crate) fn snapshot_devices(&self) -> std::result::Result<VmDevicesState, String> {
        let mut state = VmDevicesState::default();
        for d in &self.virtio_devices {
            let interrupt_status = d
                .transport
                .lock()
                .expect("poisoned transport lock")
                .interrupt_status();
            let device = d.device.lock().expect("poisoned virtio device lock");
            let snapshot =
                snapshot_device(&*device).ok_or_else(|| format!("{}: can't be saved", d.id))?;
            state.devices.push(snapshot);
            state.interrupt_status.push(interrupt_status);
        }
        #[cfg(target_arch = "aarch64")]
        {
            state.rtc = self
                .rtc
                .as_ref()
                .map(|rtc| rtc.lock().expect("poisoned RTC lock").save_state());
            state.serials = self
                .serials
                .iter()
                .map(|s| s.lock().expect("poisoned serial lock").save_state())
                .collect();
        }
        Ok(state)
    }

    /// Brings the devices of a VM rebuilt from a checkpoint to their saved
    /// `state`. The VM must have registered the devices the saved VM had
    /// (`saved`: types and ids, in order); otherwise nothing is touched. A
    /// device the guest had set up is re-activated from its saved queues,
    /// without the virtio handshake a restored guest never repeats.
    pub(crate) fn restore_devices(
        &self,
        saved: &[DeviceId],
        state: &VmDevicesState,
    ) -> std::result::Result<(), String> {
        if !self.virtio_devices.iter().map(|d| &d.id).eq(saved) {
            let list = |ids: &mut dyn Iterator<Item = &DeviceId>| {
                ids.map(DeviceId::to_string).collect::<Vec<_>>().join(", ")
            };
            return Err(format!(
                "devices differ: the checkpoint has [{}], this VM has [{}]",
                list(&mut saved.iter()),
                list(&mut self.virtio_devices.iter().map(|d| &d.id))
            ));
        }
        #[cfg(target_arch = "aarch64")]
        if state.serials.len() != self.serials.len() {
            return Err(format!(
                "devices differ: the checkpoint has {} serial consoles, this VM has {}",
                state.serials.len(),
                self.serials.len()
            ));
        }
        if state.devices.len() != saved.len() || state.interrupt_status.len() != saved.len() {
            return Err(format!(
                "corrupt device state: {} devices, {} device states, {} interrupt states",
                saved.len(),
                state.devices.len(),
                state.interrupt_status.len()
            ));
        }
        let entries = self.virtio_devices.iter().zip(&state.devices);
        for ((d, snapshot), status) in entries.zip(&state.interrupt_status) {
            let fail = |e: String| format!("{}: {e}", d.id);
            let mut transport = d.transport.lock().expect("poisoned transport lock");
            restore_device(&mut *transport.locked_device(), snapshot).map_err(fail)?;
            if snapshot.activated() {
                transport
                    .restore_and_activate(&snapshot.queue_states(), snapshot.acked_features())
                    .map_err(fail)?;
                transport.set_restored_interrupt_status(*status);
                transport.locked_device().finish_restore_activation();
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            if let (Some(rtc), Some(saved)) = (&self.rtc, &state.rtc) {
                rtc.lock()
                    .expect("poisoned RTC lock")
                    .restore_state(saved);
            }
            for (serial, saved) in self.serials.iter().zip(&state.serials) {
                serial
                    .lock()
                    .expect("poisoned serial lock")
                    .restore_state(saved);
            }
        }
        Ok(())
    }

    /// Raises the interrupts the restored devices had pending. Only once the
    /// vCPUs' state is restored: loading a vCPU's LAPIC drops what was
    /// delivered to it before.
    pub(crate) fn replay_restored_interrupts(&self) {
        for d in &self.virtio_devices {
            d.transport
                .lock()
                .expect("poisoned transport lock")
                .replay_restored_interrupt();
        }
    }
}

/// Private structure for storing information about the MMIO device registered at some address on the bus.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct MMIODeviceInfo {
    addr: u64,
    _irq: u32,
    _len: u64,
}

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
impl DeviceInfoForFDT for MMIODeviceInfo {
    fn addr(&self) -> u64 {
        self.addr
    }
    fn irq(&self) -> u32 {
        self._irq
    }
    fn length(&self) -> u64 {
        self._len
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::super::builder;
    use super::*;
    use arch;
    use devices::legacy::DummyIrqChip;
    #[cfg(target_arch = "aarch64")]
    use devices::legacy::KvmGicV3;
    #[cfg(target_arch = "x86_64")]
    use devices::legacy::KvmIoapic;
    use devices::virtio::{
        ActivateResult, DeviceQueue, InterruptTransport, QueueConfig, VirtioDevice,
    };
    use std::sync::Arc;
    use utils::errno;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    const QUEUE_CONFIG: &[QueueConfig] = &[QueueConfig::new(64)];

    impl MMIODeviceManager {
        fn register_virtio_device(
            &mut self,
            vm: &VmFd,
            guest_mem: GuestMemoryMmap,
            device: Arc<Mutex<dyn devices::virtio::VirtioDevice>>,
            _cmdline: &mut kernel_cmdline::Cmdline,
            type_id: u32,
            device_id: &str,
        ) -> Result<u64> {
            let mmio_device =
                devices::virtio::MmioTransport::new(guest_mem, DummyIrqChip::new().into(), device)
                    .unwrap();
            let (mmio_base, _irq) =
                self.register_mmio_device(vm, mmio_device, type_id, device_id.to_string())?;
            #[cfg(target_arch = "x86_64")]
            self.add_device_to_cmdline(_cmdline, mmio_base, _irq)?;
            Ok(mmio_base)
        }
    }

    #[allow(dead_code)]
    struct DummyDevice {
        dummy: u32,
    }

    impl DummyDevice {
        pub fn new() -> Self {
            DummyDevice { dummy: 0 }
        }
    }

    impl devices::virtio::VirtioDevice for DummyDevice {
        fn avail_features(&self) -> u64 {
            0
        }

        fn acked_features(&self) -> u64 {
            0
        }

        fn set_acked_features(&mut self, _: u64) {}

        fn device_type(&self) -> u32 {
            0
        }

        fn device_name(&self) -> &str {
            "dummy"
        }

        fn queue_config(&self) -> &[QueueConfig] {
            QUEUE_CONFIG
        }

        fn read_config(&self, offset: u64, data: &mut [u8]) {
            let _ = offset;
            let _ = data;
        }

        fn write_config(&mut self, offset: u64, data: &[u8]) {
            let _ = offset;
            let _ = data;
        }

        fn activate(
            &mut self,
            _mem: GuestMemoryMmap,
            _intc: InterruptTransport,
            _queues: Vec<DeviceQueue>,
        ) -> ActivateResult {
            Ok(())
        }

        fn is_activated(&self) -> bool {
            false
        }
    }

    #[test]
    fn test_register_virtio_device() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemoryMmap::from_ranges(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();
        let mut arch_mem_info = arch::ArchMemoryInfo::default();
        let vm = builder::setup_vm(&guest_mem, &mut arch_mem_info, false).unwrap();
        let mut device_manager =
            MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));
        #[cfg(target_arch = "x86_64")]
        let _kvmioapic = KvmIoapic::new(vm.fd()).unwrap();
        #[cfg(target_arch = "aarch64")]
        let _gic = KvmGicV3::new(vm.fd(), 1).unwrap();

        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        let dummy = Arc::new(Mutex::new(DummyDevice::new()));

        assert!(
            device_manager
                .register_virtio_device(vm.fd(), guest_mem, dummy, &mut cmdline, 0, "dummy")
                .is_ok()
        );
    }

    #[test]
    fn test_register_too_many_devices() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemoryMmap::from_ranges(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();
        let mut arch_mem_info = arch::ArchMemoryInfo::default();
        let vm = builder::setup_vm(&guest_mem, &mut arch_mem_info, false).unwrap();
        let mut device_manager =
            MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));
        #[cfg(target_arch = "x86_64")]
        let _kvmioapic = KvmIoapic::new(vm.fd()).unwrap();
        #[cfg(target_arch = "aarch64")]
        let _gic = KvmGicV3::new(vm.fd(), 1).unwrap();

        let mut cmdline = kernel_cmdline::Cmdline::new(4096);

        for _i in arch::IRQ_BASE..=arch::IRQ_MAX {
            device_manager
                .register_virtio_device(
                    vm.fd(),
                    guest_mem.clone(),
                    Arc::new(Mutex::new(DummyDevice::new())),
                    &mut cmdline,
                    0,
                    "dummy1",
                )
                .unwrap();
        }
        assert_eq!(
            format!(
                "{}",
                device_manager
                    .register_virtio_device(
                        vm.fd(),
                        guest_mem,
                        Arc::new(Mutex::new(DummyDevice::new())),
                        &mut cmdline,
                        0,
                        "dummy2"
                    )
                    .unwrap_err()
            ),
            "no more IRQs are available".to_string()
        );
    }

    #[test]
    fn test_dummy_device() {
        let dummy = DummyDevice::new();
        assert_eq!(dummy.device_type(), 0);
        assert_eq!(dummy.queue_config().len(), QUEUE_CONFIG.len());
    }

    #[test]
    fn test_error_messages() {
        let device_manager =
            MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));
        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        let e = Error::Cmdline(
            cmdline
                .insert(
                    "virtio_mmio=device",
                    &format!(
                        "{}K@0x{:08x}:{}",
                        MMIO_LEN / 1024,
                        device_manager.mmio_base,
                        device_manager.irq
                    ),
                )
                .unwrap_err(),
        );
        assert_eq!(
            format!("{e}"),
            format!(
                "unable to add device to kernel command line: {}",
                kernel_cmdline::Error::HasEquals
            ),
        );
        assert_eq!(
            format!("{}", Error::BusError(devices::BusError::Overlap)),
            format!(
                "failed to perform bus operation: {}",
                devices::BusError::Overlap
            )
        );
        assert_eq!(
            format!("{}", Error::IrqsExhausted),
            "no more IRQs are available"
        );
        assert_eq!(
            format!("{}", Error::RegisterIoEvent(errno::Error::new(0))),
            format!("failed to register IO event: {}", errno::Error::new(0))
        );
        assert_eq!(
            format!("{}", Error::RegisterIrqFd(errno::Error::new(0))),
            format!("failed to register irqfd: {}", errno::Error::new(0))
        );
    }

    #[test]
    fn test_device_info() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemoryMmap::from_ranges(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();
        let mut arch_mem_info = arch::ArchMemoryInfo::default();
        let vm = builder::setup_vm(&guest_mem, &mut arch_mem_info, false).unwrap();
        let mut device_manager =
            MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));
        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        let dummy = Arc::new(Mutex::new(DummyDevice::new()));

        let type_id = 0;
        let id = String::from("foo");
        if let Ok(addr) = device_manager.register_virtio_device(
            vm.fd(),
            guest_mem,
            dummy,
            &mut cmdline,
            type_id,
            &id,
        ) {
            assert_eq!(
                addr,
                device_manager.id_to_dev_info[&(DeviceType::Virtio(type_id), id.clone())].addr
            );
            assert_eq!(
                arch::IRQ_BASE,
                device_manager.id_to_dev_info[&(DeviceType::Virtio(type_id), id.clone())]._irq
            );
        }
    }
    #[test]
    fn test_virtio_mmio_devices() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemoryMmap::from_ranges(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();
        let mut arch_mem_info = arch::ArchMemoryInfo::default();
        let vm = builder::setup_vm(&guest_mem, &mut arch_mem_info, false).unwrap();
        let mut device_manager =
            MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));
        #[cfg(target_arch = "x86_64")]
        let _kvmioapic = KvmIoapic::new(vm.fd()).unwrap();
        #[cfg(target_arch = "aarch64")]
        let _gic = KvmGicV3::new(vm.fd(), 1).unwrap();

        let mut cmdline = kernel_cmdline::Cmdline::new(4096);

        assert!(device_manager.virtio_mmio_devices().is_empty());

        device_manager
            .register_virtio_device(
                vm.fd(),
                guest_mem.clone(),
                Arc::new(Mutex::new(DummyDevice::new())),
                &mut cmdline,
                0,
                "dev0",
            )
            .unwrap();
        device_manager
            .register_virtio_device(
                vm.fd(),
                guest_mem,
                Arc::new(Mutex::new(DummyDevice::new())),
                &mut cmdline,
                0,
                "dev1",
            )
            .unwrap();

        let devices = device_manager.virtio_mmio_devices();
        assert_eq!(devices.len(), 2);
        let first = if cfg!(any(target_arch = "aarch64", target_arch = "riscv64")) {
            0xd000_1000
        } else {
            0xd000_0000
        };
        assert_eq!(devices[0], (first, arch::IRQ_BASE));
        assert_eq!(devices[1], (first + MMIO_LEN, arch::IRQ_BASE + 1));
    }

    #[cfg(all(checkpoint, target_arch = "x86_64"))]
    mod checkpoint {
        use super::*;
        use devices::virtio::block::{DiskFormat, SyncMode};
        use devices::virtio::persist::DeviceSnapshot;
        use devices::virtio::{Block, CacheType, QueueState, TYPE_BLOCK};
        use utils::tempfile::TempFile;

        /// A VM with a block device per id, each over its own small disk.
        struct Rig {
            manager: MMIODeviceManager,
            blocks: Vec<Arc<Mutex<Block>>>,
            _disks: Vec<TempFile>,
            _ioapic: KvmIoapic,
            _vm: crate::vmm::vstate::Vm,
        }

        fn rig(ids: &[&str]) -> Rig {
            let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
            let vm = builder::setup_vm(&mem, &mut arch::ArchMemoryInfo::default(), false).unwrap();
            let ioapic = KvmIoapic::new(vm.fd()).unwrap();
            let mut manager =
                MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));
            let mut cmdline = kernel_cmdline::Cmdline::new(4096);
            let (mut blocks, mut disks) = (Vec::new(), Vec::new());
            for id in ids {
                let disk = TempFile::new().unwrap();
                disk.as_file().set_len(4096).unwrap();
                let block = Arc::new(Mutex::new(
                    Block::new(
                        id.to_string(),
                        None,
                        CacheType::Unsafe,
                        disk.as_path().to_str().unwrap().into(),
                        DiskFormat::Raw,
                        false,
                        false,
                        SyncMode::Full,
                    )
                    .unwrap(),
                ));
                manager
                    .register_virtio_device(
                        vm.fd(),
                        mem.clone(),
                        block.clone(),
                        &mut cmdline,
                        TYPE_BLOCK,
                        id,
                    )
                    .unwrap();
                blocks.push(block);
                disks.push(disk);
            }
            Rig {
                manager,
                blocks,
                _disks: disks,
                _ioapic: ioapic,
                _vm: vm,
            }
        }

        /// What a checkpoint holds for `block` once the guest had set it up.
        fn set_up(block: &Arc<Mutex<Block>>) -> DeviceSnapshot {
            let mut state = block.lock().unwrap().save_state();
            state.activated = true;
            state.queue = Some(QueueState {
                size: 16,
                ready: true,
                desc_table: 0x1000,
                avail_ring: 0x2000,
                used_ring: 0x3000,
                next_avail: 5,
                next_used: 5,
                ..QueueState::default()
            });
            DeviceSnapshot::Block(state)
        }

        fn block(id: &str) -> DeviceId {
            DeviceId {
                type_id: TYPE_BLOCK,
                id: id.into(),
            }
        }

        #[test]
        fn restore_into_other_devices_touches_none() {
            let rig = rig(&["root", "vol1"]);
            // Each state would apply cleanly to the device in its position;
            // only the ids say the checkpoint came from another device set.
            let state = VmDevicesState {
                devices: rig.blocks.iter().map(set_up).collect(),
                interrupt_status: vec![0, 0],
                ..Default::default()
            };
            let err = rig
                .manager
                .restore_devices(&[block("root"), block("vol0")], &state)
                .unwrap_err();
            assert!(err.contains("devices differ"), "{err}");
            for b in &rig.blocks {
                assert!(!b.lock().unwrap().is_activated(), "a device was restored");
            }
        }

        #[test]
        fn restore_leaves_a_device_the_guest_never_set_up_for_it() {
            let rig = rig(&["root", "spare"]);
            let spare = DeviceSnapshot::Block(rig.blocks[1].lock().unwrap().save_state());
            let state = VmDevicesState {
                devices: vec![set_up(&rig.blocks[0]), spare],
                interrupt_status: vec![0, 0],
                ..Default::default()
            };
            rig.manager
                .restore_devices(&rig.manager.device_ids(), &state)
                .unwrap();
            assert!(rig.blocks[0].lock().unwrap().is_activated());
            // The restored guest may still set it up, through the handshake
            // an activated device would refuse.
            assert!(!rig.blocks[1].lock().unwrap().is_activated());
        }
    }
}
