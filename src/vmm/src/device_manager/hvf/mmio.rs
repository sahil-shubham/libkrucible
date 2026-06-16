// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::{fmt, io};

use devices::fdt::DeviceInfoForFDT;
use devices::legacy::IrqChip;
use devices::{BusDevice, DeviceType};
use kernel::cmdline as kernel_cmdline;
use polly::event_manager::EventManager;
#[cfg(target_arch = "aarch64")]
use utils::eventfd::EventFd;

use crate::vstate::Vm;

/// Errors for MMIO device manager.
#[allow(clippy::enum_variant_names)]
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
    RegisterIoEvent,
    /// Registering an IRQ FD failed.
    RegisterIrqFd,
    /// The device couldn't be found
    DeviceNotFound,
    /// Failed to update the mmio device.
    UpdateFailed,
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
            Error::RegisterIoEvent => write!(f, "failed to register IO event"),
            Error::RegisterIrqFd => write!(f, "failed to register irqfd"),
            Error::DeviceNotFound => write!(f, "the device couldn't be found"),
            Error::UpdateFailed => write!(f, "failed to update the mmio device"),
        }
    }
}

impl From<devices::virtio::CreateMmioTransportError> for crate::device_manager::mmio::Error {
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
    // Side list of the virtio transports for checkpoint/restore: the bus only
    // holds `dyn BusDevice`, so we keep the concrete transports here to iterate
    // for snapshot/quiesce/restore (cold tier).
    mmio_transports: Vec<Arc<Mutex<devices::virtio::MmioTransport>>>,
}

impl MMIODeviceManager {
    /// Create a new DeviceManager handling mmio devices (virtio net, block).
    pub fn new(mmio_base: &mut u64, irq_interval: (u32, u32)) -> MMIODeviceManager {
        if cfg!(target_arch = "aarch64") {
            *mmio_base += MMIO_LEN;
        }

        MMIODeviceManager {
            mmio_base: *mmio_base,
            irq: irq_interval.0,
            last_irq: irq_interval.1,
            bus: devices::Bus::new(),
            id_to_dev_info: HashMap::new(),
            mmio_transports: Vec::new(),
        }
    }

    /// Capture the runtime state of every snapshot-supporting virtio device for
    /// a VM checkpoint. The caller must pause vCPUs and quiesce_devices first so
    /// queue indices are at a clean boundary.
    pub fn snapshot_devices(&self) -> devices::virtio::persist::VmDevicesState {
        let mut snapshots = Vec::new();
        for t in &self.mmio_transports {
            let guard = t.lock().expect("poisoned transport lock");
            if let Some(snap) = devices::virtio::persist::snapshot_device(&*guard.locked_device()) {
                snapshots.push(snap);
            }
        }
        devices::virtio::persist::VmDevicesState { devices: snapshots }
    }

    /// Quiesce every virtio device (drain+reclaim its worker) before snapshot.
    /// Pair with [`Self::rearm_devices`].
    pub fn quiesce_devices(&self) {
        for t in &self.mmio_transports {
            t.lock()
                .expect("poisoned transport lock")
                .locked_device()
                .quiesce_for_snapshot();
        }
    }

    /// Re-arm every device quiesced by [`Self::quiesce_devices`] (in-process).
    pub fn rearm_devices(&self) {
        for t in &self.mmio_transports {
            t.lock()
                .expect("poisoned transport lock")
                .locked_device()
                .rearm_after_snapshot();
        }
    }

    /// Re-activate devices on a freshly-built VM from a checkpoint: for each
    /// saved device snapshot, find a not-yet-consumed transport of the matching
    /// device type, restore its device-level state, then re-activate it from the
    /// saved queue state + features (bypassing the guest handshake).
    pub fn restore_activate_devices(
        &self,
        state: &devices::virtio::persist::VmDevicesState,
    ) -> std::result::Result<(), String> {
        let mut used = vec![false; self.mmio_transports.len()];
        for snap in &state.devices {
            let want = snap.device_type();
            let queue_states = snap.queue_states();
            let acked = snap.acked_features();
            let mut applied = false;
            for (i, transport) in self.mmio_transports.iter().enumerate() {
                if used[i] {
                    continue;
                }
                let mut t = transport.lock().expect("poisoned transport lock");
                if t.locked_device().device_type() != want {
                    continue;
                }
                // Restore device-level state onto the not-yet-activated device
                // first, so the subsequent activate rebuilds its worker from it.
                devices::virtio::persist::restore_device(&mut *t.locked_device(), snap)?;
                t.restore_and_activate(&queue_states, acked)?;
                t.locked_device().finish_restore_activation();
                used[i] = true;
                applied = true;
                break;
            }
            if !applied {
                return Err(format!("no matching transport to restore device type {want}"));
            }
        }
        Ok(())
    }

    /// Register an already created MMIO device to be used via MMIO transport.
    pub fn register_mmio_device(
        &mut self,
        mut mmio_device: devices::virtio::MmioTransport,
        type_id: u32,
        device_id: String,
    ) -> Result<(u64, u32)> {
        if self.irq > self.last_irq {
            return Err(Error::IrqsExhausted);
        }

        mmio_device.set_irq_line(self.irq);

        let transport = Arc::new(Mutex::new(mmio_device));
        self.mmio_transports.push(transport.clone());
        self.bus
            .insert(transport, self.mmio_base, MMIO_LEN)
            .map_err(Error::BusError)?;
        let ret = (self.mmio_base, self.irq);
        self.id_to_dev_info.insert(
            (DeviceType::Virtio(type_id), device_id),
            MMIODeviceInfo {
                addr: self.mmio_base,
                len: MMIO_LEN,
                irq: self.irq,
            },
        );
        self.mmio_base += MMIO_LEN;
        self.irq += 1;

        Ok(ret)
    }

    #[cfg(target_arch = "aarch64")]
    /// Register an early console at some MMIO address.
    pub fn register_mmio_serial(
        &mut self,
        _vm: &Vm,
        cmdline: &mut kernel_cmdline::Cmdline,
        intc: IrqChip,
        serial: Arc<Mutex<devices::legacy::Serial>>,
    ) -> Result<()> {
        if self.irq > self.last_irq {
            return Err(Error::IrqsExhausted);
        }

        {
            let mut serial = serial.lock().unwrap();
            serial.set_intc(intc);
            serial.set_irq_line(self.irq);
        }

        self.bus
            .insert(serial, self.mmio_base, MMIO_LEN)
            .map_err(Error::BusError)?;

        cmdline
            .insert(
                "earlycon",
                &format!("pl011,mmio32,0x{:08x}", self.mmio_base),
            )
            .map_err(Error::Cmdline)?;

        let ret = self.mmio_base;
        self.id_to_dev_info.insert(
            (DeviceType::Serial, DeviceType::Serial.to_string()),
            MMIODeviceInfo {
                addr: ret,
                len: MMIO_LEN,
                irq: self.irq,
            },
        );

        self.mmio_base += MMIO_LEN;
        self.irq += 1;

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    /// Register a MMIO RTC device.
    pub fn register_mmio_rtc(&mut self, _vm: &Vm, _intc: IrqChip) -> Result<()> {
        if self.irq > self.last_irq {
            return Err(Error::IrqsExhausted);
        }

        // Attaching the RTC device.
        let rtc_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(Error::EventFd)?;
        let device = devices::legacy::RTC::new(rtc_evt.try_clone().map_err(Error::EventFd)?);

        self.bus
            .insert(Arc::new(Mutex::new(device)), self.mmio_base, MMIO_LEN)
            .map_err(Error::BusError)?;

        let ret = self.mmio_base;
        self.id_to_dev_info.insert(
            (DeviceType::RTC, "rtc".to_string()),
            MMIODeviceInfo {
                addr: ret,
                len: MMIO_LEN,
                irq: self.irq,
            },
        );

        self.mmio_base += MMIO_LEN;
        self.irq += 1;

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    /// Register a GPIO
    pub fn register_mmio_gpio(
        &mut self,
        _vm: &Vm,
        intc: IrqChip,
        event_manager: &mut EventManager,
        shutdown_efd: EventFd,
    ) -> Result<()> {
        // Attaching the GPIO device.
        let gpio_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(Error::EventFd)?;
        let gpio = Arc::new(Mutex::new(devices::legacy::Gpio::new(
            shutdown_efd,
            gpio_evt.try_clone().map_err(Error::EventFd)?,
        )));

        event_manager.add_subscriber(gpio.clone()).unwrap();

        if self.irq > self.last_irq {
            return Err(Error::IrqsExhausted);
        }

        {
            let mut gpio = gpio.lock().unwrap();
            gpio.set_intc(intc);
            gpio.set_irq_line(self.irq);
        }

        self.bus
            .insert(gpio, self.mmio_base, MMIO_LEN)
            .map_err(Error::BusError)?;

        let ret = self.mmio_base;
        self.id_to_dev_info.insert(
            (DeviceType::Gpio, DeviceType::Gpio.to_string()),
            MMIODeviceInfo {
                addr: ret,
                len: MMIO_LEN,
                irq: self.irq,
            },
        );

        self.mmio_base += MMIO_LEN;
        self.irq += 1;

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    /// Register a MMIO GIC device.
    pub fn register_mmio_gic(&mut self, _vm: &Vm, intc: IrqChip) -> Result<()> {
        let (mmio_addr, mmio_size) = {
            let intc = intc.lock().unwrap();
            (intc.get_mmio_addr(), intc.get_mmio_size())
        };

        // The in-kernel GIC reports a size of 0 to tell us we don't need to map
        // anything in the guest.
        if mmio_size != 0 {
            self.bus
                .insert(intc, mmio_addr, mmio_size)
                .map_err(Error::BusError)?;
        }

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    /// Gets the information of the devices registered up to some point in time.
    pub fn get_device_info(&self) -> &HashMap<(DeviceType, String), MMIODeviceInfo> {
        &self.id_to_dev_info
    }

    /// Gets the specified device.
    pub fn get_device(
        &self,
        device_type: DeviceType,
        device_id: &str,
    ) -> Option<&Mutex<dyn BusDevice>> {
        if let Some(dev_info) = self
            .id_to_dev_info
            .get(&(device_type, device_id.to_string()))
            && let Some((_, device)) = self.bus.get_device(dev_info.addr)
        {
            return Some(device);
        }
        None
    }
}

/// Private structure for storing information about the MMIO device registered at some address on the bus.
#[derive(Clone, Debug)]
pub struct MMIODeviceInfo {
    addr: u64,
    irq: u32,
    len: u64,
}

#[cfg(target_arch = "aarch64")]
impl DeviceInfoForFDT for MMIODeviceInfo {
    fn addr(&self) -> u64 {
        self.addr
    }
    fn irq(&self) -> u32 {
        self.irq
    }
    fn length(&self) -> u64 {
        self.len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arch;
    use devices::legacy::DummyIrqChip;
    use devices::virtio::{
        ActivateResult, DeviceQueue, InterruptTransport, QueueConfig, VirtioDevice,
    };
    use std::sync::Arc;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    const QUEUE_SIZES: &[u16] = &[64];

    impl MMIODeviceManager {
        fn register_virtio_device(
            &mut self,
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
                self.register_mmio_device(mmio_device, type_id, device_id.to_string())?;
            Ok(mmio_base)
        }
    }

    #[allow(dead_code)]
    struct DummyDevice {
        dummy: u32,
        queue_config: Vec<QueueConfig>,
    }

    impl DummyDevice {
        pub fn new() -> Self {
            DummyDevice {
                dummy: 0,
                queue_config: QUEUE_SIZES.iter().map(|&s| QueueConfig::new(s)).collect(),
            }
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
            &self.queue_config
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
            _interrupt: InterruptTransport,
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
        let mut device_manager =
            MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));

        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        let dummy = Arc::new(Mutex::new(DummyDevice::new()));

        assert!(
            device_manager
                .register_virtio_device(guest_mem, dummy, &mut cmdline, 0, "dummy")
                .is_ok()
        );
    }

    #[test]
    fn test_register_too_many_devices() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemoryMmap::from_ranges(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();
        let mut device_manager =
            MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));

        let mut cmdline = kernel_cmdline::Cmdline::new(4096);

        for _i in arch::IRQ_BASE..=arch::IRQ_MAX {
            device_manager
                .register_virtio_device(
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
        assert_eq!(dummy.queue_config().len(), QUEUE_SIZES.len());
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
            format!("{}", e),
            format!(
                "unable to add device to kernel command line: {}",
                kernel_cmdline::Error::HasEquals
            ),
        );
        assert_eq!(
            format!("{}", Error::UpdateFailed),
            "failed to update the mmio device"
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
            format!("{}", Error::RegisterIoEvent),
            "failed to register IO event"
        );
        assert_eq!(
            format!("{}", Error::RegisterIrqFd),
            "failed to register irqfd"
        );
    }

    #[test]
    fn test_device_info() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemoryMmap::from_ranges(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();
        let mut device_manager =
            MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));
        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        let dummy = Arc::new(Mutex::new(DummyDevice::new()));

        let type_id = 0;
        let id = String::from("foo");
        if let Ok(addr) =
            device_manager.register_virtio_device(guest_mem, dummy, &mut cmdline, type_id, &id)
        {
            assert!(
                device_manager
                    .get_device(DeviceType::Virtio(type_id), &id)
                    .is_some()
            );
            assert_eq!(
                addr,
                device_manager.id_to_dev_info[&(DeviceType::Virtio(type_id), id.clone())].addr
            );
            assert_eq!(
                arch::IRQ_BASE,
                device_manager.id_to_dev_info[&(DeviceType::Virtio(type_id), id.clone())].irq
            );
        }
        let id = "bar";
        assert!(
            device_manager
                .get_device(DeviceType::Virtio(type_id), &id)
                .is_none()
        );
    }
}
