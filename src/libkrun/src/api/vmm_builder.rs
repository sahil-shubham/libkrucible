use std::marker::PhantomData;
#[cfg(not(target_os = "windows"))]
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[cfg(any(target_os = "macos", target_os = "linux"))]
use crate::vmm::VmCtl;
use crate::vmm::Vmm as InnerVmm;
#[cfg(unix)]
use crate::vmm::resources::SerialConsoleConfig;
use crate::vmm::resources::VmResources;
use crate::vmm::vmm_config::machine_config::VmConfig;
use crossbeam_channel::unbounded;
use polly::event_manager::EventManager;
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
use utils::eventfd::EventFd;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use utils::pollable_channel::PollableChannelSender;

use super::device_builders::{DeviceManager, MmioDeviceManager};
use super::error::VmmError;
use super::payload::Payload;

#[derive(Default)]
pub struct VmmBuilder<'a> {
    vcpus: Option<u8>,
    ram_mib: Option<u32>,
    payload: Option<Payload>,
    device_manager: Option<Box<dyn DeviceManager<'a> + 'a>>,
    #[cfg(unix)]
    serial_consoles: Vec<SerialConsoleConfig>,
    kernel_console: Option<String>,
    nested_virt: bool,
    split_irqchip: bool,
    acpi: bool,
    smbios_oem_strings: Vec<String>,
    shutdown_support: bool,
    restore_from: Option<PathBuf>,
}

#[cfg_attr(feature = "ffi", ffier::export)]
impl<'a> VmmBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn vcpus(mut self, count: u8) -> Result<Self, VmmError> {
        if count == 0 {
            return Err(VmmError::OutOfRange());
        }
        self.vcpus = Some(count);
        Ok(self)
    }

    pub fn ram_mib(mut self, mib: u32) -> Result<Self, VmmError> {
        if mib == 0 {
            return Err(VmmError::OutOfRange());
        }
        self.ram_mib = Some(mib);
        Ok(self)
    }

    pub fn payload(mut self, payload: Payload) -> Self {
        self.payload = Some(payload);
        self
    }

    pub fn devices(mut self, devices: MmioDeviceManager<'a>) -> Self {
        self.device_manager = Some(Box::new(devices));
        self
    }

    pub fn set_kernel_console(mut self, console: &str) -> Self {
        self.kernel_console = Some(console.to_string());
        self
    }

    /// Add a legacy serial console device with the given input and output file descriptors.
    ///
    /// Can be called multiple times to add multiple serial consoles (ttyS0, ttyS1, …).
    /// This is required for FreeBSD guests which use the legacy serial console instead
    /// of the virtio console.
    ///
    /// The descriptors are borrowed, not duplicated. They must remain open and valid
    /// until the VMM exits.
    #[cfg(not(target_os = "windows"))]
    pub fn add_serial_console(
        mut self,
        input_fd: Option<BorrowedFd<'a>>,
        output_fd: Option<BorrowedFd<'a>>,
    ) -> Result<Self, VmmError> {
        let in_fd = input_fd.map_or(-1, |fd| fd.as_raw_fd());
        let out_fd = output_fd.map_or(-1, |fd| fd.as_raw_fd());
        self.serial_consoles.push(SerialConsoleConfig {
            input_fd: in_fd,
            output_fd: out_fd,
        });
        Ok(self)
    }

    pub fn nested_virt(mut self, enabled: bool) -> Self {
        self.nested_virt = enabled;
        self
    }

    pub fn split_irqchip(mut self, enabled: bool) -> Result<Self, VmmError> {
        if enabled && !cfg!(target_arch = "x86_64") {
            return Err(VmmError::InvalidParam());
        }
        self.split_irqchip = enabled;
        Ok(self)
    }

    /// Enable ACPI table generation for x86_64 guests.
    ///
    /// When disabled (the default), virtio-mmio devices are passed on the kernel
    /// command line and SMP uses the MP table. When enabled, devices are described
    /// in the ACPI DSDT and the RSDP is published in boot parameters.
    pub fn acpi(mut self, enabled: bool) -> Result<Self, VmmError> {
        if enabled && !cfg!(target_arch = "x86_64") {
            return Err(VmmError::InvalidParam());
        }
        self.acpi = enabled;
        Ok(self)
    }

    pub fn add_smbios_oem_string(mut self, s: &str) -> Self {
        self.smbios_oem_strings.push(s.to_string());
        self
    }

    /// Enable the optional guest shutdown device.
    ///
    /// When enabled on aarch64 macOS, [`VmmHandle::shutdown`] signals the
    /// guest through the PL061 GPIO device. The device is not attached by
    /// default. On other platforms, shutdown remains unsupported.
    pub fn shutdown_support(mut self, enabled: bool) -> Self {
        self.shutdown_support = enabled;
        self
    }

    /// Restore the VM from a checkpoint directory instead of booting:
    /// [`build`](Self::build) maps the checkpoint's `memory.bin` privately
    /// (the directory is never modified, so it can be restored any number of
    /// times), checks the checkpoint against this host (see
    /// [`checkpoint_check_host`]) and this builder's vCPUs, RAM and devices,
    /// and the VM resumes where [`VmmHandle::save`] froze it. The payload and
    /// every device must be configured as for the saved VM (same types, ids and
    /// order); their host-side resources (socket paths, disk files) are new.
    pub fn restore_from(mut self, dir: &str) -> Self {
        self.restore_from = Some(PathBuf::from(dir));
        self
    }

    pub fn build(self) -> Result<Vmm<'a>, VmmError> {
        build_vm(self).inspect_err(|e| log::error!("{e}"))
    }
}

enum VmmInner {
    Vmm {
        #[allow(dead_code)]
        vmm: Arc<Mutex<InnerVmm>>,
        event_manager: EventManager,
        #[allow(dead_code)]
        _worker_sender: crossbeam_channel::Sender<utils::worker_message::WorkerMessage>,
        #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
        shutdown_efd: Option<EventFd>,
    },
    #[cfg(feature = "aws-nitro")]
    Nitro(aws_nitro::enclave::NitroEnclave),
}

pub struct Vmm<'a> {
    inner: VmmInner,
    _lifetime: PhantomData<&'a ()>,
}

/// Handle to the inner VMM, usable from another thread while the
/// event loop runs on the main thread via [`Vmm::run`].
///
/// Obtain via [`Vmm::handle`] before calling `run()`.
// FIXME: make Vmm::run() non-blocking (requires making EventManager Send)
// so that run() returns a RunningVmm with wait(). Then this handle
// can be obtained from RunningVmm instead of requiring a pre-run call.
pub struct VmmHandle {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    vm_ctl_tx: PollableChannelSender<VmCtl>,
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    shutdown_efd: Option<EventFd>,
}

impl Clone for VmmHandle {
    fn clone(&self) -> Self {
        Self {
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            vm_ctl_tx: self.vm_ctl_tx.clone(),
            #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
            shutdown_efd: self
                .shutdown_efd
                .as_ref()
                .map(|efd| efd.try_clone().expect("dup shutdown_efd")),
        }
    }
}

impl VmmHandle {
    /// Send a pause/resume request to the VMM's event loop and wait for its
    /// outcome, so a successful return means the vCPUs are actually parked
    /// (or running again).
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn vm_ctl(
        &self,
        req: fn(crossbeam_channel::Sender<Result<(), String>>) -> VmCtl,
        op: &str,
    ) -> Result<(), VmmError> {
        let (tx, rx) = crossbeam_channel::bounded(1);
        self.vm_ctl_tx
            .send(req(tx))
            .map_err(|e| VmmError::Internal(format!("{op}: {e}")))?;
        match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(VmmError::Internal(format!("{op}: {e}"))),
            Err(e) => Err(VmmError::Internal(format!("{op}: no answer from the VMM: {e}"))),
        }
    }
}

#[cfg_attr(feature = "ffi", ffier::export)]
impl VmmHandle {
    pub fn pause(&self) -> Result<(), VmmError> {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            self.vm_ctl(VmCtl::Pause, "pause")
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        Err(VmmError::FeatureDisabled())
    }

    pub fn resume(&self) -> Result<(), VmmError> {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            self.vm_ctl(VmCtl::Resume, "resume")
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        Err(VmmError::FeatureDisabled())
    }

    /// Signal the guest to perform an orderly ACPI shutdown.
    ///
    /// This requires [`VmmBuilder::shutdown_support`] to have been enabled
    /// before building the VMM. On aarch64 macOS it writes to the GPIO
    /// device's eventfd, which triggers a restart-key press in the guest. On
    /// other platforms, or when support was not enabled, it returns
    /// [`VmmError::FeatureDisabled`].
    pub fn shutdown(&self) -> Result<(), VmmError> {
        #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
        {
            let Some(shutdown_efd) = &self.shutdown_efd else {
                return Err(VmmError::FeatureDisabled());
            };
            shutdown_efd
                .write(1)
                .map_err(|e| VmmError::Internal(format!("shutdown: {e}")))
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "macos")))]
        Err(VmmError::FeatureDisabled())
    }

    /// Save the running VM to `dir`, which must not exist (its parent must):
    /// the guest's RAM to `memory.bin`, the rest to `checkpoint.bin`, written
    /// last, every file fsync'd. On success the VM is left paused with its
    /// devices' I/O stopped, so the caller can copy its disks at this exact
    /// point, then [`resume`](Self::resume) it (which restarts the devices) or
    /// end the VMM. On failure the VM is back as it was and `dir` doesn't
    /// exist.
    ///
    /// Takes as long as writing the guest's RAM out does. Linux KVM on x86_64
    /// and aarch64 only (see [`checkpoint_supported`]); elsewhere it returns
    /// [`VmmError::FeatureDisabled`].
    pub fn save(&self, dir: &str) -> Result<(), VmmError> {
        #[cfg(checkpoint)]
        {
            let (reply, answer) = crossbeam_channel::bounded(1);
            self.vm_ctl_tx
                .send(VmCtl::Save {
                    dir: PathBuf::from(dir),
                    reply,
                })
                .map_err(|e| VmmError::Internal(format!("save: {e}")))?;
            // No deadline: giving up early would report a failure while the
            // save carries on and leaves the VM paused. The channel closes if
            // the VMM goes away.
            match answer.recv() {
                Ok(result) => result.map_err(|e| VmmError::Internal(format!("save: {e}"))),
                Err(_) => Err(VmmError::Internal("save: the VMM is gone".into())),
            }
        }
        #[cfg(not(checkpoint))]
        {
            let _ = dir;
            Err(VmmError::FeatureDisabled())
        }
    }
}

#[cfg_attr(feature = "ffi", ffier::export)]
impl<'a> Vmm<'a> {
    /// Obtain a thread-safe handle to the inner VMM.
    ///
    /// Must be called before [`run`](Self::run) which consumes `self`.
    /// The handle can be moved to another thread for pause/resume.
    pub fn handle(&self) -> Result<VmmHandle, VmmError> {
        match &self.inner {
            VmmInner::Vmm {
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                vmm,
                #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
                shutdown_efd,
                ..
            } => Ok(VmmHandle {
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                vm_ctl_tx: vmm.lock().unwrap().vm_ctl_sender(),
                #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
                shutdown_efd: shutdown_efd
                    .as_ref()
                    .map(|efd| efd.try_clone().expect("dup shutdown_efd")),
            }),
            #[cfg(feature = "aws-nitro")]
            VmmInner::Nitro(_) => Err(VmmError::FeatureDisabled()),
        }
    }

    pub fn run(self) {
        match self.inner {
            VmmInner::Vmm {
                mut event_manager, ..
            } => loop {
                if let Err(e) = event_manager.run() {
                    log::error!("fatal event loop error: {e:?}");
                    return;
                }
            },
            #[cfg(feature = "aws-nitro")]
            VmmInner::Nitro(enclave) => {
                let exit_code = enclave.run().unwrap_or_else(|e| {
                    log::error!("Error running nitro enclave: {e}");
                    -libc::EINVAL
                });
                unsafe { libc::_exit(exit_code) }
            }
        }
    }
}

#[cfg_attr(feature = "ffi", ffier::export)]
pub fn check_nested_virt() -> bool {
    #[cfg(target_os = "macos")]
    {
        hvf::check_nested_virt().unwrap_or(false)
    }

    #[cfg(target_os = "linux")]
    {
        use std::fs;
        let paths = [
            "/sys/module/kvm_intel/parameters/nested",
            "/sys/module/kvm_amd/parameters/nested",
        ];
        paths.iter().any(|path| {
            fs::read_to_string(path).is_ok_and(|contents| {
                let val = contents.trim();
                val == "1" || val.eq_ignore_ascii_case("Y")
            })
        })
    }
    #[cfg(target_os = "windows")]
    {
        false
    }
}

/// Whether this build, on this host, can save and restore VMs
/// ([`VmmHandle::save`], [`VmmBuilder::restore_from`]): Linux KVM on x86_64
/// and aarch64 for now.
#[cfg_attr(feature = "ffi", ffier::export)]
pub fn checkpoint_supported() -> bool {
    #[cfg(checkpoint)]
    {
        crate::vmm::checkpoint_supported()
    }
    #[cfg(not(checkpoint))]
    {
        false
    }
}

/// Whether this host can restore the checkpoint in `dir`, without building a
/// VM: the error carries the reason [`VmmBuilder::restore_from`] would refuse
/// it here. A checkpoint records the host it was taken on; another CPU (x86:
/// vendor; arm64: model and revision) or page size, CPU features the guest
/// uses that this host lacks, or a guest clock this host can't run at (x86:
/// TSC rate; arm64: counter frequency) refuse it, as do, on x86, MSRs and on
/// arm64, registers or a GIC version this host's KVM can't restore, and a
/// damaged or foreign `checkpoint.bin`. The RAM image isn't read.
///
/// Linux KVM on x86_64 and aarch64 only (see [`checkpoint_supported`]);
/// elsewhere it returns [`VmmError::FeatureDisabled`].
#[cfg_attr(feature = "ffi", ffier::export)]
pub fn checkpoint_check_host(dir: &str) -> Result<(), VmmError> {
    #[cfg(checkpoint)]
    {
        crate::vmm::check_checkpoint_host(std::path::Path::new(dir)).map_err(VmmError::Checkpoint)
    }
    #[cfg(not(checkpoint))]
    {
        let _ = dir;
        Err(VmmError::FeatureDisabled())
    }
}

fn build_vm(builder_cfg: VmmBuilder<'_>) -> Result<Vmm<'_>, VmmError> {
    use super::payload::PayloadKind;

    let vcpus_count = builder_cfg
        .vcpus
        .ok_or_else(|| VmmError::MissingConfig("vcpus not set".into()))?;
    let ram_mib = builder_cfg
        .ram_mib
        .ok_or_else(|| VmmError::MissingConfig("ram_mib not set".into()))?;
    let payload = builder_cfg
        .payload
        .ok_or_else(|| VmmError::MissingConfig("payload not set".into()))?;

    #[cfg(feature = "aws-nitro")]
    if let PayloadKind::Nitro(nitro_config) = payload.kind {
        let enclave = nitro_config
            .into_enclave(vcpus_count, ram_mib as usize)
            .map_err(|e| VmmError::MissingConfig(e.to_string()))?;
        return Ok(Vmm {
            inner: VmmInner::Nitro(enclave),
            _lifetime: PhantomData,
        });
    }

    let device_manager = builder_cfg
        .device_manager
        .ok_or_else(|| VmmError::MissingConfig("no device manager set (call .devices())".into()))?;

    #[cfg(checkpoint)]
    let restore = builder_cfg
        .restore_from
        .as_deref()
        .map(|dir| {
            crate::vmm::checkpoint::format::Checkpoint::load(dir)
                .map(|(checkpoint, memory)| crate::vmm::builder::RestoreCtx { checkpoint, memory })
                .map_err(|e| VmmError::BootError(format!("restore: {e}")))
        })
        .transpose()?;
    #[cfg(not(checkpoint))]
    if builder_cfg.restore_from.is_some() {
        return Err(VmmError::FeatureDisabled());
    }

    let mut vm_resources = VmResources::default();
    vm_resources
        .set_vm_config(&VmConfig {
            vcpu_count: Some(vcpus_count),
            mem_size_mib: Some(ram_mib as usize),
            ht_enabled: Some(false),
            cpu_template: None,
        })
        .map_err(|e| {
            log::error!("vm config: {e:?}");
            VmmError::InvalidParam()
        })?;

    match payload.kind {
        PayloadKind::Kernel { bundle } => {
            vm_resources.kernel_bundle = Some(bundle);
        }
        PayloadKind::External { kernel } => {
            vm_resources.external_kernel = Some(kernel);
        }
        PayloadKind::Firmware { path } => {
            vm_resources
                .set_firmware_config(crate::vmm::vmm_config::firmware::FirmwareConfig { path });
        }
        #[cfg(feature = "tee")]
        PayloadKind::Tee {
            bundle,
            qboot_bundle,
            initrd_bundle,
            tee_config_path,
            #[cfg(feature = "tdx")]
            firmware_path,
        } => {
            vm_resources.kernel_bundle = Some(bundle);
            if let Some(qboot_bundle) = qboot_bundle {
                vm_resources.set_qboot_bundle(qboot_bundle).map_err(|e| {
                    log::error!("qboot bundle: {e}");
                    VmmError::InvalidParam()
                })?;
            }
            #[cfg(feature = "tdx")]
            if let Some(path) = firmware_path {
                vm_resources.set_tee_firmware_config(
                    crate::vmm::vmm_config::firmware::TeeFirmwareConfig {
                        fw_type: crate::vmm::vmm_config::firmware::TeeFirmwareType::TdShim,
                        path,
                    },
                );
            }
            vm_resources.set_initrd_bundle(initrd_bundle);
            vm_resources.set_tee_config(tee_config_path).map_err(|e| {
                log::error!("tee config: {e:?}");
                VmmError::InvalidParam()
            })?;
        }
        #[cfg(feature = "aws-nitro")]
        PayloadKind::Nitro(_) => unreachable!("handled above"),
    }

    vm_resources.kernel_cmdline.prolog = Some(payload.cmdline);

    vm_resources.nested_enabled = builder_cfg.nested_virt;
    vm_resources.split_irqchip = builder_cfg.split_irqchip;
    vm_resources.acpi_enabled = builder_cfg.acpi;
    if !builder_cfg.smbios_oem_strings.is_empty() {
        vm_resources.smbios_oem_strings = Some(builder_cfg.smbios_oem_strings);
    }

    if let Some(console) = builder_cfg.kernel_console {
        vm_resources.kernel_console = Some(console);
    }

    #[cfg(unix)]
    {
        vm_resources.serial_consoles = builder_cfg.serial_consoles;
    }

    let mut event_manager =
        EventManager::new().map_err(|e| VmmError::Internal(format!("{e:?}")))?;

    let (sender, receiver) = unbounded();

    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    let shutdown_efd = if builder_cfg.shutdown_support {
        Some(EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(|_| VmmError::ResourceAlloc())?)
    } else {
        None
    };
    #[cfg(not(all(target_arch = "aarch64", target_os = "macos")))]
    let _ = builder_cfg.shutdown_support;

    let inner = crate::vmm::builder::build_microvm(
        &vm_resources,
        &mut event_manager,
        #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
        shutdown_efd
            .as_ref()
            .map(|efd| EventFd::try_clone(efd).expect("dup shutdown_efd")),
        #[cfg(not(all(target_arch = "aarch64", target_os = "macos")))]
        None,
        sender.clone(),
        device_manager,
        #[cfg(checkpoint)]
        restore,
    )
    .map_err(|e| match e {
        // A refused restore explains itself; the rest are internal states.
        #[cfg(checkpoint)]
        crate::vmm::builder::StartMicrovmError::Checkpoint(e) => {
            VmmError::BootError(format!("restore: {e}"))
        }
        e => VmmError::BootError(format!("{e:?}")),
    })?;

    let needs_worker = {
        #[cfg(any(feature = "amd-sev", feature = "tdx"))]
        {
            true
        }
        #[cfg(not(any(feature = "amd-sev", feature = "tdx")))]
        {
            #[cfg(target_arch = "x86_64")]
            {
                builder_cfg.split_irqchip
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                false
            }
        }
    };

    if needs_worker {
        crate::vmm::worker::start_worker_thread(inner.clone(), receiver.clone())
            .map_err(|e| VmmError::Internal(format!("worker thread: {e}")))?;
    } else {
        let _ = receiver;
    }

    Ok(Vmm {
        inner: VmmInner::Vmm {
            vmm: inner,
            event_manager,
            _worker_sender: sender,
            #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
            shutdown_efd,
        },
        _lifetime: PhantomData,
    })
}
