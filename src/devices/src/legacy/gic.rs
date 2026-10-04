pub trait GICDevice {
    /// Returns an array with GIC device properties
    fn device_properties(&self) -> Vec<u64>;

    /// Returns the number of vCPUs this GIC handles
    fn vcpu_count(&self) -> u64;

    /// Returns the fdt compatibility property of the device
    fn fdt_compatibility(&self) -> String;

    /// Returns the maint_irq fdt property of the device
    fn fdt_maint_irq(&self) -> u32;

    /// Returns the GIC version of the device
    fn version(&self) -> u32;

    /// The in-kernel vGIC's KVM device, through which a checkpoint saves and
    /// restores its state. None for a GIC emulated in userspace.
    #[cfg(target_os = "linux")]
    fn kvm_device_fd(&self) -> Option<&kvm_ioctls::DeviceFd> {
        None
    }
}
