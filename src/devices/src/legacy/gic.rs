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

    /// Capture the interrupt-controller state for a cold snapshot as a
    /// version-tagged, opaque blob. Default: unsupported — only the in-kernel
    /// KVM GICs implement it; the macOS/HVF and userspace paths capture state
    /// their own way or don't support the cold tier.
    fn save_state(&self) -> std::result::Result<Vec<u8>, String> {
        Err("interrupt controller does not support cold-tier save/restore".to_string())
    }

    /// Restore a blob produced by [`GICDevice::save_state`]. Default: unsupported.
    fn restore_state(&self, _blob: &[u8]) -> std::result::Result<(), String> {
        Err("interrupt controller does not support cold-tier save/restore".to_string())
    }
}
