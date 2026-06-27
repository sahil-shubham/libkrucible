// Copyright 2025 The libkrun Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::os::fd::AsRawFd;

use crate::bus::BusDevice;
use crate::legacy::gic::GICDevice;
use crate::legacy::irqchip::IrqChipT;
use crate::Error as DeviceError;

use kvm_ioctls::{DeviceFd, VmFd};
use utils::eventfd::EventFd;

const KVM_VGIC_V2_DIST_SIZE: u64 = 0x1000;
const KVM_VGIC_V2_CPU_SIZE: u64 = 0x2000;

// Device trees specific constants
const ARCH_GIC_V2_MAINT_IRQ: u32 = 8;

// --- GICv2 cold-tier save/restore -----------------------------------------
//
// A restored VM gets a freshly-created vGIC (KvmGicV2::new runs CTRL_INIT, so it
// starts disabled with all state reset). `save_state` reads the live registers
// via KVM_GET_DEVICE_ATTR; `restore_state` replays them via SET. The blob is a
// version-tagged sequence of (group, attr, value) entries stored in restore-safe
// order — configuration first, GICD_CTLR last — so restore is a straight replay.
//
// Banking: for GICv2 the distributor registers covering the 32 private IRQs
// (SGI 0-15, PPI 16-31) are banked per-vCPU; the KVM ABI takes the vCPU in the
// attr's CPUID field. SPI registers (IRQ 32+) are shared (CPUID 0). The CPU
// interface (GICC_*) registers go through CPU_REGS, also per-vCPU.

/// Blob tag — "GIC v2, format 1". `restore_state` refuses any other tag (e.g. a
/// GICv3 snapshot), the same classify-or-refuse posture as the bundle validator.
const GICV2_BLOB_TAG: [u8; 4] = *b"GV2\x01";

/// kvm-ioctls 0.24 wraps KVM_SET_DEVICE_ATTR but not the GET, so issue the GET
/// ioctl directly: `_IOW(KVMIO, 0xe2, struct kvm_device_attr)`.
const fn kvm_ioc_get_device_attr() -> libc::c_ulong {
    const DIR_WRITE: u64 = 1;
    const KVMIO: u64 = 0xAE;
    let size = core::mem::size_of::<kvm_bindings::kvm_device_attr>() as u64;
    ((DIR_WRITE << 30) | (size << 16) | (KVMIO << 8) | 0xe2) as libc::c_ulong
}
const KVM_GET_DEVICE_ATTR: libc::c_ulong = kvm_ioc_get_device_attr();

/// A GICD per-IRQ register family: word-0 offset, bits stored per IRQ, and
/// whether to skip the read-only banked SGI/PPI words (ITARGETSR).
struct GicdPerIrq {
    offset: u32,
    bits_per_irq: u32,
    spi_only: bool,
}

/// GICD per-IRQ registers in restore-safe order: group / priority / targets /
/// config before enable, then pending, then active. GICD_CTLR is handled
/// separately, last of all.
const GICD_PER_IRQ: &[GicdPerIrq] = &[
    GicdPerIrq {
        offset: 0x080,
        bits_per_irq: 1,
        spi_only: false,
    }, // GICD_IGROUPR
    GicdPerIrq {
        offset: 0x400,
        bits_per_irq: 8,
        spi_only: false,
    }, // GICD_IPRIORITYR
    GicdPerIrq {
        offset: 0x800,
        bits_per_irq: 8,
        spi_only: true,
    }, // GICD_ITARGETSR (SGI/PPI RO)
    GicdPerIrq {
        offset: 0xc00,
        bits_per_irq: 2,
        spi_only: false,
    }, // GICD_ICFGR
    GicdPerIrq {
        offset: 0x100,
        bits_per_irq: 1,
        spi_only: false,
    }, // GICD_ISENABLER
    GicdPerIrq {
        offset: 0x200,
        bits_per_irq: 1,
        spi_only: false,
    }, // GICD_ISPENDR
    GicdPerIrq {
        offset: 0x300,
        bits_per_irq: 1,
        spi_only: false,
    }, // GICD_ISACTIVER
];

/// GICv2 CPU-interface (GICC_*) register offsets captured per-vCPU.
const GICC_REGS: &[u32] = &[
    0x00, // GICC_CTLR
    0x04, // GICC_PMR
    0x08, // GICC_BPR
    0x1c, // GICC_ABPR
    0xd0, 0xd4, 0xd8, 0xdc, // GICC_APR0..3 (active priorities — mid-ISR state)
];

/// Encode the KVM vGIC device-attr: CPUID in bits[47:32], offset in bits[31:0].
fn vgic_attr(cpuid: u64, offset: u32) -> u64 {
    ((cpuid << kvm_bindings::KVM_DEV_ARM_VGIC_CPUID_SHIFT)
        & kvm_bindings::KVM_DEV_ARM_VGIC_CPUID_MASK as u64)
        | (u64::from(offset) & kvm_bindings::KVM_DEV_ARM_VGIC_OFFSET_MASK as u64)
}

fn push_entry(out: &mut Vec<u8>, group: u32, attr: u64, val: u32) {
    out.extend_from_slice(&group.to_le_bytes());
    out.extend_from_slice(&attr.to_le_bytes());
    out.extend_from_slice(&val.to_le_bytes());
}

pub struct KvmGicV2 {
    /// Held to keep the in-kernel vGIC alive; also read by the cold-tier
    /// save/restore (`KVM_{GET,SET}_DEVICE_ATTR`).
    device_fd: DeviceFd,

    /// GIC device properties, to be used for setting up the fdt entry
    properties: [u64; 4],

    /// Number of CPUs handled by the device
    vcpu_count: u64,

    /// Total IRQ lines the vGIC was created with (== the NR_IRQS attr); bounds
    /// the distributor register sweep in save/restore.
    nr_irqs: u32,
}

impl KvmGicV2 {
    pub fn new(vm: &VmFd, vcpu_count: u64) -> Self {
        let dist_size = KVM_VGIC_V2_DIST_SIZE;
        let dist_addr = arch::MMIO_MEM_START - dist_size;
        let cpu_size = KVM_VGIC_V2_CPU_SIZE;
        let cpu_addr = dist_addr - cpu_size;

        let mut gic_device = kvm_bindings::kvm_create_device {
            type_: kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2,
            fd: 0,
            flags: 0,
        };
        let device_fd = vm.create_device(&mut gic_device).unwrap();

        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            attr: u64::from(kvm_bindings::KVM_VGIC_V2_ADDR_TYPE_DIST),
            addr: &dist_addr as *const u64 as u64,
            flags: 0,
        };
        device_fd.set_device_attr(&attr).unwrap();

        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_ADDR,
            attr: u64::from(kvm_bindings::KVM_VGIC_V2_ADDR_TYPE_CPU),
            addr: &cpu_addr as *const u64 as u64,
            flags: 0,
        };
        device_fd.set_device_attr(&attr).unwrap();

        let nr_irqs: u32 = arch::aarch64::layout::IRQ_MAX - arch::aarch64::layout::IRQ_BASE + 1;
        let nr_irqs_ptr = &nr_irqs as *const u32;
        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
            attr: 0,
            addr: nr_irqs_ptr as u64,
            flags: 0,
        };
        device_fd.set_device_attr(&attr).unwrap();

        let attr = kvm_bindings::kvm_device_attr {
            group: kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CTRL,
            attr: u64::from(kvm_bindings::KVM_DEV_ARM_VGIC_CTRL_INIT),
            addr: 0,
            flags: 0,
        };
        device_fd.set_device_attr(&attr).unwrap();

        Self {
            device_fd,
            properties: [dist_addr, dist_size, cpu_addr, cpu_size],
            vcpu_count,
            nr_irqs,
        }
    }

    /// Read one vGIC register via KVM_GET_DEVICE_ATTR (kvm-ioctls wraps only the
    /// SET). `attr` is a pre-encoded CPUID|offset (see [`vgic_attr`]).
    fn get_reg(&self, group: u32, attr: u64) -> Result<u32, String> {
        let mut val: u32 = 0;
        let kattr = kvm_bindings::kvm_device_attr {
            group,
            attr,
            addr: &mut val as *mut u32 as u64,
            flags: 0,
        };
        // SAFETY: `kattr` is a valid &kvm_device_attr for the duration of the
        // call; its `addr` points at `val`, the u32 the kernel fills in.
        let ret = unsafe {
            libc::ioctl(
                self.device_fd.as_raw_fd(),
                KVM_GET_DEVICE_ATTR,
                &kattr as *const kvm_bindings::kvm_device_attr,
            )
        };
        if ret < 0 {
            return Err(format!(
                "KVM_GET_DEVICE_ATTR(group={group}, attr={attr:#x}): {}",
                io::Error::last_os_error()
            ));
        }
        Ok(val)
    }

    /// Write one vGIC register via KVM_SET_DEVICE_ATTR.
    fn set_reg(&self, group: u32, attr: u64, val: u32) -> Result<(), String> {
        let kattr = kvm_bindings::kvm_device_attr {
            group,
            attr,
            addr: &val as *const u32 as u64,
            flags: 0,
        };
        self.device_fd
            .set_device_attr(&kattr)
            .map_err(|e| format!("KVM_SET_DEVICE_ATTR(group={group}, attr={attr:#x}): {e}"))
    }
}

impl IrqChipT for KvmGicV2 {
    fn get_mmio_addr(&self) -> u64 {
        0
    }

    fn get_mmio_size(&self) -> u64 {
        0
    }

    fn set_irq(
        &self,
        _irq_line: Option<u32>,
        interrupt_evt: Option<&EventFd>,
    ) -> Result<(), DeviceError> {
        if let Some(interrupt_evt) = interrupt_evt {
            if let Err(e) = interrupt_evt.write(1) {
                error!("Failed to signal used queue: {e:?}");
                return Err(DeviceError::FailedSignalingUsedQueue(e));
            }
        } else {
            error!("EventFd not set up for irq line");
            return Err(DeviceError::FailedSignalingUsedQueue(io::Error::new(
                io::ErrorKind::NotFound,
                "EventFd not set up for irq line".to_string(),
            )));
        }
        Ok(())
    }
}

impl BusDevice for KvmGicV2 {
    fn read(&mut self, _vcpuid: u64, _offset: u64, _data: &mut [u8]) {
        unreachable!("MMIO operations are managed in-kernel");
    }

    fn write(&mut self, _vcpuid: u64, _offset: u64, _data: &[u8]) {
        unreachable!("MMIO operations are managed in-kernel");
    }
}

impl GICDevice for KvmGicV2 {
    fn device_properties(&self) -> Vec<u64> {
        self.properties.to_vec()
    }

    fn vcpu_count(&self) -> u64 {
        self.vcpu_count
    }

    fn fdt_compatibility(&self) -> String {
        "arm,gic-400".to_string()
    }

    fn fdt_maint_irq(&self) -> u32 {
        ARCH_GIC_V2_MAINT_IRQ
    }

    fn version(&self) -> u32 {
        kvm_bindings::kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2
    }

    fn save_state(&self) -> std::result::Result<Vec<u8>, String> {
        let dist = kvm_bindings::KVM_DEV_ARM_VGIC_GRP_DIST_REGS;
        let cpu = kvm_bindings::KVM_DEV_ARM_VGIC_GRP_CPU_REGS;
        let num = self.nr_irqs;
        let mut out = Vec::new();
        out.extend_from_slice(&GICV2_BLOB_TAG);

        // 1. GICD per-IRQ families (config/priority/targets/cfg, then enable,
        //    pending, active). Banked words (IRQs 0-31) captured per-vCPU; SPI
        //    words once (CPUID 0).
        for reg in GICD_PER_IRQ {
            let total_words = num * reg.bits_per_irq / 32;
            let banked_words = reg.bits_per_irq; // words covering IRQs 0-31
            let first = if reg.spi_only { banked_words } else { 0 };
            for w in first..total_words {
                let offset = reg.offset + w * 4;
                if w < banked_words {
                    for c in 0..self.vcpu_count {
                        let a = vgic_attr(c, offset);
                        push_entry(&mut out, dist, a, self.get_reg(dist, a)?);
                    }
                } else {
                    let a = vgic_attr(0, offset);
                    push_entry(&mut out, dist, a, self.get_reg(dist, a)?);
                }
            }
        }

        // 2. Per-vCPU CPU interface (GICC_*).
        for c in 0..self.vcpu_count {
            for &off in GICC_REGS {
                let a = vgic_attr(c, off);
                push_entry(&mut out, cpu, a, self.get_reg(cpu, a)?);
            }
        }

        // 3. GICD_CTLR last — the distributor is only (re)enabled once all of its
        //    state is in place.
        let ctlr = vgic_attr(0, 0x0);
        push_entry(&mut out, dist, ctlr, self.get_reg(dist, ctlr)?);

        Ok(out)
    }

    fn restore_state(&self, blob: &[u8]) -> std::result::Result<(), String> {
        if blob.len() < 4 || blob[0..4] != GICV2_BLOB_TAG {
            return Err(
                "gicv2 restore: blob tag mismatch (snapshot from a different GIC version?)"
                    .to_string(),
            );
        }
        let mut pos = 4;
        while pos + 16 <= blob.len() {
            let group = u32::from_le_bytes(blob[pos..pos + 4].try_into().unwrap());
            let attr = u64::from_le_bytes(blob[pos + 4..pos + 12].try_into().unwrap());
            let val = u32::from_le_bytes(blob[pos + 12..pos + 16].try_into().unwrap());
            self.set_reg(group, attr, val)?;
            pos += 16;
        }
        if pos != blob.len() {
            return Err("gicv2 restore: trailing bytes in blob".to_string());
        }
        Ok(())
    }
}
