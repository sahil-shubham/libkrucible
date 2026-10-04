//! The in-kernel vGIC's state for checkpoints: its distributor,
//! redistributors (GICv3) and CPU interfaces, read and written through the
//! KVM device's register groups.
//!
//! A save records the register writes a restore replays, in the order QEMU
//! restores a vGIC. The implementation revision (GICD_IIDR) goes first: KVM
//! only lets userspace set a GICv2's interrupt groups after it. An
//! interrupt's configuration and routing go before its pending state, so that
//! lands on the right CPU and is treated as edge or level as the guest set it
//! up. Each write-1-to-set register follows a write of all ones to its
//! write-1-to-clear twin, so nothing a fresh vGIC has enabled (KVM enables
//! SGIs) stays enabled unless the guest had it.
//!
//! The vCPUs must be out of KVM_RUN throughout: KVM refuses (EBUSY) to touch
//! the vGIC's state while one runs.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd};

use devices::legacy::IrqChip;
use devices::legacy::gic::GICDevice;
use kvm_bindings::{
    KVM_DEV_ARM_VGIC_CPUID_SHIFT, KVM_DEV_ARM_VGIC_GRP_CPU_REGS, KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS,
    KVM_DEV_ARM_VGIC_GRP_DIST_REGS, KVM_DEV_ARM_VGIC_GRP_LEVEL_INFO,
    KVM_DEV_ARM_VGIC_GRP_REDIST_REGS, KVM_DEV_ARM_VGIC_LINE_LEVEL_INFO_SHIFT, kvm_device_attr,
    kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2, kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
};
use kvm_ioctls::DeviceFd;

use crate::vmm::checkpoint::codec::{Decoder, Encoder, Pod};

const DIST: u32 = KVM_DEV_ARM_VGIC_GRP_DIST_REGS;
const CPU: u32 = KVM_DEV_ARM_VGIC_GRP_CPU_REGS;
const REDIST: u32 = KVM_DEV_ARM_VGIC_GRP_REDIST_REGS;
const SYSREGS: u32 = KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS;
const LEVELS: u32 = KVM_DEV_ARM_VGIC_GRP_LEVEL_INFO;

// Distributor registers (both versions).
const GICD_CTLR: u64 = 0x000;
const GICD_TYPER: u64 = 0x004;
const GICD_IIDR: u64 = 0x008;
const GICD_STATUSR: u64 = 0x010;
const GICD_IGROUPR: u64 = 0x080;
const GICD_ISENABLER: u64 = 0x100;
const GICD_ICENABLER: u64 = 0x180;
const GICD_ISPENDR: u64 = 0x200;
const GICD_ICPENDR: u64 = 0x280;
const GICD_ISACTIVER: u64 = 0x300;
const GICD_ICACTIVER: u64 = 0x380;
const GICD_IPRIORITYR: u64 = 0x400;
const GICD_ITARGETSR: u64 = 0x800;
const GICD_ICFGR: u64 = 0xc00;
const GICD_CPENDSGIR: u64 = 0xf10;
const GICD_SPENDSGIR: u64 = 0xf20;
const GICD_IROUTER: u64 = 0x6000;

// GICv2 CPU interface registers.
const GICC_CTLR: u64 = 0x00;
const GICC_PMR: u64 = 0x04;
const GICC_BPR: u64 = 0x08;
const GICC_ABPR: u64 = 0x1c;
const GICC_APR: u64 = 0xd0;

// GICv3 redistributor registers, and those of its SGI frame.
const GICR_CTLR: u64 = 0x0000;
const GICR_TYPER: u64 = 0x0008;
const GICR_STATUSR: u64 = 0x0010;
const GICR_WAKER: u64 = 0x0014;
const GICR_TYPER_PLPIS: u64 = 1;
const SGI: u64 = 0x1_0000;
const GICR_IGROUPR0: u64 = SGI + GICD_IGROUPR;
const GICR_ISENABLER0: u64 = SGI + GICD_ISENABLER;
const GICR_ICENABLER0: u64 = SGI + GICD_ICENABLER;
const GICR_ISPENDR0: u64 = SGI + GICD_ISPENDR;
const GICR_ISACTIVER0: u64 = SGI + GICD_ISACTIVER;
const GICR_ICACTIVER0: u64 = SGI + GICD_ICACTIVER;
const GICR_IPRIORITYR0: u64 = SGI + GICD_IPRIORITYR;
const GICR_ICFGR0: u64 = SGI + GICD_ICFGR;

/// A GICv3 CPU interface register: the A64 encoding (op0, op1, CRn, CRm,
/// op2) of its system register.
const fn icc(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) -> u64 {
    op0 << 14 | op1 << 11 | crn << 7 | crm << 3 | op2
}
const ICC_PMR_EL1: u64 = icc(3, 0, 4, 6, 0);
const ICC_BPR0_EL1: u64 = icc(3, 0, 12, 8, 3);
const ICC_BPR1_EL1: u64 = icc(3, 0, 12, 12, 3);
const ICC_CTLR_EL1: u64 = icc(3, 0, 12, 12, 4);
const ICC_SRE_EL1: u64 = icc(3, 0, 12, 12, 5);
const ICC_IGRPEN0_EL1: u64 = icc(3, 0, 12, 12, 6);
const ICC_IGRPEN1_EL1: u64 = icc(3, 0, 12, 12, 7);
const fn icc_ap0r(n: u64) -> u64 {
    icc(3, 0, 12, 8, 4 + n)
}
const fn icc_ap1r(n: u64) -> u64 {
    icc(3, 0, 12, 9, n)
}

/// KVM_DEV_ARM_VGIC_GRP_LEVEL_INFO's info for the input lines' levels.
const VGIC_LEVEL_INFO_LINE_LEVEL: u64 = 0;

/// The line-level attribute for the 32 interrupts from `intid`.
fn line_level(intid: u64) -> u64 {
    VGIC_LEVEL_INFO_LINE_LEVEL << KVM_DEV_ARM_VGIC_LINE_LEVEL_INFO_SHIFT | intid
}

/// How many interrupts (SGIs, PPIs and SPIs) a GIC whose GICD_TYPER is
/// `typer` has.
fn irq_count(typer: u32) -> u64 {
    (u64::from(typer & 0x1f) + 1) * 32
}

/// A GICv3 redistributor's (or CPU interface's) address in an attribute: the
/// vCPU's MPIDR_EL1 affinity as Aff3.Aff2.Aff1.Aff0, in bits 63:32.
fn affinity(mpidr: u64) -> u64 {
    ((mpidr & 0xff_ffff) | (mpidr >> 32 & 0xff) << 24) << 32
}

/// One register write: a KVM device attribute and the value it takes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct GicReg {
    pub group: u32,
    pad: u32,
    pub attr: u64,
    pub value: u64,
}

// SAFETY: integers only, the padding spelled out.
unsafe impl Pod for GicReg {}

/// A vGIC's state, as the writes that bring a fresh one to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GicState {
    /// The GIC architecture version: 2 or 3.
    pub version: u32,
    /// GICD_TYPER, for its interrupt count.
    pub typer: u32,
    /// The vCPUs' MPIDR_EL1s: the registers' attributes address the vCPUs
    /// by them (GICv3) or by their index (GICv2).
    pub mpidrs: Vec<u64>,
    pub regs: Vec<GicReg>,
}

impl GicState {
    pub(crate) fn encode(&self, enc: &mut Encoder) {
        enc.u32(self.version);
        enc.u32(self.typer);
        enc.pods(&self.mpidrs);
        enc.pods(&self.regs);
    }

    pub(crate) fn decode(dec: &mut Decoder) -> Result<Self, String> {
        Ok(GicState {
            version: dec.u32()?,
            typer: dec.u32()?,
            mpidrs: dec.pods()?,
            regs: dec.pods()?,
        })
    }
}

/// A VM's in-kernel vGIC.
pub(crate) struct VmGic {
    /// The vGIC's KVM device (a duplicate of the GIC device's fd).
    fd: DeviceFd,
    /// 2 or 3.
    pub(crate) version: u32,
    /// Its vCPUs' MPIDR_EL1s, by vCPU index.
    mpidrs: Vec<u64>,
}

impl VmGic {
    /// The vGIC behind `intc`, for a VM whose vCPUs have these MPIDR_EL1s.
    pub(crate) fn of(intc: &IrqChip, mpidrs: Vec<u64>) -> Result<Self, String> {
        let chip = intc.lock().expect("poisoned irqchip lock");
        let version = match chip.version() {
            t if t == kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2 => 2,
            t if t == kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3 => 3,
            other => return Err(format!("unknown GIC type {other}")),
        };
        let device = chip
            .kvm_device_fd()
            .ok_or("the GIC isn't KVM's in-kernel vGIC")?;
        // SAFETY: duplicates an open fd; the new one is owned by the DeviceFd.
        let fd = unsafe { libc::dup(device.as_raw_fd()) };
        if fd < 0 {
            return Err(format!(
                "duplicate the vGIC's fd: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(VmGic {
            // SAFETY: `fd` is a fresh, open fd nothing else owns.
            fd: unsafe { DeviceFd::from_raw_fd(fd) },
            version,
            mpidrs,
        })
    }

    fn get(&self, group: u32, attr: u64) -> Result<u64, String> {
        // KVM writes 4 bytes (8 for the CPU system registers) at `addr`: the
        // low half of `value`, little-endian.
        let mut value = 0u64;
        let mut a = kvm_device_attr {
            group,
            attr,
            addr: &mut value as *mut u64 as u64,
            flags: 0,
        };
        // SAFETY: `addr` points at `value`, 8 bytes that outlive the call.
        unsafe { self.fd.get_device_attr(&mut a) }
            .map_err(|e| format!("read {}: {e}", self.describe(group, attr)))?;
        Ok(value)
    }

    fn set(&self, group: u32, attr: u64, value: u64) -> Result<(), String> {
        let a = kvm_device_attr {
            group,
            attr,
            addr: &value as *const u64 as u64,
            flags: 0,
        };
        self.fd
            .set_device_attr(&a)
            .map_err(|e| format!("write {}: {e}", self.describe(group, attr)))
    }

    fn typer(&self) -> Result<u32, String> {
        Ok(self.get(DIST, GICD_TYPER)? as u32)
    }

    /// The vGIC's state; the vCPUs must be out of KVM_RUN.
    pub(crate) fn save(&self) -> Result<GicState, String> {
        let typer = self.typer()?;
        let mut save = Save {
            gic: self,
            regs: Vec::new(),
        };
        match self.version {
            2 => save.v2(irq_count(typer))?,
            _ => save.v3(irq_count(typer))?,
        }
        Ok(GicState {
            version: self.version,
            typer,
            mpidrs: self.mpidrs.clone(),
            regs: save.regs,
        })
    }

    /// Brings this vGIC, a fresh one whose vCPUs haven't run, to `state`.
    pub(crate) fn restore(&self, state: &GicState) -> Result<(), String> {
        if state.version != self.version {
            return Err(format!(
                "interrupt controller differs: the checkpoint's guest has a GICv{}; this VM's is a GICv{}",
                state.version, self.version
            ));
        }
        if state.mpidrs != self.mpidrs {
            return Err(format!(
                "vCPUs differ: the checkpoint's GIC serves MPIDRs {:x?}; this VM's {:x?}",
                state.mpidrs, self.mpidrs
            ));
        }
        let (saved, here) = (irq_count(state.typer), irq_count(self.typer()?));
        if saved != here {
            return Err(format!(
                "interrupt controller differs: the checkpoint's GIC has {saved} interrupts; this VM's has {here}"
            ));
        }
        state
            .regs
            .iter()
            .try_for_each(|r| self.set(r.group, r.attr, r.value))
    }

    fn describe(&self, group: u32, attr: u64) -> String {
        let (vcpu, reg) = (attr >> 32, attr & 0xffff_ffff);
        match group {
            DIST if self.version == 2 => format!("GICD+{reg:#x} of vCPU {vcpu}"),
            DIST => format!("GICD+{reg:#x}"),
            CPU => format!("GICC+{reg:#x} of vCPU {vcpu}"),
            REDIST => format!("GICR+{reg:#x} of affinity {vcpu:#x}"),
            SYSREGS => format!("ICC register {reg:#x} of affinity {vcpu:#x}"),
            LEVELS => format!("line levels from INTID {} of affinity {vcpu:#x}", reg & 0x3ff),
            _ => format!("vGIC attribute {group}/{attr:#x}"),
        }
    }
}

/// The writes of a save, built as the registers are read.
struct Save<'a> {
    gic: &'a VmGic,
    regs: Vec<GicReg>,
}

impl Save<'_> {
    /// Reads a register and records writing it back.
    fn read(&mut self, group: u32, attr: u64) -> Result<u64, String> {
        let value = self.gic.get(group, attr)?;
        self.regs.push(GicReg {
            group,
            pad: 0,
            attr,
            value,
        });
        Ok(value)
    }

    /// Records clearing every bit of a write-1-to-clear register.
    fn clear(&mut self, group: u32, attr: u64) {
        self.regs.push(GicReg {
            group,
            pad: 0,
            attr,
            value: u64::from(u32::MAX),
        });
    }

    /// GICv2: a distributor whose registers for the 32 private interrupts
    /// (SGIs, PPIs) are banked per vCPU, and a memory-mapped CPU interface
    /// per vCPU. Attributes address a vCPU by its index.
    fn v2(&mut self, irqs: u64) -> Result<(), String> {
        let cpus = self.gic.mpidrs.len() as u64;
        let at = |cpu: u64, reg: u64| cpu << KVM_DEV_ARM_VGIC_CPUID_SHIFT | reg;
        self.read(DIST, at(0, GICD_IIDR))?;
        self.read(DIST, at(0, GICD_CTLR))?;
        // Registers with `bits` per interrupt: the first `bits` words cover
        // the private interrupts.
        let mut per_irq = |set: u64, clear: Option<u64>, bits: u64| -> Result<(), String> {
            for word in 0..irqs * bits / 32 {
                let banked = if word < bits { cpus } else { 1 };
                for cpu in 0..banked {
                    if let Some(clear) = clear {
                        self.clear(DIST, at(cpu, clear + 4 * word));
                    }
                    self.read(DIST, at(cpu, set + 4 * word))?;
                }
            }
            Ok(())
        };
        per_irq(GICD_ISENABLER, Some(GICD_ICENABLER), 1)?;
        per_irq(GICD_IGROUPR, None, 1)?;
        per_irq(GICD_ITARGETSR, None, 8)?;
        per_irq(GICD_ICFGR, None, 2)?;
        per_irq(GICD_ISPENDR, Some(GICD_ICPENDR), 1)?;
        per_irq(GICD_ISACTIVER, Some(GICD_ICACTIVER), 1)?;
        per_irq(GICD_IPRIORITYR, None, 8)?;
        // Which CPUs each SGI is pending from, 8 bits per SGI.
        for cpu in 0..cpus {
            for word in 0..4 {
                self.clear(DIST, at(cpu, GICD_CPENDSGIR + 4 * word));
                self.read(DIST, at(cpu, GICD_SPENDSGIR + 4 * word))?;
            }
        }
        for cpu in 0..cpus {
            for reg in [
                GICC_CTLR,
                GICC_PMR,
                GICC_BPR,
                GICC_ABPR,
                GICC_APR,
                GICC_APR + 4,
                GICC_APR + 8,
                GICC_APR + 12,
            ] {
                self.read(CPU, at(cpu, reg))?;
            }
        }
        Ok(())
    }

    /// GICv3: the private interrupts live in each vCPU's redistributor and
    /// the distributor holds only the shared ones (SPIs); the CPU interface
    /// is system registers. Attributes address a vCPU by its affinity.
    fn v3(&mut self, irqs: u64) -> Result<(), String> {
        let mpidrs = self.gic.mpidrs.clone();
        self.read(DIST, GICD_IIDR)?;
        self.read(DIST, GICD_CTLR)?;
        for &mpidr in &mpidrs {
            let at = |reg: u64| affinity(mpidr) | reg;
            if self.gic.get(REDIST, at(GICR_TYPER))? & GICR_TYPER_PLPIS != 0 {
                return Err(
                    "the GIC has LPIs (an ITS), whose state a checkpoint doesn't hold".into(),
                );
            }
            for reg in [GICR_CTLR, GICR_STATUSR, GICR_WAKER, GICR_IGROUPR0] {
                self.read(REDIST, at(reg))?;
            }
            self.clear(REDIST, at(GICR_ICENABLER0));
            self.read(REDIST, at(GICR_ISENABLER0))?;
            self.read(REDIST, at(GICR_ICFGR0))?;
            self.read(REDIST, at(GICR_ICFGR0 + 4))?;
            self.read(LEVELS, at(line_level(0)))?;
            // Reads and writes from userspace go to the pending latch itself;
            // its clear twin ignores them.
            self.read(REDIST, at(GICR_ISPENDR0))?;
            self.clear(REDIST, at(GICR_ICACTIVER0));
            self.read(REDIST, at(GICR_ISACTIVER0))?;
            for word in 0..8 {
                self.read(REDIST, at(GICR_IPRIORITYR0 + 4 * word))?;
            }
        }
        self.read(DIST, GICD_STATUSR)?;
        // The distributor's words past the private interrupts, for registers
        // with `bits` per interrupt.
        let spis = |bits: u64| bits..irqs * bits / 32;
        for word in spis(1) {
            self.clear(DIST, GICD_ICENABLER + 4 * word);
            self.read(DIST, GICD_ISENABLER + 4 * word)?;
        }
        for word in spis(1) {
            self.read(DIST, GICD_IGROUPR + 4 * word)?;
        }
        for irq in 32..irqs {
            self.read(DIST, GICD_IROUTER + 8 * irq)?;
            self.read(DIST, GICD_IROUTER + 8 * irq + 4)?;
        }
        for word in spis(2) {
            self.read(DIST, GICD_ICFGR + 4 * word)?;
        }
        for intid in (32..irqs).step_by(32) {
            self.read(LEVELS, line_level(intid))?;
        }
        for word in spis(1) {
            self.read(DIST, GICD_ISPENDR + 4 * word)?;
        }
        for word in spis(1) {
            self.clear(DIST, GICD_ICACTIVER + 4 * word);
            self.read(DIST, GICD_ISACTIVER + 4 * word)?;
        }
        for word in spis(8) {
            self.read(DIST, GICD_IPRIORITYR + 4 * word)?;
        }
        for &mpidr in &mpidrs {
            let at = |reg: u64| affinity(mpidr) | reg;
            for reg in [ICC_SRE_EL1, ICC_CTLR_EL1] {
                self.read(SYSREGS, at(reg))?;
            }
            let ctlr = self.regs.last().map_or(0, |r| r.value);
            for reg in [ICC_IGRPEN0_EL1, ICC_IGRPEN1_EL1, ICC_PMR_EL1, ICC_BPR0_EL1, ICC_BPR1_EL1] {
                self.read(SYSREGS, at(reg))?;
            }
            // The active-priority registers exist for the priority bits the
            // CPU interface implements (ICC_CTLR_EL1.PRIbits).
            let aprs = match (ctlr >> 8 & 7) + 1 {
                7 => 4,
                6 => 2,
                _ => 1,
            };
            for n in 0..aprs {
                self.read(SYSREGS, at(icc_ap0r(n)))?;
            }
            for n in 0..aprs {
                self.read(SYSREGS, at(icc_ap1r(n)))?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vmm::linux::vstate::{Vcpu, Vm};
    use crate::vmm::vstate::KvmContext;
    use arch::ArchMemoryInfo;
    use devices::legacy::{IrqChipDevice, KvmGicV2, KvmGicV3};
    use std::sync::{Arc, Mutex};
    use utils::eventfd::EventFd;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    /// A VM with `vcpus` configured vCPUs and a vGIC of `version`, or None
    /// where this host's KVM can't give it one.
    fn vm_with_gic(version: u32, vcpus: u8) -> Option<(Vm, Vec<Vcpu>, IrqChip, VmGic)> {
        let kvm = KvmContext::new().unwrap();
        let mut vm = Vm::new(kvm.fd()).unwrap();
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0x8000_0000), 0x10_0000)]).unwrap();
        vm.memory_init(&mem, kvm.max_memslots()).unwrap();
        let type_ = match version {
            2 => kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V2,
            _ => kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
        };
        // On a throwaway VM: KVM_CREATE_DEVICE_TEST returns no fd, which
        // kvm-ioctls would wrap and close anyway.
        let mut probe = kvm_bindings::kvm_create_device {
            type_,
            fd: 0,
            flags: 0,
        };
        if kvm.fd().create_vm().unwrap().create_device(&mut probe).is_err() {
            eprintln!("this host's KVM has no GICv{version}; skipping");
            return None;
        }
        let vcpus: Vec<Vcpu> = (0..vcpus)
            .map(|id| {
                let mut vcpu = Vcpu::new_aarch64(
                    id,
                    vm.fd(),
                    EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap(),
                )
                .unwrap();
                vcpu.configure_aarch64(
                    vm.fd(),
                    &ArchMemoryInfo::default(),
                    GuestAddress(0x8000_0000),
                    None,
                )
                .unwrap();
                vcpu
            })
            .collect();
        let count = vcpus.len() as u64;
        let intc: IrqChip = Arc::new(Mutex::new(match version {
            2 => IrqChipDevice::new(Box::new(KvmGicV2::new(vm.fd(), count))),
            _ => IrqChipDevice::new(Box::new(KvmGicV3::new(vm.fd(), count).unwrap())),
        }));
        let gic = VmGic::of(&intc, vcpus.iter().map(Vcpu::get_mpidr).collect()).unwrap();
        Some((vm, vcpus, intc, gic))
    }

    fn round_trip(state: &GicState) -> GicState {
        let mut enc = Encoder::new();
        state.encode(&mut enc);
        let bytes = enc.into_bytes();
        let mut dec = Decoder::new(&bytes);
        let state = GicState::decode(&mut dec).unwrap();
        dec.finish().unwrap();
        state
    }

    /// A guest that disabled what KVM enables (`clears`, write-1-to-clear
    /// registers) and set `sets` (each bit of the value it set): a fresh vGIC
    /// restored from its state must read back register for register.
    fn assert_restored(version: u32, clears: &[(u32, u64, u64)], sets: &[(u32, u64, u64)]) {
        let Some((_vm, _vcpus, _intc, gic)) = vm_with_gic(version, 2) else {
            return;
        };
        // KVM only takes a GICv2's interrupt groups from userspace that wrote
        // GICD_IIDR back, as a restore does first.
        gic.set(DIST, GICD_IIDR, gic.get(DIST, GICD_IIDR).unwrap())
            .unwrap();
        for &(group, attr, value) in clears.iter().chain(sets) {
            gic.set(group, attr, value).unwrap();
        }
        let state = round_trip(&gic.save().unwrap());
        // Not vacuous: what the guest set is in the state.
        for &(group, attr, value) in sets {
            let saved = state
                .regs
                .iter()
                .rfind(|r| (r.group, r.attr) == (group, attr))
                .unwrap_or_else(|| panic!("{} not saved", gic.describe(group, attr)))
                .value;
            assert_eq!(saved & value, value, "{}", gic.describe(group, attr));
        }

        let (_vm2, _vcpus2, _intc2, fresh) = vm_with_gic(version, 2).unwrap();
        fresh.restore(&state).unwrap();
        assert_eq!(fresh.save().unwrap(), state);
    }

    #[test]
    fn a_gicv2_comes_back_as_the_guest_left_it() {
        let cpu1 = 1u64 << KVM_DEV_ARM_VGIC_CPUID_SHIFT;
        assert_restored(
            2,
            // SGI 0 disabled on vCPU 0.
            &[(DIST, GICD_ICENABLER, 1)],
            &[
                (DIST, GICD_CTLR, 1),
                // SPIs 32 and 34 enabled; 34 in group 1, routed to vCPU 1,
                // edge-triggered, pending and prioritised.
                (DIST, GICD_ISENABLER + 4, 0b101),
                (DIST, GICD_IGROUPR + 4, 0b100),
                (DIST, GICD_ITARGETSR + 32, 0x0102_0101),
                (DIST, GICD_ICFGR + 8, 0b10 << 4),
                (DIST, GICD_ISPENDR + 4, 0b100),
                (DIST, GICD_IPRIORITYR + 32, 0xa0 << 16),
                // The virtual timer's PPI, enabled and prioritised on vCPU 1
                // only (banked).
                (DIST, cpu1 | GICD_ISENABLER, 1 << 27),
                (DIST, cpu1 | (GICD_IPRIORITYR + 24), 0x80 << 24),
                // SGI 1 pending on vCPU 0, sent by vCPU 1.
                (DIST, GICD_SPENDSGIR, 0b10 << 8),
                // vCPU 1's CPU interface: enabled, priority mask, binary point.
                (CPU, cpu1 | GICC_CTLR, 1),
                (CPU, cpu1 | GICC_PMR, 0x1e),
                (CPU, cpu1 | GICC_BPR, 3),
            ],
        );
    }

    #[test]
    fn a_gicv3_comes_back_as_the_guest_left_it() {
        let Some((_vm, vcpus, _intc, _gic)) = vm_with_gic(3, 2) else {
            return;
        };
        let (rd0, rd1) = (affinity(vcpus[0].get_mpidr()), affinity(vcpus[1].get_mpidr()));
        assert_restored(
            3,
            // SGI 0 disabled on vCPU 0.
            &[(REDIST, rd0 | GICR_ICENABLER0, 1)],
            &[
                // Group 1 enabled.
                (DIST, GICD_CTLR, 0x2),
                (DIST, GICD_ISENABLER + 4, 0b101),
                (DIST, GICD_IGROUPR + 4, 0b100),
                (DIST, GICD_IROUTER + 8 * 34, 0x1),
                (DIST, GICD_ICFGR + 8, 0b10 << 4),
                (DIST, GICD_ISPENDR + 4, 0b100),
                (DIST, GICD_IPRIORITYR + 32, 0xa0 << 16),
                // vCPU 1's redistributor: the virtual timer's PPI enabled and
                // prioritised, the physical one's pending.
                (REDIST, rd1 | GICR_ISENABLER0, 1 << 27),
                (REDIST, rd1 | (GICR_IPRIORITYR0 + 24), 0x80 << 24),
                (REDIST, rd1 | GICR_ISPENDR0, 1 << 30),
                // vCPU 1's CPU interface.
                (SYSREGS, rd1 | ICC_PMR_EL1, 0xf0),
                (SYSREGS, rd1 | ICC_BPR1_EL1, 3),
                (SYSREGS, rd1 | ICC_IGRPEN1_EL1, 1),
            ],
        );
    }

    #[test]
    fn a_vgic_for_other_vcpus_is_refused() {
        for version in [2, 3] {
            let Some((_vm, _vcpus, _intc, gic)) = vm_with_gic(version, 2) else {
                continue;
            };
            let state = gic.save().unwrap();
            let (_vm2, _vcpus2, _intc2, three) = vm_with_gic(version, 3).unwrap();
            let err = three.restore(&state).unwrap_err();
            assert!(err.starts_with("vCPUs differ"), "{err}");

            let mut other = state.clone();
            other.version = 5 - version;
            let (_vm3, _vcpus3, _intc3, two) = vm_with_gic(version, 2).unwrap();
            let err = two.restore(&other).unwrap_err();
            assert!(err.starts_with("interrupt controller differs"), "{err}");
            two.restore(&state).unwrap();
        }
    }

    #[test]
    fn affinities_follow_the_mpidr() {
        // Aff3 sits apart from Aff2..0 in MPIDR_EL1.
        assert_eq!(affinity(0x0000_0012_8001_0203), 0x1201_0203 << 32);
        assert_eq!(irq_count(3), 128);
    }
}
