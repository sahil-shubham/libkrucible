//! arm64: what a checkpoint's guest needs from the host that restores it.
//!
//! A checkpoint records the CPU the guest ran on (MIDR_EL1 and REVIDR_EL1, as
//! the guest read them), the page size, the generic timer's counter frequency,
//! the GIC version, the features its vCPUs were created with (pointer
//! authentication, SVE and its vector lengths), the AArch64 ID registers the
//! guest saw, and every vCPU register its state holds. A restore builds the
//! same record for this host and [`HostRecord::check`]s the two.
//!
//! It refuses another CPU, down to its variant and revision: the guest picked
//! its errata workarounds for the CPU it booted on, and KVM won't present one
//! CPU as another. It refuses another page size, another counter frequency
//! (the guest's clocks were calibrated against it and KVM can't scale it), or
//! another GIC version; a vCPU feature, an SVE vector length or an ID-register
//! feature the guest has and this host can't give it; and a register the
//! guest's state holds that this host's KVM doesn't have.

use kvm_bindings::{
    KVM_ARM_VCPU_EL1_32BIT, KVM_ARM_VCPU_HAS_EL2, KVM_ARM_VCPU_PMU_V3, KVM_ARM_VCPU_PSCI_0_2,
    KVM_ARM_VCPU_PTRAUTH_ADDRESS, KVM_ARM_VCPU_PTRAUTH_GENERIC, KVM_ARM_VCPU_SVE,
    KVM_REG_ARM_COPROC_MASK, KVM_REG_ARM_CORE, KVM_REG_ARM_DEMUX, KVM_REG_ARM_FW,
    KVM_REG_ARM_FW_FEAT_BMAP, KVM_REG_ARM64, KVM_REG_ARM64_SVE, KVM_REG_ARM64_SYSREG,
    KVM_REG_SIZE_U64,
};

use crate::vmm::checkpoint::codec::{Decoder, Encoder, Pod};

/// An ID register's value, as the guest read it or as a vCPU here reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct IdReg {
    /// The register's KVM id.
    pub id: u64,
    pub value: u64,
}

// SAFETY: two u64s, no padding.
unsafe impl Pod for IdReg {}

/// A host as far as running a checkpointed guest goes. In a checkpoint it
/// describes the host the guest ran on and what the guest was given; for a
/// restore, what this host would give it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HostRecord {
    /// MIDR_EL1: implementer, variant, part number and revision.
    pub midr: u64,
    /// REVIDR_EL1: the implementation's revision (errata) bits.
    pub revidr: u64,
    pub page_size: u32,
    /// CNTFRQ_EL0: the frequency of the generic timer's counter, in Hz.
    pub counter_hz: u32,
    /// The GIC architecture version: 2 or 3.
    pub gic_version: u32,
    /// `kvm_vcpu_init` features (bit n is feature n) the guest's vCPUs were
    /// created with (a checkpoint), or every one this host's KVM can give a
    /// vCPU (a restore). Never POWER_OFF: that only says how a vCPU boots.
    pub vcpu_features: u32,
    /// KVM_REG_ARM64_SVE_VLS, a bitmap of vector lengths in quadwords (bit n:
    /// n+1 quadwords): the guest's, or every one this host has. Empty without
    /// SVE.
    pub sve_vls: Vec<u64>,
    /// The AArch64 feature ID registers: the guest's, or this host's for a
    /// vCPU with every feature it can give one.
    pub id_regs: Vec<IdReg>,
    /// The vCPU registers (KVM ids) the guest's state holds, or that a vCPU
    /// here has.
    pub regs: Vec<u64>,
}

impl HostRecord {
    pub(crate) fn encode(&self, enc: &mut Encoder) {
        enc.u64(self.midr);
        enc.u64(self.revidr);
        enc.u32(self.page_size);
        enc.u32(self.counter_hz);
        enc.u32(self.gic_version);
        enc.u32(self.vcpu_features);
        enc.pods(&self.sve_vls);
        enc.pods(&self.id_regs);
        enc.pods(&self.regs);
    }

    pub(crate) fn decode(dec: &mut Decoder) -> Result<Self, String> {
        Ok(HostRecord {
            midr: dec.u64()?,
            revidr: dec.u64()?,
            page_size: dec.u32()?,
            counter_hz: dec.u32()?,
            gic_version: dec.u32()?,
            vcpu_features: dec.u32()?,
            sve_vls: dec.pods()?,
            id_regs: dec.pods()?,
            regs: dec.pods()?,
        })
    }

    /// Refuses `here` when it can't run the guest this record (a
    /// checkpoint's) describes.
    pub(crate) fn check(&self, here: &HostRecord) -> Result<(), String> {
        if self.page_size != here.page_size {
            return Err(format!(
                "page size differs: the checkpoint was taken with {}-byte pages; this host's are {} bytes",
                self.page_size, here.page_size
            ));
        }
        if (self.midr, self.revidr) != (here.midr, here.revidr) {
            return Err(format!(
                "CPU differs: the checkpoint was taken on {}; this host is {}",
                self.cpu(),
                here.cpu()
            ));
        }
        if self.counter_hz != here.counter_hz {
            return Err(format!(
                "timer frequency differs: the guest's counter runs at {} Hz and this host's at {} Hz",
                self.counter_hz, here.counter_hz
            ));
        }
        if self.gic_version != here.gic_version {
            return Err(format!(
                "interrupt controller differs: the checkpoint's guest has a GICv{}; this host's KVM gives a guest a GICv{}",
                self.gic_version, here.gic_version
            ));
        }
        let features = self.vcpu_features & !here.vcpu_features;
        if features != 0 {
            return Err(format!(
                "this host's KVM can't give the guest's vCPUs {}",
                feature_names(features)
            ));
        }
        if !self.sve_vls.is_empty() {
            self.check_sve(here)?;
        }
        let lacking = self.lacking_id_features(here);
        if !lacking.is_empty() {
            return Err(format!(
                "this host's CPU lacks features the guest uses: {} (the checkpoint was taken on {}; this host is {})",
                lacking.join(", "),
                self.cpu(),
                here.cpu()
            ));
        }
        let regs: Vec<String> = self
            .regs
            .iter()
            .filter(|id| !here.regs.contains(id))
            .map(|&id| reg_name(id))
            .collect();
        if !regs.is_empty() {
            return Err(format!(
                "this host's KVM can't restore registers the guest's state holds: {} (the checkpoint was taken on {}; this host is {})",
                regs.join(", "),
                self.cpu(),
                here.cpu()
            ));
        }
        Ok(())
    }

    /// KVM can only cap a vCPU's vector lengths, not leave some out: the
    /// guest's set must be exactly this host's, up to the guest's longest.
    fn check_sve(&self, here: &HostRecord) -> Result<(), String> {
        let has = |vls: &[u64], vq: usize| vls.get((vq - 1) / 64).is_some_and(|w| w >> ((vq - 1) % 64) & 1 != 0);
        let max = (1..=self.sve_vls.len() * 64)
            .rev()
            .find(|&vq| has(&self.sve_vls, vq))
            .unwrap_or(0);
        if (1..=max).all(|vq| has(&self.sve_vls, vq) == has(&here.sve_vls, vq)) {
            return Ok(());
        }
        let lengths = |vls: &[u64]| {
            let list: Vec<String> = (1..=vls.len() * 64)
                .filter(|&vq| has(vls, vq))
                .map(|vq| (vq * 128).to_string())
                .collect();
            match list.is_empty() {
                true => "none".to_string(),
                false => list.join(", "),
            }
        };
        Err(format!(
            "SVE vector lengths differ: the guest's vCPUs have {} bits; this host's have {} bits",
            lengths(&self.sve_vls),
            lengths(&here.sve_vls)
        ))
    }

    /// The ID-register fields where this host offers less than the guest saw.
    fn lacking_id_features(&self, here: &HostRecord) -> Vec<String> {
        let mut lacking = Vec::new();
        for saved in &self.id_regs {
            let Some(layout) = id_reg_layout(saved.id) else {
                continue;
            };
            // A register this host lacks altogether is reported as such.
            let Some(offered) = here.id_regs.iter().find(|r| r.id == saved.id) else {
                continue;
            };
            for field in (0..16).filter(|f| layout.ignored & (1 << f) == 0) {
                let signed = layout.signed & (1 << field) != 0;
                let (guest, host) = (
                    id_field(saved.value, field, signed),
                    id_field(offered.value, field, signed),
                );
                if host < guest {
                    let name = match layout.fields[field] {
                        "" => format!("{}[{}:{}]", layout.name, field * 4 + 3, field * 4),
                        f => format!("{}.{f}", layout.name),
                    };
                    lacking.push(format!("{name} (the guest has {guest}, this host {host})"));
                }
            }
        }
        lacking
    }

    fn cpu(&self) -> String {
        format!(
            "{} (MIDR_EL1 {:#x}, REVIDR_EL1 {:#x})",
            cpu_name(self.midr),
            self.midr,
            self.revidr
        )
    }
}

/// This host's page size.
pub(crate) fn page_size() -> u32 {
    // SAFETY: sysconf has no preconditions.
    u32::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap_or(0)
}

/// The KVM id of the system register (op0, op1, CRn, CRm, op2).
pub(crate) const fn sysreg(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) -> u64 {
    KVM_REG_ARM64
        | KVM_REG_SIZE_U64
        | KVM_REG_ARM64_SYSREG as u64
        | op0 << 14
        | op1 << 11
        | crn << 7
        | crm << 3
        | op2
}

pub(crate) const MIDR_EL1: u64 = sysreg(3, 0, 0, 0, 0);
pub(crate) const REVIDR_EL1: u64 = sysreg(3, 0, 0, 0, 6);

/// (op0, op1, CRn, CRm, op2) of a system register's KVM id.
fn sysreg_fields(id: u64) -> Option<[u64; 5]> {
    if id & u64::from(KVM_REG_ARM_COPROC_MASK) != u64::from(KVM_REG_ARM64_SYSREG) {
        return None;
    }
    Some([
        id >> 14 & 3,
        id >> 11 & 7,
        id >> 7 & 0xf,
        id >> 3 & 0xf,
        id & 7,
    ])
}

/// Whether `id` is an AArch64 feature ID register (ID_AA64*_EL1): the ones a
/// host record compares.
pub(crate) fn is_feature_id_reg(id: u64) -> bool {
    matches!(sysreg_fields(id), Some([3, 0, 0, 4..=7, _])) && id_reg_layout(id).is_some()
}

struct IdRegLayout {
    name: String,
    /// Field names, from bits [3:0] up; "" for unnamed ones.
    fields: [&'static str; 16],
    /// Fields whose all-ones value means "not implemented" (lower than 0).
    signed: u16,
    /// Fields that aren't ordered by capability.
    ignored: u16,
}

/// How to compare an AArch64 ID register, by its (CRm, op2). The auxiliary
/// feature registers (AFR) are implementation defined: never compared.
fn id_reg_layout(id: u64) -> Option<IdRegLayout> {
    let [3, 0, 0, crm @ 4..=7, op2] = sysreg_fields(id)? else {
        return None;
    };
    let layout = |name: &str, fields, signed, ignored| IdRegLayout {
        name: name.to_string(),
        fields,
        signed,
        ignored,
    };
    Some(match (crm, op2) {
        (4, 0) => layout(
            "ID_AA64PFR0_EL1",
            [
                "EL0", "EL1", "EL2", "EL3", "FP", "AdvSIMD", "GIC", "RAS", "SVE", "SEL2", "MPAM",
                "AMU", "DIT", "RME", "CSV2", "CSV3",
            ],
            1 << 4 | 1 << 5,
            0,
        ),
        (4, 1) => layout(
            "ID_AA64PFR1_EL1",
            [
                "BT", "SSBS", "MTE", "RAS_frac", "MPAM_frac", "", "SME", "RNDR_trap", "CSV2_frac",
                "NMI", "MTE_frac", "GCS", "THE", "MTEX", "DF2", "PFAR",
            ],
            0,
            0,
        ),
        (4, 4) => layout(
            "ID_AA64ZFR0_EL1",
            [
                "SVEver", "AES", "", "", "BitPerm", "BF16", "B16B16", "", "SHA3", "", "SM4",
                "I8MM", "", "F32MM", "F64MM", "",
            ],
            0,
            0,
        ),
        (5, 0) => layout(
            "ID_AA64DFR0_EL1",
            [
                "DebugVer",
                "TraceVer",
                "PMUVer",
                "BRPs",
                "PMSS",
                "WRPs",
                "SEBEP",
                "CTX_CMPs",
                "PMSVer",
                "DoubleLock",
                "TraceFilt",
                "TraceBuffer",
                "MTPMU",
                "BRBE",
                "ExtTrcBuff",
                "HPMN0",
            ],
            1 << 2 | 1 << 9 | 1 << 12,
            0,
        ),
        (5, 4 | 5) => return None,
        (6, 0) => layout(
            "ID_AA64ISAR0_EL1",
            [
                "", "AES", "SHA1", "SHA2", "CRC32", "Atomic", "TME", "RDM", "SHA3", "SM3", "SM4",
                "DP", "FHM", "TS", "TLB", "RNDR",
            ],
            0,
            0,
        ),
        (6, 1) => layout(
            "ID_AA64ISAR1_EL1",
            [
                "DPB", "APA", "API", "JSCVT", "FCMA", "LRCPC", "GPA", "GPI", "FRINTTS", "SB",
                "SPECRES", "BF16", "DGH", "I8MM", "XS", "LS64",
            ],
            0,
            0,
        ),
        (6, 2) => layout(
            "ID_AA64ISAR2_EL1",
            [
                "WFxT",
                "RPRES",
                "GPA3",
                "APA3",
                "MOPS",
                "BC",
                "PAC_frac",
                "CLRBHB",
                "SYSREG_128",
                "SYSINSTR_128",
                "PRFMSLC",
                "",
                "RPRFM",
                "CSSC",
                "LUT",
                "ATS1A",
            ],
            0,
            0,
        ),
        // TGran{16,64,4}_2 describe stage 2 translation, with "as stage 1"
        // as their lowest value.
        (7, 0) => layout(
            "ID_AA64MMFR0_EL1",
            [
                "PARange",
                "ASIDBits",
                "BigEnd",
                "SNSMem",
                "BigEndEL0",
                "TGran16",
                "TGran64",
                "TGran4",
                "TGran16_2",
                "TGran64_2",
                "TGran4_2",
                "ExS",
                "",
                "",
                "FGT",
                "ECV",
            ],
            1 << 6 | 1 << 7,
            1 << 8 | 1 << 9 | 1 << 10,
        ),
        (7, 1) => layout(
            "ID_AA64MMFR1_EL1",
            [
                "HAFDBS", "VMIDBits", "VH", "HPDS", "LO", "PAN", "SpecSEI", "XNX", "TWED", "ETS",
                "HCX", "AFP", "nTLBPA", "TIDCP1", "CMOW", "ECBHB",
            ],
            0,
            0,
        ),
        (7, 2) => layout(
            "ID_AA64MMFR2_EL1",
            [
                "CnP", "UAO", "LSM", "IESB", "VARange", "CCIDX", "NV", "ST", "AT", "IDS", "FWB", "",
                "TTL", "BBM", "EVT", "E0PD",
            ],
            0,
            0,
        ),
        _ => IdRegLayout {
            name: format!("S3_0_C0_C{crm}_{op2}"),
            fields: [""; 16],
            signed: 0,
            ignored: 0,
        },
    })
}

/// An ID register field's value, signed fields sign-extended (all ones: not
/// implemented).
fn id_field(value: u64, field: usize, signed: bool) -> i8 {
    let v = (value >> (field * 4) & 0xf) as i8;
    if signed && v >= 8 { v - 16 } else { v }
}

/// "Arm Cortex-A76 r4p1" for a MIDR_EL1 value.
fn cpu_name(midr: u64) -> String {
    let implementer = midr >> 24 & 0xff;
    let (variant, part, revision) = (midr >> 20 & 0xf, midr >> 4 & 0xfff, midr & 0xf);
    let vendor = match implementer {
        0x41 => "Arm".to_string(),
        0x42 => "Broadcom".to_string(),
        0x43 => "Cavium".to_string(),
        0x46 => "Fujitsu".to_string(),
        0x48 => "HiSilicon".to_string(),
        0x4e => "NVIDIA".to_string(),
        0x50 => "Applied Micro".to_string(),
        0x51 => "Qualcomm".to_string(),
        0x61 => "Apple".to_string(),
        0x6d => "Microsoft".to_string(),
        0xc0 => "Ampere".to_string(),
        n => format!("implementer {n:#x}"),
    };
    let core = match (implementer, part) {
        (0x41, 0xd03) => "Cortex-A53".to_string(),
        (0x41, 0xd05) => "Cortex-A55".to_string(),
        (0x41, 0xd07) => "Cortex-A57".to_string(),
        (0x41, 0xd08) => "Cortex-A72".to_string(),
        (0x41, 0xd09) => "Cortex-A73".to_string(),
        (0x41, 0xd0a) => "Cortex-A75".to_string(),
        (0x41, 0xd0b) => "Cortex-A76".to_string(),
        (0x41, 0xd0c) => "Neoverse-N1".to_string(),
        (0x41, 0xd0d) => "Cortex-A77".to_string(),
        (0x41, 0xd40) => "Neoverse-V1".to_string(),
        (0x41, 0xd41) => "Cortex-A78".to_string(),
        (0x41, 0xd44) => "Cortex-X1".to_string(),
        (0x41, 0xd46) => "Cortex-A510".to_string(),
        (0x41, 0xd47) => "Cortex-A710".to_string(),
        (0x41, 0xd48) => "Cortex-X2".to_string(),
        (0x41, 0xd49) => "Neoverse-N2".to_string(),
        (0x41, 0xd4f) => "Neoverse-V2".to_string(),
        (0x41, 0xd80) => "Cortex-A520".to_string(),
        (0x41, 0xd81) => "Cortex-A720".to_string(),
        (0x41, 0xd84) => "Neoverse-V3".to_string(),
        (0x41, 0xd8e) => "Neoverse-N3".to_string(),
        (0xc0, 0xac3) => "Ampere-1".to_string(),
        _ => format!("part {part:#x}"),
    };
    format!("{vendor} {core} r{variant}p{revision}")
}

fn feature_names(features: u32) -> String {
    (0u32..32)
        .filter(|bit| features & (1 << bit) != 0)
        .map(|bit| match bit {
            KVM_ARM_VCPU_EL1_32BIT => "a 32-bit EL1".to_string(),
            KVM_ARM_VCPU_PSCI_0_2 => "PSCI 0.2".to_string(),
            KVM_ARM_VCPU_PMU_V3 => "a PMUv3".to_string(),
            KVM_ARM_VCPU_SVE => "SVE".to_string(),
            KVM_ARM_VCPU_PTRAUTH_ADDRESS => "address pointer authentication".to_string(),
            KVM_ARM_VCPU_PTRAUTH_GENERIC => "generic pointer authentication".to_string(),
            KVM_ARM_VCPU_HAS_EL2 => "EL2".to_string(),
            n => format!("vCPU feature {n}"),
        })
        .collect::<Vec<_>>()
        .join(" and ")
}

/// A register's name for messages: an architectural name where there's an
/// obvious one, else where KVM files it.
pub(crate) fn reg_name(id: u64) -> String {
    const NAMED: &[(u64, &str)] = &[
        (MIDR_EL1, "MIDR_EL1"),
        (REVIDR_EL1, "REVIDR_EL1"),
        (sysreg(3, 0, 0, 0, 5), "MPIDR_EL1"),
        // KVM's timer ids; CNT and CVAL of the virtual timer are swapped in
        // KVM's ABI.
        (sysreg(3, 3, 14, 3, 1), "CNTV_CTL_EL0"),
        (sysreg(3, 3, 14, 3, 2), "CNTVCT_EL0"),
        (sysreg(3, 3, 14, 0, 2), "CNTV_CVAL_EL0"),
        (sysreg(3, 3, 14, 2, 1), "CNTP_CTL_EL0"),
        (sysreg(3, 3, 14, 0, 1), "CNTPCT_EL0"),
        (sysreg(3, 3, 14, 2, 2), "CNTP_CVAL_EL0"),
    ];
    if let Some((_, name)) = NAMED.iter().find(|(named, _)| *named == id) {
        return name.to_string();
    }
    if let Some(layout) = id_reg_layout(id) {
        return layout.name;
    }
    if let Some([op0, op1, crn, crm, op2]) = sysreg_fields(id) {
        return format!("S{op0}_{op1}_C{crn}_C{crm}_{op2}");
    }
    let index = id & 0xffff;
    match (id & u64::from(KVM_REG_ARM_COPROC_MASK)) as u32 {
        KVM_REG_ARM_CORE => match index {
            0..=61 if index % 2 == 0 => format!("x{}", index / 2),
            62 => "sp".to_string(),
            64 => "pc".to_string(),
            66 => "pstate".to_string(),
            _ => format!("core register {index:#x}"),
        },
        KVM_REG_ARM_FW => format!("firmware register {index}"),
        KVM_REG_ARM_FW_FEAT_BMAP => format!("firmware feature bitmap {index}"),
        KVM_REG_ARM64_SVE => format!("SVE register {index:#x}"),
        KVM_REG_ARM_DEMUX => format!("CCSIDR {}", index & 0xff),
        _ => format!("register {id:#x}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID_AA64PFR0_EL1: u64 = sysreg(3, 0, 0, 4, 0);
    const ID_AA64ISAR0_EL1: u64 = sysreg(3, 0, 0, 6, 0);
    const ID_AA64MMFR0_EL1: u64 = sysreg(3, 0, 0, 7, 0);
    const TPIDR_EL1: u64 = sysreg(3, 0, 13, 0, 4);
    const X0: u64 = KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE as u64;

    /// A Raspberry Pi 5 (Cortex-A76 r4p1) as a checkpoint records it.
    fn saved() -> HostRecord {
        HostRecord {
            midr: 0x414f_d0b1,
            revidr: 0,
            page_size: 4096,
            counter_hz: 54_000_000,
            gic_version: 2,
            vcpu_features: 1 << KVM_ARM_VCPU_PSCI_0_2,
            sve_vls: vec![],
            id_regs: vec![
                IdReg {
                    id: ID_AA64PFR0_EL1,
                    value: 0x1100_0000_1011_1112,
                },
                IdReg {
                    id: ID_AA64ISAR0_EL1,
                    value: 0x0000_1000_1021_0000, // DP, RDM, Atomic (LSE), CRC32
                },
                IdReg {
                    id: ID_AA64MMFR0_EL1,
                    value: 0x0000_0000_0010_1122,
                },
            ],
            regs: vec![X0, MIDR_EL1, TPIDR_EL1, ID_AA64ISAR0_EL1],
        }
    }

    fn set_field(r: &mut HostRecord, id: u64, field: usize, value: u64) {
        let reg = r.id_regs.iter_mut().find(|r| r.id == id).unwrap();
        reg.value = reg.value & !(0xf << (field * 4)) | value << (field * 4);
    }

    #[test]
    fn an_identical_host_runs_the_guest() {
        saved().check(&saved()).unwrap();
    }

    #[test]
    fn a_host_offering_more_runs_the_guest() {
        let mut here = saved();
        here.vcpu_features |= 1 << KVM_ARM_VCPU_PTRAUTH_ADDRESS | 1 << KVM_ARM_VCPU_SVE;
        here.sve_vls = vec![0b1011];
        set_field(&mut here, ID_AA64ISAR0_EL1, 1, 2); // AES with PMULL
        here.regs.push(sysreg(3, 0, 2, 1, 0)); // APIAKEYLO_EL1
        saved().check(&here).unwrap();
    }

    #[test]
    fn another_cpu_is_refused_down_to_its_revision() {
        let mut here = saved();
        here.midr = 0x413f_d0c1; // Neoverse-N1 r3p1
        let err = saved().check(&here).unwrap_err();
        assert!(
            err.starts_with(
                "CPU differs: the checkpoint was taken on Arm Cortex-A76 r4p1 (MIDR_EL1 0x414fd0b1, REVIDR_EL1 0x0); this host is Arm Neoverse-N1 r3p1"
            ),
            "{err}"
        );
        let mut here = saved();
        here.midr = 0x414f_d0b0; // r4p0
        assert!(saved().check(&here).unwrap_err().contains("CPU differs"));
        let mut here = saved();
        here.revidr = 1;
        assert!(saved().check(&here).unwrap_err().contains("REVIDR_EL1 0x1"));
    }

    #[test]
    fn another_page_size_counter_rate_or_gic_is_refused() {
        let cases: [(fn(&mut HostRecord), &str); 3] = [
            (|h| h.page_size = 16384, "page size differs"),
            (
                |h| h.counter_hz = 1_000_000_000,
                "the guest's counter runs at 54000000 Hz and this host's at 1000000000 Hz",
            ),
            (|h| h.gic_version = 3, "the checkpoint's guest has a GICv2; this host's KVM gives a guest a GICv3"),
        ];
        for (change, want) in cases {
            let mut here = saved();
            change(&mut here);
            let err = saved().check(&here).unwrap_err();
            assert!(err.contains(want), "want {want:?}, got {err:?}");
        }
    }

    #[test]
    fn vcpu_features_the_host_lacks_are_named() {
        let mut guest = saved();
        guest.vcpu_features |= 1 << KVM_ARM_VCPU_PTRAUTH_ADDRESS | 1 << KVM_ARM_VCPU_PTRAUTH_GENERIC;
        let err = guest.check(&saved()).unwrap_err();
        assert_eq!(
            err,
            "this host's KVM can't give the guest's vCPUs address pointer authentication and generic pointer authentication"
        );
    }

    #[test]
    fn sve_vector_lengths_must_match_up_to_the_guests_longest() {
        let mut guest = saved();
        guest.vcpu_features |= 1 << KVM_ARM_VCPU_SVE;
        guest.sve_vls = vec![0b11]; // 128 and 256 bits
        let mut here = guest.clone();
        here.sve_vls = vec![0b1011]; // and 512 besides
        guest.check(&here).unwrap();

        here.sve_vls = vec![0b01]; // no 256
        let err = guest.check(&here).unwrap_err();
        assert_eq!(
            err,
            "SVE vector lengths differ: the guest's vCPUs have 128, 256 bits; this host's have 128 bits"
        );

        // A length the guest skipped below its longest can't be hidden.
        guest.sve_vls = vec![0b1001];
        here.sve_vls = vec![0b1011];
        assert!(guest.check(&here).unwrap_err().contains("SVE vector lengths differ"));
    }

    #[test]
    fn missing_id_register_features_are_named() {
        let mut here = saved();
        set_field(&mut here, ID_AA64ISAR0_EL1, 5, 0); // no LSE atomics
        set_field(&mut here, ID_AA64PFR0_EL1, 4, 0xf); // no FP (signed: -1)
        let err = saved().check(&here).unwrap_err();
        assert!(
            err.starts_with(
                "this host's CPU lacks features the guest uses: ID_AA64PFR0_EL1.FP (the guest has 1, this host -1), ID_AA64ISAR0_EL1.Atomic (the guest has 2, this host 0) ("
            ),
            "{err}"
        );
    }

    #[test]
    fn signed_and_unordered_id_fields_compare_as_they_mean() {
        // The guest saw no FP (all ones); a host with FP offers more.
        let mut guest = saved();
        set_field(&mut guest, ID_AA64PFR0_EL1, 4, 0xf);
        guest.check(&saved()).unwrap();
        // TGran4_2 isn't ordered: 0 ("as stage 1") is fine against 2.
        let mut guest = saved();
        set_field(&mut guest, ID_AA64MMFR0_EL1, 10, 2);
        guest.check(&saved()).unwrap();
        // An unnamed field of a known register still counts.
        let mut here = saved();
        set_field(&mut here, ID_AA64ISAR0_EL1, 0, 0);
        let mut guest = saved();
        set_field(&mut guest, ID_AA64ISAR0_EL1, 0, 1);
        assert!(
            guest
                .check(&here)
                .unwrap_err()
                .contains("ID_AA64ISAR0_EL1[3:0] (the guest has 1, this host 0)")
        );
    }

    #[test]
    fn registers_the_host_lacks_are_named() {
        let mut here = saved();
        here.regs.retain(|&r| r != TPIDR_EL1 && r != X0);
        let err = saved().check(&here).unwrap_err();
        assert!(
            err.starts_with(
                "this host's KVM can't restore registers the guest's state holds: x0, S3_0_C13_C0_4 ("
            ),
            "{err}"
        );
    }

    #[test]
    fn a_record_round_trips_and_truncations_are_refused() {
        let mut record = saved();
        record.sve_vls = vec![0b11, 0, 0, 0, 0, 0, 0, 0];
        let mut enc = Encoder::new();
        record.encode(&mut enc);
        let buf = enc.into_bytes();
        let mut dec = Decoder::new(&buf);
        assert_eq!(HostRecord::decode(&mut dec).unwrap(), record);
        dec.finish().unwrap();
        for len in 0..buf.len() {
            let err = HostRecord::decode(&mut Decoder::new(&buf[..len])).unwrap_err();
            assert!(err.contains("truncated"), "cut at {len}: {err}");
        }
    }

    #[test]
    fn registers_have_readable_names() {
        assert_eq!(reg_name(sysreg(3, 3, 14, 3, 2)), "CNTVCT_EL0");
        assert_eq!(reg_name(ID_AA64ISAR0_EL1), "ID_AA64ISAR0_EL1");
        assert_eq!(reg_name(sysreg(3, 0, 0, 4, 7)), "S3_0_C0_C4_7");
        assert_eq!(reg_name(X0 | 64), "pc");
        assert_eq!(cpu_name(0x410f_d083), "Arm Cortex-A72 r0p3");
        assert_eq!(cpu_name(0x611f_0221), "Apple part 0x22 r1p1");
        assert!(is_feature_id_reg(ID_AA64MMFR0_EL1));
        assert!(!is_feature_id_reg(sysreg(3, 0, 0, 5, 4))); // ID_AA64AFR0_EL1
        assert!(!is_feature_id_reg(sysreg(3, 0, 0, 1, 0))); // ID_PFR0_EL1 (AArch32)
        assert!(!is_feature_id_reg(MIDR_EL1));
    }

    #[test]
    fn this_host_has_a_sane_page_size() {
        let size = page_size();
        assert!(size >= 4096 && size.is_power_of_two(), "{size}");
    }
}
