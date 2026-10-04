//! Whether a checkpoint taken on one host can run on another.
//!
//! A checkpoint carries a record of the host it was taken on and of what that
//! host gave the guest: the CPU (vendor, family, model, stepping), the CPUID
//! feature words the guest saw, the guest's TSC rate, the KVM capabilities its
//! state depends on, the page size and the MSRs its vCPU state holds. A restore
//! builds the same record for its own host and [`HostRecord::check`]s the two.
//! It refuses a host that can't run the guest: another CPU vendor or page size,
//! a CPU feature or MSR the guest may be using that this host doesn't offer, a
//! missing KVM capability, or a TSC rate this host can neither match nor scale
//! to. Another model from the same vendor is fine as long as it offers
//! everything the guest saw: the guest keeps the CPUID it was given.

use kvm_bindings::kvm_cpuid_entry2;

use super::codec::{Decoder, Encoder, Pod};

/// KVM_SET_CLOCK takes KVM_CLOCK_REALTIME: the saved kvmclock is anchored to
/// wall-clock time, so a restore must be able to set it that way.
pub(crate) const CAP_CLOCK_REALTIME: u32 = 1 << 0;
/// KVM exposes a vCPU's TSC offset (KVM_VCPU_TSC_CTRL); a checkpoint taken
/// with it carries the offsets a restore rebases and writes back.
pub(crate) const CAP_TSC_OFFSET: u32 = 1 << 1;
/// KVM can run a guest's TSC at another rate than the host's
/// (KVM_CAP_TSC_CONTROL).
pub(crate) const CAP_TSC_SCALING: u32 = 1 << 2;

/// The capabilities a restore can't do without when the checkpoint was taken
/// with them.
const REQUIRED_CAPS: u32 = CAP_CLOCK_REALTIME | CAP_TSC_OFFSET;

/// KVM runs a guest's TSC unscaled at the host's rate when the requested rate
/// is within this many parts per million of it (its `tsc_tolerance_ppm`
/// default), so two hosts of one model never need TSC scaling.
const TSC_TOLERANCE_PPM: u64 = 250;

const EAX: u32 = 0;
const EBX: u32 = 1;
const ECX: u32 = 2;
const EDX: u32 = 3;

/// The CPUID registers that enumerate features, as (leaf, subleaf, register,
/// bits that mirror guest state rather than what the CPU offers).
const FEATURE_WORDS: &[(u32, u32, u32, u32)] = &[
    (0x1, 0, ECX, 1 << 27), // OSXSAVE mirrors CR4.OSXSAVE
    (0x1, 0, EDX, 0),
    (0x7, 0, EBX, 0),
    (0x7, 0, ECX, 1 << 4), // OSPKE mirrors CR4.PKE
    (0x7, 0, EDX, 0),
    (0x7, 1, EAX, 0),
    (0x7, 1, EDX, 0),
    (0xd, 0, EAX, 0), // XSAVE state components (XCR0)
    (0xd, 0, EDX, 0),
    (0xd, 1, EAX, 0),
    (0x4000_0001, 0, EAX, 0), // KVM paravirtual features
    (0x8000_0001, 0, ECX, 0),
    (0x8000_0001, 0, EDX, 0),
    (0x8000_0007, 0, EDX, 0),
    (0x8000_0008, 0, EBX, 0),
];

/// One CPUID output register: the features it enumerates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct CpuidWord {
    pub leaf: u32,
    pub subleaf: u32,
    /// 0 = EAX, 1 = EBX, 2 = ECX, 3 = EDX.
    pub reg: u32,
    pub bits: u32,
}

// SAFETY: four u32s, no padding.
unsafe impl Pod for CpuidWord {}

/// A host as far as running a checkpointed guest goes. In a checkpoint it
/// describes the host the guest ran on and what the guest was given; for a
/// restore, what this host would give it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HostRecord {
    /// The CPUID vendor string ("GenuineIntel", "AuthenticAMD").
    pub vendor: [u8; 12],
    pub family: u32,
    pub model: u32,
    pub stepping: u32,
    pub page_size: u32,
    /// The guest's TSC rate (a checkpoint), or the rate a vCPU here runs at
    /// unless told otherwise (a restore).
    pub tsc_khz: u32,
    /// `CAP_*` bits.
    pub kvm_caps: u32,
    /// The feature words of the guest's CPUID.
    pub cpuid: Vec<CpuidWord>,
    /// The MSRs the guest's vCPU state holds (a checkpoint), or the ones KVM
    /// here can restore (a restore).
    pub msrs: Vec<u32>,
}

impl HostRecord {
    /// This host's CPU and page size, with what a guest has or would get here.
    pub(crate) fn here(
        guest_cpuid: &[kvm_cpuid_entry2],
        tsc_khz: u32,
        kvm_caps: u32,
        msrs: Vec<u32>,
    ) -> Self {
        let (vendor, signature) = host_cpu();
        let (family, model, stepping) = decode_signature(signature);
        // SAFETY: sysconf has no preconditions.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        HostRecord {
            vendor,
            family,
            model,
            stepping,
            page_size: u32::try_from(page_size).unwrap_or(0),
            tsc_khz,
            kvm_caps,
            cpuid: feature_words(guest_cpuid),
            msrs,
        }
    }

    pub(crate) fn encode(&self, enc: &mut Encoder) {
        enc.raw(&self.vendor);
        enc.u32(self.family);
        enc.u32(self.model);
        enc.u32(self.stepping);
        enc.u32(self.page_size);
        enc.u32(self.tsc_khz);
        enc.u32(self.kvm_caps);
        enc.pods(&self.cpuid);
        enc.pods(&self.msrs);
    }

    pub(crate) fn decode(dec: &mut Decoder) -> Result<Self, String> {
        Ok(HostRecord {
            vendor: dec.raw(12)?.try_into().unwrap(),
            family: dec.u32()?,
            model: dec.u32()?,
            stepping: dec.u32()?,
            page_size: dec.u32()?,
            tsc_khz: dec.u32()?,
            kvm_caps: dec.u32()?,
            cpuid: dec.pods()?,
            msrs: dec.pods()?,
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
        if self.vendor != here.vendor {
            return Err(format!(
                "CPU vendor differs: the checkpoint was taken on {}; this host is {}",
                self.cpu(),
                here.cpu()
            ));
        }
        let caps = self.kvm_caps & REQUIRED_CAPS & !here.kvm_caps;
        if caps != 0 {
            return Err(format!(
                "this host's KVM lacks {}, which the checkpoint's guest state needs",
                cap_names(caps)
            ));
        }
        let missing: Vec<String> = self
            .cpuid
            .iter()
            .flat_map(|saved| {
                let offered = here
                    .cpuid
                    .iter()
                    .find(|w| (w.leaf, w.subleaf, w.reg) == (saved.leaf, saved.subleaf, saved.reg))
                    .map_or(0, |w| w.bits);
                let lacking = saved.bits & !offered;
                (0..32)
                    .filter(move |bit| lacking & (1 << bit) != 0)
                    .map(move |bit| feature_name(saved, bit))
            })
            .collect();
        if !missing.is_empty() {
            return Err(format!(
                "this host's CPU lacks features the guest uses: {} (the checkpoint was taken on {}; this host is {})",
                missing.join(", "),
                self.cpu(),
                here.cpu()
            ));
        }
        let msrs: Vec<String> = self
            .msrs
            .iter()
            .filter(|msr| !here.msrs.contains(msr))
            .map(|msr| format!("{msr:#x}"))
            .collect();
        if !msrs.is_empty() {
            return Err(format!(
                "this host's KVM can't restore MSRs the guest's state holds: {} (the checkpoint was taken on {}; this host is {})",
                msrs.join(", "),
                self.cpu(),
                here.cpu()
            ));
        }
        let (guest, host) = (u64::from(self.tsc_khz), u64::from(here.tsc_khz));
        if guest.abs_diff(host) * 1_000_000 > host * TSC_TOLERANCE_PPM
            && here.kvm_caps & CAP_TSC_SCALING == 0
        {
            return Err(format!(
                "TSC rate differs: the guest's TSC runs at {guest} kHz and this host's at {host} kHz, and this host can't scale a guest's TSC (no KVM_CAP_TSC_CONTROL)"
            ));
        }
        Ok(())
    }

    fn cpu(&self) -> String {
        format!(
            "{} family {} model {} stepping {}",
            String::from_utf8_lossy(&self.vendor),
            self.family,
            self.model,
            self.stepping
        )
    }
}

/// The feature words of a CPUID, with the bits that mirror guest state
/// cleared. A word whose leaf the CPUID lacks enumerates nothing.
pub(crate) fn feature_words(cpuid: &[kvm_cpuid_entry2]) -> Vec<CpuidWord> {
    FEATURE_WORDS
        .iter()
        .filter_map(|&(leaf, subleaf, reg, state)| {
            let e = cpuid
                .iter()
                .find(|e| e.function == leaf && e.index == subleaf)?;
            let value = [e.eax, e.ebx, e.ecx, e.edx][reg as usize];
            Some(CpuidWord {
                leaf,
                subleaf,
                reg,
                bits: value & !state,
            })
        })
        .collect()
}

/// The host CPU's vendor string and signature (CPUID leaf 1 EAX).
#[allow(unused_unsafe)]
fn host_cpu() -> ([u8; 12], u32) {
    use std::arch::x86_64::__cpuid;
    // SAFETY: every x86_64 CPU has CPUID; leaves 0 and 1 always exist.
    let (leaf0, leaf1) = unsafe { (__cpuid(0), __cpuid(1)) };
    let mut vendor = [0u8; 12];
    vendor[..4].copy_from_slice(&leaf0.ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&leaf0.edx.to_le_bytes());
    vendor[8..].copy_from_slice(&leaf0.ecx.to_le_bytes());
    (vendor, leaf1.eax)
}

/// (family, model, stepping) from a CPUID signature, as the vendors define
/// them: the extended family counts only past family 0xf, and the extended
/// model only for families 6 and 0xf.
fn decode_signature(eax: u32) -> (u32, u32, u32) {
    let stepping = eax & 0xf;
    let base_model = (eax >> 4) & 0xf;
    let base_family = (eax >> 8) & 0xf;
    let family = match base_family {
        0xf => base_family + ((eax >> 20) & 0xff),
        f => f,
    };
    let model = match base_family {
        0x6 | 0xf => base_model | (((eax >> 16) & 0xf) << 4),
        _ => base_model,
    };
    (family, model, stepping)
}

fn cap_names(caps: u32) -> String {
    [
        (CAP_CLOCK_REALTIME, "KVM_CLOCK_REALTIME"),
        (CAP_TSC_OFFSET, "the vCPU TSC offset (KVM_VCPU_TSC_CTRL)"),
        (CAP_TSC_SCALING, "TSC scaling (KVM_CAP_TSC_CONTROL)"),
    ]
    .iter()
    .filter(|(cap, _)| caps & cap != 0)
    .map(|(_, name)| *name)
    .collect::<Vec<_>>()
    .join(" and ")
}

/// Linux's /proc/cpuinfo name for a feature bit where it has one, else the
/// bit's CPUID coordinates.
fn feature_name(word: &CpuidWord, bit: u32) -> String {
    let names: &[&str] = match (word.leaf, word.subleaf, word.reg) {
        (0x1, 0, EDX) => &LEAF_1_EDX,
        (0x1, 0, ECX) => &LEAF_1_ECX,
        (0x7, 0, EBX) => &LEAF_7_0_EBX,
        (0x7, 0, ECX) => &LEAF_7_0_ECX,
        (0x7, 0, EDX) => &LEAF_7_0_EDX,
        (0xd, 0, EAX) => &LEAF_D_0_EAX,
        (0xd, 1, EAX) => &LEAF_D_1_EAX,
        (0x8000_0001, 0, ECX) => &LEAF_8000_0001_ECX,
        (0x8000_0001, 0, EDX) => &LEAF_8000_0001_EDX,
        _ => &[],
    };
    match names.get(bit as usize) {
        Some(name) if !name.is_empty() => (*name).to_string(),
        _ => format!(
            "cpuid {:#x}.{} {}[{bit}]",
            word.leaf,
            word.subleaf,
            ["eax", "ebx", "ecx", "edx"][word.reg as usize & 3]
        ),
    }
}

#[rustfmt::skip]
const LEAF_1_EDX: [&str; 32] = [
    "fpu", "vme", "de", "pse", "tsc", "msr", "pae", "mce",
    "cx8", "apic", "", "sep", "mtrr", "pge", "mca", "cmov",
    "pat", "pse36", "pn", "clflush", "", "dts", "acpi", "mmx",
    "fxsr", "sse", "sse2", "ss", "ht", "tm", "ia64", "pbe",
];
#[rustfmt::skip]
const LEAF_1_ECX: [&str; 32] = [
    "pni", "pclmulqdq", "dtes64", "monitor", "ds_cpl", "vmx", "smx", "est",
    "tm2", "ssse3", "cid", "sdbg", "fma", "cx16", "xtpr", "pdcm",
    "", "pcid", "dca", "sse4_1", "sse4_2", "x2apic", "movbe", "popcnt",
    "tsc_deadline_timer", "aes", "xsave", "osxsave", "avx", "f16c", "rdrand", "hypervisor",
];
#[rustfmt::skip]
const LEAF_7_0_EBX: [&str; 32] = [
    "fsgsbase", "tsc_adjust", "sgx", "bmi1", "hle", "avx2", "fdp_excptn_only", "smep",
    "bmi2", "erms", "invpcid", "rtm", "cqm", "zero_fcs_fds", "mpx", "rdt_a",
    "avx512f", "avx512dq", "rdseed", "adx", "smap", "avx512ifma", "", "clflushopt",
    "clwb", "intel_pt", "avx512pf", "avx512er", "avx512cd", "sha_ni", "avx512bw", "avx512vl",
];
#[rustfmt::skip]
const LEAF_7_0_ECX: [&str; 32] = [
    "prefetchwt1", "avx512vbmi", "umip", "pku", "ospke", "waitpkg", "avx512_vbmi2", "shstk",
    "gfni", "vaes", "vpclmulqdq", "avx512_vnni", "avx512_bitalg", "tme", "avx512_vpopcntdq", "",
    "la57", "", "", "", "", "", "rdpid", "",
    "bus_lock_detect", "cldemote", "", "movdiri", "movdir64b", "enqcmd", "sgx_lc", "pks",
];
#[rustfmt::skip]
const LEAF_7_0_EDX: [&str; 32] = [
    "", "", "avx512_4vnniw", "avx512_4fmaps", "fsrm", "uintr", "", "",
    "avx512_vp2intersect", "srbds_ctrl", "md_clear", "rtm_always_abort", "", "tsx_force_abort", "serialize", "hybrid_cpu",
    "tsxldtrk", "", "pconfig", "arch_lbr", "ibt", "", "amx_bf16", "avx512_fp16",
    "amx_tile", "amx_int8", "ibrs_ibpb", "stibp", "flush_l1d", "arch_capabilities", "core_capabilities", "ssbd",
];
#[rustfmt::skip]
const LEAF_D_0_EAX: [&str; 32] = [
    "xstate x87", "xstate sse", "xstate avx", "xstate bndregs", "xstate bndcsr", "xstate opmask", "xstate zmm_hi256", "xstate hi16_zmm",
    "", "xstate pkru", "", "", "", "", "", "",
    "", "xstate xtilecfg", "xstate xtiledata", "", "", "", "", "",
    "", "", "", "", "", "", "", "",
];
#[rustfmt::skip]
const LEAF_D_1_EAX: [&str; 32] = [
    "xsaveopt", "xsavec", "xgetbv1", "xsaves", "xfd", "", "", "",
    "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "",
];
#[rustfmt::skip]
const LEAF_8000_0001_ECX: [&str; 32] = [
    "lahf_lm", "cmp_legacy", "svm", "extapic", "cr8_legacy", "abm", "sse4a", "misalignsse",
    "3dnowprefetch", "osvw", "ibs", "xop", "skinit", "wdt", "", "lwp",
    "fma4", "tce", "", "nodeid_msr", "", "tbm", "topoext", "perfctr_core",
    "perfctr_nb", "", "bpext", "ptsc", "perfctr_llc", "mwaitx", "", "",
];
#[rustfmt::skip]
const LEAF_8000_0001_EDX: [&str; 32] = [
    "fpu", "vme", "de", "pse", "tsc", "msr", "pae", "mce",
    "cx8", "apic", "", "syscall", "mtrr", "pge", "mca", "cmov",
    "pat", "pse36", "", "mp", "nx", "", "mmxext", "mmx",
    "fxsr", "fxsr_opt", "pdpe1gb", "rdtscp", "", "lm", "3dnowext", "3dnow",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn word(leaf: u32, subleaf: u32, reg: u32, bits: u32) -> CpuidWord {
        CpuidWord {
            leaf,
            subleaf,
            reg,
            bits,
        }
    }

    /// An i9-9900K host as a checkpoint records it.
    fn saved() -> HostRecord {
        HostRecord {
            vendor: *b"GenuineIntel",
            family: 6,
            model: 158,
            stepping: 13,
            page_size: 4096,
            tsc_khz: 3_600_000,
            kvm_caps: CAP_CLOCK_REALTIME | CAP_TSC_OFFSET,
            cpuid: vec![
                word(0x1, 0, ECX, 1 << 28 | 1 << 26), // avx, xsave
                word(0x7, 0, EBX, 1 << 5 | 1 << 3),   // avx2, bmi1
                word(0x8000_0008, 0, EBX, 1 << 9),    // an unnamed bit
            ],
            msrs: vec![0x10, 0x174, 0xc000_0080],
        }
    }

    #[test]
    fn an_identical_host_runs_the_guest() {
        saved().check(&saved()).unwrap();
    }

    #[test]
    fn another_model_offering_every_feature_runs_the_guest() {
        let mut here = saved();
        here.model = 85;
        here.stepping = 7;
        here.cpuid[1].bits |= 1 << 16; // and avx512f besides
        here.cpuid.push(word(0x7, 0, ECX, 1 << 1));
        here.msrs.push(0x6a0);
        saved().check(&here).unwrap();
    }

    #[test]
    fn another_vendor_is_refused() {
        let mut here = saved();
        here.vendor = *b"AuthenticAMD";
        here.family = 25;
        let err = saved().check(&here).unwrap_err();
        assert!(err.contains("CPU vendor differs"), "{err}");
        assert!(err.contains("GenuineIntel family 6 model 158"), "{err}");
        assert!(err.contains("this host is AuthenticAMD family 25"), "{err}");
    }

    #[test]
    fn another_page_size_is_refused() {
        let mut here = saved();
        here.page_size = 16384;
        let err = saved().check(&here).unwrap_err();
        assert!(err.contains("page size differs"), "{err}");
    }

    #[test]
    fn missing_cpu_features_are_named() {
        let mut here = saved();
        here.cpuid[0].bits &= !(1 << 28); // no avx
        here.cpuid.remove(2); // nor anything in 0x80000008 EBX
        let err = saved().check(&here).unwrap_err();
        assert!(
            err.starts_with(
                "this host's CPU lacks features the guest uses: avx, cpuid 0x80000008.0 ebx[9] ("
            ),
            "{err}"
        );
    }

    #[test]
    fn bits_that_mirror_guest_state_are_not_features() {
        let entry = |ecx| kvm_cpuid_entry2 {
            function: 1,
            ecx,
            ..Default::default()
        };
        // The guest had set CR4.OSXSAVE; a fresh vCPU here hasn't.
        let guest = feature_words(&[entry(1 << 27 | 1 << 26)]);
        let fresh = feature_words(&[entry(1 << 26)]);
        assert_eq!(guest, fresh);
        assert_eq!(guest, vec![word(1, 0, ECX, 1 << 26), word(1, 0, EDX, 0)]);
    }

    #[test]
    fn missing_msrs_are_refused() {
        let mut here = saved();
        here.msrs.retain(|&m| m != 0x174);
        let err = saved().check(&here).unwrap_err();
        assert!(
            err.contains("can't restore MSRs the guest's state holds: 0x174"),
            "{err}"
        );
    }

    #[test]
    fn a_capability_the_guest_state_needs_is_required() {
        let mut here = saved();
        here.kvm_caps &= !CAP_TSC_OFFSET;
        let err = saved().check(&here).unwrap_err();
        assert!(err.contains("KVM_VCPU_TSC_CTRL"), "{err}");

        // A checkpoint taken without TSC offsets doesn't need them.
        let mut without = saved();
        without.kvm_caps &= !CAP_TSC_OFFSET;
        without.check(&here).unwrap();
    }

    #[test]
    fn a_tsc_rate_within_kvm_tolerance_runs_unscaled() {
        let mut here = saved();
        here.tsc_khz = 3_599_200; // 222 ppm off
        saved().check(&here).unwrap();
    }

    #[test]
    fn another_tsc_rate_needs_scaling() {
        let mut here = saved();
        here.tsc_khz = 2_400_000;
        let err = saved().check(&here).unwrap_err();
        assert!(
            err.contains("the guest's TSC runs at 3600000 kHz and this host's at 2400000 kHz"),
            "{err}"
        );
        here.tsc_khz = 3_598_000; // 556 ppm off: past KVM's tolerance
        assert!(
            saved()
                .check(&here)
                .unwrap_err()
                .contains("TSC rate differs")
        );

        here.kvm_caps |= CAP_TSC_SCALING;
        saved().check(&here).unwrap();
    }

    #[test]
    fn a_record_round_trips_and_truncations_are_refused() {
        let mut enc = Encoder::new();
        saved().encode(&mut enc);
        let buf = enc.into_bytes();
        let mut dec = Decoder::new(&buf);
        assert_eq!(HostRecord::decode(&mut dec).unwrap(), saved());
        dec.finish().unwrap();
        for len in 0..buf.len() {
            let err = HostRecord::decode(&mut Decoder::new(&buf[..len])).unwrap_err();
            assert!(err.contains("truncated"), "cut at {len}: {err}");
        }
    }

    #[test]
    fn signatures_decode_as_the_vendors_define_them() {
        // i9-9900K, Xeon Platinum 8280, Ryzen 5000 (Zen 3), Pentium 4.
        assert_eq!(decode_signature(0x0009_06ed), (6, 158, 13));
        assert_eq!(decode_signature(0x0005_0657), (6, 85, 7));
        assert_eq!(decode_signature(0x00a2_0f10), (25, 33, 0));
        assert_eq!(decode_signature(0x0000_0f29), (15, 2, 9));
    }

    #[test]
    fn this_host_describes_itself() {
        let here = HostRecord::here(&[], 1, 0, vec![]);
        assert!(here.page_size >= 4096 && here.page_size.is_power_of_two());
        assert!(here.family > 0, "{here:?}");
        assert!(
            [*b"GenuineIntel", *b"AuthenticAMD"].contains(&here.vendor)
                || here.vendor.iter().all(u8::is_ascii_graphic),
            "{here:?}"
        );
    }
}
