//! Whether a checkpoint taken on one host can run on another: a checkpoint
//! records the host it was taken on and what that host gave the guest, and a
//! restore checks that record against what this host would give it. What
//! matters differs per architecture (x86: CPUID, MSRs, the TSC; arm64: the
//! CPU's identity and ID registers, the generic timer, the GIC).

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "x86_64")]
mod x86_64;

#[cfg(target_arch = "aarch64")]
pub(crate) use aarch64::*;
#[cfg(target_arch = "x86_64")]
pub(crate) use x86_64::*;
