#[cfg(feature = "tee")]
pub mod tee;

pub mod vstate;

/// arm64 vCPU state for checkpoints.
#[cfg(all(checkpoint, target_arch = "aarch64"))]
pub(crate) mod arm64;
/// The in-kernel vGIC's state for checkpoints.
#[cfg(all(checkpoint, target_arch = "aarch64"))]
pub(crate) mod vgic;
