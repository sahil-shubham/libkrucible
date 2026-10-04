//! VM checkpoints: the state SAVE writes to a directory and a restore reads back.
//!
//! Built only where `cfg(checkpoint)` is set (see build.rs).

pub(crate) mod codec;
