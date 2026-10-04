#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "ffi", derive(ffier::FfiError))]
#[non_exhaustive]
pub enum VmmError {
    #[error("invalid parameter")]
    #[cfg_attr(feature = "ffi", ffier(code = 1))]
    InvalidParam(),

    #[error("missing required configuration: {0}")]
    #[cfg_attr(feature = "ffi", ffier(code = 2, opaque))]
    MissingConfig(String),

    #[error("value out of range")]
    #[cfg_attr(feature = "ffi", ffier(code = 3))]
    OutOfRange(),

    #[error("file not found")]
    #[cfg_attr(feature = "ffi", ffier(code = 4))]
    FileNotFound(),

    #[error("resource allocation failed")]
    #[cfg_attr(feature = "ffi", ffier(code = 5))]
    ResourceAlloc(),

    #[error("bad file descriptor")]
    #[cfg_attr(feature = "ffi", ffier(code = 6))]
    BadFd(),

    #[error("feature not enabled in this build")]
    #[cfg_attr(feature = "ffi", ffier(code = 7))]
    FeatureDisabled(),

    #[error("boot error: {0}")]
    #[cfg_attr(feature = "ffi", ffier(code = 8, opaque))]
    BootError(String),

    #[error("internal error: {0}")]
    #[cfg_attr(feature = "ffi", ffier(code = 9, opaque))]
    Internal(String),

    /// A checkpoint that can't be restored here: damaged, foreign, or saved on
    /// a host this one can't stand in for.
    #[error("checkpoint: {0}")]
    #[cfg_attr(feature = "ffi", ffier(code = 10, opaque))]
    Checkpoint(String),
}
