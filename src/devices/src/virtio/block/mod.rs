// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod device;
mod worker;

pub use self::device::{Block, BlockState, CacheType};

use vm_memory::GuestMemoryError;

use super::QueueConfig;

pub const CONFIG_SPACE_SIZE: usize = 8;
pub const SECTOR_SHIFT: u8 = 9;
pub const SECTOR_SIZE: u64 = (0x01_u64) << SECTOR_SHIFT;
const QUEUE_SIZE: u16 = 256;
pub const NUM_QUEUES: usize = 1;
pub static QUEUE_CONFIG: [QueueConfig; NUM_QUEUES] = [QueueConfig::new(QUEUE_SIZE)];

#[derive(Debug)]
pub enum Error {
    /// Guest gave us too few descriptors in a descriptor chain.
    DescriptorChainTooShort,
    /// Guest gave us a descriptor that was too short to use.
    DescriptorLengthTooSmall,
    /// Getting a block's metadata fails for any reason.
    GetFileMetadata(std::io::Error),
    /// Guest gave us bad memory addresses.
    GuestMemory(GuestMemoryError),
    /// The requested operation would cause a seek beyond disk end.
    InvalidOffset,
    /// Guest gave us a read only descriptor that protocol says to write to.
    UnexpectedReadOnlyDescriptor,
    /// Guest gave us a write only descriptor that protocol says to read from.
    UnexpectedWriteOnlyDescriptor,
}

/// Supported disk image formats
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImageType {
    Raw,
    Qcow2,
    Vmdk,
}

impl TryFrom<u32> for ImageType {
    type Error = ();

    fn try_from(disk_format: u32) -> Result<Self, Self::Error> {
        match disk_format {
            0 => Ok(ImageType::Raw),
            1 => Ok(ImageType::Qcow2),
            2 => Ok(ImageType::Vmdk),
            _ => {
                // Do not continue if the user cannot specify a valid disk format
                Err(())
            }
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum SyncMode {
    None,
    Relaxed,
    #[default]
    Full,
}

impl TryFrom<u32> for SyncMode {
    type Error = ();

    fn try_from(sync_mode: u32) -> Result<Self, Self::Error> {
        match sync_mode {
            0 => Ok(SyncMode::None),
            1 => Ok(SyncMode::Relaxed),
            2 => Ok(SyncMode::Full),
            _ => {
                // Do not continue if the user cannot specify a valid sync mode
                Err(())
            }
        }
    }
}

/// Create a qcow2 copy-on-write overlay at `overlay_path` backed by the raw
/// image at `backing_path` (of `virtual_size` bytes). The overlay starts empty
/// — reads fall through to the backing, writes land in the overlay — so creating
/// one is instant and **host-filesystem-independent** (no reflink / no btrfs).
///
/// Reuses `imago`, the same library that *opens* these images at boot, so the
/// result is correct-by-construction (one qcow2 implementation, not two).
pub fn create_qcow2_overlay(
    overlay_path: &str,
    backing_path: &str,
    virtual_size: u64,
) -> std::io::Result<()> {
    use std::sync::Arc;

    use imago::{
        DynStorage, FormatAccess, FormatCreateBuilder, Storage, StorageOpenOptions,
        file::File as ImagoFile, qcow2::Qcow2,
    };

    // Truncate-create the destination so imago can open it for writing.
    std::fs::File::create(overlay_path)?;
    let dest = ImagoFile::open_sync(StorageOpenOptions::new().write(true).filename(overlay_path))?;

    let builder =
        Qcow2::<Box<dyn DynStorage>, Arc<FormatAccess<Box<dyn DynStorage>>>>::create_builder(
            Box::new(dest),
        )
        .backing(backing_path.to_string(), "raw".to_string())
        .size(virtual_size);

    // imago's create() is async and has no sync wrapper, so drive it on a
    // current-thread tokio runtime (the same kind imago's sync wrappers use).
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|e| std::io::Error::other(format!("tokio runtime: {e}")))?;
    runtime.block_on(builder.create())
}
