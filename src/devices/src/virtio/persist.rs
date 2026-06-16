// Copyright 2026. SPDX-License-Identifier: Apache-2.0
//
//! VM-level device-state aggregation for checkpoint/restore.
//!
//! Composes each device's `*State` snapshot (built on `Queue::save_state` and
//! the per-device `save_state`/`restore_state`) into a single [`VmDevicesState`].
//! The device manager holds devices polymorphically as `&dyn VirtioDevice`, so
//! this downcasts (via the `AsAny` supertrait) to the concrete types. Devices
//! without a Persist impl (balloon, gpu, input) — and virtio-fs, whose FUSE map
//! persist is a separate capability (see docs/PLAN-krucible-cold-tier.md §1) —
//! are simply skipped; cold-capable guests root on a block device.

use crate::virtio::{Console, ConsoleState, Rng, RngState, VirtioDevice, Vsock, VsockState};
#[cfg(feature = "blk")]
use crate::virtio::{Block, BlockState};

/// Snapshot of a single virtio device's runtime state.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DeviceSnapshot {
    Console(ConsoleState),
    Vsock(VsockState),
    Rng(RngState),
    #[cfg(feature = "blk")]
    Block(BlockState),
}

impl DeviceSnapshot {
    /// The virtio device type id (`TYPE_*`) this snapshot belongs to — used to
    /// match a snapshot to its transport when restoring a fresh VM.
    pub fn device_type(&self) -> u32 {
        use crate::virtio::*;
        match self {
            DeviceSnapshot::Console(_) => TYPE_CONSOLE,
            DeviceSnapshot::Vsock(_) => TYPE_VSOCK,
            DeviceSnapshot::Rng(_) => TYPE_RNG,
            #[cfg(feature = "blk")]
            DeviceSnapshot::Block(_) => TYPE_BLOCK,
        }
    }

    /// Negotiated feature bits to restore before re-activation.
    pub fn acked_features(&self) -> u64 {
        match self {
            DeviceSnapshot::Console(s) => s.acked_features,
            DeviceSnapshot::Vsock(s) => s.acked_features,
            DeviceSnapshot::Rng(s) => s.acked_features,
            #[cfg(feature = "blk")]
            DeviceSnapshot::Block(s) => s.acked_features,
        }
    }

    /// Per-queue saved state, in queue-index order, for rebuilding the
    /// transport's queues on re-activation.
    pub fn queue_states(&self) -> Vec<Option<crate::virtio::queue::QueueState>> {
        match self {
            DeviceSnapshot::Console(s) => s.queues.clone(),
            DeviceSnapshot::Vsock(s) => vec![s.queue_rx.clone(), s.queue_tx.clone()],
            DeviceSnapshot::Rng(s) => vec![s.queue.clone()],
            #[cfg(feature = "blk")]
            DeviceSnapshot::Block(s) => vec![s.queue.clone()],
        }
    }
}

/// Aggregate of all snapshot-supporting devices in a VM, for checkpoint/restore.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VmDevicesState {
    pub devices: Vec<DeviceSnapshot>,
}

impl VmDevicesState {
    /// Serialize to bytes (JSON — the state is small: queue indices, features,
    /// ids — and human-readable output eases debugging snapshots). No
    /// cross-version compatibility is promised.
    pub fn to_bytes(&self) -> std::result::Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| format!("serialize device state: {e}"))
    }

    /// Reconstruct from bytes produced by [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> std::result::Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|e| format!("deserialize device state: {e}"))
    }

    /// Capture all snapshot-supporting devices from an iterator of device refs.
    /// The device manager calls this over its activated virtio devices (after
    /// quiescing their workers so queue indices are at a clean boundary).
    pub fn capture<'a, I>(devices: I) -> Self
    where
        I: IntoIterator<Item = &'a dyn VirtioDevice>,
    {
        VmDevicesState {
            devices: devices.into_iter().filter_map(snapshot_device).collect(),
        }
    }
}

/// Capture one device's state if it supports persist; `None` for unsupported
/// device types (balloon/gpu/input/fs — skipped).
pub fn snapshot_device(dev: &dyn VirtioDevice) -> Option<DeviceSnapshot> {
    let any = dev.as_any();
    if let Some(d) = any.downcast_ref::<Console>() {
        return Some(DeviceSnapshot::Console(d.save_state()));
    }
    if let Some(d) = any.downcast_ref::<Vsock>() {
        return Some(DeviceSnapshot::Vsock(d.save_state()));
    }
    if let Some(d) = any.downcast_ref::<Rng>() {
        return Some(DeviceSnapshot::Rng(d.save_state()));
    }
    #[cfg(feature = "blk")]
    if let Some(d) = any.downcast_ref::<Block>() {
        return Some(DeviceSnapshot::Block(d.save_state()));
    }
    None
}

/// Restore one device's state, matching the snapshot variant to the concrete
/// device type. Errors on a snapshot/device-type mismatch.
pub fn restore_device(dev: &mut dyn VirtioDevice, snap: &DeviceSnapshot) -> Result<(), String> {
    let any = dev.as_mut_any();
    match snap {
        DeviceSnapshot::Console(s) => any
            .downcast_mut::<Console>()
            .ok_or_else(|| "snapshot/device mismatch: expected Console".to_string())?
            .restore_state(s),
        DeviceSnapshot::Vsock(s) => any
            .downcast_mut::<Vsock>()
            .ok_or_else(|| "snapshot/device mismatch: expected Vsock".to_string())?
            .restore_state(s),
        DeviceSnapshot::Rng(s) => any
            .downcast_mut::<Rng>()
            .ok_or_else(|| "snapshot/device mismatch: expected Rng".to_string())?
            .restore_state(s),
        #[cfg(feature = "blk")]
        DeviceSnapshot::Block(s) => any
            .downcast_mut::<Block>()
            .ok_or_else(|| "snapshot/device mismatch: expected Block".to_string())?
            .restore_state(s),
    }
}
