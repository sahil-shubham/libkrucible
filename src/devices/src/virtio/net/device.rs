// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.
use crate::Error as DeviceError;
use crate::virtio::net::Result;
use crate::virtio::net::{NUM_QUEUES, QUEUE_CONFIG};
use crate::virtio::queue::Error as QueueError;
use crate::virtio::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, InterruptTransport, QueueConfig,
    QueueState, TYPE_NET, VirtioDevice,
};

use super::backend::{ReadError, WriteError};
use super::worker::NetWorker;

#[cfg(unix)]
use std::os::fd::RawFd;
#[cfg(windows)]
use std::os::windows::io::RawSocket;

use std::cmp;
use std::io::Write;
use std::path::PathBuf;
#[cfg(unix)]
use std::thread::JoinHandle;
#[cfg(unix)]
use utils::eventfd::{EFD_NONBLOCK, EventFd};
use virtio_bindings::virtio_net::VIRTIO_NET_F_MAC;
use virtio_bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::{ByteValued, GuestMemoryError, GuestMemoryMmap};

const VIRTIO_F_VERSION_1: u32 = 32;

#[derive(Debug)]
pub enum FrontendError {
    DescriptorChainTooSmall,
    EmptyQueue,
    GuestMemory(GuestMemoryError),
    QueueError(QueueError),
    ReadOnlyDescriptor,
}

#[derive(Debug)]
pub enum RxError {
    Backend(ReadError),
    DeviceError(DeviceError),
}

#[derive(Debug)]
pub enum TxError {
    Backend(WriteError),
    DeviceError(DeviceError),
    QueueError(QueueError),
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioNetConfig {
    mac: [u8; 6],
    status: u16,
    max_virtqueue_pairs: u16,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioNetConfig {}

#[derive(Clone)]
pub enum VirtioNetBackend {
    #[cfg(unix)]
    UnixstreamFd(RawFd),
    #[cfg(windows)]
    UnixstreamFd(RawSocket),
    UnixstreamPath(PathBuf),
    #[cfg(unix)]
    UnixgramFd(RawFd),
    #[cfg(unix)]
    UnixgramPath(PathBuf, bool),
    #[cfg(target_os = "linux")]
    Tap(String),
}

pub struct Net {
    id: String,
    pub cfg_backend: VirtioNetBackend,

    avail_features: u64,
    acked_features: u64,

    pub(crate) device_state: DeviceState,

    config: VirtioNetConfig,
    #[cfg(unix)]
    worker_thread: Option<JoinHandle<NetWorker>>,
    #[cfg(unix)]
    worker_stopfd: EventFd,
    #[cfg(unix)]
    quiesced_worker: Option<NetWorker>,
    snapshot_error: Option<String>,
}

impl Net {
    /// Create a new virtio network device using the backend
    pub fn new(
        id: String,
        cfg_backend: VirtioNetBackend,
        mac: [u8; 6],
        features: u32,
    ) -> Result<Self> {
        let avail_features = features as u64
            | (1 << VIRTIO_NET_F_MAC)
            | (1 << VIRTIO_RING_F_EVENT_IDX)
            | (1 << VIRTIO_F_VERSION_1);

        let config = VirtioNetConfig {
            mac,
            status: 0,
            max_virtqueue_pairs: 0,
        };

        Ok(Net {
            id,
            cfg_backend,

            avail_features,
            acked_features: 0u64,

            device_state: DeviceState::Inactive,
            config,
            #[cfg(unix)]
            worker_thread: None,
            #[cfg(unix)]
            worker_stopfd: EventFd::new(EFD_NONBLOCK).map_err(super::Error::EventFd)?,
            #[cfg(unix)]
            quiesced_worker: None,
            snapshot_error: None,
        })
    }

    /// Provides the ID of this net device.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Provides the virtio-net backend of this net device.
    pub fn backend(&self) -> &VirtioNetBackend {
        &self.cfg_backend
    }
}

/// Runtime indices and negotiated features of a stopped network worker.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NetState {
    pub acked_features: u64,
    pub activated: bool,
    pub queue_rx: Option<QueueState>,
    pub queue_tx: Option<QueueState>,
}

impl Net {
    pub fn save_state(&self) -> NetState {
        #[cfg(unix)]
        let queues = self
            .quiesced_worker
            .as_ref()
            .map(NetWorker::save_queue_states);
        #[cfg(windows)]
        let queues: Option<(QueueState, QueueState)> = None;
        NetState {
            acked_features: self.acked_features,
            activated: self.device_state.is_activated(),
            queue_rx: queues.as_ref().map(|(rx, _)| rx.clone()),
            queue_tx: queues.map(|(_, tx)| tx),
        }
    }

    pub fn restore_state(&mut self, state: &NetState) -> std::result::Result<(), String> {
        #[cfg(unix)]
        if let (Some(worker), Some(rx), Some(tx)) = (
            self.quiesced_worker.as_mut(),
            state.queue_rx.as_ref(),
            state.queue_tx.as_ref(),
        ) {
            worker.restore_queue_states(rx, tx)?;
        }
        self.acked_features = state.acked_features;
        Ok(())
    }
}

impl VirtioDevice for Net {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn device_type(&self) -> u32 {
        TYPE_NET
    }

    fn device_name(&self) -> &str {
        "net"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &QUEUE_CONFIG
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_slice = self.config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        log::warn!(
            "Net: guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        let [rx_q, tx_q]: [_; NUM_QUEUES] = queues.try_into().map_err(|_| {
            error!("Cannot perform activate. Expected {} queue(s)", NUM_QUEUES);
            ActivateError::BadActivate
        })?;

        #[cfg(unix)]
        let stop_fd = self
            .worker_stopfd
            .try_clone()
            .map_err(|_| ActivateError::BadActivate)?;
        match NetWorker::new(
            rx_q,
            tx_q,
            interrupt.clone(),
            mem.clone(),
            self.acked_features,
            self.cfg_backend.clone(),
            #[cfg(unix)]
            stop_fd,
        ) {
            Ok(worker) => {
                #[cfg(unix)]
                {
                    self.worker_thread = Some(worker.run());
                }
                #[cfg(windows)]
                worker.run();
                self.device_state = DeviceState::Activated(mem, interrupt);
                Ok(())
            }
            Err(err) => {
                error!(
                    "Error activating virtio-net ({}) backend: {err:?}",
                    self.id()
                );
                Err(ActivateError::BadActivate)
            }
        }
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    #[cfg(unix)]
    fn reset(&mut self) -> bool {
        if let Some(handle) = self.worker_thread.take() {
            let _ = self.worker_stopfd.write(1);
            if let Err(error) = handle.join() {
                error!("net: worker failed during reset: {error:?}");
            }
        }
        self.quiesced_worker = None;
        self.snapshot_error = None;
        self.device_state = DeviceState::Inactive;
        true
    }

    fn quiesce_for_snapshot(&mut self) {
        #[cfg(unix)]
        if let Some(handle) = self.worker_thread.take() {
            if let Err(error) = self.worker_stopfd.write(1) {
                self.snapshot_error
                    .get_or_insert_with(|| format!("net worker stop: {error}"));
            }
            match handle.join() {
                Ok(worker) => self.quiesced_worker = Some(worker),
                Err(error) => {
                    error!("net: worker failed before checkpoint: {error:?}");
                    self.snapshot_error
                        .get_or_insert_with(|| "network worker failed before checkpoint".into());
                }
            }
        }
        #[cfg(windows)]
        {
            self.snapshot_error
                .get_or_insert_with(|| "network checkpoint unsupported on Windows".into());
        }
    }

    fn snapshot_error(&self) -> Option<&str> {
        self.snapshot_error.as_deref()
    }

    fn rearm_after_snapshot(&mut self) {
        #[cfg(unix)]
        if let Some(worker) = self.quiesced_worker.take() {
            self.worker_thread = Some(worker.run());
        }
    }
}

#[cfg(all(test, unix))]
mod checkpoint_failure_probe {
    use super::*;
    use std::thread;

    #[test]
    fn failed_worker_rejects_checkpoint_and_repeated_attempts() {
        let mut net = Net::new(
            "checkpoint-probe".into(),
            VirtioNetBackend::UnixstreamPath(PathBuf::from("unused-probe-socket")),
            [0; 6],
            0,
        )
        .unwrap();
        net.worker_thread = Some(thread::spawn(|| panic!("simulated network worker failure")));
        net.quiesce_for_snapshot();
        assert!(net.snapshot_error().is_some());
        assert!(net.worker_thread.is_none());
        assert!(net.quiesced_worker.is_none());
        assert!(net.save_state().queue_rx.is_none());
        net.quiesce_for_snapshot();
        net.rearm_after_snapshot();
        assert!(net.worker_thread.is_none());
        assert!(net.snapshot_error().is_some());
        net.reset();
        assert!(net.snapshot_error().is_none());
    }
}
