// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use utils::byte_order;
use utils::eventfd::EventFd;
use vm_memory::{Bytes, GuestMemoryMmap};

use super::super::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, Queue as VirtQueue, QueueConfig,
    VirtioDevice,
};
use super::TsiFlags;
use super::muxer::VsockMuxer;
use super::packet::VsockPacket;
use super::rx_queue::RxQueue;
use super::snapshot_gate::SnapshotGate;
use super::{defs, defs::uapi};
use crate::virtio::InterruptTransport;
use crate::virtio::queue::QueueState;

pub(crate) const RXQ_INDEX: usize = 0;
pub(crate) const TXQ_INDEX: usize = 1;
pub(crate) const EVQ_INDEX: usize = 2;
const TRANSPORT_RESET_ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const VIRTIO_VSOCK_EVENT_TRANSPORT_RESET: u32 = 0;

/// The virtio features supported by our vsock device:
/// - VIRTIO_F_VERSION_1: the device conforms to at least version 1.0 of the VirtIO spec.
/// - VIRTIO_F_IN_ORDER: the device returns used buffers in the same order that the driver makes
///   them available.
pub(crate) const AVAIL_FEATURES: u64 = (1 << uapi::VIRTIO_F_VERSION_1 as u64)
    | (1 << uapi::VIRTIO_F_IN_ORDER as u64)
    | (1 << uapi::VIRTIO_VSOCK_F_DGRAM);

pub struct Vsock {
    cid: u64,
    pub(crate) muxer: VsockMuxer,
    pub(crate) queue_rx: Option<RxQueue>,
    pub(crate) queue_tx: Option<Arc<Mutex<VirtQueue>>>,
    pub(crate) queue_ev: Option<Arc<Mutex<VirtQueue>>>,
    pub(super) rx_gate: Arc<SnapshotGate>,
    pub(crate) quiesced: bool,
    pub(crate) deferred_rx: bool,
    pub(crate) deferred_tx: bool,
    pub(crate) deferred_ev: bool,
    pending_transport_reset: bool,
    pub(crate) awaiting_transport_reset_ack: bool,
    // Queue events are stored separately for event handling.
    pub(crate) queue_events: Vec<Arc<EventFd>>,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
}

impl Vsock {
    /// Create a new virtio-vsock device with the given VM CID.
    pub fn new(
        cid: u64,
        host_port_map: Option<HashMap<u16, u16>>,
        unix_ipc_port_map: Option<HashMap<u32, (PathBuf, bool)>>,
        tsi_flags: TsiFlags,
    ) -> super::Result<Vsock> {
        Ok(Vsock {
            cid,
            muxer: VsockMuxer::new(cid, host_port_map, unix_ipc_port_map, tsi_flags),
            queue_rx: None,
            queue_tx: None,
            queue_ev: None,
            rx_gate: Arc::default(),
            quiesced: false,
            deferred_rx: false,
            deferred_tx: false,
            deferred_ev: false,
            pending_transport_reset: false,
            awaiting_transport_reset_ack: false,
            queue_events: Vec::new(),
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            activate_evt: EventFd::new(utils::eventfd::EFD_NONBLOCK)
                .map_err(super::VsockError::EventFd)?,
            device_state: DeviceState::Inactive,
        })
    }

    pub fn id(&self) -> &str {
        defs::VSOCK_DEV_ID
    }

    pub fn cid(&self) -> u64 {
        self.cid
    }

    /// Walk the driver-provided RX queue buffers and attempt to fill them up with any data that we
    /// have pending. Return `true` if descriptors have been added to the used ring, and `false`
    /// otherwise.
    pub fn process_stream_rx(&mut self) -> bool {
        debug!("process_stream_rx()");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem, _) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        let mut have_used = false;

        debug!("process_rx before while");
        let queue_rx = self
            .queue_rx
            .as_ref()
            .expect("queue_rx should exist when activated");
        let Some(mut queue_rx) = queue_rx.try_lock() else {
            // A producer can briefly own the queue even with an open gate.
            // Retry on the event loop rather than waiting on its mutex.
            if !self.quiesced && !self.rx_gate.is_held_for_transport_reset() {
                let _ = self.queue_events[RXQ_INDEX].write(1);
            }
            self.deferred_rx = true;
            return false;
        };
        self.deferred_rx = false;
        while let Some(head) = queue_rx.pop(mem) {
            debug!("process_rx inside while");
            let used_len = match VsockPacket::from_rx_virtq_head(&head) {
                Ok(mut pkt) => {
                    if self.muxer.recv_pkt(&mut pkt).is_ok() {
                        pkt.hdr().len() as u32 + pkt.len()
                    } else {
                        // We are using a consuming iterator over the virtio buffers, so, if we can't
                        // fill in this buffer, we'll need to undo the last iterator step.
                        queue_rx.undo_pop();
                        break;
                    }
                }
                Err(e) => {
                    warn!("RX queue error: {e:?}");
                    0
                }
            };

            debug!("process_rx: something to queue");
            have_used = true;
            if let Err(e) = queue_rx.add_used(mem, head.index, used_len) {
                error!("failed to add used elements to the queue: {e:?}");
            }
        }

        have_used
    }

    /// Walk the driver-provided TX queue buffers, package them up as vsock packets, and process
    /// them. Return `true` if descriptors have been added to the used ring, and `false` otherwise.
    pub fn process_stream_tx(&mut self) -> bool {
        debug!("process_stream_tx()");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem, _) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        let mut have_used = false;

        let queue_tx = self
            .queue_tx
            .as_ref()
            .expect("queue_tx should exist when activated");
        let mut queue_tx = queue_tx.lock().unwrap();
        while let Some(head) = queue_tx.pop(mem) {
            let pkt = match VsockPacket::from_tx_virtq_head(&head) {
                Ok(pkt) => pkt,
                Err(e) => {
                    error!("error reading TX packet: {e:?}");
                    have_used = true;
                    if let Err(e) = queue_tx.add_used(mem, head.index, 0) {
                        error!("failed to add used elements to the queue: {e:?}");
                    }
                    continue;
                }
            };

            if pkt.type_() == uapi::VSOCK_TYPE_DGRAM {
                debug!("process_stream_tx() is DGRAM");
                if self.muxer.send_dgram_pkt(&pkt).is_err() {
                    queue_tx.undo_pop();
                    break;
                }
            } else {
                debug!("process_stream_tx() is STREAM");
                if self.muxer.send_stream_pkt(&pkt).is_err() {
                    queue_tx.undo_pop();
                    break;
                }
            }

            have_used = true;
            if let Err(e) = queue_tx.add_used(mem, head.index, 0) {
                error!("failed to add used elements to the queue: {e:?}");
            }
        }

        have_used
    }
}

/// Host-backed connections are not serialized. A freshly restored guest is
/// notified via the event queue and reconnects after a transport reset.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VsockState {
    pub cid: u64,
    pub acked_features: u64,
    pub activated: bool,
    pub queue_rx: Option<QueueState>,
    pub queue_tx: Option<QueueState>,
    pub queue_ev: Option<QueueState>,
}

impl Vsock {
    pub fn save_state(&self) -> VsockState {
        VsockState {
            cid: self.cid,
            acked_features: self.acked_features,
            activated: self.is_activated(),
            queue_rx: self.queue_rx.as_ref().map(RxQueue::save_state_paused),
            queue_tx: self
                .queue_tx
                .as_ref()
                .map(|q| q.lock().unwrap().save_state()),
            queue_ev: self
                .queue_ev
                .as_ref()
                .map(|q| q.lock().unwrap().save_state()),
        }
    }

    /// Apply feature bits to a fresh device; the transport restores the rings
    /// before activating it. CID stays the constructed one for future forks.
    pub fn restore_state(&mut self, state: &VsockState) -> Result<(), String> {
        if self.is_activated() {
            return Err("cannot restore an activated vsock".into());
        }
        self.acked_features = state.acked_features;
        if let (Some(queue), Some(saved)) = (&self.queue_rx, &state.queue_rx) {
            queue.restore_state_paused(saved)?;
        }
        if let (Some(queue), Some(saved)) = (&self.queue_tx, &state.queue_tx) {
            queue.lock().unwrap().restore_state(saved)?;
        }
        if let (Some(queue), Some(saved)) = (&self.queue_ev, &state.queue_ev) {
            queue.lock().unwrap().restore_state(saved)?;
        }
        if state.queue_ev.is_some() {
            self.pending_transport_reset = true;
            self.rx_gate.hold_for_transport_reset();
        }
        Ok(())
    }

    /// Return an event buffer to the guest only after successfully writing the
    /// little-endian transport reset identifier (event id zero).
    fn send_transport_reset(&mut self) -> bool {
        let DeviceState::Activated(ref mem, _) = self.device_state else {
            return false;
        };
        let Some(queue_ev) = self.queue_ev.as_ref() else {
            return false;
        };
        let mut queue = queue_ev.lock().unwrap();
        let Some(head) = queue.pop(mem) else {
            warn!("vsock: no event buffer available for transport reset");
            return false;
        };
        let event_len = std::mem::size_of::<u32>() as u32;
        let used_len = if head.is_write_only() && head.len >= event_len {
            match mem.write_obj(VIRTIO_VSOCK_EVENT_TRANSPORT_RESET.to_le(), head.addr) {
                Ok(()) => event_len,
                Err(e) => {
                    error!("vsock: failed to write transport reset: {e:?}");
                    0
                }
            }
        } else {
            error!("vsock: event buffer is not a writable vsock event");
            0
        };
        if let Err(e) = queue.add_used(mem, head.index, used_len) {
            error!("vsock: failed to return event buffer: {e:?}");
            return false;
        }
        self.device_state.signal_used_queue();
        used_len == event_len
    }

    pub(crate) fn process_deferred_queues(&mut self) {
        if self.quiesced || !self.is_activated() || self.rx_gate.is_held_for_transport_reset() {
            return;
        }
        let mut raise_irq = false;
        if std::mem::take(&mut self.deferred_tx) {
            raise_irq |= self.process_stream_tx();
        }
        if std::mem::take(&mut self.deferred_rx) || self.muxer.has_pending_rx() {
            raise_irq |= self.process_stream_rx();
        }
        if raise_irq {
            self.device_state.signal_used_queue();
        }
    }
}

impl VirtioDevice for Vsock {
    fn quiesce_for_snapshot(&mut self) {
        if self.quiesced {
            return;
        }
        self.quiesced = true;
        self.rx_gate.pause();
        // Writers may have filled used entries immediately before the gate
        // closed, but not yet signalled their corresponding queue interrupt.
        if self.is_activated() {
            self.device_state.signal_used_queue();
        }
    }

    fn rearm_after_snapshot(&mut self) {
        if !self.quiesced {
            return;
        }
        self.quiesced = false;
        self.rx_gate.resume();
        if std::mem::take(&mut self.deferred_ev)
            && std::mem::take(&mut self.awaiting_transport_reset_ack)
        {
            self.rx_gate.release_transport_reset();
            self.deferred_rx = true;
        }
        self.process_deferred_queues();
    }

    fn finish_restore_activation(&mut self) {
        if !std::mem::take(&mut self.pending_transport_reset) {
            return;
        }
        if !self.send_transport_reset() {
            self.rx_gate.release_transport_reset();
            return;
        }
        self.awaiting_transport_reset_ack = true;
        let gate = self.rx_gate.clone();
        let rx_event = self.queue_events[RXQ_INDEX].clone();
        let tx_event = self.queue_events[TXQ_INDEX].clone();
        // Even if the guest never kicks the event queue, unblock host
        // producers and wake the event loop to drain any buffered responses.
        if let Err(e) = std::thread::Builder::new()
            .name("vsock-reset-hold".into())
            .spawn(move || {
                std::thread::sleep(TRANSPORT_RESET_ACK_TIMEOUT);
                if gate.release_transport_reset() {
                    warn!("vsock: transport reset acknowledgment timed out");
                    let _ = rx_event.write(1);
                    let _ = tx_event.write(1);
                }
            })
        {
            error!("vsock: could not start reset hold timer: {e}");
            self.rx_gate.release_transport_reset();
        }
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
    }

    fn device_type(&self) -> u32 {
        uapi::VIRTIO_ID_VSOCK
    }

    fn device_name(&self) -> &str {
        "vsock"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &defs::QUEUE_CONFIG
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        match offset {
            0 if data.len() == 8 => byte_order::write_le_u64(data, self.cid()),
            0 if data.len() == 4 => {
                byte_order::write_le_u32(data, (self.cid() & 0xffff_ffff) as u32)
            }
            4 if data.len() == 4 => {
                byte_order::write_le_u32(data, ((self.cid() >> 32) & 0xffff_ffff) as u32)
            }
            _ => warn!(
                "virtio-vsock received invalid read request of {} bytes at offset {}",
                data.len(),
                offset
            ),
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "guest driver attempted to write device config (offset={:x}, len={:x})",
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
        if queues.len() != defs::NUM_QUEUES {
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                defs::NUM_QUEUES,
                queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        if self.activate_evt.write(1).is_err() {
            error!("Cannot write to activate_evt",);
            return Err(ActivateError::BadActivate);
        }

        // Store queue events for event handling.
        self.queue_events = queues.iter().map(|dq| dq.event.clone()).collect();

        // Extract queues from DeviceQueues and wrap in Arc<Mutex<>>.
        let mut queues_vec: Vec<VirtQueue> = queues.into_iter().map(|dq| dq.queue).collect();
        // The event queue must survive activation to deliver a restore reset.
        let ev_queue = queues_vec.pop().unwrap();
        let tx_queue = queues_vec.pop().unwrap();
        let rx_queue = queues_vec.pop().unwrap();

        self.queue_tx = Some(Arc::new(Mutex::new(tx_queue)));
        self.queue_rx = Some(RxQueue::new(rx_queue, self.rx_gate.clone()));
        self.queue_ev = Some(Arc::new(Mutex::new(ev_queue)));
        self.muxer.activate(
            mem.clone(),
            self.queue_rx.clone().unwrap(),
            interrupt.clone(),
        );

        self.device_state = DeviceState::Activated(mem, interrupt);

        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }
}

#[cfg(all(test, unix))]
mod checkpoint_tests {
    use super::*;
    use crate::legacy::DummyIrqChip;
    use polly::event_manager::{EventManager, Subscriber};
    use std::os::fd::AsRawFd;
    use utils::epoll::{EpollEvent, EventSet};
    use vm_memory::GuestAddress;

    fn restored_with_event_buffer() -> (Vsock, GuestMemoryMmap) {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let mut device = Vsock::new(7, None, None, TsiFlags::empty()).unwrap();
        let event_state = QueueState {
            size: 8,
            ready: true,
            desc_table: 0x1000,
            avail_ring: 0x2000,
            used_ring: 0x3000,
            ..QueueState::default()
        };
        device
            .restore_state(&VsockState {
                cid: 7,
                acked_features: AVAIL_FEATURES,
                activated: true,
                queue_rx: None,
                queue_tx: None,
                queue_ev: Some(event_state.clone()),
            })
            .unwrap();
        let mut event_queue = VirtQueue::new(256);
        event_queue.restore_state(&event_state).unwrap();
        device.queue_ev = Some(Arc::new(Mutex::new(event_queue)));
        device.queue_rx = Some(RxQueue::new(VirtQueue::new(256), device.rx_gate.clone()));
        device.queue_tx = Some(Arc::new(Mutex::new(VirtQueue::new(256))));
        device.queue_events = (0..defs::NUM_QUEUES)
            .map(|_| Arc::new(EventFd::new(utils::eventfd::EFD_NONBLOCK).unwrap()))
            .collect();
        device.device_state = DeviceState::Activated(
            mem.clone(),
            InterruptTransport::new(DummyIrqChip::new().into(), "test-vsock".into()).unwrap(),
        );
        // One writable four-byte virtio_vsock_event on EVQ.
        mem.write_obj(0x4000u64, GuestAddress(0x1000)).unwrap();
        mem.write_obj(4u32, GuestAddress(0x1008)).unwrap();
        mem.write_obj(2u16, GuestAddress(0x100c)).unwrap();
        mem.write_obj(1u16, GuestAddress(0x2002)).unwrap();
        mem.write_obj(0u16, GuestAddress(0x2004)).unwrap();
        mem.write_obj(0xfeedbeefu32, GuestAddress(0x4000)).unwrap();
        (device, mem)
    }

    #[test]
    fn transport_reset_writes_event_and_holds_rx_until_guest_evq_kick() {
        let (mut device, mem) = restored_with_event_buffer();
        assert!(device.rx_gate.is_held_for_transport_reset());
        device.finish_restore_activation();
        assert_eq!(mem.read_obj::<u32>(GuestAddress(0x4000)).unwrap(), 0);
        assert_eq!(mem.read_obj::<u16>(GuestAddress(0x3002)).unwrap(), 1);
        assert_eq!(mem.read_obj::<u32>(GuestAddress(0x3008)).unwrap(), 4);
        assert!(device.awaiting_transport_reset_ack);
        assert!(device.queue_rx.as_ref().unwrap().try_lock().is_none());
        assert!(!device.process_stream_rx());

        let event = device.queue_events[EVQ_INDEX].clone();
        event.write(1).unwrap();
        device.process(
            &EpollEvent::new(EventSet::IN, event.as_raw_fd() as u64),
            &mut EventManager::new().unwrap(),
        );
        assert!(!device.rx_gate.is_held_for_transport_reset());
        assert!(device.queue_rx.as_ref().unwrap().try_lock().is_some());
        assert!(!device.awaiting_transport_reset_ack);
    }

    #[test]
    fn no_event_buffer_releases_rx_instead_of_holding_guest_forever() {
        let (mut device, mem) = restored_with_event_buffer();
        mem.write_obj(0u16, GuestAddress(0x2002)).unwrap();
        device.finish_restore_activation();
        assert!(!device.rx_gate.is_held_for_transport_reset());
        assert!(!device.awaiting_transport_reset_ack);
    }

    #[test]
    fn transport_reset_timeout_releases_gate_and_wakes_rx_event_loop() {
        let (mut device, _mem) = restored_with_event_buffer();
        device.finish_restore_activation();
        let rx_event = device.queue_events[RXQ_INDEX].clone();
        let start = std::time::Instant::now();
        let kicked = loop {
            match rx_event.read() {
                Ok(value) => break value,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("failed to read RX event: {e}"),
            }
            if start.elapsed() >= std::time::Duration::from_secs(12) {
                panic!("fallback did not wake the RX event loop");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert_eq!(kicked, 1);
        assert!(start.elapsed() >= TRANSPORT_RESET_ACK_TIMEOUT);
        assert!(!device.rx_gate.is_held_for_transport_reset());
    }

    #[test]
    fn quiesced_events_do_not_touch_queues_until_rearm() {
        let (mut device, _mem) = restored_with_event_buffer();
        // This test isolates snapshot pause from the separate reset hold.
        device.rx_gate.release_transport_reset();
        device.quiesce_for_snapshot();
        let tx_event = device.queue_events[TXQ_INDEX].clone();
        tx_event.write(1).unwrap();
        device.process(
            &EpollEvent::new(EventSet::IN, tx_event.as_raw_fd() as u64),
            &mut EventManager::new().unwrap(),
        );
        assert!(device.deferred_tx);
        assert_eq!(
            tx_event.read().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        device.rearm_after_snapshot();
        assert!(!device.deferred_tx);
    }
}
