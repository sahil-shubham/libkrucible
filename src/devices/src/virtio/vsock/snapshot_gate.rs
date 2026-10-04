use parking_lot::{Condvar, Mutex};

#[derive(Default)]
struct GateState {
    paused: bool,
    transport_reset: bool,
    active: usize,
}

/// Drain in-flight RX writers before capturing guest RAM and virtqueue indices.
#[derive(Default)]
pub(super) struct SnapshotGate {
    state: Mutex<GateState>,
    changed: Condvar,
}

impl SnapshotGate {
    pub(super) fn enter(&self) -> SnapshotActivity<'_> {
        let mut state = self.state.lock();
        while state.paused || state.transport_reset {
            self.changed.wait(&mut state);
        }
        state.active += 1;
        SnapshotActivity { gate: self }
    }

    /// Event-loop callers must not wait for a gate they themselves release.
    pub(super) fn try_enter(&self) -> Option<SnapshotActivity<'_>> {
        let mut state = self.state.lock();
        if state.paused || state.transport_reset {
            return None;
        }
        state.active += 1;
        Some(SnapshotActivity { gate: self })
    }

    pub(super) fn pause(&self) {
        let mut state = self.state.lock();
        state.paused = true;
        while state.active != 0 {
            self.changed.wait(&mut state);
        }
    }

    pub(super) fn resume(&self) {
        let mut state = self.state.lock();
        state.paused = false;
        self.changed.notify_all();
    }

    /// Fresh restore has no in-flight writers; wait until the guest handles reset.
    pub(super) fn hold_for_transport_reset(&self) {
        self.state.lock().transport_reset = true;
    }

    pub(super) fn release_transport_reset(&self) -> bool {
        let mut state = self.state.lock();
        if !state.transport_reset {
            return false;
        }
        state.transport_reset = false;
        self.changed.notify_all();
        true
    }

    pub(super) fn is_held_for_transport_reset(&self) -> bool {
        self.state.lock().transport_reset
    }
}

pub(super) struct SnapshotActivity<'a> {
    gate: &'a SnapshotGate,
}

impl Drop for SnapshotActivity<'_> {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock();
        state.active -= 1;
        if state.active == 0 {
            self.gate.changed.notify_all();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SnapshotGate;
    use std::sync::{Arc, mpsc};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn pause_waits_for_active_writer_and_blocks_new_writers() {
        let gate = Arc::new(SnapshotGate::default());
        let active = gate.enter();
        let (paused_tx, paused_rx) = mpsc::channel();
        let pause_gate = gate.clone();
        let pauser = thread::spawn(move || {
            pause_gate.pause();
            paused_tx.send(()).unwrap();
        });
        assert!(paused_rx.recv_timeout(Duration::from_millis(20)).is_err());
        drop(active);
        paused_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(gate.try_enter().is_none());
        let (entered_tx, entered_rx) = mpsc::channel();
        let enter_gate = gate.clone();
        let writer = thread::spawn(move || {
            let _activity = enter_gate.enter();
            entered_tx.send(()).unwrap();
        });
        assert!(entered_rx.recv_timeout(Duration::from_millis(20)).is_err());
        gate.resume();
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        pauser.join().unwrap();
        writer.join().unwrap();
    }

    #[test]
    fn transport_reset_hold_releases_producers() {
        let gate = Arc::new(SnapshotGate::default());
        gate.hold_for_transport_reset();
        assert!(gate.try_enter().is_none());
        let (entered_tx, entered_rx) = mpsc::channel();
        let writer_gate = gate.clone();
        let writer = thread::spawn(move || {
            let _activity = writer_gate.enter();
            entered_tx.send(()).unwrap();
        });
        assert!(entered_rx.recv_timeout(Duration::from_millis(20)).is_err());
        assert!(gate.release_transport_reset());
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(!gate.is_held_for_transport_reset());
        writer.join().unwrap();
    }
}
