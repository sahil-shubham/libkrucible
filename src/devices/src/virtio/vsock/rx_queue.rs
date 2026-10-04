use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use parking_lot::{Mutex, MutexGuard};

use super::snapshot_gate::{SnapshotActivity, SnapshotGate};
use crate::virtio::Queue;
use crate::virtio::queue::QueueState;

struct RxQueueInner {
    queue: Mutex<Queue>,
    gate: Arc<SnapshotGate>,
}

/// The gate and queue must travel together to every detached RX producer.
#[derive(Clone)]
pub(crate) struct RxQueue(Arc<RxQueueInner>);

pub(crate) struct RxQueueGuard<'a> {
    // Drop the queue mutex before marking this producer inactive.
    queue: MutexGuard<'a, Queue>,
    _activity: SnapshotActivity<'a>,
}

impl Deref for RxQueueGuard<'_> {
    type Target = Queue;

    fn deref(&self) -> &Queue {
        &self.queue
    }
}

impl DerefMut for RxQueueGuard<'_> {
    fn deref_mut(&mut self) -> &mut Queue {
        &mut self.queue
    }
}

impl RxQueue {
    pub(super) fn new(queue: Queue, gate: Arc<SnapshotGate>) -> Self {
        Self(Arc::new(RxQueueInner {
            queue: Mutex::new(queue),
            gate,
        }))
    }

    /// For worker threads, which may wait until snapshot/resume or guest reset.
    pub(crate) fn lock(&self) -> RxQueueGuard<'_> {
        let activity = self.0.gate.enter();
        let queue = self.0.queue.lock();
        RxQueueGuard {
            queue,
            _activity: activity,
        }
    }

    /// For the event loop: never wait for a gate or queue held by a worker.
    pub(crate) fn try_lock(&self) -> Option<RxQueueGuard<'_>> {
        let activity = self.0.gate.try_enter()?;
        let queue = self.0.queue.try_lock()?;
        Some(RxQueueGuard {
            queue,
            _activity: activity,
        })
    }

    /// The event loop has closed the gate and drained every producer first.
    pub(crate) fn save_state_paused(&self) -> QueueState {
        self.0.queue.lock().save_state()
    }

    /// Restore the ring only when producers are not running yet or are paused.
    pub(crate) fn restore_state_paused(&self, state: &QueueState) -> Result<(), String> {
        self.0.queue.lock().restore_state(state)
    }

    #[cfg(test)]
    fn gate(&self) -> &SnapshotGate {
        &self.0.gate
    }
}

#[cfg(test)]
mod tests {
    use super::RxQueue;
    use crate::virtio::Queue;
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn producer_waits_for_rearm_and_event_loop_does_not() {
        let queue = RxQueue::new(Queue::new(8), Arc::default());
        queue.gate().pause();
        assert!(queue.try_lock().is_none());
        let (entered_tx, entered_rx) = mpsc::channel();
        let worker_queue = queue.clone();
        let worker = thread::spawn(move || {
            let mut guard = worker_queue.lock();
            guard.next_avail = std::num::Wrapping(9);
            entered_tx.send(()).unwrap();
        });
        assert!(entered_rx.recv_timeout(Duration::from_millis(20)).is_err());
        queue.gate().resume();
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        worker.join().unwrap();
        assert_eq!(queue.lock().next_avail.0, 9);
    }
}
