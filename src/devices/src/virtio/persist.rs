//! VM checkpoint device state. Unsupported devices intentionally return `None`
//! so the VMM refuses snapshots that it cannot reconstruct.

use super::VirtioDevice;
#[cfg(feature = "blk")]
use super::block::{Block, BlockState};
use super::console::{Console, ConsoleState};
#[cfg(feature = "net")]
use super::net::{Net, NetState};
use super::queue::QueueState;
use super::vsock::{Vsock, VsockState};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DeviceSnapshot {
    Console(ConsoleState),
    Vsock(VsockState),
    #[cfg(feature = "blk")]
    Block(BlockState),
    #[cfg(feature = "net")]
    Net(NetState),
}

impl DeviceSnapshot {
    pub fn device_type(&self) -> u32 {
        match self {
            Self::Console(_) => super::TYPE_CONSOLE,
            Self::Vsock(_) => super::TYPE_VSOCK,
            #[cfg(feature = "blk")]
            Self::Block(_) => super::TYPE_BLOCK,
            #[cfg(feature = "net")]
            Self::Net(_) => super::TYPE_NET,
        }
    }

    pub fn acked_features(&self) -> u64 {
        match self {
            Self::Console(s) => s.acked_features,
            Self::Vsock(s) => s.acked_features,
            #[cfg(feature = "blk")]
            Self::Block(s) => s.acked_features,
            #[cfg(feature = "net")]
            Self::Net(s) => s.acked_features,
        }
    }

    /// Queue index order matches the guest's MMIO queue selector.
    pub fn queue_states(&self) -> Vec<Option<QueueState>> {
        match self {
            Self::Console(s) => s.queues.clone(),
            Self::Vsock(s) => vec![s.queue_rx.clone(), s.queue_tx.clone(), s.queue_ev.clone()],
            #[cfg(feature = "blk")]
            Self::Block(s) => vec![s.queue.clone()],
            #[cfg(feature = "net")]
            Self::Net(s) => vec![s.queue_rx.clone(), s.queue_tx.clone()],
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VmDevicesState {
    pub devices: Vec<DeviceSnapshot>,
    /// Saved MMIO interrupt bits, positionally paired with `devices`.
    pub interrupt_status: Vec<u32>,
}

impl VmDevicesState {
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| format!("serialize device state: {e}"))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|e| format!("deserialize device state: {e}"))
    }
}

pub fn snapshot_device(dev: &dyn VirtioDevice) -> Option<DeviceSnapshot> {
    let any = dev.as_any();
    if let Some(d) = any.downcast_ref::<Console>() {
        return Some(DeviceSnapshot::Console(d.save_state()));
    }
    if let Some(d) = any.downcast_ref::<Vsock>() {
        return Some(DeviceSnapshot::Vsock(d.save_state()));
    }
    #[cfg(feature = "blk")]
    if let Some(d) = any.downcast_ref::<Block>() {
        return Some(DeviceSnapshot::Block(d.save_state()));
    }
    #[cfg(feature = "net")]
    if let Some(d) = any.downcast_ref::<Net>() {
        return Some(DeviceSnapshot::Net(d.save_state()));
    }
    None
}

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
        #[cfg(feature = "blk")]
        DeviceSnapshot::Block(s) => any
            .downcast_mut::<Block>()
            .ok_or_else(|| "snapshot/device mismatch: expected Block".to_string())?
            .restore_state(s),
        #[cfg(feature = "net")]
        DeviceSnapshot::Net(s) => any
            .downcast_mut::<Net>()
            .ok_or_else(|| "snapshot/device mismatch: expected Net".to_string())?
            .restore_state(s),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(feature = "blk", feature = "net"))]
    #[test]
    fn all_device_states_round_trip_with_queue_order_and_interrupts() {
        let rx = QueueState {
            size: 8,
            ready: true,
            next_avail: 7,
            next_used: 6,
            ..QueueState::default()
        };
        let tx = QueueState {
            next_avail: 19,
            ..rx.clone()
        };
        let ev = QueueState {
            next_avail: 21,
            ..rx.clone()
        };
        let state = VmDevicesState {
            devices: vec![
                DeviceSnapshot::Console(ConsoleState {
                    acked_features: 1,
                    activated: true,
                    queues: vec![Some(rx.clone()), None],
                    pending_control: vec![vec![7, 8, 9]],
                }),
                DeviceSnapshot::Vsock(VsockState {
                    cid: 123,
                    acked_features: 2,
                    activated: true,
                    queue_rx: Some(rx.clone()),
                    queue_tx: Some(tx.clone()),
                    queue_ev: Some(ev.clone()),
                }),
                DeviceSnapshot::Block(BlockState {
                    acked_features: 3,
                    activated: true,
                    disk_image_id: vec![1, 2, 3],
                    capacity: 512,
                    queue: Some(rx.clone()),
                }),
                DeviceSnapshot::Net(NetState {
                    acked_features: 4,
                    activated: true,
                    queue_rx: Some(rx.clone()),
                    queue_tx: Some(tx.clone()),
                }),
            ],
            interrupt_status: vec![1, 2, 0, 1],
        };
        let restored = VmDevicesState::from_bytes(&state.to_bytes().unwrap()).unwrap();
        assert_eq!(restored, state);
        assert_eq!(
            restored.devices[1].queue_states(),
            vec![Some(rx), Some(tx), Some(ev)]
        );
        assert_eq!(restored.devices[3].acked_features(), 4);
    }

    #[test]
    fn mismatched_restore_is_rejected_without_touching_device() {
        let mut console = Console::new(vec![super::super::console::PortDescription {
            name: String::new().into(),
            input: None,
            output: None,
            terminal: None,
        }])
        .unwrap();
        let snapshot = DeviceSnapshot::Vsock(VsockState {
            acked_features: 0x50,
            ..VsockState::default()
        });
        assert!(restore_device(&mut console, &snapshot).is_err());
        assert_eq!(console.acked_features(), 0);
    }

    #[cfg(not(feature = "tee"))]
    #[test]
    fn unsupported_rng_refuses_checkpoint() {
        let rng = super::super::Rng::new().unwrap();
        assert!(snapshot_device(&rng).is_none());
    }
}
