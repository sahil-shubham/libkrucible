//! arm64 vCPU state for checkpoints: every register KVM lists for a vCPU, its
//! power state and pending exceptions, and the guest's virtual counter read
//! against wall-clock time, so a restore can move it on by the time the VM
//! spent saved.

use std::io;

use kvm_bindings::{
    KVM_REG_ARM64, KVM_REG_ARM64_SVE, KVM_REG_SIZE_MASK, KVM_REG_SIZE_SHIFT, KVM_REG_SIZE_U512,
    KVMIO, kvm_mp_state, kvm_reg_list, kvm_vcpu_events,
};
use kvm_ioctls::VcpuFd;
use vmm_sys_util::ioctl::ioctl_with_mut_ptr;

use crate::vmm::checkpoint::codec::{Decoder, Encoder, Pod};
use crate::vmm::checkpoint::compat::{reg_name, sysreg};

// kvm-ioctls caps the list at 500 registers; an SVE vCPU on a recent kernel
// can have more.
vmm_sys_util::ioctl_iowr_nr!(KVM_GET_REG_LIST, KVMIO, 0xb0, kvm_reg_list);

/// KVM's id for the guest's virtual counter, CNTVCT_EL0 (its encoding is
/// swapped with CNTV_CVAL_EL0's in KVM's ABI).
pub(crate) const TIMER_CNT: u64 = sysreg(3, 3, 14, 3, 2);
/// KVM's id for the guest's physical counter, CNTPCT_EL0.
pub(crate) const PTIMER_CNT: u64 = sysreg(3, 3, 14, 0, 1);
/// KVM_REG_ARM64_SVE_VLS: the vector lengths of an SVE vCPU.
pub(crate) const SVE_VLS: u64 =
    KVM_REG_ARM64 | KVM_REG_ARM64_SVE as u64 | KVM_REG_SIZE_U512 | 0xffff;

/// The widest register KVM has: an SVE Z register, 2048 bits.
const MAX_REG_BYTES: usize = 256;

/// How many bytes register `id` holds.
pub(crate) fn reg_bytes(id: u64) -> usize {
    1 << ((id & KVM_REG_SIZE_MASK) >> KVM_REG_SIZE_SHIFT)
}

/// A vCPU register: its KVM id and as many bytes of value as the id says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Reg {
    pub id: u64,
    pub value: Vec<u8>,
}

/// What a vCPU is created as, beyond its index.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VcpuShape {
    /// `kvm_vcpu_init` features (bit n: feature n), POWER_OFF aside.
    pub features: u32,
    /// With SVE: its vector lengths (KVM_REG_ARM64_SVE_VLS), which KVM only
    /// takes before the vCPU is finalized. Empty: all the host has.
    pub sve_vls: Vec<u64>,
}

/// The guest's virtual counter, read between two reads of the host's wall
/// clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CounterSample {
    /// CNTVCT_EL0.
    pub count: u64,
    /// When it read `count`: host CLOCK_REALTIME, in ns.
    pub realtime_ns: u64,
    /// The counter's frequency (CNTFRQ_EL0), in Hz.
    pub hz: u32,
}

impl CounterSample {
    /// The counter at wall-clock time `now_ns`, had it kept counting since
    /// the sample: a restore loads this, so the guest's clocks show the time
    /// that passed while it was saved and its timers expire as if it had run
    /// on. Never earlier than the sample, should the host's clock step back.
    pub(crate) fn at(&self, now_ns: u64) -> u64 {
        let elapsed = u128::from(now_ns.saturating_sub(self.realtime_ns));
        let ticks = elapsed * u128::from(self.hz) / 1_000_000_000;
        self.count.wrapping_add(ticks as u64)
    }
}

/// The frequency of the generic timer's counter (CNTFRQ_EL0). KVM doesn't
/// virtualise it: a guest reads the host's.
pub(crate) fn counter_hz() -> u32 {
    let hz: u64;
    // SAFETY: reads a system register into a local; Linux lets EL0 read
    // CNTFRQ_EL0 (or emulates the read).
    unsafe {
        std::arch::asm!("mrs {}, cntfrq_el0", out(reg) hz, options(nomem, nostack, preserves_flags))
    };
    hz as u32
}

/// The ids of every register KVM lists for `vcpu`, which must be initialized
/// (and finalized, with SVE).
pub(crate) fn reg_list(vcpu: &VcpuFd) -> Result<Vec<u64>, String> {
    let mut capacity = 0;
    loop {
        // A kvm_reg_list: the count, then that many ids.
        let mut list = vec![0u64; capacity + 1];
        list[0] = capacity as u64;
        // SAFETY: `list` holds a kvm_reg_list with room for `capacity` ids;
        // KVM writes the count and at most that many ids into it.
        if unsafe { ioctl_with_mut_ptr(vcpu, KVM_GET_REG_LIST(), list.as_mut_ptr()) } == 0 {
            let count = list[0] as usize;
            list.truncate(count + 1);
            list.remove(0);
            return Ok(list);
        }
        let err = io::Error::last_os_error();
        // E2BIG: KVM wrote how many ids it has.
        match err.raw_os_error() {
            Some(libc::E2BIG) if list[0] as usize > capacity => capacity = list[0] as usize,
            _ => return Err(format!("list the vCPU's registers: {err}")),
        }
    }
}

/// Every register KVM lists for `vcpu`, with its value.
pub(crate) fn read_regs(vcpu: &VcpuFd) -> Result<Vec<Reg>, String> {
    reg_list(vcpu)?
        .into_iter()
        .map(|id| {
            let len = reg_bytes(id);
            if len > MAX_REG_BYTES {
                return Err(format!("{}: a {len}-byte register", reg_name(id)));
            }
            let mut value = vec![0u8; len];
            vcpu.get_one_reg(id, &mut value)
                .map_err(|e| format!("read {}: {e}", reg_name(id)))?;
            Ok(Reg { id, value })
        })
        .collect()
}

/// The value of the 64-bit register `id`.
pub(crate) fn read_u64(vcpu: &VcpuFd, id: u64) -> Result<u64, String> {
    let mut value = [0u8; 8];
    vcpu.get_one_reg(id, &mut value)
        .map_err(|e| format!("read {}: {e}", reg_name(id)))?;
    Ok(u64::from_le_bytes(value))
}

/// Reads the guest's virtual counter between two reads of the host's wall
/// clock.
pub(crate) fn sample_counter(vcpu: &VcpuFd) -> Result<CounterSample, String> {
    let before = super::vstate::realtime_ns().map_err(|e| e.to_string())?;
    let count = read_u64(vcpu, TIMER_CNT)?;
    let after = super::vstate::realtime_ns().map_err(|e| e.to_string())?;
    Ok(CounterSample {
        count,
        realtime_ns: super::vstate::midpoint(before, after).map_err(|e| e.to_string())?,
        hz: counter_hz(),
    })
}

/// A vCPU's state as KVM holds it.
pub struct VcpuState {
    /// What the vCPU was created as (see [`VcpuShape::features`]).
    pub(crate) features: u32,
    /// Every register KVM lists for the vCPU, in KVM's order.
    pub(crate) regs: Vec<Reg>,
    /// Running, or powered off (PSCI).
    pub(crate) mp_state: kvm_mp_state,
    /// Pending SError and external aborts.
    pub(crate) events: kvm_vcpu_events,
    pub(crate) counter: CounterSample,
}

impl std::fmt::Debug for VcpuState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // Hundreds of registers; a marker keeps `VcpuEvent: Debug` cheap.
        f.write_str("VcpuState { .. }")
    }
}

// SAFETY: KVM uapi structs: #[repr(C)] integers and arrays of them.
unsafe impl Pod for kvm_mp_state {}
unsafe impl Pod for kvm_vcpu_events {}

impl VcpuState {
    /// The value of register `id`, if the state holds it.
    pub(crate) fn reg(&self, id: u64) -> Option<&[u8]> {
        self.regs
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.value.as_slice())
    }

    pub(crate) fn reg_u64(&self, id: u64) -> Option<u64> {
        self.reg(id)
            .and_then(|v| v.try_into().ok())
            .map(u64::from_le_bytes)
    }

    pub(crate) fn encode(&self, enc: &mut Encoder) {
        enc.u32(self.features);
        enc.u32(self.regs.len() as u32);
        for r in &self.regs {
            enc.u64(r.id);
            enc.raw(&r.value);
        }
        enc.pod(&self.mp_state);
        enc.pod(&self.events);
        enc.u64(self.counter.count);
        enc.u64(self.counter.realtime_ns);
        enc.u32(self.counter.hz);
    }

    pub(crate) fn decode(dec: &mut Decoder) -> Result<Self, String> {
        let features = dec.u32()?;
        let count = dec.u32()?;
        let regs = (0..count)
            .map(|_| {
                let id = dec.u64()?;
                let len = reg_bytes(id);
                if len > MAX_REG_BYTES {
                    return Err(format!("corrupt register id {id:#x}"));
                }
                Ok(Reg {
                    id,
                    value: dec.raw(len)?.to_vec(),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(VcpuState {
            features,
            regs,
            mp_state: dec.pod()?,
            events: dec.pod()?,
            counter: CounterSample {
                count: dec.u64()?,
                realtime_ns: dec.u64()?,
                hz: dec.u32()?,
            },
        })
    }
}

/// Registers a restore doesn't write back as saved: the SVE vector lengths
/// are set when the vCPU is created (KVM takes them only before the vCPU is
/// finalized); the guest's virtual counter is loaded last, moved on by the
/// time since the save; and its physical counter stays the host's, since
/// writing it would make KVM trap the guest's every use of it and of the
/// physical timer.
pub(crate) fn restored_as_saved(id: u64) -> bool {
    !matches!(id, SVE_VLS | TIMER_CNT | PTIMER_CNT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_counter_moves_on_by_the_wall_clock_gap() {
        let sample = CounterSample {
            count: 1_000,
            realtime_ns: 5_000_000_000,
            hz: 54_000_000,
        };
        assert_eq!(sample.at(5_000_000_000), 1_000);
        // 65 s at 54 MHz.
        assert_eq!(sample.at(70_000_000_000), 1_000 + 65 * 54_000_000);
        // A host clock that stepped back never winds the guest's back.
        assert_eq!(sample.at(4_000_000_000), 1_000);
        // Across the counter's wrap.
        let near_wrap = CounterSample {
            count: u64::MAX,
            ..sample
        };
        assert_eq!(near_wrap.at(5_000_000_000 + 1_000_000_000), 54_000_000 - 1);
    }

    #[test]
    fn register_widths_follow_their_ids() {
        assert_eq!(reg_bytes(TIMER_CNT), 8);
        assert_eq!(reg_bytes(SVE_VLS), 64);
        assert!(!restored_as_saved(PTIMER_CNT));
        assert!(restored_as_saved(sysreg(3, 0, 13, 0, 4)));
    }

    #[test]
    fn this_host_has_a_counter_frequency() {
        assert!(counter_hz() > 0);
    }
}
