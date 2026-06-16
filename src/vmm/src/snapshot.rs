// Copyright 2026. SPDX-License-Identifier: Apache-2.0
//
//! Guest-memory checkpoint: serialize/restore guest RAM to a byte stream.
//!
//! Platform-neutral by design — it operates only on the `GuestMemoryMmap` host
//! mapping and `std::io`, so the same code serves both the KVM (Linux) and HVF
//! (macOS) snapshot paths. This eager byte-copy path is the cold-to-disk
//! baseline: a self-contained memory image that survives the VMM process
//! exiting (unlike a CoW clone, which shares a live parent's pages).
//!
//! A full VM checkpoint composes three parts: this guest-memory image, the
//! paused-vCPU register state (`vstate` save_state), and the virtio device
//! state (`devices::virtio::persist`).

use std::io::{self, Read, Write};

use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryRegion, GuestMemoryMmap};

/// Describes one guest-RAM region in a memory snapshot: where it maps in guest
/// physical address space and how many bytes it holds. The region bytes follow
/// in the memory stream in region order; the descriptors carry the lengths, so
/// the byte stream itself needs no per-region framing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryRegionDesc {
    /// Guest physical base address of the region.
    pub gpa: u64,
    /// Region length in bytes.
    pub len: u64,
}

/// Serialize all guest-memory regions to `out`, returning the region layout the
/// restore side needs (each region's guest address + length). Bytes are written
/// in region order with no per-region framing.
///
/// The caller must have paused the vCPUs (and drained device workers) first so
/// the bytes are captured at a stable, consistent boundary.
pub fn write_guest_memory<W: Write>(
    mem: &GuestMemoryMmap,
    out: &mut W,
) -> io::Result<Vec<MemoryRegionDesc>> {
    let mut descs = Vec::new();
    for region in mem.iter() {
        let gpa = region.start_addr();
        let len = region.len();
        let host = mem
            .get_host_address(gpa)
            .map_err(|e| io::Error::other(format!("get_host_address: {e:?}")))?;
        // Safety: `host` points to `len` bytes of live guest RAM owned by the
        // mmap region currently being iterated. The VM is paused, so the bytes
        // are stable for the duration of the copy.
        let bytes = unsafe { std::slice::from_raw_parts(host as *const u8, len as usize) };
        out.write_all(bytes)?;
        descs.push(MemoryRegionDesc {
            gpa: gpa.raw_value(),
            len,
        });
    }
    Ok(descs)
}

/// Load guest-memory bytes from `inp` back into `mem`, using the region layout
/// captured by [`write_guest_memory`]. Each region's bytes are read directly
/// into the live host mapping. `mem` must have been built with a layout that
/// covers every `desc.gpa..desc.gpa+desc.len` range (i.e. the same VM config).
///
/// Must be called before the restored vCPUs are resumed.
pub fn read_guest_memory_into<R: Read>(
    mem: &GuestMemoryMmap,
    descs: &[MemoryRegionDesc],
    inp: &mut R,
) -> io::Result<()> {
    for desc in descs {
        let host = mem
            .get_host_address(GuestAddress(desc.gpa))
            .map_err(|e| io::Error::other(format!("get_host_address: {e:?}")))?;
        // Safety: `host` points to `desc.len` bytes of guest RAM for this
        // region, and the VM is not yet running, so writing into it is sound.
        let dst = unsafe { std::slice::from_raw_parts_mut(host, desc.len as usize) };
        inp.read_exact(dst)?;
    }
    Ok(())
}

/// Total byte length of all regions in a descriptor list (the size of the
/// memory image stream).
pub fn memory_image_len(descs: &[MemoryRegionDesc]) -> u64 {
    descs.iter().map(|d| d.len).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    #[test]
    fn test_guest_memory_snapshot_roundtrip_single_region() {
        let size = 0x20000usize; // 128 KiB
        let src = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), size)]).unwrap();

        // Write a recognizable, non-trivial pattern across the whole region.
        let pattern: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        src.write_slice(&pattern, GuestAddress(0)).unwrap();

        // Dump to an in-memory stream.
        let mut buf = Vec::new();
        let descs = write_guest_memory(&src, &mut buf).unwrap();
        assert_eq!(descs.len(), 1);
        assert_eq!(descs[0].gpa, 0);
        assert_eq!(descs[0].len as usize, size);
        assert_eq!(buf.len(), size);
        assert_eq!(memory_image_len(&descs) as usize, size);

        // Restore into a fresh, zeroed guest memory.
        let dst = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), size)]).unwrap();
        read_guest_memory_into(&dst, &descs, &mut buf.as_slice()).unwrap();

        let mut got = vec![0u8; size];
        dst.read_slice(&mut got, GuestAddress(0)).unwrap();
        assert_eq!(got, pattern, "restored bytes must match the snapshot");
    }

    #[test]
    fn test_guest_memory_snapshot_roundtrip_multi_region() {
        // Two regions separated by a gap in guest physical space.
        let regions = [
            (GuestAddress(0), 0x10000usize),
            (GuestAddress(0x100000), 0x8000usize),
        ];
        let src = GuestMemoryMmap::from_ranges(&regions).unwrap();
        src.write_slice(&[0xAB; 0x10000], GuestAddress(0)).unwrap();
        src.write_slice(&[0xCD; 0x8000], GuestAddress(0x100000))
            .unwrap();

        let mut buf = Vec::new();
        let descs = write_guest_memory(&src, &mut buf).unwrap();
        assert_eq!(descs.len(), 2);
        assert_eq!(buf.len(), 0x10000 + 0x8000);

        let dst = GuestMemoryMmap::from_ranges(&regions).unwrap();
        read_guest_memory_into(&dst, &descs, &mut buf.as_slice()).unwrap();

        let mut got_lo = vec![0u8; 0x10000];
        let mut got_hi = vec![0u8; 0x8000];
        dst.read_slice(&mut got_lo, GuestAddress(0)).unwrap();
        dst.read_slice(&mut got_hi, GuestAddress(0x100000)).unwrap();
        assert_eq!(got_lo, vec![0xAB; 0x10000]);
        assert_eq!(got_hi, vec![0xCD; 0x8000]);
    }

    // The aggregated device state is serialized into the on-disk checkpoint and
    // read back on restore; the JSON roundtrip must be lossless across device
    // variants, their negotiated features, and per-queue ring positions.
    #[test]
    fn test_device_state_roundtrip() {
        use devices::virtio::persist::{DeviceSnapshot, VmDevicesState};
        use devices::virtio::QueueState;
        use devices::virtio::{ConsoleState, RngState, VsockState};

        let qs = QueueState {
            size: 256,
            ready: true,
            desc_table: 0x1000,
            avail_ring: 0x2000,
            used_ring: 0x3000,
            next_avail: 42,
            next_used: 41,
            event_idx_enabled: true,
            num_added: 7,
        };
        let state = VmDevicesState {
            devices: vec![
                DeviceSnapshot::Console(ConsoleState {
                    acked_features: 0xABCD,
                    activated: true,
                    queues: vec![Some(qs.clone()), None],
                }),
                DeviceSnapshot::Vsock(VsockState {
                    cid: 7,
                    acked_features: 0x1234,
                    activated: true,
                    queue_rx: Some(qs.clone()),
                    queue_tx: Some(qs.clone()),
                }),
                DeviceSnapshot::Rng(RngState {
                    acked_features: 0x9,
                    queue: Some(qs),
                }),
            ],
        };
        let bytes = state.to_bytes().expect("serialize");
        let restored = VmDevicesState::from_bytes(&bytes).expect("deserialize");
        assert_eq!(state, restored, "device state must round-trip through bytes");
    }

    #[test]
    fn test_short_stream_is_an_error() {
        let size = 0x4000usize;
        let descs = [MemoryRegionDesc {
            gpa: 0,
            len: size as u64,
        }];
        let dst = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), size)]).unwrap();
        // Stream has fewer bytes than the descriptor claims -> read_exact errors.
        let truncated = vec![0u8; size - 1];
        let err = read_guest_memory_into(&dst, &descs, &mut truncated.as_slice()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
