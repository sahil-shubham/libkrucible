//! Guest RAM in a checkpoint: written to `memory.bin` with all-zero pages left
//! as holes, and mapped back copy-on-write on restore.

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;

use vm_memory::{
    FileOffset, GuestAddress, GuestMemoryBackend, GuestMemoryMmap, GuestMemoryRegion,
    GuestRegionMmap, MmapRegion,
};

/// One guest RAM region. `memory.bin` holds the regions back to back, in
/// guest-physical order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RamRegion {
    pub gpa: u64,
    pub len: u64,
}

const PAGE: usize = 4096;

/// The guest's RAM regions, in guest-physical order.
pub(crate) fn layout(mem: &GuestMemoryMmap) -> Vec<RamRegion> {
    mem.iter()
        .map(|r| RamRegion {
            gpa: r.start_addr().0,
            len: r.len(),
        })
        .collect()
}

/// The size `memory.bin` must have for `layout`.
pub(crate) fn image_len(layout: &[RamRegion]) -> u64 {
    layout.iter().map(|r| r.len).sum()
}

/// Writes guest RAM to the empty `file`. Nothing may write guest memory
/// meanwhile: the vCPUs are parked and the devices quiesced.
pub(crate) fn write(mem: &GuestMemoryMmap, file: &File) -> io::Result<()> {
    let mut base = 0u64;
    for region in mem.iter() {
        let len = region.len() as usize;
        // SAFETY: the region maps `len` bytes at `as_ptr()` for as long as
        // `mem` lives, and nothing writes them while they are saved.
        let bytes = unsafe { std::slice::from_raw_parts(region.as_ptr(), len) };
        // A guest touches a fraction of its RAM; skipping the rest keeps
        // the file (and the time to fsync it) proportional to what it uses.
        let mut run: Option<usize> = None;
        for (i, page) in bytes.chunks(PAGE).enumerate() {
            match (is_zero(page), run) {
                (false, None) => run = Some(i * PAGE),
                (true, Some(start)) => {
                    file.write_all_at(&bytes[start..i * PAGE], base + start as u64)?;
                    run = None;
                }
                _ => {}
            }
        }
        if let Some(start) = run {
            file.write_all_at(&bytes[start..], base + start as u64)?;
        }
        base += len as u64;
    }
    file.set_len(base)
}

fn is_zero(page: &[u8]) -> bool {
    // SAFETY: any bytes are a valid u64.
    let (head, words, tail) = unsafe { page.align_to::<u64>() };
    head.iter().all(|b| *b == 0) && words.iter().all(|w| *w == 0) && tail.iter().all(|b| *b == 0)
}

/// Maps `memory.bin` as the guest's RAM, private and writable: the guest's
/// writes are copied on write and never reach the file, so the checkpoint
/// stays intact and any number of restores of it share its page cache.
pub(crate) fn map_private(file: &File, layout: &[RamRegion]) -> io::Result<GuestMemoryMmap> {
    let mut offset = 0u64;
    let mut regions = Vec::with_capacity(layout.len());
    for r in layout {
        let len = usize::try_from(r.len).map_err(io::Error::other)?;
        let mapping = MmapRegion::build(
            Some(FileOffset::new(file.try_clone()?, offset)),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_NORESERVE,
        )
        .map_err(io::Error::other)?;
        regions.push(
            GuestRegionMmap::new(mapping, GuestAddress(r.gpa))
                .ok_or_else(|| io::Error::other(format!("RAM region {r:?} overflows")))?,
        );
        offset += r.len;
    }
    GuestMemoryMmap::from_regions(regions).map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use vm_memory::Bytes;

    fn guest() -> GuestMemoryMmap {
        let mem = GuestMemoryMmap::from_ranges(&[
            (GuestAddress(0), 64 * PAGE),
            (GuestAddress(0x10_0000), 64 * PAGE),
        ])
        .unwrap();
        mem.write_slice(b"first page", GuestAddress(0)).unwrap();
        // A run of non-zero pages, and the last page of the first region.
        mem.write_slice(&[0xab; 3 * PAGE], GuestAddress(5 * PAGE as u64))
            .unwrap();
        mem.write_slice(b"tail", GuestAddress(64 * PAGE as u64 - 4))
            .unwrap();
        mem.write_slice(b"high", GuestAddress(0x10_0000 + 7 * PAGE as u64))
            .unwrap();
        mem
    }

    fn read(mem: &GuestMemoryMmap, gpa: u64, len: usize) -> Vec<u8> {
        let mut buf = vec![0; len];
        mem.read_slice(&mut buf, GuestAddress(gpa)).unwrap();
        buf
    }

    #[test]
    fn ram_round_trips_sparsely() {
        let src = guest();
        let file = utils::tempfile::TempFile::new().unwrap();
        write(&src, file.as_file()).unwrap();

        let meta = file.as_file().metadata().unwrap();
        assert_eq!(meta.len(), image_len(&layout(&src)));
        // 6 non-zero pages of 128: the zero pages are holes.
        assert!(meta.blocks() * 512 <= 16 * PAGE as u64, "{} blocks", meta.blocks());

        let restored = map_private(file.as_file(), &layout(&src)).unwrap();
        assert_eq!(layout(&restored), layout(&src));
        for (gpa, len) in [(0, 64 * PAGE), (0x10_0000, 64 * PAGE)] {
            assert_eq!(read(&restored, gpa, len), read(&src, gpa, len));
        }
    }

    /// The guest's writes must stay in its own copy: the checkpoint can be
    /// restored again, and every restore starts from what was saved.
    #[test]
    fn restored_ram_never_writes_the_checkpoint() {
        let src = guest();
        let file = utils::tempfile::TempFile::new().unwrap();
        write(&src, file.as_file()).unwrap();
        let before = std::fs::read(file.as_path()).unwrap();

        let first = map_private(file.as_file(), &layout(&src)).unwrap();
        first
            .write_slice(b"diverged", GuestAddress(0x10_0000))
            .unwrap();
        first.write_slice(b"also", GuestAddress(0)).unwrap();
        drop(first);

        assert_eq!(std::fs::read(file.as_path()).unwrap(), before);
        let second = map_private(file.as_file(), &layout(&src)).unwrap();
        assert_eq!(read(&second, 0, 10), b"first page");
        assert_eq!(read(&second, 0x10_0000, 8), [0; 8]);
    }
}
