//! Byte encoding for checkpoint sections.
//!
//! Little-endian and length-prefixed. Decoding is strict: every read is bounds
//! checked and a section must be consumed exactly, so a truncated or garbled
//! checkpoint is refused rather than restored as garbage.

/// Plain old data that is saved by copying its bytes.
///
/// # Safety
///
/// Implementors must be `#[repr(C)]` types made only of integers (and arrays
/// or unions of them): no pointers, references, `bool`s or enums, so that every
/// bit pattern read back from a file is a valid value. The KVM uapi structs
/// qualify.
pub(crate) unsafe trait Pod {}

unsafe impl Pod for u8 {}
unsafe impl Pod for u32 {}
unsafe impl Pod for u64 {}

/// Largest element count a decoded array may claim, so a corrupt count can't
/// make the decoder reserve gigabytes before the bounds check fails.
const MAX_ELEMENTS: usize = 1 << 16;

#[derive(Default)]
pub(crate) struct Encoder(Vec<u8>);

impl Encoder {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    pub(crate) fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    /// A length-prefixed byte string.
    pub(crate) fn bytes(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.0.extend_from_slice(b);
    }

    pub(crate) fn pod<T: Pod>(&mut self, v: &T) {
        // SAFETY: `T: Pod` has no padding-dependent invariants or pointers;
        // reading its bytes is sound.
        let bytes = unsafe {
            std::slice::from_raw_parts((v as *const T).cast::<u8>(), std::mem::size_of::<T>())
        };
        self.0.extend_from_slice(bytes);
    }

    /// A count-prefixed array.
    pub(crate) fn pods<T: Pod>(&mut self, v: &[T]) {
        self.u32(v.len() as u32);
        for e in v {
            self.pod(e);
        }
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

pub(crate) struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|end| *end <= self.buf.len())
            .ok_or_else(|| {
                format!(
                    "truncated: need {n} bytes at offset {}, have {}",
                    self.pos,
                    self.buf.len()
                )
            })?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub(crate) fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub(crate) fn bytes(&mut self) -> Result<&'a [u8], String> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    pub(crate) fn pod<T: Pod>(&mut self) -> Result<T, String> {
        let bytes = self.take(std::mem::size_of::<T>())?;
        // SAFETY: the slice holds exactly size_of::<T>() bytes, every bit
        // pattern is a valid `T: Pod`, and read_unaligned tolerates any
        // alignment.
        Ok(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) })
    }

    pub(crate) fn pods<T: Pod>(&mut self) -> Result<Vec<T>, String> {
        let count = self.u32()? as usize;
        if count > MAX_ELEMENTS {
            return Err(format!("corrupt: array claims {count} elements"));
        }
        (0..count).map(|_| self.pod()).collect()
    }

    /// Every byte must have been consumed: trailing data means the section
    /// isn't what this build wrote.
    pub(crate) fn finish(self) -> Result<(), String> {
        match self.buf.len() - self.pos {
            0 => Ok(()),
            n => Err(format!("corrupt: {n} unexpected trailing bytes")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, Default, PartialEq)]
    #[repr(C)]
    struct Regs {
        a: u64,
        b: [u32; 3],
    }
    unsafe impl Pod for Regs {}

    fn sample() -> Vec<u8> {
        let mut enc = Encoder::new();
        enc.u32(7);
        enc.bytes(b"vm");
        enc.pod(&Regs {
            a: 1 << 40,
            b: [1, 2, 3],
        });
        enc.pods(&[10u64, 20, 30]);
        enc.into_bytes()
    }

    #[test]
    fn round_trip() {
        let buf = sample();
        let mut dec = Decoder::new(&buf);
        assert_eq!(dec.u32().unwrap(), 7);
        assert_eq!(dec.bytes().unwrap(), b"vm");
        assert_eq!(
            dec.pod::<Regs>().unwrap(),
            Regs {
                a: 1 << 40,
                b: [1, 2, 3]
            }
        );
        assert_eq!(dec.pods::<u64>().unwrap(), vec![10, 20, 30]);
        dec.finish().unwrap();
    }

    #[test]
    fn every_truncation_is_refused() {
        let buf = sample();
        for len in 0..buf.len() {
            let mut dec = Decoder::new(&buf[..len]);
            let res = (|| {
                dec.u32()?;
                dec.bytes()?;
                dec.pod::<Regs>()?;
                dec.pods::<u64>()?;
                Ok::<_, String>(())
            })();
            let err = res.expect_err("a truncated buffer decoded");
            assert!(err.contains("truncated"), "{err}");
        }
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut buf = sample();
        buf.push(0);
        let mut dec = Decoder::new(&buf);
        dec.u32().unwrap();
        dec.bytes().unwrap();
        dec.pod::<Regs>().unwrap();
        dec.pods::<u64>().unwrap();
        assert!(dec.finish().unwrap_err().contains("trailing"));
    }

    #[test]
    fn absurd_counts_are_refused_before_allocating() {
        let mut enc = Encoder::new();
        enc.u32(u32::MAX);
        let buf = enc.into_bytes();
        let err = Decoder::new(&buf).pods::<u64>().unwrap_err();
        assert!(err.contains("corrupt"), "{err}");
    }
}
