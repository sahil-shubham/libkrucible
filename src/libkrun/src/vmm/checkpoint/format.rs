//! The checkpoint directory.
//!
//! - `memory.bin`: guest RAM, regions back to back in guest-physical order,
//!   all-zero pages left as holes.
//! - `checkpoint.bin`: everything else. Written last, so its presence means
//!   the save completed.
//!
//! `checkpoint.bin` starts with a fixed header that anything can check
//! without parsing the rest (all little-endian): the 8-byte magic
//! `KRUNCKPT`, then u32 format version, u32 architecture, u32 hypervisor. The
//! host record (see [`super::compat`]) follows as a length-prefixed section,
//! then the body: the RAM layout, the vCPU count, the device list and the VM,
//! vCPU and device state. A checkpoint is only read back by a build of the same
//! format version (bumped whenever the record or the body changes), on a host
//! its record admits; other files in the directory are ignored.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

use vm_memory::GuestMemoryMmap;

use super::codec::{Decoder, Encoder};
use super::compat::HostRecord;
use super::memory::{self, RamRegion};
use crate::vmm::vstate::{VcpuState, VmState};

pub(crate) const CHECKPOINT_FILE: &str = "checkpoint.bin";
pub(crate) const MEMORY_FILE: &str = "memory.bin";

const MAGIC: &[u8; 8] = b"KRUNCKPT";
const VERSION: u32 = 2;

// Header platform codes.
const ARCH_X86_64: u32 = 1;
const ARCH_AARCH64: u32 = 2;
const HV_KVM: u32 = 1;
const HV_HVF: u32 = 2;

#[cfg(target_arch = "x86_64")]
const HOST: (u32, u32) = (ARCH_X86_64, HV_KVM);
#[cfg(target_arch = "aarch64")]
const HOST: (u32, u32) = (ARCH_AARCH64, HV_KVM);

fn platform_name((arch, hv): (u32, u32)) -> String {
    let arch = match arch {
        ARCH_X86_64 => "x86_64".to_string(),
        ARCH_AARCH64 => "aarch64".to_string(),
        n => format!("architecture {n}"),
    };
    let hv = match hv {
        HV_KVM => "KVM".to_string(),
        HV_HVF => "HVF".to_string(),
        n => format!("hypervisor {n}"),
    };
    format!("{arch}/{hv}")
}

/// A virtio device as the VM registered it: its type and id, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DeviceId {
    pub type_id: u32,
    pub id: String,
}

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:{}", self.id, self.type_id)
    }
}

/// Everything a checkpoint holds besides the RAM contents.
pub(crate) struct Checkpoint {
    /// The host the checkpoint was taken on and what it gave the guest.
    pub host: HostRecord,
    pub ram: Vec<RamRegion>,
    pub devices: Vec<DeviceId>,
    pub vm: VmState,
    pub vcpus: Vec<VcpuState>,
    /// The virtio devices' state, as the devices crate encodes it.
    pub device_state: Vec<u8>,
}

impl Checkpoint {
    fn encode(&self) -> Vec<u8> {
        let mut enc = Encoder::new();
        enc.raw(MAGIC);
        enc.u32(VERSION);
        enc.u32(HOST.0);
        enc.u32(HOST.1);
        let mut host = Encoder::new();
        self.host.encode(&mut host);
        enc.bytes(&host.into_bytes());
        enc.u32(self.ram.len() as u32);
        for r in &self.ram {
            enc.u64(r.gpa);
            enc.u64(r.len);
        }
        enc.u32(self.devices.len() as u32);
        for d in &self.devices {
            enc.u32(d.type_id);
            enc.bytes(d.id.as_bytes());
        }
        let mut vm = Encoder::new();
        self.vm.encode(&mut vm);
        enc.bytes(&vm.into_bytes());
        enc.u32(self.vcpus.len() as u32);
        for v in &self.vcpus {
            let mut vcpu = Encoder::new();
            v.encode(&mut vcpu);
            enc.bytes(&vcpu.into_bytes());
        }
        enc.bytes(&self.device_state);
        enc.into_bytes()
    }

    fn decode(buf: &[u8]) -> Result<Self, String> {
        let mut dec = Decoder::new(buf);
        if dec.raw(MAGIC.len()).ok() != Some(MAGIC.as_slice()) {
            return Err("not a checkpoint (bad magic)".into());
        }
        let version = dec.u32()?;
        if version != VERSION {
            return Err(format!(
                "unsupported checkpoint version {version} (this build reads version {VERSION})"
            ));
        }
        let platform = (dec.u32()?, dec.u32()?);
        if platform != HOST {
            return Err(format!(
                "checkpoint was taken on {}; this host is {}",
                platform_name(platform),
                platform_name(HOST)
            ));
        }
        let host = section(dec.bytes()?, HostRecord::decode)?;
        let ram = (0..dec.u32()?)
            .map(|_| {
                Ok(RamRegion {
                    gpa: dec.u64()?,
                    len: dec.u64()?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let devices = (0..dec.u32()?)
            .map(|_| {
                let type_id = dec.u32()?;
                let id = String::from_utf8(dec.bytes()?.to_vec())
                    .map_err(|_| "corrupt device id".to_string())?;
                Ok(DeviceId { type_id, id })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let vm = section(dec.bytes()?, VmState::decode)?;
        let vcpus = (0..dec.u32()?)
            .map(|_| section(dec.bytes()?, VcpuState::decode))
            .collect::<Result<Vec<_>, String>>()?;
        let device_state = dec.bytes()?.to_vec();
        dec.finish()?;
        Ok(Checkpoint {
            host,
            ram,
            devices,
            vm,
            vcpus,
            device_state,
        })
    }

    /// Writes the checkpoint and `mem` into `dir`, which this creates and must
    /// not exist yet; every file and the directory are fsync'd before this
    /// returns. A failed save leaves no directory behind.
    pub(crate) fn save(&self, dir: &Path, mem: &GuestMemoryMmap) -> Result<(), String> {
        self.save_with(dir, |file| memory::write(mem, file))
    }

    fn save_with(
        &self,
        dir: &Path,
        write_memory: impl FnOnce(&File) -> std::io::Result<()>,
    ) -> Result<(), String> {
        std::fs::create_dir(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        self.publish(dir, write_memory).inspect_err(|_| {
            let _ = std::fs::remove_dir_all(dir);
        })
    }

    fn publish(
        &self,
        dir: &Path,
        write_memory: impl FnOnce(&File) -> std::io::Result<()>,
    ) -> Result<(), String> {
        let create = |name: &str| {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(dir.join(name))
                .map_err(|e| format!("create {name}: {e}"))
        };
        let memory_tmp = format!("{MEMORY_FILE}.partial");
        let file = create(&memory_tmp)?;
        write_memory(&file).map_err(|e| format!("write {MEMORY_FILE}: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("sync {MEMORY_FILE}: {e}"))?;

        let checkpoint_tmp = format!("{CHECKPOINT_FILE}.partial");
        let mut file = create(&checkpoint_tmp)?;
        file.write_all(&self.encode())
            .and_then(|_| file.sync_all())
            .map_err(|e| format!("write {CHECKPOINT_FILE}: {e}"))?;

        let rename = |from: &str, to: &str| {
            std::fs::rename(dir.join(from), dir.join(to)).map_err(|e| format!("publish {to}: {e}"))
        };
        rename(&memory_tmp, MEMORY_FILE)?;
        // Last: its presence marks a complete checkpoint.
        rename(&checkpoint_tmp, CHECKPOINT_FILE)?;
        File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(|e| format!("sync {}: {e}", dir.display()))
    }

    /// Reads and decodes the checkpoint in `dir`, without its RAM image.
    pub(crate) fn read(dir: &Path) -> Result<Self, String> {
        let buf = std::fs::read(dir.join(CHECKPOINT_FILE)).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => format!(
                "incomplete checkpoint: {} has no {CHECKPOINT_FILE} (an unfinished or failed save?)",
                dir.display()
            ),
            _ => format!("read {CHECKPOINT_FILE}: {e}"),
        })?;
        Self::decode(&buf).map_err(|e| format!("{CHECKPOINT_FILE}: {e}"))
    }

    /// Reads the checkpoint in `dir` and opens its RAM image (read-only: a
    /// restore never writes the checkpoint).
    pub(crate) fn load(dir: &Path) -> Result<(Self, File), String> {
        let checkpoint = Self::read(dir)?;
        let memory = File::open(dir.join(MEMORY_FILE)).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => format!(
                "incomplete checkpoint: {} has no {MEMORY_FILE} (an unfinished or failed save?)",
                dir.display()
            ),
            _ => format!("open {MEMORY_FILE}: {e}"),
        })?;
        let len = memory
            .metadata()
            .map_err(|e| format!("stat {MEMORY_FILE}: {e}"))?
            .len();
        let want = memory::image_len(&checkpoint.ram);
        if len != want {
            return Err(format!(
                "{MEMORY_FILE} is {len} bytes; the checkpoint's RAM layout needs {want}"
            ));
        }
        Ok((checkpoint, memory))
    }

    /// Refuses a VM with another vCPU count than the saved one.
    pub(crate) fn check_vcpus(&self, count: usize) -> Result<(), String> {
        match self.vcpus.len() {
            saved if saved == count => Ok(()),
            saved => Err(format!(
                "vCPU count differs: the checkpoint has {saved}, this VM has {count}"
            )),
        }
    }

    /// Refuses a VM whose guest RAM isn't laid out as the saved one's.
    pub(crate) fn check_ram(&self, layout: &[RamRegion]) -> Result<(), String> {
        if layout == self.ram {
            return Ok(());
        }
        let list = |regions: &[RamRegion]| {
            regions
                .iter()
                .map(|r| format!("{:#x}+{:#x}", r.gpa, r.len))
                .collect::<Vec<_>>()
                .join(", ")
        };
        Err(format!(
            "RAM layout differs: the checkpoint has [{}], this VM has [{}]",
            list(&self.ram),
            list(layout)
        ))
    }
}

/// Decodes a length-prefixed section that must be consumed exactly.
fn section<T>(
    bytes: &[u8],
    decode: impl FnOnce(&mut Decoder) -> Result<T, String>,
) -> Result<T, String> {
    let mut dec = Decoder::new(bytes);
    let value = decode(&mut dec)?;
    dec.finish()?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vmm::vstate::sample_states;
    use std::path::PathBuf;
    use vm_memory::{Bytes, GuestAddress};
    use vmm_sys_util::tempdir::TempDir;

    #[cfg(target_arch = "x86_64")]
    fn sample_host() -> HostRecord {
        use crate::vmm::checkpoint::compat::CAP_CLOCK_REALTIME;
        HostRecord::here(&[], 3_600_000, CAP_CLOCK_REALTIME, vec![0x10, 0x174])
    }

    #[cfg(target_arch = "aarch64")]
    fn sample_host() -> HostRecord {
        HostRecord {
            midr: 0x414f_d0b1,
            revidr: 0,
            page_size: 4096,
            counter_hz: 54_000_000,
            gic_version: 2,
            vcpu_features: 1 << 2,
            sve_vls: vec![],
            id_regs: vec![],
            regs: vec![0x6030_0000_0010_0000],
        }
    }

    /// The other architecture's header code, and the names of both.
    #[cfg(target_arch = "x86_64")]
    const FOREIGN: (u32, &str, &str) = (ARCH_AARCH64, "aarch64", "x86_64");
    #[cfg(target_arch = "aarch64")]
    const FOREIGN: (u32, &str, &str) = (ARCH_X86_64, "x86_64", "aarch64");

    fn sample() -> (Checkpoint, GuestMemoryMmap) {
        let mem =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000), (GuestAddress(0x10000), 0x2000)])
                .unwrap();
        mem.write_slice(b"ram", GuestAddress(0x1000)).unwrap();
        let (vm, vcpus) = sample_states(2);
        let checkpoint = Checkpoint {
            host: sample_host(),
            ram: memory::layout(&mem),
            devices: vec![
                DeviceId {
                    type_id: 2,
                    id: "root".into(),
                },
                DeviceId {
                    type_id: 19,
                    id: "vsock".into(),
                },
            ],
            vm,
            vcpus,
            device_state: br#"{"devices":[]}"#.to_vec(),
        };
        (checkpoint, mem)
    }

    fn saved() -> (TempDir, PathBuf, Vec<u8>) {
        let (checkpoint, mem) = sample();
        let tmp = TempDir::new().unwrap();
        let dir = tmp.as_path().join("ckpt");
        checkpoint.save(&dir, &mem).unwrap();
        (tmp, dir, checkpoint.encode())
    }

    #[test]
    fn a_saved_checkpoint_loads_back_identically() {
        let (_tmp, dir, encoded) = saved();
        let mut names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, [CHECKPOINT_FILE, MEMORY_FILE]);

        let (loaded, memory) = Checkpoint::load(&dir).unwrap();
        // Re-encoding gives the same bytes: every section round-tripped.
        assert_eq!(loaded.encode(), encoded);
        assert_eq!(memory.metadata().unwrap().len(), 0x6000);
    }

    #[test]
    fn read_takes_only_the_checkpoint_file() {
        let (_tmp, dir, encoded) = saved();
        std::fs::remove_file(dir.join(MEMORY_FILE)).unwrap();
        assert_eq!(Checkpoint::read(&dir).unwrap().encode(), encoded);
        assert!(Checkpoint::load(&dir).is_err());
    }

    #[test]
    fn save_leaves_an_existing_directory_alone() {
        let (checkpoint, mem) = sample();
        let tmp = TempDir::new().unwrap();
        let dir = tmp.as_path().join("taken");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("keep"), b"x").unwrap();
        assert!(checkpoint.save(&dir, &mem).is_err());
        assert_eq!(std::fs::read(dir.join("keep")).unwrap(), b"x");
        assert!(!dir.join(CHECKPOINT_FILE).exists());
    }

    #[test]
    fn a_failed_save_leaves_no_directory() {
        let (checkpoint, _mem) = sample();
        let tmp = TempDir::new().unwrap();
        let dir = tmp.as_path().join("ckpt");
        // The RAM image half written when the disk fills up.
        let res = checkpoint.save_with(&dir, |file| {
            file.set_len(4096)?;
            Err(std::io::Error::from_raw_os_error(libc::ENOSPC))
        });
        assert!(res.unwrap_err().contains(MEMORY_FILE));
        assert!(!dir.exists(), "a failed save left {} behind", dir.display());
    }

    #[test]
    fn load_refuses_incomplete_foreign_and_damaged_checkpoints() {
        let patch = |dir: &PathBuf, at: usize, value: u32| {
            let mut buf = std::fs::read(dir.join(CHECKPOINT_FILE)).unwrap();
            buf[at..at + 4].copy_from_slice(&value.to_le_bytes());
            std::fs::write(dir.join(CHECKPOINT_FILE), buf).unwrap();
        };
        let (foreign_arch, foreign, here) = FOREIGN;
        let other_arch = format!("checkpoint was taken on {foreign}/KVM; this host is {here}/KVM");
        let other_hypervisor = format!("checkpoint was taken on {here}/HVF");
        let cases: Vec<(&str, Box<dyn Fn(&PathBuf)>)> = vec![
            (
                "incomplete checkpoint",
                Box::new(|d: &PathBuf| std::fs::remove_file(d.join(CHECKPOINT_FILE)).unwrap()),
            ),
            (
                "incomplete checkpoint",
                Box::new(|d: &PathBuf| std::fs::remove_file(d.join(MEMORY_FILE)).unwrap()),
            ),
            (
                "not a checkpoint",
                Box::new(|d: &PathBuf| std::fs::write(d.join(CHECKPOINT_FILE), b"KRUNCKP").unwrap()),
            ),
            (
                "unsupported checkpoint version 3",
                Box::new(move |d: &PathBuf| patch(d, 8, 3)),
            ),
            // Written before checkpoints carried a host record.
            (
                "unsupported checkpoint version 1",
                Box::new(move |d: &PathBuf| patch(d, 8, 1)),
            ),
            (
                &other_arch,
                Box::new(move |d: &PathBuf| patch(d, 12, foreign_arch)),
            ),
            (
                &other_hypervisor,
                Box::new(move |d: &PathBuf| patch(d, 16, HV_HVF)),
            ),
            (
                "trailing",
                Box::new(|d: &PathBuf| {
                    let mut buf = std::fs::read(d.join(CHECKPOINT_FILE)).unwrap();
                    buf.push(0);
                    std::fs::write(d.join(CHECKPOINT_FILE), buf).unwrap();
                }),
            ),
            (
                "memory.bin is 20480 bytes",
                Box::new(|d: &PathBuf| {
                    let f = OpenOptions::new().write(true).open(d.join(MEMORY_FILE)).unwrap();
                    f.set_len(0x5000).unwrap();
                }),
            ),
        ];
        for (want, damage) in cases {
            let (_tmp, dir, _) = saved();
            damage(&dir);
            let err = Checkpoint::load(&dir).err().expect("a damaged checkpoint loaded");
            assert!(err.contains(want), "want {want:?}, got {err:?}");
        }

        // Cut anywhere: never accepted, never a panic.
        let (_tmp, dir, encoded) = saved();
        for len in (0..encoded.len()).step_by(61) {
            std::fs::write(dir.join(CHECKPOINT_FILE), &encoded[..len]).unwrap();
            let err = Checkpoint::load(&dir).err().expect("a truncated checkpoint loaded");
            assert!(
                err.contains("truncated") || err.contains("not a checkpoint"),
                "cut at {len}: {err}"
            );
        }
    }
}
