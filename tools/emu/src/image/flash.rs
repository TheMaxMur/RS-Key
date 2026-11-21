// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The flash array behind the QMI model, optionally backed by a file:
//! `--store` for this backend is the whole chip, image and KV store together.
//! Placing an image rewrites only the sectors it covers, so the KV store stays.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use super::elf::Elf;

pub const FLASH_SIZE: usize = 4 * 1024 * 1024;
const MIN_FLASH_SIZE: usize = 2 * 1024 * 1024;
const MAX_FLASH_SIZE: usize = 16 * 1024 * 1024;
pub const XIP_BASE: u32 = 0x1000_0000;
/// The end of the XIP window; the flash backing occupies its beginning.
const XIP_END: u32 = 0x1400_0000;
const SECTOR: usize = 4096;

fn capacity(elf: &Elf) -> Result<usize, String> {
    let Some(end) = elf.symbols.iter().find(|s| s.name == "__kvcnt_end") else {
        return Ok(FLASH_SIZE);
    };
    let end = end.value as usize;
    // The 16 MiB linker layout leaves the E10 absolute-block sector outside KV.
    if end == MAX_FLASH_SIZE - SECTOR {
        return Ok(MAX_FLASH_SIZE);
    }
    if end.is_power_of_two() && (MIN_FLASH_SIZE..=MAX_FLASH_SIZE).contains(&end) {
        return Ok(end);
    }
    Err(format!("unsupported flash boundary __kvcnt_end={end:#x}"))
}

pub struct Flash {
    file: Option<File>,
    bytes: Vec<u8>,
}

impl Flash {
    /// Open (or create) the chip at `path`, or a blank one in memory, and program
    /// the image's flash segments the way a loader would: erase each touched
    /// sector, then write. Returns whether the chip was blank.
    pub fn open(path: Option<&Path>, elf: &Elf) -> Result<(Self, bool), String> {
        let size = capacity(elf)?;
        let mut bytes = vec![0xFFu8; size];
        let mut fresh = true;
        let file = match path {
            None => None,
            Some(path) => {
                fresh = !path.exists();
                let mut file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(path)
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                if !fresh {
                    let mut existing = Vec::new();
                    file.read_to_end(&mut existing)
                        .map_err(|e| format!("{}: {e}", path.display()))?;
                    if existing.len() != size {
                        return Err(format!(
                            "{}: {} bytes, but a --image store is the whole {size}-byte chip",
                            path.display(),
                            existing.len()
                        ));
                    }
                    bytes = existing;
                }
                Some(file)
            }
        };
        let mut placed = Vec::new();
        for seg in &elf.segments {
            if !(XIP_BASE..XIP_END).contains(&seg.paddr) {
                continue; // loaded somewhere other than flash: nothing to program
            }
            let off = (seg.paddr - XIP_BASE) as usize;
            let end = off + seg.data.len();
            if end > size {
                return Err(format!("segment at {:#x} leaves the flash", seg.paddr));
            }
            placed.push((off, end, &seg.data));
        }
        // Erase first: segments share sectors.
        for &(off, end, _) in &placed {
            bytes[off / SECTOR * SECTOR..end.div_ceil(SECTOR) * SECTOR].fill(0xFF);
        }
        for (off, end, data) in placed {
            bytes[off..end].copy_from_slice(data);
        }
        let mut f = Self { file, bytes };
        f.persist(0, size)?;
        Ok((f, fresh))
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn snapshot(&self, path: &Path) -> Result<(), String> {
        std::fs::write(path, &self.bytes).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Bring this copy (and the file) in line with the chip's flash after the
    /// QMI model erased or programmed it: every sector that differs.
    pub fn sync_from(&mut self, backing: &[u8]) -> Result<usize, String> {
        if backing.len() != self.bytes.len() {
            return Err(format!(
                "flash backing is {} bytes; expected {}",
                backing.len(),
                self.bytes.len()
            ));
        }
        let mut n = 0;
        for s in (0..backing.len()).step_by(SECTOR) {
            if self.bytes[s..s + SECTOR] != backing[s..s + SECTOR] {
                self.bytes[s..s + SECTOR].copy_from_slice(&backing[s..s + SECTOR]);
                self.persist(s, SECTOR)?;
                n += 1;
            }
        }
        Ok(n)
    }

    fn persist(&mut self, off: usize, len: usize) -> Result<(), String> {
        let Some(file) = self.file.as_mut() else {
            return Ok(());
        };
        file.seek(SeekFrom::Start(off as u64))
            .and_then(|_| file.write_all(&self.bytes[off..off + len]))
            .map_err(|e| format!("flash file write: {e}"))
    }
}

#[cfg(test)]
#[path = "flash_tests.rs"]
mod tests;
