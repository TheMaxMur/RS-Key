// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The emulator's [`Storage`] backend: an in-memory FID → bytes map, optionally
//! mirrored to a file so a run survives a restart.
//!
//! This is **not** the device's log-structured `sequential-storage`: it
//! overwrites in place, so it reproduces neither the append-only remnants nor
//! the torn-write windows a power cut opens on real flash. Anything about
//! power-cut ordering still has to be proved on hardware (or by `rsk-fs`'s own
//! host tests), not here.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::PathBuf;

use rsk_fs::Storage;
use rsk_sdk::error::{Error, Result};

/// File magic + layout version, so a store written by an older emulator is
/// refused rather than misparsed.
const MAGIC: &[u8; 8] = b"RSKEMU\x00\x01";

pub struct FileStore {
    map: BTreeMap<u16, Vec<u8>>,
    path: Option<PathBuf>,
}

impl FileStore {
    /// Load the store at `path` (empty when absent), or a purely in-memory one
    /// when `path` is `None`.
    pub fn open(path: Option<PathBuf>) -> io::Result<Self> {
        let mut s = FileStore {
            map: BTreeMap::new(),
            path,
        };
        if let Some(p) = s.path.clone()
            && p.exists()
        {
            s.map = decode(&fs::read(&p)?)?;
        }
        Ok(s)
    }

    /// Number of stored records — for the startup banner.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Rewrite the whole file. Called after every mutation: the emulator is not
    /// hot enough for the O(n) rewrite to matter, and a store that only persists
    /// at exit would lose everything on a crash — the one case where you most
    /// want to look at what the device had.
    fn flush(&self) {
        let Some(p) = &self.path else { return };
        if let Err(e) = fs::write(p, encode(&self.map)) {
            eprintln!("emu: cannot write store {}: {e}", p.display());
        }
    }
}

fn encode(map: &BTreeMap<u16, Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::from(*MAGIC);
    for (fid, v) in map {
        out.extend_from_slice(&fid.to_le_bytes());
        out.extend_from_slice(&(v.len() as u32).to_le_bytes());
        out.extend_from_slice(v);
    }
    out
}

fn decode(raw: &[u8]) -> io::Result<BTreeMap<u16, Vec<u8>>> {
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_string());
    if raw.len() < MAGIC.len() || &raw[..MAGIC.len()] != MAGIC {
        return Err(bad("not an rsk-emu store (bad magic or layout version)"));
    }
    let mut map = BTreeMap::new();
    let mut i = MAGIC.len();
    while i < raw.len() {
        if i + 6 > raw.len() {
            return Err(bad("truncated record header"));
        }
        let fid = u16::from_le_bytes([raw[i], raw[i + 1]]);
        let len = u32::from_le_bytes([raw[i + 2], raw[i + 3], raw[i + 4], raw[i + 5]]) as usize;
        i += 6;
        if i + len > raw.len() {
            return Err(bad("truncated record body"));
        }
        map.insert(fid, raw[i..i + len].to_vec());
        i += len;
    }
    Ok(map)
}

impl Storage for FileStore {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        let v = self.map.get(&fid)?;
        let n = v.len().min(buf.len());
        buf[..n].copy_from_slice(&v[..n]);
        Some(v.len())
    }

    fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
        // The device backend refuses anything past `MAX_VALUE`; a host store with
        // no ceiling would let a value through here that no real key could hold.
        if data.len() > Self::MAX_VALUE {
            return Err(Error::NoMemory);
        }
        self.map.insert(fid, data.to_vec());
        self.flush();
        Ok(())
    }

    fn remove(&mut self, fid: u16) -> Result<()> {
        self.map.remove(&fid);
        self.flush();
        Ok(())
    }

    fn size(&mut self, fid: u16) -> Option<usize> {
        self.map.get(&fid).map(Vec::len)
    }

    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        for fid in self.map.keys() {
            f(*fid);
        }
        true
    }
}
