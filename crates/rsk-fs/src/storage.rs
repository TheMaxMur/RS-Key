// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The FID → bytes persistence backend. On device this is `sequential-storage`
//! over embassy-rp flash (implemented in `firmware`); tests use `RamStorage`.

use rsk_sdk::error::Result;

/// A persistent map from 16-bit file id to a byte value.
pub trait Storage {
    /// Largest value this backend can store for one FID. A log-structured backend
    /// serialises key+value through one scratch buffer, so the real ceiling is
    /// smaller than the buffer and was previously an unstated property of it —
    /// callers that picked their own cap could exceed it (audit run-32). Defaults
    /// to the device backend's, so a host test hits the same rejection.
    const MAX_VALUE: usize = crate::MAX_VALUE_BYTES;
    /// Copy the value for `fid` into `buf` (truncated to `buf.len()`), returning
    /// the value's full length, or `None` if `fid` is absent.
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize>;
    /// Store (or replace) the value for `fid`.
    fn write(&mut self, fid: u16, data: &[u8]) -> Result<()>;
    /// Remove `fid` if present.
    fn remove(&mut self, fid: u16) -> Result<()>;
    /// Length of the value for `fid`, or `None`.
    fn size(&mut self, fid: u16) -> Option<usize>;
    /// Whether `fid` has a stored value.
    fn exists(&mut self, fid: u16) -> bool {
        self.size(fid).is_some()
    }
    /// Invoke `f` once per stored key (used to rebuild the dynamic-file set and to
    /// probe credential slots without a per-slot `read` of every absent FID).
    /// Returns `true` iff the enumeration ran to completion — every live key was
    /// yielded. A `false` return means the walk was truncated (a flash read fault),
    /// so the caller MUST NOT treat an un-yielded FID as absent (see [`Fs::scan`]).
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool;
    /// Physically reclaim superseded records so that *overwritten* and *deleted*
    /// payloads are erased from the medium, not merely unlinked.
    ///
    /// A log-structured backend ([`crate::Storage`] over `sequential-storage`)
    /// only appends: an overwrite leaves the prior value in the log and a delete
    /// flips a header flag, so the old bytes survive a raw flash dump until the
    /// page is naturally reclaimed. That is fine for the device-root seal in the
    /// steady state, but it means a record re-sealed under a *stronger* root (the
    /// pre-OTP → OTP seed migration) leaves a copy sealed under the *weaker*
    /// chip-serial-only root readable until compaction. This drives that
    /// compaction on demand. Default: no-op (backends, like the test RAM map,
    /// that overwrite in place and keep no remnants).
    fn compact(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(any(test, feature = "test-util"))]
pub mod ram {
    use super::*;
    use std::collections::HashMap;

    /// In-memory `Storage` for host tests. `Clone` lets fuzz targets snapshot
    /// an initialized image instead of re-deriving it per exec.
    #[derive(Default, Clone)]
    pub struct RamStorage {
        map: HashMap<u16, Vec<u8>>,
    }

    impl RamStorage {
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl Storage for RamStorage {
        fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
            let v = self.map.get(&fid)?;
            let n = v.len().min(buf.len());
            buf[..n].copy_from_slice(&v[..n]);
            Some(v.len())
        }
        fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
            self.map.insert(fid, data.to_vec());
            Ok(())
        }
        fn remove(&mut self, fid: u16) -> Result<()> {
            self.map.remove(&fid);
            Ok(())
        }
        fn size(&mut self, fid: u16) -> Option<usize> {
            self.map.get(&fid).map(|v| v.len())
        }
        fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
            for &k in self.map.keys() {
                f(k);
            }
            true // the RAM map iterates in memory; it cannot fault mid-walk
        }
    }
}
