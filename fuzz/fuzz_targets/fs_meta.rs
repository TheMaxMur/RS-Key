// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the meta side-store record parser by feeding arbitrary bytes as the
//! EF_META blob and reading several FIDs back out.

use libfuzzer_sys::fuzz_target;
use rsk_fs::{Fs, Storage};
use rsk_sdk::error::Result;

/// Storage exposing the fuzz input as EF_META and nothing else.
struct MetaBlob<'a>(&'a [u8]);

impl Storage for MetaBlob<'_> {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        if fid != rsk_fs::EF_META {
            return None;
        }
        let n = self.0.len().min(buf.len());
        buf[..n].copy_from_slice(&self.0[..n]);
        Some(self.0.len())
    }
    fn write(&mut self, _fid: u16, _data: &[u8]) -> Result<()> {
        Ok(())
    }
    fn remove(&mut self, _fid: u16) -> Result<()> {
        Ok(())
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        (fid == rsk_fs::EF_META).then_some(self.0.len())
    }
    // Non-enumerating stub: report "incomplete" so `scan` keeps confirm-on-miss.
    fn for_each_key(&mut self, _f: &mut dyn FnMut(u16)) -> bool {
        false
    }
}

fuzz_target!(|data: &[u8]| {
    let mut fs = Fs::new(MetaBlob(data));
    let mut out = [0u8; 256];
    for fid in [0x0000, 0xCF01, 0xE010, 0xFFFF] {
        let _ = fs.meta_find(fid, &mut out);
    }
});
