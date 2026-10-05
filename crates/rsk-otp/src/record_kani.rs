// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![allow(
    clippy::indexing_slicing,
    reason = "the proof's fixed arrays and checked read length bound each index"
)]

use super::*;
use rsk_sdk::error::Error;

// Map one valid slot into Fs's 24-FID Kani cache. Slot authorization is outside
// this proof; the real reader, cache, returned length and copy remain intact.
const RECORD_FID: u16 = 7;

fn valid_slot(fid: u16) -> bool {
    fid == RECORD_FID
}

struct Medium {
    bytes: [u8; seal::MAX_BLOB],
    len: usize,
    writes: usize,
}

impl Storage for Medium {
    fn read(&mut self, fid: u16, out: &mut [u8]) -> Option<usize> {
        if fid != RECORD_FID {
            return None;
        }
        let n = self.len.min(out.len()).min(self.bytes.len());
        out[..n].copy_from_slice(&self.bytes[..n]);
        Some(self.len)
    }

    fn write(&mut self, _: u16, _: &[u8]) -> Result<()> {
        self.writes += 1;
        Err(Error::MemoryFatal)
    }

    fn remove(&mut self, _: u16) -> Result<()> {
        self.writes += 1;
        Err(Error::MemoryFatal)
    }

    fn size(&mut self, fid: u16) -> Option<usize> {
        (fid == RECORD_FID).then_some(self.len)
    }

    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        f(RECORD_FID);
        true
    }
}

#[kani::proof]
#[kani::unwind(90)]
#[kani::stub(crate::record::is_slot, valid_slot)]
fn plaintext_read_bounds_and_wiping_follow_the_returned_length() {
    let bytes: [u8; seal::MAX_BLOB] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= rsk_fs::MAX_VALUE_BYTES);
    kani::cover!(len == CONFIG_SIZE, "short legacy record");
    kani::cover!(len > seal::MAX_BLOB, "stored length exceeds scratch");
    let mut fs = Fs::new(Medium {
        bytes,
        len,
        writes: 0,
    });
    let mut rec = SlotRecord::vacant();
    rec.configure(&kani::any());
    rec.press_yubico(0);
    let result = rec.try_read_plaintext(&mut fs, RECORD_FID);
    let accepted = (CONFIG_SIZE..=SLOT_SIZE).contains(&len);
    if accepted {
        assert!(rec.bytes.expose().get(..len).is_some());
        assert!(bytes.get(..len).is_some());
    }
    assert!(result == Ok(accepted.then_some(len)));
    assert!(rec.stored().len() == if accepted { len } else { 0 });
    for (i, byte) in rec.expose().iter().enumerate() {
        let expected = if accepted && i < len { bytes[i] } else { 0 };
        assert!(*byte == expected, "a plaintext read retained old bytes");
    }
    assert!(fs.write_gen() == 0 && fs.into_storage().writes == 0);
}
