// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the audit-journal readers (`rsk_fido::journal`) against a HOSTILE
//! `EF_AUDIT_META` — the record the device only ever writes itself, but that a
//! flash-snapshot rollback (issue #37) can replace with an arbitrary one. The
//! fail-closed guard in `load_meta` must reject any persisted live-window span
//! wider than `AUDIT_RING_SLOTS` (falling back to genesis), so `vendor_read` /
//! `chain_head` / `for_each_event` can never overrun their fixed
//! `AUDIT_RING_SLOTS`-entry walk. Oracle: window > ring ⇒ genesis (0, 0).

use libfuzzer_sys::fuzz_target;
use rsk_crypto::Device;
use rsk_fido::consts::{AUDIT_RING_SLOTS, EF_AUDIT_META, EF_AUDIT_RING};
use rsk_fido::journal::{ENTRY_LEN, chain_head, for_each_event, vendor_read};
use rsk_fido::{Ctx, Rng};
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;

struct SeqRng(u64);
impl Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let seq_next = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let start = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let mut epoch = [0u8; 32];
    let esrc = &data[8..data.len().min(40)];
    epoch[..esrc.len()].copy_from_slice(esrc);

    let dev = Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
        latched: false,
    };
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();

    // Plant a crafted EF_AUDIT_META: ver(1) ‖ seq_next(4 LE) ‖ start(4 LE) ‖ epoch(32).
    let mut meta = [0u8; 41];
    meta[0] = 1; // META_VER
    meta[1..5].copy_from_slice(&seq_next.to_le_bytes());
    meta[5..9].copy_from_slice(&start.to_le_bytes());
    meta[9..].copy_from_slice(&epoch);
    let _ = fs.put(EF_AUDIT_META, &meta);

    // Seed some ring slots (presence chosen by the input tail) so the window walk
    // has real 20-byte entries to fold when the meta is in-bounds.
    for i in 0..AUDIT_RING_SLOTS as u16 {
        if data.get(8 + i as usize).is_some_and(|b| b & 1 == 1) {
            let entry = [(i as u8).wrapping_add(1); ENTRY_LEN];
            let _ = fs.put(EF_AUDIT_RING + i, &entry);
        }
    }

    // The fail-closed oracle: a window wider than the ring MUST clamp to genesis.
    let raw_window = seq_next.wrapping_sub(start);
    // `RamStorage` never faults, so the fallible head always answers here; the
    // `expect` is the oracle for that, not a swallowed error.
    let (_, m) = chain_head(&dev, &mut fs).expect("a RAM medium serves every probe");
    if raw_window > AUDIT_RING_SLOTS {
        assert_eq!((m.start, m.seq_next), (0, 0));
    } else {
        assert_eq!((m.start, m.seq_next), (start, seq_next));
    }

    // Newest-first walk: never panics.
    let _ = for_each_event(&dev, &mut fs, |_| true);

    // Export: never panics, always writes within the bounded buffer.
    let mut state = rsk_fido::FidoState::new();
    let mut rng = SeqRng(1);
    let mut presence = rsk_fido::AlwaysConfirm;
    let mut out = [0u8; AUDIT_RING_SLOTS as usize * ENTRY_LEN + 128];
    let mut ctx = Ctx {
        presence: &mut presence,
        dev,
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
    };
    if let Ok(n) = vendor_read(&mut ctx, &mut out) {
        assert!(n <= out.len());
    }
});
