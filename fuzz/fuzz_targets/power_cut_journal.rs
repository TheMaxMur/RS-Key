// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fido::consts::{AUDIT_RING_SLOTS, EF_AUDIT_ENABLED, EF_COUNTER};
use rsk_fido::journal::{
    ENTRY_LEN, EV_PIN_CHANGE, EV_PIN_SET, append, chain_head, fold_and_scrub, vendor_read,
};
use sha2::{Digest, Sha256};

pub struct Outcome {
    pub interrupted: bool,
    pub recovery_interrupted: bool,
    pub appended: bool,
    pub operation_stats: sequential_storage::mock_flash::FlashStatsResult,
    pub recovery_stats: sequential_storage::mock_flash::FlashStatsResult,
}

fn fold(head: &[u8; 32], entry: &[u8; ENTRY_LEN]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(head);
    hash.update(entry);
    hash.finalize().into()
}

fn entry(seq: u32, event: u8) -> [u8; ENTRY_LEN] {
    let mut out = [0; ENTRY_LEN];
    out[..4].copy_from_slice(&seq.to_le_bytes());
    out[4..8].copy_from_slice(&17u32.to_le_bytes());
    out[8] = event;
    out
}

fn budget(data: &[u8], offset: usize) -> u32 {
    u16::from_be_bytes([
        data.get(offset).copied().unwrap_or(0),
        data.get(offset + 1).copied().unwrap_or(0),
    ])
    .into()
}

fn command(fs: &mut Fs<TortureStorage>, identity: rsk_crypto::Device<'_>, scrub: bool) {
    let mut state = rsk_fido::FidoState::new();
    state.audit_boot_logged = true;
    let mut ctx = rsk_fido::Ctx {
        dev: identity,
        fs,
        rng: &mut ResetRng(1),
        state: &mut state,
        now_ms: 17,
        presence: &mut rsk_fido::AlwaysConfirm,
    };
    if scrub {
        fold_and_scrub(&mut ctx);
    } else {
        append(&mut ctx, EV_PIN_CHANGE, 0, &[]);
    }
}

fn exported_head(fs: &mut Fs<TortureStorage>, identity: rsk_crypto::Device<'_>) -> [u8; 32] {
    let mut out = [0; AUDIT_RING_SLOTS as usize * ENTRY_LEN + 128];
    let n = vendor_read(
        &mut rsk_fido::Ctx {
            dev: identity,
            fs,
            rng: &mut ResetRng(1),
            state: &mut rsk_fido::FidoState::new(),
            now_ms: 17,
            presence: &mut rsk_fido::AlwaysConfirm,
        },
        &mut out,
    )
    .unwrap();
    let mut decoder = minicbor::Decoder::new(&out[..n]);
    assert_eq!(decoder.map().unwrap(), Some(4));
    assert_eq!(decoder.u8().unwrap(), 1);
    let start = decoder.u32().unwrap();
    assert_eq!(decoder.u8().unwrap(), 2);
    let next = decoder.u32().unwrap();
    assert_eq!(decoder.u8().unwrap(), 3);
    let mut head: [u8; 32] = decoder.bytes().unwrap().try_into().unwrap();
    assert_eq!(decoder.u8().unwrap(), 4);
    let entries = decoder.bytes().unwrap();
    assert_eq!(entries.len(), next.wrapping_sub(start) as usize * ENTRY_LEN);
    for (offset, raw) in entries.chunks_exact(ENTRY_LEN).enumerate() {
        assert_eq!(
            u32::from_le_bytes(raw[..4].try_into().unwrap()),
            start.wrapping_add(offset as u32)
        );
        head = fold(&head, raw.try_into().unwrap());
    }
    assert_eq!(decoder.position(), n);
    assert_eq!(chain_head(&identity, fs).unwrap().0, head);
    head
}

/// Append or scrub, then interrupt the next scrub independently and remount twice.
pub fn run(data: &[u8]) -> Outcome {
    let flash = Rc::new(RefCell::new(Mock::new(WriteCountCheck::Twice, None, true)));
    let mut dev = MockDevice {
        shared: SharedMock {
            flash: flash.clone(),
            dead: Rc::new(Cell::new(false)),
        },
        boots: 0,
    };
    let identity = rsk_crypto::Device {
        serial_hash: &[0xA5; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
        latched: false,
    };
    let setting = data.get(1).copied().unwrap_or(0);
    let count = if setting & 1 == 0 {
        3
    } else {
        AUDIT_RING_SLOTS
    };
    let scrub = data.first().is_some_and(|b| b & 1 != 0);
    let mut fs = dev.boot();
    fs.scan();
    fs.put(EF_AUDIT_ENABLED, &[1]).unwrap();
    fs.put(0xB001, b"unrelated record").unwrap();
    fs.put_counter(EF_COUNTER, &73u32.to_le_bytes()).unwrap();
    let mut hash = Sha256::new();
    hash.update(b"RSK-AUDIT-GENESIS-v1");
    hash.update(identity.serial_hash);
    let mut original: [u8; 32] = hash.finalize().into();
    let mut state = rsk_fido::FidoState::new();
    state.audit_boot_logged = true;
    for seq in 0..count {
        append(
            &mut rsk_fido::Ctx {
                dev: identity,
                fs: &mut fs,
                rng: &mut ResetRng(1),
                state: &mut state,
                now_ms: 17,
                presence: &mut rsk_fido::AlwaysConfirm,
            },
            EV_PIN_SET,
            0,
            &[],
        );
        original = fold(&original, &entry(seq, EV_PIN_SET));
    }
    assert_eq!(exported_head(&mut fs, identity), original);
    for value in 0..(setting >> 1) % 32 {
        fs.put(0xB000, &[value; 1024]).unwrap();
    }
    let counter_bytes = flash.borrow().as_bytes()
        [COUNTER_RANGE.start as usize..COUNTER_RANGE.end as usize]
        .to_vec();
    let before = flash.borrow().stats_snapshot();
    flash.borrow_mut().bytes_until_shutoff = Some(budget(data, 2));
    command(&mut fs, identity, scrub);
    let operation_stats = before.compare_to(flash.borrow().stats_snapshot());
    let interrupted = dev.dead();
    flash.borrow_mut().bytes_until_shutoff = None;
    dev.revive();
    fs = dev.boot();
    fs.scan();
    let head = exported_head(&mut fs, identity);
    let appended = head != original;
    if scrub {
        assert_eq!(head, original, "a scrub lost chain history");
    } else {
        assert!(
            head == original || head == fold(&original, &entry(count, EV_PIN_CHANGE)),
            "a cut broke the chain"
        );
        if !interrupted {
            assert!(appended, "a healthy append lost its event");
        }
    }
    let before = flash.borrow().stats_snapshot();
    flash.borrow_mut().bytes_until_shutoff = Some(budget(data, 4));
    command(&mut fs, identity, true);
    let recovery_stats = before.compare_to(flash.borrow().stats_snapshot());
    let recovery_interrupted = dev.dead();
    flash.borrow_mut().bytes_until_shutoff = None;
    dev.revive();
    fs = dev.boot();
    fs.scan();
    assert_eq!(
        exported_head(&mut fs, identity),
        head,
        "interrupted recovery changed the head"
    );
    command(&mut fs, identity, true);
    assert_eq!(exported_head(&mut fs, identity), head);
    assert_eq!(
        chain_head(&identity, &mut fs).unwrap().1.start,
        chain_head(&identity, &mut fs).unwrap().1.seq_next
    );
    command(&mut fs, identity, false);
    let next = chain_head(&identity, &mut fs).unwrap().1.seq_next - 1;
    assert_eq!(
        exported_head(&mut fs, identity),
        fold(&head, &entry(next, EV_PIN_CHANGE))
    );
    fs = dev.boot();
    fs.scan();
    assert_eq!(record(&mut fs, 0xB001), b"unrelated record");
    assert_eq!(rsk_fido::seed::global_sign_counter(&mut fs), Ok(73));
    assert_eq!(
        flash.borrow().as_bytes()[COUNTER_RANGE.start as usize..COUNTER_RANGE.end as usize],
        counter_bytes
    );
    Outcome {
        interrupted,
        recovery_interrupted,
        appended,
        operation_stats,
        recovery_stats,
    }
}
