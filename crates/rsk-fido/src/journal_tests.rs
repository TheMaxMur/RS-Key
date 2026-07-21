// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::{AlwaysConfirm, FidoState};
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

fn dev() -> Device<'static> {
    Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    }
}

fn run_ctx<T>(
    fs: &mut Fs<RamStorage>,
    state: &mut FidoState,
    f: impl FnOnce(&mut Ctx<RamStorage, SeqRng>) -> T,
) -> T {
    // The journal is opt-in (OFF by default); these tests drive the ring machinery
    // with logging ON. The default-OFF gate is covered by `append_is_noop_when_off`.
    let _ = set_enabled(fs, true);
    let mut rng = SeqRng(1);
    let mut presence = AlwaysConfirm;
    let mut ctx = Ctx {
        dev: dev(),
        fs,
        rng: &mut rng,
        state,
        now_ms: 12345,
        presence: &mut presence,
    };
    f(&mut ctx)
}

/// Host-side reference fold: genesis/epoch + every entry ever appended.
fn reference_head(entries: &[[u8; ENTRY_LEN]]) -> [u8; 32] {
    let mut h = genesis(&dev());
    for e in entries {
        h = chain(&h, e);
    }
    h
}

#[test]
fn append_wrap_folds_and_head_matches_reference() {
    let mut fs = Fs::new(RamStorage::new());
    let mut state = FidoState::new();
    state.audit_boot_logged = true; // keep the reference list exact

    // 200 appends on a 128-slot ring: 72 evictions fold into the epoch.
    let mut reference = std::vec::Vec::new();
    run_ctx(&mut fs, &mut state, |ctx| {
        for i in 0..200u32 {
            let detail = i.to_le_bytes();
            raw_append(ctx, EV_GET_ASSERT, 0, &detail).unwrap();
            reference.push(build_entry(i, ctx.now_ms, EV_GET_ASSERT, 0, &detail));
        }
    });

    let (head, m) = chain_head(&dev(), &mut fs);
    assert_eq!(m.seq_next, 200);
    assert_eq!(m.start, 200 - AUDIT_RING_SLOTS);
    assert_eq!(head, reference_head(&reference));
}

#[test]
fn boot_entry_logged_once_per_cycle() {
    let mut fs = Fs::new(RamStorage::new());
    let mut state = FidoState::new();
    run_ctx(&mut fs, &mut state, |ctx| {
        append(ctx, EV_MAKE_CRED, 0, &[0xAA; 8]);
        append(ctx, EV_GET_ASSERT, 0, &[0xBB; 8]);
    });
    let (_, m) = chain_head(&dev(), &mut fs);
    assert_eq!(m.seq_next, 3); // BOOT + the two events
    let mut e = [0u8; ENTRY_LEN];
    read_slot(&mut fs, 0, &mut e).unwrap();
    assert_eq!(e[8], EV_BOOT);
}

#[test]
fn fold_and_scrub_keeps_chain_and_deletes_details() {
    let mut fs = Fs::new(RamStorage::new());
    let mut state = FidoState::new();
    state.audit_boot_logged = true;

    let mut reference = std::vec::Vec::new();
    run_ctx(&mut fs, &mut state, |ctx| {
        for i in 0..5u32 {
            raw_append(ctx, EV_GET_ASSERT, 0, &i.to_le_bytes()).unwrap();
            reference.push(build_entry(
                i,
                ctx.now_ms,
                EV_GET_ASSERT,
                0,
                &i.to_le_bytes(),
            ));
        }
        fold_and_scrub(ctx);
    });

    // Window empty, slots gone, epoch carries the whole history.
    let (head, m) = chain_head(&dev(), &mut fs);
    assert_eq!(m.start, m.seq_next);
    assert!(!fs.has_data(EF_AUDIT_RING));
    assert_eq!(head, reference_head(&reference));

    // The chain continues seamlessly after the scrub.
    run_ctx(&mut fs, &mut state, |ctx| {
        raw_append(ctx, EV_RESET, 0, &[]).unwrap();
        reference.push(build_entry(5, ctx.now_ms, EV_RESET, 0, &[]));
    });
    let (head, _) = chain_head(&dev(), &mut fs);
    assert_eq!(head, reference_head(&reference));
}

#[test]
fn append_is_noop_when_off() {
    // Opt-in: with EF_AUDIT_ENABLED absent (the shipped default), append writes
    // nothing to flash — no boot entry, no meta, chain stays at genesis.
    let mut fs = Fs::new(RamStorage::new());
    let mut state = FidoState::new();
    {
        let mut rng = SeqRng(1);
        let mut presence = AlwaysConfirm;
        let mut ctx = Ctx {
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 12345,
            presence: &mut presence,
        };
        assert!(!is_enabled(ctx.fs));
        append(&mut ctx, EV_MAKE_CRED, 0, &[0xAA; 8]);
        append(&mut ctx, EV_GET_ASSERT, 0, &[0xBB; 8]);
    }

    let (head, m) = chain_head(&dev(), &mut fs);
    assert_eq!(m.seq_next, 0, "off: nothing appended");
    assert!(!fs.has_data(EF_AUDIT_META));
    assert!(!fs.has_data(EF_AUDIT_RING));
    assert_eq!(head, genesis(&dev()));
}

#[test]
fn set_enabled_round_trips() {
    let mut fs = Fs::new(RamStorage::new());
    assert!(!is_enabled(&mut fs)); // default OFF
    set_enabled(&mut fs, true).unwrap();
    assert!(is_enabled(&mut fs));
    set_enabled(&mut fs, false).unwrap();
    assert!(!is_enabled(&mut fs));
}

#[test]
fn attestation_key_is_deterministic_and_devk_bound() {
    let k1 = attestation_key(&[7; 32], &[0xAB; 32]).unwrap();
    let k2 = attestation_key(&[7; 32], &[0xAB; 32]).unwrap();
    let k3 = attestation_key(&[8; 32], &[0xAB; 32]).unwrap();
    assert_eq!(k1.public_xy(), k2.public_xy());
    assert_ne!(k1.public_xy(), k3.public_xy());
}

#[test]
fn checkpoint_requires_devk_and_signature_verifies() {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    let mut fs = Fs::new(RamStorage::new());
    let mut state = FidoState::new();
    let mut out = [0u8; 512];

    // Without a DEVK the checkpoint is refused.
    let err = run_ctx(&mut fs, &mut state, |ctx| {
        vendor_checkpoint(ctx, &[0x55; 16], &mut out)
    });
    assert_eq!(err, Err(CtapError::NotAllowed));

    state.devk = Some([7; 32]);
    run_ctx(&mut fs, &mut state, |ctx| {
        append(ctx, EV_MAKE_CRED, 0, &[1; 8]);
    });
    let n = run_ctx(&mut fs, &mut state, |ctx| {
        vendor_checkpoint(ctx, &[0x55; 16], &mut out)
    })
    .unwrap();

    // {1: head, 2: seq_next, 3: sig, 4: pubkey}
    let mut d = minicbor::Decoder::new(&out[..n]);
    assert_eq!(d.map().unwrap().unwrap(), 4);
    assert_eq!(d.u8().unwrap(), 1);
    let head: [u8; 32] = d.bytes().unwrap().try_into().unwrap();
    assert_eq!(d.u8().unwrap(), 2);
    let seq_next = d.u32().unwrap();
    assert_eq!(d.u8().unwrap(), 3);
    let sig = d.bytes().unwrap().to_vec();
    assert_eq!(d.u8().unwrap(), 4);
    let pubkey = d.bytes().unwrap().to_vec();

    // The signed head matches the device state *before* the EV_CHECKPOINT
    // entry the call itself appends.
    let (now_head, m) = chain_head(&dev(), &mut fs);
    assert_eq!(m.seq_next, seq_next + 1);
    assert_ne!(head, now_head);

    let mut msg = std::vec::Vec::new();
    msg.extend_from_slice(CKPT_TAG);
    msg.extend_from_slice(&head);
    msg.extend_from_slice(&seq_next.to_le_bytes());
    msg.extend_from_slice(&[0x55; 16]);
    let vk = VerifyingKey::from_sec1_bytes(&pubkey).unwrap();
    let sig = Signature::from_der(&sig).unwrap();
    vk.verify(&msg, &sig).unwrap();
}

#[test]
fn read_exports_window_that_folds_to_head() {
    let mut fs = Fs::new(RamStorage::new());
    let mut state = FidoState::new();
    let mut out = [0u8; 4096];
    let n = run_ctx(&mut fs, &mut state, |ctx| {
        append(ctx, EV_MAKE_CRED, 1, &[2; 8]);
        append(ctx, EV_PIN_SET, 0, &[]);
        vendor_read(ctx, &mut out)
    })
    .unwrap();

    let mut d = minicbor::Decoder::new(&out[..n]);
    assert_eq!(d.map().unwrap().unwrap(), 4);
    assert_eq!(d.u8().unwrap(), 1);
    let start = d.u32().unwrap();
    assert_eq!(d.u8().unwrap(), 2);
    let seq_next = d.u32().unwrap();
    assert_eq!(d.u8().unwrap(), 3);
    let mut epoch: [u8; 32] = d.bytes().unwrap().try_into().unwrap();
    assert_eq!(d.u8().unwrap(), 4);
    let entries = d.bytes().unwrap();

    assert_eq!(start, 0);
    assert_eq!(seq_next, 3); // BOOT + two events
    assert_eq!(entries.len(), 3 * ENTRY_LEN);
    for e in entries.chunks_exact(ENTRY_LEN) {
        epoch = chain(&epoch, e.try_into().unwrap());
    }
    let (head, _) = chain_head(&dev(), &mut fs);
    assert_eq!(epoch, head);
}

#[test]
fn for_each_event_visits_newest_first_and_counts() {
    let mut fs = Fs::new(RamStorage::new());
    let mut state = FidoState::new();
    run_ctx(&mut fs, &mut state, |ctx| {
        // EV_BOOT is auto-logged first, then these three.
        append(ctx, EV_MAKE_CRED, 0, &[]);
        append(ctx, EV_GET_ASSERT, 0, &[]);
        append(ctx, EV_PIN_SET, 0, &[]);
    });

    let mut seen = std::vec::Vec::new();
    let total = for_each_event(&dev(), &mut fs, |e| {
        seen.push(e.event);
        true
    });
    assert_eq!(total, 4);
    assert_eq!(
        seen,
        std::vec![EV_PIN_SET, EV_GET_ASSERT, EV_MAKE_CRED, EV_BOOT]
    );

    // A visitor that keeps only the first two still reports the true total.
    let mut kept = 0u32;
    let total2 = for_each_event(&dev(), &mut fs, |_| {
        kept += 1;
        kept < 2
    });
    assert_eq!(total2, 4);
    assert_eq!(kept, 2);
}
