// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::faults::{Cut, Op};

struct RefusedMeta {
    inner: RamStorage,
    refuse: bool,
}

impl Storage for RefusedMeta {
    fn read(&mut self, fid: u16, out: &mut [u8]) -> Option<usize> {
        self.inner.read(fid, out)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> FsResult<()> {
        if fid == EF_AUDIT_META && self.refuse {
            self.refuse = false;
            return Err(rsk_sdk::error::Error::MemoryFatal);
        }
        self.inner.write(fid, data)
    }
    fn remove(&mut self, fid: u16) -> FsResult<()> {
        self.inner.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.inner.size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(f)
    }
}

fn with_ctx<S: Storage, T>(fs: &mut Fs<S>, f: impl FnOnce(&mut Ctx<S, SeqRng>) -> T) -> T {
    let mut state = FidoState::new();
    state.audit_boot_logged = true;
    f(&mut Ctx {
        dev: dev(),
        fs,
        rng: &mut SeqRng(1),
        state: &mut state,
        now_ms: 12345,
        presence: &mut AlwaysConfirm,
    })
}

#[test]
fn invalid_metadata_cannot_expose_stale_ring_entries() {
    for (version, next, start, len) in [
        (META_VER + 1, 2, 0u32, META_LEN),
        (META_VER, AUDIT_RING_SLOTS + 1, 0, META_LEN),
        (META_VER, 0, 1, META_LEN),
        (META_VER, 2, 0, META_LEN - 1),
    ] {
        let mut fs = Fs::new(RamStorage::new());
        let mut meta = [0xA5; META_LEN];
        meta[0] = version;
        meta[1..5].copy_from_slice(&next.to_le_bytes());
        meta[5..9].copy_from_slice(&start.to_le_bytes());
        fs.put(EF_AUDIT_META, &meta[..len]).unwrap();
        fs.put(slot_fid(0), &build_entry(0, 7, EV_PIN_SET, 0, &[]))
            .unwrap();
        let generation = fs.write_gen();
        let (head, m) = chain_head(&dev(), &mut fs).unwrap();
        assert_eq!((m.start, m.seq_next), (0, 0));
        assert_eq!(head, genesis(&dev()));
        assert_eq!(
            for_each_event(&dev(), &mut fs, |_| panic!("stale event")),
            0
        );
        let mut out = [0; 128];
        let n = with_ctx(&mut fs, |ctx| vendor_read(ctx, &mut out)).unwrap();
        let mut decoder = minicbor::Decoder::new(&out[..n]);
        assert_eq!(decoder.map().unwrap(), Some(4));
        for key in [1, 2] {
            assert_eq!(decoder.u8().unwrap(), key);
            assert_eq!(decoder.u32().unwrap(), 0);
        }
        assert_eq!(decoder.u8().unwrap(), 3);
        assert_eq!(decoder.bytes().unwrap(), genesis(&dev()));
        assert_eq!(decoder.u8().unwrap(), 4);
        assert!(decoder.bytes().unwrap().is_empty());
        assert_eq!(fs.write_gen(), generation);
    }
}

#[test]
fn a_full_sparse_ring_evicts_an_absent_oldest_slot_without_folding_stale_bytes() {
    let mut fs = Fs::new(RamStorage::new());
    set_enabled(&mut fs, true).unwrap();
    put_meta(
        &mut fs,
        &Meta {
            start: 0,
            seq_next: AUDIT_RING_SLOTS,
            epoch: genesis(&dev()),
        },
    )
    .unwrap();
    let mut entries = std::vec::Vec::new();
    for seq in 1..AUDIT_RING_SLOTS {
        let e = build_entry(seq, 12345, EV_PIN_SET, 0, &[]);
        fs.put(slot_fid(seq), &e).unwrap();
        entries.push(e);
    }
    let original = reference_head(&entries);
    assert_eq!(chain_head(&dev(), &mut fs).unwrap().0, original);
    with_ctx(&mut fs, |ctx| append(ctx, EV_PIN_CHANGE, 0, &[]));
    let (head, m) = chain_head(&dev(), &mut fs).unwrap();
    assert_eq!((m.start, m.seq_next), (1, AUDIT_RING_SLOTS + 1));
    assert_eq!(m.epoch, genesis(&dev()));
    assert_eq!(
        head,
        chain(
            &original,
            &build_entry(AUDIT_RING_SLOTS, 12345, EV_PIN_CHANGE, 0, &[])
        )
    );
}

#[test]
fn sparse_wrapping_windows_export_and_fold_only_readable_entries() {
    let mut fs = Fs::new(RamStorage::new());
    let start = u32::MAX - 1;
    let first = build_entry(start, 3, EV_PIN_SET, 0, &[]);
    let last = build_entry(0, 9, EV_PIN_CHANGE, 0, &[]);
    let anchor = [0x42; 32];
    put_meta(
        &mut fs,
        &Meta {
            start,
            seq_next: 1,
            epoch: anchor,
        },
    )
    .unwrap();
    fs.put(slot_fid(start), &first).unwrap();
    fs.put(slot_fid(u32::MAX), &[0; ENTRY_LEN - 1]).unwrap();
    fs.put(slot_fid(0), &last).unwrap();
    let expected = chain(&chain(&anchor, &first), &last);
    assert_eq!(chain_head(&dev(), &mut fs).unwrap().0, expected);
    let mut seen = std::vec::Vec::new();
    assert_eq!(
        for_each_event(&dev(), &mut fs, |e| {
            seen.push(e.event);
            true
        }),
        3
    );
    assert_eq!(seen, [EV_PIN_CHANGE, EV_PIN_SET]);
    let mut out = [0; 256];
    let n = with_ctx(&mut fs, |ctx| vendor_read(ctx, &mut out)).unwrap();
    let mut decoder = minicbor::Decoder::new(&out[..n]);
    decoder.map().unwrap();
    for _ in 0..3 {
        decoder.skip().unwrap();
        decoder.skip().unwrap();
    }
    assert_eq!(decoder.u8().unwrap(), 4);
    assert_eq!(decoder.bytes().unwrap(), [first, last].concat());
    with_ctx(&mut fs, fold_and_scrub);
    let (head, m) = chain_head(&dev(), &mut fs).unwrap();
    assert_eq!(head, expected);
    assert_eq!((m.start, m.seq_next), (1, 1));
    assert!(!fs.has_data(slot_fid(start)));
    assert!(!fs.has_data(slot_fid(u32::MAX)));
    assert!(!fs.has_data(slot_fid(0)));
}

#[test]
fn a_scrub_cut_commits_the_fold_before_deleting_any_detail() {
    let mut torn = false;
    let mut complete = false;
    for budget in 0..32 {
        let (backend, medium) = Cut::new();
        let mut fs = Fs::new(backend);
        fs.scan();
        let mut entries = std::vec::Vec::new();
        for seq in 0..3 {
            raw_append(&dev(), &mut fs, 12345, EV_PIN_SET, 0, &[]).unwrap();
            entries.push(build_entry(seq, 12345, EV_PIN_SET, 0, &[]));
        }
        fs.put(0xB000, b"another applet").unwrap();
        let meta = medium.value(EF_AUDIT_META).unwrap();
        medium.clear_ops();
        medium.arm(budget);
        with_ctx(&mut fs, fold_and_scrub);
        let ops = medium.ops();
        medium.arm(u32::MAX);
        let mut fs = Fs::new(fs.into_storage());
        fs.scan();
        let (head, m) = chain_head(&dev(), &mut fs).unwrap();
        assert_eq!(head, reference_head(&entries), "budget {budget}");
        if ops.is_empty() {
            torn = true;
            assert_eq!(medium.value(EF_AUDIT_META).unwrap(), meta);
            for seq in 0..3 {
                assert_eq!(medium.value(slot_fid(seq)).unwrap(), entries[seq as usize]);
            }
        } else {
            assert!(matches!(&ops[0], Op::Write(fid, _) if *fid == EF_AUDIT_META));
            assert_eq!((m.start, m.seq_next), (3, 3));
        }
        let all_removed = (0..3).all(|seq| medium.value(slot_fid(seq)).is_none());
        with_ctx(&mut fs, fold_and_scrub);
        assert_eq!(chain_head(&dev(), &mut fs).unwrap().0, head);
        for seq in 0..3 {
            assert!(medium.value(slot_fid(seq)).is_none());
        }
        assert_eq!(medium.value(0xB000).unwrap(), b"another applet");
        if all_removed {
            complete = true;
            break;
        }
    }
    assert!(
        torn && complete,
        "the sweep must reach both cut and completed scrubs"
    );
}

#[test]
fn a_refused_fold_commit_preserves_details_even_when_deletion_would_succeed() {
    let mut fs = Fs::new(RefusedMeta {
        inner: RamStorage::new(),
        refuse: false,
    });
    for _ in 0..3 {
        raw_append(&dev(), &mut fs, 12345, EV_PIN_SET, 0, &[]).unwrap();
    }
    let head = chain_head(&dev(), &mut fs).unwrap().0;
    let generation = fs.write_gen();
    let mut backend = fs.into_storage();
    backend.refuse = true;
    let mut fs = Fs::new(backend);
    fs.scan();
    with_ctx(&mut fs, fold_and_scrub);
    let (after, m) = chain_head(&dev(), &mut fs).unwrap();
    assert_eq!(after, head, "a refused fold commit lost the live chain");
    assert_eq!((m.start, m.seq_next), (0, 3));
    for seq in 0..3 {
        assert!(fs.has_data(slot_fid(seq)), "an unfolded detail was deleted");
    }
    assert_eq!(fs.write_gen(), 0);
    assert!(generation > 0);
    with_ctx(&mut fs, fold_and_scrub);
    assert_eq!(chain_head(&dev(), &mut fs).unwrap().0, head);
    for seq in 0..3 {
        assert!(!fs.has_data(slot_fid(seq)));
    }
}

#[test]
fn coalescing_faults_preserve_the_window_and_retry_healthy() {
    for config in [false, true] {
        let (mut fs, medium, _) = stuck_journal(1);
        let ev = if config {
            EV_CONFIG_WRITE
        } else {
            EV_GET_ASSERT
        };
        fs.put(slot_fid(0), &build_entry(0, 12345, ev, 0, &[]))
            .unwrap();
        let head = chain_head(&dev(), &mut fs).unwrap().0;
        let saved = medium.value(EF_AUDIT_META).unwrap();
        medium.stick(Some(EF_AUDIT_META));
        with_ctx(&mut fs, |ctx| {
            if config {
                append_config_write(ctx, 1);
            } else {
                append_run(ctx, ev, 0, &[]);
            }
        });
        medium.stick(None);
        assert_eq!(medium.value(EF_AUDIT_META).unwrap(), saved);
        assert_eq!(chain_head(&dev(), &mut fs).unwrap().0, head);
        let first = medium.value(slot_fid(0)).unwrap();
        medium.stick(Some(slot_fid(0)));
        with_ctx(&mut fs, |ctx| {
            if config {
                append_config_write(ctx, 1);
            } else {
                append_run(ctx, ev, 0, &[]);
            }
        });
        medium.stick(None);
        assert_eq!(medium.value(slot_fid(0)).unwrap(), first);
        assert_eq!(load_meta(&dev(), &mut fs).unwrap().seq_next, 2);
        with_ctx(&mut fs, |ctx| {
            if config {
                append_config_write(ctx, 1);
            } else {
                append_run(ctx, ev, 0, &[]);
            }
        });
        let (_, m) = chain_head(&dev(), &mut fs).unwrap();
        assert_eq!((m.start, m.seq_next), (0, 2));
        let entry = medium.value(slot_fid(1)).unwrap();
        let at = if config {
            CW_REPEATS_AT
        } else {
            RUN_REPEATS_AT
        };
        assert_eq!(u16::from_le_bytes(entry[at..at + 2].try_into().unwrap()), 1);
    }
}

#[test]
fn coalescing_skips_missing_and_unrelated_events() {
    for config in [false, true] {
        let mut fs = Fs::new(RamStorage::new());
        set_enabled(&mut fs, true).unwrap();
        for round in 0..2 {
            with_ctx(&mut fs, |ctx| {
                if config {
                    append_config_write(ctx, 1);
                } else {
                    append_run(ctx, EV_GET_ASSERT, 0, &[]);
                }
            });
            assert_eq!(load_meta(&dev(), &mut fs).unwrap().seq_next, round * 2 + 1);
            fs.delete(slot_fid(round * 2)).unwrap();
            raw_append(&dev(), &mut fs, 12345, EV_PIN_SET, 0, &[]).unwrap();
        }
    }
}

#[test]
fn a_faulted_display_walk_keeps_the_reported_count_and_healthy_neighbors() {
    let (mut fs, medium, _) = stuck_journal(3);
    medium.stick(Some(EF_AUDIT_META));
    assert_eq!(
        for_each_event(&dev(), &mut fs, |_| panic!("faulted metadata")),
        0
    );
    medium.stick(Some(slot_fid(1)));
    let mut seen = 0;
    assert_eq!(
        for_each_event(&dev(), &mut fs, |_| {
            seen += 1;
            true
        }),
        3
    );
    assert_eq!(seen, 2);
    medium.stick(None);
    assert_eq!(for_each_event(&dev(), &mut fs, |_| true), 3);
}

#[test]
fn checkpoint_refusals_do_not_append_a_checkpoint_event() {
    let (mut fs, _, _) = stuck_journal(2);
    let (head, meta) = chain_head(&dev(), &mut fs).unwrap();
    let generation = fs.write_gen();
    let mut state = FidoState::new();
    state.audit_boot_logged = true;
    state.devk_source = Some(rsk_crypto::FusedKey::open(|out| {
        *out = [7; 32];
        true
    }));
    let mut out = [0xA5; 512];
    for (challenge, capacity, expected) in [
        (&[0x55; 33][..], 512, CtapError::InvalidParameter),
        (&[0x55; 32][..], 1, CtapError::Other),
    ] {
        let result = vendor_checkpoint(
            &mut Ctx {
                dev: dev(),
                fs: &mut fs,
                rng: &mut SeqRng(1),
                state: &mut state,
                now_ms: 12345,
                presence: &mut AlwaysConfirm,
            },
            challenge,
            &mut out[..capacity],
        );
        assert_eq!(result, Err(expected));
        assert_eq!(&out[capacity..], &[0xA5; 512][capacity..]);
        assert_eq!(chain_head(&dev(), &mut fs).unwrap().0, head);
        assert_eq!(load_meta(&dev(), &mut fs).unwrap().seq_next, meta.seq_next);
    }
    assert_eq!(fs.write_gen(), generation);
    run_ctx(&mut fs, &mut state, |ctx| {
        vendor_checkpoint(ctx, &[0x55; 32], &mut out)
    })
    .unwrap();
    assert_eq!(
        load_meta(&dev(), &mut fs).unwrap().seq_next,
        meta.seq_next + 1
    );
}
