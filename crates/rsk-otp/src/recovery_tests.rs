// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use std::cell::Cell;

const FUSED: [u8; 32] = [0x77; 32];
const KEY: [u8; KEY_SIZE] = [0xab; KEY_SIZE];

#[derive(Clone, Copy)]
enum Reader {
    Ready,
    Unread,
    Through(usize),
}

thread_local! {
    static READER: Cell<(Reader, usize)> = const { Cell::new((Reader::Ready, 0)) };
}

fn arm_reader(answer: Reader) {
    READER.set((answer, 0));
}

fn fused(out: &mut [u8; 32]) -> bool {
    READER.with(|state| {
        let (answer, reads) = state.get();
        let (next, ok) = match answer {
            Reader::Ready => (Reader::Ready, true),
            Reader::Unread | Reader::Through(0) => (Reader::Unread, false),
            Reader::Through(n) => (Reader::Through(n - 1), true),
        };
        state.set((next, reads + 1));
        out.copy_from_slice(&FUSED);
        ok
    })
}

fn device(otp_key: Option<&[u8; 32]>) -> Device<'_> {
    Device {
        serial_hash: &SERIAL_HASH,
        serial_id: &SERIAL,
        otp_key,
        latched: false,
    }
}

fn slot(counter: u16) -> SlotRecord {
    let cfg = build_config(b"public", &[1; 6], &KEY, &[0; 6], 0, 0, 0);
    let mut bytes = [0; SLOT_SIZE];
    bytes[..CONFIG_SIZE].copy_from_slice(&cfg);
    bytes[CONFIG_SIZE..CONFIG_SIZE + 2].copy_from_slice(&counter.to_be_bytes());
    SlotRecord::from_bytes(&bytes).unwrap()
}

fn raw_slot<S: Storage>(fs: &mut Fs<S>, fid: u16) -> Option<Vec<u8>> {
    let mut bytes = [0; seal::MAX_BLOB];
    fs.read_key(KeyFid::new(fid), &mut bytes)
        .map(|n| bytes[..n].to_vec())
}

fn reopen<S: Storage>(fs: Fs<S>) -> Fs<S> {
    let mut reopened = Fs::new(fs.into_storage());
    reopened.scan();
    reopened
}

#[test]
fn the_last_use_counter_advance_and_session_wrap_stop_at_the_ceiling() {
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut fs = new_fs();
    assert!(seal::seal_put(
        &device(None),
        &mut fs,
        &mut *rng.borrow_mut(),
        KeyFid::new(EF_OTP_SLOT1),
        &slot(USE_COUNTER_MAX - 1)
    ));
    let generation = fs.write_gen();
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    for session in 0..=u8::MAX {
        assert_eq!(
            press_position(&mut app, &mut fs, 1, &KEY),
            Some((*b"public", USE_COUNTER_MAX, session))
        );
        assert_eq!(fs.write_gen(), generation + 1);
    }
    let stored = raw_slot(&mut fs, EF_OTP_SLOT1);
    assert_eq!(app.session_counter[0], 0);
    assert!(app.advanced[0]);
    assert_eq!(
        press_position(&mut app, &mut fs, 1, &KEY),
        Some((*b"public", USE_COUNTER_MAX, 0))
    );
    assert_eq!(raw_slot(&mut fs, EF_OTP_SLOT1), stored);
    fs = reopen(fs);
    let mut rebooted = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    assert_eq!(
        press_position(&mut rebooted, &mut fs, 1, &KEY),
        Some((*b"public", USE_COUNTER_MAX, 0))
    );
    assert_eq!(raw_slot(&mut fs, EF_OTP_SLOT1), stored);
    assert_eq!(fs.write_gen(), 0);
}

#[test]
fn a_first_press_never_lowers_an_at_or_above_ceiling_record() {
    for counter in [USE_COUNTER_MAX, USE_COUNTER_MAX + 1, u16::MAX] {
        let presence = RefCell::new(AlwaysConfirm);
        let rng = RefCell::new(CountRng(7));
        let mut fs = new_fs();
        assert!(seal::seal_put(
            &device(None),
            &mut fs,
            &mut *rng.borrow_mut(),
            KeyFid::new(EF_OTP_SLOT1),
            &slot(counter)
        ));
        let stored = raw_slot(&mut fs, EF_OTP_SLOT1);
        fs = reopen(fs);
        let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
        for session in [0, 1] {
            assert_eq!(
                press_position(&mut app, &mut fs, 1, &KEY),
                Some((*b"public", counter, session))
            );
        }
        assert_eq!(raw_slot(&mut fs, EF_OTP_SLOT1), stored);
        assert_eq!(fs.write_gen(), 0);
        assert!(app.advanced[0]);
    }
}

#[test]
fn a_refused_last_counter_advance_stays_owed_after_another_failed_boot() {
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let (mut fs, refused, budget) = write_stuck_fs();
    assert!(seal::seal_put(
        &device(None),
        &mut fs,
        &mut *rng.borrow_mut(),
        KeyFid::new(EF_OTP_SLOT1),
        &slot(USE_COUNTER_MAX - 1)
    ));
    let stored = raw_slot(&mut fs, EF_OTP_SLOT1);
    refused.set(Some(EF_OTP_SLOT1));
    budget.set(2);
    for _ in 0..2 {
        fs = reopen(fs);
        let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
        assert_eq!(press_position(&mut app, &mut fs, 1, &KEY), None);
        assert_eq!(raw_slot(&mut fs, EF_OTP_SLOT1), stored);
        assert_eq!(fs.write_gen(), 0);
        assert_eq!(app.session_counter, [0; SLOT_COUNT as usize]);
        assert_eq!(app.advanced, [false; SLOT_COUNT as usize]);
    }
    assert_eq!(budget.get(), 0);
    fs = reopen(fs);
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    assert_eq!(
        press_position(&mut app, &mut fs, 1, &KEY),
        Some((*b"public", USE_COUNTER_MAX, 0))
    );
    assert_eq!(fs.write_gen(), 1);
    assert_eq!(
        press_position(&mut app, &mut fs, 1, &KEY),
        Some((*b"public", USE_COUNTER_MAX, 1))
    );
    assert_eq!(fs.write_gen(), 1);
}

#[test]
fn a_fused_key_lost_between_slot_probe_and_write_refuses_the_mutation() {
    for command in [P1_CONFIG_SLOT1, P1_UPDATE_SLOT1] {
        arm_reader(Reader::Ready);
        let presence = RefCell::new(AlwaysConfirm);
        let rng = RefCell::new(CountRng(7));
        let mut app = OtpApplet::new(
            SERIAL,
            SERIAL_HASH,
            Some(FusedKey::latched(fused)),
            &rng,
            &presence,
        );
        let mut fs = new_fs();
        let old = chalresp_config(&[0xab; 20], &[1; 6], 0);
        let new = chalresp_config(&[0xac; 20], &[2; 6], CFG_HMAC_LT64);
        assert_eq!(
            configure(&mut app, &mut fs, P1_CONFIG_SLOT1, 0, &old, &[0; 6]).0,
            Sw::OK
        );
        let stored = raw_slot(&mut fs, EF_OTP_SLOT1);
        let generation = fs.write_gen();
        arm_reader(Reader::Through(1));
        assert_eq!(
            configure(&mut app, &mut fs, command, 0, &new, &[1; 6]),
            (Sw::MEMORY_FAILURE, vec![])
        );
        assert_eq!(READER.get().1, 2);
        assert_eq!(raw_slot(&mut fs, EF_OTP_SLOT1), stored);
        assert_eq!(fs.write_gen(), generation);
        assert_eq!(app.config_seq, 2);
        arm_reader(Reader::Ready);
        assert_eq!(
            configure(&mut app, &mut fs, command, 0, &new, &[1; 6]).0,
            Sw::OK
        );
        assert_eq!(app.config_seq, 3);
        assert_eq!(
            configure(
                &mut app,
                &mut fs,
                P1_CONFIG_SLOT1,
                0,
                &[0; CONFIG_SIZE],
                &[1; 6]
            ),
            (Sw::SECURITY_STATUS_NOT_SATISFIED, vec![])
        );
        assert_eq!(
            configure(
                &mut app,
                &mut fs,
                P1_CONFIG_SLOT1,
                0,
                &[0; CONFIG_SIZE],
                &[2; 6]
            )
            .0,
            Sw::OK
        );
    }
}

#[test]
fn a_button_press_with_a_lost_fused_key_cannot_spend_its_boot_advance() {
    arm_reader(Reader::Ready);
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(
        SERIAL,
        SERIAL_HASH,
        Some(FusedKey::latched(fused)),
        &rng,
        &presence,
    );
    let mut fs = new_fs();
    let config = build_config(b"public", &[1; 6], &KEY, &[0; 6], 0, 0, 0);
    assert_eq!(
        configure(&mut app, &mut fs, P1_CONFIG_SLOT1, 0, &config, &[0; 6]).0,
        Sw::OK
    );
    let stored = raw_slot(&mut fs, EF_OTP_SLOT1);
    let generation = fs.write_gen();
    arm_reader(Reader::Through(1));
    assert_eq!(press_position(&mut app, &mut fs, 1, &KEY), None);
    assert_eq!(READER.get().1, 2);
    assert_eq!(raw_slot(&mut fs, EF_OTP_SLOT1), stored);
    assert_eq!(fs.write_gen(), generation);
    assert_eq!(app.session_counter, [0; SLOT_COUNT as usize]);
    assert_eq!(app.advanced, [false; SLOT_COUNT as usize]);
    arm_reader(Reader::Ready);
    assert_eq!(
        press_position(&mut app, &mut fs, 1, &KEY),
        Some((*b"public", 1, 0))
    );
    assert_eq!(
        press_position(&mut app, &mut fs, 1, &KEY),
        Some((*b"public", 1, 1))
    );
}

#[test]
fn swap_refuses_an_unread_latched_key_before_either_record_moves() {
    arm_reader(Reader::Ready);
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(
        SERIAL,
        SERIAL_HASH,
        Some(FusedKey::latched(fused)),
        &rng,
        &presence,
    );
    let mut fs = new_fs();
    for offset in 0..2 {
        let cfg = chalresp_config(&[0xab + offset; 20], &[0; 6], 0);
        assert_eq!(
            configure(&mut app, &mut fs, P1_CONFIG_SLOT1, offset, &cfg, &[0; 6]).0,
            Sw::OK
        );
    }
    let before = [
        raw_slot(&mut fs, EF_OTP_SLOT1),
        raw_slot(&mut fs, EF_OTP_SLOT2),
    ];
    let generation = fs.write_gen();
    arm_reader(Reader::Unread);
    assert_eq!(
        run(&mut app, &mut fs, &otp_apdu(P1_SWAP, 0, &[])),
        (Sw::FUSED_KEY_UNREAD, vec![])
    );
    assert_eq!(READER.get().1, 1);
    assert_eq!(
        [
            raw_slot(&mut fs, EF_OTP_SLOT1),
            raw_slot(&mut fs, EF_OTP_SLOT2)
        ],
        before
    );
    assert_eq!(fs.write_gen(), generation);
    assert_eq!(app.config_seq, 3);
    arm_reader(Reader::Ready);
    assert_eq!(run(&mut app, &mut fs, &otp_apdu(P1_SWAP, 0, &[])).0, Sw::OK);
    for (p1, key) in [(P1_CHAL_HMAC_SLOT1, 0xac), (P1_CHAL_HMAC_SLOT2, 0xab)] {
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                &otp_apdu(p1, 0, &[0x55; hid::PAYLOAD_SIZE])
            ),
            (
                Sw::OK,
                hmac_sha1(&[key; 20], &[0x55; hid::PAYLOAD_SIZE]).to_vec()
            )
        );
    }
}

#[test]
fn both_swap_writes_use_the_one_fused_read_even_if_status_cannot_read_it() {
    arm_reader(Reader::Ready);
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(
        SERIAL,
        SERIAL_HASH,
        Some(FusedKey::latched(fused)),
        &rng,
        &presence,
    );
    let mut fs = new_fs();
    for offset in 0..2 {
        let cfg = chalresp_config(&[0xab + offset; 20], &[0; 6], 0);
        assert_eq!(
            configure(&mut app, &mut fs, P1_CONFIG_SLOT1, offset, &cfg, &[0; 6]).0,
            Sw::OK
        );
    }
    let generation = fs.write_gen();
    arm_reader(Reader::Through(1));
    let (major, minor, patch) = VERSION;
    assert_eq!(
        run(&mut app, &mut fs, &otp_apdu(P1_SWAP, 0, &[])),
        (Sw::OK, vec![major, minor, patch, 4, 0, 0])
    );
    assert_eq!(READER.get().1, 3);
    assert_eq!(fs.write_gen(), generation + 2);
    arm_reader(Reader::Ready);
    for (p1, key) in [(P1_CHAL_HMAC_SLOT1, 0xac), (P1_CHAL_HMAC_SLOT2, 0xab)] {
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                &otp_apdu(p1, 0, &[0x55; hid::PAYLOAD_SIZE])
            ),
            (
                Sw::OK,
                hmac_sha1(&[key; 20], &[0x55; hid::PAYLOAD_SIZE]).to_vec()
            )
        );
    }
}

#[test]
fn repeated_migration_write_refusals_preserve_the_old_root_and_counter() {
    for (has_otp, presealed) in [(false, false), (true, false), (true, true)] {
        let presence = RefCell::new(AlwaysConfirm);
        let rng = RefCell::new(CountRng(7));
        let (mut fs, refused, budget) = write_stuck_fs();
        let current = device(has_otp.then_some(&FUSED));
        let rec = slot(5);
        if presealed {
            assert!(seal::seal_put(
                &device(None),
                &mut fs,
                &mut *rng.borrow_mut(),
                KeyFid::new(EF_OTP_SLOT1),
                &rec
            ));
        } else {
            fs.put(EF_OTP_SLOT1, rec.stored()).unwrap();
        }
        fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
        let stored = raw_slot(&mut fs, EF_OTP_SLOT1);
        refused.set(Some(EF_OTP_SLOT1));
        budget.set(2);
        for _ in 0..2 {
            fs = reopen(fs);
            assert_eq!(
                migrate_seal(&current, &mut fs, &mut *rng.borrow_mut()),
                has_otp
            );
            assert_eq!(raw_slot(&mut fs, EF_OTP_SLOT1), stored);
            assert_eq!(fs.has_data(rsk_fs::EF_HARDENED), !has_otp);
            let mut read = SlotRecord::vacant();
            assert_eq!(
                try_read_slot(&current, &mut fs, EF_OTP_SLOT1, &mut read),
                Ok(None)
            );
        }
        assert_eq!(budget.get(), 0);
        fs = reopen(fs);
        assert!(!migrate_seal(&current, &mut fs, &mut *rng.borrow_mut()));
        let mut read = SlotRecord::vacant();
        assert_eq!(
            try_read_slot(&current, &mut fs, EF_OTP_SLOT1, &mut read),
            Ok(Some(SLOT_SIZE))
        );
        assert_eq!(read.stored(), rec.stored());
        let migrated = raw_slot(&mut fs, EF_OTP_SLOT1);
        assert_ne!(migrated, stored);
        let generation = fs.write_gen();
        assert!(!migrate_seal(&current, &mut fs, &mut *rng.borrow_mut()));
        assert_eq!(raw_slot(&mut fs, EF_OTP_SLOT1), migrated);
        assert_eq!(fs.write_gen(), generation);
        arm_reader(Reader::Ready);
        let source = has_otp.then_some(FusedKey::open(fused));
        let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, source, &rng, &presence);
        assert_eq!(
            press_position(&mut app, &mut fs, 1, &KEY),
            Some((*b"public", 6, 0))
        );
    }
}

#[test]
fn a_second_recovery_read_fault_cannot_ack_or_replace_an_unmigrated_slot() {
    for presealed in [false, true] {
        let faults = if presealed {
            &[0, 1][..]
        } else {
            &[0, 1, 2][..]
        };
        for &skip in faults {
            let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
            let mut fs = Fs::new(backend);
            fs.scan();
            let mut rng = CountRng(7);
            let rec = slot(5);
            if presealed {
                assert!(seal::seal_put(
                    &device(None),
                    &mut fs,
                    &mut rng,
                    KeyFid::new(EF_OTP_SLOT1),
                    &rec
                ));
            } else {
                fs.put(EF_OTP_SLOT1, rec.stored()).unwrap();
            }
            fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
            let stored = medium.value(EF_OTP_SLOT1);
            for _ in 0..2 {
                fs = reopen(fs);
                medium.stick_after(EF_OTP_SLOT1, skip);
                assert!(
                    migrate_seal(&device(Some(&FUSED)), &mut fs, &mut rng),
                    "presealed={presealed}, skip={skip}"
                );
                medium.stick(None);
                assert_eq!(medium.value(EF_OTP_SLOT1), stored);
                assert!(fs.has_data(rsk_fs::EF_HARDENED));
                assert_eq!(fs.write_gen(), 0);
            }
            fs = reopen(fs);
            assert!(!migrate_seal(&device(Some(&FUSED)), &mut fs, &mut rng));
            let mut read = SlotRecord::vacant();
            assert_eq!(
                try_read_slot(&device(Some(&FUSED)), &mut fs, EF_OTP_SLOT1, &mut read),
                Ok(Some(SLOT_SIZE))
            );
            assert_eq!(read.stored(), rec.stored());
            assert!(!fs.has_data(rsk_fs::EF_HARDENED));
        }
    }
}

#[test]
fn directly_constructed_apdus_refuse_inconsistent_lengths_without_mutation() {
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let mut fs = new_fs();
    let cfg = chalresp_config(&[0xab; 20], &[0; 6], 0);
    assert_eq!(
        configure(&mut app, &mut fs, P1_CONFIG_SLOT1, 0, &cfg, &[0; 6]).0,
        Sw::OK
    );
    let stored = raw_slot(&mut fs, EF_OTP_SLOT1);
    let generation = fs.write_gen();
    for (p1, nc, data) in [
        (P1_CONFIG_SLOT1, CONFIG_SIZE, &cfg[..CONFIG_SIZE - 1]),
        (P1_UPDATE_SLOT1, CONFIG_SIZE, &cfg[..CONFIG_SIZE - 1]),
        (P1_CHAL_HMAC_SLOT1, hid::PAYLOAD_SIZE, &cfg[..]),
        (P1_SWAP, ACC_CODE_SIZE, &[0; ACC_CODE_SIZE - 1][..]),
        (P1_SWAP, 2, &[0][..]),
        (P1_SWAP, 2 + ACC_CODE_SIZE, &[0; 2 + ACC_CODE_SIZE - 1][..]),
    ] {
        let raw = otp_apdu(p1, 0, data);
        let mut apdu = Apdu::parse(&raw).unwrap();
        apdu.nc = nc;
        let mut out = [0x55; 64];
        let mut res = ResBuf::new(&mut out);
        assert_eq!(
            Applet::process(&mut app, &apdu, &mut fs, &mut res),
            Sw::WRONG_LENGTH
        );
        assert!(res.as_slice().is_empty());
        assert_eq!(out, [0x55; 64]);
        assert_eq!(raw_slot(&mut fs, EF_OTP_SLOT1), stored);
        assert_eq!(fs.write_gen(), generation);
        assert_eq!(app.config_seq, 2);
    }
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &otp_apdu(P1_CHAL_HMAC_SLOT1, 0, &[0x55; hid::PAYLOAD_SIZE])
        ),
        (
            Sw::OK,
            hmac_sha1(&[0xab; 20], &[0x55; hid::PAYLOAD_SIZE]).to_vec()
        )
    );
}
