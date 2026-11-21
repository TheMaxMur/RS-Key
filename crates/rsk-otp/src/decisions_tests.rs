// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

struct MeasuredPresence {
    answer: Presence,
    hits: usize,
}

impl UserPresence for MeasuredPresence {
    fn request(&mut self, _confirm: Confirm<'_>) -> Presence {
        self.hits += 1;
        self.answer
    }
}

fn slots<S: Storage>(app: &OtpApplet, fs: &mut Fs<S>) -> Vec<Option<Vec<u8>>> {
    (EF_OTP_SLOT1..=EF_OTP_SLOT_LAST)
        .map(|fid| {
            let mut rec = SlotRecord::vacant();
            app.try_read_slot_m(fs, fid, &mut rec)
                .unwrap()
                .map(|n| rec.expose()[..n].to_vec())
        })
        .collect()
}

#[test]
fn either_reserved_config_byte_refuses_before_a_slot_changes() {
    for slot in 0..SLOT_COUNT {
        let presence = RefCell::new(AlwaysConfirm);
        let rng = RefCell::new(CountRng(7));
        let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
        let mut fs = new_fs();
        let code = [1; ACC_CODE_SIZE];
        let good = chalresp_config(&[0xab; 20], &code, 0);
        assert_eq!(
            configure(&mut app, &mut fs, P1_CONFIG_SLOT1, slot, &good, &[0; 6]).0,
            Sw::OK
        );
        let before = slots(&app, &mut fs);
        let generation = fs.write_gen();
        for reserved in [OFF_RFU, OFF_RFU + 1] {
            let mut bad = good;
            bad[reserved] = 1;
            let crc = !crc16(&bad[..CONFIG_SIZE - 2]);
            bad[CONFIG_SIZE - 2..].copy_from_slice(&crc.to_le_bytes());
            assert_eq!(
                configure(&mut app, &mut fs, P1_CONFIG_SLOT1, slot, &bad, &code),
                (SW_WRONG_DATA, vec![])
            );
            assert_eq!(slots(&app, &mut fs), before);
            assert_eq!(fs.write_gen(), generation);
            assert_eq!(app.config_seq, 2);
        }
        assert_eq!(
            configure(&mut app, &mut fs, P1_CONFIG_SLOT1, slot, &good, &code).0,
            Sw::OK
        );
        assert_eq!(app.config_seq, 3);
    }
}

#[test]
fn extended_status_discloses_a_public_id_only_for_plain_yubico_otp() {
    for (tkt, cfg, plain) in [
        (0, 0, true),
        (TKT_APPEND_CR, CFG_CHAL_YUBICO, false),
        (TKT_CHAL_RESP, CFG_CHAL_YUBICO, false),
        (TKT_CHAL_RESP, CFG_CHAL_HMAC, false),
        (TKT_OATH_HOTP, 0, false),
        (TKT_OATH_HOTP, CFG_OATH_HOTP8, false),
        (0, CFG_SHORT_TICKET, false),
        (0, CFG_STATIC_TICKET, false),
    ] {
        let presence = RefCell::new(AlwaysConfirm);
        let rng = RefCell::new(CountRng(7));
        let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
        let mut fs = new_fs();
        let mut expected = vec![];
        for slot in 0..SLOT_COUNT {
            let fixed = [b'c' + slot; 6];
            let config = build_config(&fixed, &[0x55; 6], &[0xab; 16], &[0; 6], 0, tkt, cfg);
            assert_eq!(
                configure(&mut app, &mut fs, P1_CONFIG_SLOT1, slot, &config, &[0; 6]).0,
                Sw::OK
            );
            expected.extend_from_slice(&[
                0xb0 + slot,
                if plain { 12 } else { 4 },
                0xa0,
                2,
                tkt,
                cfg,
            ]);
            if plain {
                expected.extend_from_slice(&[0xc0, 6]);
                expected.extend_from_slice(&fixed);
            }
        }
        let generation = fs.write_gen();
        assert_eq!(
            run(&mut app, &mut fs, &otp_apdu(0x14, 0, &[])),
            (Sw::OK, expected)
        );
        assert_eq!(fs.write_gen(), generation);
        assert_eq!(app.config_seq, 5);
    }
}

#[test]
fn challenge_modes_and_touch_results_preserve_the_slot_until_confirmation() {
    for mode in [CFG_CHAL_YUBICO, CFG_CHAL_HMAC] {
        for touch in [false, true] {
            for answer in [
                Presence::Confirmed,
                Presence::Declined,
                Presence::Timeout,
                Presence::Cancelled,
            ] {
                let presence = RefCell::new(MeasuredPresence { answer, hits: 0 });
                let rng = RefCell::new(CountRng(7));
                let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
                let mut fs = new_fs();
                let cfg = mode | if touch { CFG_CHAL_BTN_TRIG } else { 0 };
                let config =
                    build_config(&[], &[0; 6], &[0x42; 16], &[0; 6], 0, TKT_CHAL_RESP, cfg);
                assert_eq!(
                    configure(&mut app, &mut fs, P1_CONFIG_SLOT1, 0, &config, &[0; 6]).0,
                    Sw::OK
                );
                let before = slots(&app, &mut fs);
                let generation = fs.write_gen();
                let (p1, challenge) = if mode == CFG_CHAL_HMAC {
                    (P1_CHAL_HMAC_SLOT1, vec![0x5a; hid::PAYLOAD_SIZE])
                } else {
                    (P1_CHAL_OTP_SLOT1, vec![9, 8, 7, 6, 5, 4])
                };
                let command = otp_apdu(p1, 0, &challenge);
                let result = run(&mut app, &mut fs, &command);
                if touch && answer != Presence::Confirmed {
                    assert_eq!(result, (Sw::CONDITIONS_NOT_SATISFIED, vec![]));
                } else {
                    assert_eq!(result.0, Sw::OK);
                }
                assert_eq!(presence.borrow().hits, usize::from(touch));
                assert_eq!(slots(&app, &mut fs), before);
                assert_eq!(fs.write_gen(), generation);
                assert_eq!(app.session_counter, [0; SLOT_COUNT as usize]);
                assert_eq!(app.advanced, [false; SLOT_COUNT as usize]);
                presence.borrow_mut().answer = Presence::Confirmed;
                let (sw, body) = run(&mut app, &mut fs, &command);
                assert_eq!(sw, Sw::OK);
                if mode == CFG_CHAL_HMAC {
                    assert_eq!(body, hmac_sha1(&[0x42; 16], &challenge));
                } else {
                    let mut block: [u8; 16] = body.try_into().unwrap();
                    tests_support::aes128_decrypt_block(&[0x42; 16], &mut block);
                    assert_eq!(&block[..6], &challenge);
                    assert_eq!(&block[6..], b"123456789A");
                }
                assert_eq!(presence.borrow().hits, 2 * usize::from(touch));
                assert_eq!(slots(&app, &mut fs), before);
            }
        }
    }
}

#[test]
fn yubico_challenges_refuse_short_bodies_and_slot_two_offsets() {
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let mut fs = new_fs();
    let config = build_config(
        &[],
        &[0; 6],
        &[0x42; 16],
        &[0; 6],
        0,
        TKT_CHAL_RESP,
        CFG_CHAL_YUBICO,
    );
    assert_eq!(
        configure(&mut app, &mut fs, P1_CONFIG_SLOT2, 0, &config, &[0; 6]).0,
        Sw::OK
    );
    let before = slots(&app, &mut fs);
    let generation = fs.write_gen();
    for len in 0..6 {
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                &otp_apdu(P1_CHAL_OTP_SLOT2, 0, &vec![0x55; len])
            ),
            (Sw::WRONG_LENGTH, vec![])
        );
    }
    for p1 in [P1_CHAL_OTP_SLOT2, P1_CHAL_HMAC_SLOT2] {
        for offset in [1, 3, u8::MAX] {
            assert_eq!(
                run(
                    &mut app,
                    &mut fs,
                    &otp_apdu(p1, offset, &[0x55; hid::PAYLOAD_SIZE])
                ),
                (Sw::INCORRECT_P1P2, vec![])
            );
        }
    }
    assert_eq!(slots(&app, &mut fs), before);
    assert_eq!(fs.write_gen(), generation);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &otp_apdu(P1_CHAL_OTP_SLOT2, 0, &[0x55; 6])
        )
        .1
        .len(),
        16
    );
}

#[test]
fn select_counts_classic_slots_but_not_the_extended_pair() {
    for slot in 0..SLOT_COUNT {
        let presence = RefCell::new(AlwaysConfirm);
        let rng = RefCell::new(CountRng(7));
        let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
        let mut fs = new_fs();
        let config = chalresp_config(&[0xab; 20], &[0; 6], 0);
        assert_eq!(
            configure(&mut app, &mut fs, P1_CONFIG_SLOT1, slot, &config, &[0; 6]).0,
            Sw::OK
        );
        let generation = fs.write_gen();
        let (major, minor, patch) = VERSION;
        let opts = match slot {
            0 => CONFIG1_VALID,
            1 => CONFIG2_VALID,
            _ => 0,
        };
        assert_eq!(
            select(&mut app, &mut fs),
            (
                Sw::OK,
                vec![major, minor, patch, u8::from(slot < 2), opts, 0]
            )
        );
        assert_eq!(fs.write_gen(), generation);
        assert_eq!(
            slots(&app, &mut fs)[usize::from(slot)].as_ref().unwrap()[..CONFIG_SIZE],
            config
        );
    }
}

#[test]
fn swap_checks_both_offset_bounds_before_mutating_any_slot() {
    for a in [0, 1, 2, 3, 4, u8::MAX] {
        for b in [0, 1, 2, 3, u8::MAX] {
            let presence = RefCell::new(AlwaysConfirm);
            let rng = RefCell::new(CountRng(7));
            let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
            let mut fs = new_fs();
            for slot in 0..SLOT_COUNT {
                let config = chalresp_config(&[0xa0 + slot; 20], &[0; 6], 0);
                assert_eq!(
                    configure(&mut app, &mut fs, P1_CONFIG_SLOT1, slot, &config, &[0; 6]).0,
                    Sw::OK
                );
            }
            let mut expected = slots(&app, &mut fs);
            let generation = fs.write_gen();
            let (sw, body) = run(&mut app, &mut fs, &otp_apdu(P1_SWAP, 0, &[a, b]));
            if a >= SLOT_COUNT || b >= SLOT_COUNT - 1 {
                assert_eq!((sw, body), (Sw::INCORRECT_P1P2, vec![]), "offsets {a}, {b}");
                assert_eq!(fs.write_gen(), generation);
                assert_eq!(app.config_seq, 5);
            } else {
                assert_eq!(sw, Sw::OK);
                assert_eq!(body.len(), 6);
                expected.swap(usize::from(a), usize::from(b) + 1);
                assert_eq!(app.config_seq, 6);
            }
            assert_eq!(slots(&app, &mut fs), expected);
            assert_eq!(app.session_counter, [0; SLOT_COUNT as usize]);
            assert_eq!(app.advanced, [false; SLOT_COUNT as usize]);
        }
    }
}

#[test]
fn the_first_refused_swap_write_preserves_both_records_and_can_be_retried() {
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let (mut fs, refused, budget) = write_stuck_fs();
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    for slot in 0..2 {
        let config = chalresp_config(&[0xa0 + slot; 20], &[0; 6], 0);
        assert_eq!(
            configure(&mut app, &mut fs, P1_CONFIG_SLOT1, slot, &config, &[0; 6]).0,
            Sw::OK
        );
    }
    let mut expected = slots(&app, &mut fs);
    refused.set(Some(EF_OTP_SLOT1));
    budget.set(1);
    assert_eq!(
        run(&mut app, &mut fs, &otp_apdu(P1_SWAP, 0, &[])),
        (Sw::MEMORY_FAILURE, vec![])
    );
    assert_eq!(slots(&app, &mut fs), expected);
    assert_eq!(app.config_seq, 3);
    assert_eq!(budget.get(), 0);
    refused.set(None);
    assert_eq!(run(&mut app, &mut fs, &otp_apdu(P1_SWAP, 0, &[])).0, Sw::OK);
    expected.swap(0, 1);
    assert_eq!(slots(&app, &mut fs), expected);
    assert_eq!(app.config_seq, 4);
}

#[test]
fn swap_accepts_completed_deletes_when_an_unrelated_metadata_read_fails() {
    for occupied in [0, 1] {
        let (backend, medium) = MetaStuck::new();
        let mut fs = Fs::new(backend);
        fs.scan();
        fs.meta_add(0x1234, &[1, 2, 3]).unwrap();
        let presence = RefCell::new(AlwaysConfirm);
        let rng = RefCell::new(CountRng(7));
        let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
        let config = chalresp_config(&[0xab; 20], &[0; 6], 0);
        assert_eq!(
            configure(
                &mut app,
                &mut fs,
                P1_CONFIG_SLOT1,
                occupied,
                &config,
                &[0; 6]
            )
            .0,
            Sw::OK
        );
        let mut expected = slots(&app, &mut fs);
        medium.stick(true);
        let result = run(&mut app, &mut fs, &otp_apdu(P1_SWAP, 0, &[]));
        medium.stick(false);
        assert_eq!(result.0, Sw::OK);
        assert_eq!(
            result.1[4],
            if occupied == 0 {
                CONFIG2_VALID
            } else {
                CONFIG1_VALID
            }
        );
        expected.swap(0, 1);
        assert_eq!(slots(&app, &mut fs), expected);
        assert!(!medium.live(EF_OTP_SLOT1 + u16::from(occupied)));
        assert_eq!(app.config_seq, 3);
    }
}

#[cfg(not(feature = "strict-config"))]
#[test]
fn a_scan_map_without_a_code_is_allowed_only_when_every_slot_is_unprotected() {
    for protected in [None, Some(0), Some(1), Some(2), Some(3)] {
        let presence = RefCell::new(AlwaysConfirm);
        let rng = RefCell::new(CountRng(7));
        let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
        let mut fs = new_fs();
        if let Some(slot) = protected {
            let config = chalresp_config(&[0xab; 20], &[1; 6], 0);
            assert_eq!(
                configure(&mut app, &mut fs, P1_CONFIG_SLOT1, slot, &config, &[0; 6]).0,
                Sw::OK
            );
        }
        let before = slots(&app, &mut fs);
        let generation = fs.write_gen();
        let sequence = app.config_seq;
        let result = run(
            &mut app,
            &mut fs,
            &otp_apdu(P1_SCAN_MAP, 0, &[0x40; SCANMAP_LEN]),
        );
        if protected.is_some() {
            assert_eq!(result, (Sw::SECURITY_STATUS_NOT_SATISFIED, vec![]));
            assert!(!fs.has_data(EF_OTP_SCANMAP));
            assert_eq!(fs.write_gen(), generation);
            assert_eq!(app.config_seq, sequence);
            let body = [&[0x40; SCANMAP_LEN][..], &[1; 6]].concat();
            assert_eq!(
                run(&mut app, &mut fs, &otp_apdu(P1_SCAN_MAP, 0, &body)),
                (Sw::OK, vec![])
            );
        } else {
            assert_eq!(result, (Sw::OK, vec![]));
        }
        let mut map = [0; SCANMAP_LEN];
        assert_eq!(fs.read(EF_OTP_SCANMAP, &mut map), Some(SCANMAP_LEN));
        assert_eq!(map, [0x40; SCANMAP_LEN]);
        assert_eq!(slots(&app, &mut fs), before);
        assert_eq!(app.config_seq, sequence + 1);
    }
}

#[cfg(not(feature = "strict-config"))]
#[test]
fn an_empty_legacy_device_config_is_a_noop_over_an_existing_record() {
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let mut fs = new_fs();
    fs.put(EF_OTP_DEVCFG, &[0x55; EF_OTP_DEVCFG_MAX]).unwrap();
    let generation = fs.write_gen();
    assert_eq!(
        run(&mut app, &mut fs, &otp_apdu(P1_DEVICE_CONFIG, 0, &[])),
        (Sw::OK, vec![])
    );
    let mut config = [0; EF_OTP_DEVCFG_MAX];
    assert_eq!(fs.read(EF_OTP_DEVCFG, &mut config), Some(EF_OTP_DEVCFG_MAX));
    assert_eq!(config, [0x55; EF_OTP_DEVCFG_MAX]);
    assert_eq!(fs.write_gen(), generation);
    assert_eq!(app.config_seq, 1);
}
