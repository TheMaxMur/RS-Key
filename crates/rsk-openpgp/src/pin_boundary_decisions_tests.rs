// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::faults::ProbeStuck;

fn stored<S: Storage>(fs: &mut Fs<S>, fid: u16) -> Option<Vec<u8>> {
    let mut out = [0; rsk_fs::MAX_VALUE_BYTES];
    fs.read(fid, &mut out)
        .map(|n| out[..n.min(out.len())].to_vec())
}

#[test]
fn undefined_verify_p1_never_queries_compares_or_changes_a_standing_session() {
    for authenticated in [false, true] {
        let mut fs = setup();
        let mut sess = Session::new();
        if authenticated {
            arm_all(&dev(), &mut fs, &mut sess);
        }
        let generation = fs.write_gen();
        let counters = stored(&mut fs, EF_PW_PRIV);
        for (mode, pin) in [
            (PW1_MODE81, PW1_DEFAULT),
            (PW1_MODE82, PW1_DEFAULT),
            (PW3_MODE83, PW3_DEFAULT),
        ] {
            for p1 in 1..0xFF {
                for body in [&[][..], pin] {
                    assert_eq!(
                        verify(&dev(), &mut fs, &mut sess, &mut CountRng(7), p1, mode, body),
                        Sw::WRONG_P1P2,
                        "P1={p1:02X}, mode={mode:02X}, authenticated={authenticated}"
                    );
                    assert_eq!(
                        (sess.has_pw1, sess.has_pw2, sess.has_pw3),
                        (authenticated, authenticated, authenticated)
                    );
                    assert!(!sess.has_rc);
                    if authenticated {
                        assert_eq!(
                            &sess.session_pw1,
                            dev().pin_derive_session(PW1_DEFAULT).expose()
                        );
                        assert_eq!(
                            &sess.session_pw3,
                            dev().pin_derive_session(PW3_DEFAULT).expose()
                        );
                    } else {
                        assert_eq!(sess.session_pw1, [0; 32]);
                        assert_eq!(sess.session_pw3, [0; 32]);
                    }
                    assert_eq!(fs.write_gen(), generation);
                }
            }
        }
        assert_eq!(stored(&mut fs, EF_PW_PRIV), counters);
    }
}

#[test]
fn a_missing_query_counter_reports_zero_without_revoking_a_standing_status() {
    for (mode, fid, pin) in [
        (PW1_MODE81, EF_PW1, PW1_DEFAULT),
        (PW1_MODE82, EF_PW1, PW1_DEFAULT),
        (PW3_MODE83, EF_PW3, PW3_DEFAULT),
    ] {
        for authenticated in [false, true] {
            for length in [None, Some(0), Some(pw_retry_idx(fid))] {
                let mut fs = setup();
                let mut sess = Session::new();
                if authenticated {
                    assert_eq!(
                        verify(&dev(), &mut fs, &mut sess, &mut CountRng(7), 0, mode, pin),
                        Sw::OK
                    );
                }
                let counters = stored(&mut fs, EF_PW_PRIV).unwrap();
                match length {
                    None => fs.delete(EF_PW_PRIV).unwrap(),
                    Some(n) => fs.put(EF_PW_PRIV, &counters[..n]).unwrap(),
                }
                let generation = fs.write_gen();
                let broken = stored(&mut fs, EF_PW_PRIV);
                assert_eq!(
                    verify(&dev(), &mut fs, &mut sess, &mut CountRng(7), 0, mode, &[]),
                    if authenticated {
                        Sw::OK
                    } else {
                        Sw::retries(0)
                    }
                );
                assert_eq!(
                    (sess.has_pw1, sess.has_pw2, sess.has_pw3),
                    (
                        authenticated && mode == PW1_MODE81,
                        authenticated && mode == PW1_MODE82,
                        authenticated && mode == PW3_MODE83
                    )
                );
                assert_eq!(stored(&mut fs, EF_PW_PRIV), broken);
                assert_eq!(fs.write_gen(), generation);
                fs.put(EF_PW_PRIV, &counters).unwrap();
                assert_eq!(
                    verify(&dev(), &mut fs, &mut sess, &mut CountRng(7), 0, mode, &[]),
                    if authenticated {
                        Sw::OK
                    } else {
                        Sw::retries(PW_RETRIES_DEFAULT)
                    }
                );
            }
        }
    }
}

#[test]
fn a_dek_load_without_any_access_status_cannot_read_or_recover_a_key() {
    let mut fs = setup();
    let pw1 = stored(&mut fs, EF_DEK_PW1.get());
    let pw3 = stored(&mut fs, EF_DEK_PW3.get());
    let generation = fs.write_gen();
    let mut sess = Session::new();
    let mut out = Secret::new([0xA5; DEK_SIZE]);
    assert_eq!(
        load_dek(&dev(), &mut fs, &sess, &mut out),
        Err(Sw::CONDITIONS_NOT_SATISFIED)
    );
    assert_eq!(out.expose(), &[0xA5; DEK_SIZE]);
    assert_eq!(stored(&mut fs, EF_DEK_PW1.get()), pw1);
    assert_eq!(stored(&mut fs, EF_DEK_PW3.get()), pw3);
    assert_eq!(fs.write_gen(), generation);
    assert_eq!(
        verify(
            &dev(),
            &mut fs,
            &mut sess,
            &mut CountRng(7),
            0,
            PW1_MODE81,
            PW1_DEFAULT
        ),
        Sw::OK
    );
    load_dek(&dev(), &mut fs, &sess, &mut out).unwrap();
    let mut expected = Secret::<[u8; DEK_SIZE]>::zeroed();
    for (i, byte) in expected.expose_mut().iter_mut().enumerate() {
        *byte = u8::try_from(i).unwrap();
    }
    assert_eq!(out.expose(), expected.expose());
    assert_eq!(logout(&mut sess, PW1_MODE81, &[]), Sw::OK);
    assert_eq!(
        &sess.session_pw1,
        dev().pin_derive_session(PW1_DEFAULT).expose()
    );
    let generation = fs.write_gen();
    out.expose_mut().fill(0xA5);
    assert_eq!(
        load_dek(&dev(), &mut fs, &sess, &mut out),
        Err(Sw::CONDITIONS_NOT_SATISFIED),
        "revoked access must not open a key held by the prior session"
    );
    assert_eq!(out.expose(), &[0xA5; DEK_SIZE]);
    assert_eq!(fs.write_gen(), generation);
}

#[test]
fn a_failed_first_retry_probe_cannot_bypass_the_block_at_the_charging_write() {
    for (mode, fid, pin) in [
        (PW1_MODE81, EF_PW1, PW1_DEFAULT),
        (PW1_MODE82, EF_PW1, PW1_DEFAULT),
        (PW3_MODE83, EF_PW3, PW3_DEFAULT),
    ] {
        let (backend, medium) = ProbeStuck::new();
        let mut fs = Fs::new(backend);
        fs.scan();
        scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
        let counters = stored(&mut fs, EF_PW_PRIV).unwrap();
        let mut blocked = counters.clone();
        blocked[pw_retry_idx(fid)] = 0;
        fs.put(EF_PW_PRIV, &blocked).unwrap();
        let generation = fs.write_gen();
        let verifier = medium.value(fid);
        for body in [pin, &[b'X'; 8][..pin.len()]] {
            let mut sess = Session::new();
            medium.stick_once(EF_PW_PRIV);
            assert_eq!(
                verify(&dev(), &mut fs, &mut sess, &mut CountRng(7), 0, mode, body),
                Sw::PIN_BLOCKED
            );
            assert!(!sess.has_pw1 && !sess.has_pw2 && !sess.has_pw3 && !sess.has_rc);
            assert_eq!(medium.value(EF_PW_PRIV).unwrap(), blocked);
            assert_eq!(medium.value(fid), verifier);
            assert_eq!(fs.write_gen(), generation);
        }
        fs.put(EF_PW_PRIV, &counters).unwrap();
        assert_eq!(
            verify(
                &dev(),
                &mut fs,
                &mut Session::new(),
                &mut CountRng(7),
                0,
                mode,
                pin
            ),
            Sw::OK
        );
    }
}

#[test]
fn a_zero_length_reset_reference_cannot_install_a_pin_even_with_an_openable_copy() {
    let mut fs = setup();
    let mut sess = Session::new();
    let mut rng = CountRng(7);
    assert_eq!(
        verify(
            &dev(),
            &mut fs,
            &mut sess,
            &mut rng,
            0,
            PW3_MODE83,
            PW3_DEFAULT
        ),
        Sw::OK
    );
    let mut expected = Secret::<[u8; DEK_SIZE]>::zeroed();
    load_dek(&dev(), &mut fs, &sess, &mut expected).unwrap();
    let rearmed = rsk_fs::request_rescrub(&mut fs).unwrap();
    let _ = rewrap_dek(
        &dev(),
        &mut fs,
        &mut rng,
        EF_DEK_RC,
        &[],
        expected.expose(),
        &rearmed,
    )
    .unwrap();
    let mut verifier = Secret::<[u8; 34]>::zeroed();
    verifier.expose_mut()[1] = PIN_FORMAT_V1;
    verifier.expose_mut()[2..].copy_from_slice(dev().pin_derive_verifier(&[]).expose());
    fs.put(EF_RC, verifier.expose()).unwrap();
    set_pin_retry_counter(&mut fs, EF_RC, PW_RETRIES_DEFAULT).unwrap();
    let pw1 = stored(&mut fs, EF_PW1);
    let copy = stored(&mut fs, EF_DEK_PW1.get());
    let counters = stored(&mut fs, EF_PW_PRIV);
    let generation = fs.write_gen();
    sess.reset();
    assert_eq!(
        reset_retry(
            &dev(),
            &mut fs,
            &mut sess,
            &mut rng,
            0,
            PW1_MODE81,
            b"222222"
        ),
        Sw::REFERENCE_NOT_FOUND
    );
    assert!(!sess.has_pw1 && !sess.has_pw2 && !sess.has_pw3 && !sess.has_rc);
    assert_eq!(stored(&mut fs, EF_PW1), pw1);
    assert_eq!(stored(&mut fs, EF_DEK_PW1.get()), copy);
    assert_eq!(stored(&mut fs, EF_PW_PRIV), counters);
    assert_eq!(fs.write_gen(), generation);
}

#[test]
fn empty_and_wrong_format_committed_copies_recover_only_from_their_valid_stage() {
    for (mode, pin, target) in [
        (PW1_MODE81, PW1_DEFAULT, EF_DEK_PW1),
        (PW3_MODE83, PW3_DEFAULT, EF_DEK_PW3),
    ] {
        for bad in [&[][..], &[DEK_FORMAT_V3 + 1][..]] {
            let mut fs = setup();
            let mut sess = Session::new();
            let mut rng = CountRng(7);
            assert_eq!(
                verify(&dev(), &mut fs, &mut sess, &mut rng, 0, mode, pin),
                Sw::OK
            );
            let mut expected = Secret::<[u8; DEK_SIZE]>::zeroed();
            load_dek(&dev(), &mut fs, &sess, &mut expected).unwrap();
            let _ = stage_dek(&dev(), &mut fs, &mut rng, target, pin, expected.expose()).unwrap();
            fs.put_key(target, Sealed::wrap(bad)).unwrap();
            let stage = stage_fid(target).unwrap();
            let valid = stored(&mut fs, stage.get()).unwrap();
            let mut recovered = Secret::<[u8; DEK_SIZE]>::zeroed();
            load_dek(&dev(), &mut fs, &sess, &mut recovered).unwrap();
            assert_eq!(recovered.expose(), expected.expose());
            assert_eq!(stored(&mut fs, target.get()).unwrap(), valid[1..]);
            assert!(stored(&mut fs, stage.get()).is_none());
            load_dek(&dev(), &mut fs, &sess, &mut recovered).unwrap();
            assert_eq!(recovered.expose(), expected.expose());
        }
    }
}

#[test]
fn a_short_counter_cannot_make_a_partial_reset_code_clear_report_success() {
    let mut fs = setup();
    let mut sess = Session::new();
    let mut rng = CountRng(7);
    assert_eq!(
        verify(
            &dev(),
            &mut fs,
            &mut sess,
            &mut rng,
            0,
            PW3_MODE83,
            PW3_DEFAULT
        ),
        Sw::OK
    );
    assert_eq!(
        put_reset_code(&dev(), &mut fs, &mut sess, &mut rng, b"resetme0"),
        Sw::OK
    );
    let counters = stored(&mut fs, EF_PW_PRIV).unwrap();
    fs.put(EF_PW_PRIV, &counters[..pw_retry_idx(EF_RC)])
        .unwrap();
    let short = stored(&mut fs, EF_PW_PRIV);
    assert_eq!(
        put_reset_code(&dev(), &mut fs, &mut sess, &mut rng, &[]),
        Sw::MEMORY_FAILURE
    );
    assert_eq!(stored(&mut fs, EF_PW_PRIV), short);
    assert!(stored(&mut fs, EF_RC).is_none());
    assert!(stored(&mut fs, EF_DEK_RC.get()).is_none());
    assert!(!sess.has_rc && sess.has_pw3);
    fs.put(EF_PW_PRIV, &counters).unwrap();
    assert_eq!(
        put_reset_code(&dev(), &mut fs, &mut sess, &mut rng, &[]),
        Sw::OK
    );
}

#[test]
fn migration_of_an_absent_pw1_copy_keeps_the_admin_copy_and_can_be_repaired() {
    let mut fs = setup();
    let mut sess = Session::new();
    let mut rng = CountRng(7);
    assert_eq!(
        verify(
            &dev(),
            &mut fs,
            &mut sess,
            &mut rng,
            0,
            PW3_MODE83,
            PW3_DEFAULT
        ),
        Sw::OK
    );
    let mut expected = Secret::<[u8; DEK_SIZE]>::zeroed();
    load_dek(&dev(), &mut fs, &sess, &mut expected).unwrap();
    let admin_copy = stored(&mut fs, EF_DEK_PW3.get());
    fs.delete_key(EF_DEK_PW1).unwrap();
    sess.reset();
    assert_eq!(
        verify(
            &otp_dev(),
            &mut fs,
            &mut sess,
            &mut rng,
            0,
            PW1_MODE81,
            PW1_DEFAULT
        ),
        Sw::OK
    );
    assert!(!fs.has_key(EF_DEK_PW1));
    assert_eq!(stored(&mut fs, EF_DEK_PW3.get()), admin_copy);
    let mut out = Secret::<[u8; DEK_SIZE]>::zeroed();
    assert_eq!(
        load_dek(&otp_dev(), &mut fs, &sess, &mut out),
        Err(Sw::EXEC_ERROR)
    );
    sess.reset();
    assert_eq!(
        verify(
            &otp_dev(),
            &mut fs,
            &mut sess,
            &mut rng,
            0,
            PW3_MODE83,
            PW3_DEFAULT
        ),
        Sw::OK
    );
    load_dek(&otp_dev(), &mut fs, &sess, &mut out).unwrap();
    assert_eq!(out.expose(), expected.expose());
    assert_eq!(
        reset_retry(
            &otp_dev(),
            &mut fs,
            &mut sess,
            &mut rng,
            2,
            PW1_MODE81,
            b"222222"
        ),
        Sw::OK
    );
    sess.reset();
    assert_eq!(
        verify(
            &otp_dev(),
            &mut fs,
            &mut sess,
            &mut rng,
            0,
            PW1_MODE81,
            b"222222"
        ),
        Sw::OK
    );
    load_dek(&otp_dev(), &mut fs, &sess, &mut out).unwrap();
    assert_eq!(out.expose(), expected.expose());
}

#[test]
fn empty_verifier_records_cannot_supply_a_length_or_authorize_pin_recovery() {
    let mut fs = setup();
    let mut sess = Session::new();
    arm_all(&dev(), &mut fs, &mut sess);
    let flags = (sess.has_pw1, sess.has_pw2, sess.has_pw3, sess.has_rc);
    for fid in [EF_PW1, EF_PW3, EF_RC] {
        fs.put(fid, &[]).unwrap();
    }
    let generation = fs.write_gen();
    assert!(!offered_len_impossible(&mut fs, EF_PW1, PIN_MAX_LEN + 1));
    assert_eq!(
        change_pin(
            &dev(),
            &mut fs,
            &mut sess,
            &mut CountRng(0),
            0,
            PW1_MODE81,
            PW1_DEFAULT
        ),
        Sw::REFERENCE_NOT_FOUND
    );
    assert_eq!(
        reset_retry(
            &dev(),
            &mut fs,
            &mut sess,
            &mut CountRng(0),
            0,
            PW1_MODE81,
            PW1_DEFAULT
        ),
        Sw::REFERENCE_NOT_FOUND
    );
    assert_eq!(fs.write_gen(), generation);
    assert_eq!(
        (sess.has_pw1, sess.has_pw2, sess.has_pw3, sess.has_rc),
        flags
    );
    fs.put(EF_PW3, &[0, 1, 0]).unwrap();
    assert!(verifier_unusable(&mut fs, EF_PW3));
}

#[test]
fn retry_restoration_refuses_both_missing_counter_positions_before_writing() {
    for (fid, width, short_priv) in [
        (EF_PW1, PW1_RETRY_IDX, true),
        (EF_PW3, (EF_PW3 & 0xf) as usize, false),
    ] {
        let mut fs = setup();
        fs.put(
            if short_priv {
                EF_PW_PRIV
            } else {
                EF_PW_RETRIES
            },
            &vec![1; width],
        )
        .unwrap();
        let generation = fs.write_gen();
        assert_eq!(
            pin_reset_retries(&mut fs, fid, true),
            Err(Sw::MEMORY_FAILURE)
        );
        assert_eq!(fs.write_gen(), generation);
    }
}

#[test]
fn a_truncated_verifier_is_unusable_even_with_a_nonzero_length_byte() {
    let mut fs = setup();
    for value in [&[][..], &[1][..], &[1, 1][..]] {
        fs.put(EF_PW3, value).unwrap();
        let generation = fs.write_gen();
        assert!(verifier_unusable(&mut fs, EF_PW3));
        assert_eq!(fs.write_gen(), generation);
    }
}
