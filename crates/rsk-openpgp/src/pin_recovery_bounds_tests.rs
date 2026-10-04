// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn otp_migration_accepts_an_already_migrated_dek_copy() {
    let mut fs = setup();
    let mut rng = CountRng(7);
    let mut old_session = Session::new();
    assert_eq!(
        verify(
            &dev(),
            &mut fs,
            &mut old_session,
            &mut rng,
            0,
            PW1_MODE81,
            PW1_DEFAULT
        ),
        Sw::OK
    );
    let mut original = Secret::<[u8; DEK_SIZE]>::zeroed();
    load_dek(&dev(), &mut fs, &old_session, &mut original).unwrap();
    let rearmed = rsk_fs::request_rescrub(&mut fs).unwrap();
    rewrap_dek(
        &otp_dev(),
        &mut fs,
        &mut rng,
        EF_DEK_PW1,
        PW1_DEFAULT,
        original.expose(),
        &rearmed,
    )
    .unwrap();
    let mut session = Session::new();
    assert_eq!(
        verify(
            &otp_dev(),
            &mut fs,
            &mut session,
            &mut rng,
            0,
            PW1_MODE81,
            PW1_DEFAULT
        ),
        Sw::OK
    );
    let mut recovered = Secret::<[u8; DEK_SIZE]>::zeroed();
    load_dek(&otp_dev(), &mut fs, &session, &mut recovered).unwrap();
    assert_eq!(recovered.expose(), original.expose());
    let mut counters = [0; 8];
    fs.read(EF_PW_PRIV, &mut counters).unwrap();
    assert_eq!(counters[pw_retry_idx(EF_PW1)], PW_RETRIES_DEFAULT);
}

#[test]
fn otp_migration_refuses_a_copy_that_neither_generation_can_open() {
    for bad in [&[][..], &[0xff][..], &[DEK_FORMAT_V3, 0, 0][..]] {
        let mut fs = setup();
        let mut before = [0; 64];
        let n = fs.read(EF_PW1, &mut before).unwrap();
        fs.put_key(EF_DEK_PW1, Sealed::wrap(bad)).unwrap();
        let mut session = Session::new();
        assert_eq!(
            verify(
                &otp_dev(),
                &mut fs,
                &mut session,
                &mut CountRng(7),
                0,
                PW1_MODE81,
                PW1_DEFAULT
            ),
            Sw::EXEC_ERROR
        );
        assert!(!session.has_pw1 && !session.has_pw2);
        let mut after = [0; 64];
        assert_eq!(fs.read(EF_PW1, &mut after), Some(n));
        assert_eq!(after, before);
    }
}

fn interrupted_update<S: Storage>(fs: &mut Fs<S>) -> (Session, Secret<[u8; 32]>, rsk_fs::Rearmed) {
    let mut session = Session::new();
    let mut rng = CountRng(7);
    assert_eq!(
        verify(
            &dev(),
            fs,
            &mut session,
            &mut rng,
            0,
            PW1_MODE81,
            PW1_DEFAULT
        ),
        Sw::OK
    );
    let mut dek = Secret::<[u8; DEK_SIZE]>::zeroed();
    load_dek(&dev(), fs, &session, &mut dek).unwrap();
    let (key, rearmed) =
        stage_dek(&dev(), fs, &mut rng, EF_DEK_PW1, b"654321", dek.expose()).unwrap();
    put_verifier(&dev(), fs, EF_PW1, b"654321", Some(&rearmed)).unwrap();
    let mut new_session = Session::new();
    assert_eq!(
        verify(
            &dev(),
            fs,
            &mut new_session,
            &mut rng,
            0,
            PW1_MODE81,
            b"654321"
        ),
        Sw::OK
    );
    (new_session, key, rearmed)
}

#[test]
fn staging_target_and_format_must_match_on_both_recovery_and_commit() {
    for bad in [
        vec![],
        vec![EF_DEK_PW1.get() as u8],
        vec![EF_DEK_PW3.get() as u8, DEK_FORMAT_V3, 0],
        vec![EF_DEK_PW1.get() as u8, 0xff, 0],
    ] {
        let mut fs = setup();
        let (session, _, rearmed) = interrupted_update(&mut fs);
        let mut before = [0; DEK_FILE_SIZE];
        let n = fs.read_key(EF_DEK_PW1, &mut before).unwrap();
        fs.put_key(EF_DEK_STAGE_PW1, Sealed::wrap(&bad)).unwrap();
        let mut out = Secret::<[u8; DEK_SIZE]>::zeroed();
        assert_eq!(
            load_dek(&dev(), &mut fs, &session, &mut out),
            Err(Sw::EXEC_ERROR)
        );
        assert_eq!(
            commit_staged_dek(&mut fs, EF_DEK_PW1, &rearmed),
            Err(Sw::EXEC_ERROR)
        );
        let mut after = [0; DEK_FILE_SIZE];
        assert_eq!(fs.read_key(EF_DEK_PW1, &mut after), Some(n));
        assert_eq!(after, before);
        let mut stored = [0; DEK_FILE_SIZE + 1];
        assert_eq!(fs.read_key(EF_DEK_STAGE_PW1, &mut stored), Some(bad.len()));
        assert_eq!(&stored[..bad.len()], bad);
    }
    for (field, value) in [(0, EF_DEK_PW3.get() as u8), (1, 0xff)] {
        let mut fs = setup();
        let (session, _, _) = interrupted_update(&mut fs);
        let mut staged = [0; DEK_FILE_SIZE + 1];
        let staged_len = fs.read_key(EF_DEK_STAGE_PW1, &mut staged).unwrap();
        staged[field] = value;
        fs.put_key(EF_DEK_STAGE_PW1, Sealed::wrap(&staged[..staged_len]))
            .unwrap();
        let mut before = [0; DEK_FILE_SIZE];
        let live_len = fs.read_key(EF_DEK_PW1, &mut before).unwrap();
        let mut out = Secret::<[u8; DEK_SIZE]>::zeroed();
        assert_eq!(
            load_dek(&dev(), &mut fs, &session, &mut out),
            Err(Sw::EXEC_ERROR)
        );
        let mut after = [0; DEK_FILE_SIZE];
        assert_eq!(fs.read_key(EF_DEK_PW1, &mut after), Some(live_len));
        assert_eq!(after, before);
        let mut stored = [0; DEK_FILE_SIZE + 1];
        assert_eq!(fs.read_key(EF_DEK_STAGE_PW1, &mut stored), Some(staged_len));
        assert_eq!(stored, staged);
    }
}

#[test]
fn a_tampered_stage_never_replaces_the_live_dek_copy() {
    let mut fs = setup();
    let (session, _, _) = interrupted_update(&mut fs);
    let mut staged = [0; DEK_FILE_SIZE + 1];
    let n = fs.read_key(EF_DEK_STAGE_PW1, &mut staged).unwrap();
    staged[n - 1] ^= 1;
    fs.put_key(EF_DEK_STAGE_PW1, Sealed::wrap(&staged[..n]))
        .unwrap();
    let mut before = [0; DEK_FILE_SIZE];
    let live_len = fs.read_key(EF_DEK_PW1, &mut before).unwrap();
    let mut out = Secret::<[u8; DEK_SIZE]>::zeroed();
    assert_eq!(
        load_dek(&dev(), &mut fs, &session, &mut out),
        Err(Sw::EXEC_ERROR)
    );
    assert_eq!(out.expose(), &[0; DEK_SIZE]);
    let mut after = [0; DEK_FILE_SIZE];
    assert_eq!(fs.read_key(EF_DEK_PW1, &mut after), Some(live_len));
    assert_eq!(after, before);
    assert!(fs.has_key(EF_DEK_STAGE_PW1));
}

#[test]
fn refused_recovery_rearm_wipes_the_decrypted_output_and_keeps_the_stage() {
    let (mut fs, medium) = setup_cut();
    let (session, _, _) = interrupted_update(&mut fs);
    let old_copy = medium.value(EF_DEK_PW1.get());
    let stage = medium.value(EF_DEK_STAGE_PW1.get());
    medium.arm(0);
    let mut out = Secret::new([0x55; DEK_SIZE]);
    assert_eq!(
        load_dek(&dev(), &mut fs, &session, &mut out),
        Err(Sw::MEMORY_FAILURE)
    );
    assert_eq!(out.expose(), &[0; DEK_SIZE]);
    assert_eq!(medium.value(EF_DEK_PW1.get()), old_copy);
    assert_eq!(medium.value(EF_DEK_STAGE_PW1.get()), stage);
}

#[test]
fn pin_command_parameter_errors_leave_the_session_and_pin_unchanged() {
    let mut fs = setup();
    let mut rng = CountRng(7);
    let mut session = Session::new();
    assert_eq!(
        verify(
            &dev(),
            &mut fs,
            &mut session,
            &mut rng,
            0,
            PW1_MODE81,
            PW1_DEFAULT
        ),
        Sw::OK
    );
    assert_eq!(logout(&mut session, PW1_MODE81, b"body"), Sw::WRONG_DATA);
    assert!(session.has_pw1);
    assert_eq!(
        change_pin(
            &dev(),
            &mut fs,
            &mut session,
            &mut rng,
            1,
            PW1_MODE81,
            PW1_DEFAULT
        ),
        Sw::WRONG_P1P2
    );
    assert_eq!(
        change_pin(
            &dev(),
            &mut fs,
            &mut session,
            &mut rng,
            0,
            PW1_MODE81,
            b"123"
        ),
        Sw::WRONG_LENGTH
    );
    assert_eq!(
        reset_retry(
            &dev(),
            &mut fs,
            &mut session,
            &mut rng,
            0,
            PW1_MODE82,
            b"body"
        ),
        Sw::REFERENCE_NOT_FOUND
    );
    assert_eq!(
        reset_retry(
            &dev(),
            &mut fs,
            &mut session,
            &mut rng,
            1,
            PW1_MODE81,
            b"body"
        ),
        Sw::INCORRECT_P1P2
    );
    assert!(session.has_pw1);
    assert_eq!(
        verify(
            &dev(),
            &mut fs,
            &mut session,
            &mut rng,
            0,
            PW1_MODE81,
            PW1_DEFAULT
        ),
        Sw::OK
    );
}
