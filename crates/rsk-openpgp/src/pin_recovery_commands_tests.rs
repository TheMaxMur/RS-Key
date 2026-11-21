// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

const RESET_PIN: &[u8] = b"24681357";
const OLD_CODE: &[u8] = b"resetme0";
const NEW_CODE: &[u8] = b"resetnew1";

#[derive(Clone, Copy, Debug)]
enum Authority {
    Admin,
    ResetCode,
}

fn admin<S: Storage>(fs: &mut Fs<S>, sess: &mut Session) -> Sw {
    verify(
        &dev(),
        fs,
        sess,
        &mut CountRng(7),
        0,
        PW3_MODE83,
        PW3_DEFAULT,
    )
}

fn remount(fs: Fs<Cut>) -> Fs<Cut> {
    let mut fs = Fs::new(fs.into_storage());
    fs.scan();
    fs
}

fn reset_command(fs: &mut Fs<Cut>, sess: &mut Session, authority: Authority) -> Sw {
    let (p1, body) = match authority {
        Authority::Admin => (2, RESET_PIN.to_vec()),
        Authority::ResetCode => (0, [OLD_CODE, RESET_PIN].concat()),
    };
    reset_retry(&dev(), fs, sess, &mut CountRng(7), p1, PW1_MODE81, &body)
}

fn interrupted_reset(
    authority: Authority,
    blocked: bool,
    budget: u32,
) -> (Fs<Cut>, CutMedium, Secret<[u8; DEK_SIZE]>, u32) {
    let (mut fs, medium) = setup_cut();
    let mut sess = Session::new();
    assert_eq!(admin(&mut fs, &mut sess), Sw::OK);
    let mut expected = Secret::<[u8; DEK_SIZE]>::zeroed();
    load_dek(&dev(), &mut fs, &sess, &mut expected).unwrap();
    if matches!(authority, Authority::ResetCode) {
        assert_eq!(
            put_reset_code(&dev(), &mut fs, &mut sess, &mut CountRng(7), OLD_CODE),
            Sw::OK
        );
        sess.reset();
    }
    if blocked {
        set_pin_retry_counter(&mut fs, EF_PW1, 0).unwrap();
    }
    fs.put(0xB000, b"another applet").unwrap();
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    medium.clear_ops();
    medium.arm(budget);
    let sw = reset_command(&mut fs, &mut sess, authority);
    assert!(
        matches!(sw, Sw::OK | Sw::MEMORY_FAILURE),
        "{authority:?}, cut {budget}: {sw:?}"
    );
    let cost = u32::try_from(medium.ops().len()).unwrap();
    medium.arm(u32::MAX);
    (remount(fs), medium, expected, cost)
}

fn recover_reset(fs: &mut Fs<Cut>, out: &mut Secret<[u8; DEK_SIZE]>) -> Result<(), Sw> {
    let mut counters = [0; 8];
    fs.read(EF_PW_PRIV, &mut counters).unwrap();
    let mut reference = [0; 34];
    assert_eq!(fs.read(EF_PW1, &mut reference), Some(reference.len()));
    let mut sess = Session::new();
    let pin = if counters[pw_retry_idx(EF_PW1)] == 0 {
        let sw = admin(fs, &mut sess);
        if sw != Sw::OK {
            return Err(sw);
        }
        let sw = reset_command(fs, &mut sess, Authority::Admin);
        if sw != Sw::OK {
            return Err(sw);
        }
        RESET_PIN
    } else if usize::from(reference[0]) == RESET_PIN.len() {
        RESET_PIN
    } else {
        assert_eq!(usize::from(reference[0]), PW1_DEFAULT.len());
        PW1_DEFAULT
    };
    sess.reset();
    let sw = verify(&dev(), fs, &mut sess, &mut CountRng(7), 0, PW1_MODE81, pin);
    if sw != Sw::OK {
        return Err(sw);
    }
    load_dek(&dev(), fs, &sess, out)
}

#[test]
fn both_reset_retry_authorities_survive_command_and_recovery_record_cuts() {
    for authority in [Authority::Admin, Authority::ResetCode] {
        for blocked in [false, true] {
            let (_, _, _, command_cost) = interrupted_reset(authority, blocked, u32::MAX);
            assert!(command_cost > 0);
            let mut refused = false;
            let mut completed = false;
            for first in 0..=command_cost {
                let (mut fs, medium, expected, _) = interrupted_reset(authority, blocked, first);
                medium.clear_ops();
                let mut out = Secret::<[u8; DEK_SIZE]>::zeroed();
                recover_reset(&mut fs, &mut out).unwrap();
                assert_eq!(out.expose(), expected.expose());
                let recovery_cost = u32::try_from(medium.ops().len()).unwrap();
                for second in 0..=recovery_cost {
                    let (mut fs, medium, expected, _) =
                        interrupted_reset(authority, blocked, first);
                    medium.arm(second);
                    let mut out = Secret::<[u8; DEK_SIZE]>::zeroed();
                    match recover_reset(&mut fs, &mut out) {
                        Ok(()) => {
                            assert_eq!(out.expose(), expected.expose());
                            completed = true;
                        }
                        Err(sw) => {
                            assert_eq!(
                                sw,
                                Sw::MEMORY_FAILURE,
                                "{authority:?}, blocked={blocked}, cuts {first}/{second}"
                            );
                            refused = true;
                        }
                    }
                    medium.arm(u32::MAX);
                    let mut fs = remount(fs);
                    let mut out = Secret::<[u8; DEK_SIZE]>::zeroed();
                    recover_reset(&mut fs, &mut out).unwrap_or_else(|sw| {
                        panic!("{authority:?}, blocked={blocked}, cuts {first}/{second}: {sw:?}")
                    });
                    assert_eq!(out.expose(), expected.expose());
                    assert!(medium.value(EF_DEK_STAGE_PW1.get()).is_none());
                    assert_eq!(medium.value(0xB000).unwrap(), b"another applet");
                }
            }
            assert!(
                refused && completed,
                "{authority:?}, blocked={blocked}: both recovery outcomes must run"
            );
        }
    }
}

fn interrupted_code_update(
    existing: bool,
    budget: u32,
) -> (Fs<Cut>, CutMedium, Secret<[u8; DEK_SIZE]>, u32) {
    let (mut fs, medium) = setup_cut();
    let mut sess = Session::new();
    assert_eq!(admin(&mut fs, &mut sess), Sw::OK);
    let mut expected = Secret::<[u8; DEK_SIZE]>::zeroed();
    load_dek(&dev(), &mut fs, &sess, &mut expected).unwrap();
    if existing {
        assert_eq!(
            put_reset_code(&dev(), &mut fs, &mut sess, &mut CountRng(7), OLD_CODE),
            Sw::OK
        );
    }
    fs.put(0xB000, b"another applet").unwrap();
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    medium.clear_ops();
    medium.arm(budget);
    let sw = put_reset_code(&dev(), &mut fs, &mut sess, &mut CountRng(7), NEW_CODE);
    assert!(matches!(sw, Sw::OK | Sw::MEMORY_FAILURE));
    let cost = u32::try_from(medium.ops().len()).unwrap();
    medium.arm(u32::MAX);
    (remount(fs), medium, expected, cost)
}

fn repeat_code_update(fs: &mut Fs<Cut>) -> Sw {
    let mut sess = Session::new();
    let sw = admin(fs, &mut sess);
    if sw != Sw::OK {
        return sw;
    }
    put_reset_code(&dev(), fs, &mut sess, &mut CountRng(7), NEW_CODE)
}

fn check_standing_code(fs: &mut Fs<Cut>, expected: &Secret<[u8; DEK_SIZE]>) {
    let mut reference = [0; 34];
    let stored = fs.read(EF_RC, &mut reference);
    let code = if stored.is_none() || usize::from(reference[0]) == NEW_CODE.len() {
        NEW_CODE
    } else {
        assert_eq!(usize::from(reference[0]), OLD_CODE.len());
        OLD_CODE
    };
    let mut counters = [0; 8];
    fs.read(EF_PW_PRIV, &mut counters).unwrap();
    let body = [code, PW1_DEFAULT].concat();
    let mut sess = Session::new();
    let generation = fs.write_gen();
    let sw = reset_retry(
        &dev(),
        fs,
        &mut sess,
        &mut CountRng(7),
        0,
        PW1_MODE81,
        &body,
    );
    if stored.is_none() {
        assert_eq!(sw, Sw::REFERENCE_NOT_FOUND);
        assert_eq!(fs.write_gen(), generation);
    } else if counters[pw_retry_idx(EF_RC)] == 0 {
        assert_eq!(sw, Sw::PIN_BLOCKED);
        assert_eq!(fs.write_gen(), generation);
    } else {
        assert_eq!(
            sw,
            Sw::OK,
            "a standing code cannot open its committed or staged DEK"
        );
        let mut out = Secret::<[u8; DEK_SIZE]>::zeroed();
        load_dek(&dev(), fs, &sess, &mut out).unwrap();
        assert_eq!(out.expose(), expected.expose());
    }
}

#[test]
fn new_and_replacement_reset_codes_survive_a_second_interrupted_admin_retry() {
    for existing in [false, true] {
        let (_, _, _, command_cost) = interrupted_code_update(existing, u32::MAX);
        assert!(command_cost > 0);
        let mut refused = false;
        let mut completed = false;
        for first in 0..=command_cost {
            let (mut observed, _, expected, _) = interrupted_code_update(existing, first);
            check_standing_code(&mut observed, &expected);
            let (mut fs, medium, _, _) = interrupted_code_update(existing, first);
            medium.clear_ops();
            assert_eq!(repeat_code_update(&mut fs), Sw::OK);
            let recovery_cost = u32::try_from(medium.ops().len()).unwrap();
            for second in 0..=recovery_cost {
                let (mut fs, medium, expected, _) = interrupted_code_update(existing, first);
                medium.arm(second);
                let sw = repeat_code_update(&mut fs);
                assert!(matches!(sw, Sw::OK | Sw::MEMORY_FAILURE));
                refused |= sw == Sw::MEMORY_FAILURE;
                completed |= sw == Sw::OK;
                medium.arm(u32::MAX);
                let mut fs = remount(fs);
                check_standing_code(&mut fs, &expected);
                let mut sess = Session::new();
                assert_eq!(admin(&mut fs, &mut sess), Sw::OK);
                let mut out = Secret::<[u8; DEK_SIZE]>::zeroed();
                load_dek(&dev(), &mut fs, &sess, &mut out).unwrap();
                assert_eq!(out.expose(), expected.expose());
                assert_eq!(
                    put_reset_code(&dev(), &mut fs, &mut sess, &mut CountRng(7), NEW_CODE),
                    Sw::OK
                );
                check_standing_code(&mut fs, &expected);
                assert!(medium.value(EF_DEK_STAGE_RC.get()).is_none());
                assert_eq!(medium.value(0xB000).unwrap(), b"another applet");
            }
        }
        assert!(
            refused && completed,
            "existing={existing}: both retry outcomes must run"
        );
    }
}
