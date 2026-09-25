// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! E44: a failed OTP-PIN CHANGE (`0xB3`) must drop the standing authentication,
//! exactly as its sibling VERIFY (`0xB2`) does.
//!
//! No YubiKey behaviour exists to copy — measured, not assumed: a 5.7.4 answers
//! `6D00` to all 256 INS bytes in this family and does not distinguish it from
//! any other unimplemented instruction (worklog TRACK-oath §8). So the applet's
//! own siblings decide, and they disagreed about one rule.

use super::*;

/// A store with one password-safe credential and an OTP PIN of `1234`.
fn safe_store(app: &mut OathApplet, fs: &mut Fs<RamStorage>) {
    let mut cred = put_data(b"bank", 0x21, 6, SECRET_SHA1, false, None);
    cred.extend(tlv(TAG_PWS_PASSWORD, b"s3cr3t"));
    assert_eq!(put(app, fs, &cred), Sw::OK);
    assert_eq!(
        run(
            app,
            fs,
            &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))
        )
        .0,
        Sw::OK
    );
}

/// Whether `0xB5` GET CREDENTIAL still serves the stored password.
fn safe_open(app: &mut OathApplet, fs: &mut Fs<RamStorage>) -> bool {
    let (sw, _) = run(
        app,
        fs,
        &apdu(INS_GET_CREDENTIAL, 0, 0, &tlv(TAG_NAME, b"bank")),
    );
    match sw {
        Sw::OK => true,
        Sw::SECURITY_STATUS_NOT_SATISFIED => false,
        other => panic!("unexpected GET CREDENTIAL status {other:?}"),
    }
}

fn verify(app: &mut OathApplet, fs: &mut Fs<RamStorage>, pin: &[u8]) -> Sw {
    run(
        app,
        fs,
        &apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, pin)),
    )
    .0
}

fn change<S: Storage>(app: &mut OathApplet, fs: &mut Fs<S>, old: &[u8], new: &[u8]) -> Sw {
    let mut d = tlv(TAG_PASSWORD, old);
    d.extend(tlv(TAG_NEW_PASSWORD, new));
    run(app, fs, &apdu(INS_CHANGE_PIN, 0, 0, &d)).0
}

#[test]
fn a_failed_change_drops_the_standing_authentication() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    safe_store(&mut app, &mut fs);
    assert!(!safe_open(&mut app, &mut fs), "closed before any PIN");

    assert_eq!(verify(&mut app, &mut fs, b"1234"), Sw::OK);
    assert!(safe_open(&mut app, &mut fs), "a correct PIN opens it");
    assert_eq!(
        change(&mut app, &mut fs, b"9999", b"5678"),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert!(
        !safe_open(&mut app, &mut fs),
        "a failed CHANGE left the password safe open",
    );

    // The sibling, same store, same run: the rule they must agree on.
    assert_eq!(verify(&mut app, &mut fs, b"1234"), Sw::OK);
    assert!(safe_open(&mut app, &mut fs));
    assert_eq!(
        verify(&mut app, &mut fs, b"9999"),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert!(!safe_open(&mut app, &mut fs), "the control must fire");
}

#[test]
fn the_safe_closes_when_the_retry_budget_is_spent() {
    // The sharpest cell: the anti-bruteforce machinery worked perfectly and
    // protected nothing that was already open — the card refused even the
    // correct PIN while `0xB5` went on serving the stored password.
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    safe_store(&mut app, &mut fs);
    assert_eq!(verify(&mut app, &mut fs, b"1234"), Sw::OK);
    assert!(safe_open(&mut app, &mut fs));

    for i in 0..=MAX_OTP_COUNTER {
        assert_eq!(
            change(&mut app, &mut fs, b"9999", b"5678"),
            Sw::SECURITY_STATUS_NOT_SATISFIED,
            "failed CHANGE {i}",
        );
    }
    // Locked out, as designed — and the safe is shut with it.
    assert_eq!(
        change(&mut app, &mut fs, b"1234", b"5678"),
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "the correct old PIN after lock-out",
    );
    assert!(
        !safe_open(&mut app, &mut fs),
        "the safe served secrets through a full lock-out",
    );
}

#[test]
fn a_malformed_change_keeps_the_standing_authentication() {
    // Where the sibling actually draws its line is "a PIN was compared", not
    // "at entry": VERIFY with no password TLV answers 6A80 and keeps the unlock.
    // CHANGE has to match the placement, not the comment above it.
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    safe_store(&mut app, &mut fs);

    for (label, body) in [
        ("no 0x80 TLV", tlv(TAG_NEW_PASSWORD, b"5678")),
        ("no 0x81 TLV", tlv(TAG_PASSWORD, b"1234")),
    ] {
        assert_eq!(verify(&mut app, &mut fs, b"1234"), Sw::OK);
        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_CHANGE_PIN, 0, 0, &body));
        assert_eq!(sw, Sw::WRONG_DATA, "CHANGE with {label}");
        assert!(safe_open(&mut app, &mut fs), "CHANGE with {label}");
    }
    // And the sibling agrees on that half.
    assert_eq!(verify(&mut app, &mut fs, b"1234"), Sw::OK);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(INS_VERIFY_PIN, 0, 0, &tlv(0x71, b"x")),
    );
    assert_eq!(sw, Sw::WRONG_DATA);
    assert!(safe_open(&mut app, &mut fs));
}

#[test]
fn a_failed_change_drops_an_access_code_unlock_too() {
    // The fix's width. `validated` is reachable THROUGH the OTP PIN — VERIFY
    // sets it, doubling as VALIDATE for the nitropy flow — so one bool carries
    // both provenances and the applet cannot tell them apart. Leaving it
    // standing after a failed compare leaves a status that could have been
    // obtained by proving the very PIN the caller just failed. VERIFY already
    // makes that trade; the two siblings now make the same one.
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let mut cred = put_data(b"bank", 0x21, 6, SECRET_SHA1, false, None);
    cred.extend(tlv(TAG_PWS_PASSWORD, b"s3cr3t"));
    assert_eq!(put(&mut app, &mut fs, &cred), Sw::OK);
    // The code first: SET CODE deliberately drops any standing OTP-PIN.
    lock_with_code(&mut app, &mut fs);

    /// Answer the challenge the current SELECT handed out — nothing else.
    fn validate(app: &mut OathApplet, fs: &mut Fs<RamStorage>, body: &[u8]) -> Sw {
        let card_chal = find_tag(body, TAG_CHALLENGE as u16).unwrap().to_vec();
        let mut d = tlv(TAG_RESPONSE, &hmac_sha1(&[0xAB; 16], &card_chal));
        d.extend(tlv(TAG_CHALLENGE, &[9u8, 9, 9, 9, 8, 8, 8, 8]));
        run(app, fs, &apdu(INS_VALIDATE, 0, 0, &d)).0
    }

    let (_, body) = select(&mut app, &mut fs);
    assert_eq!(validate(&mut app, &mut fs, &body), Sw::OK);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))
        )
        .0,
        Sw::OK
    );

    // A fresh session that proves ONLY the access code: the applet is open, the
    // password safe is not.
    let (_, body) = select(&mut app, &mut fs);
    assert_eq!(validate(&mut app, &mut fs, &body), Sw::OK);
    assert_eq!(run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[])).0, Sw::OK);
    assert!(!safe_open(&mut app, &mut fs));

    assert_eq!(
        change(&mut app, &mut fs, b"9999", b"5678"),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[])).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "a failed PIN compare left the applet unlocked",
    );
}

#[test]
fn a_successful_change_does_not_open_the_safe() {
    // CHANGE never grants, only drops: it is a one-way loss, and stays one.
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    safe_store(&mut app, &mut fs);
    assert_eq!(change(&mut app, &mut fs, b"1234", b"5678"), Sw::OK);
    assert!(!safe_open(&mut app, &mut fs), "CHANGE opened the safe");
    assert_eq!(verify(&mut app, &mut fs, b"5678"), Sw::OK);
    assert!(safe_open(&mut app, &mut fs), "the new PIN opens it");
}

/// A PIN set before the OTP burn is stored under the chip-serial root, and CHANGE
/// re-keys it to the OTP one. That is a lazy re-key after the boot lap has latched,
/// so the copy it supersedes stays offline-brute-forceable in the flash ring until
/// something re-arms the lap — the rule audit run-35 wrote, which the sibling
/// VERIFY already keeps and this command did not.
#[test]
fn a_change_after_the_otp_burn_rearms_the_at_rest_lap() {
    let (mut fs, medium) = new_cut_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);

    // Pre-burn: SET PIN stores v1 under the NO-OTP (chip-serial) kbase.
    {
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))
            )
            .0,
            Sw::OK
        );
    }
    let nootp = Device {
        serial_hash: &[0x22; 32],
        serial_id: &SERIAL,
        otp_key: None,
    };
    let mut rec = [0u8; OTP_PIN_REC_V1];
    assert_eq!(fs.read(EF_OTP_PIN, &mut rec), Some(OTP_PIN_REC_V1));
    assert_eq!(
        &rec[2..],
        &nootp.pin_derive_verifier(b"1234").expose()[..],
        "the record CHANGE is about to supersede is chip-serial-rooted",
    );

    // The one-shot at-rest lap has already run on this device, so the CHANGE
    // below supersedes that copy AFTER the only pass that could reclaim it.
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    assert!(
        fs.has_data(rsk_fs::EF_HARDENED),
        "fixture: the lap has latched"
    );

    // CHANGE spends its retry by rewriting the record with the SAME verifier, so
    // "still weak" is every write that leaves the verifier bytes alone.
    let before = medium
        .value(EF_OTP_PIN)
        .expect("fixture: EF_OTP_PIN is on the medium");
    medium.clear_ops();
    let mut app = OathApplet::new(SERIAL, [0x22; 32], Some(test_mkek), &rng, &touch);
    assert_eq!(change(&mut app, &mut fs, b"1234", b"5678"), Sw::OK);
    medium.assert_re_armed_before(
        EF_OTP_PIN,
        |v| v.len() == before.len() && v[2..] == before[2..],
        "CHANGE OTP PIN",
    );
    assert!(
        !fs.has_data(rsk_fs::EF_HARDENED),
        "CHANGE re-keyed the verifier off the chip-serial root and must re-arm \
         the at-rest lap: the marker is still latched",
    );

    // …and it really did re-key: the standing record is the OTP-arm one.
    let otp = Device {
        otp_key: Some(&TEST_MKEK),
        ..nootp
    };
    assert_eq!(fs.read(EF_OTP_PIN, &mut rec), Some(OTP_PIN_REC_V1));
    assert_eq!(
        &rec[2..],
        &otp.pin_derive_verifier(b"5678").expose()[..],
        "the new verifier is stored under the OTP arm",
    );
}

/// F1: the re-arm's own failure. A medium that refuses `remove(EF_HARDENED)` and
/// serves every other mutation reaches the end state the write ORDER exists to keep
/// out — the marker latched over a superseded chip-serial-rooted verifier — with no
/// reset anywhere in it, so ordering alone cannot be the whole fix. The re-key is
/// conditional on the re-arm now, and this command already answers `6581` when its
/// write does not land.
#[test]
fn a_change_whose_re_arm_the_medium_refuses_does_not_re_key() {
    let (stuck, medium) = RemoveStuck::new();
    let mut fs = Fs::new(stuck);
    fs.scan();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);

    {
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))
            )
            .0,
            Sw::OK
        );
    }
    let nootp = Device {
        serial_hash: &[0x22; 32],
        serial_id: &SERIAL,
        otp_key: None,
    };
    let mut rec = [0u8; OTP_PIN_REC_V1];
    assert_eq!(fs.read(EF_OTP_PIN, &mut rec), Some(OTP_PIN_REC_V1));
    assert_eq!(
        &rec[2..],
        &nootp.pin_derive_verifier(b"1234").expose()[..],
        "fixture: the record CHANGE would supersede is chip-serial-rooted",
    );
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    assert!(
        fs.has_data(rsk_fs::EF_HARDENED),
        "fixture: the lap has latched"
    );
    medium.refuse(Some(rsk_fs::EF_HARDENED));

    let mut app = OathApplet::new(SERIAL, [0x22; 32], Some(test_mkek), &rng, &touch);
    let sw = change(&mut app, &mut fs, b"1234", b"5678");
    assert!(
        medium.live(rsk_fs::EF_HARDENED),
        "fixture: the medium really refused, so the marker is still on it"
    );
    assert_eq!(
        sw,
        Sw::MEMORY_FAILURE,
        "the lap will not run, so the re-key must not happen and the command must \
         say so — a 9000 here is the marker latched over a superseded chip-serial \
         copy, permanently and with no reset in it",
    );
    assert_eq!(fs.read(EF_OTP_PIN, &mut rec), Some(OTP_PIN_REC_V1));
    assert_eq!(
        &rec[2..],
        &nootp.pin_derive_verifier(b"1234").expose()[..],
        "the refused re-arm must leave the pre-existing verifier in force, not a \
         re-keyed one the lap can no longer reach",
    );

    // The control, and not a no-op: clear the fault and the same CHANGE re-keys,
    // clears the marker, and answers 9000.
    medium.refuse(None);
    assert_eq!(change(&mut app, &mut fs, b"1234", b"5678"), Sw::OK);
    assert!(!fs.has_data(rsk_fs::EF_HARDENED));
    let otp = Device {
        otp_key: Some(&TEST_MKEK),
        ..nootp
    };
    assert_eq!(fs.read(EF_OTP_PIN, &mut rec), Some(OTP_PIN_REC_V1));
    assert_eq!(&rec[2..], &otp.pin_derive_verifier(b"5678").expose()[..]);
}

/// The OTP-PIN gate is `has_data(EF_OTP_PIN)`, and `Fs::has_data` answers the same
/// `false` for "the owner never set one" and for a probe the flash could not
/// serve. On a code-less applet `select()` leaves `validated` true unconditionally,
/// so that probe is the whole gate: one faulted read handed the stored password to
/// an unauthenticated host. It is refused now.
#[test]
fn a_faulted_probe_does_not_open_the_otp_pin_gate() {
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    select(&mut app, &mut fs);
    let mut cred = put_data(b"bank", 0x21, 6, SECRET_SHA1, false, None);
    cred.extend(tlv(TAG_PWS_PASSWORD, b"s3cr3t"));
    assert_eq!(put(&mut app, &mut fs, &cred), Sw::OK);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))
        )
        .0,
        Sw::OK
    );

    // A fresh connection that presents nothing, with EF_OTP_PIN's reads faulting.
    let mut fs = Fs::new(fs.into_storage());
    fs.scan();
    medium.stick(Some(EF_OTP_PIN));
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    select(&mut app, &mut fs);
    let (sw, body) = run(
        &mut app,
        &mut fs,
        &apdu(INS_GET_CREDENTIAL, 0, 0, &tlv(TAG_NAME, b"bank")),
    );
    assert_ne!(
        sw,
        Sw::OK,
        "a faulted EF_OTP_PIN probe opened the gate the owner's PIN closed"
    );
    assert!(
        !body.windows(6).any(|w| w == b"s3cr3t"),
        "and served the stored password with it"
    );

    // The other half of the same reading: `SET OTP PIN` mints the unlock secret on
    // `!has_data(EF_OTP_PIN)`, so a faulted probe let the operator at the port
    // overwrite the PIN the owner set (`select` leaves `validated` true on a
    // code-less applet, and the touch is the only other gate).
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"9999"))
        )
        .0,
        Sw::MEMORY_FAILURE,
        "a faulted EF_OTP_PIN probe let SET OTP PIN replace the owner's PIN"
    );

    // The gate still lets a PIN-less store through once the medium recovers.
    medium.stick(None);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))
        )
        .0,
        Sw::OK
    );
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &apdu(INS_GET_CREDENTIAL, 0, 0, &tlv(TAG_NAME, b"bank"))
        )
        .0,
        Sw::OK
    );
}
