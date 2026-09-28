// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! E59: what SET CODE (`0x03`) accepts as an access code. A YubiKey 5.7.4 takes
//! an algorithm byte plus **14..=64 bytes** of key — the same range it enforces
//! on a credential's secret — and answers `6A80` for everything else, leaving
//! the installed code exactly as it was (worklog ORACLE-oathfido §E59). E62 is
//! the other half of the same lock: which word VALIDATE (`0xA3`) refuses with.

use super::*;

fn fixture() -> (Fs<RamStorage>, RefCell<CountRng>) {
    (new_fs(), RefCell::new(CountRng(7)))
}

const PROOF_CHAL: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

/// SET CODE with `secret` as the key material, proving knowledge of it over
/// `chal` the way ykman does: `75` = `HMAC(secret, 74)`.
fn set_code_over<S: Storage>(
    app: &mut OathApplet,
    fs: &mut Fs<S>,
    secret: &[u8],
    chal: &[u8],
) -> Sw {
    let mut key = vec![ALG_HMAC_SHA1];
    key.extend_from_slice(secret);
    let mut d = tlv(TAG_KEY, &key);
    d.extend(tlv(TAG_CHALLENGE, chal));
    d.extend(tlv(TAG_RESPONSE, &hmac_sha1(secret, chal)));
    run(app, fs, &apdu(INS_SET_CODE, 0, 0, &d)).0
}

/// SET CODE over the 8-byte challenge every host sends.
fn set_code<S: Storage>(app: &mut OathApplet, fs: &mut Fs<S>, secret: &[u8]) -> Sw {
    set_code_over(app, fs, secret, &PROOF_CHAL)
}

/// Whether a code is installed, asked the way a host would: SELECT offers a
/// challenge only when there is one, and the applet then starts locked.
fn code_installed(app: &mut OathApplet, fs: &mut Fs<RamStorage>) -> bool {
    let (_, body) = select(app, fs);
    let offered = find_tag(&body, TAG_CHALLENGE as u16).is_some();
    let listed = run(app, fs, &apdu(INS_LIST, 0, 0, &[])).0;
    assert_eq!(
        offered,
        listed == Sw::SECURITY_STATUS_NOT_SATISFIED,
        "the challenge and the gate disagree about whether a code is set",
    );
    offered
}

/// The challenge this SELECT offered, which VALIDATE proves knowledge over.
fn card_challenge(app: &mut OathApplet, fs: &mut Fs<RamStorage>) -> Vec<u8> {
    let (_, body) = select(app, fs);
    find_tag(&body, TAG_CHALLENGE as u16).unwrap().to_vec()
}

/// VALIDATE carrying `proof`. Takes no SELECT of its own — every SELECT rotates
/// the challenge the proof was built for.
fn validate_proof(app: &mut OathApplet, fs: &mut Fs<RamStorage>, proof: &[u8]) -> Sw {
    let mut d = tlv(TAG_RESPONSE, proof);
    d.extend(tlv(TAG_CHALLENGE, &[9u8; 8]));
    run(app, fs, &apdu(INS_VALIDATE, 0, 0, &d)).0
}

/// VALIDATE against the challenge this SELECT offered, with `secret`.
fn validate(app: &mut OathApplet, fs: &mut Fs<RamStorage>, secret: &[u8]) -> Sw {
    let chal = card_challenge(app, fs);
    validate_proof(app, fs, &hmac_sha1(secret, &chal))
}

#[test]
fn a_code_with_no_key_material_is_refused() {
    // `73 01 01` — an algorithm byte and nothing else. It used to install a lock
    // whose VALIDATE response is `HMAC(empty key, challenge)`: a code every host
    // in the world can compute, standing between the owner and their store.
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(set_code(&mut app, &mut fs, &[]), Sw::WRONG_DATA);
    assert!(!code_installed(&mut app, &mut fs));
}

#[test]
fn the_key_material_bound_is_the_card_s_fourteen_to_sixty_four() {
    // 126 is the widest the short-form `tlv` helper can carry, not a card cell.
    for len in [1usize, 2, 13, 14, 15, 16, 20, 32, 63, 64, 65, 66, 100, 126] {
        let (mut fs, rng) = fixture();
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        let secret = vec![0xABu8; len];
        let accepted = (SECRET_MIN..=SECRET_MAX).contains(&len);
        assert_eq!(
            set_code(&mut app, &mut fs, &secret),
            if accepted { Sw::OK } else { Sw::WRONG_DATA },
            "{len} bytes of key material",
        );
        assert_eq!(code_installed(&mut app, &mut fs), accepted, "{len} bytes");
        if accepted {
            assert_eq!(validate(&mut app, &mut fs, &secret), Sw::OK, "{len} bytes");
        }
    }
}

#[test]
fn it_is_the_same_bound_a_credential_secret_gets() {
    // One rule, two commands — on the card as here. Tie them, so narrowing one
    // cannot silently leave the other behind.
    assert_eq!(KEY_TLV_MIN - 2, CODE_TLV_MIN - 1);
    assert_eq!(KEY_TLV_MAX - 2, CODE_TLV_MAX - 1);
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    for len in [SECRET_MIN - 1, SECRET_MIN, SECRET_MAX, SECRET_MAX + 1] {
        let secret = vec![0xCDu8; len];
        let put_sw = put(
            &mut app,
            &mut fs,
            &put_data(b"c", 0x21, 6, &secret, false, None),
        );
        let set_sw = set_code(&mut app, &mut fs, &secret);
        assert_eq!(
            put_sw, set_sw,
            "{len} bytes: PUT {put_sw:?}, SET CODE {set_sw:?}"
        );
        if set_sw == Sw::OK {
            // Put it back for the next row.
            assert_eq!(validate(&mut app, &mut fs, &secret), Sw::OK);
            assert_eq!(
                run(
                    &mut app,
                    &mut fs,
                    &apdu(INS_SET_CODE, 0, 0, &tlv(TAG_KEY, &[]))
                )
                .0,
                Sw::OK
            );
        }
    }
}

#[test]
fn a_refused_set_code_leaves_the_installed_one_alone() {
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let good = [0xABu8; 16];
    assert_eq!(set_code(&mut app, &mut fs, &good), Sw::OK);
    assert_eq!(validate(&mut app, &mut fs, &good), Sw::OK);

    let short = [0xCDu8; 13];
    assert_eq!(set_code(&mut app, &mut fs, &short), Sw::WRONG_DATA);
    assert!(code_installed(&mut app, &mut fs));
    assert_eq!(
        validate(&mut app, &mut fs, &short),
        Sw::WRONG_DATA,
        "the refused key must not open the applet",
    );
    assert_eq!(
        validate(&mut app, &mut fs, &good),
        Sw::OK,
        "the standing code must still open it",
    );
}

#[test]
fn only_the_card_s_spelling_removes_a_code() {
    // `73 00` is the card's spelling, and it is the one ykman sends. A body-less
    // APDU is the YKOATH document's ("If length 0 is sent, authentication is
    // removed") and a 5.7.4 answers `6A80` to it; we follow the card, which costs
    // no functionality — the standing code survives the refusal either way.
    for (body, want, removed) in [
        (&tlv(TAG_KEY, &[])[..], Sw::OK, true),
        (&[][..], Sw::WRONG_DATA, false),
    ] {
        let (mut fs, rng) = fixture();
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        assert_eq!(set_code(&mut app, &mut fs, &[0xABu8; 16]), Sw::OK);
        assert_eq!(validate(&mut app, &mut fs, &[0xABu8; 16]), Sw::OK);
        assert_eq!(
            run(&mut app, &mut fs, &apdu(INS_SET_CODE, 0, 0, body)).0,
            want,
            "{body:02X?}"
        );
        assert_eq!(code_installed(&mut app, &mut fs), !removed, "{body:02X?}");
        // A refusal must leave the standing code opening the applet, not a card
        // locked behind something neither side can now name.
        if !removed {
            assert_eq!(validate(&mut app, &mut fs, &[0xABu8; 16]), Sw::OK);
        }
    }
}

#[test]
fn a_body_less_set_code_is_refused_before_the_gate_it_would_open() {
    // The refusal must not become a way past the access code: an unvalidated
    // session gets `6982` and the code stays installed, exactly as before.
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(set_code(&mut app, &mut fs, &[0xABu8; 16]), Sw::OK);
    assert!(code_installed(&mut app, &mut fs));
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_SET_CODE, 0, 0, &[])).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert!(code_installed(&mut app, &mut fs));
}

#[test]
fn the_proof_is_carried_over_exactly_eight_bytes() {
    // E63: the card takes its own challenge width and nothing else, and every
    // host sends 8 (ykman: `os.urandom(8)`). We took any length, so a one-byte
    // challenge installed a code on a proof with one byte of margin.
    for len in [0usize, 1, 2, 4, 7, 8, 9, 16, 20, 64] {
        let (mut fs, rng) = fixture();
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        let secret = [0xABu8; 16];
        let chal: Vec<u8> = (0..len).map(|i| 0x30 + i as u8).collect();
        let accepted = len == CHALLENGE_LEN;
        assert_eq!(
            set_code_over(&mut app, &mut fs, &secret, &chal),
            if accepted { Sw::OK } else { Sw::WRONG_DATA },
            "a {len}-byte challenge",
        );
        assert_eq!(code_installed(&mut app, &mut fs), accepted, "{len} bytes");
    }
}

#[test]
fn a_wrong_proof_is_not_the_word_for_no_code_at_all() {
    // E62: the card answers `6A80` to a proof that does not match and keeps
    // `6984` for "no such object" — nothing installed to match against. We
    // answered `6984` to both, so a host could not tell a wrong access code
    // from an applet that has none (worklog ORACLE-oathfido §E62).
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let good = [0xABu8; 16];
    assert_eq!(
        validate_proof(&mut app, &mut fs, &hmac_sha1(&good, &[0u8; 8])),
        Sw::DATA_INVALID,
        "no code installed",
    );

    assert_eq!(set_code(&mut app, &mut fs, &good), Sw::OK);
    assert_eq!(
        validate(&mut app, &mut fs, &[0xCDu8; 16]),
        Sw::WRONG_DATA,
        "a wrong key",
    );
    // A right key proved over the wrong bytes, and a truncated proof of the
    // right one: the card refuses both the same way.
    assert_eq!(
        validate_proof(&mut app, &mut fs, &hmac_sha1(&good, &[0u8; 8])),
        Sw::WRONG_DATA,
        "the right key over a stale challenge",
    );
    let chal = card_challenge(&mut app, &mut fs);
    assert_eq!(
        validate_proof(&mut app, &mut fs, &hmac_sha1(&good, &chal)[..1]),
        Sw::WRONG_DATA,
        "a one-byte proof",
    );
    assert_eq!(validate(&mut app, &mut fs, &good), Sw::OK);
}

#[test]
fn a_code_an_older_build_stored_still_opens_the_applet() {
    // The bound is on what SET CODE takes, never on what VALIDATE can read: a
    // key provisioned by a build that accepted up to 128 bytes must go on
    // working, or the upgrade locks its owner out of their own store.
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let dev = Device {
        serial_hash: &[0x22; 32],
        serial_id: &SERIAL,
        otp_key: None,
        latched: false,
    };
    let secret = [0x5Au8; OATH_CODE_MAX - 1];
    let mut stored = vec![ALG_HMAC_SHA1];
    stored.extend_from_slice(&secret);
    assert!(seal::seal_put(
        &dev,
        &mut fs,
        &mut CountRng(1),
        EF_OATH_CODE,
        &stored
    ));
    assert!(code_installed(&mut app, &mut fs));
    assert_eq!(validate(&mut app, &mut fs, &secret), Sw::OK);
}

// The two below were derived by co-refutation (`scripts/comutate.py`), which
// re-injects each model mutant into the Rust and demands a red slice. Three of
// this file's rules came back GREEN under the injection: the removal gate and
// both directions of a refused VALIDATE were held by the model alone.

#[test]
fn a_deselect_drops_the_validate_unlock() {
    // `RSKeyAppletSeams!NoStatusOutsideItsSelection` — SEC-SEAM-001 at the code
    // level. The model catches an applet that keeps its status across a
    // deselect (`BugSelectKeepsOtherApplet`); emptying this applet's `deselect`
    // was killed by no test, so a second application selected in between would
    // have inherited an unlocked store.
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let secret = [0xABu8; 20];
    assert_eq!(set_code(&mut app, &mut fs, &secret), Sw::OK);
    assert_eq!(validate(&mut app, &mut fs, &secret), Sw::OK);
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[])).0,
        Sw::OK,
        "the unlock must hold inside its own selection"
    );
    Applet::deselect(&mut app, &mut fs);
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[])).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "the unlock must not outlive the selection that earned it"
    );
}

#[test]
fn the_removal_is_behind_the_same_gate_as_the_install() {
    // `RSKeyAppletSeams!AccessCodeRemovalNeedsTheCode` — SEC-SEAM-006, at the
    // code level. `73 00` is the card's one spelling of "remove the access
    // code", so the gate above it is the whole distance between a stranger with
    // a reader and a store unlocked for good. The model was blind to this for
    // two revisions (its exemption fired exactly on the state the removal
    // creates); the Rust half was asserted by nobody at all.
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(set_code(&mut app, &mut fs, &[0xAB; 20]), Sw::OK);
    // A SELECT leaves the applet locked, which is the state the removal must
    // not escape — and `code_installed` asserts the gate and the challenge agree.
    assert!(code_installed(&mut app, &mut fs));
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &apdu(INS_SET_CODE, 0, 0, &tlv(TAG_KEY, &[]))
        )
        .0,
        Sw::SECURITY_STATUS_NOT_SATISFIED,
    );
    assert!(
        code_installed(&mut app, &mut fs),
        "an unvalidated `73 00` removed the access code",
    );
}

#[test]
fn a_refused_validate_neither_grants_nor_drops_the_unlock() {
    // `RSKeyAppletSeams!ExemptRefusalPreservesStatus` — SEC-SEAM-005, both
    // directions. VALIDATE is exempt from the refusal rule its siblings follow,
    // and exempt cuts both ways: a wrong proof may not unlock a locked applet,
    // and may not lock an unlocked one either. A MAC challenge-response has no
    // retry counter for a refusal to protect, so dropping the standing unlock
    // would cost availability and buy nothing. E62 pins the word; this is the
    // state behind it.
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let secret = [0xABu8; 20];
    assert_eq!(set_code(&mut app, &mut fs, &secret), Sw::OK);

    // One SELECT for the whole test: every new SELECT rotates the challenge AND
    // re-locks, so a second one would erase the standing unlock this measures.
    let chal = card_challenge(&mut app, &mut fs);
    let good = hmac_sha1(&secret, &chal);
    let mut wrong = good;
    wrong[0] ^= 0xFF;
    let list =
        |app: &mut OathApplet, fs: &mut Fs<RamStorage>| run(app, fs, &apdu(INS_LIST, 0, 0, &[])).0;

    assert_eq!(validate_proof(&mut app, &mut fs, &wrong), Sw::WRONG_DATA);
    assert_eq!(
        list(&mut app, &mut fs),
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "a refused VALIDATE unlocked the applet",
    );

    assert_eq!(validate_proof(&mut app, &mut fs, &good), Sw::OK);
    assert_eq!(list(&mut app, &mut fs), Sw::OK);
    assert_eq!(validate_proof(&mut app, &mut fs, &wrong), Sw::WRONG_DATA);
    assert_eq!(
        list(&mut app, &mut fs),
        Sw::OK,
        "a refused VALIDATE dropped the standing unlock",
    );
}

/// SET CODE keeps `EF_OTP_PIN` (a code any host could set once deleted it, and the
/// password safe with it), and re-arms the at-rest lap before its seal: the code
/// it supersedes can still be keyed under the pre-OTP arm a boot did not move.
#[test]
fn set_code_keeps_the_otp_pin_and_re_arms_the_lap_before_its_seal() {
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
        latched: false,
    };
    let mut rec = [0u8; OTP_PIN_REC_V1];
    assert_eq!(fs.read(EF_OTP_PIN, &mut rec), Some(OTP_PIN_REC_V1));
    assert_eq!(
        &rec[2..],
        &nootp.pin_derive_verifier(b"1234").expose()[..],
        "fixture: the PIN on the card is chip-serial-rooted",
    );

    // The OTP build, and the lap has already run.
    let mut app = OathApplet::new(
        SERIAL,
        [0x22; 32],
        Some(rsk_crypto::FusedKey::open(test_mkek)),
        &rng,
        &touch,
    );
    select(&mut app, &mut fs);
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    assert!(
        fs.has_data(rsk_fs::EF_HARDENED),
        "fixture: the lap has latched"
    );

    medium.clear_ops();
    assert_eq!(set_code(&mut app, &mut fs, &[0xABu8; 20]), Sw::OK);
    let mut kept = [0u8; OTP_PIN_REC_V1];
    assert_eq!(fs.read(EF_OTP_PIN, &mut kept), Some(OTP_PIN_REC_V1));
    assert_eq!(kept, rec, "SET CODE touched the OTP PIN");
    medium.assert_re_armed_before(EF_OATH_CODE.get(), |_| false, "SET CODE (the seal)");
    assert!(
        !fs.has_data(rsk_fs::EF_HARDENED),
        "SET CODE superseded a code record and must re-arm the at-rest lap",
    );
}

/// The re-arm's own refusal, on the one OATH command that INSTALLS an
/// authorization. A medium that refuses `remove(EF_HARDENED)` and serves every
/// other mutation once reached `6581` with the access code already sealed: a lock
/// the host was told had failed. The gate leads the seal, so a refused re-arm
/// writes nothing and the card is the one the caller started with.
#[test]
fn a_set_code_whose_re_arm_the_medium_refuses_installs_no_code() {
    let (stuck, medium) = RemoveStuck::new();
    let mut fs = Fs::new(stuck);
    fs.scan();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);

    // Pre-burn: SET PIN stores v1 under the NO-OTP (chip-serial) kbase — the copy
    // SET CODE's tombstone would supersede, which is why it owes the re-arm.
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
    assert!(fs.has_data(EF_OTP_PIN), "fixture: the OTP PIN is set");

    // The OTP build, unlocked (no code yet), and the lap has already run.
    let mut app = OathApplet::new(
        SERIAL,
        [0x22; 32],
        Some(rsk_crypto::FusedKey::open(test_mkek)),
        &rng,
        &touch,
    );
    select(&mut app, &mut fs);
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    assert!(
        fs.has_data(rsk_fs::EF_HARDENED),
        "fixture: the lap has latched"
    );
    medium.refuse(Some(rsk_fs::EF_HARDENED));

    let sw = set_code(&mut app, &mut fs, &[0xABu8; 20]);
    assert!(
        medium.live(rsk_fs::EF_HARDENED),
        "fixture: the medium really refused, so the marker is still on it"
    );
    assert!(
        !fs.has_key(EF_OATH_CODE),
        "the re-arm was refused, so nothing may be written — the access code is \
         installed under a refusal: a lock the owner now has to open",
    );
    assert_eq!(
        sw,
        Sw::MEMORY_FAILURE,
        "the lap will not run and the command must say so"
    );
    assert!(
        fs.has_data(EF_OTP_PIN),
        "the refusal leaves the standing PIN in force"
    );

    // The control, and not a no-op: clear the fault and the same SET CODE seals
    // the code, keeps the PIN and clears the marker.
    medium.refuse(None);
    assert_eq!(set_code(&mut app, &mut fs, &[0xABu8; 20]), Sw::OK);
    assert!(fs.has_key(EF_OATH_CODE), "the control installed the code");
    assert!(fs.has_data(EF_OTP_PIN), "the control kept the OTP PIN");
    assert!(
        !fs.has_data(rsk_fs::EF_HARDENED),
        "the control re-armed the lap"
    );
}

/// The undeclared half of moving the gate above the seal: the early return also
/// stands above `self.validated = false`, so a refused re-arm no longer locks the
/// session down. That is the right half to keep — the command wrote NOTHING, so it
/// must leave the card as it found it, and the lock-down exists to revoke the
/// second unlock path SET CODE creates, which a refused re-arm never created. The
/// status word is unchanged either way, so only this pins it.
#[test]
fn a_refused_re_arm_leaves_the_session_exactly_as_it_found_it() {
    let (stuck, medium) = RemoveStuck::new();
    let mut fs = Fs::new(stuck);
    fs.scan();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(
        SERIAL,
        [0x22; 32],
        Some(rsk_crypto::FusedKey::open(test_mkek)),
        &rng,
        &touch,
    );
    assert_eq!(set_code(&mut app, &mut fs, &[0xCDu8; 20]), Sw::OK);
    let (_, sel) = select(&mut app, &mut fs);
    let chal = find_tag(&sel, TAG_CHALLENGE as u16).unwrap().to_vec();
    let mut d = tlv(TAG_RESPONSE, &hmac_sha1(&[0xCDu8; 20], &chal));
    d.extend(tlv(TAG_CHALLENGE, &[9u8; 8]));
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_VALIDATE, 0, 0, &d)).0,
        Sw::OK
    );
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[])).0,
        Sw::OK,
        "fixture: the standing code was presented, so the session is open"
    );

    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    medium.refuse(Some(rsk_fs::EF_HARDENED));
    let sw = set_code(&mut app, &mut fs, &[0xABu8; 20]);
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[])).0,
        Sw::OK,
        "the refused SET CODE wrote nothing, so it must not revoke an unlock the \
         caller had already earned with the code that is still the standing one",
    );
    assert_eq!(sw, Sw::MEMORY_FAILURE);
    assert!(
        fs.has_data(rsk_fs::EF_HARDENED),
        "fixture: the marker stands"
    );

    // The control on the same medium, fault cleared: the command lands and the
    // lock-down DOES happen, so the assertion above is about the refused arm and
    // not about a session this applet never locks.
    medium.refuse(None);
    assert_eq!(set_code(&mut app, &mut fs, &[0xABu8; 20]), Sw::OK);
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[])).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "a SET CODE that landed must lock the session it just re-keyed",
    );
}

/// A code-less applet with an OTP PIN guarding the password safe. Setting a code
/// needs no credential there (nor on a YubiKey), and it deleted that PIN: any host
/// set its own code, VALIDATEd with it and read every stored password.
#[test]
fn a_host_that_sets_a_code_does_not_open_the_password_safe() {
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    select(&mut app, &mut fs);
    let mut cred = put_data(b"bank", 0x21, 6, SECRET_SHA1, false, None);
    cred.extend(tlv(TAG_PWS_PASSWORD, b"s3cr3t"));
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_PUT, 0, 0, &cred)).0,
        Sw::OK
    );
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))
        )
        .0,
        Sw::OK
    );

    // Another host, on a new connection: no PIN, a code of its own.
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    select(&mut app, &mut fs);
    assert_eq!(set_code(&mut app, &mut fs, &[0xABu8; 20]), Sw::OK);
    assert_eq!(validate(&mut app, &mut fs, &[0xABu8; 20]), Sw::OK);
    let get = apdu(INS_GET_CREDENTIAL, 0, 0, &tlv(TAG_NAME, b"bank"));
    assert_eq!(
        run(&mut app, &mut fs, &get).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "a code the host set itself read the password safe"
    );
    assert!(
        fs.has_data(EF_OTP_PIN),
        "the owner's PIN is still the safe's lock"
    );
}

/// On a coded applet the code opens the applet and the PIN the password safe: a
/// right PIN keeps the unlock VALIDATE gave and adds the safe, opens nothing
/// without it, and a wrong one drops both, as a failed CHANGE does.
#[test]
fn the_otp_pin_opens_a_coded_applets_safe_and_never_the_applet() {
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    select(&mut app, &mut fs);
    let mut cred = put_data(b"bank", 0x21, 6, SECRET_SHA1, false, None);
    cred.extend(tlv(TAG_PWS_PASSWORD, b"s3cr3t"));
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_PUT, 0, 0, &cred)).0,
        Sw::OK
    );
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))
        )
        .0,
        Sw::OK
    );
    assert_eq!(set_code(&mut app, &mut fs, &[0xABu8; 20]), Sw::OK);
    let pin = |app: &mut OathApplet, fs: &mut Fs<RamStorage>, pw: &[u8]| {
        run(app, fs, &apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, pw))).0
    };
    let list =
        |app: &mut OathApplet, fs: &mut Fs<RamStorage>| run(app, fs, &apdu(INS_LIST, 0, 0, &[])).0;
    let get = apdu(INS_GET_CREDENTIAL, 0, 0, &tlv(TAG_NAME, b"bank"));

    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    select(&mut app, &mut fs);
    assert_eq!(pin(&mut app, &mut fs, b"1234"), Sw::OK);
    assert_eq!(
        list(&mut app, &mut fs),
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "the PIN alone opened a coded applet"
    );
    assert_eq!(validate(&mut app, &mut fs, &[0xABu8; 20]), Sw::OK);
    assert_eq!(pin(&mut app, &mut fs, b"1234"), Sw::OK);
    assert_eq!(
        list(&mut app, &mut fs),
        Sw::OK,
        "the right PIN dropped VALIDATE's unlock"
    );
    assert_eq!(run(&mut app, &mut fs, &get).0, Sw::OK);
    assert_ne!(pin(&mut app, &mut fs, b"0000"), Sw::OK);
    assert_eq!(list(&mut app, &mut fs), Sw::SECURITY_STATUS_NOT_SATISFIED);
    assert_eq!(
        run(&mut app, &mut fs, &get).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
}
