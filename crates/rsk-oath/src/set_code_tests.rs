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
fn set_code_over(app: &mut OathApplet, fs: &mut Fs<RamStorage>, secret: &[u8], chal: &[u8]) -> Sw {
    let mut key = vec![ALG_HMAC_SHA1];
    key.extend_from_slice(secret);
    let mut d = tlv(TAG_KEY, &key);
    d.extend(tlv(TAG_CHALLENGE, chal));
    d.extend(tlv(TAG_RESPONSE, &hmac_sha1(secret, chal)));
    run(app, fs, &apdu(INS_SET_CODE, 0, 0, &d)).0
}

/// SET CODE over the 8-byte challenge every host sends.
fn set_code(app: &mut OathApplet, fs: &mut Fs<RamStorage>, secret: &[u8]) -> Sw {
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

    // One SELECT for the whole test: every SELECT rotates the challenge AND
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
