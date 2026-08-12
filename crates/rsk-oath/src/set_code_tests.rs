// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! E59: what SET CODE (`0x03`) accepts as an access code. A YubiKey 5.7.4 takes
//! an algorithm byte plus **14..=64 bytes** of key — the same range it enforces
//! on a credential's secret — and answers `6A80` for everything else, leaving
//! the installed code exactly as it was (worklog ORACLE-oathfido §E59).

use super::*;

fn fixture() -> (Fs<RamStorage>, RefCell<CountRng>) {
    (new_fs(), RefCell::new(CountRng(7)))
}

const PROOF_CHAL: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

/// SET CODE with `secret` as the key material, proving knowledge of it the way
/// ykman does: `75` = `HMAC(secret, 74)`.
fn set_code(app: &mut OathApplet, fs: &mut Fs<RamStorage>, secret: &[u8]) -> Sw {
    let mut key = vec![ALG_HMAC_SHA1];
    key.extend_from_slice(secret);
    let mut d = tlv(TAG_KEY, &key);
    d.extend(tlv(TAG_CHALLENGE, &PROOF_CHAL));
    d.extend(tlv(TAG_RESPONSE, &hmac_sha1(secret, &PROOF_CHAL)));
    run(app, fs, &apdu(INS_SET_CODE, 0, 0, &d)).0
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

/// VALIDATE against the challenge this SELECT offered, with `secret`.
fn validate(app: &mut OathApplet, fs: &mut Fs<RamStorage>, secret: &[u8]) -> Sw {
    let (_, body) = select(app, fs);
    let chal = find_tag(&body, TAG_CHALLENGE as u16).unwrap().to_vec();
    let mut d = tlv(TAG_CHALLENGE, &[9u8; 8]);
    d.extend(tlv(TAG_RESPONSE, &hmac_sha1(secret, &chal)));
    run(app, fs, &apdu(INS_VALIDATE, 0, 0, &d)).0
}

#[test]
fn a_code_with_no_key_material_is_refused() {
    // `73 01 01` — an algorithm byte and nothing else. It used to install a lock
    // whose VALIDATE response is `HMAC(empty key, challenge)`: a code every host
    // in the world can compute, standing between the owner and their store.
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(set_code(&mut app, &mut fs, &[]), Sw::INCORRECT_PARAMS);
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
            if accepted {
                Sw::OK
            } else {
                Sw::INCORRECT_PARAMS
            },
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
    assert_eq!(set_code(&mut app, &mut fs, &short), Sw::INCORRECT_PARAMS);
    assert!(code_installed(&mut app, &mut fs));
    assert_eq!(
        validate(&mut app, &mut fs, &short),
        Sw::DATA_INVALID,
        "the refused key must not open the applet",
    );
    assert_eq!(
        validate(&mut app, &mut fs, &good),
        Sw::OK,
        "the standing code must still open it",
    );
}

#[test]
fn the_two_documented_ways_to_remove_a_code_still_work() {
    // `73 00` is the card's spelling. An absent body is the YKOATH document's
    // ("If length 0 is sent, authentication is removed") — a 5.7.4 answers
    // `6A80` to that one, and the divergence is the maintainer's call, not a
    // fix's: copying the card would break a host that follows the document.
    for body in [&tlv(TAG_KEY, &[])[..], &[][..]] {
        let (mut fs, rng) = fixture();
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        assert_eq!(set_code(&mut app, &mut fs, &[0xABu8; 16]), Sw::OK);
        assert_eq!(validate(&mut app, &mut fs, &[0xABu8; 16]), Sw::OK);
        assert_eq!(
            run(&mut app, &mut fs, &apdu(INS_SET_CODE, 0, 0, body)).0,
            Sw::OK
        );
        assert!(!code_installed(&mut app, &mut fs));
    }
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
