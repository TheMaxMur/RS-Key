// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! E61: the bodies CALCULATE, VALIDATE and SET CODE accept. A YubiKey 5.7.4
//! reads them by position — exactly the documented TLVs, in the documented
//! order, nothing before, between or after — and answers `6A80` to everything
//! else, including a duplicate tag, a reordering and a trailing byte. Ours found
//! each tag anywhere and ignored the rest, so a body the host did not mean came
//! back `9000` (worklog ORACLE-oathfido §E61). CALCULATE ALL is the card's one
//! exception: its `74` must come first, and what follows is ignored.
//!
//! The orders below are ykman 5.9.2's (`yubikit/oath.py`) and the vendored
//! pico-fido suite's, byte for byte — VALIDATE really does send the response
//! before the challenge.

use super::*;

fn fixture() -> (Fs<RamStorage>, RefCell<CountRng>, RefCell<AlwaysConfirm>) {
    (
        new_fs(),
        RefCell::new(CountRng(7)),
        RefCell::new(AlwaysConfirm),
    )
}

/// A credential to read, and the well-formed CALCULATE body for it.
fn one_cred(app: &mut OathApplet, fs: &mut Fs<RamStorage>) -> (Vec<u8>, Vec<u8>) {
    assert_eq!(
        put(app, fs, &put_data(b"c", 0x21, 6, SECRET_SHA1, false, None)),
        Sw::OK
    );
    (tlv(TAG_NAME, b"c"), tlv(TAG_CHALLENGE, &1u64.to_be_bytes()))
}

/// Whether an access code stands, asked the way a host would.
fn code_set(app: &mut OathApplet, fs: &mut Fs<RamStorage>) -> bool {
    find_tag(&select(app, fs).1, TAG_CHALLENGE as u16).is_some()
}

#[test]
fn calculate_takes_the_name_then_the_challenge_and_nothing_else() {
    let (mut fs, rng, touch) = fixture();
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let (name, chal) = one_cred(&mut app, &mut fs);
    let good = [name.clone(), chal.clone()].concat();
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_CALCULATE, 0, 0x01, &good)).0,
        Sw::OK,
        "the documented body",
    );
    for (label, body) in [
        ("reordered", [chal.clone(), name.clone()].concat()),
        (
            "a duplicate name",
            [name.clone(), name.clone(), chal.clone()].concat(),
        ),
        (
            "a duplicate challenge",
            [name.clone(), chal.clone(), chal.clone()].concat(),
        ),
        (
            "trailing junk",
            [good.as_slice(), &[0xAA, 0x01, 0x00]].concat(),
        ),
        ("a trailing byte", [good.as_slice(), &[0x00]].concat()),
        (
            "an unknown tag first",
            [&[0xAAu8, 0x01, 0x00][..], &good].concat(),
        ),
        ("the name alone", name.clone()),
        ("the challenge alone", chal.clone()),
    ] {
        assert_eq!(
            run(&mut app, &mut fs, &apdu(INS_CALCULATE, 0, 0x01, &body)).0,
            Sw::INCORRECT_PARAMS,
            "{label}",
        );
    }
}

#[test]
fn calculate_all_wants_the_challenge_first_and_ignores_the_rest() {
    let (mut fs, rng, touch) = fixture();
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let (name, chal) = one_cred(&mut app, &mut fs);
    for (label, body, want) in [
        ("the documented body", chal.clone(), Sw::OK),
        // The card computes and ignores whatever follows its challenge.
        (
            "trailing junk",
            [chal.as_slice(), &[0xAA, 0x01, 0x00]].concat(),
            Sw::OK,
        ),
        (
            "an unknown tag first",
            [&[0xAAu8, 0x01, 0x00][..], &chal].concat(),
            Sw::INCORRECT_PARAMS,
        ),
        ("a name first", [name, chal].concat(), Sw::INCORRECT_PARAMS),
        ("no challenge at all", vec![], Sw::INCORRECT_PARAMS),
    ] {
        assert_eq!(
            run(&mut app, &mut fs, &apdu(INS_CALC_ALL, 0, 0x01, &body)).0,
            want,
            "{label}",
        );
    }
}

#[test]
fn validate_takes_the_response_then_the_challenge() {
    let (mut fs, rng, touch) = fixture();
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    // No code installed: a well-formed body reaches the code lookup and answers
    // `6984`, so every `6A80` below is the grammar and nothing else.
    let chal = tlv(TAG_CHALLENGE, &[9u8; 8]);
    let resp = tlv(TAG_RESPONSE, &[0u8; 20]);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &apdu(INS_VALIDATE, 0, 0, &[resp.clone(), chal.clone()].concat())
        )
        .0,
        Sw::DATA_INVALID,
        "the documented body",
    );
    for (label, body) in [
        ("reordered", [chal.clone(), resp.clone()].concat()),
        (
            "a duplicate response",
            [resp.clone(), resp.clone(), chal.clone()].concat(),
        ),
        ("the response alone", resp.clone()),
        ("the challenge alone", chal.clone()),
        (
            "trailing junk",
            [resp.clone(), chal.clone(), tlv(0xAA, &[0x00])].concat(),
        ),
    ] {
        assert_eq!(
            run(&mut app, &mut fs, &apdu(INS_VALIDATE, 0, 0, &body)).0,
            Sw::INCORRECT_PARAMS,
            "{label}",
        );
    }
}

#[test]
fn set_code_takes_the_key_then_the_proof_and_leaves_a_refusal_alone() {
    let (mut fs, rng, touch) = fixture();
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let secret = [0xABu8; 16];
    let mut material = vec![ALG_HMAC_SHA1];
    material.extend_from_slice(&secret);
    let key = tlv(TAG_KEY, &material);
    let chal = tlv(TAG_CHALLENGE, &[1u8, 2, 3, 4, 5, 6, 7, 8]);
    let resp = tlv(
        TAG_RESPONSE,
        &hmac_sha1(&secret, &[1u8, 2, 3, 4, 5, 6, 7, 8]),
    );
    let good = [key.clone(), chal.clone(), resp.clone()].concat();
    for (label, body) in [
        (
            "reordered",
            [resp.clone(), chal.clone(), key.clone()].concat(),
        ),
        (
            "key last",
            [chal.clone(), resp.clone(), key.clone()].concat(),
        ),
        (
            "a duplicate key",
            [key.clone(), key.clone(), chal.clone(), resp.clone()].concat(),
        ),
        (
            "trailing junk",
            [good.as_slice(), &[0xAA, 0x01, 0x00]].concat(),
        ),
        (
            "an unknown tag first",
            [&[0xAAu8, 0x01, 0x00][..], &good].concat(),
        ),
        ("the key alone", key.clone()),
    ] {
        assert_eq!(
            run(&mut app, &mut fs, &apdu(INS_SET_CODE, 0, 0, &body)).0,
            Sw::INCORRECT_PARAMS,
            "{label}",
        );
        assert!(!code_set(&mut app, &mut fs), "{label} installed a code");
    }
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_SET_CODE, 0, 0, &good)).0,
        Sw::OK,
        "the documented body",
    );
    assert!(code_set(&mut app, &mut fs));
}
