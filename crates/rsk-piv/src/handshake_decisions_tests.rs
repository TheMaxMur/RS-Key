// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn body(tag: u8, payload: &[u8], host_challenge: Option<&[u8]>) -> Vec<u8> {
    let mut inner = vec![tag, payload.len() as u8];
    inner.extend_from_slice(payload);
    if let Some(challenge) = host_challenge {
        inner.extend_from_slice(&[TAG_AUTH_CHALLENGE, challenge.len() as u8]);
        inner.extend_from_slice(challenge);
    }
    let mut outer = vec![TAG_DYN_AUTH, inner.len() as u8];
    outer.extend_from_slice(&inner);
    outer
}

fn begin(app: &mut PivApplet, fs: &mut Fs<RamStorage>, tag: u8) -> [u8; 16] {
    let (sw, response) = run(
        app,
        fs,
        INS_AUTHENTICATE,
        ALGO_AES192,
        SLOT_CARDMGM,
        &body(tag, &[], None),
    );
    assert_eq!(sw, Sw::OK);
    assert!(app.sess.has_challenge);
    assert!(!app.sess.has_mgm);
    let mut block: [u8; 16] = find_tag(
        find_tag(&response, u16::from(TAG_DYN_AUTH)).unwrap(),
        u16::from(tag),
    )
    .unwrap()
    .try_into()
    .unwrap();
    if tag == TAG_AUTH_WITNESS {
        rsk_crypto::aes_ecb_decrypt_block(&DEFAULT_MGM, &mut block).unwrap();
    } else {
        rsk_crypto::aes_ecb_encrypt_block(&DEFAULT_MGM, &mut block).unwrap();
    }
    block
}

fn authenticate(app: &mut PivApplet, fs: &mut Fs<RamStorage>, body: &[u8]) -> (Sw, Vec<u8>) {
    run(app, fs, INS_AUTHENTICATE, ALGO_AES192, SLOT_CARDMGM, body)
}

#[test]
fn management_answers_at_a_private_slot_leave_the_pending_witness_usable() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            INS_ASYM_KEYGEN,
            0,
            SLOT_SIGNATURE,
            &gen_template(ALGO_ECCP256)
        )
        .0,
        Sw::OK
    );
    verify_pin(&mut app, &mut fs);
    let witness = begin(&mut app, &mut fs, TAG_AUTH_WITNESS);
    let challenge = app.sess.challenge;
    let mutual = body(TAG_AUTH_WITNESS, &witness, Some(&[0xa5; 16]));
    let single = body(TAG_AUTH_RESPONSE, &witness, None);
    for request in [&mutual, &single] {
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                INS_AUTHENTICATE,
                ALGO_ECCP256,
                SLOT_SIGNATURE,
                request
            ),
            (Sw::WRONG_DATA, Vec::new())
        );
        assert!(app.sess.has_pin && app.sess.pin_fresh && app.sess.has_challenge);
        assert_eq!(app.sess.challenge, challenge);
        assert!(!app.sess.has_mgm);
    }
    // A single-auth answer cannot consume a mutual-auth witness at 9B either.
    assert_eq!(
        authenticate(&mut app, &mut fs, &single),
        (Sw::WRONG_DATA, Vec::new())
    );
    assert!(app.sess.has_challenge && app.sess.pin_fresh);
    let (sw, response) = authenticate(&mut app, &mut fs, &mutual);
    assert_eq!(sw, Sw::OK);
    let mut expected = [0xa5; 16];
    rsk_crypto::aes_ecb_encrypt_block(&DEFAULT_MGM, &mut expected).unwrap();
    assert_eq!(&response[4..], expected);
    assert!(app.sess.has_mgm && app.sess.has_pin && app.sess.pin_fresh);
    assert!(!app.sess.has_challenge);
    assert_eq!(sign_p256(&mut app, &mut fs, SLOT_SIGNATURE), Sw::OK);
}

#[test]
fn a_mutual_witness_cannot_be_replayed_as_a_single_auth_answer() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    let (sw, response) = authenticate(&mut app, &mut fs, &body(TAG_AUTH_WITNESS, &[], None));
    assert_eq!(sw, Sw::OK);
    // These are bytes the card supplied, with no management-key knowledge at the host.
    let encrypted_witness = find_tag(
        find_tag(&response, u16::from(TAG_DYN_AUTH)).unwrap(),
        u16::from(TAG_AUTH_WITNESS),
    )
    .unwrap();
    assert_eq!(
        authenticate(
            &mut app,
            &mut fs,
            &body(TAG_AUTH_RESPONSE, encrypted_witness, None)
        ),
        (Sw::WRONG_DATA, Vec::new())
    );
    assert!(!app.sess.has_mgm);
    assert!(app.sess.has_challenge && app.sess.has_pin && app.sess.pin_fresh);
    assert!(matches!(app.sess.chal_kind, ChallengeKind::MutualWitness));
    assert_eq!(
        run(&mut app, &mut fs, INS_SET_RETRIES, 5, 4, &[]).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(retries_left(&mut fs, RETRY_PIN), Ok(DEFAULT_RETRIES));
    auth_mgm(&mut app, &mut fs);
    assert_eq!(run(&mut app, &mut fs, INS_SET_RETRIES, 5, 4, &[]).0, Sw::OK);
    assert_eq!(retries_left(&mut fs, RETRY_PIN), Ok(5));
}

#[test]
fn non_block_sized_answers_consume_the_challenge_without_authenticating() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    for (start, answer) in [
        (TAG_AUTH_WITNESS, TAG_AUTH_WITNESS),
        (TAG_AUTH_CHALLENGE, TAG_AUTH_RESPONSE),
    ] {
        for len in [1, 15, 17] {
            verify_pin(&mut app, &mut fs);
            let block = begin(&mut app, &mut fs, start);
            let host = (start == TAG_AUTH_WITNESS).then_some(&[0xa5; 16][..]);
            let mut malformed = block.to_vec();
            malformed.resize(len, 0);
            assert_eq!(
                authenticate(&mut app, &mut fs, &body(answer, &malformed, host)),
                (Sw::DATA_INVALID, Vec::new()),
                "tag={answer:#x}, len={len}"
            );
            assert!(!app.sess.has_mgm && !app.sess.has_challenge);
            assert!(matches!(app.sess.chal_kind, ChallengeKind::None));
            assert!(app.sess.has_pin && app.sess.pin_fresh);
            assert_eq!(
                authenticate(&mut app, &mut fs, &body(answer, &block, host)),
                (Sw::WRONG_DATA, Vec::new())
            );
            auth_mgm(&mut app, &mut fs);
            assert!(app.sess.has_mgm && app.sess.has_pin && app.sess.pin_fresh);
        }
    }
}

#[test]
fn a_missing_host_challenge_does_not_consume_a_correct_witness() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    let witness = begin(&mut app, &mut fs, TAG_AUTH_WITNESS);
    for host in [None, Some(&[][..])] {
        assert_eq!(
            authenticate(&mut app, &mut fs, &body(TAG_AUTH_WITNESS, &witness, host)),
            (Sw::WRONG_DATA, Vec::new())
        );
        assert!(app.sess.has_challenge && app.sess.has_pin && app.sess.pin_fresh);
        assert!(matches!(app.sess.chal_kind, ChallengeKind::MutualWitness));
        assert!(!app.sess.has_mgm);
    }
    assert_eq!(
        authenticate(
            &mut app,
            &mut fs,
            &body(TAG_AUTH_WITNESS, &witness, Some(&[0xa5; 16]))
        )
        .0,
        Sw::OK
    );
    assert!(app.sess.has_mgm && !app.sess.has_challenge);
}

#[test]
fn a_correct_witness_authenticates_even_when_the_host_challenge_has_the_wrong_width() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    for len in [1, 15, 17] {
        verify_pin(&mut app, &mut fs);
        let witness = begin(&mut app, &mut fs, TAG_AUTH_WITNESS);
        let request = body(TAG_AUTH_WITNESS, &witness, Some(&vec![0xa5; len]));
        assert_eq!(
            authenticate(&mut app, &mut fs, &request),
            (Sw::DATA_INVALID, Vec::new())
        );
        assert!(app.sess.has_mgm && app.sess.has_pin && app.sess.pin_fresh);
        assert!(!app.sess.has_challenge);
        assert_eq!(
            authenticate(&mut app, &mut fs, &request),
            (Sw::WRONG_DATA, Vec::new())
        );
        let object = [0x5c, 3, 0x5f, 0xc1, 9, 0x53, 3, 0x41, 0x42, 0x43];
        assert_eq!(
            run(&mut app, &mut fs, INS_PUT_DATA, 0x3f, 0xff, &object).0,
            Sw::OK
        );
        let (sw, response) = run(&mut app, &mut fs, INS_GET_DATA, 0x3f, 0xff, &object[..5]);
        assert_eq!(sw, Sw::OK);
        assert_eq!(find_tag(&response, 0x53), Some(&object[7..]));
        auth_mgm(&mut app, &mut fs);
    }
}
