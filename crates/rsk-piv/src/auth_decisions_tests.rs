// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

struct MeasuredPresence {
    answer: Presence,
    requests: usize,
}

impl UserPresence for MeasuredPresence {
    fn request(&mut self, _confirm: rsk_sdk::Confirm<'_>) -> Presence {
        self.requests += 1;
        self.answer
    }
}

#[derive(Clone, Copy, Debug)]
enum Operation {
    Sign,
    Agree,
}

impl Operation {
    fn body(self, payload: &[u8]) -> Vec<u8> {
        let tag = match self {
            Self::Sign => TAG_AUTH_CHALLENGE,
            Self::Agree => TAG_AUTH_EXPONENTIATION,
        };
        let mut body = vec![
            TAG_DYN_AUTH,
            (payload.len() + 4) as u8,
            TAG_AUTH_RESPONSE,
            0,
            tag,
            payload.len() as u8,
        ];
        body.extend_from_slice(payload);
        body
    }
}

fn generate(app: &mut PivApplet, fs: &mut Fs<RamStorage>, algo: u8) -> Vec<u8> {
    let template = [
        0xac,
        9,
        0x80,
        1,
        algo,
        0xaa,
        1,
        PINPOLICY_ALWAYS,
        0xab,
        1,
        TOUCHPOLICY_ALWAYS,
    ];
    let (sw, public) = run(app, fs, INS_ASYM_KEYGEN, 0, SLOT_SIGNATURE, &template);
    assert_eq!(sw, Sw::OK);
    ec_point_of(&public)
}

fn pin_policy_matrix(operation: Operation) {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(MeasuredPresence {
        answer: Presence::Confirmed,
        requests: 0,
    });
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    let point = generate(&mut app, &mut fs, ALGO_ECCP256);
    let body = operation.body(match operation {
        Operation::Sign => &[0x42; 32],
        Operation::Agree => &point,
    });
    for policy in [
        PINPOLICY_NEVER,
        PINPOLICY_ONCE,
        PINPOLICY_ALWAYS,
        PINPOLICY_DEFAULT,
        0xff,
    ] {
        // DEFAULT and undefined bytes model heads left by older builds.
        fs.meta_add(
            key_fid(SLOT_SIGNATURE).get(),
            &[ALGO_ECCP256, policy, TOUCHPOLICY_ALWAYS],
        )
        .unwrap();
        select(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
        let never = policy == PINPOLICY_NEVER;
        for verified in [false, true] {
            if verified {
                verify_pin(&mut app, &mut fs);
            }
            presence.borrow_mut().requests = 0;
            let (sw, out) = run(
                &mut app,
                &mut fs,
                INS_AUTHENTICATE,
                ALGO_ECCP256,
                SLOT_SIGNATURE,
                &body,
            );
            let admitted = never || verified;
            assert_eq!(
                sw,
                if admitted {
                    Sw::OK
                } else {
                    Sw::SECURITY_STATUS_NOT_SATISFIED
                },
                "{operation:?}, policy={policy:#x}, verified={verified}"
            );
            assert_eq!(out.is_empty(), !admitted);
            assert_eq!(presence.borrow().requests, usize::from(admitted));
            assert_eq!(app.sess.has_pin, verified);
            assert_eq!(app.sess.pin_fresh, verified && never);
            assert!(app.sess.has_mgm);
        }
        let once = matches!(policy, PINPOLICY_ONCE | 0xff);
        presence.borrow_mut().requests = 0;
        let (sw, out) = run(
            &mut app,
            &mut fs,
            INS_AUTHENTICATE,
            ALGO_ECCP256,
            SLOT_SIGNATURE,
            &body,
        );
        let admitted = never || once;
        assert_eq!(
            sw,
            if admitted {
                Sw::OK
            } else {
                Sw::SECURITY_STATUS_NOT_SATISFIED
            },
            "{operation:?}, policy={policy:#x}, spent freshness"
        );
        assert_eq!(out.is_empty(), !admitted);
        assert_eq!(presence.borrow().requests, usize::from(admitted));
        assert!(app.sess.has_pin && app.sess.has_mgm);
        assert_eq!(app.sess.pin_fresh, never);
        verify_pin(&mut app, &mut fs);
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                INS_AUTHENTICATE,
                ALGO_ECCP256,
                SLOT_SIGNATURE,
                &body,
            )
            .0,
            Sw::OK
        );
        assert_eq!(retries_left(&mut fs, RETRY_PIN), Ok(DEFAULT_RETRIES));
    }
}

#[test]
fn signing_requires_the_resolved_pin_policy_before_the_touch() {
    pin_policy_matrix(Operation::Sign);
}

#[test]
fn agreement_requires_the_resolved_pin_policy_before_the_touch() {
    pin_policy_matrix(Operation::Agree);
}

#[test]
fn every_non_never_touch_policy_requires_confirmation_before_the_key() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(MeasuredPresence {
        answer: Presence::Confirmed,
        requests: 0,
    });
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    let point = generate(&mut app, &mut fs, ALGO_ECCP256);
    for operation in [Operation::Sign, Operation::Agree] {
        let body = operation.body(match operation {
            Operation::Sign => &[0x42; 32],
            Operation::Agree => &point,
        });
        for policy in [
            TOUCHPOLICY_NEVER,
            TOUCHPOLICY_ALWAYS,
            TOUCHPOLICY_CACHED,
            TOUCHPOLICY_DEFAULT,
            0xff,
        ] {
            fs.meta_add(
                key_fid(SLOT_SIGNATURE).get(),
                &[ALGO_ECCP256, PINPOLICY_ALWAYS, policy],
            )
            .unwrap();
            for answer in [
                Presence::Confirmed,
                Presence::Declined,
                Presence::Timeout,
                Presence::Cancelled,
            ] {
                verify_pin(&mut app, &mut fs);
                presence.borrow_mut().answer = answer;
                presence.borrow_mut().requests = 0;
                let (sw, out) = run(
                    &mut app,
                    &mut fs,
                    INS_AUTHENTICATE,
                    ALGO_ECCP256,
                    SLOT_SIGNATURE,
                    &body,
                );
                let never = policy == TOUCHPOLICY_NEVER;
                let admitted = never || answer == Presence::Confirmed;
                assert_eq!(
                    sw,
                    if admitted {
                        Sw::OK
                    } else {
                        Sw::SECURITY_STATUS_NOT_SATISFIED
                    },
                    "{operation:?}, policy={policy:#x}, answer={answer:?}"
                );
                assert_eq!(out.is_empty(), !admitted);
                assert_eq!(presence.borrow().requests, usize::from(!never));
                assert!(app.sess.has_pin && app.sess.has_mgm);
                assert_eq!(app.sess.pin_fresh, !admitted);
                presence.borrow_mut().answer = Presence::Confirmed;
                if !admitted {
                    assert_eq!(
                        run(
                            &mut app,
                            &mut fs,
                            INS_AUTHENTICATE,
                            ALGO_ECCP256,
                            SLOT_SIGNATURE,
                            &body
                        )
                        .0,
                        Sw::OK
                    );
                }
            }
        }
    }
}

#[test]
fn a_sealed_curve_mismatch_preserves_pin_freshness() {
    for (stored, declared, operation, len) in [
        (ALGO_ECCP256, ALGO_ECCP384, Operation::Sign, 48),
        (ALGO_ECCP384, ALGO_ECCP256, Operation::Sign, 32),
        (ALGO_ECCP256, ALGO_ECCP384, Operation::Agree, 97),
        (ALGO_ECCP384, ALGO_ECCP256, Operation::Agree, 65),
        (ALGO_ED25519, ALGO_X25519, Operation::Agree, 32),
        (ALGO_X25519, ALGO_ED25519, Operation::Sign, 32),
    ] {
        let rng = RefCell::new(TestRng(7));
        let presence = RefCell::new(MeasuredPresence {
            answer: Presence::Confirmed,
            requests: 0,
        });
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
        let point = generate(&mut app, &mut fs, stored);
        // A mismatched head can pass the outer algorithm check, but not the seal's curve.
        fs.meta_add(
            key_fid(SLOT_SIGNATURE).get(),
            &[declared, PINPOLICY_ALWAYS, TOUCHPOLICY_ALWAYS],
        )
        .unwrap();
        verify_pin(&mut app, &mut fs);
        presence.borrow_mut().requests = 0;
        let (sw, out) = run(
            &mut app,
            &mut fs,
            INS_AUTHENTICATE,
            declared,
            SLOT_SIGNATURE,
            &operation.body(&vec![0x42; len]),
        );
        assert_eq!(
            sw,
            Sw::WRONG_DATA,
            "stored={stored:#x}, declared={declared:#x}"
        );
        assert!(out.is_empty());
        assert_eq!(presence.borrow().requests, 1);
        assert!(app.sess.has_pin && app.sess.pin_fresh && app.sess.has_mgm);
        fs.meta_add(
            key_fid(SLOT_SIGNATURE).get(),
            &[stored, PINPOLICY_ALWAYS, TOUCHPOLICY_ALWAYS],
        )
        .unwrap();
        let healthy = if stored == ALGO_X25519 {
            Operation::Agree.body(&point)
        } else {
            Operation::Sign.body(&[0x42; 32])
        };
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                INS_AUTHENTICATE,
                stored,
                SLOT_SIGNATURE,
                &healthy
            )
            .0,
            Sw::OK
        );
    }
}

#[test]
fn a_signing_only_key_cannot_agree_or_consume_pin_freshness() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(MeasuredPresence {
        answer: Presence::Confirmed,
        requests: 0,
    });
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    let point = generate(&mut app, &mut fs, ALGO_ED25519);
    verify_pin(&mut app, &mut fs);
    presence.borrow_mut().requests = 0;
    let (sw, out) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_ED25519,
        SLOT_SIGNATURE,
        &Operation::Agree.body(&[9; 32]),
    );
    assert_eq!(sw, Sw::WRONG_DATA);
    assert!(out.is_empty());
    assert_eq!(presence.borrow().requests, 0);
    assert!(app.sess.has_pin && app.sess.pin_fresh && app.sess.has_mgm);
    let message = b"PIV signing-only key";
    let (sw, response) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_ED25519,
        SLOT_SIGNATURE,
        &Operation::Sign.body(message),
    );
    assert_eq!(sw, Sw::OK);
    let signature = ed25519_dalek::Signature::from_slice(
        find_tag(
            find_tag(&response, u16::from(TAG_DYN_AUTH)).unwrap(),
            u16::from(TAG_AUTH_RESPONSE),
        )
        .unwrap(),
    )
    .unwrap();
    ed25519_dalek::VerifyingKey::from_bytes(point.as_slice().try_into().unwrap())
        .unwrap()
        .verify_strict(message, &signature)
        .unwrap();
}

#[test]
fn short_private_operation_responses_still_spend_pin_freshness() {
    for (algo, operation) in [
        (ALGO_ECCP256, Operation::Sign),
        (ALGO_ECCP384, Operation::Sign),
        (ALGO_ED25519, Operation::Sign),
        (ALGO_ECCP256, Operation::Agree),
        (ALGO_ECCP384, Operation::Agree),
        (ALGO_X25519, Operation::Agree),
    ] {
        let rng = RefCell::new(TestRng(7));
        let presence = RefCell::new(MeasuredPresence {
            answer: Presence::Confirmed,
            requests: 0,
        });
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
        let point = generate(&mut app, &mut fs, algo);
        let body = operation.body(match operation {
            Operation::Sign => &[0x42; 32],
            Operation::Agree => &point,
        });
        verify_pin(&mut app, &mut fs);
        let (sw, expected) = run(
            &mut app,
            &mut fs,
            INS_AUTHENTICATE,
            algo,
            SLOT_SIGNATURE,
            &body,
        );
        assert_eq!(sw, Sw::OK);
        let raw = apdu_bytes(INS_AUTHENTICATE, algo, SLOT_SIGNATURE, &body);
        let apdu = Apdu::parse(&raw).unwrap();
        for capacity in [0, 1, 2, 3, expected.len() - 1, expected.len()] {
            verify_pin(&mut app, &mut fs);
            presence.borrow_mut().requests = 0;
            let mut buffer = vec![0; capacity];
            let mut response = ResBuf::new(&mut buffer);
            assert_eq!(
                Applet::process(&mut app, &apdu, &mut fs, &mut response),
                if capacity == expected.len() {
                    Sw::OK
                } else {
                    Sw::WRONG_LENGTH
                },
                "algo={algo:#x}, {operation:?}, capacity={capacity}"
            );
            assert_eq!(response.as_slice(), &expected[..response.len()]);
            assert_eq!(presence.borrow().requests, 1);
            assert!(app.sess.has_pin && app.sess.has_mgm);
            assert!(!app.sess.pin_fresh);
            assert_eq!(
                run(
                    &mut app,
                    &mut fs,
                    INS_AUTHENTICATE,
                    algo,
                    SLOT_SIGNATURE,
                    &body
                ),
                (Sw::SECURITY_STATUS_NOT_SATISFIED, Vec::new())
            );
            assert_eq!(presence.borrow().requests, 1);
        }
        verify_pin(&mut app, &mut fs);
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                INS_AUTHENTICATE,
                algo,
                SLOT_SIGNATURE,
                &body
            ),
            (Sw::OK, expected)
        );
    }
}

#[test]
fn malformed_dynamic_templates_do_not_prompt_or_spend_the_pin() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(MeasuredPresence {
        answer: Presence::Confirmed,
        requests: 0,
    });
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    generate(&mut app, &mut fs, ALGO_ECCP256);
    verify_pin(&mut app, &mut fs);
    presence.borrow_mut().requests = 0;
    for body in [
        &[TAG_DYN_AUTH, 0][..],
        &[TAG_DYN_AUTH, 3, TAG_AUTH_CHALLENGE, 0],
        &[TAG_DYN_AUTH, 0x81],
    ] {
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                INS_AUTHENTICATE,
                ALGO_ECCP256,
                SLOT_SIGNATURE,
                body
            ),
            (Sw::WRONG_DATA, Vec::new())
        );
        assert_eq!(presence.borrow().requests, 0);
        assert!(app.sess.has_pin && app.sess.pin_fresh && app.sess.has_mgm);
    }
    assert_eq!(sign_p256(&mut app, &mut fs, SLOT_SIGNATURE), Sw::OK);
}
