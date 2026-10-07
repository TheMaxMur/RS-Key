// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn malformed_u2f_bodies_are_refused_before_presence_or_persistence() {
    let mut fs = Fs::new(RamStorage::new());
    crate::tests::uv_optional(&mut fs);
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let mut state = crate::FidoState::new();
    let mut presence = CountingPresence {
        verdict: crate::Presence::Confirmed,
        calls: 0,
    };
    let mut cases = std::vec::Vec::new();
    for len in [0, 1, 63, 65, 128] {
        cases.push((CTAP_REGISTER, std::vec![0; len], Sw::WRONG_LENGTH));
    }
    for len in [0, 1, 32, 64, 65] {
        cases.push((CTAP_AUTHENTICATE, std::vec![0; len], Sw::WRONG_DATA));
    }
    for (len, handle_len) in [(129, 0), (129, 63), (129, 65)] {
        let mut body = std::vec![0; len];
        body[64] = handle_len;
        cases.push((CTAP_AUTHENTICATE, body, Sw::WRONG_DATA));
    }
    for (ins, body, expected) in cases {
        let raw = ext_apdu(ins, U2F_AUTH_ENFORCE, &body);
        let apdu = hid_apdu(&raw).unwrap();
        let generation = fs.write_gen();
        let mut out = [0xA5; 1024];
        let result = process_u2f(
            &mut Ctx {
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 0,
                presence: &mut presence,
            },
            &apdu,
            &mut out,
        );
        assert_eq!(result, (expected, 0), "INS {ins:#x}, {} bytes", body.len());
        assert_eq!(out, [0xA5; 1024]);
        assert_eq!(presence.calls, 0);
        assert_eq!(fs.write_gen(), generation);
    }
}

#[test]
fn a_short_version_output_cannot_report_a_partial_version() {
    let mut fs = Fs::new(RamStorage::new());
    crate::tests::uv_optional(&mut fs);
    let mut rng = SeqRng(1);
    let mut state = crate::FidoState::new();
    let mut presence = CountingPresence {
        verdict: crate::Presence::Confirmed,
        calls: 0,
    };
    let apdu = hid_apdu(&[0, CTAP_VERSION, 0, 0]).unwrap();
    for len in 0..=crate::consts::U2F_VERSION.len() {
        let mut out = [0xA5; 16];
        let generation = fs.write_gen();
        let result = process_u2f(
            &mut Ctx {
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 0,
                presence: &mut presence,
            },
            &apdu,
            &mut out[..len],
        );
        if len < crate::consts::U2F_VERSION.len() {
            assert_eq!(result, (Sw::EXEC_ERROR, 0));
            assert_eq!(out, [0xA5; 16]);
        } else {
            assert_eq!(result, (Sw::OK, len));
            assert_eq!(&out[..len], crate::consts::U2F_VERSION);
            assert!(out[len..].iter().all(|&byte| byte == 0xA5));
        }
        assert_eq!(presence.calls, 0);
        assert_eq!(fs.write_gen(), generation);
    }
}

#[test]
fn a_short_registration_output_returns_no_certificate_or_key_handle() {
    let mut fs = Fs::new(RamStorage::new());
    crate::tests::uv_optional(&mut fs);
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let initial_rng = rng.0;
    let raw = ext_apdu(CTAP_REGISTER, 0, &[CHAL, APP].concat());
    let apdu = hid_apdu(&raw).unwrap();
    let mut lengths = std::vec![1024];
    let mut expected = None;
    while let Some(len) = lengths.pop() {
        let mut rng = SeqRng(initial_rng);
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut out = [0xA5; 1024];
        let generation = fs.write_gen();
        let result = process_u2f(
            &mut Ctx {
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 0,
                presence: &mut presence,
            },
            &apdu,
            &mut out[..len],
        );
        if let Some(total) = expected {
            if len < total {
                assert_eq!(result, (Sw::EXEC_ERROR, 0), "capacity {len}");
                assert_eq!(out, [0xA5; 1024]);
            } else {
                assert_eq!(result, (Sw::OK, total));
                assert_eq!(out[0], U2F_REGISTER_ID);
                assert!(out[total..].iter().all(|&byte| byte == 0xA5));
            }
        } else {
            assert_eq!(result.0, Sw::OK);
            let total = result.1;
            expected = Some(total);
            lengths.extend([0, 1, 66, 1 + 65 + 1 + KEY_HANDLE_LEN, total - 1, total]);
        }
        assert_eq!(fs.write_gen(), generation);
    }
}

#[test]
fn a_short_authentication_output_spends_the_counter_without_emitting_a_signature() {
    let mut fs = Fs::new(RamStorage::new());
    crate::tests::uv_optional(&mut fs);
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let seed = crate::seed::load_keydev(&dev(), &mut fs).unwrap();
    let (handle, scalar) = derive_new(seed.expose(), &APP, &mut rng);
    let public = P256Key::from_scalar(scalar.expose()).unwrap().public_xy();
    let raw = ext_apdu(
        CTAP_AUTHENTICATE,
        U2F_AUTH_ENFORCE,
        &[
            CHAL.as_slice(),
            APP.as_slice(),
            &[KEY_HANDLE_LEN as u8],
            &handle,
        ]
        .concat(),
    );
    let apdu = hid_apdu(&raw).unwrap();
    let mut state = crate::FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    for len in [0, 1, 4, 5, 64, 1024] {
        let counter = crate::seed::global_sign_counter(&mut fs).unwrap();
        let mut out = [0xA5; 1024];
        let (sw, n) = process_u2f(
            &mut Ctx {
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 0,
                presence: &mut presence,
            },
            &apdu,
            &mut out[..len],
        );
        assert_eq!(
            crate::seed::global_sign_counter(&mut fs).unwrap(),
            counter + 1
        );
        if len < 1024 {
            assert_eq!((sw, n), (Sw::EXEC_ERROR, 0), "capacity {len}");
            assert_eq!(out, [0xA5; 1024]);
        } else {
            assert_eq!(sw, Sw::OK);
            let signature = Signature::from_der(&out[5..n]).unwrap();
            let signed = [APP.as_slice(), &out[..5], CHAL.as_slice()].concat();
            vkey(&public.0, &public.1)
                .verify(&signed, &signature)
                .unwrap();
            assert!(out[n..].iter().all(|&byte| byte == 0xA5));
        }
    }
}
