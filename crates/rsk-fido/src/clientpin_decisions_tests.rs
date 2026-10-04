// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn missing_pin_authorization_preserves_the_pin_and_session() {
    for (proto, wire) in [(PinProto::One, 1), (PinProto::Two, 2)] {
        for (subcommand, pin_set) in [(3, false), (3, true), (4, true)] {
            let (mut fs, mut rng) = setup();
            if pin_set {
                store_local_pin(&dev(), &mut fs, PIN).unwrap();
            }
            let mut state = FidoState::new();
            let plat = key_agreement(&mut fs, &mut rng, &mut state, proto, wire);
            let mut out = [0u8; 256];
            if pin_set {
                run(
                    &mut fs,
                    &mut rng,
                    &mut state,
                    &plat.get_token_req(PIN),
                    &mut out,
                )
                .unwrap();
            }
            let token = state.paut.token;
            let in_use = state.paut.in_use;
            let ephemeral = state.ephemeral_public();
            let mut before = [0u8; PIN_FILE_LEN];
            let length = fs.read(EF_PIN, &mut before);
            let mut padded = [0u8; PADDED_PIN_LEN];
            padded[..NEW_PIN.len()].copy_from_slice(NEW_PIN);
            let new_pin_enc = plat.enc(&padded);
            let pin_hash_enc = plat.enc(&sha256(PIN)[..16]);
            let mut fields = vec![
                (1, V::U(wire)),
                (2, V::U(subcommand)),
                (3, V::Cose(&plat.x, &plat.y)),
                (5, V::B(&new_pin_enc)),
            ];
            if subcommand == 4 {
                fields.push((6, V::B(&pin_hash_enc)));
            }
            out.fill(0x55);
            assert_eq!(
                run(&mut fs, &mut rng, &mut state, &build(&fields), &mut out),
                Err(CtapError::MissingParameter),
                "protocol {wire}, subcommand {subcommand}, PIN set {pin_set}"
            );
            let mut after = [0u8; PIN_FILE_LEN];
            assert_eq!(fs.read(EF_PIN, &mut after), length);
            assert_eq!(after, before, "an unauthenticated request changed the PIN");
            assert_eq!(state.paut.token, token);
            assert_eq!(state.paut.in_use, in_use);
            assert_eq!(state.ephemeral_public(), ephemeral);
            assert_eq!(out, [0x55; 256]);
        }
    }
}

#[test]
fn legacy_token_permissions_are_refused_before_spending_a_retry() {
    for (proto, wire) in [(PinProto::One, 1), (PinProto::Two, 2)] {
        let (mut fs, mut rng, mut state, _) = setup_with_pin(PIN);
        let plat = key_agreement(&mut fs, &mut rng, &mut state, proto, wire);
        let mut out = [0u8; 256];
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_token_req(PIN),
            &mut out,
        )
        .unwrap();
        let token = state.paut.token;
        let permissions = state.paut.permissions;
        let pin_hash_enc = plat.enc(&sha256(PIN)[..16]);
        for requested in [u64::from(PERM_MC), 0x100, u64::from(u32::MAX)] {
            let req = build(&[
                (1, V::U(wire)),
                (2, V::U(5)),
                (3, V::Cose(&plat.x, &plat.y)),
                (6, V::B(&pin_hash_enc)),
                (9, V::U(requested)),
            ]);
            out.fill(0x55);
            assert_eq!(
                run(&mut fs, &mut rng, &mut state, &req, &mut out),
                Err(CtapError::InvalidParameter),
                "protocol {wire}, requested permissions {requested:#x}"
            );
            assert_eq!(ef_pin_retries(&mut fs), MAX_PIN_RETRIES);
            assert!(state.paut.in_use);
            assert_eq!(
                state.paut.token, token,
                "a refused request replaced the token"
            );
            assert_eq!(state.paut.permissions, permissions);
            assert_eq!(out, [0x55; 256]);
        }
    }
}

#[test]
fn skipped_or_repeated_mandatory_keys_do_not_touch_the_pin() {
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
    let mut out = [0u8; 256];
    for (fields, want) in [
        (vec![(2, V::U(1))], CtapError::MissingParameter),
        (
            vec![(1, V::U(plat.wire)), (3, V::Cose(&plat.x, &plat.y))],
            CtapError::MissingParameter,
        ),
        (
            vec![(1, V::U(plat.wire)), (2, V::U(1)), (2, V::U(1))],
            CtapError::InvalidCbor,
        ),
    ] {
        out.fill(0x55);
        assert_eq!(
            run(&mut fs, &mut rng, &mut state, &build(&fields), &mut out),
            Err(want)
        );
        assert_eq!(ef_pin_retries(&mut fs), MAX_PIN_RETRIES);
        assert!(!state.paut.in_use);
        assert_eq!(out, [0x55; 256]);
    }
    let req = build(&[(1, V::U(plat.wire)), (2, V::U(1))]);
    let n = run(&mut fs, &mut rng, &mut state, &req, &mut out).unwrap();
    assert_eq!(&out[..n], &[0xA1, 3, MAX_PIN_RETRIES]);
}

#[test]
fn pin_complexity_refuses_invalid_text_and_an_unrepresentable_length() {
    for pin in [&[][..], b"A", &[0xFF], &[b'A'; PADDED_PIN_LEN + 1]] {
        assert!(pin_is_trivial(pin));
    }
    assert!(!pin_is_trivial(PIN));
}

#[test]
fn local_pin_verification_blocks_when_either_counter_write_fails() {
    for fid in [EF_PIN, EF_DEVICE_PIN] {
        for budget in [0, 1] {
            let (storage, medium) = Cut::new();
            let mut fs = Fs::new(storage);
            let mut rng = SeqRng(1);
            ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
            let pin = if fid == EF_PIN { PIN } else { DEVICE_PIN };
            if fid == EF_PIN {
                store_local_pin(&dev(), &mut fs, pin).unwrap();
            } else {
                store_device_pin(&dev(), &mut fs, pin).unwrap();
            }
            let before = medium.value(fid).unwrap();
            medium.arm(budget);
            let result = if fid == EF_PIN {
                spend_and_verify_local_pin(&dev(), &mut fs, pin)
            } else {
                spend_and_verify_device_pin(&dev(), &mut fs, pin)
            };
            assert!(
                matches!(result, LocalPin::Blocked),
                "fid {fid:#06x}, write budget {budget}: a failed counter write authorized the PIN"
            );
            let after = medium.value(fid).unwrap();
            assert_eq!(after[0], MAX_PIN_RETRIES - u8::try_from(budget).unwrap());
            assert_eq!(&after[1..], &before[1..]);
            medium.arm(u32::MAX);
            let result = if fid == EF_PIN {
                spend_and_verify_local_pin(&dev(), &mut fs, pin)
            } else {
                spend_and_verify_device_pin(&dev(), &mut fs, pin)
            };
            assert!(matches!(result, LocalPin::Ok));
            assert_eq!(medium.value(fid).unwrap()[0], MAX_PIN_RETRIES);
        }
    }
}
