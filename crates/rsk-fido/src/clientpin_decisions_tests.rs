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

#[test]
fn missing_pin_hash_preserves_the_existing_token_and_retry_budget() {
    for (proto, wire) in [(PinProto::One, 1), (PinProto::Two, 2)] {
        for subcommand in [4, CP_GET_PIN_TOKEN, CP_GET_PIN_UV_TOKEN_USING_PIN] {
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
            let ephemeral = state.ephemeral_public();
            let mut before = [0u8; PIN_FILE_LEN];
            assert_eq!(fs.read(EF_PIN, &mut before), Some(PIN_FILE_LEN));
            let mut padded = [0u8; PADDED_PIN_LEN];
            padded[..NEW_PIN.len()].copy_from_slice(NEW_PIN);
            let encrypted = plat.enc(&padded);
            let auth = plat.mac(&encrypted);
            let mut fields = vec![
                (1, V::U(wire)),
                (2, V::U(subcommand)),
                (3, V::Cose(&plat.x, &plat.y)),
            ];
            if subcommand == 4 {
                fields.extend([(4, V::B(&auth)), (5, V::B(&encrypted))]);
            }
            if subcommand == CP_GET_PIN_UV_TOKEN_USING_PIN {
                fields.push((9, V::U(u64::from(PERM_MC))));
            }
            out.fill(0x55);
            assert_eq!(
                run(&mut fs, &mut rng, &mut state, &build(&fields), &mut out),
                Err(CtapError::MissingParameter),
                "protocol {wire}, subcommand {subcommand}"
            );
            let mut after = [0u8; PIN_FILE_LEN];
            assert_eq!(fs.read(EF_PIN, &mut after), Some(PIN_FILE_LEN));
            assert_eq!(after, before);
            assert!(state.paut.in_use);
            assert_eq!(state.paut.token, token);
            assert_eq!(state.ephemeral_public(), ephemeral);
            assert_eq!(out, [0x55; 256]);
        }
    }
}

#[test]
fn configured_complexity_checks_each_family_on_both_pin_protocols_and_the_pad() {
    for (weak, replacement) in [
        (&b"AbCAbC"[..], &b"AbCAbD"[..]),
        (b"345678", b"345679"),
        (b"876543", b"876542"),
        (b"aababb", b"aababc"),
        (b"159753", b"159754"),
    ] {
        for (proto, wire) in [(PinProto::One, 1), (PinProto::Two, 2)] {
            let (mut fs, mut rng) = setup();
            let policy = [MIN_PIN_LENGTH, crate::pinpolicy::COMPLEXITY];
            fs.put(EF_MINPINLEN, &policy).unwrap();
            let mut state = FidoState::new();
            let plat = key_agreement(&mut fs, &mut rng, &mut state, proto, wire);
            let mut out = [0x55; 256];
            assert_eq!(
                run(
                    &mut fs,
                    &mut rng,
                    &mut state,
                    &plat.set_pin_req(weak),
                    &mut out
                ),
                Err(CtapError::PinPolicyViolation),
                "protocol {wire}, weak PIN {weak:?}"
            );
            assert!(!fs.has_data(EF_PIN));
            assert_eq!(out, [0x55; 256]);
            assert_eq!(
                store_local_pin(&dev(), &mut fs, weak),
                Err(SetPinError::TooWeak)
            );
            assert!(!fs.has_data(EF_PIN));
            run(
                &mut fs,
                &mut rng,
                &mut state,
                &plat.set_pin_req(replacement),
                &mut out,
            )
            .unwrap();
            store_local_pin(&dev(), &mut fs, replacement).unwrap();
            assert!(matches!(
                spend_and_verify_local_pin(&dev(), &mut fs, replacement),
                LocalPin::Ok
            ));
            let mut after = [0u8; 2];
            assert_eq!(fs.read(EF_MINPINLEN, &mut after), Some(policy.len()));
            assert_eq!(after, policy);
            assert!(!state.paut.in_use);
        }
    }
}

#[test]
fn an_absent_or_malformed_verifier_cannot_establish_a_different_pin() {
    for length in [None, Some(PIN_FILE_LEN - 1), Some(PIN_FILE_LEN + 1)] {
        let (mut fs, mut rng) = setup();
        let mut state = FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        if let Some(n) = length {
            fs.put(EF_PIN, &vec![0; n]).unwrap();
        }
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        assert_eq!(
            pin_verifier_matches(&mut ctx, NEW_PIN),
            Err(CtapError::Other)
        );
        store_local_pin(&dev(), ctx.fs, PIN).unwrap();
        assert_eq!(pin_verifier_matches(&mut ctx, PIN), Ok(true));
        assert_eq!(pin_verifier_matches(&mut ctx, NEW_PIN), Ok(false));
    }
}

#[test]
fn a_legacy_minimum_without_flags_allows_tokens_and_keeps_its_layout() {
    for (proto, wire) in [(PinProto::One, 1), (PinProto::Two, 2)] {
        let (mut fs, mut rng, mut state, _) = setup_with_pin(PIN);
        fs.put(EF_MINPINLEN, &[MIN_PIN_LENGTH]).unwrap();
        let plat = key_agreement(&mut fs, &mut rng, &mut state, proto, wire);
        let mut out = [0u8; 256];
        let n = run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_token_req(PIN),
            &mut out,
        )
        .unwrap();
        assert_eq!(plat.decrypt_token(&out[..n]), state.paut.token);
        assert!(state.paut.in_use);
        assert_eq!(ef_pin_retries(&mut fs), MAX_PIN_RETRIES);
        let mut policy = [0x55; 2];
        assert_eq!(fs.read(EF_MINPINLEN, &mut policy), Some(1));
        assert_eq!(policy, [MIN_PIN_LENGTH, 0x55]);
    }
}

#[test]
fn local_verification_refuses_failed_legacy_seed_migration_and_recovers() {
    for corrupt in [false, true] {
        let (mut fs, medium, _) = setup_cut();
        store_local_pin(&dev(), &mut fs, PIN).unwrap();
        let mut seed = load_keydev(&dev(), &mut fs).unwrap();
        let hash = sha256(PIN);
        crate::seed::wrap_keydev_legacy(&dev(), &mut fs, seed.expose(), &hash[..16]);
        let original = medium.value(EF_KEY_DEV.get()).unwrap();
        if corrupt {
            let mut bad = original.clone();
            *bad.last_mut().unwrap() ^= 0x80;
            fs.put(EF_KEY_DEV.get(), &bad).unwrap();
        } else {
            medium.arm(1);
        }
        let before = medium.value(EF_KEY_DEV.get()).unwrap();
        assert!(load_keydev(&dev(), &mut fs).is_none());
        assert!(
            matches!(
                spend_and_verify_local_pin(&dev(), &mut fs, PIN),
                LocalPin::Blocked
            ),
            "failed migration authorized the local PIN, corrupt seed {corrupt}"
        );
        assert_eq!(medium.value(EF_KEY_DEV.get()).unwrap(), before);
        assert_eq!(medium.value(EF_PIN).unwrap()[0], MAX_PIN_RETRIES - 1);
        assert!(load_keydev(&dev(), &mut fs).is_none());
        medium.arm(u32::MAX);
        if corrupt {
            fs.put(EF_KEY_DEV.get(), &original).unwrap();
        }
        let mut fs = Fs::new(fs.into_storage());
        fs.scan();
        assert!(matches!(
            spend_and_verify_local_pin(&dev(), &mut fs, PIN),
            LocalPin::Ok
        ));
        let mut recovered = load_keydev(&dev(), &mut fs).unwrap();
        assert_eq!(recovered.expose(), seed.expose());
        assert_eq!(medium.value(EF_PIN).unwrap()[0], MAX_PIN_RETRIES);
        seed.wipe();
        recovered.wipe();
    }
}
