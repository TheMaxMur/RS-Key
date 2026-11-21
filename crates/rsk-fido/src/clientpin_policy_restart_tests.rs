// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn a_forced_pin_change_never_clears_its_flag_before_the_new_verifier_commits() {
    for local in [false, true] {
        let mut policy = vec![MIN_PIN_LENGTH, crate::pinpolicy::FORCE_CHANGE];
        policy.extend([0x55; 32]);
        let provision = || {
            let (mut fs, medium, _) = setup_cut();
            store_local_pin(&dev(), &mut fs, PIN).unwrap();
            ensure_seed(&dev(), &mut fs, &mut SeqRng(1)).unwrap();
            fs.put(EF_MINPINLEN, &policy).unwrap();
            fs.put(0xB000, b"another applet").unwrap();
            (fs, medium)
        };
        let command = |fs: &mut Fs<Cut>| {
            if local {
                store_local_pin(&dev(), fs, NEW_PIN).is_ok()
            } else {
                let mut rng = SeqRng(71);
                let mut state = FidoState::new();
                let platform = key_agreement(fs, &mut rng, &mut state, PinProto::Two, 2);
                run(
                    fs,
                    &mut rng,
                    &mut state,
                    &platform.change_pin_req(PIN, NEW_PIN),
                    &mut [0; 256],
                )
                .is_ok()
            }
        };
        let (_, baseline) = provision();
        let before = baseline.value(EF_PIN).unwrap();
        let (mut reference, medium) = provision();
        assert!(command(&mut reference));
        let after = medium.value(EF_PIN).unwrap();
        let cleared = medium.value(EF_MINPINLEN).unwrap();
        assert!(sweep_restarts(
            provision,
            command,
            boot,
            |fs, _, _, completed, medium| {
                let actual = medium.value(EF_PIN).unwrap();
                let settings = medium.value(EF_MINPINLEN).unwrap();
                assert!(settings == policy || settings == cleared);
                assert!(actual[1..] == before[1..] || actual[1..] == after[1..]);
                if settings == cleared {
                    assert_eq!(&actual[1..], &after[1..]);
                }
                if completed {
                    assert_eq!(&actual[1..], &after[1..]);
                    if !local {
                        assert_eq!(settings, cleared);
                    }
                }
                assert_eq!(settings[0], MIN_PIN_LENGTH);
                assert_eq!(&settings[2..], &[0x55; 32]);
                assert!(fs.has_data(EF_PAUTHTOKEN.get()));
                assert_eq!(
                    medium.value(0xB000).as_deref(),
                    Some(&b"another applet"[..])
                );
            }
        ));
    }
}

#[test]
fn builtin_uv_retry_and_persistent_token_writes_survive_two_boots() {
    for (proto, wire) in [(PinProto::One, 1), (PinProto::Two, 2)] {
        for (correct, persistent) in [(false, false), (true, false), (true, true)] {
            let issued = RefCell::new(None);
            let provision = || {
                let (mut fs, medium, _) = setup_cut();
                store_local_pin(&dev(), &mut fs, PIN).unwrap();
                ensure_seed(&dev(), &mut fs, &mut SeqRng(1)).unwrap();
                let mut record = medium.value(EF_PIN).unwrap();
                record[0] = MAX_PIN_RETRIES - 1;
                fs.put(EF_PIN, &record).unwrap();
                if persistent {
                    crate::seed::clear_ppuat(&mut fs).unwrap();
                }
                fs.put(0xB000, b"another applet").unwrap();
                (fs, medium)
            };
            let command = |fs: &mut Fs<Cut>| {
                let mut rng = SeqRng(71);
                let mut state = FidoState::new();
                let platform = key_agreement(fs, &mut rng, &mut state, proto, wire);
                let mut presence = UvPad::typing(if correct { PIN } else { WRONG_PIN });
                let mut ctx = Ctx {
                    dev: dev(),
                    fs,
                    state: &mut state,
                    rng: &mut rng,
                    presence: &mut presence,
                    now_ms: 10,
                };
                let mut out = [0; 256];
                let result = client_pin(
                    &mut ctx,
                    &platform.get_uv_token_req(if persistent {
                        PERM_PCMR.into()
                    } else {
                        PERM_GA.into()
                    }),
                    &mut out,
                );
                *issued.borrow_mut() = result
                    .as_ref()
                    .ok()
                    .map(|&n| rsk_secret::Secret::new(platform.decrypt_token(&out[..n])));
                if correct {
                    result.is_ok()
                } else {
                    result == Err(CtapError::UvInvalid)
                }
            };
            let repairs =
                sweep_restarts(provision, command, boot, |fs, _, _, completed, medium| {
                    let record = medium.value(EF_PIN).unwrap();
                    let maximum = if correct {
                        MAX_PIN_RETRIES
                    } else {
                        MAX_PIN_RETRIES - 1
                    };
                    assert!((MAX_PIN_RETRIES - 2..=maximum).contains(&record[0]));
                    if completed {
                        assert_eq!(
                            record[0],
                            if correct {
                                MAX_PIN_RETRIES
                            } else {
                                MAX_PIN_RETRIES - 2
                            }
                        );
                        if persistent {
                            assert_eq!(
                                crate::seed::load_ppuat(&dev(), fs).unwrap().expose(),
                                issued.borrow().as_ref().unwrap().expose()
                            );
                        }
                    }
                    assert!(!FidoState::new().paut.in_use);
                    assert_eq!(
                        medium.value(0xB000).as_deref(),
                        Some(&b"another applet"[..])
                    );
                });
            assert_eq!(repairs, persistent);
        }
    }
}
