// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::consts::{EF_DEVICE_PIN, EF_PAUTHTOKEN};
use rsk_fs::cut::sweep_restarts;
use std::cell::RefCell;

#[path = "clientpin_policy_restart_tests.rs"]
mod policy;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Command {
    Set,
    Change,
    Token,
    Permissions,
    Persistent,
    Wrong,
}

fn boot(fs: &mut Fs<Cut>) {
    let _ = ensure_seed(&dev(), fs, &mut SeqRng(91));
}

#[test]
fn pin_commands_and_token_remint_survive_both_cut_stages_on_each_protocol() {
    for (proto, wire) in [(PinProto::One, 1), (PinProto::Two, 2)] {
        for command in [
            Command::Set,
            Command::Change,
            Command::Token,
            Command::Permissions,
            Command::Persistent,
            Command::Wrong,
        ] {
            let old_token = RefCell::new(None);
            let issued = RefCell::new(None);
            let provision = || {
                let (mut fs, medium, _) = setup_cut();
                if command != Command::Set {
                    store_local_pin(&dev(), &mut fs, PIN).unwrap();
                    ensure_seed(&dev(), &mut fs, &mut SeqRng(1)).unwrap();
                }
                *old_token.borrow_mut() = medium.value(EF_PAUTHTOKEN.get());
                if command == Command::Persistent {
                    crate::seed::clear_ppuat(&mut fs).unwrap();
                }
                fs.put(0xB000, b"another applet").unwrap();
                fs.meta_add(0xB000, b"metadata").unwrap();
                (fs, medium)
            };
            let execute = |fs: &mut Fs<Cut>| {
                let mut rng = SeqRng(71);
                let mut state = FidoState::new();
                let platform = key_agreement(fs, &mut rng, &mut state, proto, wire);
                let request = match command {
                    Command::Set => platform.set_pin_req(PIN),
                    Command::Change => platform.change_pin_req(PIN, NEW_PIN),
                    Command::Token => platform.get_token_req(PIN),
                    Command::Permissions => platform.get_token_perms_req(PIN, PERM_GA.into()),
                    Command::Persistent => platform.get_token_perms_req(PIN, PERM_PCMR.into()),
                    Command::Wrong => platform.get_token_req(WRONG_PIN),
                };
                let mut out = [0; 256];
                let result = run(fs, &mut rng, &mut state, &request, &mut out);
                *issued.borrow_mut() = result
                    .as_ref()
                    .ok()
                    .filter(|_| {
                        matches!(
                            command,
                            Command::Token | Command::Permissions | Command::Persistent
                        )
                    })
                    .map(|&n| rsk_secret::Secret::new(platform.decrypt_token(&out[..n])));
                result.is_ok()
                    || (command == Command::Wrong && result == Err(CtapError::PinInvalid))
            };
            let (mut reference, medium) = provision();
            let before = medium.value(EF_PIN);
            assert!(execute(&mut reference), "{command:?}, protocol {wire}");
            let after = medium.value(EF_PIN).unwrap();
            let repairs =
                sweep_restarts(provision, execute, boot, |fs, _, _, completed, medium| {
                    if let Some(pin) = medium.value(EF_PIN) {
                        assert_eq!(pin.len(), PIN_FILE_LEN);
                        assert!(
                            before.as_ref().is_some_and(|old| pin[1..] == old[1..])
                                || pin[1..] == after[1..]
                        );
                        assert!(pin[0] == MAX_PIN_RETRIES || pin[0] == MAX_PIN_RETRIES - 1);
                        if completed {
                            assert_eq!(pin, after);
                        }
                        if before.as_ref().is_none_or(|old| pin[1..] != old[1..]) {
                            assert_ne!(
                                medium.value(EF_PAUTHTOKEN.get()),
                                *old_token.borrow(),
                                "the changed PIN retained its revoked grant"
                            );
                        }
                    } else {
                        assert!(command == Command::Set && !completed);
                    }
                    if command == Command::Persistent && completed {
                        let stored = crate::seed::ensure_ppuat(&dev(), fs, &mut SeqRng(7)).unwrap();
                        assert_eq!(issued.borrow().as_ref().unwrap().expose(), stored.expose());
                    }
                    assert_eq!(
                        medium.value(0xB000).as_deref(),
                        Some(&b"another applet"[..])
                    );
                    let mut meta = [0; 8];
                    assert_eq!(fs.meta_find(0xB000, &mut meta), Some(8));
                    assert_eq!(&meta, b"metadata");
                    assert!(!FidoState::new().paut.in_use);
                });
            assert_eq!(
                repairs,
                matches!(
                    command,
                    Command::Set | Command::Change | Command::Persistent
                )
            );
        }
    }
}

#[test]
fn local_and_device_pin_updates_keep_seed_identity_and_independent_limiters() {
    for device_pin in [false, true] {
        for replace in [false, true] {
            let fid = if device_pin { EF_DEVICE_PIN } else { EF_PIN };
            let store = |fs: &mut Fs<Cut>, pin: &[u8]| {
                if device_pin {
                    store_device_pin(&dev(), fs, pin)
                } else {
                    store_local_pin(&dev(), fs, pin)
                }
            };
            let provision = || {
                let (mut fs, medium, _) = setup_cut();
                if replace {
                    store(&mut fs, PIN).unwrap();
                }
                let other = if device_pin { EF_PIN } else { EF_DEVICE_PIN };
                if device_pin {
                    store_local_pin(&dev(), &mut fs, PIN).unwrap();
                } else {
                    store_device_pin(&dev(), &mut fs, DEVICE_PIN).unwrap();
                }
                ensure_seed(&dev(), &mut fs, &mut SeqRng(1)).unwrap();
                fs.put(0xB000, b"another applet").unwrap();
                assert!(fs.has_data(other));
                (fs, medium)
            };
            let (_, baseline) = provision();
            let before = baseline.value(fid);
            let seed = baseline.value(EF_KEY_DEV.get());
            let other = if device_pin { EF_PIN } else { EF_DEVICE_PIN };
            let other_pin = baseline.value(other);
            let token = baseline.value(EF_PAUTHTOKEN.get());
            let mut reference = provision().0;
            store(&mut reference, NEW_PIN).unwrap();
            let mut record = [0; PIN_FILE_LEN];
            reference.read(fid, &mut record).unwrap();
            let repairs = sweep_restarts(
                provision,
                |fs| store(fs, NEW_PIN).is_ok(),
                boot,
                |_fs, _, _, completed, medium| {
                    let actual = medium.value(fid);
                    assert!(actual == before || actual.as_deref() == Some(&record[..]));
                    if completed {
                        assert_eq!(actual.as_deref(), Some(&record[..]));
                    }
                    assert_eq!(medium.value(EF_KEY_DEV.get()), seed);
                    assert_eq!(medium.value(other), other_pin);
                    if device_pin {
                        assert_eq!(medium.value(EF_PAUTHTOKEN.get()), token);
                    }
                    assert_eq!(
                        medium.value(0xB000).as_deref(),
                        Some(&b"another applet"[..])
                    );
                },
            );
            assert!(!repairs || !device_pin);
        }
    }
}

#[test]
fn current_and_pre_otp_pin_verifiers_keep_retry_depletion_over_two_boots() {
    let otp = [0x55; 32];
    let current = Device {
        otp_key: Some(&otp),
        ..dev()
    };
    for device_pin in [false, true] {
        for old_root in [false, true] {
            for correct in [false, true] {
                let fid = if device_pin { EF_DEVICE_PIN } else { EF_PIN };
                let provision = || {
                    let (mut fs, medium, _) = setup_cut();
                    let arm = if old_root { dev() } else { current };
                    if device_pin {
                        store_device_pin(&arm, &mut fs, PIN).unwrap();
                    } else {
                        store_local_pin(&arm, &mut fs, PIN).unwrap();
                    }
                    fs.put(0xB000, b"another applet").unwrap();
                    (fs, medium)
                };
                let (_, original) = provision();
                let before = original.value(fid).unwrap();
                let execute = |fs: &mut Fs<Cut>| {
                    let pin = if correct { PIN } else { WRONG_PIN };
                    let result = if device_pin {
                        spend_and_verify_device_pin(&current, fs, pin)
                    } else {
                        spend_and_verify_local_pin(&current, fs, pin)
                    };
                    if correct {
                        matches!(result, LocalPin::Ok)
                    } else {
                        matches!(result, LocalPin::Wrong { .. })
                    }
                };
                assert!(!sweep_restarts(
                    provision,
                    execute,
                    |_| {},
                    |fs, _, _, completed, medium| {
                        let actual = medium.value(fid).unwrap();
                        assert_eq!(actual.len(), PIN_FILE_LEN);
                        assert!(actual[0] == MAX_PIN_RETRIES || actual[0] == MAX_PIN_RETRIES - 1);
                        let mut hash = rsk_secret::Secret::new(sha256(PIN));
                        let new = current.pin_derive_verifier(&hash.expose()[..16]);
                        hash.wipe();
                        assert!(actual[3..] == before[3..] || actual[3..] == *new.expose());
                        if completed {
                            assert_eq!(
                                actual[0],
                                if correct {
                                    MAX_PIN_RETRIES
                                } else {
                                    MAX_PIN_RETRIES - 1
                                }
                            );
                            if correct {
                                assert_eq!(&actual[3..], new.expose());
                            }
                        }
                        assert_eq!(
                            medium.value(0xB000).as_deref(),
                            Some(&b"another applet"[..])
                        );
                        assert!(fs.has_data(fid));
                    }
                ));
            }
        }
    }
}
