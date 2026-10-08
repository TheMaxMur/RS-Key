// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::cut::sweep_restarts;
use rsk_fs::storage::faults::Cut;
use std::cell::RefCell;

#[test]
fn a_u2f_handle_asserted_over_ctap2_keeps_its_global_counter_after_two_boots() {
    let identity = RefCell::new(None);
    let response = RefCell::new(Vec::new());
    assert!(!sweep_restarts(
        || {
            let (storage, medium) = Cut::new();
            let mut fs = Fs::new(storage);
            fs.scan();
            crate::tests::uv_optional(&mut fs);
            let mut rng = SeqRng(1);
            ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
            let seed = crate::seed::load_keydev(&dev(), &mut fs).unwrap();
            let (handle, scalar) =
                crate::keyderiv::derive_new(seed.expose(), &sha256(b"example.com"), &mut rng);
            let point = rsk_crypto::pinproto::public_xy(scalar.expose()).unwrap();
            *identity.borrow_mut() = Some((handle, point));
            fs.put_counter(crate::consts::EF_COUNTER, &73u32.to_le_bytes())
                .unwrap();
            fs.put(0xB000, b"another applet").unwrap();
            (fs, medium)
        },
        |fs| {
            let mut rng = SeqRng(91);
            let mut state = crate::FidoState::new();
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                dev: dev(),
                fs,
                rng: &mut rng,
                state: &mut state,
                presence: &mut presence,
                now_ms: 10,
            };
            let mut out = [0; 1024];
            let result = get_assertion(
                &mut ctx,
                &ga_request(Some(&identity.borrow().as_ref().unwrap().0)),
                &mut out,
            );
            *response.borrow_mut() = result
                .as_ref()
                .ok()
                .map(|&n| out[..n].to_vec())
                .unwrap_or_default();
            result.is_ok()
        },
        |fs| {
            let _ = ensure_seed(&dev(), fs, &mut SeqRng(7));
        },
        |fs, _, _, completed, medium| {
            let count = crate::seed::global_sign_counter(fs).unwrap();
            assert!(count == 73 || count == 74);
            if completed {
                assert_eq!(count, 74);
                assert_eq!(assertion_sign_count(&response.borrow()), 73);
                let key = identity.borrow();
                let (_, (x, y)) = key.as_ref().unwrap();
                verify_assertion(&response.borrow(), x, y);
            } else {
                assert!(response.borrow().is_empty());
            }
            assert_eq!(
                medium.value(0xB000).as_deref(),
                Some(&b"another applet"[..])
            );
        }
    ));
}

#[cfg(feature = "largeblob-ext")]
#[test]
fn assertion_blob_writes_and_the_signature_counter_keep_their_prefix_after_two_boots() {
    for replace in [false, true] {
        let identity = RefCell::new(None);
        let response = RefCell::new(Vec::new());
        let provision = || {
            let (storage, medium) = Cut::new();
            let mut fs = Fs::new(storage);
            fs.scan();
            crate::tests::uv_optional(&mut fs);
            let mut rng = SeqRng(1);
            ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
            *identity.borrow_mut() =
                Some(parse_mc(&run_make(&mut fs, &mut rng, &mc_request(true))));
            crate::seed::set_cred_sign_counter(&mut fs, 0, 73).unwrap();
            if replace {
                let seed = crate::seed::load_keydev(&dev(), &mut fs).unwrap();
                let id: [u8; crate::credential::CRED_RESIDENT_LEN] = identity
                    .borrow()
                    .as_ref()
                    .unwrap()
                    .0
                    .as_slice()
                    .try_into()
                    .unwrap();
                let mut state = crate::FidoState::new();
                let mut presence = crate::AlwaysConfirm;
                let mut ctx = Ctx {
                    dev: dev(),
                    fs: &mut fs,
                    rng: &mut rng,
                    state: &mut state,
                    presence: &mut presence,
                    now_ms: 10,
                };
                assert!(crate::largeblobext::write(
                    &mut ctx,
                    seed.expose(),
                    &id,
                    0,
                    b"before",
                    93
                ));
            }
            fs.put(0xB000, b"another applet").unwrap();
            (fs, medium)
        };
        let execute = |fs: &mut Fs<Cut>| {
            let mut raw = [0; 512];
            let mut e = Encoder::new(Cursor::new(raw.as_mut_slice()));
            e.map(4)
                .unwrap()
                .u8(1)
                .unwrap()
                .str("example.com")
                .unwrap()
                .u8(2)
                .unwrap()
                .bytes(&CDH)
                .unwrap();
            e.u8(3)
                .unwrap()
                .array(1)
                .unwrap()
                .map(2)
                .unwrap()
                .str("type")
                .unwrap()
                .str("public-key")
                .unwrap()
                .str("id")
                .unwrap()
                .bytes(&identity.borrow().as_ref().unwrap().0)
                .unwrap();
            e.u8(4)
                .unwrap()
                .map(1)
                .unwrap()
                .str("largeBlob")
                .unwrap()
                .map(2)
                .unwrap()
                .str("write")
                .unwrap()
                .bytes(b"after")
                .unwrap()
                .str("originalSize")
                .unwrap()
                .u32(93)
                .unwrap();
            let n = e.writer().position();
            let mut rng = SeqRng(91);
            let mut state = crate::FidoState::new();
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                dev: dev(),
                fs,
                rng: &mut rng,
                state: &mut state,
                presence: &mut presence,
                now_ms: 10,
            };
            let mut out = [0; 1024];
            let result = get_assertion(&mut ctx, &raw[..n], &mut out);
            *response.borrow_mut() = result
                .as_ref()
                .ok()
                .map(|&n| out[..n].to_vec())
                .unwrap_or_default();
            result.is_ok()
        };
        let (_, baseline) = provision();
        let before = baseline.value(crate::consts::EF_CRED_BLOB);
        let (mut reference, medium) = provision();
        assert!(execute(&mut reference));
        let after = medium.value(crate::consts::EF_CRED_BLOB);
        assert_ne!(before, after);
        assert!(!sweep_restarts(
            provision,
            execute,
            |fs| {
                let _ = ensure_seed(&dev(), fs, &mut SeqRng(7));
            },
            |fs, _, _, completed, medium| {
                let actual = medium.value(crate::consts::EF_CRED_BLOB);
                assert!(actual == before || actual == after);
                let counter = crate::seed::report_sign_counter(fs, 0).unwrap();
                assert!(counter == 73 || counter == 74);
                if completed {
                    assert_eq!(actual, after);
                    assert_eq!(counter, 74);
                    let key = identity.borrow();
                    let (_, x, y) = key.as_ref().unwrap();
                    verify_assertion(&response.borrow(), x, y);
                    assert_eq!(assertion_sign_count(&response.borrow()), 73);
                    let out = response.borrow();
                    let mut d = Decoder::new(&out);
                    let fields = d.map().unwrap().unwrap();
                    let mut written = false;
                    for _ in 0..fields {
                        if d.u8().unwrap() == 8 {
                            d.map().unwrap();
                            assert_eq!(d.str().unwrap(), "largeBlob");
                            d.map().unwrap();
                            assert_eq!(d.str().unwrap(), "written");
                            written = d.bool().unwrap();
                        } else {
                            d.skip().unwrap();
                        }
                    }
                    assert!(written);
                }
                assert_eq!(
                    medium.value(0xB000).as_deref(),
                    Some(&b"another applet"[..])
                );
            }
        ));
    }
}

#[test]
fn assertion_and_next_assertion_cuts_preserve_each_counter_and_discard_the_walk_on_boot() {
    for next in [false, true] {
        let session = RefCell::new(crate::FidoState::new());
        let response = RefCell::new(Vec::new());
        let points = RefCell::new(Vec::new());
        let counters = std::cell::Cell::new([0; 2]);
        let provision = || {
            let (storage, medium) = Cut::new();
            let mut fs = Fs::new(storage);
            fs.scan();
            crate::tests::uv_optional(&mut fs);
            let mut rng = SeqRng(1);
            ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
            points.borrow_mut().clear();
            for user in [[9, 8, 7, 6], [1, 1, 1, 1]] {
                let made = run_make(&mut fs, &mut rng, &mc_request_user(&user));
                points.borrow_mut().push(parse_mc(&made));
            }
            crate::seed::set_cred_sign_counter(&mut fs, 0, 73).unwrap();
            crate::seed::set_cred_sign_counter(&mut fs, 1, 59).unwrap();
            *session.borrow_mut() = crate::FidoState::new();
            if next {
                let mut presence = crate::AlwaysConfirm;
                let mut state = session.borrow_mut();
                let mut ctx = Ctx {
                    dev: dev(),
                    fs: &mut fs,
                    rng: &mut rng,
                    state: &mut state,
                    presence: &mut presence,
                    now_ms: 30,
                };
                get_assertion(&mut ctx, &ga_request(None), &mut [0; 1024]).unwrap();
            }
            counters.set([0, 1].map(|slot| {
                crate::seed::cred_sign_counter(&mut fs, slot)
                    .unwrap()
                    .unwrap()
            }));
            (fs, medium)
        };
        assert!(!sweep_restarts(
            provision,
            |fs| {
                let mut rng = SeqRng(91);
                let mut presence = crate::AlwaysConfirm;
                let mut state = session.borrow_mut();
                let mut ctx = Ctx {
                    dev: dev(),
                    fs,
                    rng: &mut rng,
                    state: &mut state,
                    presence: &mut presence,
                    now_ms: 40,
                };
                let mut out = [0; 1024];
                let answer = if next {
                    get_next_assertion(&mut ctx, &mut out)
                } else {
                    get_assertion(&mut ctx, &ga_request(None), &mut out)
                };
                *response.borrow_mut() = answer
                    .as_ref()
                    .ok()
                    .map(|&n| out[..n].to_vec())
                    .unwrap_or_default();
                answer.is_ok()
            },
            |fs| {
                let _ = ensure_seed(&dev(), fs, &mut SeqRng(7));
            },
            |fs, _, _, completed, _| {
                let now =
                    [0, 1].map(|slot| crate::seed::cred_sign_counter(fs, slot).unwrap().unwrap());
                let before = counters.get();
                assert!(
                    [
                        before,
                        [before[0] + 1, before[1]],
                        [before[0], before[1] + 1]
                    ]
                    .contains(&now)
                );
                if completed {
                    let out = response.borrow();
                    let count = assertion_sign_count(&out);
                    let mut d = Decoder::new(&out);
                    d.map().unwrap();
                    d.u8().unwrap();
                    d.map().unwrap();
                    d.str().unwrap();
                    let id = d.bytes().unwrap();
                    let keys = points.borrow();
                    let (index, (_, x, y)) = keys
                        .iter()
                        .enumerate()
                        .find(|(_, (rid, _, _))| rid == id)
                        .unwrap();
                    verify_assertion(&out, x, y);
                    assert_eq!(count, before[index]);
                    assert_eq!(now[index], count + 1);
                    assert_eq!(now[1 - index], before[1 - index]);
                }
                let mut state = crate::FidoState::new();
                let mut rng = SeqRng(7);
                let mut presence = crate::AlwaysConfirm;
                let mut ctx = Ctx {
                    dev: dev(),
                    fs,
                    rng: &mut rng,
                    state: &mut state,
                    presence: &mut presence,
                    now_ms: 50,
                };
                assert_eq!(
                    get_next_assertion(&mut ctx, &mut [0; 1024]),
                    Err(CtapError::NotAllowed)
                );
                assert_eq!(
                    [0, 1].map(|slot| crate::seed::cred_sign_counter(ctx.fs, slot)
                        .unwrap()
                        .unwrap()),
                    now
                );
            }
        ));
    }
}
