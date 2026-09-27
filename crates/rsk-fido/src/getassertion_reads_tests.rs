// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::probe::{Traced, sweep};

/// What the command needs beside the store, rebuilt per run.
struct Session {
    rng: SeqRng,
    state: crate::FidoState,
    req: std::vec::Vec<u8>,
}

fn seeded(fs: &mut Fs<Traced>) -> SeqRng {
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), fs, &mut rng).unwrap();
    rng
}

fn assert(fs: &mut Fs<Traced>, s: &mut Session) -> Option<std::vec::Vec<u8>> {
    let mut out = [0u8; 1024];
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs,
        rng: &mut s.rng,
        state: &mut s.state,
        now_ms: 20,
    };
    let n = get_assertion(&mut ctx, &s.req, &mut out).ok()?;
    out.get(..n).map(<[u8]>::to_vec)
}

/// A non-resident credential signs with no counter (signCount 0), so a faulted read
/// can only fail the assertion or give the clean one, signature included.
#[test]
fn a_faulted_read_fails_a_non_resident_assertion_or_answers_it_as_clean() {
    sweep(
        |fs| {
            let mut rng = seeded(fs);
            let id = register_non_resident(fs, &mut rng);
            Session {
                rng,
                state: crate::FidoState::new(),
                req: ga_request(Some(&id)),
            }
        },
        assert,
        &[],
    );
}

/// A discoverable credential, found by walking the store, with its own counter.
#[test]
fn a_faulted_read_fails_a_discoverable_assertion_or_advances_its_counter() {
    sweep(
        |fs| {
            let mut rng = seeded(fs);
            let mut out = [0u8; 1024];
            let mut state = crate::FidoState::new();
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 10,
            };
            make_credential(&mut ctx, &mc_request(true), &mut out).unwrap();
            Session {
                rng,
                state: crate::FidoState::new(),
                req: ga_request(None),
            }
        },
        assert,
        &[],
    );
}

#[test]
fn a_faulted_read_fails_a_token_authorised_assertion_or_answers_it_as_clean() {
    sweep(
        |fs| {
            let mut rng = seeded(fs);
            let id = register_non_resident(fs, &mut rng);
            let mut state = crate::FidoState::new();
            let token = arm_pin(fs, &mut state);
            let mut param = [0u8; 32];
            let plen = rsk_crypto::pinproto::authenticate(PinProto::Two, &token, &CDH, &mut param)
                .unwrap();
            Session {
                rng,
                state,
                req: ga_request_pin(&id, &param[..plen], 2),
            }
        },
        assert,
        &[],
    );
}

/// alwaysUv with no PIN: a token-less assertion is refused, fault or no fault.
#[test]
fn no_faulted_read_asserts_what_always_uv_refuses() {
    sweep(
        |fs| {
            let mut rng = seeded(fs);
            let id = register_non_resident(fs, &mut rng);
            fs.put(EF_ALWAYS_UV, &[1]).unwrap();
            Session {
                rng,
                state: crate::FidoState::new(),
                req: ga_request(Some(&id)),
            }
        },
        assert,
        &[],
    );
}
