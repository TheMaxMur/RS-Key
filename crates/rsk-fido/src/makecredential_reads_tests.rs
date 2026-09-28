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

fn seeded(fs: &mut Fs<Traced>) -> Session {
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), fs, &mut rng).unwrap();
    Session {
        rng,
        state: crate::FidoState::new(),
        req: std::vec::Vec::new(),
    }
}

fn make(fs: &mut Fs<Traced>, s: &mut Session) -> Option<std::vec::Vec<u8>> {
    let mut out = [0u8; 1024];
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs,
        rng: &mut s.rng,
        state: &mut s.state,
        now_ms: 1000,
    };
    let n = make_credential(&mut ctx, &s.req, &mut out).ok()?;
    out.get(..n).map(<[u8]>::to_vec)
}

/// A resident request authorised by the session's live token.
fn with_token(token: &[u8; 32]) -> std::vec::Vec<u8> {
    let mut param = [0u8; 32];
    let plen =
        rsk_crypto::pinproto::authenticate(PinProto::Two, token, &[0xCD; 32], &mut param).unwrap();
    build_request_uv(true, Some((&param[..plen], 2)))
}

/// §6.1.2 steps 7/10 with a PIN set: a token-less resident request is refused, and
/// no failed read may turn it into a credential minted on presence alone.
#[test]
fn no_faulted_read_mints_a_credential_the_pin_refuses() {
    sweep(
        |fs| {
            let mut s = seeded(fs);
            crate::clientpin::store_local_pin(&dev(), fs, PIN).unwrap();
            s.req = build_request(true);
            s
        },
        make,
        &[],
    );
}

/// alwaysUv with no PIN: the request is refused for want of UV, fault or no fault.
#[test]
fn no_faulted_read_mints_a_credential_always_uv_refuses() {
    sweep(
        |fs| {
            let mut s = seeded(fs);
            fs.put(EF_ALWAYS_UV, &[1]).unwrap();
            s.req = build_request(false);
            s
        },
        make,
        &[],
    );
}

#[test]
fn a_faulted_read_fails_a_token_authorised_registration_or_lands_it_whole() {
    sweep(
        |fs| {
            let mut s = seeded(fs);
            let token = arm_pin(fs, &mut s.state);
            s.req = with_token(&token);
            s
        },
        make,
        &[],
    );
}

#[test]
fn a_faulted_read_fails_an_unprotected_registration_or_lands_it_whole() {
    sweep(
        |fs| {
            let mut s = seeded(fs);
            s.req = build_request(true);
            s
        },
        make,
        &[],
    );
}

/// The same user again: the new credential replaces the old one's slot, and a
/// failed read of either may not leave a third record or two for one user.
#[test]
fn a_faulted_read_fails_a_re_registration_or_replaces_the_credential_whole() {
    sweep(
        |fs| {
            let mut s = seeded(fs);
            s.req = build_request(true);
            assert!(make(fs, &mut s).is_some());
            s
        },
        make,
        &[],
    );
}

/// A resident registration whose excludeList names the passkey the same user
/// already has is refused, and a failed read of that passkey may not let it through
/// to replace the credential the RP registered.
#[test]
fn no_faulted_read_lets_an_excluded_registration_replace_the_passkey() {
    sweep(
        |fs| {
            let mut s = seeded(fs);
            s.req = build_request(true);
            let made = make(fs, &mut s).unwrap();
            let ad = verify_response(&made, &[0xCD; 32]);
            let id = ad[55..55 + usize::from(u16::from_be_bytes([ad[53], ad[54]]))].to_vec();
            s.req = mc_build(6, |e| {
                good_params(e);
                e.u8(5).unwrap().array(1).unwrap().map(2).unwrap();
                e.str("id").unwrap().bytes(&id).unwrap();
                e.str("type").unwrap().str("public-key").unwrap();
                e.u8(7).unwrap().map(1).unwrap();
                e.str("rk").unwrap().bool(true).unwrap();
            });
            s
        },
        make,
        &[],
    );
}
