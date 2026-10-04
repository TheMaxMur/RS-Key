// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::probe::{Traced, sweep};

/// What the command needs beside the store, rebuilt per run.
struct Session {
    rng: SeqRng,
    state: FidoState,
    plat: Platform,
    req: std::vec::Vec<u8>,
}

fn agreed(fs: &mut Fs<Traced>) -> Session {
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), fs, &mut rng).unwrap();
    let mut state = FidoState::new();
    let plat = key_agreement(fs, &mut rng, &mut state, PinProto::Two, 2);
    Session {
        rng,
        state,
        plat,
        req: std::vec::Vec::new(),
    }
}

/// [`agreed`], with [`PIN`] set over the same key agreement.
fn pinned(fs: &mut Fs<Traced>) -> Session {
    let mut s = agreed(fs);
    let req = s.plat.set_pin_req(PIN);
    let mut out = [0u8; 256];
    run(fs, &mut s.rng, &mut s.state, &req, &mut out).unwrap();
    s
}

fn send(fs: &mut Fs<Traced>, s: &mut Session) -> Option<std::vec::Vec<u8>> {
    let mut out = [0u8; 256];
    let n = run(fs, &mut s.rng, &mut s.state, &s.req, &mut out).ok()?;
    out.get(..n).map(<[u8]>::to_vec)
}

#[test]
fn a_faulted_read_fails_a_first_set_pin_or_lands_it_whole() {
    sweep(
        |fs| {
            let mut s = agreed(fs);
            s.req = s.plat.set_pin_req(PIN);
            s
        },
        send,
        &[],
    );
}

#[test]
fn no_faulted_read_lets_set_pin_replace_a_pin() {
    sweep(
        |fs| {
            let mut s = pinned(fs);
            s.req = s.plat.set_pin_req(NEW_PIN);
            s
        },
        send,
        &[],
    );
}

#[test]
fn no_faulted_read_lets_set_pin_under_the_owners_floor() {
    sweep(
        |fs| {
            let mut s = agreed(fs);
            fs.put(EF_MINPINLEN, &[16, 0]).unwrap();
            s.req = s.plat.set_pin_req(PIN);
            s
        },
        send,
        &[],
    );
}

#[test]
fn a_faulted_read_fails_a_change_pin_or_lands_it_whole() {
    sweep(
        |fs| {
            let mut s = pinned(fs);
            s.req = s.plat.change_pin_req(PIN, NEW_PIN);
            s
        },
        send,
        &[],
    );
}

/// A wrong current PIN is refused; a fault may not take the change. Whether a fault
/// can refund the retry is not this sweep's to judge (an unspent retry is also the
/// state before the spend): the dying-write tests hold that ordering.
#[test]
fn no_faulted_read_takes_a_change_pin_the_wrong_pin_refuses() {
    sweep(
        |fs| {
            let mut s = pinned(fs);
            s.req = s.plat.change_pin_req(WRONG_PIN, NEW_PIN);
            s
        },
        send,
        &[],
    );
}

#[test]
fn no_faulted_read_satisfies_a_forced_change_with_the_current_pin() {
    assert_eq!(
        sweep(
            |fs| {
                let mut s = pinned(fs);
                fs.put(
                    EF_MINPINLEN,
                    &[MIN_PIN_LENGTH, crate::pinpolicy::FORCE_CHANGE],
                )
                .unwrap();
                s.req = s.plat.change_pin_req(PIN, PIN);
                s
            },
            send,
            &[],
        ),
        None,
        "the current PIN cannot satisfy a forced change even without a read fault"
    );
}

#[test]
fn a_faulted_read_fails_a_get_pin_token_or_answers_it_as_clean() {
    sweep(
        |fs| {
            let mut s = pinned(fs);
            s.req = s.plat.get_token_req(PIN);
            s
        },
        send,
        &[],
    );
}

#[test]
fn no_faulted_read_hands_a_token_to_the_wrong_pin() {
    sweep(
        |fs| {
            let mut s = pinned(fs);
            s.req = s.plat.get_token_req(WRONG_PIN);
            s
        },
        send,
        &[],
    );
}

/// §6.5.5.7.1: while forceChangePin is pending, the right PIN still buys no token.
#[test]
fn no_faulted_read_waives_a_pending_pin_change() {
    sweep(
        |fs| {
            let mut s = pinned(fs);
            fs.put(EF_MINPINLEN, &[4, 1]).unwrap();
            s.req = s.plat.get_token_req(PIN);
            s
        },
        send,
        &[],
    );
}

/// The persistent grant: minted once, and a fault may never re-mint it over the
/// live one, which would revoke every other platform's.
#[test]
fn no_faulted_read_re_mints_the_persistent_grant() {
    sweep(
        |fs| {
            let mut s = pinned(fs);
            s.req = s.plat.get_token_perms_req(PIN, PERM_PCMR as u64);
            let mut out = [0u8; 256];
            run(fs, &mut s.rng, &mut s.state, &s.req, &mut out).unwrap();
            s
        },
        send,
        &[],
    );
}

/// With the retries spent, the right PIN is refused too.
#[test]
fn no_faulted_read_revives_a_blocked_pin() {
    sweep(
        |fs| {
            let mut s = pinned(fs);
            let mut rec = [0u8; PIN_FILE_LEN];
            fs.read(EF_PIN, &mut rec).unwrap();
            rec[0] = 0;
            fs.put(EF_PIN, &rec).unwrap();
            s.req = s.plat.get_token_req(PIN);
            s
        },
        send,
        &[],
    );
}
