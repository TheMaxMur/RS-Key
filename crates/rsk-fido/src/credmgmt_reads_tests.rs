// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::probe::{Traced, sweep};

/// What the command needs beside the store, rebuilt per run.
struct Session {
    state: FidoState,
    req: std::vec::Vec<u8>,
}

/// alice and bob at example.com, carol alone at other.com; their resident ids.
fn stocked(fs: &mut Fs<Traced>) -> [std::vec::Vec<u8>; 3] {
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), fs, &mut rng).unwrap();
    let (alice, ..) = register(fs, &mut rng, "example.com", &[1, 1], "alice");
    let (bob, ..) = register(fs, &mut rng, "example.com", &[2, 2], "bob");
    let (carol, ..) = register(fs, &mut rng, "other.com", &[3, 3], "carol");
    [alice, bob, carol]
}

fn session(req: std::vec::Vec<u8>) -> Session {
    Session {
        state: armed(PERM_CM),
        req,
    }
}

fn send(fs: &mut Fs<Traced>, s: &mut Session) -> Option<std::vec::Vec<u8>> {
    let mut out = [0u8; 1024];
    let n = run(fs, &mut s.state, &s.req, &mut out).ok()?;
    out.get(..n).map(<[u8]>::to_vec)
}

#[test]
fn a_faulted_read_fails_a_delete_or_lands_it_whole() {
    sweep(
        |fs| {
            let [alice, ..] = stocked(fs);
            session(cm_request(0x06, Some(&subpara_cred(&alice)), &TOKEN))
        },
        send,
        &[],
    );
}

/// The RP's last credential: the delete takes its RP record with it.
#[test]
fn a_faulted_read_fails_a_last_delete_or_lands_it_whole() {
    sweep(
        |fs| {
            let [.., carol] = stocked(fs);
            session(cm_request(0x06, Some(&subpara_cred(&carol)), &TOKEN))
        },
        send,
        &[],
    );
}

#[test]
fn a_faulted_read_fails_an_update_or_lands_it_whole() {
    sweep(
        |fs| {
            let [alice, ..] = stocked(fs);
            let sub = subpara_update(&alice, &[1, 1], "alice2", "Alice Two");
            session(cm_request(0x07, Some(&sub), &TOKEN))
        },
        send,
        &[],
    );
}

/// A token scoped to example.com manages nothing at other.com, fault or no fault.
#[test]
fn no_faulted_read_lets_a_scoped_token_delete_another_rps_credential() {
    sweep(
        |fs| {
            let [.., carol] = stocked(fs);
            let mut s = session(cm_request(0x06, Some(&subpara_cred(&carol)), &TOKEN));
            s.state.paut.rp_id_hash = sha256(b"example.com");
            s.state.paut.has_rp_id = true;
            s
        },
        send,
        &[],
    );
}
