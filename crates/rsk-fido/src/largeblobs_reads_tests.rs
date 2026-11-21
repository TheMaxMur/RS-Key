// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::probe::{Traced, sweep};

/// What the command needs beside the store, rebuilt per run.
struct Session {
    state: FidoState,
    req: std::vec::Vec<u8>,
}

fn stored(fs: &mut Fs<Traced>) {
    fs.put(EF_LARGEBLOB, &LARGEBLOB_INITIAL).unwrap();
}

fn with_pin(fs: &mut Fs<Traced>) {
    stored(fs);
    let mut pin_file = [0u8; 35];
    pin_file[0] = 8; // retries
    pin_file[1] = 4; // length
    pin_file[2] = 1; // format
    fs.put(EF_PIN, &pin_file).unwrap();
}

/// A one-fragment write carrying no pinUvAuthParam/protocol pair (keys 5, 6 absent).
fn bare_set(blob: &[u8]) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 1100];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(3).unwrap();
        e.u8(0x02).unwrap().bytes(blob).unwrap();
        e.u8(0x03).unwrap().u64(0).unwrap();
        e.u8(0x04).unwrap().u64(blob.len() as u64).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

fn send(fs: &mut Fs<Traced>, s: &mut Session) -> Option<std::vec::Vec<u8>> {
    let mut out = [0u8; 1100];
    let n = run(fs, &mut s.state, &s.req, &mut out).ok()?;
    out.get(..n).map(<[u8]>::to_vec)
}

#[test]
fn a_faulted_read_fails_a_token_authorised_write_or_lands_it_whole() {
    sweep(
        |fs| {
            with_pin(fs);
            let blob = valid_blob(b"a serialized large-blob array payload");
            Session {
                state: armed(PERM_LBW),
                req: set_request(0, Some(blob.len() as u64), &blob, &TOKEN),
            }
        },
        send,
        &[],
    );
}

/// §6.10.2 with a PIN set: a write with no token is refused, and no failed read
/// may make it look like one on an unprotected authenticator.
#[test]
fn no_faulted_read_takes_a_tokenless_write_the_pin_refuses() {
    sweep(
        |fs| {
            with_pin(fs);
            Session {
                state: FidoState::new(),
                req: bare_set(&valid_blob(&[0x55; 40])),
            }
        },
        send,
        &[],
    );
}

#[test]
fn no_faulted_read_takes_a_tokenless_write_always_uv_refuses() {
    sweep(
        |fs| {
            stored(fs);
            fs.put(crate::consts::EF_ALWAYS_UV, &[1]).unwrap();
            Session {
                state: FidoState::new(),
                req: bare_set(&valid_blob(&[0x66; 40])),
            }
        },
        send,
        &[],
    );
}

#[test]
fn a_faulted_read_fails_an_unprotected_write_or_lands_it_whole() {
    sweep(
        |fs| {
            stored(fs);
            Session {
                state: FidoState::new(),
                req: bare_set(&valid_blob(&[0x55; 40])),
            }
        },
        send,
        &[],
    );
}
