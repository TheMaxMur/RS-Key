// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::test_pins::PIN;
use rsk_fs::probe::{Traced, sweep};

/// What the command needs beside the store, rebuilt per run.
struct Session {
    state: FidoState,
    req: std::vec::Vec<u8>,
}

/// A PIN set, as every config request past the first setPIN finds the device.
fn pinned(fs: &mut Fs<Traced>, req: std::vec::Vec<u8>) -> Session {
    crate::clientpin::store_local_pin(&dev(), fs, PIN).unwrap();
    Session {
        state: armed(PERM_ACFG),
        req,
    }
}

/// authenticatorConfig answers with its status byte alone, so a success's answer
/// is empty and only its store is compared. A token-less request is not swept: it
/// is refused before anything is read, which the sweep refuses as vacuous.
fn send(fs: &mut Fs<Traced>, s: &mut Session) -> Option<std::vec::Vec<u8>> {
    run_fs(fs, &mut s.state, &s.req)
        .ok()
        .map(|_| std::vec::Vec::new())
}

#[test]
fn a_faulted_read_fails_toggle_always_uv_or_lands_it_whole() {
    for on in [false, true] {
        sweep(
            |fs| {
                let s = pinned(
                    fs,
                    config_request(CONFIG_TOGGLE_ALWAYS_UV as u8, &[], &TOKEN),
                );
                if on {
                    fs.put(EF_ALWAYS_UV, &[1]).unwrap();
                }
                s
            },
            send,
            &[],
        );
    }
}

#[test]
fn a_faulted_read_fails_set_min_pin_length_or_lands_it_whole() {
    sweep(
        |fs| pinned(fs, config_request(0x03, &subpara_min_pin(6), &TOKEN)),
        send,
        &[],
    );
}

/// §6.11.4: the floor never goes down, and a faulted read of it may not read as the
/// build's default and let a lower one in.
#[test]
fn no_faulted_read_lowers_the_min_pin_length() {
    sweep(
        |fs| {
            let s = pinned(fs, config_request(0x03, &subpara_min_pin(6), &TOKEN));
            fs.put(EF_MINPINLEN, &[8, 0]).unwrap();
            s
        },
        send,
        &[],
    );
}

/// A floor raised past the PIN's own length forces its change.
#[test]
fn a_faulted_read_never_drops_the_forced_change_a_raised_floor_owes() {
    sweep(
        |fs| pinned(fs, config_request(0x03, &subpara_min_pin(8), &TOKEN)),
        send,
        &[],
    );
}

#[test]
fn a_faulted_read_fails_enable_enterprise_attestation_or_lands_it_whole() {
    sweep(
        |fs| pinned(fs, config_request(0x01, &[], &TOKEN)),
        send,
        &[],
    );
}

#[test]
fn a_faulted_read_fails_an_ea_rp_list_write_or_lands_it_whole() {
    sweep(
        |fs| {
            pinned(
                fs,
                vendor_req(&subpara_ea_rpids(&["a.example", "b.example"]), &TOKEN),
            )
        },
        send,
        &[],
    );
}
