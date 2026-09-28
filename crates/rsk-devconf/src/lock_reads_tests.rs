// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::probe::{Traced, sweep};

/// [`locked_fs`] on the sweep's medium.
fn locked(fs: &mut Fs<Traced>) {
    persist_touched(&SERIAL, fs, &[TAG_USB_ENABLED, 2, 0x02, 0x3B]).unwrap();
    persist_touched(&SERIAL, fs, &write(None, &[], Some(&CODE))).unwrap();
}

/// A configuration write answers with its status alone: a success's answer is
/// empty and only its store is compared.
fn writes(blob: Vec<u8>) -> impl Fn(&mut Fs<Traced>, &mut ()) -> Option<Vec<u8>> {
    move |fs, _| {
        persist_touched(&SERIAL, fs, &blob)
            .ok()
            .map(|()| Vec::new())
    }
}

/// A lock whose record the flash would not serve is still a lock: no write
/// passes it without the code, and none with another.
#[test]
fn no_faulted_read_passes_the_lock_without_its_code() {
    for blob in [
        write(None, &FIDO_ONLY, None),
        write(Some(&OTHER), &FIDO_ONLY, None),
        write(None, &[], Some(&CLEAR)),
    ] {
        sweep(locked, writes(blob), &[]);
    }
}

#[test]
fn a_faulted_read_fails_a_configuration_write_or_lands_it_whole() {
    for blob in [
        write(Some(&CODE), &FIDO_ONLY, None),
        write(Some(&CODE), &[], Some(&OTHER)),
        write(Some(&CODE), &[], Some(&CLEAR)),
    ] {
        sweep(locked, writes(blob), &[]);
    }
    sweep(|_| (), writes(write(None, &FIDO_ONLY, Some(&CODE))), &[]);
}
