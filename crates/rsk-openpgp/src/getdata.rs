// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! GET DATA / GET NEXT DATA: build the DO ([`DoWriter`]) the way a host reads it: a
//! template (6E/65/7A/FA) with its own tag+length, which yubikit requires
//! (`Tlv.unpack(0x6E, …)`), and any other DO served alone as its bare value.

use rsk_fs::{Fs, Storage};
use rsk_sdk::Sw;

use crate::consts::*;
use crate::dobj::DoWriter;
use crate::files::{DoSource, nested_only, source};

/// Resolve the tag, enforce the read ACL and build the DO into `out`. Returns
/// `(len, sw)` and records the tag in `current_ef`, served or refused, for a
/// following GET NEXT DATA.
pub fn get_data<S: Storage>(
    fid: u16,
    has_pw2: bool,
    has_pw3: bool,
    fs: &mut Fs<S>,
    full_aid: &[u8; 16],
    current_ef: &mut Option<u16>,
    out: &mut [u8],
) -> (usize, Sw) {
    // Whatever it answers: a YubiKey 5.8.0 ends a 7F21 walk at a GET DATA of any
    // other DO, the ones it refuses included.
    *current_ef = Some(fid);
    match source(fid) {
        // A P1P2 this command does not serve is a wrong P1P2, whether it names
        // nothing at all or an internal EF: a YubiKey 5.7.4 answers `6B00` to
        // 65513 of the 65536 cells and keeps `6982` for the two private DOs it
        // does serve. Telling the two apart located every internal EF for a
        // caller holding no credential.
        DoSource::None | DoSource::Internal => return (0, Sw::WRONG_P1P2),
        _ if nested_only(fid) => return (0, Sw::WRONG_P1P2),
        _ => {}
    }
    // §5's access table gives the private DOs two different owners and no admin
    // override: `0103` is the cardholder's (PW1 no. 82), `0104` the admin's. A
    // YubiKey 5.7.4 implements exactly that, 3/3 from a genuine deselect —
    // unauthenticated both are `6982`, PW1-82 alone opens `0103` and not `0104`,
    // PW3 alone opens `0104` and not `0103`. (An earlier reading had it serving
    // `0104` to anyone; that one was taken with PW3 still standing, since a
    // re-SELECT of the same AID does not clear this card's PW state.)
    if fid == EF_PRIV_DO_3 && !has_pw2 {
        return (0, Sw::SECURITY_STATUS_NOT_SATISFIED);
    }
    if fid == EF_PRIV_DO_4 && !has_pw3 {
        return (0, Sw::SECURITY_STATUS_NOT_SATISFIED);
    }

    let data_len = {
        let mut w = DoWriter::new(out, fs, full_aid);
        w.build(fid)
    };
    // A failed build reports past the output bound: insufficient room or an
    // unreadable mandatory counter must never publish a partial template.
    if data_len > out.len() {
        return (0, Sw::MEMORY_FAILURE);
    }
    (data_len, Sw::OK)
}

#[cfg(test)]
#[path = "getdata_tests.rs"]
mod tests;
