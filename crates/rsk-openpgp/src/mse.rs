// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! MANAGE SECURITY ENVIRONMENT (INS 0x22): repoints the key slot the next
//! INTERNAL AUTHENTICATE (`P2 = 0xA4`, ISO 7816-8 Authentication Template) or
//! PSO:DECIPHER (`P2 = 0xB8`, Confidentiality Template) uses at the DEC (ref 2)
//! or AUT (ref 3) slot, until the next deselect ([`Session::reset`]).

use rsk_sdk::{Apdu, Sw};

use crate::consts::*;
use crate::pin::Session;

/// MANAGE SECURITY ENVIRONMENT (INS 0x22).
pub fn mse(sess: &mut Session, apdu: &Apdu) -> Sw {
    if apdu.p1 != 0x41 || (apdu.p2 != 0xA4 && apdu.p2 != 0xB8) {
        return Sw::WRONG_P1P2;
    }
    let d = apdu.data;
    // CRT `83 01 <02|03>` — a key-reference template; a short field is wrong data.
    if d.len() < 3 || d[0] != 0x83 || d[1] != 0x01 || (d[2] != 0x02 && d[2] != 0x03) {
        return WRONG_DATA;
    }
    let (algo, pk) = if d[2] == 0x02 {
        (EF_ALGO_PRIV2, EF_PK_DEC)
    } else {
        (EF_ALGO_PRIV3, EF_PK_AUT)
    };
    // OpenPGP 3.4 §7.2.18 names the CRT by its ISO 7816-8 meaning, and its worked
    // example `00 22 41 A4 03 83 01 02` is an AT: A4 configures INTERNAL
    // AUTHENTICATE, B8 (CT) configures PSO:DECIPHER. Reversed, the one form a
    // conformant host sends was a no-op that answered 9000.
    if apdu.p2 == 0xA4 {
        sess.algo_aut = algo;
        sess.pk_aut = pk;
    } else {
        sess.algo_dec = algo;
        sess.pk_dec = pk;
    }
    Sw::OK
}

#[cfg(test)]
#[path = "mse_tests.rs"]
mod tests;
