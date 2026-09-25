// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! SELECT DATA. The application itself answers no other SELECT: a YubiKey 5.8.0
//! has none inside it, and only the dispatcher's SELECT by AID reaches the applet.

use rsk_sdk::{Apdu, Sw};

use crate::consts::{CERT_OCCURRENCES, SELECT_DATA_CH_CERT};
use crate::pin::Session;

/// SELECT DATA (INS 0xA5): choose the occurrence (`P1` = 0/1/2) of a DO with
/// several instances — here only the cardholder certificate (7F21, occurrences
/// `EF_CH_1/2/3`); the choice is recorded in the session for GET / PUT DATA.
///
/// Command data is exactly `60 04 5C 02 7F 21` with `P2 = 0x04`. Occurrence
/// selection is deliberately not PW3-gated: it is not itself a security
/// operation (the PUT DATA write stays PW3-gated), and it lets a non-admin
/// host read occurrences 1/2.
pub fn select_data(apdu: &Apdu, sess: &mut Session) -> Sw {
    // A YubiKey 5.8.0 judges P1 and P2 first, `6B00` for an occurrence past the
    // last or a P2 but 04, then takes one body only, byte for byte (measured).
    if apdu.p2 != 0x04 || apdu.p1 >= CERT_OCCURRENCES {
        return Sw::WRONG_P1P2;
    }
    if apdu.data != SELECT_DATA_CH_CERT {
        return Sw::WRONG_DATA;
    }
    sess.cert_occ = apdu.p1;
    Sw::OK
}
