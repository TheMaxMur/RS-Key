// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// [`assemble_verify`] never panics and, on success, `out[..n]` is *exactly* the
/// VERIFY APDU the trusted pad promises — for EVERY host template, typed PIN and
/// buffer size up to the modelled widths:
///
/// * the write stays wholly inside `out` and `out[4]` (Lc) is the body length;
/// * `out[0] == 0x00` whatever the host put in the template's CLA — the
///   anti-chaining defence documented at `secure_pin.rs:96`;
/// * `INS P1 P2` are the template's, and the INS is always VERIFY;
/// * the body starts with the digits the user actually typed;
/// * PIV (`P2 == PIV_PIN_P2`) is the fixed 8-byte block, `0xFF` past the typed
///   digits; every other reference is the typed length exactly.
///
/// The last four are the point: the bounds claim alone would still hold if the
/// function wrote a bare header, or padded with host-chosen bytes.
///
/// Written as `assert!`, not `assert_eq!`: Kani cannot format a message at
/// runtime, so every `assert_eq!` collapses into one shared `core::panicking`
/// check and a counterexample no longer names the clause that broke.
#[kani::proof]
// Longest loop is the PIV body, PIV_PIN_LEN = 8 iterations, +1 for the
// unwinding assertion. Both loops report `unwind SUCCESS` at this bound.
#[kani::unwind(9)]
fn assemble_verify_never_writes_out_of_bounds() {
    let tbuf: [u8; 5] = kani::any();
    let tlen: usize = kani::any();
    kani::assume(tlen <= tbuf.len());
    let pbuf: [u8; 8] = kani::any();
    let plen: usize = kani::any();
    kani::assume(plen <= pbuf.len());
    // Symbolic, never zeroed: against a zeroed buffer "the function never wrote
    // out[0]" is indistinguishable from "it forced the class byte to 0x00".
    let mut obuf: [u8; 16] = kani::any();
    let olen: usize = kani::any();
    kani::assume(olen <= obuf.len());

    if let Some(n) = assemble_verify(&tbuf[..tlen], &pbuf[..plen], &mut obuf[..olen]) {
        assert!((5..=olen).contains(&n), "length outside out");
        assert!(n == obuf[4] as usize + 5, "Lc disagrees with the length");

        // Copying the host CLA would let it carry the 7816-4 chaining bit (0x10),
        // so the dispatcher buffers the on-pad PIN as a chain segment instead of
        // running VERIFY. Proven for all 256 values of the symbolic `tbuf[0]`.
        assert!(obuf[0] == 0x00, "host CLA reached the wire");
        assert!(obuf[1] == tbuf[1], "INS is not the template's");
        assert!(obuf[2] == tbuf[2], "P1 is not the template's");
        assert!(obuf[3] == tbuf[3], "P2 is not the template's");
        assert!(obuf[1] == INS_VERIFY, "assembled a non-VERIFY APDU");

        // The body carries the typed secret itself — not zeros, not host bytes.
        for i in 0..plen {
            assert!(obuf[5 + i] == pbuf[i], "body is not the typed PIN");
        }

        if tbuf[3] == PIV_PIN_P2 {
            assert!(n == 5 + PIV_PIN_LEN, "PIV block is not 8 bytes");
            for i in plen..PIV_PIN_LEN {
                assert!(obuf[5 + i] == PIV_PAD, "PIV padding is not 0xFF");
            }
        } else {
            assert!(n == 5 + plen, "body is not the typed length");
        }

        // Every assertion above sits inside this branch, so it asserts nothing
        // unless the branch is reachable with the shape it is aimed at.
        kani::cover!(tbuf[0] & 0x10 != 0, "host CLA carries the chaining bit");
        kani::cover!(
            tbuf[3] == PIV_PIN_P2 && plen < PIV_PIN_LEN,
            "PIV block padded"
        );
        kani::cover!(tbuf[3] != PIV_PIN_P2 && plen > 0, "variable-length body");
    }
}

/// [`parse_secure`] never panics on host bytes; a parsed template is a suffix of
/// the input at least 4 bytes long (a bare `CLA INS P1 P2`).
#[kani::proof]
fn parse_secure_is_total() {
    let buf: [u8; APDU_TEMPLATE_OFFSET + 5] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= buf.len());
    if let Some(req) = parse_secure(&buf[..len]) {
        assert!(req.apdu_template.len() >= 4);
        assert!(req.apdu_template.len() <= len);
    }
}
