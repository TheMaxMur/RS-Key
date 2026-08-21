// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn short_form_wraps_a_p256_point() {
    // A 65-byte SEC1 point: both lengths fit in one byte, so the DO is
    // `7F49 43 { 86 41 <point> }` — 4 bytes of framing plus the point.
    let point = [0xA5u8; 65];
    let mut out = [0u8; MAX_EC_PUBDO];
    let n = make_ec_pubkey_do(&point, &mut out);
    assert_eq!(&out[..5], &[0x7f, 0x49, 67, 0x86, 65]);
    assert_eq!(&out[5..n], &point);
    assert_eq!(n, 70);
}

#[test]
fn long_form_wraps_a_p521_point() {
    // 133 bytes ≥ 128, so BOTH lengths take the `81 <len>` long form and the
    // framing grows to 7 bytes. This is the widest DO, and what MAX_EC_PUBDO
    // is sized for.
    let point = [0x5Au8; MAX_EC_POINT];
    let mut out = [0u8; MAX_EC_PUBDO];
    let n = make_ec_pubkey_do(&point, &mut out);
    assert_eq!(&out[..7], &[0x7f, 0x49, 0x81, 136, 0x86, 0x81, 133]);
    assert_eq!(&out[7..n], &point);
    assert_eq!(n, 140);
    assert!(n <= MAX_EC_PUBDO, "MAX_EC_PUBDO must cover the widest DO");
}

#[test]
fn every_reachable_point_width_re_parses() {
    // The four widths a `PrivKey` public point can actually be: 25519 (32),
    // P-256/brainpoolP256r1 (65), P-384/brainpoolP384r1 (97), P-521 (133).
    // Walk the DO back out with the same rules a host does, so the framing is
    // checked against a reader rather than against itself.
    for plen in [32usize, 65, 97, MAX_EC_POINT] {
        let point: Vec<u8> = (0..plen).map(|i| i as u8).collect();
        let mut out = [0u8; MAX_EC_PUBDO];
        let n = make_ec_pubkey_do(&point, &mut out);
        let (tag, body) = read_tlv(&out[..n]).expect("outer DO parses");
        assert_eq!(tag, 0x7f49, "outer tag");
        let (tag, value) = read_tlv(body).expect("inner DO parses");
        assert_eq!(tag, 0x86, "inner tag");
        assert_eq!(value, &point[..], "point survives the wrapper");
        assert_eq!(body.len(), value.len() + if plen >= 128 { 3 } else { 2 });
    }
}

#[test]
fn every_width_the_encoder_is_specified_for_encodes_a_readable_length() {
    // The test above walks the four widths a `PrivKey` can actually produce, and
    // all four sit clear of the byte where a length stops fitting in the short
    // form. Walk the whole documented domain instead: at a 126- or 127-byte
    // point the point is still short-form while the object around it is 128 or
    // 129, and choosing both forms from the point width put 0x80 (the indefinite
    // length DER forbids) and 0x81 (a long form with no byte behind it) where a
    // reader takes a short-form length.
    for plen in 0..=MAX_EC_POINT {
        let point: Vec<u8> = (0..plen).map(|i| i as u8).collect();
        let mut out = [0u8; MAX_EC_PUBDO];
        let n = make_ec_pubkey_do(&point, &mut out);
        assert!(n <= MAX_EC_PUBDO, "plen {plen} overran MAX_EC_PUBDO");
        let (tag, body) =
            read_tlv(&out[..n]).unwrap_or_else(|| panic!("plen {plen}: outer DO unreadable"));
        assert_eq!(tag, 0x7f49, "plen {plen}: outer tag");
        let (tag, value) =
            read_tlv(body).unwrap_or_else(|| panic!("plen {plen}: inner DO unreadable"));
        assert_eq!(tag, 0x86, "plen {plen}: inner tag");
        assert_eq!(value, &point[..], "plen {plen}: point survives the wrapper");
    }
}

/// Minimal BER reader for the two shapes this DO uses: a 2-byte tag on the
/// outer object, a 1-byte tag on the inner, and a short or `81`-long length.
/// Strict about which form a length may take — DER wants the shortest encoding,
/// so `81` may only carry a value the short form cannot hold. Without that, a
/// mis-chosen threshold re-parses cleanly and the boundary is pinned by nothing.
fn read_tlv(b: &[u8]) -> Option<(u16, &[u8])> {
    let mut p = 0;
    let mut tag = *b.get(p)? as u16;
    p += 1;
    if tag & 0x1f == 0x1f {
        tag = (tag << 8) | *b.get(p)? as u16;
        p += 1;
    }
    let len = match *b.get(p)? {
        0x81 => {
            p += 2;
            let n = *b.get(p - 1)? as usize;
            if n < 0x80 {
                return None;
            }
            n
        }
        n if n < 0x80 => {
            p += 1;
            n as usize
        }
        _ => return None,
    };
    Some((tag, b.get(p..p + len)?))
}
