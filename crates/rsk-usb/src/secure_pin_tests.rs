// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// A minimal gpg/OpenSC-style `abPINDataStructure` for VERIFY: the 15-byte
/// prefix (bPINOperation=verify, bmFormatString=0x82 ASCII, rest zero) then the
/// 4-byte VERIFY template.
fn secure_block(p2: u8) -> Vec<u8> {
    let mut v = vec![
        0x00, // bPINOperation = verify
        0x00, // bTimeOut
        0x82, // bmFormatString: ASCII, left, byte units
        0x00, // bmPINBlockString
        0x00, // bmPINLengthFormat
        0x00, 0x00, // wPINMaxExtraDigit
        0x02, // bEntryValidationCondition
        0x00, // bNumberMessage
        0x00, 0x00, // wLangId
        0x00, // bMsgIndex
        0x00, 0x00, 0x00, // bTeoPrologue
    ];
    v.extend_from_slice(&[0x00, INS_VERIFY, 0x00, p2]); // VERIFY template
    v
}

#[test]
fn parse_extracts_template_and_ascii() {
    let block = secure_block(0x81);
    let req = parse_secure(&block).expect("parse");
    assert_eq!(req.operation, 0x00);
    assert!(req.ascii);
    assert_eq!(req.apdu_template, &[0x00, 0x20, 0x00, 0x81]);
}

#[test]
fn parse_reads_non_ascii_format() {
    let mut block = secure_block(0x81);
    block[2] = 0x01; // bmFormatString bits[1:0]=01 = BCD, not ASCII
    assert!(!parse_secure(&block).unwrap().ascii);
    block[2] = 0x00; // bits[1:0]=00 = binary, not ASCII
    assert!(!parse_secure(&block).unwrap().ascii);
}

#[test]
fn parse_rejects_short_input() {
    assert!(parse_secure(&[]).is_none());
    assert!(parse_secure(&[0u8; 14]).is_none()); // no template
    assert!(parse_secure(&[0u8; 18]).is_none()); // template < 4 bytes
}

#[test]
fn assemble_openpgp_pw1_is_variable_length() {
    let mut out = [0u8; 64];
    let n = assemble_verify(&[0x00, 0x20, 0x00, 0x81], b"123456", &mut out).unwrap();
    assert_eq!(
        &out[..n],
        &[
            0x00, 0x20, 0x00, 0x81, 0x06, b'1', b'2', b'3', b'4', b'5', b'6'
        ]
    );
}

#[test]
fn assemble_openpgp_pw3_admin_no_padding() {
    let mut out = [0u8; 64];
    let n = assemble_verify(&[0x00, 0x20, 0x00, 0x83], b"12345678", &mut out).unwrap();
    assert_eq!(out[4], 8); // Lc = the typed length, no padding
    assert_eq!(&out[5..n], b"12345678");
}

#[test]
fn openpgp_maximum_pin_and_the_next_length_have_independent_output_bounds() {
    for reference in [0x81, 0x82, 0x83] {
        let block = secure_block(reference);
        let request = parse_secure(&block).unwrap();
        let mut out = [0xA5; 5 + MAX_PIN + 2];
        let pin = [b'1'; MAX_PIN];
        assert_eq!(
            assemble_verify(request.apdu_template, &pin, &mut out),
            Some(5 + MAX_PIN)
        );
        assert_eq!(&out[..5], &[0, INS_VERIFY, 0, reference, 0x7F]);
        assert_eq!(&out[5..5 + MAX_PIN], &pin);
        assert_eq!(&out[5 + MAX_PIN..], &[0xA5; 2]);
        let mut out = [0xA5; 5 + MAX_PIN + 2];
        assert_eq!(
            assemble_verify(request.apdu_template, &[b'1'; MAX_PIN + 1], &mut out),
            None
        );
        assert_eq!(out, [0xA5; 5 + MAX_PIN + 2]);
    }
}

#[test]
fn assemble_piv_pads_with_ff_to_eight() {
    let mut out = [0u8; 64];
    let n = assemble_verify(&[0x00, 0x20, 0x00, 0x80], b"123456", &mut out).unwrap();
    assert_eq!(n, 5 + 8);
    assert_eq!(
        &out[..n],
        &[
            0x00, 0x20, 0x00, 0x80, 0x08, b'1', b'2', b'3', b'4', b'5', b'6', 0xFF, 0xFF
        ]
    );
}

#[test]
fn assemble_rejects_overlong_piv_pin() {
    let mut out = [0u8; 64];
    assert!(assemble_verify(&[0x00, 0x20, 0x00, 0x80], b"123456789", &mut out).is_none());
}

#[test]
fn assemble_rejects_non_verify_ins() {
    let mut out = [0u8; 64];
    assert!(assemble_verify(&[0x00, 0x24, 0x00, 0x81], b"123456", &mut out).is_none());
}

#[test]
fn assemble_forces_class_zero_ignoring_host_cla() {
    // A host CLA with the ISO 7816-4 command-chaining bit (0x10) must not survive
    // into the assembled APDU — else the dispatcher would buffer the on-pad PIN as a
    // chain segment instead of running VERIFY. The class is always forced to 0x00.
    let mut out = [0u8; 64];
    let n = assemble_verify(&[0x10, 0x20, 0x00, 0x81], b"123456", &mut out).unwrap();
    assert_eq!(
        out[0], 0x00,
        "class byte must be forced to 0x00, not the host 0x10"
    );
    assert_eq!(
        &out[..n],
        &[
            0x00, 0x20, 0x00, 0x81, 0x06, b'1', b'2', b'3', b'4', b'5', b'6'
        ]
    );
}

#[test]
fn assemble_rejects_short_template_and_buffer() {
    let mut out = [0u8; 64];
    assert!(assemble_verify(&[0x00, 0x20, 0x00], b"123456", &mut out).is_none());
    let mut tiny = [0u8; 8];
    assert!(assemble_verify(&[0x00, 0x20, 0x00, 0x81], b"123456", &mut tiny).is_none());
}

#[test]
fn parse_then_assemble_round_trips_piv() {
    let block = secure_block(PIV_PIN_P2);
    let req = parse_secure(&block).unwrap();
    let mut out = [0u8; 64];
    let n = assemble_verify(req.apdu_template, b"654321", &mut out).unwrap();
    assert_eq!(&out[..5], &[0x00, 0x20, 0x00, 0x80, 0x08]);
    assert_eq!(
        &out[5..n],
        &[b'6', b'5', b'4', b'3', b'2', b'1', 0xFF, 0xFF]
    );
}

/// Host stand-in for the secure-PIN Kani proofs: LCG-mutated templates, PINs
/// and buffers must never make `assemble_verify` / `parse_secure` write or read
/// out of bounds, and a success is always a self-consistent APDU.
#[test]
fn secure_pin_codec_property_fuzz() {
    let mut lcg: u64 = 0x1D87_2B41_C6A3_09F5;
    let mut next = || -> u8 {
        lcg = lcg
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (lcg >> 33) as u8
    };
    let make = |max: usize, bias_verify: bool, n: &mut dyn FnMut() -> u8| -> Vec<u8> {
        let len = (n() as usize) % (max + 1);
        let mut v = Vec::with_capacity(len);
        for i in 0..len {
            v.push(match (i, bias_verify, n() & 3) {
                (1, true, 0) => INS_VERIFY,
                (3, true, 0) => PIV_PIN_P2,
                _ => n(),
            });
        }
        v
    };
    for _ in 0..40000 {
        let template = make(6, true, &mut next);
        let pin = make(10, false, &mut next);
        let olen = (next() as usize) % 20;
        let mut out = vec![0u8; olen];
        if let Some(k) = assemble_verify(&template, &pin, &mut out) {
            assert!((5..=olen).contains(&k));
            assert_eq!(k, out[4] as usize + 5);
            let _ = &out[..k]; // fully written, in bounds
        }
        let abdata = make(APDU_TEMPLATE_OFFSET + 6, true, &mut next);
        if let Some(req) = parse_secure(&abdata) {
            assert!(req.apdu_template.len() >= 4);
            assert_eq!(
                req.apdu_template,
                &abdata[abdata.len() - req.apdu_template.len()..]
            );
        }
    }
}
