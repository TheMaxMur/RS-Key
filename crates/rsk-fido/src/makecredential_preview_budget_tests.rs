// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn the_unsigned_preview_output_fits_its_budget_apart_from_certificate_payloads() {
    let mut request_bytes = [0; 16];
    let mut enc = Encoder::new(Cursor::new(&mut request_bytes[..]));
    enc.map(1)
        .unwrap()
        .i64(3)
        .unwrap()
        .array(1)
        .unwrap()
        .i64(crate::consts::ALG_ESP256_SPLIT_ARKG)
        .unwrap();
    let n = enc.writer().position();
    let input = previewsign::parse_mc(&mut Decoder::new(&request_bytes[..n])).unwrap();
    let request = previewsign::negotiate(&input, i64::from(crate::consts::CURVE_P256))
        .unwrap()
        .unwrap();
    let mut seed = Secret::new([1; 32]);
    let rp_id_hash = [7; 32];
    let key = previewsign::generate(
        seed.expose(),
        b"credential",
        &rp_id_hash,
        request,
        &mut SeqRng(1),
    )
    .unwrap();
    let signer = P256Key::from_scalar(seed.expose()).unwrap();
    seed.wipe();
    let preview = previewsign::attest(
        &key,
        &rp_id_hash,
        FLAG_UP | crate::consts::FLAG_AT | crate::consts::FLAG_ED,
        &[9; 32],
        Some(&signer),
    )
    .unwrap();
    let mut certificate = [0; 512];
    let n = cert::build_attestation_cert(&signer, &[1; 16], &mut certificate).unwrap();
    let chain = certificate[..n].repeat(cert::ATT_CHAIN_MAX_CERTS);
    let mut att = AttBufs::new();
    let chain_len = cert::att_chain_pack(&chain, &mut att.chain).unwrap();
    let shape = AttShape {
        sig_len: 0,
        chain_len,
        certs: u8::try_from(cert::ATT_CHAIN_MAX_CERTS).unwrap(),
        ea_performed: false,
        omitted: false,
    };
    let mut out = vec![0; previewsign::UNSIGNED_SANS_CHAIN_MAX + chain.len()];
    let mut enc = Encoder::new(Cursor::new(&mut out[..]));
    assert!(
        encode_unsigned_outputs(&mut enc, false, Some(&preview), &att, &shape).is_ok(),
        "preview output heads and attestation must fit their advertised budget"
    );
    let len = enc.writer().position();
    let mut decoder = Decoder::new(&out[..len]);
    assert_eq!(decoder.u8().unwrap(), 6);
    assert_eq!(decoder.map().unwrap(), Some(1));
    assert_eq!(decoder.str().unwrap(), "previewSign");
    assert_eq!(decoder.map().unwrap(), Some(1));
    assert_eq!(decoder.i64().unwrap(), 7);
    let object = decoder.bytes().unwrap();
    assert_eq!(decoder.position(), len);
    let mut decoder = Decoder::new(object);
    assert_eq!(decoder.map().unwrap(), Some(3));
    assert_eq!(decoder.u8().unwrap(), 1);
    assert_eq!(decoder.str().unwrap(), "packed");
    assert_eq!(decoder.u8().unwrap(), 2);
    assert_eq!(decoder.bytes().unwrap().len(), 316);
    assert_eq!(decoder.u8().unwrap(), 3);
    assert_eq!(decoder.map().unwrap(), Some(3));
    assert_eq!(decoder.str().unwrap(), "alg");
    assert_eq!(decoder.i64().unwrap(), ALG_ES256);
    assert_eq!(decoder.str().unwrap(), "sig");
    assert_eq!(
        decoder.bytes().unwrap(),
        previewsign::attestation_sig(&preview).unwrap().unwrap()
    );
    assert_eq!(decoder.str().unwrap(), "x5c");
    assert_eq!(decoder.array().unwrap(), Some(4));
    for _ in 0..4 {
        assert_eq!(decoder.bytes().unwrap(), &certificate[..n]);
    }
    assert_eq!(decoder.position(), object.len());
}
