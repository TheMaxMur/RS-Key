// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn an_admitted_der_signature_fits_the_advertised_extension_budget() {
    let der = Signature::from_scalars([0x80; 32], [0x81; 32])
        .unwrap()
        .to_der();
    assert_eq!(der.as_bytes().len(), MAX_DER_SIG);
    let mut sig = DerSig {
        der: [0; MAX_DER_SIG],
        len: der.as_bytes().len(),
    };
    sig.der.copy_from_slice(der.as_bytes());
    let mut out = [0; GA_EXT_MAX];
    let mut enc = Encoder::new(Cursor::new(&mut out[..]));
    assert!(
        write_ga_ext(&mut enc, &sig).is_ok(),
        "an admitted DER signature must fit the advertised extension budget"
    );
    let len = enc.writer().position();
    let mut decoder = Decoder::new(&out[..len]);
    assert_eq!(decoder.str().unwrap(), NAME);
    assert_eq!(decoder.map().unwrap(), Some(1));
    assert_eq!(decoder.i64().unwrap(), KEY_SIG);
    assert_eq!(decoder.bytes().unwrap(), der.as_bytes());
    assert_eq!(decoder.position(), len);
}

#[test]
fn the_largest_classic_public_key_fits_its_advertised_cose_budget() {
    let mut raw = rsk_secret::Secret::new([1; 66]);
    let key =
        crate::ec::CredKey::from_raw(i64::from(crate::consts::CURVE_P521), raw.expose()).unwrap();
    raw.wipe();
    let mut out = [0; COSE_EC2_MAX];
    let mut enc = Encoder::new(Cursor::new(&mut out[..]));
    assert!(
        key.cose_public(crate::consts::ALG_ES512, &mut enc).is_ok(),
        "the largest classic public key must fit the advertised COSE budget"
    );
    let len = enc.writer().position();
    let mut decoder = Decoder::new(&out[..len]);
    assert_eq!(decoder.map().unwrap(), Some(5));
    assert_eq!(decoder.u8().unwrap(), 1);
    assert_eq!(decoder.u8().unwrap(), 2);
    assert_eq!(decoder.u8().unwrap(), 3);
    assert_eq!(decoder.i64().unwrap(), crate::consts::ALG_ES512);
    assert_eq!(decoder.i8().unwrap(), -1);
    assert_eq!(decoder.u8().unwrap(), crate::consts::CURVE_P521);
    for label in [-2, -3] {
        assert_eq!(decoder.i8().unwrap(), label);
        assert_eq!(decoder.bytes().unwrap().len(), 66);
    }
    assert_eq!(decoder.position(), len);
}
