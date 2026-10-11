// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn a_readable_non_p384_attestation_signer_is_refused_without_replacing_owner_records() {
    with_card(|app, fs| {
        verify(app, fs, PW3_MODE83);
        generate(app, fs, CRT_SIG, P256);
        let dev = Device {
            serial_hash: &[0x22; 32],
            serial_id: &SERIAL_ID,
            otp_key: None,
            latched: false,
        };
        let original = crate::keys::load_ec_key(&dev, fs, &app.sess, EF_PK_ATT).unwrap();
        let wrong = PrivKey::from_scalar(Curve::P256, &[1; 32]).unwrap();
        crate::keys::store_ec_key(&dev, fs, &app.sess, EF_PK_ATT, &wrong).unwrap();
        verify(app, fs, PW1_MODE81);
        let before = fs.write_gen();
        assert_eq!(attest(app, fs, KEY_REF_SIG), Sw::MEMORY_FAILURE);
        assert_eq!(fs.write_gen(), before);
        let retained = crate::keys::load_ec_key(&dev, fs, &app.sess, EF_PK_ATT).unwrap();
        assert_eq!(retained.curve(), Curve::P256);
        assert_eq!(retained.scalar(), wrong.scalar());
        crate::keys::store_ec_key(&dev, fs, &app.sess, EF_PK_ATT, &original).unwrap();
        verify(app, fs, PW1_MODE81);
        assert_eq!(attest(app, fs, KEY_REF_SIG), Sw::OK);
        let signer = root(app, fs);
        signed_by(&parse(&occurrence(app, fs, 2)), &signer);
    });
}
