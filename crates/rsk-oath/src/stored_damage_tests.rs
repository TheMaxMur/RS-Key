// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn no_truncated_access_code_record_opens_an_unvalidated_session() {
    let (mut reference, rng) = fixture();
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &presence);
    assert_eq!(set_code(&mut app, &mut reference, &[0xAB; 16]), Sw::OK);
    let mut blob = [0; OATH_CODE_MAX];
    let width = reference.read_key(EF_OATH_CODE, &mut blob).unwrap();
    let storage = reference.into_storage();
    for len in 0..width {
        let mut damaged = storage.clone();
        damaged.write(EF_OATH_CODE.get(), &blob[..len]).unwrap();
        let mut fs = Fs::new(damaged);
        fs.scan();
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &presence);
        assert_eq!(select(&mut app, &mut fs).0, Sw::OK);
        assert!(!app.validated, "stored width {len}");
        let body = [
            tlv(TAG_RESPONSE, &hmac_sha1(&[0xAB; 16], &app.challenge)),
            tlv(TAG_CHALLENGE, &PROOF_CHAL),
        ]
        .concat();
        assert_ne!(
            run(&mut app, &mut fs, &apdu(INS_VALIDATE, 0, 0, &body)).0,
            Sw::OK
        );
        assert!(!app.validated);
        assert_eq!(
            run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[])),
            (Sw::SECURITY_STATUS_NOT_SATISFIED, vec![])
        );
        let mut after = [0; OATH_CODE_MAX];
        assert_eq!(fs.read_key(EF_OATH_CODE, &mut after), Some(len));
        assert_eq!(&after[..len], &blob[..len]);
    }
}

#[test]
fn no_truncated_otp_pin_can_expose_passwords_or_be_replaced_by_set_pin() {
    let (mut reference, rng) = fixture();
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(
        SERIAL,
        [0x22; 32],
        Some(rsk_crypto::FusedKey::open(test_mkek)),
        &rng,
        &presence,
    );
    select(&mut app, &mut reference);
    let mut credential = put_data(b"bank", 0x21, 6, SECRET_SHA1, false, None);
    credential.extend(tlv(TAG_PWS_PASSWORD, b"retained password"));
    assert_eq!(put(&mut app, &mut reference, &credential), Sw::OK);
    assert_eq!(
        run(
            &mut app,
            &mut reference,
            &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))
        )
        .0,
        Sw::OK
    );
    let mut pin = [0; OTP_PIN_REC_V1];
    assert_eq!(reference.read(EF_OTP_PIN, &mut pin), Some(OTP_PIN_REC_V1));
    let storage = reference.into_storage();
    for len in 0..OTP_PIN_REC_V1 {
        let mut damaged = storage.clone();
        damaged.write(EF_OTP_PIN, &pin[..len]).unwrap();
        let mut fs = Fs::new(damaged);
        fs.scan();
        let mut app = OathApplet::new(
            SERIAL,
            [0x22; 32],
            Some(rsk_crypto::FusedKey::open(test_mkek)),
            &rng,
            &presence,
        );
        select(&mut app, &mut fs);
        let generation = fs.write_gen();
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                &apdu(INS_GET_CREDENTIAL, 0, 0, &tlv(TAG_NAME, b"bank"))
            ),
            (Sw::SECURITY_STATUS_NOT_SATISFIED, vec![])
        );
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"5678"))
            )
            .0,
            Sw::CONDITIONS_NOT_SATISFIED
        );
        assert!(!app.otp_pin_verified);
        assert_eq!(fs.write_gen(), generation);
        let mut after = [0; OTP_PIN_REC_V1];
        assert_eq!(fs.read(EF_OTP_PIN, &mut after), Some(len));
        assert_eq!(&after[..len], &pin[..len]);
    }
}

#[test]
fn an_algorithm_only_access_code_cannot_validate_with_a_public_empty_key() {
    for secret in [&[][..], &[0xAB][..]] {
        let (mut fs, rng) = fixture();
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &presence);
        let code = [&[ALG_HMAC_SHA1][..], secret].concat();
        let device = Device {
            serial_hash: &[0x22; 32],
            serial_id: &SERIAL,
            otp_key: None,
            latched: false,
        };
        assert!(seal::seal_put(
            &device,
            &mut fs,
            &mut CountRng(3),
            EF_OATH_CODE,
            &code
        ));
        select(&mut app, &mut fs);
        let body = [
            tlv(TAG_RESPONSE, &hmac_sha1(secret, &app.challenge)),
            tlv(TAG_CHALLENGE, &PROOF_CHAL),
        ]
        .concat();
        let (sw, response) = run(&mut app, &mut fs, &apdu(INS_VALIDATE, 0, 0, &body));
        if secret.is_empty() {
            assert_eq!((sw, response), (Sw::DATA_INVALID, vec![]));
            assert!(!app.validated);
        } else {
            assert_eq!(sw, Sw::OK);
            assert!(app.validated);
            assert_eq!(
                find_tag(&response, TAG_RESPONSE as u16),
                Some(&hmac_sha1(secret, &PROOF_CHAL)[..])
            );
        }
    }
}
