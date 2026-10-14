// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_sdk::Dispatcher;

#[test]
fn every_key_operation_names_its_declined_uif_prompt_without_writing() {
    struct Recording(Vec<&'static str>);
    impl UserPresence for Recording {
        fn request(&mut self, confirm: Confirm<'_>) -> Presence {
            self.0.push(confirm.title);
            Presence::Declined
        }
    }
    for (fid, title) in [
        (consts::EF_UIF_SIG, "Sign data?"),
        (consts::EF_UIF_DEC, "Decrypt data?"),
        (consts::EF_UIF_AUT, "Authenticate?"),
        (consts::EF_UIF_ATT, "Attest key?"),
    ] {
        let mut fs = Fs::new(RamStorage::new());
        fs.put(fid, &[1, 0x20]).unwrap();
        let generation = fs.write_gen();
        let mut presence = Recording(Vec::new());
        assert_eq!(
            check_uif(&mut fs, fid, &mut presence),
            Err(Sw::SECURE_MESSAGE_EXEC_ERROR)
        );
        assert_eq!(presence.0, [title]);
        assert_eq!(fs.write_gen(), generation);
        let mut retained = [0; 2];
        assert_eq!(fs.read(fid, &mut retained), Some(2));
        assert_eq!(retained, [1, 0x20]);
    }
}

#[test]
fn certificate_reads_respect_the_space_after_an_existing_response_prefix() {
    for (cert, sw, expected) in [
        (b"abc".as_slice(), Sw::OK, b"\xA5abc".as_slice()),
        (b"abcd".as_slice(), Sw::MEMORY_FAILURE, b"\xA5".as_slice()),
    ] {
        let mut fs = make_fs();
        fs.put(consts::EF_CH_1, cert).unwrap();
        let rng = RefCell::new(CountRng(0));
        let presence = RefCell::new(crate::AlwaysConfirm);
        let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
        let raw = [0, consts::INS_GET_DATA, 0x7F, 0x21];
        let mut out = [0; 4];
        let mut res = ResBuf::new(&mut out);
        res.push(0xA5);
        assert_eq!(
            app.process(&Apdu::parse(&raw).unwrap(), &mut fs, &mut res),
            sw
        );
        assert_eq!(res.as_slice(), expected);
    }
}

#[test]
fn a_short_le_returns_one_certificate_frame_and_get_response_returns_the_tail() {
    let mut fs = make_fs();
    fs.put(consts::EF_CH_1, b"123456789").unwrap();
    let rng = RefCell::new(CountRng(0));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    let mut dispatcher = Dispatcher::default();
    let mut applets: [&mut dyn Applet<Fs<RamStorage>>; 1] = [&mut app];
    let mut send = |raw: &[u8]| {
        let mut out = [0; rsk_sdk::applet::RESP_BUILD];
        let mut res = ResBuf::new(&mut out);
        let sw = dispatcher.process(raw, &mut applets, &mut fs, &mut res);
        (res.as_slice().to_vec(), sw)
    };
    let mut select = vec![
        0,
        consts::INS_SELECT,
        4,
        0,
        u8::try_from(consts::OPENPGP_AID.len()).unwrap(),
    ];
    select.extend(consts::OPENPGP_AID);
    assert_eq!(send(&select).1, Sw::OK);
    assert_eq!(
        send(&[0, consts::INS_GET_DATA, 0x7F, 0x21, 4]),
        (b"1234".to_vec(), Sw(0x6105))
    );
    assert_eq!(send(&[0, 0xC0, 0, 0, 5]), (b"56789".to_vec(), Sw::OK));
}

#[test]
fn a_long_import_template_advances_past_each_tag_and_length() {
    let mut body = vec![0x7F, 0x48, 0x81, 0x81, 0x91, 0x81, 1];
    for _ in 0..63 {
        body.extend([0x92, 0]);
    }
    body.extend([0x5F, 0x48, 1, 0xA5]);
    let (offsets, lengths) = crate::importdata::parse_ehl_body(&body, 0).unwrap();
    assert_eq!(
        offsets,
        [Some(136), None, None, None, None, None, None, None, None]
    );
    assert_eq!(lengths, [1, 0, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn public_slot_info_reads_each_slots_own_fingerprint() {
    let mut fs = make_fs();
    for (fid, marker) in [
        (consts::EF_FP_SIG, 0xA1),
        (consts::EF_FP_DEC, 0xB2),
        (consts::EF_FP_AUT, 0xC3),
    ] {
        fs.put(fid, &[marker; 20]).unwrap();
    }
    let info = crate::info::read_info(&mut fs);
    for (slot, marker) in info.slots.iter().zip([0xA1, 0xB2, 0xC3]) {
        assert_eq!(slot.fingerprint, Some([marker; 20]));
    }
}

#[test]
fn internal_authenticate_uses_rsa_when_the_stored_algorithm_is_empty() {
    let mut fs = make_fs();
    let rng = RefCell::new(CountRng(7));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &rsa_import(0xA4, &[0x01, 0x00, 0x01], &hx(RSA_P), &hx(RSA_Q)),
        )
        .1,
        Sw::OK
    );
    verify_pin(&mut app, &mut fs, consts::PW1_MODE82, consts::PW1_DEFAULT);
    fs.put(consts::EF_ALGO_PRIV3, &[]).unwrap();
    let mut digest_info = DI_SHA256.to_vec();
    digest_info.extend([0x55; 32]);
    let mut command = vec![
        0,
        consts::INS_INTERNAL_AUT,
        0,
        0,
        u8::try_from(digest_info.len()).unwrap(),
    ];
    command.extend_from_slice(&digest_info);
    let (signature, sw) = run(&mut app, &mut fs, &command);
    assert_eq!(sw, Sw::OK);
    assert_eq!(signature.len(), 256);
    assert!(rsa_verify(&digest_info, &signature));
}

#[test]
fn crypto_rng_adapters_fill_the_requested_buffer_from_the_source() {
    let mut rsa_source = CountRng(7);
    let mut rsa_bytes = [0xA5; 4];
    rsk_rsa::Rng::fill(&mut crate::keys::RsaRng(&mut rsa_source), &mut rsa_bytes);
    assert_eq!(rsa_bytes, [7, 8, 9, 10]);

    let mut ec_source = CountRng(7);
    let mut ec_bytes = [0xA5; 4];
    rsk_ec::Rng::fill(&mut crate::keys::EcRng(&mut ec_source), &mut ec_bytes);
    assert_eq!(ec_bytes, [7, 8, 9, 10]);
}
