// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use rsk_fs::storage::ram::RamStorage;

use super::*;

#[test]
fn over_long_algo_do_does_not_panic() {
    // `Storage::read` reports the DO's FULL stored length and PUT DATA caps
    // nothing, so a PW3 host can leave an over-16-byte C1/C2/C3 algorithm
    // attribute. The read+slice in generate / rsa_generate_params must clamp
    // to the fixed buffer — an index-OOB panic on device is a brick.
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    let mut algo = [0u8; 48]; // > the 16-byte reader buffer
    algo[0] = ALGO_RSA;
    algo[1] = 0x08; // 2048-bit
    fs.put(EF_ALGO_PRIV1, &algo).unwrap();
    let mut sess = Session::new();
    sess.has_pw3 = true; // GENERATE is a PW3 op; reach the algo read past the gate
    // Must not panic. It is also refused rather than clamped: DO 0xFA advertises no
    // 48-byte attribute, and acting on a 16-byte prefix of a value the card reports
    // in full is how a slot ends up holding a key its own attribute misdescribes.
    assert_eq!(
        rsa_generate_params(&mut fs, &sess, 0x80, 0x00, &[0xB6, 0x00]),
        Err(Sw::WRONG_DATA)
    );
}

#[test]
fn generate_refuses_an_unadvertised_stored_algorithm_attribute() {
    // Builds predating the `put_data` gate accepted any C1/C2/C3 under PW3, and
    // `EF_ALGO_PRIV*` is `DoSource::Internal` — no default, no migration — so the
    // value survives the upgrade and it is the *owner's* next GENERATE that mints
    // the weak key. `RsaKeygen::usable` is an asm alignment constraint (any 32-byte
    // multiple = a 512-bit floor), so the refusal has to happen here.
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    // rsa512, as a pre-gate build would have stored it.
    fs.put(EF_ALGO_PRIV1, &[ALGO_RSA, 0x02, 0x00, 0x00, 0x20, 0x00])
        .unwrap();
    let mut sess = Session::new();
    sess.has_pw3 = true;
    assert_eq!(
        rsa_generate_params(&mut fs, &sess, 0x80, 0x00, &[0xB6, 0x00]),
        Err(Sw::WRONG_DATA)
    );

    // An advertised size is still generated normally.
    fs.put(EF_ALGO_PRIV1, &[ALGO_RSA, 0x08, 0x00, 0x00, 0x20, 0x00])
        .unwrap();
    assert_eq!(
        rsa_generate_params(&mut fs, &sess, 0x80, 0x00, &[0xB6, 0x00]),
        Ok(Some((EF_PK_SIG, 2048)))
    );
}

#[test]
fn short_algo_do_does_not_panic() {
    // run-4: the sibling under-length case of the above. PUT DATA caps no
    // minimum length, so a PW3 host can leave a 1- or 2-byte C1 whose first
    // byte is ALGO_RSA; reading the modulus-size bytes algo[1]/algo[2] must be
    // guarded, else the slice index panics (device reset), not clamp it away.
    let mut sess = Session::new();
    sess.has_pw3 = true;
    for short in [&[ALGO_RSA][..], &[ALGO_RSA, 0x00][..]] {
        let mut fs = Fs::new(RamStorage::new());
        fs.scan();
        fs.put(EF_ALGO_PRIV1, short).unwrap();
        assert_eq!(
            rsa_generate_params(&mut fs, &sess, 0x80, 0x00, &[0xB6, 0x00]),
            Err(Sw::WRONG_DATA)
        );
    }
}

// ---- the control-reference template, read against a YubiKey 5.8.0 ----------

struct Lcg(u64);
impl Rng for Lcg {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (self.0 >> 33) as u8;
        }
    }
}

/// A fresh card, factory PINs, no keys.
fn with_card(f: impl FnOnce(&mut crate::OpenpgpApplet, &mut Fs<RamStorage>)) {
    const SERIAL_ID: [u8; 8] = [0xAA, 0xBB, 0xCC, 0xDD, 5, 6, 7, 8];
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    let dev = Device {
        serial_hash: &[0x22; 32],
        serial_id: &SERIAL_ID,
        otp_key: None,
        latched: false,
    };
    crate::init::scan_files(&dev, &mut fs, &mut Lcg(1)).unwrap();
    let rng = core::cell::RefCell::new(Lcg(2));
    let presence = core::cell::RefCell::new(crate::AlwaysConfirm);
    let mut app = crate::OpenpgpApplet::new(SERIAL_ID, [0x22; 32], None, &rng, &presence);
    f(&mut app, &mut fs);
}

fn run(app: &mut crate::OpenpgpApplet, fs: &mut Fs<RamStorage>, raw: &[u8]) -> (Vec<u8>, Sw) {
    use rsk_sdk::Applet;
    let apdu = rsk_sdk::Apdu::parse(raw).unwrap();
    let mut buf = [0u8; 1024];
    let mut res = rsk_sdk::ResBuf::new(&mut buf);
    let sw = app.process(&apdu, fs, &mut res);
    (res.as_slice().to_vec(), sw)
}

fn apdu(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut a = vec![0x00, ins, p1, p2];
    if !data.is_empty() {
        a.push(data.len() as u8);
        a.extend_from_slice(data);
    }
    a.push(0x00);
    a
}

fn admin(app: &mut crate::OpenpgpApplet, fs: &mut Fs<RamStorage>) {
    assert_eq!(
        run(app, fs, &apdu(INS_VERIFY, 0, PW3_MODE83, PW3_DEFAULT)).1,
        Sw::OK
    );
    let p256 = [ALGO_ECDSA, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    for tag in [EF_ALGO_SIG, EF_ALGO_DEC, EF_ALGO_AUT] {
        assert_eq!(
            run(app, fs, &apdu(INS_PUT_DATA, 0, tag as u8, &p256)).1,
            Sw::OK
        );
    }
}

/// IMPORT of a P-256 scalar behind the template `crt`.
fn import(crt: &[u8], scalar: u8) -> Vec<u8> {
    let body = [
        crt,
        &[0x7F, 0x48, 0x02, 0x92, 0x20, 0x5F, 0x48, 0x20],
        &[scalar; 32],
    ]
    .concat();
    let ehl = [&[0x4D, body.len() as u8][..], &body].concat();
    let mut a = vec![0x00, INS_PUT_DATA_ODD, 0x3F, 0xFF, ehl.len() as u8];
    a.extend_from_slice(&ehl);
    a
}

fn key_info(app: &mut crate::OpenpgpApplet, fs: &mut Fs<RamStorage>) -> Vec<u8> {
    run(app, fs, &apdu(INS_GET_DATA, 0, EF_KEY_INFO as u8, &[])).0
}

/// GENERATE's `P1 = 81` read on a card with no keys, every template as a YubiKey
/// 5.8.0 answered it: `6581` for a well-formed template naming an empty slot, `6A80`
/// for one it will not read.
#[test]
fn a_template_is_read_as_a_yubikey_reads_it() {
    let absent = Sw::MEMORY_FAILURE;
    let refused = Sw::WRONG_DATA;
    let held = Sw::OK;
    let table: &[(&[u8], Sw)] = &[
        (&[], refused),
        (&[0xB6], refused),
        (&[0xB8], refused),
        (&[0xC6, 0x00], refused),
        (&[0xB6, 0x00], absent),
        (&[0xB6, 0x00, 0x00], absent),
        (&[0xB6, 0x00, 0x84, 0x01], absent),
        (&[0xB6, 0x00, 0x84, 0x01, 0x81], absent),
        (&[0xB6, 0x01, 0x00], refused),
        (&[0xB6, 0x03, 0x84, 0x01], refused),
        (&[0xB6, 0x04, 0x84, 0x01, 0x01], refused),
        (&[0xB6, 0x05, 0x84, 0x01, 0x81], refused),
        (&[0xB6, 0x04, 0x84, 0x01, 0x01, 0x00], refused),
        (&[0xB6, 0x04, 0x84, 0x01, 0x81, 0x00], refused),
        (&[0xB6, 0x03, 0x84, 0x01, 0x01], absent),
        (&[0xB6, 0x03, 0x84, 0x01, 0x02], refused),
        (&[0xB6, 0x03, 0x84, 0x01, 0x82], refused),
        (&[0xB6, 0x03, 0x83, 0x01, 0x81], absent),
        (&[0xB6, 0x03, 0x83, 0x05, 0x81], refused),
        (&[0xB6, 0x05, 0x83, 0x03, 0x01, 0x02, 0x03], absent),
        (&[0xB6, 0x05, 0x84, 0x01, 0x01, 0x83, 0x00], absent),
        (&[0xB6, 0x02, 0x84, 0x00], refused),
        (&[0xB6, 0x81, 0x00], refused),
        (&[0xB6, 0x81, 0x03, 0x84, 0x01, 0x01], refused),
        (&[0xB8, 0x06, 0x84, 0x01, 0x02, 0x84, 0x01, 0x02], absent),
        (&[0xB8, 0x03, 0x84, 0x01, 0x02], absent),
        (&[0xB8, 0x05, 0x84, 0x01, 0x02, 0x00, 0x00], absent),
        (&[0xB8, 0x05, 0x84, 0x01, 0x02, 0x00], refused),
        (&[0xB8, 0x03, 0x84, 0x01, 0x81], refused),
        (&[0xB8, 0x02, 0x84, 0x02], refused),
        (&[0xB6, 0x02, 0x84, 0xFF], refused),
        (&[0xB6, 0x03, 0x84, 0x02, 0x01], refused),
        (&[0xB8, 0x03, 0x84, 0x05, 0x02], refused),
        (&[0xB8, 0x04, 0x84, 0x02, 0x02, 0x02], refused),
        (&[0xA4, 0x03, 0x84, 0x01, 0x03], absent),
        (&[0xA4, 0x03, 0x84, 0x01, 0x81], refused),
        // The attestation key's template, alone or beside a SIG reference: a YubiKey
        // answers with its key, as this card does from its first boot.
        (&[0xB6, 0x03, 0x84, 0x01, 0x81], held),
        (&[0xB6, 0x03, 0x84, 0x01, 0x81, 0xFF], held),
        (&[0xB6, 0x06, 0x84, 0x01, 0x81, 0x84, 0x01, 0x01], held),
        (&[0xB6, 0x06, 0x84, 0x01, 0x01, 0x84, 0x01, 0x81], held),
    ];
    with_card(|app, fs| {
        for (crt, want) in table {
            let got = run(app, fs, &apdu(INS_KEYPAIR_GEN, 0x81, 0x00, crt)).1;
            assert_eq!(got, *want, "GENERATE 81 {crt:02X?}");
        }
    });
}

/// ykman names Yubico's attestation key `B6 { 84 01 81 }`. Read by its first byte
/// that template was the signature slot's, and an IMPORT or GENERATE under it replaced
/// the signing key; it still names no slot beside a second reference, to SIG's.
#[test]
fn the_attestation_template_never_reaches_the_signature_slot() {
    const ATT: &[u8] = &[0xB6, 0x03, 0x84, 0x01, 0x81];
    with_card(|app, fs| {
        admin(app, fs);
        assert_eq!(run(app, fs, &import(&[0xB6, 0x00], 0x11)).1, Sw::OK);
        let read_sig = apdu(INS_KEYPAIR_GEN, 0x81, 0x00, &[0xB6, 0x00]);
        let (sig_key, sw) = run(app, fs, &read_sig);
        assert_eq!(sw, Sw::OK);
        let before = key_info(app, fs);

        let both = [0xB6, 0x06, 0x84, 0x01, 0x81, 0x84, 0x01, 0x01];
        for crt in [
            ATT,
            &both,
            &[0xB6, 0x06, 0x84, 0x01, 0x01, 0x84, 0x01, 0x81],
        ] {
            assert_eq!(
                run(app, fs, &import(crt, 0x22)).1,
                Sw::WRONG_DATA,
                "IMPORT {crt:02X?}"
            );
            let generate = apdu(INS_KEYPAIR_GEN, 0x80, 0x00, crt);
            assert_eq!(
                run(app, fs, &generate).1,
                Sw::WRONG_DATA,
                "GENERATE {crt:02X?}"
            );
        }
        assert_eq!(
            run(app, fs, &read_sig),
            (sig_key.clone(), Sw::OK),
            "the SIG key moved"
        );
        assert_eq!(key_info(app, fs), before, "DO DE moved");
        let (att_key, sw) = run(app, fs, &apdu(INS_KEYPAIR_GEN, 0x81, 0x00, ATT));
        assert_eq!(sw, Sw::OK);
        assert_ne!(att_key, sig_key, "the attestation key read as SIG's");
        assert_eq!(
            att_key[..5],
            [0x7F, 0x49, 0x63, 0x86, 0x61],
            "a P-384 point"
        );
    });
}

/// The firmware runs an RSA GENERATE ahead of dispatch through `rsa_generate_params`,
/// which reads the template as GENERATE does: the attestation template is no RSA
/// slot, and one it cannot read is refused before the password.
#[test]
fn the_rsa_fast_path_reads_the_template_as_generate_does() {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    let mut sess = Session::new();
    let att = [0xB6, 0x03, 0x84, 0x01, 0x81];
    assert_eq!(
        rsa_generate_params(&mut fs, &sess, 0x80, 0x00, &[0xB6, 0x01, 0x00]),
        Err(Sw::WRONG_DATA)
    );
    assert_eq!(
        rsa_generate_params(&mut fs, &sess, 0x80, 0x00, &att),
        Err(Sw::SECURITY_STATUS_NOT_SATISFIED)
    );
    sess.has_pw3 = true;
    assert_eq!(
        rsa_generate_params(&mut fs, &sess, 0x80, 0x00, &att),
        Err(Sw::WRONG_DATA)
    );
    for (crt, slot) in [
        (&[0xB6, 0x03, 0x84, 0x01, 0x01][..], EF_PK_SIG),
        (&[0xB8, 0x03, 0x84, 0x01, 0x02], EF_PK_DEC),
        (&[0xA4, 0x00, 0xFF], EF_PK_AUT),
    ] {
        assert_eq!(
            rsa_generate_params(&mut fs, &sess, 0x80, 0x00, crt),
            Ok(Some((slot, 2048))),
            "{crt:02X?}"
        );
    }
}

/// A key reference that names the template's own slot is that slot, and a tag the
/// card does not know inside the template is skipped, for IMPORT and GENERATE both.
#[test]
fn a_key_reference_to_the_templates_own_slot_is_that_slot() {
    with_card(|app, fs| {
        admin(app, fs);
        let dec = import(&[0xB8, 0x03, 0x84, 0x01, 0x02], 0x11);
        assert_eq!(run(app, fs, &dec).1, Sw::OK);
        let sig = import(&[0xB6, 0x03, 0x83, 0x01, 0x81], 0x22);
        assert_eq!(run(app, fs, &sig).1, Sw::OK);
        let aut = apdu(INS_KEYPAIR_GEN, 0x80, 0x00, &[0xA4, 0x03, 0x84, 0x01, 0x03]);
        assert_eq!(run(app, fs, &aut).1, Sw::OK);
        assert_eq!(
            key_info(app, fs),
            [0x01, 0x02, 0x02, 0x02, 0x03, 0x01, 0x81, 0x01]
        );
    });
}

/// GENERATE judges P2, the template, P1 and then the admin password, each answer
/// here measured on a YubiKey 5.8.0 with no password verified.
#[test]
fn generate_judges_p2_the_template_p1_and_the_password_in_turn() {
    with_card(|app, fs| {
        let gen_ = |app: &mut _, fs: &mut _, p1, p2, crt: &[u8]| {
            run(app, fs, &apdu(INS_KEYPAIR_GEN, p1, p2, crt)).1
        };
        for crt in [&[][..], &[0xB6], &[0xB6, 0x01, 0x00], &[0xC6, 0x00]] {
            assert_eq!(gen_(app, fs, 0x80, 0, crt), Sw::WRONG_DATA, "{crt:02X?}");
        }
        let locked = Sw::SECURITY_STATUS_NOT_SATISFIED;
        assert_eq!(gen_(app, fs, 0x80, 0, &[0xB6, 0x00]), locked);
        assert_eq!(
            gen_(app, fs, 0x80, 0, &[0xB6, 0x03, 0x84, 0x01, 0x81]),
            locked
        );
        let order: [(u8, u8, &[u8], Sw); 5] = [
            (0x80, 0x01, &[0xC6, 0x00], Sw::WRONG_P1P2),
            (0x81, 0x01, &[0xC6, 0x00], Sw::WRONG_P1P2),
            (0x82, 0x00, &[0xC6, 0x00], Sw::WRONG_DATA),
            (0x82, 0x00, &[0xB6], Sw::WRONG_DATA),
            (0x82, 0x00, &[0xB6, 0x00], Sw::WRONG_P1P2),
        ];
        for (p1, p2, crt, want) in order {
            assert_eq!(
                gen_(app, fs, p1, p2, crt),
                want,
                "{p1:02X} {p2:02X} {crt:02X?}"
            );
        }
    });
}

/// IMPORT judges its P1-P2, then the admin password, then the body, where a body
/// too short to hold a key is `6A80` like any other it cannot read — no `6700`.
#[test]
fn import_judges_the_password_before_any_body() {
    let bodies: &[&[u8]] = &[
        &[0x4D],
        &[0x4D, 0x00],
        &[0x4D, 0x02, 0xB6],
        &[0x4D, 0x02, 0xB6, 0x00],
        &[0x4D, 0x02, 0xC6, 0x00],
        &[0x4D, 0x03, 0xB6, 0x01, 0x00],
        &[0x4D, 0x05, 0xB6, 0x03, 0x84, 0x01, 0x02],
    ];
    with_card(|app, fs| {
        let imp = |app: &mut _, fs: &mut _, p2, body: &[u8]| {
            let mut a = vec![0x00, INS_PUT_DATA_ODD, 0x3F, p2, body.len() as u8];
            a.extend_from_slice(body);
            run(app, fs, &a).1
        };
        assert_eq!(
            imp(app, fs, 0xFE, &[0x4D, 0x02, 0xB6, 0x00]),
            Sw::WRONG_P1P2
        );
        for body in bodies {
            let sw = imp(app, fs, 0xFF, body);
            assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED, "{body:02X?}");
        }
        admin(app, fs);
        for body in bodies {
            assert_eq!(imp(app, fs, 0xFF, body), Sw::WRONG_DATA, "{body:02X?}");
        }
    });
}

#[test]
fn a_direct_public_key_read_clamps_to_every_supplied_output_width() {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    let public = [0x7f, 0x49, 3, 0x86, 1, 7];
    fs.put(slot_pub_fid(EF_PK_SIG), &public).unwrap();
    let generation = fs.write_gen();
    for capacity in 0..=public.len() {
        let mut out = [0xa5; 8];
        assert_eq!(
            read_public(&mut fs, EF_PK_SIG, &mut out[..capacity]),
            Ok(capacity)
        );
        assert_eq!(&out[..capacity], &public[..capacity]);
        assert_eq!(&out[capacity..], &[0xa5; 8][capacity..]);
        assert_eq!(fs.write_gen(), generation);
    }
}

#[test]
#[should_panic(expected = "no 0x0093")]
fn a_tlv_oracle_refuses_a_missing_required_child() {
    let run = crate::test_tlv::children(&[0x5e, 1, 7]);
    assert_eq!(crate::test_tlv::child(&run, 0x5e), [7]);
    let _ = crate::test_tlv::child(&run, 0x93);
}

#[test]
fn a_public_key_read_that_shrinks_after_the_probe_emits_no_stale_scratch_bytes() {
    use rsk_sdk::Applet;
    let (backend, control) = rsk_fs::read_change::ChangingRead::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    let serial = [1, 2, 3, 4, 5, 6, 7, 8];
    let hash = [0x22; 32];
    let dev = Device {
        serial_hash: &hash,
        serial_id: &serial,
        otp_key: None,
        latched: false,
    };
    crate::init::scan_files(&dev, &mut fs, &mut Lcg(1)).unwrap();
    let fid = slot_pub_fid(EF_PK_SIG);
    fs.put(fid, &[0x7f, 0x49, 3, 0x86, 1, 7]).unwrap();
    let rng = core::cell::RefCell::new(Lcg(2));
    let presence = core::cell::RefCell::new(crate::AlwaysConfirm);
    let mut app = crate::OpenpgpApplet::new(serial, hash, None, &rng, &presence);
    app.scratch.fill(0xa5);
    control.replace_on_read(fid, 0, Some(&[]));
    let generation = fs.write_gen();
    let request = rsk_sdk::Apdu::parse(&[0, INS_KEYPAIR_GEN, 0x81, 0, 2, CRT_SIG, 0]).unwrap();
    let mut out = [0xa5; 32];
    let mut res = rsk_sdk::ResBuf::new(&mut out);
    assert_eq!(app.process(&request, &mut fs, &mut res), Sw::OK);
    assert!(res.as_slice().is_empty());
    assert_eq!(out, [0xa5; 32]);
    assert!(control.served());
    assert_eq!(fs.write_gen(), generation);
}
