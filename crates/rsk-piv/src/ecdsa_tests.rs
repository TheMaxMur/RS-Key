// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// One ECDSA GENERAL AUTHENTICATE at 9C over the challenge `c`.
fn sign_at_9c<S: Storage>(
    app: &mut PivApplet,
    fs: &mut Fs<S>,
    algo: u8,
    c: &[u8],
) -> (Sw, Vec<u8>) {
    let mut msg = vec![0x7C, (c.len() + 4) as u8, 0x82, 0x00, 0x81, c.len() as u8];
    msg.extend_from_slice(c);
    run(app, fs, INS_AUTHENTICATE, algo, SLOT_SIGNATURE, &msg)
}

/// Whether `resp`'s DER signature verifies under `point` over `prehash`.
fn verifies(algo: u8, point: &[u8], prehash: &[u8], resp: &[u8]) -> bool {
    let der = find_tag(find_tag(resp, 0x7C).unwrap(), 0x82).unwrap();
    if algo == ALGO_ECCP256 {
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(point).unwrap();
        let sig = p256::ecdsa::Signature::from_der(der).unwrap();
        vk.verify_prehash(prehash, &sig).is_ok()
    } else {
        let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(point).unwrap();
        let sig = p384::ecdsa::Signature::from_der(der).unwrap();
        vk.verify_prehash(prehash, &sig).is_ok()
    }
}

/// A YubiKey 5.8.0 answers `6A80` to a P-256 ECDSA challenge of 33, 48 or 64 bytes
/// (measured 2026-09-30) and left-pads a shorter one; ours signed the leftmost 32.
/// P-384 is held to its 48 the same way. The refusal comes before the touch and the
/// PIN spend, as a mismatched algorithm's does: a malformed request buys nothing.
#[test]
fn an_ecdsa_challenge_longer_than_the_field_is_wrong_data() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(Scripted { confirm: true });
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    for (algo, field, over) in [
        (ALGO_ECCP256, 32usize, [33usize, 48, 64]),
        (ALGO_ECCP384, 48, [49, 64, 96]),
    ] {
        // 9C is PIN ALWAYS by default: one VERIFY buys exactly one operation.
        let mut tmpl = gen_template(algo);
        tmpl.extend_from_slice(&[0xAB, 0x01, TOUCHPOLICY_ALWAYS]);
        tmpl[1] += 3;
        let (sw, resp) = run(&mut app, &mut fs, INS_ASYM_KEYGEN, 0, SLOT_SIGNATURE, &tmpl);
        assert_eq!(sw, Sw::OK);
        let point = ec_point_of(&resp);

        verify_pin(&mut app, &mut fs);
        for n in over {
            assert_eq!(
                sign_at_9c(&mut app, &mut fs, algo, &vec![0x42; n]).0,
                Sw::WRONG_DATA,
                "{algo:02X}: a {n}-byte challenge must be refused, not cut to {field}"
            );
        }
        // The refusals spent nothing: the one VERIFY still signs a full-width challenge.
        let full = vec![0x42u8; field];
        let (sw, resp) = sign_at_9c(&mut app, &mut fs, algo, &full);
        assert_eq!(sw, Sw::OK, "{algo:02X}: a full width after the refusals");
        assert!(verifies(algo, &point, &full, &resp));

        // …and none of them asked for the touch: a declining finger is never reached.
        verify_pin(&mut app, &mut fs);
        pres.borrow_mut().confirm = false;
        for n in over {
            assert_eq!(
                sign_at_9c(&mut app, &mut fs, algo, &vec![0x42; n]).0,
                Sw::WRONG_DATA,
                "{algo:02X}: a {n}-byte challenge asked for the touch first"
            );
        }
        pres.borrow_mut().confirm = true;

        // A shorter challenge is still signed left-padded to the field.
        let short = [0x5Au8; 20];
        let (sw, resp) = sign_at_9c(&mut app, &mut fs, algo, &short);
        assert_eq!(sw, Sw::OK, "{algo:02X}: a 20-byte challenge");
        let mut padded = vec![0u8; field];
        padded[field - short.len()..].copy_from_slice(&short);
        assert!(
            verifies(algo, &point, &padded, &resp),
            "{algo:02X}: not left-padded"
        );
    }
}
