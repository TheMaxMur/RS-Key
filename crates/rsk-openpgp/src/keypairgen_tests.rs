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
