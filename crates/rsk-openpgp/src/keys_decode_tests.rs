// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::ram::RamStorage;

fn card() -> (Device<'static>, Fs<RamStorage>, Session) {
    struct Fill;
    impl Rng for Fill {
        fn fill(&mut self, out: &mut [u8]) {
            out.fill(7);
        }
    }
    let dev = Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
        latched: false,
    };
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    crate::init::scan_files(&dev, &mut fs, &mut Fill).unwrap();
    let mut session = Session::new();
    session.adopt_reseeded(
        &dev.pin_derive_session(PW1_DEFAULT),
        &dev.pin_derive_session(PW3_DEFAULT),
    );
    session.has_pw3 = true;
    (dev, fs, session)
}

#[test]
fn an_authenticated_one_byte_ec_scalar_is_padded_by_the_loader() {
    let (dev, mut fs, session) = card();
    let plain = Secret::new([Curve::P256.id(), 1]);
    let mut blob = Secret::<[u8; 2 + DEK_SEAL_OVERHEAD]>::zeroed();
    let n = dek_seal(
        &dev,
        &mut fs,
        &session,
        EF_PK_SIG,
        plain.expose(),
        blob.expose_mut(),
    )
    .unwrap();
    fs.put_key(EF_PK_SIG, Sealed::wrap(&blob.expose()[..n]))
        .unwrap();
    let generation = fs.write_gen();

    let loaded = load_ec_key(&dev, &mut fs, &session, EF_PK_SIG).unwrap();

    let mut expected = Secret::<[u8; 32]>::zeroed();
    expected.expose_mut()[31] = 1;
    assert_eq!(loaded.curve(), Curve::P256);
    assert_eq!(loaded.scalar(), expected.expose());
    assert_eq!(fs.write_gen(), generation);
}

#[test]
fn an_overlong_ec_record_keeps_the_authenticated_maximum_prefix() {
    const P521_RECORD_LEN: usize = 95;
    let (dev, mut fs, session) = card();
    let key = PrivKey::from_scalar(Curve::P521, &[1]).unwrap();
    store_ec_key(&dev, &mut fs, &session, EF_PK_SIG, &key).unwrap();
    let mut record = Secret::<[u8; P521_RECORD_LEN + 1]>::zeroed();
    assert_eq!(
        fs.read_key(EF_PK_SIG, record.expose_mut()),
        Some(P521_RECORD_LEN)
    );
    record.expose_mut()[P521_RECORD_LEN] = 0xA5;
    fs.put_key(EF_PK_SIG, Sealed::wrap(record.expose()))
        .unwrap();
    assert_eq!(fs.size(EF_PK_SIG.get()), Some(P521_RECORD_LEN + 1));
    let generation = fs.write_gen();

    let loaded = load_ec_key(&dev, &mut fs, &session, EF_PK_SIG).unwrap();

    assert_eq!(loaded.curve(), Curve::P521);
    assert_eq!(loaded.scalar(), key.scalar());
    assert_eq!(fs.write_gen(), generation);
}
