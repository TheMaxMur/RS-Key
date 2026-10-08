// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "fixed test fixtures define every input window"
)]

use super::*;

struct CountRng(usize);
impl Rng for CountRng {
    fn fill(&mut self, bytes: &mut [u8]) {
        self.0 += 1;
        bytes.fill(7);
    }
}

fn dev() -> Device<'static> {
    Device {
        serial_hash: &[0x22; 32],
        serial_id: &[1; 8],
        otp_key: None,
        latched: false,
    }
}

#[test]
fn direct_generation_and_import_reject_unknown_algorithms_before_entropy_or_retirement() {
    let mut fs = Fs::new(rsk_fs::storage::ram::RamStorage::new());
    let mut rng = CountRng(0);
    let request = GenReq {
        algo: 0xff,
        pin_policy: None,
        touch_policy: None,
    };
    let mut out = [0xa5; 64];
    let mut res = ResBuf::new(&mut out);
    assert_eq!(
        generate_ec(
            &dev(),
            &mut fs,
            &mut rng,
            SLOT_SIGNATURE,
            &request,
            &mut res
        ),
        Sw::WRONG_DATA
    );
    assert_eq!(
        generate_rsa_blocking(
            &dev(),
            &mut fs,
            &mut rng,
            SLOT_SIGNATURE,
            &request,
            &mut res
        ),
        Sw::WRONG_DATA
    );
    assert!(res.is_empty());
    assert_eq!(out, [0xa5; 64]);
    assert_eq!(
        import_rsa(&dev(), &mut fs, &mut rng, 0xff, SLOT_SIGNATURE, &[]),
        Err(Sw::WRONG_DATA)
    );
    assert_eq!(
        import_ec(&dev(), &mut fs, &mut rng, 0xff, SLOT_SIGNATURE, &[6, 1, 1]),
        Err(Sw::WRONG_DATA)
    );
    assert_eq!(rng.0, 0);
    assert_eq!(fs.write_gen(), 0);
}

#[test]
fn an_oversized_direct_metadata_cache_falls_back_to_the_stored_key() {
    let mut fs = Fs::new(rsk_fs::storage::ram::RamStorage::new());
    let key = PrivKey::from_scalar(Curve::P256, &[0x11; 32]).unwrap();
    seal::store_ec_key(
        &dev(),
        &mut fs,
        &mut CountRng(0),
        key_fid(SLOT_SIGNATURE),
        &key,
    )
    .unwrap();
    let mut metadata = vec![
        ALGO_ECCP256,
        PINPOLICY_NEVER,
        TOUCHPOLICY_NEVER,
        ORIGIN_IMPORTED,
    ];
    metadata.extend([0x42; MAX_EC_POINT + 1]);
    let generation = fs.write_gen();
    let mut out = [0xa5; MAX_EC_POINT];
    let n = slot_public(&dev(), &mut fs, SLOT_SIGNATURE, &metadata, &mut out).unwrap();
    let mut expected = [0; MAX_EC_POINT];
    assert_eq!(key.public_point(&mut expected), Ok(n));
    assert_eq!(&out[..n], &expected[..n]);
    assert_eq!(&out[n..], &[0xa5; MAX_EC_POINT][n..]);
    assert_eq!(fs.write_gen(), generation);
}
