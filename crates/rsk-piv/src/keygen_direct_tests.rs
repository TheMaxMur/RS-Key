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

#[test]
fn a_sealed_signer_without_signing_support_cannot_issue_attestation() {
    let mut fs = Fs::new(rsk_fs::storage::ram::RamStorage::new());
    fs.scan();
    let mut rng = CountRng(0);
    crate::files::scan_files(&dev(), &mut fs, &mut rng).unwrap();
    let request = GenReq {
        algo: ALGO_ECCP256,
        pin_policy: None,
        touch_policy: None,
    };
    let mut output = [0; 2048];
    assert_eq!(
        generate_ec(
            &dev(),
            &mut fs,
            &mut rng,
            SLOT_SIGNATURE,
            &request,
            &mut ResBuf::new(&mut output)
        ),
        Sw::OK
    );
    let original = seal::load_ec_key(&dev(), &mut fs, key_fid(SLOT_ATTESTATION)).unwrap();
    let wrong = PrivKey::from_scalar(Curve::X25519, &[0x11; 32]).unwrap();
    seal::store_ec_key(&dev(), &mut fs, &mut rng, key_fid(SLOT_ATTESTATION), &wrong).unwrap();
    let generation = fs.write_gen();
    let mut res = ResBuf::new(&mut output);
    assert_eq!(
        attest(&dev(), &mut fs, &mut rng, SLOT_SIGNATURE, [0; 4], &mut res),
        crate::ec_sw(rsk_ec::EcError::Unsupported)
    );
    assert!(res.is_empty());
    assert_eq!(fs.write_gen(), generation);
    seal::store_ec_key(
        &dev(),
        &mut fs,
        &mut rng,
        key_fid(SLOT_ATTESTATION),
        &original,
    )
    .unwrap();
    let mut res = ResBuf::new(&mut output);
    assert_eq!(
        attest(&dev(), &mut fs, &mut rng, SLOT_SIGNATURE, [0; 4], &mut res),
        Sw::OK
    );
    assert!(!res.is_empty());
}

#[test]
fn direct_rsa_generation_refuses_invalid_policies_before_drawing_entropy() {
    for (pin_policy, touch_policy) in [(Some(0), None), (None, Some(0))] {
        let mut fs = Fs::new(rsk_fs::storage::ram::RamStorage::new());
        let mut rng = CountRng(0);
        let request = GenReq {
            algo: ALGO_RSA2048,
            pin_policy,
            touch_policy,
        };
        let mut output = [0xA5; 512];
        let mut res = ResBuf::new(&mut output);
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
        assert_eq!(output, [0xA5; 512]);
        assert_eq!(rng.0, 0);
        assert_eq!(fs.write_gen(), 0);
    }
}

#[test]
fn correctly_sealed_invalid_target_scalars_cannot_issue_attestation() {
    for algo in [ALGO_ECCP256, ALGO_ED25519] {
        let mut fs = Fs::new(rsk_fs::storage::ram::RamStorage::new());
        fs.scan();
        let mut rng = CountRng(0);
        crate::files::scan_files(&dev(), &mut fs, &mut rng).unwrap();
        let request = GenReq {
            algo,
            pin_policy: None,
            touch_policy: None,
        };
        let mut output = [0; 2048];
        assert_eq!(
            generate_ec(
                &dev(),
                &mut fs,
                &mut rng,
                SLOT_SIGNATURE,
                &request,
                &mut ResBuf::new(&mut output)
            ),
            Sw::OK
        );
        let original = seal::load_ec_key(&dev(), &mut fs, key_fid(SLOT_SIGNATURE)).unwrap();
        let invalid = PrivKey::from_scalar(Curve::P256, &[0; 32]).unwrap();
        seal::store_ec_key(&dev(), &mut fs, &mut rng, key_fid(SLOT_SIGNATURE), &invalid).unwrap();
        let generation = fs.write_gen();
        let mut res = ResBuf::new(&mut output);
        assert_eq!(
            attest(&dev(), &mut fs, &mut rng, SLOT_SIGNATURE, [0; 4], &mut res),
            crate::ec_sw(rsk_ec::EcError::Failed)
        );
        assert!(res.is_empty());
        assert_eq!(fs.write_gen(), generation);
        seal::store_ec_key(
            &dev(),
            &mut fs,
            &mut rng,
            key_fid(SLOT_SIGNATURE),
            &original,
        )
        .unwrap();
        assert_eq!(
            attest(
                &dev(),
                &mut fs,
                &mut rng,
                SLOT_SIGNATURE,
                [0; 4],
                &mut ResBuf::new(&mut output)
            ),
            Sw::OK
        );
    }
}

std::thread_local! {
    static REJECT_GENERATION: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

pub(super) fn generate_rsa_with_injected_failure(
    rng: &mut dyn rsk_rsa::Rng,
    bits: usize,
) -> Result<RsaKey, rsk_rsa::RsaError> {
    if REJECT_GENERATION.with(|reject| reject.replace(false)) {
        Err(rsk_rsa::RsaError::Failed)
    } else {
        super::generate_rsa(rng, bits)
    }
}

#[test]
fn a_refused_rsa_primitive_publishes_neither_a_key_nor_a_response() {
    let mut fs = Fs::new(rsk_fs::storage::ram::RamStorage::new());
    let mut rng = CountRng(0);
    let request = GenReq {
        algo: ALGO_RSA2048,
        pin_policy: None,
        touch_policy: None,
    };
    let mut output = [0xA5; 512];
    let mut res = ResBuf::new(&mut output);
    REJECT_GENERATION.with(|reject| reject.set(true));
    assert_eq!(
        generate_rsa_blocking(
            &dev(),
            &mut fs,
            &mut rng,
            SLOT_SIGNATURE,
            &request,
            &mut res
        ),
        crate::rsa_sw(rsk_rsa::RsaError::Failed)
    );
    assert!(!REJECT_GENERATION.with(core::cell::Cell::get));
    assert!(res.is_empty());
    assert_eq!(output, [0xA5; 512]);
    assert_eq!(fs.write_gen(), 0);
    assert_eq!(rng.0, 0);
}

#[test]
fn direct_edwards_import_requires_the_named_nonempty_scalar_in_every_profile() {
    for (algo, tag) in [(ALGO_ED25519, 0x07), (ALGO_X25519, 0x08)] {
        let mut fs = Fs::new(rsk_fs::storage::ram::RamStorage::new());
        let fid = key_fid(SLOT_SIGNATURE);
        fs.put_key(fid, rsk_fs::Sealed::wrap(&[0xa5; 32])).unwrap();
        let generation = fs.write_gen();
        let mut rng = CountRng(0);
        for data in [&[][..], &[tag, 0][..], &[0x06, 1, 1][..]] {
            assert_eq!(
                import_edwards(&dev(), &mut fs, &mut rng, algo, SLOT_SIGNATURE, data),
                Err(Sw::WRONG_DATA)
            );
            assert_eq!(rng.0, 0);
            assert_eq!(fs.write_gen(), generation);
            let mut retained = [0; 32];
            assert_eq!(fs.read_key(fid, &mut retained), Some(32));
            assert_eq!(retained, [0xa5; 32]);
        }
    }
}

#[test]
fn direct_free_slot_probe_handles_slots_without_a_certificate_mapping() {
    let mut fs = Fs::new(rsk_fs::storage::ram::RamStorage::new());
    for slot in [SLOT_CARDMGM, 0xff] {
        assert_eq!(cert_fid_for_slot(slot), None);
        assert_eq!(retired_slot_is_free(&mut fs, slot), Ok(true));
        fs.put_key(key_fid(slot), rsk_fs::Sealed::wrap(&[0xa5; 32]))
            .unwrap();
        let generation = fs.write_gen();
        assert_eq!(retired_slot_is_free(&mut fs, slot), Ok(false));
        assert_eq!(fs.write_gen(), generation);
    }
}
