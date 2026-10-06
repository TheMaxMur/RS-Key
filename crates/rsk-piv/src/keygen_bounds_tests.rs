// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::keygen::*;
use rsk_ec::{MAX_EC_POINT, MAX_EC_PUBDO};

fn device() -> Device<'static> {
    Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
        latched: false,
    }
}

fn retired_fixture() -> (Fs<Cut>, CutMedium) {
    let (mut fs, medium) = new_cut_fs();
    let key = PrivKey::from_scalar(Curve::P256, &[0x39; 32]).unwrap();
    seal::store_ec_key(
        &device(),
        &mut fs,
        &mut TestRng(17),
        key_fid(SLOT_RETIRED_LAST),
        &key,
    )
    .unwrap();
    for (slot, algo) in [
        (SLOT_RETIRED_FIRST, ALGO_ECCP384),
        (SLOT_RETIRED_LAST, ALGO_ECCP256),
    ] {
        fs.meta_add(
            key_fid(slot).get(),
            &[algo, PINPOLICY_NEVER, TOUCHPOLICY_ALWAYS, ORIGIN_IMPORTED],
        )
        .unwrap();
    }
    fs.put(
        cert_fid_for_slot(SLOT_RETIRED_LAST).unwrap(),
        b"other certificate",
    )
    .unwrap();
    (fs, medium)
}

fn retired_cut_state(
    fs: &mut Fs<Cut>,
    medium: &CutMedium,
    other_key: &[u8],
    algo: u8,
    completed: bool,
) -> bool {
    assert_eq!(
        medium.value(key_fid(SLOT_RETIRED_LAST).get()).as_deref(),
        Some(other_key)
    );
    assert_eq!(
        medium
            .value(cert_fid_for_slot(SLOT_RETIRED_LAST).unwrap())
            .as_deref(),
        Some(&b"other certificate"[..])
    );
    let mut meta = [0; 4 + MAX_EC_POINT];
    assert!(
        fs.meta_find(key_fid(SLOT_RETIRED_LAST).get(), &mut meta)
            .is_some()
    );
    assert_eq!(
        &meta[..4],
        &[
            ALGO_ECCP256,
            PINPOLICY_NEVER,
            TOUCHPOLICY_ALWAYS,
            ORIGIN_IMPORTED,
        ]
    );
    let key_present = fs.has_key(key_fid(SLOT_RETIRED_FIRST));
    let headed = fs
        .meta_find(key_fid(SLOT_RETIRED_FIRST).get(), &mut meta)
        .is_some();
    if key_present && headed {
        assert_eq!(
            &meta[..4],
            &[algo, PINPOLICY_ONCE, TOUCHPOLICY_NEVER, ORIGIN_GENERATED],
            "a committed key inherited the stale head"
        );
    }
    if completed {
        assert!(key_present && headed, "success requires a key and its head");
    }
    if key_present && !headed {
        let rng = RefCell::new(TestRng(7));
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
        let mut request = vec![0x7c, 0x24, 0x82, 0, 0x81, 32];
        request.extend_from_slice(&[0x42; 32]);
        let (sw, body) = run(
            &mut app,
            fs,
            INS_AUTHENTICATE,
            algo,
            SLOT_RETIRED_FIRST,
            &request,
        );
        assert_eq!(sw, Sw::REFERENCE_NOT_FOUND, "a headless key was usable");
        assert!(body.is_empty());
    }
    key_present
}

#[test]
fn retired_ec_generation_cuts_never_inherit_a_stale_policy() {
    let (_, baseline) = retired_fixture();
    let other_key = baseline.value(key_fid(SLOT_RETIRED_LAST).get()).unwrap();
    for (algo, point_len) in [
        (ALGO_ECCP256, 65),
        (ALGO_ECCP384, 97),
        (ALGO_ED25519, 32),
        (ALGO_X25519, 32),
    ] {
        let mut headless = false;
        rsk_fs::cut::sweep(
            retired_fixture,
            |fs| match crate::info::generate_slot_key(
                &device(),
                fs,
                &mut TestRng(7),
                SLOT_RETIRED_FIRST,
                algo,
            ) {
                Ok(()) => true,
                Err(Sw::MEMORY_FAILURE) => false,
                other => panic!("unexpected generation result: {other:?}"),
            },
            |fs, _, completed, medium| {
                if retired_cut_state(fs, medium, &other_key, algo, completed) {
                    let key =
                        seal::load_ec_key(&device(), fs, key_fid(SLOT_RETIRED_FIRST)).unwrap();
                    assert_eq!(key.public_point(&mut [0; MAX_EC_POINT]).unwrap(), point_len);
                    headless |= fs
                        .meta_find(key_fid(SLOT_RETIRED_FIRST).get(), &mut [0; 4])
                        .is_none();
                }
            },
        );
        assert!(headless, "the key-before-head cut was not reached");
    }
}

#[test]
fn retired_rsa_persistence_cuts_never_inherit_a_stale_policy() {
    let (_, baseline) = retired_fixture();
    let other_key = baseline.value(key_fid(SLOT_RETIRED_LAST).get()).unwrap();
    let key = rsk_rsa::generate_rsa(&mut RsaRng(&mut TestRng(99)), RSA_FIXTURE_BYTES * 8).unwrap();
    let mut headless = false;
    rsk_fs::cut::sweep(
        retired_fixture,
        |fs| match crate::info::store_retired_rsa(
            &device(),
            fs,
            &mut TestRng(7),
            SLOT_RETIRED_FIRST,
            &key,
        ) {
            Ok(()) => true,
            Err(Sw::MEMORY_FAILURE) => false,
            other => panic!("unexpected persistence result: {other:?}"),
        },
        |fs, _, completed, medium| {
            if retired_cut_state(fs, medium, &other_key, ALGO_RSA_FIXTURE, completed) {
                let mut modulus = [0; MAX_RSA_BYTES];
                assert_eq!(
                    seal::load_rsa_modulus(
                        &device(),
                        fs,
                        key_fid(SLOT_RETIRED_FIRST),
                        &mut modulus
                    ),
                    Ok(RSA_FIXTURE_BYTES)
                );
                assert_eq!(&modulus[..RSA_FIXTURE_BYTES], key.n_be());
                headless |= fs
                    .meta_find(key_fid(SLOT_RETIRED_FIRST).get(), &mut [0; 4])
                    .is_none();
            }
        },
    );
    assert!(headless, "the key-before-head cut was not reached");
}

#[test]
fn rsa_sizes_and_algorithm_ids_are_exact_inverses() {
    let expected = [
        (128, ALGO_RSA1024),
        (256, ALGO_RSA2048),
        (384, ALGO_RSA3072),
        (512, ALGO_RSA4096),
    ];
    for size in 0..=513 {
        assert_eq!(
            rsa_algo_from_size(size),
            expected
                .iter()
                .find_map(|&(bytes, algo)| (size == bytes).then_some(algo))
        );
    }
    for algo in 0..=u8::MAX {
        assert_eq!(
            rsa_size_from_algo(algo),
            expected
                .iter()
                .find_map(|&(bytes, id)| (algo == id).then_some(bytes))
        );
    }
}

#[test]
fn malformed_generation_templates_never_start_key_generation() {
    for (body, expected) in [
        (&[][..], Sw::WRONG_LENGTH),
        (&[0xad, 3, 0x80, 1, ALGO_ECCP256][..], Sw::WRONG_DATA),
        (&[0xac, 0][..], Sw::WRONG_DATA),
        (&[0xac, 3, 0x81, 1, ALGO_ECCP256][..], Sw::WRONG_DATA),
        (&[0xac, 2, 0x80, 0][..], Sw::WRONG_DATA),
    ] {
        assert!(matches!(parse_gen_template(body), Err(sw) if sw == expected));
    }
    let req = parse_gen_template(&[
        0xac,
        9,
        0x80,
        1,
        ALGO_ECCP256,
        0xaa,
        1,
        PINPOLICY_ALWAYS,
        0xab,
        1,
        TOUCHPOLICY_CACHED,
    ])
    .unwrap();
    assert_eq!(req.algo, ALGO_ECCP256);
    assert_eq!(req.pin_policy, Some(PINPOLICY_ALWAYS));
    assert_eq!(req.touch_policy, Some(TOUCHPOLICY_CACHED));
}

#[test]
fn unusable_slot_metadata_produces_no_public_key_bytes() {
    let mut fs = new_fs();
    for meta in [&[][..], &[0xff], &[ALGO_ECCP256]] {
        let mut out = [0x55; MAX_EC_POINT];
        assert_eq!(
            slot_public(&device(), &mut fs, SLOT_AUTHENTICATION, meta, &mut out),
            Err(if meta == [ALGO_ECCP256] {
                Sw::EXEC_ERROR
            } else {
                Sw::REFERENCE_NOT_FOUND
            })
        );
        assert_eq!(out, [0x55; MAX_EC_POINT]);
    }
    assert_eq!(
        slot_public(
            &device(),
            &mut fs,
            SLOT_AUTHENTICATION,
            &[ALGO_ECCP256],
            &mut [0; MAX_EC_POINT - 1]
        ),
        Err(Sw::EXEC_ERROR)
    );
}

#[test]
fn a_short_generation_response_does_not_hide_a_committed_ec_key() {
    let mut fs = new_fs();
    let req = GenReq {
        algo: ALGO_ECCP256,
        pin_policy: None,
        touch_policy: None,
    };
    let mut out = [];
    let mut response = ResBuf::new(&mut out);
    assert_eq!(
        generate_ec(
            &device(),
            &mut fs,
            &mut TestRng(7),
            SLOT_AUTHENTICATION,
            &req,
            &mut response
        ),
        Sw::WRONG_LENGTH
    );
    assert!(response.is_empty());
    let key = seal::load_ec_key(&device(), &mut fs, key_fid(SLOT_AUTHENTICATION)).unwrap();
    let mut point = [0; MAX_EC_POINT];
    assert_eq!(key.public_point(&mut point).unwrap(), 65);
    let mut cached = [0; MAX_EC_POINT];
    assert_eq!(
        fs.read(pubkey_fid(SLOT_AUTHENTICATION), &mut cached),
        Some(65)
    );
    assert_eq!(&cached[..65], &point[..65]);
    let mut meta = [0; 4 + MAX_EC_POINT];
    assert!(
        fs.meta_find(key_fid(SLOT_AUTHENTICATION).get(), &mut meta)
            .is_some()
    );
    assert_eq!(
        &meta[..4],
        &[
            ALGO_ECCP256,
            PINPOLICY_ONCE,
            TOUCHPOLICY_NEVER,
            ORIGIN_GENERATED
        ]
    );
}

#[test]
fn an_ec_generation_write_failure_returns_no_success_body() {
    let req = GenReq {
        algo: ALGO_ECCP256,
        pin_policy: None,
        touch_policy: None,
    };
    let mut failures = 0;
    let mut successes = 0;
    for budget in 0..=4 {
        let (mut fs, medium) = new_cut_fs();
        medium.arm(budget);
        let mut out = [0; MAX_EC_PUBDO];
        let mut response = ResBuf::new(&mut out);
        match generate_ec(
            &device(),
            &mut fs,
            &mut TestRng(7),
            SLOT_AUTHENTICATION,
            &req,
            &mut response,
        ) {
            Sw::MEMORY_FAILURE => {
                failures += 1;
                assert!(response.is_empty());
            }
            Sw::OK => {
                successes += 1;
                assert_eq!(&response.as_slice()[..5], &[0x7f, 0x49, 67, 0x86, 65]);
                assert!(
                    fs.meta_find(key_fid(SLOT_AUTHENTICATION).get(), &mut [0; 80])
                        .is_some()
                );
            }
            other => panic!("budget={budget}: {other:?}"),
        }
    }
    assert!(failures > 0 && successes > 0);
}

#[test]
fn a_short_der_signature_buffer_maps_the_builder_error() {
    assert_eq!(x509::ecdsa_sig_der(&[1; 64], &mut []), Err(Sw::EXEC_ERROR));
    assert_eq!(
        x509::ecdsa_sig_der(&[1; 63], &mut [0; 80]),
        Err(Sw::EXEC_ERROR)
    );
}

#[test]
fn rsa_finish_reports_each_refused_write_and_response_limit() {
    let key = rsk_rsa::generate_rsa(&mut RsaRng(&mut TestRng(99)), RSA_FIXTURE_BYTES * 8).unwrap();
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut completed = 0;
    let mut refused = 0;
    for budget in 0..=4 {
        let (mut fs, medium) = new_cut_fs();
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
        medium.arm(budget);
        let mut out = [0; MAX_RSA_PUBDO];
        let (n, sw) = app.rsa_generate_finish(
            &mut fs,
            &mut TestRng(7),
            SLOT_AUTHENTICATION,
            [PINPOLICY_ONCE, TOUCHPOLICY_NEVER],
            &key,
            &mut out,
        );
        match sw {
            Sw::MEMORY_FAILURE => {
                refused += 1;
                assert_eq!(n, 0);
            }
            Sw::OK => {
                completed += 1;
                assert_eq!(&out[..2], &[0x7f, 0x49]);
                let mut modulus = [0; MAX_RSA_BYTES];
                assert_eq!(
                    seal::load_rsa_modulus(
                        &device(),
                        &mut fs,
                        key_fid(SLOT_AUTHENTICATION),
                        &mut modulus
                    ),
                    Ok(RSA_FIXTURE_BYTES)
                );
                assert_eq!(&modulus[..RSA_FIXTURE_BYTES], key.n_be());
            }
            other => panic!("budget {budget}: {other:?}"),
        }
    }
    assert!(completed > 0 && refused > 0);
    let mut fs = new_fs();
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    assert_eq!(
        app.rsa_generate_finish(
            &mut fs,
            &mut TestRng(7),
            SLOT_AUTHENTICATION,
            [PINPOLICY_ONCE, TOUCHPOLICY_NEVER],
            &key,
            &mut []
        ),
        (0, Sw::WRONG_LENGTH)
    );
    assert!(
        seal::load_rsa_modulus(
            &device(),
            &mut fs,
            key_fid(SLOT_AUTHENTICATION),
            &mut [0; MAX_RSA_BYTES]
        )
        .is_ok()
    );
}
