// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::faults::ProbeStuck;

fn sealed_key<S: Storage>(fs: &mut Fs<S>, slot: u8) -> Vec<u8> {
    let mut out = [0; 128];
    let n = fs.read_key(key_fid(slot), &mut out).unwrap();
    out[..n].to_vec()
}

#[derive(Clone, Copy, Debug)]
enum Replacement {
    GenerateEc,
    GenerateRsa,
    ImportEc,
    Move,
    FinishRsa,
    RetiredEc,
    RetiredRsa,
    RecreateF9,
}

fn value<S: Storage>(fs: &mut Fs<S>, fid: u16) -> Option<Vec<u8>> {
    let mut out = [0; rsk_fs::MAX_VALUE_BYTES];
    fs.read(fid, &mut out)
        .map(|n| out[..n.min(out.len())].to_vec())
}

#[test]
fn a_truncated_boot_walk_cannot_hide_the_destination_cache_from_retirement() {
    let (backend, medium) = ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    let (from, to) = (SLOT_AUTHENTICATION, SLOT_RETIRED_FIRST);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            INS_ASYM_KEYGEN,
            0,
            from,
            &gen_template(ALGO_ECCP256)
        )
        .0,
        Sw::OK
    );
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
        latched: false,
    };
    let mut wanted = [0; MAX_EC_POINT];
    let n = seal::load_ec_key(&dev, &mut fs, key_fid(from))
        .unwrap()
        .public_point(&mut wanted)
        .unwrap();
    fs.meta_add(
        key_fid(from).get(),
        &[
            ALGO_ECCP256,
            PINPOLICY_ONCE,
            TOUCHPOLICY_NEVER,
            ORIGIN_GENERATED,
        ],
    )
    .unwrap();
    fs.delete(pubkey_fid(from)).unwrap();
    fs.put(pubkey_fid(to), &[0x5a; 65]).unwrap();
    let mut fs = Fs::new(fs.into_storage());
    medium.truncate_walk(true);
    fs.scan();
    medium.truncate_walk(false);
    assert_eq!(
        run(&mut app, &mut fs, INS_MOVE_KEY, to, from, &[]),
        (Sw::OK, vec![])
    );
    assert_eq!(medium.value(pubkey_fid(to)), None);
    let (sw, metadata) = run(&mut app, &mut fs, INS_GET_METADATA, 0, to, &[]);
    assert_eq!(sw, Sw::OK);
    assert!(metadata.windows(n).any(|word| word == &wanted[..n]));
}

#[test]
fn every_key_replacement_refuses_a_cache_retirement_failure_before_writing_the_key() {
    let key = rsk_rsa::generate_rsa(&mut RsaRng(&mut TestRng(99)), RSA_FIXTURE_BYTES * 8).unwrap();
    let algo = crate::keygen::rsa_algo_from_size(key.size()).unwrap();
    for operation in [
        Replacement::GenerateEc,
        Replacement::GenerateRsa,
        Replacement::ImportEc,
        Replacement::Move,
        Replacement::FinishRsa,
        Replacement::RetiredEc,
        Replacement::RetiredRsa,
        Replacement::RecreateF9,
    ] {
        let rng = RefCell::new(TestRng(7));
        let presence = RefCell::new(AlwaysConfirm);
        let remove = Rc::new(Cell::new(None));
        let mut fs = Fs::new(RefuseWrite {
            inner: RamStorage::new(),
            refuse: Rc::new(Cell::new(None)),
            refuse_remove: remove.clone(),
        });
        fs.scan();
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
        select(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
        let target = match operation {
            Replacement::Move | Replacement::RetiredEc | Replacement::RetiredRsa => {
                SLOT_RETIRED_FIRST
            }
            Replacement::RecreateF9 => SLOT_ATTESTATION,
            _ => SLOT_AUTHENTICATION,
        };
        if matches!(operation, Replacement::RecreateF9) {
            fs.delete_key(key_fid(target)).unwrap();
        } else {
            assert_eq!(
                run(
                    &mut app,
                    &mut fs,
                    INS_ASYM_KEYGEN,
                    0,
                    SLOT_AUTHENTICATION,
                    &gen_template(ALGO_ECCP256)
                )
                .0,
                Sw::OK
            );
        }
        fs.put(pubkey_fid(target), b"old public point").unwrap();
        fs.put(0xb000, b"neighbor").unwrap();
        let before = value(&mut fs, key_fid(target).get());
        let source = value(&mut fs, key_fid(SLOT_AUTHENTICATION).get());
        let mut metadata = [0; 4 + MAX_EC_POINT];
        let head = fs.meta_find(key_fid(target).get(), &mut metadata);
        remove.set(Some(pubkey_fid(target)));
        let dev = Device {
            serial_hash: &HASH,
            serial_id: &SERIAL,
            otp_key: None,
            latched: false,
        };
        let result = match operation {
            Replacement::GenerateEc => {
                run(
                    &mut app,
                    &mut fs,
                    INS_ASYM_KEYGEN,
                    0,
                    target,
                    &gen_template(ALGO_ECCP256),
                )
                .0
            }
            Replacement::GenerateRsa => {
                run(
                    &mut app,
                    &mut fs,
                    INS_ASYM_KEYGEN,
                    0,
                    target,
                    &gen_template(algo),
                )
                .0
            }
            Replacement::ImportEc => {
                let mut data = vec![0x06, 32];
                data.extend_from_slice(&[0x39; 32]);
                run(
                    &mut app,
                    &mut fs,
                    INS_IMPORT_ASYM,
                    ALGO_ECCP256,
                    target,
                    &data,
                )
                .0
            }
            Replacement::Move => {
                run(
                    &mut app,
                    &mut fs,
                    INS_MOVE_KEY,
                    target,
                    SLOT_AUTHENTICATION,
                    &[],
                )
                .0
            }
            Replacement::FinishRsa => {
                app.rsa_generate_finish(
                    &mut fs,
                    &mut TestRng(17),
                    target,
                    [PINPOLICY_ONCE, TOUCHPOLICY_NEVER],
                    &key,
                    &mut [0; 1024],
                )
                .1
            }
            Replacement::RetiredEc => crate::keygen::generate_retired_ec(
                &dev,
                &mut fs,
                &mut TestRng(17),
                target,
                ALGO_ECCP256,
            )
            .err()
            .unwrap(),
            Replacement::RetiredRsa => {
                crate::keygen::store_retired_rsa(&dev, &mut fs, &mut TestRng(17), target, &key)
                    .err()
                    .unwrap()
            }
            Replacement::RecreateF9 => {
                let mut fresh = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
                Applet::select(&mut fresh, false, &mut fs, &mut ResBuf::new(&mut [0; 256]))
            }
        };
        assert_eq!(
            result,
            Sw::MEMORY_FAILURE,
            "{operation:?}: a refused cache retirement permitted a key write"
        );
        assert_eq!(
            value(&mut fs, key_fid(target).get()),
            before,
            "{operation:?}"
        );
        assert_eq!(
            value(&mut fs, key_fid(SLOT_AUTHENTICATION).get()),
            source,
            "{operation:?}"
        );
        assert_eq!(
            value(&mut fs, pubkey_fid(target)),
            Some(b"old public point".to_vec())
        );
        let mut after = [0; 4 + MAX_EC_POINT];
        assert_eq!(fs.meta_find(key_fid(target).get(), &mut after), head);
        assert_eq!(after, metadata);
        assert_eq!(
            value(&mut fs, 0xb000).as_deref(),
            Some(b"neighbor".as_slice())
        );
    }
}

#[test]
fn a_refused_cache_write_after_generate_or_import_cannot_publish_the_previous_key() {
    for import in [false, true] {
        let rng = RefCell::new(TestRng(7));
        let presence = RefCell::new(AlwaysConfirm);
        let refuse = Rc::new(Cell::new(None));
        let mut fs = Fs::new(RefuseWrite {
            inner: RamStorage::new(),
            refuse: refuse.clone(),
            refuse_remove: Rc::new(Cell::new(None)),
        });
        fs.scan();
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
        select(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
        let slot = SLOT_AUTHENTICATION;
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                INS_ASYM_KEYGEN,
                0,
                slot,
                &gen_template(ALGO_ECCP256)
            )
            .0,
            Sw::OK
        );
        let dev = Device {
            serial_hash: &HASH,
            serial_id: &SERIAL,
            otp_key: None,
            latched: false,
        };
        let mut old = [0; MAX_EC_POINT];
        let old_n = seal::load_ec_key(&dev, &mut fs, key_fid(slot))
            .unwrap()
            .public_point(&mut old)
            .unwrap();
        refuse.set(Some(pubkey_fid(slot)));
        let response = if import {
            let mut data = vec![0x06, 32];
            data.extend_from_slice(&[0x39; 32]);
            run(
                &mut app,
                &mut fs,
                INS_IMPORT_ASYM,
                ALGO_ECCP256,
                slot,
                &data,
            )
        } else {
            run(
                &mut app,
                &mut fs,
                INS_ASYM_KEYGEN,
                0,
                slot,
                &gen_template(ALGO_ECCP256),
            )
        };
        assert_eq!(response.0, Sw::OK);
        refuse.set(None);
        let mut wanted = [0; MAX_EC_POINT];
        let n = seal::load_ec_key(&dev, &mut fs, key_fid(slot))
            .unwrap()
            .public_point(&mut wanted)
            .unwrap();
        assert_ne!(&wanted[..n], &old[..old_n]);
        let (sw, metadata) = run(&mut app, &mut fs, INS_GET_METADATA, 0, slot, &[]);
        assert_eq!(sw, Sw::OK);
        assert!(
            metadata.windows(n).any(|word| word == &wanted[..n]),
            "replacement published the old cache after its refresh was refused"
        );
        assert!(!metadata.windows(old_n).any(|word| word == &old[..old_n]));
    }
}

#[test]
fn f9_recreation_with_a_refused_cache_refresh_keeps_metadata_bound_to_the_new_key() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let refuse = Rc::new(Cell::new(None));
    let mut fs = Fs::new(RefuseWrite {
        inner: RamStorage::new(),
        refuse: refuse.clone(),
        refuse_remove: Rc::new(Cell::new(None)),
    });
    fs.scan();
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    select(&mut app, &mut fs);
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
        latched: false,
    };
    let mut old = [0; MAX_EC_POINT];
    let old_n = seal::load_ec_key(&dev, &mut fs, key_fid(SLOT_ATTESTATION))
        .unwrap()
        .public_point(&mut old)
        .unwrap();
    fs.delete_key(key_fid(SLOT_ATTESTATION)).unwrap();
    refuse.set(Some(pubkey_fid(SLOT_ATTESTATION)));
    let mut fresh = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    select(&mut fresh, &mut fs);
    refuse.set(None);
    let mut wanted = [0; MAX_EC_POINT];
    let n = seal::load_ec_key(&dev, &mut fs, key_fid(SLOT_ATTESTATION))
        .unwrap()
        .public_point(&mut wanted)
        .unwrap();
    assert_ne!(&wanted[..n], &old[..old_n]);
    let (sw, metadata) = run(
        &mut fresh,
        &mut fs,
        INS_GET_METADATA,
        0,
        SLOT_ATTESTATION,
        &[],
    );
    assert_eq!(sw, Sw::OK);
    assert!(
        metadata.windows(n).any(|word| word == &wanted[..n]),
        "F9 recreation published the previous public point"
    );
}

#[test]
fn a_move_without_a_source_cache_never_publishes_the_destination_orphan_point() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    let (from, to) = (SLOT_AUTHENTICATION, SLOT_RETIRED_FIRST);
    let source = PrivKey::from_scalar(Curve::P256, &[0x39; 32]).unwrap();
    let other = PrivKey::from_scalar(Curve::P256, &[0x27; 32]).unwrap();
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
        latched: false,
    };
    seal::store_ec_key(&dev, &mut fs, &mut TestRng(17), key_fid(from), &source).unwrap();
    fs.meta_add(
        key_fid(from).get(),
        &[
            ALGO_ECCP256,
            PINPOLICY_ONCE,
            TOUCHPOLICY_NEVER,
            ORIGIN_IMPORTED,
        ],
    )
    .unwrap();
    fs.delete(pubkey_fid(from)).unwrap();
    let mut expected = [0; MAX_EC_POINT];
    let n = source.public_point(&mut expected).unwrap();
    let mut orphan = [0; MAX_EC_POINT];
    let on = other.public_point(&mut orphan).unwrap();
    assert_ne!(&expected[..n], &orphan[..on]);
    fs.put(pubkey_fid(to), &orphan[..on]).unwrap();
    let sealed = sealed_key(&mut fs, from);
    assert_eq!(
        run(&mut app, &mut fs, INS_MOVE_KEY, to, from, &[]),
        (Sw::OK, vec![])
    );
    assert_eq!(sealed_key(&mut fs, to), sealed);
    assert!(!fs.has_key(key_fid(from)));
    let (sw, metadata) = run(&mut app, &mut fs, INS_GET_METADATA, 0, to, &[]);
    assert_eq!(sw, Sw::OK);
    assert!(
        metadata.windows(n).any(|word| word == &expected[..n]),
        "MOVE published the destination's orphan public point"
    );
    assert!(!metadata.windows(on).any(|word| word == &orphan[..on]));
    verify_pin(&mut app, &mut fs);
    let digest = [0x42; 32];
    let mut challenge = vec![0x7c, 0x24, 0x82, 0, 0x81, 32];
    challenge.extend_from_slice(&digest);
    let (sw, signature) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_ECCP256,
        to,
        &challenge,
    );
    assert_eq!(sw, Sw::OK);
    let body = rsk_sdk::tlv::find_tag(&signature, 0x7c).unwrap();
    let der = rsk_sdk::tlv::find_tag(body, 0x82).unwrap();
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&expected[..n]).unwrap();
    key.verify_prehash(&digest, &p256::ecdsa::Signature::from_der(der).unwrap())
        .unwrap();
}
