// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::cut::sweep_restarts;
use rsk_fs::storage::faults::{Cut, CutMedium};

fn fixture() -> (Fs<Cut>, CutMedium) {
    let (storage, medium) = Cut::new();
    let mut fs = Fs::new(storage);
    fs.scan();
    fs.put(0xB000, b"another applet").unwrap();
    fs.meta_add(0xB000, b"metadata").unwrap();
    (fs, medium)
}

fn check(fs: &mut Fs<Cut>, medium: &CutMedium) {
    let mut decoded = Vec::new();
    for (fid, pin) in [(EF_DEK_PW1, PW1_DEFAULT), (EF_DEK_PW3, PW3_DEFAULT)] {
        let mut record = [0; DEK_FILE_SIZE];
        assert_eq!(fs.read_key(fid, &mut record), Some(DEK_FILE_SIZE));
        assert_eq!(record[0], DEK_FORMAT_V3);
        let session = dev().pin_derive_session(pin);
        let mut dek = [0; DEK_SIZE];
        assert_eq!(
            dev().decrypt_with_aad(session.expose(), &record[1..], PinKdf::V2, &mut dek),
            Ok(DEK_SIZE)
        );
        decoded.push(dek);
    }
    assert_eq!(decoded[0], decoded[1]);
    assert!(!fs.has_data(EF_RC));
    assert_eq!(rc_counter(fs), 0);
    let generation = fs.write_gen();
    scan_files(&dev(), fs, &mut CountRng(200)).unwrap();
    assert_eq!(fs.write_gen(), generation);
    assert_eq!(
        medium.value(0xB000).as_deref(),
        Some(&b"another applet"[..])
    );
    let mut meta = [0; 8];
    assert_eq!(fs.meta_find(0xB000, &mut meta), Some(8));
    assert_eq!(&meta, b"metadata");
}

#[test]
fn initialization_finishes_after_both_initialization_boots_are_interrupted() {
    assert!(sweep_restarts(
        fixture,
        |fs| scan_files(&dev(), fs, &mut CountRng(0)).is_ok(),
        |fs| {
            let _ = scan_files(&dev(), fs, &mut CountRng(91));
        },
        |fs, _, _, _, medium| check(fs, medium)
    ));
}

#[test]
fn supported_boot_repairs_can_be_interrupted_twice_without_replacing_the_dek() {
    for obsolete_code in [false, true] {
        let provision = || {
            let (mut fs, medium) = fixture();
            scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
            let mut status = PW_STATUS_LEGACY.to_vec();
            status[1..4].fill(6);
            fs.put(EF_PW_PRIV, &status).unwrap();
            fs.put(EF_SEX, b"0").unwrap();
            if obsolete_code {
                put_pin_verifier(&mut fs, &dev(), EF_RC, PW3_DEFAULT).unwrap();
                let mut wrapper = [0; DEK_FILE_SIZE];
                assert_eq!(fs.read_key(EF_DEK_PW3, &mut wrapper), Some(DEK_FILE_SIZE));
                fs.put_key(EF_DEK_RC, rsk_fs::Sealed::wrap(&wrapper))
                    .unwrap();
            }
            (fs, medium)
        };
        let (_, reference) = provision();
        let identity = reference.value(EF_DEK_PW3.get());
        assert!(sweep_restarts(
            provision,
            |fs| scan_files(&dev(), fs, &mut CountRng(7)).is_ok(),
            |fs| {
                let _ = scan_files(&dev(), fs, &mut CountRng(91));
            },
            |fs, _, _, _, medium| {
                check(fs, medium);
                assert_eq!(medium.value(EF_DEK_PW3.get()), identity);
                assert_eq!(medium.value(EF_SEX).as_deref(), Some(&b"9"[..]));
                assert!(!fs.has_key(EF_DEK_RC));
            }
        ));
    }
}

#[test]
fn orphan_cleanup_preserves_a_wrapper_that_the_public_reset_code_cannot_open() {
    for wrong_code in [false, true] {
        let (mut fs, medium) = fixture();
        scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
        let session = dev().pin_derive_session(if wrong_code { b"87654321" } else { PW3_DEFAULT });
        let mut wrapper = [0; DEK_FILE_SIZE];
        wrapper[0] = DEK_FORMAT_V3;
        dev()
            .encrypt_with_aad(
                session.expose(),
                &[0x5A; DEK_SIZE],
                PinKdf::V2,
                &[7; 12],
                &mut wrapper[1..],
            )
            .unwrap();
        fs.put_key(EF_DEK_RC, rsk_fs::Sealed::wrap(&wrapper))
            .unwrap();
        scan_files(&dev(), &mut fs, &mut CountRng(91)).unwrap();
        assert_eq!(
            medium.value(EF_DEK_RC.get()),
            wrong_code.then(|| wrapper.to_vec())
        );
        assert_eq!(rc_counter(&mut fs), 0);
    }
}

#[test]
fn public_orphan_identification_checks_both_root_generations_and_authentication() {
    let otp = [0x55; 32];
    let current = Device {
        otp_key: Some(&otp),
        ..dev()
    };
    for arm in [dev(), current] {
        for invalid in 0..4 {
            let (mut fs, medium) = fixture();
            scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
            let session = arm.pin_derive_session(PW3_DEFAULT);
            let mut wrapper = [0; DEK_FILE_SIZE];
            wrapper[0] = DEK_FORMAT_V3;
            arm.encrypt_with_aad(
                session.expose(),
                &[0x5A; DEK_SIZE],
                PinKdf::V2,
                &[7; 12],
                &mut wrapper[1..],
            )
            .unwrap();
            let n = match invalid {
                0 => DEK_FILE_SIZE,
                1 => {
                    wrapper[DEK_FILE_SIZE - 1] ^= 1;
                    DEK_FILE_SIZE
                }
                2 => DEK_FILE_SIZE - 1,
                3 => {
                    wrapper[0] = 0;
                    DEK_FILE_SIZE
                }
                _ => unreachable!(),
            };
            fs.put_key(EF_DEK_RC, rsk_fs::Sealed::wrap(&wrapper[..n]))
                .unwrap();
            fs.put_key(
                EF_DEK_STAGE_RC,
                rsk_fs::Sealed::wrap(b"pending owner change"),
            )
            .unwrap();
            let pw3 = medium.value(EF_DEK_PW3.get());
            scan_files(&current, &mut fs, &mut CountRng(91)).unwrap();
            assert_eq!(
                medium.value(EF_DEK_RC.get()),
                (invalid != 0).then(|| wrapper[..n].to_vec())
            );
            assert_eq!(medium.value(EF_DEK_PW3.get()), pw3);
            assert_eq!(
                medium.value(EF_DEK_STAGE_RC.get()).as_deref(),
                Some(&b"pending owner change"[..])
            );
            assert_eq!(rc_counter(&mut fs), 0);
        }
    }
}

#[test]
fn an_unread_orphan_does_not_prevent_neutralizing_the_absent_reference_retry_counter() {
    let (storage, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(storage);
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    let mut wrapper = [0; DEK_FILE_SIZE];
    fs.read_key(EF_DEK_PW3, &mut wrapper).unwrap();
    fs.put_key(EF_DEK_RC, rsk_fs::Sealed::wrap(&wrapper))
        .unwrap();
    fs.put(EF_PW_PRIV, PW_STATUS_LEGACY).unwrap();
    medium.stick(Some(EF_DEK_RC.get()));
    scan_files(&dev(), &mut fs, &mut CountRng(91)).unwrap();
    medium.stick(None);
    assert_eq!(medium.value(EF_DEK_RC.get()), Some(wrapper.to_vec()));
    let mut status = [0; 7];
    fs.read(EF_PW_PRIV, &mut status).unwrap();
    assert_eq!(status[pw_retry_idx(EF_RC)], 0);
}
