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
    (fs, medium)
}

fn command(fs: &mut Fs<Cut>, raw: &[u8]) -> (Sw, Vec<u8>) {
    let rng = RefCell::new(LcgRng(7));
    let platform = RefCell::new(FakePlatform::default());
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = RescueApplet::new(
        SERIAL_ID,
        SERIAL_HASH,
        None,
        None,
        &rng,
        &platform,
        &presence,
        KV_TOTAL,
        FLASH_SIZE,
    );
    run(&mut app, fs, raw)
}

#[test]
fn certificate_upload_and_phy_merge_keep_whole_records_through_two_boots() {
    for phy in [false, true] {
        let fid = if phy {
            rsk_phy::EF_PHY
        } else {
            keydev::EF_DEVCERT
        };
        let old = if phy {
            vec![0, 4, 0x12, 0x09, 0xF1, 0xD2, 2, 1, 63]
        } else {
            b"old certificate".to_vec()
        };
        let raw = if phy {
            apdu(0x80, INS_WRITE, 1, 0, &[2, 1, 127])
        } else {
            apdu(0x80, INS_KEYDEV_SIGN, 3, 0, b"new certificate")
        };
        let provision = || {
            let (mut fs, medium) = fixture();
            fs.put(fid, &old).unwrap();
            (fs, medium)
        };
        let (mut reference, medium) = provision();
        assert_eq!(command(&mut reference, &raw).0, Sw::OK);
        let after = medium.value(fid).unwrap();
        assert_ne!(after, old);
        assert!(!sweep_restarts(
            provision,
            |fs| command(fs, &raw).0 == Sw::OK,
            |_| {},
            |fs, _, _, completed, medium| {
                let value = medium.value(fid).unwrap();
                assert!(value == old || value == after);
                if completed {
                    assert_eq!(value, after);
                }
                if phy {
                    assert_eq!(
                        rsk_phy::try_load(fs).unwrap().unwrap().vid_pid,
                        Some((0x1209, 0xF1D2))
                    );
                }
                assert_eq!(
                    medium.value(0xB000).as_deref(),
                    Some(&b"another applet"[..])
                );
            }
        ));
    }
}

#[test]
fn device_key_generation_and_its_second_attempt_keep_a_single_persistent_identity() {
    let raw = apdu(0x80, INS_KEYDEV_SIGN, 2, 0, &[]);
    assert!(sweep_restarts(
        fixture,
        |fs| command(fs, &raw).0 == Sw::OK,
        |fs| {
            let mut record = [0; 64];
            let before = fs
                .try_read_key(keydev::EF_DEVCERT_KEY, &mut record)
                .unwrap()
                .map(|n| record[..n].to_vec());
            let _ = command(fs, &raw);
            if let Some(before) = before {
                let n = fs.read_key(keydev::EF_DEVCERT_KEY, &mut record).unwrap();
                assert_eq!(&record[..n], before);
            }
        },
        |fs, _, _, _, medium| {
            let (sw, first) = command(fs, &raw);
            assert_eq!(sw, Sw::OK);
            assert_eq!(first.len(), 65);
            let generation = fs.write_gen();
            assert_eq!(command(fs, &raw), (Sw::OK, first));
            assert_eq!(fs.write_gen(), generation);
            assert_eq!(
                medium.value(0xB000).as_deref(),
                Some(&b"another applet"[..])
            );
        }
    ));
}
