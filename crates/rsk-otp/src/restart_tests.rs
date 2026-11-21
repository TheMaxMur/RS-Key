// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::cut::sweep_restarts;
use rsk_fs::storage::faults::CutMedium;

const NEIGHBOR: u16 = 0xB000;
const CODE: [u8; ACC_CODE_SIZE] = [0x5A; ACC_CODE_SIZE];

fn device() -> Device<'static> {
    Device {
        serial_hash: &SERIAL_HASH,
        serial_id: &SERIAL,
        otp_key: None,
        latched: false,
    }
}

fn empty() -> (Fs<Cut>, CutMedium) {
    let (storage, medium) = Cut::new();
    let mut fs = Fs::new(storage);
    fs.scan();
    fs.put(NEIGHBOR, b"another applet").unwrap();
    fs.meta_add(NEIGHBOR, b"metadata").unwrap();
    (fs, medium)
}

fn send(fs: &mut Fs<Cut>, raw: &[u8]) -> Sw {
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &touch);
    select(&mut app, fs);
    run(&mut app, fs, raw).0
}

fn boot(fs: &mut Fs<Cut>) {
    migrate_seal(&device(), fs, &mut CountRng(91));
    let rng = RefCell::new(CountRng(9));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &touch);
    select(&mut app, fs);
}

fn plain(fs: &mut Fs<Cut>, fid: u16) -> Option<Vec<u8>> {
    let mut record = SlotRecord::vacant();
    record
        .try_read(&device(), fs, fid)
        .unwrap()
        .map(|_| record.stored().to_vec())
}

fn plant(fs: &mut Fs<Cut>, fid: u16, label: u8) {
    let cfg = build_config(&[label; 6], &[label; 6], &[label; 16], &CODE, 0, 0, 0);
    let mut raw = cfg.to_vec();
    raw.extend([0, label, 0, 0, 0, 0, 0, 0]);
    assert!(seal::seal_put(
        &device(),
        fs,
        &mut CountRng(7),
        KeyFid::new(fid),
        &SlotRecord::from_bytes(&raw).unwrap()
    ));
}

fn retained(fs: &mut Fs<Cut>, medium: &CutMedium) {
    assert_eq!(
        medium.value(NEIGHBOR).as_deref(),
        Some(&b"another applet"[..])
    );
    let mut meta = [0; 8];
    assert_eq!(fs.meta_find(NEIGHBOR, &mut meta), Some(8));
    assert_eq!(&meta, b"metadata");
}

#[test]
fn configure_update_and_delete_keep_whole_records_and_access_gates_across_two_boots() {
    for (slot, dedicated) in [(0, false), (1, false), (1, true), (2, false), (3, false)] {
        let fid = EF_OTP_SLOT1 + u16::from(slot);
        for operation in [P1_CONFIG_SLOT1, P1_UPDATE_SLOT1] {
            for delete in [false, true] {
                if delete && operation != P1_CONFIG_SLOT1 {
                    continue;
                }
                let cfg = if delete {
                    [0; CONFIG_SIZE]
                } else {
                    build_config(b"newpub", &[9; 6], &[9; 16], &CODE, 1, TKT_APPEND_CR, 0)
                };
                let wire = if dedicated {
                    if operation == P1_CONFIG_SLOT1 {
                        P1_CONFIG_SLOT2
                    } else {
                        P1_UPDATE_SLOT2
                    }
                } else {
                    operation
                };
                let raw = otp_apdu(
                    wire,
                    if dedicated { 0 } else { slot },
                    &[&cfg[..], &CODE].concat(),
                );
                let provision = || {
                    let (mut fs, medium) = empty();
                    plant(&mut fs, fid, 3);
                    (fs, medium)
                };
                let (mut reference, _) = provision();
                let before = plain(&mut reference, fid);
                assert_eq!(send(&mut reference, &raw), Sw::OK);
                let after = plain(&mut reference, fid);
                assert_ne!(before, after);
                if operation == P1_UPDATE_SLOT1 {
                    let (old, new) = (before.as_ref().unwrap(), after.as_ref().unwrap());
                    assert_eq!(&new[..OFF_ACC_CODE], &old[..OFF_ACC_CODE]);
                    assert_eq!(&new[CONFIG_SIZE..], &old[CONFIG_SIZE..]);
                }
                assert!(!sweep_restarts(
                    provision,
                    |fs| send(fs, &raw) == Sw::OK,
                    boot,
                    |fs, _, second, completed, medium| {
                        assert_eq!(second, 0);
                        let stored = plain(fs, fid);
                        assert!(stored == before || stored == after);
                        if completed {
                            assert_eq!(stored, after);
                        }
                        if stored.is_some() {
                            let refused = otp_apdu(
                                P1_CONFIG_SLOT1,
                                slot,
                                &[&[0; CONFIG_SIZE][..], &[0; ACC_CODE_SIZE]].concat(),
                            );
                            assert_eq!(send(fs, &refused), Sw::SECURITY_STATUS_NOT_SATISFIED);
                            assert_eq!(plain(fs, fid), stored);
                        }
                        retained(fs, medium);
                    }
                ));
            }
        }
    }
}

#[test]
fn creating_each_slot_is_atomic_and_does_not_program_its_neighbors() {
    for slot in 0..SLOT_COUNT {
        let fid = EF_OTP_SLOT1 + u16::from(slot);
        let cfg = build_config(b"newpub", &[9; 6], &[9; 16], &CODE, 0, 0, 0);
        let raw = otp_apdu(P1_CONFIG_SLOT1, slot, &cfg);
        let (mut reference, _) = empty();
        assert_eq!(send(&mut reference, &raw), Sw::OK);
        let after = plain(&mut reference, fid).unwrap();
        assert!(!sweep_restarts(
            empty,
            |fs| send(fs, &raw) == Sw::OK,
            boot,
            |fs, _, _, completed, medium| {
                let stored = plain(fs, fid);
                assert!(stored.is_none() || stored.as_ref() == Some(&after));
                if completed {
                    assert_eq!(stored.as_ref(), Some(&after));
                }
                for other in EF_OTP_SLOT1..=EF_OTP_SLOT_LAST {
                    if other != fid {
                        assert!(plain(fs, other).is_none());
                    }
                }
                retained(fs, medium);
            }
        ));
    }
}

#[test]
fn swap_retains_only_the_documented_prefix_states_without_swapping_again_on_boot() {
    for (fa, fb) in [
        (EF_OTP_SLOT1, EF_OTP_SLOT2),
        (EF_OTP_SLOT1 + 2, EF_OTP_SLOT2 + 2),
    ] {
        for (have_a, have_b) in [(true, true), (true, false), (false, true)] {
            let provision = || {
                let (mut fs, medium) = empty();
                if have_a {
                    plant(&mut fs, fa, 3);
                }
                if have_b {
                    plant(&mut fs, fb, 7);
                }
                (fs, medium)
            };
            let (mut reference, _) = provision();
            let (a, b) = (plain(&mut reference, fa), plain(&mut reference, fb));
            let allowed = [
                (a.clone(), b.clone()),
                (b.clone(), b.clone()),
                (b.clone(), a.clone()),
            ];
            assert!(!sweep_restarts(
                provision,
                |fs| send(
                    fs,
                    &otp_apdu(
                        P1_SWAP,
                        0,
                        &[
                            &[
                                u8::try_from(fa - EF_OTP_SLOT1).unwrap(),
                                u8::try_from(fb - EF_OTP_SLOT2).unwrap()
                            ][..],
                            &CODE
                        ]
                        .concat()
                    )
                ) == Sw::OK,
                boot,
                |fs, first, _, completed, medium| {
                    let now = (plain(fs, fa), plain(fs, fb));
                    assert!(allowed.contains(&now), "cut {first}: illegal swap prefix");
                    if completed {
                        assert_eq!(now, (b.clone(), a.clone()));
                    }
                    retained(fs, medium);
                }
            ));
        }
    }
}

#[test]
fn typed_counter_writes_survive_two_boots_without_reissuing_the_press() {
    for hotp in [false, true] {
        let rng = RefCell::new(CountRng(7));
        let touch = RefCell::new(AlwaysConfirm);
        let press = |fs: &mut Fs<Cut>| {
            let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &touch);
            app.button_ticket(1, 0, [0; 2], fs, &mut [0; ticket::MAX_TICKET])
                .is_some()
        };
        let provision = || {
            let (mut fs, medium) = empty();
            let cfg = build_config(
                b"public",
                &[1; 6],
                &[0xA1; 16],
                &CODE,
                0,
                if hotp { TKT_OATH_HOTP } else { 0 },
                0,
            );
            assert_eq!(send(&mut fs, &otp_apdu(P1_CONFIG_SLOT1, 0, &cfg)), Sw::OK);
            assert!(press(&mut fs));
            (fs, medium)
        };
        let (mut reference, _) = provision();
        let before = plain(&mut reference, EF_OTP_SLOT1).unwrap();
        assert!(press(&mut reference));
        let after = plain(&mut reference, EF_OTP_SLOT1).unwrap();
        assert_ne!(&before[CONFIG_SIZE..], &after[CONFIG_SIZE..]);
        assert!(!sweep_restarts(
            provision,
            press,
            boot,
            |fs, _, _, completed, medium| {
                let stored = plain(fs, EF_OTP_SLOT1).unwrap();
                assert!(stored == before || stored == after);
                if completed {
                    assert_eq!(stored, after);
                }
                retained(fs, medium);
            }
        ));
    }
}

#[test]
#[cfg(not(feature = "strict-config"))]
fn auxiliary_records_survive_two_boots_even_when_the_command_swallows_a_write_error() {
    for (p1, fid, len) in [
        (P1_NDEF1, EF_OTP_NDEF1, EF_OTP_NDEF_MAX),
        (P1_NDEF2, EF_OTP_NDEF2, EF_OTP_NDEF_MAX),
        (P1_SCAN_MAP, EF_OTP_SCANMAP, SCANMAP_LEN),
        (P1_DEVICE_CONFIG, EF_OTP_DEVCFG, EF_OTP_DEVCFG_MAX),
    ] {
        let before = vec![0x33; len];
        let after = vec![0x55; len];
        let mut body = after.clone();
        body.extend(CODE);
        let raw = otp_apdu(p1, 0, &body);
        let (mut reference, _) = empty();
        plant(&mut reference, EF_OTP_SLOT1, 3);
        reference.put(fid, &before).unwrap();
        assert_eq!(send(&mut reference, &raw), Sw::OK);
        let mut healthy = vec![0; len];
        assert_eq!(reference.read(fid, &mut healthy), Some(len));
        assert_eq!(healthy, after);
        assert!(!sweep_restarts(
            || {
                let (mut fs, medium) = empty();
                plant(&mut fs, EF_OTP_SLOT1, 3);
                fs.put(fid, &before).unwrap();
                (fs, medium)
            },
            |fs| {
                assert_eq!(send(fs, &raw), Sw::OK);
                true
            },
            boot,
            |fs, _, _, _, medium| {
                let now = medium.value(fid).unwrap();
                assert!(now == before || now == after);
                assert_eq!(
                    &plain(fs, EF_OTP_SLOT1).unwrap()[OFF_ACC_CODE..OFF_ACC_CODE + ACC_CODE_SIZE],
                    &CODE
                );
                retained(fs, medium);
            }
        ));
    }
}

#[path = "restart_migration_tests.rs"]
mod migration;
