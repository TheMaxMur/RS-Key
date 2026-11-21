// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::{TAG_AUTO_EJECT_TIMEOUT, scrub_legacy_lock};
use rsk_fs::cut::{Snap, sweep_recovery};

#[derive(Clone, Copy, Debug)]
enum Change {
    Arm,
    Replace,
    Clear,
}

fn provision(fs: &mut Fs<Snap>, change: Change) {
    persist_touched(
        &SERIAL,
        fs,
        &[
            TAG_USB_ENABLED,
            2,
            0x02,
            0x3B,
            TAG_AUTO_EJECT_TIMEOUT,
            2,
            0x12,
            0x34,
        ],
    )
    .unwrap();
    if !matches!(change, Change::Arm) {
        persist_touched(&SERIAL, fs, &write(None, &[], Some(&CODE))).unwrap();
    }
    fs.put(0xB000, b"other applet").unwrap();
    fs.meta_add(0xB000, b"other metadata").unwrap();
}

fn request(change: Change, recovery: bool, fs: &mut Fs<Snap>) -> Vec<u8> {
    let new = match change {
        Change::Arm => &CODE,
        Change::Replace => &OTHER,
        Change::Clear => &CLEAR,
    };
    let unlock = if recovery {
        // The owner retains both submitted codes; a reply lost after commit
        // takes the new one, and a cut before commit still takes the old one.
        if lock_change(&SERIAL, fs, &write(Some(new), &[], None)).is_ok() {
            Some(new.as_slice())
        } else {
            Some(CODE.as_slice())
        }
    } else if matches!(change, Change::Arm) {
        None
    } else {
        Some(CODE.as_slice())
    };
    write(unlock, &FIDO_ONLY, Some(new))
}

fn check(fs: &mut Fs<Snap>, change: Change, first: u32, second: u32) {
    assert_eq!(
        read_enabled_caps(fs),
        CAP_FIDO2,
        "{change:?}: {first}/{second}"
    );
    let mut bytes = [0; 64];
    let n = fs.read(EF_DEV_CONF, &mut bytes).unwrap();
    assert_eq!(
        tag_value(&bytes[..n], TAG_AUTO_EJECT_TIMEOUT),
        Some(&[0x12, 0x34][..])
    );
    assert_eq!(fs.read(0xB000, &mut bytes), Some(b"other applet".len()));
    assert_eq!(&bytes[..b"other applet".len()], b"other applet");
    let n = fs.meta_find(0xB000, &mut bytes).unwrap();
    assert_eq!(&bytes[..n], b"other metadata");
    let generation = fs.write_gen();
    if matches!(change, Change::Clear) {
        assert_eq!(ensure_unlocked(fs), Ok(()));
    } else {
        assert_eq!(ensure_unlocked(fs), Err(DevConfError::Locked));
        assert_eq!(
            persist_touched(&SERIAL, fs, &FIDO_ONLY),
            Err(DevConfError::Locked)
        );
        let wrong = if matches!(change, Change::Arm) {
            &OTHER
        } else {
            &CODE
        };
        assert_eq!(
            persist_touched(&SERIAL, fs, &write(Some(wrong), &FIDO_ONLY, None)),
            Err(DevConfError::WrongCode)
        );
    }
    let replay = request(change, true, fs);
    assert_eq!(persist_touched(&SERIAL, fs, &replay), Ok(()));
    assert_eq!(
        fs.write_gen(),
        generation,
        "settled replay rewrote the store"
    );
}

#[test]
fn configuration_and_lock_changes_survive_a_second_cut_during_owner_replay() {
    for change in [Change::Arm, Change::Replace, Change::Clear] {
        sweep_recovery(
            |fs| provision(fs, change),
            |fs, ()| {
                let body = request(change, false, fs);
                let _ = persist_touched(&SERIAL, fs, &body);
            },
            |fs| {
                let body = request(change, true, fs);
                let _ = persist_touched(&SERIAL, fs, &body);
            },
            |fs, first, second| check(fs, change, first, second),
        );
    }
}

#[test]
fn legacy_lock_scrubbing_survives_a_second_interrupted_boot() {
    sweep_recovery(
        |fs| {
            let legacy = write(None, &FIDO_ONLY, Some(&CODE));
            fs.put(EF_DEV_CONF, &legacy).unwrap();
            fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
            fs.put(0xB000, b"other applet").unwrap();
        },
        |fs, ()| {
            let _ = scrub_legacy_lock(fs);
        },
        |fs| {
            let _ = scrub_legacy_lock(fs);
        },
        |fs, first, second| {
            let mut bytes = [0; 64];
            assert_eq!(fs.read(EF_DEV_CONF, &mut bytes), Some(FIDO_ONLY.len()));
            assert_eq!(&bytes[..FIDO_ONLY.len()], &FIDO_ONLY, "{first}/{second}");
            assert_eq!(ensure_unlocked(fs), Ok(()));
            assert!(!fs.has_data(rsk_fs::EF_HARDENED));
            assert_eq!(fs.read(0xB000, &mut bytes), Some(b"other applet".len()));
            assert_eq!(&bytes[..b"other applet".len()], b"other applet");
            let generation = fs.write_gen();
            assert_eq!(scrub_legacy_lock(fs), Ok(()));
            assert_eq!(fs.write_gen(), generation);
        },
    );
}
