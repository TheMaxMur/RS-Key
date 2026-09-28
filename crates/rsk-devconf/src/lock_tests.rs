// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::{
    CAP_FIDO2, CAP_OATH, EF_DEV_CONF, TAG_USB_ENABLED, config_tlv, dev_conf_unchanged,
    persist_dev_conf, persist_touched, read_enabled_caps,
};
use rsk_fs::storage::ram::RamStorage;
use rsk_sdk::{ResBuf, Sw};

const SERIAL: [u8; 4] = [0x01, 0x23, 0x45, 0x67];
const CODE: [u8; LOCK_CODE_LEN] = [0xA5; LOCK_CODE_LEN];
const OTHER: [u8; LOCK_CODE_LEN] = [0x5A; LOCK_CODE_LEN];
/// ykman's `--clear`: a new code of sixteen zero bytes.
const CLEAR: [u8; LOCK_CODE_LEN] = [0; LOCK_CODE_LEN];
const FIDO_ONLY: [u8; 4] = [TAG_USB_ENABLED, 2, 0x02, 0x00];

fn fs() -> Fs<RamStorage> {
    Fs::new(RamStorage::new())
}

/// A DeviceConfig blob laid out as yubikit's `get_bytes` lays it out: `UNLOCK`
/// first, then the fields, then the new code in `CONFIG_LOCK`.
fn write(unlock: Option<&[u8]>, fields: &[u8], new_code: Option<&[u8]>) -> Vec<u8> {
    let mut blob = Vec::new();
    if let Some(code) = unlock {
        blob.extend_from_slice(&[TAG_CONFIG_UNLOCK, code.len() as u8]);
        blob.extend_from_slice(code);
    }
    blob.extend_from_slice(fields);
    if let Some(code) = new_code {
        blob.extend_from_slice(&[TAG_CONFIG_LOCK, code.len() as u8]);
        blob.extend_from_slice(code);
    }
    blob
}

/// A device whose owner ran `ykman config usb` and then `set-lock-code`.
fn locked_fs() -> Fs<RamStorage> {
    let mut fs = fs();
    persist_touched(&SERIAL, &mut fs, &[TAG_USB_ENABLED, 2, 0x02, 0x3B]).unwrap();
    persist_touched(&SERIAL, &mut fs, &write(None, &[], Some(&CODE))).unwrap();
    fs
}

fn read_config(fs: &mut Fs<RamStorage>) -> Vec<u8> {
    let mut body = [0u8; 64];
    let mut res = ResBuf::new(&mut body);
    assert_eq!(config_tlv(&SERIAL, fs, &mut res), Sw::OK);
    res.as_slice().to_vec()
}

/// READ CONFIG's `CONFIG_LOCK` byte.
fn reported(fs: &mut Fs<RamStorage>) -> u8 {
    let body = read_config(fs);
    match tag_value(&body[1..], TAG_CONFIG_LOCK) {
        Some(&[byte]) => byte,
        other => panic!("CONFIG_LOCK is {other:02x?}"),
    }
}

fn record(fs: &mut Fs<RamStorage>, fid: u16) -> Option<Vec<u8>> {
    let mut buf = [0u8; 64];
    fs.read(fid, &mut buf).map(|n| buf[..n].to_vec())
}

/// Both records a write can move.
fn records(fs: &mut Fs<RamStorage>) -> [Option<Vec<u8>>; 2] {
    [record(fs, EF_DEV_CONF), record(fs, EF_DEV_LOCK)]
}

#[test]
fn a_locked_configuration_refuses_a_write_without_its_code() {
    let mut fs = locked_fs();
    let before = records(&mut fs);
    assert_eq!(
        persist_touched(&SERIAL, &mut fs, &FIDO_ONLY),
        Err(DevConfError::Locked)
    );
    assert_eq!(records(&mut fs), before, "a refused write moved a record");
}

#[test]
fn a_wrong_code_is_refused_and_changes_nothing() {
    let mut fs = locked_fs();
    let before = records(&mut fs);
    for code in [&OTHER[..], &CLEAR[..]] {
        assert_eq!(
            persist_touched(&SERIAL, &mut fs, &write(Some(code), &FIDO_ONLY, None)),
            Err(DevConfError::WrongCode),
            "{code:02x?} opened the lock"
        );
    }
    assert_eq!(records(&mut fs), before, "a refused write moved a record");
}

#[test]
fn its_code_opens_the_lock_for_one_write_and_leaves_it_set() {
    let mut fs = locked_fs();
    let oath_only = [TAG_USB_ENABLED, 2, 0x00, 0x20];
    persist_touched(&SERIAL, &mut fs, &write(Some(&CODE), &oath_only, None)).unwrap();
    assert_eq!(read_enabled_caps(&mut fs), CAP_OATH);
    assert_eq!(
        reported(&mut fs),
        0x01,
        "a write through the lock cleared it"
    );
    assert_eq!(
        persist_touched(&SERIAL, &mut fs, &FIDO_ONLY),
        Err(DevConfError::Locked)
    );
}

#[test]
fn a_code_of_zeroes_clears_the_lock() {
    let mut fs = locked_fs();
    persist_touched(&SERIAL, &mut fs, &write(Some(&CODE), &[], Some(&CLEAR))).unwrap();
    assert_eq!(reported(&mut fs), 0x00);
    assert_eq!(
        record(&mut fs, EF_DEV_LOCK),
        None,
        "the verifier outlived the lock"
    );
    persist_touched(&SERIAL, &mut fs, &FIDO_ONLY).unwrap();
}

#[test]
fn a_new_code_takes_the_old_one_and_replaces_it() {
    let mut fs = locked_fs();
    assert_eq!(
        persist_touched(&SERIAL, &mut fs, &write(None, &[], Some(&OTHER))),
        Err(DevConfError::Locked)
    );
    persist_touched(&SERIAL, &mut fs, &write(Some(&CODE), &[], Some(&OTHER))).unwrap();
    assert_eq!(
        persist_touched(&SERIAL, &mut fs, &write(Some(&CODE), &FIDO_ONLY, None)),
        Err(DevConfError::WrongCode),
        "the replaced code still opens the lock"
    );
    persist_touched(&SERIAL, &mut fs, &write(Some(&OTHER), &FIDO_ONLY, None)).unwrap();
}

/// Both arms of `config_tlv`: the tail it synthesises when no record is stored, and
/// the one it appends to an echoed record.
#[test]
fn read_config_reports_whether_a_code_is_set() {
    let mut fs = fs();
    assert_eq!(reported(&mut fs), 0x00, "a fresh device reads locked");
    persist_touched(&SERIAL, &mut fs, &write(None, &[], Some(&CODE))).unwrap();
    assert!(record(&mut fs, EF_DEV_CONF).unwrap_or_default().is_empty());
    assert_eq!(reported(&mut fs), 0x01, "synthesised tail");
    persist_touched(&SERIAL, &mut fs, &write(Some(&CODE), &FIDO_ONLY, None)).unwrap();
    assert!(!record(&mut fs, EF_DEV_CONF).unwrap_or_default().is_empty());
    assert_eq!(reported(&mut fs), 0x01, "echoed record");
    persist_touched(&SERIAL, &mut fs, &write(Some(&CODE), &[], Some(&CLEAR))).unwrap();
    assert_eq!(reported(&mut fs), 0x00);
}

#[test]
fn the_code_is_neither_kept_nor_sent() {
    let mut fs = locked_fs();
    let [conf, lock] = records(&mut fs);
    let lock = lock.expect("a set lock keeps a record");
    for bytes in [conf.unwrap_or_default(), lock, read_config(&mut fs)] {
        assert!(
            !bytes.windows(LOCK_CODE_LEN).any(|w| w == CODE),
            "the code itself went into {bytes:02x?}"
        );
    }
}

/// The lock is asked before the idempotent short-circuits, as a YubiKey refuses a
/// no-op without its code too.
#[test]
fn a_locked_device_refuses_even_a_write_that_changes_nothing() {
    let mut fs = locked_fs();
    let same = [TAG_USB_ENABLED, 2, 0x02, 0x3B];
    assert_eq!(
        persist_touched(&SERIAL, &mut fs, &same),
        Err(DevConfError::Locked)
    );
    assert!(
        !dev_conf_unchanged(&SERIAL, &mut fs, &same),
        "the replay check answered for a write the lock refuses"
    );
    assert!(
        dev_conf_unchanged(&SERIAL, &mut fs, &write(Some(&CODE), &same, None)),
        "an authorised no-op must still skip the flash and the journal"
    );
}

#[test]
fn a_write_that_moves_the_lock_is_never_a_replay() {
    let mut fs = fs();
    // A stored record, so the config half of every request below is a replay.
    persist_touched(&SERIAL, &mut fs, &FIDO_ONLY).unwrap();
    let set = write(None, &[], Some(&CODE));
    assert!(
        !dev_conf_unchanged(&SERIAL, &mut fs, &set),
        "setting a code"
    );
    persist_touched(&SERIAL, &mut fs, &set).unwrap();
    assert!(
        dev_conf_unchanged(&SERIAL, &mut fs, &write(Some(&CODE), &[], Some(&CODE))),
        "setting the code the lock already has is a replay"
    );
    assert!(
        !dev_conf_unchanged(&SERIAL, &mut fs, &write(Some(&CODE), &[], Some(&CLEAR))),
        "clearing the lock"
    );
}

#[test]
fn a_code_of_another_width_is_refused() {
    let mut fs = fs();
    let long = [0xA5; LOCK_CODE_LEN + 1];
    for blob in [
        write(None, &[], Some(&CODE[1..])),
        write(Some(&long), &FIDO_ONLY, None),
    ] {
        assert_eq!(
            persist_touched(&SERIAL, &mut fs, &blob),
            Err(DevConfError::BadTlv)
        );
    }
    assert_eq!(records(&mut fs), [None, None]);
}

#[test]
fn a_lock_record_no_code_can_be_checked_against_stays_locked() {
    let unknown_format = [0x02; LOCK_RECORD_LEN];
    let short = [LOCK_FORMAT; 5];
    let long = [LOCK_FORMAT; LOCK_RECORD_LEN + 7];
    for rec in [&unknown_format[..], &short[..], &long[..], &[][..]] {
        let mut fs = fs();
        fs.put(EF_DEV_LOCK, rec).unwrap();
        assert_eq!(reported(&mut fs), 0x01, "{rec:02x?} read unlocked");
        assert_eq!(
            persist_touched(&SERIAL, &mut fs, &FIDO_ONLY),
            Err(DevConfError::Locked)
        );
        assert_eq!(
            persist_touched(&SERIAL, &mut fs, &write(Some(&CODE), &[], Some(&CLEAR))),
            Err(DevConfError::WrongCode),
            "{rec:02x?} opened for a code"
        );
    }
}

#[test]
fn an_unanswered_lock_probe_refuses_the_write_and_reads_locked() {
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    persist_touched(&SERIAL, &mut fs, &write(None, &[], Some(&CODE))).unwrap();
    let before = medium.value(EF_DEV_CONF);
    medium.stick(Some(EF_DEV_LOCK));
    assert_eq!(
        persist_touched(&SERIAL, &mut fs, &write(Some(&CODE), &FIDO_ONLY, None)),
        Err(DevConfError::Store)
    );
    assert_eq!(
        medium.value(EF_DEV_CONF),
        before,
        "a write went past an unread lock"
    );
    let mut body = [0u8; 64];
    let mut res = ResBuf::new(&mut body);
    assert_eq!(config_tlv(&SERIAL, &mut fs, &mut res), Sw::OK);
    assert_eq!(
        tag_value(&res.as_slice()[1..], TAG_CONFIG_LOCK),
        Some(&[0x01][..])
    );
}

#[test]
fn the_serial_salts_the_verifier() {
    let mut fs = locked_fs();
    let another_device = [0x01, 0x23, 0x45, 0x68];
    assert_eq!(
        persist_touched(
            &another_device,
            &mut fs,
            &write(Some(&CODE), &FIDO_ONLY, None)
        ),
        Err(DevConfError::WrongCode),
        "two serials derived one verifier from one code"
    );
}

/// A build before 0.4.5 stored the code as `0A 10 <code>` in `EF_DEV_CONF` and
/// enforced nothing, and every build since reported that device unlocked; honouring
/// the stale code now would lock its owner out of a device they were told was open.
#[test]
fn a_code_an_old_build_left_in_the_record_is_not_a_lock() {
    let mut fs = fs();
    let mut legacy = std::vec![TAG_CONFIG_LOCK, 16];
    legacy.extend_from_slice(&CODE);
    legacy.extend_from_slice(&[TAG_USB_ENABLED, 2, 0x02, 0x3B]);
    fs.put(EF_DEV_CONF, &legacy).unwrap();
    assert_eq!(reported(&mut fs), 0x00);
    persist_touched(&SERIAL, &mut fs, &FIDO_ONLY).unwrap();
}

/// A write that narrows the enabled set and sets a code, cut at every mutation. The
/// record lands before the lock, so no cut leaves a lock over the set it came with,
/// and the same request, retried with no code, completes whatever a cut left.
#[test]
fn a_torn_write_never_leaves_a_lock_over_the_old_set() {
    let request = write(None, &FIDO_ONLY, Some(&CODE));
    rsk_fs::cut::sweep(
        || {
            let (cut, medium) = rsk_fs::storage::faults::Cut::new();
            let mut fs = Fs::new(cut);
            persist_touched(&SERIAL, &mut fs, &[TAG_USB_ENABLED, 2, 0x02, 0x3B]).unwrap();
            (fs, medium)
        },
        |fs| persist_touched(&SERIAL, fs, &request).is_ok(),
        |fs, budget, completed, medium| {
            let narrowed = read_enabled_caps(fs) == CAP_FIDO2;
            let locked = lock_reported(fs) == 0x01;
            assert!(
                narrowed || !locked,
                "budget {budget}: a lock landed over the set it came with — {:?}",
                medium.ops()
            );
            if completed {
                assert!(narrowed && locked, "budget {budget}: reported done, is not");
                return;
            }
            assert_eq!(
                persist_touched(&SERIAL, fs, &request),
                Ok(()),
                "budget {budget}: the retry was refused — {:?}",
                medium.ops()
            );
        },
    );
}

/// The device-wide wipe removes both records last (`gates_wiped_last`): a torn wipe
/// that took the lock first would leave the OTP slots behind an open configuration.
#[test]
fn both_records_are_gates_for_the_device_wide_wipe() {
    assert!(crate::is_devconf_gate_fid(EF_DEV_CONF));
    assert!(crate::is_devconf_gate_fid(EF_DEV_LOCK));
}

/// A lock set where none is set takes a touch, on every writer: from a hostile host
/// it shuts the owner out of every config change until a factory wipe. Refused, it
/// stores neither the lock nor the fields the write carried.
#[test]
fn a_lock_set_where_none_is_takes_a_touch() {
    let mut fs = fs();
    let request = write(None, &FIDO_ONLY, Some(&CODE));
    let mut asked = 0;
    assert_eq!(
        persist_dev_conf(&SERIAL, &mut fs, &request, &mut || {
            asked += 1;
            false
        }),
        Err(DevConfError::NotConfirmed)
    );
    assert_eq!(asked, 1);
    assert_eq!(
        records(&mut fs),
        [None, None],
        "a refused lock stored a record"
    );
    assert!(!dev_conf_unchanged(&SERIAL, &mut fs, &request));

    persist_dev_conf(&SERIAL, &mut fs, &request, &mut || true).unwrap();
    assert_eq!(
        (reported(&mut fs), read_enabled_caps(&mut fs)),
        (0x01, CAP_FIDO2)
    );
}

/// Only arming a lock asks: a write through a set lock carries its code, and a write
/// with no code to set asks for nothing, which is what keeps every other write
/// YubiKey-shaped.
#[test]
fn no_other_write_asks_for_a_touch() {
    let mut never = || -> bool { panic!("a write that sets no new lock asked for a touch") };
    let mut fs = fs();
    persist_dev_conf(&SERIAL, &mut fs, &FIDO_ONLY, &mut never).unwrap();
    persist_dev_conf(
        &SERIAL,
        &mut fs,
        &write(None, &[], Some(&CLEAR)),
        &mut never,
    )
    .unwrap();
    assert_eq!(reported(&mut fs), 0x00);

    let mut fs = locked_fs();
    for request in [
        write(Some(&CODE), &FIDO_ONLY, None),
        write(Some(&CODE), &[], Some(&CODE)),
        write(Some(&CODE), &[], Some(&OTHER)),
        write(Some(&OTHER), &[], Some(&CLEAR)),
    ] {
        persist_dev_conf(&SERIAL, &mut fs, &request, &mut never).unwrap();
    }
    assert_eq!(reported(&mut fs), 0x00);
}

// The read-fault sweep lives in its own file; it needs this module's fixtures.
#[path = "lock_reads_tests.rs"]
mod reads;
