// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_devconf::raw::{
    EF_DEV_CONF, EF_DEV_LOCK, TAG_AUTO_EJECT_TIMEOUT, TAG_CONFIG_LOCK, TAG_CONFIG_UNLOCK,
    TAG_USB_ENABLED,
};
use rsk_devconf::{CAP_FIDO2, DevConfError, ensure_unlocked, persist_touched, read_enabled_caps};

pub const MODE_PREFIX: u8 = 0xa0;
pub const CASE_COUNT: u8 = 5;

const SERIAL: [u8; 4] = [1, 2, 3, 4];
const OLD_CODE: [u8; 16] = [0xa5; 16];
const NEW_CODE: [u8; 16] = [0x5a; 16];
const CLEAR: [u8; 16] = [0; 16];
const FIDO_ONLY: [u8; 4] = [TAG_USB_ENABLED, 2, 2, 0];
const INITIAL: [u8; 8] = [
    TAG_USB_ENABLED,
    2,
    2,
    0x3b,
    TAG_AUTO_EJECT_TIMEOUT,
    2,
    0x12,
    0x34,
];
const NEIGHBOR: u16 = 0xb001;

#[derive(Clone, Copy, Debug)]
enum Change {
    Arm,
    Replace,
    Clear,
    Merge,
    Legacy,
}

pub struct Outcome {
    pub interrupted: bool,
    pub recovery_interrupted: bool,
    pub operation_stats: sequential_storage::mock_flash::FlashStatsResult,
    pub recovery_stats: sequential_storage::mock_flash::FlashStatsResult,
}

fn blob(unlock: Option<&[u8; 16]>, fields: &[u8], code: Option<&[u8; 16]>) -> Vec<u8> {
    let mut out = Vec::new();
    if let Some(unlock) = unlock {
        out.extend_from_slice(&[TAG_CONFIG_UNLOCK, 16]);
        out.extend_from_slice(unlock);
    }
    out.extend_from_slice(fields);
    if let Some(code) = code {
        out.extend_from_slice(&[TAG_CONFIG_LOCK, 16]);
        out.extend_from_slice(code);
    }
    out
}

fn records(fs: &mut Fs<TortureStorage>) -> [Option<Vec<u8>>; 2] {
    [EF_DEV_CONF, EF_DEV_LOCK].map(|fid| {
        let mut bytes = [0; 128];
        fs.read(fid, &mut bytes).map(|n| bytes[..n].to_vec())
    })
}

fn execute(fs: &mut Fs<TortureStorage>, change: Change, replay: bool) -> Result<(), DevConfError> {
    if matches!(change, Change::Legacy) {
        return rsk_devconf::scrub_legacy_lock(fs);
    }
    let code = match change {
        Change::Arm => Some(&OLD_CODE),
        Change::Replace => Some(&NEW_CODE),
        Change::Clear => Some(&CLEAR),
        Change::Merge | Change::Legacy => None,
    };
    let unlock = if matches!(change, Change::Arm) {
        replay.then_some(&OLD_CODE)
    } else if replay && matches!(change, Change::Replace) {
        match persist_touched(&SERIAL, fs, &blob(Some(&NEW_CODE), &[], None)) {
            Ok(()) => Some(&NEW_CODE),
            Err(DevConfError::WrongCode) => Some(&OLD_CODE),
            Err(error) => return Err(error),
        }
    } else {
        Some(&OLD_CODE)
    };
    persist_touched(&SERIAL, fs, &blob(unlock, &FIDO_ONLY, code))
}

fn partial(
    fs: &mut Fs<TortureStorage>,
    before: &[Option<Vec<u8>>; 2],
    after: &[Option<Vec<u8>>; 2],
) {
    let current = records(fs);
    for index in 0..current.len() {
        assert!(
            current[index] == before[index] || current[index] == after[index],
            "torn config record {index}"
        );
    }
    if before[1] != after[1] && current[1] == after[1] {
        assert_eq!(
            current[0], after[0],
            "lock changed before configuration committed"
        );
    }
}

fn check(fs: &mut Fs<TortureStorage>, change: Change, after: &[Option<Vec<u8>>; 2]) {
    assert_eq!(&records(fs), after);
    let cfg = after[0].as_deref().unwrap();
    assert!(
        cfg.windows(4)
            .any(|entry| entry == [TAG_AUTO_EJECT_TIMEOUT, 2, 0x12, 0x34])
    );
    if !matches!(change, Change::Legacy) {
        assert_eq!(read_enabled_caps(fs), CAP_FIDO2);
    }
    if matches!(change, Change::Clear | Change::Legacy) {
        assert_eq!(ensure_unlocked(fs), Ok(()));
    } else {
        assert_eq!(ensure_unlocked(fs), Err(DevConfError::Locked));
        assert_eq!(
            persist_touched(&SERIAL, fs, &FIDO_ONLY),
            Err(DevConfError::Locked)
        );
        let wrong = if matches!(change, Change::Replace) {
            &OLD_CODE
        } else {
            &NEW_CODE
        };
        assert_eq!(
            persist_touched(&SERIAL, fs, &blob(Some(wrong), &[], None)),
            Err(DevConfError::WrongCode)
        );
    }
    if matches!(change, Change::Legacy) {
        assert!(!fs.has_data(rsk_fs::EF_HARDENED));
    }
}

fn preserved(fs: &mut Fs<TortureStorage>, flash: &Rc<RefCell<Mock>>, counter: &[u8]) {
    assert_eq!(record(fs, NEIGHBOR), b"other applet");
    let mut metadata = [0; 32];
    let n = fs.meta_find(NEIGHBOR, &mut metadata).unwrap();
    assert_eq!(&metadata[..n], b"other metadata");
    assert_eq!(rsk_fido::seed::global_sign_counter(fs), Ok(73));
    assert_eq!(
        &flash.borrow().as_bytes()[COUNTER_RANGE.start as usize..COUNTER_RANGE.end as usize],
        counter
    );
}

fn remount(dev: &mut MockDevice) -> Fs<TortureStorage> {
    dev.shared.flash.borrow_mut().bytes_until_shutoff = None;
    dev.revive();
    let mut fs = dev.boot();
    fs.scan();
    fs
}

pub fn run(data: &[u8]) -> Outcome {
    let change = match data.get(1).copied().unwrap_or(0) % CASE_COUNT {
        0 => Change::Arm,
        1 => Change::Replace,
        2 => Change::Clear,
        3 => Change::Merge,
        _ => Change::Legacy,
    };
    let flash = Rc::new(RefCell::new(Mock::new(WriteCountCheck::Twice, None, true)));
    let mut dev = MockDevice {
        shared: SharedMock {
            flash: flash.clone(),
            dead: Rc::new(Cell::new(false)),
        },
        boots: 0,
    };
    let mut fs = dev.boot();
    fs.scan();
    persist_touched(&SERIAL, &mut fs, &INITIAL).unwrap();
    if matches!(change, Change::Legacy) {
        fs.put(EF_DEV_CONF, &blob(None, &INITIAL, Some(&OLD_CODE)))
            .unwrap();
        fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    } else if !matches!(change, Change::Arm) {
        persist_touched(&SERIAL, &mut fs, &blob(None, &[], Some(&OLD_CODE))).unwrap();
    }
    fs.put(NEIGHBOR, b"other applet").unwrap();
    fs.meta_add(NEIGHBOR, b"other metadata").unwrap();
    fs.put_counter(rsk_fido::consts::EF_COUNTER, &73u32.to_le_bytes())
        .unwrap();
    for value in 0..data.get(6).copied().unwrap_or(0) % 32 {
        fs.put(0xb000, &[value; 1024]).unwrap();
    }
    let before = records(&mut fs);
    let counter = flash.borrow().as_bytes()
        [COUNTER_RANGE.start as usize..COUNTER_RANGE.end as usize]
        .to_vec();
    let reference = SharedMock {
        flash: Rc::new(RefCell::new(flash.borrow().clone())),
        dead: Rc::new(Cell::new(false)),
    };
    let mut healthy = Fs::new(new_storage(reference));
    healthy.scan();
    execute(&mut healthy, change, false).unwrap();
    let after = records(&mut healthy);
    assert_ne!(before, after, "fixture changes no persistent record");
    let budget = |offset| {
        u16::from_be_bytes([
            data.get(offset).copied().unwrap_or(0),
            data.get(offset + 1).copied().unwrap_or(0),
        ]) as u32
    };
    let start = flash.borrow().stats_snapshot();
    flash.borrow_mut().bytes_until_shutoff = Some(budget(2));
    let result = execute(&mut fs, change, false);
    let operation_stats = start.compare_to(flash.borrow().stats_snapshot());
    let interrupted = dev.dead();
    if !interrupted {
        assert_eq!(result, Ok(()));
    }
    // Diagnose on a clone so the first real recovery mount remains cuttable.
    let mut observed = diagnostic_mount(&dev);
    partial(&mut observed, &before, &after);
    preserved(&mut observed, &flash, &counter);
    // Arm before mount: repair of a torn NOR header is recovery too.
    let start = flash.borrow().stats_snapshot();
    fs = recovery_mount(&mut dev, budget(4));
    let result = execute(&mut fs, change, true);
    let recovery_stats = start.compare_to(flash.borrow().stats_snapshot());
    let recovery_interrupted = dev.dead();
    if !recovery_interrupted {
        assert_eq!(result, Ok(()));
    }
    fs = remount(&mut dev);
    partial(&mut fs, &before, &after);
    preserved(&mut fs, &flash, &counter);
    execute(&mut fs, change, true).unwrap();
    check(&mut fs, change, &after);
    fs = remount(&mut dev);
    let generation = fs.write_gen();
    execute(&mut fs, change, true).unwrap();
    assert_eq!(
        fs.write_gen(),
        generation,
        "settled replay rewrote configuration"
    );
    check(&mut fs, change, &after);
    preserved(&mut fs, &flash, &counter);
    Outcome {
        interrupted,
        recovery_interrupted,
        operation_stats,
        recovery_stats,
    }
}
