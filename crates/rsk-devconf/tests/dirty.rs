// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

// A separate test binary keeps other config writers out of the process-wide latch.
use rsk_devconf::{persist_dev_conf, take_dev_conf_dirty};
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;

const TAG_USB_ENABLED: u8 = 0x03;

#[test]
fn a_configuration_change_sets_the_latch_once_and_a_replay_keeps_it_clear() {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    let serial = [1, 2, 3, 4];
    let policy = [TAG_USB_ENABLED, 2, 0x02, 0];
    assert!(!take_dev_conf_dirty());
    persist_dev_conf(&serial, &mut fs, &policy, &mut || true).unwrap();
    assert!(take_dev_conf_dirty());
    assert!(!take_dev_conf_dirty());
    let generation = fs.write_gen();
    persist_dev_conf(&serial, &mut fs, &policy, &mut || true).unwrap();
    assert_eq!(fs.write_gen(), generation);
    assert!(!take_dev_conf_dirty());
    persist_dev_conf(&serial, &mut fs, &[TAG_USB_ENABLED, 2, 0, 1], &mut || true).unwrap();
    assert!(take_dev_conf_dirty());
    assert!(!take_dev_conf_dirty());
}
