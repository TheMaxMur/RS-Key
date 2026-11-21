// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn the_configuration_gate_set_leaves_other_records_in_the_first_wipe_phase() {
    assert!(is_devconf_gate_fid(EF_DEV_CONF));
    assert!(is_devconf_gate_fid(lock::EF_DEV_LOCK));
    for fid in [rsk_fs::EF_META, rsk_fs::EF_HARDENED, 0, u16::MAX] {
        assert!(!is_devconf_gate_fid(fid), "unrelated record {fid:04x}");
    }
}

#[test]
fn a_short_tlv_entry_reports_only_complete_value_boundaries() {
    let record = [TAG_USB_ENABLED, 2, 0, 1, TAG_DEVICE_FLAGS, 1, 0x80];
    assert_eq!(entry_at(&record, 0), Some((TAG_USB_ENABLED, 4)));
    assert_eq!(entry_at(&record, 4), Some((TAG_DEVICE_FLAGS, 7)));
    assert_eq!(entry_at(&record, 7), None);
    assert_eq!(entry_at(&record[..1], 0), None);
    assert_eq!(entry_at(&record[..3], 0), None);
    assert_eq!(entry_at(&[], 0), None);
}

#[test]
fn read_config_normalizes_legacy_records_the_current_writer_would_refuse() {
    for record in [
        vec![TAG_USB_ENABLED, 1, 0xff],
        vec![TAG_DEVICE_FLAGS, 1, 0x80, TAG_DEVICE_FLAGS, 1, 0x40],
        vec![TAG_VERSION, 1, 0xee],
    ] {
        let mut fs = fs();
        fs.put(EF_DEV_CONF, &record).unwrap();
        let generation = fs.write_gen();
        let enforced = read_enabled_caps(&mut fs).to_be_bytes();
        let mut out = [0; MIN_CONFIG_RES_CAP];
        let mut res = ResBuf::new(&mut out);
        assert_eq!(config_tlv(&SERIAL, &mut fs, &mut res), Sw::OK);
        let body = res.as_slice();
        assert_eq!(body[0] as usize, body.len() - 1);
        assert!(tlv_whole(&body[1..]));
        assert_eq!(tlv_get(&body[1..], TAG_USB_ENABLED), Some(&enforced[..]));
        assert_eq!(tlv_count(&body[1..], TAG_DEVICE_FLAGS), 1);
        assert_eq!(tlv_get(&body[1..], TAG_DEVICE_FLAGS), Some(&[0][..]));
        assert_eq!(tlv_count(&body[1..], TAG_VERSION), 1);
        assert_eq!(fs.write_gen(), generation);
    }
}

#[test]
fn a_legacy_delta_keeps_whole_entries_until_the_transport_write_cap() {
    for n in [42, 43] {
        let mut old = vec![TAG_AUTO_EJECT_TIMEOUT, (n - 6) as u8];
        old.resize(n - 4, 0x55);
        let policy = [TAG_USB_ENABLED, 2, 0, 1];
        old.extend_from_slice(&policy);
        let mut fs = fs();
        fs.put(EF_DEV_CONF, &old).unwrap();
        persist_touched(&SERIAL, &mut fs, &[]).unwrap();
        let mut stored = [0; EF_DEV_CONF_READ_MAX];
        let full = fs.read(EF_DEV_CONF, &mut stored).unwrap();
        let want = if n == 42 { &old[..] } else { &policy[..] };
        assert_eq!(&stored[..full], want, "legacy length {n}");
        assert_eq!(read_enabled_caps(&mut fs), 1);
    }
}

#[test]
fn an_exact_request_cap_legacy_replay_can_still_strip_to_an_unchanged_record() {
    let mut fs = fs();
    let record = [TAG_REBOOT, 0];
    persist_touched(&SERIAL, &mut fs, &record).unwrap();
    let mut request = Vec::new();
    for _ in 0..7 {
        request.extend_from_slice(&[TAG_CONFIG_LOCK, 16]);
        request.extend_from_slice(&[0; 16]);
    }
    request.extend_from_slice(&record);
    assert_eq!(request.len(), 128);
    let generation = fs.write_gen();
    assert!(dev_conf_unchanged(&SERIAL, &mut fs, &request));
    assert_eq!(fs.write_gen(), generation);
}

#[test]
fn a_trailing_header_and_an_oversized_request_leave_the_record_unchanged() {
    let mut fs = fs();
    let owner = [TAG_USB_ENABLED, 2, 0, 1];
    persist_touched(&SERIAL, &mut fs, &owner).unwrap();
    let before = fs.write_gen();
    for (blob, want) in [
        (vec![TAG_DEVICE_FLAGS], DevConfError::BadTlv),
        (vec![0; DEV_CONF_WRITE_MAX], DevConfError::BadTlv),
        (vec![0; DEV_CONF_WRITE_MAX + 1], DevConfError::TooLong),
    ] {
        assert_eq!(persist_touched(&SERIAL, &mut fs, &blob), Err(want));
        assert!(!dev_conf_unchanged(&SERIAL, &mut fs, &blob));
        assert_eq!(fs.write_gen(), before);
        let mut stored = [0; 4];
        assert_eq!(fs.read(EF_DEV_CONF, &mut stored), Some(owner.len()));
        assert_eq!(stored, owner);
    }
}

#[test]
fn a_refused_config_write_reports_memory_failure_and_keeps_the_mask() {
    let (backend, medium) = rsk_fs::storage::faults::Cut::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    let owner = [TAG_USB_ENABLED, 2, 0, 1];
    persist_touched(&SERIAL, &mut fs, &owner).unwrap();
    let old = medium.value(EF_DEV_CONF);
    medium.arm(0);
    let err = persist_touched(&SERIAL, &mut fs, &[TAG_DEVICE_FLAGS, 1, 0x80]).unwrap_err();
    assert_eq!(err, DevConfError::Store);
    assert_eq!(err.sw(), Sw::MEMORY_FAILURE);
    assert_eq!(medium.value(EF_DEV_CONF), old);
    medium.arm(u32::MAX);
    assert_eq!(read_enabled_caps(&mut fs), 1);
}

#[test]
fn a_legacy_oversized_mask_is_preserved_when_no_other_entry_can_be_evicted() {
    let mut fs = fs();
    let mut old = vec![TAG_USB_ENABLED, (EF_DEV_CONF_READ_MAX - 2) as u8];
    old.resize(EF_DEV_CONF_READ_MAX, 0x55);
    fs.put(EF_DEV_CONF, &old).unwrap();
    let before = fs.write_gen();
    assert_eq!(
        persist_touched(&SERIAL, &mut fs, &[TAG_DEVICE_FLAGS, 1, 0x80]),
        Err(DevConfError::TooLong)
    );
    assert_eq!(fs.write_gen(), before);
    let mut stored = [0; EF_DEV_CONF_READ_MAX];
    assert_eq!(fs.read(EF_DEV_CONF, &mut stored), Some(old.len()));
    assert_eq!(stored.as_slice(), old);
}

#[test]
fn the_legacy_scrub_keeps_an_unparseable_tail_byte_stable() {
    let mut fs = fs();
    let mut old = legacy_locked_record();
    old.push(TAG_DEVICE_FLAGS);
    fs.put(EF_DEV_CONF, &old).unwrap();
    scrub_legacy_lock(&mut fs).unwrap();
    let mut stored = [0; EF_DEV_CONF_READ_MAX];
    let n = fs.read(EF_DEV_CONF, &mut stored).unwrap();
    assert_eq!(&stored[..n], old);
}

#[test]
fn default_config_does_not_answer_success_in_a_short_response_buffer() {
    let mut fs = fs();
    let mut full = [0; MIN_CONFIG_RES_CAP];
    let mut res = ResBuf::new(&mut full);
    assert_eq!(config_tlv(&SERIAL, &mut fs, &mut res), Sw::OK);
    let expected = res.as_slice().to_vec();
    for cap in 0..=expected.len() {
        let mut out = vec![0x55; cap];
        let mut res = ResBuf::new(&mut out);
        let sw = config_tlv(&SERIAL, &mut fs, &mut res);
        if cap < expected.len() {
            assert_eq!((sw, res.len()), (Sw::EXEC_ERROR, 0), "cap {cap}");
        } else {
            assert_eq!(sw, Sw::OK);
            assert_eq!(res.as_slice(), expected);
        }
    }
}
