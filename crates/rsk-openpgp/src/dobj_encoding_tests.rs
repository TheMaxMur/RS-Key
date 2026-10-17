// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn a_public_algorithm_info_response_preserves_the_literal_fa_header() {
    let mut fs = fs();
    let aid = full_aid(&[1, 2, 3, 4], OPGP_MFR_UNMANAGED);
    let mut current = None;
    let mut output = [0xA5; 512];
    assert_eq!(
        crate::getdata::get_data(
            EF_ALGO_INFO,
            false,
            false,
            &mut fs,
            &aid,
            &mut current,
            &mut output
        ),
        (322, rsk_sdk::Sw::OK)
    );
    assert_eq!(&output[..4], &[0xFA, 0x82, 0x01, 0x3E]);
    assert_eq!(output[4], 0xC1);
    assert_eq!(current, Some(EF_ALGO_INFO));
}

#[test]
fn direct_do_lengths_use_the_shortest_ber_form_at_each_boundary() {
    let cases: &[(usize, &[u8])] = &[
        (0, &[0]),
        (127, &[0x7F]),
        (128, &[0x81, 0x80]),
        (255, &[0x81, 0xFF]),
        (256, &[0x82, 0x01, 0x00]),
        (257, &[0x82, 0x01, 0x01]),
    ];
    for &(len, expected) in cases {
        let mut fs = fs();
        let aid = full_aid(&[1, 2, 3, 4], OPGP_MFR_UNMANAGED);
        let mut output = [0xA5; 3];
        let mut writer = DoWriter::new(&mut output, &mut fs, &aid);
        writer.fmt_len(len);
        assert_eq!(writer.bytes(), expected, "length {len}");
        assert_eq!(writer.len(), expected.len());
        assert!(!writer.failed);
    }
}

#[test]
fn a_truncated_extension_latches_failure_across_later_empty_extensions() {
    let mut fs = fs();
    let aid = full_aid(&[1, 2, 3, 4], OPGP_MFR_UNMANAGED);
    let mut output = [0xA5; 2];
    let mut writer = DoWriter::new(&mut output, &mut fs, &aid);
    writer.extend(&[1, 2, 3]);
    assert!(writer.failed);
    assert_eq!(writer.pos, 3);
    assert_eq!(writer.bytes(), [1, 2]);
    writer.extend(&[]);
    assert!(writer.failed);
    assert_eq!(writer.pos, 3);
    assert_eq!(writer.bytes(), [1, 2]);
}

#[test]
fn successive_singleton_builds_append_raw_objects_without_child_headers() {
    let mut fs = fs();
    fs.put(EF_LOGIN_DATA, b"login").unwrap();
    let aid = full_aid(&[1, 2, 3, 4], OPGP_MFR_UNMANAGED);
    let mut output = [0xA5; 32];
    let mut writer = DoWriter::new(&mut output, &mut fs, &aid);
    assert_eq!(writer.build(EF_GFM), 3);
    assert_eq!(writer.bytes(), [0x81, 0x01, 0x20]);
    assert_eq!(writer.build(EF_FULL_AID), 16);
    assert_eq!(writer.len(), 19);
    let mut expected = vec![0x81, 0x01, 0x20];
    expected.extend(aid);
    assert_eq!(writer.bytes(), expected);
    for _ in 0..2 {
        assert_eq!(writer.build(EF_LOGIN_DATA), 5);
        expected.extend(b"login");
        assert_eq!(writer.bytes(), expected);
    }
    assert!(!writer.failed);
}

#[test]
fn fixed_ca_fingerprints_and_timestamps_report_the_whole_encoded_object_length() {
    for (fid, tag, body_len, total_len) in [(EF_CA_FP, 0xC6, 80, 82), (EF_TS_ALL, 0xCD, 16, 18)] {
        let mut fs = fs();
        let aid = full_aid(&[1, 2, 3, 4], OPGP_MFR_UNMANAGED);
        let mut output = [0xA5; 128];
        let mut writer = DoWriter::new(&mut output, &mut fs, &aid);
        assert_eq!(writer.build(fid), total_len);
        let mut expected = vec![tag, body_len];
        expected.extend(core::iter::repeat_n(0, usize::from(body_len)));
        assert_eq!(writer.bytes(), expected);
        assert!(!writer.failed);
    }
}

#[test]
fn appended_function_objects_report_only_their_own_encoded_length() {
    let cases: &[(u16, &[u8])] = &[
        (EF_SEC_TPL, &[0x7A, 5, 0x93, 3, 1, 2, 3]),
        (EF_KEY_INFO, &[0xDE, 8, 1, 0, 2, 0, 3, 0, 0x81, 0]),
        (EF_PW_STATUS, &[0xC4, 7, 1, 127, 127, 127, 3, 0, 3]),
    ];
    for &(fid, expected) in cases {
        let mut fs = fs();
        fs.put(EF_LOGIN_DATA, b"L").unwrap();
        fs.put(EF_SIG_COUNT, &[1, 2, 3]).unwrap();
        fs.put(EF_PW_PRIV, crate::files::PW_STATUS_DEFAULT).unwrap();
        let aid = full_aid(&[1, 2, 3, 4], OPGP_MFR_UNMANAGED);
        let mut output = [0xA5; 128];
        let mut writer = DoWriter::new(&mut output, &mut fs, &aid);
        assert_eq!(writer.build(EF_LOGIN_DATA), 1);
        assert_eq!(writer.build(fid), expected.len());
        assert_eq!(writer.bytes().first(), Some(&b'L'));
        assert_eq!(&writer.bytes()[1..], expected);
        assert!(!writer.failed);
    }
}

#[test]
fn advertised_algorithm_headers_preserve_the_tag_and_length_after_a_prefix() {
    for prefixed in [false, true] {
        let mut fs = fs();
        fs.put(EF_LOGIN_DATA, b"L").unwrap();
        let aid = full_aid(&[1, 2, 3, 4], OPGP_MFR_UNMANAGED);
        let mut output = [0xA5; 512];
        let mut writer = DoWriter::new(&mut output, &mut fs, &aid);
        if prefixed {
            assert_eq!(writer.build(EF_LOGIN_DATA), 1);
        }
        assert_eq!(writer.build(EF_ALGO_INFO), 322);
        let offset = usize::from(prefixed);
        assert_eq!(writer.len(), 322 + offset);
        assert_eq!(
            &writer.bytes()[offset..offset + 4],
            &[0xFA, 0x82, 0x01, 0x3E]
        );
        assert_eq!(writer.bytes()[offset + 4], 0xC1);
        assert!(!writer.failed);
    }
}
