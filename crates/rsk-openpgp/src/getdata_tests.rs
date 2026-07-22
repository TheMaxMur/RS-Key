// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::consts::OPGP_MFR_UNMANAGED;
use crate::files::full_aid;
use rsk_fs::storage::ram::RamStorage;

fn fs() -> Fs<RamStorage> {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    fs
}

fn aid() -> [u8; 16] {
    full_aid(&[1, 2, 3, 4], OPGP_MFR_UNMANAGED)
}

#[test]
fn full_aid_returns_16_raw_bytes() {
    let mut fs = fs();
    let a = aid();
    let mut out = [0u8; 64];
    let mut cur = None;
    let (n, sw) = get_data(EF_FULL_AID, false, false, &mut fs, &a, &mut cur, &mut out);
    assert_eq!(sw, Sw::OK);
    assert_eq!(n, 16);
    assert_eq!(&out[..6], OPENPGP_AID);
    assert_eq!(&out[10..14], &[1, 2, 3, 4]);
    assert_eq!(cur, Some(EF_FULL_AID));
}

#[test]
fn algo_sig_is_stripped_to_bare_value() {
    let mut fs = fs();
    let a = aid();
    let mut out = [0u8; 64];
    let mut cur = None;
    // C1 06 01 08 00 00 20 00 -> strip outer C1 06 -> bare rsa2k attributes.
    let (n, sw) = get_data(EF_ALGO_SIG, false, false, &mut fs, &a, &mut cur, &mut out);
    assert_eq!(sw, Sw::OK);
    assert_eq!(&out[..n], &[ALGO_RSA, 0x08, 0x00, 0x00, 0x20, 0x00]);
}

#[test]
fn gfm_7f74_keeps_its_sub_do() {
    // 7F74 (general feature management): its value is the sub-DO 81 01 20 and must
    // be returned whole, as a real YubiKey does — NOT unwrapped to a bare 20.
    let mut fs = fs();
    let a = aid();
    let mut out = [0u8; 64];
    let mut cur = None;
    let (n, sw) = get_data(EF_GFM, false, false, &mut fs, &a, &mut cur, &mut out);
    assert_eq!(sw, Sw::OK);
    assert_eq!(&out[..n], &[0x81, 0x01, 0x20]);
}

#[test]
fn app_data_keeps_6e_wrapper_for_ykman() {
    let mut fs = fs();
    let a = aid();
    let mut out = [0u8; 512];
    let mut cur = None;
    let (n, sw) = get_data(EF_APP_DATA, false, false, &mut fs, &a, &mut cur, &mut out);
    assert_eq!(sw, Sw::OK);
    // The constructed 6E template keeps its tag+length — this is exactly
    // what yubikit's `Tlv.unpack(0x6E, response)` consumes. An unwrapped
    // `4F …` here made `ykman openpgp info` raise ValueError.
    assert_eq!(out[0], 0x6E);
    assert_eq!(out[1], 0x82);
    let nested = ((out[2] as usize) << 8) | out[3] as usize;
    assert_eq!(n, nested + 4); // the whole response is one well-formed TLV
    // First nested DO is the full AID (4F 10 …).
    assert_eq!(out[4], 0x4F);
    assert_eq!(out[5], 16);
    assert_eq!(&out[6..12], OPENPGP_AID);
}

#[test]
fn cardholder_data_keeps_65_wrapper() {
    // 0x65 is another constructed template ykman unpacks by tag
    // (`Tlv.unpack(0x65, …)`); it must keep its wrapper even when the nested
    // name/lang/sex DOs are empty.
    let mut fs = fs();
    let a = aid();
    let mut out = [0u8; 128];
    let mut cur = None;
    let (n, sw) = get_data(EF_CH_DATA, false, false, &mut fs, &a, &mut cur, &mut out);
    assert_eq!(sw, Sw::OK);
    assert_eq!(out[0], 0x65);
    assert_eq!(out[1], 0x82);
    let nested = ((out[2] as usize) << 8) | out[3] as usize;
    assert_eq!(n, nested + 4);
}

#[test]
fn pw_status_reads_ef_pw_priv() {
    let mut fs = fs();
    fs.put(EF_PW_PRIV, crate::files::PW_STATUS_DEFAULT).unwrap();
    let a = aid();
    let mut out = [0u8; 64];
    let mut cur = None;
    let (n, sw) = get_data(EF_PW_STATUS, false, false, &mut fs, &a, &mut cur, &mut out);
    assert_eq!(sw, Sw::OK);
    assert_eq!(&out[..n], crate::files::PW_STATUS_DEFAULT);
}

#[test]
fn flash_do_returns_raw_no_strip() {
    let mut fs = fs();
    // A login-data value that happens to look like a TLV must NOT be stripped.
    fs.put(EF_LOGIN_DATA, &[0x05, 0x02, 0xAA, 0xBB]).unwrap();
    let a = aid();
    let mut out = [0u8; 64];
    let mut cur = None;
    let (n, sw) = get_data(EF_LOGIN_DATA, false, false, &mut fs, &a, &mut cur, &mut out);
    assert_eq!(sw, Sw::OK);
    assert_eq!(&out[..n], &[0x05, 0x02, 0xAA, 0xBB]);
}

#[test]
fn unknown_tag_is_reference_not_found() {
    let mut fs = fs();
    let a = aid();
    let mut out = [0u8; 16];
    let mut cur = None;
    let (_, sw) = get_data(0x4242, false, false, &mut fs, &a, &mut cur, &mut out);
    assert_eq!(sw, Sw::REFERENCE_NOT_FOUND);
}

#[test]
fn internal_ef_read_is_denied() {
    let mut fs = fs();
    let a = aid();
    let mut out = [0u8; 16];
    let mut cur = None;
    let (_, sw) = get_data(EF_PW1, false, false, &mut fs, &a, &mut cur, &mut out);
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
}

#[test]
fn priv_do_3_needs_pw2_or_pw3() {
    let mut fs = fs();
    let a = aid();
    let mut out = [0u8; 16];
    let mut cur = None;
    let (_, sw) = get_data(EF_PRIV_DO_3, false, false, &mut fs, &a, &mut cur, &mut out);
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    // With PW2 it becomes readable (a plain flash DO).
    let (_, sw) = get_data(EF_PRIV_DO_3, true, false, &mut fs, &a, &mut cur, &mut out);
    assert_eq!(sw, Sw::OK);
}

#[test]
fn get_next_without_prior_get_data_is_record_not_found() {
    let mut fs = fs();
    let a = aid();
    let mut out = [0u8; 16];
    let mut cur = None;
    let (_, sw) = get_next_data(EF_PRIV_DO_1, false, true, &mut fs, &a, &mut cur, &mut out);
    assert_eq!(sw, Sw::RECORD_NOT_FOUND);
}

#[test]
fn get_next_walks_to_following_priv_do() {
    let mut fs = fs();
    fs.put(EF_PRIV_DO_2, &[0xCA, 0xFE]).unwrap();
    let a = aid();
    let mut out = [0u8; 16];
    let mut cur = Some(EF_PRIV_DO_1);
    let (n, sw) = get_next_data(EF_PRIV_DO_1, false, true, &mut fs, &a, &mut cur, &mut out);
    assert_eq!(sw, Sw::OK);
    assert_eq!(&out[..n], &[0xCA, 0xFE]);
    assert_eq!(cur, Some(EF_PRIV_DO_2));
}

#[test]
fn oversized_algo_attr_truncates_without_panic() {
    // run-3 #1 / run-2 F3 regression: Fs::read reports the value's FULL stored
    // length; an over-long DO (here a 1500-byte C1 algorithm attribute) must
    // clamp to the output buffer, never slice past it (which would panic-reset).
    let mut fs = fs();
    fs.put(EF_ALGO_PRIV1, &[0x01u8; 1500]).unwrap();
    let a = aid();
    let mut out = [0u8; 1024];
    let mut cur = None;
    let (n, sw) = get_data(EF_ALGO_SIG, false, false, &mut fs, &a, &mut cur, &mut out);
    assert_eq!(sw, Sw::OK);
    assert!(
        n <= out.len(),
        "returned length clamped to the output buffer"
    );
}
