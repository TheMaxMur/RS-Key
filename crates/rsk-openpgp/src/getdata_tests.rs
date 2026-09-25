// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::consts::OPGP_MFR_UNMANAGED;
use crate::files::full_aid;
use crate::test_tlv::{child, children};
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

/// 6E's 73, on a store holding the PW status every card's init writes there.
fn discrete(fs: &mut Fs<RamStorage>) -> Vec<(u16, Vec<u8>)> {
    fs.put(EF_PW_PRIV, crate::files::PW_STATUS_DEFAULT).unwrap();
    let a = aid();
    let mut out = [0u8; 1024];
    let mut cur = None;
    let (n, sw) = get_data(EF_APP_DATA, false, false, fs, &a, &mut cur, &mut out);
    assert_eq!(sw, Sw::OK);
    let related = children(&child(&children(&out[..n]), EF_APP_DATA));
    children(&child(&related, EF_DISCRETE_DO))
}

/// A YubiKey 5.8.0 answers `6B00` to each of these read on its own, with a key,
/// a name, a language and a sex set (measured 2026-09-25), and serves them inside
/// 65, 6E and 7A — the only places OpenPGP 3.4 §4.4.1 lists them.
#[test]
fn a_do_a_template_carries_is_not_read_on_its_own() {
    let mut fs = fs();
    fs.put(EF_CH_NAME, b"Doe<<John").unwrap();
    fs.put(EF_LANG_PREF, b"en").unwrap();
    fs.put(EF_SEX, b"1").unwrap();
    fs.put(EF_SIG_COUNT, &[0, 0, 7]).unwrap();
    fs.put(EF_FP_SIG, &[0x11; FP_LEN]).unwrap();
    fs.put(EF_FP_CA1, &[0x22; FP_LEN]).unwrap();
    fs.put(EF_TS_SIG, &[0x33; TS_LEN]).unwrap();
    let a = aid();
    let mut out = [0u8; 1024];
    for fid in [
        EF_CH_NAME,
        EF_LANG_PREF,
        EF_SEX,
        EF_SIG_COUNT,
        EF_DISCRETE_DO,
        EF_EXT_CAP,
        EF_ALGO_SIG,
        EF_ALGO_DEC,
        EF_ALGO_AUT,
        EF_FP,
        EF_CA_FP,
        EF_TS_ALL,
        EF_FP_SIG,
        EF_FP_DEC,
        EF_FP_AUT,
        EF_FP_CA1,
        EF_FP_CA2,
        EF_FP_CA3,
        EF_TS_SIG,
        EF_TS_DEC,
        EF_TS_AUT,
    ] {
        let mut cur = None;
        let (n, sw) = get_data(fid, true, true, &mut fs, &a, &mut cur, &mut out);
        assert_eq!((n, sw), (0, Sw::WRONG_P1P2), "{fid:#06x}");
        assert_eq!(cur, Some(fid), "a refused read is still the current DO");
    }

    // The templates still carry every one of them.
    let mut template = |fid| {
        let mut cur = None;
        let (n, sw) = get_data(fid, false, false, &mut fs, &a, &mut cur, &mut out);
        assert_eq!(sw, Sw::OK, "{fid:#06x}");
        children(&child(&children(&out[..n]), fid))
    };
    let ch = template(EF_CH_DATA);
    assert_eq!(child(&ch, EF_CH_NAME), b"Doe<<John");
    assert_eq!(child(&ch, EF_LANG_PREF), b"en");
    assert_eq!(child(&ch, EF_SEX), b"1");
    assert_eq!(child(&template(EF_SEC_TPL), EF_SIG_COUNT), [0, 0, 7]);
    let dd = discrete(&mut fs);
    assert_eq!(child(&dd, EF_FP)[..FP_LEN], [0x11; FP_LEN]);
    assert_eq!(child(&dd, EF_CA_FP)[..FP_LEN], [0x22; FP_LEN]);
    assert_eq!(child(&dd, EF_TS_ALL)[..TS_LEN], [0x33; TS_LEN]);
    for tag in [EF_EXT_CAP, EF_ALGO_SIG, EF_ALGO_DEC, EF_ALGO_AUT] {
        assert!(!child(&dd, tag).is_empty(), "{tag:#04x}");
    }
}

#[test]
fn unknown_tag_is_wrong_p1p2() {
    let mut fs = fs();
    let a = aid();
    let mut out = [0u8; 16];
    let mut cur = None;
    let (_, sw) = get_data(0x4242, false, false, &mut fs, &a, &mut cur, &mut out);
    assert_eq!(sw, Sw::WRONG_P1P2);
}

/// An internal EF is not a DO with a denied ACL — it is a P1P2 this command does
/// not serve, and it answers what an absent one does. `6982` here told anyone
/// which of the 65536 cells name a file.
#[test]
fn internal_ef_read_is_indistinguishable_from_an_absent_do() {
    let mut fs = fs();
    let a = aid();
    let mut out = [0u8; 16];
    let mut cur = None;
    let (_, sw) = get_data(EF_PW1, false, false, &mut fs, &a, &mut cur, &mut out);
    assert_eq!(sw, Sw::WRONG_P1P2);
    let (_, absent) = get_data(0x4242, false, false, &mut fs, &a, &mut cur, &mut out);
    assert_eq!(sw, absent);
}

#[test]
fn priv_do_3_needs_pw2_and_pw3_will_not_do() {
    let mut fs = fs();
    let a = aid();
    let mut out = [0u8; 16];
    let mut cur = None;
    let (_, sw) = get_data(EF_PRIV_DO_3, false, false, &mut fs, &a, &mut cur, &mut out);
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    // The admin PIN is not the cardholder's: §5 gives `0103` READ to PW1 no. 82
    // alone, and a YubiKey 5.7.4 refuses PW3 on it.
    let (_, sw) = get_data(EF_PRIV_DO_3, false, true, &mut fs, &a, &mut cur, &mut out);
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    // With PW2 it becomes readable (a plain flash DO).
    let (_, sw) = get_data(EF_PRIV_DO_3, true, false, &mut fs, &a, &mut cur, &mut out);
    assert_eq!(sw, Sw::OK);
}

#[test]
fn oversized_do_is_refused_not_truncated() {
    // run-3 #1 / run-2 F3 regression: `Fs::read` reports the value's FULL stored
    // length, so an over-long DO (here a 1500-byte private DO) must
    // never be sliced past the output buffer — that would panic-reset the device.
    // It used to clamp and answer `9000`, which is the same short-body-reported-
    // as-complete lie PUT DATA's length bound now prevents at the source; only a
    // value written by an older build can still get here, and it says so.
    let mut fs = fs();
    fs.put(EF_PRIV_DO_1, &[0x01u8; 1500]).unwrap();
    let a = aid();
    let mut out = [0u8; 1024];
    let mut cur = None;
    let (n, sw) = get_data(EF_PRIV_DO_1, false, false, &mut fs, &a, &mut cur, &mut out);
    assert_eq!(sw, Sw::MEMORY_FAILURE);
    assert_eq!(n, 0, "an error carries no body");
}

/// Every attribute the card advertises must come back byte for byte where a host
/// reads it: inside 6E's 73, GET DATA serving no C1/C2/C3 on its own. `rsa1024`
/// once came back from a standalone read as `00 00 20 00`, its header sniffed
/// off. One case per advertised attribute, so no value of any shape slips.
#[test]
fn every_advertised_algo_attribute_round_trips() {
    use crate::dobj::{ALGO_AUT_SUPPORTED, ALGO_DEC_SUPPORTED, ALGO_SIG_SUPPORTED};

    for (fid, set) in [
        (EF_ALGO_SIG, ALGO_SIG_SUPPORTED),
        (EF_ALGO_DEC, ALGO_DEC_SUPPORTED),
        (EF_ALGO_AUT, ALGO_AUT_SUPPORTED),
    ] {
        for attr in set {
            // The templates carry a leading TLV length byte; the DO value is the rest.
            let value = &attr[1..];
            let mut fs = fs();
            fs.put(crate::consts::algo_tag_to_priv(fid), value).unwrap();
            let read = child(&discrete(&mut fs), fid);
            assert_eq!(read, value, "{fid:#06x} attribute did not round-trip");
        }
    }
}
