// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::consts::OPGP_MFR_UNMANAGED;
use crate::files::full_aid;
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;

fn fs() -> Fs<RamStorage> {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    fs
}

#[test]
fn algo_default_is_rsa2k() {
    let mut fs = fs();
    let aid = full_aid(&[1, 2, 3, 4], OPGP_MFR_UNMANAGED);
    let mut out = [0u8; 64];
    let n = {
        let mut w = DoWriter::new(&mut out, &mut fs, &aid);
        w.build(EF_ALGO_SIG)
    };
    // emit_algo always self-writes the tag + length (C1 06) ahead of the
    // value; GET DATA strips the outer tag for FUNC DOs.
    assert_eq!(
        &out[..n],
        &[0xC1, 6, ALGO_RSA, 0x08, 0x00, 0x00, 0x20, 0x00]
    );
}

#[test]
fn full_aid_is_returned_with_serial() {
    let mut fs = fs();
    let aid = full_aid(&[0xAA, 0xBB, 0xCC, 0xDD], OPGP_MFR_UNMANAGED);
    let mut out = [0u8; 64];
    let n = {
        let mut w = DoWriter::new(&mut out, &mut fs, &aid);
        w.build(EF_FULL_AID)
    };
    assert_eq!(n, 16);
    assert_eq!(&out[..6], OPENPGP_AID);
    assert_eq!(&out[8..10], &[0xFF, 0xFE], "unmanaged manufacturer");
    assert_eq!(&out[10..14], &[0xAA, 0xBB, 0xCC, 0xDD]);
}

#[test]
fn discretionary_contains_key_information() {
    // 0xDE must be nested inside the 0x73 discretionary DOs, where ykman >= 5.2
    // looks for it — a bare child of 0x6E is invisible to that parser.
    let mut fs = fs();
    let aid = full_aid(&[1, 2, 3, 4], OPGP_MFR_UNMANAGED);
    let mut out = [0u8; 256];
    let n = {
        let mut w = DoWriter::new(&mut out, &mut fs, &aid);
        w.build(EF_DISCRETE_DO)
    };
    assert!(
        out[..n]
            .windows(8)
            .any(|w| w == [0xDE, 0x06, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00]),
        "0x73 discretionary must contain the 0xDE key-info DO with spec key-refs"
    );
}

#[test]
fn algo_info_dec_list_uses_ecdh_for_nist() {
    // In the FA algorithm-info DO the DEC (C2) slot advertises NIST/secp256k1
    // curves as ECDH (0x12), not ECDSA (0x13): a decryption key does key agreement,
    // matching the YubiKey. (The applet already accepts ECDH NIST keys — the FA
    // advert was the only thing lying.)
    let mut fs = fs();
    let aid = full_aid(&[1, 2, 3, 4], OPGP_MFR_UNMANAGED);
    let mut out = [0u8; 512];
    let n = {
        let mut w = DoWriter::new(&mut out, &mut fs, &aid);
        w.build(EF_ALGO_INFO)
    };
    let p256 = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    // Under C2 (DEC), P-256 is 09 12 <oid> (ECDH); it must NOT be 09 13 <oid>.
    let ecdh: Vec<u8> = [0xC2u8, 0x09, 0x12].iter().chain(&p256).copied().collect();
    let ecdsa: Vec<u8> = [0xC2u8, 0x09, 0x13].iter().chain(&p256).copied().collect();
    assert!(
        out[..n].windows(ecdh.len()).any(|w| w == ecdh.as_slice()),
        "DEC P-256 must be advertised as ECDH (0x12)"
    );
    assert!(
        !out[..n].windows(ecdsa.len()).any(|w| w == ecdsa.as_slice()),
        "DEC P-256 must not be advertised as ECDSA (0x13)"
    );
}

#[test]
fn key_information_uses_spec_key_refs() {
    // OpenPGP Card 3.4 §4.4.3.8: (key-ref, status) pairs with refs 01/02/03 for
    // SIG/DEC/AUT. ykman >= 5.2 keys its parse on these; 0-indexed refs crash it.
    let mut fs = fs();
    let aid = full_aid(&[1, 2, 3, 4], OPGP_MFR_UNMANAGED);
    let mut out = [0u8; 64];
    let n = {
        let mut w = DoWriter::new(&mut out, &mut fs, &aid);
        w.build(EF_KEY_INFO)
    };
    assert_eq!(n, 6);
    assert_eq!(&out[..6], &[0x01, 0x00, 0x02, 0x00, 0x03, 0x00]);
}

#[test]
fn app_data_is_constructed_6e_with_nested_aid_and_hist() {
    let mut fs = fs();
    let aid = full_aid(&[1, 2, 3, 4], OPGP_MFR_UNMANAGED);
    let mut out = [0u8; 512];
    let n = {
        let mut w = DoWriter::new(&mut out, &mut fs, &aid);
        w.build(EF_APP_DATA)
    };
    // 6E 82 HH LL ...
    assert_eq!(out[0], 0x6E);
    assert_eq!(out[1], 0x82);
    let nested = ((out[2] as usize) << 8) | out[3] as usize;
    assert_eq!(n, nested + 4);
    // first nested DO is 4F (full AID), len 16.
    assert_eq!(out[4], 0x4F);
    assert_eq!(out[5], 16);
    assert_eq!(&out[6..12], OPENPGP_AID);
    // 5F52 historical bytes follows.
    let hist_tag = 6 + 16;
    assert_eq!(&out[hist_tag..hist_tag + 2], &[0x5F, 0x52]);
}

#[test]
fn over_long_flash_do_does_not_overflow_the_output_buffer() {
    // Regression: an over-long stored DO (cardholder name here) must not push the
    // write cursor past `out` and panic. PUT DATA is uncapped and `fs.read`
    // returns the full stored length, so GET DATA 65 used to slice out of range.
    let mut fs = fs();
    fs.put(EF_CH_NAME, &[0x41u8; 2000]).unwrap();
    let aid = full_aid(&[0; 4], OPGP_MFR_UNMANAGED);
    let cap = 1024;
    let mut out = [0u8; 1024];
    let mut w = DoWriter::new(&mut out, &mut fs, &aid);
    w.build(EF_CH_DATA); // 0x65 cardholder template, nests EF_CH_NAME
    // Reaching here means no OOB slice panicked; the cursor stayed in bounds.
    assert!(w.len() <= cap);
    let _ = w.bytes(); // bytes() slices out[..pos] — would panic if pos overran
}

#[test]
fn discrete_do_nests_algo_pw_fp() {
    let mut fs = fs();
    // seed a PW status so emit_pw_status emits its 7 bytes.
    fs.put(EF_PW_PRIV, crate::files::PW_STATUS_DEFAULT).unwrap();
    let aid = full_aid(&[0; 4], OPGP_MFR_UNMANAGED);
    let mut out = [0u8; 512];
    let n = {
        let mut w = DoWriter::new(&mut out, &mut fs, &aid);
        w.build(EF_DISCRETE_DO)
    };
    assert_eq!(out[0], 0x73);
    assert_eq!(out[1], 0x82);
    assert!(n > 4);
    // C0 (ext caps) is the first nested DO.
    assert_eq!(out[4], 0xC0);
    assert_eq!(out[5], 10);
}

#[test]
fn short_fingerprint_slot_does_not_leak_scratch_tail() {
    // Regression: PUT DATA is uncapped, so a present-but-short fingerprint slot used
    // to make the C5 DO declare 60 bytes while only writing a few — the tail slicing
    // stale scratch from a prior command. Each slot must be zero-padded to its fixed
    // 20-byte width so the declared length equals what was written.
    let mut fs = fs();
    fs.put(EF_FP_SIG, &[0xAA]).unwrap(); // 1-byte fingerprint (would over-report as 20)
    let aid = full_aid(&[0; 4], OPGP_MFR_UNMANAGED);
    // Pre-fill the buffer (the DoWriter's scratch here) with a sentinel standing in for
    // prior-command residue; nothing past the real 1 byte may survive into the DO.
    let mut out = [0x7Eu8; 128];
    let n = {
        let mut w = DoWriter::new(&mut out, &mut fs, &aid);
        w.build(EF_FP)
    };
    // C5 60 || sig(20) || dec(20 zeros) || aut(20 zeros) = 62 bytes, fully accounted.
    assert_eq!(out[0], (EF_FP & 0xff) as u8);
    assert_eq!(out[1], 60);
    assert_eq!(n, 62);
    assert_eq!(out[2], 0xAA); // the one real fingerprint byte
    assert!(
        out[3..62].iter().all(|&b| b == 0),
        "short/absent slots must be zero-padded — no sentinel/scratch leak"
    );
}
