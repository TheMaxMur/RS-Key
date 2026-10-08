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

/// A template's length goes in BER's shortest form, as a YubiKey 5.8.0 writes `65 09`:
/// one byte under 128, `81 LL` under 256, `82 HH LL` from there.
#[test]
fn a_template_length_takes_the_shortest_form() {
    for (body, head) in [
        (0usize, &[0x65, 0x00][..]),
        (127, &[0x65, 0x7F]),
        (128, &[0x65, 0x81, 0x80]),
        (255, &[0x65, 0x81, 0xFF]),
        (256, &[0x65, 0x82, 0x01, 0x00]),
    ] {
        let mut fs = fs();
        let aid = full_aid(&[1, 2, 3, 4], OPGP_MFR_UNMANAGED);
        let mut out = [0u8; 512];
        let n = {
            let mut w = DoWriter::new(&mut out, &mut fs, &aid);
            let lp = w.open(0x65);
            w.extend(&vec![0xAB; body]);
            let n = w.close(lp);
            assert_eq!(w.len(), n, "{body} bytes: the cursor after the shrink");
            n
        };
        assert_eq!(&out[..head.len()], head, "{body} bytes");
        assert_eq!(n, head.len() + body, "{body} bytes");
        assert!(
            out[head.len()..n].iter().all(|&b| b == 0xAB),
            "{body} bytes"
        );
    }
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
    // value, the child 73 carries. A reset YubiKey 5.8.0
    // reports 01 0800 0011 00: e is 17 bits long.
    assert_eq!(
        &out[..n],
        &[0xC1, 6, ALGO_RSA, 0x08, 0x00, 0x00, 0x11, 0x00]
    );
}

/// An older build stored the exponent length it was sent, 32 from gpg's default;
/// the card reports 17 for it, as a YubiKey 5.8.0 does for any length it took.
#[test]
fn a_stored_32_bit_exponent_length_reads_as_17() {
    let mut fs = fs();
    fs.put(EF_ALGO_PRIV1, &[ALGO_RSA, 0x0C, 0x00, 0x00, 0x20, 0x00])
        .unwrap();
    let aid = full_aid(&[1, 2, 3, 4], OPGP_MFR_UNMANAGED);
    let mut out = [0u8; 64];
    let n = DoWriter::new(&mut out, &mut fs, &aid).build(EF_ALGO_SIG);
    assert_eq!(
        &out[..n],
        &[0xC1, 6, ALGO_RSA, 0x0C, 0x00, 0x00, 0x11, 0x00]
    );
}

/// A length below 65537's, which only a build older than the PUT DATA check could have
/// stored, reads back as stored: GENERATE and IMPORT refuse it, so the card must not
/// report the advertised 17 over it.
#[test]
fn a_stored_16_bit_exponent_length_reads_back_as_stored() {
    let mut fs = fs();
    let stored = [ALGO_RSA, 0x08, 0x00, 0x00, 0x10, 0x00];
    fs.put(EF_ALGO_PRIV1, &stored).unwrap();
    let aid = full_aid(&[1, 2, 3, 4], OPGP_MFR_UNMANAGED);
    let mut out = [0u8; 64];
    let n = DoWriter::new(&mut out, &mut fs, &aid).build(EF_ALGO_SIG);
    assert_eq!(&out[2..n], &stored);
    assert!(!advertised_algo(EF_ALGO_SIG, &out[2..n]));
}

/// DO `0xFA` offers RSA with the 17-bit exponent length a YubiKey 5.8.0 offers,
/// in every slot and at 2048, 3072 and 4096 bits: `yubikit` refuses to set any
/// attribute the list does not hold, so a 32 here left it no RSA at all.
#[test]
fn algorithm_information_offers_rsa_with_a_17_bit_exponent() {
    let mut fs = fs();
    let aid = full_aid(&[1, 2, 3, 4], OPGP_MFR_UNMANAGED);
    let mut out = [0u8; 512];
    let n = DoWriter::new(&mut out, &mut fs, &aid).build(EF_ALGO_INFO);
    let body = &out[4..n]; // FA 82 LL LL
    let mut rsa = Vec::new();
    let mut at = 0;
    while at < body.len() {
        let (tag, len) = (body[at], usize::from(body[at + 1]));
        let value = &body[at + 2..at + 2 + len];
        if value[0] == ALGO_RSA {
            assert_eq!(&value[3..], &[0x00, 0x11, 0x00], "{tag:02x}: {value:02x?}");
            rsa.push((tag, u16::from_be_bytes([value[1], value[2]])));
        }
        at += 2 + len;
    }
    for tag in [0xC1, 0xC2, 0xC3] {
        for bits in [2048, 3072, 4096] {
            assert!(rsa.contains(&(tag, bits)), "{tag:02x} lacks RSA-{bits}");
        }
    }
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
    let mut out = [0u8; 512];
    let n = {
        let mut w = DoWriter::new(&mut out, &mut fs, &aid);
        w.build(EF_DISCRETE_DO)
    };
    assert!(n <= out.len(), "the whole discretionary template must fit");
    assert!(
        out[..n]
            .windows(10)
            .any(|w| w == [0xDE, 0x08, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x81, 0x00]),
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
    // SIG/DEC/AUT, and Yubico's 81 for the attestation key after them. ykman >= 5.2
    // keys its parse on these; 0-indexed refs crash it.
    let mut fs = fs();
    let aid = full_aid(&[1, 2, 3, 4], OPGP_MFR_UNMANAGED);
    let mut out = [0u8; 64];
    let n = {
        let mut w = DoWriter::new(&mut out, &mut fs, &aid);
        w.build(EF_KEY_INFO)
    };
    assert_eq!(n, 8);
    assert_eq!(&out[..8], &[0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x81, 0x00]);
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
    // to make the C5 DO declare its width while only writing a few bytes — the tail slicing
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
    // C5 80 || sig(20) || dec, aut, att (20 zeros each) = 82 bytes, fully accounted.
    assert_eq!(out[0], (EF_FP & 0xff) as u8);
    assert_eq!(out[1], 80);
    assert_eq!(n, 82);
    assert_eq!(out[2], 0xAA); // the one real fingerprint byte
    assert!(
        out[3..82].iter().all(|&b| b == 0),
        "short/absent slots must be zero-padded — no sentinel/scratch leak"
    );
}

#[test]
fn a_writer_is_empty_until_it_has_emitted_a_byte() {
    let mut fs = fs();
    let aid = full_aid(&[1, 2, 3, 4], OPGP_MFR_UNMANAGED);
    let mut out = [0; 8];
    let mut writer = DoWriter::new(&mut out, &mut fs, &aid);
    assert!(writer.is_empty());
    writer.push(0x55);
    assert!(!writer.is_empty());
    assert_eq!(writer.bytes(), &[0x55]);
    let mut empty = [];
    let mut writer = DoWriter::new(&mut empty, &mut fs, &aid);
    writer.push(0x55);
    assert!(writer.is_empty());
    assert!(writer.bytes().is_empty());
}

#[test]
fn fixed_short_lengths_refuse_a_long_form_body() {
    let length: fn(usize) -> u8 = core::hint::black_box(short_len);
    for n in 0..0x80 {
        assert_eq!(usize::from(length(n)), n);
    }
    assert!(std::panic::catch_unwind(|| length(0x80)).is_err());
}

#[test]
fn a_stored_legacy_rsa_attribute_refuses_each_short_constructed_template() {
    let mut store = fs();
    store
        .put(EF_ALGO_PRIV1, &[ALGO_RSA, 8, 0, 0, 0x20, 0])
        .unwrap();
    let aid = full_aid(&[1, 2, 3, 4], OPGP_MFR_UNMANAGED);
    let mut full = [0; 512];
    let length = DoWriter::new(&mut full, &mut store, &aid).build(EF_DISCRETE_DO);
    assert!(length <= full.len());
    assert!(
        full[..length]
            .windows(8)
            .any(|w| w == [0xc1, 6, ALGO_RSA, 8, 0, 0, 17, 0])
    );
    let generation = store.write_gen();
    for room in 0..length {
        let mut output = vec![0xa5; room];
        let claimed = DoWriter::new(&mut output, &mut store, &aid).build(EF_DISCRETE_DO);
        assert!(claimed > output.len(), "room {room} answered success");
        assert_eq!(store.write_gen(), generation);
    }
}

#[test]
fn a_flash_tail_that_exactly_fits_is_a_complete_template() {
    let mut store = fs();
    store.put(EF_SEX, &[0x39]).unwrap();
    let aid = full_aid(&[1, 2, 3, 4], OPGP_MFR_UNMANAGED);
    let mut full = [0; 512];
    let n = DoWriter::new(&mut full, &mut store, &aid).build(EF_CH_DATA);
    assert!(n < 0x80);
    assert!(full[..n].ends_with(&[0x5f, 0x35, 1, 0x39]));
    let generation = store.write_gen();
    let mut exact = vec![0xa5; n];
    assert_eq!(
        DoWriter::new(&mut exact, &mut store, &aid).build(EF_CH_DATA),
        n
    );
    assert_eq!(exact, full[..n]);
    assert_eq!(store.write_gen(), generation);
}

#[test]
fn a_flat_record_that_outgrows_its_size_probe_refuses_the_short_output() {
    let (backend, control) = rsk_fs::read_change::ChangingRead::new();
    let mut store = Fs::new(backend);
    store.scan();
    store.put(EF_LOGIN_DATA, b"old").unwrap();
    control.replace_on_read(EF_LOGIN_DATA, 0, Some(&[0x42; 32]));
    let aid = full_aid(&[1, 2, 3, 4], OPGP_MFR_UNMANAGED);
    let mut output = [0xa5; 8];
    let generation = store.write_gen();
    assert!(DoWriter::new(&mut output, &mut store, &aid).build(EF_LOGIN_DATA) > output.len());
    assert!(control.served());
    assert_eq!(store.write_gen(), generation);
    let mut retained = [0; 3];
    assert_eq!(
        store.into_storage().value(EF_LOGIN_DATA, &mut retained),
        Some(3)
    );
    assert_eq!(&retained, b"old");
}

#[test]
fn a_direct_do_walk_distinguishes_sizing_from_emission() {
    let mut store = fs();
    store.put(EF_LOGIN_DATA, b"login").unwrap();
    let aid = full_aid(&[1, 2, 3, 4], OPGP_MFR_UNMANAGED);
    let generation = store.write_gen();
    let mut out = [0xa5; 64];
    let mut writer = DoWriter::new(&mut out, &mut store, &aid);
    assert_eq!(writer.emit_do(&[], 1), 0);
    assert!(writer.is_empty());
    assert_eq!(writer.emit_do(&[2, EF_LOGIN_DATA, EF_LOGIN_DATA], 0), 10);
    assert!(writer.is_empty());
    assert_eq!(writer.out, &[0xa5; 64]);
    assert_eq!(writer.fs.write_gen(), generation);
    let mut out = [0xa5; 64];
    let mut writer = DoWriter::new(&mut out, &mut store, &aid);
    assert_eq!(writer.emit_do(&[2, EF_LOGIN_DATA, EF_LOGIN_DATA], 1), 10);
    assert_eq!(
        writer.bytes(),
        [b"login".as_slice(), &[0x5e, 5], b"login"].concat()
    );
    assert_eq!(writer.fs.write_gen(), generation);
}
