// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::ram::RamStorage;

// Stored algorithm-attribute values (the form `[algo_id ‖ oid]`, no length
// prefix — that is what PUT DATA C1/C2/C3 lands in EF_ALGO_PRIV*).
const ATTR_ED25519: &[u8] = &[0x16, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01];
const ATTR_P256: &[u8] = &[0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

fn fs() -> Fs<RamStorage> {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    fs
}

#[test]
fn empty_card_has_no_keys_and_default_retries() {
    let mut fs = fs();
    let info = read_info(&mut fs);
    assert_eq!(info.key_count(), 0);
    for s in &info.slots {
        assert!(!s.present);
        assert_eq!(s.algo, SlotAlgo::None);
        assert!(s.fingerprint.is_none());
        assert!(!s.created && !s.touch);
    }
    assert_eq!(info.sig_count, 0);
    // No EF_PW_PRIV seeded → the reader falls back to the default 3/3.
    assert_eq!((info.pw1_retries, info.pw3_retries), (3, 3));
}

#[test]
fn sig_slot_decodes_ed25519_with_fingerprint_and_touch() {
    let mut fs = fs();
    fs.put(EF_PK_SIG.get(), &[0xAB; 40]).unwrap();
    fs.put(EF_ALGO_PRIV1, ATTR_ED25519).unwrap();
    fs.put(EF_FP_SIG, &[0x11; 20]).unwrap();
    fs.put(EF_UIF_SIG, &[0x01, 0x20]).unwrap();
    fs.put(EF_TS_SIG, &0x6500_0000u32.to_be_bytes()).unwrap();
    let s = read_info(&mut fs).slots[0];
    assert!(s.present);
    assert_eq!(s.algo, SlotAlgo::Ec(Curve::Ed25519));
    assert_eq!(s.algo.label(), "Ed25519");
    assert_eq!(s.fingerprint, Some([0x11; 20]));
    assert!(s.created);
    assert!(s.touch);
}

#[test]
fn dec_slot_p256_aut_slot_defaults_to_rsa2k() {
    let mut fs = fs();
    fs.put(EF_PK_DEC.get(), &[0xCD; 32]).unwrap();
    fs.put(EF_ALGO_PRIV2, ATTR_P256).unwrap();
    // AUT key present but no stored attribute → the applet default rsa2k.
    fs.put(EF_PK_AUT.get(), &[0xEF; 256]).unwrap();
    let info = read_info(&mut fs);
    assert_eq!(info.slots[1].algo, SlotAlgo::Ec(Curve::P256));
    assert_eq!(info.slots[1].algo.label(), "NIST P-256");
    assert_eq!(info.slots[2].algo, SlotAlgo::Rsa(2048));
    assert_eq!(info.slots[2].algo.label(), "RSA 2048");
    assert!(info.slots[1].fingerprint.is_none());
    assert_eq!(info.key_count(), 2);
}

#[test]
fn over_long_stored_dos_do_not_panic_read_info() {
    // `Storage::read` reports the value's FULL stored length, and PUT DATA caps
    // nothing, so a PW3 host (or flash corruption) can leave a fingerprint /
    // timestamp / algo DO longer than the reader's fixed stack buffer. read_info
    // must clamp before slicing — an index-OOB panic on device is a brick.
    let mut fs = fs();
    fs.put(EF_PK_SIG.get(), &[0xAB; 40]).unwrap();
    fs.put(EF_FP_SIG, &[0x11; 64]).unwrap(); // > 20-byte fp buffer
    fs.put(EF_TS_SIG, &[0x65; 16]).unwrap(); // > 4-byte ts buffer
    fs.put(EF_ALGO_PRIV1, &[0x13; 48]).unwrap(); // > 16-byte algo buffer
    let s = read_info(&mut fs).slots[0]; // must not panic
    assert!(s.present);
    assert!(s.created);
    assert_eq!(s.fingerprint, Some([0x11; 20]));
}

#[test]
fn empty_card_has_no_cardholder_data() {
    let mut fs = fs();
    let ch = read_cardholder(&mut fs);
    assert!(!ch.any());
    assert!(ch.name().is_empty() && ch.login().is_empty() && ch.url().is_empty());
}

#[test]
fn cardholder_fields_read_back_and_truncate() {
    let mut fs = fs();
    fs.put(EF_CH_NAME, b"Alice Dev").unwrap();
    fs.put(EF_LOGIN_DATA, b"alice").unwrap();
    fs.put(EF_URI_URL, b"https://keys.example.org/alice")
        .unwrap();
    fs.put(EF_LANG_PREF, b"en").unwrap();
    let ch = read_cardholder(&mut fs);
    assert!(ch.any());
    assert_eq!(ch.name(), b"Alice Dev");
    assert_eq!(ch.login(), b"alice");
    assert_eq!(ch.url(), b"https://keys.example.org/alice");
    assert_eq!(ch.lang(), b"en");

    // A field longer than the cap is truncated, never overflowed — and the reader
    // hands back one byte MORE than the panel label keeps, so `Label::clamp` can
    // still see that it was cut. Reading exactly the label width made the marker
    // unreachable and a cut value rendered as complete (audit run-34 #39).
    let long = [b'x'; CH_FIELD_MAX + 20];
    fs.put(EF_CH_NAME, &long).unwrap();
    assert_eq!(read_cardholder(&mut fs).name().len(), CH_FIELD_MAX);
    // The boundary that matters: a value one over the label width must survive the
    // read intact, or nothing downstream can tell it apart from a complete one.
    let over = [b'y'; 49];
    fs.put(EF_CH_NAME, &over).unwrap();
    assert_eq!(read_cardholder(&mut fs).name().len(), 49);
    let exact = [b'z'; 48];
    fs.put(EF_CH_NAME, &exact).unwrap();
    assert_eq!(read_cardholder(&mut fs).name().len(), 48);
}

#[test]
fn pw_status_and_sig_counter_are_read() {
    let mut fs = fs();
    fs.put(EF_PW_PRIV, &[0x01, 127, 127, 127, 2, 3, 1]).unwrap();
    fs.put(EF_SIG_COUNT, &[0x00, 0x00, 0x2A]).unwrap();
    let info = read_info(&mut fs);
    assert_eq!((info.pw1_retries, info.pw3_retries), (2, 1));
    assert_eq!(info.sig_count, 42);
}
