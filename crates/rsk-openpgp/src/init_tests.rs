// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::ram::RamStorage;

/// Deterministic counter RNG for tests.
struct CountRng(u8);
impl Rng for CountRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

fn dev() -> Device<'static> {
    Device {
        serial_hash: &[0x11; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    }
}

fn fresh() -> Fs<RamStorage> {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    fs
}

#[test]
fn creates_all_default_files() {
    let mut fs = fresh();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();

    // DEK files are 77 bytes, format byte 0x03.
    for fid in [EF_DEK_PW1, EF_DEK_PW3] {
        assert_eq!(fs.size(fid.get()), Some(DEK_FILE_SIZE));
        let mut b = [0u8; 1];
        fs.read(fid.get(), &mut b);
        assert_eq!(b[0], DEK_FORMAT_V3);
    }
    // The resetting code ships DEACTIVATED: no RC verifier and no RC-sealed DEK.
    assert_eq!(fs.size(EF_DEK_RC.get()), None);
    let mut rc = [0u8; 34];
    assert!(fs.read(EF_RC, &mut rc).is_none());
    // PIN verifiers: [len, 1, verifier(32)].
    let mut rec = [0u8; 34];
    fs.read(EF_PW1, &mut rec);
    assert_eq!(rec[0], 6);
    assert_eq!(rec[1], PIN_FORMAT_V1);
    let mut rec3 = [0u8; 34];
    fs.read(EF_PW3, &mut rec3);
    assert_eq!(rec3[0], 8);

    assert_eq!(fs.size(EF_SIG_COUNT), Some(3));
    let mut pw = [0u8; 7];
    fs.read(EF_PW_PRIV, &mut pw);
    // RC retry counter (index 5) is 0: the resetting code ships deactivated.
    assert_eq!(&pw, &[0x01, 127, 127, 127, 3, 0, 3]);
    assert!(fs.has_data(EF_KDF));
    assert!(fs.has_data(EF_SEX));
    assert!(fs.has_data(EF_PW_RETRIES));
}

#[test]
fn dek_decrypts_under_default_pin() {
    let mut fs = fresh();
    let d = dev();
    scan_files(&d, &mut fs, &mut CountRng(0)).unwrap();

    // The wrapped DEK is recoverable with the default PW1 session key.
    let mut blob = [0u8; DEK_FILE_SIZE];
    let n = fs.read(EF_DEK_PW1.get(), &mut blob).unwrap();
    assert_eq!(blob[0], DEK_FORMAT_V3);
    let session = d.pin_derive_session(PW1_DEFAULT);
    let mut dek = [0u8; DEK_SIZE];
    let m = d
        .decrypt_with_aad(&session, &blob[1..n], PinKdf::V2, &mut dek)
        .unwrap();
    assert_eq!(m, DEK_SIZE);
    // RC and PW3 are the same blob sealed under PW3 and decrypt to the same DEK.
    let mut blob3 = [0u8; DEK_FILE_SIZE];
    fs.read(EF_DEK_PW3.get(), &mut blob3);
    let session3 = d.pin_derive_session(PW3_DEFAULT);
    let mut dek3 = [0u8; DEK_SIZE];
    d.decrypt_with_aad(&session3, &blob3[1..], PinKdf::V2, &mut dek3)
        .unwrap();
    assert_eq!(dek, dek3);
}

/// The record firmware 0x07F7..=0x0852 wrote: no RC verifier, but a live RC
/// error counter (index 5).
const PW_STATUS_LEGACY: &[u8] = &[0x01, 127, 127, 127, 3, 3, 3];

fn rc_counter<S: rsk_fs::Storage>(fs: &mut Fs<S>) -> u8 {
    let mut pw = [0u8; 7];
    fs.read(EF_PW_PRIV, &mut pw).unwrap();
    pw[pw_retry_idx(EF_RC)]
}

#[test]
fn legacy_rc_counter_is_zeroed_when_no_reset_code_exists() {
    let mut fs = fresh();
    fs.put(EF_PW_PRIV, PW_STATUS_LEGACY).unwrap();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();

    assert!(!fs.has_data(EF_RC), "no RC was ever set on this card");
    assert_eq!(
        rc_counter(&mut fs),
        0,
        "DO C4 must not advertise an absent RC"
    );
}

#[test]
fn a_real_reset_code_keeps_its_retry_counter() {
    let mut fs = fresh();
    let d = dev();
    fs.put(EF_PW_PRIV, PW_STATUS_LEGACY).unwrap();
    put_pin_verifier(&mut fs, &d, EF_RC, b"87654321").unwrap();
    scan_files(&d, &mut fs, &mut CountRng(0)).unwrap();

    assert!(fs.has_data(EF_RC), "an admin-set RC survives init");
    assert_eq!(rc_counter(&mut fs), 3);
}

#[test]
fn the_default_reset_code_is_deleted_and_its_counter_cleared() {
    let mut fs = fresh();
    let d = dev();
    fs.put(EF_PW_PRIV, PW_STATUS_LEGACY).unwrap();
    put_pin_verifier(&mut fs, &d, EF_RC, PW3_DEFAULT).unwrap();
    scan_files(&d, &mut fs, &mut CountRng(0)).unwrap();

    assert!(!fs.has_data(EF_RC), "the 0x07F6-era backdoor RC is removed");
    assert_eq!(rc_counter(&mut fs), 0);
}

#[test]
fn is_idempotent() {
    let mut fs = fresh();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    let mut first = [0u8; DEK_FILE_SIZE];
    fs.read(EF_DEK_PW1.get(), &mut first);
    // A second run with a different RNG must not rewrite existing files.
    scan_files(&dev(), &mut fs, &mut CountRng(200)).unwrap();
    let mut second = [0u8; DEK_FILE_SIZE];
    fs.read(EF_DEK_PW1.get(), &mut second);
    assert_eq!(first, second);
}

#[test]
fn an_overlong_pw_status_record_cannot_panic_the_rc_settle() {
    // Same clamp as `pin::check_pin`: `Fs::read` reports the stored length, and an
    // unclamped `&pw[..n]` here would panic on the pre-USB boot path.
    let mut fs = fresh();
    let mut overlong = PW_STATUS_LEGACY.to_vec();
    overlong.resize(16, 0xAA);
    fs.put(EF_PW_PRIV, &overlong).unwrap();

    settle_rc_retry_counter(&mut fs).unwrap();
    assert_eq!(
        rc_counter(&mut fs),
        0,
        "DO C4 must not advertise an absent RC"
    );
}
