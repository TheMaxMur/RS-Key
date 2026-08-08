// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::Rng;
use crate::init::scan_files;
use crate::pin::verify;
use rsk_crypto::Device;
use rsk_fs::storage::ram::RamStorage;

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
        serial_hash: &[0x44; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    }
}

fn setup() -> (Fs<RamStorage>, Session) {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    (fs, Session::new())
}

fn admin(fs: &mut Fs<RamStorage>, sess: &mut Session) {
    assert_eq!(
        verify(
            &dev(),
            fs,
            sess,
            &mut CountRng(0),
            0x00,
            PW3_MODE83,
            PW3_DEFAULT
        ),
        Sw::OK
    );
}

#[test]
fn write_login_requires_pw3() {
    let (mut fs, mut sess) = setup();
    // Without admin auth → denied.
    assert_eq!(
        put_data(&mut fs, &sess, EF_LOGIN_DATA, b"alice"),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    admin(&mut fs, &mut sess);
    assert_eq!(put_data(&mut fs, &sess, EF_LOGIN_DATA, b"alice"), Sw::OK);
    let mut buf = [0u8; 16];
    let n = fs.read(EF_LOGIN_DATA, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"alice");
}

#[test]
fn empty_data_deletes() {
    let (mut fs, mut sess) = setup();
    admin(&mut fs, &mut sess);
    put_data(&mut fs, &sess, EF_CH_NAME, b"Doe<<John");
    assert!(fs.has_data(EF_CH_NAME));
    assert_eq!(put_data(&mut fs, &sess, EF_CH_NAME, &[]), Sw::OK);
    assert!(!fs.has_data(EF_CH_NAME));
}

#[test]
fn algo_attr_redirects_to_priv_storage() {
    let (mut fs, mut sess) = setup();
    admin(&mut fs, &mut sess);
    // PUT C1 writes EF_ALGO_PRIV1 (0x1000 | 0x00C1).
    let attr = [0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]; // P-256 ECDSA
    assert_eq!(put_data(&mut fs, &sess, EF_ALGO_SIG, &attr), Sw::OK);
    assert!(fs.has_data(EF_ALGO_PRIV1));
    assert!(!fs.has_data(EF_ALGO_SIG));
}

#[test]
fn priv_do_1_accepts_pw2() {
    let (mut fs, mut sess) = setup();
    // PW2 (PW1 in mode 82) authorizes private DO 1.
    assert_eq!(
        verify(
            &dev(),
            &mut fs,
            &mut sess,
            &mut CountRng(0),
            0x00,
            PW1_MODE82,
            PW1_DEFAULT
        ),
        Sw::OK
    );
    assert_eq!(put_data(&mut fs, &sess, EF_PRIV_DO_1, b"secret"), Sw::OK);
    // ...but a normal DO still needs PW3.
    assert_eq!(
        put_data(&mut fs, &sess, EF_LOGIN_DATA, b"x"),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
}

#[test]
fn put_pw_status_updates_flag_in_place() {
    let (mut fs, mut sess) = setup();
    // Without admin auth → denied.
    assert_eq!(
        put_pw_status(&mut fs, &sess, &[0x00]),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    admin(&mut fs, &mut sess);
    // Clear the "PW1 valid for multiple signatures" flag; retry counters survive.
    assert_eq!(put_pw_status(&mut fs, &sess, &[0x00]), Sw::OK);
    let mut pw = [0u8; 7];
    let n = fs.read(EF_PW_PRIV, &mut pw).unwrap();
    assert_eq!(n, 7);
    assert_eq!(pw[0], 0x00);
    // RC (index 5) ships deactivated at 0; PW1/PW3 counters at 3.
    assert_eq!(&pw[4..7], &[3, 0, 3], "retry counters preserved");
}

#[test]
fn put_pw_status_cannot_overwrite_retry_counters() {
    // A >=5-byte C4 field must update only the flag + 3 max-length bytes; the
    // three retry counters that follow are read-only. A host writing a full
    // 7-byte record must never zero them — that would block every PIN across a
    // power cycle, recoverable only by a key-destroying TERMINATE DF.
    let (mut fs, mut sess) = setup();
    admin(&mut fs, &mut sess);
    assert_eq!(
        put_pw_status(&mut fs, &sess, &[0x01, 0x7F, 0x7F, 0x7F, 0, 0, 0]),
        Sw::OK
    );
    let mut pw = [0u8; 7];
    let n = fs.read(EF_PW_PRIV, &mut pw).unwrap();
    assert_eq!(n, 7);
    assert_eq!(
        &pw[0..4],
        &[0x01, 0x7F, 0x7F, 0x7F],
        "flag + max-lengths written"
    );
    assert_eq!(&pw[4..7], &[3, 0, 3], "retry counters must be read-only");
}

#[test]
fn generic_put_data_does_not_handle_specials() {
    // The reset code / PW status are routed away from the generic DO write.
    let (mut fs, mut sess) = setup();
    admin(&mut fs, &mut sess);
    assert_eq!(
        put_data(&mut fs, &sess, EF_RESET_CODE, b"x"),
        Sw::CONDITIONS_NOT_SATISFIED
    );
    assert_eq!(
        put_data(&mut fs, &sess, EF_PW_STATUS, &[0x00]),
        Sw::CONDITIONS_NOT_SATISFIED
    );
}

#[test]
fn unknown_tag_not_found() {
    let (mut fs, mut sess) = setup();
    admin(&mut fs, &mut sess);
    assert_eq!(
        put_data(&mut fs, &sess, 0x4242, b"x"),
        Sw::REFERENCE_NOT_FOUND
    );
}

#[test]
fn an_overlong_pw_status_record_cannot_panic_put_pw_status() {
    // Same clamp as `pin::check_pin`: `Fs::read` reports the stored length, so an
    // EF_PW_PRIV longer than the array would panic the `&pw[..n]` write-back.
    let (mut fs, mut sess) = setup();
    admin(&mut fs, &mut sess);
    let mut overlong = crate::files::PW_STATUS_DEFAULT.to_vec();
    overlong.resize(16, 0xAA);
    fs.put(EF_PW_PRIV, &overlong).unwrap();

    assert_eq!(put_pw_status(&mut fs, &sess, &[0x00]), Sw::OK);
    let mut pw = [0u8; 7];
    assert_eq!(fs.read(EF_PW_PRIV, &mut pw), Some(7));
    assert_eq!(&pw[4..7], &[3, 0, 3], "retry counters preserved");
}
