// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::init::scan_files;
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
        serial_hash: &[0x33; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    }
}

fn setup() -> Fs<RamStorage> {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    fs
}

const OTP_KEY: [u8; 32] = [0x66; 32];

fn otp_dev() -> Device<'static> {
    Device {
        otp_key: Some(&OTP_KEY),
        ..dev()
    }
}

#[test]
fn pw2_status_query_reports_pw1_retries() {
    // An empty-data VERIFY in PW2 mode (p2 = 0x82) is a status query. PW2 shares
    // the PW1 verifier and its retry counter, so it must report PW1's retries,
    // not probe the (absent) reset-code EF and answer REFERENCE_NOT_FOUND.
    let mut fs = setup();
    let mut sess = Session::new();
    let sw = verify(
        &dev(),
        &mut fs,
        &mut sess,
        &mut CountRng(0),
        0x00,
        PW1_MODE82,
        &[],
    );
    assert_eq!(sw, Sw::retries(PW_RETRIES_DEFAULT));
}

#[test]
fn pin_and_dek_migrate_to_otp_kbase_at_verify() {
    // State written by a pre-OTP firmware…
    let mut fs = setup();
    let mut sess = Session::new();
    let mut rng = CountRng(0);
    let d = otp_dev();

    // …verifies under the OTP build via the fallback, without burning a retry
    // and with a working session (the DEK copy was re-wrapped).
    assert_eq!(
        verify(
            &d,
            &mut fs,
            &mut sess,
            &mut rng,
            0x00,
            PW1_MODE81,
            PW1_DEFAULT
        ),
        Sw::OK
    );
    assert!(sess.has_pw1);
    let mut dek = [0u8; DEK_SIZE];
    load_dek(&d, &mut fs, &sess, &mut dek).unwrap();

    // The stored verifier is now the OTP-arm one: a fresh session verifies
    // directly, and a wrong PIN still sees the full retry budget (C2 = 3-1).
    let mut sess2 = Session::new();
    assert_eq!(
        verify(
            &d,
            &mut fs,
            &mut sess2,
            &mut rng,
            0x00,
            PW1_MODE81,
            PW1_DEFAULT
        ),
        Sw::OK
    );
    let mut sess3 = Session::new();
    assert_eq!(
        verify(
            &d, &mut fs, &mut sess3, &mut rng, 0x00, PW1_MODE81, b"000000"
        ),
        Sw::new(0x63, 0xC2)
    );

    // PW3 migrates independently at its own verify.
    assert_eq!(
        verify(
            &d,
            &mut fs,
            &mut sess,
            &mut rng,
            0x00,
            PW3_MODE83,
            PW3_DEFAULT
        ),
        Sw::OK
    );
    let mut dek3 = [0u8; DEK_SIZE];
    load_dek(&d, &mut fs, &sess, &mut dek3).unwrap();
    // Same underlying DEK either way.
    assert_eq!(dek, dek3);

    // A pre-OTP device can no longer verify against the migrated verifier
    // (counter sits at 2 after the sess3 miss, so this burns it to 1).
    let mut sess4 = Session::new();
    assert_eq!(
        verify(
            &dev(),
            &mut fs,
            &mut sess4,
            &mut CountRng(0),
            0x00,
            PW1_MODE81,
            PW1_DEFAULT
        ),
        Sw::new(0x63, 0xC1)
    );
}

#[test]
fn verify_default_pw1_and_load_dek() {
    let mut fs = setup();
    let mut sess = Session::new();
    // PW1 default "123456", mode 0x81.
    let sw = verify(
        &dev(),
        &mut fs,
        &mut sess,
        &mut CountRng(0),
        0x00,
        PW1_MODE81,
        PW1_DEFAULT,
    );
    assert_eq!(sw, Sw::OK);
    assert!(sess.has_pw1);
    let mut dek = [0u8; DEK_SIZE];
    load_dek(&dev(), &mut fs, &sess, &mut dek).unwrap();
}

#[test]
fn verify_wrong_pin_decrements_then_blocks() {
    let mut fs = setup();
    let mut sess = Session::new();
    let d = dev();
    let mut rng = CountRng(0);
    // Wrong PW3 ("12345678" is right); 3 tries → block.
    for expect in [0xC2u8, 0xC1, 0x00] {
        let sw = verify(
            &d,
            &mut fs,
            &mut sess,
            &mut rng,
            0x00,
            PW3_MODE83,
            b"99999999",
        );
        if expect == 0 {
            assert_eq!(sw, Sw::PIN_BLOCKED);
        } else {
            assert_eq!(sw, Sw::new(0x63, expect));
        }
    }
    assert!(!sess.has_pw3);
}

#[test]
fn verify_resets_counter_on_success() {
    let mut fs = setup();
    let mut sess = Session::new();
    let d = dev();
    let mut rng = CountRng(0);
    // Two wrong, then correct, then wrong again → counter is back at C2.
    verify(
        &d,
        &mut fs,
        &mut sess,
        &mut rng,
        0x00,
        PW3_MODE83,
        b"00000000",
    );
    verify(
        &d,
        &mut fs,
        &mut sess,
        &mut rng,
        0x00,
        PW3_MODE83,
        b"00000000",
    );
    assert_eq!(
        verify(
            &d,
            &mut fs,
            &mut sess,
            &mut rng,
            0x00,
            PW3_MODE83,
            PW3_DEFAULT
        ),
        Sw::OK
    );
    assert_eq!(
        verify(
            &d,
            &mut fs,
            &mut sess,
            &mut rng,
            0x00,
            PW3_MODE83,
            b"00000000"
        ),
        Sw::new(0x63, 0xC2)
    );
}

#[test]
fn logout_clears_flag() {
    let mut fs = setup();
    let mut sess = Session::new();
    let d = dev();
    let mut rng = CountRng(0);
    verify(
        &d,
        &mut fs,
        &mut sess,
        &mut rng,
        0x00,
        PW1_MODE81,
        PW1_DEFAULT,
    );
    assert!(sess.has_pw1);
    assert_eq!(
        verify(&d, &mut fs, &mut sess, &mut rng, 0xFF, PW1_MODE81, &[]),
        Sw::OK
    );
    assert!(!sess.has_pw1);
}

#[test]
fn pw1_modes_are_independent_latches_issue25() {
    // Reproduces #25: gpg/scdaemon verifies one PIN entry into BOTH PW1 modes
    // back-to-back (82 then 81) before a decrypt. PW1.82 (the DECIPHER latch,
    // pso.rs `has_pw3 || has_pw2`) must survive the following PW1.81 verify —
    // else the next PSO:DECIPHER returns 6982 and gpg reports "Bad PIN".
    let mut fs = setup();
    let mut sess = Session::new();
    let d = dev();
    let mut rng = CountRng(0);
    assert_eq!(
        verify(
            &d,
            &mut fs,
            &mut sess,
            &mut rng,
            0x00,
            PW1_MODE82,
            PW1_DEFAULT
        ),
        Sw::OK
    );
    assert!(sess.has_pw2);
    assert_eq!(
        verify(
            &d,
            &mut fs,
            &mut sess,
            &mut rng,
            0x00,
            PW1_MODE81,
            PW1_DEFAULT
        ),
        Sw::OK
    );
    assert!(sess.has_pw1, "PW1.81 raised");
    assert!(
        sess.has_pw2,
        "PW1.82 must survive a later PW1.81 verify (else DECIPHER → 6982)"
    );
    // The DEK still unwraps under the surviving PW1 session.
    let mut dek = [0u8; DEK_SIZE];
    load_dek(&d, &mut fs, &sess, &mut dek).unwrap();
}

#[test]
fn change_pw1_then_new_pin_works_and_dek_survives() {
    let mut fs = setup();
    let mut sess = Session::new();
    let d = dev();
    let mut rng = CountRng(99);
    // The DEK as unwrapped before the change.
    verify(
        &d,
        &mut fs,
        &mut sess,
        &mut rng,
        0x00,
        PW1_MODE81,
        PW1_DEFAULT,
    );
    let mut dek_before = [0u8; DEK_SIZE];
    load_dek(&d, &mut fs, &sess, &mut dek_before).unwrap();
    sess.reset();

    // CHANGE PIN PW1: old "123456" -> new "654321".
    let mut data = Vec::new();
    data.extend_from_slice(PW1_DEFAULT);
    data.extend_from_slice(b"654321");
    assert_eq!(
        change_pin(&d, &mut fs, &mut sess, &mut rng, 0x00, PW1_MODE81, &data),
        Sw::OK
    );
    sess.reset();

    // Old PIN now fails, new PIN verifies + unwraps the SAME DEK.
    assert_ne!(
        verify(
            &d,
            &mut fs,
            &mut sess,
            &mut rng,
            0x00,
            PW1_MODE81,
            PW1_DEFAULT
        ),
        Sw::OK
    );
    assert_eq!(
        verify(
            &d, &mut fs, &mut sess, &mut rng, 0x00, PW1_MODE81, b"654321"
        ),
        Sw::OK
    );
    let mut dek_after = [0u8; DEK_SIZE];
    load_dek(&d, &mut fs, &sess, &mut dek_after).unwrap();
    assert_eq!(dek_before, dek_after);
}

#[test]
fn change_pin_rejects_unsupported_p2_without_touching_rc() {
    // Regression (audit run-14): CHANGE REFERENCE DATA with P2=0x82 (RC) must be
    // rejected up front. The old flow verified the current RC and then wrote the
    // EF_RC verifier before the trailing `match p2` rejected — desyncing the RC
    // verifier from its EF_DEK_RC seal.
    let mut fs = setup();
    let mut sess = Session::new();
    let d = dev();
    let mut rng = CountRng(21);

    // Provision a resetting code under admin (PW3), then snapshot EF_RC.
    verify(
        &d,
        &mut fs,
        &mut sess,
        &mut rng,
        0x00,
        PW3_MODE83,
        PW3_DEFAULT,
    );
    assert_eq!(
        put_reset_code(&d, &mut fs, &mut sess, &mut rng, b"resetcode"),
        Sw::OK
    );
    let mut rc_before = [0u8; 64];
    let n_before = fs.read(EF_RC, &mut rc_before).expect("RC provisioned");

    // CHANGE with P2=0x82 and the *correct* current RC: pre-fix this passed
    // check_pin and rewrote EF_RC before returning WRONG_P1P2.
    let mut data = Vec::new();
    data.extend_from_slice(b"resetcode");
    data.extend_from_slice(b"654321");
    assert_eq!(
        change_pin(&d, &mut fs, &mut sess, &mut rng, 0x00, PW1_MODE82, &data),
        Sw::WRONG_P1P2
    );

    // EF_RC is byte-identical: no stray verifier write happened.
    let mut rc_after = [0u8; 64];
    let n_after = fs.read(EF_RC, &mut rc_after).expect("RC still present");
    assert_eq!(rc_before[..n_before], rc_after[..n_after]);
}

#[test]
fn reset_retry_via_pw3_unblocks_pw1() {
    let mut fs = setup();
    let mut sess = Session::new();
    let d = dev();
    let mut rng = CountRng(7);
    // Block PW1 (3 wrong tries).
    for _ in 0..3 {
        verify(
            &d, &mut fs, &mut sess, &mut rng, 0x00, PW1_MODE81, b"000000",
        );
    }
    assert_eq!(
        verify(
            &d,
            &mut fs,
            &mut sess,
            &mut rng,
            0x00,
            PW1_MODE81,
            PW1_DEFAULT
        ),
        Sw::PIN_BLOCKED
    );
    // Admin (PW3) resets PW1 to "111111".
    verify(
        &d,
        &mut fs,
        &mut sess,
        &mut rng,
        0x00,
        PW3_MODE83,
        PW3_DEFAULT,
    );
    assert_eq!(
        reset_retry(
            &d, &mut fs, &mut sess, &mut rng, 0x02, PW1_MODE81, b"111111"
        ),
        Sw::OK
    );
    sess.reset();
    // PW1 works again with the new value, and the DEK is intact.
    verify(
        &d,
        &mut fs,
        &mut sess,
        &mut rng,
        0x00,
        PW3_MODE83,
        PW3_DEFAULT,
    ); // restore pw3
    assert_eq!(
        verify(
            &d, &mut fs, &mut sess, &mut rng, 0x00, PW1_MODE81, b"111111"
        ),
        Sw::OK
    );
    let mut dek = [0u8; DEK_SIZE];
    load_dek(&d, &mut fs, &sess, &mut dek).unwrap();
}

#[test]
fn reset_retry_via_pw3_needs_pw3() {
    let mut fs = setup();
    let mut sess = Session::new();
    let mut rng = CountRng(7);
    assert_eq!(
        reset_retry(
            &dev(),
            &mut fs,
            &mut sess,
            &mut rng,
            0x02,
            PW1_MODE81,
            b"111111"
        ),
        Sw::CONDITIONS_NOT_SATISFIED
    );
}

#[test]
fn reset_retry_via_default_rc_is_rejected() {
    let mut fs = setup();
    let mut sess = Session::new();
    let d = dev();
    let mut rng = CountRng(7);
    // The resetting code ships DEACTIVATED (no EF_RC): RESET RETRY P1=0 with the
    // old default "12345678" || new-PW1 must NOT reset PW1 — this was an
    // unauthenticated PW1-reset backdoor.
    let mut data = [0u8; 14];
    data[..8].copy_from_slice(PW3_DEFAULT);
    data[8..].copy_from_slice(b"111111");
    assert_eq!(
        reset_retry(&d, &mut fs, &mut sess, &mut rng, 0x00, PW1_MODE81, &data),
        Sw::REFERENCE_NOT_FOUND
    );
    // PW1 is unchanged: the original default still verifies, the attacker value does not.
    sess.reset();
    assert_eq!(
        verify(
            &d,
            &mut fs,
            &mut sess,
            &mut rng,
            0x00,
            PW1_MODE81,
            PW1_DEFAULT
        ),
        Sw::OK
    );
    sess.reset();
    assert_ne!(
        verify(
            &d, &mut fs, &mut sess, &mut rng, 0x00, PW1_MODE81, b"111111"
        ),
        Sw::OK
    );
}

#[test]
fn scan_files_neutralizes_a_legacy_default_reset_code() {
    let d = dev();
    let mut fs = setup();
    // Recreate the legacy-vulnerable state: RC verifier = default admin PIN with
    // an enabled retry counter (what firmware <= 0x07F6 wrote at init).
    put_verifier(&d, &mut fs, EF_RC, PW3_DEFAULT).unwrap();
    set_pin_retry_counter(&mut fs, EF_RC, PW_RETRIES_DEFAULT).unwrap();
    // Re-run init (reboot): the migration must delete the default RC.
    scan_files(&d, &mut fs, &mut CountRng(0)).unwrap();
    let mut rec = [0u8; 64];
    assert!(fs.read(EF_RC, &mut rec).is_none());
    // And the reset path is closed.
    let mut sess = Session::new();
    let mut rng = CountRng(7);
    let mut data = [0u8; 14];
    data[..8].copy_from_slice(PW3_DEFAULT);
    data[8..].copy_from_slice(b"111111");
    assert_ne!(
        reset_retry(&d, &mut fs, &mut sess, &mut rng, 0x00, PW1_MODE81, &data),
        Sw::OK
    );
}

#[test]
fn scan_files_preserves_a_custom_reset_code() {
    let d = dev();
    let mut fs = setup();
    let mut sess = Session::new();
    let mut rng = CountRng(7);
    verify(
        &d,
        &mut fs,
        &mut sess,
        &mut rng,
        0x00,
        PW3_MODE83,
        PW3_DEFAULT,
    );
    assert_eq!(
        put_reset_code(&d, &mut fs, &mut sess, &mut rng, b"resetme0"),
        Sw::OK
    );
    // Reboot: a real admin-set RC (verifier != default) must survive the migration.
    scan_files(&d, &mut fs, &mut CountRng(0)).unwrap();
    sess.reset();
    let mut data = [0u8; 14];
    data[..8].copy_from_slice(b"resetme0");
    data[8..].copy_from_slice(b"222222");
    assert_eq!(
        reset_retry(&d, &mut fs, &mut sess, &mut rng, 0x00, PW1_MODE81, &data),
        Sw::OK
    );
    sess.reset();
    // The new PW1 works and its DEK is recoverable.
    assert_eq!(
        verify(
            &d, &mut fs, &mut sess, &mut rng, 0x00, PW1_MODE81, b"222222"
        ),
        Sw::OK
    );
    let mut dek = [0u8; DEK_SIZE];
    load_dek(&d, &mut fs, &sess, &mut dek).unwrap();
}

#[test]
fn put_reset_code_then_reset_retry_via_rc() {
    let mut fs = setup();
    let mut sess = Session::new();
    let d = dev();
    let mut rng = CountRng(7);
    // Admin sets a custom reset code, which then unlocks a PW1 reset.
    verify(
        &d,
        &mut fs,
        &mut sess,
        &mut rng,
        0x00,
        PW3_MODE83,
        PW3_DEFAULT,
    );
    assert_eq!(
        put_reset_code(&d, &mut fs, &mut sess, &mut rng, b"resetme0"),
        Sw::OK
    );
    sess.reset();
    let mut data = [0u8; 14];
    data[..8].copy_from_slice(b"resetme0");
    data[8..].copy_from_slice(b"222222");
    assert_eq!(
        reset_retry(&d, &mut fs, &mut sess, &mut rng, 0x00, PW1_MODE81, &data),
        Sw::OK
    );
    sess.reset();
    assert_eq!(
        verify(
            &d, &mut fs, &mut sess, &mut rng, 0x00, PW1_MODE81, b"222222"
        ),
        Sw::OK
    );
    let mut dek = [0u8; DEK_SIZE];
    load_dek(&d, &mut fs, &sess, &mut dek).unwrap();
}

#[test]
fn put_reset_code_requires_pw3() {
    let mut fs = setup();
    let mut sess = Session::new();
    let mut rng = CountRng(7);
    assert_eq!(
        put_reset_code(&dev(), &mut fs, &mut sess, &mut rng, b"resetme0"),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    // A bad reset code is rejected by RESET RETRY P1=0.
    let mut data = [0u8; 14];
    data[..8].copy_from_slice(b"wrongrc0");
    data[8..].copy_from_slice(b"222222");
    let sw = reset_retry(
        &dev(),
        &mut fs,
        &mut sess,
        &mut rng,
        0x00,
        PW1_MODE81,
        &data,
    );
    assert_ne!(sw, Sw::OK);
}

/// VERIFY's P2 selects the verifier EF as `0x1000 | p2`, so it decides which
/// *file* the wrong-PIN path decrements and rewrites. The old filter was the bit
/// test `(p2 & 0x60) != 0`, which let 64 values through — internal FIDs belonging
/// to other applets among them, FIDO's `EF_PIN` included. Only a one-byte length
/// coincidence kept that from being a live cross-applet primitive, and that
/// constant is owned by a different crate (audit run-34 #21). Enumerate the three
/// defined modes, the way `change_pin` already did.
#[test]
fn verify_refuses_every_undefined_p2() {
    let d = dev();
    let mut fs = setup();
    let mut rng = CountRng(0);
    for p2 in 0u16..=0xFF {
        let p2 = p2 as u8;
        if matches!(p2, PW1_MODE81 | PW1_MODE82 | PW3_MODE83) {
            continue;
        }
        let mut sess = Session::new();
        assert_eq!(
            verify(&d, &mut fs, &mut sess, &mut rng, 0x00, p2, b"123456"),
            Sw::WRONG_P1P2,
            "P2={p2:#04x} must be refused before it names a file"
        );
    }
}
