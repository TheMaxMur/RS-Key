// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::init::scan_files;
use rsk_fs::storage::faults::{Cut, CutMedium, RemoveStuck};
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

/// [`setup`] on a medium that logs the order of the appends it serves — the only
/// place the re-arm of the at-rest lap can be seen to land BEFORE the re-key it
/// covers rather than after it.
fn setup_cut() -> (Fs<Cut>, CutMedium) {
    let (cut, medium) = Cut::new();
    let mut fs = Fs::new(cut);
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    (fs, medium)
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
    let (mut fs, medium) = setup_cut();
    let mut sess = Session::new();
    let mut rng = CountRng(0);
    let d = otp_dev();

    // The one-shot at-rest lap has already run on this device: the migration
    // below supersedes a chip-serial-rooted verifier and DEK copy AFTER it, so
    // it must re-arm the lap (audit run-35's rule).
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    assert!(
        fs.has_data(rsk_fs::EF_HARDENED),
        "fixture: the lap has latched"
    );

    // …verifies under the OTP build via the fallback, without burning a retry
    // and with a working session (the DEK copy was re-wrapped).
    medium.clear_ops();
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
    // Both appends of the migration, DEK first as `migrate_pin_kbase` orders them.
    medium.assert_re_armed_before(EF_DEK_PW1.get(), |_| false, "migrate_pin_kbase's DEK");
    medium.assert_re_armed_before(EF_PW1, |_| false, "migrate_pin_kbase's verifier");
    assert!(
        !fs.has_data(rsk_fs::EF_HARDENED),
        "migrate_pin_kbase re-keyed the verifier and the DEK off the chip-serial \
         root and must re-arm the at-rest lap",
    );
    let mut dek = Secret::<[u8; DEK_SIZE]>::zeroed();
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
    // The fallback arm is a SUCCESS: it must not take the wrong-password exit
    // that clears the addressed status, nor a sibling's.
    assert!(sess.has_pw3 && sess.has_pw1);
    let mut dek3 = Secret::<[u8; DEK_SIZE]>::zeroed();
    load_dek(&d, &mut fs, &sess, &mut dek3).unwrap();
    // Same underlying DEK either way.
    assert_eq!(dek.expose(), dek3.expose());

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
    let mut dek = Secret::<[u8; DEK_SIZE]>::zeroed();
    load_dek(&dev(), &mut fs, &sess, &mut dek).unwrap();
}

#[test]
fn a_malformed_pw_record_is_reference_not_found_not_a_verifier() {
    // `check_pin` accepts a record only at `n >= 3 && rec[0] != 0`. Neither half
    // was tested: a short record and a zeroed-length record both survived the
    // suite (the reverse mutation pass, D2). Both must exit
    // REFERENCE_NOT_FOUND — a record too short to hold `[len, fmt, verifier]`
    // reaches `size - 2` below, and a zero first byte is the poisoned shape PIV
    // already pins with `a_poisoned_reference_keeps_every_exit_it_had`. Sweep by
    // class, not by site.
    for (label, rec) in [
        ("empty", &[][..]),
        ("one byte", &[0x20][..]),
        ("two bytes", &[0x20, 0x01][..]),
        ("zeroed length", &[0x00, 0x01, 0xAB][..]),
    ] {
        let mut fs = setup();
        let mut sess = Session::new();
        fs.put(EF_PW1, rec).unwrap();
        assert_eq!(
            verify(
                &dev(),
                &mut fs,
                &mut sess,
                &mut CountRng(0),
                0x00,
                PW1_MODE81,
                PW1_DEFAULT,
            ),
            Sw::REFERENCE_NOT_FOUND,
            "a {label} PW1 record must not be read as a verifier"
        );
        assert!(!sess.has_pw1, "{label}: nothing may be authorised");
    }
}

#[test]
fn verify_wrong_pin_decrements_then_blocks() {
    let mut fs = setup();
    let mut sess = Session::new();
    let d = dev();
    let mut rng = CountRng(0);
    // Arm PW3 first, else the trailing `!sess.has_pw3` holds on a Session that was
    // never raised and the assertion cannot fail (run-34 #9 class).
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
    assert!(sess.has_pw3);
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
    let mut dek = Secret::<[u8; DEK_SIZE]>::zeroed();
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
    let mut dek_before = Secret::<[u8; DEK_SIZE]>::zeroed();
    load_dek(&d, &mut fs, &sess, &mut dek_before).unwrap();
    sess.reset();

    // CHANGE PIN PW1: old "123456" -> new "654321".
    let mut data = Vec::new();
    data.extend_from_slice(PW1_DEFAULT);
    data.extend_from_slice(b"654321");
    // The at-rest lap has already run: the commit below supersedes the DEK copy
    // sealed under the PIN the owner has just replaced, so it must re-arm it.
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    assert!(
        fs.has_data(rsk_fs::EF_HARDENED),
        "fixture: the lap has latched"
    );
    assert_eq!(
        change_pin(&d, &mut fs, &mut sess, &mut rng, 0x00, PW1_MODE81, &data),
        Sw::OK
    );
    assert!(
        !fs.has_data(rsk_fs::EF_HARDENED),
        "commit_staged_dek retired the copy sealed under the old PIN and must \
         re-arm the at-rest lap",
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
    let mut dek_after = Secret::<[u8; DEK_SIZE]>::zeroed();
    load_dek(&d, &mut fs, &sess, &mut dek_after).unwrap();
    assert_eq!(dek_before.expose(), dek_after.expose());
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
    let mut dek = Secret::<[u8; DEK_SIZE]>::zeroed();
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
    put_verifier(&d, &mut fs, EF_RC, PW3_DEFAULT, None).unwrap();
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
    let mut dek = Secret::<[u8; DEK_SIZE]>::zeroed();
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
    let mut dek = Secret::<[u8; DEK_SIZE]>::zeroed();
    load_dek(&d, &mut fs, &sess, &mut dek).unwrap();
}

/// Revoking the resetting code must take its STAGE slot with it. A torn or refused
/// PUT DATA 0xD3 leaves `EF_DEK_STAGE_RC` holding the whole DEK under the code the
/// next deactivation revokes — LIVE, so no at-rest lap can reach it, and invisible
/// to `load_dek`'s retirement, which needs an `sess.has_rc` that needs the `EF_RC`
/// the same deactivation has just deleted.
#[test]
fn deactivating_the_reset_code_takes_its_staged_dek_copy_with_it() {
    let mut fs = setup();
    let mut sess = Session::new();
    let mut rng = CountRng(7);
    let d = dev();
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
        put_reset_code(&d, &mut fs, &mut sess, &mut rng, b"resetme0"),
        Sw::OK
    );
    let mut dek = Secret::<[u8; DEK_SIZE]>::zeroed();
    load_dek(&d, &mut fs, &sess, &mut dek).unwrap();

    // An update that staged and then did not land.
    let (_session, _rearmed) =
        stage_dek(&d, &mut fs, &mut rng, EF_DEK_RC, b"resetme0", dek.expose()).unwrap();
    assert!(fs.has_key(EF_DEK_STAGE_RC), "fixture: the stage is live");

    assert_eq!(
        put_reset_code(&d, &mut fs, &mut sess, &mut rng, &[]),
        Sw::OK,
        "an empty PUT DATA 0xD3 deactivates the code"
    );
    assert!(!fs.has_data(EF_RC));
    assert!(!fs.has_key(EF_DEK_RC));
    assert!(
        !fs.has_key(EF_DEK_STAGE_RC),
        "the staged copy holds the whole DEK under the code this just revoked"
    );
}

/// A faulted read of the DEK copy must not leave the verifier migrated over it.
/// `store_verifier` runs after the re-wrap, so taking a failed read for "no copy"
/// moved PW1 to the fused root while its DEK copy stayed on the old one: the PIN
/// then verifies for ever and everything behind it answers `6A00`, with TERMINATE
/// DF the only way back.
#[test]
fn a_faulted_dek_read_does_not_migrate_the_verifier_alone() {
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    let mut rng = CountRng(0);
    scan_files(&dev(), &mut fs, &mut rng).unwrap();
    let d = otp_dev();

    let mut sess = Session::new();
    medium.stick_once(EF_DEK_PW1.get());
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
        Sw::MEMORY_FAILURE,
        "a migration that could not read the DEK copy must fail, not half-run"
    );

    // The verifier is where it was, so the PIN still opens its own DEK copy.
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
    let mut dek = Secret::<[u8; DEK_SIZE]>::zeroed();
    load_dek(&d, &mut fs, &sess2, &mut dek).expect("the DEK copy is still reachable");
}

/// The one secret the burn cannot move, and the shape of the residual. Both other
/// verifiers migrate at their first use; `migrate_pin_kbase` runs from `check_pin`'s
/// fallback, so it needs the secret in hand — and nothing presents a resetting code
/// except a RESET RETRY that may never come. Until one does, the RC verifier and the
/// DEK copy behind it stay rooted in the PUBLIC chip serial, where a flash dump
/// brute-forces the one and opens the other. The card cannot retire them on its own:
/// a verifier is an opaque hash of a secret it does not hold, so a pre-burn code and
/// one set afterwards are indistinguishable. Registered in docs/limitations.md and
/// as `PLAT-THREAT-002`; the last third of this case is the cure the card does have.
#[test]
fn a_reset_code_set_before_the_burn_stays_on_the_chip_serial_root() {
    let mut fs = setup();
    let mut sess = Session::new();
    let mut rng = CountRng(7);
    let pre = dev();
    assert_eq!(
        verify(
            &pre,
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
        put_reset_code(&pre, &mut fs, &mut sess, &mut rng, b"resetme0"),
        Sw::OK
    );
    sess.reset();

    // The burn, the boot pass it runs, and the PW1 verify that migrates PW1.
    let d = otp_dev();
    scan_files(&d, &mut fs, &mut rng).unwrap();
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
    let mut rec = [0u8; 64];
    fs.read(EF_PW1, &mut rec).unwrap();
    assert!(
        ct_eq(&rec[2..34], d.pin_derive_verifier(PW1_DEFAULT).expose()),
        "fixture: PW1 moved to the fused root at its first verify"
    );
    assert!(
        !ct_eq(&rec[2..34], pre.pin_derive_verifier(PW1_DEFAULT).expose()),
        "fixture: the two arms really do derive different verifiers"
    );
    fs.read(EF_RC, &mut rec).unwrap();
    assert!(
        ct_eq(&rec[2..34], pre.pin_derive_verifier(b"resetme0").expose()),
        "the resetting code is still rooted in the public chip serial"
    );
    // And PW3 with it — the likelier member of the same class, since ordinary use
    // presents PW1 and the admin surface may not be touched again after the burn.
    fs.read(EF_PW3, &mut rec).unwrap();
    assert!(
        ct_eq(&rec[2..34], pre.pin_derive_verifier(PW3_DEFAULT).expose()),
        "PW3 has not been presented since the burn, so it has not moved either"
    );

    // And the prize behind it: the DEK copy opens under the pre-burn session, so a
    // dump plus the public serial yields every key the DEK seals.
    let mut blob = [0u8; DEK_FILE_SIZE];
    let n = fs.read_key(EF_DEK_RC, &mut blob).unwrap().min(blob.len());
    let session = pre.pin_derive_session(b"resetme0");
    let mut from_flash = [0u8; DEK_SIZE];
    pre.decrypt_with_aad(session.expose(), &blob[1..n], PinKdf::V2, &mut from_flash)
        .expect("the DEK copy behind the resetting code is on the pre-burn root");
    let mut sess_pw1 = Session::new();
    assert_eq!(
        verify(
            &d,
            &mut fs,
            &mut sess_pw1,
            &mut rng,
            0x00,
            PW1_MODE81,
            PW1_DEFAULT
        ),
        Sw::OK
    );
    let mut live = Secret::<[u8; DEK_SIZE]>::zeroed();
    load_dek(&d, &mut fs, &sess_pw1, &mut live).unwrap();
    assert_eq!(
        &from_flash,
        live.expose(),
        "and it is the same DEK the card uses"
    );

    // And the cure the card has: USING the code is what re-keys it, both records.
    sess.reset();
    let mut data = [0u8; 14];
    data[..8].copy_from_slice(b"resetme0");
    data[8..].copy_from_slice(b"222222");
    assert_eq!(
        reset_retry(&d, &mut fs, &mut sess, &mut rng, 0x00, PW1_MODE81, &data),
        Sw::OK
    );
    fs.read(EF_RC, &mut rec).unwrap();
    assert!(
        ct_eq(&rec[2..34], d.pin_derive_verifier(b"resetme0").expose()),
        "the RESET RETRY that presented the code is what moves it to the fused root"
    );
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

#[test]
fn an_overlong_pw_status_record_cannot_panic_the_retry_writers() {
    // EF_PW_PRIV is Internal-only and has been 7 bytes in every revision, so this
    // is hardening, not a live bug: `Fs::read` reports the record's stored length,
    // and an unclamped `&pw[..n]` write-back would panic a panic-halt image.
    let mut fs = setup();
    let mut overlong = crate::files::PW_STATUS_DEFAULT.to_vec();
    overlong.resize(16, 0xAA);
    fs.put(EF_PW_PRIV, &overlong).unwrap();

    assert_eq!(spend_pin_retry(&mut fs, EF_PW1), Ok(PW_RETRIES_DEFAULT - 1));
    assert_eq!(pin_reset_retries(&mut fs, EF_PW1, false), Ok(()));
    assert_eq!(set_pin_retry_counter(&mut fs, EF_RC, 0), Ok(()));

    let mut pw = [0u8; 8];
    let n = fs.read(EF_PW_PRIV, &mut pw).unwrap();
    assert_eq!((n, pw[PW1_RETRY_IDX], pw[pw_retry_idx(EF_RC)]), (8, 3, 0));
}

use crate::dying_storage::DyingStorage;

/// Drive the REAL `change_pin` with the flash dying partway through, at every
/// write it makes, and require the card to be usable afterwards in every case.
///
/// Updating a PIN writes the verifier and the DEK copy sealed under it, and a cut
/// between them used to leave the new verifier standing over a copy sealed under
/// the PIN nobody holds: the new PIN verified and everything needing the DEK
/// answered `6400`. Ordering cannot fix it — mirrored, the tear is mirrored — so
/// the update stages, writes the verifier, then commits, and `load_dek` finishes
/// an interrupted one.
///
/// This drives the command, not the helpers. Rewiring `change_pin` back to a
/// straight re-wrap has to fail here, which is the point.
#[test]
fn change_pin_is_recoverable_at_every_write_it_makes() {
    const NEW: &[u8] = b"87654321";
    let d = dev();

    for budget in 0..12 {
        let (storage, tap) = DyingStorage::new();
        let mut fs = Fs::new(storage);
        fs.scan();
        scan_files(&d, &mut fs, &mut CountRng(0)).unwrap();
        let mut sess = Session::new();
        assert_eq!(
            verify(
                &d,
                &mut fs,
                &mut sess,
                &mut CountRng(0),
                0x00,
                PW3_MODE83,
                PW3_DEFAULT
            ),
            Sw::OK
        );
        let mut want = Secret::<[u8; DEK_SIZE]>::zeroed();
        load_dek(&d, &mut fs, &sess, &mut want).unwrap();

        tap.set(budget);
        let mut data = PW3_DEFAULT.to_vec();
        data.extend_from_slice(NEW);
        let sw = change_pin(
            &d,
            &mut fs,
            &mut sess,
            &mut CountRng(3),
            0x00,
            PW3_MODE83,
            &data,
        );
        tap.set(usize::MAX);

        // Whichever PIN the card came back on, that PIN must open the DEK — and
        // it must be the SAME key, not a new one.
        let mut after = Session::new();
        if verify(
            &d,
            &mut fs,
            &mut after,
            &mut CountRng(0),
            0x00,
            PW3_MODE83,
            NEW,
        ) != Sw::OK
        {
            after = Session::new();
            assert_eq!(
                verify(
                    &d,
                    &mut fs,
                    &mut after,
                    &mut CountRng(0),
                    0x00,
                    PW3_MODE83,
                    PW3_DEFAULT
                ),
                Sw::OK,
                "budget {budget}: neither PIN verifies — the card is unusable"
            );
        }
        let mut got = Secret::<[u8; DEK_SIZE]>::zeroed();
        load_dek(&d, &mut fs, &after, &mut got).unwrap_or_else(|e| {
            panic!("budget {budget} (change returned {sw:?}): the standing PIN cannot open the DEK: {e:?}")
        });
        assert_eq!(
            got.expose(),
            want.expose(),
            "budget {budget}: recovered a different key"
        );
        assert!(
            !fs.has_key(EF_DEK_STAGE_PW3),
            "budget {budget}: a stage survived a recovered card"
        );
    }
}

/// One staging slot per target. A shared slot is destroyed by the next PIN update
/// of any kind — including one the card refuses — and that takes the pending
/// recovery with it.
#[test]
fn a_pending_stage_survives_an_unrelated_pin_update() {
    let d = dev();
    let (mut fs, medium) = setup_cut();
    let mut sess = Session::new();
    verify(
        &d,
        &mut fs,
        &mut sess,
        &mut CountRng(0),
        0x00,
        PW3_MODE83,
        PW3_DEFAULT,
    );
    let mut dek = Secret::<[u8; DEK_SIZE]>::zeroed();
    load_dek(&d, &mut fs, &sess, &mut dek).unwrap();

    // A PW3 update torn after its verifier: PW3 stands on b"87654321", its copy
    // is still sealed under the default, and the stage holds the new one.
    const NEW3: &[u8] = b"87654321";
    let (_session, _rearmed) = stage_dek(
        &d,
        &mut fs,
        &mut CountRng(9),
        EF_DEK_PW3,
        NEW3,
        dek.expose(),
    )
    .unwrap();
    put_verifier(&d, &mut fs, EF_PW3, NEW3, None).unwrap();

    // Now a completely unrelated PW1 change, and a refused one for good measure.
    let mut s1 = Session::new();
    verify(
        &d,
        &mut fs,
        &mut s1,
        &mut CountRng(0),
        0x00,
        PW1_MODE81,
        PW1_DEFAULT,
    );
    let mut short = PW1_DEFAULT.to_vec();
    short.extend_from_slice(b"12");
    change_pin(
        &d,
        &mut fs,
        &mut s1,
        &mut CountRng(4),
        0x00,
        PW1_MODE81,
        &short,
    );
    let mut ok = PW1_DEFAULT.to_vec();
    ok.extend_from_slice(b"654321");
    assert_eq!(
        change_pin(
            &d,
            &mut fs,
            &mut s1,
            &mut CountRng(5),
            0x00,
            PW1_MODE81,
            &ok
        ),
        Sw::OK
    );

    // PW3's recovery must still be there.
    let mut s3 = Session::new();
    assert_eq!(
        verify(
            &d,
            &mut fs,
            &mut s3,
            &mut CountRng(0),
            0x00,
            PW3_MODE83,
            NEW3
        ),
        Sw::OK
    );
    // The at-rest lap has already run: the recovery below retires a copy sealed
    // under a PIN the owner has replaced, so it must re-arm it.
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    assert!(
        fs.has_data(rsk_fs::EF_HARDENED),
        "fixture: the lap has latched"
    );
    let mut got = Secret::<[u8; DEK_SIZE]>::zeroed();
    medium.clear_ops();
    load_dek(&d, &mut fs, &s3, &mut got)
        .expect("the PW3 stage was destroyed by an unrelated PW1 update");
    assert_eq!(got.expose(), dek.expose());
    medium.assert_re_armed_before(EF_DEK_PW3.get(), |_| false, "recover_staged_dek");
    assert!(
        !fs.has_data(rsk_fs::EF_HARDENED),
        "recover_staged_dek superseded the copy sealed under the old PIN and \
         must re-arm the at-rest lap",
    );
}

/// A DEK update abandoned before its verifier landed leaves a stage holding the
/// copy under a PIN nobody presents. The next successful open retires it — a lazy
/// supersession like every other, so it re-arms the at-rest lap too. Neither half
/// of that had a test.
#[test]
fn a_stale_stage_is_retired_and_re_arms_the_at_rest_lap() {
    let d = dev();
    let (mut fs, medium) = setup_cut();
    let mut sess = Session::new();
    assert_eq!(
        verify(
            &d,
            &mut fs,
            &mut sess,
            &mut CountRng(0),
            0x00,
            PW3_MODE83,
            PW3_DEFAULT
        ),
        Sw::OK
    );
    let mut dek = Secret::<[u8; DEK_SIZE]>::zeroed();
    load_dek(&d, &mut fs, &sess, &mut dek).unwrap();

    // An update that staged under a new PW3 and died before `put_verifier`: the
    // committed copy still opens under the standing PIN, so the stage is garbage.
    let (_session, _rearmed) = stage_dek(
        &d,
        &mut fs,
        &mut CountRng(9),
        EF_DEK_PW3,
        b"87654321",
        dek.expose(),
    )
    .unwrap();
    assert!(fs.has_key(EF_DEK_STAGE_PW3), "the fixture staged nothing");
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    assert!(
        fs.has_data(rsk_fs::EF_HARDENED),
        "fixture: the lap has latched"
    );

    let mut got = Secret::<[u8; DEK_SIZE]>::zeroed();
    medium.clear_ops();
    load_dek(&d, &mut fs, &sess, &mut got).unwrap();
    assert!(
        !fs.has_key(EF_DEK_STAGE_PW3),
        "a stage the committed copy proves garbage was left live",
    );
    medium.assert_re_armed_before(
        EF_DEK_STAGE_PW3.get(),
        |_| false,
        "load_dek retiring a stale stage",
    );
    assert!(
        !fs.has_data(rsk_fs::EF_HARDENED),
        "retiring a stale stage supersedes a copy sealed under a PIN nobody \
         holds and must re-arm the at-rest lap",
    );
    assert_eq!(got.expose(), dek.expose());
}

/// A refused new PIN must leave nothing behind. Staging before the value is
/// judged left an orphan record holding the DEK sealed under a value the card
/// rejected, which nothing ever retires.
#[test]
fn a_refused_new_pin_leaves_no_staged_record() {
    let d = dev();
    let mut fs = setup();
    let mut sess = Session::new();
    verify(
        &d,
        &mut fs,
        &mut sess,
        &mut CountRng(0),
        0x00,
        PW3_MODE83,
        PW3_DEFAULT,
    );
    let mut data = PW3_DEFAULT.to_vec();
    data.extend_from_slice(b"12"); // under PW3_MIN_LEN
    assert_ne!(
        change_pin(
            &d,
            &mut fs,
            &mut sess,
            &mut CountRng(3),
            0x00,
            PW3_MODE83,
            &data
        ),
        Sw::OK
    );
    assert!(!fs.has_key(EF_DEK_STAGE_PW3));
    // And the card is untouched.
    let mut s2 = Session::new();
    assert_eq!(
        verify(
            &d,
            &mut fs,
            &mut s2,
            &mut CountRng(0),
            0x00,
            PW3_MODE83,
            PW3_DEFAULT
        ),
        Sw::OK
    );
    let mut got = Secret::<[u8; DEK_SIZE]>::zeroed();
    load_dek(&d, &mut fs, &s2, &mut got).unwrap();
}

/// VERIFY's P1=FF security-status reset must refuse a password reference that
/// does not exist. §7.2.2 defines P2 = 81 / 82 / 83; an undefined one used to
/// fall through to `9000`, reporting a reset of nothing — while the very same
/// P2 on the P1=00 path answered `6B00`, so one command disagreed with itself.
/// A YubiKey 5.7.4 answers `6B00` to every undefined P2 here.
#[test]
fn a_status_reset_for_a_reference_that_does_not_exist_is_refused() {
    let d = dev();
    let mut fs = setup();
    let mut sess = Session::new();
    for p2 in [0x00u8, 0x80, 0x84, 0x85, 0xFF] {
        assert_eq!(
            verify(&d, &mut fs, &mut sess, &mut CountRng(0), 0xFF, p2, &[]),
            Sw::WRONG_P1P2,
            "P1=FF P2={p2:#04x}"
        );
        // The same undefined P2 on the other path, for the comparison that made
        // this a defect rather than a taste question.
        assert_eq!(
            verify(
                &d,
                &mut fs,
                &mut sess,
                &mut CountRng(0),
                0x00,
                p2,
                PW1_DEFAULT
            ),
            Sw::WRONG_P1P2,
            "P1=00 P2={p2:#04x}"
        );
    }
    // The three defined ones still reset, and only their own latch.
    for (p2, set, get) in [
        (PW1_MODE81, 0u8, 0u8),
        (PW1_MODE82, 1, 1),
        (PW3_MODE83, 2, 2),
    ] {
        let _ = (set, get);
        verify(
            &d,
            &mut fs,
            &mut sess,
            &mut CountRng(0),
            0x00,
            p2,
            PW1_DEFAULT,
        );
        assert_eq!(
            verify(&d, &mut fs, &mut sess, &mut CountRng(0), 0xFF, p2, &[]),
            Sw::OK,
            "P1=FF P2={p2:#04x} is defined and must work"
        );
    }
    assert!(!sess.has_pw1 && !sess.has_pw2 && !sess.has_pw3);
}

/// Verify all three references, leaving every access status standing.
fn arm_all(d: &Device, fs: &mut Fs<RamStorage>, sess: &mut Session) {
    let mut rng = CountRng(0);
    for (p2, pw) in [
        (PW1_MODE82, PW1_DEFAULT),
        (PW1_MODE81, PW1_DEFAULT),
        (PW3_MODE83, PW3_DEFAULT),
    ] {
        assert_eq!(verify(d, fs, sess, &mut rng, 0x00, p2, pw), Sw::OK);
    }
    assert!(sess.has_pw1 && sess.has_pw2 && sess.has_pw3);
}

#[test]
fn wrong_password_drops_only_the_addressed_access_status() {
    // E38(b): a failed comparison must clear the access status of exactly the
    // reference it addressed — measured on a YubiKey 5.7.4, which does it in
    // VERIFY and in CHANGE REFERENCE DATA alike. Ours kept all three, so PSO:CDS
    // went on signing with PW1 at 0/3 and the admin surface stayed open at PW3 0/3.
    let mut fs = setup();
    let mut sess = Session::new();
    let d = dev();
    let mut rng = CountRng(0);
    for (p2, wrong, keep) in [
        (PW1_MODE81, b"999999".as_slice(), [false, true, true]),
        (PW1_MODE82, b"999999".as_slice(), [true, false, true]),
        (PW3_MODE83, b"99999999".as_slice(), [true, true, false]),
    ] {
        arm_all(&d, &mut fs, &mut sess);
        assert_eq!(
            verify(&d, &mut fs, &mut sess, &mut rng, 0x00, p2, wrong),
            Sw::new(0x63, 0xC2),
            "VERIFY {p2:#04x} wrong"
        );
        assert_eq!(
            [sess.has_pw1, sess.has_pw2, sess.has_pw3],
            keep,
            "after a wrong VERIFY {p2:#04x}"
        );
    }
}

#[test]
fn change_pin_wrong_old_drops_only_the_addressed_access_status() {
    // Same rule on INS 0x24: the write-up named this path and only this one.
    let mut fs = setup();
    let mut sess = Session::new();
    let d = dev();
    let mut rng = CountRng(0);
    for (p2, data, keep) in [
        (PW1_MODE81, b"999999654321".as_slice(), [false, true, true]),
        (
            PW3_MODE83,
            b"9999999987654321".as_slice(),
            [true, true, false],
        ),
    ] {
        arm_all(&d, &mut fs, &mut sess);
        assert_eq!(
            change_pin(&d, &mut fs, &mut sess, &mut rng, 0x00, p2, data),
            Sw::new(0x63, 0xC2),
            "CHANGE {p2:#04x} wrong old"
        );
        assert_eq!(
            [sess.has_pw1, sess.has_pw2, sess.has_pw3],
            keep,
            "after a wrong CHANGE {p2:#04x}"
        );
    }
}

#[test]
fn wrong_reset_code_keeps_every_access_status() {
    // The trap in the same rule: RESET RETRY COUNTER checks EF_RC but passes
    // P2 = 0x81, so a clear keyed on P2 would revoke PW1.81 on a wrong resetting
    // code. A YubiKey keeps all three here — EF_RC carries no access status.
    let mut fs = setup();
    let mut sess = Session::new();
    let d = dev();
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
    arm_all(&d, &mut fs, &mut sess);
    assert_eq!(
        reset_retry(
            &d,
            &mut fs,
            &mut sess,
            &mut rng,
            0x00,
            PW1_MODE81,
            b"99999999111111"
        ),
        Sw::new(0x63, 0xC2)
    );
    assert!(sess.has_pw1 && sess.has_pw2 && sess.has_pw3);
}

#[test]
fn blocking_pw1_through_mode81_leaves_mode82_standing() {
    // PW1.81 and PW1.82 share one error counter but are independent statuses
    // (measured: a YubiKey with PW1 at 0/3 still serves a PW1.82-gated write).
    // Blocking through 81 must not take 82 down with it — the #25 shape again,
    // and the reason the clear is keyed per reference rather than per counter.
    let mut fs = setup();
    let mut sess = Session::new();
    let d = dev();
    let mut rng = CountRng(0);
    arm_all(&d, &mut fs, &mut sess);
    for expect in [
        Sw::new(0x63, 0xC2),
        Sw::new(0x63, 0xC1),
        Sw::PIN_BLOCKED,
        // The fourth is refused by the blocked floor, before any comparison: it
        // must not clear anything either.
        Sw::PIN_BLOCKED,
    ] {
        assert_eq!(
            verify(
                &d, &mut fs, &mut sess, &mut rng, 0x00, PW1_MODE81, b"999999"
            ),
            expect
        );
        assert!(!sess.has_pw1);
        assert!(sess.has_pw2 && sess.has_pw3);
    }
    // The floor sits above the clear for the *addressed* reference too, which
    // the loop above cannot show (81's latch is already down). Measured twice on
    // a YubiKey 5.7.4 with PW1 at 0/3: 6983 either way, and its PW1.82-gated
    // write (DO 0101, PW3 down) still answers 9000.
    for pw in [b"999999".as_slice(), PW1_DEFAULT] {
        assert_eq!(
            verify(&d, &mut fs, &mut sess, &mut rng, 0x00, PW1_MODE82, pw),
            Sw::PIN_BLOCKED
        );
        assert!(sess.has_pw2 && sess.has_pw3, "the floor cleared a latch");
    }
}

#[test]
fn the_status_query_reports_the_latch_before_the_counter() {
    // E47. §7.2.2's empty-Lc VERIFY reports the *verification state*, and a
    // YubiKey 5.7.4 never answers 6983 to it — measured with PW1 at 0/3: the
    // standing PW1.82 latch reports 9000 three readings running, and once that
    // latch is dropped the same query reports 63C0, not 6983. Ours returned
    // PIN_BLOCKED for both, so a host could not tell an authorised session from
    // a dead one — and the latch really is live, since it still authorises
    // PSO:DECIPHER and INTERNAL AUTHENTICATE.
    let mut fs = setup();
    let mut sess = Session::new();
    let d = dev();
    let mut rng = CountRng(0);
    arm_all(&d, &mut fs, &mut sess);

    // Block PW1 through mode 81; 82's latch stays up (they share one counter).
    for _ in 0..PW_RETRIES_DEFAULT {
        verify(
            &d, &mut fs, &mut sess, &mut rng, 0x00, PW1_MODE81, b"999999",
        );
    }
    assert!(sess.has_pw2, "the counter is blocked, the 82 latch is not");

    let status = |fs: &mut Fs<RamStorage>, sess: &mut Session, p2| {
        verify(&d, fs, sess, &mut CountRng(0), 0x00, p2, &[])
    };
    // Latch up, retries 0 → the session is still good.
    assert_eq!(status(&mut fs, &mut sess, PW1_MODE82), Sw::OK);
    // Latch down, retries 0 → the count, which is zero. Never PIN_BLOCKED.
    assert_eq!(status(&mut fs, &mut sess, PW1_MODE81), Sw::retries(0));
    assert_eq!(
        verify(&d, &mut fs, &mut sess, &mut rng, 0xFF, PW1_MODE82, &[]),
        Sw::OK,
        "P1=FF drops the 82 latch"
    );
    assert_eq!(status(&mut fs, &mut sess, PW1_MODE82), Sw::retries(0));

    // The unblocked reference is unaffected in both directions.
    assert_eq!(status(&mut fs, &mut sess, PW3_MODE83), Sw::OK);
    assert_eq!(
        verify(&d, &mut fs, &mut sess, &mut rng, 0xFF, PW3_MODE83, &[]),
        Sw::OK
    );
    assert_eq!(
        status(&mut fs, &mut sess, PW3_MODE83),
        Sw::retries(PW_RETRIES_DEFAULT)
    );

    // The DATA form still refuses a blocked reference — that floor is separate,
    // and the YubiKey answers 6983 there with the correct password too.
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
}

/// The retry counters as DO C4 reports them, and whether the reference is latched.
fn state(fs: &mut Fs<RamStorage>, sess: &mut Session, p2: u8, fid: u16) -> (u8, Sw) {
    let mut pw = [0u8; 8];
    let n = fs.read(EF_PW_PRIV, &mut pw).unwrap_or(0);
    let idx = pw_retry_idx(fid);
    let left = if idx < n { pw[idx] } else { 0 };
    let latch = verify(&dev(), fs, sess, &mut CountRng(0), 0x00, p2, &[]);
    (left, latch)
}

#[test]
fn a_password_of_an_impossible_length_is_not_a_wrong_password() {
    // Measured on a YubiKey 5.7.4, 3/3 at every boundary: PW1 below 6 or above 127
    // and PW3 below 8 or above 127 answer `6A80`, spend no retry and leave the
    // standing access status up. A length the reference could not have is a
    // malformed request; only a plausible one is an attempt.
    for (p2, fid, good, impossible, plausible) in [
        (
            PW1_MODE81,
            EF_PW1,
            PW1_DEFAULT,
            [1usize, 2, 5, 128, 129, 200, 255].as_slice(),
            [6usize, 7, 127].as_slice(),
        ),
        (
            PW3_MODE83,
            EF_PW3,
            PW3_DEFAULT,
            [1, 2, 5, 6, 7, 128, 129, 200, 255].as_slice(),
            [8, 9, 127].as_slice(),
        ),
    ] {
        let mut fs = setup();
        let mut sess = Session::new();
        let d = dev();
        let arm = |fs: &mut Fs<RamStorage>, sess: &mut Session| {
            assert_eq!(
                verify(&d, fs, sess, &mut CountRng(0), 0x00, p2, good),
                Sw::OK
            );
        };

        arm(&mut fs, &mut sess);
        for len in impossible {
            let sw = verify(
                &d,
                &mut fs,
                &mut sess,
                &mut CountRng(0),
                0x00,
                p2,
                &vec![b'A'; *len],
            );
            assert_eq!(sw, Sw::WRONG_DATA, "{p2:02X}: a {len}-byte value");
            assert_eq!(
                state(&mut fs, &mut sess, p2, fid),
                (PW_RETRIES_DEFAULT, Sw::OK),
                "{p2:02X}: a {len}-byte value cost a retry or the latch"
            );
        }
        // The control: a wrong password of a length the reference could have IS an
        // attempt, and must go on costing one.
        for len in plausible {
            arm(&mut fs, &mut sess);
            let sw = verify(
                &d,
                &mut fs,
                &mut sess,
                &mut CountRng(0),
                0x00,
                p2,
                &vec![b'A'; *len],
            );
            assert_eq!(sw, Sw::retries(PW_RETRIES_DEFAULT - 1), "{p2:02X}/{len}");
            assert_eq!(
                state(&mut fs, &mut sess, p2, fid).1,
                Sw::retries(PW_RETRIES_DEFAULT - 1),
                "{p2:02X}: a plausible wrong value must drop the latch"
            );
        }
    }
}

#[test]
fn a_stored_reference_outside_the_policy_still_verifies() {
    // `PIN_MAX_LEN` arrived with 055ef86, whose diff ADDS `check_pin_len` — so an
    // older build stored whatever it was given, and the guide still promises a
    // shorter legacy value keeps working. The length gate must not lock that owner
    // out of their own key: it applies only where the stored reference is itself
    // inside the policy.
    let mut fs = setup();
    let mut sess = Session::new();
    let d = dev();
    store_verifier(&d, &mut fs, EF_PW1, b"abc", None).unwrap();

    assert_eq!(
        verify(
            &d,
            &mut fs,
            &mut sess,
            &mut CountRng(0),
            0x00,
            PW1_MODE81,
            b"abc"
        ),
        Sw::OK,
        "a legacy 3-byte reference must still verify"
    );
    // And a wrong value of that same impossible length is still an attempt here —
    // the gate is off for this card, not inverted.
    assert_eq!(
        verify(
            &d,
            &mut fs,
            &mut sess,
            &mut CountRng(0),
            0x00,
            PW1_MODE81,
            b"abd"
        ),
        Sw::retries(PW_RETRIES_DEFAULT - 1)
    );
}

/// Drive the REAL first boot with the flash dying at every write it makes, boot
/// again on the same flash, and require the card to be usable afterwards.
///
/// Provisioning writes the DEK sealed under PW1 and then the same DEK sealed
/// under PW3, and a cut between them used to be permanent: the next boot saw
/// PW1's copy, skipped the whole block — and wrote the PW3 verifier anyway. PW3
/// then verified for ever over a DEK copy that did not exist, so every operation
/// needing it answered `6A88` and only TERMINATE DF escaped. The trigger is
/// narrow (a first boot interrupted at exactly the wrong moment) and the outcome
/// was not.
#[test]
fn provisioning_is_recoverable_at_every_write_it_makes() {
    let d = dev();
    for budget in 0..14 {
        let (storage, tap) = DyingStorage::new();
        let mut fs = Fs::new(storage);
        fs.scan();

        tap.set(budget);
        let _ = scan_files(&d, &mut fs, &mut CountRng(0));
        // Power comes back; a different RNG, so a DEK regenerated on this boot is
        // provably not the one the interrupted boot was writing.
        tap.set(usize::MAX);
        scan_files(&d, &mut fs, &mut CountRng(9))
            .unwrap_or_else(|e| panic!("budget {budget}: the second boot failed: {e:?}"));

        // Both defaults verify, and both open the SAME DEK.
        let mut deks = [
            Secret::<[u8; DEK_SIZE]>::zeroed(),
            Secret::<[u8; DEK_SIZE]>::zeroed(),
        ];
        for (i, (p2, pw)) in [(PW1_MODE81, PW1_DEFAULT), (PW3_MODE83, PW3_DEFAULT)]
            .into_iter()
            .enumerate()
        {
            let mut sess = Session::new();
            assert_eq!(
                verify(&d, &mut fs, &mut sess, &mut CountRng(0), 0x00, p2, pw),
                Sw::OK,
                "budget {budget}: the default {p2:02X} does not verify"
            );
            load_dek(&d, &mut fs, &sess, &mut deks[i]).unwrap_or_else(|e| {
                panic!("budget {budget}: {p2:02X} verifies but cannot open the DEK: {e:?}")
            });
        }
        assert_eq!(
            deks[0].expose(),
            deks[1].expose(),
            "budget {budget}: the two PINs unwrap different keys"
        );
    }
}

/// A store whose write to ONE fid reports success and keeps the old bytes — the
/// flash program that answered `Ok` and did not land. `DyingStorage` models the
/// loud half of that (an `Err` the caller can see); this is the silent half,
/// which is the one a limiter cannot notice on its own.
///
/// Deliberately narrow: one fid, `write` only. An injector that faults more than
/// the property is about makes the interleaving unreachable and then passes over
/// its own blind spot.
struct DeafStorage {
    inner: RamStorage,
    fid: u16,
    deaf: std::rc::Rc<std::cell::Cell<bool>>,
}

impl rsk_fs::Storage for DeafStorage {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.inner.read(fid, buf)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
        if self.deaf.get() && fid == self.fid {
            return Ok(());
        }
        self.inner.write(fid, data)
    }
    fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
        self.inner.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.inner.size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(f)
    }
}

/// A provisioned card whose EF_PW_PRIV writes can be made deaf after boot — the
/// counter must be real while the applet provisions itself.
fn deaf_setup() -> (Fs<DeafStorage>, std::rc::Rc<std::cell::Cell<bool>>) {
    let deaf = std::rc::Rc::new(std::cell::Cell::new(false));
    let mut fs = Fs::new(DeafStorage {
        inner: RamStorage::new(),
        fid: EF_PW_PRIV,
        deaf: deaf.clone(),
    });
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    (fs, deaf)
}

fn pw3_retries_left<S: rsk_fs::Storage>(fs: &mut Fs<S>) -> u8 {
    let mut pw = [0u8; 8];
    let n = fs.read(EF_PW_PRIV, &mut pw).expect("EF_PW_PRIV");
    assert!(n > PW3_RETRY_IDX);
    pw[PW3_RETRY_IDX]
}

/// The retry counter is this applet's ONLY rate limit — there is no per-boot soft
/// lock like clientPIN's — so an attempt whose decrement never reaches flash is a
/// free guess, repeatable at one power cycle apiece. A wrong password must
/// therefore be refused outright when the charge cannot be proved.
#[test]
fn a_wrong_password_is_refused_when_the_attempt_cannot_be_charged() {
    let (mut fs, deaf) = deaf_setup();
    let mut sess = Session::new();
    deaf.set(true);
    let sw = verify(
        &dev(),
        &mut fs,
        &mut sess,
        &mut CountRng(0),
        0x00,
        PW3_MODE83,
        b"99999999",
    );
    deaf.set(false);
    assert_eq!(
        sw,
        Sw::MEMORY_FAILURE,
        "a wrong password answered from a limiter that did not move is a free guess"
    );
    assert_eq!(
        pw3_retries_left(&mut fs),
        PW_RETRIES_DEFAULT,
        "the counter really did not move — the refusal is the whole protection here"
    );
}

/// Order is what closes it, not the read-back: on a full counter the success path
/// rewrites the value it already holds, so a read-back placed after the comparison
/// is satisfied by a store that stored nothing. The consequence, and the only
/// assertion that can tell the two orders apart — the RIGHT password fails too
/// when the attempt cannot be charged. Measured, not assumed: with the charge
/// moved back after the comparison and the read-back kept, the wrong-password
/// case above still passes and only this one falls.
#[test]
fn even_the_right_password_is_charged_before_it_is_compared() {
    let (mut fs, deaf) = deaf_setup();
    let mut sess = Session::new();
    deaf.set(true);
    let sw = verify(
        &dev(),
        &mut fs,
        &mut sess,
        &mut CountRng(0),
        0x00,
        PW3_MODE83,
        PW3_DEFAULT,
    );
    deaf.set(false);
    assert_eq!(sw, Sw::MEMORY_FAILURE);
    assert!(
        !sess.has_pw3,
        "an uncharged attempt may not raise an access status"
    );
}

/// Clearing the reset code (`PUT DATA 0xD3` with an empty body) drops the RC
/// verifier and the DEK copy sealed under it. Both were `let _ =` and the card
/// answered `9000` regardless — so a flash that refused the removals left a
/// RESET RETRY path live behind a card that had just reported it revoked. The
/// delete-caller audit's fail-OPEN direction: the survivor is a credential, not
/// a lock, and nothing else on the card repairs it (`init`'s
/// `neutralize_default_reset_code` only reaches the FACTORY one).
#[test]
fn clearing_the_reset_code_answers_for_a_reset_code_that_survives() {
    let d = dev();
    let (storage, tap) = DyingStorage::new();
    let mut fs = Fs::new(storage);
    fs.scan();
    scan_files(&d, &mut fs, &mut CountRng(0)).unwrap();
    let mut sess = Session::new();
    assert_eq!(
        verify(
            &d,
            &mut fs,
            &mut sess,
            &mut CountRng(0),
            0x00,
            PW3_MODE83,
            PW3_DEFAULT
        ),
        Sw::OK
    );
    assert_eq!(
        put_reset_code(&d, &mut fs, &mut sess, &mut CountRng(7), b"resetme0"),
        Sw::OK
    );

    tap.set(0); // the medium takes nothing more
    let cleared = put_reset_code(&d, &mut fs, &mut sess, &mut CountRng(7), b"");
    tap.set(usize::MAX);

    // The proof that the answer would have been a lie: the code it says is gone
    // still resets PW1.
    sess.reset();
    let mut data = [0u8; 14];
    data[..8].copy_from_slice(b"resetme0");
    data[8..].copy_from_slice(b"222222");
    let still_resets = reset_retry(
        &d,
        &mut fs,
        &mut sess,
        &mut CountRng(7),
        0x00,
        PW1_MODE81,
        &data,
    ) == Sw::OK;

    assert_eq!(
        (cleared, still_resets),
        (Sw::MEMORY_FAILURE, true),
        "the reset code outlived the command that says it cleared it"
    );
}

/// `put_reset_code`'s clear arm folds `set_pin_retry_counter`'s failures into the
/// delete answer, and says so because only one of the three is reachable. This is
/// the half of that claim a script can hold: the shipped record has to be long
/// enough for every counter index, or the fold starts hiding a real `idx >= n`.
#[test]
fn pw_status_default_holds_every_retry_counter() {
    for fid in [EF_PW1, EF_RC, EF_PW3] {
        assert!(
            pw_retry_idx(fid) < crate::files::PW_STATUS_DEFAULT.len(),
            "{fid:#06x}'s retry counter is past the end of the shipped EF_PW_PRIV"
        );
    }
}

/// F5: a fourteenth site, invisible to `git grep request_rescrub` because it called
/// it never. `init::neutralize_default_reset_code` drops the SAME two records as PUT
/// DATA `0xD3`'s clear arm, on a card from firmware <= 0x07F6 whose RC verifier is
/// still the public admin default — and it runs from `scan_files`, which TERMINATE DF
/// re-runs mid-session and boot runs BEFORE the lap. A sweep that failed to clear
/// EF_RC therefore reaches it with the marker already latched.
#[test]
fn neutralizing_a_pre_otp_default_reset_code_re_arms_the_at_rest_lap() {
    let (mut fs, medium) = setup_cut();
    let d_pre = dev();
    let d_otp = otp_dev();

    // The legacy state, rooted where firmware <= 0x07F6 wrote it: the chip serial.
    put_verifier(&d_pre, &mut fs, EF_RC, PW3_DEFAULT, None).unwrap();
    set_pin_retry_counter(&mut fs, EF_RC, PW_RETRIES_DEFAULT).unwrap();
    let mut rc_rec = [0u8; 34];
    assert_eq!(fs.read(EF_RC, &mut rc_rec), Some(34));
    assert_eq!(
        &rc_rec[2..],
        &d_pre.pin_derive_verifier(PW3_DEFAULT).expose()[..],
        "fixture: the record about to be tombstoned is chip-serial-rooted",
    );
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    assert!(
        fs.has_data(rsk_fs::EF_HARDENED),
        "fixture: the lap has latched"
    );

    medium.clear_ops();
    scan_files(&d_otp, &mut fs, &mut CountRng(0)).unwrap();
    assert!(
        fs.read(EF_RC, &mut rc_rec).is_none(),
        "fixture: the neutralisation really ran and dropped EF_RC"
    );
    medium.assert_re_armed_before(EF_RC, |_| false, "neutralize_default_reset_code");
    assert!(
        !fs.has_data(rsk_fs::EF_HARDENED),
        "the tombstone supersedes a chip-serial-rooted verifier after the lap, so \
         this site owes the same re-arm as PUT DATA 0xD3's clear arm",
    );
}

/// The other direction of F5's one exception, so nobody tightens it into the gate
/// every other site got. When the medium refuses the re-arm, this tombstone still
/// goes ahead: leaving the record in force here means leaving a live unauthenticated
/// `RESET RETRY P1=0` path, which is worse than a superseded copy in the ring.
#[test]
fn a_refused_re_arm_still_closes_the_default_reset_code_backdoor() {
    let (stuck, medium) = RemoveStuck::new();
    let mut fs = Fs::new(stuck);
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    let d_pre = dev();
    let d_otp = otp_dev();

    put_verifier(&d_pre, &mut fs, EF_RC, PW3_DEFAULT, None).unwrap();
    set_pin_retry_counter(&mut fs, EF_RC, PW_RETRIES_DEFAULT).unwrap();
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    medium.refuse(Some(rsk_fs::EF_HARDENED));

    scan_files(&d_otp, &mut fs, &mut CountRng(0)).unwrap();
    assert!(
        medium.live(rsk_fs::EF_HARDENED) && fs.has_data(rsk_fs::EF_HARDENED),
        "fixture: the medium really refused the re-arm"
    );
    let mut rc_rec = [0u8; 34];
    assert!(
        fs.read(EF_RC, &mut rc_rec).is_none(),
        "the failed re-arm must not leave the public-default reset code standing",
    );
    // The load-bearing half: the unauthenticated reset path is shut.
    let mut sess = Session::new();
    let mut rng = CountRng(7);
    let mut data = [0u8; 14];
    data[..8].copy_from_slice(PW3_DEFAULT);
    data[8..].copy_from_slice(b"111111");
    assert_ne!(
        reset_retry(
            &d_otp, &mut fs, &mut sess, &mut rng, 0x00, PW1_MODE81, &data
        ),
        Sw::OK
    );
}

/// Clearing the reset code tombstones `EF_RC` AND `EF_DEK_RC`. Neither migrates
/// off the pre-OTP root except through the RC's own verify, so on a card whose
/// reset code was set before the burn both are still rooted in the public chip
/// serial — and `EF_DEK_RC` is the card's DEK, which the clear does not rotate.
/// A revoked credential wrapping a live key: audit run-35's rule reaches it.
#[test]
fn clearing_a_pre_otp_reset_code_re_arms_the_at_rest_lap() {
    let (mut fs, medium) = setup_cut();
    let d_pre = dev();
    let d_otp = otp_dev();
    let mut rng = CountRng(7);
    const RC: &[u8] = b"resetme0";

    // Pre-burn: admin sets a reset code, so EF_RC and EF_DEK_RC are both
    // chip-serial-rooted.
    let mut sess = Session::new();
    assert_eq!(
        verify(
            &d_pre,
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
        put_reset_code(&d_pre, &mut fs, &mut sess, &mut rng, RC),
        Sw::OK
    );

    let mut rc_rec = [0u8; 34];
    assert_eq!(fs.read(EF_RC, &mut rc_rec), Some(34));
    assert_eq!(
        &rc_rec[2..],
        &d_pre.pin_derive_verifier(RC).expose()[..],
        "fixture: EF_RC is rooted in the public chip serial",
    );

    // Open the RC-sealed DEK the way an offline attacker with the flash dump
    // and a candidate RC would: the session key is chip-serial-derived.
    let mut blob = [0u8; DEK_FILE_SIZE];
    let n = fs
        .read_key(EF_DEK_RC, &mut blob)
        .expect("EF_DEK_RC present");
    assert_eq!(blob[0], DEK_FORMAT_V3);
    let mut dek_from_rc = [0u8; DEK_SIZE];
    d_pre
        .decrypt_with_aad(
            d_pre.pin_derive_session(RC).expose(),
            &blob[1..n],
            PinKdf::V2,
            &mut dek_from_rc,
        )
        .expect("fixture: the RC-sealed copy opens under the chip-serial arm");

    // The OTP build. PW3's own verify migrates and re-arms; a boot re-latches.
    let mut sess = Session::new();
    assert_eq!(
        verify(
            &d_otp,
            &mut fs,
            &mut sess,
            &mut rng,
            0x00,
            PW3_MODE83,
            PW3_DEFAULT
        ),
        Sw::OK
    );
    assert!(
        !fs.has_data(rsk_fs::EF_HARDENED),
        "fixture: PW3's own migrating verify re-arms the lap"
    );
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    assert!(
        fs.has_data(rsk_fs::EF_HARDENED),
        "fixture: the lap has latched"
    );

    // The RC half is untouched by that migration: still chip-serial-rooted.
    assert_eq!(fs.read(EF_RC, &mut rc_rec), Some(34));
    assert_eq!(
        &rc_rec[2..],
        &d_pre.pin_derive_verifier(RC).expose()[..],
        "fixture: the PW3 migration did not touch EF_RC",
    );
    assert!(fs.has_key(EF_DEK_RC), "fixture: EF_DEK_RC is still there");

    medium.clear_ops();
    assert_eq!(
        put_reset_code(&d_otp, &mut fs, &mut sess, &mut rng, b""),
        Sw::OK
    );
    assert!(
        fs.read(EF_RC, &mut rc_rec).is_none(),
        "fixture: EF_RC dropped"
    );
    assert!(!fs.has_key(EF_DEK_RC), "fixture: EF_DEK_RC dropped");
    // Both tombstones the clear appends; each supersedes a chip-serial-rooted copy.
    medium.assert_re_armed_before(EF_RC, |_| false, "PUT DATA 0xD3 clearing EF_RC");
    medium.assert_re_armed_before(
        EF_DEK_RC.get(),
        |_| false,
        "PUT DATA 0xD3 clearing EF_DEK_RC",
    );

    // The load-bearing half: the clear did NOT rotate the DEK, so the copy it
    // tombstoned still opens the card's keys.
    let mut dek_live = Secret::<[u8; DEK_SIZE]>::zeroed();
    load_dek(&d_otp, &mut fs, &sess, &mut dek_live).unwrap();
    assert_eq!(
        dek_live.expose(),
        &dek_from_rc,
        "the DEK recoverable from the tombstoned RC copy is still the live one",
    );

    assert!(
        !fs.has_data(rsk_fs::EF_HARDENED),
        "clearing the reset code superseded a chip-serial-rooted DEK copy and must re-arm the lap",
    );
}

/// `stage_dek` is claimed as the ONE re-arm covering four call sequences, and only
/// `reset_retry`'s P1=0x02 arm held it. This is the RC arm: `check_pin` verifies
/// EF_RC — already OTP-rooted here, so it migrates nothing and re-arms nothing — and
/// the sequence then re-keys EF_PW1, which no RC verify ever touches. The only
/// re-arm in the whole command is the one under test.
#[test]
fn reset_retry_via_the_reset_code_re_arms_the_at_rest_lap() {
    let (mut fs, medium) = setup_cut();
    let d_otp = otp_dev();
    let mut rng = CountRng(7);
    let mut sess = Session::new();
    assert_eq!(
        verify(
            &d_otp,
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
        put_reset_code(&d_otp, &mut fs, &mut sess, &mut rng, b"resetme0"),
        Sw::OK
    );
    // EF_PW1 was never verified, so it is still chip-serial-rooted.
    let mut rec = [0u8; 34];
    assert_eq!(fs.read(EF_PW1, &mut rec), Some(34));
    assert_eq!(
        &rec[2..],
        &dev().pin_derive_verifier(PW1_DEFAULT).expose()[..],
        "fixture: EF_PW1 is rooted in the public chip serial",
    );
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();

    medium.clear_ops();
    let mut data = [0u8; 14];
    data[..8].copy_from_slice(b"resetme0");
    data[8..].copy_from_slice(b"222222");
    assert_eq!(
        reset_retry(
            &d_otp, &mut fs, &mut sess, &mut rng, 0x00, PW1_MODE81, &data
        ),
        Sw::OK
    );
    medium.assert_re_armed_before(EF_PW1, |_| false, "RESET RETRY P1=0's verifier write");
    medium.assert_re_armed_before(EF_DEK_PW1.get(), |_| false, "RESET RETRY P1=0's DEK commit");
    assert_eq!(fs.read(EF_PW1, &mut rec), Some(34));
    assert_eq!(
        &rec[2..],
        &d_otp.pin_derive_verifier(b"222222").expose()[..],
        "fixture: the reset re-keyed EF_PW1 under the OTP arm",
    );
    assert!(!fs.has_data(rsk_fs::EF_HARDENED));
}

/// The third of the four: PUT DATA `0xD3`'s SET arm. PW3's verify migrates PW3 and
/// re-arms on its own, so the marker is re-latched after it — what re-keys EF_RC and
/// EF_DEK_RC here, both still chip-serial-rooted from a pre-burn reset code, is the
/// stage/verifier/commit sequence and nothing else.
#[test]
fn setting_a_new_reset_code_re_arms_the_at_rest_lap() {
    let (mut fs, medium) = setup_cut();
    let d_pre = dev();
    let d_otp = otp_dev();
    let mut rng = CountRng(7);

    let mut sess = Session::new();
    assert_eq!(
        verify(
            &d_pre,
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
        put_reset_code(&d_pre, &mut fs, &mut sess, &mut rng, b"resetme0"),
        Sw::OK
    );
    let mut rc_rec = [0u8; 34];
    assert_eq!(fs.read(EF_RC, &mut rc_rec), Some(34));
    assert_eq!(
        &rc_rec[2..],
        &d_pre.pin_derive_verifier(b"resetme0").expose()[..],
        "fixture: the RC the SET below supersedes is chip-serial-rooted",
    );

    sess.reset();
    assert_eq!(
        verify(
            &d_otp,
            &mut fs,
            &mut sess,
            &mut rng,
            0x00,
            PW3_MODE83,
            PW3_DEFAULT
        ),
        Sw::OK
    );
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    assert_eq!(fs.read(EF_RC, &mut rc_rec), Some(34));
    assert_eq!(
        &rc_rec[2..],
        &d_pre.pin_derive_verifier(b"resetme0").expose()[..],
        "fixture: the PW3 migration did not touch EF_RC",
    );

    medium.clear_ops();
    assert_eq!(
        put_reset_code(&d_otp, &mut fs, &mut sess, &mut rng, b"resetme1"),
        Sw::OK
    );
    medium.assert_re_armed_before(EF_RC, |_| false, "PUT DATA 0xD3 setting EF_RC");
    medium.assert_re_armed_before(
        EF_DEK_RC.get(),
        |_| false,
        "PUT DATA 0xD3 setting EF_DEK_RC",
    );
    assert!(!fs.has_data(rsk_fs::EF_HARDENED));
}

/// The fourth: CHANGE REFERENCE DATA on PW1. Its `check_pin` verifies the very
/// reference the sequence re-keys, so by the time `stage_dek` runs there is nothing
/// pre-OTP left to supersede — which is exactly why the re-arm there is
/// unconditional. Make it conditional and this row is the one that goes quiet.
#[test]
fn a_pw1_change_re_arms_the_at_rest_lap() {
    let (mut fs, medium) = setup_cut();
    let d_otp = otp_dev();
    let mut rng = CountRng(7);
    let mut sess = Session::new();
    assert_eq!(
        verify(
            &d_otp,
            &mut fs,
            &mut sess,
            &mut rng,
            0x00,
            PW1_MODE81,
            PW1_DEFAULT
        ),
        Sw::OK
    );
    assert!(
        !fs.has_data(rsk_fs::EF_HARDENED),
        "fixture: PW1's own migrating verify re-armed, so the CHANGE below cannot \
         borrow that re-arm"
    );
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();

    medium.clear_ops();
    let mut data = [0u8; 12];
    data[..6].copy_from_slice(PW1_DEFAULT);
    data[6..].copy_from_slice(b"654321");
    assert_eq!(
        change_pin(
            &d_otp, &mut fs, &mut sess, &mut rng, 0x00, PW1_MODE81, &data
        ),
        Sw::OK
    );
    medium.assert_re_armed_before(EF_PW1, |_| false, "CHANGE PW1's verifier write");
    medium.assert_re_armed_before(EF_DEK_PW1.get(), |_| false, "CHANGE PW1's DEK commit");
    assert!(!fs.has_data(rsk_fs::EF_HARDENED));
}

/// RESET RETRY verifies PW3 and re-keys `EF_PW1` — the same asymmetry as PIV's
/// RESET RETRY COUNTER, and `check_ref`'s migrating fallback has never run on the
/// reference it overwrites. Nothing on the call re-arms directly: the one re-arm
/// is inside `commit_staged_dek`. This case is where that coupling goes red.
#[test]
fn reset_retry_via_pw3_re_arms_the_at_rest_lap() {
    let (mut fs, medium) = setup_cut();
    let d_otp = otp_dev();
    let mut rng = CountRng(7);
    let mut sess = Session::new();
    assert_eq!(
        verify(
            &d_otp,
            &mut fs,
            &mut sess,
            &mut rng,
            0x00,
            PW3_MODE83,
            PW3_DEFAULT
        ),
        Sw::OK
    );
    // EF_PW1 was never verified, so it is still chip-serial-rooted.
    let mut rec = [0u8; 34];
    assert_eq!(fs.read(EF_PW1, &mut rec), Some(34));
    assert_eq!(
        &rec[2..],
        &dev().pin_derive_verifier(PW1_DEFAULT).expose()[..],
        "fixture: EF_PW1 is rooted in the public chip serial",
    );
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    assert!(
        fs.has_data(rsk_fs::EF_HARDENED),
        "fixture: the lap has latched"
    );

    medium.clear_ops();
    assert_eq!(
        reset_retry(
            &d_otp, &mut fs, &mut sess, &mut rng, 0x02, PW1_MODE81, b"222222"
        ),
        Sw::OK
    );
    // Both re-keys of the stage/verifier/commit sequence, which is why the re-arm
    // is at its head and not at the commit that ends it: EF_PW1 is superseded
    // FIRST, and a re-arm behind it is one a reset can take while that copy stands.
    medium.assert_re_armed_before(EF_PW1, |_| false, "reset_retry's verifier write");
    medium.assert_re_armed_before(EF_DEK_PW1.get(), |_| false, "reset_retry's DEK commit");
    assert_eq!(fs.read(EF_PW1, &mut rec), Some(34));
    assert_eq!(
        &rec[2..],
        &d_otp.pin_derive_verifier(b"222222").expose()[..],
        "fixture: the reset re-keyed EF_PW1 under the OTP arm",
    );
    assert!(
        !fs.has_data(rsk_fs::EF_HARDENED),
        "RESET RETRY superseded a chip-serial-rooted verifier and must re-arm the lap",
    );
}

/// Every session key this module hands back wipes itself when it drops: a caller
/// that discards one (`stage_dek(..)?;`) or loses it to a `?` leaves nothing.
#[test]
fn every_session_key_handed_back_wipes_itself() {
    fn wipes_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}
    let d = dev();
    let mut fs = setup();
    let mut sess = Session::new();
    verify(
        &d,
        &mut fs,
        &mut sess,
        &mut CountRng(0),
        0x00,
        PW3_MODE83,
        PW3_DEFAULT,
    );
    let mut dek = Secret::<[u8; DEK_SIZE]>::zeroed();
    load_dek(&d, &mut fs, &sess, &mut dek).unwrap();

    let staged = stage_dek(
        &d,
        &mut fs,
        &mut CountRng(9),
        EF_DEK_PW3,
        b"87654321",
        dek.expose(),
    );
    wipes_on_drop(&staged.unwrap().0);
    let rearmed = rsk_fs::request_rescrub(&mut fs).unwrap();
    let rewrapped = rewrap_dek(
        &d,
        &mut fs,
        &mut CountRng(9),
        EF_DEK_PW1,
        b"123456",
        dek.expose(),
        &rearmed,
    );
    wipes_on_drop(&rewrapped.unwrap());
    let reseeded = reseed_pin(
        &d,
        &mut fs,
        &mut CountRng(9),
        EF_PW3,
        b"87654321",
        dek.expose(),
    );
    wipes_on_drop(&reseeded.unwrap());
}
