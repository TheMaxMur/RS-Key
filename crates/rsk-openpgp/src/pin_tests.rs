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
    // The fallback arm is a SUCCESS: it must not take the wrong-password exit
    // that clears the addressed status, nor a sibling's.
    assert!(sess.has_pw3 && sess.has_pw1);
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

#[test]
fn an_overlong_pw_status_record_cannot_panic_the_retry_writers() {
    // EF_PW_PRIV is Internal-only and has been 7 bytes in every revision, so this
    // is hardening, not a live bug: `Fs::read` reports the record's stored length,
    // and an unclamped `&pw[..n]` write-back would panic a panic-halt image.
    let mut fs = setup();
    let mut overlong = crate::files::PW_STATUS_DEFAULT.to_vec();
    overlong.resize(16, 0xAA);
    fs.put(EF_PW_PRIV, &overlong).unwrap();

    assert_eq!(pin_wrong_retry(&mut fs, EF_PW1), Ok(PW_RETRIES_DEFAULT - 1));
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
        let mut want = [0u8; DEK_SIZE];
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
        let mut got = [0u8; DEK_SIZE];
        load_dek(&d, &mut fs, &after, &mut got).unwrap_or_else(|e| {
            panic!("budget {budget} (change returned {sw:?}): the standing PIN cannot open the DEK: {e:?}")
        });
        assert_eq!(got, want, "budget {budget}: recovered a different key");
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
    let mut dek = [0u8; DEK_SIZE];
    load_dek(&d, &mut fs, &sess, &mut dek).unwrap();

    // A PW3 update torn after its verifier: PW3 stands on b"87654321", its copy
    // is still sealed under the default, and the stage holds the new one.
    const NEW3: &[u8] = b"87654321";
    stage_dek(&d, &mut fs, &mut CountRng(9), EF_DEK_PW3, NEW3, &dek).unwrap();
    put_verifier(&d, &mut fs, EF_PW3, NEW3).unwrap();

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
    let mut got = [0u8; DEK_SIZE];
    load_dek(&d, &mut fs, &s3, &mut got)
        .expect("the PW3 stage was destroyed by an unrelated PW1 update");
    assert_eq!(got, dek);
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
    let mut got = [0u8; DEK_SIZE];
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
            assert_eq!(sw, WRONG_DATA, "{p2:02X}: a {len}-byte value");
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
    store_verifier(&d, &mut fs, EF_PW1, b"abc").unwrap();

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
        let mut deks = [[0u8; DEK_SIZE]; 2];
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
            deks[0], deks[1],
            "budget {budget}: the two PINs unwrap different keys"
        );
    }
}
