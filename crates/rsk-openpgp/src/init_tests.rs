// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::dying_storage::DyingStorage;
use rsk_fs::storage::ram::RamStorage;
use rsk_sdk::Sw;

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
        latched: false,
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
        .decrypt_with_aad(session.expose(), &blob[1..n], PinKdf::V2, &mut dek)
        .unwrap();
    assert_eq!(m, DEK_SIZE);
    // RC and PW3 are the same blob sealed under PW3 and decrypt to the same DEK.
    let mut blob3 = [0u8; DEK_FILE_SIZE];
    fs.read(EF_DEK_PW3.get(), &mut blob3);
    let session3 = d.pin_derive_session(PW3_DEFAULT);
    let mut dek3 = [0u8; DEK_SIZE];
    d.decrypt_with_aad(session3.expose(), &blob3[1..], PinKdf::V2, &mut dek3)
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

#[test]
fn maxima_an_older_build_moved_are_restored_at_boot() {
    // A card that took `PUT DATA 00 C4 = 01 06 06 06` under a build that copied
    // the whole body announced max 6 for the rest of its life: PUT DATA writes
    // the flag only now, and no other writer touches these bytes. gpg reads the
    // announcement as the limit, so the owner could never set a longer PIN again.
    let mut fs = fresh();
    fs.put(EF_PW_PRIV, &[0x01, 6, 6, 6, 3, 0, 3]).unwrap();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();

    let mut pw = [0u8; 7];
    let n = fs.read(EF_PW_PRIV, &mut pw).unwrap();
    assert_eq!(&pw[1..4], &PW_STATUS_DEFAULT[1..4], "the announced maxima");
    // Only those three bytes: the flag the owner set and the retry counters stay.
    assert_eq!(pw[0], 0x01);
    assert_eq!(&pw[4..n], &[3, 0, 3]);

    // Idempotent, and it does not resurrect a shorter record's missing bytes.
    let mut short = fresh();
    short.put(EF_PW_PRIV, &[0x00, 6]).unwrap();
    settle_pw_status_maxima(&mut short).unwrap();
    let mut got = [0u8; 7];
    let n = short.read(EF_PW_PRIV, &mut got).unwrap();
    assert_eq!(&got[..n], &[0x00, PW_STATUS_DEFAULT[1]]);
}

/// E70: `SEX_VALUES` narrowed to the set a YubiKey accepts — `{'1','2','9'}` —
/// and `'0'`, which older builds seeded, is no longer in it. Boot repairs the
/// stranded byte rather than leaving a card that can read `5F35` and not write it
/// back. Both directions, because the second is the one that catches a per-boot
/// flash write on a card that needs no repair.
#[test]
fn boot_settles_a_sex_code_outside_the_value_list() {
    // `Fs::read` reports the value's FULL stored length, so clamp before slicing —
    // a stale row longer than the buffer would panic instead of failing.
    let sex_of = |fs: &mut Fs<RamStorage>| {
        let mut b = [0u8; 4];
        let n = fs.read(EF_SEX, &mut b).unwrap();
        b[..n.min(b.len())].to_vec()
    };
    // Every shape a provisioned card could be holding: the `'0'` firmware through
    // 0x08F1 wrote, another ISO 5218 code we never accepted, an absent DO, and two
    // lengths no value list can describe.
    for stale in [Some(&b"0"[..]), Some(b"3"), None, Some(b""), Some(b"19")] {
        let mut fs = fresh();
        scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
        match stale {
            None => fs.delete(EF_SEX).unwrap(),
            Some(v) => fs.put(EF_SEX, v).unwrap(),
        }
        scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
        assert_eq!(
            sex_of(&mut fs),
            SEX_DEFAULT,
            "not settled from {stale:02X?}"
        );
        // …and the boot after it writes nothing, or the repair is a wear bug.
        let writes = fs.write_gen();
        scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
        assert_eq!(
            fs.write_gen(),
            writes,
            "a settled card rewrote 5F35 on boot"
        );
        assert_eq!(sex_of(&mut fs), SEX_DEFAULT);
    }

    // A code the card does accept is the cardholder's, not ours to overwrite.
    for keep in SEX_VALUES {
        let mut fs = fresh();
        scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
        fs.put(EF_SEX, &[*keep]).unwrap();
        let writes = fs.write_gen();
        scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
        assert_eq!(sex_of(&mut fs), [*keep], "boot moved an accepted code");
        assert_eq!(fs.write_gen(), writes, "boot rewrote an accepted code");
    }
}

/// A repair the store REFUSES leaves the old byte and the next boot retries. The
/// budget also pins the cost: zero writes fails, one write is enough, so the
/// repair is exactly one `put` — and on an already-provisioned card it is the
/// FIRST write `scan_files` makes, which is what makes that count meaningful.
///
/// This models a rejected write, not a torn one: the flash's own power-cut
/// behaviour (an append-only CRC'd item, so a cut leaves the previous value live)
/// belongs to `rsk-store` and `fuzz/fuzz_targets/power_cut.rs`, not here.
#[test]
fn a_refused_sex_repair_leaves_the_old_byte_and_retries() {
    let (store, budget) = DyingStorage::new();
    let mut fs = Fs::new(store);
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    fs.put(EF_SEX, b"0").unwrap();
    let mut b = [0u8; 4];

    // Nothing else in `scan_files` writes on an already-provisioned card, so the
    // first refused write IS the repair.
    budget.set(0);
    assert_eq!(
        scan_files(&dev(), &mut fs, &mut CountRng(0)),
        Err(Error::Storage)
    );
    let n = fs.read(EF_SEX, &mut b).unwrap();
    assert_eq!(&b[..n], b"0", "a refused write must not eat the old value");

    // One write is the whole repair, and the boot after it is free.
    budget.set(1);
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    let n = fs.read(EF_SEX, &mut b).unwrap();
    assert_eq!(&b[..n], SEX_DEFAULT);
    budget.set(0);
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
}

/// The same shape as PIV's `scan_files`, at boot instead of at SELECT: one
/// faulted probe must not re-seed the factory PW1 verifier.
///
/// `Storage::read`/`size` answer the same `None` for "no such record" and for
/// "that read failed", and every guard here writes a factory default over the
/// file it reads absent — so a faulted `EF_PW1` probe put `PW1_DEFAULT` back over
/// the owner's verifier, locking the owner out and handing `123456` the PW1
/// security status. `scan_files` runs from `main`'s boot path, so no host command
/// is needed to reach it.
#[test]
fn a_faulted_probe_does_not_reseed_the_factory_pw1() {
    const OWNER_PW1: &[u8] = b"9988776655";
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    let mut sess = crate::pin::Session::default();
    let mut change = PW1_DEFAULT.to_vec();
    change.extend_from_slice(OWNER_PW1);
    assert_eq!(
        crate::pin::change_pin(
            &dev(),
            &mut fs,
            &mut sess,
            &mut CountRng(9),
            0,
            0x81,
            &change
        ),
        Sw::OK
    );
    let owner = medium
        .value(EF_PW1)
        .expect("the owner's verifier is on the medium");

    // The next boot re-runs `scan_files`, with EF_PW1's reads faulting.
    let mut fs = Fs::new(fs.into_storage());
    fs.scan();
    medium.stick(Some(EF_PW1));
    let r = scan_files(&dev(), &mut fs, &mut CountRng(0));
    assert_eq!(
        medium.value(EF_PW1).as_deref(),
        Some(&owner[..]),
        "a faulted EF_PW1 probe re-seeded the owner's verifier with PW1_DEFAULT"
    );
    assert_eq!(
        r,
        Err(Error::Storage),
        "an init that could not read the files it provisions must say so"
    );

    // The medium recovers; the card must be exactly as its owner left it.
    medium.stick(None);
    let mut sess = crate::pin::Session::default();
    assert_ne!(
        crate::pin::verify(
            &dev(),
            &mut fs,
            &mut sess,
            &mut CountRng(0),
            0,
            0x81,
            PW1_DEFAULT
        ),
        Sw::OK,
        "the factory PW1 must not verify on a card whose owner changed it"
    );
    let mut sess = crate::pin::Session::default();
    assert_eq!(
        crate::pin::verify(
            &dev(),
            &mut fs,
            &mut sess,
            &mut CountRng(0),
            0,
            0x81,
            OWNER_PW1
        ),
        Sw::OK,
        "and the owner's PW1 must still verify"
    );
}

/// Every guard in [`scan_files`] writes a FACTORY DEFAULT over the record it reads
/// absent, and the fallible probe is the only thing that stops a flash fault from
/// taking that arm. One row per guard, each aimed at its own record and — where two
/// guards read the SAME record — at its own probe of it, because a persistent fault
/// is caught by whichever guard reads first and the ones behind it never run.
///
/// The `Fs` is rebuilt over a TRUNCATED boot walk on purpose: a complete scan
/// decides the whole FID space, so `try_*` short-circuits an absent record before
/// the backend and no fault can reach the guards whose record is legitimately
/// absent (`EF_RC` on every settled card). A walk one read fault cut short is the
/// state where they are live, and it is reachable on the same flaky medium.
#[test]
fn every_scan_files_guard_refuses_its_own_faulted_probe() {
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();

    // An admin-set resetting code, so the two guards that probe `EF_RC` both reach
    // the backend: the first `try_*` over an ABSENT record caches the absence, and
    // the second then answers from RAM with no probe to fault.
    let mut rc = std::vec![32u8, 0x01];
    rc.extend_from_slice(&[0x5A; 32]);

    for (fid, skip, plant_rc, what) in [
        (EF_PW1, 0, false, "the first-boot latch's PW1 probe"),
        (EF_PW1, 1, false, "the PW1 verifier"),
        (EF_PW3, 0, false, "the PW3 verifier"),
        (EF_SIG_COUNT, 0, false, "the signature counter"),
        (EF_PW_PRIV, 0, false, "the PW-status record"),
        (EF_UIF_SIG, 0, false, "the signature UIF flag"),
        (EF_KDF, 0, false, "the KDF DO"),
        (EF_PW_RETRIES, 0, false, "the retry counters"),
        (EF_RC, 0, true, "the resetting-code verifier"),
        (EF_RC, 1, true, "the RC probe that holds C4's error counter"),
        (
            EF_PW_PRIV,
            1,
            false,
            "the PW-status record settle_rc_retry_counter reads",
        ),
        (
            EF_PW_PRIV,
            2,
            false,
            "the PW-status record settle_pw_status_maxima reads",
        ),
        (EF_SEX, 0, false, "the sex DO"),
    ] {
        // A boot walk the medium cut short: nothing is decided, so every probe
        // below reaches the backend whether its record is present or absent.
        let mut fs2 = Fs::new(fs.into_storage());
        medium.truncate_walk(true);
        fs2.scan();
        medium.truncate_walk(false);
        // `force_delete`, not `delete`: the truncated walk left every present bit
        // clear, and `delete` skips the backend on a clear one — so the record would
        // survive and `settle_rc_retry_counter` would return early on it.
        if plant_rc {
            fs2.put(EF_RC, &rc).unwrap();
        } else {
            let _ = fs2.force_delete(EF_RC);
        }

        let before = medium.value(fid);
        medium.stick_after(fid, skip);
        let r = scan_files(&dev(), &mut fs2, &mut CountRng(9));
        medium.stick(None);
        assert_eq!(
            medium.value(fid),
            before,
            "a faulted probe rewrote {what} with the factory default"
        );
        assert_eq!(
            r,
            Err(Error::Storage),
            "a boot that could not read {what} must refuse, not re-provision"
        );
        fs = fs2;
    }
}

/// The four DEK guards run only inside the first-boot window — `provisioning`,
/// i.e. NEITHER PW verifier exists — and their absent arm mints a fresh random DEK
/// and re-seals both copies. Every key on the card is wrapped under the old one, so
/// that write is the most destructive this module makes. The window is reachable
/// after a torn first boot, which is exactly what the latch is for; each row leaves
/// the card in the state its own guard is the last one standing in.
#[test]
fn every_first_boot_dek_guard_refuses_its_own_faulted_probe() {
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();

    for (fid, drop_dek_pw1, what) in [
        (EF_DEK_PW1.get(), false, "PW1's DEK copy"),
        (EF_DEK_PW3.get(), false, "PW3's DEK copy"),
        (EF_DEK_RC.get(), true, "the resetting code's DEK copy"),
        (EF_DEK, true, "the legacy DEK"),
    ] {
        let mut fs2 = Fs::new(fs.into_storage());
        medium.truncate_walk(true);
        fs2.scan();
        medium.truncate_walk(false);
        // A first boot torn between the DEK writes and the PW verifiers.
        let _ = fs2.force_delete(EF_PW1);
        let _ = fs2.force_delete(EF_PW3);
        if drop_dek_pw1 {
            let _ = fs2.force_delete(EF_DEK_PW1.get());
        }
        let survivor = if drop_dek_pw1 { EF_DEK_PW3 } else { EF_DEK_PW1 };
        let before = medium.value(survivor.get()).expect("a DEK copy survives");

        medium.stick(Some(fid));
        let r = scan_files(&dev(), &mut fs2, &mut CountRng(9));
        medium.stick(None);
        assert_eq!(
            medium.value(survivor.get()).as_deref(),
            Some(&before[..]),
            "a faulted {what} probe minted a new DEK over the one every key is wrapped under"
        );
        assert_eq!(
            r,
            Err(Error::Storage),
            "a boot that could not read {what} must refuse, not re-key"
        );
        fs = fs2;
    }
}
