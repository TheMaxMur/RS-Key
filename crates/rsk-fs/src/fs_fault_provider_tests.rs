// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::storage::faults::{MetaStuck, ProbeStuck, Silent};

#[test]
fn metadata_fault_inventory_and_removal_match_the_physical_records() {
    let (mut backend, medium) = MetaStuck::new();
    assert!(!medium.live(KEY_DEV));
    backend.write(KEY_DEV, b"owner").unwrap();
    backend.write(KEY_DEV + 2, b"neighbor").unwrap();
    assert!(medium.live(KEY_DEV));
    let mut keys = std::vec::Vec::new();
    assert!(backend.for_each_key(&mut |fid| keys.push(fid)));
    keys.sort_unstable();
    assert_eq!(keys, [KEY_DEV, KEY_DEV + 2]);
    backend.remove(KEY_DEV).unwrap();
    assert_eq!(backend.read(KEY_DEV, &mut [0; 8]), None);
    assert!(!medium.live(KEY_DEV));
    assert_eq!(backend.read(KEY_DEV + 2, &mut [0; 8]), Some(8));
}

#[test]
fn probe_faults_skip_only_target_probes_then_recover_and_forward_removals() {
    let (mut backend, medium) = ProbeStuck::new();
    backend.write(KEY_DEV, b"abc").unwrap();
    backend.write(KEY_DEV + 2, b"neighbor").unwrap();
    assert_eq!(medium.value(KEY_DEV), Some(b"abc".to_vec()));
    assert_eq!(medium.value(KEY_DEV + 1), None);
    medium.stick_once(KEY_DEV);
    assert_eq!(backend.read(KEY_DEV, &mut [0; 2]), None);
    assert!(backend.last_error());
    let mut out = [0; 2];
    assert_eq!(backend.read(KEY_DEV, &mut out), Some(3));
    assert_eq!(&out, b"ab");
    assert!(!backend.last_error());
    medium.stick_after(KEY_DEV, 2);
    assert_eq!(backend.size(KEY_DEV + 2), Some(8));
    assert_eq!(backend.read(KEY_DEV, &mut out), Some(3));
    assert_eq!(backend.size(KEY_DEV + 2), Some(8));
    assert_eq!(backend.size(KEY_DEV), Some(3));
    assert_eq!(backend.read(KEY_DEV, &mut out), None);
    assert!(backend.last_error());
    assert_eq!(backend.size(KEY_DEV), Some(3));
    assert!(!backend.last_error());
    medium.refuse_remove(Some(KEY_DEV));
    assert_eq!(backend.remove(KEY_DEV), Err(Error::MemoryFatal));
    assert_eq!(medium.value(KEY_DEV), Some(b"abc".to_vec()));
    medium.refuse_remove(None);
    assert_eq!(backend.remove(KEY_DEV), Ok(()));
    assert_eq!(medium.value(KEY_DEV), None);
}

#[test]
fn removal_faults_count_refused_and_served_calls_and_preserve_full_lengths() {
    let (mut backend, medium) = RemoveStuck::new();
    backend.write(KEY_DEV, b"abc").unwrap();
    let mut out = [0; 2];
    assert_eq!(backend.read(KEY_DEV, &mut out), Some(3));
    assert_eq!(&out, b"ab");
    assert_eq!(backend.size(KEY_DEV), Some(3));
    assert_eq!(backend.read(KEY_DEV + 1, &mut out), None);
    assert_eq!(backend.size(KEY_DEV + 1), None);
    assert_eq!(medium.attempts(), 0);
    medium.refuse_once(KEY_DEV);
    assert_eq!(backend.remove(KEY_DEV), Err(Error::MemoryFatal));
    assert_eq!(medium.attempts(), 1);
    assert!(medium.live(KEY_DEV));
    assert_eq!(backend.remove(KEY_DEV), Ok(()));
    assert_eq!(medium.attempts(), 2);
    assert!(!medium.live(KEY_DEV));
}

#[test]
fn truncated_inventory_still_forwards_value_lengths_and_removals() {
    let mut backend = TruncatedWalk::new();
    backend.write(KEY_DEV, b"abc").unwrap();
    assert_eq!(backend.size(KEY_DEV), Some(3));
    assert_eq!(backend.size(KEY_DEV + 1), None);
    backend.remove(KEY_DEV).unwrap();
    assert_eq!(backend.read(KEY_DEV, &mut [0; 3]), None);
}

#[test]
fn rearm_order_ignores_weak_and_unrelated_writes() {
    let (mut backend, medium) = Cut::new();
    backend.write(KEY_DEV, b"weak").unwrap();
    backend.write(KEY_DEV + 2, b"strong").unwrap();
    backend.remove(crate::EF_HARDENED).unwrap();
    backend.write(KEY_DEV, b"strong").unwrap();
    medium.assert_re_armed_before(KEY_DEV, |value| value == b"weak", "strong rewrite");
    assert_eq!(backend.size(KEY_DEV), Some(6));
    backend.remove(KEY_DEV).unwrap();
    assert_eq!(backend.read(KEY_DEV, &mut [0; 6]), None);
    assert_eq!(medium.value(KEY_DEV), None);
}

#[test]
fn factory_wipe_leaves_an_empty_first_batch_in_finite_steps() {
    let mut fs = fs();
    fs.put(KEY_DEV, b"owner").unwrap();
    let calls = core::cell::Cell::new(0);
    fs.factory_wipe(
        |_| false,
        |_| {
            calls.set(calls.get() + 1);
            assert!(calls.get() <= 2, "empty first batch must finish");
            false
        },
        |_| false,
    )
    .unwrap();
    assert_eq!(calls.get(), 2);
    assert_eq!(fs.read(KEY_DEV, &mut [0; 5]), None);
}

/// A stand-in for the applet commands that persist a record and then read it back
/// to confirm the program took — FIDO's `spend_and_verify_pin_hash` and OATH's
/// `spend_otp_retry` are the shipped pair. `Ok` only when the store hands back the
/// bytes the command meant to write; those applets fail closed on anything else.
fn persist_and_confirm<S: Storage>(fs: &mut Fs<S>, fid: u16, value: &[u8]) -> Result<()> {
    fs.put(fid, value)?;
    let mut back = [0u8; 64];
    match fs.try_read(fid, &mut back)? {
        Some(n) if n == value.len() && back[..n] == *value => Ok(()),
        _ => Err(Error::MemoryFatal),
    }
}

/// A backend that REPORTS a write applied and did not apply it is invisible to the
/// write's own answer: only the read-back a command makes afterwards can tell it
/// from a write that landed. Drive that pair over [`Silent`] and hold the command
/// to the fault — it must report failure rather than `Ok` over a lost record, and
/// the medium must still hold the value the write never replaced.
#[test]
fn a_silent_overwrite_is_caught_by_the_read_back_the_command_relies_on() {
    let (backend, medium) = Silent::new();
    let mut fs = Fs::new(backend);
    assert_eq!(
        persist_and_confirm(&mut fs, KEY_DEV, b"old"),
        Ok(()),
        "fixture: the healthy medium must confirm the seed write"
    );
    medium.arm(Some(KEY_DEV));

    assert_eq!(
        persist_and_confirm(&mut fs, KEY_DEV, b"new"),
        Err(Error::MemoryFatal),
        "the write answered Ok over a record the medium never replaced, and the \
         read-back did not catch it"
    );
    assert_eq!(
        medium.attempts(),
        1,
        "the medium was never asked for the write, so nothing was verified"
    );
    assert_eq!(
        medium.value(KEY_DEV).as_deref(),
        Some(b"old".as_slice()),
        "the medium applied an overwrite the drop should have swallowed"
    );
    // A healthy retry lands, so the refusal above is the fault and not a blanket
    // refusal — which would make this pass over a medium that stores nothing.
    medium.arm(None);
    assert_eq!(persist_and_confirm(&mut fs, KEY_DEV, b"new"), Ok(()));
    assert_eq!(medium.value(KEY_DEV).as_deref(), Some(b"new".as_slice()));
}

/// The acute case: a command's FIRST write of a record, swallowed, leaves the
/// record absent — the store's own `put` still answered `Ok`, so without the
/// read-back the command reports success over a record it never stored.
#[test]
fn a_silent_first_write_is_not_a_stored_record() {
    let (backend, medium) = Silent::new();
    let mut fs = Fs::new(backend);
    medium.arm(Some(KEY_DEV));

    assert_eq!(
        persist_and_confirm(&mut fs, KEY_DEV, b"fresh"),
        Err(Error::MemoryFatal)
    );
    assert_eq!(medium.attempts(), 1);
    assert!(
        !medium.live(KEY_DEV),
        "the medium holds a record a dropped write never gave it"
    );
    // A reboot sees the same absence off a fresh cache: the record really is gone,
    // not merely uncached.
    let mut rebooted = Fs::new(fs.into_storage());
    rebooted.scan();
    let mut out = [0u8; 8];
    assert_eq!(rebooted.read(KEY_DEV, &mut out), None);
}

/// The double's own contract, so a test driving it cannot fail for the wrong
/// reason: the drop is per-fid, counts only what it swallowed, recovers, and a
/// `remove` tombstone is a mutation it can swallow too.
#[test]
fn the_silent_medium_drops_only_its_armed_fid_and_counts_what_it_swallowed() {
    let (mut backend, medium) = Silent::new();
    backend.write(KEY_DEV, b"mine").unwrap();
    backend.write(KEY_DEV + 2, b"other").unwrap();
    medium.arm(Some(KEY_DEV));
    backend.write(KEY_DEV, b"overwrite").unwrap();
    backend.write(KEY_DEV + 2, b"changed").unwrap();
    assert_eq!(medium.attempts(), 1);
    assert_eq!(medium.value(KEY_DEV).as_deref(), Some(b"mine".as_slice()));
    assert_eq!(
        medium.value(KEY_DEV + 2).as_deref(),
        Some(b"changed".as_slice())
    );

    medium.arm(None);
    backend.write(KEY_DEV, b"overwrite").unwrap();
    assert_eq!(
        medium.attempts(),
        1,
        "a healthy write is not a swallowed one"
    );
    assert_eq!(
        medium.value(KEY_DEV).as_deref(),
        Some(b"overwrite".as_slice())
    );

    // A one-shot arming is spent by the next mutation of the fid and no later one.
    medium.arm_once(KEY_DEV);
    backend.write(KEY_DEV, b"lost").unwrap();
    backend.write(KEY_DEV, b"kept").unwrap();
    assert_eq!(medium.attempts(), 2);
    assert_eq!(medium.value(KEY_DEV).as_deref(), Some(b"kept".as_slice()));

    // A tombstone is a write on a log-structured medium, so the drop covers it:
    // the record stays live on the medium.
    medium.arm(Some(KEY_DEV));
    backend.remove(KEY_DEV).unwrap();
    assert_eq!(medium.attempts(), 3);
    assert!(
        medium.live(KEY_DEV),
        "the swallowed tombstone removed the record"
    );
    medium.arm(None);
    backend.remove(KEY_DEV).unwrap();
    assert!(!medium.live(KEY_DEV));
}

/// `request_rescrub` re-arms the at-rest lap by deleting [`crate::EF_HARDENED`] and
/// re-reading it. A `Silent` medium that answers `Ok` for that `remove` and applies
/// nothing leaves the marker live, and `Fs::delete` marks it absent from its own
/// present bit the moment the removal returns — so a cache-satisfied probe reports
/// the marker gone and the re-arm as landed. That is a marker standing over the copy
/// the re-arm was owed: the next boot's lap skips because EF_HARDENED is present, and
/// the superseded pre-OTP record the lap existed to scrub survives. The probe must
/// ask the MEDIUM, and a swallowed tombstone must refuse rather than answer `Ok`.
#[test]
fn a_silently_dropped_marker_remove_is_not_a_landed_re_arm() {
    let (backend, medium) = Silent::new();
    let mut fs = Fs::new(backend);
    fs.put(crate::EF_HARDENED, b"\x01").unwrap();
    assert!(
        medium.live(crate::EF_HARDENED),
        "fixture: the lap has latched the marker"
    );

    medium.arm(Some(crate::EF_HARDENED));
    assert_eq!(
        crate::request_rescrub(&mut fs).err(),
        Some(Error::MemoryFatal),
        "the medium swallowed the tombstone, so the marker is still live and the \
         re-arm did not land — a cache-satisfied probe answers Ok over it"
    );
    assert!(
        medium.live(crate::EF_HARDENED),
        "the marker left the medium on a tombstone the drop never applied"
    );
    assert!(
        fs.rescrub_refused(),
        "a swallowed re-arm left no trace outside the return value the wipe paths \
         throw away"
    );

    // The control, and not a no-op: with the drop cleared the same re-arm lands,
    // says so, and the marker really leaves the medium.
    medium.arm(None);
    assert!(
        crate::request_rescrub(&mut fs).is_ok(),
        "a healthy medium must still report the re-arm as landed"
    );
    assert!(
        !medium.live(crate::EF_HARDENED),
        "the marker must be gone once the tombstone is applied"
    );
}

/// The ordinary path the fix must not disturb: a plain `RamStorage` re-arms, reports
/// it, and clears the marker — no refusal latched.
#[test]
fn a_healthy_ram_medium_still_rearms_the_lap() {
    let mut fs = fs();
    fs.put(crate::EF_HARDENED, b"\x01").unwrap();
    assert!(crate::request_rescrub(&mut fs).is_ok());
    assert!(!fs.rescrub_refused());
    assert!(!fs.has_data(crate::EF_HARDENED));
}
