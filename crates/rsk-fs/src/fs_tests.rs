// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::storage::faults::{Cut, RemoveStuck, TruncatedWalk};
use crate::storage::ram::RamStorage;

// A stand-in working-EF fid used by the plain put/read tests.
const KEY_DEV: u16 = 0xCC00;

fn fs() -> Fs<RamStorage> {
    Fs::new(RamStorage::new())
}

/// A `Storage` that counts backend probes, proving the present-cache answers
/// absent lookups without the (on-device, O(flash)) `fetch_item` scan.
struct CountingStorage {
    inner: RamStorage,
    read_calls: u32,
    size_calls: u32,
    remove_calls: u32,
    write_calls: u32,
    /// What `for_each_key` reports as its completion (models a read-fault-truncated
    /// boot scan when `false`); the keys are still yielded either way.
    scan_complete: bool,
}
impl CountingStorage {
    fn new() -> Self {
        Self {
            inner: RamStorage::new(),
            read_calls: 0,
            size_calls: 0,
            remove_calls: 0,
            write_calls: 0,
            scan_complete: true,
        }
    }
}
impl Storage for CountingStorage {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.read_calls += 1;
        self.inner.read(fid, buf)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
        self.write_calls += 1;
        self.inner.write(fid, data)
    }
    fn remove(&mut self, fid: u16) -> Result<()> {
        self.remove_calls += 1;
        self.inner.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.size_calls += 1;
        self.inner.size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        let _ = self.inner.for_each_key(f);
        self.scan_complete
    }
}

#[test]
fn complete_scan_decides_absence_o1() {
    // The cold-Certificates fix: a scan that runs to completion enumerated every
    // live key, so an un-yielded sibling FID is authoritatively absent and
    // read/size/has_data answer from the decided bitmap — no per-slot backend scan
    // (on device the ~92 ms flash walk the Yubico Authenticator triggers per empty
    // PIV cert slot).
    let mut st = CountingStorage::new();
    st.inner.write(0xD20A, b"cert").unwrap(); // one live cert, bypass the counters
    let mut fs = Fs::new(st);
    fs.scan(); // scan_complete = true → decides the whole FID space
    let mut buf = [0u8; 8];
    assert_eq!(fs.read(0xD20B, &mut buf), None); // empty sibling: from the bitmap
    assert_eq!(fs.size(0xD20B), None);
    assert!(!fs.has_data(0xD20B));
    let st = fs.into_storage();
    assert_eq!(
        st.read_calls, 0,
        "complete scan → absence answered without a probe"
    );
    assert_eq!(st.size_calls, 0);
}

#[test]
fn truncated_scan_keeps_confirm_on_miss() {
    // A boot scan cut short by a flash read fault must NOT decide absence: an
    // un-yielded FID stays unknown and is confirmed against the reliable backend,
    // so a committed key the truncated walk missed is never read back as absent.
    let mut st = CountingStorage::new();
    st.scan_complete = false; // model the read-fault truncation
    st.inner.write(0xD20A, b"cert").unwrap();
    let mut fs = Fs::new(st);
    fs.scan(); // reports incomplete → decided stays per-yielded-key only
    let mut buf = [0u8; 8];
    assert_eq!(fs.read(0xD20B, &mut buf), None); // absent, but confirmed via backend
    let st = fs.into_storage();
    assert_eq!(
        st.read_calls, 1,
        "incomplete scan → an absent read still confirms once against the backend"
    );
}

#[test]
fn put_read_size() {
    let mut fs = fs();
    assert!(!fs.has_data(KEY_DEV));
    fs.put(KEY_DEV, &[1, 2, 3, 4]).unwrap();
    assert_eq!(fs.size(KEY_DEV), Some(4));
    assert!(fs.has_data(KEY_DEV));
    let mut buf = [0u8; 8];
    assert_eq!(fs.read(KEY_DEV, &mut buf), Some(4));
    assert_eq!(&buf[..4], &[1, 2, 3, 4]);
}

#[test]
fn force_delete_removes_a_false_absent_key() {
    const CRED: u16 = 0xCF05;
    // A torn-migration false-absent key: live in the backend, present bit clear.
    // Model it by writing through one Fs, extracting the backend, and re-wrapping
    // WITHOUT a scan — the new Fs never learned the key is present.
    let backend = || {
        let mut seed = fs();
        seed.put(CRED, &[0u8; 8]).unwrap();
        seed.into_storage()
    };

    // delete() is gated on the (clear) present bit, so it skips the backend removal:
    // the key survives (has_data probes the backend and finds it still there).
    let mut a = Fs::new(backend());
    a.delete(CRED).unwrap();
    assert!(a.has_data(CRED), "delete skips a false-absent key");

    // force_delete() removes it unconditionally.
    let mut b = Fs::new(backend());
    b.force_delete(CRED).unwrap();
    assert!(!b.has_data(CRED), "force_delete removes a false-absent key");
}

#[test]
fn factory_wipe_erases_all_but_preserved() {
    let mut fs = fs();
    fs.put(0x1080, b"pin").unwrap();
    fs.put(0xCF01, b"cred").unwrap(); // a dynamic resident credential
    fs.put(0xC000, b"ctr").unwrap(); // a counter
    fs.put(0xAAAA, b"keep").unwrap(); // stands in for the preserved attestation

    fs.factory_wipe(|fid| fid == 0xAAAA, |_| false, |_| false)
        .unwrap();

    let mut buf = [0u8; 8];
    // Everything not preserved is gone — including the dynamic-file registration.
    assert!(fs.read(0x1080, &mut buf).is_none());
    assert!(fs.read(0xCF01, &mut buf).is_none());
    assert!(fs.read(0xC000, &mut buf).is_none());
    // The preserved key survives, contents intact.
    assert_eq!(fs.read(0xAAAA, &mut buf), Some(4));
    assert_eq!(&buf[..4], b"keep");
}

#[test]
fn factory_wipe_with_nothing_to_keep_empties_the_store() {
    let mut fs = fs();
    fs.put(0xCF01, b"a").unwrap();
    fs.put(0xCF02, b"b").unwrap();
    fs.factory_wipe(|_| false, |_| false, |_| false).unwrap();
    let mut seen = 0;
    fs.for_each_key(&mut |_| seen += 1);
    assert_eq!(seen, 0);
}

#[test]
fn put_over_dynamic_cap_commits_nothing() {
    // A `put` that overflows the dynamic-file set must fail atomically: reject
    // before touching flash, not commit the bytes and then report NoMemory —
    // otherwise the value is stranded on flash, readable yet unregistered, and
    // survives a reboot as a phantom (`scan` re-drops it at the same cap).
    let mut fs = fs();
    for i in 0..MAX_DYNAMIC_FILES as u16 {
        fs.put(0xD000 + i, b"x").unwrap();
    }
    let overflow = 0xD000 + MAX_DYNAMIC_FILES as u16;
    assert_eq!(fs.put(overflow, b"orphan"), Err(Error::NoMemory));

    // The rejected value left no trace: absent, unreadable — this run and across
    // a modelled reboot.
    let mut buf = [0u8; 8];
    assert!(fs.read(overflow, &mut buf).is_none());
    let mut fs2 = Fs::new(fs.into_storage());
    fs2.scan();
    assert!(fs2.read(overflow, &mut buf).is_none());
}

#[test]
fn dynamic_budget_exceeds_the_old_256_cap() {
    // The shared dynamic-file budget is 1280, not the old 256, so applets no longer
    // starve each other (filling PIV cannot shrink the passkey ceiling). 300 dynamic
    // files — well past the old cap — coexist, and free_dynamic tracks the budget.
    let mut fs = fs();
    for i in 0..300u16 {
        fs.put(0xD000 + i, b"x").unwrap();
    }
    let mut buf = [0u8; 8];
    assert_eq!(fs.read(0xD000, &mut buf), Some(1)); // first still live
    assert_eq!(fs.read(0xD000 + 299, &mut buf), Some(1)); // and the 300th
    assert_eq!(fs.free_dynamic(), MAX_DYNAMIC_FILES - 300);
}

#[test]
fn delete_removes() {
    let mut fs = fs();
    fs.put(0xCF02, b"x").unwrap();
    assert!(fs.has_data(0xCF02));
    fs.delete(0xCF02).unwrap();
    assert!(!fs.has_data(0xCF02));
}

#[test]
fn present_cache_tracks_put_delete_reput() {
    let mut fs = fs();
    let fid = 0xD205; // a PIV-style object FID; absent at first
    let mut buf = [0u8; 8];
    // Absent → fast-negative path, no stale data.
    assert_eq!(fs.read(fid, &mut buf), None);
    assert_eq!(fs.size(fid), None);
    // Put → readable (fails if the write did not mark the FID present).
    fs.put(fid, b"cert").unwrap();
    assert_eq!(fs.read(fid, &mut buf), Some(4));
    assert_eq!(fs.size(fid), Some(4));
    // Delete → absent again.
    fs.delete(fid).unwrap();
    assert_eq!(fs.read(fid, &mut buf), None);
    assert_eq!(fs.size(fid), None);
    // Re-put after delete → readable (catches a clear-then-set cache bug).
    fs.put(fid, b"again").unwrap();
    assert_eq!(fs.read(fid, &mut buf), Some(5));
    assert_eq!(&buf[..5], b"again");
}

#[test]
fn present_slots_matches_for_each_key_occupancy() {
    // slot_map (credMgmt / makeCredential) now reads the in-RAM present index
    // instead of scanning flash; it MUST report the same occupancy a for_each_key
    // pass would over the range — including after a delete and after a reboot scan.
    const BASE: u16 = 0xCF00; // EF_CRED-style range
    let mut fs = fs();
    for fid in [0xCF00u16, 0xCF01, 0xCF05, 0xCF10, 0xCFFE] {
        fs.put(fid, b"rk").unwrap();
    }
    fs.delete(0xCF05).unwrap();

    let mut want = [false; 256];
    fs.for_each_key(&mut |fid| {
        if let Some(i) = fid.checked_sub(BASE)
            && (i as usize) < want.len()
        {
            want[i as usize] = true;
        }
    });
    let mut got = [false; 256];
    fs.present_slots(BASE, &mut got);
    assert_eq!(got, want);
    assert!(
        got[0] && got[1] && got[0x10] && got[0xFE],
        "live slots occupied"
    );
    assert!(!got[5] && !got[2], "deleted and never-written slots free");

    // Reboot: the present index is reseeded from flash by scan(), so the RAM-read
    // occupancy must survive a rebuild identically.
    let mut fs2 = Fs::new(fs.into_storage());
    fs2.scan();
    let mut got2 = [false; 256];
    fs2.present_slots(BASE, &mut got2);
    assert_eq!(got2, want);
}

#[test]
fn present_cache_rebuilt_by_scan() {
    // The negative cache MUST be rebuilt by scan(), or post-reboot reads of
    // present files would falsely return None — silent data loss.
    let mut fs = fs();
    fs.put(0xD20A, b"sig-cert").unwrap();
    fs.put(0xCF09, b"resident").unwrap();
    let storage = fs.into_storage();
    let mut fs2 = Fs::new(storage);
    fs2.scan();
    let mut buf = [0u8; 16];
    assert_eq!(fs2.read(0xD20A, &mut buf), Some(8));
    assert_eq!(&buf[..8], b"sig-cert");
    assert_eq!(fs2.read(0xCF09, &mut buf), Some(8));
    assert_eq!(fs2.read(0xD20B, &mut buf), None); // never-written sibling
}

#[test]
fn absent_probe_confirms_once_then_caches() {
    // Tri-state cache: the FIRST probe of an UNKNOWN FID confirms via the
    // backend (one ~160 ms flash scan on device), then memoises the result so
    // every later probe — `read`, `size`, `has_data` — is O(1) and never
    // touches the backend again. Confirming (rather than trusting a bulk-scan
    // clear bit) is what prevents a post-power-cut false-absent; the PIV-tab
    // lag returns only as a one-time-per-boot first probe, then stays fast.
    let mut fs = Fs::new(CountingStorage::new());
    let mut buf = [0u8; 8];
    assert_eq!(fs.read(0xD205, &mut buf), None); // unknown → one confirming read
    // Now decided-absent — answered from the cache, no backend.
    assert_eq!(fs.read(0xD205, &mut buf), None);
    assert_eq!(fs.size(0xD205), None);
    assert!(!fs.has_data(0xD205));
    let st = fs.into_storage();
    assert_eq!(st.read_calls, 1, "exactly one confirming read, then cached");
    assert_eq!(
        st.size_calls, 0,
        "size/has_data answered from the cache after the first read decided it"
    );
}

#[test]
fn confirm_on_miss_recovers_unscanned_key() {
    // A torn-migration false-absent: the backend holds a key the present-cache
    // never learned (the bulk `scan` under-counted it). `read` MUST confirm
    // against the reliable backend, not fast-return None — otherwise committed
    // data reads back lost. Modelled by writing straight to the backend and
    // building an Fs that never scanned it.
    let mut backend = RamStorage::new();
    backend.write(0xCF09, b"resident-cred").unwrap();
    let mut fs = Fs::new(backend);
    let mut buf = [0u8; 32];
    assert_eq!(fs.read(0xCF09, &mut buf), Some(13)); // recovered, not false-absent
    assert_eq!(&buf[..13], b"resident-cred");
    // A genuinely absent sibling is confirmed absent and then cached.
    assert_eq!(fs.read(0xCF0A, &mut buf), None);
}

#[test]
fn meta_add_keeps_records_when_ef_meta_unknown() {
    // Bug B at unit scope: EF_META present in the backend but UNKNOWN to the
    // cache (the torn-migration false-absent). A `meta_add` must read the real
    // blob and KEEP existing records — the bug was treating an unknown EF_META
    // as empty and wiping every record on the rewrite.
    let mut fs = fs();
    fs.meta_add(0xB000, b"keep-me").unwrap();
    let backend = fs.into_storage(); // backend now holds EF_META = {B000}
    // Rebuild without scan() → EF_META is unknown (decided clear).
    let mut fs2 = Fs::new(backend);
    fs2.meta_add(0xB004, b"new").unwrap();
    assert_eq!(fs2.meta_find(0xB000, &mut [0u8; 16]), Some(7)); // survived
    assert_eq!(fs2.meta_find(0xB004, &mut [0u8; 16]), Some(3));
}

#[test]
fn a_faulted_ef_meta_read_never_rebuilds_the_blob_from_empty() {
    // The same databug's OTHER door: not an unknown cache but a read that
    // FAILS. `meta_add` must refuse (the blob's true contents are unknowable),
    // never treat the fault as an empty blob — that rewrite drops every other
    // FID's committed record in one write.
    let mut fs = fs();
    fs.meta_add(0xB000, b"keep-me").unwrap();
    let ram = fs.into_storage();
    // Rebuild without scan(), over a backend whose first read faults: the
    // meta_add cannot answer from the cache and meets the fault head-on.
    let mut fs2 = Fs::new(FailFirstRead {
        inner: ram,
        remaining: 1,
        err: false,
    });
    assert!(
        fs2.meta_add(0xB004, b"new").is_err(),
        "a meta_add over a faulted EF_META read must refuse, not rebuild from empty"
    );
    // The committed record survived the refusal; the next, clean read sees it.
    assert_eq!(fs2.meta_find(0xB000, &mut [0u8; 16]), Some(7));
}

#[test]
fn requesting_a_rescrub_clears_the_hardened_marker() {
    // `MarkerNeverLies` — SEC-BOOT-001 at the code level. Every lazy re-key or
    // delete of a pre-OTP record must re-arm the at-rest lap, and run-35 found
    // four of five re-key sites skipping it. The model catches the removal
    // (`BugRekeyKeepsTheMarker`); nothing here did, so the re-arm was untested.
    let mut fs = fs();
    fs.put(crate::EF_HARDENED, b"\x01").unwrap();
    assert!(fs.has_data(crate::EF_HARDENED));
    crate::request_rescrub(&mut fs).expect("a healthy medium re-arms and says so");
    assert!(
        !fs.has_data(crate::EF_HARDENED),
        "a rescrub request must clear the marker, or the lap never runs again"
    );
}

#[test]
fn a_reset_between_a_re_key_and_its_rescrub_leaves_the_marker_lying() {
    // Why every lazy re-key re-arms BEFORE it writes, and not after. The re-key and
    // the `request_rescrub` under it are two separate appends with nothing between
    // them, so a reset in that window keeps whichever one already landed. Only a
    // medium that stops serving mid-command shows it: one that refuses a chosen fid
    // refuses it under either order.
    const REKEYED: u16 = 0xB100;

    // Write first. The write lands, the reset eats the re-arm, and the marker now
    // stands over the copy that write superseded — which is still sealed under the
    // pre-OTP root the public chip serial derives. `run_at_rest_lap` gates on the
    // marker alone, so no later boot ever scrubs it (that early return is
    // `the_at_rest_lap_writes_its_marker_only_after_a_completed_scrub`).
    let (cut, medium) = Cut::new();
    let mut fs = Fs::new(cut);
    fs.put(REKEYED, b"pre-otp").unwrap();
    fs.put(crate::EF_HARDENED, b"\x01").unwrap();
    assert!(
        fs.has_data(crate::EF_HARDENED),
        "fixture: the lap has latched"
    );
    medium.arm(1);
    let _ = fs.put(REKEYED, b"otp");
    assert!(
        crate::request_rescrub(&mut fs).is_err(),
        "the cut ate the re-arm, and this order is the one that cannot be told"
    );
    assert_eq!(
        medium.value(REKEYED).as_deref(),
        Some(&b"otp"[..]),
        "fixture: the re-key never landed, so the reset fell outside the window"
    );
    assert!(
        medium.value(crate::EF_HARDENED).is_some(),
        "fixture: the marker was cleared, so this is not the state under test"
    );

    // Re-arm first. The same reset eats the WRITE instead: the marker is gone, the
    // next boot laps, and what it laps over is the record still in force. That is
    // the whole cost of the order — one idempotent lap over nothing.
    let (cut, medium) = Cut::new();
    let mut fs = Fs::new(cut);
    fs.put(REKEYED, b"pre-otp").unwrap();
    fs.put(crate::EF_HARDENED, b"\x01").unwrap();
    medium.arm(1);
    crate::request_rescrub(&mut fs).expect("the re-arm is what the cut let through");
    let _ = fs.put(REKEYED, b"otp");
    assert_eq!(
        medium.value(REKEYED).as_deref(),
        Some(&b"pre-otp"[..]),
        "fixture: the write landed too, so the reset fell outside the window"
    );
    assert!(
        medium.value(crate::EF_HARDENED).is_none(),
        "the re-arm must land before the write, or the marker outlives what it promises"
    );
}

/// A `Storage` whose compaction lap fails on demand, counting the laps it ran. A
/// backend that always compacts cannot tell "the marker lands after a completed
/// scrub" from "the marker lands regardless", which is the whole of the order.
struct TearableCompact {
    inner: RamStorage,
    tears: bool,
    laps: u32,
}
impl TearableCompact {
    fn new(tears: bool) -> Self {
        Self {
            inner: RamStorage::new(),
            tears,
            laps: 0,
        }
    }
}
impl Storage for TearableCompact {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.inner.read(fid, buf)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
        self.inner.write(fid, data)
    }
    fn remove(&mut self, fid: u16) -> Result<()> {
        self.inner.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.inner.size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(f)
    }
    fn compact(&mut self) -> Result<()> {
        self.laps += 1;
        if self.tears {
            Err(Error::MemoryFatal)
        } else {
            Ok(())
        }
    }
}

#[test]
fn the_at_rest_lap_writes_its_marker_only_after_a_completed_scrub() {
    // `MarkerNeverLies` — SEC-BOOT-001 at the code level. The order lived in
    // `firmware/`, which no host test reaches, so `BugMarkerBeforeScrub` had no code
    // twin: a torn lap that sets the marker anyway is never re-run, and the weak
    // copies it left ride under it forever.
    let mut torn = Fs::new(TearableCompact::new(true));
    crate::run_at_rest_lap(&mut torn);
    let mut medium = torn.into_storage();
    assert_eq!(medium.laps, 1, "an absent marker did not run the lap");
    // Past `Fs`'s present cache: the marker's absence has to be true of the MEDIUM,
    // since a cache-level check passes over a write that never happened.
    assert!(
        !medium.exists(crate::EF_HARDENED),
        "a torn lap claimed completion, so no later boot ever scrubs what it left"
    );

    // A completed lap does claim it, and the marker then gates the next boot's stall.
    let mut done = Fs::new(TearableCompact::new(false));
    crate::run_at_rest_lap(&mut done);
    assert!(
        done.into_storage().exists(crate::EF_HARDENED),
        "a completed lap left no marker, so every boot pays the stall again"
    );
    let mut again = Fs::new(TearableCompact::new(false));
    crate::run_at_rest_lap(&mut again);
    crate::run_at_rest_lap(&mut again);
    assert_eq!(
        again.into_storage().laps,
        1,
        "the marker did not gate the second boot"
    );
}

#[test]
fn a_boot_scan_registers_every_dynamic_key_and_neither_shared_record() {
    // The registry `scan` rebuilds is the capacity budget every later `put`
    // spends. Three mutations of this loop survived the suite (D2): an inverted
    // EF_META test, and two ways of never reaching the `push`. All three leave
    // the budget claiming the store is empty, so the cap stops binding.
    let mut st = RamStorage::new();
    st.write(0xCC10, b"one").unwrap();
    st.write(0xCC11, b"two").unwrap();
    st.write(EF_META, b"\x00").unwrap();
    st.write(EF_SCRUB_FILLER, b"filler").unwrap();
    let mut fs = Fs::new(st);
    fs.scan();
    assert_eq!(
        fs.free_dynamic(),
        MAX_DYNAMIC_FILES - 2,
        "scan must register both dynamic keys and neither shared record"
    );
}

#[test]
fn a_delete_frees_its_own_registration_and_no_other() {
    // `retain(|f| f != fid)` inverted keeps ONLY the deleted key and drops every
    // other registration — the budget then reads as free while the keys are live.
    let mut fs = fs();
    fs.put(0xCC10, b"one").unwrap();
    fs.put(0xCC11, b"two").unwrap();
    assert_eq!(fs.free_dynamic(), MAX_DYNAMIC_FILES - 2);
    fs.delete(0xCC10).unwrap();
    // Counting is not enough: the inverted retain keeps exactly one entry too,
    // just the WRONG one. Re-writing the survivor is what tells them apart —
    // it must already be registered, so the budget does not move.
    fs.put(0xCC11, b"again").unwrap();
    assert_eq!(
        fs.free_dynamic(),
        MAX_DYNAMIC_FILES - 1,
        "the surviving key must keep its registration, not be re-registered"
    );
}

#[test]
fn an_empty_record_is_not_data() {
    // `has_data` is the gate several applets read as "provisioned". A zero-length
    // record is a record, not data — audit run-35 is what an empty record read as
    // content costs one layer up.
    let mut fs = fs();
    fs.put(0xCC10, b"").unwrap();
    assert!(
        !fs.has_data(0xCC10),
        "a zero-length record must not read as data"
    );
    fs.put(0xCC10, b"x").unwrap();
    assert!(fs.has_data(0xCC10), "a one-byte record must");
}

#[test]
fn a_factory_wipe_clears_more_keys_than_one_batch_holds() {
    // `factory_wipe` deletes in [`WIPE_BATCH`] batches. Nothing drove it past the
    // first one, so the bound that keeps `batch[n]` in range was untested — and
    // the mutation that breaks it is an out-of-bounds index, not a wrong answer.
    //
    // Sized OFF the batch, not off a copy of it: a widened batch would otherwise
    // swallow the whole fill in one pass and leave this green over the untested
    // wrap it exists to cross.
    const FILL: u16 = 2 * WIPE_BATCH as u16 + 22;
    let mut fs = fs();
    for i in 0..FILL {
        fs.put(0xCC00 + i, b"x").unwrap();
    }
    fs.factory_wipe(|_| false, |_| false, |_| false).unwrap();
    for i in 0..FILL {
        assert!(
            !fs.has_data(0xCC00 + i),
            "0x{:04X} survived the wipe",
            0xCC00 + i
        );
    }
    assert_eq!(fs.free_dynamic(), MAX_DYNAMIC_FILES);
}

#[test]
fn a_faulted_ef_meta_read_never_caches_the_blob_as_absent() {
    // `meta_delete`'s half of the same rule, and the one nothing held: a FAILED
    // EF_META read must refuse, never `mark_absent(EF_META)`. Caching that
    // false-absent is worse than losing the delete — the NEXT `meta_add` trusts
    // `known_absent` and rebuilds the blob from empty, dropping every record.
    let mut fs = fs();
    fs.meta_add(0xB000, b"keep-me").unwrap();
    let ram = fs.into_storage();
    let mut fs2 = Fs::new(FailFirstRead {
        inner: ram,
        remaining: 1,
        err: false,
    });
    assert!(
        fs2.meta_delete(0xB004).is_err(),
        "a meta_delete over a faulted EF_META read must refuse, not cache absence"
    );
    // The false-absent would show here: a clean meta_add after the fault must
    // still find the committed record, not rebuild over it.
    fs2.meta_add(0xB008, b"new").unwrap();
    assert_eq!(
        fs2.meta_find(0xB000, &mut [0u8; 16]),
        Some(7),
        "the record must survive a faulted meta_delete and the write after it"
    );
}

#[test]
fn absent_delete_never_touches_the_backend() {
    // A backend `remove` of an absent FID scans the whole flash partition
    // (and writes a tombstone) on sequential-storage. The present-cache MUST
    // short-circuit it, exactly like read/size/has_data. A blind delete sweep
    // over absent slots is otherwise O(slots·partition): the FIDO reset
    // audit-ring scrub deletes AUDIT_RING_SLOTS(128) slots and measured ~12 s
    // on hardware, overrunning the conformance tool's 10 s reset timeout.
    let mut fs = Fs::new(CountingStorage::new());
    for fid in 0xC110u16..0xC110 + 128 {
        fs.delete(fid).unwrap(); // all absent
    }
    // A present FID still takes the real delete path (proves the guard isn't
    // a blanket skip that would leak data on reset).
    fs.put(0xC110, b"entry").unwrap();
    fs.delete(0xC110).unwrap();
    assert!(!fs.has_data(0xC110));
    let st = fs.into_storage();
    assert_eq!(
        st.remove_calls, 1,
        "only the one present FID may reach the backend remove; \
         absent deletes must be answered by the present-cache"
    );
}

#[test]
fn typed_key_api_roundtrips() {
    // The typed key API (`put_key`/`read_key`/`has_key`/`delete_key`) is the
    // only way to reach a `KeyFid` slot; it must behave exactly like the
    // plaintext path it delegates to.
    let mut fs = fs();
    let slot = KeyFid::new(0xCEFF);
    let mut buf = [0u8; 32];
    // Absent at first.
    assert_eq!(fs.read_key(slot, &mut buf), None);
    assert!(!fs.has_key(slot));
    // Store a (notionally sealed) blob and read it back.
    let blob = b"nonce|ciphertext|tag";
    fs.put_key(slot, Sealed::wrap(blob)).unwrap();
    assert!(fs.has_key(slot));
    assert_eq!(fs.read_key(slot, &mut buf), Some(blob.len()));
    assert_eq!(&buf[..blob.len()], blob);
    // Same bytes underneath — the type is a guard rail, not a separate store.
    assert_eq!(fs.read(slot.get(), &mut buf), Some(blob.len()));
    // Delete clears it.
    fs.delete_key(slot).unwrap();
    assert!(!fs.has_key(slot));
    assert_eq!(fs.read_key(slot, &mut buf), None);
}

#[test]
fn meta_roundtrip() {
    let mut fs = fs();
    let mut out = [0u8; 32];
    assert_eq!(fs.meta_find(0xCF00, &mut out), None);

    fs.meta_add(0xCF00, b"alpha").unwrap();
    fs.meta_add(0xCF01, b"beta").unwrap();
    assert_eq!(fs.meta_find(0xCF00, &mut out), Some(5));
    assert_eq!(&out[..5], b"alpha");
    assert_eq!(fs.meta_find(0xCF01, &mut out), Some(4));
    assert_eq!(&out[..4], b"beta");

    // Replace.
    fs.meta_add(0xCF00, b"ALPHA2").unwrap();
    assert_eq!(fs.meta_find(0xCF00, &mut out), Some(6));
    assert_eq!(&out[..6], b"ALPHA2");

    // Delete.
    fs.meta_delete(0xCF00).unwrap();
    assert_eq!(fs.meta_find(0xCF00, &mut out), None);
    assert_eq!(fs.meta_find(0xCF01, &mut out), Some(4)); // sibling untouched
}

#[test]
fn meta_find_oversized_does_not_panic() {
    let mut fs = fs();
    // > META_MAX (1024): must clamp, not slice out of range. Sized at the store's
    // own ceiling, which `put` now enforces.
    let big = [0u8; crate::MAX_VALUE_BYTES];
    fs.put(crate::EF_META, &big).unwrap();
    let mut out = [0u8; 32];
    assert_eq!(fs.meta_find(0xAAAA, &mut out), None);
}

/// The backend's per-value ceiling is enforced at the `Fs::put` chokepoint, so an
/// applet cannot pick a cap the store cannot honour (audit run-32).
#[test]
fn put_rejects_past_the_backend_ceiling() {
    let mut fs = fs();
    assert!(fs.put(0xCF10, &[0u8; crate::MAX_VALUE_BYTES]).is_ok());
    assert_eq!(
        fs.put(0xCF11, &[0u8; crate::MAX_VALUE_BYTES + 1]),
        Err(rsk_sdk::error::Error::WrongLength)
    );
    assert!(!fs.has_data(0xCF11));
}

#[test]
fn meta_find_truncates_into_short_out() {
    let mut fs = fs();
    fs.meta_add(0xCF00, b"0123456789").unwrap();
    let mut out = [0u8; 4];
    // Full length reported even though only `out.len()` bytes are copied.
    assert_eq!(fs.meta_find(0xCF00, &mut out), Some(10));
    assert_eq!(&out, b"0123");
}

#[test]
fn meta_add_overflow_is_nomemory() {
    let mut fs = fs();
    // 4-byte header + 1021 bytes overflows META_MAX (1024).
    let big = [0u8; 1021];
    assert_eq!(fs.meta_add(0xCF00, &big), Err(Error::NoMemory));
}

#[test]
fn meta_add_reserve_protects_reserved_headroom() {
    let mut fs = fs();
    // A record (4-byte header + 700 = 704) fits within META_MAX (1024) but leaves
    // only 320 bytes free — under a 400-byte reserve, so the reserved write is
    // rejected while the plain write (reserve 0) succeeds.
    let big = [0u8; 700];
    assert_eq!(fs.meta_add_reserve(0xCF00, &big, 400), Err(Error::NoMemory));
    fs.meta_add(0xCF00, &big).unwrap();
    // With the store now near full, a further reserved write still rejects (no
    // headroom), but a plain small write — a slot's essential head — still fits
    // in the reserved space. This is exactly PIV's best-effort cache fallback.
    let head = [1u8, 2, 3, 4];
    assert_eq!(
        fs.meta_add_reserve(0xCF01, &head, 400),
        Err(Error::NoMemory)
    );
    fs.meta_add(0xCF01, &head).unwrap();
    assert_eq!(fs.meta_find(0xCF01, &mut [0u8; 8]), Some(4));
}

#[test]
fn meta_delete_clears_ef_meta() {
    let mut fs = fs();
    fs.meta_add(0xCF00, b"x").unwrap();
    assert!(fs.size(crate::EF_META).is_some());
    fs.meta_delete(0xCF00).unwrap();
    // Last record gone → the whole EF_META blob is removed.
    assert_eq!(fs.size(crate::EF_META), None);
    assert_eq!(fs.meta_find(0xCF00, &mut [0u8; 8]), None);
}

#[test]
fn delete_drops_meta() {
    let mut fs = fs();
    fs.put(0xCF06, b"data").unwrap();
    fs.meta_add(0xCF06, b"m").unwrap();
    fs.delete(0xCF06).unwrap();
    assert_eq!(fs.meta_find(0xCF06, &mut [0u8; 8]), None);
}

#[test]
fn delete_drops_meta_even_without_file_data() {
    // Regression (power_cut / fs_ops fuzz): metadata can be attached to a FID
    // that was never `put`. `delete` must still drop that metadata; gating the
    // meta cleanup on the file's own present bit orphaned the record, so a
    // deleted file's metadata read back alive (after a reboot the stale
    // EF_META record reappeared, diverging from the model).
    let mut fs = fs();
    let fid = 0xB001; // metadata only — the file contents are never present
    fs.meta_add(fid, b"orphan").unwrap();
    assert_eq!(fs.meta_find(fid, &mut [0u8; 8]), Some(6));
    assert!(!fs.has_data(fid));
    fs.delete(fid).unwrap();
    assert_eq!(fs.meta_find(fid, &mut [0u8; 8]), None);
    // That was the only record, so EF_META is gone entirely now.
    assert_eq!(fs.size(crate::EF_META), None);
}

#[test]
fn meta_delete_of_absent_record_does_not_rewrite() {
    // Deleting a meta-less FID while EF_META holds other records must not
    // rewrite EF_META: a FIDO-reset sweep deletes many absent slots, and a
    // redundant rewrite each time is flash churn plus a needless torn-write
    // window. The sibling record must survive untouched.
    let mut fs = Fs::new(CountingStorage::new());
    fs.meta_add(0xCF00, b"keep").unwrap(); // exactly one EF_META write
    fs.delete(0xB001).unwrap(); // neither data nor a meta record
    assert_eq!(fs.meta_find(0xCF00, &mut [0u8; 8]), Some(4)); // sibling intact
    let st = fs.into_storage();
    assert_eq!(
        st.write_calls, 1,
        "deleting a meta-less FID must not rewrite EF_META (only the setup write)"
    );
    assert_eq!(st.remove_calls, 0, "absent delete must not hit the backend");
}

/// A `Storage` whose enumeration faults immediately: it yields nothing and reports
/// the walk as truncated, while the keys are still live and readable. This is the
/// interrupted-page-erase shape (`sequential-storage` `find_first_page` →
/// `Error::Corrupted`, which `fetch_all_items` propagates before its auto-repair).
struct TruncatedScan(RamStorage);
impl Storage for TruncatedScan {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.0.read(fid, buf)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
        self.0.write(fid, data)
    }
    fn remove(&mut self, fid: u16) -> Result<()> {
        self.0.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.0.size(fid)
    }
    fn for_each_key(&mut self, _f: &mut dyn FnMut(u16)) -> bool {
        false
    }
}

/// A wipe must fail rather than report a range clear it never enumerated — the
/// rule PIV and OpenPGP already enforce. Without it a truncated walk deletes
/// nothing and still answers success, and the trusted display paints "RS-Key
/// erased" over live credentials (audit run-32).
#[test]
fn factory_wipe_fails_on_a_truncated_enumeration() {
    let mut st = TruncatedScan(RamStorage::new());
    st.0.write(0xCF20, b"credential").unwrap();
    let mut fs = Fs::new(st);
    assert_eq!(
        fs.factory_wipe(|_| false, |_| false, |_| false),
        Err(Error::MemoryFatal)
    );
    let mut out = [0u8; 16];
    assert_eq!(
        fs.read(0xCF20, &mut out),
        Some(10),
        "the key the wipe never saw is still live"
    );
}

/// Audit run-35: the device-wide wipe bypasses every applet's own two-phase sweep,
/// so it has to carry the rule itself — the records that gate an applet (PIN
/// verifiers, retry counters) go only after everything else is provably gone.
#[test]
fn factory_wipe_removes_the_gate_records_last() {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    for fid in [0x1000u16, 0x1001, 0x1002] {
        fs.put(fid, &[0xAA]).unwrap();
    }
    fs.put(0xD180, &[0xBB]).unwrap(); // the "gate" record

    // A store that stops removing part-way: every prefix must leave the gate intact
    // while any secret is still present.
    for budget in 0..4usize {
        let mut fs = Fs::new(CountedRemove {
            inner: RamStorage::new(),
            budget,
        });
        fs.scan();
        for fid in [0x1000u16, 0x1001, 0x1002] {
            fs.put(fid, &[0xAA]).unwrap();
        }
        fs.put(0xD180, &[0xBB]).unwrap();
        let _ = fs.factory_wipe(|_| false, |_| false, |fid| fid == 0xD180);
        let secrets_left = [0x1000u16, 0x1001, 0x1002].iter().any(|&f| fs.has_data(f));
        if secrets_left {
            assert!(
                fs.has_data(0xD180),
                "remove budget {budget} dropped the gate record while a secret was live"
            );
        }
    }
}

/// The device-wide wipe is a tombstone sweep like the four applet ones, so it owes
/// the at-rest lap the same re-arm — and the `compact()` at its tail is what makes
/// that look unnecessary. It is not: the lap sits behind every `?` above it, and
/// neither caller reboots on a failure (`worker.rs` folds to `.is_ok()` and skips
/// the reboot; `rsk-display`'s `pin.rs` paints "wipe failed" and returns), so a
/// wipe that dies mid-sweep leaves the marker latched over the tombstones it had
/// already written and no later boot ever laps over them.
#[test]
fn a_factory_wipe_that_dies_mid_sweep_re_armed_the_lap_first() {
    // The verifier a card reset supersedes without re-keying it — FIDO's EF_PIN,
    // OpenPGP's PW1 — still sealed under the chip-serial root at the tombstone.
    const VERIFIER: u16 = 0x1080;

    let (cut, medium) = Cut::new();
    let mut fs = Fs::new(cut);
    fs.put(VERIFIER, b"pre-otp verifier").unwrap();
    fs.put(crate::EF_HARDENED, b"\x01").unwrap();
    assert!(
        fs.has_data(crate::EF_HARDENED),
        "fixture: the lap has latched"
    );
    medium.clear_ops();

    // One mutation, then the medium dies: whichever append the wipe makes first is
    // the only one that lands. Ordering the verifier `first` keeps that append
    // deterministic — `for_each_key` yields in ring order, phases do not.
    medium.arm(1);
    assert_eq!(
        fs.factory_wipe(|_| false, |fid| fid == VERIFIER, |_| false),
        Err(Error::MemoryFatal),
        "fixture: the cut must kill the wipe, or the tail `compact()` runs and \
         there is no error path under test"
    );
    assert!(
        medium.value(crate::EF_HARDENED).is_none(),
        "the wipe returned Err with the marker still latched, so `run_at_rest_lap` \
         gates itself off forever and every copy this wipe superseded stays \
         readable in a flash dump — {:?}",
        medium.ops()
    );
}

/// The success path's half of the same rule: `EF_HARDENED` is in neither the
/// preserve set nor `first`/`last`, so the sweep drops it in phase 1 in flash-ring
/// order — after an arbitrary prefix of tombstones. A cut in that window is the
/// state `request_rescrub`'s own doc calls the one order cannot cover.
#[test]
fn a_factory_wipe_re_arms_the_lap_before_it_supersedes_anything() {
    const VERIFIER: u16 = 0x1080;
    const GATE: u16 = 0xD180;

    let (cut, medium) = Cut::new();
    let mut fs = Fs::new(cut);
    fs.put(VERIFIER, b"pre-otp verifier").unwrap();
    fs.put(GATE, b"retry counter").unwrap();
    fs.put(crate::EF_HARDENED, b"\x01").unwrap();
    // The fixture's own writes are supersessions of `VERIFIER` too, and they sit
    // ahead of anything the wipe does.
    medium.clear_ops();

    fs.factory_wipe(|_| false, |fid| fid == VERIFIER, |fid| fid == GATE)
        .expect("a healthy medium wipes");
    medium.assert_re_armed_before(VERIFIER, |_| false, "factory wipe");
}

/// Best-effort, and this is the direction that separates the wipe from every gated
/// re-key site: a refused re-arm leaves a marker standing, a refused WIPE leaves
/// the secrets themselves live. `request_rescrub` answers rather than swallowing
/// (0x09BE), so the swallow has to be here, at the call.
#[test]
fn a_refused_re_arm_does_not_stop_a_factory_wipe() {
    const VERIFIER: u16 = 0x1080;

    let (stuck, medium) = RemoveStuck::new();
    let mut fs = Fs::new(stuck);
    fs.put(VERIFIER, b"pre-otp verifier").unwrap();
    fs.put(crate::EF_HARDENED, b"\x01").unwrap();
    // Single-shot: the one refusal a retry recovers from, and the only one that
    // tells a swallowed re-arm from a gating one — a persistent refusal stops the
    // sweep's own phase-1 removal of EF_HARDENED and fails the wipe either way.
    medium.refuse_once(crate::EF_HARDENED);

    // `first`, so the verifier's removal cannot land after EF_HARDENED's: phases
    // are ordered, `for_each_key` inside one is not.
    let wiped = fs.factory_wipe(|_| false, |fid| fid == VERIFIER, |_| false);
    assert!(
        !medium.live(VERIFIER),
        "the refused re-arm stopped the wipe before it erased anything, so every \
         secret is still on the medium — the one direction a wipe must not fail in"
    );
    assert_eq!(
        wiped,
        Ok(()),
        "a refusal of `remove(EF_HARDENED)` became the wipe's own answer, and the \
         device reported `wipe failed` over a medium it had in fact cleared"
    );
    assert!(
        !medium.live(crate::EF_HARDENED),
        "the sweep's own phase-1 removal is this re-arm's retry, and it did not run"
    );
    // The headline, read at the wipe rather than at `request_rescrub`: the `Ok` above
    // is correct AND it is the whole report, so the refusal the wipe swallowed to
    // give it has to leave by `Fs::rescrub_refused` or by nothing. A wipe does not
    // repair flash, so it does not clear this either.
    assert!(
        fs.rescrub_refused(),
        "the wipe answered success over a re-arm the medium refused, and left no \
         trace of the refusal anywhere on the device"
    );
}

/// `Storage` whose `remove` starts failing after `budget` successes.
struct CountedRemove {
    inner: RamStorage,
    budget: usize,
}

impl Storage for CountedRemove {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.inner.read(fid, buf)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
        self.inner.write(fid, data)
    }
    fn remove(&mut self, fid: u16) -> Result<()> {
        if self.budget == 0 {
            return Err(Error::MemoryFatal);
        }
        self.budget -= 1;
        self.inner.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.inner.size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(f)
    }
}

/// `Storage` whose first `remaining` reads/sizes FAIL rather than finding the key
/// absent — the two are indistinguishable through an `Option` return, which is the
/// whole point.
struct FailFirstRead {
    inner: RamStorage,
    remaining: usize,
    err: bool,
}

impl Storage for FailFirstRead {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        if self.remaining > 0 {
            self.remaining -= 1;
            self.err = true;
            return None;
        }
        self.err = false;
        self.inner.read(fid, buf)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
        self.inner.write(fid, data)
    }
    fn remove(&mut self, fid: u16) -> Result<()> {
        self.inner.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        if self.remaining > 0 {
            self.remaining -= 1;
            self.err = true;
            return None;
        }
        self.err = false;
        self.inner.size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(f)
    }
    fn last_error(&self) -> bool {
        self.err
    }
}

/// Audit run-36: a backend read that FAILED is not a key that is absent, but
/// `Storage::read`/`size` collapse both into `None` — and `Fs` memoises the answer
/// with the DECIDED bit, so one transient fault would answer "absent" for the rest
/// of the boot without touching flash again. `clientpin::set_pin` has exactly one
/// guard, `if has_data(EF_PIN)`, so a poisoned absence lets an unauthenticated host
/// install its own PIN over the owner's. Only a definitive answer may be cached.
#[test]
fn a_failed_read_is_never_memoised_as_an_absence() {
    let mut ram = RamStorage::new();
    ram.write(0x1080, b"the owner's PIN verifier").unwrap();
    // No `scan()`: that decides every enumerated key up front, which is exactly the
    // path this test must avoid.
    let mut fs = Fs::new(FailFirstRead {
        inner: ram,
        remaining: 1,
        err: false,
    });

    assert!(!fs.has_data(0x1080), "the faulting probe cannot see it");
    assert!(
        fs.has_data(0x1080),
        "a transient backend fault became a permanent absence"
    );
}

/// Audit run-36: `Storage::compact` writes its scrub filler straight through the
/// backend, never through `Fs`, so `Fs::scan` counted it as a dynamic file — and the
/// dynamic set is sized at exactly `MAX_DYNAMIC_FILES`, so the over-cap push is
/// discarded. At the cap plus a leftover filler one live key silently lost its
/// registration and every later `put` to it returned `NoMemory`.
#[test]
fn the_scrub_filler_never_costs_a_dynamic_slot() {
    let mut ram = RamStorage::new();
    for i in 0..MAX_DYNAMIC_FILES as u16 {
        ram.write(0x2000 + i, &[0xAA]).unwrap();
    }
    // What a failed or power-cut compaction lap leaves behind.
    ram.write(EF_SCRUB_FILLER, &[0xA5; 8]).unwrap();

    let mut fs = Fs::new(ram);
    fs.scan();

    for i in 0..MAX_DYNAMIC_FILES as u16 {
        fs.put(0x2000 + i, &[0xBB])
            .unwrap_or_else(|_| panic!("{:#06x} lost its registration to the filler", 0x2000 + i));
    }
}

/// The store-refinement pilot's clauses at concrete FIDs, so the PR gate carries
/// them too: `cargo kani` proves them over a symbolic pair once a week, and a
/// rename or a deleted hook there would otherwise take them away silently.
///
/// A window is walked rather than a pair checked, for the reason the panel's key
/// grids needed the same: a pair only collides under SOME wrong shift. `>> 3`
/// mistyped as `>> 2` and `& 7` as `& 3` alias different pairs, and a test that
/// names two FIDs catches whichever of them its two happen to meet. Twenty-four
/// consecutive FIDs span three bytes, so every within-byte and cross-byte
/// neighbour is present and any aliasing shows up as a second FID moving.
#[test]
fn a_cache_write_moves_one_fid_and_no_other_across_three_bytes() {
    use crate::fs::store_assurance::{CacheView, fresh};

    const BASE: u16 = 0x0100;
    const N: u16 = 24;
    for victim in BASE..BASE + N {
        let mut fs = fresh(false);
        for f in BASE..BASE + N {
            fs.step_put(f);
        }
        fs.step_delete(victim);
        for f in BASE..BASE + N {
            let want = if f == victim {
                CacheView::ABSENT
            } else {
                CacheView::LIVE
            };
            assert_eq!(
                fs.cache_view(f),
                want,
                "deleting {victim:#06x} moved {f:#06x}"
            );
        }
        assert!(fs.reads_absent(victim));
        assert!(!fs.reads_absent(BASE + (victim + 1 - BASE) % N));
    }
}

/// The rest of the pilot's clauses, which are about one FID rather than the map:
/// what `Init` decides (nothing), what a clean confirm caches (the answer), and
/// what a faulted one caches (nothing at all — audit run-36, one transient error
/// made permanent for the boot).
#[test]
fn a_faulted_confirm_caches_nothing_and_a_clean_one_caches_the_answer() {
    use crate::fs::store_assurance::{CacheView, fresh};

    const F: u16 = 0x0107;
    const G: u16 = 0x0108;
    let mut fs = fresh(false);
    assert_eq!(fs.cache_view(F), CacheView::CLEAR, "Init decided something");
    assert!(
        !fs.reads_absent(F),
        "an unprobed FID read as a decided absence"
    );

    fs.step_confirm(F, true);
    assert_eq!(fs.cache_view(F), CacheView::LIVE);
    fs.step_confirm(F, false);
    assert_eq!(fs.cache_view(F), CacheView::ABSENT);

    let mut fs = fresh(true);
    fs.step_put(G);
    fs.step_confirm(F, false);
    assert_eq!(
        fs.cache_view(F),
        CacheView::CLEAR,
        "a fault was cached as a decision"
    );
    assert!(!fs.reads_absent(F));
    assert_eq!(fs.cache_view(G), CacheView::LIVE);
}

/// A medium whose reads fail while the budget is ARMED, holding its map behind an
/// `Rc` so a case can read the medium back once the arm is off.
///
/// The arm is what keeps the observation honest: a projection taken over a dead
/// medium answers "gone" for a record that is still on it, and every refused write
/// then reads as a lost one (the G4 lesson). So the fault covers the step and
/// nothing else — and it covers `read`/`size` only, which is the shape a
/// log-structured backend actually fails in: a CRC failure on one item, a fresh
/// page for the next.
struct ArmedRead {
    inner: std::rc::Rc<std::cell::RefCell<RamStorage>>,
    armed: std::rc::Rc<std::cell::Cell<bool>>,
    err: bool,
}

impl Storage for ArmedRead {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        if self.armed.get() {
            self.err = true;
            return None;
        }
        self.err = false;
        self.inner.borrow_mut().read(fid, buf)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
        self.inner.borrow_mut().write(fid, data)
    }
    fn remove(&mut self, fid: u16) -> Result<()> {
        self.inner.borrow_mut().remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        if self.armed.get() {
            self.err = true;
            return None;
        }
        self.err = false;
        self.inner.borrow_mut().size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        self.inner.borrow_mut().for_each_key(f)
    }
    fn last_error(&self) -> bool {
        self.err
    }
}

/// A stand-in PIV key slot: the only FIDs that carry an EF_META head are
/// `rsk-piv`'s, so the case is built at the shape it is about.
const SLOT: u16 = 0x9A00;

fn armed_fs() -> (
    Fs<ArmedRead>,
    std::rc::Rc<std::cell::RefCell<RamStorage>>,
    std::rc::Rc<std::cell::Cell<bool>>,
) {
    let inner = std::rc::Rc::new(std::cell::RefCell::new(RamStorage::new()));
    let armed = std::rc::Rc::new(std::cell::Cell::new(false));
    let fs = Fs::new(ArmedRead {
        inner: inner.clone(),
        armed: armed.clone(),
        err: false,
    });
    (fs, inner, armed)
}

/// `delete` used to swallow `meta_delete`'s error (`let _ =`) and remove the value
/// anyway, so over a medium whose EF_META read fails ONCE the caller was told
/// `Ok(())` about a file whose value was gone and whose record still stood — the
/// 0x077C databug's end state, with no power cut in it.
///
/// The removal is still unconditional, because EF_META is one blob shared by every
/// applet and refusing on a read fault would stop every delete on the device,
/// wipes included. What changed is that the caller is told: `Err` names the state
/// (value gone, record may stand) instead of hiding it.
#[test]
fn a_faulted_metadata_drop_is_reported_and_the_value_still_goes() {
    let (mut fs, ram, armed) = armed_fs();
    fs.put(SLOT, b"sealed key material").unwrap();
    fs.meta_add(SLOT, &[0xAA, 0x01, 0x02, 0x03]).unwrap();

    armed.set(true);
    let answered = fs.delete(SLOT);
    armed.set(false);

    assert!(
        matches!(answered, Err(Error::MemoryFatal)),
        "a delete that could not drop the record answered {answered:?}"
    );
    // Read the MEDIUM, not the cache: the present bit is marked absent by the
    // delete either way, so a cache-level assertion would pass with the backend
    // `remove` never called.
    let mut buf = [0u8; 32];
    assert!(
        ram.borrow_mut().read(SLOT, &mut buf).is_none(),
        "the value must go even when the record could not be dropped"
    );
    assert!(
        ram.borrow_mut().read(EF_META, &mut buf).is_some(),
        "the record is what the error is about — it stands"
    );
}

/// The control, and the half that says the case above is not simply asserting that
/// deletes fail: with nothing armed the same sequence answers `Ok(())` and takes
/// both halves with it.
#[test]
fn an_unfaulted_delete_takes_the_value_and_the_record() {
    let (mut fs, ram, _armed) = armed_fs();
    fs.put(SLOT, b"sealed key material").unwrap();
    fs.meta_add(SLOT, &[0xAA, 0x01, 0x02, 0x03]).unwrap();

    assert_eq!(fs.delete(SLOT), Ok(()));

    let mut buf = [0u8; 32];
    assert!(ram.borrow_mut().read(SLOT, &mut buf).is_none());
    assert!(
        ram.borrow_mut().read(EF_META, &mut buf).is_none(),
        "the last record was dropped, so EF_META goes with it"
    );
}

/// The third deleter owes the same answer, and it used to hide it: `force_delete`
/// spelled the drop `let _ = self.meta_delete(fid)` and then reported `Ok(())`,
/// which is `BugDeleteHidesFaultedDrop` — `NoSilentOrphan`'s mutant — standing in
/// the shipped tree at the one deleter all four applet reset sweeps go through.
/// The audit's second half is that `rsk-piv`'s wipe reaches metadata-carrying fids
/// through it, so MOVE was never "the one path" that does.
#[test]
fn a_faulted_metadata_drop_is_reported_by_force_delete_too() {
    let (mut fs, ram, armed) = armed_fs();
    fs.put(SLOT, b"sealed key material").unwrap();
    fs.meta_add(SLOT, &[0xAA, 0x01, 0x02, 0x03]).unwrap();

    armed.set(true);
    let answered = fs.force_delete(SLOT);
    armed.set(false);

    assert!(
        matches!(answered, Err(Error::MemoryFatal)),
        "a force_delete that could not drop the record answered {answered:?}"
    );
    let mut buf = [0u8; 32];
    assert!(
        ram.borrow_mut().read(SLOT, &mut buf).is_none(),
        "the value must go even when the record could not be dropped"
    );
    assert!(
        ram.borrow_mut().read(EF_META, &mut buf).is_some(),
        "the record is what the error is about — it stands"
    );
}

/// `force_delete`'s control: nothing armed, so the same sequence answers `Ok(())`
/// and both halves go — the unconditional backend `remove` is unchanged.
#[test]
fn an_unfaulted_force_delete_takes_the_value_and_the_record() {
    let (mut fs, ram, _armed) = armed_fs();
    fs.put(SLOT, b"sealed key material").unwrap();
    fs.meta_add(SLOT, &[0xAA, 0x01, 0x02, 0x03]).unwrap();

    assert_eq!(fs.force_delete(SLOT), Ok(()));

    let mut buf = [0u8; 32];
    assert!(ram.borrow_mut().read(SLOT, &mut buf).is_none());
    assert!(
        ram.borrow_mut().read(EF_META, &mut buf).is_none(),
        "the last record was dropped, so EF_META goes with it"
    );
}

/// What `force_delete` folds, and why the fold cannot be the only shape on offer:
/// the value went, the record could not be dropped, and those pull a reset sweep in
/// opposite directions. With one answer for both, the four applet sweeps `?`-ed a
/// faulted read of the SHARED EF_META blob out of their loops after a single file —
/// at the same fid on every retry, so no retry made progress (0x0987, measured on
/// `authenticatorReset`).
#[test]
fn force_delete_halves_keeps_the_value_and_the_record_apart() {
    let (mut fs, ram, armed) = armed_fs();
    fs.put(SLOT, b"sealed key material").unwrap();
    fs.meta_add(SLOT, &[0xAA, 0x01, 0x02, 0x03]).unwrap();

    armed.set(true);
    let gone = fs.force_delete_halves(SLOT);
    armed.set(false);

    assert_eq!(
        (gone.value, gone.record),
        (Ok(()), Err(Error::MemoryFatal)),
        "the removal is unconditional, so only the record half may fail here"
    );
    let mut buf = [0u8; 32];
    assert!(
        ram.borrow_mut().read(SLOT, &mut buf).is_none(),
        "the value must go even when the record could not be dropped"
    );
    assert!(
        ram.borrow_mut().read(EF_META, &mut buf).is_some(),
        "the record is what the error is about — it stands"
    );
}

/// The three answers, kept apart. `Storage::read`/`size` collapse "no such record"
/// and "that read failed" into one `None`, and an absent record is how this
/// firmware spells *not provisioned* — so the collapsing probes must keep behaving
/// exactly as before, and the `try_*` ones must separate the two. Both halves
/// matter: a fix that answered `Err` for a genuine absence would stop an
/// unprovisioned card from ever provisioning.
#[test]
fn a_failed_probe_is_an_error_and_an_absence_is_still_an_absence() {
    use crate::storage::faults::ProbeStuck;
    const LIVE: u16 = 0x1081;
    const NEVER: u16 = 0x1082;
    let (backend, medium) = ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.put(LIVE, b"the owner's verifier").unwrap();
    fs.meta_add(LIVE, &[0x03, 0x00, 0x02]).unwrap();

    // A record that was never written: absent, and cheaply so. This is the arm
    // first-use provisioning rides on.
    assert_eq!(fs.try_has_data(NEVER), Ok(false));
    assert_eq!(fs.try_read(NEVER, &mut [0u8; 8]), Ok(None));
    assert_eq!(fs.try_meta_find(NEVER, &mut [0u8; 8]), Ok(None));

    // The same answers for a live record the medium refuses — with the fault kept.
    medium.stick(Some(LIVE));
    assert_eq!(fs.try_has_data(LIVE), Err(Error::MemoryFatal));
    assert_eq!(fs.try_read(LIVE, &mut [0u8; 8]), Err(Error::MemoryFatal));
    assert!(!fs.has_data(LIVE), "the collapsing probe is unchanged");
    assert_eq!(fs.read(LIVE, &mut [0u8; 8]), None);
    medium.stick(Some(EF_META));
    assert_eq!(
        fs.try_meta_find(LIVE, &mut [0u8; 8]),
        Err(Error::MemoryFatal)
    );
    assert_eq!(fs.meta_find(LIVE, &mut [0u8; 8]), None);

    // And none of it was memoised: the medium recovers, the record is back.
    medium.stick(None);
    assert!(fs.try_has_data(LIVE).unwrap());
    assert_eq!(fs.try_meta_find(LIVE, &mut [0u8; 8]).unwrap(), Some(3));
}

/// A boot [`scan`](Fs::scan) cut short by a read fault leaves the FIDs it never
/// reached UNKNOWN, and a clear `present` bit means "unknown" as readily as
/// "empty". `present_slots` is the one reader with no backend to fall through to,
/// and `credential_store` writes the first slot it is told is free WITHOUT
/// re-reading it — so a truncated walk turned a live credential's slot into a
/// free one. The range reads occupied now, which costs capacity, not records.
#[test]
fn a_truncated_scan_leaves_no_slot_reading_free() {
    use crate::storage::faults::TruncatedWalk;
    const BASE: u16 = 0x2000;
    let mut fs = Fs::new(TruncatedWalk::new());
    fs.put(BASE + 1, b"a live credential record").unwrap();

    // A reboot: the same medium, a fresh cache, and a walk that yields nothing.
    let mut fs = Fs::new(fs.into_storage());
    fs.scan();
    let mut slots = [false; 4];
    fs.present_slots(BASE, &mut slots);
    assert_eq!(
        slots, [true; 4],
        "a walk that enumerated nothing decided nothing — no slot here is free"
    );
    assert_eq!(
        fs.read(BASE + 1, &mut [0u8; 32]),
        Some(24),
        "and the record the walk missed is still readable per key"
    );

    // A COMPLETE walk over the same records is bit-for-bit the raw present index.
    let mut fs = Fs::new(RamStorage::new());
    fs.put(BASE + 1, b"a live credential record").unwrap();
    fs.scan();
    let mut slots = [false; 4];
    fs.present_slots(BASE, &mut slots);
    assert_eq!(slots, [false, true, false, false]);
}

/// [`Fs::scan`] latches `scan_truncated` and [`Fs::factory_wipe`] resets the caches
/// it describes — but not that flag. So a card whose boot walk hit ONE transient
/// fault reported every slot occupied for the rest of the power cycle, factory reset
/// included: `credential_store` and OATH's `free_slot` answer FULL over a store that
/// is provably empty. The doc comment's own defence — "a fresh `Fs` that has not
/// scanned still reports free — its store is empty" — is exactly this case.
#[test]
fn a_factory_wipe_clears_the_truncated_scan_flag() {
    use crate::storage::faults::ProbeStuck;
    const BASE: u16 = 0x2000;
    let (backend, medium) = ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.put(BASE + 1, b"a live credential record").unwrap();

    // A reboot whose walk is cut short by a transient read fault.
    let mut fs = Fs::new(fs.into_storage());
    medium.truncate_walk(true);
    fs.scan();
    let mut slots = [false; 4];
    fs.present_slots(BASE, &mut slots);
    assert_eq!(
        slots, [true; 4],
        "control: a walk that enumerated nothing leaves no slot free"
    );

    // The medium recovers and the card is factory-reset.
    medium.truncate_walk(false);
    fs.factory_wipe(|_| false, |_| false, |_| false).unwrap();
    let mut seen = 0;
    fs.for_each_key(&mut |_| seen += 1);
    assert_eq!(seen, 0, "the store really is empty");
    fs.present_slots(BASE, &mut slots);
    assert_eq!(
        slots, [false; 4],
        "a just-wiped store reported every slot occupied"
    );
}

/// A RAM medium whose `for_each_key` yields in ASCENDING fid order. `RamStorage`
/// walks a `HashMap`, so WHICH key falls off the end of a full dynamic set is
/// whatever that run's hasher decided — which would make the test below flaky about
/// the one fid it is entirely about.
struct OrderedKeys(RamStorage);
impl Storage for OrderedKeys {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.0.read(fid, buf)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
        self.0.write(fid, data)
    }
    fn remove(&mut self, fid: u16) -> Result<()> {
        self.0.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.0.size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        let mut fids = std::vec::Vec::new();
        let complete = self.0.for_each_key(&mut |fid| fids.push(fid));
        fids.sort_unstable();
        for fid in fids {
            f(fid);
        }
        complete
    }
}

/// What a boot scan over MORE dynamic-eligible keys than [`MAX_DYNAMIC_FILES`]
/// actually costs the key whose registration is dropped. `Fs` carried an `over_cap`
/// flag for this, set here and read by nothing — so it recorded no more than the
/// `debug_assert!` it replaced. These four answers are the record: the key still
/// reads, the budget reports zero, a `put` to it is refused while a REGISTERED key
/// still writes, and a factory wipe still takes it. Only a key written outside `Fs`
/// can be in this state — `put` refuses a new file at the cap (see
/// `the_scrub_filler_never_costs_a_dynamic_slot` for the one historical way in).
#[test]
fn a_key_past_the_dynamic_cap_reads_refuses_writes_and_still_wipes() {
    const BASE: u16 = 0x2000;
    // The ascending walk's last key, so it is the push that finds the set full.
    const OVER: u16 = BASE + MAX_DYNAMIC_FILES as u16;

    let mut ram = RamStorage::new();
    for i in 0..=MAX_DYNAMIC_FILES as u16 {
        ram.write(BASE + i, &[0xAA]).unwrap();
    }
    let mut fs = Fs::new(OrderedKeys(ram));
    fs.scan();

    // `scan` sets present/decided for every enumerated key BEFORE it reaches the
    // push, so losing the registration must not cost the value: an unregistered key
    // marked absent instead would read `None` here without touching the backend.
    let mut buf = [0u8; 4];
    assert_eq!(
        fs.read(OVER, &mut buf),
        Some(1),
        "the key that lost its registration stopped reading"
    );
    assert_eq!(buf[0], 0xAA, "and it must read back its own value");

    assert_eq!(
        fs.free_dynamic(),
        0,
        "an over-subscribed budget must report no headroom"
    );

    // The refusal is about REGISTRATION, not a store-wide stop: without the
    // `register &&` half of `put`'s guard the second half of this pair goes too, and
    // the cap would refuse writes to keys it had already accepted.
    assert_eq!(
        fs.put(OVER, &[0xBB]),
        Err(Error::NoMemory),
        "an unregistered key's put should have been refused"
    );
    fs.put(BASE, &[0xBB])
        .expect("a registered key must still write at the cap");

    // The wipe takes its key set from the backend, not from the registry the key is
    // missing from — a reset that walked `dynamic` would leave it on the medium.
    fs.factory_wipe(|_| false, |_| false, |_| false).unwrap();
    assert!(
        !fs.has_data(OVER),
        "an unregistered key survived the factory wipe"
    );
}

#[test]
fn a_healthy_device_reports_no_refused_re_arm() {
    // Written first, because it is the whole false-positive argument for
    // `Fs::rescrub_refused`. The obvious surface — read EF_HARDENED on demand —
    // reports trouble on every healthy key: latched is the STEADY STATE of an
    // OTP-provisioned device past its first lap. The latch is a fact about a
    // transition instead, and this is that transition on a medium that serves it.
    let mut fs = fs();
    fs.put(KEY_DEV, b"pre-otp").unwrap();
    crate::run_at_rest_lap(&mut fs);
    assert!(
        fs.has_data(crate::EF_HARDENED),
        "fixture: the lap completed and the marker is latched, as on every \
         provisioned key"
    );
    assert!(
        !fs.rescrub_refused(),
        "a completed lap is not a refused re-arm"
    );

    // An ordinary wipe. `factory_wipe` re-arms at its head, best-effort, and this
    // medium serves it — no medium fault happened, so none may be reported.
    fs.factory_wipe(|_| false, |_| false, |_| false).unwrap();
    assert!(
        !fs.rescrub_refused(),
        "a healthy wipe reported the medium as refusing a re-arm, which would make \
         the signal fire on every shipped key and mean nothing"
    );
    assert!(
        !fs.has_data(crate::EF_HARDENED),
        "fixture: the head re-arm really did clear the marker"
    );
}

#[test]
fn a_marker_probe_that_cannot_answer_is_a_refusal_too() {
    // The other arm of `request_rescrub`'s `Err`, and the one the tests missed: the
    // removal may land and the READ-BACK still fault, and a re-arm nobody could
    // confirm is not a re-arm that landed. Narrowing the latch to the marker-still-
    // there arm left this whole shape reported as a healthy device.
    use crate::storage::faults::ProbeStuck;
    let (backend, medium) = ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.put(crate::EF_HARDENED, b"\x01").unwrap();
    // Rebuilt without a `scan`, as a boot that never enumerated leaves it: the
    // present bit is UNDECIDED, so `delete` skips the backend and the read-back is
    // the only thing that can answer — and it is exactly what faults.
    let mut fs = Fs::new(fs.into_storage());
    medium.stick(Some(crate::EF_HARDENED));

    assert_eq!(
        crate::request_rescrub(&mut fs),
        Err(Error::MemoryFatal),
        "fixture: the probe faulted rather than reading the marker back"
    );
    assert!(
        fs.rescrub_refused(),
        "a re-arm whose read-back could not answer was reported as one that landed"
    );
}

#[test]
fn a_single_shot_refusal_the_retry_recovered_still_reports() {
    // The judgement this latch turns on, argued rather than assumed. `refuse_once`
    // is the arm the wipe sites' retry recovers: the marker leaves the medium, so
    // the lap WILL run and nothing lies. Setting the latch anyway is what makes it
    // honest — it says the medium refused a re-arm this power cycle, and it did.
    // Clearing it on the retry would narrow it to "the LAST re-arm failed", and a
    // wipe is exactly that shape: head refused, retry served, host told nothing.
    let (stuck, medium) = RemoveStuck::new();
    let mut fs = Fs::new(stuck);
    fs.put(crate::EF_HARDENED, b"\x01").unwrap();
    medium.refuse_once(crate::EF_HARDENED);

    assert!(
        crate::request_rescrub(&mut fs).is_err(),
        "fixture: the single-shot fault fired on the head re-arm"
    );
    assert!(
        crate::request_rescrub(&mut fs).is_ok(),
        "fixture: and the retry recovered it, which is what makes this the arm the \
         answer alone cannot distinguish from a healthy device"
    );
    assert!(
        !fs.has_data(crate::EF_HARDENED),
        "fixture: the lap is genuinely re-armed — this is NOT a marker that lies"
    );
    assert!(
        fs.rescrub_refused(),
        "a recovered retry cleared the latch, so a medium that refused is now \
         indistinguishable from one that never did"
    );
}

#[test]
fn a_refused_re_arm_is_reported_and_not_swallowed() {
    // F1: the write order alone covers a power cut and nothing else. A medium that
    // refuses `remove(EF_HARDENED)` and serves everything around it reaches the SAME
    // end state — the marker latched over a copy the caller is about to supersede —
    // with no reset in it, so `request_rescrub` must answer instead of `let _ =`.
    let (stuck, medium) = RemoveStuck::new();
    let mut fs = Fs::new(stuck);
    fs.put(crate::EF_HARDENED, b"\x01").unwrap();
    assert!(
        fs.has_data(crate::EF_HARDENED),
        "fixture: the lap has latched"
    );
    medium.refuse(Some(crate::EF_HARDENED));

    assert!(
        crate::request_rescrub(&mut fs).is_err(),
        "the medium refused the re-arm, so the lap will NOT run and the caller must \
         not go on to supersede a pre-OTP copy"
    );
    assert!(
        medium.live(crate::EF_HARDENED),
        "fixture: the refusal really left the marker on the medium",
    );
    assert!(
        fs.has_data(crate::EF_HARDENED),
        "fixture: and the lap's own gate still reads it as done",
    );
    // The answer is the gated sites' half. The wipe paths discard it on purpose —
    // refusing there would leave the secrets live — so a refusal nothing latches
    // is a refusal nothing can ever report, and the wipe answers the host success.
    assert!(
        fs.rescrub_refused(),
        "a persistently stuck medium left no trace of the refusal outside the \
         return value the wipe paths throw away"
    );

    // The control, and not a no-op: the same medium with the fault cleared re-arms,
    // says so, and the marker leaves the medium.
    medium.refuse(None);
    assert!(
        crate::request_rescrub(&mut fs).is_ok(),
        "a healthy medium must still report the re-arm as landed"
    );
    assert!(!medium.live(crate::EF_HARDENED));
    assert!(
        fs.rescrub_refused(),
        "the latch is per POWER CYCLE, not per call: a later healthy re-arm does \
         not un-refuse the one this medium already refused"
    );
}

#[test]
fn a_re_arm_the_present_cache_skipped_is_not_reported_as_landed() {
    // `Fs::delete` skips the backend `remove` when the present bit is clear and then
    // answers `Ok` — and a read-fault-truncated `scan` leaves that bit clear over a
    // live marker (the `if complete` guard on the decided-fill). So `delete`'s own
    // result is not sufficient either: the re-arm is judged by reading the marker
    // back through the gate `run_at_rest_lap` uses.
    let mut walk = TruncatedWalk::new();
    walk.write(crate::EF_HARDENED, b"\x01").unwrap();
    let mut fs = Fs::new(walk);
    fs.scan();
    assert!(
        fs.delete(crate::EF_HARDENED).is_ok(),
        "fixture: this is the swallow's input — the delete answers Ok here"
    );

    assert!(
        crate::request_rescrub(&mut fs).is_err(),
        "the backend removal never ran, so the marker is still there and the lap \
         will not run — reporting that re-arm as landed is the swallow one layer down"
    );
    assert!(
        fs.has_data(crate::EF_HARDENED),
        "fixture: the marker really was live — the probe that refused read it off \
         the medium, past the cleared present bit"
    );
    // That probe settled the bit, so the retry reaches the backend the first skipped.
    assert!(
        crate::request_rescrub(&mut fs).is_ok(),
        "the failed re-arm settled the cache, so a retry must actually re-arm"
    );
    assert!(!fs.has_data(crate::EF_HARDENED));
    assert!(
        fs.rescrub_refused(),
        "the swallow one layer down again: a cache-skipped re-arm the retry \
         recovered is still a re-arm this power cycle could not be shown to land"
    );
}

/// A record whose length runs past the end of `EF_META` is where the walk stops.
/// Both parsers own that stop — the reader and the rebuild a later `meta_add`
/// runs — so a truncated tail is unreadable, never a slice out of bounds, and it
/// is dropped rather than carried forward into the blob that gets written back.
#[test]
fn a_meta_record_longer_than_the_blob_stops_both_walks() {
    let mut st = RamStorage::new();
    let mut blob = std::vec![0xB0, 0x00, 0x00, 0x07];
    blob.extend_from_slice(b"keep-me");
    // Claims 16 bytes and carries none.
    blob.extend_from_slice(&[0xB0, 0x01, 0x00, 0x10]);
    st.write(EF_META, &blob).unwrap();
    let mut fs = Fs::new(st);
    fs.scan();

    let mut out = [0u8; 32];
    assert_eq!(fs.meta_find(0xB000, &mut out), Some(7));
    assert_eq!(&out[..7], b"keep-me");
    assert_eq!(
        fs.meta_find(0xB001, &mut out),
        None,
        "a truncated record read"
    );

    fs.meta_add(0xB002, b"new").unwrap();
    assert_eq!(fs.meta_find(0xB000, &mut out), Some(7));
    assert_eq!(fs.meta_find(0xB002, &mut out), Some(3));
    assert_eq!(
        fs.meta_find(0xB001, &mut out),
        None,
        "the rebuild carried the truncated tail forward"
    );
}

/// A backend whose enumeration yields every key TWICE — what a ring holding two
/// live copies of one fid looks like from `for_each_key`.
struct DoubleWalk(RamStorage);

impl Storage for DoubleWalk {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.0.read(fid, buf)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
        self.0.write(fid, data)
    }
    fn remove(&mut self, fid: u16) -> Result<()> {
        self.0.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.0.size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        let mut seen = std::vec::Vec::new();
        let complete = self.0.for_each_key(&mut |fid| seen.push(fid));
        for fid in seen {
            f(fid);
            f(fid);
        }
        complete
    }
}

/// The registry `scan` rebuilds is a set, not a tally: a key yielded twice spends
/// ONE file of the capacity budget, or a store carrying a duplicate would bind the
/// cap at half the files it actually holds.
#[test]
fn an_enumeration_that_yields_a_key_twice_registers_it_once() {
    let mut st = RamStorage::new();
    st.write(0xCC10, b"one").unwrap();
    st.write(0xCC11, b"two").unwrap();
    let mut fs = Fs::new(DoubleWalk(st));
    fs.scan();
    assert_eq!(fs.free_dynamic(), MAX_DYNAMIC_FILES - 2);
}
