// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
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

    fs.factory_wipe(|fid| fid == 0xAAAA).unwrap();

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
    fs.factory_wipe(|_| false).unwrap();
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
    let big = [0u8; 2048]; // > META_MAX (1024): must clamp, not slice out of range
    fs.put(crate::EF_META, &big).unwrap();
    let mut out = [0u8; 32];
    assert_eq!(fs.meta_find(0xAAAA, &mut out), None);
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
