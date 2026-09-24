// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The key/value file and metadata API over a [`Storage`] backend.

use heapless::Vec;
use rsk_sdk::error::{Error, Result};

use crate::sealed::{KeyFid, Sealed};
use crate::storage::Storage;
use crate::{EF_META, EF_SCRUB_FILLER, MAX_DYNAMIC_FILES};

/// Max size of the meta side-store blob.
const META_MAX: usize = 1024;

/// EF_META record header: `[fid: u16 BE][len: u16 BE]`.
const META_REC_HDR: usize = 4;

/// One bit per 16-bit FID: the full `0x0000..=0xFFFF` space as a present/absent
/// bitmap (8 KiB). Backs the fast-negative cache in [`Fs`].
#[cfg(not(kani))]
const FID_PRESENT_BYTES: usize = (u16::MAX as usize + 1) / 8;
/// Three bytes under `cfg(kani)`: a symbolic index into 8 KiB costs CBMC 2.5 to
/// 13 minutes per writing harness (measured — two of the six were over
/// `scripts/kani.sh`'s 5-minute FAST cap), while the cache clauses are uniform in
/// `fid`, and three bytes keep every within-byte and cross-byte neighbour
/// reachable. What the shrink stops proving is stated below instead.
#[cfg(kani)]
const FID_PRESENT_BYTES: usize = 3;

/// No `fid` can index past the map — the fact that lets every cache primitive
/// skip a bound check. Compile-time and about the SHIPPED width, so it holds
/// where the shrunk proofs no longer look, and it is the stronger statement
/// anyway: a proof would only have covered the FIDs a harness enumerated.
#[cfg(not(kani))]
const _: () = assert!(((u16::MAX >> 3) as usize) < FID_PRESENT_BYTES);

/// Where `fid` lives in the present/decided maps: byte index and bit mask.
///
/// One definition because the theorem below is about THIS function. Spelled out
/// at each of its five call sites — four helpers plus the copy inside `scan`'s
/// closure, which cannot borrow `self` — the arithmetic could drift at one site
/// and leave a compile-time assertion about the other four still passing.
#[inline]
const fn slot(fid: u16) -> (usize, u8) {
    ((fid >> 3) as usize, 1u8 << (fid & 7))
}

/// And no two FIDs share a bit. [`slot`] is injective because its two halves
/// RECOMPOSE `fid`, so equal slots force equal FIDs — which is exactly "a put
/// never aliases another file", over the whole shipped domain rather than the
/// 24 bits `cfg(kani)` leaves. Enumerated for all 65 536 rather than argued for
/// a symbolic pair: at this width enumerating is cheaper than reasoning, and it
/// holds in the shrunk arm too, which is where the proofs cannot look.
const _: () = {
    let mut fid: u32 = 0;
    while fid <= u16::MAX as u32 {
        let (i, m) = slot(fid as u16);
        assert!(((i as u32) << 3) | (m.trailing_zeros()) == fid);
        fid += 1;
    }
};

/// Fids one [`Fs::factory_wipe`] pass collects before removing them. Named
/// because the wrap to a second pass is a code path, and the test that crosses it
/// has to size its fixture off this rather than off a copy of the number.
const WIPE_BATCH: usize = 64;

/// The two answers a removal gives, kept apart for the callers that must act on
/// them differently. [`Fs::force_delete`] folds them into one `Result`, which is
/// the right default; a reset sweep cannot use it, because the two failures pull
/// it in opposite directions.
#[must_use]
pub struct Removal {
    /// The backend removal. `Err` is "the medium refused, and the value may
    /// still be live" — a sweep must stop on it, because `for_each_key` keeps
    /// re-yielding a fid it could not remove.
    pub value: Result<()>,
    /// The EF_META drop. `Err` is "the value is gone, a record may still stand
    /// over it" — a sweep must NOT stop on it, because EF_META is one blob shared
    /// by every applet, so one faulted read of it would end the wipe after a
    /// single file and end it at the same fid on every retry.
    pub record: Result<()>,
}

/// The file system: the set of live dynamic FIDs and a present-cache over a
/// [`Storage`] backend.
pub struct Fs<S: Storage> {
    storage: S,
    dynamic: Vec<u16, MAX_DYNAMIC_FILES>,
    /// Negative cache (paired with [`decided`](Self#structfield.decided)): bit
    /// `fid` set iff the backend is KNOWN to hold a value for `fid`. Lets
    /// `read`/`size` answer "absent" without touching the backend — a backend
    /// `read` of an absent key scans the whole flash partition, so probing a
    /// sparse object range (e.g. the ~25 mostly-empty PIV certificate slots
    /// Yubico Authenticator reads) was O(slots · flash). Set on every write,
    /// cleared on every remove; `scan` seeds it from `for_each_key`.
    ///
    /// A bare clear bit is trusted as "absent" only once `decided` confirms it:
    /// `for_each_key` returning *complete* means it enumerated every live key (its
    /// forward ring walk is a page-superset of `fetch_item`'s, and reclaim erases a
    /// source only after forwarding its items — no torn power cut can hide a
    /// committed key), so `scan` decides the whole space. A walk truncated by a
    /// flash read fault leaves the un-yielded FIDs undecided instead.
    present: [u8; FID_PRESENT_BYTES],
    /// Authority bit for [`present`](Self#structfield.present): set iff `fid`'s
    /// present/absent state is confirmed. After a *complete* `scan` (`for_each_key`
    /// ran to its `None` terminator) EVERY FID is decided — present ones from the
    /// walk, all others authoritatively absent — so a cold absent read is O(1). If
    /// the walk was truncated (a read fault) only the enumerated keys are decided;
    /// the rest stay *unknown* and fall through to the reliable per-key `fetch_item`,
    /// which memoises the answer, so a false-absent is impossible either way. See
    /// [`known_absent`](Self::known_absent) and [`scan`](Self::scan).
    decided: [u8; FID_PRESENT_BYTES],
    /// Monotonic counter bumped on every content-changing `put`/`delete`. A caller
    /// caching a derived view of the store (e.g. the credMgmt slot→rpIdHash index)
    /// snapshots it and rebuilds when it moves, so no mutation path can leave that
    /// cache stale. In-RAM only (resets to 0 each boot); `u32` never realistically
    /// wraps between two reads of a mutation-free session.
    write_gen: u32,
    /// Set by [`scan`](Self::scan) when the boot enumeration was cut short, so the
    /// FIDs it never reached are unknown rather than absent. Only
    /// [`present_slots`](Self::present_slots) reads it: the per-key probes fall
    /// through to the backend on an undecided FID and are sound already, but the
    /// slot bitmap answers from RAM alone and has no such fallback. Distinct from
    /// "nothing decided yet" — a fresh `Fs` that has not scanned has an empty
    /// `present` map and reports free, which is what it is.
    ///
    /// It is a claim about ONE walk, so anything that replaces the store it walked
    /// clears it — [`factory_wipe`](Self::factory_wipe) does. Left latched, one
    /// transient boot fault made every slot read occupied for the rest of the power
    /// cycle, a factory reset included.
    scan_truncated: bool,
    /// Set when a [`crate::request_rescrub`] this power cycle could not be shown to
    /// have landed. It says the MEDIUM refused a re-arm — NOT that the marker lies:
    /// at the gated call sites the refusal stops the write it guards, so nothing is
    /// superseded and the marker stays true, whether the site then errors to the
    /// host or skips a lazy migration. The wipe paths are why it exists: there the
    /// refusal is best-effort, because "leave the record in force" would mean leave
    /// the secrets live, so a wipe over a persistently stuck medium answers the host
    /// success with the lap latched off, and nothing else in the tree says so.
    ///
    /// In RAM, per power cycle, and never persisted: a flash breadcrumb would be a
    /// write to the medium that is refusing, and its own failure would be
    /// unreportable by the same argument. Reading the marker on demand is no
    /// substitute — latched is the steady state of every provisioned device past its
    /// first lap, so a bare marker read reports trouble on a healthy key.
    rescrub_refused: bool,
}

impl<S: Storage> Fs<S> {
    pub fn new(storage: S) -> Self {
        Fs {
            storage,
            dynamic: Vec::new(),
            present: [0u8; FID_PRESENT_BYTES],
            decided: [0u8; FID_PRESENT_BYTES],
            write_gen: 0,
            scan_truncated: false,
            rescrub_refused: false,
        }
    }

    /// The store's mutation generation — bumped by every content-changing
    /// `put`/`delete`. Snapshot it beside a cached derived view and rebuild when it
    /// changes (see [`write_gen`](Self#structfield.write_gen)).
    pub fn write_gen(&self) -> u32 {
        self.write_gen
    }

    /// Did the medium refuse an at-rest-lap re-arm this power cycle? Medium health,
    /// reported out of band because the wipe paths discard the refusal by design
    /// (see [`rescrub_refused`](Self#structfield.rescrub_refused)).
    pub fn rescrub_refused(&self) -> bool {
        self.rescrub_refused
    }

    /// Latch the answer [`rescrub_refused`](Self::rescrub_refused) carries.
    /// `pub(crate)` because [`crate::request_rescrub`] is what decides that a re-arm
    /// was refused, and it is the only re-arm in the tree.
    pub(crate) fn note_rescrub_refused(&mut self) {
        self.rescrub_refused = true;
    }

    /// Recover the backend (e.g. to rebuild the `Fs` — used in tests to model a
    /// reboot).
    pub fn into_storage(self) -> S {
        self.storage
    }

    /// Raw present bit (does NOT consult `decided`). Authoritative only for a
    /// FID known present; for the trustworthy absent test use
    /// [`known_absent`](Self::known_absent).
    #[inline]
    fn present_bit(&self, fid: u16) -> bool {
        let (i, m) = slot(fid);
        self.present[i] & m != 0
    }

    /// Is `fid`'s present/absent state confirmed (vs. unknown-until-probed)?
    #[inline]
    fn decided_bit(&self, fid: u16) -> bool {
        let (i, m) = slot(fid);
        self.decided[i] & m != 0
    }

    /// Trustworthy fast-negative test: true only when `fid` is *confirmed*
    /// absent. An unknown FID returns false so the caller falls through to the
    /// reliable backend (and then caches the result) — this is what prevents a
    /// post-power-cut false-absent. Confirmed-absent stays O(1).
    ///
    /// Refines `RSKeyStore!NoFalseAbsent` — SEC-STORE-002.
    #[inline]
    fn known_absent(&self, fid: u16) -> bool {
        self.decided_bit(fid) && !self.present_bit(fid)
    }

    /// Cache the backend's authoritative answer for `fid`.
    #[inline]
    fn record(&mut self, fid: u16, present: bool) {
        if present {
            self.mark_present(fid);
        } else {
            self.mark_absent(fid);
        }
    }

    /// Mark `fid` known present (sets the authority bit too).
    #[inline]
    fn mark_present(&mut self, fid: u16) {
        let (i, m) = slot(fid);
        self.present[i] |= m;
        self.decided[i] |= m;
    }

    /// Judge one backend probe: `Err` iff the backend FAILED, `Ok(None)` only for
    /// an absence it actually reported, and the answer cached only when there was
    /// one.
    ///
    /// `Storage::read`/`size` return `None` for both outcomes. Caching a fault would
    /// set the DECIDED bit and turn one transient error into a permanent "file
    /// absent" for the rest of the boot (audit run-36); leaving the FID undecided
    /// re-probes it next time, which is the pre-cache behaviour. Separating the two
    /// at the RETURN is the other half, and the one the `try_*` probes publish —
    /// see [`try_has_data`](Self::try_has_data).
    #[inline]
    fn settle<T>(&mut self, fid: u16, r: Option<T>) -> Result<Option<T>> {
        if r.is_none() && self.storage.last_error() {
            return Err(Error::MemoryFatal);
        }
        self.record(fid, r.is_some());
        Ok(r)
    }

    /// Mark `fid` known absent (sets the authority bit, clears present).
    #[inline]
    fn mark_absent(&mut self, fid: u16) {
        let (i, m) = slot(fid);
        self.present[i] &= !m;
        self.decided[i] |= m;
    }

    /// Rebuild the dynamic-file set from what's already in storage (run once
    /// after a reboot). The `if complete` guard on the decided-fill is the
    /// owner of the truncated-scan half of the cache-soundness property.
    ///
    /// Refines `RSKeyStore!NoFalseAbsent` — SEC-STORE-002.
    pub fn scan(&mut self) {
        // Disjoint field borrows so the `for_each_key` closure can update all
        // three while `self.storage` drives the pass.
        let dynamic = &mut self.dynamic;
        let present = &mut self.present;
        let decided = &mut self.decided;
        dynamic.clear();
        present.fill(0);
        decided.fill(0);
        let complete = self.storage.for_each_key(&mut |fid| {
            // Every enumerated key — dynamic or EF_META — is confirmed present.
            let (i, m) = slot(fid);
            present[i] |= m;
            decided[i] |= m;
            // Neither is a file: EF_META is the shared metadata record, and the
            // scrub filler is written by `Storage::compact` straight through the
            // backend. Counting the filler as a dynamic file is what cost a live key
            // its registration at the cap (audit run-36).
            if fid == EF_META || fid == EF_SCRUB_FILLER {
                return;
            }
            if !dynamic.contains(&fid) {
                // Only a key written outside `Fs` can be here past the cap — `put`
                // refuses a new file at it. Its value stays readable; what the
                // dropped registration costs it is every future `put` (`NoMemory`).
                let _ = dynamic.push(fid);
            }
        });
        // A COMPLETE enumeration yielded every live key: the backend's forward ring
        // walk is a page-superset of `fetch_item`'s, and page reclaim erases a source
        // only after forwarding its items, so no torn power cut can hide a committed
        // key from it. An un-yielded FID is then authoritatively absent — decide the
        // whole FID space so a cold absent `read`/`has_data` is O(1) instead of a
        // full-partition scan. Only a flash READ FAULT can truncate the walk
        // (`complete == false`); then leave the un-yielded FIDs *undecided* so
        // confirm-on-miss re-probes them and a hidden live page is never read absent.
        if complete {
            decided.fill(0xFF);
        }
        self.scan_truncated = !complete;
    }

    /// Copy file contents into `buf`; returns the value's full length, or `None`.
    ///
    /// A probe the backend could not complete reads as an absence here — see
    /// [`try_read`](Self::try_read) for when that collapse is not allowed.
    pub fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.try_read(fid, buf).ok().flatten()
    }

    /// [`read`](Self::read) with the failed probe kept apart from the absence:
    /// `Ok(None)` is a confirmed absence, `Err` is "the backend could not answer".
    ///
    /// An absent record is how this firmware spells *no gate configured* and *not
    /// provisioned yet*, so a caller that takes `None` for a decision acts on a
    /// flash fault — one faulted `EF_PIN` probe re-seeded PIV's factory PIN, PUK
    /// and management key over the owner's. Use these `try_*` probes wherever the
    /// absent arm overwrites configured material or opens a gate; the collapsing
    /// ones stay right where an absence costs a status field or a repeated repair.
    ///
    /// **Do not derive the sites by asking "does the absent arm write?"** That
    /// question found 37 guards and missed six live regressions, because in each of
    /// the six the collapsed answer is not acted on where it is read. It becomes an
    /// **unwritten branch** — `if probe { return Err(..) }`, where the harm is a
    /// `return` that does not happen (`vendor::pin_gate`, `backup_export`); a
    /// **consumed value** — `None` resolving to a default a later statement persists
    /// or signs (`journal::load_meta`'s genesis, PIV GENERATE's "no certificate");
    /// or a **latched flag** — stored and read by a later command, so the fault and
    /// the harm sit in different call frames (`oath::select`'s `validated`,
    /// [`scan_truncated`](Self#structfield.scan_truncated), PIV `scan_files`'
    /// `have_meta`).
    ///
    /// The question that finds all of them: **if this probe answered `false`/`None`
    /// where the truth is `true`/`Some`, what becomes reachable?** — then follow that
    /// answer to whoever consumes it, the empty `else` included.
    pub fn try_read(&mut self, fid: u16, buf: &mut [u8]) -> Result<Option<usize>> {
        if self.known_absent(fid) {
            return Ok(None); // confirmed absent — skip the backend's full scan
        }
        // Present or unknown: the backend (reliable per-key `fetch_item`) is the
        // source of truth; cache what it says so the next probe is O(1).
        let r = self.storage.read(fid, buf);
        self.settle(fid, r)
    }

    /// Length of the file's contents, or `None` if absent (or unreadable — see
    /// [`try_read`](Self::try_read)).
    pub fn size(&mut self, fid: u16) -> Option<usize> {
        self.try_size(fid).ok().flatten()
    }

    /// [`size`](Self::size), fallible — see [`try_read`](Self::try_read).
    fn try_size(&mut self, fid: u16) -> Result<Option<usize>> {
        if self.known_absent(fid) {
            return Ok(None);
        }
        let r = self.storage.size(fid);
        self.settle(fid, r)
    }

    /// Whether the file exists with non-empty contents — `false` for an
    /// unreadable one too, which is the collapse [`try_has_data`](Self::try_has_data)
    /// exists to keep out.
    pub fn has_data(&mut self, fid: u16) -> bool {
        self.try_has_data(fid).unwrap_or(false)
    }

    /// [`has_data`](Self::has_data), fallible — see [`try_read`](Self::try_read).
    pub fn try_has_data(&mut self, fid: u16) -> Result<bool> {
        Ok(self.try_size(fid)?.is_some_and(|n| n > 0))
    }

    /// Invoke `f` once per live key in the backend, in a single storage pass.
    /// Use this instead of probing a fixed FID range with `read`: a `read` of an
    /// *absent* key rescans the whole flash, so probing 256 slots is O(256·items)
    /// while one `for_each_key` pass is O(items).
    ///
    /// A FID can be yielded MORE THAN ONCE — the log-structured backend walks
    /// stored items, and an overwritten file keeps one item per superseded version
    /// until reclaim — so a caller that counts or batches FIDs must de-dup (`scan`
    /// below does).
    ///
    /// Returns [`Storage::for_each_key`]'s completeness flag: `false` means a read
    /// fault truncated the walk, so an un-yielded FID is NOT evidence of absence —
    /// a wipe sweep must then fail rather than report its range clear.
    pub fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        self.storage.for_each_key(f)
    }

    /// Fill `out[i]` with whether `base + i` may hold a record, read straight from
    /// the in-RAM present index — no backend scan. Occupancy-equivalent to a
    /// [`for_each_key`](Self::for_each_key) pass over the range (both derive from
    /// the boot [`scan`](Self::scan) seed, kept live by every `put`/`delete`), but
    /// O(len) RAM bit tests instead of O(flash items). Use it where a caller needs
    /// only the occupied-slot bitmap over a FID range (credMgmt enumerate,
    /// makeCredential dedup / free-slot); occupied slots must still be `read` for
    /// their data. A `present` bit is only ever set by a confirmed put/read, so a
    /// stale-positive at worst costs one skipped `read`.
    ///
    /// A clear `present` bit means two different things after a boot
    /// [`scan`](Self::scan): a slot the walk proved empty, and — if a read fault cut
    /// the walk short — one it never reached. `makeCredential` writes the first free
    /// slot it is handed WITHOUT re-reading it, so answering the second "free"
    /// overwrites a live credential. A truncated scan therefore reports the whole
    /// range occupied, which costs capacity instead. Every other caller re-`read`s a
    /// slot it was told is occupied and skips the empty ones, so the cost stops at
    /// one wasted probe. A scan that COMPLETED is bit-for-bit the raw index, and a
    /// fresh `Fs` that has not scanned still reports free — its store is empty.
    pub fn present_slots(&self, base: u16, out: &mut [bool]) {
        for (i, b) in out.iter_mut().enumerate() {
            *b = base
                .checked_add(i as u16)
                .is_some_and(|fid| self.scan_truncated || self.present_bit(fid));
        }
    }

    /// Free slots in the shared dynamic-file budget: how many more dynamic files
    /// (across every applet) can be stored before [`MAX_DYNAMIC_FILES`] binds. Lets
    /// a caller report capacity honestly against the SHARED store — e.g. FIDO's
    /// remaining-credential estimate, which must not promise slots a PIV or OATH
    /// fill has already consumed.
    pub fn free_dynamic(&self) -> usize {
        MAX_DYNAMIC_FILES - self.dynamic.len()
    }

    /// Physically scrub superseded records from the backing store (a full
    /// garbage-collection lap). See [`Storage::compact`]. No-op on backends that
    /// overwrite in place and accumulate no remnants. Used once, after the
    /// post-OTP-provisioning seal migrations, to erase the chip-serial-sealed
    /// copies those migrations supersede.
    pub fn compact(&mut self) -> Result<()> {
        self.storage.compact()
    }

    /// Factory-wipe: erase every stored key except those `preserve` keeps, then
    /// physically scrub the backing store so no superseded secret survives a raw
    /// flash dump. The caller supplies the keep-set (e.g. the org attestation,
    /// which is device identity rather than user data) and is expected to reboot
    /// afterwards — the device re-provisions a fresh seed on the next boot, and a
    /// [`compact`](Self::compact) lap leaves the partition with only the preserved
    /// keys live.
    ///
    /// The removal is unconditional — unlike [`delete`](Self::delete) it does not
    /// consult the present-cache, because every key the backend enumerates is live
    /// by definition, so removing it directly both wipes it and stays O(items)
    /// (there are no absent probes to skip). Keys are taken in bounded batches: the
    /// enumerator can't run while the store mutates, so each pass collects a batch,
    /// removes it, and re-enumerates until only the preserved keys remain.
    /// `last` names the records that *gate* the applets — PIN and PUK verifiers,
    /// retry counters, management keys, the `alwaysUv` latch, access codes. They are
    /// removed in a second phase, after everything else is provably gone, because a
    /// single sweep can reach them first (`for_each_key` yields in flash-ring order,
    /// not FID order) and a power cut there leaves the applet's secrets reachable:
    /// the next boot either re-provisions a *published* credential over key material
    /// that is still live and, for PIV, not PIN-bound at rest — or, for OATH, leaves
    /// no credential at all, its `select` reading an absent access code as unlocked.
    ///
    /// This is the same rule all four applet sweeps carry — `rsk_fido`'s `reset`,
    /// `wipe_piv`, `wipe_oath` and `wipe_openpgp` — and this path bypasses every one
    /// of them, so it has to carry it itself and the caller has to supply a `last`
    /// that is genuinely the union of theirs. Saying it here is not enforcing it:
    /// `wipe_oath`'s half was missing from the firmware's union for a release
    /// (audit run-36), which is why each applet now exports its own predicate rather
    /// than having its fids open-coded at the call site.
    ///
    /// `first` is the mirror image: a record every *other* record's secrecy hangs
    /// on, so a prefix of the wipe that stops after it leaves nothing readable. Only
    /// FIDO has one — its device seed — since PIV, OATH and OpenPGP hold key
    /// material per slot; `rsk_fido::is_fido_seed_fid` names it.
    pub fn factory_wipe(
        &mut self,
        preserve: impl Fn(u16) -> bool,
        first: impl Fn(u16) -> bool,
        last: impl Fn(u16) -> bool,
    ) -> Result<()> {
        // Every tombstone below appends like a re-seal, so the at-rest lap owes a
        // re-arm ahead of the first — best-effort, because on a wipe a stopped
        // re-arm means live secrets. Phase 1 removes EF_HARDENED itself, retrying it.
        let _ = crate::request_rescrub(self);
        // `first` wins over `last` if a caller ever hands in overlapping predicates:
        // deleting a record early can only ever be safe, deleting it late cannot.
        let phase_of = |fid: u16| {
            if first(fid) {
                0
            } else if last(fid) {
                2
            } else {
                1
            }
        };
        for phase in 0..3 {
            loop {
                let mut batch = [0u16; WIPE_BATCH];
                let mut n = 0usize;
                let complete = self.storage.for_each_key(&mut |fid| {
                    if !preserve(fid) && phase_of(fid) == phase && n < batch.len() {
                        batch[n] = fid;
                        n += 1;
                    }
                });
                if n == 0 {
                    // An un-yielded FID is only evidence of absence when the walk
                    // finished; a truncated one must fail rather than report the
                    // range clear (the rule PIV and OpenPGP already enforce).
                    if !complete {
                        return Err(Error::MemoryFatal);
                    }
                    break;
                }
                for &fid in &batch[..n] {
                    self.storage.remove(fid)?;
                }
            }
        }
        // The caches described the now-erased store; reset them so any reuse before
        // the reboot re-probes the backend (the dynamic set is gone too), then scrub.
        // `scan_truncated` goes with them: it is a claim about the boot walk over a
        // store that no longer exists, and this wipe would not have returned without
        // a COMPLETE walk of every phase — so the empty index is authoritative and
        // `present_slots` may report free again.
        self.present.fill(0);
        self.decided.fill(0);
        self.scan_truncated = false;
        self.dynamic.clear();
        self.storage.compact()
    }

    /// Store file contents, registering a dynamic file if new.
    pub fn put(&mut self, fid: u16, data: &[u8]) -> Result<()> {
        // Reject past the backend's own ceiling here, so no applet has to know it.
        if data.len() > S::MAX_VALUE {
            return Err(Error::WrongLength);
        }
        // A new dynamic file that would overflow the set is rejected *before* the
        // flash write: registering only after committing would strand the value
        // on flash — readable yet unregistered — and leave `scan` to re-drop it
        // at the same cap on every reboot.
        let register = !self.dynamic.contains(&fid);
        if register && self.dynamic.is_full() {
            return Err(Error::NoMemory);
        }
        self.storage.write(fid, data)?;
        self.mark_present(fid);
        self.write_gen = self.write_gen.wrapping_add(1);
        if register {
            let _ = self.dynamic.push(fid); // cap checked above — cannot fail
        }
        Ok(())
    }

    /// Delete a file: drop its contents, metadata, and any dynamic entry.
    ///
    /// The backend `remove` (a full-partition scan plus a tombstone write) is
    /// skipped for an absent FID — the present-cache answers in O(1), matching
    /// [`read`](Self::read) / [`has_data`](Self::has_data). Without that guard a
    /// blind delete sweep over many absent slots is O(slots·partition): the FIDO
    /// `authenticatorReset` audit-ring scrub (128 slots) measured ~12 s on
    /// hardware, overrunning host reset timeouts (the FIDO conformance tool gives
    /// a reset 10 s) and wedging the suite.
    ///
    /// The metadata drop and the dynamic-set cleanup, by contrast, run
    /// unconditionally: a file can carry metadata (a [`meta_add`](Self::meta_add)
    /// with no `put`) without its contents ever being present, so gating the meta
    /// cleanup on the file's present bit would orphan it — a deleted file's
    /// metadata would read back alive. It stays O(1) when there is nothing to
    /// drop: `meta_delete` has its own EF_META present-cache guard and skips the
    /// rewrite when `fid` had no record.
    ///
    /// **The metadata drop's failure is returned, and the value goes anyway.** A
    /// failed EF_META read is "cannot tell", not "no record", and EF_META is one
    /// blob shared by every applet — so refusing the removal would stop every
    /// delete on the device (a wipe included, since most callers discard this
    /// result) for the lifetime of one flash fault, which trades an orphaned
    /// record for a secret that outlives its erase. `Err` therefore names a
    /// state, not a no-op: the value is gone and a record may still stand over
    /// it. A caller that cannot live with that reads it — `rsk-piv`'s MOVE does,
    /// because GET METADATA would answer for a key that is no longer there.
    ///
    /// Refines `RSKeyStore!NoOrphanedMetadata` — SEC-STORE-001, where the drop
    /// landed, and Refines `RSKeyStore!NoSilentOrphan` — SEC-STORE-006, where not.
    ///
    /// Unlike the read paths, the backend `remove` keys off the *raw* present bit
    /// rather than `known_absent`: an UNKNOWN FID is skipped, not confirmed. This
    /// deliberately keeps the cold-boot reset sweep O(1) (confirming 128 unknown
    /// audit slots would re-introduce the multi-second scan). The cost is only
    /// that a delete of a (rare) torn-migration false-absent FID no-ops its own
    /// removal — the file lingers rather than data being lost, and the next read
    /// of it confirms-and-caches it present, after which delete works normally.
    pub fn delete(&mut self, fid: u16) -> Result<()> {
        let meta = self.meta_delete(fid);
        if self.present_bit(fid) {
            self.storage.remove(fid)?;
            self.mark_absent(fid);
            self.write_gen = self.write_gen.wrapping_add(1);
        }
        self.dynamic.retain(|&f| f != fid);
        meta
    }

    /// Delete `fid`, removing it from the backend UNCONDITIONALLY (unlike
    /// [`delete`](Self::delete), which skips the backend when the present-cache reads
    /// absent). A torn-migration false-absent key — live in the backend, present bit
    /// clear — is still removed; otherwise `authenticatorReset`'s re-enumerating wipe
    /// (it reads the backend directly) keeps re-finding it and loops forever.
    ///
    /// **The metadata half is [`delete`](Self::delete)'s, not a variant of it, and it
    /// is what separates the three outcomes a caller can get.** `Ok(())` is "value
    /// gone and record gone"; `Err` from the drop is "value gone, a record may still
    /// stand over it" — the removal is unconditional, so no secret outlives its erase
    /// either way; `Err` from the backend `remove` is "the medium refused" and the
    /// value may be live. This folds the two into one answer, which is what a caller
    /// deleting one named record wants. **A sweep must not use it**: the two failures
    /// pull it in opposite directions, so it takes
    /// [`force_delete_halves`](Self::force_delete_halves) instead.
    ///
    /// Refines `RSKeyStore!NoOrphanedMetadata` — SEC-STORE-001, where the drop
    /// landed, and Refines `RSKeyStore!NoSilentOrphan` — SEC-STORE-006, where not.
    pub fn force_delete(&mut self, fid: u16) -> Result<()> {
        let gone = self.force_delete_halves(fid);
        gone.value?;
        gone.record
    }

    /// [`force_delete`](Self::force_delete) with its two answers handed back apart,
    /// for the four applet reset sweeps — the callers that cannot fold them.
    ///
    /// A sweep must **stop** on a refused backend removal, or `for_each_key` re-yields
    /// the fid it could not remove until the delete budget runs out; and it must
    /// **not** stop on a faulted metadata drop, because EF_META is one blob shared by
    /// every applet, so one unreadable head would abort `authenticatorReset` after a
    /// single file — at the same fid on every retry, so no retry makes progress, and
    /// the wrapped device seed would outlive the credentials derived from it. Folding
    /// them left that distinction unrepresentable, which is how it was measured at
    /// 0x0987. What the sweep owes instead is both halves: erase the whole range, and
    /// still answer for the record it could not PROVE dropped.
    ///
    /// Refines `RSKeyStore!NoOrphanedMetadata` — SEC-STORE-001, where the drop
    /// landed, and Refines `RSKeyStore!NoSilentOrphan` — SEC-STORE-006, where not.
    pub fn force_delete_halves(&mut self, fid: u16) -> Removal {
        let record = self.meta_delete(fid);
        if let Err(refused) = self.storage.remove(fid) {
            // Not marked absent: a refused removal may have left the value live, and
            // caching that as absence is the false-absent the present cache exists to
            // keep out.
            return Removal {
                value: Err(refused),
                record,
            };
        }
        self.mark_absent(fid);
        self.dynamic.retain(|&f| f != fid);
        self.write_gen = self.write_gen.wrapping_add(1);
        Removal {
            value: Ok(()),
            record,
        }
    }

    // ---- typed key-slot API ----
    // Secret key material reaches flash only through these. They delegate to the
    // plaintext primitives, but because a [`KeyFid`] is not a `u16` and
    // [`put_key`](Self::put_key) demands a [`Sealed`] payload, a key slot can be
    // neither written nor read by the generic `put`/`read` — the seal API is the
    // only route in. See [`crate::sealed`].

    /// Store sealed key material at `fid`.
    pub fn put_key(&mut self, fid: KeyFid, sealed: Sealed) -> Result<()> {
        self.put(fid.get(), sealed.as_bytes())
    }

    /// Copy a sealed key blob into `buf`; returns its full length, or `None` if
    /// the slot is absent (or unreadable — see [`try_read`](Self::try_read)).
    pub fn read_key(&mut self, fid: KeyFid, buf: &mut [u8]) -> Option<usize> {
        self.read(fid.get(), buf)
    }

    /// [`read_key`](Self::read_key), fallible — see [`try_read`](Self::try_read).
    pub fn try_read_key(&mut self, fid: KeyFid, buf: &mut [u8]) -> Result<Option<usize>> {
        self.try_read(fid.get(), buf)
    }

    /// Whether the key slot holds non-empty data.
    pub fn has_key(&mut self, fid: KeyFid) -> bool {
        self.has_data(fid.get())
    }

    /// [`has_key`](Self::has_key), fallible — see [`try_read`](Self::try_read).
    pub fn try_has_key(&mut self, fid: KeyFid) -> Result<bool> {
        self.try_has_data(fid.get())
    }

    /// Delete a key slot.
    pub fn delete_key(&mut self, fid: KeyFid) -> Result<()> {
        self.delete(fid.get())
    }

    // ---- meta side-store ----
    // Format: a sequence of records `[fid: u16 BE][len: u16 BE][data; len]`.
    // `read` reports the value's full length, which can exceed our scratch buffer
    // (corrupt/oversized EF_META), so clamp before slicing.

    /// Copy the metadata for `fid` into `out`; returns its full length. An EF_META
    /// read that FAILED reads as "no record" here — see
    /// [`try_meta_find`](Self::try_meta_find).
    pub fn meta_find(&mut self, fid: u16, out: &mut [u8]) -> Option<usize> {
        self.try_meta_find(fid, out).ok().flatten()
    }

    /// [`meta_find`](Self::meta_find), fallible — see [`try_read`](Self::try_read).
    /// EF_META carries the PIV slots' algorithm and touch policy, and a missing
    /// record there resolves to the published default, so the collapse costs a
    /// touch gate.
    pub fn try_meta_find(&mut self, fid: u16, out: &mut [u8]) -> Result<Option<usize>> {
        if self.known_absent(EF_META) {
            return Ok(None);
        }
        let mut scratch = [0u8; META_MAX];
        let read = self.storage.read(EF_META, &mut scratch);
        let Some(n) = self.settle(EF_META, read)? else {
            return Ok(None);
        };
        let n = n.min(scratch.len());
        let blob = &scratch[..n];
        let mut i = 0;
        while i + META_REC_HDR <= blob.len() {
            let rec_fid = u16::from_be_bytes([blob[i], blob[i + 1]]);
            let len = u16::from_be_bytes([blob[i + 2], blob[i + 3]]) as usize;
            let start = i + META_REC_HDR;
            let end = start + len;
            if end > blob.len() {
                break;
            }
            if rec_fid == fid {
                let m = len.min(out.len());
                out[..m].copy_from_slice(&blob[start..start + m]);
                return Ok(Some(len));
            }
            i = end;
        }
        Ok(None)
    }

    /// Insert or replace the metadata for `fid`.
    pub fn meta_add(&mut self, fid: u16, data: &[u8]) -> Result<()> {
        self.meta_add_reserve(fid, data, 0)
    }

    /// Insert or replace the metadata for `fid`, keeping at least `reserve` bytes
    /// of the meta store free — the write fails with [`Error::NoMemory`] if it
    /// would not. Lets a caller reserve guaranteed headroom for other, essential
    /// records: PIV writes an optional cached public point this way, reserving
    /// space for every slot's 4-byte head so the cache can never crowd a head out
    /// (which would fail provisioning). `reserve == 0` is the plain add.
    ///
    /// Refines `RSKeyStore!NoRecordLostToMetaWrite` — SEC-STORE-003.
    pub fn meta_add_reserve(&mut self, fid: u16, data: &[u8], reserve: usize) -> Result<()> {
        let mut scratch = [0u8; META_MAX];
        // Read the existing blob unless EF_META is *confirmed* absent. Treating
        // an UNKNOWN EF_META as empty is the power-cut bug: a torn-migration
        // false-absent would drop every existing record on this rewrite. The
        // reliable backend read recovers the real blob.
        let n = if self.known_absent(EF_META) {
            0
        } else {
            let r = self.storage.read(EF_META, &mut scratch);
            // A FAILED read must not read as "no blob": rebuilding from an empty
            // scratch would drop every other applet's metadata on this write. Same
            // rule as the present-cache — only a definitive answer may be acted on.
            if r.is_none() && self.storage.last_error() {
                return Err(Error::MemoryFatal);
            }
            r.unwrap_or(0).min(scratch.len())
        };
        let mut out = [0u8; META_MAX];
        // Cap the rebuild at META_MAX - reserve so the write leaves `reserve`
        // bytes free (rebuild_meta bounds its output by the slice length).
        let limit = META_MAX.saturating_sub(reserve);
        let w = rebuild_meta(&scratch[..n], fid, Some(data), &mut out[..limit])?;
        self.storage.write(EF_META, &out[..w])?;
        self.mark_present(EF_META);
        Ok(())
    }

    /// Remove the metadata for `fid` (clears EF_META once empty).
    ///
    /// The `known_absent(EF_META)` bit is only ever set from a definitive answer
    /// — a faulted read is `MemoryFatal` below, never absence — which is what
    /// keeps the cache honest while records stand.
    ///
    /// Refines `RSKeyStore!NoFalseMetaAbsent` — SEC-STORE-004.
    /// Refines `RSKeyStore!CacheHonest` — SEC-STORE-005.
    pub fn meta_delete(&mut self, fid: u16) -> Result<()> {
        if self.known_absent(EF_META) {
            return Ok(()); // confirmed no meta blob → nothing to drop
        }
        let mut scratch = [0u8; META_MAX];
        let n = match self.storage.read(EF_META, &mut scratch) {
            Some(n) => n.min(scratch.len()),
            // Absent means there is nothing to drop; a FAILED read means we do not
            // know, and caching that as absence would orphan every stored head.
            None if self.storage.last_error() => return Err(Error::MemoryFatal),
            None => {
                self.mark_absent(EF_META);
                return Ok(());
            }
        };
        self.mark_present(EF_META);
        let mut out = [0u8; META_MAX];
        let w = rebuild_meta(&scratch[..n], fid, None, &mut out)?;
        if w == n {
            // `fid` had no record (removing one always shrinks the blob), so the
            // rebuild is byte-identical — skip the redundant EF_META rewrite.
            // Keeps a delete sweep over meta-less absent slots write-free.
            Ok(())
        } else if w == 0 {
            self.storage.remove(EF_META)?;
            self.mark_absent(EF_META);
            Ok(())
        } else {
            self.storage.write(EF_META, &out[..w]) // EF_META stays present
        }
    }
}

/// Copy all meta records except `fid` into `out`, then optionally append a new
/// `fid` record. Returns bytes written.
fn rebuild_meta(blob: &[u8], fid: u16, new: Option<&[u8]>, out: &mut [u8]) -> Result<usize> {
    let mut w = 0usize;
    let mut i = 0usize;
    while i + META_REC_HDR <= blob.len() {
        let rec_fid = u16::from_be_bytes([blob[i], blob[i + 1]]);
        let len = u16::from_be_bytes([blob[i + 2], blob[i + 3]]) as usize;
        let start = i + META_REC_HDR;
        let end = start + len;
        if end > blob.len() {
            break;
        }
        if rec_fid != fid {
            let rec = &blob[i..end];
            if w + rec.len() > out.len() {
                return Err(Error::NoMemory);
            }
            out[w..w + rec.len()].copy_from_slice(rec);
            w += rec.len();
        }
        i = end;
    }
    if let Some(data) = new {
        if w + META_REC_HDR + data.len() > out.len() {
            return Err(Error::NoMemory);
        }
        out[w..w + 2].copy_from_slice(&fid.to_be_bytes());
        out[w + 2..w + META_REC_HDR].copy_from_slice(&(data.len() as u16).to_be_bytes());
        out[w + META_REC_HDR..w + META_REC_HDR + data.len()].copy_from_slice(data);
        w += META_REC_HDR + data.len();
    }
    Ok(w)
}

/// Kani proof harnesses (`cargo kani -p rsk-fs`).
#[cfg(any(kani, test))]
#[path = "store_assurance.rs"]
pub mod store_assurance;

#[cfg(kani)]
#[path = "fs_kani.rs"]
mod proofs;

#[cfg(kani)]
#[path = "store_refinement_kani.rs"]
mod store_refinement_proofs;

#[cfg(kani)]
#[path = "store_meta_kani.rs"]
mod store_meta_proofs;

#[cfg(test)]
#[path = "fs_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "store_steps_tests.rs"]
mod store_steps;

#[cfg(test)]
#[path = "store_domain_tests.rs"]
mod store_domain;
