// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![cfg_attr(not(any(test, feature = "test-util")), no_std)]

//! `rsk-fs` — key/value file API over a backend-agnostic `Storage`: file contents
//! are keyed by 16-bit FID. On device the backend is `sequential-storage` over
//! embassy-rp flash (provided by `firmware`); tests use a RAM backend. A dynamic
//! present-cache plus a metadata side-store sit on top; applets own their own FID
//! ranges and access control, so `Fs` is a plain typed KV store.

pub mod fs;
// The power-cut oracle. Its rules are `no_std` so `cargo kani` can prove them;
// the driver that runs them against a real `Fs` needs a heap and is behind
// `test-util`, which only `[dev-dependencies]` entries turn on.
#[cfg(any(test, feature = "test-util", kani))]
pub mod powercut;
pub mod sealed;
pub mod storage;

use rsk_sdk::error::{Error, Result};

pub use fs::{Fs, Removal};
pub use sealed::{KeyFid, Sealed};
pub use storage::Storage;

/// The metadata side-store EF.
/// Set (`[1]`) once the post-OTP-provisioning at-rest hardening pass has run: the seal
/// migrations re-key secrets from the chip-serial root to the OTP root, and this
/// log-structured store keeps the superseded chip-serial copies until compaction, so a
/// one-shot [`Fs::compact`] scrubs them. The marker gates that lap to the first OTP boot
/// and makes it crash-safe (absent ⇒ re-run; the lap is idempotent).
///
/// Lives here, not in an applet, because **any** applet that lazily re-keys *or deletes*
/// a pre-OTP record after the lap has already run must clear it ([`request_rescrub`]) —
/// a tombstone is an append too, so either way the chip-serial copy stays dumpable.
pub const EF_HARDENED: u16 = 0xCE14;

/// Re-arm the one-shot at-rest scrub: clear [`EF_HARDENED`] so the next boot runs the
/// compaction lap again. Call from any lazy migration that re-keys a pre-OTP record off
/// that root *after* the lap has already run, and from any that deletes one — a
/// tombstone appends like a re-seal, so both leave the pre-OTP copy readable in a flash
/// dump until a lap reclaims its page, and without this the lap never runs again.
/// Deferring to the next boot is deliberate: the lap is a multi-second stall that must
/// not land inside a host command, and it is idempotent, so an interrupted one re-runs.
///
/// **Call it BEFORE the write, and make that write conditional on `Ok`.** Order is
/// half the rule and covers exactly one fault: this is a second append, so a reset
/// between the two keeps whichever landed — re-arm first and a cut costs the re-key,
/// which leaves the record still in force and the next boot lapping over it; write
/// first and a cut costs the re-arm, and the marker stands over the superseded copy
/// for the life of the key, because [`run_at_rest_lap`] gates on it and nothing else.
/// Order does NOT cover a medium that refuses the re-arm and serves the write: that
/// reaches the same end state with no reset in it at all. So this answers rather than
/// swallowing, and `Ok` means what the caller needs — the lap WILL run.
/// Every caller shipped the second order until 0x09BD and the swallow until 0x09BE.
/// A refusal is ALSO latched in RAM for [`Fs::rescrub_refused`], because the wipe
/// paths take this best-effort and their refusal reaches nobody: the latch says the
/// medium refused a re-arm this power cycle, never that the marker lies.
/// Refines `RSKeyBootHardening!MarkerNeverLies` — SEC-BOOT-001.
pub fn request_rescrub<S: Storage>(fs: &mut Fs<S>) -> Result<()> {
    let _ = fs.delete(EF_HARDENED);
    // Not `delete`'s own answer: it reports the METADATA drop (EF_HARDENED, a one-byte
    // flag, keeps none) and answers `Ok` where the present bit is clear over a live
    // marker — what a read-fault-truncated `Fs::scan` leaves. Ask the lap's own gate.
    let answer = match fs.try_has_data(EF_HARDENED) {
        Ok(true) => Err(Error::MemoryFatal),
        Ok(false) => Ok(()),
        Err(e) => Err(e),
    };
    // Both arms, and before the caller can drop it: an unreadable probe is a re-arm
    // that cannot be shown to have landed, which is the same medium fault the wipe
    // sites discard.
    if answer.is_err() {
        fs.note_rescrub_refused();
    }
    answer
}

/// Run the one-shot at-rest scrub lap: iff [`EF_HARDENED`] is absent, drive a full
/// [`Fs::compact`] to push every superseded pre-OTP-sealed copy off the medium, and
/// set the marker only if that lap returned `Ok`. Marker AFTER scrub, so a torn or
/// failed lap leaves it absent and the next boot retries; the lap is idempotent, and a
/// failed marker write is the same fail-safe, so its error is deliberately dropped.
///
/// The caller owns the OTP gate: a pre-OTP board has no stronger root to re-key to and
/// nothing to scrub. It is a multi-second stall, so the caller runs it at boot, before
/// USB attach. The write ORDER is the property this refines, and `firmware/` has no
/// host tests, which is why the order lives here rather than in the boot glue.
///
/// Standing after the boot migrations does NOT exempt them from [`request_rescrub`]:
/// this latches once per device, so a boot that silently skipped a record leaves the
/// marker over the boot that finally supersedes it. They re-arm too, for that reason.
/// Refines `RSKeyBootHardening!MarkerNeverLies` — SEC-BOOT-001.
pub fn run_at_rest_lap<S: Storage>(fs: &mut Fs<S>) {
    if fs.has_data(EF_HARDENED) {
        return;
    }
    if fs.compact().is_ok() {
        let _ = fs.put(EF_HARDENED, &[1u8]);
    }
}

/// The metadata side-store EF: one blob, shared by every applet.
#[cfg(not(kani))]
pub const EF_META: u16 = 0xE010;
/// `0x0017` under `cfg(kani)`, because the metadata paths address EF_META in the
/// present map and [`fs::Fs`]'s map is 24 bits wide there — `0xE010` is index
/// 7170 of it, so every one of them panicked before this alias existed. Index 23
/// puts EF_META INSIDE the symbolic FID domain rather than outside it, which is a
/// different store topology and not the same one faster; `store_meta_kani.rs`
/// carries what that stops proving.
#[cfg(kani)]
pub const EF_META: u16 = 0x0017;

/// The scrub filler a [`Storage::compact`] lap writes to push superseded payloads
/// off the medium. It is a backend-internal key, not a file — but `compact` writes
/// it straight through the backend, never through [`Fs`], so `Fs::scan` would count
/// it as a dynamic file. At the [`MAX_DYNAMIC_FILES`] cap plus a filler left behind
/// by a failed or power-cut lap, that silently cost one live key its registration
/// and every later `put` to it returned `NoMemory` (audit run-36). Defined here so
/// the backend and `scan` share one definition of what to skip.
pub const EF_SCRUB_FILLER: u16 = 0xCEFE;

/// Largest value one FID may hold, and the value every [`Storage`] backend
/// declares as `MAX_VALUE`. The device backend serialises the 2-byte key and the
/// value through one scratch buffer sized to what a single flash page holds
/// (`rsk_store::KV_BUF`), so the real ceiling is 2 bytes under it. [`Fs::put`]
/// enforces it, so no applet has to know the number — a cap picked independently
/// is how ATT_IMPORT came to accept records the store could not hold (audit run-32).
pub const MAX_VALUE_BYTES: usize = 4078;

/// Max number of dynamic (runtime-created) files — the shared budget across ALL
/// applets (each FIDO cred, each PIV key + cert, each OATH cred, each OpenPGP DO, …).
/// Sized to the union of every applet's own logical cap so one applet can't starve
/// another (e.g. filling PIV must not shrink the passkey ceiling). The storage
/// backend's key-pointer cache (firmware `MAIN_CACHE_KEYS`) MUST stay `>=` this, or
/// files past the cache read/migrate off an O(flash) latency cliff.
pub const MAX_DYNAMIC_FILES: usize = 1280;

/// The command-level power-cut sweep the applet suites share. Dev-only, like
/// [`storage::faults`], whose media it drives.
#[cfg(any(test, feature = "test-util"))]
#[path = "cut.rs"]
pub mod cut;
