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

pub use fs::Fs;
pub use sealed::{KeyFid, Sealed};
pub use storage::Storage;

/// The metadata side-store EF.
/// Set (`[1]`) once the post-OTP-provisioning at-rest hardening pass has run: the seal
/// migrations re-key secrets from the chip-serial root to the OTP root, and this
/// log-structured store keeps the superseded chip-serial copies until compaction, so a
/// one-shot [`Fs::compact`] scrubs them. The marker gates that lap to the first OTP boot
/// and makes it crash-safe (absent ⇒ re-run; the lap is idempotent).
///
/// Lives here, not in an applet, because **any** applet that lazily re-keys a pre-OTP
/// record after the lap has already run must clear it ([`request_rescrub`]) — otherwise
/// its superseded chip-serial-rooted copy stays readable in a flash dump forever.
pub const EF_HARDENED: u16 = 0xCE14;

/// Re-arm the one-shot at-rest scrub: clear [`EF_HARDENED`] so the next boot runs the
/// compaction lap again. Call from any lazy migration that re-keys a record off the
/// pre-OTP (chip-serial) root *after* the lap has already run — the migration is an
/// append, so the pre-OTP copy it supersedes stays readable in a flash dump until a lap
/// reclaims its page, and without this the lap never runs again. Deferring to the next
/// boot is deliberate: the lap is a multi-second stall that must not land inside a host
/// command, and it is idempotent, so an interrupted one simply re-runs.
/// Refines `RSKeyBootHardening!MarkerNeverLies` — SEC-BOOT-001.
pub fn request_rescrub<S: Storage>(fs: &mut Fs<S>) {
    let _ = fs.delete(EF_HARDENED);
}

pub const EF_META: u16 = 0xE010;

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
