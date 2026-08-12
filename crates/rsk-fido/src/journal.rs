// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Tamper-evident audit journal: a fixed flash ring of 20-byte entries
//! hash-chained from a sealed "epoch" accumulator, exported and attested over
//! `authenticatorVendor` (AUDIT_READ / AUDIT_CHECKPOINT).
//!
//! Layout. `EF_AUDIT_META` = `ver(1) ‖ seq_next(4 LE) ‖ start(4 LE) ‖ epoch(32)`;
//! entry `seq` lives in slot `EF_AUDIT_RING + (seq % AUDIT_RING_SLOTS)` and the
//! live window is `[start, seq_next)`. When the ring is full the oldest entry
//! is folded into the epoch — `epoch' = SHA-256(epoch ‖ entry)` — and that meta
//! is committed *before* the slot is reused, so a power cut anywhere loses at
//! most the newest event and never produces a false tamper verdict.
//!
//! Entries are append-only with one bounded exception: a run of the events an
//! ungated host can drive on demand — a device-config write, a silent (`up:false`)
//! assertion, a don't-enforce U2F authenticate — is counted inside an entry the
//! window already holds instead of appending ([`append_config_write`],
//! [`append_run`]).
//!
//! The chain head is `fold(epoch, window entries)`. A checkpoint signs
//! `"RSK-AUDIT-CKPT-v1" ‖ head ‖ seq_next ‖ challenge` with an ECDSA P-256 key
//! derived (HKDF) from the OTP DEVK — the reset-stable device attestation
//! root — so history evicted from the ring (or scrubbed by a reset, which
//! folds the whole window for privacy) stays attested in aggregate.
//!
//! There is no wall clock: entries carry the boot-relative uptime, and the
//! first entry of every power cycle is an [`EV_BOOT`], so ordering is total
//! (`seq`) and boot boundaries are explicit. Appends never fail their caller —
//! an authentication must not break because the log could not be written.

use minicbor::Encoder;
use minicbor::encode::write::Cursor;
use zeroize::Zeroize;

use rsk_crypto::mac::hkdf_sha256;
use rsk_crypto::{Device, sha256};
use rsk_fs::{Fs, Storage};

use crate::consts::{AUDIT_RING_SLOTS, EF_AUDIT_ENABLED, EF_AUDIT_META, EF_AUDIT_RING};
use crate::ec::{MAX_DER_SIG, P256Key};
use crate::error::{CtapError, CtapResult};
use crate::{Ctx, Rng};

// ---- events ----
pub const EV_BOOT: u8 = 0x01;
pub const EV_MAKE_CRED: u8 = 0x02;
pub const EV_GET_ASSERT: u8 = 0x03;
pub const EV_RESET: u8 = 0x04;
pub const EV_PIN_SET: u8 = 0x05;
pub const EV_PIN_CHANGE: u8 = 0x06;
/// aux: 0 = retry counter exhausted, 1 = per-boot mismatch block.
pub const EV_PIN_LOCKOUT: u8 = 0x07;
/// aux = new minimum; `detail[0]` = forceChangePin flag.
pub const EV_CFG_MIN_PIN: u8 = 0x08;
pub const EV_CFG_EA: u8 = 0x09;
pub const EV_LOCK_ENGAGE: u8 = 0x0A;
pub const EV_LOCK_RELEASE: u8 = 0x0B;
pub const EV_BACKUP_EXPORT: u8 = 0x0C;
pub const EV_BACKUP_LOAD: u8 = 0x0D;
pub const EV_BACKUP_FINALIZE: u8 = 0x0E;
pub const EV_U2F_REGISTER: u8 = 0x0F;
pub const EV_U2F_AUTH: u8 = 0x10;
pub const EV_CHECKPOINT: u8 = 0x11;
pub const EV_ATT_IMPORT: u8 = 0x12;
pub const EV_ATT_CLEAR: u8 = 0x13;
pub const EV_CFG_ALWAYS_UV: u8 = 0x14;
/// Device-config write over the FIDO vendor channel. `aux` = the target that opened
/// the entry; the detail counts the writes coalesced into it ([`append_config_write`]).
pub const EV_CONFIG_WRITE: u8 = 0x15;
/// aux: 1 = journalling turned on, 0 = turned off (the off entry is the last one
/// written, recorded before the flag flips, so the trail shows when it stopped).
pub const EV_AUDIT_CFG: u8 = 0x16;

/// Entry: `seq(4 LE) ‖ uptime_ms(4 LE) ‖ event(1) ‖ aux(1) ‖ detail(8) ‖ repeats(2 LE)`.
pub const ENTRY_LEN: usize = 20;
const DETAIL_AT: usize = 10;
const DETAIL_LEN: usize = 8;
/// [`EV_CONFIG_WRITE`] detail: `repeats(2 LE) ‖ targets(1)` — how many further
/// config writes were folded into the entry, and a `1 << target` mask of every
/// record the run touched.
const CW_REPEATS_AT: usize = DETAIL_AT;
const CW_TARGETS_AT: usize = DETAIL_AT + 2;
/// [`append_run`]'s repeat count, in the trailing two bytes every event leaves free.
/// [`EV_CONFIG_WRITE`] keeps its own count inside the detail instead: that layout
/// predates this one and is already on the wire (`AUDIT_READ`, `rsk audit log`).
const RUN_REPEATS_AT: usize = ENTRY_LEN - 2;
const META_LEN: usize = 1 + 4 + 4 + 32;
const META_VER: u8 = 1;
const GENESIS_TAG: &[u8] = b"RSK-AUDIT-GENESIS-v1";
const CKPT_TAG: &[u8] = b"RSK-AUDIT-CKPT-v1";

/// The persistent ring state (`EF_AUDIT_META`).
pub struct Meta {
    pub seq_next: u32,
    pub start: u32,
    pub epoch: [u8; 32],
}

/// `SHA-256(tag ‖ serial_hash)` — the chain anchor of an empty journal, bound
/// to the device so two devices' empty journals do not share a head.
fn genesis(dev: &Device) -> [u8; 32] {
    let mut buf = [0u8; 52];
    buf[..GENESIS_TAG.len()].copy_from_slice(GENESIS_TAG);
    buf[GENESIS_TAG.len()..].copy_from_slice(dev.serial_hash);
    sha256(&buf)
}

/// One chain step: `SHA-256(h ‖ entry)`.
fn chain(h: &[u8; 32], entry: &[u8; ENTRY_LEN]) -> [u8; 32] {
    let mut buf = [0u8; 32 + ENTRY_LEN];
    buf[..32].copy_from_slice(h);
    buf[32..].copy_from_slice(entry);
    sha256(&buf)
}

fn load_meta<S: Storage>(dev: &Device, fs: &mut Fs<S>) -> Meta {
    let mut buf = [0u8; META_LEN];
    if let Some(META_LEN) = fs.read(EF_AUDIT_META, &mut buf)
        && buf[0] == META_VER
    {
        let seq_next = u32::from_le_bytes(buf[1..5].try_into().unwrap());
        let start = u32::from_le_bytes(buf[5..9].try_into().unwrap());
        // raw_append keeps the live window [start, seq_next) at most
        // AUDIT_RING_SLOTS wide; a persisted meta claiming a wider span is
        // corrupt (only reachable by raw flash write). Fail closed to genesis
        // rather than let the vendor_read / fold walk overrun its fixed
        // AUDIT_RING_SLOTS-entry buffer.
        if seq_next.wrapping_sub(start) <= AUDIT_RING_SLOTS {
            return Meta {
                seq_next,
                start,
                epoch: buf[9..].try_into().unwrap(),
            };
        }
    }
    Meta {
        seq_next: 0,
        start: 0,
        epoch: genesis(dev),
    }
}

fn put_meta<S: Storage>(fs: &mut Fs<S>, m: &Meta) -> Result<(), ()> {
    let mut buf = [0u8; META_LEN];
    buf[0] = META_VER;
    buf[1..5].copy_from_slice(&m.seq_next.to_le_bytes());
    buf[5..9].copy_from_slice(&m.start.to_le_bytes());
    buf[9..].copy_from_slice(&m.epoch);
    fs.put(EF_AUDIT_META, &buf).map_err(|_| ())
}

fn slot_fid(seq: u32) -> u16 {
    EF_AUDIT_RING + (seq % AUDIT_RING_SLOTS) as u16
}

fn read_slot<S: Storage>(fs: &mut Fs<S>, seq: u32, out: &mut [u8; ENTRY_LEN]) -> Option<()> {
    match fs.read(slot_fid(seq), out) {
        Some(ENTRY_LEN) => Some(()),
        _ => None,
    }
}

fn build_entry(seq: u32, now_ms: u64, ev: u8, aux: u8, detail: &[u8]) -> [u8; ENTRY_LEN] {
    let mut e = [0u8; ENTRY_LEN];
    e[..4].copy_from_slice(&seq.to_le_bytes());
    e[4..8].copy_from_slice(&(now_ms.min(u32::MAX as u64) as u32).to_le_bytes());
    e[8] = ev;
    e[9] = aux;
    let n = detail.len().min(DETAIL_LEN);
    e[DETAIL_AT..DETAIL_AT + n].copy_from_slice(&detail[..n]);
    e
}

/// Whether the audit journal is turned on. Opt-in: OFF unless the host enabled it
/// (`EF_AUDIT_ENABLED` present), so a default device writes no journal entries. The
/// probe is O(1) — a decided-absent bitmap hit when off, a cached read when on.
pub(crate) fn is_enabled<S: Storage>(fs: &mut Fs<S>) -> bool {
    fs.has_data(EF_AUDIT_ENABLED)
}

/// Turn journalling on (write the flag) or off (delete it). Best-effort; the
/// caller records the transition in the journal itself (see [`vendor`]).
pub(crate) fn set_enabled<S: Storage>(fs: &mut Fs<S>, on: bool) -> Result<(), ()> {
    if on {
        fs.put(EF_AUDIT_ENABLED, &[1]).map_err(|_| ())
    } else {
        fs.delete(EF_AUDIT_ENABLED).map_err(|_| ())
    }
}

/// Append one event, opening the power cycle with an [`EV_BOOT`] entry first.
/// Errors are swallowed — the journal never fails the operation it records.
/// A no-op while journalling is off (opt-in, `is_enabled`): no flash is written.
pub fn append<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, ev: u8, aux: u8, detail: &[u8]) {
    if !is_enabled(ctx.fs) {
        return;
    }
    if !ctx.state.audit_boot_logged {
        ctx.state.audit_boot_logged = true;
        let _ = raw_append(&ctx.dev, ctx.fs, ctx.now_ms, EV_BOOT, 0, &[]);
    }
    let _ = raw_append(&ctx.dev, ctx.fs, ctx.now_ms, ev, aux, detail);
}

/// Append a device-config write, coalescing a *run* of them into one ring entry.
///
/// [`EV_CONFIG_WRITE`] is one of the journalled events a silent host can drive on
/// demand — the write is ungated on the default build — so 128 of them would evict
/// every other event from the 128-slot ring. A run therefore costs a single slot:
/// the entry keeps its `seq`, opening target and timestamp, and counts the rest in
/// its detail. `seq_next`, `start` and the epoch never move, so a coalesce evicts
/// nothing and the host-side fold over the exported window still reproduces the
/// head. Its own event class only: [`append_run`] carries the other two, and every
/// remaining event is behind a PIN or a gesture, which is distinct evidence worth
/// its own slot.
pub fn append_config_write<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, target: u8) {
    if !is_enabled(ctx.fs) {
        return; // off: write no flash at all, not even a bump of a stale entry
    }
    // Never coalesce across a power cycle — that would swallow this cycle's EV_BOOT.
    if ctx.state.audit_boot_logged && coalesce_config_write(ctx, target) {
        return;
    }
    append(ctx, EV_CONFIG_WRITE, target, &[0, 0, target_bit(target)]);
}

/// The `targets` mask bit of a config-write target. The `CONFIG_TARGET_*` ids are
/// 0..2; anything else is unreachable (`config_write` rejects unknown targets) and
/// collapses onto the top bit rather than shifting out of range.
fn target_bit(target: u8) -> u8 {
    1u8.checked_shl(target as u32).unwrap_or(0x80)
}

/// Fold one more config write into the newest ring entry when that entry is itself
/// an [`EV_CONFIG_WRITE`]: bump its saturating repeat count and OR in the target
/// bit. `false` when there is no such entry — or its slot could not be rewritten —
/// leaving the caller to append a fresh one.
fn coalesce_config_write<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, target: u8) -> bool {
    let m = load_meta(&ctx.dev, ctx.fs);
    if m.seq_next == m.start {
        return false;
    }
    let seq = m.seq_next.wrapping_sub(1);
    let mut e = [0u8; ENTRY_LEN];
    if read_slot(ctx.fs, seq, &mut e).is_none() || e[8] != EV_CONFIG_WRITE {
        return false;
    }
    bump_repeats(&mut e, CW_REPEATS_AT);
    e[CW_TARGETS_AT] |= target_bit(target);
    ctx.fs.put(slot_fid(seq), &e).is_ok()
}

/// Append an event a silent host can drive on demand, coalescing repeats into a ring
/// entry the window already holds — the same bounded exception [`append_config_write`]
/// makes for its own event, and the same guarantees: `seq_next`, `start` and the epoch
/// never move, so nothing is evicted and the exported window still folds to the head.
///
/// It scans the whole window rather than only the newest entry, because a fold that
/// looks at the newest alone is broken by interleaving two events that both take this
/// path — 128 alternating appends still flush the ring (audit run-37). The surviving
/// entry keeps its `seq`, timestamp and the detail of the *first* occurrence, so a run
/// over several relying parties is one entry naming one of them.
pub fn append_run<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, ev: u8, aux: u8, detail: &[u8]) {
    if !is_enabled(ctx.fs) {
        return; // off: write no flash at all, not even a bump of a stale entry
    }
    // Never coalesce across a power cycle — that would swallow this cycle's EV_BOOT.
    if ctx.state.audit_boot_logged && coalesce_run(ctx, ev) {
        return;
    }
    append(ctx, ev, aux, detail);
}

/// Fold one more occurrence of `ev` into the newest live-window entry carrying it.
/// `false` when the window holds none — or its slot could not be rewritten — leaving
/// the caller to append a fresh one.
fn coalesce_run<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, ev: u8) -> bool {
    let m = load_meta(&ctx.dev, ctx.fs);
    let mut e = [0u8; ENTRY_LEN];
    let mut seq = m.seq_next;
    while seq != m.start {
        seq = seq.wrapping_sub(1);
        if read_slot(ctx.fs, seq, &mut e).is_some() && e[8] == ev {
            bump_repeats(&mut e, RUN_REPEATS_AT);
            return ctx.fs.put(slot_fid(seq), &e).is_ok();
        }
    }
    false
}

/// Bump a saturating little-endian `u16` repeat counter at `at` inside an entry.
fn bump_repeats(e: &mut [u8; ENTRY_LEN], at: usize) {
    let n = u16::from_le_bytes([e[at], e[at + 1]]).saturating_add(1);
    e[at..at + 2].copy_from_slice(&n.to_le_bytes());
}

fn raw_append<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    now_ms: u64,
    ev: u8,
    aux: u8,
    detail: &[u8],
) -> Result<(), ()> {
    let mut m = load_meta(dev, fs);
    if m.seq_next.wrapping_sub(m.start) >= AUDIT_RING_SLOTS {
        // Full: fold the oldest entry into the epoch and commit that *before*
        // its slot is reused — see the module docs for the power-cut argument.
        let mut e = [0u8; ENTRY_LEN];
        if read_slot(fs, m.start, &mut e).is_some() {
            m.epoch = chain(&m.epoch, &e);
        }
        m.start = m.start.wrapping_add(1);
        put_meta(fs, &m)?;
    }
    let entry = build_entry(m.seq_next, now_ms, ev, aux, detail);
    fs.put(slot_fid(m.seq_next), &entry).map_err(|_| ())?;
    m.seq_next = m.seq_next.wrapping_add(1);
    put_meta(fs, &m)
}

/// Append one event from a caller that is not a CTAP dispatch — the trusted
/// panel, which holds the device identity and the flash but no [`Ctx`].
///
/// The panel's own actions were absent from the log the panel itself renders as
/// its evidence surface: no `journal::append` existed anywhere under
/// `firmware/src/display`, so an on-screen seed reveal or PIN change left no
/// trace while their USB equivalents were logged (audit run-34 #17). Same opt-in
/// gate and same best-effort contract as [`append`]. It cannot open the cycle
/// with [`EV_BOOT`] — that latch lives on `FidoState`, which the panel does not
/// have — so a power cycle whose first event is local starts at that event.
pub fn append_local<S: Storage>(dev: &Device, fs: &mut Fs<S>, now_ms: u64, ev: u8, aux: u8) {
    if !is_enabled(fs) {
        return;
    }
    let _ = raw_append(dev, fs, now_ms, ev, aux, &[]);
}

/// Fold the whole window into the epoch and delete the entry slots: aggregate
/// history stays attested, per-event details are scrubbed. Run by
/// `authenticatorReset` so a handed-over device keeps chain continuity without
/// leaking where it has been.
pub fn fold_and_scrub<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>) {
    let mut m = load_meta(&ctx.dev, ctx.fs);
    let mut e = [0u8; ENTRY_LEN];
    while m.start != m.seq_next {
        if read_slot(ctx.fs, m.start, &mut e).is_some() {
            m.epoch = chain(&m.epoch, &e);
        }
        m.start = m.start.wrapping_add(1);
    }
    if put_meta(ctx.fs, &m).is_err() {
        return; // keep the slots — a half-scrub must not orphan the chain
    }
    for i in 0..AUDIT_RING_SLOTS {
        let _ = ctx.fs.delete(EF_AUDIT_RING + i as u16);
    }
}

/// The current chain head: the epoch folded through the live window.
pub fn chain_head<S: Storage>(dev: &Device, fs: &mut Fs<S>) -> ([u8; 32], Meta) {
    let m = load_meta(dev, fs);
    let mut h = m.epoch;
    let mut e = [0u8; ENTRY_LEN];
    let mut seq = m.start;
    while seq != m.seq_next {
        if read_slot(fs, seq, &mut e).is_some() {
            h = chain(&h, &e);
        }
        seq = seq.wrapping_add(1);
    }
    (h, m)
}

/// A decoded journal entry for the read-only on-device audit log. The host export
/// path ([`vendor_read`]) carries the raw bytes + attestation for real verification;
/// this is the lean in-device view (no CBOR, no signature) the trusted display walks.
pub struct EventView {
    /// Monotonic boot-relative timestamp (ms) — only comparable within a power cycle.
    pub uptime_ms: u32,
    /// The event code (one of the `EV_*` constants).
    pub event: u8,
}

/// Visit the live journal window **newest first**, calling `f` for each decoded entry
/// until it returns `false` (the display keeps only the few most recent) or the window
/// is exhausted. Returns the total number of live entries, so a caller that keeps a
/// subset can still show a true count — mirrors [`crate::passkeys::for_each_rp`].
pub fn for_each_event<S: Storage, F: FnMut(&EventView) -> bool>(
    dev: &Device,
    fs: &mut Fs<S>,
    mut f: F,
) -> u32 {
    let m = load_meta(dev, fs);
    let total = m.seq_next.wrapping_sub(m.start);
    let mut seq = m.seq_next;
    let mut e = [0u8; ENTRY_LEN];
    while seq != m.start {
        seq = seq.wrapping_sub(1);
        if read_slot(fs, seq, &mut e).is_some() {
            let view = EventView {
                uptime_ms: u32::from_le_bytes(e[4..8].try_into().unwrap()),
                event: e[8],
            };
            if !f(&view) {
                break;
            }
        }
    }
    total
}

/// The checkpoint signing key: HKDF(salt = serial_hash, ikm = DEVK) → P-256
/// scalar. Deterministic and reset-stable; the counter byte retries the
/// (cosmically unlikely) out-of-range scalar.
pub fn attestation_key(devk: &[u8; 32], serial_hash: &[u8]) -> Option<P256Key> {
    const INFO_TAG: &[u8] = b"RSK audit attestation v1";
    let mut info = [0u8; 25];
    info[..INFO_TAG.len()].copy_from_slice(INFO_TAG);
    let mut scalar = [0u8; 32];
    for i in 0u8..8 {
        info[INFO_TAG.len()] = i;
        if hkdf_sha256(serial_hash, devk, &info, &mut scalar).is_err() {
            return None;
        }
        if let Some(k) = P256Key::from_scalar(&scalar) {
            scalar.zeroize();
            return Some(k);
        }
    }
    scalar.zeroize();
    None
}

/// `AUDIT_READ` (vendor 0x07): export the journal —
/// `{1: start, 2: seq_next, 3: epoch, 4: entries}`. The host recomputes
/// `fold(epoch, entries)` and matches it against a checkpoint head.
pub fn vendor_read<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, out: &mut [u8]) -> CtapResult {
    let m = load_meta(&ctx.dev, ctx.fs);
    let mut entries = [0u8; AUDIT_RING_SLOTS as usize * ENTRY_LEN];
    let mut len = 0usize;
    let mut e = [0u8; ENTRY_LEN];
    let mut seq = m.start;
    while seq != m.seq_next {
        if read_slot(ctx.fs, seq, &mut e).is_some() {
            entries[len..len + ENTRY_LEN].copy_from_slice(&e);
            len += ENTRY_LEN;
        }
        seq = seq.wrapping_add(1);
    }
    encode(out, |enc| {
        enc.map(4)?
            .u8(1)?
            .u32(m.start)?
            .u8(2)?
            .u32(m.seq_next)?
            .u8(3)?
            .bytes(&m.epoch)?
            .u8(4)?
            .bytes(&entries[..len])?;
        Ok(())
    })
}

/// `AUDIT_CHECKPOINT` (vendor 0x08): sign the chain head with the DEVK-derived
/// attestation key — `{1: head, 2: seq_next, 3: sig(DER), 4: pubkey(0x04‖x‖y)}`.
/// `challenge` (≤ 32 bytes, host-chosen) gives the verdict freshness. Refused
/// without a provisioned DEVK: a meaningful attestation needs the OTP root.
pub fn vendor_checkpoint<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    challenge: &[u8],
    out: &mut [u8],
) -> CtapResult {
    if challenge.len() > 32 {
        return Err(CtapError::InvalidParameter);
    }
    // Fetched here rather than held: the DEVK is unrotatable, and this is the one
    // command that wants it. Zeroize before the `?` so a failed derivation still
    // wipes the copy.
    let mut devk =
        ctx.state.devk_source.ok_or(CtapError::NotAllowed)?().ok_or(CtapError::NotAllowed)?;
    let key = attestation_key(&devk, ctx.dev.serial_hash);
    devk.zeroize();
    let key = key.ok_or(CtapError::Other)?;
    let (head, m) = chain_head(&ctx.dev, ctx.fs);

    let mut msg = [0u8; CKPT_TAG.len() + 32 + 4 + 32];
    let mut p = 0;
    msg[p..p + CKPT_TAG.len()].copy_from_slice(CKPT_TAG);
    p += CKPT_TAG.len();
    msg[p..p + 32].copy_from_slice(&head);
    p += 32;
    msg[p..p + 4].copy_from_slice(&m.seq_next.to_le_bytes());
    p += 4;
    msg[p..p + challenge.len()].copy_from_slice(challenge);
    p += challenge.len();

    let mut sig = [0u8; MAX_DER_SIG];
    let sl = key.sign_der(&msg[..p], &mut sig);
    let (px, py) = key.public_xy();
    let mut pubkey = [0u8; 65];
    pubkey[0] = 0x04;
    pubkey[1..33].copy_from_slice(&px);
    pubkey[33..].copy_from_slice(&py);

    let r = encode(out, |enc| {
        enc.map(4)?
            .u8(1)?
            .bytes(&head)?
            .u8(2)?
            .u32(m.seq_next)?
            .u8(3)?
            .bytes(&sig[..sl])?
            .u8(4)?
            .bytes(&pubkey)?;
        Ok(())
    });
    if r.is_ok() {
        append(ctx, EV_CHECKPOINT, 0, &[]);
    }
    r
}

fn encode<F>(out: &mut [u8], f: F) -> CtapResult
where
    F: FnOnce(
        &mut Encoder<Cursor<&mut [u8]>>,
    ) -> Result<(), minicbor::encode::Error<minicbor::encode::write::EndOfSlice>>,
{
    let mut enc = Encoder::new(Cursor::new(out));
    f(&mut enc).map_err(|_| CtapError::Other)?;
    Ok(enc.writer().position())
}

#[cfg(test)]
#[path = "journal_tests.rs"]
mod tests;
