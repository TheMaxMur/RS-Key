// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Yubico management applet: reports device capabilities, serial and firmware
//! version — what `ykman` / Yubico Authenticator SELECT first to identify the key.
//! READ CONFIG (0x1D) returns the DeviceInfo TLV; WRITE CONFIG (0x1C) persists it.
#![cfg_attr(not(test), no_std)]

use core::cell::RefCell;
use rsk_fs::{Fs, Storage};
// The user-presence seam gating WRITE CONFIG against a hostile USB host is
// `rsk-sdk`'s, shared with every sibling applet — the board has one button.
pub use rsk_sdk::{AlwaysConfirm, Confirm, Presence, UserPresence};
use rsk_sdk::{Apdu, Applet, ResBuf, Sw};

/// Management applet AID.
pub const MANAGEMENT_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];

/// Reported firmware version `(major, minor, patch)` — the shared
/// [`rsk_sdk::FIRMWARE_VERSION`] so CTAP getInfo, the DeviceInfo TLV and `ykman`
/// all agree.
pub const VERSION: (u8, u8, u8) = rsk_sdk::FIRMWARE_VERSION;

// Capability bits (YubiKey `CAPABILITY.*`) — the USB_ENABLED bitmask vocabulary,
// also the applet-gate keys the firmware maps each applet to.
pub const CAP_OTP: u16 = 0x01;
pub const CAP_U2F: u16 = 0x02;
pub const CAP_OPENPGP: u16 = 0x08;
pub const CAP_OATH: u16 = 0x20;
pub const CAP_FIDO2: u16 = 0x200;
pub const CAP_PIV: u16 = 0x10;

/// Capabilities this firmware actually implements. Reporting only what exists
/// keeps Yubico Authenticator from showing tabs that would error on SELECT; it is
/// also the ceiling a host-written USB_ENABLED is clamped to and the factory
/// default enabled set.
pub const SUPPORTED_CAPS: u16 = CAP_FIDO2 | CAP_U2F | CAP_OPENPGP | CAP_OATH | CAP_OTP | CAP_PIV;

// DeviceInfo TLV tags.
const TAG_USB_SUPPORTED: u8 = 0x01;
const TAG_SERIAL: u8 = 0x02;
const TAG_USB_ENABLED: u8 = 0x03;
const TAG_FORM_FACTOR: u8 = 0x04;
const TAG_VERSION: u8 = 0x05;
const TAG_DEVICE_FLAGS: u8 = 0x08;
const TAG_CONFIG_LOCK: u8 = 0x0A;
const TAG_CONFIG_UNLOCK: u8 = 0x0B;
// The rest of ykman's writable DeviceConfig set (`DeviceConfig.get_bytes`). We do
// not act on these, but a host may legitimately send them, so they round-trip.
const TAG_AUTO_EJECT_TIMEOUT: u8 = 0x06;
const TAG_CHALRESP_TIMEOUT: u8 = 0x07;
const TAG_REBOOT: u8 = 0x0C;
const TAG_NFC_ENABLED: u8 = 0x0E;
const TAG_NFC_RESTRICTED: u8 = 0x17;

/// Whether a host may write this DeviceInfo tag. The complement — `USB_SUPPORTED`,
/// `SERIAL`, `FORM_FACTOR`, `VERSION` — is device-owned and emitted by
/// [`config_tlv`] itself; storing a host copy would append a *second* instance
/// after the authentic one, and `ykman`'s `Tlv.parse_dict` is last-wins, so the
/// host value would win. A malformed one (e.g. a 1-byte `VERSION`) makes
/// `DeviceInfo.parse` raise, which hides the device from `ykman` for good —
/// `EF_DEV_CONF` survives `authenticatorReset` and no first-party tool rewrites it
/// (audit run-33). Refusing the write is what keeps that unreachable; real
/// hardware has no path to a self-inflicted unparseable DeviceInfo either.
fn writable_tag(tag: u8) -> bool {
    matches!(
        tag,
        TAG_USB_ENABLED
            | TAG_AUTO_EJECT_TIMEOUT
            | TAG_CHALRESP_TIMEOUT
            | TAG_DEVICE_FLAGS
            | TAG_CONFIG_LOCK
            | TAG_CONFIG_UNLOCK
            | TAG_REBOOT
            | TAG_NFC_ENABLED
            | TAG_NFC_RESTRICTED
    )
}

const FLAG_EJECT: u8 = 0x80;
const FORM_FACTOR_USB_A_KEYCHAIN: u8 = 0x01;

const INS_WRITE_CONFIG: u8 = 0x1C;
const INS_READ_CONFIG: u8 = 0x1D;
const INS_RESET: u8 = 0x1E;
// ykman's device-wide reset (ManagementSession.device_reset) is INS 0x1F; RS-Key's
// own placeholder was 0x1E. The DEFAULT build honours BOTH as a factory reset;
// strict-config keeps them unsupported. DEFAULT-build only.
#[cfg(not(feature = "strict-config"))]
const INS_DEVICE_RESET: u8 = 0x1F;

/// Pending device-wide factory-reset request, set by the Management RESET command
/// and drained by the firmware after the command's SW_OK. DEFAULT build only.
#[cfg(not(feature = "strict-config"))]
static DEVICE_RESET: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Take (and clear) a pending device-wide factory-reset request. The firmware
/// polls this after the RESET SW_OK, then wipes all flash (keeping attestation)
/// and reboots. `strict-config` never sets it (RESET stays `6D00`).
#[cfg(not(feature = "strict-config"))]
pub fn take_device_reset() -> bool {
    DEVICE_RESET.swap(false, core::sync::atomic::Ordering::Relaxed)
}

/// EF holding the persisted enabled-applications TLV. Outside both the FIDO and
/// OpenPGP reset scopes, so the capability config is sticky.
const EF_DEV_CONF: u16 = 0x1122;

/// Bytes of `EF_DEV_CONF` that READ CONFIG can echo back. Derived from the
/// *smallest* response buffer any transport gives us — the OTP-HID frame's 64
/// bytes — minus the fixed part of the DeviceInfo TLV, so a stored blob can never
/// be one a consumer must silently drop. Sizing the writer against its own scratch
/// instead is what let a 43-byte config wedge OTP-HID READ CONFIG into an empty
/// success response, persistently (audit run-33). It is slack rather than a bound
/// today: `well_formed_writable`'s per-tag widths (run-34 #25) hold a storable
/// record to 24 bytes, so only an unbounded writable tag makes this bind again.
const EF_DEV_CONF_MAX: usize = MIN_CONFIG_RES_CAP - CONFIG_TLV_FIXED;

/// Largest WRITE CONFIG request accepted, before the lock tags are stripped. A
/// request may legitimately be larger than what it stores — `set-lock-code` sends
/// a 16-byte UNLOCK *and* a 16-byte CONFIG_LOCK, neither of which is kept — so the
/// request bound is the transport's own limit and [`EF_DEV_CONF_MAX`] is applied
/// to the stripped result.
const DEV_CONF_WRITE_MAX: usize = 128;

/// Smallest `ResBuf` a READ CONFIG response is built into (the OTP-HID transport).
const MIN_CONFIG_RES_CAP: usize = 64;

/// How much of `EF_DEV_CONF` a read reaches for. Larger than [`EF_DEV_CONF_MAX`],
/// which bounds only *new* writes: builds before that cap stored up to this much,
/// and the record survives `authenticatorReset`, so an upgraded device must still
/// be read whole. Reading through the smaller cap would slice such a blob
/// mid-entry and hand the host the unparseable DeviceInfo the cap exists to
/// prevent.
const EF_DEV_CONF_READ_MAX: usize = 64;

/// Scratch a merge is assembled in before [`trim_to_cap`] shrinks it: a legacy
/// record (up to [`EF_DEV_CONF_READ_MAX`]) plus everything the request contributes.
/// Sizing it by the *stored* cap instead is what made [`overlay_dev_conf`] answer
/// `TooLong` before the trim could run, so a 64-byte legacy record refused every
/// write that added a tag it did not already carry (audit run-37).
const DEV_CONF_MERGE_MAX: usize = EF_DEV_CONF_READ_MAX + DEV_CONF_WRITE_MAX;

/// The device-owned part of every READ CONFIG response: the overall length byte,
/// `USB_SUPPORTED` + `SERIAL` + `FORM_FACTOR` + `VERSION`, and the trailing
/// `CONFIG_LOCK`. Each `push_tlv` costs 2 bytes of header plus its value.
const CONFIG_TLV_FIXED: usize = 1 + (2 + 2) + (2 + 4) + (2 + 1) + (2 + 3) + CONFIG_LOCK_TLV_LEN;

/// The trailing `CONFIG_LOCK` entry `config_tlv` always appends after the echo.
const CONFIG_LOCK_TLV_LEN: usize = 2 + 1;

pub struct ManagementApplet<'a> {
    /// First 4 bytes of the chip id → the 8-digit serial.
    serial: [u8; 4],
    /// Touch/approval gate for the privileged WRITE CONFIG.
    presence: &'a RefCell<dyn UserPresence>,
}

/// First 4 bytes of the chip id with the top 6 bits cleared (`&= ~0xFC`) — the
/// 8-digit Yubico serial. Shared with the OTP applet's GET SERIAL.
pub fn serial4(serial_id: [u8; 8]) -> [u8; 4] {
    let mut serial = [0u8; 4];
    serial.copy_from_slice(&serial_id[..4]);
    serial[0] &= 0x03;
    serial
}

/// Build the READ CONFIG TLV: a leading overall-length byte, then
/// USB_SUPPORTED / SERIAL / FORM_FACTOR / VERSION, then either the persisted
/// `EF_DEV_CONF` blob or the default USB_ENABLED / DEVICE_FLAGS / CONFIG_LOCK
/// tail. Public because the OTP applet serves the same TLV (P1=0x13).
pub fn config_tlv<S: Storage>(serial: &[u8; 4], fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
    let mut buf = [0u8; 128];
    let mut n = 1; // byte 0 = overall length, filled at the end.

    push_tlv(
        &mut buf,
        &mut n,
        TAG_USB_SUPPORTED,
        &SUPPORTED_CAPS.to_be_bytes(),
    );
    push_tlv(&mut buf, &mut n, TAG_SERIAL, serial);
    push_tlv(
        &mut buf,
        &mut n,
        TAG_FORM_FACTOR,
        &[FORM_FACTOR_USB_A_KEYCHAIN],
    );
    let (maj, min, patch) = VERSION;
    push_tlv(&mut buf, &mut n, TAG_VERSION, &[maj, min, patch]);

    let mut conf = [0u8; EF_DEV_CONF_READ_MAX];
    // A stored record is validated on READ, not only on write. `well_formed_writable`
    // has only ever guarded the write path, so a record a **pre-`9171ccf` build**
    // accepted — a 1-byte `USB_ENABLED`, a duplicate tag — survived the upgrade and
    // kept being echoed, which is how one permanently hid the device from ykman
    // (audit run-34 #25). An unusable record falls back to the factory default: the
    // host then sees "everything supported is enabled", which is exactly what
    // `enabled_from_conf` enforces for a record it cannot read either, so the two
    // sides agree instead of diverging.
    let stored = match fs.read(EF_DEV_CONF, &mut conf) {
        Some(full) if full > 0 && full <= conf.len() && well_formed_writable(&conf[..full]) => {
            Some(full)
        }
        _ => None,
    };
    match stored {
        Some(full) if full > 0 => {
            // A host wrote an enabled-applications config — echo it back. Three
            // steps: (1) `Storage::read` reports the value's *full* length even
            // when it exceeds the buffer, so bound `len` before slicing — WRITE
            // CONFIG caps new writes, but a blob from an older build or corrupt
            // flash could be over-length and must not slice past `conf`/`buf`;
            // (2) strip any config-lock tag before echoing — we do not enforce the
            // lock and must never hand a user-entered 16-byte code to an
            // unauthenticated reader (audit run-30); (3) mask USB_ENABLED down to
            // what this firmware supports, so READ CONFIG never reports enabled ⊄
            // supported.
            let len = full.min(conf.len());
            let mut echoed = [0u8; EF_DEV_CONF_READ_MAX];
            // Bound the echo by the caller's buffer as well as ours: `ResBuf::extend`
            // writes *nothing* on overflow, so an echo that fits `buf` but not the
            // transport's response would turn READ CONFIG into an empty `9000`
            // forever. `EF_DEV_CONF_MAX` makes that unreachable for anything this
            // firmware stored; the clamp covers a blob from an older build.
            let taken = res.capacity().saturating_sub(res.len());
            let room = taken
                .saturating_sub(n + CONFIG_LOCK_TLV_LEN)
                .min(buf.len().saturating_sub(n + CONFIG_LOCK_TLV_LEN));
            let stripped = strip_config_lock(&conf[..len], &mut echoed).min(room);
            // …and to whole entries. Every bound above is a byte count, so any of
            // them can land inside a TLV; emitting the head of one is precisely the
            // unparseable DeviceInfo this response must never produce. Only a record
            // an older build stored (or corrupt flash) can reach the cut.
            let elen = whole_tlvs(&echoed[..stripped]);
            buf[n..n + elen].copy_from_slice(&echoed[..elen]);
            clamp_usb_enabled(&mut buf[n..n + elen]);
            n += elen;
            // The stored blob never carries a lock tag; report it unset on read, as
            // real hardware does.
            push_tlv(&mut buf, &mut n, TAG_CONFIG_LOCK, &[0x00]);
        }
        _ => {
            // No record, or one this firmware's writer would refuse. Either way the
            // echo is synthesised from the mask actually enforced — never the raw
            // bytes. A record a pre-`9171ccf` build accepted (a 1-byte USB_ENABLED)
            // used to be echoed verbatim and permanently hid the device from ykman,
            // while `enabled_from_conf` ignored the same value and enforced the
            // default: report and enforcement disagreed on one record (run-34 #25).
            // Normalising leaves them one answer, always parseable.
            push_tlv(
                &mut buf,
                &mut n,
                TAG_USB_ENABLED,
                &read_enabled_caps(fs).to_be_bytes(),
            );
            push_tlv(&mut buf, &mut n, TAG_DEVICE_FLAGS, &[FLAG_EJECT]);
            push_tlv(&mut buf, &mut n, TAG_CONFIG_LOCK, &[0x00]);
        }
    }

    buf[0] = (n - 1) as u8;
    if !res.extend(&buf[..n]) {
        // Unreachable given the clamp above, but never answer OK over a body the
        // buffer silently dropped — an empty success is what the host parses.
        return Sw::EXEC_ERROR;
    }
    Sw::OK
}

/// Failure to persist a device-config blob — shared by the CCID WRITE CONFIG and
/// the FIDO vendor config-write, which map it to their own status/error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevConfError {
    /// Over `EF_DEV_CONF_MAX` — refused so READ CONFIG can never slice past its
    /// fixed buffer (an over-length blob in flash is a sticky DoS).
    TooLong,
    /// Not well-formed TLV, or it carries a tag the device owns (see
    /// `writable_tag`). Refused so a host cannot forge an identity field or
    /// store a blob that makes the DeviceInfo response unparseable.
    BadTlv,
    /// The flash write failed.
    Store,
}

/// Validate and persist the device-config TLV to `EF_DEV_CONF` — the
/// transport-agnostic core of WRITE CONFIG, shared by the CCID applet and the
/// FIDO vendor config-write ([`crate::ManagementApplet`] / `rsk-fido`). `blob` is
/// the enabled-applications TLV *without* any transport length prefix; the caller
/// applies its own auth gate (CCID presence, FIDO PIN + touch) before this.
/// Refines `RSKeyAdminSurface!DisableSetSurvivesLockWrite` — SEC-ADM-003.
pub fn persist_dev_conf<S: Storage>(fs: &mut Fs<S>, blob: &[u8]) -> Result<(), DevConfError> {
    if blob.len() > DEV_CONF_WRITE_MAX {
        return Err(DevConfError::TooLong);
    }
    if !well_formed_writable(blob) {
        return Err(DevConfError::BadTlv);
    }
    // Never retain the config-lock tags (see `strip_config_lock`): we do not enforce
    // the lock, and READ CONFIG echoes this blob to any unauthenticated host, so a
    // 16-byte 0x0A would sit unsealed in flash and be disclosed (audit run-30).
    let mut stripped = [0u8; DEV_CONF_WRITE_MAX];
    let n = strip_config_lock(blob, &mut stripped);
    // Bound what is actually STORED, not what was sent: the two lock tags carry
    // 16-byte codes that never reach flash, and `ykman config set-lock-code` sends
    // both the old and the new one at once — 59 bytes of request for at most 23
    // bytes of config. Measuring the request would refuse that legitimate write.
    // MERGE onto the stored record; do not replace it. ykman sends only the fields
    // it is changing — `config set-lock-code` sends the 0x0A TLV and nothing else,
    // which strips to zero bytes here. Storing that verbatim left an EMPTY record,
    // and `read_enabled_caps` reads empty as "no record" and returns
    // SUPPORTED_CAPS, so a lock-code write silently re-enabled every application
    // the owner had disabled (audit run-35).
    let mut merged = [0u8; DEV_CONF_MERGE_MAX];
    let m = merged_dev_conf(fs, &stripped[..n], &mut merged)?;
    if m > EF_DEV_CONF_MAX {
        return Err(DevConfError::TooLong);
    }
    // An idempotent write costs no flash and no audit-journal entry. Folded in here
    // rather than left to the caller: only one of the four call sites ever ran the
    // check, and after the merge landed it could not recognise a partial replay at
    // all, which is the only shape ykman sends (audit run-36).
    if stored_matches(fs, &merged[..m]) {
        return Ok(());
    }
    fs.put(EF_DEV_CONF, &merged[..m])
        .map_err(|_| DevConfError::Store)?;
    // The enabled-applications set changed; the firmware reloads its cached mask
    // (which gates applet dispatch) before the next command it guards.
    DEV_CONF_DIRTY.store(true, core::sync::atomic::Ordering::Relaxed);
    Ok(())
}

/// The record a write of `incoming` (already lock-stripped) would store: the merge
/// onto what is on flash, trimmed to the cap. One definition, so the writer and
/// [`dev_conf_unchanged`] can never disagree about what "unchanged" means. `out`
/// must be [`DEV_CONF_MERGE_MAX`] — the merge is over-cap before the trim.
fn merged_dev_conf<S: Storage>(
    fs: &mut Fs<S>,
    incoming: &[u8],
    out: &mut [u8],
) -> Result<usize, DevConfError> {
    let m = overlay_dev_conf(fs, incoming, out)?;
    Ok(trim_to_cap(out, m, incoming.len()))
}

/// Drop whole stored entries from the front of a merged record until it fits
/// [`EF_DEV_CONF_MAX`], never touching the trailing `keep` bytes the request itself
/// contributed, and never [`TAG_USB_ENABLED`].
///
/// [`overlay_dev_conf`] emits the stored, un-restated entries first and appends the
/// request last, so trimming the front evicts the oldest stored fields and always
/// leaves the owner's own write intact. Without it, stored bytes could veto a write:
/// released firmware bounded writes at [`EF_DEV_CONF_READ_MAX`] with no shape
/// validation, so a field device may carry a record the write cap refuses, and one
/// ungated oversized entry could deny the owner their config surface for good
/// (audit run-36).
///
/// The enabled-applications tag is exempt because nothing canonicalises the stored
/// order, so it sits at the front of any record whose writer emitted it first — and
/// it is the one stored entry this firmware enforces, with an absence that resolves
/// permissively ([`enabled_from_conf`] → [`SUPPORTED_CAPS`]). Evicting it by
/// position let a lock-code write silently re-enable every disabled application
/// (audit run-37).
fn trim_to_cap(merged: &mut [u8], mut m: usize, keep: usize) -> usize {
    while m > EF_DEV_CONF_MAX && m > keep {
        let stored = m - keep;
        let mut i = 0;
        let victim = loop {
            if i + 2 > stored {
                break None;
            }
            let entry = 2 + merged[i + 1] as usize;
            if i + entry > stored {
                break None;
            }
            if merged[i] != TAG_USB_ENABLED {
                break Some((i, entry));
            }
            i += entry;
        };
        // Only the policy (or a half entry) left to give: refusing the write beats
        // dropping it, and `persist_dev_conf` turns the over-cap length into 6A80.
        let Some((at, entry)) = victim else { break };
        merged.copy_within(at + entry..m, at);
        m -= entry;
    }
    m
}

/// Whether `EF_DEV_CONF` already holds exactly `want`.
fn stored_matches<S: Storage>(fs: &mut Fs<S>, want: &[u8]) -> bool {
    let mut cur = [0u8; EF_DEV_CONF_READ_MAX];
    // `read` reports the value's *full* stored length, which an over-length record
    // from an older build can push past `cur` — compare only when it fits.
    matches!(fs.read(EF_DEV_CONF, &mut cur),
        Some(c) if c == want.len() && c <= cur.len() && cur[..c] == *want)
}

/// Overlay the TLV entries `incoming` carries onto the stored `EF_DEV_CONF`,
/// writing the result into `out` and returning its length.
///
/// A DeviceConfig write is a *delta*: real hardware merges it, and every ykman
/// command that touches one field sends that field alone. Replacing the record
/// wholesale therefore discards every setting the request did not mention.
/// Entries the request repeats win; the rest are kept in their stored order, so a
/// no-op write is byte-stable and `dev_conf_unchanged` still short-circuits it.
fn overlay_dev_conf<S: Storage>(
    fs: &mut Fs<S>,
    incoming: &[u8],
    out: &mut [u8],
) -> Result<usize, DevConfError> {
    let mut stored = [0u8; EF_DEV_CONF_READ_MAX];
    let stored_n = fs
        .read(EF_DEV_CONF, &mut stored)
        .map(|n| n.min(EF_DEV_CONF_READ_MAX))
        .unwrap_or(0);
    // A stored record an older build may have written is only merged onto when it
    // parses; otherwise the incoming blob replaces it, which is what the previous
    // behaviour did for every input and is still the safe answer for a record we
    // cannot read.
    let stored = &stored[..whole_tlvs(&stored[..stored_n])];

    let mut n = 0usize;
    let mut push = |src: &[u8], out: &mut [u8]| -> Result<(), DevConfError> {
        if n + src.len() > out.len() {
            return Err(DevConfError::TooLong);
        }
        out[n..n + src.len()].copy_from_slice(src);
        n += src.len();
        Ok(())
    };
    // Stored entries first, minus any tag the request restates.
    let mut i = 0;
    while i + 1 < stored.len() {
        let len = stored[i + 1] as usize;
        let end = i + 2 + len;
        if end > stored.len() {
            break;
        }
        if !has_tag(incoming, stored[i]) {
            push(&stored[i..end], out)?;
        }
        i = end;
    }
    push(incoming, out)?;
    Ok(n)
}

/// Whether a well-formed TLV run carries an entry with `tag`.
fn has_tag(blob: &[u8], tag: u8) -> bool {
    let mut i = 0;
    while i + 1 < blob.len() {
        let end = i + 2 + blob[i + 1] as usize;
        if end > blob.len() {
            return false;
        }
        if blob[i] == tag {
            return true;
        }
        i = end;
    }
    false
}

/// Copy `blob` minus any CONFIG_LOCK (0x0A) / UNLOCK (0x0B) TLV entry into `out`,
/// returning the stripped length. We do not implement the config lock, and READ
/// CONFIG echoes this blob verbatim to any unauthenticated host over three transports,
/// so retaining a 16-byte lock code would hand back a secret the user typed — real
/// hardware treats 0x0A as write-only. If the TLV does not parse cleanly the blob is
/// copied unchanged, so a config we do not understand is never corrupted (an attacker's
/// own malformed write is readable by them regardless). `out` must be at least
/// `blob.len()` bytes.
/// Whether `blob` is a clean run of TLV entries whose every tag a host may write.
/// Empty is fine (it clears the record). Rejecting here rather than sanitizing on
/// read keeps one definition of "what a host may store" and means READ CONFIG can
/// go on echoing the stored bytes verbatim.
fn well_formed_writable(blob: &[u8]) -> bool {
    let mut i = 0;
    let mut seen = [0u8; 16];
    let mut seen_n = 0;
    while i < blob.len() {
        let Some(&len) = blob.get(i + 1) else {
            return false; // truncated header
        };
        let Some(end) = i.checked_add(2).and_then(|h| h.checked_add(len as usize)) else {
            return false;
        };
        let tag = blob[i];
        if end > blob.len() || !writable_tag(tag) {
            return false;
        }
        // One entry per tag. A real YubiKey emits each exactly once; a duplicate
        // makes this device (first-wins, `enabled_from_conf`) and ykman (last-wins,
        // `Tlv.parse_dict`) disagree about what was just stored.
        if seen[..seen_n].contains(&tag) {
            return false;
        }
        if seen_n == seen.len() {
            return false; // more distinct tags than the writable set has
        }
        seen[seen_n] = tag;
        seen_n += 1;
        // `enabled_from_conf` and `clamp_usb_enabled` both act only on a two-byte
        // value, so any other width would store a mask the device silently ignores
        // while a host parser reads it — including one wide enough to escape the
        // "enabled ⊆ supported" clamp entirely.
        if tag == TAG_USB_ENABLED && len != 2 {
            return false;
        }
        // Every other writable tag gets a width bound too. Only `USB_ENABLED` had
        // one, so an ungated 38-byte `AUTO_EJECT_TIMEOUT` stored fine and then made
        // every later *partial* write — the only shape ykman sends — exceed the
        // post-merge cap, denying the owner their own config surface for good
        // (audit run-36). These are the widths ykman can actually express.
        if max_value_len(tag).is_some_and(|max| len as usize > max) {
            return false;
        }
        i = end;
    }
    true
}

/// The widest value ykman can put in each writable tag, or `None` where no bound
/// applies (the two lock tags carry 16-byte codes, and `strip_config_lock` drops
/// them before storage either way). `USB_ENABLED` keeps its own EXACT-width rule at
/// the call site: relaxing it to a maximum would let a stored `03 00` be echoed by
/// `config_tlv` while `enabled_from_conf` ignores it, reintroducing the
/// report-vs-enforcement divergence of audit run-34 #25.
fn max_value_len(tag: u8) -> Option<usize> {
    match tag {
        TAG_NFC_ENABLED | TAG_AUTO_EJECT_TIMEOUT | TAG_CHALRESP_TIMEOUT => Some(2),
        TAG_DEVICE_FLAGS | TAG_NFC_RESTRICTED => Some(1),
        TAG_REBOOT => Some(0),
        _ => None,
    }
}

/// Length of the leading run of complete TLV entries in `blob` — how much of a
/// stored record READ CONFIG may echo. Unlike [`well_formed_writable`] this judges
/// only the framing, never the tags: the bytes are already on flash, and dropping
/// a half entry is the whole point.
fn whole_tlvs(blob: &[u8]) -> usize {
    let mut i = 0;
    while i + 2 <= blob.len() {
        let end = i + 2 + blob[i + 1] as usize;
        if end > blob.len() {
            break;
        }
        i = end;
    }
    i
}

fn strip_config_lock(blob: &[u8], out: &mut [u8]) -> usize {
    let mut i = 0;
    let mut n = 0;
    while i < blob.len() {
        let Some(&len) = blob.get(i + 1) else {
            out[..blob.len()].copy_from_slice(blob);
            return blob.len();
        };
        let end = i + 2 + len as usize;
        if end > blob.len() {
            out[..blob.len()].copy_from_slice(blob);
            return blob.len();
        }
        if blob[i] != TAG_CONFIG_LOCK && blob[i] != TAG_CONFIG_UNLOCK {
            out[n..n + (end - i)].copy_from_slice(&blob[i..end]);
            n += end - i;
        }
        i = end;
    }
    n
}

/// Whether `EF_DEV_CONF` already holds exactly `blob`, so a WRITE CONFIG carrying
/// it would change nothing. `EF_DEV_CONF` is private to this crate, so the FIDO
/// vendor `CONFIG_WRITE` asks here: it skips the flash write *and* its audit-journal
/// entry on an idempotent replay, which a silent host could otherwise use to evict
/// the whole ring.
pub fn dev_conf_unchanged<S: Storage>(fs: &mut Fs<S>, blob: &[u8]) -> bool {
    // Request-side bound: this takes the blob as sent, lock tags included.
    if blob.len() > DEV_CONF_WRITE_MAX {
        return false;
    }
    // Deliberately NOT gated on `well_formed_writable`: a legacy record an older,
    // laxer build stored (duplicate tags and all) must still be recognised when it
    // is replayed verbatim, or every replay churns flash and the audit ring — the
    // run-34 #35 property this function carries.
    // Compare against the stripped form we would actually store, so an idempotent
    // replay of a blob that still carries 0x0A/0x0B is still recognised as unchanged
    // (otherwise every replay would churn flash and the audit ring — audit run-30).
    let mut stripped = [0u8; DEV_CONF_WRITE_MAX];
    let n = strip_config_lock(blob, &mut stripped);
    // Compare what the write would actually STORE, not the request. The writer
    // merges onto the stored record, so a partial blob — the only shape ykman sends
    // — is never byte-equal to the whole record, and comparing the request meant
    // this short-circuit could not fire at all after the merge landed (audit
    // run-36). Sized like the writer's own scratch, not by a cap: `EF_DEV_CONF_MAX`
    // is the *write* limit, and sizing a reader by it meant a legacy record between
    // the limits never fitted, so every replay of it looked "changed" and churned
    // flash plus the audit ring (audit run-34 #35).
    let mut merged = [0u8; DEV_CONF_MERGE_MAX];
    let Ok(m) = merged_dev_conf(fs, &stripped[..n], &mut merged) else {
        return false;
    };
    stored_matches(fs, &merged[..m])
}

/// Set by [`persist_dev_conf`] on any successful write, drained by the firmware to
/// know when to reload its cached enabled-capability mask. Same swap-to-consume
/// latch as the device-reset request; enforcement is build-agnostic (a
/// `strict-config` build still honours a persisted config), so this is ungated.
static DEV_CONF_DIRTY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Take (and clear) the "enabled-applications config changed" latch.
pub fn take_dev_conf_dirty() -> bool {
    DEV_CONF_DIRTY.swap(false, core::sync::atomic::Ordering::Relaxed)
}

/// The enabled-applications mask from a persisted `EF_DEV_CONF` TLV blob — the
/// `USB_ENABLED` (`0x03`) tag, clamped to [`SUPPORTED_CAPS`]. A blob without that
/// tag, or none persisted at all, is the factory default: everything supported is
/// enabled. Walks short-form TLVs like `clamp_usb_enabled`; a malformed length
/// stops the walk (→ default), never slicing out of bounds.
pub fn enabled_from_conf(conf: &[u8]) -> u16 {
    let mut i = 0;
    while i + 2 <= conf.len() {
        let len = conf[i + 1] as usize;
        if i + 2 + len > conf.len() {
            break;
        }
        if conf[i] == TAG_USB_ENABLED && len == 2 {
            return u16::from_be_bytes([conf[i + 2], conf[i + 3]]) & SUPPORTED_CAPS;
        }
        i += 2 + len;
    }
    SUPPORTED_CAPS
}

/// Read `EF_DEV_CONF` and return its enabled-applications mask ([`enabled_from_conf`]).
/// The firmware caches this and re-reads it when [`take_dev_conf_dirty`] fires.
pub fn read_enabled_caps<S: Storage>(fs: &mut Fs<S>) -> u16 {
    // The read width, not the write cap: a pre-cap build's larger record must still
    // be scanned whole, or a disabled applet silently comes back after the upgrade.
    let mut conf = [0u8; EF_DEV_CONF_READ_MAX];
    match fs.read(EF_DEV_CONF, &mut conf) {
        Some(full) if full > 0 => enabled_from_conf(&conf[..full.min(conf.len())]),
        _ => SUPPORTED_CAPS,
    }
    // Deliberately NOT gated on `well_formed_writable`, unlike the echo: this walk
    // is already defensive (a `USB_ENABLED` that is not exactly two bytes is
    // skipped, and an unreadable record yields the default), and refusing to honour
    // a record it cannot *fully* validate would silently re-enable applets the owner
    // disabled. The echo is normalised to this answer instead (audit run-34 #25).
}

/// Whether an applet guarded by capability bit `cap` is enabled under `mask`.
/// `cap == 0` marks an always-available applet (management, vendor, rescue) — the
/// re-enable path must never be gated off, or a disable becomes irreversible.
pub fn cap_enabled(mask: u16, cap: u16) -> bool {
    cap == 0 || mask & cap != 0
}

impl<'a> ManagementApplet<'a> {
    /// `serial_id` is the device chip id; its first 4 bytes form the serial.
    pub fn new(serial_id: [u8; 8], presence: &'a RefCell<dyn UserPresence>) -> Self {
        Self {
            serial: serial4(serial_id),
            presence,
        }
    }

    /// Require a physical user-presence confirmation before a privileged op.
    /// `true` only on Confirmed — a hostile USB host cannot drive it alone.
    fn require_presence(&self, confirm: Confirm<'_>) -> bool {
        self.presence.borrow_mut().request(confirm) == Presence::Confirmed
    }

    /// Serve READ CONFIG to a non-CCID transport — the same DeviceInfo TLV as the
    /// CCID path. The OTP keyboard interface and the CTAPHID Management vendor
    /// command both answer it (a YubiKey replies on every transport).
    pub fn read_config<S: Storage>(&self, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        config_tlv(&self.serial, fs, res)
    }

    /// WRITE CONFIG: the first data byte is the length of the rest; persist that
    /// TLV blob as `EF_DEV_CONF`.
    fn write_config<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>) -> Sw {
        if apdu.nc == 0 || apdu.data[0] as usize != apdu.nc - 1 {
            return Sw::WRONG_DATA;
        }
        // Request-side bound only. What actually reaches flash is bounded by
        // `persist_dev_conf` against `EF_DEV_CONF_MAX` *after* the lock tags are
        // stripped, so a legitimate `set-lock-code` (two 16-byte codes in one
        // request, neither stored) is not refused for the size of its request.
        if apdu.nc - 1 > DEV_CONF_WRITE_MAX {
            return Sw::WRONG_DATA;
        }
        // Rewriting the reported DeviceInfo is a privileged, sticky change. Under
        // `strict-config` gate it on operator presence (the CONFIG_LOCK byte is
        // only reported, never enforced, so presence is the authentication of
        // record). The DEFAULT build is ungated for full YubiKey/ykman parity —
        // any USB host can rewrite DeviceInfo (docs/threat-model.md).
        if cfg!(feature = "strict-config")
            && !self.require_presence(Confirm::titled("Write device config?"))
        {
            return Sw::CONDITIONS_NOT_SATISFIED;
        }
        match persist_dev_conf(fs, &apdu.data[1..apdu.nc]) {
            Ok(()) => Sw::OK,
            Err(DevConfError::TooLong | DevConfError::BadTlv) => Sw::WRONG_DATA,
            Err(DevConfError::Store) => Sw::MEMORY_FAILURE,
        }
    }

    /// Management RESET (INS 0x1E / ykman's 0x1F): request a device-wide factory
    /// reset. Even on the permissive default this is presence-gated — an
    /// unauthenticated one-APDU wipe from any USB host would be a silent-brick
    /// footgun. The firmware does the flash wipe + reboot after this SW_OK.
    #[cfg(not(feature = "strict-config"))]
    fn request_device_reset(&mut self) -> Sw {
        if !self.require_presence(Confirm::titled("Factory reset device?")) {
            return Sw::CONDITIONS_NOT_SATISFIED;
        }
        DEVICE_RESET.store(true, core::sync::atomic::Ordering::Relaxed);
        Sw::OK
    }
}

impl<S: Storage> Applet<Fs<S>> for ManagementApplet<'_> {
    fn aid(&self) -> &'static [u8] {
        MANAGEMENT_AID
    }

    /// SELECT returns the firmware version as an ASCII string.
    fn select(&mut self, _reselect: bool, _fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        let (maj, min, patch) = VERSION;
        push_dec(res, maj);
        res.push(b'.');
        push_dec(res, min);
        res.push(b'.');
        push_dec(res, patch);
        Sw::OK
    }

    fn process(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        if apdu.cla != 0x00 {
            return Sw::CLA_NOT_SUPPORTED;
        }
        match apdu.ins {
            INS_READ_CONFIG => config_tlv(&self.serial, fs, res),
            INS_WRITE_CONFIG => self.write_config(apdu, fs),
            // DEFAULT build: a presence-gated device-wide factory reset (ykman
            // parity), serviced by the firmware after this SW_OK. strict-config
            // keeps it unsupported (ykman resets FIDO over CTAP instead).
            #[cfg(not(feature = "strict-config"))]
            INS_RESET | INS_DEVICE_RESET => self.request_device_reset(),
            #[cfg(feature = "strict-config")]
            INS_RESET => Sw::INS_NOT_SUPPORTED,
            _ => Sw::INS_NOT_SUPPORTED,
        }
    }
}

/// Clamp any USB_ENABLED (`0x03`) TLV in a persisted config blob to
/// `SUPPORTED_CAPS`, so READ CONFIG never reports an enabled capability this
/// firmware does not implement. A real YubiKey guarantees enabled ⊆ supported;
/// RS-Key echoes the host-written `EF_DEV_CONF` blob, which could carry a wider
/// mask (a newer host that knows capability bits we lack). Walks short-form
/// TLVs in place; a malformed length stops the walk, leaving the rest untouched.
fn clamp_usb_enabled(blob: &mut [u8]) {
    let mut i = 0;
    while i + 2 <= blob.len() {
        let len = blob[i + 1] as usize;
        if i + 2 + len > blob.len() {
            break;
        }
        if blob[i] == TAG_USB_ENABLED && len == 2 {
            let masked =
                (u16::from_be_bytes([blob[i + 2], blob[i + 3]]) & SUPPORTED_CAPS).to_be_bytes();
            blob[i + 2..i + 4].copy_from_slice(&masked);
        }
        i += 2 + len;
    }
}

/// Append a `tag, len, value` TLV; silently truncated by the fixed `read_config`
/// buffer (sized for the largest config, so this never actually overflows).
fn push_tlv(buf: &mut [u8], n: &mut usize, tag: u8, val: &[u8]) {
    if *n + 2 + val.len() > buf.len() {
        return;
    }
    buf[*n] = tag;
    buf[*n + 1] = val.len() as u8;
    buf[*n + 2..*n + 2 + val.len()].copy_from_slice(val);
    *n += 2 + val.len();
}

/// Append a `u8` as 1-3 ASCII decimal digits.
fn push_dec(res: &mut ResBuf, v: u8) {
    if v >= 100 {
        res.push(b'0' + v / 100);
    }
    if v >= 10 {
        res.push(b'0' + (v / 10) % 10);
    }
    res.push(b'0' + v % 10);
}

#[cfg(test)]
mod tests;
