// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `EF_DEV_CONF` (`0x1122`) — the Yubico DeviceInfo record: the
//! enabled-applications TLV a host writes with `ykman config usb`, and the READ
//! CONFIG response built around it. Four command surfaces read or write the same
//! record (CCID `0x1C`/`0x1D`, the OTP keyboard slots `0x13`/`0x15`, the CTAPHID
//! vendor pair, the FIDO vendor `CONFIG_WRITE`), so the codec sits below all of
//! them instead of inside the management applet that needed it first — and so does
//! the configuration lock that guards it (`lock.rs`), which all four then enforce.
#![cfg_attr(not(test), no_std)]
// Host-written records: a panic here is a board that answers nothing until unplugged.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use rsk_fs::{Fs, Storage};
use rsk_sdk::{Confirm, FIRMWARE_VERSION, ResBuf, Sw};

mod lock;
pub use lock::ensure_unlocked;
use lock::{LOCK_CODE_LEN, LockChange, lock_change, lock_reported};

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

const DEVICE_FLAGS_FACTORY: u8 = 0x00; // a factory YubiKey's: no touch-eject (80), no wakeup (40)

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
/// request bound is the transport's own limit and the crate-private
/// `EF_DEV_CONF_MAX` is applied to the stripped result.
pub const DEV_CONF_WRITE_MAX: usize = 128;

/// The touch a write that sets a lock where none is set asks for, on every writer.
pub const LOCK_SET_CONFIRM: Confirm<'static> = Confirm::titled("Set config lock?");

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

/// Build the READ CONFIG TLV: a leading overall-length byte, then
/// USB_SUPPORTED / SERIAL / FORM_FACTOR / VERSION, then the persisted `EF_DEV_CONF`
/// blob (DEVICE_FLAGS added where it has none) or the default USB_ENABLED /
/// DEVICE_FLAGS, then CONFIG_LOCK. Public: the OTP applet serves it too (P1=0x13).
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
    push_tlv(&mut buf, &mut n, TAG_FORM_FACTOR, &[rsk_sdk::FORM_FACTOR]);
    let (maj, min, patch) = FIRMWARE_VERSION;
    push_tlv(&mut buf, &mut n, TAG_VERSION, &[maj, min, patch]);

    let mut conf = [0u8; EF_DEV_CONF_READ_MAX];
    // A stored record is validated on READ, not only on write. `well_formed_writable`
    // has only ever guarded the write path, so a record a **pre-`9171ccf` build**
    // accepted — a 1-byte `USB_ENABLED`, a duplicate tag — survived the upgrade and
    // kept being echoed, which is how one permanently hid the device from ykman
    // (audit run-34 #25). An unusable record falls back to the arm below, which
    // synthesises the echo from `read_enabled_caps` — so what is reported is what is
    // enforced by construction, for an unreadable record as much as an unparseable
    // one, instead of the two sides diverging.
    let stored = match fs.read(EF_DEV_CONF, &mut conf) {
        Some(full) if full > 0 && conf.get(..full).is_some_and(well_formed_writable) => Some(full),
        _ => None,
    };
    match stored {
        Some(full) if full > 0 => {
            // A host wrote an enabled-applications config — echo it back. Three
            // steps: (1) `Storage::read` reports the value's *full* length even
            // when it exceeds the buffer, so bound `len` before slicing — WRITE
            // CONFIG caps new writes, but a blob from an older build or corrupt
            // flash could be over-length and must not slice past `conf`/`buf`;
            // (2) strip any config-lock tag before echoing — a record a build
            // before 0.4.5 wrote can still carry the 16-byte code the user typed,
            // which must never reach an unauthenticated reader (audit run-30);
            // (3) mask USB_ENABLED down to what this firmware supports, so READ
            // CONFIG never reports enabled ⊄ supported.
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
            let stored = conf.get(..len).unwrap_or_default();
            let stripped = strip_config_lock(stored, &mut echoed).min(room);
            // …and to whole entries. Every bound above is a byte count, so any of
            // them can land inside a TLV; emitting the head of one is precisely the
            // unparseable DeviceInfo this response must never produce. Only a record
            // an older build stored (or corrupt flash) can reach the cut.
            let elen = whole_tlvs(echoed.get(..stripped).unwrap_or_default());
            if let (Some(dst), Some(src)) = (buf.get_mut(n..n + elen), echoed.get(..elen)) {
                dst.copy_from_slice(src);
                clamp_usb_enabled(dst);
            }
            n = push_device_flags_if_absent(&mut buf, n, n + elen, taken);
            // Whether a code is set, never the code, as a YubiKey reports it.
            push_tlv(&mut buf, &mut n, TAG_CONFIG_LOCK, &[lock_reported(fs)]);
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
            push_tlv(&mut buf, &mut n, TAG_DEVICE_FLAGS, &[DEVICE_FLAGS_FACTORY]);
            push_tlv(&mut buf, &mut n, TAG_CONFIG_LOCK, &[lock_reported(fs)]);
        }
    }

    let Ok(overall) = u8::try_from(n - 1) else {
        return Sw::EXEC_ERROR;
    };
    buf[0] = overall;
    let Some(body) = buf.get(..n) else {
        return Sw::EXEC_ERROR;
    };
    if !res.extend(body) {
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
    /// The flash access failed — the write, or the read of the record it merges
    /// onto (see `overlay_dev_conf`), or of the lock.
    Store,
    /// A configuration lock is set and the write carried no `UNLOCK` code.
    Locked,
    /// The write's `UNLOCK` code is not the one the lock was set with.
    WrongCode,
    /// The write sets a lock where none is set, and the touch that takes was not
    /// given.
    NotConfirmed,
}

impl DevConfError {
    /// The status word a CCID or OTP-slot write answers: a YubiKey 5.8.0's `6986`
    /// for a locked device written without its code, `63C0` for a wrong one.
    pub fn sw(self) -> Sw {
        match self {
            Self::TooLong | Self::BadTlv => Sw::WRONG_DATA,
            Self::Store => Sw::MEMORY_FAILURE,
            Self::Locked => Sw::COMMAND_NOT_ALLOWED,
            Self::WrongCode => Sw::retries(0),
            Self::NotConfirmed => Sw::CONDITIONS_NOT_SATISFIED,
        }
    }
}

/// Validate and persist the device-config TLV to `EF_DEV_CONF` — the
/// transport-agnostic core of WRITE CONFIG, shared by the CCID applet and the
/// FIDO vendor config-write (`rsk-mgmt` / `rsk-fido`). `blob` is
/// the enabled-applications TLV *without* any transport length prefix; the caller
/// applies its own auth gate (CCID presence, FIDO PIN + touch) before this; the
/// configuration lock is checked here, for all four. `serial` is the DeviceInfo
/// serial, which salts the lock's verifier. `confirm` asks for a touch
/// ([`LOCK_SET_CONFIRM`]), and only a write that sets a lock where none is set asks.
/// Refines `RSKeyAdminSurface!DisableSetSurvivesLockWrite` — SEC-ADM-003.
pub fn persist_dev_conf<S: Storage>(
    serial: &[u8; 4],
    fs: &mut Fs<S>,
    blob: &[u8],
    confirm: &mut dyn FnMut() -> bool,
) -> Result<(), DevConfError> {
    if blob.len() > DEV_CONF_WRITE_MAX {
        return Err(DevConfError::TooLong);
    }
    if !well_formed_writable(blob) {
        return Err(DevConfError::BadTlv);
    }
    // Asked before anything is compared or stored: a locked device refuses a write
    // without its code even when the write would change nothing.
    let lock = lock_change(serial, fs, blob)?;
    // Never retain the lock tags (see `strip_config_lock`): the lock keeps only a
    // verifier, and READ CONFIG echoes this blob to any unauthenticated host (audit
    // run-30).
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
    let m = merged_dev_conf(fs, stripped.get(..n).unwrap_or_default(), &mut merged)?;
    let Some(record) = merged.get(..m).filter(|_| m <= EF_DEV_CONF_MAX) else {
        return Err(DevConfError::TooLong);
    };
    // Set by a hostile host, a lock shuts its owner out of every config change until
    // a factory wipe, and a YubiKey asks nothing here: the one step past parity.
    if matches!(lock, LockChange::Arm(_)) && !confirm() {
        return Err(DevConfError::NotConfirmed);
    }
    // An idempotent write costs no flash and no audit-journal entry. Folded in here
    // rather than left to the caller: only one of the four call sites ever ran the
    // check, and after the merge landed it could not recognise a partial replay at
    // all, which is the only shape ykman sends (audit run-36).
    if !stored_matches(fs, record) {
        fs.put(EF_DEV_CONF, record)
            .map_err(|_| DevConfError::Store)?;
        // The enabled-applications set changed; the firmware reloads its cached mask
        // (which gates applet dispatch) before the next command it guards.
        DEV_CONF_DIRTY.store(true, core::sync::atomic::Ordering::Relaxed);
    }
    // The record lands before the lock moves, so a cut between the two leaves a state
    // the same request completes when retried: lock first, the retry would meet a
    // lock the host does not know it set.
    lock.apply(fs)
}

/// Drop the configuration-lock code a build before 0.4.5 stored verbatim in
/// `EF_DEV_CONF`: audit run-30 stopped storing it but left what was there, a secret
/// the owner typed, at rest in plaintext. The at-rest scrub is re-armed before the
/// write, per [`rsk_fs::request_rescrub`], so the lap erases the superseded copy too.
/// A record with no lock tag is left alone; one wider than a read reaches is too,
/// since writing back its readable head would cut it.
pub fn scrub_legacy_lock<S: Storage>(fs: &mut Fs<S>) -> Result<(), DevConfError> {
    let mut stored = [0u8; EF_DEV_CONF_READ_MAX];
    let n = match fs.try_read(EF_DEV_CONF, &mut stored) {
        Ok(Some(n)) if n <= EF_DEV_CONF_READ_MAX => n,
        Ok(_) => return Ok(()),
        Err(_) => return Err(DevConfError::Store),
    };
    let stored = stored.get(..n).unwrap_or_default();
    if !has_tag(stored, TAG_CONFIG_LOCK) && !has_tag(stored, TAG_CONFIG_UNLOCK) {
        return Ok(());
    }
    let mut kept = [0u8; EF_DEV_CONF_READ_MAX];
    let m = strip_config_lock(stored, &mut kept);
    let rearmed = rsk_fs::request_rescrub(fs).map_err(|_| DevConfError::Store)?;
    fs.put_over(
        EF_DEV_CONF,
        kept.get(..m).unwrap_or_default(),
        Some(&rearmed),
    )
    .map_err(|_| DevConfError::Store)
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
        let stored = merged.get(..m - keep).unwrap_or_default();
        let mut i = 0;
        let victim = loop {
            let Some((tag, end)) = entry_at(stored, i) else {
                break None;
            };
            if tag != TAG_USB_ENABLED {
                break Some((i, end - i));
            }
            i = end;
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
        Some(c) if c == want.len() && cur.get(..c) == Some(want))
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
    // Three answers, not two. ABSENT (`Ok(None)`) merges onto nothing, so the
    // request becomes the record — a first write. UNPARSEABLE keeps only the whole
    // TLV prefix below, so the tail an older, laxer build wrote is replaced; that is
    // what the previous behaviour did for every input and is still right for bytes
    // no parser can attribute to a tag. FAULTED is neither: merging onto nothing
    // turns ykman's one-field delta into a REPLACEMENT that discards every other
    // setting the owner wrote, so refusing is the only answer that cannot lose data.
    let stored_n = match fs.try_read(EF_DEV_CONF, &mut stored) {
        Ok(n) => n.unwrap_or(0).min(EF_DEV_CONF_READ_MAX),
        Err(_) => return Err(DevConfError::Store),
    };
    let stored = stored.get(..stored_n).unwrap_or_default();
    let stored = stored.get(..whole_tlvs(stored)).unwrap_or_default();

    let mut n = 0usize;
    let mut push = |src: &[u8], out: &mut [u8]| -> Result<(), DevConfError> {
        let Some(dst) = out.get_mut(n..n + src.len()) else {
            return Err(DevConfError::TooLong);
        };
        dst.copy_from_slice(src);
        n += src.len();
        Ok(())
    };
    // Stored entries first, minus any tag the request restates and any lock tag: a
    // build before 0.4.5 stored the code verbatim, and a merge must not carry it on.
    let mut i = 0;
    while let Some((tag, end)) = entry_at(stored, i) {
        if !has_tag(incoming, tag) && tag != TAG_CONFIG_LOCK && tag != TAG_CONFIG_UNLOCK {
            push(stored.get(i..end).unwrap_or_default(), out)?;
        }
        i = end;
    }
    push(incoming, out)?;
    Ok(n)
}

/// Whether a well-formed TLV run carries an entry with `tag`.
fn has_tag(blob: &[u8], tag: u8) -> bool {
    tag_value(blob, tag).is_some()
}

/// The value of the first entry with `tag` in a TLV run.
fn tag_value(blob: &[u8], tag: u8) -> Option<&[u8]> {
    let mut i = 0;
    while let Some((t, end)) = entry_at(blob, i) {
        if t == tag {
            return blob.get(i + 2..end);
        }
        i = end;
    }
    None
}

/// The short-form TLV entry at `i`: its tag and the offset just past its value, or
/// `None` at the end of `blob` or where the entry's length runs past it.
fn entry_at(blob: &[u8], i: usize) -> Option<(u8, usize)> {
    let &[tag, len] = blob.get(i..)?.first_chunk::<2>()?;
    let end = i + 2 + len as usize;
    (end <= blob.len()).then_some((tag, end))
}

/// Whether `blob` is a clean run of TLV entries whose every tag a host may write.
/// Empty is fine (it clears the record). Rejecting here rather than sanitizing on
/// read keeps one definition of "what a host may store" and means READ CONFIG can
/// go on echoing the stored bytes verbatim.
fn well_formed_writable(blob: &[u8]) -> bool {
    let mut i = 0;
    let mut seen = [0u8; 16];
    let mut seen_n = 0;
    while i < blob.len() {
        let Some(&[tag, len]) = blob.get(i..).and_then(<[u8]>::first_chunk::<2>) else {
            return false; // truncated header
        };
        let Some(end) = i.checked_add(2).and_then(|h| h.checked_add(len as usize)) else {
            return false;
        };
        if end > blob.len() || !writable_tag(tag) {
            return false;
        }
        // One entry per tag. A real YubiKey emits each exactly once; a duplicate
        // makes this device (first-wins, `enabled_from_conf`) and ykman (last-wins,
        // `Tlv.parse_dict`) disagree about what was just stored.
        if seen.get(..seen_n).is_some_and(|seen| seen.contains(&tag)) {
            return false;
        }
        let Some(slot) = seen.get_mut(seen_n) else {
            return false; // more distinct tags than the writable set has
        };
        *slot = tag;
        seen_n += 1;
        // `enabled_from_conf` and `clamp_usb_enabled` both act only on a two-byte
        // value, so any other width would store a mask the device silently ignores
        // while a host parser reads it — including one wide enough to escape the
        // "enabled ⊆ supported" clamp entirely.
        if tag == TAG_USB_ENABLED && len != 2 {
            return false;
        }
        // A lock code is exact too. The lock hashes what it is given, so a shorter
        // one would set a lock ykman, which always sends sixteen bytes, cannot open.
        if (tag == TAG_CONFIG_LOCK || tag == TAG_CONFIG_UNLOCK) && len as usize != LOCK_CODE_LEN {
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

/// The widest value ykman can put in each writable tag, or `None` where the width is
/// EXACT instead, a rule kept at the call site: the two lock tags' 16-byte codes, and
/// `USB_ENABLED`, which relaxed to a maximum would let a stored `03 00` be echoed by
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
    while let Some((_, end)) = entry_at(blob, i) {
        i = end;
    }
    i
}

/// Copy `blob` minus any CONFIG_LOCK (0x0A) / UNLOCK (0x0B) TLV entry into `out`,
/// returning the stripped length. The lock keeps a verifier of its code in its own
/// record ([`lock`]), and READ CONFIG echoes this blob verbatim to any unauthenticated
/// host over three transports, so retaining a 16-byte lock code here would hand back
/// a secret the user typed — real hardware treats 0x0A as write-only. If the TLV does
/// not parse cleanly the blob is copied unchanged, so a config we do not understand is
/// never corrupted (an attacker's own malformed write is readable by them regardless).
/// `out` must be at least `blob.len()` bytes.
fn strip_config_lock(blob: &[u8], out: &mut [u8]) -> usize {
    let mut i = 0;
    let mut n = 0;
    while i < blob.len() {
        let Some((tag, end)) = entry_at(blob, i) else {
            if let Some(dst) = out.get_mut(..blob.len()) {
                dst.copy_from_slice(blob);
            }
            return blob.len();
        };
        if tag != TAG_CONFIG_LOCK && tag != TAG_CONFIG_UNLOCK {
            if let (Some(dst), Some(src)) = (out.get_mut(n..n + (end - i)), blob.get(i..end)) {
                dst.copy_from_slice(src);
            }
            n += end - i;
        }
        i = end;
    }
    n
}

/// Whether `EF_DEV_CONF` already holds exactly `blob`, so a WRITE CONFIG carrying
/// it would change nothing. The FIDO vendor `CONFIG_WRITE` asks here rather than
/// comparing for itself: it skips the flash write *and* its audit-journal entry on
/// an idempotent replay, which a silent host could otherwise use to evict the whole
/// ring. `serial` salts the lock's verifier, as for [`persist_dev_conf`].
pub fn dev_conf_unchanged<S: Storage>(serial: &[u8; 4], fs: &mut Fs<S>, blob: &[u8]) -> bool {
    // Request-side bound: this takes the blob as sent, lock tags included.
    if blob.len() > DEV_CONF_WRITE_MAX {
        return false;
    }
    // A write the lock refuses, or one that moves it, is never a replay: the writer
    // must see it, to answer the refusal or to store the new verifier.
    if !matches!(lock_change(serial, fs, blob), Ok(LockChange::Keep)) {
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
    let Ok(m) = merged_dev_conf(fs, stripped.get(..n).unwrap_or_default(), &mut merged) else {
        return false;
    };
    merged
        .get(..m)
        .is_some_and(|record| stored_matches(fs, record))
}

/// Set by [`persist_dev_conf`] on any successful write, drained by the firmware to
/// know when to reload its cached enabled-capability mask. Same swap-to-consume
/// latch as the device-reset request; enforcement is build-agnostic (a
/// `strict-config` build still honours a persisted config), so this is ungated.
static DEV_CONF_DIRTY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Whether `fid` decides which applets a host may reach, so the device-wide wipe
/// removes it last: once a lock code is set these records are the only gate on the
/// OTP slots, whose secrets type on a touch as soon as `CAP_OTP` is back.
pub fn is_devconf_gate_fid(fid: u16) -> bool {
    fid == EF_DEV_CONF || fid == lock::EF_DEV_LOCK
}

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
    while let Some((tag, end)) = entry_at(conf, i) {
        if tag == TAG_USB_ENABLED
            && end - i == 4
            && let Some(&mask) = conf.get(i + 2..end).and_then(<[u8]>::first_chunk::<2>)
        {
            return u16::from_be_bytes(mask) & SUPPORTED_CAPS;
        }
        i = end;
    }
    SUPPORTED_CAPS
}

/// Read `EF_DEV_CONF` and return its enabled-applications mask ([`enabled_from_conf`]).
/// The firmware caches this and re-reads it when [`take_dev_conf_dirty`] fires.
///
/// No record, or an empty one, is the factory default: everything supported is
/// enabled. A probe the backend could not answer is NOT that absence: it enables
/// nothing gated, because resolving it permissively re-enabled every application
/// the owner had disabled. Failing closed is recoverable in the direction that
/// matters — [`cap_enabled`] keeps management, vendor and rescue selectable at
/// `cap == 0`, so the owner can still rewrite the record, and the next boot or
/// config write re-reads flash.
pub fn read_enabled_caps<S: Storage>(fs: &mut Fs<S>) -> u16 {
    // The read width, not the write cap: a pre-cap build's larger record must still
    // be scanned whole, or a disabled applet silently comes back after the upgrade.
    let mut conf = [0u8; EF_DEV_CONF_READ_MAX];
    match fs.try_read(EF_DEV_CONF, &mut conf) {
        Ok(Some(full)) if full > 0 => {
            enabled_from_conf(conf.get(..full.min(conf.len())).unwrap_or_default())
        }
        Ok(_) => SUPPORTED_CAPS,
        Err(_) => NO_CAPS,
    }
    // Deliberately NOT gated on `well_formed_writable`, unlike the echo: this walk
    // is already defensive (a `USB_ENABLED` that is not exactly two bytes is
    // skipped), and refusing to honour a record it cannot *fully* validate would
    // silently re-enable applets the owner disabled. The echo is normalised to this
    // answer instead (audit run-34 #25).
}

/// What a `EF_DEV_CONF` probe the backend could not answer enables: nothing gated.
/// The argument for the direction is on [`read_enabled_caps`], its one caller.
const NO_CAPS: u16 = 0;

/// Whether an applet guarded by capability bit `cap` is enabled under `mask`.
/// `cap == 0` marks an always-available applet (management, vendor, rescue) — the
/// re-enable path must never be gated off, or a disable becomes irreversible.
pub fn cap_enabled(mask: u16, cap: u16) -> bool {
    cap == 0 || mask & cap != 0
}

/// Clamp any USB_ENABLED (`0x03`) TLV in a persisted config blob to
/// `SUPPORTED_CAPS`, so READ CONFIG never reports an enabled capability this
/// firmware does not implement. A real YubiKey guarantees enabled ⊆ supported;
/// RS-Key echoes the host-written `EF_DEV_CONF` blob, which could carry a wider
/// mask (a newer host that knows capability bits we lack). Walks short-form
/// TLVs in place; a malformed length stops the walk, leaving the rest untouched.
fn clamp_usb_enabled(blob: &mut [u8]) {
    let mut i = 0;
    while let Some((tag, end)) = entry_at(blob, i) {
        if tag == TAG_USB_ENABLED
            && end - i == 4
            && let Some(mask) = blob
                .get_mut(i + 2..end)
                .and_then(<[u8]>::first_chunk_mut::<2>)
        {
            *mask = (u16::from_be_bytes(*mask) & SUPPORTED_CAPS).to_be_bytes();
        }
        i = end;
    }
}

/// The `DEVICE_FLAGS` entry [`push_device_flags_if_absent`] may add to an echo.
const DEVICE_FLAGS_TLV_LEN: usize = 2 + 1;

/// A YubiKey reports `DEVICE_FLAGS` in every DeviceInfo; an echo `buf[start..end]`
/// without it gets the factory byte, where the body still fits `room` and the
/// smallest transport's frame, so every transport answers alike. Returns the new end.
fn push_device_flags_if_absent(buf: &mut [u8], start: usize, end: usize, room: usize) -> usize {
    let mut n = end;
    let echo = buf.get(start..end).unwrap_or_default();
    if !has_tag(echo, TAG_DEVICE_FLAGS)
        && end + DEVICE_FLAGS_TLV_LEN + CONFIG_LOCK_TLV_LEN <= room.min(MIN_CONFIG_RES_CAP)
    {
        push_tlv(buf, &mut n, TAG_DEVICE_FLAGS, &[DEVICE_FLAGS_FACTORY]);
    }
    n
}

/// Append a `tag, len, value` TLV; silently truncated by the fixed `read_config`
/// buffer (sized for the largest config, so this never actually overflows).
fn push_tlv(buf: &mut [u8], n: &mut usize, tag: u8, val: &[u8]) {
    let Ok(len) = u8::try_from(val.len()) else {
        return;
    };
    let Some(entry) = buf.get_mut(*n..*n + 2 + val.len()) else {
        return;
    };
    let Some((head, value)) = entry.split_first_chunk_mut::<2>() else {
        return;
    };
    *head = [tag, len];
    value.copy_from_slice(val);
    *n += 2 + val.len();
}

/// The record's raw vocabulary — the FID, the stored-size cap and the DeviceInfo
/// tag numbers — for tests and fuzz harnesses that must seed a record no accepted
/// write can produce (a pre-cap legacy blob, a device-owned tag).
///
/// Dev-only, so no firmware image can name the FID: this codec stays the only
/// writer of a record that survives `authenticatorReset`, which an unparseable
/// value would hide the device behind for good (audit run-33). `rsk-phy` keeps
/// its own tag set crate-private for the same reason.
#[cfg(any(test, feature = "test-util"))]
pub mod raw {
    pub const EF_DEV_CONF: u16 = super::EF_DEV_CONF;
    pub const EF_DEV_LOCK: u16 = super::lock::EF_DEV_LOCK;
    pub const EF_DEV_CONF_MAX: usize = super::EF_DEV_CONF_MAX;
    pub const TAG_USB_SUPPORTED: u8 = super::TAG_USB_SUPPORTED;
    pub const TAG_SERIAL: u8 = super::TAG_SERIAL;
    pub const TAG_USB_ENABLED: u8 = super::TAG_USB_ENABLED;
    pub const TAG_FORM_FACTOR: u8 = super::TAG_FORM_FACTOR;
    pub const TAG_VERSION: u8 = super::TAG_VERSION;
    pub const TAG_DEVICE_FLAGS: u8 = super::TAG_DEVICE_FLAGS;
    pub const TAG_CONFIG_LOCK: u8 = super::TAG_CONFIG_LOCK;
    pub const TAG_CONFIG_UNLOCK: u8 = super::TAG_CONFIG_UNLOCK;
    pub const TAG_AUTO_EJECT_TIMEOUT: u8 = super::TAG_AUTO_EJECT_TIMEOUT;
    pub const TAG_CHALRESP_TIMEOUT: u8 = super::TAG_CHALRESP_TIMEOUT;
    pub const TAG_REBOOT: u8 = super::TAG_REBOOT;
    pub const TAG_NFC_ENABLED: u8 = super::TAG_NFC_ENABLED;
    pub const TAG_NFC_RESTRICTED: u8 = super::TAG_NFC_RESTRICTED;
}

/// [`persist_dev_conf`] with its touch given, as a present owner gives it: for the
/// tests and harnesses that set a lock, and the many writes that never ask.
#[cfg(any(test, feature = "test-util"))]
pub fn persist_touched<S: Storage>(
    serial: &[u8; 4],
    fs: &mut Fs<S>,
    blob: &[u8],
) -> Result<(), DevConfError> {
    persist_dev_conf(serial, fs, blob, &mut || true)
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    reason = "a test's fixture is its own bound, and a panic is its failure report"
)]
mod tests;
