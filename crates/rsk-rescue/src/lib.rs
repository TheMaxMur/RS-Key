// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Rescue applet — the recovery / provisioning CCID interface under its own AID:
//! KEYDEV_SIGN 0x10 (device attestation), WRITE 0x1C (phy record, RTC time), READ
//! 0x1E (phy / flash stats / secure-boot status / time / anti-rollback state),
//! REBOOT 0x1F, OTP_LOCK 0x1B (one-way fuse writes: page-58 lock, rollback-required).

#![cfg_attr(not(test), no_std)]

pub mod keydev;
pub mod otp_lock;
pub mod rollback;

use core::cell::RefCell;

use rsk_crypto::{Device, FusedKey, FusedRead, read_fused};
use rsk_fs::{Fs, Storage};
// The randomness and the presence check gating the privileged rescue commands
// (attestation sign, cert write, phy/identity write, reboot-to-BOOTSEL) against
// a hostile USB host are `rsk-sdk`'s seams, shared with every sibling applet.
pub use rsk_sdk::{AlwaysConfirm, Confirm, Presence, Rng, UserPresence};
use rsk_sdk::{Apdu, Applet, ResBuf, Sw};

/// Rescue applet AID.
pub const RESCUE_AID: &[u8] = &[0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x21];

// SELECT response identity: MCU, product, SDK version.
const MCU_RP2350: u8 = 1;
const PRODUCT_FIDO: u8 = 2;
const SDK_VERSION_MAJOR: u8 = 8;
const SDK_VERSION_MINOR: u8 = 6;

const INS_KEYDEV_SIGN: u8 = 0x10;
const INS_OTP_LOCK: u8 = 0x1B;
const INS_WRITE: u8 = 0x1C;
const INS_READ: u8 = 0x1E;
const INS_REBOOT_BOOTSEL: u8 = 0x1F;

/// OTP_LOCK payload guard: the irreversible page-58 lock fires only for this
/// exact data, so a stray or fuzzed APDU on INS 0x1B can never trigger it.
const OTP_LOCK_MAGIC: &[u8] = b"LOCK58";

/// OTP_LOCK P1=0x48 payload guard, same idea: the irreversible
/// ROLLBACK_REQUIRED fuse fires only for this exact data.
const ROLLBACK_MAGIC: &[u8] = b"ROLLBK";

/// READ P1=0x03 result.
pub struct SecureBootStatus {
    pub enabled: bool,
    pub locked: bool,
    /// Valid boot-key slot index, 0xFF when none.
    pub bootkey: u8,
}

/// Firmware-side services the applet needs: OTP secure-boot status (read-only),
/// the session RTC, and the deferred reboot (executed by the worker after the
/// response has flushed).
pub trait Platform {
    fn secure_boot_status(&self) -> SecureBootStatus;
    /// Seconds since the epoch; `None` until set this power cycle (the RTC is
    /// not battery-backed).
    fn now(&self) -> Option<u32>;
    fn set_time(&mut self, epoch: u32);
    fn request_reboot(&mut self, bootsel: bool);
    /// Raw 24-bit value of PAGE58_LOCK1; `None` on a read error. Drives the
    /// idempotency / refuse-foreign decision in [`otp_lock`].
    fn read_page58_lock_raw(&self) -> Option<u32>;
    /// Burn the page-58 access lock ([`otp_lock::PAGE58_LOCK_VALUE`] into
    /// [`otp_lock::PAGE58_LOCK1_ROW`]). The implementation fixes both the row
    /// and the value, so a caller can never redirect this write. IRREVERSIBLE;
    /// returns whether it succeeded.
    fn lock_page58(&mut self) -> bool;
    /// Raw RBIT-3 copies of the anti-rollback rows ([`rollback`]); `None` on
    /// any read error. Drives the idempotency decision and the READ report.
    fn read_rollback_raw(&self) -> Option<rollback::RollbackRaw>;
    /// Burn [`rollback::ROLLBACK_REQUIRED_BIT`] into every BOOT_FLAGS0 copy.
    /// The implementation fixes both the rows and the bit, so a caller can
    /// never redirect this write. IRREVERSIBLE; returns whether it succeeded.
    fn set_rollback_required(&mut self) -> bool;
}

pub struct RescueApplet<'a> {
    serial_id: [u8; 8],
    serial_hash: [u8; 32],
    /// How to read the OTP MKEK, once provisioned — never the key itself, so no
    /// copy of it sits in this applet's memory between operations.
    mkek_source: Option<FusedKey>,
    /// How to fetch the OTP DEVK (the keydev secp256k1 scalar), rather than the
    /// scalar itself: two rarely-run commands want it, and it is fused, so it is
    /// not one to park in RAM for the power cycle.
    devk: Option<FusedKey>,
    rng: &'a RefCell<dyn Rng>,
    platform: &'a RefCell<dyn Platform>,
    /// Touch/approval gate for the runtime-reachable privileged commands.
    presence: &'a RefCell<dyn UserPresence>,
    /// FLASH INFO `total`: the KV partition byte size.
    kv_total: u32,
    /// FLASH INFO `size`: the flash chip byte size.
    flash_size: u32,
}

impl<'a> RescueApplet<'a> {
    #[allow(clippy::too_many_arguments)] // boot-time wiring, mirrors CcidApplets::new
    pub fn new(
        serial_id: [u8; 8],
        serial_hash: [u8; 32],
        mkek_source: Option<FusedKey>,
        devk: Option<FusedKey>,
        rng: &'a RefCell<dyn Rng>,
        platform: &'a RefCell<dyn Platform>,
        presence: &'a RefCell<dyn UserPresence>,
        kv_total: u32,
        flash_size: u32,
    ) -> Self {
        Self {
            serial_id,
            serial_hash,
            mkek_source,
            devk,
            rng,
            platform,
            presence,
            kv_total,
            flash_size,
        }
    }

    fn device<'k>(&'k self, mkek: &'k FusedRead) -> Device<'k> {
        Device {
            serial_hash: &self.serial_hash,
            serial_id: &self.serial_id,
            otp_key: mkek.as_deref(),
        }
    }

    /// Require a physical user-presence confirmation before a privileged
    /// runtime operation. On the display build this renders a named Approve/Deny
    /// prompt; the BOOTSEL backend waits for a press. `true` only on Confirmed —
    /// a hostile USB host cannot drive these commands without the operator.
    /// Refines `RSKeyAdminSurface!PrivilegedOpNeedsPresence` — SEC-ADM-002.
    fn require_presence(&self, confirm: Confirm<'_>) -> bool {
        self.presence.borrow_mut().request(confirm) == Presence::Confirmed
    }

    fn keydev_sign<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        match apdu.p1 {
            0x01 => {
                if apdu.nc != 32 {
                    return Sw::WRONG_LENGTH;
                }
                // Attestation signing over a host-chosen digest is an oracle over
                // the device key; require the operator, not just the USB host.
                if !self.require_presence(Confirm::titled("Attestation sign?")) {
                    return Sw::CONDITIONS_NOT_SATISFIED;
                }
                let mut rng = self.rng.borrow_mut();
                // Both fuses are read for this command alone: each local is the
                // only copy in RAM and dies at the end of this arm.
                let fused = read_fused(self.devk);
                let mkek = read_fused(self.mkek_source);
                let dev = self.device(&mkek);
                let key = keydev::load_or_generate(&dev, fused.as_deref(), fs, &mut *rng);
                let Some(key) = key else {
                    return Sw::EXEC_ERROR;
                };
                let mut digest = [0u8; 32];
                digest.copy_from_slice(apdu.data);
                match keydev::sign_digest(&key, &digest) {
                    Some(sig) => {
                        res.extend(&sig);
                        Sw::OK
                    }
                    None => Sw::EXEC_ERROR,
                }
            }
            0x02 => {
                if apdu.nc != 0 {
                    return Sw::WRONG_LENGTH;
                }
                let mut rng = self.rng.borrow_mut();
                // Both fuses are read for this command alone: each local is the
                // only copy in RAM and dies at the end of this arm.
                let fused = read_fused(self.devk);
                let mkek = read_fused(self.mkek_source);
                let dev = self.device(&mkek);
                let key = keydev::load_or_generate(&dev, fused.as_deref(), fs, &mut *rng);
                let Some(key) = key else {
                    return Sw::EXEC_ERROR;
                };
                res.extend(&keydev::public_uncompressed(&key));
                Sw::OK
            }
            0x03 => {
                if apdu.nc == 0 {
                    return Sw::WRONG_LENGTH;
                }
                // Overwriting the device attestation certificate is device
                // identity — gate it behind the operator.
                if !self.require_presence(Confirm::titled("Write device cert?")) {
                    return Sw::CONDITIONS_NOT_SATISFIED;
                }
                if fs.put(keydev::EF_DEVCERT, apdu.data).is_err() {
                    return Sw::MEMORY_FAILURE;
                }
                Sw::OK
            }
            _ => Sw::INCORRECT_P1P2,
        }
    }

    fn write<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>) -> Sw {
        if apdu.nc < 2 {
            return Sw::WRONG_LENGTH;
        }
        match apdu.p1 {
            0x01 => {
                // The phy record is device identity (VID/PID, USB interfaces,
                // LED); a hostile host must not rewrite it silently.
                if !self.require_presence(Confirm::titled("Write device config?")) {
                    return Sw::CONDITIONS_NOT_SATISFIED;
                }
                // Read-modify-write merge: a partial record overlays the stored one
                // (a host that sends only changed tags can't wipe the rest).
                if rsk_phy::merge_save(fs, apdu.data).is_err() {
                    return Sw::EXEC_ERROR;
                }
                Sw::OK
            }
            0x02 => {
                let epoch = match apdu.p2 {
                    0x01 => {
                        if apdu.nc != 8 {
                            return Sw::WRONG_LENGTH;
                        }
                        let d = apdu.data;
                        let year = u16::from_be_bytes([d[0], d[1]]) as i64;
                        // d[4] is tm_wday — ignored on set, like mktime.
                        match epoch_from_civil(year, d[2], d[3], d[5], d[6], d[7]) {
                            Some(t) => t,
                            None => return Sw::DATA_INVALID,
                        }
                    }
                    0x02 => {
                        if apdu.nc != 4 {
                            return Sw::WRONG_LENGTH;
                        }
                        u32::from_be_bytes([apdu.data[0], apdu.data[1], apdu.data[2], apdu.data[3]])
                    }
                    _ => return Sw::INCORRECT_P1P2,
                };
                self.platform.borrow_mut().set_time(epoch);
                Sw::OK
            }
            // Refuse a selector this build does not implement. The comment here
            // used to read "an unknown P1 is a no-op OK", framed as forward
            // compatibility — but for a WRITE that is backwards. This is the
            // PROVISIONING path: P1=0x01 writes the phy record, i.e. VID/PID, the
            // USB interfaces and the LED, the device's identity. A newer `rsk` or
            // PicoForge against older firmware sends a selector that firmware does
            // not know, is told the write landed, and the operator moves on
            // believing the device is provisioned. Silent success is exactly what
            // stops a host detecting the version mismatch, which is what 0x6A86
            // exists for — and the inner P2 dispatch and `keydev_sign` right above
            // already answer that way, so only this one arm disagreed.
            _ => Sw::INCORRECT_P1P2,
        }
    }

    fn read<S: Storage>(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        if apdu.nc != 0 {
            return Sw::WRONG_LENGTH;
        }
        match apdu.p1 {
            0x01 => {
                // A never-written phy serializes to just the zeroed OPTS TLV.
                let data = rsk_phy::load(fs).unwrap_or_default();
                let mut buf = [0u8; rsk_phy::PHY_MAX_SIZE];
                match data.serialize(&mut buf) {
                    Some(n) => {
                        res.extend(&buf[..n]);
                        Sw::OK
                    }
                    None => Sw::EXEC_ERROR,
                }
            }
            0x02 => {
                let (nfiles, used) = fs_usage(fs);
                let free = self.kv_total.saturating_sub(used);
                res.extend(&free.to_be_bytes());
                res.extend(&used.to_be_bytes());
                res.extend(&self.kv_total.to_be_bytes());
                res.extend(&nfiles.to_be_bytes());
                res.extend(&self.flash_size.to_be_bytes());
                Sw::OK
            }
            0x03 => {
                let st = self.platform.borrow().secure_boot_status();
                res.extend(&[st.enabled as u8, st.locked as u8, st.bootkey]);
                Sw::OK
            }
            0x04 => {
                if apdu.p2 != 0x01 && apdu.p2 != 0x02 {
                    return Sw::INCORRECT_P1P2;
                }
                let Some(t) = self.platform.borrow().now() else {
                    return Sw::CONDITIONS_NOT_SATISFIED;
                };
                if apdu.p2 == 0x01 {
                    let c = civil_from_epoch(t);
                    res.extend(&c.year.to_be_bytes());
                    res.extend(&[c.mon0, c.mday, c.wday, c.hour, c.min, c.sec]);
                } else {
                    res.extend(&t.to_be_bytes());
                }
                Sw::OK
            }
            // 0x05 (trust digest) is deliberately not implemented.
            0x06 => {
                let Some(raw) = self.platform.borrow().read_rollback_raw() else {
                    return Sw::EXEC_ERROR;
                };
                let required = rollback::required(rollback::majority(raw.flags0));
                let version = rollback::version_count(
                    rollback::majority(raw.version0),
                    rollback::majority(raw.version1),
                );
                res.extend(&[required as u8, version, rollback::VERSION_CAPACITY]);
                Sw::OK
            }
            _ => Sw::INCORRECT_P1P2,
        }
    }

    fn reboot(&mut self, apdu: &Apdu) -> Sw {
        if apdu.nc != 0 {
            return Sw::WRONG_LENGTH;
        }
        match apdu.p1 {
            0x01 => {
                // Reboot-to-BOOTSEL drops the device into the mass-storage
                // bootloader, aiding an at-rest flash/OTP dump — require the
                // operator. A plain restart (P1=0x00) stays ungated.
                if !self.require_presence(Confirm::titled("Reboot to BOOTSEL?")) {
                    return Sw::CONDITIONS_NOT_SATISFIED;
                }
                self.platform.borrow_mut().request_reboot(true)
            }
            0x00 => self.platform.borrow_mut().request_reboot(false),
            _ => return Sw::INCORRECT_P1P2,
        }
        Sw::OK
    }

    /// INS 0x1B: the one-way OTP writes only secure firmware can perform, one
    /// per P1 (= the OTP row being targeted), each double-keyed by its own
    /// magic payload so a stray or fuzzed APDU can never burn a fuse.
    fn otp_lock(&mut self, apdu: &Apdu) -> Sw {
        if apdu.p2 != 0x00 {
            return Sw::INCORRECT_P1P2;
        }
        match apdu.p1 {
            0x58 => self.lock_page58(apdu),
            0x48 => self.rollback_require(apdu),
            _ => Sw::INCORRECT_P1P2,
        }
    }

    /// Apply the permanent page-58 access lock from secure firmware — host
    /// tooling cannot (the lock row lives in bootloader-read-only OTP page 63).
    /// IRREVERSIBLE, so it is triply guarded: P1=0x58 (the page), the
    /// [`OTP_LOCK_MAGIC`] payload, and a provisioned MKEK (locking a blank
    /// page would only hide nothing while blinding BOOTSEL). Idempotent: a row
    /// already holding our value returns OK; any other non-blank value is
    /// refused rather than clobbered. See [`otp_lock`].
    fn lock_page58(&mut self, apdu: &Apdu) -> Sw {
        if apdu.data != OTP_LOCK_MAGIC {
            return Sw::DATA_INVALID;
        }
        // Reads the fuses, not the source: firmware always wires a reader, so
        // testing the `Option` would answer "is a reader present" instead of "are
        // the keys provisioned" — and this guard is the whole reason the lock
        // cannot be burnt over a blank page (audit run-36).
        if read_fused(self.mkek_source).is_none() {
            return Sw::CONDITIONS_NOT_SATISFIED;
        }
        let Some(cur) = self.platform.borrow().read_page58_lock_raw() else {
            return Sw::EXEC_ERROR;
        };
        match otp_lock::lock_decision(cur) {
            otp_lock::LockDecision::AlreadyLocked => Sw::OK,
            otp_lock::LockDecision::Unexpected => Sw::CONDITIONS_NOT_SATISFIED,
            otp_lock::LockDecision::Write => {
                // Irreversible fuse burn: gate on the operator like every other
                // privileged rescue op — the magic payload is a source-visible
                // constant, not authentication against a hostile USB host.
                if !self.require_presence(Confirm::titled("Lock OTP page 58?")) {
                    return Sw::CONDITIONS_NOT_SATISFIED;
                }
                if !self.platform.borrow_mut().lock_page58() {
                    return Sw::EXEC_ERROR;
                }
                // Confirm the fuse took with a raw read-back.
                match self.platform.borrow().read_page58_lock_raw() {
                    Some(otp_lock::PAGE58_LOCK_VALUE) => Sw::OK,
                    _ => Sw::EXEC_ERROR,
                }
            }
        }
    }

    /// Fuse BOOT_FLAGS0.ROLLBACK_REQUIRED from secure firmware — on a board
    /// whose fuse pages are already bootloader-read-only (`rsk secure-boot
    /// lock`), host tooling cannot. IRREVERSIBLE, so it is triply guarded:
    /// P1=0x48 (the row), the [`ROLLBACK_MAGIC`] payload, and secure boot
    /// actually enabled — without enforcement the bit does nothing on this
    /// board, so burning it would be pointless fuse damage; with it, the
    /// command can only ever run from an image that itself passed the rollback
    /// check, which is exactly the safe ordering. Idempotent: already-fused
    /// (by 2-of-3 majority) returns OK without another write. See [`rollback`].
    fn rollback_require(&mut self, apdu: &Apdu) -> Sw {
        if apdu.data != ROLLBACK_MAGIC {
            return Sw::DATA_INVALID;
        }
        if !self.platform.borrow().secure_boot_status().enabled {
            return Sw::CONDITIONS_NOT_SATISFIED;
        }
        let Some(raw) = self.platform.borrow().read_rollback_raw() else {
            return Sw::EXEC_ERROR;
        };
        if rollback::required(rollback::majority(raw.flags0)) {
            return Sw::OK;
        }
        // Irreversible fuse burn: gate on the operator like every other
        // privileged rescue op (the magic payload is not authentication).
        if !self.require_presence(Confirm::titled("Require anti-rollback?")) {
            return Sw::CONDITIONS_NOT_SATISFIED;
        }
        if !self.platform.borrow_mut().set_rollback_required() {
            return Sw::EXEC_ERROR;
        }
        // Confirm the fuse took with a raw read-back of all three copies.
        match self.platform.borrow().read_rollback_raw() {
            Some(r) if rollback::required(rollback::majority(r.flags0)) => Sw::OK,
            _ => Sw::EXEC_ERROR,
        }
    }
}

impl<S: Storage> Applet<Fs<S>> for RescueApplet<'_> {
    fn aid(&self) -> &'static [u8] {
        RESCUE_AID
    }

    fn select(&mut self, _reselect: bool, _fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        res.extend(&[
            MCU_RP2350,
            PRODUCT_FIDO,
            SDK_VERSION_MAJOR,
            SDK_VERSION_MINOR,
        ]);
        res.extend(&self.serial_id);
        Sw::OK
    }

    fn process(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        if apdu.cla != 0x80 {
            return Sw::CLA_NOT_SUPPORTED;
        }
        match apdu.ins {
            INS_KEYDEV_SIGN => self.keydev_sign(apdu, fs, res),
            INS_OTP_LOCK => self.otp_lock(apdu),
            INS_WRITE => self.write(apdu, fs),
            INS_READ => self.read(apdu, fs, res),
            INS_REBOOT_BOOTSEL => self.reboot(apdu),
            _ => Sw::INS_NOT_SUPPORTED,
        }
    }
}

/// How many files FLASH INFO sums the sizes of. A window, not a limit: the store
/// holds `MAX_DYNAMIC_FILES` and the count below is always exact.
const FS_USAGE_WINDOW: usize = 512;

/// File count + summed payload bytes for FLASH INFO. Sizes are summed for the
/// first [`FS_USAGE_WINDOW`] files; the count is always exact.
fn fs_usage<S: Storage>(fs: &mut Fs<S>) -> (u32, u32) {
    let mut fids = [0u16; FS_USAGE_WINDOW];
    let mut nfiles = 0u32;
    fs.for_each_key(&mut |fid| {
        if (nfiles as usize) < fids.len() {
            fids[nfiles as usize] = fid;
        }
        nfiles += 1;
    });
    let mut used = 0u32;
    for &fid in &fids[..(nfiles as usize).min(fids.len())] {
        used += fs.size(fid).unwrap_or(0) as u32;
    }
    (nfiles, used)
}

struct Civil {
    year: u16,
    mon0: u8,
    mday: u8,
    /// 0 = Sunday, like `tm_wday`.
    wday: u8,
    hour: u8,
    min: u8,
    sec: u8,
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) as i64 + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Wire calendar (full year, 0-based month like `tm_mon`) to a u32 epoch.
fn epoch_from_civil(year: i64, mon0: u8, mday: u8, hour: u8, min: u8, sec: u8) -> Option<u32> {
    if mon0 > 11 || mday == 0 || mday > 31 || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let days = days_from_civil(year, mon0 as u32 + 1, mday as u32);
    let secs = days * 86400 + hour as i64 * 3600 + min as i64 * 60 + sec as i64;
    u32::try_from(secs).ok()
}

fn civil_from_epoch(t: u32) -> Civil {
    let days = (t / 86400) as i64;
    let rem = t % 86400;
    // Inverse of days_from_civil.
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    Civil {
        year: year as u16,
        mon0: (m - 1) as u8,
        mday: d as u8,
        wday: ((days + 4).rem_euclid(7)) as u8,
        hour: (rem / 3600) as u8,
        min: (rem % 3600 / 60) as u8,
        sec: (rem % 60) as u8,
    }
}

#[cfg(test)]
mod tests;
