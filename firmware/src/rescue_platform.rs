// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! [`rsk_rescue::Platform`] for the RP2350: read-only OTP secure-boot status (the
//! PAC's OTP_DATA_RAW alias), a session RTC carried as an epoch base plus uptime
//! (lost on power-cycle), the deferred reboot via the vendor applet's
//! pending-reboot slot (run by the worker after the response has flushed), and
//! the pass-throughs to [`crate::otp_keys`] for the two guarded one-way fuse
//! writes (page-58 lock, rollback-required).

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use rsk_rescue::{Platform, SecureBootStatus};

static TIME_SET: AtomicBool = AtomicBool::new(false);
/// What this boot's seal passes left under the pre-burn key; above `u16::MAX` until
/// a boot with the fused key has recorded it ([`record_pre_otp_left`]).
static PRE_OTP_LEFT: AtomicU32 = AtomicU32::new(PRE_OTP_UNRECORDED);
const PRE_OTP_UNRECORDED: u32 = u32::MAX;

/// Record what the boot's seal passes left under the pre-burn key, `None` for a boot
/// that ran them without the fused key; `lock_page58` reads it through the platform.
pub fn record_pre_otp_left(left: Option<u16>) {
    PRE_OTP_LEFT.store(
        left.map_or(PRE_OTP_UNRECORDED, u32::from),
        Ordering::Relaxed,
    );
}
static EPOCH_AT_SET: AtomicU32 = AtomicU32::new(0);
static UPTIME_AT_SET: AtomicU32 = AtomicU32::new(0);

fn uptime_secs() -> u32 {
    embassy_time::Instant::now().as_secs() as u32
}

pub struct RescuePlatform;

impl Platform for RescuePlatform {
    /// The BOOT_FLAGS1 valid-key flags are authoritative for "enabled" (the
    /// bootrom ignores a KEY_VALID bit without a real key). "Locked" additionally
    /// requires every other boot key invalidated, debug disabled, and the glitch
    /// detectors enabled at full sensitivity.
    fn secure_boot_status(&self) -> SecureBootStatus {
        use rp_pac::otp_data_raw::regs::{BootFlags1, Crit1};
        use rsk_rescue::rollback::majority;
        // Read the two gating OTP rows three times and 2-of-3 majority-vote each
        // bit. `locked`/`enabled` gate the irreversible fuse burns (page-58 lock,
        // ROLLBACK_REQUIRED), yet were decided from a single read of crit1 +
        // boot_flags1; a transient read fault on debug_disable / glitch_detector_*
        // could flip the verdict. Voting brings this read up to the RBIT-3 standard
        // the anti-rollback path already trusts (`rsk_rescue::rollback::majority`).
        let crit1 = Crit1(majority([
            rp_pac::OTP_DATA_RAW.crit1().read().0,
            rp_pac::OTP_DATA_RAW.crit1().read().0,
            rp_pac::OTP_DATA_RAW.crit1().read().0,
        ]));
        let flags1 = BootFlags1(majority([
            rp_pac::OTP_DATA_RAW.boot_flags1().read().0,
            rp_pac::OTP_DATA_RAW.boot_flags1().read().0,
            rp_pac::OTP_DATA_RAW.boot_flags1().read().0,
        ]));
        let valid = flags1.key_valid() & 0x0F;
        let bootkey = (0..4u8).find(|i| valid & (1 << i) != 0);
        let enabled = crit1.secure_boot_enable() && bootkey.is_some();
        let locked = enabled && {
            let bk = bootkey.unwrap();
            let others = 0x0F & !(1 << bk);
            (flags1.key_invalid() & others) == others
                && crit1.debug_disable()
                && crit1.glitch_detector_enable()
                && crit1.glitch_detector_sens() == 3
        };
        SecureBootStatus {
            enabled,
            locked,
            bootkey: bootkey.unwrap_or(0xFF),
        }
    }

    fn now(&self) -> Option<u32> {
        if !TIME_SET.load(Ordering::Relaxed) {
            return None;
        }
        let base = EPOCH_AT_SET.load(Ordering::Relaxed);
        let at = UPTIME_AT_SET.load(Ordering::Relaxed);
        Some(base.wrapping_add(uptime_secs().wrapping_sub(at)))
    }

    fn set_time(&mut self, epoch: u32) {
        EPOCH_AT_SET.store(epoch, Ordering::Relaxed);
        UPTIME_AT_SET.store(uptime_secs(), Ordering::Relaxed);
        TIME_SET.store(true, Ordering::Relaxed);
    }

    fn request_reboot(&mut self, bootsel: bool) {
        crate::vendor::request_reboot(bootsel);
    }

    fn read_page58_lock_raw(&self) -> Option<u32> {
        crate::otp_keys::read_page58_lock()
    }

    fn pre_otp_left(&self) -> Option<u16> {
        u16::try_from(PRE_OTP_LEFT.load(Ordering::Relaxed)).ok()
    }

    fn lock_page58(&mut self) -> bool {
        crate::otp_keys::apply_page58_lock()
    }

    fn read_rollback_raw(&self) -> Option<rsk_rescue::rollback::RollbackRaw> {
        crate::otp_keys::read_rollback_raw()
    }

    fn set_rollback_required(&mut self) -> bool {
        crate::otp_keys::apply_rollback_required()
    }
}
