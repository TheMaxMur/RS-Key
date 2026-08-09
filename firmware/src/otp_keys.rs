// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! READ-ONLY view of the two provisioned OTP keys (all of page 58):
//!
//!   DEVK @ rows 0xE80..=0xE8F — the rescue keydev secp256k1 scalar
//!   MKEK @ rows 0xE90..=0xE9F — the kbase root (`Device.otp_key`)
//!   chaff complements @ 0xEA0 / 0xEB0, hard page lock = PAGE58_LOCK1
//!
//! Key provisioning is a deliberate host-side picotool ritual; blank rows (the
//! factory state) read as `None` → the pre-OTP kbase arm, so this build is safe
//! on every board. The only things the firmware ever writes to OTP are the two
//! one-way fuses the host ritual cannot reach from BOOTSEL — the page-58
//! access lock ([`apply_page58_lock`], bootloader-read-only OTP page 63) and
//! BOOT_FLAGS0.ROLLBACK_REQUIRED ([`apply_rollback_required`], page 1 once
//! `rsk secure-boot lock` has made it bootloader-read-only) — each triggered
//! explicitly via the rescue applet, never at boot. `FAKE_MKEK` / `FAKE_DEVK`
//! (build.rs env) bake a fake key into the image INSTEAD of reading OTP — test
//! builds only.

use embassy_rp::otp;
use rsk_rescue::otp_lock::{PAGE58_LOCK_VALUE, PAGE58_LOCK1_ROW};
use rsk_rescue::rollback::{
    BOOT_FLAGS0_ROW, DEFAULT_BOOT_VERSION0_ROW, DEFAULT_BOOT_VERSION1_ROW, ROLLBACK_REQUIRED_BIT,
    RollbackRaw,
};

const DEVK_ROW: usize = 0xE80;
const MKEK_ROW: usize = 0xE90;
/// 32 bytes = 16 ECC rows of 16 data bits.
const KEY_ROWS: usize = 16;
/// The OTP page holding both keys and their chaff (0xE80 >> 6).
const KEY_PAGE: usize = 58;

/// Read the provisioned MKEK. `None` when unprovisioned.
///
/// Every seal and unseal needs it, so this one is read once at boot and held.
pub fn read_mkek() -> Option<[u8; 32]> {
    match option_env!("PK_FAKE_MKEK") {
        Some(hex) => Some(parse_hex32(hex)),
        None => read_key(MKEK_ROW),
    }
}

/// Read the provisioned DEVK. `None` when unprovisioned.
///
/// Fetched per use rather than held: three rarely-run commands want it (the two
/// rescue keydev ones and the opt-in audit checkpoint), and it is the one secret
/// on the device that can never be rotated — it is fused. Passed around as this
/// `fn` so no caller has to keep a copy. Reading it late is only possible because
/// [`sw_lock_key_page`] leaves the page's secure side open; see the note there.
pub fn read_devk() -> Option<[u8; 32]> {
    match option_env!("PK_FAKE_DEVK") {
        Some(hex) => Some(parse_hex32(hex)),
        None => read_key(DEVK_ROW),
    }
}

/// What one provisioned [`read_key`] costs, for the latency harness (`rsk bench
/// otp`). Deliberately not [`read_mkek`]: that short-circuits on a blank page
/// after the presence loop, so an unprovisioned board would time half the work
/// and under-report. Doing both halves unconditionally makes the number the same
/// on any board. Returns a checksum for the caller to `black_box` — the reads
/// have no other effect and would otherwise be optimized away.
#[cfg(feature = "bench")]
pub fn bench_key_read() -> u32 {
    let mut acc = 0u32;
    for i in 0..KEY_ROWS {
        acc ^= otp::read_raw_word(MKEK_ROW + i).unwrap_or(0);
    }
    for i in 0..KEY_ROWS {
        acc ^= otp::read_ecc_word(MKEK_ROW + i).unwrap_or(0) as u32;
    }
    acc
}

/// The volatile, every-boot half of the key-page lock: block non-secure access
/// to the key page for this power cycle via SW_LOCK (secure access stays
/// read-write — this firmware runs entirely secure). The irreversible LOCK1
/// fuse below is the permanent counterpart.
///
/// Closing the *secure* side as well, once [`read_mkek`] has run, would
/// deny a later code-execution bug a second read of the fuses. It does not work:
/// SW_LOCK is documented to re-initialise from the OTP lock pages "at reset", but
/// measured on A4 it **survives `SCB::sys_reset`** (only the bootrom path clears
/// it). The vendor warm reboot would therefore come back to a page it cannot
/// read, fall through to the pre-OTP key arm, and lose access to its own sealed
/// records until a power cycle. Do not add `set_sec` here without changing what
/// that reboot does.
pub fn sw_lock_key_page() {
    rp_pac::OTP.sw_lock(KEY_PAGE).write(|w| {
        w.set_nsec(rp_pac::otp::vals::SwLockNsec::Inaccessible);
    });
}

/// Raw 24-bit value of PAGE58_LOCK1, or `None` on a read error. Drives the
/// rescue applet's idempotency / refuse-foreign decision before any write.
pub fn read_page58_lock() -> Option<u32> {
    otp::read_raw_word(PAGE58_LOCK1_ROW)
        .ok()
        .map(|w| w & 0x00FF_FFFF)
}

/// Burn the permanent page-58 access lock (PAGE58_LOCK_VALUE → PAGE58_LOCK1)
/// from secure firmware — the half the host burn ritual cannot do, since that
/// lock row lives in bootloader-read-only OTP page 63 (page 63 `LOCK_S` = rw, so
/// secure code can). The row and value are fixed constants here, so this call
/// can only ever write that one lock; it is reached only after the rescue applet
/// has confirmed the row is blank and the keys are provisioned. IRREVERSIBLE.
/// Returns whether the bootrom write succeeded.
pub fn apply_page58_lock() -> bool {
    if faked_keys() {
        return false;
    }
    otp::write_raw_word(PAGE58_LOCK1_ROW, PAGE58_LOCK_VALUE).is_ok()
}

/// Whether this image carries a baked test key instead of reading OTP.
///
/// The rescue applet's precondition for both irreversible burns is
/// `Device.otp_key`, which [`read_mkek`] populates from `PK_FAKE_MKEK` **without
/// touching OTP** — so on a test image the guard whose whole job is to say "the real
/// fuses are already written" is forged, and the page-58 lock could be burned on a
/// board whose page 58 is blank. That is unrecoverable: `rsk otp burn`'s preflight
/// then dies on the unreadable row and the board can never be provisioned, leaving it
/// forever on the chip-serial-derivable pre-OTP key arm (audit run-36). `docs/build.md`
/// already promises a fake-key image writes no fuses; this makes that true.
fn faked_keys() -> bool {
    option_env!("PK_FAKE_MKEK").is_some() || option_env!("PK_FAKE_DEVK").is_some()
}

/// Raw RBIT-3 copies of the anti-rollback rows (BOOT_FLAGS0 + the two
/// DEFAULT_BOOT_VERSION thermometer words); `None` on any read error. Majority
/// and interpretation live in `rsk_rescue::rollback` so they stay host-tested.
pub fn read_rollback_raw() -> Option<RollbackRaw> {
    fn triple(row: usize) -> Option<[u32; 3]> {
        let mut out = [0u32; 3];
        for (i, w) in out.iter_mut().enumerate() {
            *w = otp::read_raw_word(row + i).ok()? & 0x00FF_FFFF;
        }
        Some(out)
    }
    Some(RollbackRaw {
        flags0: triple(BOOT_FLAGS0_ROW)?,
        version0: triple(DEFAULT_BOOT_VERSION0_ROW)?,
        version1: triple(DEFAULT_BOOT_VERSION1_ROW)?,
    })
}

/// Burn ROLLBACK_REQUIRED into each RBIT-3 copy of BOOT_FLAGS0 that does not
/// already carry it — the half the host ritual cannot do once the fuse pages
/// are bootloader-read-only (page 1 `LOCK_S` = rw, so secure code can). Each
/// write programs ONLY our bit (OTP writes OR into the row, so the other boot
/// flags are untouched) and is read back before moving on. The rows and the
/// bit are fixed constants here, so this call can only ever set that one flag;
/// it is reached only through the rescue applet's triple guard. IRREVERSIBLE.
pub fn apply_rollback_required() -> bool {
    if faked_keys() {
        return false;
    }
    for i in 0..3 {
        let row = BOOT_FLAGS0_ROW + i;
        match otp::read_raw_word(row) {
            Ok(w) if w & ROLLBACK_REQUIRED_BIT != 0 => continue, // copy already fused
            Ok(_) => {}
            Err(_) => return false,
        }
        if otp::write_raw_word(row, ROLLBACK_REQUIRED_BIT).is_err() {
            return false;
        }
        match otp::read_raw_word(row) {
            Ok(w) if w & ROLLBACK_REQUIRED_BIT != 0 => {}
            _ => return false,
        }
    }
    true
}

/// One 32-byte key at `row`: presence test first (all 16 raw rows zero =
/// unprovisioned), then the ECC-corrected data. Read errors (a page locked away
/// even from secure reads — a misconfiguration, not a factory state) also yield
/// `None`: fail to the pre-OTP arm, never panic at boot.
fn read_key(row: usize) -> Option<[u8; 32]> {
    let mut any = false;
    for i in 0..KEY_ROWS {
        match otp::read_raw_word(row + i) {
            Ok(w) => any |= w & 0x00FF_FFFF != 0,
            Err(_) => return None,
        }
    }
    if !any {
        return None;
    }
    let mut key = [0u8; 32];
    for i in 0..KEY_ROWS {
        let w = otp::read_ecc_word(row + i).ok()?;
        key[2 * i] = w as u8;
        key[2 * i + 1] = (w >> 8) as u8;
    }
    Some(key)
}

/// Decode a build.rs-validated 64-char hex string; build.rs rejects anything
/// else at compile time, so the panic arms are unreachable in a real image.
fn parse_hex32(hex: &str) -> [u8; 32] {
    fn nib(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => unreachable!(),
        }
    }
    let bytes = hex.as_bytes();
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = (nib(bytes[2 * i]) << 4) | nib(bytes[2 * i + 1]);
    }
    out
}
