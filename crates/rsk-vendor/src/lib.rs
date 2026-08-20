// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Vendor applet: a flash-persisted test counter, LED customization (SET/GET
//! LED, persisted in `EF_LED_CONF` and applied live), the second core's only
//! window (CORE1 STATS), the measurement microbenchmarks, and the reboot
//! command — which is only *queued* here and run once the response has flushed.
//!
//! Everything that needs hardware sits behind [`Platform`], whose defaults all
//! answer "not supported". That is what lets the applet live in a crate at all:
//! the counter is portable, the rest is the firmware's, and a host build (the
//! emulator) implements the one arm it can honestly serve rather than pretending
//! to have an LED.

#![no_std]

use core::cell::RefCell;

use rsk_fs::{Fs, Storage};
// The LED config-block FID (sticky, outside both reset scopes) is single-sourced
// in `rsk_led` so the FIDO CONFIG_WRITE/READ LED target agrees on it.
use rsk_led::{CONF_LEN, EF_LED_CONF};
// The presence check gating reboot-to-BOOTSEL, the counter write and the LED
// write is `rsk-sdk`'s seam — the same source rescue uses, deliberately: this
// applet is on *both* CCID and CTAPHID, so an ungated twin is a cross-AID bypass.
pub use rsk_sdk::{AlwaysConfirm, Confirm, Presence, UserPresence};
use rsk_sdk::{Apdu, Applet, ResBuf, Sw};

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

/// Vendor AID (RID `F0 00 00 00`, app `01`).
pub const VENDOR_AID: &[u8] = &[0xF0, 0x00, 0x00, 0x00, 0x01];

/// Dynamic file holding the counter; `Fs::scan` rediscovers it after a reboot.
pub const COUNTER_FID: u16 = 0xCC01;
/// SET LED P2 bit that turns blinking off (solid color); the low 3 bits are the
/// color and bits 5:4 select which status is being configured.
const P2_STEADY: u8 = 0x08;

const INS_INCREMENT: u8 = 0x01;
const INS_GET: u8 = 0x02;
// SET LED: P1 = brightness (0–255), P2 = color(0–7) | steady(0x08) | status<<4.
const INS_SET_LED: u8 = 0x10;
const INS_GET_LED: u8 = 0x11;
// CORE1 STATS: 32 bytes LE — core1 wakes + jobs, candidates tried / primes
// found per core, entry-deadline misses, then the live flags (busy, stop,
// job-pending, degraded). The second core has no debugger and no UART; this
// is its only window.
const INS_CORE1_STATS: u8 = 0x12;
// KEYGEN MICROBENCH (measurement builds only): times the two keygen hot
// primitives so the small-prime sieve can be sized against the modexp cost.
const INS_KEYGEN_BENCH: u8 = 0x13;
// LATENCY MICROBENCH (measurement builds only): times one EC / KDF hot path.
const INS_BENCH: u8 = 0x14;
/// REBOOT. P1: 0 = warm reboot, 1 = secure reboot to BOOTSEL.
const INS_REBOOT: u8 = 0x1F;

/// The hardware this applet reaches for, none of which a crate can have. Every
/// method defaults to "this build has none", which the applet reports as
/// `INS_NOT_SUPPORTED` — an honest answer, and the one a host tool can act on.
pub trait Platform {
    /// The live LED configuration block, or `None` on a build with no LED.
    fn led_block(&self) -> Option<[u8; CONF_LEN]> {
        None
    }

    /// Apply a SET LED and return the block to persist. `effect` and `speed` are
    /// the optional data bytes: they are independent, so an effect-only update
    /// keeps the status's current speed rather than resetting it.
    fn set_led(
        &mut self,
        _status: u8,
        _color: u8,
        _brightness: u8,
        _steady: bool,
        _effect: Option<u8>,
        _speed: Option<u8>,
    ) -> Option<[u8; CONF_LEN]> {
        None
    }

    /// The second core's 32-byte statistics block.
    fn core1_stats(&self) -> Option<[u8; 32]> {
        None
    }

    /// Queue a reboot — never run it inline, or the host never sees the reply.
    /// `false` when this build has no reset to run.
    fn request_reboot(&mut self, _bootsel: bool) -> bool {
        false
    }

    /// Keygen microbenchmark (INS 0x13); a timing oracle, so it exists only on a
    /// measurement build.
    fn keygen_bench(&mut self, _p1: u8, _data: &[u8], _res: &mut ResBuf) -> Sw {
        Sw::INS_NOT_SUPPORTED
    }

    /// Latency harness (INS 0x14); likewise measurement-only.
    fn latency_bench(&mut self, _p1: u8, _p2: u8, _res: &mut ResBuf) -> Sw {
        Sw::INS_NOT_SUPPORTED
    }
}

/// The platform is owned, not borrowed: the firmware's is a ZST over atomics and
/// the emulator's a handle, so neither needs sharing, and owning it keeps the
/// applet out of a second `RefCell` dance.
pub struct VendorApplet<'a, P: Platform> {
    platform: P,
    presence: &'a RefCell<dyn UserPresence>,
}

impl<'a, P: Platform> VendorApplet<'a, P> {
    pub fn new(platform: P, presence: &'a RefCell<dyn UserPresence>) -> Self {
        Self { platform, presence }
    }

    /// The consent titles stay written out at their call sites, not funnelled
    /// through a helper: `rsk-ui`'s census scans the tree for `Confirm::titled`
    /// literals so no ceremony title can reach the trusted display unmeasured,
    /// and a helper hides them from it.
    fn confirmed(&self, confirm: Confirm<'_>) -> bool {
        self.presence.borrow_mut().request(confirm) == Presence::Confirmed
    }
}

impl<S: Storage, P: Platform> Applet<Fs<S>> for VendorApplet<'_, P> {
    fn aid(&self) -> &'static [u8] {
        VENDOR_AID
    }

    fn select(&mut self, _reselect: bool, _fs: &mut Fs<S>, _res: &mut ResBuf) -> Sw {
        Sw::OK
    }

    fn process(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        match apdu.ins {
            INS_GET => {
                res.extend(&read_counter(fs).to_be_bytes());
                Sw::OK
            }
            INS_INCREMENT => {
                // A test hook has no business handing a host a flash-write primitive:
                // ungated this was ~390 writes/s over either transport, 16 B each.
                // (SET LED below is its ungated main-partition twin, by decision.)
                if !self.confirmed(Confirm::titled("Write test counter?")) {
                    return Sw::CONDITIONS_NOT_SATISFIED;
                }
                let next = read_counter(fs).wrapping_add(1);
                if fs.put(COUNTER_FID, &next.to_be_bytes()).is_err() {
                    return Sw::MEMORY_FAILURE;
                }
                res.extend(&next.to_be_bytes());
                Sw::OK
            }
            INS_SET_LED => {
                // On a build without the trusted display the LED is the only signal
                // that the key is waiting for a touch, so a host that can rewrite it
                // can make "awaiting consent" look identical to idle. `strict-config`
                // gates the FIDO twin of this write (CONFIG_TARGET_LED); gate this
                // one too, or the CCID vendor AID simply bypasses that.
                #[cfg(feature = "strict-config")]
                if !self.confirmed(Confirm::titled("Change LED?")) {
                    return Sw::SECURITY_STATUS_NOT_SATISFIED;
                }
                // One status (P2 bits 5:4) gets P1 brightness + P2 color; the
                // steady bit is global. Optional data bytes set effect and speed.
                let block = self.platform.set_led(
                    (apdu.p2 >> 4) & 0x3,
                    apdu.p2 & 0x7,
                    apdu.p1,
                    apdu.p2 & P2_STEADY != 0,
                    (apdu.nc >= 1).then(|| apdu.data[0]),
                    (apdu.nc >= 2).then(|| apdu.data[1]),
                );
                let Some(block) = block else {
                    return Sw::INS_NOT_SUPPORTED;
                };
                // A replay costs no flash — the guard run-27 gave the FIDO twin
                // (CONFIG_TARGET_LED) and never swept here. Ungated on this AID,
                // each identical write appended 28 B of the credential ring.
                let mut cur = [0u8; CONF_LEN];
                if fs.read(EF_LED_CONF, &mut cur) == Some(CONF_LEN) && cur == block {
                    return Sw::OK;
                }
                if fs.put(EF_LED_CONF, &block).is_err() {
                    return Sw::MEMORY_FAILURE;
                }
                Sw::OK
            }
            INS_GET_LED => match self.platform.led_block() {
                Some(block) => {
                    res.extend(&block);
                    Sw::OK
                }
                None => Sw::INS_NOT_SUPPORTED,
            },
            INS_CORE1_STATS => match self.platform.core1_stats() {
                Some(stats) => {
                    res.extend(&stats);
                    Sw::OK
                }
                None => Sw::INS_NOT_SUPPORTED,
            },
            INS_KEYGEN_BENCH => self.platform.keygen_bench(apdu.p1, apdu.data, res),
            INS_BENCH => self.platform.latency_bench(apdu.p1, apdu.p2, res),
            INS_REBOOT => {
                // Just record the request — the reset runs after this SW_OK
                // reaches the host.
                if apdu.nc != 0 {
                    return Sw::WRONG_LENGTH;
                }
                let bootsel = match apdu.p1 {
                    0x00 => false,
                    // Reboot-to-BOOTSEL aids an at-rest flash/OTP dump; gate it
                    // behind the operator, matching the rescue applet's
                    // REBOOT_BOOTSEL — otherwise this ungated twin would let a
                    // hostile host bypass that gate. A warm restart (P1=00)
                    // stays ungated.
                    0x01 => {
                        if !self.confirmed(Confirm::titled("Reboot to BOOTSEL?")) {
                            return Sw::CONDITIONS_NOT_SATISFIED;
                        }
                        true
                    }
                    _ => return Sw::INCORRECT_P1P2,
                };
                if self.platform.request_reboot(bootsel) {
                    Sw::OK
                } else {
                    Sw::INS_NOT_SUPPORTED
                }
            }
            _ => Sw::INS_NOT_SUPPORTED,
        }
    }
}

fn read_counter<S: Storage>(fs: &mut Fs<S>) -> u32 {
    let mut buf = [0u8; 4];
    match fs.read(COUNTER_FID, &mut buf) {
        Some(n) if n >= 4 => u32::from_be_bytes(buf),
        _ => 0,
    }
}
