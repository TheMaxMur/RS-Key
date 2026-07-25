// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Vendor applet: a flash-persisted test counter, LED customization (SET/GET LED,
//! persisted in `EF_LED_CONF` and applied live), and the reboot command — which
//! is only queued here and run by the worker after the response has flushed.

use core::cell::RefCell;
use core::sync::atomic::{AtomicU8, Ordering};

use rsk_fs::{Fs, Storage};
// The LED config-block FID (sticky, outside both reset scopes) is single-sourced
// in `rsk_led` so the FIDO CONFIG_WRITE/READ LED target agrees on it. A legacy
// 2/3-byte record is mapped onto the idle status by [`crate::led::load_block`].
use rsk_led::EF_LED_CONF;
use rsk_rescue::{Confirm, Presence, UserPresence};
use rsk_sdk::{Apdu, Applet, ResBuf, Sw};

/// Vendor AID (RID `F0 00 00 00`, app `01`).
pub const VENDOR_AID: &[u8] = &[0xF0, 0x00, 0x00, 0x00, 0x01];

/// Dynamic file holding the counter; `Fs::scan` rediscovers it after a reboot.
const COUNTER_FID: u16 = 0xCC01;
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
// KEYGEN MICROBENCH (debug builds only): time the two keygen hot primitives so
// the small-prime sieve can be sized against the modexp cost. P1 selects the
// primitive (0 = strong Miller-Rabin base 2, 1 = the full small-factor sieve),
// data = a candidate (little-endian, length a multiple of 32). Runs it
// BENCH_ITERS times and returns; the host times the whole APDU. Behind
// `keygen-bench` so it never ships.
#[cfg(feature = "keygen-bench")]
const INS_KEYGEN_BENCH: u8 = 0x13;
#[cfg(feature = "keygen-bench")]
const BENCH_ITERS: u32 = 400;
// LATENCY MICROBENCH (bench builds only): time one EC / KDF hot path via the
// RP2350 timer. P1 selects the primitive (0 = variable-base P-256 ECDH, the
// XIP-cache-sensitive clientPIN path; 1 = the getAssertion comb sign; 2 = the
// HKDF-SHA512 ratchet), P2 = warmup samples dropped from the warm stats. Computes
// a robust median/MAD + a cold sample on-device (via the Kani-proved rsk-bench)
// and returns the 20-byte Summary. Behind `bench` so it never ships — a timing
// oracle, like keygen-bench. Sample count is kept modest so the slowest path
// (ECDH, ~106 ms) finishes one blocking CCID APDU well inside PC/SC timeouts.
#[cfg(feature = "bench")]
const INS_BENCH: u8 = 0x14;
#[cfg(feature = "bench")]
const BENCH_SAMPLES: usize = 32;
const INS_REBOOT: u8 = 0x1F; // P1: 0 = warm reboot, 1 = secure reboot to BOOTSEL

/// Pending reboot request: 0 = none, 1 = warm reboot,
/// 2 = secure reboot to the BOOTSEL bootloader. Set by [`INS_REBOOT`] and consumed
/// by the worker once the SW_OK response has been sent — the reset can't run inline
/// or the host never sees the reply.
static REBOOT: AtomicU8 = AtomicU8::new(0);

/// Take and clear any pending reboot request (the worker, after the response
/// flushes). `Some(1)` = warm reboot, `Some(2)` = secure reboot to BOOTSEL.
pub fn take_reboot() -> Option<u8> {
    match REBOOT.swap(0, Ordering::Relaxed) {
        0 => None,
        m => Some(m),
    }
}

/// Queue a reboot (also used by the rescue applet's REBOOT_BOOTSEL command).
pub fn request_reboot(bootsel: bool) {
    REBOOT.store(if bootsel { 2 } else { 1 }, Ordering::Relaxed);
}

/// Whether a reboot is queued but not yet serviced (peek, does not clear). The display's
/// ambient loop reads this to park itself once a Settings → Firmware update is requested —
/// it must stop busy-waiting and yield so the worker (same thread-mode executor) gets
/// scheduled to scrub the live secrets and reset. Display-only: the standard key never
/// queues a reboot off-transport (the worker services those inline after the SW_OK).
#[cfg(feature = "display")]
pub fn reboot_pending() -> bool {
    REBOOT.load(Ordering::Relaxed) != 0
}

pub struct VendorApplet<'a> {
    /// Gates the reboot-to-BOOTSEL command (P1=01). The same physical presence
    /// source the rescue applet uses, so a hostile host cannot drop the device
    /// into the mass-storage bootloader without the operator via *either*
    /// transport (this applet is reachable over both CCID and CTAPHID).
    presence: &'a RefCell<dyn UserPresence>,
}

impl<'a> VendorApplet<'a> {
    pub fn new(presence: &'a RefCell<dyn UserPresence>) -> Self {
        Self { presence }
    }
}

impl<S: Storage> Applet<Fs<S>> for VendorApplet<'_> {
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
                if self
                    .presence
                    .borrow_mut()
                    .request(Confirm::titled("Change LED?"))
                    != Presence::Confirmed
                {
                    return Sw::SECURITY_STATUS_NOT_SATISFIED;
                }
                // One status (P2 bits 5:4) gets P1 brightness + P2 color; the
                // steady bit is global. Optional data bytes set effect and speed.
                let status = (apdu.p2 >> 4) & 0x3;
                crate::led::set_status_config(status, apdu.p2 & 0x7, apdu.p1);
                crate::led::set_steady(apdu.p2 & P2_STEADY != 0);
                // Optional data bytes: data[0] = effect, data[1] = speed. They
                // are independent, so an effect-only update (one data byte)
                // keeps the status's current speed rather than resetting it.
                if apdu.nc >= 1 {
                    crate::led::set_status_effect(status, apdu.data[0]);
                }
                if apdu.nc >= 2 {
                    crate::led::set_status_speed(status, apdu.data[1]);
                }
                if fs.put(EF_LED_CONF, &crate::led::config_block()).is_err() {
                    return Sw::MEMORY_FAILURE;
                }
                Sw::OK
            }
            INS_GET_LED => {
                res.extend(&crate::led::config_block());
                Sw::OK
            }
            INS_CORE1_STATS => {
                res.extend(&crate::core1::stats());
                Sw::OK
            }
            #[cfg(feature = "keygen-bench")]
            INS_KEYGEN_BENCH => {
                let cand = apdu.data;
                if cand.is_empty() || !cand.len().is_multiple_of(32) || cand.len() > 256 {
                    return Sw::WRONG_LENGTH;
                }
                // `core::hint::black_box` keeps the loop from being optimized to
                // one iteration (the result is otherwise unused).
                use core::hint::black_box;
                match apdu.p1 {
                    0 => {
                        for _ in 0..BENCH_ITERS {
                            black_box(rsk_rsa_asm::passes_strong_mr_base2(black_box(cand)));
                        }
                    }
                    1 => {
                        for _ in 0..BENCH_ITERS {
                            black_box(rsk_rsa_asm::has_small_factor(black_box(cand)));
                        }
                    }
                    _ => return Sw::INCORRECT_P1P2,
                }
                res.extend(&BENCH_ITERS.to_le_bytes());
                Sw::OK
            }
            #[cfg(feature = "bench")]
            INS_BENCH => {
                use embassy_time::Instant;
                if apdu.p1 > 2 {
                    return Sw::INCORRECT_P1P2;
                }
                let sel = apdu.p1;
                let warmup = apdu.p2 as usize;
                let mut samples = [0u32; BENCH_SAMPLES];
                for slot in samples.iter_mut() {
                    let t0 = Instant::now();
                    // black_box so the compiler can't hoist/fold the timed call.
                    core::hint::black_box(rsk_fido::bench::run(sel));
                    // Ops are 60–500 ms → microseconds fit u32 with room to spare.
                    *slot = t0.elapsed().as_micros() as u32;
                }
                let summary = rsk_bench::summarize(&mut samples, warmup);
                res.extend(&summary.to_le_bytes());
                Sw::OK
            }
            INS_REBOOT => {
                // Just record the request — the worker runs the secure wipe +
                // reset after this SW_OK reaches the host.
                if apdu.nc != 0 {
                    return Sw::WRONG_LENGTH;
                }
                match apdu.p1 {
                    0x00 => request_reboot(false),
                    0x01 => {
                        // Reboot-to-BOOTSEL aids an at-rest flash/OTP dump; gate it
                        // behind the operator, matching the rescue applet's
                        // REBOOT_BOOTSEL — otherwise this ungated twin would let a
                        // hostile host bypass that gate. A warm restart (P1=00)
                        // stays ungated.
                        if self
                            .presence
                            .borrow_mut()
                            .request(Confirm::titled("Reboot to BOOTSEL?"))
                            != Presence::Confirmed
                        {
                            return Sw::CONDITIONS_NOT_SATISFIED;
                        }
                        request_reboot(true)
                    }
                    _ => return Sw::INCORRECT_P1P2,
                }
                Sw::OK
            }
            _ => Sw::INS_NOT_SUPPORTED,
        }
    }
}

/// Apply the LED config persisted in `EF_LED_CONF` (called by `main` on boot).
/// `load_block` tolerates a legacy 2/3-byte record from an older firmware.
///
/// On a device that has never customised the LEDs the record is absent, so the
/// live defaults are persisted once here. That way a host `CONFIG_READ` over FIDO
/// always gets the full block to read-modify-write (it can't know the build
/// defaults); the stored block equals the defaults, so the LED output is unchanged.
pub fn load_led_config<S: Storage>(fs: &mut Fs<S>) {
    let mut buf = [0u8; crate::led::CONF_LEN];
    match fs.read(EF_LED_CONF, &mut buf) {
        Some(n) => crate::led::load_block(&buf[..n.min(buf.len())]),
        None => {
            let _ = fs.put(EF_LED_CONF, &crate::led::config_block());
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
