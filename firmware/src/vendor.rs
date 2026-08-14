// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The firmware half of the vendor applet: the pending-reboot slot, and the
//! [`rsk_vendor::Platform`] that gives the applet its hardware — the LED atomics,
//! the reset, and (measurement builds only) the second core's counters and the
//! timing benches.
//!
//! The applet itself (its AID, the counter, the APDU dispatch and the
//! reboot-to-BOOTSEL gate) lives in `crates/rsk-vendor`, where it is host-tested
//! and where `tools/emu` can reach it.

use core::sync::atomic::{AtomicU8, Ordering};

use rsk_fs::{Fs, Storage};
// The LED config-block FID (sticky, outside both reset scopes) is single-sourced
// in `rsk_led` so the FIDO CONFIG_WRITE/READ LED target agrees on it. A legacy
// 2/3-byte record is mapped onto the idle status by [`crate::led::load_block`].
use rsk_led::EF_LED_CONF;
// Only the measurement builds answer a bench APDU, so only they name a status
// word here; the shipped image has no use for either import.
#[cfg(any(feature = "keygen-bench", feature = "bench"))]
use rsk_sdk::{ResBuf, Sw};

#[cfg(feature = "keygen-bench")]
const BENCH_ITERS: u32 = 400;
#[cfg(feature = "bench")]
const BENCH_SAMPLES: usize = 32;
/// Bench selector for the OTP key-page read. The crypto primitives are 0..=2 and
/// live in `rsk_fido::bench`; this one is served here because OTP is board
/// hardware that host-testable crate cannot reach.
#[cfg(feature = "bench")]
const SEL_OTP_READ: u8 = 3;
/// Reads batched into one [`SEL_OTP_READ`] sample. A key read is microseconds and
/// the timer ticks at 1 µs, so timing a single one would quantise it into noise;
/// the host divides the sample by this.
#[cfg(feature = "bench")]
const OTP_READ_REPS: u32 = 100;

/// Pending reboot request: 0 = none, 1 = warm reboot,
/// 2 = secure reboot to the BOOTSEL bootloader. Set by the applet's REBOOT and
/// consumed by the worker once the SW_OK response has been sent — the reset can't
/// run inline or the host never sees the reply.
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

/// This board's hardware, handed to the applet. A ZST: every capability it
/// exposes lives in a static or an atomic, so both transports can hold their own
/// copy without sharing anything.
pub struct VendorPlatform;

impl rsk_vendor::Platform for VendorPlatform {
    fn led_block(&self) -> Option<[u8; rsk_led::CONF_LEN]> {
        Some(crate::led::config_block())
    }

    fn set_led(
        &mut self,
        status: u8,
        color: u8,
        brightness: u8,
        steady: bool,
        effect: Option<u8>,
        speed: Option<u8>,
    ) -> Option<[u8; rsk_led::CONF_LEN]> {
        crate::led::set_status_config(status, color, brightness);
        crate::led::set_steady(steady);
        if let Some(effect) = effect {
            crate::led::set_status_effect(status, effect);
        }
        if let Some(speed) = speed {
            crate::led::set_status_speed(status, speed);
        }
        Some(crate::led::config_block())
    }

    /// Behind `core1-stats` so it never ships, for the reason the two benches
    /// below are gated: the per-core candidate/find counters are a timing oracle
    /// over the RSA keygen prime search. Gated out, the trait default answers
    /// `INS_NOT_SUPPORTED`.
    #[cfg(feature = "core1-stats")]
    fn core1_stats(&self) -> Option<[u8; 32]> {
        Some(crate::core1::stats())
    }

    fn request_reboot(&mut self, bootsel: bool) -> bool {
        request_reboot(bootsel);
        true
    }

    /// P1 selects the primitive (0 = strong Miller-Rabin base 2, 1 = the full
    /// small-factor sieve), data = a candidate (little-endian, length a multiple
    /// of 32). Runs it `BENCH_ITERS` times and returns; the host times the whole
    /// APDU. Behind `keygen-bench` so it never ships — it is a timing oracle over
    /// the primality primitives.
    #[cfg(feature = "keygen-bench")]
    fn keygen_bench(&mut self, p1: u8, data: &[u8], res: &mut ResBuf) -> Sw {
        if data.is_empty() || !data.len().is_multiple_of(32) || data.len() > 256 {
            return Sw::WRONG_LENGTH;
        }
        // `core::hint::black_box` keeps the loop from being optimized to one
        // iteration (the result is otherwise unused).
        use core::hint::black_box;
        match p1 {
            0 => {
                for _ in 0..BENCH_ITERS {
                    black_box(rsk_rsa_asm::passes_strong_mr_base2(black_box(data)));
                }
            }
            1 => {
                for _ in 0..BENCH_ITERS {
                    black_box(rsk_rsa_asm::has_small_factor(black_box(data)));
                }
            }
            _ => return Sw::INCORRECT_P1P2,
        }
        res.extend(&BENCH_ITERS.to_le_bytes());
        Sw::OK
    }

    /// P1 selects the primitive (0 = variable-base P-256 ECDH, the
    /// XIP-cache-sensitive clientPIN path; 1 = the getAssertion comb sign; 2 = the
    /// HKDF-SHA512 ratchet; 3 = an OTP key-page read, batched `OTP_READ_REPS` per
    /// sample), P2 = warmup samples dropped from the warm stats.
    /// Computes a robust median/MAD + a cold sample on-device (via the Kani-proved
    /// `rsk-bench`) and returns the 20-byte Summary. Behind `bench` so it never
    /// ships — a timing oracle, like keygen-bench. The sample count is kept modest
    /// so the slowest path (ECDH, ~106 ms) finishes one blocking CCID APDU well
    /// inside PC/SC timeouts.
    #[cfg(feature = "bench")]
    fn latency_bench(&mut self, p1: u8, p2: u8, res: &mut ResBuf) -> Sw {
        use embassy_time::Instant;
        if p1 > SEL_OTP_READ {
            return Sw::INCORRECT_P1P2;
        }
        let warmup = p2 as usize;
        let mut samples = [0u32; BENCH_SAMPLES];
        for slot in samples.iter_mut() {
            let t0 = Instant::now();
            // black_box so the compiler can't hoist/fold the timed call.
            match p1 {
                SEL_OTP_READ => {
                    for _ in 0..OTP_READ_REPS {
                        core::hint::black_box(crate::otp_keys::bench_key_read());
                    }
                }
                sel => {
                    core::hint::black_box(rsk_fido::bench::run(sel));
                }
            }
            // Ops are 60–500 ms → microseconds fit u32 with room to spare.
            *slot = t0.elapsed().as_micros() as u32;
        }
        let summary = rsk_bench::summarize(&mut samples, warmup);
        res.extend(&summary.to_le_bytes());
        // A batched selector declares its own divisor, so the host keeps no copy
        // of `OTP_READ_REPS` to drift against this one.
        if p1 == SEL_OTP_READ {
            res.extend(&OTP_READ_REPS.to_le_bytes());
        }
        Sw::OK
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
