// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The board's half of the applet wiring: the TRNG-backed DRBG every applet draws
//! from, the store type, and the [`rsk_device::Hooks`] that reach the hardware the
//! wiring itself cannot have. The wiring is `crates/rsk-device`.

use embassy_rp::peripherals::TRNG;
use embassy_rp::trng::Trng;

use rsk_crypto::HmacDrbg;
use rsk_fs::Fs;
use zeroize::Zeroize;

use crate::flash_storage::FlashStorage;
use crate::vendor::VendorPlatform;

/// Raised when the trusted display commits a new clientPIN; consumed by the next
/// CBOR dispatch to end the RAM session token. The flash-backed `pcmr` grant is not
/// signalled — `store_local_pin` revokes that where the flash is.
///
/// Cross-task because the display holds only `Fs` while `FidoState` lives here in
/// the worker's handler. Same shape as `worker::MSG_DESELECT`: set on one task,
/// swapped by the other, and the panel flow cannot overlap a dispatch (both run on
/// the single thread executor), so a token outlives the change by nothing. Only a
/// `display` build has an on-device pad to re-key a PIN from.
#[cfg(feature = "display")]
static LOCAL_PIN_CHANGED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Signal that the on-device pad just re-keyed the clientPIN.
#[cfg(feature = "display")]
pub fn note_local_pin_changed() {
    LOCAL_PIN_CHANGED.store(true, core::sync::atomic::Ordering::Release);
}

/// The applet-dispatch context (the flash file system).
pub type Store = Fs<FlashStorage>;

/// Hardware-seeded HMAC-DRBG ([`rsk_crypto::HmacDrbg`]) over the RP2350 TRNG.
///
/// Per-operation randomness comes from the DRBG (a few HMAC-SHA256 ops, microseconds,
/// uniform). The slow health-checked TRNG block is touched only to seed + periodically
/// reseed — and only through a *working* ROSC config (`chain=0`): with the default
/// `chain=One` the autocorrelation health test stalls catastrophically on this
/// RP2350 (0 valid blocks, a reset storm).
pub struct FidoRng {
    trng: Trng<'static, TRNG>,
    drbg: HmacDrbg,
    since_reseed: usize,
}

/// Draw fresh hardware entropy into the DRBG after this many output bytes. HMAC-DRBG
/// is secure for vastly longer between reseeds (SP 800-90A permits 2^48); this only
/// keeps the TRNG rarely touched while periodically refreshing entropy / forward
/// secrecy.
const RESEED_INTERVAL: usize = 1 << 16; // 64 KiB

impl FidoRng {
    /// Seed the DRBG from 48 bytes of hardware entropy (32 B security strength + a
    /// 16 B nonce, SP 800-90A 10.1.2.3), drawn through the working ROSC config the
    /// caller set on the `Trng`.
    pub fn new(mut trng: Trng<'static, TRNG>) -> Self {
        let mut seed = [0u8; 48];
        trng.blocking_fill_bytes(&mut seed);
        let drbg = HmacDrbg::new(&seed);
        seed.zeroize();
        Self {
            trng,
            drbg,
            since_reseed: 0,
        }
    }

    fn draw(&mut self, buf: &mut [u8]) {
        if self.since_reseed >= RESEED_INTERVAL {
            let mut e = [0u8; 32];
            self.trng.blocking_fill_bytes(&mut e);
            self.drbg.reseed(&e);
            e.zeroize();
            self.since_reseed = 0;
        }
        self.drbg.fill(buf);
        self.since_reseed = self.since_reseed.saturating_add(buf.len());
    }

    /// Wipe the DRBG state for a secure reboot; it reseeds from the TRNG at the
    /// next boot, so this only destroys the current session's keystream.
    pub fn scrub(&mut self) {
        self.drbg.scrub();
    }
}

impl rsk_fido::Rng for FidoRng {
    fn fill(&mut self, buf: &mut [u8]) {
        self.draw(buf);
    }
}

impl rsk_openpgp::Rng for FidoRng {
    fn fill(&mut self, buf: &mut [u8]) {
        self.draw(buf);
    }
}

impl rsk_oath::Rng for FidoRng {
    fn fill(&mut self, buf: &mut [u8]) {
        self.draw(buf);
    }
}

impl rsk_otp::Rng for FidoRng {
    fn fill(&mut self, buf: &mut [u8]) {
        self.draw(buf);
    }
}

impl rsk_rescue::Rng for FidoRng {
    fn fill(&mut self, buf: &mut [u8]) {
        self.draw(buf);
    }
}

/// The applet wiring, bound to this board's types. The wiring itself is
/// `rsk-device`; these aliases are what the worker names.
pub type Ctap<'a> = rsk_device::AppletHandler<'a, FlashStorage, FidoRng, VendorPlatform>;
pub type Ccid<'a> = rsk_device::CcidApplets<'a, FlashStorage, FidoRng, VendorPlatform>;

/// What `rsk-device` reaches back into the board for: the LED atomics a flash
/// record cannot reach, the watchdog register that carries the clientPIN soft
/// lock across a warm reset, the trusted display's PIN latch, and the second
/// core's prime search.
pub struct DeviceHooks;

impl rsk_device::Hooks<FlashStorage> for DeviceHooks {
    fn config_written(&mut self, fs: &mut Store) {
        crate::vendor::load_led_config(fs);
    }

    fn request_reboot(&mut self) {
        crate::vendor::request_reboot(false);
    }

    fn store_pin_lock(&mut self, lock: rsk_fido::state::PinLock) {
        crate::pin_lock::set(lock);
    }

    /// Restores the soft lock and reports whether this power cycle was entered
    /// warm. Runs exactly once — `restore_and_arm` consumes the tag — which is why
    /// `rsk-device` calls it only when the handler is built.
    fn boot_state(&mut self) -> rsk_device::BootState {
        let boot = crate::pin_lock::restore_and_arm();
        rsk_device::BootState {
            warm: boot.warm,
            lock: boot.lock,
        }
    }

    /// The trusted display committed a new clientPIN since the last command.
    /// Consumed here, set on the display task — `FidoState` is the handler's, not
    /// the panel's.
    #[cfg(feature = "display")]
    fn local_pin_changed(&mut self) -> bool {
        LOCAL_PIN_CHANGED.swap(false, core::sync::atomic::Ordering::AcqRel)
    }

    /// Both cores race the prime search while the transports keep the host alive.
    /// `Some` either way: this board *has* an accelerator, so a failed search is a
    /// failed command, not a fall-through to the single-core path.
    fn rsa_search(
        &mut self,
        nbits: usize,
        rng: &mut dyn rsk_openpgp::Rng,
    ) -> rsk_device::SearchResult {
        Some(crate::core1::run_rsa_search(nbits, rng))
    }
}
