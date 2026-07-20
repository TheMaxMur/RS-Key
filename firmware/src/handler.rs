// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Bridges CTAPHID MSG/CBOR to the applet layer. The flash file system is shared
//! with the CCID handler through a `RefCell`, borrowed only for the duration of
//! one synchronous dispatch — never across an `.await`.

use core::cell::RefCell;

use embassy_rp::peripherals::TRNG;
use embassy_rp::trng::Trng;
use embassy_time::Instant;

use rsk_crypto::{Device, HmacDrbg};
use rsk_fs::Fs;
use rsk_sdk::apdu::Apdu;
use rsk_sdk::{Applet, Dispatcher, ResBuf};
use zeroize::Zeroize;

use crate::flash_storage::FlashStorage;
use crate::vendor::VendorApplet;

/// The applet-dispatch context (the flash file system).
pub type Store = Fs<FlashStorage>;

// Sized to the CTAPHID transport maximum (= getInfo's maxMsgSize): an ML-DSA-44
// makeCredential response runs ~4 KB.
const RESP_CAP: usize = rsk_usb::ctaphid::CTAP_MAX_MESSAGE;

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

pub struct AppletHandler<'a> {
    fs: &'a RefCell<Store>,
    disp: Dispatcher,
    vendor: VendorApplet<'a>,
    /// The hardware TRNG, shared with the CCID/OpenPGP transport through a
    /// `RefCell` (borrowed only for one synchronous dispatch, never across an
    /// `.await`), like the flash `Fs`.
    rng: &'a RefCell<FidoRng>,
    /// Cross-message PIN/UV-auth state (PIN token, the ephemeral ECDH key …);
    /// lives for one power cycle.
    fido_state: rsk_fido::FidoState,
    /// Physical user presence (BOOTSEL by default, optionally a GPIO button),
    /// shared with the OpenPGP applet through a
    /// `RefCell`; borrowed only for a touch wait inside one dispatch.
    presence: &'a RefCell<dyn rsk_fido::UserPresence>,
    serial_id: [u8; 8],
    serial_hash: [u8; 32],
    /// The OTP MKEK, once provisioned.
    otp_key: Option<[u8; 32]>,
    resp: [u8; RESP_CAP],
}

impl<'a> AppletHandler<'a> {
    #[allow(clippy::too_many_arguments)] // one-time wiring from the worker
    pub fn new(
        fs: &'a RefCell<Store>,
        rng: &'a RefCell<FidoRng>,
        presence: &'a RefCell<dyn rsk_fido::UserPresence>,
        // Same physical presence, as the rescue trait, for the vendor applet's
        // gated reboot-to-BOOTSEL (this transport also dispatches the vendor AID).
        vendor_presence: &'a RefCell<dyn rsk_rescue::UserPresence>,
        serial_id: [u8; 8],
        serial_hash: [u8; 32],
        otp_key: Option<[u8; 32]>,
        devk: Option<[u8; 32]>,
    ) -> Self {
        // The OTP DEVK signs audit-journal checkpoints (rsk_fido::journal); it
        // rides in FidoState so the pure FIDO logic stays caller-supplied.
        let mut fido_state = rsk_fido::FidoState::new();
        fido_state.devk = devk;
        // Generate the clientPIN ephemeral key-agreement key at power-up (CTAP 2.1
        // §6.5.5.7), not lazily on the first clientPIN — so the first PIN entry
        // after plug-in doesn't pay the one-time ~40 ms `d·G`. The TRNG is seeded
        // by the time the worker builds the handler.
        fido_state.ensure_initialized(&mut *rng.borrow_mut());
        Self {
            fs,
            disp: Dispatcher::new(),
            vendor: VendorApplet::new(vendor_presence),
            rng,
            fido_state,
            presence,
            serial_id,
            serial_hash,
            otp_key,
            resp: [0; RESP_CAP],
        }
    }

    /// Wipe the response buffer — it can hold a PIN token or other secrets after
    /// a dispatch. Called by the worker once the response has been handed off.
    pub fn scrub(&mut self) {
        self.resp.zeroize();
    }

    /// Secure-reboot wipe: clear the response buffer and the cross-message FIDO
    /// auth state — `reset` zeroizes the PIN/UV token, session key and ephemeral
    /// ECDH scalar via their `Drop` impls.
    pub fn scrub_secrets(&mut self) {
        self.resp.zeroize();
        self.fido_state.reset();
    }
}

// Synchronous dispatch called by the worker (`crate::worker`) on the thread
// executor; the CTAPHID transport reaches it through the worker handshake.
impl AppletHandler<'_> {
    /// Drop any applet selected over CTAPHID_MSG. Called (via the worker) on a
    /// CTAPHID_INIT so a fresh session starts with nothing selected — U2F has no
    /// SELECT and must not inherit a prior vendor-AID selection.
    pub fn deselect_msg(&mut self) {
        self.disp.clear_selection();
    }

    pub fn handle_msg(&mut self, apdu: &[u8]) -> &[u8] {
        // U2F (CTAP1) has no SELECT over CTAPHID: route its INS straight to the
        // FIDO applet when nothing else is selected. A vendor AID SELECT takes
        // the dispatcher path below.
        if let Ok(parsed) = Apdu::parse(apdu) {
            const INS_SELECT: u8 = 0xA4;
            if self.disp.current().is_none() && parsed.ins != INS_SELECT {
                // Borrow only the serial fields so rng/state/resp stay free.
                let dev = Device {
                    serial_hash: &self.serial_hash,
                    serial_id: &self.serial_id,
                    otp_key: self.otp_key.as_ref(),
                };
                let now_ms = Instant::now().as_millis();
                let (sw, n) = {
                    let mut fsb = self.fs.borrow_mut();
                    let mut rngb = self.rng.borrow_mut();
                    let mut presence = self.presence.borrow_mut();
                    let mut ctx = rsk_fido::Ctx {
                        dev,
                        fs: &mut *fsb,
                        rng: &mut *rngb,
                        state: &mut self.fido_state,
                        now_ms,
                        presence: &mut *presence,
                    };
                    rsk_fido::u2f::process_u2f(&mut ctx, &parsed, &mut self.resp[..RESP_CAP - 2])
                };
                self.resp[n..n + 2].copy_from_slice(&sw.to_bytes());
                return &self.resp[..n + 2];
            }
        }

        // Body fills resp[..cap-2]; the status word is appended after it.
        let (sw, n) = {
            let mut res = ResBuf::new(&mut self.resp[..RESP_CAP - 2]);
            let mut applets: [&mut dyn Applet<Store>; 1] = [&mut self.vendor];
            let mut fsb = self.fs.borrow_mut();
            let sw = self.disp.process(apdu, &mut applets, &mut *fsb, &mut res);
            (sw, res.len())
        };
        self.resp[n..n + 2].copy_from_slice(&sw.to_bytes());
        &self.resp[..n + 2]
    }

    pub fn handle_cbor(&mut self, data: &[u8]) -> &[u8] {
        let dev = Device {
            serial_hash: &self.serial_hash,
            serial_id: &self.serial_id,
            otp_key: self.otp_key.as_ref(),
        };
        let now_ms = Instant::now().as_millis();
        let n = {
            let mut fsb = self.fs.borrow_mut();
            let mut rngb = self.rng.borrow_mut();
            let mut presence = self.presence.borrow_mut();
            let mut ctx = rsk_fido::Ctx {
                dev,
                fs: &mut *fsb,
                rng: &mut *rngb,
                state: &mut self.fido_state,
                now_ms,
                presence: &mut *presence,
            };
            rsk_fido::process_cbor(&mut ctx, data, &mut self.resp)
        };
        // A vendor (0x41) CONFIG_WRITE with the LED target persists EF_LED_CONF,
        // but the LED atomics live here in the firmware — reload the block after
        // any 0x41 command to apply it live, matching the CCID SET_LED. 0x41 is
        // rare (backup/audit/config), so the extra flash read is negligible, and
        // it is a no-op when the record is absent or unchanged.
        if data.first() == Some(&rsk_fido::consts::CTAP_VENDOR) {
            let mut fsb = self.fs.borrow_mut();
            crate::vendor::load_led_config(&mut fsb);
            // A PHY config-write changes the USB identity, which is only read at
            // boot. If power-cycle-on-reset is enabled (phy opts, the default),
            // warm-reboot so the new VID/PID/product/interfaces apply without a
            // manual replug (fixes the "config doesn't take effect" report). The
            // reset runs in the worker after this response flushes.
            if rsk_fido::vendor::take_phy_written() {
                let phy = rsk_rescue::phy::load(&mut fsb).unwrap_or_default();
                if phy.opts & rsk_rescue::phy::OPT_DISABLE_POWER_RESET == 0 {
                    crate::vendor::request_reboot(false);
                }
            }
        }
        &self.resp[..n]
    }
}
