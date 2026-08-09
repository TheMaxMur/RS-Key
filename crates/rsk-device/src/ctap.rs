// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Bridges CTAPHID MSG/CBOR to the applet layer. The file system is shared with
//! the CCID handler through a `RefCell`, borrowed only for the duration of one
//! synchronous dispatch — never across an `.await` on the device.

use core::cell::RefCell;

use rsk_crypto::Device;
use rsk_fs::{Fs, Storage};
use rsk_sdk::apdu::Apdu;
use rsk_sdk::{Applet, Dispatcher, ResBuf};
use rsk_vendor::VendorApplet;
use zeroize::Zeroize;

use crate::Hooks;

// Sized to the CTAPHID transport maximum (= getInfo's maxMsgSize): an ML-DSA-44
// makeCredential response runs ~4 KB.
const RESP_CAP: usize = rsk_usb::ctaphid::CTAP_MAX_MESSAGE;

pub struct AppletHandler<'a, S: Storage, R: crate::Rng + 'static, VP: rsk_vendor::Platform> {
    fs: &'a RefCell<Fs<S>>,
    hooks: &'a RefCell<dyn Hooks<S>>,
    disp: Dispatcher,
    vendor: VendorApplet<'a, VP>,
    /// The hardware TRNG, shared with the CCID/OpenPGP transport through a
    /// `RefCell` (borrowed only for one synchronous dispatch, never across an
    /// `.await`), like the flash `Fs`.
    rng: &'a RefCell<R>,
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

impl<'a, S: Storage, R: crate::Rng + 'static, VP: rsk_vendor::Platform>
    AppletHandler<'a, S, R, VP>
{
    #[allow(clippy::too_many_arguments)] // one-time wiring from the worker
    pub fn new<PR: crate::UserPresence + 'static>(
        fs: &'a RefCell<Fs<S>>,
        rng: &'a RefCell<R>,
        hooks: &'a RefCell<dyn Hooks<S>>,
        // One physical presence source: CTAP user presence and the vendor applet's
        // gated reboot-to-BOOTSEL (this transport also dispatches the vendor AID)
        // are the same button behind two traits.
        presence: &'a RefCell<PR>,
        vendor_platform: VP,
        serial_id: [u8; 8],
        serial_hash: [u8; 32],
        otp_key: Option<[u8; 32]>,
        devk: Option<fn() -> Option<[u8; 32]>>,
    ) -> Self {
        // The OTP DEVK signs audit-journal checkpoints (rsk_fido::journal); it
        // rides in FidoState so the pure FIDO logic stays caller-supplied.
        let mut fido_state = rsk_fido::FidoState::new();
        // Restore the clientPIN soft lock if the last boot was a warm reset: the
        // canary survives `sys_reset` but not a real power cycle, which is the
        // distinction CTAP 2.1 §6.5.5.6 draws. The same canary reports the warm
        // boot itself, which §6.6's reset window keys on.
        let boot = hooks.borrow_mut().boot_state();
        fido_state.restore_pin_lock(boot.lock);
        fido_state.warm_boot = boot.warm;
        fido_state.devk_source = devk;
        // Generate the clientPIN ephemeral key-agreement key at power-up (CTAP 2.1
        // §6.5.5.7), not lazily on the first clientPIN — so the first PIN entry
        // after plug-in doesn't pay the one-time ~40 ms `d·G`. The TRNG is seeded
        // by the time the worker builds the handler.
        fido_state.ensure_initialized(&mut *rng.borrow_mut());
        Self {
            fs,
            hooks,
            disp: Dispatcher::new(),
            vendor: VendorApplet::new(vendor_platform, presence),
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
impl<S: Storage, R: crate::Rng + 'static, VP: rsk_vendor::Platform> AppletHandler<'_, S, R, VP> {
    /// Drop any applet selected over CTAPHID_MSG. Called (via the worker) on a
    /// CTAPHID_INIT so a fresh session starts with nothing selected — U2F has no
    /// SELECT and must not inherit a prior vendor-AID selection.
    pub fn deselect_msg(&mut self) {
        self.disp.clear_selection();
    }

    pub fn handle_msg(&mut self, apdu: &[u8], now_ms: u64) -> &[u8] {
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
            let mut applets: [&mut dyn Applet<Fs<S>>; 1] = [&mut self.vendor];
            let mut fsb = self.fs.borrow_mut();
            let sw = self.disp.process(apdu, &mut applets, &mut *fsb, &mut res);
            (sw, res.len())
        };
        self.resp[n..n + 2].copy_from_slice(&sw.to_bytes());
        &self.resp[..n + 2]
    }

    /// `now_ms` is measured since the USB *attach*, not since power-up: the §6.6
    /// reset window a host has to hit runs from the moment the device could answer
    /// at all. The transport owns that clock, so it supplies it.
    pub fn handle_cbor(&mut self, cid: u32, data: &[u8], now_ms: u64) -> &[u8] {
        // The trusted display re-keyed the clientPIN since the last command: end
        // every session credential the old PIN authorized, before this one can use
        // it. Set on the display task, consumed here — `FidoState` is ours, not its.
        //
        // RAM only. §6.5.5.6 step 15's persistent half used to be signalled through
        // this same flag, which an APDU-only warm reboot drops before any CBOR command
        // consumes it — leaving the `pcmr` grant live for ever (audit run-37). It is
        // now revoked inside the write that installs the new verifier.
        if self.hooks.borrow_mut().local_pin_changed() {
            let mut rngb = self.rng.borrow_mut();
            self.fido_state.reset_pin_uv_auth_token(&mut *rngb);
            // The host path also clears `needs_power_cycle` here; that field is
            // crate-private and leaving the RAM soft lock armed only fails closed
            // (host clientPIN stays blocked until a replug), so it stays as it is.
        }
        let dev = Device {
            serial_hash: &self.serial_hash,
            serial_id: &self.serial_id,
            otp_key: self.otp_key.as_ref(),
        };
        // Which CTAPHID channel is asking. Cross-message state a second process on
        // its own channel must not be able to ride — the seed-backup MSE key —
        // binds to this (see `FidoState::mse_ready`).
        self.fido_state.channel = cid;
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
        // Persist the clientPIN soft lock across a warm reboot. It is RAM-only, and a
        // host can request `SCB::sys_reset` ungated (vendor 0x1F P1=0, the rescue
        // twin, or the phy config-write auto-reboot) — which cleared it and let host
        // malware burn the whole retry budget unattended, the exact thing CTAP 2.1
        // §6.5.5.6's power-cycle requirement exists to prevent.
        self.hooks
            .borrow_mut()
            .store_pin_lock(self.fido_state.pin_lock());
        // A vendor (0x41) CONFIG_WRITE with the LED target persists EF_LED_CONF,
        // but the LED atomics live here in the firmware — reload the block after
        // any 0x41 command to apply it live, matching the CCID SET_LED. 0x41 is
        // rare (backup/audit/config), so the extra flash read is negligible, and
        // it is a no-op when the record is absent or unchanged.
        if data.first() == Some(&rsk_fido::consts::CTAP_VENDOR) {
            let mut fsb = self.fs.borrow_mut();
            self.hooks.borrow_mut().config_written(&mut fsb);
            // A PHY config-write changes the USB identity, which is only read at
            // boot. If power-cycle-on-reset is enabled (phy opts, the default),
            // warm-reboot so the new VID/PID/product/interfaces apply without a
            // manual replug (fixes the "config doesn't take effect" report). The
            // reset runs in the worker after this response flushes.
            if rsk_fido::vendor::take_phy_written() {
                let phy = rsk_rescue::phy::load(&mut fsb).unwrap_or_default();
                if phy.opts & rsk_rescue::phy::OPT_DISABLE_POWER_RESET == 0 {
                    self.hooks.borrow_mut().request_reboot();
                }
            }
        }
        &self.resp[..n]
    }
}

#[cfg(test)]
#[path = "ctap_tests.rs"]
mod tests;
