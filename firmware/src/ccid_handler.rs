// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Bridges CCID `XfrBlock` APDUs to the applet dispatcher; selection state is
//! independent of the CTAPHID channel. Runs on the worker (thread executor), so
//! on-card RSA keygen blocks here to completion while the CCID transport, on its
//! high-priority task, streams T=1 time-extensions.

use core::cell::RefCell;

use rsk_mgmt::ManagementApplet;
use rsk_oath::OathApplet;
use rsk_openpgp::OpenpgpApplet;
use rsk_openpgp::consts::INS_KEYPAIR_GEN;
use rsk_otp::OtpApplet;
use rsk_piv::PivApplet;
use rsk_rescue::RescueApplet;
use rsk_sdk::{Apdu, Applet, Dispatcher, ResBuf, Sw};

use crate::handler::{FidoRng, Store};
use crate::vendor::VendorApplet;

// A CCID XfrBlock frame carries MAX_CCID_MSG (2048) minus the 10-byte CCID
// header = 2038 payload bytes. The applet response (body + 2-byte SW) must fit
// one frame; sizing this to the full message let a large response (e.g. a long
// OATH LIST) overrun the frame, and `run_xfr` silently dropped the tail incl. SW.
const RESP_CAP: usize = 2038;

/// Registration-order indices of the applets whose RSA keygen is fast-pathed.
const IDX_OPENPGP: usize = 1;
const IDX_PIV: usize = 5;

/// YubiKey Management vendor command number carried over CTAPHID (logical, i.e.
/// `TYPE_INIT` already stripped by the transport). Only READ CONFIG is served — it
/// is what `ykman` / Yubico Authenticator read to identify the key over the FIDO
/// interface; WRITE CONFIG / mode-switch stay CCID + OTP only.
const CTAP_READ_CONFIG: u8 = 0x42;

pub struct CcidApplets<'a> {
    fs: &'a RefCell<Store>,
    rng: &'a RefCell<FidoRng>,
    disp: Dispatcher,
    vendor: VendorApplet<'a>,
    openpgp: OpenpgpApplet<'a>,
    management: ManagementApplet<'a>,
    oath: OathApplet<'a>,
    otp: OtpApplet<'a>,
    piv: PivApplet<'a>,
    rescue: RescueApplet<'a>,
    resp: [u8; RESP_CAP],
}

impl<'a> CcidApplets<'a> {
    /// `serial_id` is the device chip id (its BCD-encoded 8-digit serial goes into
    /// the OpenPGP full AID); `rng` is the hardware TRNG shared with the CTAPHID handler.
    /// The three `presence` params are the same physical presence source (BOOTSEL
    /// by default, optionally a GPIO button) behind per-applet traits (the
    /// caller's concrete `&RefCell` coerces to each).
    #[allow(clippy::too_many_arguments)] // one-time wiring from the worker
    pub fn new(
        fs: &'a RefCell<Store>,
        rng: &'a RefCell<FidoRng>,
        presence: &'a RefCell<dyn rsk_openpgp::UserPresence>,
        otp_presence: &'a RefCell<dyn rsk_otp::UserPresence>,
        oath_presence: &'a RefCell<dyn rsk_oath::UserPresence>,
        rescue_presence: &'a RefCell<dyn rsk_rescue::UserPresence>,
        mgmt_presence: &'a RefCell<dyn rsk_mgmt::UserPresence>,
        platform: &'a RefCell<dyn rsk_rescue::Platform>,
        serial_id: [u8; 8],
        serial_hash: [u8; 32],
        otp_key: Option<[u8; 32]>,
        devk: Option<[u8; 32]>,
        kv_total: u32,
        openpgp_mfr: u16,
    ) -> Self {
        Self {
            fs,
            rng,
            disp: Dispatcher::new(),
            // The vendor reboot-to-BOOTSEL (P1=01) is gated by the same presence
            // as the rescue applet, closing the cross-AID bypass of that gate.
            vendor: VendorApplet::new(rescue_presence),
            openpgp: OpenpgpApplet::new(serial_id, serial_hash, otp_key, rng, presence)
                .with_manufacturer(openpgp_mfr),
            management: ManagementApplet::new(serial_id, mgmt_presence),
            // Touch-flagged OATH credentials gate CALCULATE on the same button.
            oath: OathApplet::new(serial_id, serial_hash, otp_key, rng, oath_presence),
            otp: OtpApplet::new(serial_id, serial_hash, otp_key, rng, otp_presence),
            // PIV reuses the OpenPGP user-presence trait, so the same presence
            // source drives its slot/management touch policies.
            piv: PivApplet::new(serial_id, serial_hash, otp_key, rng, presence),
            // The recovery/provisioning interface: phy config, flash stats,
            // secure-boot status, session RTC, device-key attestation, reboot.
            // Registered last so the fast-path indices above stay valid.
            rescue: RescueApplet::new(
                serial_id,
                serial_hash,
                otp_key,
                devk,
                rng,
                platform,
                rescue_presence,
                kv_total,
                crate::flash_storage::FLASH_SIZE as u32,
            ),
            resp: [0; RESP_CAP],
        }
    }

    /// Serve a YubiKey Management vendor command received over the CTAPHID
    /// interface (the worker routes `Kind::Vendor` here). `cmd` is the logical
    /// command number. Returns the response body in `self.resp`, or `None` for an
    /// unsupported command (the transport then replies `CTAPHID_ERROR`). This is
    /// the FIDO-transport twin of the CCID `INS_READ_CONFIG` / OTP slot 0x13 paths,
    /// so all three report the same caps/serial/version DeviceInfo.
    pub fn ctap_mgmt(&mut self, cmd: u8, _data: &[u8]) -> Option<&[u8]> {
        match cmd {
            CTAP_READ_CONFIG => {
                let n = {
                    let mut res = ResBuf::new(&mut self.resp[..RESP_CAP]);
                    let mut fsb = self.fs.borrow_mut();
                    self.management.read_config(&mut *fsb, &mut res);
                    res.len()
                };
                Some(&self.resp[..n])
            }
            _ => None,
        }
    }

    /// Wipe the response buffer — it can hold a deciphered session key or other
    /// secrets after a dispatch. Called by the worker after the hand-off.
    pub fn scrub(&mut self) {
        use zeroize::Zeroize;
        self.resp.zeroize();
    }

    /// Drop any in-flight incoming command chain and held response remainder. Called
    /// before the out-of-band secure-PIN VERIFY dispatch so a host-initiated chaining
    /// latch cannot absorb the on-pad PIN as a chain segment (defence-in-depth beside
    /// `assemble_verify` forcing CLA 0x00). Only the trusted-display build has the
    /// on-device pad that reaches this path.
    #[cfg(feature = "display")]
    pub fn reset_chaining(&mut self) {
        self.disp.clear_chaining();
        self.disp.clear_pending();
    }

    /// Dispatch one CCID APDU synchronously, returning the response APDU (body +
    /// SW1 SW2). On-card RSA keygen is run to completion inline (see module docs);
    /// everything else goes straight to the applet dispatcher.
    pub fn handle_apdu(&mut self, apdu: &[u8]) -> &[u8] {
        // The keygen fast paths bypass `Dispatcher::process`, which is what would
        // normally drop a stale GET RESPONSE remainder and reset an interrupted
        // command chain; a GENERATE is neither a 0xC0 nor a chain segment, so
        // clearing both here matches the ordinary dispatch (applet.rs).
        if let Some(n) = self.try_rsa_keygen(apdu) {
            self.disp.clear_pending();
            self.disp.clear_chaining();
            return &self.resp[..n];
        }
        if let Some(n) = self.try_piv_rsa_keygen(apdu) {
            self.disp.clear_pending();
            self.disp.clear_chaining();
            return &self.resp[..n];
        }
        let (sw, n) = {
            let mut res = ResBuf::new(&mut self.resp[..RESP_CAP - 2]);
            let mut applets: [&mut dyn Applet<Store>; 7] = [
                &mut self.vendor,
                &mut self.openpgp,
                &mut self.management,
                &mut self.oath,
                &mut self.otp,
                &mut self.piv,
                &mut self.rescue,
            ];
            let mut fsb = self.fs.borrow_mut();
            let sw = self.disp.process(apdu, &mut applets, &mut *fsb, &mut res);
            (sw, res.len())
        };
        self.resp[n..n + 2].copy_from_slice(&sw.to_bytes());
        &self.resp[..n + 2]
    }

    /// Run one keyboard-interface OTP frame command: the 64-byte `payload` is
    /// the APDU data, `slot_id` its P1. Returns the
    /// response body (with its length) and the refreshed 8-byte status frame. The
    /// configure / update / swap commands answer only with the status record on
    /// CCID, so over the frame protocol their body is suppressed (length 0) — the
    /// host reads the bumped sequence from the status frame instead.
    pub fn handle_otp_hid(
        &mut self,
        slot_id: u8,
        payload: &[u8; 64],
    ) -> ([u8; 64], usize, [u8; 8]) {
        let mut body = [0u8; 64];
        let n = {
            let mut res = ResBuf::new(&mut body);
            let mut fsb = self.fs.borrow_mut();
            let sw = self.otp.process_hid(slot_id, payload, &mut *fsb, &mut res);
            let is_config = matches!(slot_id, 0x01 | 0x03 | 0x04 | 0x05 | 0x06);
            if sw == Sw::OK && !is_config {
                res.len()
            } else {
                0
            }
        };
        let status = {
            let mut fsb = self.fs.borrow_mut();
            self.otp.hid_status_frame(&mut *fsb)
        };
        (body, n, status)
    }

    /// The applet's 7-byte status record, for seeding the keyboard status frame at
    /// boot.
    pub fn otp_status_record(&mut self) -> [u8; 7] {
        let mut fsb = self.fs.borrow_mut();
        let f = self.otp.hid_status_frame(&mut *fsb);
        [f[1], f[2], f[3], f[4], f[5], f[6], f[7]]
    }

    /// Generate the typed ticket for a physical button press on `slot` (1 or 2),
    /// drawing the Yubico-OTP randomness from the TRNG and persisting any bumped
    /// counter. Returns the bytes to type and whether they are ASCII (to be
    /// keycode-mapped) or raw scancodes; `None` for an empty / challenge-response
    /// slot (nothing is typed).
    pub fn otp_button_ticket(
        &mut self,
        slot: u8,
        ts_secs: u32,
    ) -> Option<([u8; rsk_otp::ticket::MAX_TICKET], usize, bool)> {
        let mut rnd = [0u8; 2];
        {
            let mut r = self.rng.borrow_mut();
            rsk_fido::Rng::fill(&mut *r, &mut rnd);
        }
        let mut out = [0u8; rsk_otp::ticket::MAX_TICKET];
        let mut fsb = self.fs.borrow_mut();
        let (len, encode) = self
            .otp
            .button_ticket(slot, ts_secs, rnd, &mut *fsb, &mut out)?;
        Some((out, len, encode))
    }

    /// If `apdu` is an on-card RSA `GENERATE ASYMMETRIC KEY`, run the (slow) prime
    /// search + key store to completion and return the response length in
    /// `self.resp`. Returns `None` for everything else (incl. EC generate, which
    /// the dispatcher handles inline) so the caller falls through to normal
    /// dispatch. The search runs on BOTH cores ([`crate::core1`]) and blocks this
    /// thread-executor task; the CCID transport streams time-extensions meanwhile.
    fn try_rsa_keygen(&mut self, apdu: &[u8]) -> Option<usize> {
        if self.disp.current() != Some(IDX_OPENPGP) {
            return None;
        }
        let p = Apdu::parse(apdu).ok()?;
        if p.ins != INS_KEYPAIR_GEN || p.p1 != 0x80 {
            return None;
        }
        let (fid, nbits) =
            match self
                .openpgp
                .rsa_generate_params(&mut *self.fs.borrow_mut(), p.p1, p.p2, p.data)
            {
                // RSA slot: orchestrate the keygen here.
                Ok(Some(params)) => params,
                // EC slot (Ok(None)) or an error: let normal dispatch handle/report it.
                _ => return None,
            };
        // Both cores search; the worker blocks here while the interrupt
        // executor streams the CCID time-extensions (and the kbd/LED tasks run).
        let key = {
            let mut rng = self.rng.borrow_mut();
            crate::core1::run_rsa_search(nbits, &mut *rng)
        };
        let Some(key) = key else {
            self.resp[..2].copy_from_slice(&Sw::EXEC_ERROR.to_bytes());
            return Some(2);
        };
        let (n, sw) = {
            let mut fsb = self.fs.borrow_mut();
            let mut rng = self.rng.borrow_mut();
            self.openpgp.rsa_generate_finish(
                &mut *fsb,
                &mut *rng,
                fid,
                &key,
                &mut self.resp[..RESP_CAP - 2],
            )
        };
        self.resp[n..n + 2].copy_from_slice(&sw.to_bytes());
        Some(n + 2)
    }

    /// The PIV twin of [`Self::try_rsa_keygen`]: PIV GENERATE (INS 0x47,
    /// P1 = 0x00) with an RSA algorithm runs its dual-core prime search here so
    /// the CCID transport can stream time-extensions. Validation errors fall
    /// through to normal dispatch for the right status word.
    fn try_piv_rsa_keygen(&mut self, apdu: &[u8]) -> Option<usize> {
        if self.disp.current() != Some(IDX_PIV) {
            return None;
        }
        let p = Apdu::parse(apdu).ok()?;
        if p.ins != rsk_piv::INS_ASYM_KEYGEN || p.p1 != 0x00 {
            return None;
        }
        let (slot, nbits, pol) = {
            let mut fsb = self.fs.borrow_mut();
            self.piv
                .rsa_generate_params(&mut *fsb, p.p1, p.p2, p.data)?
        };
        // Same dual-core search as the OpenPGP arm above.
        let key = {
            let mut rng = self.rng.borrow_mut();
            crate::core1::run_rsa_search(nbits, &mut *rng)
        };
        let Some(key) = key else {
            self.resp[..2].copy_from_slice(&Sw::EXEC_ERROR.to_bytes());
            return Some(2);
        };
        let (n, sw) = {
            let mut fsb = self.fs.borrow_mut();
            let mut rng = self.rng.borrow_mut();
            self.piv.rsa_generate_finish(
                &mut *fsb,
                &mut *rng,
                slot,
                pol,
                &key,
                &mut self.resp[..RESP_CAP - 2],
            )
        };
        self.resp[n..n + 2].copy_from_slice(&sw.to_bytes());
        Some(n + 2)
    }
}
