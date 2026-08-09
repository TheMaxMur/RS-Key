// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Bridges CCID `XfrBlock` APDUs to the applet dispatcher; selection state is
//! independent of the CTAPHID channel. On the device this runs on the worker
//! (thread executor), so on-card RSA keygen blocks here to completion while the
//! CCID transport, on its high-priority task, streams T=1 time-extensions.

use core::cell::RefCell;

use rsk_fs::{Fs, Storage};

use rsk_mgmt::ManagementApplet;
use rsk_oath::OathApplet;
use rsk_openpgp::OpenpgpApplet;
use rsk_openpgp::consts::INS_KEYPAIR_GEN;
use rsk_otp::OtpApplet;
use rsk_piv::PivApplet;
use rsk_rescue::RescueApplet;
use rsk_sdk::{Apdu, Applet, Dispatcher, ResBuf, Sw};

use rsk_vendor::VendorApplet;

use crate::Hooks;

// A CCID XfrBlock frame carries MAX_CCID_MSG (2048) minus the 10-byte CCID
// header = 2038 payload bytes. The applet response (body + 2-byte SW) must fit
// one frame; sizing this to the full message let a large response (e.g. a long
// OATH LIST) overrun the frame, and `run_xfr` silently dropped the tail incl. SW.
const RESP_CAP: usize = 2038;

/// Registration-order indices of the applets whose RSA keygen is fast-pathed.
const IDX_OPENPGP: usize = 1;
const IDX_PIV: usize = 5;

/// The YubiKey capability bit that gates each applet, in registration order
/// `[vendor, openpgp, management, oath, otp, piv, rescue]`. `0` = always
/// available: management (the re-enable path), vendor and rescue (recovery) must
/// never be gated off, or `ykman config usb --disable` would be irreversible.
const APPLET_CAPS: [u16; 7] = [
    0,
    rsk_mgmt::CAP_OPENPGP,
    0,
    rsk_mgmt::CAP_OATH,
    rsk_mgmt::CAP_OTP,
    rsk_mgmt::CAP_PIV,
    0,
];

/// YubiKey Management vendor commands carried over CTAPHID (logical, i.e.
/// `TYPE_INIT` already stripped by the transport). READ CONFIG (`0x42`) is what
/// `ykman` / Yubico Authenticator read to identify the key over the FIDO
/// interface. The DEFAULT build ALSO serves WRITE CONFIG (`0x43`) ungated, for
/// full ykman parity; `--features strict-config` refuses it (see the write arm).
const CTAP_READ_CONFIG: u8 = 0x42;
/// WRITE CONFIG (ykman `CTAP_WRITE_CONFIG`): persist the DeviceConfig blob. Served
/// only on the DEFAULT (permissive) build — under `strict-config` a config write
/// stays CCID/FIDO-CBOR-gated only, so this is not carried.
#[cfg(not(feature = "strict-config"))]
const CTAP_WRITE_CONFIG: u8 = 0x43;

pub struct CcidApplets<'a, S: Storage, R: crate::Rng + 'static, VP: rsk_vendor::Platform> {
    fs: &'a RefCell<Fs<S>>,
    rng: &'a RefCell<R>,
    hooks: &'a RefCell<dyn Hooks<S>>,
    disp: Dispatcher,
    vendor: VendorApplet<'a, VP>,
    openpgp: OpenpgpApplet<'a>,
    management: ManagementApplet<'a>,
    oath: OathApplet<'a>,
    otp: OtpApplet<'a>,
    piv: PivApplet<'a>,
    rescue: RescueApplet<'a>,
    /// Cached enabled-applications mask from `EF_DEV_CONF`; reloaded when a config
    /// write sets the dirty latch. Gates CCID SELECT, the OTP keyboard interface
    /// and (via the worker) the FIDO2/U2F transports.
    enabled_caps: u16,
    resp: [u8; RESP_CAP],
}

/// The records that *gate* each applet, passed to [`rsk_fs::Fs::factory_wipe`] so
/// they are removed only after everything else is provably gone. A device-wide wipe
/// bypasses each applet's own two-phase sweep, so it has to carry the same rule: a
/// prefix that took a gate record first and then lost power leaves the applet's
/// secrets reachable — either behind a *published* credential the next boot
/// re-provisions (PIV's PIN/PUK/retries and its 0x9B management key, whose slot keys
/// are not PIN-bound at rest; FIDO's PIN and `alwaysUv` latch) or, for OATH, behind
/// no credential at all, since its `select` derives `validated` from the absence of
/// the access code. OpenPGP's PW verifiers are uniformity — its DEK chain already
/// makes a restored default PW1 useless — but its UIF flags and every other arm are
/// load-bearing.
///
/// `EF_DEV_CONF` is deliberately **not** here, though its absence also resolves to a
/// published default ("every supported application enabled"). It gates which applets
/// are reachable, not whether a surviving secret is protected: for FIDO, PIV, OATH
/// and OpenPGP the applet's own credential gate is in this set, so re-enabling one
/// buys nothing. That argument does **not** cover OTP — its slot records are phase 1
/// with no gate of their own, and a surviving static-password or HOTP slot emits on
/// touch alone once `CAP_OTP` is back. What decides it is the other half: the record
/// is host-writable ungated on the default build, so deferring it denies an attacker
/// nothing they cannot simply write back.
///
/// **This must stay a plain fold over the applets' own exported predicates.** The one
/// arm that was ever open-coded here is the one that went missing: OATH's
/// `is_oath_lock_fid` was private, so it could not be named from this crate and was
/// simply left out, and a torn device reset then served every surviving TOTP secret
/// unauthenticated (audit run-36). A new applet adds its predicate to its own crate
/// and one line here; `scripts/gate_union.py` fails the gate when it does not.
#[cfg(any(not(feature = "strict-config"), feature = "display"))]
pub fn gates_wiped_last(fid: u16) -> bool {
    rsk_fido::is_fido_gate_fid(fid)
        || rsk_piv::files::is_piv_gate_fid(fid)
        || rsk_oath::is_oath_lock_fid(fid)
        || rsk_openpgp::terminate::is_openpgp_gate_fid(fid)
}

impl<'a, S: Storage, R: crate::Rng + 'static, VP: rsk_vendor::Platform> CcidApplets<'a, S, R, VP> {
    /// `serial_id` is the device chip id (its BCD-encoded 8-digit serial goes into
    /// the OpenPGP full AID); `rng` is the hardware TRNG, shared with the CTAPHID
    /// handler. `presence` is the one physical presence source (BOOTSEL by
    /// default, optionally a GPIO button, or the screen): it was five parameters
    /// of the same `&RefCell` because each applet names its own trait, and the
    /// caller's concrete type coerces to every one of them here instead.
    #[allow(clippy::too_many_arguments)] // one-time wiring from the worker
    pub fn new<PR: crate::UserPresence + 'static>(
        fs: &'a RefCell<Fs<S>>,
        rng: &'a RefCell<R>,
        hooks: &'a RefCell<dyn Hooks<S>>,
        presence: &'a RefCell<PR>,
        platform: &'a RefCell<dyn rsk_rescue::Platform>,
        vendor_platform: VP,
        serial_id: [u8; 8],
        serial_hash: [u8; 32],
        otp_key: Option<[u8; 32]>,
        devk: Option<[u8; 32]>,
        kv_total: u32,
        flash_size: u32,
        openpgp_mfr: u16,
    ) -> Self {
        Self {
            fs,
            rng,
            hooks,
            disp: Dispatcher::new(),
            // The vendor reboot-to-BOOTSEL (P1=01) is gated by the same presence
            // as the rescue applet (one `&RefCell<Presence>` behind two traits),
            // closing the cross-AID bypass of that gate.
            vendor: VendorApplet::new(vendor_platform, presence),
            openpgp: OpenpgpApplet::new(serial_id, serial_hash, otp_key, rng, presence)
                .with_manufacturer(openpgp_mfr),
            management: ManagementApplet::new(serial_id, presence),
            // Touch-flagged OATH credentials gate CALCULATE on the same button.
            oath: OathApplet::new(serial_id, serial_hash, otp_key, rng, presence),
            otp: OtpApplet::new(serial_id, serial_hash, otp_key, rng, presence),
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
                presence,
                kv_total,
                flash_size,
            ),
            enabled_caps: rsk_mgmt::read_enabled_caps(&mut fs.borrow_mut()),
            resp: [0; RESP_CAP],
        }
    }

    /// Reload the cached enabled-applications mask from flash — called after a
    /// config write flips [`rsk_mgmt::take_dev_conf_dirty`], so the next gated
    /// command sees the new set. Returns the reloaded mask.
    pub fn refresh_enabled(&mut self) -> u16 {
        self.enabled_caps = rsk_mgmt::read_enabled_caps(&mut self.fs.borrow_mut());
        self.enabled_caps
    }

    /// Whether the applet/transport guarded by capability bit `cap` is enabled.
    /// The worker consults this to gate the FIDO2 (CBOR) and U2F (MSG) transports.
    pub fn caps_enabled(&self, cap: u16) -> bool {
        rsk_mgmt::cap_enabled(self.enabled_caps, cap)
    }

    /// The `Dispatcher::set_enabled` index-mask derived from the current cap mask:
    /// bit `i` set → applet `i` (in `APPLET_CAPS` order) is selectable.
    fn applet_enable_mask(&self) -> u32 {
        let mut mask = 0u32;
        for (i, &cap) in APPLET_CAPS.iter().enumerate() {
            if rsk_mgmt::cap_enabled(self.enabled_caps, cap) {
                mask |= 1 << i;
            }
        }
        mask
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
            // DEFAULT build only: ykman's WRITE CONFIG over FIDO. The payload is
            // the DeviceConfig `get_bytes()` blob — a leading length byte then the
            // TLV — the same store CCID WRITE CONFIG / OTP-HID SET_DEVICE_INFO use,
            // so it round-trips into every READ CONFIG. Ungated for parity (a
            // strict build never defines this arm; the write stays gated elsewhere).
            #[cfg(not(feature = "strict-config"))]
            CTAP_WRITE_CONFIG => {
                if _data.is_empty() {
                    return None;
                }
                let len = _data[0] as usize;
                if 1 + len > _data.len() {
                    return None;
                }
                let ok = {
                    let mut fsb = self.fs.borrow_mut();
                    rsk_mgmt::persist_dev_conf(&mut *fsb, &_data[1..1 + len]).is_ok()
                };
                // An empty body is the ykman-expected acknowledgement.
                if ok { Some(&self.resp[..0]) } else { None }
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

    /// Device-wide factory reset: wipe all flash but the org attestation, exactly
    /// like the trusted-display factory-reset flow (`rsk_fido::survives_factory_reset`).
    /// The next boot re-provisions a fresh seed. Called by the worker after a
    /// Management RESET's SW_OK, then a reboot. DEFAULT build only.
    ///
    /// Returns whether the wipe actually completed: a truncated enumeration or a
    /// failed remove must not be laundered into a reboot that looks like success.
    #[cfg(not(feature = "strict-config"))]
    pub fn factory_wipe(&mut self) -> bool {
        self.fs
            .borrow_mut()
            .factory_wipe(rsk_fido::survives_factory_reset, gates_wiped_last)
            .is_ok()
    }

    /// Whether the applet that owns PIN reference `p2` is the one currently SELECTED
    /// and enabled.
    ///
    /// The CCID pinpad path had no gate at all: a bare `PC_to_RDR_Secure` painted the
    /// trusted display's PIN pad for up to 30 s with nothing selected and even with
    /// the target applet disabled by `ykman config usb --disable` — the capability
    /// check ran later, on the VERIFY, so it stopped the authentication and not the
    /// screen (audit run-36). Refusing here means the panel is never painted for a
    /// credential the host has not addressed.
    #[cfg(feature = "display")]
    pub fn pin_ref_ready(&self, p2: u8) -> bool {
        let idx = match p2 {
            rsk_openpgp::consts::PW1_MODE81
            | rsk_openpgp::consts::PW1_MODE82
            | rsk_openpgp::consts::PW3_MODE83 => IDX_OPENPGP,
            rsk_usb::secure_pin::PIV_PIN_P2 => IDX_PIV,
            _ => return false,
        };
        self.disp.current() == Some(idx) && self.caps_enabled(APPLET_CAPS[idx])
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

    /// Drop the selected applet's security status on an ICC power transition, so a
    /// `SCardDisconnect(SCARD_RESET_CARD)` really does force re-authentication
    /// instead of leaving a verified PIN for whoever connects next.
    pub fn reset_card(&mut self) {
        let mut applets: [&mut dyn Applet<Fs<S>>; 7] = [
            &mut self.vendor,
            &mut self.openpgp,
            &mut self.management,
            &mut self.oath,
            &mut self.otp,
            &mut self.piv,
            &mut self.rescue,
        ];
        let mut fsb = self.fs.borrow_mut();
        self.disp.reset_card(&mut applets, &mut *fsb);
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
        // A disabled application's applet is invisible: SELECT (and any command to
        // it) returns FILE_NOT_FOUND, so `ykman config usb --disable X` really
        // removes X over CCID, not just from the DeviceInfo report.
        self.disp.set_enabled(self.applet_enable_mask());
        let (sw, n) = {
            let mut res = ResBuf::new(&mut self.resp[..RESP_CAP - 2]);
            let mut applets: [&mut dyn Applet<Fs<S>>; 7] = [
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
        // OTP disabled: the function slots (program/update/swap/challenge-response)
        // go inert, but the identify/config slots (serial, READ/WRITE CONFIG,
        // status) stay live so the host can still read DeviceInfo and re-enable OTP.
        if !self.caps_enabled(rsk_mgmt::CAP_OTP) && rsk_otp::is_function_slot(slot_id) {
            let status = self.otp.hid_status_frame(&mut self.fs.borrow_mut());
            return ([0u8; 64], 0, status);
        }
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
        if !self.caps_enabled(rsk_mgmt::CAP_OTP) {
            return None; // OTP disabled — a button press types nothing.
        }
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
    /// dispatch. The search is the board's ([`crate::Hooks::rsa_search`]) and
    /// blocks this task; the CCID transport streams time-extensions meanwhile.
    fn try_rsa_keygen(&mut self, apdu: &[u8]) -> Option<usize> {
        // The cap check closes the contrived window where OpenPGP was selected and
        // then disabled — the fast path bypasses the dispatcher's own gate.
        if self.disp.current() != Some(IDX_OPENPGP) || !self.caps_enabled(rsk_mgmt::CAP_OPENPGP) {
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
        // Both cores search; the worker blocks here while the interrupt executor
        // streams the CCID time-extensions (and the kbd/LED tasks run). A build
        // with no accelerator answers `None` and never reaches here — the applet's
        // own single-core path runs from normal dispatch instead.
        let key = {
            let mut rng = self.rng.borrow_mut();
            self.hooks.borrow_mut().rsa_search(nbits, &mut *rng)?
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
        if self.disp.current() != Some(IDX_PIV) || !self.caps_enabled(rsk_mgmt::CAP_PIV) {
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
        // Same search as the OpenPGP arm above, and the same fall-through when
        // there is no accelerator to run it.
        let key = {
            let mut rng = self.rng.borrow_mut();
            self.hooks.borrow_mut().rsa_search(nbits, &mut *rng)?
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

#[cfg(test)]
#[path = "ccid_tests.rs"]
mod tests;
