// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The FIDO applet on the **CCID** transport: CTAP2 and U2F carried as ISO 7816
//! APDUs, the encoding CTAP 2.1 §11.2 defines for ISO7816 readers and
//! `python-fido2`'s `CtapPcscDevice` (hence `ykman`) speaks. PC/SC does not care
//! whether the reader is NFC or the device's own CCID interface, so this is
//! reachable over plain USB.
//!
//! Nothing here is FIDO logic. Selection, the enabled-applications gate, command
//! chaining and GET RESPONSE all belong to the dispatcher; below the framing this
//! calls the same `rsk_fido` entry points the CTAPHID handler calls, over **the
//! same `FidoState`** — see the field's comment for why that is not optional.

use core::cell::RefCell;

use rsk_crypto::{Device, FusedKey, read_fused};
use rsk_fido::CtapError;
use rsk_fido::consts::{CTAP_AUTHENTICATE, CTAP_REGISTER, CTAP_VERSION};
use rsk_fs::{Fs, Storage};
use rsk_sdk::{Apdu, Applet, ResBuf, Sw};
// CTAP 2.1 §11.2.1 gives CTAP-over-ISO7816 the proprietary class; U2F refuses it.
use rsk_sdk::apdu::CLA_PROPRIETARY;

/// `NFCCTAP_MSG`: one CTAP2 command in the data field, its response in the body.
const INS_CTAP_MSG: u8 = 0x10;
/// `NFCCTAP_GETRESPONSE`: the poll a host issues after a `91 00`, and at
/// `P1 = 0x11` the cancel. This device never answers `91 00` — see `process` below.
const INS_CTAP_GETRESPONSE: u8 = 0x11;
/// `NFCCTAP_CONTROL`, from a CTAP 2.1 draft and in no published revision. A
/// YubiKey 5.8.0 takes `P1 01` (end of session) with `P2 00` alone.
const INS_CTAP_CONTROL: u8 = 0x12;
/// The end of session, answered with nothing ended: a host may send it between a
/// ceremony and its next getInfo, which needs the applet as it was.
const P1_CONTROL_END: u8 = 0x01;

/// FIDO over CCID. Holds no FIDO state of its own; every field is a handle the
/// CTAPHID transport also holds.
pub struct FidoCcidApplet<'a, R: rsk_sdk::Rng + 'static> {
    /// **The device's one FIDO session state**, borrowed from the worker. A second
    /// copy would give a host a second per-boot [`rsk_fido::consts::PIN_MISMATCH_LIMIT`]
    /// budget — six PIN guesses per power cycle instead of three — which is exactly
    /// the restart-by-reboot attack `FidoState::restore_pin_lock` exists to close.
    /// It also carries the PIN/UV token, the credential-management walk and the
    /// soft lock's RAM seed, none of which may fork per transport.
    pub(crate) state: &'a RefCell<rsk_fido::FidoState>,
    rng: &'a RefCell<R>,
    presence: &'a RefCell<dyn rsk_sdk::UserPresence>,
    serial_id: [u8; 8],
    serial_hash: [u8; 32],
    mkek_source: Option<FusedKey>,
    /// Device uptime at the current APDU, set by the router before each dispatch.
    /// The `Applet` trait carries only the filesystem as context, and this decides
    /// the CTAP 2.1 §6.6 reset window and every credential timestamp, so a stale
    /// zero here would leave the reset window open for ever.
    now_ms: u64,
    /// The enabled-applications mask, same source and same dispatch. One AID
    /// carries two applications here, and `ykman config usb --disable` names them
    /// separately, so the *commands* are gated rather than only the SELECT — else
    /// disabling FIDO2 would leave every CTAP2 command reachable behind U2F's bit.
    enabled_caps: u16,
}

impl<'a, R: rsk_sdk::Rng + 'static> FidoCcidApplet<'a, R> {
    pub fn new<PR: rsk_sdk::UserPresence + 'static>(
        state: &'a RefCell<rsk_fido::FidoState>,
        rng: &'a RefCell<R>,
        presence: &'a RefCell<PR>,
        serial_id: [u8; 8],
        serial_hash: [u8; 32],
        mkek_source: Option<FusedKey>,
    ) -> Self {
        Self {
            state,
            rng,
            presence,
            serial_id,
            serial_hash,
            mkek_source,
            now_ms: 0,
            enabled_caps: 0,
        }
    }

    /// Stamp the dispatch about to run with the two things the `Applet` trait's
    /// filesystem-only context cannot carry: the transport's clock and the
    /// enabled-applications mask. Called by the router immediately before it
    /// dispatches, so neither can be a value from a previous command.
    pub fn stamp(&mut self, now_ms: u64, enabled_caps: u16) {
        self.now_ms = now_ms;
        self.enabled_caps = enabled_caps;
    }

    /// Run `f` against a fully-built FIDO context. Every borrow is taken here and
    /// released with the closure, so no `RefCell` is held across two commands.
    /// `None` past the latch when the fused key did not read ([`Device::fused`]).
    fn with_ctx<S: Storage, T>(
        &mut self,
        fs: &mut Fs<S>,
        f: impl FnOnce(&mut rsk_fido::Ctx<'_, S, R>) -> T,
    ) -> Option<T> {
        let mkek = read_fused(self.mkek_source);
        let dev = Device::fused(&self.serial_hash, &self.serial_id, &mkek)?;
        let mut rngb = self.rng.borrow_mut();
        let mut presence = self.presence.borrow_mut();
        let mut stb = self.state.borrow_mut();
        let mut ctx = rsk_fido::Ctx {
            dev,
            fs,
            rng: &mut *rngb,
            state: &mut stb,
            now_ms: self.now_ms,
            presence: &mut *presence,
        };
        Some(f(&mut ctx))
    }
}

impl<S: Storage, R: rsk_sdk::Rng + 'static> Applet<Fs<S>> for FidoCcidApplet<'_, R> {
    fn aid(&self) -> &'static [u8] {
        rsk_fido::consts::FIDO_AID
    }

    /// A CTAP2 response routinely passes the 256 bytes a short `Le` asks for —
    /// getInfo alone is ~400 — and `CtapPcscDevice` answers `61xx` with standard
    /// GET RESPONSE, so opt into the dispatcher's outgoing chaining.
    fn response_chaining(&self) -> bool {
        true
    }

    /// SELECT answers `U2F_V2`, which is how a host learns CTAP1 is served here.
    /// A re-SELECT clears nothing: the session state is the device's, shared with
    /// the CTAPHID transport, and dropping a PIN token because a reader re-selected
    /// the applet would let either transport revoke the other's authorization.
    fn select(&mut self, _reselect: bool, _fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        if res.extend(rsk_fido::consts::U2F_VERSION) {
            Sw::OK
        } else {
            Sw::WRONG_LENGTH
        }
    }

    /// CTAP2's three instructions are served under `00` as under `80`, and U2F's
    /// under `00` alone, which is how a YubiKey 5.8.0 answers them. Over CCID no
    /// other class gets here; called directly, one goes to U2F and is refused there.
    ///
    /// **No `91 00` keep-alive is ever returned**, so the host's GETRESPONSE poll
    /// loop never runs. A touch wait blocks inside this call while the CCID
    /// transport streams T=1 time extensions on its own task — the same thing an
    /// OATH `PROP_TOUCH` calculate and an OpenPGP UIF signature already do, and the
    /// reason those need no keep-alive of their own either. A poll or a cancel is
    /// still answered, because a host that gave up on a wait sends one regardless.
    fn process(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        match (apdu.is_basic_class(), apdu.ins) {
            (true, INS_CTAP_MSG)
                if !rsk_devconf::cap_enabled(self.enabled_caps, rsk_devconf::CAP_FIDO2) =>
            {
                Sw::COMMAND_NOT_ALLOWED
            }
            (true, INS_CTAP_MSG) => {
                let Some(n) = self.with_ctx(fs, |ctx| {
                    rsk_fido::process_cbor(ctx, apdu.data, res.spare_mut())
                }) else {
                    res.push(CtapError::FUSED_KEY_UNREAD.as_u8());
                    return Sw::OK;
                };
                res.commit(n);
                Sw::OK
            }
            // Nothing is ever pending, so a poll has nothing to report and a cancel
            // nothing to stop; a YubiKey 5.8.0 answers either, whatever its P1-P2,
            // with the status of a wait that ran out.
            (true, INS_CTAP_GETRESPONSE) => {
                res.push(CtapError::UserActionTimeout.as_u8());
                Sw::OK
            }
            // What it ends there is not documented, so nothing here changes state.
            (true, INS_CTAP_CONTROL) if (apdu.p1, apdu.p2) == (P1_CONTROL_END, 0) => Sw::OK,
            (true, INS_CTAP_CONTROL) => Sw::INCORRECT_P1P2,
            (_, CTAP_REGISTER | CTAP_AUTHENTICATE | CTAP_VERSION)
                if apdu.cla == CLA_PROPRIETARY =>
            {
                Sw::CLA_NOT_SUPPORTED
            }
            _ if apdu.cla == CLA_PROPRIETARY => Sw::INS_NOT_SUPPORTED,
            _ if !rsk_devconf::cap_enabled(self.enabled_caps, rsk_devconf::CAP_U2F) => {
                Sw::COMMAND_NOT_ALLOWED
            }
            _ => {
                let Some((sw, n)) = self.with_ctx(fs, |ctx| {
                    let spare = res.spare_mut();
                    rsk_fido::u2f::process_u2f(ctx, apdu, spare)
                }) else {
                    return Sw::FUSED_KEY_UNREAD;
                };
                res.commit(n);
                sw
            }
        }
    }
}
