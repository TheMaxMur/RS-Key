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
use rsk_fs::{Fs, Storage};
use rsk_sdk::{Apdu, Applet, ResBuf, Sw};

/// CTAP-over-ISO7816 lives in the proprietary class (CTAP 2.1 §11.2.1).
const CLA_PROPRIETARY: u8 = 0x80;
/// `NFCCTAP_MSG`: one CTAP2 command in the data field, its response in the body.
const INS_CTAP_MSG: u8 = 0x10;
/// `NFCCTAP_GETRESPONSE`: the poll a host issues after a `91 00`, and at
/// `P1 = 0x11` the cancel. This device never answers `91 00` — see `process` below.
const INS_CTAP_GETRESPONSE: u8 = 0x11;
/// The `P1` that makes a GETRESPONSE a cancel rather than a poll.
const P1_CANCEL: u8 = 0x11;

/// FIDO over CCID. Holds no FIDO state of its own; every field is a handle the
/// CTAPHID transport also holds.
pub struct FidoCcidApplet<'a, R: rsk_sdk::Rng + 'static> {
    /// **The device's one FIDO session state**, borrowed from the worker. A second
    /// copy would give a host a second per-boot [`rsk_fido::consts::PIN_MISMATCH_LIMIT`]
    /// budget — six PIN guesses per power cycle instead of three — which is exactly
    /// the restart-by-reboot attack `FidoState::restore_pin_lock` exists to close.
    /// It also carries the PIN/UV token, the credential-management walk and the
    /// soft lock's RAM seed, none of which may fork per transport.
    state: &'a RefCell<rsk_fido::FidoState>,
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
    fn with_ctx<S: Storage, T>(
        &mut self,
        fs: &mut Fs<S>,
        f: impl FnOnce(&mut rsk_fido::Ctx<'_, S, R>) -> T,
    ) -> T {
        let mkek = read_fused(self.mkek_source);
        let dev = Device {
            serial_hash: &self.serial_hash,
            serial_id: &self.serial_id,
            otp_key: mkek.as_deref(),
        };
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
        f(&mut ctx)
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

    /// `80 10` is a CTAP2 command; anything in the interindustry class is U2F.
    ///
    /// **No `91 00` keep-alive is ever returned**, so the host's GETRESPONSE poll
    /// loop never runs. A touch wait blocks inside this call while the CCID
    /// transport streams T=1 time extensions on its own task — the same thing an
    /// OATH `PROP_TOUCH` calculate and an OpenPGP UIF signature already do, and the
    /// reason those need no keep-alive of their own either. The cancel arm is still
    /// answered, because a host that gave up on a wait sends it regardless.
    fn process(&mut self, apdu: &Apdu, fs: &mut Fs<S>, res: &mut ResBuf) -> Sw {
        if apdu.cla == CLA_PROPRIETARY {
            return match apdu.ins {
                INS_CTAP_MSG
                    if !rsk_devconf::cap_enabled(self.enabled_caps, rsk_devconf::CAP_FIDO2) =>
                {
                    Sw::COMMAND_NOT_ALLOWED
                }
                INS_CTAP_MSG => {
                    let n = self.with_ctx(fs, |ctx| {
                        rsk_fido::process_cbor(ctx, apdu.data, res.spare_mut())
                    });
                    res.commit(n);
                    Sw::OK
                }
                // Nothing is ever pending, so a poll has nothing to report and a
                // cancel has nothing to stop. Both are answered rather than
                // refused: a host that sends one is following the protocol.
                INS_CTAP_GETRESPONSE if apdu.p1 == P1_CANCEL || apdu.p1 == 0 => Sw::OK,
                _ => Sw::INS_NOT_SUPPORTED,
            };
        }
        if !rsk_devconf::cap_enabled(self.enabled_caps, rsk_devconf::CAP_U2F) {
            return Sw::COMMAND_NOT_ALLOWED;
        }
        let (sw, n) = self.with_ctx(fs, |ctx| {
            let spare = res.spare_mut();
            rsk_fido::u2f::process_u2f(ctx, apdu, spare)
        });
        res.commit(n);
        sw
    }
}
