// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![cfg_attr(not(test), no_std)]

//! `rsk-fido` — the FIDO2 (CTAP2) + U2F (CTAP1) applet. The logic is pure and
//! host-testable: the device seed, serial, RNG and flash come from the caller
//! ([`Ctx`]), never from globals; `firmware` wires in the RP2350 TRNG and flash.

// The ML-DSA credential keys are heap-boxed (their ~13–23 KB `rsk-mldsa` expanded
// keys would otherwise sit on the worker stack right below the stack-heavy sign;
// see `ec::CredKey`). The firmware provides the heap; everything else stays
// no-alloc.
extern crate alloc;

pub mod cbordec;
pub mod cert;
pub mod clientpin;
pub mod config;
pub mod consts;
pub mod cose;
pub mod credential;
pub mod credmgmt;
pub mod ec;
pub mod error;
pub mod getassertion;
pub mod getinfo;
pub mod hmacsecret;
pub mod journal;
pub mod keyderiv;
pub mod largeblobext;
pub mod largeblobs;
pub mod makecredential;
pub mod passkeys;
pub mod reset;
pub mod seed;
pub mod selection;
pub mod state;
pub mod u2f;
pub mod vendor;

pub use error::{CTAP2_OK, CtapError, CtapResult};
pub use reset::{is_fido_gate_fid, survives_factory_reset};

use rsk_crypto::Device;
use rsk_fs::{Fs, Storage};
pub use rsk_sdk::{Confirm, ConfirmKind};

pub use state::FidoState;

/// A source of random bytes — the device TRNG in `firmware`, a deterministic
/// stream in tests. Decouples the FIDO logic from any specific `rand_core` version.
pub trait Rng {
    fn fill(&mut self, buf: &mut [u8]);
}

/// Outcome of asking for physical user presence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// The user touched the device.
    Confirmed,
    /// No touch within the timeout.
    Timeout,
    /// The user actively declined (no decline path on the BOOTSEL button today,
    /// but tests and other front-ends can produce it → `OPERATION_DENIED`).
    Declined,
    /// The platform sent `CTAPHID_CANCEL` while the touch was awaited; the
    /// in-flight CTAP2 command must answer `CTAP2_ERR_KEEPALIVE_CANCEL`.
    Cancelled,
}

/// Outcome of collecting a built-in-UV PIN on the device's own UI (the
/// trusted-display PIN pad). Built-in UV proves *user verification* without the
/// PIN ever crossing the host — the anti-keylogger counterpart to the on-screen
/// Approve/Deny that proves *user presence*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinEntry {
    /// The user committed a PIN of this many ASCII-digit bytes, in `out[..len]`.
    Entered(usize),
    /// The user tapped Cancel on the pad — a deliberate decline.
    Declined,
    /// No completed entry within the presence timeout.
    Timeout,
    /// The platform sent `CTAPHID_CANCEL` while the pad was up.
    Cancelled,
    /// The backend has no on-device UI to collect a PIN (the default).
    Unsupported,
}

/// Obtains physical user presence. The firmware polls the BOOTSEL button; with
/// no button configured it confirms immediately, which is also what host tests
/// use via [`AlwaysConfirm`].
pub trait UserPresence {
    /// Ask for presence. `confirm` describes the pending operation for a trusted
    /// on-screen Approve/Deny prompt; the BOOTSEL-button backend ignores it.
    fn request(&mut self, confirm: Confirm<'_>) -> Presence;

    /// Whether this backend actually shows the [`Confirm`] to the user, so a touch
    /// carries *which* operation it approves. The BOOTSEL button discards the title
    /// and raises the same indication for every ceremony; only the trusted display
    /// overrides this. CTAP 2.1 §6.6 exempts exactly such an authenticator from the
    /// `authenticatorReset` power-up window ([`reset`](crate::reset::reset)).
    fn shows_confirm(&self) -> bool {
        false
    }

    /// Whether this backend can collect built-in user verification — a PIN entered
    /// on the authenticator's own UI, so it never reaches the host. Only the
    /// trusted-display backend overrides this; the BOOTSEL button and the host-test
    /// stand-in have no UI to type a PIN, so built-in UV is absent and `options.uv`
    /// stays unadvertised (and `clientPIN` 0x06/0x07 answer `UnsupportedOption`).
    fn uv_available(&self) -> bool {
        false
    }

    /// Collect a built-in-UV PIN on the device's own UI as ASCII digits into `out`,
    /// refusing to *commit* below `min_len` characters so a fat-fingered short entry
    /// can't burn a retry. Returns how the entry ended. The default — no on-device
    /// UI — reports [`PinEntry::Unsupported`]; this is only reached on a backend
    /// that also overrides [`uv_available`](Self::uv_available).
    fn collect_pin(&mut self, _min_len: usize, _out: &mut [u8]) -> PinEntry {
        PinEntry::Unsupported
    }

    /// Collect the authenticator's **own** device PIN — the one a trusted-display
    /// build's onboarding sets, not the clientPIN — on the device's own UI. Separate
    /// from [`collect_pin`](Self::collect_pin) because the screen must name which PIN
    /// it is asking for: a pad captioned "FIDO PIN" that verifies the device PIN is
    /// exactly the kind of lie the trusted display exists to prevent. Used by the
    /// vendor gate when no clientPIN is set (see `vendor::pin_gate`).
    fn collect_device_pin(&mut self, _min_len: usize, _out: &mut [u8]) -> PinEntry {
        PinEntry::Unsupported
    }
}

/// A [`UserPresence`] that confirms instantly — the no-button default and the
/// host-test stand-in.
pub struct AlwaysConfirm;

impl UserPresence for AlwaysConfirm {
    fn request(&mut self, _confirm: Confirm<'_>) -> Presence {
        Presence::Confirmed
    }
}

/// Per-request context the firmware threads into the FIDO commands: the device
/// identity, the flash file system, an RNG, the cross-message PIN/UV state and
/// the current uptime.
pub struct Ctx<'a, S: Storage, R: Rng> {
    pub dev: Device<'a>,
    pub fs: &'a mut Fs<S>,
    pub rng: &'a mut R,
    pub state: &'a mut FidoState,
    /// Device uptime at request time — the credential creation timestamp.
    pub now_ms: u64,
    /// Physical user-presence source (BOOTSEL button); [`AlwaysConfirm`] when no
    /// button is configured or in tests.
    pub presence: &'a mut dyn UserPresence,
}

impl<S: Storage, R: Rng> Ctx<'_, S, R> {
    /// Request a touch, mapping any non-confirmation (timeout, decline or
    /// cancel) to `false`. Callers that must distinguish a `CTAPHID_CANCEL`
    /// (→ `KEEPALIVE_CANCEL`) use [`require_presence`](Self::require_presence).
    pub fn check_user_presence(&mut self, confirm: Confirm<'_>) -> bool {
        self.presence.request(confirm) == Presence::Confirmed
    }

    /// Obtain user presence for a CTAP2 command, mapping the outcome to its
    /// status code: a `CTAPHID_CANCEL` aborts with `KEEPALIVE_CANCEL`, any
    /// other non-confirmation (timeout, decline) with `OPERATION_DENIED`.
    pub fn require_presence(&mut self, confirm: Confirm<'_>) -> Result<(), CtapError> {
        match self.presence.request(confirm) {
            Presence::Confirmed => Ok(()),
            Presence::Cancelled => Err(CtapError::KeepAliveCancel),
            Presence::Timeout | Presence::Declined => Err(CtapError::OperationDenied),
        }
    }

    /// The device seed for FIDO operations: the RAM copy a vendor `UNLOCK` left
    /// behind wins over flash; on a soft-locked device with no unlock this
    /// session, both fail and the operation errors out — that is the lock.
    pub fn load_keydev(&mut self) -> Option<[u8; 32]> {
        self.state
            .keydev_dec
            .or_else(|| seed::load_keydev(&self.dev, self.fs))
    }
}

/// Dispatch one CTAPHID_CBOR message: `data` is `command_byte ‖ cbor_params`.
///
/// Writes the response — one status byte then, on success, the CBOR payload —
/// into `out` and returns its length.
pub fn process_cbor<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, data: &[u8], out: &mut [u8]) -> usize {
    if out.is_empty() {
        return 0;
    }
    // Empty CTAPHID_CBOR is CTAP1_ERR_INVALID_LENGTH.
    let Some((&cmd, params)) = data.split_first() else {
        out[0] = CtapError::InvalidLength.as_u8();
        return 1;
    };

    // Retire a pinUvAuthToken whose usage timer has elapsed before it can
    // authorize this command (CTAP 2.1 §6.5.5.7), and an enumerate cursor left
    // idle past its own window — a *Next* leg brings no authorization to expire.
    ctx.state.expire_stale_token(ctx.now_ms);
    ctx.state.expire_stale_walk(ctx.now_ms);

    // CTAP 2.2 §6: a stateful sequence may assume it is "exclusively preceded" by
    // its own kind or by the command that initialized it, so every sequence this
    // command does not continue ends here. `getAssertion` continues nothing — it
    // is an initializer, and arms its own walk after this clears the previous one.
    ctx.state.retire_sequences_except(cmd);

    let result = match cmd {
        consts::CTAP_GET_INFO => {
            // minPINLength / forceChangePin come from EF_MINPINLEN ([len, force]).
            let mut mp = [0u8; 2];
            let (min_pin, force) = match ctx.fs.read(consts::EF_MINPINLEN, &mut mp) {
                Some(n) if n >= 1 => (mp[0], n >= 2 && mp[1] == 1),
                _ => (consts::MIN_PIN_LENGTH, false),
            };
            let remaining_rk = credential::remaining_discoverable(ctx.fs);
            getinfo::get_info(
                ctx.fs.has_data(consts::EF_PIN),
                min_pin,
                force,
                ctx.fs.has_data(consts::EF_EA_ENABLED),
                config::always_uv_enabled(ctx.fs),
                ctx.presence.uv_available(),
                remaining_rk,
                &mut out[1..],
            )
        }
        consts::CTAP_MAKE_CREDENTIAL => makecredential::make_credential(ctx, params, &mut out[1..]),
        consts::CTAP_GET_ASSERTION => getassertion::get_assertion(ctx, params, &mut out[1..]),
        consts::CTAP_GET_NEXT_ASSERTION => getassertion::get_next_assertion(ctx, &mut out[1..]),
        consts::CTAP_CLIENT_PIN => clientpin::client_pin(ctx, params, &mut out[1..]),
        consts::CTAP_RESET => reset::reset(ctx),
        consts::CTAP_SELECTION => selection::selection(ctx),
        consts::CTAP_CONFIG => config::authenticator_config(ctx, params, &mut out[1..]),
        consts::CTAP_CREDENTIAL_MGMT => credmgmt::cred_mgmt(ctx, params, &mut out[1..]),
        // CTAP 2.3 §12.4: a build that serves the `largeBlob` extension must not
        // also serve this command, and getInfo drops `largeBlobs` to match.
        consts::CTAP_LARGE_BLOBS if !consts::LARGE_BLOB_EXT => {
            largeblobs::large_blobs(ctx, params, &mut out[1..])
        }
        consts::CTAP_VENDOR => vendor::vendor(ctx, params, &mut out[1..]),
        _ => Err(CtapError::InvalidCommand),
    };

    match result {
        Ok(n) => {
            out[0] = CTAP2_OK;
            1 + n
        }
        Err(e) => {
            out[0] = e.as_u8();
            1
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod conformance;

/// On-device latency-harness timing entrypoints. The `bench` feature gates a
/// vendor timing oracle over the crypto primitives — a debug/measurement build,
/// never shipped (see the module docs).
#[cfg(feature = "bench")]
pub mod bench;
