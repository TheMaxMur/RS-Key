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

#[cfg(any(test, kani, feature = "assurance-trace"))]
pub mod generated_token_edges;
#[cfg(any(test, kani, feature = "assurance-trace"))]
pub mod reset_assurance;

#[cfg(any(test, kani, feature = "assurance-trace"))]
pub use generated_token_edges::{AState, AbstractOp, AbstractOutcome};
#[cfg(any(test, kani, feature = "assurance-trace"))]
pub type AbstractTokenState = AState;

pub use error::{CTAP2_OK, CtapError, CtapResult};
pub use reset::{FIDO_SEED_FIDS, is_fido_gate_fid, is_fido_seed_fid, survives_factory_reset};

use rsk_crypto::Device;
use rsk_fs::{Fs, Storage};
// The randomness and user-presence seams, declared once in `rsk-sdk` — the crate
// every applet already depends on — so the board writes one impl of each rather
// than one per applet. Re-exported: callers name them `rsk_fido::Rng` and so on.
pub use rsk_sdk::{AlwaysConfirm, Confirm, ConfirmKind, PinEntry, Presence, Rng, UserPresence};

pub use state::FidoState;
#[cfg(any(test, kani, feature = "assurance-trace"))]
pub use state::{TOKEN_PERSISTENT_FIDS, TokenPersistentView};

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
        self.presence.request_ceremony(confirm) == Presence::Confirmed
    }

    /// Obtain user presence for a CTAP2 command, mapping the outcome to its
    /// status code: a `CTAPHID_CANCEL` aborts with `KEEPALIVE_CANCEL`, any
    /// other non-confirmation (timeout, decline) with `OPERATION_DENIED`.
    pub fn require_presence(&mut self, confirm: Confirm<'_>) -> Result<(), CtapError> {
        match self.presence.request_ceremony(confirm) {
            Presence::Confirmed => Ok(()),
            Presence::Cancelled => Err(CtapError::KeepAliveCancel),
            Presence::Timeout | Presence::Declined => Err(CtapError::OperationDenied),
        }
    }

    /// The device seed for FIDO operations: the RAM copy a vendor `UNLOCK` left
    /// behind wins over flash; on a soft-locked device with no unlock this
    /// session, both fail and the operation errors out — that is the lock.
    /// Refines `RSKeySecurityState!ResetNeverWeakensSurvivingState` — SEC-FIDO-006.
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

    // Retire a pinUvAuthToken whose usage timer has elapsed before it can authorize
    // this command (CTAP 2.1 §6.5.5.7), and any stateful sequence left idle past the
    // window CTAP 2.3 §6 bounds — their continuation legs bring no token to expire.
    ctx.state.expire_stale_token(ctx.now_ms);
    ctx.state.expire_stale_sequences(ctx.now_ms);

    // CTAP 2.2 §6: a stateful sequence may assume it is "exclusively preceded" by
    // its own kind or by the command that initialized it, so every sequence this
    // command does not continue ends here. `getAssertion` continues nothing — it
    // is an initializer, and arms its own walk after this clears the previous one.
    ctx.state.retire_sequences_except(cmd);

    // The canonical-form gate for the commands that parse a request body. getInfo,
    // reset, selection and getNextAssertion take no parameters and never look at
    // the bytes — the oracle likewise answers getInfo normally with a trailing byte.
    //
    // `largeBlobs` only where this build implements it: with the `largeBlob`
    // extension served instead (§12.4), `0x0C` is a command we do not have, and a
    // trailing byte must not turn its INVALID_COMMAND into INVALID_CBOR — a
    // YubiKey answers `0x01` to every command it does not implement, body or no
    // body. Same defect this commit fixes, one layer up: the body deciding what
    // the command is.
    if (matches!(
        cmd,
        consts::CTAP_MAKE_CREDENTIAL
            | consts::CTAP_GET_ASSERTION
            | consts::CTAP_CLIENT_PIN
            | consts::CTAP_CONFIG
            | consts::CTAP_CREDENTIAL_MGMT
            | consts::CTAP_VENDOR
    ) || (cmd == consts::CTAP_LARGE_BLOBS && !consts::LARGE_BLOB_EXT))
        && let Err(e) = cbordec::one_cbor_item(params)
    {
        out[0] = e.as_u8();
        return 1;
    }

    let result = match cmd {
        consts::CTAP_GET_INFO => {
            // minPINLength / forceChangePin come from EF_MINPINLEN ([len, force]).
            let mut mp = [0u8; 2];
            let (min_pin, force) = match ctx.fs.read(consts::EF_MINPINLEN, &mut mp) {
                Some(n) if n >= 1 => (mp[0], n >= 2 && mp[1] == 1),
                _ => (consts::MIN_PIN_LENGTH, false),
            };
            let remaining_rk = credential::remaining_discoverable(ctx.fs);
            // Re-encrypted under a fresh IV on every getInfo, so the member cannot
            // become a stable fingerprint (`seed::enc_identifier`).
            let enc_id = seed::enc_identifier(&ctx.dev, ctx.fs, ctx.rng);
            let enc_css = seed::enc_cred_store_state(&ctx.dev, ctx.fs, ctx.rng);
            getinfo::get_info(
                ctx.fs.has_data(consts::EF_PIN),
                min_pin,
                force,
                ctx.fs.has_data(consts::EF_EA_ENABLED),
                config::always_uv_enabled(ctx.fs),
                ctx.presence.uv_available(),
                remaining_rk,
                enc_id.as_ref(),
                enc_css.as_ref(),
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
