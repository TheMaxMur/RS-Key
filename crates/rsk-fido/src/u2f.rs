// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! U2F / CTAP1: register, authenticate, version — ISO-7816 APDUs over
//! CTAPHID_MSG. Registration returns the new public key, a 64-byte key handle,
//! the attestation certificate and a signature by the device key;
//! authentication signs a challenge with the credential key.

// Host bytes: a panic here is a board that answers nothing until unplugged.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use rsk_secret::Secret;

use rsk_fs::{Fs, Storage};
use rsk_sdk::apdu::Apdu;
use rsk_sdk::sw::Sw;

use crate::consts::{
    CRED_PROT_UV_REQUIRED, CTAP_AUTHENTICATE, CTAP_REGISTER, CTAP_VERSION, EF_ATT_CHAIN, EF_EE_DEV,
    U2F_AUTH_CHECK_ONLY, U2F_AUTH_ENFORCE, U2F_AUTH_FLAG_TUP, U2F_AUTH_NO_ENFORCE, U2F_REGISTER_ID,
};
use crate::credential::{CRED_REC_MAX, credential_load};
use crate::ec::{MAX_DER_SIG, P256Key};
use crate::journal;
use crate::keyderiv::{KEY_HANDLE_LEN, derive_new, fido_load_key, verify_key};
use crate::seed::{bump_sign_counter, load_att_key};
use crate::{Ctx, Rng, UserPresence};

/// Dispatch a U2F APDU; writes the response body into `out`, returns `(SW, len)`.
pub fn process_u2f<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    apdu: &Apdu,
    out: &mut [u8],
) -> (Sw, usize) {
    // U2F APDUs are CLA 0x00.
    if apdu.cla != 0x00 {
        return (Sw::CLA_NOT_SUPPORTED, 0);
    }
    match apdu.ins {
        // §7.2.4: alwaysUv disables CTAP1/U2F, and a command fails at once with the
        // SW_COMMAND_NOT_ALLOWED it names (not "touch me", which a client retries for
        // ever) — VERSION too, as on a YubiKey 5.8.0 (measured 2026-09-30).
        CTAP_REGISTER | CTAP_AUTHENTICATE | CTAP_VERSION
            if u2f_gate(ctx.fs, ctx.presence) == U2fGate::Disabled =>
        {
            (Sw::COMMAND_NOT_ALLOWED, 0)
        }
        CTAP_REGISTER => cmd_register(ctx, apdu, out),
        CTAP_AUTHENTICATE => cmd_authenticate(ctx, apdu, out),
        CTAP_VERSION if apdu.nc != 0 => (Sw::WRONG_LENGTH, 0), // §6.1: "takes no data as input"
        CTAP_VERSION => {
            let Some(dst) = out.get_mut(..crate::consts::U2F_VERSION.len()) else {
                return (Sw::EXEC_ERROR, 0);
            };
            dst.copy_from_slice(crate::consts::U2F_VERSION);
            (Sw::OK, crate::consts::U2F_VERSION.len())
        }
        _ => (Sw::INS_NOT_SUPPORTED, 0),
    }
}

/// What a U2F operation owes the user before it may run — CTAP 2.1 §7.2.4.
#[derive(PartialEq, Eq, Clone, Copy)]
pub(crate) enum U2fGate {
    /// alwaysUv is off: plain user presence, the classic U2F contract.
    Presence,
    /// alwaysUv is on and a built-in user verification method is configured. §7.2.4
    /// keeps the interface alive in exactly this case — "unless the CTAP1/U2F
    /// authenticator is protected by a built-in user verification method" — so every
    /// operation runs that method instead of a bare touch, and U2F stops being a
    /// presence-only way around the always-require-UV guarantee.
    BuiltinUv,
    /// alwaysUv is on with nothing to verify against: every U2F answer says it is off.
    Disabled,
}

impl U2fGate {
    /// §7.2.4, read once for every U2F answer; `builtin_uv` is a method configured.
    pub(crate) fn of(always_uv: bool, builtin_uv: bool) -> Self {
        match (always_uv, builtin_uv) {
            (false, _) => U2fGate::Presence,
            (true, true) => U2fGate::BuiltinUv,
            (true, false) => U2fGate::Disabled,
        }
    }
}

/// Collect whatever [`U2fGate`] demands. A refusal — declined touch, wrong PIN,
/// cancelled pad — is SW_CONDITIONS_NOT_SATISFIED either way: U2F's only "interact
/// and try again" status, and the one a client knows how to act on.
///
/// Under `BuiltinUv` the pad replaces the touch, not the screen: a backend that paints
/// `confirm` still shows it, so REGISTER and AUTHENTICATE stay distinguishable to the
/// user instead of collapsing into one unlabelled PIN prompt (audit run-28). The card
/// comes first, so the operation is named before the PIN is typed.
fn u2f_interaction<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, confirm: crate::Confirm<'_>) -> bool {
    match u2f_gate(ctx.fs, ctx.presence) {
        U2fGate::BuiltinUv => {
            let owes_card =
                crate::clientpin::UvOutcome::BUILTIN.needs_confirm(ctx.presence.shows_confirm());
            (!owes_card || ctx.check_user_presence(confirm))
                && crate::clientpin::builtin_uv_step(ctx).is_ok()
        }
        _ => ctx.check_user_presence(confirm),
    }
}

/// The store's and the backend's reading of [`U2fGate`]. getInfo, which is handed the
/// same facts rather than the store, reads [`U2fGate::of`] too.
fn u2f_gate<S: Storage>(fs: &mut Fs<S>, presence: &dyn UserPresence) -> U2fGate {
    let always_uv = crate::config::always_uv_enabled(fs);
    let builtin_uv = crate::clientpin::builtin_uv_enabled(fs, presence);
    U2fGate::of(always_uv, builtin_uv)
}

fn cmd_register<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    apdu: &Apdu,
    out: &mut [u8],
) -> (Sw, usize) {
    if apdu.nc != 64 {
        return (Sw::WRONG_LENGTH, 0);
    }
    // U2F register requires a physical touch; no button → instant. Under §7.2.4's
    // built-in-UV exception the PIN pad stands in for it.
    if !u2f_interaction(ctx, crate::Confirm::titled("Register key?")) {
        return (Sw::CONDITIONS_NOT_SATISFIED, 0);
    }
    // U2F register request is challenge(32) ‖ application(32). The key handle
    // binds to the application and the signature base is
    // 0x00 ‖ application ‖ challenge ‖ … (note the swap).
    let Some(body) = apdu.data.first_chunk::<64>() else {
        return (Sw::WRONG_LENGTH, 0);
    };
    let chal = &body[..32];
    let mut app = [0u8; 32];
    app.copy_from_slice(&body[32..64]);

    let mut seed = match ctx.load_keydev() {
        Some(s) => s,
        None => return (Sw::EXEC_ERROR, 0),
    };
    let (key_handle, mut scalar) = derive_new(seed.expose(), &app, ctx.rng);
    let cred_key = P256Key::from_scalar(scalar.expose());
    scalar.wipe();
    // Org-provisioned attestation (vendor ATT_IMPORT) wins — classic U2F batch
    // attestation; otherwise the per-device key (the seed scalar) with its
    // self-signed EF_EE_DEV cert.
    let mut att_scalar = load_att_key(&ctx.dev, ctx.fs);
    let org = att_scalar.is_some();
    let device_key = match att_scalar.as_mut() {
        Some(s) => {
            let k = P256Key::from_scalar(s.expose());
            s.wipe();
            k
        }
        None => P256Key::from_scalar(seed.expose()),
    };
    seed.wipe();
    let (cred_key, device_key) = match (cred_key, device_key) {
        (Some(c), Some(d)) => (c, d),
        _ => return (Sw::EXEC_ERROR, 0),
    };
    let (x, y) = cred_key.public_xy();

    // sign base: 0x00 ‖ appId ‖ chal ‖ keyHandle ‖ (0x04 ‖ x ‖ y)
    let mut base = [0u8; 1 + 32 + 32 + KEY_HANDLE_LEN + 65];
    let fields = [0x00]
        .iter()
        .chain(&app)
        .chain(chal)
        .chain(&key_handle)
        .chain(&[0x04])
        .chain(&x)
        .chain(&y);
    for (dst, &b) in base.iter_mut().zip(fields) {
        *dst = b;
    }
    let mut sig = [0u8; MAX_DER_SIG];
    let sl = device_key.sign_der(&base, &mut sig);

    let mut cert = [0u8; crate::cert::ATT_CHAIN_REC_MAX];
    let clen = if org {
        // The chain's leaf — a U2F response carries exactly one certificate.
        let n = match ctx.fs.read(EF_ATT_CHAIN, &mut cert) {
            // Fs::read returns the full stored length; clamp it to what was copied,
            // matching the EF_EE_DEV branch.
            Some(n) if n > 3 => n.min(cert.len()),
            _ => return (Sw::EXEC_ERROR, 0),
        };
        let Some((off, len)) = cert
            .get(..n)
            .and_then(|chain| crate::cert::att_chain_cert_range(chain, 0))
        else {
            return (Sw::EXEC_ERROR, 0);
        };
        cert.copy_within(off..off + len, 0);
        len
    } else {
        match ctx.fs.read(EF_EE_DEV, &mut cert) {
            Some(n) if n > 0 => n.min(cert.len()),
            _ => return (Sw::EXEC_ERROR, 0),
        }
    };

    // response: 0x05 ‖ (0x04 ‖ x ‖ y) ‖ 64 ‖ keyHandle ‖ cert ‖ sig
    let total = 1 + 65 + 1 + KEY_HANDLE_LEN + clen + sl;
    let (Some(resp), Some(cert), Some(sig)) =
        (out.get_mut(..total), cert.get(..clen), sig.get(..sl))
    else {
        return (Sw::EXEC_ERROR, 0);
    };
    let kh_len = [u8::try_from(KEY_HANDLE_LEN).unwrap_or(u8::MAX)];
    let fields = [U2F_REGISTER_ID, 0x04]
        .iter()
        .chain(&x)
        .chain(&y)
        .chain(&kh_len)
        .chain(&key_handle)
        .chain(cert)
        .chain(sig);
    for (dst, &b) in resp.iter_mut().zip(fields) {
        *dst = b;
    }
    journal::append(ctx, journal::EV_U2F_REGISTER, 0, &app[..8]);
    (Sw::OK, total)
}

fn cmd_authenticate<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    apdu: &Apdu,
    out: &mut [u8],
) -> (Sw, usize) {
    // U2F Raw Message Formats §7.2 assigns exactly three control bytes; a reserved
    // one used to reach the signature with neither a touch nor the TUP flag — a
    // silent signing oracle for any host that sent an unassigned P1.
    let tup = match apdu.p1 {
        U2F_AUTH_CHECK_ONLY | U2F_AUTH_ENFORCE => true,
        // `strict-up` promises a touch on every assertion and `want_up`
        // (getassertion.rs) only reaches CTAP2, so that build drops don't-enforce.
        U2F_AUTH_NO_ENFORCE if !cfg!(feature = "strict-up") => false,
        _ => return (Sw::INCORRECT_P1P2, 0),
    };
    // chal(32) ‖ appId(32) ‖ khLen(1) ‖ keyHandle
    if apdu.nc < 32 + 32 + 1 + 1 {
        return (Sw::WRONG_DATA, 0);
    }
    let Some((head, rest)) = apdu.data.split_first_chunk::<65>() else {
        return (Sw::WRONG_DATA, 0);
    };
    let chal = &head[..32];
    let mut app = [0u8; 32];
    app.copy_from_slice(&head[32..64]);
    let kh_len = head[64] as usize;
    if kh_len < KEY_HANDLE_LEN || 65 + kh_len > apdu.nc {
        return (Sw::WRONG_DATA, 0);
    }
    let Some(key_handle) = rest.get(..kh_len) else {
        return (Sw::WRONG_DATA, 0);
    };

    let mut seed = match ctx.load_keydev() {
        Some(s) => s,
        None => return (Sw::EXEC_ERROR, 0),
    };
    // Resolve the key handle FIRST — before any user-presence prompt. U2F requires
    // an unknown handle (wrong AppId / not minted by us) to be rejected with
    // WRONG_DATA (0x6A80), and check-only to report status, neither gated on a
    // touch. Prompting before this check makes a negative test hang on the button,
    // and the stream of UPNEEDED keepalives desyncs a conformance tool's response
    // reader (seen as "sequence out of order").
    //
    // credential_load resolves both a CTAP2 box and a U2F key handle, flagging the
    // latter via `u2f`: a box signs with fido_load_key, a handle with its path-as-is
    // scalar (verify_key, which fido_load_key would clobber by rewriting path[0]).
    // U2F is P-256 only, so take the leading 32 bytes of the ratchet as the scalar.
    let mut scratch = [0u8; CRED_REC_MAX];
    let scalar = match credential_load(seed.expose(), key_handle, &app, &mut scratch) {
        // A CTAP2 credential box. credProtect=userVerificationRequired (L3) must
        // NOT be usable over U2F, which performs no user verification — only CTAP2
        // getAssertion (with a PIN/UV) may exercise it. L1/L2 stay usable: the RP
        // explicitly presents this credentialId as the key handle (like an allowList).
        Some(c) if !c.u2f => {
            if c.ext.cred_protect == CRED_PROT_UV_REQUIRED {
                None
            } else {
                fido_load_key(seed.expose(), key_handle).map(|raw| {
                    let mut s = Secret::<[u8; 32]>::zeroed();
                    s.expose_mut().copy_from_slice(&raw.expose()[..32]);
                    s
                })
            }
        }
        Some(_) => key_handle
            .first_chunk::<KEY_HANDLE_LEN>()
            .and_then(|kh| verify_key(seed.expose(), &app, kh)),
        None => None,
    };
    seed.wipe();
    let mut scalar = match scalar {
        Some(s) => s,
        None => return (Sw::WRONG_DATA, 0), // 0x6A80 — handle not ours
    };

    // check-only (P1=0x07): a valid handle reports "would require user presence".
    // No touch.
    if apdu.p1 == U2F_AUTH_CHECK_ONLY {
        scalar.wipe();
        return (Sw::CONDITIONS_NOT_SATISFIED, 0);
    }

    // Everything that still signs owes a touch, now that the handle is known valid;
    // only the explicit don't-enforce byte is exempt, so `tup` gates the touch and
    // the TUP flag together. No button → instant. The one thing don't-enforce cannot
    // opt out of is §7.2.4's built-in UV: that verification is the entire reason the
    // interface is still reachable under alwaysUv, so skipping it would hand back
    // exactly the presence-free signature the clause exists to prevent. The emitted
    // TUP flag still follows the raw `tup`, so the wire meaning is unchanged.
    let owes = tup || u2f_gate(ctx.fs, ctx.presence) == U2fGate::BuiltinUv;
    if owes && !u2f_interaction(ctx, crate::Confirm::titled("Sign in?")) {
        scalar.wipe();
        return (Sw::CONDITIONS_NOT_SATISFIED, 0);
    }
    let key = P256Key::from_scalar(scalar.expose());
    scalar.wipe();
    let key = match key {
        Some(k) => k,
        None => return (Sw::EXEC_ERROR, 0),
    };

    let flags = if tup { U2F_AUTH_FLAG_TUP } else { 0 };
    // Read AND advanced before anything is signed: a counter the flash could not serve
    // is not 0 (that is the clone signal itself), and one it could not advance would be
    // signed again by the next AUTHENTICATE.
    let Ok(ctr) = bump_sign_counter(ctx.fs) else {
        return (Sw::MEMORY_FAILURE, 0);
    };

    // sign base: appId ‖ flags ‖ counter(BE) ‖ chal
    let mut base = [0u8; 32 + 1 + 4 + 32];
    base[..32].copy_from_slice(&app);
    base[32] = flags;
    base[33..37].copy_from_slice(&ctr.to_be_bytes());
    base[37..69].copy_from_slice(chal);
    let mut sig = [0u8; MAX_DER_SIG];
    let sl = key.sign_der(&base, &mut sig);

    // response: flags ‖ counter(BE) ‖ signature
    let (Some(resp), Some(sig)) = (out.get_mut(..5 + sl), sig.get(..sl)) else {
        return (Sw::EXEC_ERROR, 0);
    };
    for (dst, &b) in resp
        .iter_mut()
        .zip([flags].iter().chain(&ctr.to_be_bytes()).chain(sig))
    {
        *dst = b;
    }
    // `owes` is whether this AUTHENTICATE actually collected a gesture: without one
    // (P1 = don't-enforce, alwaysUv off) it is ungated and drivable on demand, so a run
    // of those costs one ring entry rather than one each — see `journal::append_run`.
    if owes {
        journal::append(ctx, journal::EV_U2F_AUTH, 0, &app[..8]);
    } else {
        journal::append_run(ctx, journal::EV_U2F_AUTH, 0, &app[..8]);
    }
    (Sw::OK, 5 + sl)
}

/// A U2F request as CTAPHID_MSG carries it. U2F HID v1.2 §2: "all raw U2F messages
/// are encoded using extended length APDU encoding", and a YubiKey 5.8.0 reads one
/// so — the class first (`6E00`), then a bare header or `00 Lc Lc` and that many data
/// bytes (`6700` otherwise), whatever follows them ignored, an `Le` included.
pub fn hid_apdu(raw: &[u8]) -> Result<Apdu<'_>, Sw> {
    let Some((&[cla, ins, p1, p2], lengths)) = raw.split_first_chunk::<4>() else {
        return Err(Sw::WRONG_LENGTH);
    };
    if cla != 0x00 {
        return Err(Sw::CLA_NOT_SUPPORTED);
    }
    let data = match lengths {
        [] => &[][..],
        [0x00, hi, lo, rest @ ..] => rest
            .get(..usize::from(u16::from_be_bytes([*hi, *lo])))
            .ok_or(Sw::WRONG_LENGTH)?,
        _ => return Err(Sw::WRONG_LENGTH),
    };
    Ok(Apdu {
        cla,
        ins,
        p1,
        p2,
        nc: data.len(),
        ne: 0,
        data,
        extended: true,
    })
}

/// The body a SELECT of [`FIDO_AID`](crate::consts::FIDO_AID) answers: `U2F_V2` while
/// U2F is served, and once alwaysUv has switched it off the version CTAP 2.3 §11.3.3
/// gives an authenticator with CTAP2 alone, as a YubiKey 5.8.0 answers (2026-09-30).
pub fn select_version<S: Storage>(fs: &mut Fs<S>, presence: &dyn UserPresence) -> &'static [u8] {
    match u2f_gate(fs, presence) {
        U2fGate::Disabled => crate::consts::FIDO_2_0_VERSION,
        U2fGate::Presence | U2fGate::BuiltinUv => crate::consts::U2F_VERSION,
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    reason = "a test's fixture is its own bound, and a panic is its failure report"
)]
#[path = "u2f_tests.rs"]
mod tests;
