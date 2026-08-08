// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! U2F / CTAP1: register, authenticate, version — ISO-7816 APDUs over
//! CTAPHID_MSG. Registration returns the new public key, a 64-byte key handle,
//! the attestation certificate and a signature by the device key;
//! authentication signs a challenge with the credential key.

use zeroize::Zeroize;

use rsk_fs::Storage;
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
use crate::seed::{bump_sign_counter, get_sign_counter, load_att_key};
use crate::{Ctx, Rng};

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
        // §7.2.4: alwaysUv disables the CTAP1/U2F interface, so register and
        // authenticate fail immediately with the status word that clause names —
        // SW_COMMAND_NOT_ALLOWED, not the "test-of-user-presence required" code,
        // which would have the client retry a switched-off interface forever.
        // VERSION, a capability query that touches no credential, stays live.
        CTAP_REGISTER | CTAP_AUTHENTICATE if u2f_gate(ctx) == U2fGate::Disabled => {
            (Sw::COMMAND_NOT_ALLOWED, 0)
        }
        CTAP_REGISTER => cmd_register(ctx, apdu, out),
        CTAP_AUTHENTICATE => cmd_authenticate(ctx, apdu, out),
        CTAP_VERSION => {
            out[..6].copy_from_slice(b"U2F_V2");
            (Sw::OK, 6)
        }
        _ => (Sw::INS_NOT_SUPPORTED, 0),
    }
}

/// What a U2F operation owes the user before it may run — CTAP 2.1 §7.2.4.
#[derive(PartialEq, Eq, Clone, Copy)]
enum U2fGate {
    /// alwaysUv is off: plain user presence, the classic U2F contract.
    Presence,
    /// alwaysUv is on and a built-in user verification method is configured. §7.2.4
    /// keeps the interface alive in exactly this case — "unless the CTAP1/U2F
    /// authenticator is protected by a built-in user verification method" — so every
    /// operation runs that method instead of a bare touch, and U2F stops being a
    /// presence-only way around the always-require-UV guarantee.
    BuiltinUv,
    /// alwaysUv is on with nothing to verify against: the interface is disabled, and
    /// getInfo drops `U2F_V2` to match.
    Disabled,
}

fn u2f_gate<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>) -> U2fGate {
    if !crate::config::always_uv_enabled(ctx.fs) {
        U2fGate::Presence
    } else if crate::clientpin::builtin_uv_enabled(ctx) {
        U2fGate::BuiltinUv
    } else {
        U2fGate::Disabled
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
    match u2f_gate(ctx) {
        U2fGate::BuiltinUv => {
            let owes_card =
                crate::clientpin::UvOutcome::BUILTIN.needs_confirm(ctx.presence.shows_confirm());
            (!owes_card || ctx.check_user_presence(confirm))
                && crate::clientpin::builtin_uv_step(ctx).is_ok()
        }
        _ => ctx.check_user_presence(confirm),
    }
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
    let chal = &apdu.data[..32];
    let mut app = [0u8; 32];
    app.copy_from_slice(&apdu.data[32..64]);

    let mut seed = match ctx.load_keydev() {
        Some(s) => s,
        None => return (Sw::EXEC_ERROR, 0),
    };
    let (key_handle, mut scalar) = derive_new(&seed, &app, ctx.rng);
    let cred_key = P256Key::from_scalar(&scalar);
    scalar.zeroize();
    // Org-provisioned attestation (vendor ATT_IMPORT) wins — classic U2F batch
    // attestation; otherwise the per-device key (the seed scalar) with its
    // self-signed EF_EE_DEV cert.
    let mut att_scalar = load_att_key(&ctx.dev, ctx.fs);
    let org = att_scalar.is_some();
    let device_key = match att_scalar.as_mut() {
        Some(s) => {
            let k = P256Key::from_scalar(s);
            s.zeroize();
            k
        }
        None => P256Key::from_scalar(&seed),
    };
    seed.zeroize();
    let (cred_key, device_key) = match (cred_key, device_key) {
        (Some(c), Some(d)) => (c, d),
        _ => return (Sw::EXEC_ERROR, 0),
    };
    let (x, y) = cred_key.public_xy();

    // sign base: 0x00 ‖ appId ‖ chal ‖ keyHandle ‖ (0x04 ‖ x ‖ y)
    let mut base = [0u8; 1 + 32 + 32 + KEY_HANDLE_LEN + 65];
    let mut p = 0;
    base[p] = 0x00;
    p += 1;
    base[p..p + 32].copy_from_slice(&app);
    p += 32;
    base[p..p + 32].copy_from_slice(chal);
    p += 32;
    base[p..p + KEY_HANDLE_LEN].copy_from_slice(&key_handle);
    p += KEY_HANDLE_LEN;
    base[p] = 0x04;
    p += 1;
    base[p..p + 32].copy_from_slice(&x);
    p += 32;
    base[p..p + 32].copy_from_slice(&y);
    p += 32;
    let mut sig = [0u8; MAX_DER_SIG];
    let sl = device_key.sign_der(&base[..p], &mut sig);

    let mut cert = [0u8; crate::cert::ATT_CHAIN_REC_MAX];
    let clen = if org {
        // The chain's leaf — a U2F response carries exactly one certificate.
        let n = match ctx.fs.read(EF_ATT_CHAIN, &mut cert) {
            // Fs::read returns the full stored length; clamp to the buffer before
            // slicing cert[..n] below, matching the EF_EE_DEV branch.
            Some(n) if n > 3 => n.min(cert.len()),
            _ => return (Sw::EXEC_ERROR, 0),
        };
        let Some((off, len)) = crate::cert::att_chain_cert_range(&cert[..n], 0) else {
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
    if out.len() < total {
        return (Sw::EXEC_ERROR, 0);
    }
    let mut q = 0;
    out[q] = U2F_REGISTER_ID;
    q += 1;
    out[q] = 0x04;
    q += 1;
    out[q..q + 32].copy_from_slice(&x);
    q += 32;
    out[q..q + 32].copy_from_slice(&y);
    q += 32;
    out[q] = KEY_HANDLE_LEN as u8;
    q += 1;
    out[q..q + KEY_HANDLE_LEN].copy_from_slice(&key_handle);
    q += KEY_HANDLE_LEN;
    out[q..q + clen].copy_from_slice(&cert[..clen]);
    q += clen;
    out[q..q + sl].copy_from_slice(&sig[..sl]);
    q += sl;
    journal::append(ctx, journal::EV_U2F_REGISTER, 0, &apdu.data[32..40]);
    (Sw::OK, q)
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
        return (Sw::INCORRECT_PARAMS, 0);
    }
    let chal = &apdu.data[..32];
    let mut app = [0u8; 32];
    app.copy_from_slice(&apdu.data[32..64]);
    let kh_len = apdu.data[64] as usize;
    if kh_len < KEY_HANDLE_LEN || 65 + kh_len > apdu.nc {
        return (Sw::INCORRECT_PARAMS, 0);
    }
    let key_handle = &apdu.data[65..65 + kh_len];

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
    let scalar: Option<[u8; 32]> = match credential_load(&seed, key_handle, &app, &mut scratch) {
        // A CTAP2 credential box. credProtect=userVerificationRequired (L3) must
        // NOT be usable over U2F, which performs no user verification — only CTAP2
        // getAssertion (with a PIN/UV) may exercise it. L1/L2 stay usable: the RP
        // explicitly presents this credentialId as the key handle (like an allowList).
        Some(c) if !c.u2f => {
            if c.ext.cred_protect == CRED_PROT_UV_REQUIRED {
                None
            } else {
                fido_load_key(&seed, key_handle).map(|raw| {
                    let mut s = [0u8; 32];
                    s.copy_from_slice(&raw[..32]);
                    s
                })
            }
        }
        Some(_) => {
            let mut kh = [0u8; KEY_HANDLE_LEN];
            kh.copy_from_slice(&key_handle[..KEY_HANDLE_LEN]);
            verify_key(&seed, &app, &kh)
        }
        None => None,
    };
    seed.zeroize();
    let mut scalar = match scalar {
        Some(s) => s,
        None => return (Sw::INCORRECT_PARAMS, 0), // 0x6A80 WRONG_DATA — handle not ours
    };

    // check-only (P1=0x07): a valid handle reports "would require user presence".
    // No touch.
    if apdu.p1 == U2F_AUTH_CHECK_ONLY {
        scalar.zeroize();
        return (Sw::CONDITIONS_NOT_SATISFIED, 0);
    }

    // Everything that still signs owes a touch, now that the handle is known valid;
    // only the explicit don't-enforce byte is exempt, so `tup` gates the touch and
    // the TUP flag together. No button → instant. The one thing don't-enforce cannot
    // opt out of is §7.2.4's built-in UV: that verification is the entire reason the
    // interface is still reachable under alwaysUv, so skipping it would hand back
    // exactly the presence-free signature the clause exists to prevent. The emitted
    // TUP flag still follows the raw `tup`, so the wire meaning is unchanged.
    let owes = tup || u2f_gate(ctx) == U2fGate::BuiltinUv;
    if owes && !u2f_interaction(ctx, crate::Confirm::titled("Sign in?")) {
        scalar.zeroize();
        return (Sw::CONDITIONS_NOT_SATISFIED, 0);
    }
    let key = P256Key::from_scalar(&scalar);
    scalar.zeroize();
    let key = match key {
        Some(k) => k,
        None => return (Sw::EXEC_ERROR, 0),
    };

    let flags = if tup { U2F_AUTH_FLAG_TUP } else { 0 };
    let ctr = get_sign_counter(ctx.fs);

    // sign base: appId ‖ flags ‖ counter(BE) ‖ chal
    let mut base = [0u8; 32 + 1 + 4 + 32];
    base[..32].copy_from_slice(&app);
    base[32] = flags;
    base[33..37].copy_from_slice(&ctr.to_be_bytes());
    base[37..69].copy_from_slice(chal);
    let mut sig = [0u8; MAX_DER_SIG];
    let sl = key.sign_der(&base, &mut sig);

    // response: flags ‖ counter(BE) ‖ signature
    out[0] = flags;
    out[1..5].copy_from_slice(&ctr.to_be_bytes());
    out[5..5 + sl].copy_from_slice(&sig[..sl]);
    let _ = bump_sign_counter(ctx.fs);
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

#[cfg(test)]
#[path = "u2f_tests.rs"]
mod tests;
