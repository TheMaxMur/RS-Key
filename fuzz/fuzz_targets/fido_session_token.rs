// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Stateful pinUvAuthToken spend/revocation oracle for the `TOK1` input route.
//!
//! The existing target arms a token directly, which reaches the reject paths but
//! cannot distinguish "the device still holds a grant" from "the harness re-armed
//! one". This route runs a real clientPIN handshake (protocol 1 or 2) and keeps
//! its own model of what it asked for: protocol, permission mask, optional rpId
//! binding and the harness clock. Expectations come from that model and from the
//! command replies — never from `FidoState.paut`.
//!
//! The bytes after the magic choose: variant (byte 0), protocol (byte 1),
//! extra permissions (byte 2) and rpId binding (byte 3). Every variant has a
//! literal seed in `fuzz/tests/fixtures/fido_session.rs`.

use super::*;
use rsk_fido::{CTAP2_OK, CtapError};

/// The route marker checked by `fido_session::exercise` before its arm byte.
pub(crate) const MAGIC: &[u8] = b"TOK1";

/// One scenario per contract in the task; the low three bits of byte 0 select it.
const VARIANTS: u8 = 8;
/// Permissions a variant's seed may add to its base set. `be`/`pcmr` are absent:
/// getPinUvAuthTokenUsingPinWithPermissions refuses both without a PIN-only grant.
const EXTRA_PERMS: u8 = PERM_GA | PERM_CM | PERM_ACFG;
/// Scratch for one request body; the largest here is a one-fragment large blob.
const MSG_BUF: usize = 256;
/// Large-blob body size: one well inside `MAX_FRAGMENT_LENGTH` and above
/// `LARGEBLOB_MIN - 16`.
const LB_BODY: usize = 24;
const LB_LEN: usize = LB_BODY + 16;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Variant {
    /// makeCredential spends the token; every later token command but LBW fails.
    Spend,
    /// The spend refreshes the usage timer; the residual LBW right still commits.
    ResidualLbw,
    /// A token bound to one pool rp refuses the other without spending the grant.
    RpRefusal,
    /// 30 s of inactivity retires the token; a fresh issuance works.
    Inactivity,
    /// 600 s from issuance retires the token even under constant refresh.
    Absolute,
    /// authenticatorReset clears the session token; a new handshake works.
    Reset,
    /// A wrong PIN revokes the standing token; a fresh issuance works.
    WrongPin,
    /// ga-only and cm-only grants each reach their own command and not the
    /// other; an explicit reissue after the spend works.
    Reissue,
}

impl Variant {
    fn from_byte(b: u8) -> Self {
        match b % VARIANTS {
            0 => Self::Spend,
            1 => Self::ResidualLbw,
            2 => Self::RpRefusal,
            3 => Self::Inactivity,
            4 => Self::Absolute,
            5 => Self::Reset,
            6 => Self::WrongPin,
            _ => Self::Reissue,
        }
    }

    /// The permissions the contract needs. `EXTRA_PERMS` may ask for more.
    fn base_perms(self) -> u8 {
        match self {
            Self::Spend | Self::RpRefusal => PERM_MC | PERM_LBW,
            // Reset wipes the credential store too, so the post-reset proof of the
            // new grant is a fresh makeCredential.
            Self::Reset => PERM_MC | PERM_GA | PERM_LBW,
            Self::Absolute | Self::Inactivity => PERM_GA | PERM_CM | PERM_LBW,
            Self::ResidualLbw | Self::WrongPin | Self::Reissue => PERM_GA | PERM_LBW,
        }
    }
}

struct Plan {
    variant: Variant,
    proto: PinProto,
    permissions: u8,
    rp_id: Option<&'static str>,
}

impl Plan {
    fn from(rest: &[u8]) -> Self {
        let byte = |i: usize| rest.get(i).copied().unwrap_or(0);
        let variant = Variant::from_byte(byte(0));
        let proto = if byte(1) & 1 == 0 {
            PinProto::Two
        } else {
            PinProto::One
        };
        let permissions = variant.base_perms() | (byte(2) & EXTRA_PERMS);
        // The absolute-lifetime refresh uses credentialManagement's rp-less
        // metadata read, which a scoped token may not use; keep it unscoped.
        let rp_id = match variant {
            // The refusal is only meaningful on a bound token; the byte picks
            // which pool entry is bound (and so which one is refused).
            Variant::RpRefusal => Some(if byte(3) & 1 != 0 {
                RP_IDS[0]
            } else {
                RP_IDS[1]
            }),
            Variant::Absolute | Variant::Inactivity => None,
            _ if byte(3) & 1 != 0 => Some(RP_IDS[0]),
            _ => None,
        };
        Self {
            variant,
            proto,
            permissions,
            rp_id,
        }
    }
}

/// What the host asked the device for, and what it was served. `issued_ms` is
/// the harness clock at the issuance request (the device's `ctx.now_ms`).
struct Grant {
    token: [u8; 32],
    proto: PinProto,
    permissions: u8,
    rp_id: Option<&'static str>,
    issued_ms: u64,
}

impl Grant {
    fn param<'a>(&self, msg: &[u8], buf: &'a mut [u8; 32]) -> &'a [u8] {
        let n = pinproto::authenticate(self.proto, &self.token, msg, buf).unwrap_or(0);
        &buf[..n]
    }
}

// ------------------------------------------------------------------ clientPIN

/// First issuance of a session: getKeyAgreement, setPIN, then the token.
fn bootstrap(
    s: &mut Sess,
    proto: PinProto,
    permissions: u8,
    rp_id: Option<&'static str>,
    at_ms: u64,
) -> Grant {
    s.now_ms = at_ms;
    let shared = s
        .open_shared(proto)
        .expect("clientPIN getKeyAgreement must succeed");
    s.now_ms = at_ms;
    assert!(
        s.set_pin_with(proto, &shared[..proto.shared_len()]),
        "clientPIN setPIN must succeed"
    );
    issue_shared(s, proto, &shared, permissions, rp_id, at_ms)
}

/// Reissue over a fresh key agreement. A PIN mismatch regenerates the device's
/// ephemeral key, so every reissue derives its own shared secret.
fn issue(
    s: &mut Sess,
    proto: PinProto,
    permissions: u8,
    rp_id: Option<&'static str>,
    at_ms: u64,
) -> Grant {
    s.now_ms = at_ms;
    let shared = s
        .open_shared(proto)
        .expect("clientPIN getKeyAgreement must succeed");
    issue_shared(s, proto, &shared, permissions, rp_id, at_ms)
}

fn issue_shared(
    s: &mut Sess,
    proto: PinProto,
    shared: &[u8; 64],
    permissions: u8,
    rp_id: Option<&'static str>,
    at_ms: u64,
) -> Grant {
    s.now_ms = at_ms;
    let token = s
        .issue_with(
            proto,
            &shared[..proto.shared_len()],
            u64::from(permissions),
            rp_id,
        )
        .expect("clientPIN getPinUvAuthTokenUsingPinWithPermissions must succeed");
    Grant {
        token,
        proto,
        permissions,
        rp_id,
        issued_ms: at_ms,
    }
}

// ------------------------------------------------------------------- builders

fn mc_msg(buf: &mut [u8], rp: &str, cdh: &[u8; 32], grant: &Grant) -> usize {
    buf[0] = consts::CTAP_MAKE_CREDENTIAL;
    let mut enc = Encoder::new(Cursor::new(&mut buf[1..]));
    let mut mac = [0u8; 32];
    let built = (|| -> EncRes {
        enc.map(7)?;
        enc.u8(1)?.bytes(cdh)?;
        enc.u8(2)?
            .map(2)?
            .str("id")?
            .str(rp)?
            .str("name")?
            .str("Example RP")?;
        enc.u8(3)?
            .map(3)?
            .str("id")?
            .bytes(&[1, 2])?
            .str("name")?
            .str("u")?
            .str("displayName")?
            .str("")?;
        enc.u8(4)?
            .array(1)?
            .map(2)?
            .str("alg")?
            .i64(consts::ALG_ES256)?
            .str("type")?
            .str(consts::PUBLIC_KEY_TYPE)?;
        enc.u8(7)?.map(1)?.str("rk")?.bool(true)?;
        enc.u8(8)?.bytes(grant.param(cdh, &mut mac))?;
        enc.u8(9)?.u64(proto_num(grant.proto))?;
        Ok(())
    })();
    if built.is_err() {
        return 0;
    }
    1 + enc.writer().position()
}

fn ga_msg(buf: &mut [u8], rp: &str, cdh: &[u8; 32], grant: &Grant) -> usize {
    ga_msg_up(buf, rp, cdh, grant, true)
}

/// getAssertion with an explicit `up` option. A token-authorized `up:false`
/// assertion is the non-consuming use the expiry clocks need: it still verifies
/// the token and refreshes `last_used`, but it does not run the §6.5.5.7 spend.
fn ga_msg_up(buf: &mut [u8], rp: &str, cdh: &[u8; 32], grant: &Grant, up: bool) -> usize {
    buf[0] = consts::CTAP_GET_ASSERTION;
    let mut enc = Encoder::new(Cursor::new(&mut buf[1..]));
    let mut mac = [0u8; 32];
    let built = (|| -> EncRes {
        enc.map(5)?;
        enc.u8(1)?.str(rp)?;
        enc.u8(2)?.bytes(cdh)?;
        enc.u8(5)?.map(1)?.str("up")?.bool(up)?;
        enc.u8(6)?.bytes(grant.param(cdh, &mut mac))?;
        enc.u8(7)?.u64(proto_num(grant.proto))?;
        Ok(())
    })();
    if built.is_err() {
        return 0;
    }
    1 + enc.writer().position()
}

fn cm_msg(buf: &mut [u8], grant: &Grant) -> usize {
    buf[0] = consts::CTAP_CREDENTIAL_MGMT;
    let mut enc = Encoder::new(Cursor::new(&mut buf[1..]));
    let sub = [u8::try_from(consts::CM_GET_CREDS_METADATA).expect("known subcommand")];
    let mut mac = [0u8; 32];
    let built = (|| -> EncRes {
        enc.map(3)?;
        enc.u8(1)?.u64(consts::CM_GET_CREDS_METADATA)?;
        enc.u8(3)?.u64(proto_num(grant.proto))?;
        enc.u8(4)?.bytes(grant.param(&sub, &mut mac))?;
        Ok(())
    })();
    if built.is_err() {
        return 0;
    }
    1 + enc.writer().position()
}

fn cfg_msg(buf: &mut [u8], grant: &Grant) -> usize {
    buf[0] = consts::CTAP_CONFIG;
    let mut enc = Encoder::new(Cursor::new(&mut buf[1..]));
    let mut vp = [0u8; 34];
    vp[..32].fill(0xff);
    vp[32] = consts::CTAP_CONFIG;
    vp[33] = u8::try_from(consts::CONFIG_ENABLE_EA).expect("known subcommand");
    let mut mac = [0u8; 32];
    let built = (|| -> EncRes {
        enc.map(3)?;
        enc.u8(1)?.u64(consts::CONFIG_ENABLE_EA)?;
        enc.u8(3)?.u64(proto_num(grant.proto))?;
        enc.u8(4)?.bytes(grant.param(&vp, &mut mac))?;
        Ok(())
    })();
    if built.is_err() {
        return 0;
    }
    1 + enc.writer().position()
}

/// A complete valid array: `body ‖ left16(SHA-256(body))`.
fn lb_array(buf: &mut [u8; LB_LEN]) -> usize {
    for (i, b) in buf[..LB_BODY].iter_mut().enumerate() {
        *b = 0xC0u8.wrapping_add(i as u8);
    }
    let tag = sha256(&buf[..LB_BODY]);
    buf[LB_BODY..].copy_from_slice(&tag[..16]);
    LB_LEN
}

fn lb_write_msg(buf: &mut [u8], grant: &Grant, arr: &[u8]) -> usize {
    buf[0] = consts::CTAP_LARGE_BLOBS;
    let mut vd = [0u8; 70];
    vd[..32].fill(0xff);
    vd[32] = consts::CTAP_LARGE_BLOBS;
    vd[34..38].copy_from_slice(&0u32.to_le_bytes());
    vd[38..70].copy_from_slice(&sha256(arr));
    let mut enc = Encoder::new(Cursor::new(&mut buf[1..]));
    let mut mac = [0u8; 32];
    let built = (|| -> EncRes {
        enc.map(5)?;
        enc.u8(2)?.bytes(arr)?;
        enc.u8(3)?.u64(0)?;
        enc.u8(4)?
            .u64(u64::try_from(arr.len()).expect("array fits u64"))?;
        enc.u8(5)?.bytes(grant.param(&vd, &mut mac))?;
        enc.u8(6)?.u64(proto_num(grant.proto))?;
        Ok(())
    })();
    if built.is_err() {
        return 0;
    }
    1 + enc.writer().position()
}

fn lb_read_msg(buf: &mut [u8], total: usize) -> usize {
    buf[0] = consts::CTAP_LARGE_BLOBS;
    let mut enc = Encoder::new(Cursor::new(&mut buf[1..]));
    let built = (|| -> EncRes {
        enc.map(2)?;
        enc.u8(1)?
            .u64(u64::try_from(total).expect("array fits u64"))?;
        enc.u8(3)?.u64(0)?;
        Ok(())
    })();
    if built.is_err() {
        return 0;
    }
    1 + enc.writer().position()
}

// -------------------------------------------------------------------- oracles

fn refused(s: &mut Sess, msg: &[u8], what: &str) {
    let before = s.counter_bytes();
    let w = s.step(msg);
    assert_eq!(
        s.out[0],
        CtapError::PinAuthInvalid.as_u8(),
        "{what}: expected CTAP2_ERR_PIN_AUTH_INVALID (0x33), got 0x{:02X}",
        s.out[0]
    );
    assert_eq!(
        w, 1,
        "{what}: a CTAP error reply carries only its status byte"
    );
    assert_eq!(
        s.counter_bytes(),
        before,
        "{what}: a refusal changed the signature counters"
    );
}

fn ok(s: &mut Sess, msg: &[u8], what: &str) -> usize {
    let w = s.step(msg);
    assert_eq!(
        s.out[0], CTAP2_OK,
        "{what}: expected CTAP2_OK, got 0x{:02X}",
        s.out[0]
    );
    w
}

/// A token-authorized ceremony asserts UV (the token verified), as the authData
/// flags byte records it.
fn assert_uv(s: &Sess, w: usize, what: &str) -> u8 {
    let auth = map_bytes(&s.out[1..w], 2).unwrap_or_else(|| panic!("{what}: no authData"));
    assert!(auth.len() > 33, "{what}: authData too short");
    let flags = auth[32];
    assert!(
        flags & consts::FLAG_UV != 0,
        "{what}: a token-authorized ceremony omitted UV"
    );
    flags
}

/// A token-authorized ceremony asserting UP sets both flags.
fn assert_uv_up(s: &Sess, w: usize, what: &str) {
    let flags = assert_uv(s, w, what);
    assert!(
        flags & consts::FLAG_UP != 0,
        "{what}: a ceremony asserting UP omitted the UP flag"
    );
}

fn lb_write_ok(s: &mut Sess, grant: &Grant, msg: &mut [u8], what: &str) {
    let mut arr = [0u8; LB_LEN];
    let total = lb_array(&mut arr);
    let n = lb_write_msg(msg, grant, &arr[..total]);
    assert!(n > 0, "{what}: large-blob write did not encode");
    let w = ok(s, &msg[..n], what);
    assert_eq!(
        w, 1,
        "{what}: a large-blob write replies with only its status byte"
    );
    // Read it back through the same session, so the success above is a commit and
    // not merely a request that returned OK.
    let n = lb_read_msg(msg, total);
    assert!(n > 0, "{what}: large-blob read did not encode");
    let w = ok(s, &msg[..n], what);
    assert_eq!(
        map_bytes(&s.out[1..w], 1),
        Some(&arr[..total]),
        "{what}: committed large-blob array differs"
    );
}

// ------------------------------------------------------------------- variants

fn spend_mc(s: &mut Sess, plan: &Plan, grant: &Grant, msg: &mut [u8]) {
    let cdh = [0x11u8; 32];
    let n = mc_msg(msg, RP_IDS[0], &cdh, grant);
    assert!(n > 0, "makeCredential did not encode");
    let w = ok(s, msg_buf(msg, n), "makeCredential with a fresh mc token");
    assert_uv_up(s, w, "makeCredential spend");

    let n = mc_msg(msg, RP_IDS[0], &cdh, grant);
    refused(
        s,
        msg_buf(msg, n),
        "makeCredential after the token was spent",
    );

    let n = ga_msg(msg, RP_IDS[0], &cdh, grant);
    refused(s, msg_buf(msg, n), "getAssertion after the token was spent");

    let n = cm_msg(msg, grant);
    refused(
        s,
        msg_buf(msg, n),
        "credentialManagement after the token was spent",
    );

    let ea_before = s.fs.has_data(consts::EF_EA_ENABLED);
    let n = cfg_msg(msg, grant);
    refused(
        s,
        msg_buf(msg, n),
        "authenticatorConfig after the token was spent",
    );
    assert_eq!(
        s.fs.has_data(consts::EF_EA_ENABLED),
        ea_before,
        "a refused authenticatorConfig changed EA state"
    );

    lb_write_ok(
        s,
        grant,
        msg,
        "largeBlobWrite retains PERM_LBW after the spend",
    );

    // No auto-rearm: the refusals above all ran against the spent grant. Only an
    // explicit issuance may restore a usable token.
    let fresh = issue(s, plan.proto, PERM_GA | PERM_LBW, plan.rp_id, s.now_ms);
    let n = ga_msg(msg, RP_IDS[0], &cdh, &fresh);
    let w = ok(
        s,
        msg_buf(msg, n),
        "getAssertion with the explicitly reissued token",
    );
    assert_uv_up(s, w, "getAssertion after the spend");
}

fn residual_lbw(s: &mut Sess, grant: &Grant, msg: &mut [u8]) {
    // Use the token 20 s after issuance, then write 25 s later: the write is past
    // 30 s from ISSUANCE but inside 30 s from the spend, so it only works if the
    // successful ceremony refreshed last_used.
    s.now_ms = grant.issued_ms + 20_000;
    let cdh = [0x22u8; 32];
    let n = ga_msg(msg, RP_IDS[0], &cdh, grant);
    let w = ok(
        s,
        msg_buf(msg, n),
        "getAssertion before the inactivity window",
    );
    assert_uv_up(s, w, "getAssertion spend");

    s.now_ms = grant.issued_ms + 45_000;
    lb_write_ok(
        s,
        grant,
        msg,
        "largeBlobWrite after the spend refreshed the usage timer",
    );
}

fn rp_refusal(s: &mut Sess, grant: &Grant, msg: &mut [u8]) {
    let bound = grant.rp_id.expect("the rp-refusal variant is rp-bound");
    let other = if bound == RP_IDS[0] {
        RP_IDS[1]
    } else {
        RP_IDS[0]
    };
    let cdh = [0x33u8; 32];
    let n = mc_msg(msg, other, &cdh, grant);
    refused(
        s,
        msg_buf(msg, n),
        "makeCredential for another rpId with an rp-bound token",
    );
    // The refusal neither spent nor rebound the grant: the bound rp still works.
    let n = mc_msg(msg, bound, &cdh, grant);
    let w = ok(s, msg_buf(msg, n), "makeCredential for the bound rpId");
    assert_uv_up(s, w, "makeCredential on the bound rpId");

    let n = mc_msg(msg, bound, &cdh, grant);
    refused(
        s,
        msg_buf(msg, n),
        "makeCredential after the bound-rp ceremony spent the token",
    );
}

fn inactivity(s: &mut Sess, plan: &Plan, grant: &Grant, msg: &mut [u8]) {
    let cdh = [0x44u8; 32];
    // One millisecond short of the window is still usable; the refresh makes it
    // the baseline for the refusal below. CM metadata is non-consuming under
    // every build flavour, unlike an `up:false` assertion under `strict-up`.
    s.now_ms = grant.issued_ms + consts::PUAT_INITIAL_USAGE_LIMIT_MS - 1;
    let n = cm_msg(msg, grant);
    let w = ok(
        s,
        msg_buf(msg, n),
        "credentialManagement one millisecond before the inactivity window",
    );
    assert!(w > 1, "credentialManagement metadata replies with a map");

    s.now_ms = grant.issued_ms + 2 * consts::PUAT_INITIAL_USAGE_LIMIT_MS - 1;
    let n = ga_msg(msg, RP_IDS[0], &cdh, grant);
    refused(
        s,
        msg_buf(msg, n),
        "getAssertion after the token's inactivity window",
    );

    let fresh = issue(s, plan.proto, plan.permissions, plan.rp_id, s.now_ms);
    let n = ga_msg(msg, RP_IDS[0], &cdh, &fresh);
    let w = ok(
        s,
        msg_buf(msg, n),
        "getAssertion with the token reissued after expiry",
    );
    assert_uv_up(s, w, "getAssertion after inactivity expiry");
}

fn absolute(s: &mut Sess, plan: &Plan, grant: &Grant, msg: &mut [u8]) {
    // Refresh with a non-consuming metadata read every 20 s, so the rolling
    // window never expires and only the absolute cap can retire the token.
    for k in 1..=29u64 {
        s.now_ms = grant.issued_ms + k * 20_000;
        let n = cm_msg(msg, grant);
        let w = ok(
            s,
            msg_buf(msg, n),
            "credentialManagement refresh inside the absolute lifetime",
        );
        assert!(w > 1, "credentialManagement metadata replies with a map");
    }
    s.now_ms = grant.issued_ms + consts::PUAT_MAX_USAGE_PERIOD_MS;
    let cdh = [0x55u8; 32];
    let n = ga_msg(msg, RP_IDS[0], &cdh, grant);
    refused(
        s,
        msg_buf(msg, n),
        "getAssertion after the token's absolute lifetime",
    );

    let fresh = issue(s, plan.proto, plan.permissions, plan.rp_id, s.now_ms);
    let n = ga_msg(msg, RP_IDS[0], &cdh, &fresh);
    let w = ok(
        s,
        msg_buf(msg, n),
        "getAssertion with the token reissued after the absolute cap",
    );
    assert_uv_up(s, w, "getAssertion after absolute expiry");
}

fn reset_revocation(s: &mut Sess, plan: &Plan, grant: &Grant, msg: &mut [u8]) {
    // Inside the §6.6 power-up window a screenless build honors.
    s.now_ms = 2_000;
    let w = ok(
        s,
        &[consts::CTAP_RESET],
        "authenticatorReset inside the power-up window",
    );
    assert_eq!(w, 1, "authenticatorReset replies with only its status byte");

    let cdh = [0x66u8; 32];
    let n = ga_msg(msg, RP_IDS[0], &cdh, grant);
    refused(s, msg_buf(msg, n), "getAssertion with the pre-reset token");

    // Reset wiped EF_PIN and the credential store, so establishment includes
    // setPIN again and the proof of the new grant is a fresh registration.
    let fresh = bootstrap(s, plan.proto, plan.permissions, plan.rp_id, 3_000);
    let n = mc_msg(msg, RP_IDS[0], &cdh, &fresh);
    let w = ok(
        s,
        msg_buf(msg, n),
        "makeCredential with the token issued after reset",
    );
    assert_uv_up(s, w, "makeCredential after reset");
}

fn wrong_pin(s: &mut Sess, plan: &Plan, grant: &Grant, msg: &mut [u8]) {
    s.now_ms = 2_000;
    let shared = s
        .open_shared(plan.proto)
        .expect("clientPIN getKeyAgreement must succeed");
    let secret = &shared[..plan.proto.shared_len()];
    let iv = [0x5Cu8; pinproto::IV_SIZE];
    let mut pin_hash_enc = [0u8; 16 + pinproto::IV_SIZE];
    let hlen = pinproto::encrypt(
        plan.proto,
        secret,
        &iv,
        &sha256(b"00000000")[..16],
        &mut pin_hash_enc,
    )
    .expect("wrong-PIN block must encrypt");
    s.now_ms = 2_000;
    let n = cp_msg(
        msg,
        proto_num(plan.proto),
        CP_GET_PIN_UV_TOKEN_USING_PIN,
        &CpReq {
            key_agreement: true,
            pin_hash_enc: &pin_hash_enc[..hlen],
            permissions: u64::from(plan.permissions),
            rp_id: plan.rp_id,
            ..CpReq::default()
        },
    );
    let w = s.step(&msg[..n]);
    assert_eq!(
        w, 1,
        "a wrong-PIN token request carries only its status byte"
    );
    assert_eq!(
        s.out[0],
        CtapError::PinInvalid.as_u8(),
        "a wrong-PIN token request must be CTAP2_ERR_PIN_INVALID (0x31), got 0x{:02X}",
        s.out[0]
    );

    let cdh = [0x77u8; 32];
    let n = ga_msg(msg, RP_IDS[0], &cdh, grant);
    refused(
        s,
        msg_buf(msg, n),
        "getAssertion with the token revoked by a wrong PIN",
    );

    // The mismatch regenerated the device ephemeral key, so the reissue derives
    // a fresh shared secret from a fresh getKeyAgreement.
    let fresh = issue(s, plan.proto, plan.permissions, plan.rp_id, 3_000);
    let n = ga_msg(msg, RP_IDS[0], &cdh, &fresh);
    let w = ok(
        s,
        msg_buf(msg, n),
        "getAssertion with the token reissued after a wrong PIN",
    );
    assert_uv_up(s, w, "getAssertion after wrong-PIN revocation");
}

fn reissue_after_refusal(s: &mut Sess, plan: &Plan, grant: &Grant, msg: &mut [u8]) {
    // A fresh token that did not request `mc` is refused before the ceremony,
    // and that refusal must leave the grant intact for the requested `ga` use.
    let cdh = [0x88u8; 32];
    assert!(
        grant.permissions & PERM_MC == 0,
        "this variant's base permission set excludes mc"
    );
    let n = mc_msg(msg, RP_IDS[0], &cdh, grant);
    refused(
        s,
        msg_buf(msg, n),
        "makeCredential with a token that requested only ga",
    );

    let n = ga_msg(msg, RP_IDS[0], &cdh, grant);
    let w = ok(
        s,
        msg_buf(msg, n),
        "getAssertion with the requested ga permission",
    );
    assert_uv_up(s, w, "getAssertion spend");

    let n = ga_msg(msg, RP_IDS[0], &cdh, grant);
    refused(s, msg_buf(msg, n), "getAssertion after the token was spent");

    let fresh = issue(s, plan.proto, plan.permissions, plan.rp_id, s.now_ms);
    let n = ga_msg(msg, RP_IDS[0], &cdh, &fresh);
    let w = ok(
        s,
        msg_buf(msg, n),
        "getAssertion with the explicitly reissued token",
    );
    assert_uv_up(s, w, "getAssertion after reissue");

    // The mirror mask: cm only reaches credentialManagement, and the same token
    // cannot reach getAssertion. Unscoped so the rp-less metadata read is legal.
    let cm_only = issue(s, plan.proto, PERM_CM, None, s.now_ms);
    let n = ga_msg(msg, RP_IDS[0], &cdh, &cm_only);
    refused(
        s,
        msg_buf(msg, n),
        "getAssertion with a token that requested only cm",
    );
    let n = cm_msg(msg, &cm_only);
    let w = ok(
        s,
        msg_buf(msg, n),
        "credentialManagement with the requested cm permission",
    );
    assert!(w > 1, "credentialManagement metadata replies with a map");
}

// ---------------------------------------------------------------- entry point

pub(crate) fn exercise(rest: &[u8]) {
    let plan = Plan::from(rest);
    let mut s = Sess::new(provisioned());
    let mut msg = [0u8; MSG_BUF];

    let grant = bootstrap(&mut s, plan.proto, plan.permissions, plan.rp_id, 1_000);

    // A non-consuming check that the requested permission set is what the token
    // carries: cm metadata and authenticatorConfig answer on their bit alone.
    if grant.rp_id.is_none() {
        let n = cm_msg(&mut msg, &grant);
        if grant.permissions & PERM_CM != 0 {
            ok(
                &mut s,
                &msg[..n],
                "token carries the requested cm permission",
            );
        } else {
            refused(
                &mut s,
                &msg[..n],
                "token did not carry an unrequested cm permission",
            );
        }
    }
    let n = cfg_msg(&mut msg, &grant);
    if grant.permissions & PERM_ACFG != 0 {
        let w = ok(
            &mut s,
            &msg[..n],
            "token carries the requested acfg permission",
        );
        assert_eq!(
            w, 1,
            "authenticatorConfig replies with only its status byte"
        );
    } else {
        let ea_before = s.fs.has_data(consts::EF_EA_ENABLED);
        refused(
            &mut s,
            &msg[..n],
            "token did not carry an unrequested acfg permission",
        );
        assert_eq!(
            s.fs.has_data(consts::EF_EA_ENABLED),
            ea_before,
            "a refused authenticatorConfig changed EA state"
        );
    }

    match plan.variant {
        Variant::Spend => spend_mc(&mut s, &plan, &grant, &mut msg),
        Variant::ResidualLbw => residual_lbw(&mut s, &grant, &mut msg),
        Variant::RpRefusal => rp_refusal(&mut s, &grant, &mut msg),
        Variant::Inactivity => inactivity(&mut s, &plan, &grant, &mut msg),
        Variant::Absolute => absolute(&mut s, &plan, &grant, &mut msg),
        Variant::Reset => reset_revocation(&mut s, &plan, &grant, &mut msg),
        Variant::WrongPin => wrong_pin(&mut s, &plan, &grant, &mut msg),
        Variant::Reissue => reissue_after_refusal(&mut s, &plan, &grant, &mut msg),
    }

    s.display_walk();
}

/// Borrow the encoded prefix of `msg`. Kept tiny so a caller cannot accidentally
/// pass the whole scratch buffer (with trailing zeros) as a request.
fn msg_buf(msg: &[u8], n: usize) -> &[u8] {
    assert!(n > 0, "request did not encode");
    &msg[..n]
}
