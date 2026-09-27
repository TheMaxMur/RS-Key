// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `authenticatorCredentialManagement`: getCredsMetadata (0x01), enumerateRPs
//! Begin/Next (0x02/0x03), enumerateCredentials Begin/Next (0x04/0x05),
//! deleteCredential (0x06) and updateUserInformation (0x07). Every subcommand
//! except the `Next` walkers is gated on a `pinUvAuthParam` carrying the `cm`
//! permission; the MAC covers the subcommand byte for 0x01/0x02 and
//! `subcommand ‖ <raw subCommandParams>` for 0x04/0x06/0x07. The three read
//! subcommands additionally accept the persistent token's `pcmr` grant
//! (CTAP 2.2 §6.8.2/.3/.4) while a PIN is set; the two writers never do.
//! enumerateCredentials emits the core 0x06–0x09 plus the extension fields
//! 0x0A credProtect / 0x0B largeBlobKey (derived) / 0x0C thirdPartyPayment.

// Host bytes: a panic here is a board that answers nothing until unplugged.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};

use rsk_crypto::pinproto::{self, PinProto};
use rsk_fs::{Fs, Storage};

use crate::cbordec::{cbor, def_arr, def_map, skip_value};
use crate::consts::{
    CM_DELETE_CREDENTIAL, CM_ENUMERATE_CREDS_BEGIN, CM_ENUMERATE_CREDS_NEXT,
    CM_ENUMERATE_RPS_BEGIN, CM_ENUMERATE_RPS_NEXT, CM_GET_CREDS_METADATA, CM_UPDATE_USER_INFO,
    CRED_PROT_UV_OPTIONAL, EF_CRED, EF_PIN, EF_RP, LARGE_BLOB_EXT, MAX_RAW_SUBPARA,
    MAX_RESIDENT_CREDENTIALS, SETTLE_KEY_LEN,
};
use crate::credential::{
    CRED_BOX_MAX, CRED_REC_MAX, CRED_RESIDENT_LEN, CredInput, RECORD_PREFIX, RP_PREFIX, RP_REC_MAX,
    USER_NAME_MAX, compose_cred_record, cred_record_box, cred_record_pubkey, credential_create,
    credential_load, derive_large_blob_key, remaining_rk, resident_key_input, slot_map,
    truncate_utf8, unseal_rp_id,
};
use crate::ec::{CredKey, cached_point_len, cose_public_from_point};
use crate::error::{CtapError, CtapResult};
use crate::keyderiv::fido_load_key;
use crate::largeblobext;
use crate::seed::load_ppuat;
use crate::state::{FidoState, PERM_CM};
use crate::{Ctx, Rng};

// EF_RP record: `count(1) ‖ rpIdHash(32) ‖ box(rpId_text)` — the rpId domain is
// boxed under the device seed (see `credential::seal_rp_id`); `RP_PREFIX` spans
// the cleartext `count ‖ rpIdHash` head.

struct Req<'a> {
    subcommand: u64,
    raw_subpara: &'a [u8],
    proto: Option<u64>,
    param: Option<&'a [u8]>,
    rp_id_hash: Option<&'a [u8]>,
    cred_id: Option<&'a [u8]>,
    user_id: Option<&'a [u8]>,
    user_name: &'a str,
    user_display_name: &'a str,
}

fn parse(data: &[u8]) -> Result<Req<'_>, CtapError> {
    let mut d = Decoder::new(data);
    let mut req = Req {
        subcommand: 0,
        raw_subpara: &[],
        proto: None,
        param: None,
        rp_id_hash: None,
        cred_id: None,
        user_id: None,
        user_name: "",
        user_display_name: "",
    };
    let n = def_map(&mut d)?;
    let mut expected = 1u64;
    for _ in 0..n {
        let key = cbor(d.u32())? as u64;
        // Key 1 (subCommand) is mandatory and first; keys ascend (canonical CBOR).
        if expected <= 1 && key != 1 {
            return Err(CtapError::MissingParameter);
        }
        if key < expected {
            return Err(CtapError::InvalidCbor);
        }
        expected = key + 1;
        match key {
            1 => req.subcommand = cbor(d.u32())? as u64,
            2 => parse_subpara(data, &mut d, &mut req)?,
            3 => req.proto = Some(cbor(d.u32())? as u64),
            4 => req.param = Some(cbor(d.bytes())?),
            _ => skip_value(&mut d)?,
        }
    }
    Ok(req)
}

/// Parse field 2 (subCommandParams) and capture its raw CBOR bytes (covered by
/// the pinUvAuthParam MAC).
fn parse_subpara<'a>(
    data: &'a [u8],
    d: &mut Decoder<'a>,
    req: &mut Req<'a>,
) -> Result<(), CtapError> {
    let start = d.position();
    let m = def_map(d)?;
    for _ in 0..m {
        match cbor(d.u32())? as u64 {
            0x01 => req.rp_id_hash = Some(cbor(d.bytes())?),
            0x02 => {
                let im = def_map(d)?;
                for _ in 0..im {
                    match cbor(d.str())? {
                        "id" => req.cred_id = Some(cbor(d.bytes())?),
                        "transports" => {
                            let a = def_arr(d)?;
                            for _ in 0..a {
                                cbor(d.str())?;
                            }
                        }
                        _ => skip_value(d)?, // "type"
                    }
                }
            }
            0x03 => {
                let im = def_map(d)?;
                for _ in 0..im {
                    match cbor(d.str())? {
                        "id" => req.user_id = Some(cbor(d.bytes())?),
                        "name" => req.user_name = cbor(d.str())?,
                        "displayName" => req.user_display_name = cbor(d.str())?,
                        _ => skip_value(d)?,
                    }
                }
            }
            _ => skip_value(d)?,
        }
    }
    req.raw_subpara = data
        .get(start..d.position())
        .ok_or(CtapError::InvalidCbor)?;
    Ok(())
}

/// `authenticatorCredentialManagement`: write the response CBOR into `out`,
/// returning its length.
pub fn cred_mgmt<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    data: &[u8],
    out: &mut [u8],
) -> CtapResult {
    let req = parse(data)?;

    // The Next walkers reuse saved state and carry no pinUvAuthParam.
    match req.subcommand {
        CM_ENUMERATE_RPS_NEXT => return enumerate_rps(ctx, false, out),
        CM_ENUMERATE_CREDS_NEXT => {
            let rp_id_hash = ctx.state.cm.rp_id_hash;
            return enumerate_creds(ctx, false, &rp_id_hash, out);
        }
        _ => {}
    }

    // Past those two, this is a credentialManagement command that does NOT
    // continue an enumerate walk, so §6's "exclusively preceded" ends the one in
    // flight — `process_cbor` cannot do it, the subcommand is only known here. A
    // YubiKey 5.7.4 behaves the same, measured: Begin, getCredsMetadata,
    // getNextRP answers NOT_ALLOWED.
    ctx.state.cm.reset();

    // Every other subcommand requires a verified pinUvAuthParam — but the protocol
    // is judged first, and absent is not the same as unsupported: a YubiKey 5.7.4
    // answers INVALID_PARAMETER to `pinUvAuthProtocol: 0` with no param at all,
    // and MISSING_PARAMETER when the param is there and the protocol is not.
    let proto = crate::clientpin::checked_proto(req.proto)?;
    let param = req.param.ok_or(CtapError::PuatRequired)?;
    let proto = proto.ok_or(CtapError::MissingParameter)?;

    match req.subcommand {
        CM_GET_CREDS_METADATA => {
            let subcommand = u8::try_from(CM_GET_CREDS_METADATA).unwrap_or(u8::MAX);
            authorize_cm(ctx, proto, &[subcommand], param, None)?;
            creds_metadata(ctx, out)
        }
        CM_ENUMERATE_RPS_BEGIN => {
            let subcommand = u8::try_from(CM_ENUMERATE_RPS_BEGIN).unwrap_or(u8::MAX);
            authorize_cm(ctx, proto, &[subcommand], param, None)?;
            enumerate_rps(ctx, true, out)
        }
        CM_ENUMERATE_CREDS_BEGIN => {
            let h = req
                .rp_id_hash
                .filter(|h| h.len() == 32)
                .ok_or(CtapError::MissingParameter)?;
            let mut rp_id_hash = [0u8; 32];
            rp_id_hash.copy_from_slice(h);
            let mut pbuf = [0u8; 1 + MAX_RAW_SUBPARA];
            let payload =
                payload_with_subpara(CM_ENUMERATE_CREDS_BEGIN, req.raw_subpara, &mut pbuf)?;
            authorize_cm(ctx, proto, payload, param, Some(&rp_id_hash))?;
            enumerate_creds(ctx, true, &rp_id_hash, out)
        }
        // 0x06/0x07 name a credential rather than an rp, so §6.8.5/6.8.6 match the
        // token's permissions RP ID against *the credential's* rp: locate first, then
        // finish the authorization, then act.
        CM_DELETE_CREDENTIAL => {
            let cred_id = req.cred_id.ok_or(CtapError::MissingParameter)?;
            let mut pbuf = [0u8; 1 + MAX_RAW_SUBPARA];
            let payload = payload_with_subpara(CM_DELETE_CREDENTIAL, req.raw_subpara, &mut pbuf)?;
            verify_cm_token(ctx.state, proto, payload, param)?;
            // A lookup the flash failed binds as one that found nothing: a scoped
            // token must not learn which other RP's ids are stored from the word.
            let found = find_resident(ctx.fs, cred_id);
            check_rp_binding(
                ctx.state,
                found.as_ref().ok().and_then(|f| f.as_ref()).map(|(_, h)| h),
            )?;
            ctx.state.mark_token_used(ctx.now_ms);
            let (slot, rp_id_hash) = found?.ok_or(CtapError::NoCredentials)?;
            delete_credential(ctx, slot, &rp_id_hash)
        }
        CM_UPDATE_USER_INFO => {
            let cred_id = req.cred_id.ok_or(CtapError::MissingParameter)?;
            let user_id = req.user_id.ok_or(CtapError::MissingParameter)?;
            let mut pbuf = [0u8; 1 + MAX_RAW_SUBPARA];
            let payload = payload_with_subpara(CM_UPDATE_USER_INFO, req.raw_subpara, &mut pbuf)?;
            verify_cm_token(ctx.state, proto, payload, param)?;
            // A lookup the flash failed binds as one that found nothing: a scoped
            // token must not learn which other RP's ids are stored from the word.
            let found = find_resident(ctx.fs, cred_id);
            check_rp_binding(
                ctx.state,
                found.as_ref().ok().and_then(|f| f.as_ref()).map(|(_, h)| h),
            )?;
            ctx.state.mark_token_used(ctx.now_ms);
            let (slot, _) = found?.ok_or(CtapError::NoCredentials)?;
            update_user(ctx, slot, user_id, req.user_name, req.user_display_name)
        }
        // §8.1 would have this be INVALID_SUBCOMMAND; a YubiKey 5.7.4 answers
        // INVALID_PARAMETER here and hosts are written against it. Measured, both
        // 0x0A and its 0x41 prototype, stable across runs.
        _ => Err(CtapError::InvalidParameter),
    }
}

/// Authorize one of the three **read** subcommands: §6.8.2/.3/.4 try the
/// persistent token first and fall back to the session token, which must then
/// carry `cm` and match the rpId binding. Named `authorize` (not `verify`) because
/// the fallback refreshes the session token's rolling usage window.
fn authorize_cm<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    proto: PinProto,
    payload: &[u8],
    param: &[u8],
    rp_id_hash: Option<&[u8; 32]>,
) -> Result<(), CtapError> {
    if authorized_by_ppuat(ctx, proto, payload, param) {
        return Ok(());
    }
    verify_cm_token(ctx.state, proto, payload, param)?;
    check_rp_binding(ctx.state, rp_id_hash)?;
    ctx.state.mark_token_used(ctx.now_ms);
    Ok(())
}

/// Whether the MAC was made with the persistent token (CTAP 2.2 §6.8.2 step 4).
/// A holder of it *is* the `pcmr` grant, and a persistent token carries no rpId
/// binding and no usage timer, so it authorizes on its own. No record — or no
/// `EF_PIN` behind it — is no grant.
/// Refines `RSKeySecurityState!NoAccessibleSecretWithoutGate` — SEC-FIDO-004.
fn authorized_by_ppuat<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    proto: PinProto,
    payload: &[u8],
    param: &[u8],
) -> bool {
    // Both issuance paths gate on `EF_PIN` (§6.5.5.7.2/.3), but a record can stand
    // without one: provisioning mints it before any PIN exists, and an older build's
    // torn wipe could drop the PIN under a grant it had handed out. Neither authorizes.
    if !ctx.fs.has_data(EF_PIN) {
        return false;
    }
    let Some(mut tok) = load_ppuat(&ctx.dev, ctx.fs) else {
        return false;
    };
    let ok = pinproto::verify(proto, tok.expose(), payload, param);
    tok.wipe();
    ok
}

/// The half of [`authorize_cm`] that needs no credential: the pinUvAuthParam over
/// `payload` and the `cm` permission. Split out for deleteCredential /
/// updateUserInformation, whose rpId check can only run once the target credential
/// has been located.
fn verify_cm_token(
    state: &mut FidoState,
    proto: PinProto,
    payload: &[u8],
    param: &[u8],
) -> Result<(), CtapError> {
    if !state.verify_token(proto, payload, param) || state.paut.permissions & PERM_CM == 0 {
        return Err(CtapError::PinAuthInvalid);
    }
    Ok(())
}

/// An rpId-scoped token may only manage that rp. `None` means the subcommand names no
/// rp at all (0x01/0x02), which a scoped token may not use; for 0x06/0x07 it also
/// stands for "no such credential", where a scoped token is told PIN_AUTH_INVALID
/// rather than NO_CREDENTIALS — otherwise the code would reveal whether some other
/// rp owns the id it was handed.
fn check_rp_binding(state: &FidoState, rp_id_hash: Option<&[u8; 32]>) -> Result<(), CtapError> {
    if !state.paut.has_rp_id {
        return Ok(());
    }
    match rp_id_hash {
        Some(h) if state.paut.rp_id_hash == *h => Ok(()),
        _ => Err(CtapError::PinAuthInvalid),
    }
}

/// Build `subcommand ‖ raw_subpara` for the MAC payload.
fn payload_with_subpara<'a>(
    subcmd: u64,
    raw: &[u8],
    buf: &'a mut [u8; 1 + MAX_RAW_SUBPARA],
) -> Result<&'a [u8], CtapError> {
    let end = 1 + raw.len();
    let Some(tail) = buf.get_mut(1..end) else {
        return Err(CtapError::RequestTooLarge);
    };
    tail.copy_from_slice(raw);
    buf[0] = u8::try_from(subcmd).map_err(|_| CtapError::RequestTooLarge)?;
    buf.get(..end).ok_or(CtapError::RequestTooLarge)
}

/// 0x01 getCredsMetadata: count populated EF_CRED slots.
fn creds_metadata<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, out: &mut [u8]) -> CtapResult {
    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(ctx.fs, EF_CRED, &mut occupied);
    let existing =
        u16::try_from(occupied.iter().filter(|&&b| b).count()).map_err(|_| CtapError::Other)?;
    let remaining = remaining_rk(ctx.fs, existing);
    let mut enc = Encoder::new(Cursor::new(out));
    enc.map(2)
        .and_then(|e| e.u8(1)?.u16(existing))
        .and_then(|e| e.u8(2)?.u16(remaining))
        .map_err(|_| CtapError::Other)?;
    Ok(enc.writer().position())
}

/// 0x02 enumerateRPsBegin / 0x03 getNextRP: walk EF_RP records with a non-zero
/// credential count and return the `rp_counter`-th.
fn enumerate_rps<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    begin: bool,
    out: &mut [u8],
) -> CtapResult {
    if begin {
        ctx.state.cm.channel = ctx.state.channel;
        ctx.state.cm.rp_counter = 1;
        ctx.state.cm.rp_total = 0;
        ctx.state.cm.rp_next_slot = 0;
    } else if !ctx.state.cm.may_walk_rps(ctx.state.channel) {
        return Err(CtapError::NotAllowed);
    }
    let target = ctx.state.cm.rp_counter;

    let mut total = 0u16;
    let mut found = false;
    let mut rp = [0u8; RP_REC_MAX];
    let mut rp_len = 0usize;
    let mut buf = [0u8; RP_REC_MAX];
    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(ctx.fs, EF_RP, &mut occupied);
    // Resume at rp_next_slot (0 on Begin, past the last match on getNext) so a
    // getNext is O(gap-to-next) not O(scan-from-0); Begin still makes one full
    // pass to count rp_total.
    for (i, &live) in (0..MAX_RESIDENT_CREDENTIALS)
        .zip(&occupied)
        .skip(usize::from(ctx.state.cm.rp_next_slot))
    {
        if !live {
            continue;
        }
        // A record the flash would not serve fails the walk: skipping it answered
        // a total one short, and the owner was shown a list with an RP missing.
        let Some(n) = ctx
            .fs
            .try_read(EF_RP + i, &mut buf)
            .map_err(|_| CtapError::Other)?
        else {
            continue;
        };
        let n = n.min(buf.len());
        if n >= RP_PREFIX && buf[0] > 0 {
            if !found {
                found = true;
                rp = buf;
                rp_len = n;
                ctx.state.cm.rp_next_slot = i + 1;
                if !begin {
                    break;
                }
            }
            if begin {
                total = total.saturating_add(1);
            }
        }
    }
    if !found {
        return Err(CtapError::NoCredentials);
    }
    if begin {
        ctx.state.cm.rp_total = total;
    }
    ctx.state.cm.rp_counter = target.saturating_add(1);
    // Per leg, not per walk — CTAP 2.3 §6 bounds the gap "between such commands",
    // so a platform drawing an account picker cannot run out of the window halfway
    // down its own list (§6.3 step 7 says the same for the assertion walk).
    ctx.state.cm.last_leg_ms = ctx.now_ms;

    // The EF_RP tail is boxed under the device seed — recover the rpId domain.
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&rp[1..RP_PREFIX]);
    let mut seed = ctx.load_keydev().ok_or(CtapError::NotAllowed)?;
    let mut scratch = [0u8; RP_REC_MAX];
    let tail = rp.get(RP_PREFIX..rp_len).ok_or(CtapError::Other)?;
    let unsealed = unseal_rp_id(seed.expose(), &rp_id_hash, tail, &mut scratch);
    seed.wipe();
    let (rp_id, _) = unsealed.ok_or(CtapError::Other)?;

    let mut enc = Encoder::new(Cursor::new(out));
    enc.map(if begin { 3 } else { 2 })
        .and_then(|e| e.u8(3)?.map(1))
        .and_then(|e| e.str("id")?.str(rp_id))
        .and_then(|e| e.u8(4)?.bytes(&rp_id_hash))
        .map_err(|_| CtapError::Other)?;
    if begin {
        enc.u8(5)
            .and_then(|e| e.u16(total))
            .map_err(|_| CtapError::Other)?;
    }
    Ok(enc.writer().position())
}

/// 0x04 enumerateCredentialsBegin / 0x05 getNextCredential: walk EF_CRED records
/// for `rp_id_hash` and return the `cred_counter`-th credential.
fn enumerate_creds<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    begin: bool,
    rp_id_hash: &[u8; 32],
    out: &mut [u8],
) -> CtapResult {
    if begin {
        ctx.state.cm.channel = ctx.state.channel;
        ctx.state.cm.cred_counter = 1;
        ctx.state.cm.cred_total = 0;
        ctx.state.cm.cred_next_slot = 0;
    } else if !ctx.state.cm.may_walk_creds(ctx.state.channel) {
        return Err(CtapError::NotAllowed);
    }
    let target = ctx.state.cm.cred_counter;

    let mut total = 0u16;
    let mut found = false;
    let mut rec = [0u8; CRED_REC_MAX];
    let mut rec_len = 0usize;
    let mut buf = [0u8; CRED_REC_MAX];
    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(ctx.fs, EF_CRED, &mut occupied);
    let unread = refresh_rp_index(ctx, begin, &occupied, &mut buf);
    // A getNext has only the Begin's total to go by, so an unread record in a rebuild
    // under the walk ends it, before a read of the walk itself can answer first.
    if unread && !begin {
        ctx.state.cm.reset();
        return Err(CtapError::Other);
    }
    let want_prefix =
        u32::from_le_bytes([rp_id_hash[0], rp_id_hash[1], rp_id_hash[2], rp_id_hash[3]]);
    // Resume at cred_next_slot (0 on Begin, past the last match on getNext) so a
    // getNext is O(gap-to-next) not O(scan-from-0); Begin still makes one full
    // pass to count cred_total for this rp.
    for ((i, &live), &prefix) in (0..MAX_RESIDENT_CREDENTIALS)
        .zip(&occupied)
        .zip(&ctx.state.cm.rp_index)
        .skip(usize::from(ctx.state.cm.cred_next_slot))
    {
        if !live {
            continue;
        }
        // Skip a slot whose cached rpId-hash prefix can't match — the read below is
        // the store's costliest op. The full 32-byte compare still confirms a hit.
        if prefix != want_prefix {
            continue;
        }
        let Some(n) = ctx
            .fs
            .try_read(EF_CRED + i, &mut buf)
            .map_err(|_| CtapError::Other)?
        else {
            continue;
        };
        let n = n.min(buf.len());
        if n >= RECORD_PREFIX && buf[..32] == *rp_id_hash {
            if !found {
                found = true;
                rec = buf;
                rec_len = n;
                ctx.state.cm.cred_next_slot = i + 1;
                if !begin {
                    break;
                }
            }
            if begin {
                total = total.saturating_add(1);
            }
        }
    }
    // A record the flash would not serve is this rp's only if its EF_RP count says
    // more credentials than the walk found, as for makeCredential's refusal.
    if unread
        && crate::credential::rp_count(ctx.fs, rp_id_hash).map_err(|_| CtapError::Other)?
            > usize::from(total)
    {
        return Err(CtapError::Other);
    }
    if !found {
        return Err(CtapError::NoCredentials);
    }

    let mut seed = ctx.load_keydev().ok_or(CtapError::NotAllowed)?;
    let rec = rec.get(..rec_len).ok_or(CtapError::NotAllowed)?;
    let result = enumerate_creds_response(rec, rp_id_hash, begin, total, seed.expose(), out);
    seed.wipe();
    let resp_len = result?;

    if begin {
        ctx.state.cm.cred_total = total;
        ctx.state.cm.rp_id_hash = *rp_id_hash;
    }
    ctx.state.cm.cred_counter = target.saturating_add(1);
    ctx.state.cm.last_leg_ms = ctx.now_ms;
    Ok(resp_len)
}

/// Build (or refresh) the slot→rpId-hash-prefix index once per enumeration, so
/// each per-rp Begin filters slots in RAM and reads flash only for its own rp.
/// Without it every Begin re-read all slots, making a many-distinct-rp walk
/// O(rps·creds) (256 rps × 256 creds ≈ 13 s on hardware). `write_gen` moves on
/// any put/delete, so a mid-walk mutation forces a rebuild rather than a stale
/// read. See `CredMgmtState::rp_index`. Answers whether a record the flash would
/// not serve went in as prefix 0.
fn refresh_rp_index<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    begin: bool,
    occupied: &[bool; MAX_RESIDENT_CREDENTIALS as usize],
    buf: &mut [u8; CRED_REC_MAX],
) -> bool {
    // A getNext walks the index its Begin built, whose count check excused a slot
    // it could not read; only a write since then rebuilds it under the walk.
    let current = ctx.state.cm.rp_index_gen == ctx.fs.write_gen();
    if current && (ctx.state.cm.rp_index_valid || !begin) {
        return false;
    }
    let mut unread = false;
    for ((i, &live), entry) in (0..MAX_RESIDENT_CREDENTIALS)
        .zip(occupied)
        .zip(&mut ctx.state.cm.rp_index)
    {
        let prefix = if live {
            match ctx.fs.try_read(EF_CRED + i, buf) {
                Ok(Some(n)) if n >= 4 => u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
                Ok(_) => 0,
                Err(_) => {
                    unread = true;
                    0
                }
            }
        } else {
            0
        };
        *entry = prefix;
    }
    // A failed read would cache prefix 0 and hide its credential from every walk
    // until the next flash write: an index with one is rebuilt next time.
    ctx.state.cm.rp_index_gen = ctx.fs.write_gen();
    ctx.state.cm.rp_index_valid = !unread;
    unread
}

fn enumerate_creds_response(
    rec: &[u8],
    rp_id_hash: &[u8; 32],
    begin: bool,
    total: u16,
    seed: &[u8; 32],
    out: &mut [u8],
) -> CtapResult {
    let resident_id = rec.get(32..RECORD_PREFIX).ok_or(CtapError::NotAllowed)?;
    let cred_box = cred_record_box(rec);
    let cached_pubkey = cred_record_pubkey(rec);
    // The enumerated pubkey must be the one getAssertion signs with: a v2/v3
    // credential keys off its stable resident id, so both agree across a reseal.
    let key_input = resident_key_input(cred_box, Some(resident_id));

    let mut scratch = [0u8; CRED_REC_MAX];
    let cred =
        credential_load(seed, cred_box, rp_id_hash, &mut scratch).ok_or(CtapError::NotAllowed)?;

    // A v3 record caches the public point (validated against the credential's
    // curve): emit it and skip the per-call d·G — the dominant enumerate cost on
    // this MCU's software EC. A v1/v2 record (or an uncacheable curve) derives it.
    let use_cache = cached_pubkey.is_some_and(|p| cached_point_len(cred.curve) == Some(p.len()));
    let key = if use_cache {
        None
    } else {
        let mut raw = fido_load_key(seed, key_input).ok_or(CtapError::NotAllowed)?;
        let k = CredKey::from_raw(cred.curve, raw.expose()).ok_or(CtapError::NotAllowed)?;
        raw.wipe();
        Some(k)
    };

    let user_fields = u64::from(!cred.user_id.is_empty())
        + u64::from(!cred.user_name.is_empty())
        + u64::from(!cred.user_display_name.is_empty());

    // Extension response fields: 0x0A credProtect (always — defaults to level 1),
    // 0x0B largeBlobKey (derived, when the credential opted in), 0x0C
    // thirdPartyPayment (always). The stored opt-in outlives the design it belongs
    // to — a credential created by a default build carries it, and a
    // `largeblob-ext` build must still not serve half of the CTAP 2.1 pair.
    let large_blob_key = if cred.ext.large_blob_key && !LARGE_BLOB_EXT {
        Some(derive_large_blob_key(seed, key_input))
    } else {
        None
    };
    // A credential with no explicit credProtect is level 1 (userVerificationOptional);
    // the response always carries it (conformance CredMgmt-EnumerateCredentials P-1).
    let cred_protect = if cred.ext.cred_protect == 0 {
        CRED_PROT_UV_OPTIONAL
    } else {
        cred.ext.cred_protect
    };
    let fields = 3
        + u64::from(begin)
        + 1 // 0x0A credProtect (always)
        + u64::from(large_blob_key.is_some())
        + 1; // 0x0C thirdPartyPayment

    let mut enc = Encoder::new(Cursor::new(&mut *out));
    enc.map(fields).map_err(|_| CtapError::Other)?;

    // 0x06 user — only the present sub-fields.
    enc.u8(6)
        .and_then(|e| e.map(user_fields))
        .map_err(|_| CtapError::Other)?;
    if !cred.user_id.is_empty() {
        enc.str("id")
            .and_then(|e| e.bytes(cred.user_id))
            .map_err(|_| CtapError::Other)?;
    }
    if !cred.user_name.is_empty() {
        enc.str("name")
            .and_then(|e| e.str(cred.user_name))
            .map_err(|_| CtapError::Other)?;
    }
    if !cred.user_display_name.is_empty() {
        enc.str("displayName")
            .and_then(|e| e.str(cred.user_display_name))
            .map_err(|_| CtapError::Other)?;
    }

    // 0x07 credentialId, 0x08 publicKey.
    enc.u8(7)
        .and_then(|e| e.map(2))
        .and_then(|e| e.str("id")?.bytes(resident_id))
        .and_then(|e| e.str("type")?.str("public-key"))
        .map_err(|_| CtapError::Other)?;
    enc.u8(8).map_err(|_| CtapError::Other)?;
    match &key {
        Some(k) => k.cose_public(cred.alg, &mut enc),
        None => cose_public_from_point(
            cred.curve,
            cred.alg,
            cached_pubkey.unwrap_or_default(),
            &mut enc,
        ),
    }
    .map_err(|_| CtapError::Other)?;

    // 0x09 totalCredentials — Begin only.
    if begin {
        enc.u8(9)
            .and_then(|e| e.u16(total))
            .map_err(|_| CtapError::Other)?;
    }

    // 0x0A credProtect, 0x0B largeBlobKey, 0x0C thirdPartyPayment.
    enc.u8(0x0A)
        .and_then(|e| e.u64(cred_protect))
        .map_err(|_| CtapError::Other)?;
    if let Some(k) = large_blob_key {
        enc.u8(0x0B)
            .and_then(|e| e.bytes(&k))
            .map_err(|_| CtapError::Other)?;
    }
    enc.u8(0x0C)
        .and_then(|e| e.bool(cred.ext.third_party_payment))
        .map_err(|_| CtapError::Other)?;
    Ok(enc.writer().position())
}

/// Locate the resident credential carrying this 42-byte stored id: its EF_CRED slot
/// and the rp it belongs to. The rp hash is what §6.8.5/6.8.6 compare an rpId-scoped
/// pinUvAuthToken against, so the lookup precedes the authorization decision. An id
/// found nowhere fails if a record the flash would not serve could hold it.
fn find_resident<S: Storage>(
    fs: &mut Fs<S>,
    cred_id: &[u8],
) -> Result<Option<(u16, [u8; 32])>, CtapError> {
    if cred_id.len() != CRED_RESIDENT_LEN {
        return Ok(None);
    }
    let mut buf = [0u8; CRED_REC_MAX];
    let mut unread = false;
    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(fs, EF_CRED, &mut occupied);
    for (i, &live) in (0..MAX_RESIDENT_CREDENTIALS).zip(&occupied) {
        if !live {
            continue;
        }
        let n = match fs.try_read(EF_CRED + i, &mut buf) {
            Ok(Some(n)) => n.min(buf.len()),
            Ok(None) => continue,
            Err(_) => {
                unread = true;
                continue;
            }
        };
        if n >= RECORD_PREFIX && buf[32..RECORD_PREFIX] == *cred_id {
            let mut rp_id_hash = [0u8; 32];
            rp_id_hash.copy_from_slice(&buf[..32]);
            return Ok(Some((i, rp_id_hash)));
        }
    }
    if unread {
        return Err(CtapError::Other);
    }
    Ok(None)
}

/// 0x06 deleteCredential: drop the located EF_CRED record and decrement (or delete)
/// its EF_RP record. Replies with only the status byte.
fn delete_credential<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    slot: u16,
    rp_id_hash: &[u8; 32],
) -> CtapResult {
    crate::credential::bump_cred_store_state(ctx.fs).map_err(|_| CtapError::NotAllowed)?;
    ctx.fs
        .delete(EF_CRED + slot)
        .map_err(|_| CtapError::NotAllowed)?;
    // The credential's large blob goes with it. Best-effort and non-atomic: a
    // power cut between the two leaves an orphan that the AAD binding stops the
    // slot's next owner from opening, and `credential_store` clears anyway.
    largeblobext::discard(ctx.fs, slot);
    decrement_rp(ctx.fs, rp_id_hash)?;
    Ok(0)
}

/// Decrement the `EF_RP` count for `rp_id_hash`, deleting the record when it hits
/// zero. Shared by the CTAP `deleteCredential` (0x06) and the trusted-display
/// [`crate::passkeys::delete_cred`] so both keep the RP index consistent the same
/// way. Touches only the flash store, never the session state.
/// Refines `RSKeySecurityState!NoUnmanageableCredential` — SEC-FIDO-005.
pub(crate) fn decrement_rp<S: Storage>(
    fs: &mut Fs<S>,
    rp_id_hash: &[u8; 32],
) -> Result<(), CtapError> {
    let mut rp = [0u8; RP_REC_MAX];
    let mut unread = false;
    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(fs, EF_RP, &mut occupied);
    for (j, &live) in (0..MAX_RESIDENT_CREDENTIALS).zip(&occupied) {
        if !live {
            continue;
        }
        // Carried, as `bump_rp` carries its own: only an RP found nowhere else can be
        // the one the flash would not serve, and a delete must not answer over it.
        let m = match fs.try_read(EF_RP + j, &mut rp) {
            Ok(Some(m)) => m,
            Ok(None) => continue,
            Err(_) => {
                unread = true;
                continue;
            }
        };
        let m = m.min(rp.len());
        if m >= RP_PREFIX && rp[1..RP_PREFIX] == *rp_id_hash {
            rp[0] = rp[0].saturating_sub(1);
            if rp[0] == 0 {
                let _ = fs.delete(EF_RP + j);
                // The RP is gone — drop its device-local nickname too. Best-effort and
                // non-atomic with the line above: a power cut between them orphans a sealed
                // nickname, but it is never surfaced (its EF_RP slot is now empty) and the
                // rpIdHash-AAD binding rejects it if the slot is reused, so reset reclaims it.
                let _ = fs.delete(crate::consts::EF_RPNICK + j);
            } else {
                let record = rp.get(..m).ok_or(CtapError::NotAllowed)?;
                fs.put(EF_RP + j, record)
                    .map_err(|_| CtapError::NotAllowed)?;
            }
            return Ok(());
        }
    }
    if unread {
        return Err(CtapError::Other);
    }
    Ok(())
}

/// Settle every `EF_RP` record against the credentials that remain — a boot pass. A
/// delete torn after its `EF_CRED` record went and before `decrement_rp` ran leaves
/// a count one too high or, for an RP's last credential, a record naming none, which
/// `enumerateRPs` lists and whose `enumerateCredentialsBegin` answers NO_CREDENTIALS
/// until a reset. Credentials are matched on an 8-byte rpIdHash prefix, so a collision
/// can only count high, never delete a live RP's record; a credential the medium cannot
/// read settles nothing, and an RP record it cannot read is left as it is.
/// Refines `RSKeySecurityState!NoUnmanageableCredential` — SEC-FIDO-005.
pub fn settle_rp_records<S: Storage>(fs: &mut Fs<S>) -> rsk_sdk::error::Result<()> {
    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(fs, EF_CRED, &mut occupied);
    let mut prefixes = [None::<[u8; SETTLE_KEY_LEN]>; MAX_RESIDENT_CREDENTIALS as usize];
    for ((i, &live), prefix) in (0..MAX_RESIDENT_CREDENTIALS)
        .zip(&occupied)
        .zip(&mut prefixes)
    {
        let mut head = [0u8; SETTLE_KEY_LEN];
        if live && matches!(fs.try_read(EF_CRED + i, &mut head)?, Some(n) if n >= RECORD_PREFIX) {
            *prefix = Some(head);
        }
    }
    slot_map(fs, EF_RP, &mut occupied);
    let mut rp = [0u8; RP_REC_MAX];
    for (j, &live) in (0..MAX_RESIDENT_CREDENTIALS).zip(&occupied) {
        let Ok(Some(n)) = (if live {
            fs.try_read(EF_RP + j, &mut rp)
        } else {
            Ok(None)
        }) else {
            continue;
        };
        let Some(record) = rp
            .get_mut(..n.min(RP_REC_MAX))
            .filter(|r| r.len() >= RP_PREFIX)
        else {
            continue;
        };
        let named = prefixes
            .iter()
            .filter(|p| p.is_some_and(|p| record.get(1..=SETTLE_KEY_LEN) == Some(&p[..])))
            .count();
        match u8::try_from(named) {
            Ok(0) => {
                fs.delete(EF_RP + j)?;
                // As in `decrement_rp`: the nickname goes with its RP, best-effort.
                let _ = fs.delete(crate::consts::EF_RPNICK + j);
            }
            Ok(count) if record.first() != Some(&count) => {
                if let Some(c) = record.first_mut() {
                    *c = count;
                }
                fs.put(EF_RP + j, record)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// 0x07 updateUserInformation: reseal the credential with a new user name /
/// display name (same rp + user id). Replies with only the status byte.
///
/// The stored resident id (the platform's credentialId) and — for a v2
/// credential — the signing / hmac-secret / largeBlobKey keys all stay stable
/// across the reseal; see [`reseal_user`].
fn update_user<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    slot: u16,
    user_id: &[u8],
    user_name: &str,
    user_display_name: &str,
) -> CtapResult {
    let mut buf = [0u8; CRED_REC_MAX];
    let Some(n) = ctx
        .fs
        .try_read(EF_CRED + slot, &mut buf)
        .map_err(|_| CtapError::Other)?
    else {
        return Err(CtapError::NoCredentials);
    };
    let n = n.min(buf.len());
    let mut seed = ctx.load_keydev().ok_or(CtapError::NotAllowed)?;
    let record = buf.get(..n).ok_or(CtapError::NoCredentials)?;
    let r = reseal_user(
        ctx,
        slot,
        record,
        user_id,
        user_name,
        user_display_name,
        seed.expose(),
    );
    seed.wipe();
    r
}

/// Reseal a resident credential with new user name / display name, PRESERVING
/// its stored resident id. Per CTAP2.1 §6.8.5 the credentialId the platform holds
/// must stay stable across updateUserInformation; resealing draws a fresh IV
/// (nonce reuse is forbidden — see `credential::seal_rp_id`), so the box, and any
/// id re-derived from it, necessarily change. The stored 42-byte resident id is
/// the credential's stable identity, so we rewrite the same slot keeping that
/// prefix and only swapping the box. Without this, `deleteCredential` with the
/// platform's recorded id misses the (rotated) stored id → NO_CREDENTIALS
/// (conformance CredMgmt-UpdateAndDelete P-2).
///
/// The credential's signing key, hmac-secret and largeBlobKey stay stable too:
/// v2 credentials derive them from the preserved resident id
/// ([`crate::credential::resident_key_input`]), not the box, so the RP's stored pubkey
/// keeps verifying after an update. Legacy v1 credentials (created before that
/// marker) still key off the box and so DO rotate on an update — the id derived
/// from a v1 box is not re-issued, so this only affects passkeys made by older
/// firmware, not any created since.
#[allow(clippy::too_many_arguments)]
fn reseal_user<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    slot: u16,
    record: &[u8],
    user_id: &[u8],
    user_name: &str,
    user_display_name: &str,
    seed: &[u8; 32],
) -> CtapResult {
    let Some(prefix) = record.first_chunk::<RECORD_PREFIX>() else {
        return Err(CtapError::NotAllowed);
    };
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&prefix[..32]);
    let resident_id = &prefix[32..];
    let cred_box = cred_record_box(record);
    // The cached public point is stable across a reseal (v2/v3 keys off the
    // preserved resident id), so carry the trailer forward verbatim.
    let cached_pubkey = cred_record_pubkey(record).unwrap_or_default();

    let mut scratch = [0u8; CRED_REC_MAX];
    let cred =
        credential_load(seed, cred_box, &rp_id_hash, &mut scratch).ok_or(CtapError::NotAllowed)?;
    // The supplied user id must match the credential's exactly. CTAP 2.1
    // §6.8.3 keys updateUserInformation on the full userId; a min-length prefix
    // compare would let a prefix (or an empty id) match the wrong credential.
    if user_id != cred.user_id {
        return Err(CtapError::InvalidParameter);
    }

    let mut iv = [0u8; 12];
    ctx.rng.fill(&mut iv);
    let input = CredInput {
        rp_id: cred.rp_id,
        user_id: cred.user_id,
        // Same CTAP 2.1 §6.1.2 truncation as makeCredential. Both names cap at
        // USER_NAME_MAX and the reused rpId/user_id/credBlob were themselves
        // capped at create, so the resealed box stays within CRED_BOX_MAX.
        user_name: truncate_utf8(user_name, USER_NAME_MAX),
        user_display_name: truncate_utf8(user_display_name, USER_NAME_MAX),
        use_sign_count: cred.use_sign_count,
        rk: cred.rk,
        created_ms: ctx.now_ms,
        alg: cred.alg,
        curve: cred.curve,
        ext: cred.ext,
    };
    let mut new_box = [0u8; CRED_BOX_MAX];
    let len = credential_create(seed, &ctx.dev, &input, &rp_id_hash, &iv, &mut new_box)
        .map_err(|_| CtapError::NotAllowed)?;
    let new_box = new_box.get(..len).ok_or(CtapError::NotAllowed)?;

    // Rewrite the slot: rp_id_hash ‖ (preserved) resident_id ‖ [pubkey] ‖ new box.
    let mut rec = [0u8; CRED_REC_MAX];
    let total = compose_cred_record(&rp_id_hash, resident_id, cached_pubkey, new_box, &mut rec)
        .ok_or(CtapError::KeyStoreFull)?;
    crate::credential::bump_cred_store_state(ctx.fs).map_err(|_| CtapError::NotAllowed)?;
    let rec = rec.get(..total).ok_or(CtapError::KeyStoreFull)?;
    ctx.fs
        .put(EF_CRED + slot, rec)
        .map_err(|_| CtapError::NotAllowed)?;
    Ok(0)
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
#[path = "credmgmt_tests.rs"]
mod tests;

#[cfg(kani)]
#[path = "credmgmt_kani.rs"]
mod proofs;
