// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! authenticatorVendor (0x41) — wallet-style seed backup over an MSE channel.
//!
//! Lets the host read the device's 32-byte master seed once, at setup, to render
//! it as a BIP-39 / SLIP-39 mnemonic, and write a seed back when restoring onto a
//! fresh device. Six subcommands under CTAP command `0x41`:
//!
//! - `MSE` (0x01) — P-256 ECDH key agreement → a ChaCha20-Poly1305 channel.
//! - `BACKUP_EXPORT` (0x02) — hand the seed to the host over that channel (gated).
//! - `BACKUP_LOAD` (0x03) — install a seed from the host, re-sealed to this chip.
//! - `BACKUP_FINALIZE` (0x04) — seal the one-time export window.
//! - `BACKUP_STATE` (0x05) — read `{sealed, has_seed, locked, unlocked}`.
//! - `UNLOCK` (0x06) — soft-lock: decrypt `EF_KEY_DEV_ENC` into RAM for this
//!   power cycle. The lock is engaged and released by `authenticatorConfig`
//!   vendor ids AUT_ENABLE / AUT_DISABLE ([`crate::config`]).
//!
//! Exporting the seed is the one place a FIDO authenticator hands out a
//! normally non-exportable key, so it is the most-gated command here: a
//! one-time setup window (reopened only by an authenticatorReset) AND physical
//! touch AND, when a PIN is set, a pinUvAuthToken. Every message uses a fresh
//! random nonce, so an export and a load sharing one channel cannot reuse one.
//! The soft lock also wraps the seed *value*, so backup and lock stay orthogonal.

use minicbor::encode::write::Cursor;
use minicbor::{Decoder, Encoder};
use zeroize::Zeroize;

use rsk_crypto::chachapoly::{chacha20poly1305_decrypt, chacha20poly1305_encrypt};
use rsk_crypto::mac::hkdf_sha256;
use rsk_crypto::mlkem::{MLKEM768_CT_LEN, MLKEM768_EK_LEN, mlkem768_encapsulate};
use rsk_crypto::pinproto::{PinProto, ecdh_raw};
use rsk_crypto::sha256;
use rsk_fs::Storage;
use rsk_led::{CONF_LEN as LED_CONF_LEN, EF_LED_CONF};
use rsk_mgmt::{DevConfError, persist_dev_conf};
use rsk_rescue::phy;

use crate::cbordec::{cbor, def_map};
use crate::cert;
use crate::consts::{
    CONFIG_TARGET_DEV_CONF, CONFIG_TARGET_LED, CONFIG_TARGET_PHY, CTAP_VENDOR, EF_ATT_CHAIN,
    EF_ATT_KEY, EF_BACKUP_SEALED, EF_EE_DEV, EF_KEY_DEV, EF_KEY_DEV_ENC, EF_PIN, VENDOR_ATT_CLEAR,
    VENDOR_ATT_IMPORT, VENDOR_ATT_STATE, VENDOR_AUDIT_CHECKPOINT, VENDOR_AUDIT_READ,
    VENDOR_BACKUP_EXPORT, VENDOR_BACKUP_FINALIZE, VENDOR_BACKUP_LOAD, VENDOR_BACKUP_STATE,
    VENDOR_CONFIG_READ, VENDOR_CONFIG_WRITE, VENDOR_MSE, VENDOR_UNLOCK,
};
use crate::cose::cose_key_ecdh;
use crate::ec::P256Key;
use crate::error::{CtapError, CtapResult};
use crate::journal;
use crate::seed::{
    LOCK_BLOB_LEN, encrypt_keydev_f1, ensure_seed, lock_engaged, open_seed_locked, store_att_key,
};
use crate::state::{PERM_ACFG, puat_subcommand_msg};
use crate::{Ctx, Rng};

use core::sync::atomic::{AtomicBool, Ordering};

/// Set when a FIDO `CONFIG_WRITE` persists the PHY record; the firmware handler
/// consumes it to warm-reboot (re-enumerate) so the new USB identity applies
/// without a manual replug, unless `OPT_DISABLE_POWER_RESET` is set. Cross-layer
/// because the reboot verb lives in the firmware, not this applet.
static PHY_WRITTEN: AtomicBool = AtomicBool::new(false);

/// Take and clear the "a PHY config-write just happened" flag (the firmware
/// handler reads it after the `0x41` response flushes).
pub fn take_phy_written() -> bool {
    PHY_WRITTEN.swap(false, Ordering::Relaxed)
}

// Sized for ATT_IMPORT's wrapped key + a full cert chain (≤ 2048 B); every
// other subcommand stays tiny. The pinUvAuth MAC covers these bytes verbatim.
const MAX_RAW_SUBPARA: usize = 2200;

#[derive(Default)]
struct Req<'a> {
    subcommand: u64,
    kax: &'a [u8],
    kay: &'a [u8],
    /// MSE subCommandParams key 2 (optional): the host's ML-KEM-768 encapsulation
    /// key (1184 B). When present, the MSE channel is hybrid P-256 + ML-KEM-768.
    mlkem_ek: &'a [u8],
    blob: &'a [u8],
    /// ATT_IMPORT subCommandParams key 2: the DER cert chain, leaf first.
    chain: &'a [u8],
    /// CONFIG_WRITE subCommandParams key 1: which device-config record to write.
    target: u64,
    raw_subpara: &'a [u8],
    proto: u64,
    pin_uv_auth_param: Option<&'a [u8]>,
}

/// `{1: subcommand, 2: subCommandParams, 3: pinUvAuthProtocol, 4: pinUvAuthParam}`.
/// `subCommandParams` carries either the host COSE key (MSE) or the 60-byte blob
/// (LOAD); its raw bytes are captured for the pinUvAuth MAC.
fn parse(data: &[u8]) -> Result<Req<'_>, CtapError> {
    let mut d = Decoder::new(data);
    let mut req = Req::default();
    let n = def_map(&mut d)?;
    for _ in 0..n {
        let key = cbor(d.u32())? as u64;
        match key {
            1 => req.subcommand = cbor(d.u32())? as u64,
            2 => {
                let start = d.position();
                let m = def_map(&mut d)?;
                for _ in 0..m {
                    let sk = cbor(d.i32())?;
                    if sk == 1 && req.subcommand == VENDOR_MSE {
                        // COSE_Key{1:2, 3:-25, -1:1, -2:x, -3:y}
                        let c = def_map(&mut d)?;
                        for _ in 0..c {
                            match cbor(d.i32())? {
                                -2 => req.kax = cbor(d.bytes())?,
                                -3 => req.kay = cbor(d.bytes())?,
                                _ => cbor(d.skip())?,
                            }
                        }
                    } else if sk == 1
                        && matches!(
                            req.subcommand,
                            VENDOR_BACKUP_LOAD
                                | VENDOR_UNLOCK
                                | VENDOR_AUDIT_CHECKPOINT
                                | VENDOR_ATT_IMPORT
                        )
                    {
                        req.blob = cbor(d.bytes())?;
                    } else if sk == 2 && req.subcommand == VENDOR_ATT_IMPORT {
                        req.chain = cbor(d.bytes())?;
                    } else if sk == 2 && req.subcommand == VENDOR_MSE {
                        req.mlkem_ek = cbor(d.bytes())?;
                    } else if sk == 1
                        && matches!(req.subcommand, VENDOR_CONFIG_WRITE | VENDOR_CONFIG_READ)
                    {
                        req.target = cbor(d.u32())? as u64;
                    } else if sk == 2 && req.subcommand == VENDOR_CONFIG_WRITE {
                        req.blob = cbor(d.bytes())?;
                    } else {
                        cbor(d.skip())?;
                    }
                }
                req.raw_subpara = &data[start..d.position()];
            }
            3 => req.proto = cbor(d.u32())? as u64,
            4 => req.pin_uv_auth_param = Some(cbor(d.bytes())?),
            _ => cbor(d.skip())?,
        }
    }
    Ok(req)
}

/// Right-align a COSE coordinate into 32 bytes.
fn coord(src: &[u8]) -> Result<[u8; 32], CtapError> {
    if src.len() > 32 {
        return Err(CtapError::InvalidParameter);
    }
    let mut out = [0u8; 32];
    out[32 - src.len()..].copy_from_slice(src);
    Ok(out)
}

fn encode<F>(out: &mut [u8], f: F) -> Result<usize, CtapError>
where
    F: FnOnce(
        &mut Encoder<Cursor<&mut [u8]>>,
    ) -> Result<(), minicbor::encode::Error<minicbor::encode::write::EndOfSlice>>,
{
    let mut enc = Encoder::new(Cursor::new(out));
    f(&mut enc).map_err(|_| CtapError::Other)?;
    Ok(enc.writer().position())
}

pub fn vendor<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, data: &[u8], out: &mut [u8]) -> CtapResult {
    let req = parse(data)?;
    match req.subcommand {
        VENDOR_MSE => mse(ctx, &req, out),
        VENDOR_BACKUP_EXPORT => backup_export(ctx, &req, out),
        VENDOR_BACKUP_LOAD => backup_load(ctx, &req),
        VENDOR_BACKUP_FINALIZE => backup_finalize(ctx),
        VENDOR_BACKUP_STATE => backup_state(ctx, out),
        VENDOR_UNLOCK => unlock(ctx, &req),
        VENDOR_AUDIT_READ => audit_read(ctx, &req, out),
        VENDOR_AUDIT_CHECKPOINT => audit_checkpoint(ctx, &req, out),
        VENDOR_ATT_IMPORT => att_import(ctx, &req),
        VENDOR_ATT_CLEAR => att_clear(ctx, &req),
        VENDOR_ATT_STATE => att_state(ctx, out),
        VENDOR_CONFIG_WRITE => config_write(ctx, &req),
        VENDOR_CONFIG_READ => config_read(ctx, &req, out),
        _ => Err(CtapError::InvalidParameter),
    }
}

/// `CONFIG_READ`: return a device-config record so a host can read-modify-write it
/// over FIDO (the phy record has no CCID-free read otherwise). Ungated — the
/// config is not secret, like READ CONFIG (`0x42`) and the `*_STATE` subcommands.
/// Only the phy record: `EF_DEV_CONF` already round-trips via READ CONFIG.
fn config_read<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, req: &Req, out: &mut [u8]) -> CtapResult {
    match req.target {
        CONFIG_TARGET_PHY => {
            let mut buf = [0u8; phy::PHY_MAX_SIZE];
            let n = ctx
                .fs
                .read(phy::EF_PHY, &mut buf)
                .unwrap_or(0)
                .min(buf.len());
            encode(out, |e| {
                e.map(1)?.u8(1)?.bytes(&buf[..n])?;
                Ok(())
            })
        }
        CONFIG_TARGET_LED => {
            let mut buf = [0u8; LED_CONF_LEN];
            let n = ctx
                .fs
                .read(EF_LED_CONF, &mut buf)
                .unwrap_or(0)
                .min(buf.len());
            encode(out, |e| {
                e.map(1)?.u8(1)?.bytes(&buf[..n])?;
                Ok(())
            })
        }
        _ => Err(CtapError::InvalidParameter),
    }
}

/// `CONFIG_WRITE`: persist a device-configuration record over FIDO — the
/// pcscd-free twin of the CCID device-config writes, for hosts that can't reach
/// the CCID interface. Gated by a pinUvAuthToken (PERM_ACFG, when a PIN is set)
/// AND a physical touch: a *stronger* gate than the CCID path's presence-only,
/// because CTAPHID is reachable by any unprivileged host process. No MSE channel
/// — the config blobs are not secret, only their authorship must be proven.
fn config_write<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, req: &Req) -> CtapResult {
    pin_gate(ctx, req)?;
    if !ctx.check_user_presence(crate::Confirm::titled("Write device config?")) {
        return Err(CtapError::OperationDenied);
    }
    match req.target {
        CONFIG_TARGET_DEV_CONF => persist_dev_conf(ctx.fs, req.blob).map_err(|e| match e {
            DevConfError::TooLong => CtapError::InvalidLength,
            DevConfError::Store => CtapError::Other,
        })?,
        // The phy record (VID/PID, USB interfaces, LED, presence-timeout) — a
        // read-modify-write merge (the same `merge_save` the CCID rescue WRITE 0x1C
        // uses), so a host that sends only the fields it changed cannot wipe the
        // rest. Takes effect on the next boot (main reads EF_PHY), like the CCID path.
        CONFIG_TARGET_PHY => {
            phy::merge_save(ctx.fs, req.blob).map_err(|_| CtapError::Other)?;
            PHY_WRITTEN.store(true, Ordering::Relaxed);
        }
        // The LED config block; persisted here and applied *live* by the firmware
        // CTAPHID handler, which reloads EF_LED_CONF after a 0x41 command (the LED
        // atomics are firmware-side). The CCID SET_LED writes the same record.
        CONFIG_TARGET_LED => {
            if req.blob.len() < LED_CONF_LEN {
                return Err(CtapError::InvalidLength);
            }
            ctx.fs
                .put(EF_LED_CONF, &req.blob[..LED_CONF_LEN])
                .map_err(|_| CtapError::Other)?;
        }
        _ => return Err(CtapError::InvalidParameter),
    }
    journal::append(ctx, journal::EV_CONFIG_WRITE, req.target as u8, &[]);
    Ok(0)
}

/// `ATT_IMPORT`: install an org attestation key + DER chain (leaf first). The
/// P-256 scalar arrives ChaCha-wrapped on the MSE channel (the same 60-byte
/// blob as the lock key); the chain is public certificate material and travels
/// in the clear, MAC-covered like every subCommandParams. Gated like a seed
/// move (MSE + PIN + touch). Survives authenticatorReset — it is
/// org-provisioned *device* identity; ATT_CLEAR removes it.
fn att_import<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, req: &Req) -> CtapResult {
    let mut packed = [0u8; cert::ATT_CHAIN_REC_MAX];
    let plen = cert::att_chain_pack(req.chain, &mut packed).ok_or(CtapError::InvalidParameter)?;
    gate(ctx, req, "Import attestation key?")?;
    let mut scalar = open_channel_key(ctx, req.blob)?;
    if P256Key::from_scalar(&scalar).is_none() {
        scalar.zeroize();
        return Err(CtapError::InvalidParameter);
    }
    let r = store_att_key(&ctx.dev, ctx.fs, &scalar);
    scalar.zeroize();
    r.map_err(|_| CtapError::Other)?;
    ctx.fs
        .put(EF_ATT_CHAIN, &packed[..plen])
        .map_err(|_| CtapError::Other)?;
    journal::append(ctx, journal::EV_ATT_IMPORT, 0, &[]);
    Ok(0)
}

/// `ATT_CLEAR`: drop the org attestation (same gate as the import).
fn att_clear<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, req: &Req) -> CtapResult {
    gate(ctx, req, "Clear attestation key?")?;
    let _ = ctx.fs.delete_key(EF_ATT_KEY);
    let _ = ctx.fs.delete(EF_ATT_CHAIN);
    journal::append(ctx, journal::EV_ATT_CLEAR, 0, &[]);
    Ok(0)
}

/// `ATT_STATE`: `{1: present, 2: sha256(packed chain)}` — ungated, like
/// BACKUP_STATE; the chain itself is public.
fn att_state<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, out: &mut [u8]) -> CtapResult {
    let mut chain = [0u8; cert::ATT_CHAIN_REC_MAX];
    let present = ctx.fs.has_key(EF_ATT_KEY);
    let n = ctx.fs.read(EF_ATT_CHAIN, &mut chain).unwrap_or(0);
    encode(out, |e| {
        e.map(if present && n > 0 { 2 } else { 1 })?
            .u8(1)?
            .bool(present)?;
        if present && n > 0 {
            e.u8(2)?.bytes(&sha256(&chain[..n]))?;
        }
        Ok(())
    })
}

/// `AUDIT_READ`: export the journal window (`journal::vendor_read`). Gated on a
/// PIN token when a PIN is set; a touch otherwise — with no PIN `pin_gate` is a
/// no-op, and the per-entry detail is a reversible 64-bit rpId-hash prefix (not
/// truly pseudonymous), so an ungated read lets a silent host harvest the
/// RP-usage history. No MSE channel: no key material moves.
fn audit_read<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, req: &Req, out: &mut [u8]) -> CtapResult {
    pin_gate(ctx, req)?;
    if !ctx.fs.has_data(EF_PIN)
        && !ctx.check_user_presence(crate::Confirm::titled("Read audit log?"))
    {
        return Err(CtapError::OperationDenied);
    }
    journal::vendor_read(ctx, out)
}

/// `AUDIT_CHECKPOINT`: sign the chain head (`journal::vendor_checkpoint`).
/// PIN token plus a physical touch; the subCommandParams blob is the host's
/// freshness challenge (≤ 32 bytes).
fn audit_checkpoint<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    req: &Req,
    out: &mut [u8],
) -> CtapResult {
    pin_gate(ctx, req)?;
    if !ctx.check_user_presence(crate::Confirm::titled("Sign audit log?")) {
        return Err(CtapError::OperationDenied);
    }
    journal::vendor_checkpoint(ctx, req.blob, out)
}

/// Decrypt the channel-wrapped 32-byte lock key carried in `blob`
/// (nonce ‖ ct ‖ tag, AAD = the device MSE public key). Shared with the
/// `authenticatorConfig` AUT_ENABLE arm.
pub(crate) fn open_channel_key<S: Storage, R: Rng>(
    ctx: &Ctx<S, R>,
    blob: &[u8],
) -> Result<[u8; 32], CtapError> {
    if blob.len() != LOCK_BLOB_LEN {
        return Err(CtapError::InvalidParameter);
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[..12]);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&blob[44..]);
    let mut key = [0u8; 32];
    key.copy_from_slice(&blob[12..44]);
    match chacha20poly1305_decrypt(
        &ctx.state.mse_key,
        &nonce,
        &ctx.state.mse_pub,
        &mut key,
        &tag,
    ) {
        Ok(()) => Ok(key),
        Err(_) => {
            key.zeroize();
            Err(CtapError::InvalidParameter)
        }
    }
}

/// `UNLOCK`: the host sends the 32-byte lock key over the MSE channel; the
/// wrapped seed on flash decrypts into RAM ([`crate::FidoState::keydev_dec`])
/// and FIDO operations work until power-off. No PIN or touch gate — knowing
/// the 256-bit lock key *is* the authorization, and this runs on every
/// power-up of a locked device.
fn unlock<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, req: &Req) -> CtapResult {
    if !ctx.state.mse_active {
        return Err(CtapError::NotAllowed);
    }
    let mut lock_key = open_channel_key(ctx, req.blob)?;
    if !lock_engaged(ctx.fs) {
        lock_key.zeroize();
        return Err(CtapError::IntegrityFailure);
    }
    let mut blob = [0u8; LOCK_BLOB_LEN];
    let n = ctx.fs.read_key(EF_KEY_DEV_ENC, &mut blob);
    let seed = n.and_then(|n| open_seed_locked(&lock_key, &blob[..n.min(blob.len())]));
    lock_key.zeroize();
    match seed {
        Some(seed) => {
            ctx.state.clear_keydev_dec();
            ctx.state.keydev_dec = Some(seed);
            Ok(0)
        }
        None => Err(CtapError::InvalidParameter),
    }
}

/// Domain-separation salt for the hybrid channel key — keeps the post-quantum
/// derivation disjoint from the classical one (which uses an empty salt). The
/// `v1` pins the construction `HKDF-SHA256(salt, z ‖ ss_mlkem, dev_pub ‖ ct)`.
const MSE_PQ_SALT: &[u8] = b"RSK-MSE-PQ-v1";

/// `MSE` key agreement: a fresh device ephemeral keypair, ECDH with the host key,
/// then `HKDF-SHA256(ikm = shared x, info = device pubkey)` → the 32-byte channel
/// key. Returns the device public key as a COSE ECDH key.
///
/// When the host also supplies an ML-KEM-768 encapsulation key (subCommandParams
/// key 2), the channel is **hybrid**: the device encapsulates to it and folds the
/// ML-KEM shared secret into the derivation alongside the ECDH secret
/// ([`mlkem_leg`]), returning the ciphertext as response key 2. This is the
/// harvest-now-decrypt-later defense for the seed-backup channel — recording the
/// exchange today no longer hands a future quantum adversary the channel key,
/// since recovering it needs *both* P-256 and ML-KEM-768 broken. A host that
/// sends no key 2 gets the classical channel, byte-for-byte unchanged.
fn mse<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, req: &Req, out: &mut [u8]) -> CtapResult {
    if req.kax.is_empty() || req.kay.is_empty() {
        return Err(CtapError::MissingParameter);
    }
    let kax = coord(req.kax)?;
    let kay = coord(req.kay)?;

    let mut scalar = [0u8; 32];
    let (dx, dy) = loop {
        ctx.rng.fill(&mut scalar);
        if let Some(k) = P256Key::from_scalar(&scalar) {
            break k.public_xy();
        }
    };
    let mut z = match ecdh_raw(&scalar, &kax, &kay) {
        Ok(z) => z,
        Err(_) => {
            scalar.zeroize();
            return Err(CtapError::InvalidParameter);
        }
    };
    scalar.zeroize();

    let mut dev_pub = [0u8; 65];
    dev_pub[0] = 0x04;
    dev_pub[1..33].copy_from_slice(&dx);
    dev_pub[33..].copy_from_slice(&dy);

    let hybrid = !req.mlkem_ek.is_empty();
    let mut ct = [0u8; MLKEM768_CT_LEN];
    let mut key = [0u8; 32];
    let derived = if hybrid {
        mlkem_leg(ctx.rng, req.mlkem_ek, &z, &dev_pub, &mut ct, &mut key)
    } else {
        hkdf_sha256(&[], &z, &dev_pub, &mut key).map_err(|_| CtapError::Other)
    };
    z.zeroize();
    if let Err(e) = derived {
        key.zeroize();
        return Err(e);
    }
    ctx.state.mse_key = key;
    ctx.state.mse_pub = dev_pub;
    ctx.state.mse_active = true;
    key.zeroize();

    encode(out, |e| {
        e.map(if hybrid { 2 } else { 1 })?.u8(1)?;
        cose_key_ecdh(e, &dx, &dy)?;
        if hybrid {
            e.u8(2)?.bytes(&ct)?;
        }
        Ok(())
    })
}

/// The ML-KEM-768 leg of the hybrid handshake: encapsulate to the host's `ek`,
/// hand back the ciphertext for the response, and derive the channel key as
/// `HKDF-SHA256(MSE_PQ_SALT, z ‖ ss_mlkem, dev_pub ‖ ct)`. Both shared secrets go
/// into the IKM (a break of either primitive leaves the key safe); the ML-KEM
/// ciphertext is bound through `info` so the key commits to the exact
/// encapsulation. A malformed `ek` — wrong length or non-reduced coefficients —
/// is rejected before any channel is established. Only `encapsulate` runs on the
/// device (the cheap ML-KEM direction); keygen and decapsulate stay on the host.
fn mlkem_leg<R: Rng>(
    rng: &mut R,
    ek: &[u8],
    z: &[u8; 32],
    dev_pub: &[u8; 65],
    ct: &mut [u8; MLKEM768_CT_LEN],
    key: &mut [u8; 32],
) -> Result<(), CtapError> {
    let ek = <&[u8; MLKEM768_EK_LEN]>::try_from(ek).map_err(|_| CtapError::InvalidParameter)?;
    let mut m = [0u8; 32];
    rng.fill(&mut m);
    let (c, mut ss) = mlkem768_encapsulate(ek, &m).map_err(|_| CtapError::InvalidParameter)?;
    m.zeroize();
    ct.copy_from_slice(&c);

    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(z);
    ikm[32..].copy_from_slice(&ss);
    ss.zeroize();

    let mut info = [0u8; 65 + MLKEM768_CT_LEN];
    info[..65].copy_from_slice(dev_pub);
    info[65..].copy_from_slice(ct);

    let r = hkdf_sha256(MSE_PQ_SALT, &ikm, &info, key);
    ikm.zeroize();
    r.map_err(|_| CtapError::Other)
}

/// Common gate for the seed-moving commands: an established MSE channel, physical
/// presence (touch), and — when a PIN is configured — a pinUvAuthToken with the
/// `acfg` permission over `0xff×32 ‖ 0x41 ‖ subcommand ‖ rawSubCommandParams`.
///
/// `title` is the trusted-display consent line: each caller names the *specific*
/// operation (e.g. exporting the master seed) so the on-screen prompt matches the
/// stakes — a generic "Vendor config?" for a seed export would let a host phish an
/// approval for the most catastrophic op behind a benign-looking touch.
fn gate<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    req: &Req,
    title: &'static str,
) -> Result<(), CtapError> {
    if !ctx.state.mse_active {
        return Err(CtapError::NotAllowed);
    }
    pin_gate(ctx, req)?;
    if !ctx.check_user_presence(crate::Confirm::titled(title)) {
        return Err(CtapError::OperationDenied);
    }
    Ok(())
}

/// The PIN half of [`gate`], shared with the audit subcommands: when a PIN is
/// configured, require a pinUvAuthToken with the `acfg` permission over
/// `0xff×32 ‖ 0x41 ‖ subcommand ‖ rawSubCommandParams`.
fn pin_gate<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, req: &Req) -> Result<(), CtapError> {
    if ctx.fs.has_data(EF_PIN) {
        let param = req.pin_uv_auth_param.ok_or(CtapError::PuatRequired)?;
        let proto = PinProto::from_u64(req.proto).ok_or(CtapError::MissingParameter)?;
        if req.raw_subpara.len() > MAX_RAW_SUBPARA {
            return Err(CtapError::RequestTooLarge);
        }
        let mut vp = [0u8; 32 + 2 + MAX_RAW_SUBPARA];
        let vp_len =
            puat_subcommand_msg(&mut vp, CTAP_VENDOR, req.subcommand as u8, req.raw_subpara);
        if !ctx.state.verify_token(proto, &vp[..vp_len], param)
            || ctx.state.paut.permissions & PERM_ACFG == 0
        {
            return Err(CtapError::PinAuthInvalid);
        }
        ctx.state.mark_token_used(ctx.now_ms);
    }
    Ok(())
}

/// `BACKUP_EXPORT`: encrypt the 32-byte seed under the MSE channel and return it.
/// Refused once the export window is sealed by `BACKUP_FINALIZE` (a reset reopens
/// it). Export itself does not seal the window; each call re-encrypts under a
/// fresh nonce, so a repeat export before finalize is safe (no keystream reuse).
fn backup_export<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, req: &Req, out: &mut [u8]) -> CtapResult {
    // The FIPS-style profile seals the seed in entirely (non-exportable key
    // material; the MSE channel is ChaCha20-Poly1305 — not approved transport).
    // LOAD stays available: keys may migrate *into* a profile build, never out.
    if cfg!(feature = "fips-profile") {
        return Err(CtapError::NotAllowed);
    }
    if ctx.fs.has_data(EF_BACKUP_SEALED) {
        return Err(CtapError::NotAllowed);
    }
    // Name the operation explicitly: this hands the master seed to the host. A generic
    // prompt here would let a host phish the approval for a full identity export.
    gate(ctx, req, "Export secret seed to host?")?;
    let mut seed = ctx.load_keydev().ok_or(CtapError::NotAllowed)?;
    let mut nonce = [0u8; 12];
    ctx.rng.fill(&mut nonce);
    let mut ct = [0u8; 32];
    ct.copy_from_slice(&seed);
    seed.zeroize();
    let tag = chacha20poly1305_encrypt(&ctx.state.mse_key, &nonce, &ctx.state.mse_pub, &mut ct);
    let mut blob = [0u8; LOCK_BLOB_LEN]; // nonce ‖ ciphertext(seed) ‖ tag
    blob[..12].copy_from_slice(&nonce);
    blob[12..44].copy_from_slice(&ct);
    blob[44..].copy_from_slice(&tag);
    ct.zeroize();
    let r = encode(out, |e| {
        e.map(1)?.u8(1)?.bytes(&blob)?;
        Ok(())
    });
    blob.zeroize();
    if r.is_ok() {
        journal::append(ctx, journal::EV_BACKUP_EXPORT, 0, &[]);
    }
    r
}

/// `BACKUP_LOAD`: decrypt a seed from the host and install it, re-sealed under
/// this chip's kbase. The attestation cert (signed by the old seed scalar) is
/// rebuilt over the new seed. Refused while soft-locked — a restore next to a
/// live wrapped blob would leave two competing seeds; disable the lock (or
/// reset) first.
fn backup_load<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, req: &Req) -> CtapResult {
    if req.blob.len() != LOCK_BLOB_LEN {
        return Err(CtapError::MissingParameter);
    }
    if lock_engaged(ctx.fs) {
        return Err(CtapError::NotAllowed);
    }
    gate(ctx, req, "Restore seed from host?")?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&req.blob[..12]);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&req.blob[44..]);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&req.blob[12..44]);
    let r = chacha20poly1305_decrypt(
        &ctx.state.mse_key,
        &nonce,
        &ctx.state.mse_pub,
        &mut seed,
        &tag,
    );
    if r.is_err() {
        seed.zeroize();
        return Err(CtapError::IntegrityFailure);
    }
    if P256Key::from_scalar(&seed).is_none() {
        seed.zeroize();
        return Err(CtapError::InvalidParameter);
    }
    let res = encrypt_keydev_f1(&ctx.dev, ctx.fs, &seed);
    seed.zeroize();
    res.map_err(|_| CtapError::Other)?;
    let _ = ctx.fs.delete(EF_EE_DEV);
    ensure_seed(&ctx.dev, ctx.fs, ctx.rng).map_err(|_| CtapError::Other)?;
    journal::append(ctx, journal::EV_BACKUP_LOAD, 0, &[]);
    Ok(0)
}

/// `BACKUP_FINALIZE`: seal the one-time export window (a reset reopens it).
fn backup_finalize<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>) -> CtapResult {
    if !ctx.check_user_presence(crate::Confirm::titled("Finish backup?")) {
        return Err(CtapError::OperationDenied);
    }
    ctx.fs
        .put(EF_BACKUP_SEALED, &[1])
        .map_err(|_| CtapError::Other)?;
    journal::append(ctx, journal::EV_BACKUP_FINALIZE, 0, &[]);
    Ok(0)
}

/// `BACKUP_STATE`: `{1: sealed, 2: has_seed, 3: locked, 4: unlocked}` — ungated,
/// for host-side status. `locked` is the flash state (the wrapped blob is what's
/// stored); `unlocked` says a RAM copy from a vendor UNLOCK is live this power
/// cycle.
fn backup_state<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, out: &mut [u8]) -> CtapResult {
    let sealed = ctx.fs.has_data(EF_BACKUP_SEALED);
    let has_seed = ctx.fs.has_key(EF_KEY_DEV);
    let locked = lock_engaged(ctx.fs);
    let unlocked = ctx.state.keydev_dec.is_some();
    encode(out, |e| {
        e.map(4)?
            .u8(1)?
            .bool(sealed)?
            .u8(2)?
            .bool(has_seed)?
            .u8(3)?
            .bool(locked)?
            .u8(4)?
            .bool(unlocked)?;
        Ok(())
    })
}

/// The seed-backup status for the trusted-display Backup screen — the same
/// `sealed` / `has_seed` bits [`backup_state`] reports to the host, plus whether
/// this build can export at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BackupStatus {
    /// The one-time export window is sealed: the seed has been backed up (or a
    /// `BACKUP_FINALIZE` closed the window). A factory reset / authenticatorReset
    /// reopens it.
    pub sealed: bool,
    /// A device master seed (`EF_KEY_DEV`) is present.
    pub has_seed: bool,
    /// The MSE export channel exists on this build — `false` under `fips-profile`,
    /// where the seed is non-exportable and recovery is restore-only.
    pub exportable: bool,
    /// The seed is soft-locked (the stored copy is wrapped) — it can't be read for an
    /// on-device recovery-phrase reveal until a host vendor `UNLOCK` this power cycle.
    pub locked: bool,
}

/// Read the seed-backup status from the store for the on-device Backup screen
/// (Settings → Security → Backup). A lean, `Ctx`-free mirror of [`backup_state`]'s
/// flags — no CBOR — so the display task can read it directly while the worker is parked.
pub fn backup_status<S: Storage>(fs: &mut rsk_fs::Fs<S>) -> BackupStatus {
    BackupStatus {
        sealed: fs.has_data(EF_BACKUP_SEALED),
        has_seed: fs.has_key(EF_KEY_DEV),
        exportable: !cfg!(feature = "fips-profile"),
        locked: lock_engaged(fs),
    }
}

/// Seal the one-time backup window on-device (Settings → Security → Backup → Seal),
/// mirroring host [`BACKUP_FINALIZE`](backup_finalize) without the `Ctx` / journal:
/// write the `EF_BACKUP_SEALED` marker so the seed can no longer be exported **or**
/// shown as a recovery phrase until a factory reset reopens the window. The display
/// task gates this behind the device PIN and a deliberate hold.
pub fn mark_backup_sealed<S: Storage>(fs: &mut rsk_fs::Fs<S>) -> bool {
    fs.put(EF_BACKUP_SEALED, &[1]).is_ok()
}

/// Whether the seed-backup export window is sealed — the cheap `has_data` probe the
/// Security list row uses for its "Sealed / Review" status, without the `has_seed`
/// key lookup [`backup_status`] also does.
pub fn backup_sealed<S: Storage>(fs: &mut rsk_fs::Fs<S>) -> bool {
    fs.has_data(EF_BACKUP_SEALED)
}

#[cfg(test)]
#[path = "vendor_tests.rs"]
mod tests;
