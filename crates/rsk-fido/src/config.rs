// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `authenticatorConfig`: enableEnterpriseAttestation (0x01), toggleAlwaysUv
//! (0x02), setMinPINLength (0x03) and the vendor arm (0xFF) — the soft-lock pair
//! AUT_ENABLE / AUT_DISABLE and the PicoForge physical-config ids (VID/PID, LED
//! gpio/brightness, options → the phy record, so PicoForge configures hardware
//! over FIDO with no PC/SC). All gated on a `pinUvAuthParam` with the `acfg`
//! permission; the soft-lock pair additionally requires a physical touch.

use minicbor::Decoder;
use rsk_fs::{Fs, Sealed, Storage};
use zeroize::Zeroize;

use rsk_crypto::sha256;
use rsk_rescue::phy;

use crate::cbordec::{cbor, def_arr, def_map, skip_value};
use crate::consts::{
    CONFIG_AUT_DISABLE, CONFIG_AUT_ENABLE, CONFIG_ENABLE_EA, CONFIG_PHY_LED_BRIGHTNESS,
    CONFIG_PHY_LED_GPIO, CONFIG_PHY_OPTIONS, CONFIG_PHY_VIDPID, CONFIG_SET_MIN_PIN,
    CONFIG_TARGET_PHY, CONFIG_TOGGLE_ALWAYS_UV, CONFIG_VENDOR, CTAP_CONFIG, EF_ALWAYS_UV,
    EF_EA_ENABLED, EF_KEY_DEV, EF_KEY_DEV_ENC, EF_MINPINLEN, EF_PIN, MAX_MIN_PIN_RPIDS,
    MAX_RAW_SUBPARA, MIN_PIN_LENGTH,
};
use crate::error::{CtapError, CtapResult};
use crate::journal;
use crate::seed::{encrypt_keydev_f1, load_keydev, lock_engaged, seal_seed_locked};
use crate::state::{PERM_ACFG, puat_subcommand_msg};
use crate::vendor::open_channel_key;
use crate::{Ctx, Rng};

use core::sync::atomic::{AtomicU32, Ordering};

/// Boot-resolved phy values (build defaults or phy overrides) so CONFIG_READ can
/// report the *effective* LED pin / driver and touch timeout — values that live
/// in the firmware image, not the stored record — instead of leaving the host to
/// render a bare "firmware default". Packed LE `[led_gpio, led_driver,
/// presence_timeout_secs, flag]`; `flag` bit 0 marks it populated (a headless
/// `led_kind="none"` build never seeds it).
static EFFECTIVE_PHY: AtomicU32 = AtomicU32::new(0);

/// Record the boot-resolved phy values for CONFIG_READ. Call once at boot, after
/// the LED backend has resolved its effective pin/driver.
pub fn set_effective_phy(led_gpio: u8, led_driver: u8, presence_timeout_secs: u8) {
    EFFECTIVE_PHY.store(
        u32::from_le_bytes([led_gpio, led_driver, presence_timeout_secs, 1]),
        Ordering::Relaxed,
    );
}

/// The boot-resolved `(led_gpio, led_driver, presence_timeout_secs)`, or `None`
/// if never seeded.
pub(crate) fn effective_phy() -> Option<(u8, u8, u8)> {
    let b = EFFECTIVE_PHY.load(Ordering::Relaxed).to_le_bytes();
    (b[3] & 1 != 0).then_some((b[0], b[1], b[2]))
}

struct Req<'a> {
    subcommand: u64,
    raw_subpara: &'a [u8],
    proto: u64,
    /// Whether key 3 was supplied: `0` is a protocol the platform named, not one
    /// it omitted, and the two answer different codes (§6.11 → §6.1.2 step 2).
    proto_present: bool,
    pin_uv_auth_param: Option<&'a [u8]>,
    new_min_pin: u64,
    force_change: bool,
    rp_ids: [&'a str; MAX_MIN_PIN_RPIDS],
    rp_ids_len: usize,
    /// The list did not fit `MAX_MIN_PIN_RPIDS`. Reported as `KEY_STORE_FULL` by
    /// `set_min_pin_length` (CTAP 2.1 §6.11), not silently truncated — and only
    /// after the pinUvAuthParam check, so it is not an unauthenticated probe.
    rp_ids_overflow: bool,
    /// Vendor (0xFF) subCommandParams: `{1: vendorCommandId, 2: byte param,
    /// 3: int param}`. The soft-lock ids use the byte param; the PicoForge
    /// physical-config ids use the integer param.
    vendor_id: u64,
    vendor_param: &'a [u8],
    vendor_param_int: u64,
}

fn parse(data: &[u8]) -> Result<Req<'_>, CtapError> {
    let mut d = Decoder::new(data);
    let mut req = Req {
        subcommand: 0,
        raw_subpara: &[],
        proto: 0,
        proto_present: false,
        pin_uv_auth_param: None,
        new_min_pin: 0,
        force_change: false,
        rp_ids: [""; MAX_MIN_PIN_RPIDS],
        rp_ids_len: 0,
        rp_ids_overflow: false,
        vendor_id: 0,
        vendor_param: &[],
        vendor_param_int: 0,
    };
    let n = def_map(&mut d)?;
    let mut expected = 1u64;
    for _ in 0..n {
        let key = cbor(d.u32())? as u64;
        // Key 1 (subCommand) is mandatory and first.
        if expected <= 1 && key != 1 {
            return Err(CtapError::MissingParameter);
        }
        if key < expected {
            return Err(CtapError::InvalidCbor);
        }
        expected = key + 1;
        match key {
            1 => req.subcommand = cbor(d.u32())? as u64,
            2 => parse_subparams(&mut d, &mut req, data)?,
            3 => {
                req.proto = cbor(d.u32())? as u64;
                req.proto_present = true;
            }
            4 => req.pin_uv_auth_param = Some(cbor(d.bytes())?),
            _ => skip_value(&mut d)?,
        }
    }
    Ok(req)
}

/// Parse the `subCommandParams` map (request key 2), keeping the raw bytes (they
/// are covered by the pinUvAuth MAC) and dispatching each sub-key to the
/// setMinPINLength / vendor extractor for the active subcommand.
fn parse_subparams<'a>(
    d: &mut Decoder<'a>,
    req: &mut Req<'a>,
    data: &'a [u8],
) -> Result<(), CtapError> {
    let start = d.position();
    let m = def_map(d)?;
    for _ in 0..m {
        let sk = cbor(d.u32())? as u64;
        if req.subcommand == CONFIG_SET_MIN_PIN {
            parse_min_pin_sub(d, req, sk)?;
        } else if req.subcommand == CONFIG_VENDOR {
            parse_vendor_sub(d, req, sk)?;
        } else {
            skip_value(d)?;
        }
    }
    req.raw_subpara = &data[start..d.position()];
    Ok(())
}

/// One setMinPINLength subCommandParam: new length (1), rpId list (2), or
/// forceChangePin (3).
fn parse_min_pin_sub<'a>(d: &mut Decoder<'a>, req: &mut Req<'a>, sk: u64) -> Result<(), CtapError> {
    match sk {
        1 => req.new_min_pin = cbor(d.u32())? as u64,
        2 => {
            let a = def_arr(d)?;
            for _ in 0..a {
                let id = cbor(d.str())?;
                if req.rp_ids_len < MAX_MIN_PIN_RPIDS {
                    req.rp_ids[req.rp_ids_len] = id;
                    req.rp_ids_len += 1;
                } else {
                    req.rp_ids_overflow = true;
                }
            }
        }
        3 => req.force_change = cbor(d.bool())?,
        _ => skip_value(d)?,
    }
    Ok(())
}

/// One vendor (0xFF) subCommandParam: vendorCommandId (1), its byte param (2,
/// soft-lock), or its integer param (3, PicoForge physical config).
fn parse_vendor_sub<'a>(d: &mut Decoder<'a>, req: &mut Req<'a>, sk: u64) -> Result<(), CtapError> {
    match sk {
        1 => req.vendor_id = cbor(d.u64())?,
        2 => req.vendor_param = cbor(d.bytes())?,
        3 => req.vendor_param_int = cbor(d.u64())?,
        _ => skip_value(d)?,
    }
    Ok(())
}

/// `authenticatorConfig`: verify the pinUvAuthParam, then run the subcommand.
/// Replies with only the status byte.
pub fn authenticator_config<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    data: &[u8],
    out: &mut [u8],
) -> CtapResult {
    let _ = out;
    let req = parse(data)?;

    // The subcommand is judged before the token, matching a YubiKey 5.7.4 cell for
    // cell: 0 is the absent-parameter sentinel (`0x14`), an id we do not implement
    // is `0x02` with or without a token, and only a *known* one reaches the
    // authorization and its `0x36`. Nothing is disclosed by this ordering — the
    // three subcommands are already named in getInfo's options.
    // …and a protocol that is *present and unsupported* is judged before even that,
    // as on that card: it answers INVALID_PARAMETER to `pinUvAuthProtocol: 0`
    // whether the subcommand is one it implements or the `0` sentinel, i.e. before
    // it has looked at which was asked. An *absent* one is a different rule and
    // stays below, where the token it belongs to is required.
    let proto = crate::clientpin::checked_proto(req.proto_present.then_some(req.proto))?;
    match req.subcommand {
        0 => return Err(CtapError::MissingParameter),
        CONFIG_ENABLE_EA | CONFIG_TOGGLE_ALWAYS_UV | CONFIG_SET_MIN_PIN | CONFIG_VENDOR => {}
        _ => return Err(CtapError::InvalidParameter),
    }

    let param = req.pin_uv_auth_param.ok_or(CtapError::PuatRequired)?;
    let proto = proto.ok_or(CtapError::MissingParameter)?;
    if req.raw_subpara.len() > MAX_RAW_SUBPARA {
        return Err(CtapError::RequestTooLarge);
    }

    // verify_payload = 0xff×32 ‖ 0x0d ‖ subcommand ‖ raw subCommandParams.
    let mut vp = [0u8; 32 + 2 + MAX_RAW_SUBPARA];
    let vp_len = puat_subcommand_msg(&mut vp, CTAP_CONFIG, req.subcommand as u8, req.raw_subpara);

    if !ctx.state.verify_token(proto, &vp[..vp_len], param)
        || ctx.state.paut.permissions & PERM_ACFG == 0
    {
        return Err(CtapError::PinAuthInvalid);
    }
    ctx.state.mark_token_used(ctx.now_ms);

    match req.subcommand {
        CONFIG_ENABLE_EA => {
            // Persists until authenticatorReset (CTAP 2.1) — flash, not RAM.
            ctx.fs
                .put(EF_EA_ENABLED, &[1])
                .map_err(|_| CtapError::Other)?;
            journal::append(ctx, journal::EV_CFG_EA, 0, &[]);
            Ok(0)
        }
        CONFIG_TOGGLE_ALWAYS_UV => toggle_always_uv(ctx),
        CONFIG_SET_MIN_PIN if req.rp_ids_overflow => Err(CtapError::KeyStoreFull),
        CONFIG_SET_MIN_PIN => set_min_pin_length(
            ctx,
            req.new_min_pin,
            req.force_change,
            &req.rp_ids[..req.rp_ids_len],
        ),
        CONFIG_VENDOR => match req.vendor_id {
            CONFIG_AUT_ENABLE => {
                // The seed-backup channel is one-shot; spend it whatever the
                // outcome. See `FidoState::mse_active` and `vendor::consumes_mse`,
                // which does the same for the `0x41` consumers.
                let res = aut_enable(ctx, req.vendor_param);
                ctx.state.clear_mse();
                res
            }
            CONFIG_AUT_DISABLE => aut_disable(ctx),
            // PicoForge physical config over FIDO → the phy record. Gated by the
            // acfg pinUvAuthToken already verified above (no touch — matching
            // PicoForge's authenticatorConfig flow so it works out of the box).
            CONFIG_PHY_VIDPID => set_phy(ctx, |p| {
                let v = req.vendor_param_int;
                p.vid_pid = Some(((v >> 16) as u16, v as u16));
            }),
            CONFIG_PHY_LED_GPIO => set_phy(ctx, |p| p.led_gpio = Some(req.vendor_param_int as u8)),
            CONFIG_PHY_LED_BRIGHTNESS => {
                set_phy(ctx, |p| p.led_brightness = Some(req.vendor_param_int as u8))
            }
            CONFIG_PHY_OPTIONS => set_phy(ctx, |p| p.opts = req.vendor_param_int as u16),
            _ => Err(CtapError::InvalidSubcommand),
        },
        // Unreachable: the pre-auth match above admits exactly these four.
        _ => Err(CtapError::InvalidParameter),
    }
}

/// Read-modify-write the phy record for a PicoForge physical-config command: apply
/// `f`, persist to EF_PHY (effective on the next boot, like the CCID phy write),
/// and journal it. The auth was already verified by the caller.
fn set_phy<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    f: impl FnOnce(&mut phy::PhyData),
) -> CtapResult {
    let mut p = phy::load(ctx.fs).unwrap_or_default();
    f(&mut p);
    phy::save(ctx.fs, &p).map_err(|_| CtapError::Other)?;
    journal::append_config_write(ctx, CONFIG_TARGET_PHY as u8);
    Ok(0)
}

/// Compile-time default for the CTAP 2.1 `alwaysUv` option, before any explicit
/// `toggleAlwaysUv`. Off on a normal build; `--features always-uv` makes it on, so
/// the device requires user verification for every makeCredential / getAssertion
/// out of the box and again after an authenticatorReset. CTAP 2.1 §7.2 lets the
/// default be authenticator-specific.
const DEFAULT_ALWAYS_UV: bool = cfg!(feature = "always-uv");

/// Effective `alwaysUv` state. An explicit override in `EF_ALWAYS_UV` wins (`[1]` =
/// on, `[0]` = off); with no record the [`DEFAULT_ALWAYS_UV`] compile default
/// applies. authenticatorReset deletes the record, so a reset returns to that
/// default. Used by getInfo (`options.alwaysUv`) and the makeCredential /
/// getAssertion UV gate.
pub(crate) fn always_uv_enabled<S: Storage>(fs: &mut Fs<S>) -> bool {
    let mut v = [0u8; 1];
    match fs.read(EF_ALWAYS_UV, &mut v) {
        Some(n) if n >= 1 => v[0] != 0,
        _ => DEFAULT_ALWAYS_UV,
    }
}

/// `toggleAlwaysUv` (CTAP 2.1 §6.11): flip the alwaysUv state. While enabled,
/// every makeCredential / getAssertion requires user verification (a verified
/// pinUvAuthToken), not merely user presence — enforced in those commands'
/// `enforce_pin`. Disabling is supported, so the conformance toggle test
/// (AuthenticatorConfig P-2) observes the opposite value. The flipped value is
/// stored explicitly, except that toggling back to [`DEFAULT_ALWAYS_UV`] clears the
/// record instead — so a normal build's on/off is the same `[1]`/absent pair as
/// before and only an `always-uv` build ever writes the `[0]` explicit-off. State
/// persists until authenticatorReset (flash, CTAP 2.1).
fn toggle_always_uv<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>) -> CtapResult {
    let next = !always_uv_enabled(ctx.fs);
    if next == DEFAULT_ALWAYS_UV {
        ctx.fs.delete(EF_ALWAYS_UV).map_err(|_| CtapError::Other)?;
    } else {
        ctx.fs
            .put(EF_ALWAYS_UV, &[next as u8])
            .map_err(|_| CtapError::Other)?;
    }
    journal::append(ctx, journal::EV_CFG_ALWAYS_UV, 0, &[]);
    Ok(0)
}

/// `AUT_ENABLE`: engage the soft lock. The host sends a 32-byte lock key over
/// the MSE channel; the seed value is AEAD-wrapped under it into
/// `EF_KEY_DEV_ENC` and the plain `EF_KEY_DEV` is deleted. From here every
/// power cycle needs a vendor UNLOCK before any FIDO operation; recovery from a
/// lost lock key is an authenticatorReset (the identity is gone — by design).
fn aut_enable<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>, param: &[u8]) -> CtapResult {
    if !ctx.fs.has_key(EF_KEY_DEV) {
        return Err(CtapError::NotAllowed); // already locked, or no seed at all
    }
    if !ctx.state.mse_ready() {
        return Err(CtapError::NotAllowed);
    }
    let mut lock_key = open_channel_key(ctx, param)?;
    if !ctx.check_user_presence(crate::Confirm::titled("Lock device?")) {
        lock_key.zeroize();
        return Err(CtapError::OperationDenied);
    }
    let seed = load_keydev(&ctx.dev, ctx.fs);
    let r = seed.map(|mut seed| {
        let blob = seal_seed_locked(ctx.rng, &lock_key, &seed);
        seed.zeroize();
        ctx.fs
            .put_key(EF_KEY_DEV_ENC, Sealed::wrap(&blob))
            .and_then(|()| ctx.fs.delete_key(EF_KEY_DEV))
    });
    lock_key.zeroize();
    match r {
        Some(Ok(())) => {
            journal::append(ctx, journal::EV_LOCK_ENGAGE, 0, &[]);
            Ok(0)
        }
        _ => Err(CtapError::Other),
    }
}

/// `AUT_DISABLE`: release the soft lock permanently — writes the seed back
/// kbase-sealed and deletes the wrapped blob, so the device stops needing an
/// unlock at all.
///
/// The gate is that the seed was unlocked this power cycle, which proves *someone*
/// presented the lock key. It does not prove it was this caller: unlike
/// [`crate::state::FidoState::mse_cid`] two fields above it, `keydev_dec` carries no channel,
/// token or timer and lives until power-off (audit run-34 #28). That is accepted —
/// the lock key **is** the authorisation, and an attacker positioned to abuse the
/// window already meets `BACKUP_EXPORT`'s prerequisites, which hand over the seed
/// itself. What the finding does close is the consent: the prompt named "Unlock",
/// the reversible operation, for a touch that authorises the irreversible one.
fn aut_disable<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>) -> CtapResult {
    if !lock_engaged(ctx.fs) {
        return Err(CtapError::NotAllowed);
    }
    if ctx.state.keydev_dec.is_none() {
        return Err(CtapError::PinAuthInvalid);
    }
    // `require_presence`, so a platform `CTAPHID_CANCEL` reports itself as one
    // instead of being flattened into "the user declined".
    ctx.require_presence(crate::Confirm::titled("Remove device lock?"))?;
    let mut seed = ctx.state.keydev_dec.unwrap();
    let r = encrypt_keydev_f1(&ctx.dev, ctx.fs, &seed);
    seed.zeroize();
    r.map_err(|_| CtapError::Other)?;
    ctx.fs
        .delete_key(EF_KEY_DEV_ENC)
        .map_err(|_| CtapError::Other)?;
    ctx.state.clear_keydev_dec();
    journal::append(ctx, journal::EV_LOCK_RELEASE, 0, &[]);
    Ok(0)
}

fn set_min_pin_length<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    new_min_pin: u64,
    force_change: bool,
    rp_ids: &[&str],
) -> CtapResult {
    let current = current_min_pin(ctx) as u64;
    let new_min = if new_min_pin == 0 {
        current
    } else {
        new_min_pin
    };
    // minPINLength is monotonic — it can only grow.
    if new_min < current {
        return Err(CtapError::PinPolicyViolation);
    }
    // …and is bounded by the maximum PIN length. Without this the `as u8` store
    // below truncates a host-supplied u64 (e.g. 256 -> 0), passing the monotonic
    // guard yet silently lowering the floor to 0.
    if new_min > crate::clientpin::MAX_PIN_LENGTH as u64 {
        return Err(CtapError::PinPolicyViolation);
    }
    let pin_set = ctx.fs.has_data(EF_PIN);
    if force_change && !pin_set {
        return Err(CtapError::PinNotSet);
    }
    // A PIN shorter than the new minimum must be changed before next use.
    let mut force = force_change;
    if pin_set {
        let mut pf = [0u8; crate::clientpin::PIN_FILE_LEN];
        if let Some(n) = ctx.fs.read(EF_PIN, &mut pf)
            && n >= 2
            && (pf[1] as u64) < new_min
        {
            force = true;
        }
    }
    if force {
        ctx.state.reset_pin_uv_auth_token(ctx.rng);
        crate::seed::clear_ppuat(ctx.fs).map_err(|_| CtapError::Other)?;
    }
    // EF_MINPINLEN = [minPINLength, forceChangePin, sha256(rpId)…]; the rp hash
    // list authorises those RPs to read minPINLength via the makeCredential
    // extension.
    let mut data = [0u8; 2 + 32 * MAX_MIN_PIN_RPIDS];
    data[0] = new_min as u8;
    data[1] = u8::from(force);
    let mut len = 2;
    for id in rp_ids {
        data[len..len + 32].copy_from_slice(&sha256(id.as_bytes()));
        len += 32;
    }
    ctx.fs
        .put(EF_MINPINLEN, &data[..len])
        .map_err(|_| CtapError::Other)?;
    journal::append(
        ctx,
        journal::EV_CFG_MIN_PIN,
        new_min as u8,
        &[u8::from(force)],
    );
    Ok(0)
}

fn current_min_pin<S: Storage, R: Rng>(ctx: &mut Ctx<S, R>) -> u8 {
    let mut buf = [0u8; 2];
    match ctx.fs.read(EF_MINPINLEN, &mut buf) {
        Some(n) if n >= 1 => buf[0],
        _ => MIN_PIN_LENGTH,
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
