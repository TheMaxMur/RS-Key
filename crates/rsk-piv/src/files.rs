// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! PIV file ids, the wire-object map and first-boot defaults. One `Fs` is
//! shared across all applets, so PIV owns its own disjoint fid ranges:
//! keys/PINs at `0xD1xx` (low byte = wire slot), data objects at `0xD2xx` (low
//! byte of the `5FC1xx` object id) — the wire slot is the fid low byte everywhere.

use rsk_crypto::Device;
use rsk_fs::{Fs, KeyFid, Storage};
use rsk_openpgp::Rng;
use rsk_openpgp::keys::{Curve, PrivKey};
use rsk_sdk::Sw;
use zeroize::Zeroize;

use crate::seal;
use crate::x509;

// PIV algorithm identifiers (SP 800-78 / Yubico).
pub const ALGO_3DES: u8 = 0x03;
pub const ALGO_RSA3072: u8 = 0x05;
pub const ALGO_RSA1024: u8 = 0x06;
pub const ALGO_RSA2048: u8 = 0x07;
pub const ALGO_AES128: u8 = 0x08;
pub const ALGO_AES192: u8 = 0x0A;
pub const ALGO_AES256: u8 = 0x0C;
pub const ALGO_ECCP256: u8 = 0x11;
pub const ALGO_ECCP384: u8 = 0x14;
pub const ALGO_RSA4096: u8 = 0x16;
pub const ALGO_ED25519: u8 = 0xE0;
pub const ALGO_X25519: u8 = 0xE1;

/// SEC1 uncompressed point: `0x04` + two 48-byte P-384 coordinates (the largest
/// PIV curve).
pub(crate) const MAX_EC_POINT: usize = 97;

/// GENERATE ASYMMETRIC KEY PAIR request template tag (SP 800-73-4).
pub const TAG_GEN_TEMPLATE: u8 = 0xAC;

/// Management-key length for a 9B algorithm id; `None` for a non-mgm algorithm.
pub(crate) fn mgm_key_len(algo: u8) -> Option<usize> {
    match algo {
        ALGO_AES128 => Some(16),
        ALGO_AES192 | ALGO_3DES => Some(24),
        ALGO_AES256 => Some(32),
        _ => None,
    }
}

// PIN / touch policies (Yubico metadata values).
pub const PINPOLICY_DEFAULT: u8 = 0;
pub const PINPOLICY_NEVER: u8 = 1;
pub const PINPOLICY_ONCE: u8 = 2;
pub const PINPOLICY_ALWAYS: u8 = 3;
/// `0` means "the card's default" on both axes; it is resolved at store time by
/// [`crate::keygen::resolved_policies`] and never persisted.
pub const TOUCHPOLICY_DEFAULT: u8 = 0;
pub const TOUCHPOLICY_NEVER: u8 = 1;
pub const TOUCHPOLICY_ALWAYS: u8 = 2;
pub const TOUCHPOLICY_CACHED: u8 = 3;

pub const ORIGIN_GENERATED: u8 = 0x01;
pub const ORIGIN_IMPORTED: u8 = 0x02;

// Wire key references.
pub const SLOT_AUTHENTICATION: u8 = 0x9A;
pub const SLOT_CARDMGM: u8 = 0x9B;
pub const SLOT_SIGNATURE: u8 = 0x9C;
pub const SLOT_KEYMGM: u8 = 0x9D;
pub const SLOT_CARDAUTH: u8 = 0x9E;
pub const SLOT_ATTESTATION: u8 = 0xF9;
/// The twenty retired key-management slots, `82`–`95`.
pub const SLOT_RETIRED_FIRST: u8 = 0x82;
pub const SLOT_RETIRED_LAST: u8 = 0x95;
// SP 800-73 PIN / PUK key references (VERIFY / CHANGE / RESET RETRY / metadata P2).
pub const REF_PIN: u8 = 0x80;
pub const REF_PUK: u8 = 0x81;

// GENERAL AUTHENTICATE dynamic-auth template tags (SP 800-73-4).
pub const TAG_DYN_AUTH: u8 = 0x7C;
pub const TAG_AUTH_WITNESS: u8 = 0x80;
pub const TAG_AUTH_CHALLENGE: u8 = 0x81;
pub const TAG_AUTH_RESPONSE: u8 = 0x82;
pub const TAG_AUTH_EXPONENTIATION: u8 = 0x85;

/// The twenty retired key-management slots.
pub fn is_retired(slot: u8) -> bool {
    (SLOT_RETIRED_FIRST..=SLOT_RETIRED_LAST).contains(&slot)
}

/// The four primary asymmetric slots.
pub fn is_active(slot: u8) -> bool {
    matches!(
        slot,
        SLOT_AUTHENTICATION | SLOT_SIGNATURE | SLOT_KEYMGM | SLOT_CARDAUTH
    )
}

/// Any movable/attestable asymmetric slot (excludes 9B and F9).
pub fn is_key(slot: u8) -> bool {
    is_active(slot) || is_retired(slot)
}

/// Private-key file for a wire slot (also 9B and F9). A [`KeyFid`]: its contents
/// are AES-256-GCM-sealed ([`seal`]), so the slot can only be reached through the
/// typed key API, never the plaintext `Fs::put`/`read`.
pub fn key_fid(slot: u8) -> KeyFid {
    KeyFid::new(0xD100 | slot as u16)
}

/// PIN / PUK verifier files: `[len, format=0x01, verifier(32)]`.
pub const EF_PIN: u16 = 0xD180;
pub const EF_PUK: u16 = 0xD181;
/// Retry state: `[pin_total, pin_left, puk_total, puk_left]`.
pub const EF_RETRIES: u16 = 0xD1FE;

/// The X.509 certificate object that pairs with a key slot:
/// `5FC105/0A/0B/01` for the active four, `5FC10D…5FC120` for retired 1–20
/// (= slot + 0x8B), `5FFF01` for F9.
pub fn cert_fid_for_slot(slot: u8) -> Option<u16> {
    Some(match slot {
        SLOT_AUTHENTICATION => 0xD205,
        SLOT_SIGNATURE => 0xD20A,
        SLOT_KEYMGM => 0xD20B,
        SLOT_CARDAUTH => 0xD201,
        SLOT_ATTESTATION => EF_ATTESTATION_CERT,
        s if is_retired(s) => 0xD200 | ((s as u16 + 0x8B) & 0xFF),
        _ => return None,
    })
}

/// The cached public-point file for a key slot (`0xD4xx`, low byte = wire slot).
/// A plain (unsealed — the point is public) O(1) read that lets GET METADATA emit
/// the slot's public key without recomputing `d·G` at ANY slot count. Written
/// best-effort at key creation; a slot without it (pre-upgrade, or an import whose
/// derive failed) falls back to the in-EF_META cache, then to deriving the point.
/// `0xD4xx` sits outside the host-addressable `5FC1xx` object space (`0xD2xx`) and
/// every other applet's fid range, so it is private to PIV and never on the wire.
pub fn pubkey_fid(slot: u8) -> u16 {
    0xD400 | slot as u16
}

/// The F9 attestation certificate object (`5FFF01`).
pub const EF_ATTESTATION_CERT: u16 = 0xD2F1;
/// YubiKey "ADMIN DATA" object (`5FFF00`, a.k.a. PivmanData) — the protection
/// flags (e.g. "management key is PIN-protected"). Plaintext, always-readable.
pub const EF_PIVMAN_DATA: u16 = 0xD2F0;

/// Map a GET/PUT DATA object id (the `5C` tag value, 1–3 bytes big-endian) to
/// its file — the GET DATA allow-list: the `5FC1xx` objects, the discovery
/// object (`0x7E`, dynamic — `None` here), the BIT group template (`0x7F61`,
/// never populated), the Yubico attestation cert (`5FFF01`) and the ADMIN DATA
/// object (`5FFF00`). The PRINTED object (`5FC109`) is handled specially in
/// GET/PUT DATA (the PIN-protected mgmt key), not through this generic table.
pub fn object_fid(id: u32) -> Option<u16> {
    if id & 0xFFFF00 == 0x5FC100 {
        return data_object_fid((id & 0xFF) as u8);
    }
    match id & 0xFFFF {
        0xFF01 => Some(EF_ATTESTATION_CERT),
        0xFF00 => Some(EF_PIVMAN_DATA),
        0x7F61 => Some(0xD2B6), // BITGT: a valid id with no data → 6A82
        _ => None,
    }
}

/// The generic `5FC1xx` data-object fid (`0xD200 | xx`). `5FC1F0/F1` are
/// refused: the `0xD2F0`/`0xD2F1` fids are reserved for the ADMIN-DATA /
/// attestation objects and must not be aliased.
pub(crate) fn data_object_fid(low: u8) -> Option<u16> {
    (low < 0xF0).then_some(0xD200 | low as u16)
}

pub const DISCOVERY_ID: u32 = 0x7E;

/// The discovery object (returned raw, not wrapped in `53`): the full PIV AID
/// + PIN-usage policy `40 10`.
pub const DISCOVERY: &[u8] = &[
    0x7E, 0x12, 0x4F, 0x0B, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x5F,
    0x2F, 0x02, 0x40, 0x10,
];

/// SP 800-73 padded PIN-block wire length (PIN/PUK padded to 8 with `0xFF`).
pub const PIN_WIRE_LEN: usize = 8;

/// Default credentials: PIN `123456` padded to 8 with `0xFF`, PUK `12345678`,
/// management key `0102…08` ×3 typed as AES-192 (the YubiKey 5.7-era default
/// key type).
pub const DEFAULT_PIN: [u8; PIN_WIRE_LEN] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF];
pub const DEFAULT_PUK: [u8; PIN_WIRE_LEN] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];
pub const DEFAULT_MGM: [u8; 24] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];
pub const DEFAULT_RETRIES: u8 = 3;

/// PIN/PUK verifier record length: `[len, fmt=0x01, verifier(32)]`.
pub(crate) const PIN_REC_LEN: usize = 34;

/// Write a PIN/PUK verifier file: `[len, 0x01, pin_derive_verifier(pin)]`.
pub fn put_pin_verifier<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    fid: u16,
    pin: &[u8],
) -> Result<(), Sw> {
    let mut rec = [0u8; PIN_REC_LEN];
    rec[0] = pin.len() as u8;
    rec[1] = 0x01;
    rec[2..].copy_from_slice(&dev.pin_derive_verifier(pin));
    let r = fs.put(fid, &rec).map_err(|_| Sw::MEMORY_FAILURE);
    rec.zeroize();
    r
}

/// Create the PIN/PUK/retry files, the default management key and the F9
/// attestation key + its self-signed P-384 certificate on first use.
/// Idempotent — every step is guarded by a has-data check.
pub fn scan_files<S: Storage>(dev: &Device, fs: &mut Fs<S>, rng: &mut dyn Rng) -> Result<(), Sw> {
    if !fs.has_data(EF_PIN) {
        put_pin_verifier(dev, fs, EF_PIN, &DEFAULT_PIN)?;
    }
    if !fs.has_data(EF_PUK) {
        put_pin_verifier(dev, fs, EF_PUK, &DEFAULT_PUK)?;
    }
    if !fs.has_data(EF_RETRIES) {
        let d = DEFAULT_RETRIES;
        fs.put(EF_RETRIES, &[d, d, d, d])
            .map_err(|_| Sw::MEMORY_FAILURE)?;
    }
    if !fs.has_key(key_fid(SLOT_CARDMGM)) {
        let mut key = DEFAULT_MGM;
        let r = seal::seal_put(dev, fs, rng, key_fid(SLOT_CARDMGM), &key);
        key.zeroize();
        r?;
        // Real YubiKey 5 ships the management key touch-OFF; we follow that
        // (admin provisioning isn't touch-gated) while still enforcing it if a
        // host raises it via SET MGM KEY. Slot keys keep their ALWAYS default.
        fs.meta_add(
            key_fid(SLOT_CARDMGM).get(),
            &[ALGO_AES192, PINPOLICY_ALWAYS, TOUCHPOLICY_NEVER],
        )
        .map_err(|_| Sw::MEMORY_FAILURE)?;
    }
    if !fs.has_key(key_fid(SLOT_ATTESTATION)) {
        let key = PrivKey::generate(Curve::P384, rng).ok_or(Sw::EXEC_ERROR)?;
        seal::store_ec_key(dev, fs, rng, key_fid(SLOT_ATTESTATION), &key)?;
        let mut point = [0u8; MAX_EC_POINT];
        let plen = key.public_point(&mut point)?;
        let _ = fs.put(pubkey_fid(SLOT_ATTESTATION), &point[..plen]);
        let mut cert = [0u8; x509::MAX_CERT];
        let n = x509::build_cert(
            &x509::CertParams {
                subject_slot: SLOT_ATTESTATION,
                algo: ALGO_ECCP384,
                spki: x509::Spki::Ec {
                    curve: Curve::P384,
                    point: &point[..plen],
                },
                attestation: None,
                ca_pathlen: Some(1),
            },
            &x509::Signer::Ec(&key),
            rng,
            &mut cert,
        )?;
        let mut obj = [0u8; x509::MAX_CERT + 16];
        let on = crate::wrap_cert_object(&cert[..n], &mut obj);
        fs.put(EF_ATTESTATION_CERT, &obj[..on])
            .map_err(|_| Sw::MEMORY_FAILURE)?;
    }
    Ok(())
}

/// The fids a PIV factory reset owns: keys/PINs + data objects
/// (`0xD100..=0xD2FF`) and the per-slot pubkey cache (`0xD4xx`). `0xD3xx` is
/// FIDO's, so it is deliberately not in the range.
pub(crate) fn is_piv_fid(fid: u16) -> bool {
    (0xD100..=0xD2FF).contains(&fid) || (0xD400..=0xD4FF).contains(&fid)
}

/// Progress backstop for the [`wipe_piv`] sweep: every batched `force_delete`
/// clears one *distinct* live fid and [`is_piv_fid`] spans 768 of them, so needing
/// more deletes than that means the backend keeps re-yielding what it removed.
const RESET_MAX_DELETES: u32 = 768;

/// Factory-reset the applet: delete every PIV file and meta record
/// ([`is_piv_fid`]), then re-create the defaults. Scoped to the PIV fid range —
/// the other applets' data must survive a PIV reset.
pub fn reset_files<S: Storage>(dev: &Device, fs: &mut Fs<S>, rng: &mut dyn Rng) -> Result<(), Sw> {
    let wiped = wipe_piv(fs);
    // Re-provision even when the sweep failed: it deletes the PIN/PUK/retry files
    // first, and an applet left without them answers 6A88 to every later RESET
    // (no retry counters to read) instead of the honest failure below.
    let ensured = scan_files(dev, fs, rng);
    wiped.and(ensured)
}

/// Delete every live PIV file and meta record. Batched because `for_each_key`
/// cannot delete mid-iteration, and DE-DUPED because it yields one entry per
/// stored *version*: a batch of superseded copies is not a batch of distinct fids.
fn wipe_piv<S: Storage>(fs: &mut Fs<S>) -> Result<(), Sw> {
    let mut deleted = 0u32;
    loop {
        let mut fids = [0u16; 32];
        let mut n = 0;
        let complete = fs.for_each_key(&mut |fid| {
            if is_piv_fid(fid) && n < fids.len() && !fids[..n].contains(&fid) {
                fids[n] = fid;
                n += 1;
            }
        });
        if n == 0 {
            // A truncated walk (flash read fault) can hide a live fid, so an empty
            // batch only proves the range is clear when the enumeration completed.
            return if complete {
                Ok(())
            } else {
                Err(Sw::MEMORY_FAILURE)
            };
        }
        // Liveness measured as PROGRESS, not as a pass count: each pass deletes
        // `n` distinct fids, so a converging sweep can never exceed the budget.
        deleted += n as u32;
        if deleted > RESET_MAX_DELETES {
            return Err(Sw::MEMORY_FAILURE);
        }
        for &fid in &fids[..n] {
            // force_delete (unconditional, and it drops the meta record itself):
            // `delete` skips a false-absent file that `for_each_key` keeps
            // yielding, so the sweep would spin instead of converging.
            fs.force_delete(fid).map_err(|_| Sw::MEMORY_FAILURE)?;
        }
    }
}
