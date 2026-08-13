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
/// `0` on both axes is what a *stored* record can hold: a pre-run-34 build could
/// persist one, and slot `9B` stores it deliberately (see [`MGM_PIN_POLICY`] —
/// it is not a key slot and has no pin policy to report). No host may send it:
/// "default" is an omitted `AA`/`AB` tag, and an explicit `0` is refused like any
/// other undefined value (E80). A stored one is still honoured — the PIN axis
/// resolves it by slot (`crate::auth::general_authenticate`), the touch axis needs
/// no resolution because `check_touch` passes only `NEVER`.
pub const TOUCHPOLICY_DEFAULT: u8 = 0;

/// The pin-policy byte `GET METADATA 9B` reports. `is_key(0x9B)` is false in both
/// the PIN gate and the freshness spend, so the slot has no policy — two writers
/// used to fill the field in with opposite guesses. A YubiKey 5.7.4 reports `0`
/// in every state (fresh, escrowed, after a host rotation), measured.
pub const MGM_PIN_POLICY: u8 = PINPOLICY_DEFAULT;

/// The pin-policy byte `GET METADATA F9` reports. Neither card PIN-gates the
/// attestation slot — `ATTEST` answers with nothing verified on both — so the
/// byte is descriptive only; a YubiKey 5.7.4 reports `ONCE` there and we match.
pub const ATTESTATION_PIN_POLICY: u8 = PINPOLICY_ONCE;

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
/// are AES-256-GCM-sealed (`seal`), so the slot can only be reached through the
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
/// object (`0x7E`, dynamic — `None` here), the Yubico attestation cert
/// (`5FFF01`) and the ADMIN DATA object (`5FFF00`). The PRINTED object
/// (`5FC109`) is handled specially in GET/PUT DATA (the PIN-protected mgmt key),
/// not through this generic table.
///
/// The BIT group template `7F61` is deliberately absent. It used to map to
/// `0xD2B6` — which is `data_object_fid(0xB6)`, i.e. `5FC1B6`'s own file — so a
/// `PUT DATA 5FC1B6` came back out of `GET DATA 7F61`. It is never populated,
/// and an id with no file already answers the `6A82` a YubiKey 5.7.4 gives
/// `7F61` in every state (measured, before and after writing `5FC1B6`), so the
/// entry bought an alias and nothing else.
pub fn object_fid(id: u32) -> Option<u16> {
    if id & 0xFFFF00 == 0x5FC100 {
        return data_object_fid((id & 0xFF) as u8);
    }
    match id & 0xFFFF {
        0xFF01 => Some(EF_ATTESTATION_CERT),
        0xFF00 => Some(EF_PIVMAN_DATA),
        _ => None,
    }
}

/// The generic `5FC1xx` data-object fid (`0xD200 | xx`). `5FC1F0/F1` are
/// refused: the `0xD2F0`/`0xD2F1` fids are reserved for the ADMIN-DATA /
/// attestation objects and must not be aliased.
pub(crate) fn data_object_fid(low: u8) -> Option<u16> {
    (low < 0xF0).then_some(0xD200 | low as u16)
}

/// The four data objects SP 800-73-4 pt1 Table 3 gives a contact read condition
/// of PIN. YubiKey "PRINTED INFORMATION" is one of them, and here it also backs
/// the PIN-protected management key (see `get_protected_mgm`).
pub const CARDHOLDER_FINGERPRINTS_ID: u32 = 0x5FC103;
pub const CARDHOLDER_FACIAL_IMAGE_ID: u32 = 0x5FC108;
pub const PRINTED_ID: u32 = 0x5FC109;
pub const CARDHOLDER_IRIS_IMAGES_ID: u32 = 0x5FC121;

/// Whether GET DATA for this object needs the PIN. Measured on a YubiKey 5.7.4,
/// 3 runs: exactly Table 3's PIN set and nothing else, judged *before* the
/// object's existence — so an absent one answers `6982`, not `6A82` — and the
/// management key does not stand in for the PIN.
pub(crate) fn read_needs_pin(id: u32) -> bool {
    matches!(
        id,
        CARDHOLDER_FINGERPRINTS_ID
            | CARDHOLDER_FACIAL_IMAGE_ID
            | PRINTED_ID
            | CARDHOLDER_IRIS_IMAGES_ID
    )
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

/// The pad byte that fills a reference out to [`PIN_WIRE_LEN`].
pub const PIN_PAD: u8 = 0xFF;

/// Shortest PIN or PUK the card will store — SP 800-73-4 §2.4.3 puts the
/// reference at 6-8 bytes, and a YubiKey enforces that half of the rule.
pub const PIN_MIN_LEN: usize = 6;

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
    let minted_mgm = !fs.has_key(key_fid(SLOT_CARDMGM));
    if minted_mgm {
        let mut key = DEFAULT_MGM;
        let r = seal::seal_put(dev, fs, rng, key_fid(SLOT_CARDMGM), &key);
        key.zeroize();
        r?;
    }
    // The key and its meta head are written as a pair but not deleted as one, so
    // BOTH directions need repairing. The key is a phase-2 gate
    // ([`is_piv_gate_fid`]) while EF_META — one record shared by every applet —
    // goes in phase 1 of the device-wide wipe, so a tear between them leaves a live
    // key whose `meta_find` fails and `general_authenticate` answers
    // REFERENCE_NOT_FOUND for good. The other direction is `force_delete`, which
    // drops the key even when its own `meta_delete` failed (`let _ =`): a stale
    // AES-256 head left over a re-minted 24-byte DEFAULT_MGM wedges the slot on the
    // length compare, and RESET runs this very path, so nothing would clear it. The
    // mint arm is therefore an unconditional rewrite — `meta_add` replaces.
    let have_meta = {
        let mut meta = [0u8; 8];
        fs.meta_find(key_fid(SLOT_CARDMGM).get(), &mut meta)
            .is_some()
    };
    if minted_mgm || !have_meta {
        let head = if minted_mgm {
            // A card we just provisioned takes the YubiKey 5 defaults: AES-192, touch
            // OFF (admin provisioning isn't touch-gated), still enforced if a host
            // raises it via SET MGM KEY.
            Some((ALGO_AES192, TOUCHPOLICY_NEVER))
        } else {
            // A surviving key keeps its algorithm — the sealed length gives it, and
            // claiming AES-192 over a 16- or 32-byte one wedges the slot on
            // `meta[0] != algo`. Its touch policy is not recoverable, so it takes the
            // published default like every other record here (E95): inventing ALWAYS
            // gated management behind a touch whose only exit needs that same touch.
            let mut key = [0u8; 32];
            let n = seal::seal_read(dev, fs, key_fid(SLOT_CARDMGM), &mut key);
            key.zeroize();
            match n {
                Ok(16) => Some((ALGO_AES128, TOUCHPOLICY_NEVER)),
                Ok(24) => Some((ALGO_AES192, TOUCHPOLICY_NEVER)),
                Ok(32) => Some((ALGO_AES256, TOUCHPOLICY_NEVER)),
                // Unreadable: GENERAL AUTHENTICATE reads the key through the same
                // seal, so slot 9B is already dead. Leaving the head absent fails
                // just that slot closed; erroring here fails the whole SELECT
                // (`PivApplet::select` maps a `scan_files` error to MEMORY_FAILURE),
                // taking certificate reads, GET DATA and RESET down with it.
                _ => None,
            }
        };
        if let Some((algo, touch)) = head {
            fs.meta_add(key_fid(SLOT_CARDMGM).get(), &[algo, MGM_PIN_POLICY, touch])
                .map_err(|_| Sw::MEMORY_FAILURE)?;
        }
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

/// The records that *gate* the applet: the PIN and PUK verifiers, their retry
/// state, and the 0x9B management key. Public because the device-wide
/// `Fs::factory_wipe` bypasses `wipe_piv` and needs the same rule. `wipe_piv`
/// deletes these last — `scan_files` re-creates every one of them at a *published*
/// default, and PIV slot keys are sealed device-rooted rather than PIN-bound, so a
/// sweep that took one first and then lost power would re-seed a published
/// credential over live key material. 0x9B is a gate for the same reason the PIN
/// is: it is what IMPORT KEY, GENERATE, PUT DATA, MOVE KEY and SET MGM KEY check,
/// and `scan_files` re-seeds it to [`DEFAULT_MGM`] (audit run-36).
pub fn is_piv_gate_fid(fid: u16) -> bool {
    matches!(fid, EF_PIN | EF_PUK | EF_RETRIES) || fid == key_fid(SLOT_CARDMGM).get()
}

/// Everything else a PIV factory reset owns — the slot keys other than 0x9B, data
/// objects, the pubkey cache. Deleted first, so every prefix of the wipe leaves the
/// keys behind a gate.
fn is_piv_secret_fid(fid: u16) -> bool {
    is_piv_fid(fid) && !is_piv_gate_fid(fid)
}

/// Progress backstop for one [`sweep`] phase: every batched `force_delete` clears
/// one *distinct* live fid and [`is_piv_fid`] spans 768 of them, so needing more
/// deletes than that means the backend keeps re-yielding what it removed. Bounds
/// each phase separately, which is strictly tighter than the old single sweep.
const RESET_MAX_DELETES: u32 = 768;

/// Factory-reset the applet: delete every PIV file and meta record
/// (`is_piv_fid`), then re-create the defaults. Scoped to the PIV fid range —
/// the other applets' data must survive a PIV reset.
pub fn reset_files<S: Storage>(dev: &Device, fs: &mut Fs<S>, rng: &mut dyn Rng) -> Result<(), Sw> {
    let wiped = wipe_piv(fs);
    // Re-provision even when the sweep failed: an applet left without the retry
    // counters answers 6A88 to every later RESET instead of the honest failure
    // below. Safe now that the gate records go last — a failed sweep that never
    // reached them leaves the owner's PIN in place, not a default one.
    let ensured = scan_files(dev, fs, rng);
    wiped.and(ensured)
}

/// Delete every live PIV file and meta record.
///
/// Two phases, and the order carries the security property (the rule `wipe_oath`
/// states, which this function is the sibling of): `for_each_key` yields in
/// flash-ring order, not FID order, so one combined sweep can reach the PIN before
/// the keys — and a power cut there lets `scan_files` re-seed the factory PIN over
/// slot keys that are still live and, unlike OpenPGP's, not PIN-bound at rest.
fn wipe_piv<S: Storage>(fs: &mut Fs<S>) -> Result<(), Sw> {
    sweep(fs, is_piv_secret_fid)?;
    sweep(fs, is_piv_gate_fid)
}

/// One phase of [`wipe_piv`]: delete every live fid matching `pred`. Batched
/// because `for_each_key` cannot delete mid-iteration, and DE-DUPED because it
/// yields one entry per stored *version*: a batch of superseded copies is not a
/// batch of distinct fids.
fn sweep<S: Storage>(fs: &mut Fs<S>, pred: fn(u16) -> bool) -> Result<(), Sw> {
    let mut deleted = 0u32;
    loop {
        let mut fids = [0u16; 32];
        let mut n = 0;
        let complete = fs.for_each_key(&mut |fid| {
            if pred(fid) && n < fids.len() && !fids[..n].contains(&fid) {
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
