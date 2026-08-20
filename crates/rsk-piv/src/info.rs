// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Read-only slot metadata for the trusted display. PIV slot introspection is
//! entirely `rsk-fs` metadata — key presence, algorithm and PIN/touch policy
//! from the meta side-store, certificate presence — none of which needs a PIN
//! or the management key, so an on-device screen can show it freely. The private
//! key bytes are sealed and never surfaced; the public point is *not* read (that
//! is the management-key-gated GET METADATA path, deliberately out of scope).

use rsk_crypto::Device;
use rsk_fs::{Fs, Storage};
use rsk_openpgp::Rng;
use rsk_rsa::RsaKey;
use rsk_sdk::Sw;

use crate::files::*;

/// The four primary asymmetric slots, in display order: Authentication (9A),
/// Signing (9C), Key Management (9D), Card Authentication (9E). The card-mgmt
/// (9B), attestation (F9) and retired (82–95) slots are plumbing / advanced and
/// are left off the at-a-glance screen.
pub const PRIMARY_SLOTS: [u8; 4] = [
    SLOT_AUTHENTICATION,
    SLOT_SIGNATURE,
    SLOT_KEYMGM,
    SLOT_CARDAUTH,
];

/// What one PIV slot holds, all read without a PIN or the management key.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PivSlot {
    /// Wire key reference (`0x9A` …).
    pub slot: u8,
    /// Whether a private key is present in the slot.
    pub present: bool,
    /// Key algorithm (`ALGO_*`), or `0` when no key.
    pub algo: u8,
    /// PIN policy (`PINPOLICY_*`).
    pub pin_policy: u8,
    /// Touch policy (`TOUCHPOLICY_*`).
    pub touch_policy: u8,
    /// Key origin (`ORIGIN_*`), or `0` when unknown.
    pub origin: u8,
    /// Whether an X.509 certificate is stored for the slot.
    pub cert: bool,
}

/// A read-only snapshot of the PIV applet's public state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PivInfo {
    /// The four primary slots, in [`PRIMARY_SLOTS`] order.
    pub slots: [PivSlot; 4],
    /// Remaining PIN attempts.
    pub pin_retries: u8,
    /// Remaining PUK attempts.
    pub puk_retries: u8,
}

impl PivInfo {
    /// How many primary slots hold a key or a certificate.
    pub fn populated(&self) -> u8 {
        self.slots.iter().filter(|s| s.present || s.cert).count() as u8
    }
}

/// A short ASCII label for a PIV key reference.
pub fn slot_name(slot: u8) -> &'static str {
    match slot {
        SLOT_AUTHENTICATION => "Authentication",
        SLOT_SIGNATURE => "Signature",
        SLOT_KEYMGM => "Key Management",
        SLOT_CARDAUTH => "Card Auth",
        SLOT_CARDMGM => "Management",
        SLOT_ATTESTATION => "Attestation",
        _ => "Retired",
    }
}

/// A short ASCII label for a PIV algorithm id (`ALGO_*`).
pub fn algo_name(algo: u8) -> &'static str {
    match algo {
        ALGO_RSA1024 => "RSA 1024",
        ALGO_RSA2048 => "RSA 2048",
        ALGO_RSA3072 => "RSA 3072",
        ALGO_RSA4096 => "RSA 4096",
        ALGO_ECCP256 => "NIST P-256",
        ALGO_ECCP384 => "NIST P-384",
        ALGO_ED25519 => "Ed25519",
        ALGO_X25519 => "X25519",
        ALGO_3DES => "3DES",
        ALGO_AES128 => "AES-128",
        ALGO_AES192 => "AES-192",
        ALGO_AES256 => "AES-256",
        _ => "—",
    }
}

/// A short ASCII label for a PIN policy (`PINPOLICY_*`).
pub fn pin_policy_name(p: u8) -> &'static str {
    match p {
        PINPOLICY_NEVER => "Never",
        PINPOLICY_ONCE => "Once",
        PINPOLICY_ALWAYS => "Always",
        _ => "Default",
    }
}

/// A short ASCII label for a touch policy (`TOUCHPOLICY_*`).
pub fn touch_policy_name(p: u8) -> &'static str {
    match p {
        TOUCHPOLICY_NEVER => "Never",
        TOUCHPOLICY_ALWAYS => "Always",
        TOUCHPOLICY_CACHED => "Cached",
        _ => "Default",
    }
}

/// A short ASCII label for a key origin (`ORIGIN_*`).
pub fn origin_name(o: u8) -> &'static str {
    match o {
        ORIGIN_GENERATED => "Generated",
        ORIGIN_IMPORTED => "Imported",
        _ => "—",
    }
}

/// The retired key-management slots, 82–95, plus the F9 attestation slot: the most
/// the "Retired & F9" screen can list.
pub const MAX_EXTRA_SLOTS: usize = 21;

/// Read one slot's public metadata by wire reference — any slot (primary, retired
/// or F9), PIN-free. The algorithm and policy come from the meta side-store; a slot
/// with no key reports `present = false` and zeroed policy.
pub fn read_slot<S: Storage>(fs: &mut Fs<S>, slot: u8) -> PivSlot {
    let present = fs.has_key(key_fid(slot));
    let mut meta = [0u8; 4];
    let (algo, pin_policy, touch_policy, origin) = if present {
        match fs.meta_find(key_fid(slot).get(), &mut meta) {
            Some(n) if n >= 3 => (meta[0], meta[1], meta[2], if n >= 4 { meta[3] } else { 0 }),
            _ => (0, 0, 0, 0),
        }
    } else {
        (0, 0, 0, 0)
    };
    let cert = cert_fid_for_slot(slot).is_some_and(|f| fs.has_data(f));
    PivSlot {
        slot,
        present,
        algo,
        pin_policy,
        touch_policy,
        origin,
        cert,
    }
}

/// Gather the attestation (F9) and every *populated* retired slot (82–95) for the
/// trusted display, F9 first. A slot counts as populated when it holds a key or a
/// stored certificate; empty retired slots are not listed (they are reached through
/// the on-device generate action). Returns the count written to `out`.
pub fn read_extra<S: Storage>(fs: &mut Fs<S>, out: &mut [PivSlot]) -> usize {
    let mut n = 0;
    for slot in core::iter::once(SLOT_ATTESTATION).chain(SLOT_RETIRED_FIRST..=SLOT_RETIRED_LAST) {
        if n >= out.len() {
            break;
        }
        let s = read_slot(fs, slot);
        if s.present || s.cert {
            out[n] = s;
            n += 1;
        }
    }
    n
}

/// How many entries the "Retired & F9" screen will show (populated retired slots +
/// F9), for the count on the PIV overview row.
pub fn extra_count<S: Storage>(fs: &mut Fs<S>) -> u8 {
    let mut out = [PivSlot::default(); MAX_EXTRA_SLOTS];
    read_extra(fs, &mut out) as u8
}

/// The lowest-numbered retired slot (82–95) holding neither a key nor a certificate,
/// or `None` when all twenty are taken — the target for the on-device generate action.
/// The predicate is [`read_extra`]'s (`present || cert`) on purpose: keying off the key
/// alone offered a slot whose certificate the generate would then overwrite, on a screen
/// that promises it erases nothing.
pub fn next_free_retired<S: Storage>(fs: &mut Fs<S>) -> Option<u8> {
    (SLOT_RETIRED_FIRST..=SLOT_RETIRED_LAST).find(|&slot| {
        !fs.has_key(key_fid(slot)) && !cert_fid_for_slot(slot).is_some_and(|f| fs.has_data(f))
    })
}

/// Generate an instant (EC / Ed25519 / X25519) key on-device into an empty retired slot.
/// Physical presence at the trusted display authorises it (no management-key auth, unlike
/// the host GENERATE), and it is restricted to retired slots that hold no key. The slot
/// comes from [`next_free_retired`], which also skips a slot holding only a certificate —
/// this call would replace that certificate with the self-signed one it writes. Writes the
/// sealed key, that certificate (none for X25519) and the metadata, so the slot then looks
/// exactly like a host-generated one. RSA goes through [`store_retired_rsa`] (its prime
/// search runs in the firmware).
pub fn generate_slot_key<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    slot: u8,
    algo: u8,
) -> Result<(), Sw> {
    crate::keygen::generate_retired_ec(dev, fs, rng, slot, algo)
}

/// Persist a firmware-generated RSA key on-device into an empty retired slot — the RSA
/// companion to [`generate_slot_key`]. Same empty-retired-slot fence and the same writes
/// (sealed key, self-signed cert, metadata); the slow dual-core prime search runs in the
/// firmware before this is called, so the key arrives ready to store.
pub fn store_retired_rsa<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    slot: u8,
    key: &RsaKey,
) -> Result<(), Sw> {
    crate::keygen::store_retired_rsa(dev, fs, rng, slot, key)
}

/// Read the public state of the PIV applet for the trusted display.
pub fn read_info<S: Storage>(fs: &mut Fs<S>) -> PivInfo {
    let mut slots = [PivSlot::default(); 4];
    for (i, &slot) in PRIMARY_SLOTS.iter().enumerate() {
        slots[i] = read_slot(fs, slot);
    }

    let mut r = [0u8; 4];
    let (pin_retries, puk_retries) = match fs.read(EF_RETRIES, &mut r) {
        Some(n) if n >= 4 => (r[1], r[3]),
        _ => (DEFAULT_RETRIES, DEFAULT_RETRIES),
    };

    PivInfo {
        slots,
        pin_retries,
        puk_retries,
    }
}

#[cfg(test)]
#[path = "info_tests.rs"]
mod tests;
