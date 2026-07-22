// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Read-only key metadata for the trusted display. Every fact here is plaintext
//! or computed from plaintext — no DEK unseal, no PIN, no host session — so an
//! on-device screen can show the OpenPGP card's slots without ever touching a
//! secret. It mirrors what the GET DATA builder ([`crate::dobj`]) reads, but
//! returns typed values instead of TLV. The private key scalars and public
//! points are deliberately *not* exposed: the public point is reconstructed only
//! on GENERATE / INTERNAL AUTH after a PIN, so a passive read cannot show it.

use rsk_fs::{Fs, KeyFid, Storage};

use crate::consts::*;
use crate::keys::{Curve, curve_from_attr};

/// The three OpenPGP key slots (SIG, DEC, AUT), in card order.
pub const SLOTS: usize = 3;

/// Per-slot EF bases; slot `s` in `0..SLOTS` reads `base + s` (the SIG/DEC/AUT
/// FIDs are consecutive — see [`crate::consts`]).
const PK_FIDS: [KeyFid; SLOTS] = [EF_PK_SIG, EF_PK_DEC, EF_PK_AUT];

/// A slot's algorithm, decoded from its stored attribute (`[algo_id ‖ oid]`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SlotAlgo {
    /// No key in the slot.
    None,
    /// RSA with the given modulus size in bits.
    Rsa(u16),
    /// A supported EC curve.
    Ec(Curve),
    /// A key is present but its attribute is unrecognised.
    Unknown,
}

impl SlotAlgo {
    /// A short ASCII label for the slot row / detail (≤10 chars).
    pub fn label(self) -> &'static str {
        match self {
            SlotAlgo::None => "—",
            SlotAlgo::Rsa(1024) => "RSA 1024",
            SlotAlgo::Rsa(2048) => "RSA 2048",
            SlotAlgo::Rsa(3072) => "RSA 3072",
            SlotAlgo::Rsa(4096) => "RSA 4096",
            SlotAlgo::Rsa(_) => "RSA",
            SlotAlgo::Ec(Curve::P256) => "NIST P-256",
            SlotAlgo::Ec(Curve::P384) => "NIST P-384",
            SlotAlgo::Ec(Curve::P521) => "NIST P-521",
            SlotAlgo::Ec(Curve::Bp256) => "brainpoolP256r1",
            SlotAlgo::Ec(Curve::Bp384) => "brainpoolP384r1",
            SlotAlgo::Ec(Curve::K256) => "secp256k1",
            SlotAlgo::Ec(Curve::Ed25519) => "Ed25519",
            SlotAlgo::Ec(Curve::X25519) => "Cv25519",
            SlotAlgo::Unknown => "Key set",
        }
    }
}

/// What one OpenPGP slot holds, all read without a PIN.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SlotInfo {
    pub present: bool,
    pub algo: SlotAlgo,
    /// 20-byte SHA-1 key fingerprint, or `None` when unset (absent / all-zero).
    pub fingerprint: Option<[u8; 20]>,
    /// Whether a generation timestamp is recorded. The device has no real-time
    /// clock, so the value itself is meaningless to show — only presence is.
    pub created: bool,
    /// Whether the UIF touch policy gates use of the slot.
    pub touch: bool,
}

/// A read-only snapshot of the OpenPGP card's public state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OpenpgpInfo {
    /// SIG, DEC, AUT in card order.
    pub slots: [SlotInfo; SLOTS],
    /// PSO:CDS signature counter.
    pub sig_count: u32,
    /// Remaining PW1 (user) PIN attempts.
    pub pw1_retries: u8,
    /// Remaining PW3 (admin) PIN attempts.
    pub pw3_retries: u8,
}

impl OpenpgpInfo {
    /// How many of the three slots hold a key.
    pub fn key_count(&self) -> u8 {
        self.slots.iter().filter(|s| s.present).count() as u8
    }
}

fn slot_algo<S: Storage>(fs: &mut Fs<S>, slot: usize, present: bool) -> SlotAlgo {
    if !present {
        return SlotAlgo::None;
    }
    let mut buf = [0u8; 16];
    let attr = match fs.read(EF_ALGO_PRIV1 + slot as u16, &mut buf) {
        // `Storage::read` returns the value's FULL stored length, not the copied
        // count, so a DO longer than `buf` must be clamped before slicing — else a
        // PW3-written over-long record (PUT DATA caps nothing) panics here = brick.
        Some(n) if n >= 1 => &buf[..n.min(buf.len())],
        _ => return SlotAlgo::Rsa(2048),
    };
    match attr[0] {
        ALGO_RSA => {
            let bits = if attr.len() >= 3 {
                u16::from_be_bytes([attr[1], attr[2]])
            } else {
                0
            };
            SlotAlgo::Rsa(bits)
        }
        _ => match curve_from_attr(attr) {
            Some(c) => SlotAlgo::Ec(c),
            None => SlotAlgo::Unknown,
        },
    }
}

/// Read the public state of the OpenPGP applet for the trusted display.
pub fn read_info<S: Storage>(fs: &mut Fs<S>) -> OpenpgpInfo {
    let mut slots = [SlotInfo {
        present: false,
        algo: SlotAlgo::None,
        fingerprint: None,
        created: false,
        touch: false,
    }; SLOTS];
    for (s, slot) in slots.iter_mut().enumerate() {
        let present = fs.has_key(PK_FIDS[s]);
        let mut fp = [0u8; 20];
        let fingerprint = match fs.read(EF_FP_SIG + s as u16, &mut fp) {
            // Clamp the full-length read (see `slot_algo`) before slicing the
            // fixed buffer — an over-long stored DO must not panic.
            Some(n) if n > 0 && fp[..n.min(fp.len())].iter().any(|&b| b != 0) => Some(fp),
            _ => None,
        };
        let mut ts = [0u8; 4];
        let created = matches!(fs.read(EF_TS_SIG + s as u16, &mut ts), Some(n) if ts[..n.min(ts.len())].iter().any(|&b| b != 0));
        let mut uif = [0u8; 2];
        let touch =
            matches!(fs.read(EF_UIF_SIG + s as u16, &mut uif), Some(n) if n >= 1 && uif[0] != 0);
        *slot = SlotInfo {
            present,
            algo: slot_algo(fs, s, present),
            fingerprint,
            created,
            touch,
        };
    }

    let mut c = [0u8; 3];
    let sig_count = match fs.read(EF_SIG_COUNT, &mut c) {
        Some(3) => u32::from_be_bytes([0, c[0], c[1], c[2]]),
        _ => 0,
    };

    let mut pw = [0u8; 7];
    let (pw1_retries, pw3_retries) = match fs.read(EF_PW_PRIV, &mut pw) {
        Some(n) if n >= 7 => (pw[PW1_RETRY_IDX], pw[PW3_RETRY_IDX]),
        _ => (PW_RETRIES_DEFAULT, PW_RETRIES_DEFAULT),
    };

    OpenpgpInfo {
        slots,
        sig_count,
        pw1_retries,
        pw3_retries,
    }
}

/// Cap on each cardholder string surfaced to the display, matching the UI label
/// width — longer values are truncated at read time.
pub const CH_FIELD_MAX: usize = 48;

/// The card's public cardholder data objects, all plaintext (no PIN / DEK): the
/// cardholder name (`5B`), login data (`5E`), a URL (`5F50`) and the language
/// preference (`5F2D`). These are written with PUT DATA and stored verbatim, so a
/// passive read shows exactly what was provisioned; sanitise before display.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CardholderInfo {
    name: [u8; CH_FIELD_MAX],
    login: [u8; CH_FIELD_MAX],
    url: [u8; CH_FIELD_MAX],
    lang: [u8; 8],
    name_len: u8,
    login_len: u8,
    url_len: u8,
    lang_len: u8,
}

impl CardholderInfo {
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
    pub fn login(&self) -> &[u8] {
        &self.login[..self.login_len as usize]
    }
    pub fn url(&self) -> &[u8] {
        &self.url[..self.url_len as usize]
    }
    pub fn lang(&self) -> &[u8] {
        &self.lang[..self.lang_len as usize]
    }
    /// Whether the card carries any cardholder data at all.
    pub fn any(&self) -> bool {
        self.name_len != 0 || self.login_len != 0 || self.url_len != 0 || self.lang_len != 0
    }
}

/// Read one plaintext simple-DO into `buf`, returning the bytes copied (capped at
/// `buf.len()`). A zero-length or absent object yields `0`.
fn read_field<S: Storage>(fs: &mut Fs<S>, fid: u16, buf: &mut [u8]) -> u8 {
    let mut tmp = [0u8; CH_FIELD_MAX];
    match fs.read(fid, &mut tmp) {
        Some(n) if n > 0 => {
            let k = n.min(buf.len());
            buf[..k].copy_from_slice(&tmp[..k]);
            k as u8
        }
        _ => 0,
    }
}

/// Read the OpenPGP cardholder data objects for the trusted display.
pub fn read_cardholder<S: Storage>(fs: &mut Fs<S>) -> CardholderInfo {
    let mut info = CardholderInfo {
        name: [0; CH_FIELD_MAX],
        login: [0; CH_FIELD_MAX],
        url: [0; CH_FIELD_MAX],
        lang: [0; 8],
        name_len: 0,
        login_len: 0,
        url_len: 0,
        lang_len: 0,
    };
    info.name_len = read_field(fs, EF_CH_NAME, &mut info.name);
    info.login_len = read_field(fs, EF_LOGIN_DATA, &mut info.login);
    info.url_len = read_field(fs, EF_URI_URL, &mut info.url);
    info.lang_len = read_field(fs, EF_LANG_PREF, &mut info.lang);
    info
}

#[cfg(test)]
#[path = "info_tests.rs"]
mod tests;
