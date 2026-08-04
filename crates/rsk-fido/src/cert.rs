// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Minimal allocation-free DER encoder for the device attestation certificate, a
//! self-signed P-256 X.509 v3 cert. It is the `x5c` leaf of every packed
//! attestation and the certificate a U2F registration carries. Every field except
//! the 65-byte subject public key, the 16-byte serial and the signature is fixed,
//! so the TBSCertificate is a constant-length template (397 content bytes).

use crate::consts::AAGUID;
use crate::ec::{MAX_DER_SIG, P256Key};

// [0] EXPLICIT version v3 (INTEGER 2).
const VERSION: &[u8] = &[0xA0, 0x03, 0x02, 0x01, 0x02];
// AlgorithmIdentifier ecdsa-with-SHA256 (OID 1.2.840.10045.4.3.2).
const SIG_ALG: &[u8] = &[
    0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,
];
// Name = SEQUENCE{ C, O, OU, CN }. WebAuthn §8.2.1 requires all four on a packed
// x5c leaf, with OU the literal "Authenticator Attestation" and C a two-character
// ISO 3166 code; RP libraries reject the registration outright when one is absent.
// `XX` is the user-assigned code — RS-Key has no incorporating country.
const NAME: &[u8] = &[
    0x30, 0x59, // SEQUENCE, 89 content bytes
    0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, b'X', b'X', // C
    0x31, 0x0F, 0x30, 0x0D, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x06, // O
    b'R', b'S', b'-', b'K', b'e', b'y', //
    0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x19, // OU
    b'A', b'u', b't', b'h', b'e', b'n', b't', b'i', b'c', b'a', b't', b'o', b'r', b' ', //
    b'A', b't', b't', b'e', b's', b't', b'a', b't', b'i', b'o', b'n', //
    0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0C, // CN
    b'R', b'S', b'-', b'K', b'e', b'y', b' ', b'F', b'I', b'D', b'O', b'2',
];
// Extensions [3]: basicConstraints (critical, cA absent = false) and
// id-fido-gen-ce-aaguid (1.3.6.1.4.1.45724.1.1.4), which carries the AAGUID that
// follows this prefix and must equal the one in authData (§8.2.1).
const EXT_PREFIX: &[u8] = &[
    0xA3, 0x33, 0x30, 0x31, // [3] EXPLICIT { SEQUENCE, 49 content bytes }
    0x30, 0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x02, 0x30, 0x00, 0x30, 0x21,
    0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xE5, 0x1C, 0x01, 0x01, 0x04, 0x04, 0x12, 0x04,
    0x10,
];
// Validity = SEQUENCE{ GeneralizedTime notBefore, notAfter }.
const VALIDITY: &[u8] = &[
    0x30, 0x22, 0x18, 0x0F, b'2', b'0', b'2', b'2', b'0', b'9', b'0', b'1', b'0', b'0', b'0', b'0',
    b'0', b'0', b'Z', 0x18, 0x0F, b'2', b'0', b'7', b'2', b'0', b'8', b'3', b'1', b'2', b'3', b'5',
    b'9', b'5', b'9', b'Z',
];
// SubjectPublicKeyInfo header up to the BIT STRING contents: SEQ{ SEQ{ ecPublicKey
// (1.2.840.10045.2.1), prime256v1 (1.2.840.10045.3.1.7) }, BIT STRING 0x00 ‖ … }.
const SPKI_PREFIX: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
    0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// TBSCertificate length (header `30 82 01 8D` + 397 content bytes).
const TBS_LEN: usize = 401;

/// Offset of the 16-byte serial in the DER, past the cert and TBS headers and
/// `VERSION ‖ 02 10`.
pub(crate) const SERIAL_OFF: usize = 4 + 4 + VERSION.len() + 2;
/// Offset of the 65-byte uncompressed SPKI point (`04 ‖ x ‖ y`). Anchored to the
/// tail like the AAGUID check, so a change to any earlier field cannot silently
/// slide it.
const SPKI_POINT_OFF: usize = 4 + TBS_LEN - EXT_PREFIX.len() - AAGUID.len() - 65;

const _: () = assert!(
    SPKI_POINT_OFF
        == 4 + 4
            + VERSION.len()
            + 2
            + 16
            + SIG_ALG.len()
            + NAME.len()
            + VALIDITY.len()
            + NAME.len()
            + SPKI_PREFIX.len()
);

/// Is `serial` a minimally-encoded DER INTEGER body? X.690 §8.3.2 forbids a
/// leading `0x00` followed by a byte with its high bit clear, and strict parsers
/// (Go `crypto/x509`, OpenSSL, rust-asn1) reject the certificate outright.
fn serial_minimal(serial: &[u8; 16]) -> bool {
    serial[0] != 0x00 || serial[1] >= 0x80
}

/// Does `cert` come from the current template **and** certify `key`? Devices
/// provisioned before the §8.2.1 subject/extension rework carry a shorter TBS, a
/// build-time AAGUID override leaves the extension stale, a non-minimal serial
/// makes it unparseable, and a torn seed replacement leaves it certifying a
/// superseded key; every one of those must be rebuilt (audit run-32).
pub fn matches_template(cert: &[u8], key: &P256Key) -> bool {
    if cert.len() <= 4 + TBS_LEN
        || cert[4..8] != [0x30, 0x82, 0x01, 0x8D]
        || cert[4 + TBS_LEN - 16..4 + TBS_LEN] != AAGUID
    {
        return false;
    }
    let mut serial = [0u8; 16];
    serial.copy_from_slice(&cert[SERIAL_OFF..SERIAL_OFF + 16]);
    if !serial_minimal(&serial) {
        return false;
    }
    // The freshness check has to be a key binding, not just a shape check: a cert
    // that does not certify the key that signs is silently rejected by every RP.
    let (x, y) = key.public_xy();
    cert[SPKI_POINT_OFF] == 0x04
        && cert[SPKI_POINT_OFF + 1..SPKI_POINT_OFF + 33] == x
        && cert[SPKI_POINT_OFF + 33..SPKI_POINT_OFF + 65] == y
}

/// Build the self-signed attestation certificate for `key` into `out`; returns its
/// DER length. `serial` is 16 random bytes whose leading octet the caller
/// constrains to `0x01..=0x7F` — positive *and* minimally encoded, since the
/// template's INTEGER is fixed-width and cannot shorten. `out` should hold ≥ 512
/// bytes.
pub fn build_attestation_cert(key: &P256Key, serial: &[u8; 16], out: &mut [u8]) -> Option<usize> {
    if !serial_minimal(serial) || serial[0] & 0x80 != 0 {
        return None;
    }
    let (x, y) = key.public_xy();

    // --- TBSCertificate (fixed TBS_LEN bytes) ---
    let mut tbs = [0u8; TBS_LEN];
    let mut p = 0;
    let put = |dst: &mut [u8; TBS_LEN], pos: &mut usize, b: &[u8]| {
        dst[*pos..*pos + b.len()].copy_from_slice(b);
        *pos += b.len();
    };
    put(&mut tbs, &mut p, &[0x30, 0x82, 0x01, 0x8D]); // SEQUENCE, 397 content bytes
    put(&mut tbs, &mut p, VERSION);
    put(&mut tbs, &mut p, &[0x02, 0x10]); // INTEGER, 16 bytes
    put(&mut tbs, &mut p, serial);
    put(&mut tbs, &mut p, SIG_ALG);
    put(&mut tbs, &mut p, NAME); // issuer
    put(&mut tbs, &mut p, VALIDITY);
    put(&mut tbs, &mut p, NAME); // subject
    put(&mut tbs, &mut p, SPKI_PREFIX);
    put(&mut tbs, &mut p, &[0x04]); // uncompressed point marker
    put(&mut tbs, &mut p, &x);
    put(&mut tbs, &mut p, &y);
    put(&mut tbs, &mut p, EXT_PREFIX);
    put(&mut tbs, &mut p, &AAGUID);
    debug_assert_eq!(p, TBS_LEN);

    // --- sign the TBS, assemble the Certificate ---
    let mut sig = [0u8; MAX_DER_SIG];
    let sl = key.sign_der(&tbs, &mut sig);

    let content = TBS_LEN + SIG_ALG.len() + 3 + sl; // tbs + sigAlg + BITSTRING(03 len 00) + sig
    let total = 4 + content; // 30 82 hi lo
    if out.len() < total {
        return None;
    }
    let mut q = 0;
    out[q..q + 4].copy_from_slice(&[0x30, 0x82, (content >> 8) as u8, content as u8]);
    q += 4;
    out[q..q + TBS_LEN].copy_from_slice(&tbs);
    q += TBS_LEN;
    out[q..q + SIG_ALG.len()].copy_from_slice(SIG_ALG);
    q += SIG_ALG.len();
    out[q..q + 3].copy_from_slice(&[0x03, (1 + sl) as u8, 0x00]); // BIT STRING, 0 unused bits
    q += 3;
    out[q..q + sl].copy_from_slice(&sig[..sl]);
    q += sl;
    Some(q)
}

// ---- org attestation chain (EF_ATT_CHAIN) ----

/// Caps for an org-provisioned attestation chain (vendor ATT_IMPORT).
///
/// Derived from the store's own per-value ceiling, not picked: the packed record
/// is what lands in flash, so a cap chosen independently lets an in-spec import
/// fail at the write and strand a key with no chain (audit run-32).
pub(crate) const ATT_CHAIN_MAX_CERTS: usize = 4;
pub(crate) const ATT_CHAIN_MAX: usize = rsk_fs::MAX_VALUE_BYTES - 1 - 2 * ATT_CHAIN_MAX_CERTS;

/// Max packed `EF_ATT_CHAIN` record: `count(1) ‖ (len(2 LE) ‖ der)*`.
pub(crate) const ATT_CHAIN_REC_MAX: usize = ATT_CHAIN_MAX + 1 + 2 * ATT_CHAIN_MAX_CERTS;

const _: () = assert!(ATT_CHAIN_REC_MAX <= rsk_fs::MAX_VALUE_BYTES);

/// Total length of the DER TLV at the head of `b` (SEQUENCE tag), or `None`.
fn der_seq_len(b: &[u8]) -> Option<usize> {
    if b.len() < 2 || b[0] != 0x30 {
        return None;
    }
    match b[1] {
        l @ 0..=0x7F => Some(2 + l as usize),
        0x81 => (b.len() >= 3).then(|| 3 + b[2] as usize),
        0x82 => (b.len() >= 4).then(|| 4 + u16::from_be_bytes([b[2], b[3]]) as usize),
        _ => None, // > 64 KiB cannot be a sane certificate
    }
}

/// Validate a leaf-first concatenation of DER certificates and pack it into
/// the `EF_ATT_CHAIN` layout: `count(1) ‖ (len(2 LE) ‖ der)*`. Framing only —
/// the import channel is authenticated, and a key/cert mismatch is the org's
/// own first verification failure, not a parsing concern.
pub(crate) fn att_chain_pack(chain: &[u8], out: &mut [u8]) -> Option<usize> {
    if chain.is_empty() || chain.len() > ATT_CHAIN_MAX {
        return None;
    }
    let mut count = 0u8;
    let (mut src, mut dst) = (0usize, 1usize);
    while src < chain.len() {
        let l = der_seq_len(&chain[src..])?;
        if src + l > chain.len() || count as usize == ATT_CHAIN_MAX_CERTS || dst + 2 + l > out.len()
        {
            return None;
        }
        out[dst..dst + 2].copy_from_slice(&(l as u16).to_le_bytes());
        out[dst + 2..dst + 2 + l].copy_from_slice(&chain[src..src + l]);
        dst += 2 + l;
        src += l;
        count += 1;
    }
    out[0] = count;
    Some(dst)
}

/// Number of certificates in a packed chain.
pub(crate) fn att_chain_count(blob: &[u8]) -> u8 {
    blob.first().copied().unwrap_or(0)
}

/// Byte range of the `i`-th certificate in a packed chain.
pub(crate) fn att_chain_cert_range(blob: &[u8], i: u8) -> Option<(usize, usize)> {
    let mut off = 1usize;
    for idx in 0..att_chain_count(blob) {
        if off + 2 > blob.len() {
            return None;
        }
        let l = u16::from_le_bytes([blob[off], blob[off + 1]]) as usize;
        if off + 2 + l > blob.len() {
            return None;
        }
        if idx == i {
            return Some((off + 2, l));
        }
        off += 2 + l;
    }
    None
}

/// The `i`-th certificate of a packed chain.
pub(crate) fn att_chain_cert(blob: &[u8], i: u8) -> Option<&[u8]> {
    att_chain_cert_range(blob, i).map(|(o, l)| &blob[o..o + l])
}

#[cfg(test)]
#[path = "cert_tests.rs"]
mod tests;
