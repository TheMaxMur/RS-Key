// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! PIV's certificates, built by `rsk-x509`: names `RS-Key PIV {Slot|Attestation} %X`,
//! SHA-384 for `ECCP384` slots, and on attestation certs the Yubico OIDs
//! 1.3.6.1.4.1.41482.3.3 (firmware version), .3.7 (serial, raw little-endian), .3.8
//! (pin/touch policy) and .3.9 (form factor), as a YubiKey's PIV attestation carries.

use rsk_sdk::Rng;
use rsk_sdk::Sw;
pub use rsk_x509::{MAX_CERT, Signer, Spki};

use crate::files::{ALGO_ECCP384, SLOT_ATTESTATION};

const OID_YK_FIRMWARE: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x03, 0x03];
const OID_YK_SERIAL: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x03, 0x07];
const OID_YK_POLICY: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x03, 0x08];
const OID_YK_FORMFACTOR: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x03, 0x09];

/// Yubico attestation-statement extensions.
pub struct AttestExt {
    pub firmware: [u8; 3],
    /// Raw little-endian device serial.
    pub serial_le: [u8; 4],
    /// `[pin_policy, touch_policy]` from the slot metadata.
    pub policy: [u8; 2],
}

pub struct CertParams<'a> {
    pub subject_slot: u8,
    /// The slot's PIV algorithm id — selects SHA-384 for `ECCP384`, SHA-256
    /// otherwise.
    pub algo: u8,
    pub spki: Spki<'a>,
    /// `Some` ⇒ an attestation certificate (subject "Attestation %X", issuer
    /// "Slot F9", Yubico extensions, no keyUsage); `None` ⇒ self-signed slot
    /// certificate.
    pub attestation: Option<AttestExt>,
    /// `Some(pathlen)` marks a CA certificate (the F9 self-cert uses 1).
    pub ca_pathlen: Option<u8>,
}

fn slot_label(attestation: bool, slot: u8) -> ([u8; 40], usize) {
    let mut buf = [0u8; 40];
    let prefix: &[u8] = if attestation {
        b"RS-Key PIV Attestation "
    } else {
        b"RS-Key PIV Slot "
    };
    buf[..prefix.len()].copy_from_slice(prefix);
    let mut n = prefix.len();
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    if slot >= 0x10 {
        buf[n] = HEX[(slot >> 4) as usize];
        n += 1;
    }
    buf[n] = HEX[(slot & 0xF) as usize];
    (buf, n + 1)
}

fn x509_sw(e: rsk_x509::Error) -> Sw {
    e.sw(crate::ec_sw, crate::rsa_sw)
}

/// Build and sign the certificate into `out` (front-aligned); returns its
/// length.
pub fn build_cert(
    p: &CertParams,
    signer: &Signer,
    rng: &mut dyn Rng,
    out: &mut [u8],
) -> Result<usize, Sw> {
    let (subject_cn, subject_cn_len) = slot_label(p.attestation.is_some(), p.subject_slot);
    let (issuer_cn, issuer_cn_len) = if p.attestation.is_some() {
        slot_label(false, SLOT_ATTESTATION)
    } else {
        (subject_cn, subject_cn_len)
    };
    let yubico: [(&[u8], &[u8]); 4];
    let extra: &[(&[u8], &[u8])] = match &p.attestation {
        Some(att) => {
            yubico = [
                (OID_YK_FIRMWARE, &att.firmware),
                (OID_YK_SERIAL, &att.serial_le),
                (OID_YK_POLICY, &att.policy),
                (OID_YK_FORMFACTOR, &[rsk_sdk::FORM_FACTOR]),
            ];
            &yubico
        }
        None => &[],
    };
    let cert = rsk_x509::Cert {
        subject_cn: &subject_cn[..subject_cn_len],
        issuer_cn: &issuer_cn[..issuer_cn_len],
        spki: p.spki,
        sha384: p.algo == ALGO_ECCP384,
        ca_pathlen: p.ca_pathlen,
        key_usage: p.attestation.is_none(),
        extra,
    };
    rsk_x509::build(&cert, signer, rng, out).map_err(x509_sw)
}

/// DER ECDSA response for GENERAL AUTHENTICATE.
pub fn ecdsa_sig_der(raw: &[u8], out: &mut [u8]) -> Result<usize, Sw> {
    rsk_x509::ecdsa_der(raw, out).map_err(x509_sw)
}
