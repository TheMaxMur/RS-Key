// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! PIV's certificates, built by `rsk-x509`: names `RS-Key PIV {Slot|Attestation} %X`,
//! SHA-384 for `ECCP384` slots, and on attestation certs the Yubico OIDs
//! 1.3.6.1.4.1.41482.3.3 (firmware version), .3.7 (serial, raw little-endian), .3.8
//! (pin/touch policy) and .3.9 (form factor), as a YubiKey's PIV attestation carries.

use rsk_ec::PrivKey;
use rsk_sdk::Rng;
use rsk_sdk::Sw;
use rsk_sdk::tlv::{Tlv, find_tag};
pub use rsk_x509::{MAX_CERT, Spki};

use crate::files::{ALGO_ECCP384, SLOT_ATTESTATION};

const OID_YK_FIRMWARE: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x03, 0x03];
const OID_YK_SERIAL: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x03, 0x07];
const OID_YK_POLICY: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x03, 0x08];
const OID_YK_FORMFACTOR: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x03, 0x09];
const V3_SPKI_FIELD: usize = 6;

/// The subject point in our device-owned v3 F9 object; not certificate validation.
pub(crate) fn attestation_point(object: &[u8]) -> Option<&[u8]> {
    let der = find_tag(object, 0x70)?;
    let certificate = find_tag(der, 0x30)?;
    let tbs = find_tag(certificate, 0x30)?;
    let (tag, spki) = Tlv::new(tbs).nth(V3_SPKI_FIELD)?;
    if tag != 0x30 {
        return None;
    }
    find_tag(spki, 3)?.strip_prefix(&[0])
}

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
    /// "Slot F9", Yubico extensions); `None` ⇒ the F9 CA's own, self-signed.
    pub attestation: Option<AttestExt>,
    /// `Some(pathlen)` marks a CA certificate, the only kind with a keyUsage (the
    /// F9 self-cert uses 1).
    pub ca_pathlen: Option<u8>,
}

fn slot_label(attestation: bool, slot: u8) -> ([u8; 40], usize) {
    let mut buf = [0u8; 40];
    let prefix: &[u8] = if attestation {
        b"RS-Key PIV Attestation "
    } else {
        b"RS-Key PIV Slot "
    };
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let digit = |nibble: u8| HEX.get(usize::from(nibble)).copied().unwrap_or_default();
    let hex = [digit(slot >> 4), digit(slot & 0xF)];
    let digits = if slot >= 0x10 { &hex[..] } else { &hex[1..] };
    let mut n = 0;
    for (dst, &b) in buf.iter_mut().zip(prefix.iter().chain(digits)) {
        *dst = b;
        n += 1;
    }
    (buf, n)
}

fn x509_sw(e: rsk_x509::Error) -> Sw {
    e.sw(crate::ec_sw)
}

/// Build and sign the certificate into `out` (front-aligned); returns its
/// length.
pub fn build_cert(
    p: &CertParams,
    signer: &PrivKey,
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
        subject_cn: subject_cn.get(..subject_cn_len).unwrap_or_default(),
        issuer_cn: issuer_cn.get(..issuer_cn_len).unwrap_or_default(),
        spki: p.spki,
        sha384: p.algo == ALGO_ECCP384,
        ca_pathlen: p.ca_pathlen,
        extra,
    };
    rsk_x509::build(&cert, signer, rng, out).map_err(x509_sw)
}

/// DER ECDSA response for GENERAL AUTHENTICATE.
pub fn ecdsa_sig_der(raw: &[u8], out: &mut [u8]) -> Result<usize, Sw> {
    rsk_x509::ecdsa_der(raw, out).map_err(x509_sw)
}
