// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! On-card X.509 certificate generation for both card applets. The DER is
//! hand-built with a backward writer (content written right-to-left, each
//! container's length+tag prepended when closed), so no DER library is needed on
//! the device; host tests cross-check the output with `x509-parser` and verify
//! the signatures.
//!
//! Profile: X.509 v3, 20-byte random serial, validity 2024-03-25 → 2074-12-31,
//! names `C=ES, O=RS-Key, CN=<caller's>`, basicConstraints (CA when the caller
//! asks), a critical keyUsage on a CA (digitalSignature and keyCertSign) and none
//! on a leaf, SKI/AKI (SHA-1, RFC 5280 method 1), and any further non-critical
//! extensions the caller names — PIV's attestation statement is one such set. The
//! signer is an EC key, ECDSA over SHA-256 or SHA-384.
#![cfg_attr(not(test), no_std)]

use rsk_crypto::{sha1, sha256, sha384};
use rsk_ec::{Curve, EcError, MAX_EC_POINT, MAX_EC_SIG, PrivKey};
use rsk_sdk::{Rng, Sw};

/// Largest certificate the builder emits (an RSA-4096 SPKI + extensions + the
/// signature ≈ 1 KB, with margin).
pub const MAX_CERT: usize = 1536;

/// Largest DER ECDSA signature: `SEQ { INTEGER r, INTEGER s }` adds a tag and up to
/// two length bytes, and each INTEGER a tag, a length byte and a sign pad.
const MAX_ECDSA_DER: usize = MAX_EC_SIG + 9;

// OID content bytes.
const OID_EC_PUBKEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
const OID_P521: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x23];
const OID_SECP256K1: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x0A];
const OID_BP256R1: &[u8] = &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07];
const OID_BP384R1: &[u8] = &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B];
const OID_ECDSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
const OID_ECDSA_SHA384: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];
const OID_RSA_ENC: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
// RFC 8410 algorithm OIDs (id-Ed25519 1.3.101.112, id-X25519 1.3.101.110), the
// SPKI algorithm with absent parameters.
const OID_ED25519: &[u8] = &[0x2B, 0x65, 0x70];
const OID_X25519: &[u8] = &[0x2B, 0x65, 0x6E];
const OID_AT_COUNTRY: &[u8] = &[0x55, 0x04, 0x06];
const OID_AT_ORG: &[u8] = &[0x55, 0x04, 0x0A];
const OID_AT_CN: &[u8] = &[0x55, 0x04, 0x03];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x13];
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x0F];
const OID_SKI: &[u8] = &[0x55, 0x1D, 0x0E];
const OID_AKI: &[u8] = &[0x55, 0x1D, 0x23];

/// Why a certificate could not be built: the DER did not fit its buffer or names a
/// curve this profile has no OID for, or the signer's key refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Encoding,
    Ec(EcError),
}

impl Error {
    /// What a card applet answers: `EXEC_ERROR` for what the profile cannot encode,
    /// else its own status word for its signer's refusal.
    pub fn sw(self, ec: fn(EcError) -> Sw) -> Sw {
        match self {
            Error::Encoding => Sw::EXEC_ERROR,
            Error::Ec(e) => ec(e),
        }
    }
}

/// Backward DER writer: content grows from the end of the buffer toward the
/// front; `close` prepends the minimal length and the tag for everything
/// written since its `mark`.
struct DerRev<'a> {
    buf: &'a mut [u8],
    p: usize,
}

impl<'a> DerRev<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        let p = buf.len();
        DerRev { buf, p }
    }

    fn mark(&self) -> usize {
        self.p
    }

    fn raw(&mut self, b: &[u8]) -> Result<(), Error> {
        if self.p < b.len() {
            return Err(Error::Encoding);
        }
        self.p -= b.len();
        self.buf[self.p..self.p + b.len()].copy_from_slice(b);
        Ok(())
    }

    fn byte(&mut self, b: u8) -> Result<(), Error> {
        self.raw(&[b])
    }

    fn close(&mut self, tag: u8, mark: usize) -> Result<(), Error> {
        let len = mark - self.p;
        if len < 0x80 {
            self.byte(len as u8)?;
        } else if len < 0x100 {
            self.raw(&[0x81, len as u8])?;
        } else {
            self.raw(&[0x82, (len >> 8) as u8, len as u8])?;
        }
        self.byte(tag)
    }

    /// INTEGER from unsigned big-endian bytes (minimal, sign-safe).
    fn uint(&mut self, v: &[u8]) -> Result<(), Error> {
        let mut s = v;
        while s.len() > 1 && s[0] == 0 {
            s = &s[1..];
        }
        let m = self.mark();
        if s.is_empty() {
            self.byte(0)?;
        } else {
            self.raw(s)?;
            if s[0] & 0x80 != 0 {
                self.byte(0)?;
            }
        }
        self.close(0x02, m)
    }

    fn oid(&mut self, content: &[u8]) -> Result<(), Error> {
        let m = self.mark();
        self.raw(content)?;
        self.close(0x06, m)
    }

    fn written(&self) -> &[u8] {
        &self.buf[self.p..]
    }
}

/// The subject public key going into the certificate.
#[derive(Clone, Copy)]
pub enum Spki<'a> {
    Ec {
        curve: Curve,
        point: &'a [u8],
    },
    Rsa {
        n: &'a [u8],
        e: &'a [u8],
    },
    /// RFC 8410 raw key — Ed25519 (id-Ed25519) or X25519 (id-X25519). `point` is
    /// the 32-byte public key; the algorithm carries no parameters.
    Rfc8410 {
        curve: Curve,
        point: &'a [u8],
    },
}

/// What goes into one certificate besides its signer.
pub struct Cert<'a> {
    /// The subject's and the issuer's common names; the rest of each name is
    /// `C=ES, O=RS-Key`.
    pub subject_cn: &'a [u8],
    pub issuer_cn: &'a [u8],
    pub spki: Spki<'a>,
    /// The signer signs over SHA-384 rather than SHA-256.
    pub sha384: bool,
    /// `Some(pathlen)` marks a CA certificate, the only kind with a keyUsage. An
    /// attestation statement goes without, as a YubiKey's does: it says where a
    /// key came from, not what it is for.
    pub ca_pathlen: Option<u8>,
    /// Further non-critical extensions, `(OID content, extnValue content)` in DER
    /// order; they precede the profile's own.
    pub extra: &'a [(&'a [u8], &'a [u8])],
}

/// RDNSequence `C=ES, O=RS-Key, CN=<cn>` (written backward: CN, O, C).
fn name(w: &mut DerRev, cn: &[u8]) -> Result<(), Error> {
    fn rdn(w: &mut DerRev, oid: &[u8], string_tag: u8, value: &[u8]) -> Result<(), Error> {
        let m = w.mark();
        let mv = w.mark();
        w.raw(value)?;
        w.close(string_tag, mv)?;
        w.oid(oid)?;
        w.close(0x30, m)?; // AttributeTypeAndValue
        w.close(0x31, m) // RelativeDistinguishedName (SET)
    }
    let m = w.mark();
    rdn(w, OID_AT_CN, 0x0C, cn)?; // UTF8String
    rdn(w, OID_AT_ORG, 0x0C, b"RS-Key")?;
    rdn(w, OID_AT_COUNTRY, 0x13, b"ES")?; // PrintableString
    w.close(0x30, m)
}

fn spki(w: &mut DerRev, key: &Spki) -> Result<(), Error> {
    let m = w.mark();
    match key {
        Spki::Ec { curve, point } => {
            let mb = w.mark();
            w.raw(point)?;
            w.byte(0x00)?;
            w.close(0x03, mb)?;
            let ma = w.mark();
            w.oid(curve_oid(*curve)?)?;
            w.oid(OID_EC_PUBKEY)?;
            w.close(0x30, ma)?;
        }
        Spki::Rsa { n, e } => {
            let mb = w.mark();
            w.uint(e)?;
            w.uint(n)?;
            w.close(0x30, mb)?;
            w.byte(0x00)?;
            w.close(0x03, mb)?;
            let ma = w.mark();
            w.raw(&[0x05, 0x00])?;
            w.oid(OID_RSA_ENC)?;
            w.close(0x30, ma)?;
        }
        Spki::Rfc8410 { curve, point } => {
            // RFC 8410 §4: AlgorithmIdentifier is the bare OID (no parameters),
            // subjectPublicKey is the raw 32-byte key.
            let mb = w.mark();
            w.raw(point)?;
            w.byte(0x00)?;
            w.close(0x03, mb)?;
            let ma = w.mark();
            w.oid(oid_8410(*curve)?)?;
            w.close(0x30, ma)?;
        }
    }
    w.close(0x30, m)
}

/// Every short-Weierstrass curve an OpenPGP slot holds; PIV's two are the first.
fn curve_oid(c: Curve) -> Result<&'static [u8], Error> {
    match c {
        Curve::P256 => Ok(OID_P256),
        Curve::P384 => Ok(OID_P384),
        Curve::P521 => Ok(OID_P521),
        Curve::K256 => Ok(OID_SECP256K1),
        Curve::Bp256 => Ok(OID_BP256R1),
        Curve::Bp384 => Ok(OID_BP384R1),
        _ => Err(Error::Encoding),
    }
}

fn oid_8410(c: Curve) -> Result<&'static [u8], Error> {
    match c {
        Curve::Ed25519 => Ok(OID_ED25519),
        Curve::X25519 => Ok(OID_X25519),
        _ => Err(Error::Encoding),
    }
}

/// SHA-1 of the raw subject public key (point / RSAPublicKey DER) — the
/// SKI/AKI input (RFC 5280 method 1).
fn pub_hash(key: &Spki) -> Result<[u8; 20], Error> {
    match key {
        Spki::Ec { point, .. } | Spki::Rfc8410 { point, .. } => Ok(sha1(point)),
        Spki::Rsa { n, e } => {
            let mut tmp = [0u8; 600];
            let mut w = DerRev::new(&mut tmp);
            let m = w.mark();
            w.uint(e)?;
            w.uint(n)?;
            w.close(0x30, m)?;
            Ok(sha1(w.written()))
        }
    }
}

/// Wrap inner DER written since `mark` as extnValue, then prepend criticality
/// and the extension OID and close the Extension SEQUENCE.
fn finish_ext(w: &mut DerRev, oid: &[u8], critical: bool, mark: usize) -> Result<(), Error> {
    w.close(0x04, mark)?;
    if critical {
        w.raw(&[0x01, 0x01, 0xFF])?;
    }
    w.oid(oid)?;
    w.close(0x30, mark)
}

/// An extension whose value is the caller's bytes, taken as they are.
fn raw_ext(w: &mut DerRev, oid: &[u8], value: &[u8]) -> Result<(), Error> {
    let m = w.mark();
    w.raw(value)?;
    finish_ext(w, oid, false, m)
}

fn extensions(
    w: &mut DerRev,
    c: &Cert,
    subject_hash: &[u8; 20],
    issuer_hash: &[u8; 20],
) -> Result<(), Error> {
    let m_outer = w.mark();
    // DER order: [extra…,] BC, SKI, AKI[, KU] — written backward.
    if c.ca_pathlen.is_some() {
        // keyUsage, critical, and on a CA only — RFC 5280 §4.2.1.3: "if keyCertSign
        // is asserted, cA MUST also be asserted", which every leaf broke once
        // (audit run-34 #36).
        let m = w.mark();
        w.raw(&[0x03, 0x02, 0x02, 0x84])?; // digitalSignature | keyCertSign
        finish_ext(w, OID_KEY_USAGE, true, m)?;
    }
    {
        // AKI: SEQ { [0] issuer key id }.
        let m = w.mark();
        let mi = w.mark();
        w.raw(issuer_hash)?;
        w.close(0x80, mi)?;
        w.close(0x30, mi)?;
        finish_ext(w, OID_AKI, false, m)?;
    }
    {
        // SKI: OCTET STRING { subject key id }.
        let m = w.mark();
        let mi = w.mark();
        w.raw(subject_hash)?;
        w.close(0x04, mi)?;
        finish_ext(w, OID_SKI, false, m)?;
    }
    {
        // basicConstraints; critical exactly when CA.
        let m = w.mark();
        let mi = w.mark();
        if let Some(pathlen) = c.ca_pathlen {
            w.uint(&[pathlen])?;
            w.raw(&[0x01, 0x01, 0xFF])?;
        }
        w.close(0x30, mi)?;
        finish_ext(w, OID_BASIC_CONSTRAINTS, c.ca_pathlen.is_some(), m)?;
    }
    for (oid, value) in c.extra.iter().rev() {
        raw_ext(w, oid, value)?;
    }
    w.close(0x30, m_outer)?;
    w.close(0xA3, m_outer) // [3] EXPLICIT
}

fn sigalg(w: &mut DerRev, sha384: bool) -> Result<(), Error> {
    let m = w.mark();
    w.oid(if sha384 {
        OID_ECDSA_SHA384
    } else {
        OID_ECDSA_SHA256
    })?;
    w.close(0x30, m)
}

/// Build the certificate and sign it with `signer`, the subject's own key
/// (self-signed) or an issuer's, into `out` (front-aligned); returns its length.
pub fn build(
    c: &Cert,
    signer: &PrivKey,
    rng: &mut dyn Rng,
    out: &mut [u8],
) -> Result<usize, Error> {
    if out.len() < MAX_CERT {
        return Err(Error::Encoding);
    }

    let subject_hash = pub_hash(&c.spki)?;
    let issuer_hash = {
        let mut pt = [0u8; MAX_EC_POINT];
        let n = signer.public_point(&mut pt).map_err(Error::Ec)?;
        sha1(&pt[..n])
    };

    let mut serial = [0u8; 20];
    rng.fill(&mut serial);
    serial[0] = (serial[0] & 0x7F) | 0x40; // positive, no leading-zero trim

    // --- TBSCertificate, built backward in its own buffer.
    let mut tbs_buf = [0u8; MAX_CERT];
    let tbs_start = {
        let mut w = DerRev::new(&mut tbs_buf);
        let m = w.mark();
        extensions(&mut w, c, &subject_hash, &issuer_hash)?;
        spki(&mut w, &c.spki)?;
        name(&mut w, c.subject_cn)?;
        {
            let mv = w.mark();
            let ma = w.mark();
            w.raw(b"20741231235959Z")?;
            w.close(0x18, ma)?; // GeneralizedTime (≥ 2050)
            let mb = w.mark();
            w.raw(b"240325000000Z")?;
            w.close(0x17, mb)?; // UTCTime (< 2050)
            w.close(0x30, mv)?;
        }
        name(&mut w, c.issuer_cn)?;
        sigalg(&mut w, c.sha384)?;
        w.uint(&serial)?;
        w.raw(&[0xA0, 0x03, 0x02, 0x01, 0x02])?; // [0] { INTEGER 2 } — v3
        w.close(0x30, m)?;
        w.p
    };
    let tbs_bytes = &tbs_buf[tbs_start..];

    // --- Signature over the TBS digest.
    let mut digest = [0u8; 48];
    let digest = if c.sha384 {
        digest.copy_from_slice(&sha384(tbs_bytes));
        &digest[..48]
    } else {
        digest[..32].copy_from_slice(&sha256(tbs_bytes));
        &digest[..32]
    };
    let mut sig = [0u8; MAX_ECDSA_DER];
    let sig_len = {
        let mut raw = [0u8; MAX_EC_SIG];
        let rn = signer.sign(digest, &mut raw).map_err(Error::Ec)?;
        ecdsa_der(&raw[..rn], &mut sig)?
    };

    // --- Certificate = SEQ { tbs, sigalg, BIT STRING sig }.
    let (start, end) = {
        let mut w = DerRev::new(out);
        let m = w.mark();
        let mb = w.mark();
        w.raw(&sig[..sig_len])?;
        w.byte(0x00)?;
        w.close(0x03, mb)?;
        sigalg(&mut w, c.sha384)?;
        w.raw(tbs_bytes)?;
        w.close(0x30, m)?;
        (w.p, w.buf.len())
    };
    out.copy_within(start..end, 0);
    Ok(end - start)
}

/// `value`, unsigned big-endian, as a minimal DER INTEGER at the front of `out`;
/// returns its length. Attestation statements carry a few as extension values.
pub fn der_uint(value: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let (start, end) = {
        let mut w = DerRev::new(out);
        w.uint(value)?;
        (w.p, w.buf.len())
    };
    out.copy_within(start..end, 0);
    Ok(end - start)
}

/// Raw `r ‖ s` → DER `SEQ { INTEGER r, INTEGER s }`, the form an X.509 signature
/// and a PIV GENERAL AUTHENTICATE answer both carry.
pub fn ecdsa_der(raw: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if raw.is_empty() || !raw.len().is_multiple_of(2) {
        return Err(Error::Encoding);
    }
    let half = raw.len() / 2;
    let (start, end) = {
        let mut w = DerRev::new(out);
        let m = w.mark();
        w.uint(&raw[half..])?;
        w.uint(&raw[..half])?;
        w.close(0x30, m)?;
        (w.p, w.buf.len())
    };
    out.copy_within(start..end, 0);
    Ok(end - start)
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
