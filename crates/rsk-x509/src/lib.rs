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
//! asks), a critical keyUsage (digitalSignature, plus keyCertSign on a CA;
//! keyAgreement alone for X25519), SKI/AKI (SHA-1, RFC 5280 method 1), and any
//! further non-critical extensions the caller names — PIV's attestation statement
//! is one such set.
#![cfg_attr(not(test), no_std)]

use rsk_crypto::{sha1, sha256, sha384};
use rsk_ec::{Curve, EcError, MAX_EC_POINT, MAX_EC_SIG, PrivKey};
use rsk_rsa::pkcs1v15::rsa_sign;
use rsk_rsa::{RsaError, RsaKey};
use rsk_sdk::Rng;

/// Largest certificate the builder emits (RSA-4096 SPKI + a 512-byte signature
/// + extensions ≈ 1.4 KB, with margin).
pub const MAX_CERT: usize = 1536;

// OID content bytes.
const OID_EC_PUBKEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_P384: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
const OID_ECDSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
const OID_ECDSA_SHA384: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];
const OID_RSA_ENC: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
const OID_RSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
// RFC 8410 algorithm OIDs (id-Ed25519 1.3.101.112, id-X25519 1.3.101.110); each
// is both the SPKI algorithm and, for Ed25519, the signatureAlgorithm — with
// absent parameters in either role.
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
    Rsa(RsaError),
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

/// Who signs: the subject's own key (self-signed) or an issuer's.
pub enum Signer<'a> {
    Ec(&'a PrivKey),
    Rsa(&'a RsaKey),
    /// A pure-Ed25519 signer (PureEdDSA over the whole TBS, never a digest).
    Ed25519(&'a PrivKey),
}

/// What goes into one certificate besides its signer.
pub struct Cert<'a> {
    /// The subject's and the issuer's common names; the rest of each name is
    /// `C=ES, O=RS-Key`.
    pub subject_cn: &'a [u8],
    pub issuer_cn: &'a [u8],
    pub spki: Spki<'a>,
    /// An EC signer signs over SHA-384 rather than SHA-256; an RSA signer always
    /// signs PKCS#1 v1.5 over SHA-256.
    pub sha384: bool,
    /// `Some(pathlen)` marks a CA certificate.
    pub ca_pathlen: Option<u8>,
    /// Further non-critical extensions, `(OID content, extnValue content)` in DER
    /// order; they precede the four this profile always carries.
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

fn curve_oid(c: Curve) -> Result<&'static [u8], Error> {
    match c {
        Curve::P256 => Ok(OID_P256),
        Curve::P384 => Ok(OID_P384),
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
    // DER order: [extra…,] BC, SKI, AKI, KU — written backward.
    {
        // keyUsage, critical: keyAgreement for X25519, else digitalSignature, and
        // keyCertSign only on a CA — RFC 5280 §4.2.1.3: "if keyCertSign is asserted,
        // cA MUST also be asserted", which every leaf broke once (audit run-34 #36).
        let m = w.mark();
        let ku: &[u8] = if matches!(
            c.spki,
            Spki::Rfc8410 {
                curve: Curve::X25519,
                ..
            }
        ) {
            &[0x03, 0x02, 0x03, 0x08] // keyAgreement
        } else if c.ca_pathlen.is_some() {
            &[0x03, 0x02, 0x02, 0x84] // digitalSignature | keyCertSign
        } else {
            &[0x03, 0x02, 0x07, 0x80] // digitalSignature
        };
        w.raw(ku)?;
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

fn sigalg(w: &mut DerRev, signer: &Signer, sha384sig: bool) -> Result<(), Error> {
    let m = w.mark();
    match signer {
        Signer::Ec(_) => {
            w.oid(if sha384sig {
                OID_ECDSA_SHA384
            } else {
                OID_ECDSA_SHA256
            })?;
        }
        Signer::Rsa(_) => {
            w.raw(&[0x05, 0x00])?;
            w.oid(OID_RSA_SHA256)?;
        }
        // RFC 8410 §6: Ed25519 signatures carry id-Ed25519 with absent parameters.
        Signer::Ed25519(_) => {
            w.oid(OID_ED25519)?;
        }
    }
    w.close(0x30, m)
}

/// Hands the applet-tier randomness seam to `rsk-rsa`, which declares its own.
struct RsaRng<'a>(&'a mut dyn Rng);

impl rsk_rsa::Rng for RsaRng<'_> {
    fn fill(&mut self, buf: &mut [u8]) {
        self.0.fill(buf);
    }
}

/// Build and sign the certificate into `out` (front-aligned); returns its
/// length.
pub fn build(c: &Cert, signer: &Signer, rng: &mut dyn Rng, out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < MAX_CERT {
        return Err(Error::Encoding);
    }
    let sha384sig = c.sha384 && !matches!(signer, Signer::Rsa(_));

    let subject_hash = pub_hash(&c.spki)?;
    let issuer_hash = match signer {
        Signer::Ec(k) | Signer::Ed25519(k) => {
            let mut pt = [0u8; MAX_EC_POINT];
            let n = k.public_point(&mut pt).map_err(Error::Ec)?;
            sha1(&pt[..n])
        }
        Signer::Rsa(k) => {
            let n = k.n_be();
            let e = k.e_be();
            pub_hash(&Spki::Rsa { n: &n, e: &e })?
        }
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
        sigalg(&mut w, signer, sha384sig)?;
        w.uint(&serial)?;
        w.raw(&[0xA0, 0x03, 0x02, 0x01, 0x02])?; // [0] { INTEGER 2 } — v3
        w.close(0x30, m)?;
        w.p
    };
    let tbs_bytes = &tbs_buf[tbs_start..];

    // --- Signature over the TBS digest.
    let mut digest = [0u8; 48];
    let digest = if sha384sig {
        digest.copy_from_slice(&sha384(tbs_bytes));
        &digest[..48]
    } else {
        digest[..32].copy_from_slice(&sha256(tbs_bytes));
        &digest[..32]
    };
    let mut sig = [0u8; 512];
    let sig_len = match signer {
        Signer::Ec(k) => {
            let mut raw = [0u8; MAX_EC_SIG];
            let rn = k.sign(digest, &mut raw).map_err(Error::Ec)?;
            ecdsa_der(&raw[..rn], &mut sig)?
        }
        Signer::Rsa(k) => {
            rsa_sign(k, digest, &mut RsaRng(&mut *rng), &mut sig).map_err(Error::Rsa)?
        }
        // PureEdDSA signs the whole TBS, not a digest; the 64-byte signature
        // goes straight into the BIT STRING (no ASN.1 wrapping).
        Signer::Ed25519(k) => k.sign(tbs_bytes, &mut sig).map_err(Error::Ec)?,
    };

    // --- Certificate = SEQ { tbs, sigalg, BIT STRING sig }.
    let (start, end) = {
        let mut w = DerRev::new(out);
        let m = w.mark();
        let mb = w.mark();
        w.raw(&sig[..sig_len])?;
        w.byte(0x00)?;
        w.close(0x03, mb)?;
        sigalg(&mut w, signer, sha384sig)?;
        w.raw(tbs_bytes)?;
        w.close(0x30, m)?;
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
