// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! On-card X.509 certificate generation. The DER is hand-built with a backward
//! writer (content written right-to-left, each container's length+tag prepended
//! when closed), so no DER library is needed on the device; host tests
//! cross-check the output with `x509-parser` and verify the signatures.
//!
//! Profile: X.509 v3, 20-byte random serial, validity 2024-03-25 → 2074-12-31,
//! names `C=ES, O=RS-Key, CN=RS-Key PIV {Slot|Attestation} %X`,
//! basicConstraints (CA for the F9 self-cert), keyUsage =
//! digitalSignature|keyCertSign (critical), SKI/AKI (SHA-1, RFC 5280 method 1),
//! and on attestation certs the Yubico OIDs 1.3.6.1.4.1.41482.3.3 (firmware
//! version), .3.7 (serial, raw little-endian), .3.8 (pin/touch policy) and
//! .3.9 (form factor).

use rsa::RsaPrivateKey;
use rsa::traits::PublicKeyParts;
use rsk_crypto::{sha1, sha256, sha384};
use rsk_openpgp::Rng;
use rsk_openpgp::keys::{Curve, PrivKey};
use rsk_rsa::pkcs1v15::rsa_sign;
use rsk_sdk::Sw;

use crate::files::{ALGO_ECCP384, MAX_EC_POINT, SLOT_ATTESTATION};

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
const OID_YK_FIRMWARE: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x03, 0x03];
const OID_YK_SERIAL: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x03, 0x07];
const OID_YK_POLICY: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x03, 0x08];
const OID_YK_FORMFACTOR: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x03, 0x09];

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

    fn raw(&mut self, b: &[u8]) -> Result<(), Sw> {
        if self.p < b.len() {
            return Err(Sw::EXEC_ERROR);
        }
        self.p -= b.len();
        self.buf[self.p..self.p + b.len()].copy_from_slice(b);
        Ok(())
    }

    fn byte(&mut self, b: u8) -> Result<(), Sw> {
        self.raw(&[b])
    }

    fn close(&mut self, tag: u8, mark: usize) -> Result<(), Sw> {
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
    fn uint(&mut self, v: &[u8]) -> Result<(), Sw> {
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

    fn oid(&mut self, content: &[u8]) -> Result<(), Sw> {
        let m = self.mark();
        self.raw(content)?;
        self.close(0x06, m)
    }

    fn written(&self) -> &[u8] {
        &self.buf[self.p..]
    }
}

/// The subject public key going into the certificate.
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

/// Who signs: the slot's own key (self-signed) or the F9 attestation key.
pub enum Signer<'a> {
    Ec(&'a PrivKey),
    Rsa(&'a RsaPrivateKey),
    /// A pure-Ed25519 signer (PureEdDSA over the whole TBS, never a digest).
    Ed25519(&'a PrivKey),
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
    /// "Slot F9", Yubico extensions); `None` ⇒ self-signed slot certificate.
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

/// RDNSequence `C=ES, O=RS-Key, CN=<cn>` (written backward: CN, O, C).
fn name(w: &mut DerRev, cn: &[u8]) -> Result<(), Sw> {
    fn rdn(w: &mut DerRev, oid: &[u8], string_tag: u8, value: &[u8]) -> Result<(), Sw> {
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

fn spki(w: &mut DerRev, key: &Spki) -> Result<(), Sw> {
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

fn curve_oid(c: Curve) -> Result<&'static [u8], Sw> {
    match c {
        Curve::P256 => Ok(OID_P256),
        Curve::P384 => Ok(OID_P384),
        _ => Err(Sw::EXEC_ERROR),
    }
}

fn oid_8410(c: Curve) -> Result<&'static [u8], Sw> {
    match c {
        Curve::Ed25519 => Ok(OID_ED25519),
        Curve::X25519 => Ok(OID_X25519),
        _ => Err(Sw::EXEC_ERROR),
    }
}

/// SHA-1 of the raw subject public key (point / RSAPublicKey DER) — the
/// SKI/AKI input (RFC 5280 method 1).
fn pub_hash(key: &Spki) -> Result<[u8; 20], Sw> {
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
fn finish_ext(w: &mut DerRev, oid: &[u8], critical: bool, mark: usize) -> Result<(), Sw> {
    w.close(0x04, mark)?;
    if critical {
        w.raw(&[0x01, 0x01, 0xFF])?;
    }
    w.oid(oid)?;
    w.close(0x30, mark)
}

/// An extension whose value is opaque bytes (the Yubico statement OIDs).
fn raw_ext(w: &mut DerRev, oid: &[u8], value: &[u8]) -> Result<(), Sw> {
    let m = w.mark();
    w.raw(value)?;
    finish_ext(w, oid, false, m)
}

fn extensions(
    w: &mut DerRev,
    p: &CertParams,
    subject_hash: &[u8; 20],
    issuer_hash: &[u8; 20],
) -> Result<(), Sw> {
    let m_outer = w.mark();
    // DER order: [Yubico…,] BC, SKI, AKI, KU — written backward.
    {
        // keyUsage, critical: a key-agreement key (X25519) advertises keyAgreement
        // (bit 4); a signing key advertises digitalSignature, and keyCertSign only
        // when it really is a CA. RFC 5280 §4.2.1.3 makes that conditional a MUST —
        // "if keyCertSign is asserted, cA MUST also be asserted" — and it was on
        // every leaf, whose basicConstraints says `cA=FALSE` (audit run-34 #36).
        let m = w.mark();
        let ku: &[u8] = if matches!(
            p.spki,
            Spki::Rfc8410 {
                curve: Curve::X25519,
                ..
            }
        ) {
            &[0x03, 0x02, 0x03, 0x08] // keyAgreement
        } else if p.ca_pathlen.is_some() {
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
        if let Some(pathlen) = p.ca_pathlen {
            w.uint(&[pathlen])?;
            w.raw(&[0x01, 0x01, 0xFF])?;
        }
        w.close(0x30, mi)?;
        finish_ext(w, OID_BASIC_CONSTRAINTS, p.ca_pathlen.is_some(), m)?;
    }
    if let Some(att) = &p.attestation {
        raw_ext(w, OID_YK_FORMFACTOR, &[0x01])?;
        raw_ext(w, OID_YK_POLICY, &att.policy)?;
        raw_ext(w, OID_YK_SERIAL, &att.serial_le)?;
        raw_ext(w, OID_YK_FIRMWARE, &att.firmware)?;
    }
    w.close(0x30, m_outer)?;
    w.close(0xA3, m_outer) // [3] EXPLICIT
}

fn sigalg(w: &mut DerRev, signer: &Signer, sha384sig: bool) -> Result<(), Sw> {
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

/// Build and sign the certificate into `out` (front-aligned); returns its
/// length.
pub fn build_cert(
    p: &CertParams,
    signer: &Signer,
    rng: &mut dyn Rng,
    out: &mut [u8],
) -> Result<usize, Sw> {
    if out.len() < MAX_CERT {
        return Err(Sw::EXEC_ERROR);
    }
    // SHA-384 for ECCP384 slots, SHA-256 otherwise; RSA always signs PKCS#1
    // v1.5 with SHA-256.
    let sha384sig = p.algo == ALGO_ECCP384 && !matches!(signer, Signer::Rsa(_));

    let subject_hash = pub_hash(&p.spki)?;
    let issuer_hash = match signer {
        Signer::Ec(k) | Signer::Ed25519(k) => {
            let mut pt = [0u8; MAX_EC_POINT];
            let n = k.public_point(&mut pt)?;
            sha1(&pt[..n])
        }
        Signer::Rsa(k) => {
            let n = k.n().to_bytes_be();
            let e = k.e().to_bytes_be();
            pub_hash(&Spki::Rsa { n: &n, e: &e })?
        }
    };

    let mut serial = [0u8; 20];
    rng.fill(&mut serial);
    serial[0] = (serial[0] & 0x7F) | 0x40; // positive, no leading-zero trim

    let (subject_cn, subject_cn_len) = slot_label(p.attestation.is_some(), p.subject_slot);
    let (issuer_cn, issuer_cn_len) = if p.attestation.is_some() {
        slot_label(false, SLOT_ATTESTATION)
    } else {
        (subject_cn, subject_cn_len)
    };

    // --- TBSCertificate, built backward in its own buffer.
    let mut tbs_buf = [0u8; MAX_CERT];
    let tbs_start = {
        let mut w = DerRev::new(&mut tbs_buf);
        let m = w.mark();
        extensions(&mut w, p, &subject_hash, &issuer_hash)?;
        spki(&mut w, &p.spki)?;
        name(&mut w, &subject_cn[..subject_cn_len])?;
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
        name(&mut w, &issuer_cn[..issuer_cn_len])?;
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
            let mut raw = [0u8; 96];
            let rn = k.sign(digest, rng, &mut raw)?;
            ecdsa_der(&raw[..rn], &mut sig)?
        }
        Signer::Rsa(k) => rsa_sign(k, digest, rng, &mut sig).map_err(crate::rsa_sw)?,
        // PureEdDSA signs the whole TBS, not a digest; the 64-byte signature
        // goes straight into the BIT STRING (no ASN.1 wrapping).
        Signer::Ed25519(k) => k.sign(tbs_bytes, rng, &mut sig)?,
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

/// Raw `r ‖ s` → DER `SEQ { INTEGER r, INTEGER s }`.
fn ecdsa_der(raw: &[u8], out: &mut [u8]) -> Result<usize, Sw> {
    if raw.is_empty() || !raw.len().is_multiple_of(2) {
        return Err(Sw::EXEC_ERROR);
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

/// DER ECDSA response for GENERAL AUTHENTICATE — public wrapper over
/// [`ecdsa_der`] for the applet.
pub fn ecdsa_sig_der(raw: &[u8], out: &mut [u8]) -> Result<usize, Sw> {
    ecdsa_der(raw, out)
}
