// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! PKCS#1 v1.5 (RFC 8017): the DigestInfo encoding the signature paths build,
//! the two signers over it — one on the asm CRT core ([`crate::crt`]), one on a
//! full [`RsaKey`] for the PIV certificate path — the decryption both DECIPHER
//! arms end in, and the constant-time unpadding they read the block back with.
//!
//! Every structural test in that unpad is a mask, never a branch: which of the
//! four ways an EM can be malformed must not be timeable, or the status word's
//! padding oracle gains a finer-grained sibling.

use zeroize::Zeroize;

use crate::{MAX_RSA_BYTES, Rng, RsaError, RsaKey};

/// PKCS#1 DigestInfo prefixes (`SEQ { SEQ { OID, NULL }, OCTET STRING }` header,
/// without the trailing hash) for the five hashes `rsa_sign_em` recognises.
pub(crate) const DI_SHA1: &[u8] = &[
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
];
pub(crate) const DI_SHA224: &[u8] = &[
    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
    0x00, 0x04, 0x1c,
];
pub(crate) const DI_SHA256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
pub(crate) const DI_SHA384: &[u8] = &[
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
pub(crate) const DI_SHA512: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];
const DIGESTINFOS: [(&[u8], usize); 5] = [
    (DI_SHA1, 20),
    (DI_SHA224, 28),
    (DI_SHA256, 32),
    (DI_SHA384, 48),
    (DI_SHA512, 64),
];

/// Largest DigestInfo `rsa_sign_em` builds: 19-byte prefix (SHA-512) + 64-byte hash.
pub const MAX_RSA_DIGESTINFO: usize = 19 + 64;

/// Find the recognised DigestInfo prefix + hash for a canonical PKCS#1 DigestInfo
/// (`SEQ { SEQ { OID, NULL }, OCTET STRING }`). gpg always sends the canonical
/// form, so a prefix + exact-length match identifies it without a full DER walk.
fn match_digestinfo(data: &[u8]) -> Option<(&'static [u8], &[u8])> {
    for (prefix, hlen) in DIGESTINFOS {
        if data.len() == prefix.len() + hlen && data.starts_with(prefix) {
            return Some((prefix, &data[prefix.len()..]));
        }
    }
    None
}

/// Decide what PKCS#1 v1.5 should sign: write the canonical DigestInfo
/// (`prefix ‖ hash`) for a recognised DigestInfo or a bare hash whose length
/// names the algorithm into `em`, returning its length; `None` means neither (the
/// raw private-op fallback). Pure (no key / modexp), so the `openpgp_rsa_sign`
/// fuzz target exercises the parser + buffer construction at full speed.
pub fn rsa_sign_em(data: &[u8], em: &mut [u8; MAX_RSA_DIGESTINFO]) -> Option<usize> {
    let (prefix, hash): (&[u8], &[u8]) = if let Some(di) = match_digestinfo(data) {
        di
    } else {
        let &(prefix, _) = DIGESTINFOS.iter().find(|&&(_, hlen)| hlen == data.len())?;
        (prefix, data)
    };
    let dlen = prefix.len() + hash.len();
    em[..prefix.len()].copy_from_slice(prefix);
    em[prefix.len()..dlen].copy_from_slice(hash);
    Some(dlen)
}

/// PKCS#1 v1.5 sign over the supplied data with the cached CRT params on the
/// UMAAL asm. If `data` is a DigestInfo (or a bare hash whose length names the
/// algorithm), build the EMSA-PKCS1-v1_5 encoding and sign that; otherwise treat
/// `data` as a raw block. Either way the block runs through the blinded,
/// Bellcore-fault-checked private op ([`crate::crt::private_op`]).
pub fn rsa_sign_crt(
    crt: &crate::crt::RsaCrt,
    data: &[u8],
    rng: &mut dyn Rng,
    out: &mut [u8],
) -> Result<usize, RsaError> {
    let mlen = crt.modulus_len();
    let mut em = [0u8; MAX_RSA_BYTES];
    let mut di = [0u8; MAX_RSA_DIGESTINFO];
    match rsa_sign_em(data, &mut di) {
        Some(dlen) => {
            // EM = 00 01 PS 00 ‖ DigestInfo, PS = 0xFF·(mlen−dlen−3), at least 8.
            if mlen < dlen + 11 {
                return Err(RsaError::BadWidth);
            }
            let ps_end = mlen - dlen - 1;
            em[1] = 0x01;
            em[2..ps_end].fill(0xff);
            em[ps_end + 1..mlen].copy_from_slice(&di[..dlen]);
        }
        // gpg never reaches this — it always sends a DigestInfo — but a raw block
        // still signs (left-padded to the modulus width) through the same blinded,
        // fault-checked op, so no non-conformant caller sees a different path.
        None => {
            if data.len() > mlen {
                return Err(RsaError::BadBlock);
            }
            em[mlen - data.len()..mlen].copy_from_slice(data);
        }
    }
    crate::crt::private_op(crt, &em[..mlen], rng, out)
}

/// PKCS#1 v1.5 over the supplied data with a full [`RsaKey`], on the software
/// private op. Used by the PIV x509 cert-signing path (`rsk_piv::x509`), whose
/// key may be any width an IMPORT accepted; the OpenPGP applet's own PSO:CDS /
/// INTERNAL AUTHENTICATE use [`rsa_sign_crt`] (asm). If it is a DigestInfo (or a
/// bare hash whose length names the algorithm), sign that digest; otherwise fall
/// back to the raw private operation.
pub fn rsa_sign(
    key: &RsaKey,
    data: &[u8],
    rng: &mut dyn Rng,
    out: &mut [u8],
) -> Result<usize, RsaError> {
    let mut di = [0u8; MAX_RSA_DIGESTINFO];
    let Some(dlen) = rsa_sign_em(data, &mut di) else {
        return rsa_raw(key, data, out, rng);
    };
    let mlen = key.size();
    // EM = 00 01 PS 00 ‖ DigestInfo, PS = 0xFF·(mlen−dlen−3), at least 8 —
    // RFC 8017 §9.2, the block `rsa_sign_crt` builds for the asm core.
    if mlen > MAX_RSA_BYTES || mlen < dlen + 11 {
        return Err(RsaError::BadWidth);
    }
    let mut em = [0u8; MAX_RSA_BYTES];
    let ps_end = mlen - dlen - 1;
    em[1] = 0x01;
    em[2..ps_end].fill(0xff);
    em[ps_end + 1..mlen].copy_from_slice(&di[..dlen]);
    key.private_op(&em[..mlen], rng, out)
}

/// PKCS#1 v1.5 decryption with a full [`RsaKey`], on the software private op —
/// the arm PSO:DECIPHER falls back to for a legacy `P‖Q` key whose prime width
/// the asm CRT core cannot take. Same blinded, Bellcore-fault-checked operation
/// and the same constant-time [`unpad_encrypt`] as the asm arm.
pub fn rsa_decrypt(
    key: &RsaKey,
    ct: &[u8],
    rng: &mut dyn Rng,
    out: &mut [u8],
) -> Result<usize, RsaError> {
    let mlen = key.size();
    if mlen > MAX_RSA_BYTES {
        return Err(RsaError::BadWidth);
    }
    let mut em = [0u8; MAX_RSA_BYTES];
    let res = key
        .private_op(ct, rng, &mut em[..mlen])
        .and_then(|_| unpad_encrypt(&em[..mlen], out));
    em.zeroize();
    res
}

/// Run the raw RSA private operation `m^d mod n` (no padding scheme). gpg never
/// reaches this — it always sends a DigestInfo — but the operation is
/// base-blinded `(m·rᵉ)ᵈ·r⁻¹ mod n` with a fresh random `r`, so even a
/// non-conformant caller cannot turn `num-bigint-dig`'s variable-time
/// exponentiation into a Marvin-style timing oracle on the private exponent.
fn rsa_raw(
    key: &RsaKey,
    data: &[u8],
    out: &mut [u8],
    rng: &mut dyn Rng,
) -> Result<usize, RsaError> {
    use num_bigint_dig::BigUint;
    let key_size = key.size();
    if key_size > MAX_RSA_BYTES {
        return Err(RsaError::BadWidth);
    }
    if data.len() > key_size {
        return Err(RsaError::BadBlock);
    }
    let (n, e, d) = (key.n(), key.e(), key.d());
    let m = BigUint::from_bytes_be(data);
    let (r, r_inv) = crate::key::blind_pair(n, key_size, rng);
    let blinded = (&m * r.modpow(e, n)) % n;
    let res = (blinded.modpow(d, n) * &*r_inv) % n;
    let rb = res.to_bytes_be();
    if rb.len() > key_size {
        return Err(RsaError::Failed);
    }
    let off = key_size - rb.len();
    out[..off].fill(0);
    out[off..key_size].copy_from_slice(&rb);
    Ok(key_size)
}

/// `0xFF` when `a == b`, `0x00` otherwise.
fn ct_eq(a: u8, b: u8) -> u8 {
    let x = a ^ b;
    // `x | -x` has its top bit set for every non-zero `x`, and is 0 for `x == 0`.
    let nonzero = (x | x.wrapping_neg()) >> 7;
    (nonzero ^ 1).wrapping_neg()
}

/// Widen a `0x00`/`0xFF` flag to an all-ones / all-zeroes `usize` mask.
fn ct_mask(flag: u8) -> usize {
    ((flag & 1) as usize).wrapping_neg()
}

/// `0xFF` when `v >= bound`, for values far below `usize::MAX / 2`.
fn ct_ge(v: usize, bound: usize) -> u8 {
    let below = (v.wrapping_sub(bound) >> (usize::BITS - 1)) as u8 & 1;
    (below ^ 1).wrapping_neg()
}

/// Strip `0x00 ‖ 0x02 ‖ PS ‖ 0x00` from a modulus-width `em`, writing the message
/// to `out` and returning its length. `PS` is at least 8 non-zero bytes, so an
/// `em` shorter than 11 has no valid form at all.
///
/// The message is rejected as a whole — a caller learns "this ciphertext did not
/// decrypt", never which byte betrayed it.
pub fn unpad_encrypt(em: &[u8], out: &mut [u8]) -> Result<usize, RsaError> {
    if em.len() < 11 {
        return Err(RsaError::BadBlock);
    }
    let mut good = ct_eq(em[0], 0x00) & ct_eq(em[1], 0x02);

    // One pass over the whole block. `seen` latches at the first zero byte, so
    // `start` records the offset just past it — the message's first byte. Bytes
    // of PS are non-zero by construction: an earlier zero would have been this
    // separator instead.
    let mut seen = 0u8;
    let mut start = 0usize;
    for (i, &b) in em.iter().enumerate().skip(2) {
        let is_zero = ct_eq(b, 0x00);
        let first = is_zero & !seen;
        start |= (i + 1) & ct_mask(first);
        seen |= is_zero;
    }
    // |PS| = start − 3 must be at least 8, so the message starts at 11 or later.
    // A block with no separator never latched and leaves `start` at 0, which the
    // same floor rejects — so this one test covers both malformations.
    good &= ct_ge(start, 11);

    if good != 0xFF {
        return Err(RsaError::BadBlock);
    }
    let msg = &em[start..];
    if msg.len() > out.len() {
        return Err(RsaError::BadWidth);
    }
    out[..msg.len()].copy_from_slice(msg);
    Ok(msg.len())
}

#[cfg(test)]
#[path = "pkcs1v15_tests.rs"]
mod tests;
