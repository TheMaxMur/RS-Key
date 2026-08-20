// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The sealed CRT parameter layout (`P ‖ Q ‖ dP ‖ dQ ‖ qInv`), its
//! length-discriminated parse, and the blinded, Bellcore-fault-checked private
//! operation on the UMAAL asm (the crate-private `sign_crt` / `modexp_pub`).
//! The PIV and OpenPGP applets store the same plaintext and sign through the
//! same [`private_op`], so this security-critical path (blinding, fault check,
//! zeroization) lives once.
//!
//! Seal I/O stays applet-local — each derives its own DEK: PIV in
//! `rsk-piv/src/seal.rs`, OpenPGP in `rsk-openpgp/src/keys.rs`. Those callers
//! feed a decrypted plaintext to [`crt_from_plain`] / hand a key to
//! [`crt_plaintext`] and seal the result.

use rsa::traits::PrivateKeyParts;
use rsa::{BigUint, RsaPrivateKey};
use zeroize::{Zeroize, Zeroizing};

use crate::{MAX_RSA_BYTES, Rng, RsaError};

/// A single fixed-width CRT field buffer (a prime's max width, RSA-4096 = 256 B).
const CRT_FIELD: usize = crate::MAX_MOD;
/// Largest CRT plaintext: `P ‖ Q ‖ dP ‖ dQ ‖ qInv`, five `half`-byte fields.
pub const MAX_CRT_PLAIN: usize = 5 * crate::MAX_MOD;

/// The RSA public exponent [`crate::RSA_E`] as a bignum — what every stored key
/// is rebuilt with.
pub fn rsa_e() -> BigUint {
    BigUint::from(crate::RSA_E)
}

/// Copy a big-endian value (`≤ dst.len()` bytes) right-aligned into `dst`. `dst`
/// must be pre-zeroed — only the value's bytes are written, not the left pad.
fn put_field(dst: &mut [u8], src: &[u8]) -> Result<(), RsaError> {
    if src.len() > dst.len() {
        return Err(RsaError::BadWidth);
    }
    let off = dst.len() - src.len();
    dst[off..].copy_from_slice(src);
    Ok(())
}

/// Tell the two sealed RSA layouts apart: `P‖Q` is `2·half`, `P‖Q‖dP‖dQ‖qInv`
/// is `5·half`. Length alone is ambiguous for non-standard sizes (e.g. 320 =
/// 2·160 = 5·64), so when a plaintext reads validly as BOTH, the CRT invariant
/// `qInv·Q ≡ 1 (mod P)` — which only a genuine 5-field blob satisfies — breaks
/// the tie. Returns the prime width `half` and whether it is the CRT form. Only
/// this firmware writes 5-field (always a 32-multiple width); a legacy `P‖Q`
/// blob may carry any width, so the 2-field arm is not width-restricted (its
/// caller enforces what its consumer needs — the asm CRT path wants a 32-mult).
pub fn parse_rsa_blob(plain: &[u8]) -> Result<(usize, bool), RsaError> {
    let n = plain.len();
    let five = n
        .is_multiple_of(5)
        .then_some(n / 5)
        .filter(|&h| h.is_multiple_of(32) && (32..=CRT_FIELD).contains(&h));
    let two = n
        .is_multiple_of(2)
        .then_some(n / 2)
        .filter(|&h| (32..=CRT_FIELD).contains(&h));
    match (five, two) {
        (Some(h5), Some(h2)) => {
            if five_field_consistent(plain, h5) {
                Ok((h5, true))
            } else {
                Ok((h2, false))
            }
        }
        (Some(h5), None) => Ok((h5, true)),
        (None, Some(h2)) => Ok((h2, false)),
        (None, None) => Err(RsaError::BadBlob),
    }
}

/// Whether the `5·half`-byte `plain` is a genuine CRT blob: `qInv·Q ≡ 1 (mod P)`.
/// A `P‖Q` blob mis-sliced into five fields fails this with overwhelming
/// probability, so it disambiguates a colliding length.
fn five_field_consistent(plain: &[u8], half: usize) -> bool {
    let p = Zeroizing::new(BigUint::from_bytes_be(&plain[..half]));
    if *p < BigUint::from(2u8) {
        return false;
    }
    let q = Zeroizing::new(BigUint::from_bytes_be(&plain[half..2 * half]));
    let qinv = Zeroizing::new(BigUint::from_bytes_be(&plain[4 * half..5 * half]));
    let mul = Zeroizing::new(&*qinv * &*q);
    let prod = Zeroizing::new(&*mul % &*p);
    *prod == BigUint::from(1u8)
}

/// Build the CRT plaintext `P ‖ Q ‖ dP ‖ dQ ‖ qInv` (five `half`-byte big-endian
/// fields) for `key` into the pre-zeroed `out`, returning its length `5·half`.
/// Caching the CRT parameters next to the primes lets [`crt_from_plain`] feed the
/// asm CRT signer directly, so a signature no longer rebuilds `d`, `dP`, `dQ` and
/// `qInv` (two modular inversions) every time.
pub fn crt_plaintext(key: &RsaPrivateKey, out: &mut [u8]) -> Result<usize, RsaError> {
    let primes = key.primes();
    if primes.len() != 2 {
        return Err(RsaError::Failed);
    }
    // `from_p_q` (how every stored key is built) already precomputes; clone +
    // precompute defensively so dP/dQ/qInv are always present.
    let mut k = key.clone();
    let _ = k.precompute();
    let (dp, dq, qinv) = match (k.dp(), k.dq(), k.qinv()) {
        (Some(dp), Some(dq), Some(qinv)) => (dp, dq, qinv),
        _ => return Err(RsaError::Failed),
    };
    let mut pb = primes[0].to_bytes_be();
    let mut qb = primes[1].to_bytes_be();
    let half = pb.len().max(qb.len());
    let n = 5 * half;
    let mut dpb = dp.to_bytes_be();
    let mut dqb = dq.to_bytes_be();
    let qi = Zeroizing::new(qinv.to_biguint().ok_or(RsaError::Failed)?);
    let mut qib = qi.to_bytes_be();
    let r = (|| {
        // The asm CRT signer processes 32-bit words in 32-byte groups, so a
        // non-32-multiple prime width has no fast path — reject it at seal time
        // (fail loud) rather than write a blob the loader would refuse.
        if !half.is_multiple_of(32) || n > out.len() {
            return Err(RsaError::BadWidth);
        }
        put_field(&mut out[0..half], &pb)?;
        put_field(&mut out[half..2 * half], &qb)?;
        put_field(&mut out[2 * half..3 * half], &dpb)?;
        put_field(&mut out[3 * half..4 * half], &dqb)?;
        put_field(&mut out[4 * half..5 * half], &qib)?;
        Ok(n)
    })();
    pb.zeroize();
    qb.zeroize();
    dpb.zeroize();
    dqb.zeroize();
    qib.zeroize();
    r
}

/// CRT parameters of an RSA private key, loaded for signing — each field
/// big-endian, `half` bytes wide. Zeroized on drop.
pub struct RsaCrt {
    half: usize,
    p: [u8; CRT_FIELD],
    q: [u8; CRT_FIELD],
    dp: [u8; CRT_FIELD],
    dq: [u8; CRT_FIELD],
    qinv: [u8; CRT_FIELD],
}

impl RsaCrt {
    fn zeroed(half: usize) -> Self {
        Self {
            half,
            p: [0; CRT_FIELD],
            q: [0; CRT_FIELD],
            dp: [0; CRT_FIELD],
            dq: [0; CRT_FIELD],
            qinv: [0; CRT_FIELD],
        }
    }
    /// Modulus width in bytes (`2·half` — the RSA signature/challenge length).
    pub fn modulus_len(&self) -> usize {
        2 * self.half
    }
    pub fn p(&self) -> &[u8] {
        &self.p[..self.half]
    }
    pub fn q(&self) -> &[u8] {
        &self.q[..self.half]
    }
    pub fn dp(&self) -> &[u8] {
        &self.dp[..self.half]
    }
    pub fn dq(&self) -> &[u8] {
        &self.dq[..self.half]
    }
    pub fn qinv(&self) -> &[u8] {
        &self.qinv[..self.half]
    }
}

impl Drop for RsaCrt {
    fn drop(&mut self) {
        self.p.zeroize();
        self.q.zeroize();
        self.dp.zeroize();
        self.dq.zeroize();
        self.qinv.zeroize();
    }
}

/// Parse a decrypted sealed plaintext into an [`RsaCrt`]. New
/// `P‖Q‖dP‖dQ‖qInv` blobs slice directly; older `P‖Q` blobs recompute
/// `dP/dQ/qInv` once here (the cost the new layout removes — such keys still get
/// the fast asm CRT modexp, but keep the one-time precompute per signature until
/// re-provisioned).
pub fn crt_from_plain(plain: &[u8]) -> Result<RsaCrt, RsaError> {
    let (half, is_crt) = parse_rsa_blob(plain)?;
    // The asm CRT signer needs a 32-multiple field width; a legacy `P‖Q` blob of
    // a non-standard width still DECIPHERs (via load_rsa_key on num-bigint) but
    // cannot sign here — fail closed rather than feed the asm a bad width.
    if !half.is_multiple_of(32) {
        return Err(RsaError::BadWidth);
    }
    let mut crt = RsaCrt::zeroed(half);
    crt.p[..half].copy_from_slice(&plain[..half]);
    crt.q[..half].copy_from_slice(&plain[half..2 * half]);
    if is_crt {
        crt.dp[..half].copy_from_slice(&plain[2 * half..3 * half]);
        crt.dq[..half].copy_from_slice(&plain[3 * half..4 * half]);
        crt.qinv[..half].copy_from_slice(&plain[4 * half..5 * half]);
    } else {
        let p = BigUint::from_bytes_be(&plain[..half]);
        let q = BigUint::from_bytes_be(&plain[half..2 * half]);
        let mut k = RsaPrivateKey::from_p_q(p, q, rsa_e()).map_err(|_| RsaError::BadBlob)?;
        let _ = k.precompute();
        match (k.dp(), k.dq(), k.qinv()) {
            (Some(dp), Some(dq), Some(qinv)) => {
                let mut dpb = dp.to_bytes_be();
                let mut dqb = dq.to_bytes_be();
                let qi = Zeroizing::new(qinv.to_biguint().ok_or(RsaError::Failed)?);
                let mut qib = qi.to_bytes_be();
                let put = put_field(&mut crt.dp[..half], &dpb)
                    .and(put_field(&mut crt.dq[..half], &dqb))
                    .and(put_field(&mut crt.qinv[..half], &qib));
                dpb.zeroize();
                dqb.zeroize();
                qib.zeroize();
                put?;
            }
            _ => return Err(RsaError::Failed),
        }
    }
    Ok(crt)
}

/// Raw RSA private-key operation `sig = cᵈ mod n`, computed over the cached CRT
/// parameters with the UMAAL asm (the crate-private `sign_crt`, the backend this wraps —
/// same job, one layer down, without blinding or the fault check). Base-blinded
/// `(c·rᵉ)ᵈ·r⁻¹ mod n` with a fresh random `r`, so the variable-time modexp
/// cannot become a timing oracle; then Bellcore fault-checked (`sigᵉ ≡ c mod n`)
/// so a faulted CRT half — or an asm/marshaling bug — can never leave as a valid
/// signature. `c` is the full modulus-width block (a PKCS#1 EM for OpenPGP, a
/// host-padded block for PIV GENERAL AUTHENTICATE). Writes the `modulus_len`-byte
/// big-endian signature to `out`.
pub fn private_op(
    crt: &RsaCrt,
    c: &[u8],
    rng: &mut dyn Rng,
    out: &mut [u8],
) -> Result<usize, RsaError> {
    use num_bigint_dig::ModInverse;
    let mlen = crt.modulus_len();
    if c.len() != mlen {
        return Err(RsaError::BadBlock);
    }
    // num-bigint-dig's BigUint has no zeroizing Drop (its heap limbs are freed
    // un-wiped), so every secret value here rides in a `Zeroizing` that scrubs it
    // on drop — on the success path and every `?`/error return alike.
    let p = Zeroizing::new(BigUint::from_bytes_be(crt.p()));
    let q = Zeroizing::new(BigUint::from_bytes_be(crt.q()));
    let n = &*p * &*q;
    let m = BigUint::from_bytes_be(c);

    // The modulus little-endian, for the asm public-exponent modexp that both
    // blinding (`rᵉ`) and the fault check (`sigᵉ`) use — the two full-width
    // modexps that otherwise ran on num-bigint.
    let mut n_le = [0u8; MAX_RSA_BYTES];
    let nb = n.to_bytes_le();
    n_le[..nb.len()].copy_from_slice(&nb);
    let pub_pow = |base: &BigUint| -> Option<BigUint> {
        let mut b_le = [0u8; MAX_RSA_BYTES];
        let bb = base.to_bytes_le();
        b_le[..bb.len()].copy_from_slice(&bb);
        let mut o_le = [0u8; MAX_RSA_BYTES];
        let ok = crate::modexp_pub(
            &b_le[..mlen],
            crate::RSA_PUB_EXP_BE,
            &n_le[..mlen],
            &mut o_le[..mlen],
        );
        let out = ok.then(|| BigUint::from_bytes_le(&o_le[..mlen]));
        b_le.zeroize();
        o_le.zeroize();
        out
    };

    // Fresh blinding factor r, invertible mod n (retry on the negligible chance
    // r shares a factor with n — that candidate is a multiple of p or q, so wipe
    // it too rather than free a value that reveals a prime factor).
    let (r, r_inv) = loop {
        let mut rb = [0u8; MAX_RSA_BYTES];
        rng.fill(&mut rb[..mlen]);
        let mut cand = BigUint::from_bytes_be(&rb[..mlen]) % &n;
        rb.zeroize();
        match (&cand).mod_inverse(&n).and_then(|i| i.to_biguint()) {
            Some(inv) => break (Zeroizing::new(cand), Zeroizing::new(inv)),
            None => cand.zeroize(),
        }
    };
    let blinded = Zeroizing::new((&m * pub_pow(&r).ok_or(RsaError::Failed)?) % &n);

    // CRT private op on the blinded message, then unblind.
    let mut base_le = [0u8; MAX_RSA_BYTES];
    let mut bl = blinded.to_bytes_le();
    base_le[..bl.len()].copy_from_slice(&bl);
    bl.zeroize();
    let mut sig_le = [0u8; MAX_RSA_BYTES];
    crate::sign_crt(
        &base_le[..mlen],
        crt.dp(),
        crt.dq(),
        crt.p(),
        crt.q(),
        crt.qinv(),
        &mut sig_le[..mlen],
    );
    let s_blind = Zeroizing::new(BigUint::from_bytes_le(&sig_le[..mlen]));
    let s = (&*s_blind * &*r_inv) % &n;
    base_le.zeroize();
    sig_le.zeroize();

    // Bellcore fault check: a correct signature satisfies sigᵉ ≡ c (mod n).
    if pub_pow(&s).ok_or(RsaError::Failed)? != m {
        return Err(RsaError::Failed);
    }
    let sb = s.to_bytes_be();
    if sb.len() > mlen {
        return Err(RsaError::Failed);
    }
    let off = mlen - sb.len();
    out[..off].fill(0);
    out[off..mlen].copy_from_slice(&sb);
    Ok(mlen)
}

#[cfg(test)]
#[path = "crt_tests.rs"]
mod tests;
