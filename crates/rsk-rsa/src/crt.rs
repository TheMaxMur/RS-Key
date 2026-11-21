// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The sealed CRT parameter layout (`P ‖ Q ‖ dP ‖ dQ ‖ qInv`), its
//! length-discriminated parse, and the blinded, Bellcore-fault-checked private
//! operation backed by fixed-width Montgomery arithmetic.
//! The PIV and OpenPGP applets store the same plaintext and sign through the
//! same [`private_op`], so this security-critical path (blinding, fault check,
//! zeroization) lives once.
//!
//! Seal I/O stays applet-local — each derives its own DEK: PIV in
//! `rsk-piv/src/seal.rs`, OpenPGP in `rsk-openpgp/src/keys.rs`. Those callers
//! feed a decrypted plaintext to [`crt_from_plain`] / hand a key to
//! [`crt_plaintext`] and seal the result.

use num_bigint_dig::BigUint;
use rsk_secret::Secret;
use zeroize::Zeroize;

use crate::key::{blind_pair, from_secret_be};
use crate::{MAX_RSA_BYTES, Rng, RsaError, RsaKey};

/// A single fixed-width CRT field buffer (a prime's max width, RSA-4096 = 256 B).
const CRT_FIELD: usize = crate::MAX_MOD;
/// Largest CRT plaintext: `P ‖ Q ‖ dP ‖ dQ ‖ qInv`, five `half`-byte fields.
pub const MAX_CRT_PLAIN: usize = 5 * crate::MAX_MOD;

/// The RSA public exponent [`crate::RSA_E`] as a bignum — what every stored key
/// is rebuilt with.
pub(crate) fn rsa_e() -> BigUint {
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
/// caller enforces what its consumer needs — the fixed-width CRT path wants a 32-mult).
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
    let p = Secret::new(from_secret_be(&plain[..half]));
    if *p.expose() < BigUint::from(2u8) {
        return false;
    }
    let q = Secret::new(from_secret_be(&plain[half..2 * half]));
    let qinv = Secret::new(from_secret_be(&plain[4 * half..5 * half]));
    let mul = Secret::new(qinv.expose() * q.expose());
    let prod = Secret::new(mul.expose() % p.expose());
    *prod.expose() == BigUint::from(1u8)
}

/// Build the CRT plaintext `P ‖ Q ‖ dP ‖ dQ ‖ qInv` (five `half`-byte big-endian
/// fields) for `key` into the pre-zeroed `out`, returning its length `5·half`.
/// Caching the CRT parameters lets [`crt_from_plain`] feed the signer without
/// recomputing `d`, `dP`, `dQ` and `qInv` on each signature.
pub fn crt_plaintext(key: &RsaKey, out: &mut [u8]) -> Result<usize, RsaError> {
    // Absent only for a key whose primes share a factor — an IMPORT can offer
    // such a pair, and it is refused here rather than sealed unusable.
    let (dp, dq, qinv) = key.crt().ok_or(RsaError::Failed)?;
    let mut pb = Secret::new(key.p().to_bytes_be());
    let mut qb = Secret::new(key.q().to_bytes_be());
    let half = pb.expose().len().max(qb.expose().len());
    let n = 5 * half;
    let mut dpb = Secret::new(dp.to_bytes_be());
    let mut dqb = Secret::new(dq.to_bytes_be());
    let mut qib = Secret::new(qinv.to_bytes_be());
    let r = (|| {
        // The sealed CRT format accepts prime widths in multiples of 32 bytes.
        // Enforce that at seal time so the loader can reopen the blob.
        if !half.is_multiple_of(32) || n > out.len() {
            return Err(RsaError::BadWidth);
        }
        put_field(&mut out[0..half], pb.expose())?;
        put_field(&mut out[half..2 * half], qb.expose())?;
        put_field(&mut out[2 * half..3 * half], dpb.expose())?;
        put_field(&mut out[3 * half..4 * half], dqb.expose())?;
        put_field(&mut out[4 * half..5 * half], qib.expose())?;
        Ok(n)
    })();
    pb.wipe();
    qb.wipe();
    dpb.wipe();
    dqb.wipe();
    qib.wipe();
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
    #[expect(clippy::disallowed_methods, reason = "a RsaCrt's drop is its wipe")]
    fn drop(&mut self) {
        let Self {
            half: _,
            p,
            q,
            dp,
            dq,
            qinv,
        } = self;
        p.zeroize();
        q.zeroize();
        dp.zeroize();
        dq.zeroize();
        qinv.zeroize();
        #[cfg(test)]
        crate::tests::observe_crt_drop(&[p, q, dp, dq, qinv]);
    }
}

/// Parse a decrypted sealed plaintext into an [`RsaCrt`]. New
/// `P‖Q‖dP‖dQ‖qInv` blobs slice directly. Loading an older `P‖Q` blob
/// recomputes `dP/dQ/qInv` before calling the same signer.
pub fn crt_from_plain(plain: &[u8]) -> Result<RsaCrt, RsaError> {
    let (half, is_crt) = parse_rsa_blob(plain)?;
    // Legacy DECIPHER accepts other widths through the BigUint signer.
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
        let p = from_secret_be(&plain[..half]);
        let q = from_secret_be(&plain[half..2 * half]);
        let k = RsaKey::from_p_q(p, q, rsa_e()).ok_or(RsaError::BadBlob)?;
        let (dp, dq, qinv) = k.crt().ok_or(RsaError::Failed)?;
        let mut dpb = Secret::new(dp.to_bytes_be());
        let mut dqb = Secret::new(dq.to_bytes_be());
        let mut qib = Secret::new(qinv.to_bytes_be());
        let put = put_field(&mut crt.dp[..half], dpb.expose())
            .and(put_field(&mut crt.dq[..half], dqb.expose()))
            .and(put_field(&mut crt.qinv[..half], qib.expose()));
        dpb.wipe();
        dqb.wipe();
        qib.wipe();
        put?;
    }
    Ok(crt)
}

/// Raw RSA private-key operation `sig = cᵈ mod n`, computed over the cached CRT
/// parameters. Base blinding with fresh `r` randomizes the base before the
/// private exponentiation. The Bellcore check verifies `sigᵉ ≡ c mod n`
/// before returning the result. `c` is the full modulus-width block (a PKCS#1 EM for OpenPGP, a
/// host-padded block for PIV GENERAL AUTHENTICATE). Writes the `modulus_len`-byte
/// big-endian signature to `out`.
pub fn private_op(
    crt: &RsaCrt,
    c: &[u8],
    rng: &mut dyn Rng,
    out: &mut [u8],
) -> Result<usize, RsaError> {
    let mlen = crt.modulus_len();
    if c.len() != mlen {
        return Err(RsaError::BadBlock);
    }
    // num-bigint-dig's BigUint has no zeroizing Drop (its heap limbs are freed
    // un-wiped), so the key's halves, the blinding values and the result — for a
    // decipher, the plaintext — ride in a `Secret`; the library's own copies do not.
    let p = Secret::new(from_secret_be(crt.p()));
    let q = Secret::new(from_secret_be(crt.q()));
    let n = p.expose() * q.expose();
    let m = BigUint::from_bytes_be(c);

    // Blinding and the fault check share the full-width public exponentiation.
    let mut n_le = [0u8; MAX_RSA_BYTES];
    let nb = n.to_bytes_le();
    n_le[..nb.len()].copy_from_slice(&nb);
    let pub_pow = |base: &BigUint| -> Option<BigUint> {
        let mut b_le = Secret::<[u8; MAX_RSA_BYTES]>::zeroed();
        let bb = Secret::new(base.to_bytes_le());
        b_le.expose_mut()[..bb.expose().len()].copy_from_slice(bb.expose());
        let mut o_le = Secret::<[u8; MAX_RSA_BYTES]>::zeroed();
        let ok = crate::pubexp::modexp_pub(
            &b_le.expose()[..mlen],
            &n_le[..mlen],
            &mut o_le.expose_mut()[..mlen],
        );
        let out = ok.then(|| BigUint::from_bytes_le(&o_le.expose()[..mlen]));
        b_le.wipe();
        o_le.wipe();
        out
    };

    let (r, r_inv) = blind_pair(&n, mlen, rng);
    let re = Secret::new(pub_pow(r.expose()).ok_or(RsaError::Failed)?);
    let mre = Secret::new(&m * re.expose());
    let blinded = Secret::new(mre.expose() % &n);

    // CRT private op on the blinded message, then unblind.
    let mut base_le = Secret::<[u8; MAX_RSA_BYTES]>::zeroed();
    let mut bl = Secret::new(blinded.expose().to_bytes_le());
    base_le.expose_mut()[..bl.expose().len()].copy_from_slice(bl.expose());
    bl.wipe();
    let mut sig_le = Secret::<[u8; MAX_RSA_BYTES]>::zeroed();
    if !crate::privexp::sign_crt(
        &base_le.expose()[..mlen],
        crt.dp(),
        crt.dq(),
        crt.p(),
        crt.q(),
        crt.qinv(),
        &mut sig_le.expose_mut()[..mlen],
    ) {
        return Err(RsaError::Failed);
    }
    let s_blind = Secret::new(BigUint::from_bytes_le(&sig_le.expose()[..mlen]));
    let prod = Secret::new(s_blind.expose() * r_inv.expose());
    let s = Secret::new(prod.expose() % &n);
    base_le.wipe();
    sig_le.wipe();

    // Bellcore fault check: a correct signature satisfies sigᵉ ≡ c (mod n).
    if pub_pow(s.expose()).ok_or(RsaError::Failed)? != m {
        return Err(RsaError::Failed);
    }
    let sb = Secret::new(s.expose().to_bytes_be());
    if sb.expose().len() > mlen {
        return Err(RsaError::Failed);
    }
    let off = mlen - sb.expose().len();
    out[..off].fill(0);
    out[off..mlen].copy_from_slice(sb.expose());
    Ok(mlen)
}

/// The pairwise-consistency test a key takes before it is stored: laid out as the
/// signer holds it (its refusals are [`crt_plaintext`]'s too), it signs one block
/// through [`private_op`]'s fault check at e = 65537. Composite primes fail here.
pub fn pairwise_consistent(key: &RsaKey, rng: &mut dyn Rng) -> Result<(), RsaError> {
    let mut plain = Secret::<[u8; MAX_CRT_PLAIN]>::zeroed();
    let mut sig = Secret::<[u8; MAX_RSA_BYTES]>::zeroed();
    let r = (|| {
        let n = crt_plaintext(key, plain.expose_mut())?;
        let crt = crt_from_plain(&plain.expose()[..n])?;
        let mlen = crt.modulus_len();
        let mut block = [0u8; MAX_RSA_BYTES];
        block[mlen - 1] = 2;
        private_op(&crt, &block[..mlen], rng, sig.expose_mut()).map(|_| ())
    })();
    plain.wipe();
    sig.wipe();
    r
}

#[cfg(test)]
#[path = "crt_tests.rs"]
mod tests;
