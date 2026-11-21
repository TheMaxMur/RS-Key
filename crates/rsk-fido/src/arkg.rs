// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! ARKG-P256, the delegating party's half: the private seed and
//! `ARKG-Derive-Private-Key` (draft-bradleylundberg-cfrg-arkg-11 §2, §3.1–3.3,
//! §4.1). It is the instance python-fido2 2.2.1's `fido2.arkg` implements — BL
//! DST_ext `ARKG-P256`, KEM DST_ext `ARKG-ECDH.ARKG-P256` — and the tests replay
//! the draft's A.1 vectors through it. `ARKG-Derive-Public-Key` is the relying
//! party's: the device never adds points, it only ever derives private keys.
//!
//! BL is P-256 scalar addition, the KEM is P-256 ECDH behind the HMAC integrity
//! adapter, and every hash_to_field is RFC 9380 `expand_message_xmd` over SHA-256
//! with `L = 48`, into the scalar field.

// Host bytes: the key handle and ctx come from the relying party.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use p256::NonZeroScalar;
use p256::elliptic_curve::ff::FromUniformBytes;
use p256::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
use rsk_crypto::{ct_eq, hkdf_sha256, hmac_sha256, sha256};
use rsk_secret::Secret;

/// `DST_ext` of the BL half (§4.1).
const DST_EXT: &[u8] = b"ARKG-P256";
/// The KEM's `DST_aug` prefix (§3.3): its DST_ext is `'ARKG-ECDH.' ‖ DST_ext`.
const KEM_ECDH: &[u8] = b"ARKG-ECDH.";
/// BL-Derive-Key-Pair's DST prefix (§3.1).
const BL_KG: &[u8] = b"ARKG-BL-EC-KG.";
/// BL-PRF's DST prefix (§3.1).
const BL_PRF: &[u8] = b"ARKG-BL-EC.";
/// Sub-Kem-Derive-Key-Pair's DST prefix (§3.3).
const KEM_KG: &[u8] = b"ARKG-KEM-ECDH-KG.";
// The HKDF info prefixes of the MAC key and of the shared secret (§3.2).
const KEM_MAC: &[u8] = b"ARKG-KEM-HMAC-mac.";
const KEM_SHARED: &[u8] = b"ARKG-KEM-HMAC-shared.";
// The ctx prefixes ARKG-Derive-Private-Key hands the BL and the KEM half (§2.4).
const CTX_BL: &[u8] = b"ARKG-Derive-Key-BL.";
const CTX_KEM: &[u8] = b"ARKG-Derive-Key-KEM.";

/// Longest `ctx` ARKG accepts (§2.4: "Abort with an error" past it).
const CTX_MAX: usize = 64;
/// HMAC-Hash-128: the KEM tag at the head of a key handle, the ephemeral KEM
/// public point after it (§3.2).
const TAG_LEN: usize = 16;
/// A P-256 point as SEC1 encodes it without compression: `04 ‖ x ‖ y`.
pub(crate) const POINT_LEN: usize = 65;
/// The SEC1 tag of an uncompressed point.
const SEC1_UNCOMPRESSED: u8 = 0x04;
/// `L` of P256_XMD:SHA-256_SSWU_RO_ (RFC 9380 §8.2): one field element's bytes.
const H2F_LEN: u16 = 48;
const SHA256_LEN: usize = 32;
/// SHA-256's input block, the `Z_pad` of expand_message_xmd (RFC 9380 §5.3.1).
const SHA256_BLOCK: usize = 64;
/// `FromUniformBytes` reduces 64 big-endian bytes; the 48 sit at its tail.
const WIDE_LEN: usize = 64;
/// Every hash_to_field input here is a 32-byte secret (an ikm, or the KEM's k).
const MSG_MAX: usize = 32;
/// ctx with its one-byte length prefix, ahead of either half's own prefix.
const CTX_PRIME_MAX: usize = CTX_KEM.len() + 1 + CTX_MAX;
/// The longest DST: BL-PRF's, `'ARKG-BL-EC.' ‖ DST_ext ‖ ctx_bl`.
const DST_MAX: usize = BL_PRF.len() + DST_EXT.len() + CTX_PRIME_MAX;
/// The longest HKDF info: the shared secret's, over the KEM's DST_ext and ctx_kem.
const INFO_MAX: usize = KEM_SHARED.len() + KEM_ECDH.len() + DST_EXT.len() + CTX_PRIME_MAX;
/// expand_message_xmd's longest hash input, `msg' = Z_pad ‖ msg ‖ I2OSP(L, 2) ‖
/// I2OSP(0, 1) ‖ DST'` — every later block input is shorter.
const MSG_PRIME_MAX: usize = SHA256_BLOCK + MSG_MAX + 2 + 1 + DST_MAX + 1;

/// Write `parts` end to end at the head of `buf`: the prefix they fill, or `None`
/// when they do not fit.
pub(crate) fn cat<'b>(buf: &'b mut [u8], parts: &[&[u8]]) -> Option<&'b [u8]> {
    let mut at = 0;
    for part in parts {
        let end = at + part.len();
        buf.get_mut(at..end)?.copy_from_slice(part);
        at = end;
    }
    buf.get(..at)
}

/// RFC 9380 §5.2 hash_to_field(msg, 1) into the P-256 scalar field, with
/// expand_message_xmd (§5.3.1) over SHA-256 and `L = 48`. The DST arrives in parts.
fn hash_to_scalar(msg: &[u8], dst: &[&[u8]]) -> Option<p256::Scalar> {
    let mut dst_buf = [0u8; DST_MAX];
    let dst = cat(&mut dst_buf, dst)?;
    let dst_len = [u8::try_from(dst.len()).ok()?];
    if msg.len() > MSG_MAX {
        return None;
    }
    let mut buf = Secret::<[u8; MSG_PRIME_MAX]>::zeroed();
    let z_pad = [0u8; SHA256_BLOCK];
    let len_in_bytes = H2F_LEN.to_be_bytes();
    let b0 = Secret::new(sha256(cat(
        buf.expose_mut(),
        &[&z_pad, msg, &len_in_bytes, &[0], dst, &dst_len],
    )?));
    let b1 = Secret::new(sha256(cat(
        buf.expose_mut(),
        &[b0.expose(), &[1], dst, &dst_len],
    )?));
    let mut chain = Secret::<[u8; SHA256_LEN]>::zeroed();
    for (c, (x, y)) in chain
        .expose_mut()
        .iter_mut()
        .zip(b0.expose().iter().zip(b1.expose()))
    {
        *c = x ^ y;
    }
    let b2 = Secret::new(sha256(cat(
        buf.expose_mut(),
        &[chain.expose(), &[2], dst, &dst_len],
    )?));
    // uniform_bytes = (b_1 ‖ b_2)[..48], as OS2IP: zero-padded to the 64 bytes
    // the reduction takes, which leaves its value unchanged.
    let tail = b2.expose().get(..usize::from(H2F_LEN) - SHA256_LEN)?;
    let lead = [0u8; WIDE_LEN - H2F_LEN as usize];
    let mut wide = Secret::<[u8; WIDE_LEN]>::zeroed();
    if cat(wide.expose_mut(), &[&lead, b1.expose(), tail])?.len() != WIDE_LEN {
        return None;
    }
    Some(p256::Scalar::from_uniform_bytes(wide.expose()))
}

/// Keep a scalar only if it is not zero, in a wiping holder.
fn nonzero(s: p256::Scalar) -> Option<Secret<NonZeroScalar>> {
    Option::<NonZeroScalar>::from(NonZeroScalar::new(s)).map(Secret::new)
}

/// The private ARKG seed `(sk_bl, sk_kem)`. Only its public half ever leaves.
pub(crate) struct PrivateSeed {
    bl: Secret<NonZeroScalar>,
    kem: Secret<NonZeroScalar>,
}

/// ARKG-Derive-Seed (§2.2): BL-Derive-Key-Pair (§3.1) and KEM-Derive-Key-Pair
/// (§3.3) hash each half's keying material to a scalar. `None` for a zero scalar.
pub(crate) fn derive_seed(ikm_bl: &[u8], ikm_kem: &[u8]) -> Option<PrivateSeed> {
    let bl = nonzero(hash_to_scalar(ikm_bl, &[BL_KG, DST_EXT])?)?;
    let kem = nonzero(hash_to_scalar(ikm_kem, &[KEM_KG, KEM_ECDH, DST_EXT])?)?;
    Some(PrivateSeed { bl, kem })
}

impl PrivateSeed {
    /// `(pk_bl, pk_kem)`, each as an uncompressed SEC1 point.
    pub(crate) fn public(&self) -> Option<([u8; POINT_LEN], [u8; POINT_LEN])> {
        Some((public_point(&self.bl)?, public_point(&self.kem)?))
    }
}

/// `sk · G` through the fixed-base comb, uncompressed.
fn public_point(sk: &Secret<NonZeroScalar>) -> Option<[u8; POINT_LEN]> {
    let p = rsk_ec::comb_mul_p256(sk.expose())
        .to_affine()
        .to_sec1_point(false);
    <[u8; POINT_LEN]>::try_from(p.as_bytes()).ok()
}

/// ARKG-Derive-Private-Key (§2.4): `sk' = sk_bl + tau`, `tau` hashed from what the
/// KEM decapsulates out of `kh`. `None` is §2.4's abort: a ctx past 64 bytes, a
/// misshapen handle, a point off the curve, a failed MAC, or a zero sum.
pub(crate) fn derive_private_key(
    seed: &PrivateSeed,
    kh: &[u8],
    ctx: &[u8],
) -> Option<Secret<NonZeroScalar>> {
    if ctx.len() > CTX_MAX {
        return None;
    }
    let (tag, c) = kh.split_first_chunk::<TAG_LEN>()?;
    let c = <&[u8; POINT_LEN]>::try_from(c).ok()?;
    let ctx_len = [u8::try_from(ctx.len()).ok()?];
    let mut kem_buf = [0u8; CTX_PRIME_MAX];
    let ctx_kem = cat(&mut kem_buf, &[CTX_KEM, &ctx_len, ctx])?;
    let ikm_tau = kem_decaps(&seed.kem, tag, c, ctx_kem)?;
    let mut bl_buf = [0u8; CTX_PRIME_MAX];
    let ctx_bl = cat(&mut bl_buf, &[CTX_BL, &ctx_len, ctx])?;
    let tau = Secret::new(hash_to_scalar(
        ikm_tau.expose(),
        &[BL_PRF, DST_EXT, ctx_bl],
    )?);
    nonzero(**seed.bl.expose() + tau.expose())
}

/// KEM-Decaps (§3.2) over ECDH's Sub-Kem-Decaps (§3.3): `k'` from `sk · pk'`, the
/// tag checked under the MAC key HKDF draws from it, then the shared secret `k`.
fn kem_decaps(
    sk: &Secret<NonZeroScalar>,
    tag: &[u8; TAG_LEN],
    c: &[u8; POINT_LEN],
    ctx: &[u8],
) -> Option<Secret<[u8; SHA256_LEN]>> {
    let k_prime = ecdh(sk, c)?;
    let mut info = [0u8; INFO_MAX];
    // "salt: not set" — HKDF's zero salt, which an empty one keys identically.
    let mut mk = Secret::<[u8; SHA256_LEN]>::zeroed();
    let info_mk = cat(&mut info, &[KEM_MAC, KEM_ECDH, DST_EXT, ctx])?;
    hkdf_sha256(&[], k_prime.expose(), info_mk, mk.expose_mut()).ok()?;
    let t = hmac_sha256(mk.expose(), c);
    if !ct_eq(t.get(..TAG_LEN)?, tag) {
        return None;
    }
    let mut k = Secret::<[u8; SHA256_LEN]>::zeroed();
    let info_k = cat(&mut info, &[KEM_SHARED, KEM_ECDH, DST_EXT, ctx])?;
    hkdf_sha256(&[], k_prime.expose(), info_k, k.expose_mut()).ok()?;
    Some(k)
}

/// The x-coordinate of `sk · pk'`, `pk'` read from its uncompressed SEC1 encoding
/// (§3.3) — refused off the curve, at infinity, or in any other encoding.
fn ecdh(sk: &Secret<NonZeroScalar>, c: &[u8; POINT_LEN]) -> Option<Secret<[u8; SHA256_LEN]>> {
    if c.first() != Some(&SEC1_UNCOMPRESSED) {
        return None;
    }
    let point = p256::Sec1Point::from_bytes(c).ok()?;
    let peer = Option::<p256::PublicKey>::from(p256::PublicKey::from_sec1_point(&point))?;
    let shared = p256::ecdh::diffie_hellman(sk.expose(), peer.as_affine());
    let mut z = Secret::<[u8; SHA256_LEN]>::zeroed();
    for (d, s) in z.expose_mut().iter_mut().zip(shared.raw_secret_bytes()) {
        *d = *s;
    }
    Some(z)
}

// `pub(crate)`: previewSign's tests play the relying party with its
// `derive_public_key`.
#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    reason = "a test's fixture is its own bound, and a panic is its failure report"
)]
#[path = "arkg_tests.rs"]
pub(crate) mod tests;
