// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![cfg_attr(not(test), no_std)]

//! The elliptic-curve layer: the private key both card applets seal
//! ([`PrivKey`] over [`Curve`]) with its signing / public-point / ECDH
//! operations, the public-key DO they answer with ([`pubdo`]), and — underneath
//! all of it — fixed-base Lim–Lee comb scalar multiplication and comb-based
//! ECDSA signing for the NIST/secp Weierstrass curves (P-256, P-384, P-521,
//! secp256k1), shared by every applet that signs on the generator `G`: FIDO
//! credentials, PIV GENERAL AUTHENTICATE, OpenPGP PSO:CDS.
//!
//! The key type covers more curves than the comb does — Ed25519 (signing) and
//! X25519 (ECDH) are Montgomery/Edwards and brainpool has no comb table — because
//! what the applets share is the *stored blob*, `[curve_id] ‖ scalar`, and that
//! is one type or it is two copies. The comb is an implementation detail of the
//! four curves that have one.
//!
//! Nothing here names a status word or a filesystem; see [`EcError`].
//!
//! `k·G` (the ECDSA nonce commitment) and `d·G` (public-key derivation) are both
//! *fixed-base* on `G`, so a width-4 comb over a `build.rs`-precomputed table runs
//! them several× faster than the crate's generic `mul_by_generator` on the in-order
//! Cortex-M33 — and **bit-identical** to it (KAT-checked in `tests`). ECDH is
//! variable-base (`d·P`) and stays on the crate, untouched.
//!
//! The ECDSA signers reproduce `ecdsa` 0.17's `sign_prehashed_rfc6979` body with the
//! comb spliced in for `R = k·G`, so their output is byte-for-byte the crate's — the
//! caller supplies the message digest (a prehash) and encodes the returned
//! `Signature` (DER for FIDO, raw `r‖s` for PIV/OpenPGP).

pub mod pubdo;

mod curve;
mod error;
mod key;
mod rng;

pub use curve::Curve;
pub use error::EcError;
pub use key::{MAX_EC_POINT, MAX_EC_SIG, PrivKey};
pub use pubdo::{MAX_EC_PUBDO, make_ec_pubkey_do};
pub use rng::Rng;

// Fixed-base comb tables (`build.rs`-generated): 16 entries `T[i]`, affine `(x, y)`
// big-endian; `T[0]` is an unused identity sentinel.
include!(concat!(env!("OUT_DIR"), "/gen_comb_p521.rs"));
include!(concat!(env!("OUT_DIR"), "/gen_comb_p256.rs"));
include!(concat!(env!("OUT_DIR"), "/gen_comb_p384.rs"));
include!(concat!(env!("OUT_DIR"), "/gen_comb_k256.rs"));

/// Comb width / bits-per-block — MUST match `build.rs`.
const COMB_W: usize = 4;
const COMB_D_P521: usize = 131; // P-521: ceil(521 / 4)
const COMB_D_P256: usize = 64; // P-256: ceil(256 / 4)
const COMB_D_P384: usize = 96; // P-384: ceil(384 / 4)
const COMB_D_K256: usize = 64; // secp256k1: ceil(256 / 4)

/// Emits `<name>(k) -> k·G` for one curve via a width-`COMB_W` Lim–Lee comb over its
/// `build.rs` table: `D` doublings + `D` mixed additions, several× faster than the
/// crate's generic variable-base `mul_by_generator` on the in-order Cortex-M33, and
/// bit-identical to it (KAT-checked). `$rl` = the scalar's big-endian repr length,
/// `$bits` = the field bit width.
macro_rules! comb_mul_fn {
    ($name:ident, $c:ident, $table:ident, $d:expr, $bits:expr, $rl:expr) => {
        pub fn $name(k: &$c::Scalar) -> $c::ProjectivePoint {
            use $c::elliptic_curve::PrimeField;
            use $c::elliptic_curve::sec1::FromSec1Point;
            use $c::elliptic_curve::subtle::{ConditionallySelectable, ConstantTimeEq};

            // Reconstruct the table points from the const bytes (once per call; the 15
            // deserializations are negligible beside `$d` point additions). Index 0 is
            // the identity (a zero window adds nothing). 0.14 dropped
            // `Sec1Point::from_affine_coordinates`, so splice the uncompressed SEC1
            // encoding `04 ‖ x ‖ y` and parse that.
            let mut tbl = [$c::AffinePoint::IDENTITY; 1 << COMB_W];
            for (i, (x, y)) in $table.iter().enumerate().skip(1) {
                let mut sec1 = [0u8; 1 + 2 * $rl];
                sec1[0] = 0x04;
                sec1[1..1 + $rl].copy_from_slice(x);
                sec1[1 + $rl..].copy_from_slice(y);
                let ep = $c::Sec1Point::from_bytes(&sec1).expect("valid comb point bytes");
                tbl[i] =
                    Option::from($c::AffinePoint::from_sec1_point(&ep)).expect("valid comb point");
            }

            let repr = k.to_repr(); // `$rl`-byte big-endian
            let bit = |n: usize| -> usize {
                if n >= $bits {
                    0
                } else {
                    ((repr[$rl - 1 - n / 8] >> (n % 8)) & 1) as usize
                }
            };

            let mut q = $c::ProjectivePoint::IDENTITY;
            for t in (0..$d).rev() {
                q += q; // double
                let mut idx = 0u8;
                for j in 0..COMB_W {
                    idx |= (bit(j * $d + t) as u8) << j;
                }
                // Constant-time: select `tbl[idx]` (the identity when idx == 0) by
                // scanning every entry, then add unconditionally — no data-dependent
                // branch or table index on the secret scalar, matching the crate's
                // constant-time `mul_by_generator`. Adding the identity is a no-op via
                // the complete mixed-addition formula.
                let mut sel = $c::AffinePoint::IDENTITY;
                for (i, p) in tbl.iter().enumerate() {
                    sel.conditional_assign(p, (i as u8).ct_eq(&idx));
                }
                q += sel; // mixed add: ProjectivePoint += AffinePoint
            }
            q
        }
    };
}

comb_mul_fn!(comb_mul_p521, p521, GEN_COMB, COMB_D_P521, 521, 66);
comb_mul_fn!(comb_mul_p256, p256, GEN_COMB_P256, COMB_D_P256, 256, 32);
comb_mul_fn!(comb_mul_p384, p384, GEN_COMB_P384, COMB_D_P384, 384, 48);
comb_mul_fn!(comb_mul_k256, k256, GEN_COMB_K256, COMB_D_K256, 256, 32);

/// A prehash as `N`-byte field bytes, exactly as `ecdsa`'s `bits2field` for a
/// byte-aligned order (P-256/384, secp256k1): the leftmost `N` bytes of a longer
/// digest, or a shorter one left-padded with zeros. For the common case
/// `prehash.len() == N` (SHA-256 on P-256, SHA-384 on P-384) it is the identity.
fn to_field<const N: usize>(prehash: &[u8]) -> [u8; N] {
    let mut fb = [0u8; N];
    if prehash.len() >= N {
        fb.copy_from_slice(&prehash[..N]);
    } else {
        fb[N - prehash.len()..].copy_from_slice(prehash);
    }
    fb
}

/// Deterministic ECDSA (RFC 6979) over `prehash` with P-256 scalar `d`, `k·G` via
/// the fixed-base [`comb_mul_p256`] — byte-identical to `p256::ecdsa::SigningKey::
/// sign_prehash`. `None` if the derived `k`/`r`/`s` is zero (RFC 6979 retries are
/// astronomically rare; the caller maps `None` to an error).
pub fn sign_p256(d: &p256::Scalar, prehash: &[u8]) -> Option<p256::ecdsa::Signature> {
    use p256::elliptic_curve::Curve;
    use p256::elliptic_curve::PrimeField;
    use p256::elliptic_curve::ops::Reduce;
    use p256::elliptic_curve::point::AffineCoordinates;
    use p256::{NistP256, U256};

    let fb = to_field::<32>(prehash);
    let order = NistP256::ORDER;
    let mut kgen = rfc6979::KGenerator::<<NistP256 as ecdsa::DigestAlgorithm>::Digest, U256>::new(
        &d.to_repr(),
        &fb,
        &[],
        &order,
    );
    let mut kb = p256::FieldBytes::default();
    kgen.fill_next_k(&mut kb);
    let k = Option::<p256::Scalar>::from(p256::Scalar::from_repr(kb))?;
    let k_inv = Option::<p256::Scalar>::from(k.invert())?;
    let reduce = |b: &[u8]| <p256::Scalar as Reduce<U256>>::reduce(&U256::from_be_slice(b));
    let z = reduce(&fb);
    let r = reduce(&comb_mul_p256(&k).to_affine().x());
    let s = k_inv * (z + r * *d);
    p256::ecdsa::Signature::from_scalars(r, s).ok()
}

/// Deterministic ECDSA (RFC 6979) over `prehash` with P-384 scalar `d`, `k·G` via
/// the fixed-base [`comb_mul_p384`] — byte-identical to `p384::ecdsa::SigningKey::
/// sign_prehash`.
pub fn sign_p384(d: &p384::Scalar, prehash: &[u8]) -> Option<p384::ecdsa::Signature> {
    use p384::NistP384;
    use p384::elliptic_curve::Curve;
    use p384::elliptic_curve::PrimeField;
    use p384::elliptic_curve::bigint::U384;
    use p384::elliptic_curve::ops::Reduce;
    use p384::elliptic_curve::point::AffineCoordinates;

    let fb = to_field::<48>(prehash);
    let order = NistP384::ORDER;
    let mut kgen = rfc6979::KGenerator::<<NistP384 as ecdsa::DigestAlgorithm>::Digest, U384>::new(
        &d.to_repr(),
        &fb,
        &[],
        &order,
    );
    let mut kb = p384::FieldBytes::default();
    kgen.fill_next_k(&mut kb);
    let k = Option::<p384::Scalar>::from(p384::Scalar::from_repr(kb))?;
    let k_inv = Option::<p384::Scalar>::from(k.invert())?;
    let reduce = |b: &[u8]| <p384::Scalar as Reduce<U384>>::reduce(&U384::from_be_slice(b));
    let z = reduce(&fb);
    let r = reduce(&comb_mul_p384(&k).to_affine().x());
    let s = k_inv * (z + r * *d);
    p384::ecdsa::Signature::from_scalars(r, s).ok()
}

/// Deterministic ECDSA (RFC 6979) over `prehash` with secp256k1 scalar `d`, `k·G`
/// via the fixed-base [`comb_mul_k256`], low-S normalized (BIP-0062) — byte-identical
/// to `k256::ecdsa::SigningKey::sign_prehash`.
pub fn sign_k256(d: &k256::Scalar, prehash: &[u8]) -> Option<k256::ecdsa::Signature> {
    use k256::Secp256k1;
    use k256::elliptic_curve::Curve;
    use k256::elliptic_curve::PrimeField;
    use k256::elliptic_curve::bigint::U256;
    use k256::elliptic_curve::ops::Reduce;
    use k256::elliptic_curve::point::AffineCoordinates;

    let fb = to_field::<32>(prehash);
    let order = Secp256k1::ORDER;
    let mut kgen = rfc6979::KGenerator::<<Secp256k1 as ecdsa::DigestAlgorithm>::Digest, U256>::new(
        &d.to_repr(),
        &fb,
        &[],
        &order,
    );
    let mut kb = k256::FieldBytes::default();
    kgen.fill_next_k(&mut kb);
    let k = Option::<k256::Scalar>::from(k256::Scalar::from_repr(kb))?;
    let k_inv = Option::<k256::Scalar>::from(k.invert())?;
    let reduce = |b: &[u8]| <k256::Scalar as Reduce<U256>>::reduce(&U256::from_be_slice(b));
    let z = reduce(&fb);
    let r = reduce(&comb_mul_k256(&k).to_affine().x());
    let s = k_inv * (z + r * *d);
    Some(
        k256::ecdsa::Signature::from_scalars(r, s)
            .ok()?
            .normalize_s(),
    )
}

/// ECDSA over the 64-byte SHA-512 `digest` with P-521 scalar `d`, `k·G` via the
/// fixed-base [`comb_mul_p521`]. P-521's nonce is random (the 0.14 signer is not
/// deterministic here): `fill` supplies 66 raw bytes per reject-sample. Matches the
/// FIDO P-521 signer bit-for-bit (`z` = the digest left-padded into the 66-byte field).
pub fn sign_p521(
    d: &p521::Scalar,
    digest: &[u8],
    fill: &mut dyn FnMut(&mut [u8]),
) -> Option<p521::ecdsa::Signature> {
    use p521::elliptic_curve::PrimeField;
    use p521::elliptic_curve::ops::Reduce;
    use p521::elliptic_curve::point::AffineCoordinates;
    use p521::{FieldBytes, Scalar};

    if digest.len() != 64 {
        return None;
    }
    let reduce = |fb: &FieldBytes| <Scalar as Reduce<FieldBytes>>::reduce(fb);
    let mut zf = FieldBytes::default();
    zf[2..].copy_from_slice(digest);
    let z = reduce(&zf);
    loop {
        let mut kbuf = FieldBytes::default();
        fill(&mut kbuf[..]);
        kbuf[0] >>= 7; // mask the top byte to 521 bits
        let Some(k) = Option::<Scalar>::from(Scalar::from_repr(kbuf)) else {
            continue;
        };
        let Some(k_inv) = Option::<Scalar>::from(k.invert()) else {
            continue;
        };
        let r = reduce(&comb_mul_p521(&k).to_affine().x());
        let s = k_inv * (z + r * *d);
        if let Ok(sig) = p521::ecdsa::Signature::from_scalars(r, s) {
            return Some(sig);
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
