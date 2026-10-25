// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use elliptic_curve::{
    Curve, NonZeroScalar, PrimeField,
    ops::{Invert, Reduce},
    point::AffineCoordinates,
};
use p521::{NistP521, Scalar};
use rsk_secret::Secret;

type Uint = <NistP521 as Curve>::Uint;
type Digest = <NistP521 as ecdsa::DigestAlgorithm>::Digest;
const SCALAR_BYTES: usize = 66;

pub(crate) fn sign(d: &NonZeroScalar<NistP521>, prehash: &[u8]) -> p521::ecdsa::Signature {
    let order = NistP521::ORDER;
    let mut repr = Secret::new(<[u8; SCALAR_BYTES]>::from(d.to_repr()));
    // RFC6979 consumes the raw prehash; its bits2octets is not bytes2scalar.
    let mut kgen = rfc6979::KGenerator::<Digest, Uint>::new(repr.expose(), prehash, &[], &order);
    repr.wipe();
    loop {
        let mut bytes = Secret::new([0u8; SCALAR_BYTES]);
        kgen.fill_next_k(bytes.expose_mut());
        #[cfg(test)]
        tests::override_nonce(bytes.expose_mut());
        let Some(k) = NonZeroScalar::<NistP521>::from_repr((*bytes.expose()).into()).into_option()
        else {
            continue;
        };
        let k = Secret::new(k);
        bytes.wipe();
        let z = Secret::new(bytes2scalar(prehash));
        let inverse = Secret::new(k.expose().invert());
        let point = Secret::new(crate::comb_mul_p521(k.expose()).to_affine());
        let r = Secret::new(bytes2scalar(&point.expose().x()));
        let s = Secret::new(**inverse.expose() * (*z.expose() + *r.expose() * d.as_ref()));
        if let Ok(signature) = p521::ecdsa::Signature::from_scalars(*r.expose(), *s.expose()) {
            return if <NistP521 as ecdsa::EcdsaCurve>::NORMALIZE_S {
                signature.normalize_s()
            } else {
                signature
            };
        }
    }
}

// Preserve ecdsa 0.17's non-byte-aligned conversion, independently of RFC6979.
fn bytes2scalar(mut bytes: &[u8]) -> Scalar {
    let bits = NistP521::ORDER.bits();
    let width = usize::try_from(bits.div_ceil(8)).expect("P-521 order width");
    if bytes.len() > width {
        bytes = &bytes[..width];
    }
    <Scalar as Reduce<Uint>>::reduce(&Uint::from_be_slice_truncated(bytes, bits))
}

#[cfg(test)]
#[path = "sign_p521_deterministic_tests.rs"]
mod tests;
