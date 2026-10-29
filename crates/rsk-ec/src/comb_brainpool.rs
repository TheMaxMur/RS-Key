// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

macro_rules! brainpool {
    ($module:ident, $curve:ident, $name:ident, $bytes:literal, $table:literal, $variable:ident) => {
        pub(super) mod $module {
            use rsk_secret::Secret;
            use $curve::elliptic_curve::{
                Curve, PrimeField,
                ops::{Double, Invert, Reduce},
                point::AffineCoordinates,
                subtle::{ConditionallySelectable, ConstantTimeEq},
            };
            use $curve::r1::{AffinePoint, FieldBytes, NonZeroScalar, ProjectivePoint, Scalar};
            use $curve::$name;

            include!(concat!(env!("OUT_DIR"), $table));
            const WIDTH: usize = 4;
            const ROUNDS: usize = $bytes * 8 / WIDTH;

            // Isolate the public table workspace from the other curves' frames.
            #[inline(never)]
            pub(crate) fn mul(scalar: &Scalar) -> ProjectivePoint {
                let mut table = [AffinePoint::IDENTITY; 1 << WIDTH];
                for (point, (x, y)) in table.iter_mut().zip(&TABLE).skip(1) {
                    *point =
                        Option::from(AffinePoint::from_coordinates(&(*x).into(), &(*y).into()))
                            .expect("valid Brainpool comb point");
                }
                let repr = Secret::new(scalar.to_repr());
                let mut result = Secret::new(ProjectivePoint::IDENTITY);
                for round in (0..ROUNDS).rev() {
                    result.expose_mut().double_in_place();
                    let mut index = 0u8;
                    for column in 0..WIDTH {
                        let bit = column * ROUNDS + round;
                        index |= ((repr.expose()[$bytes - 1 - bit / 8] >> (bit % 8)) & 1) << column;
                    }
                    let mut selected = Secret::new(AffinePoint::IDENTITY);
                    for (i, point) in table.iter().enumerate() {
                        selected
                            .expose_mut()
                            .conditional_assign(point, (i as u8).ct_eq(&index));
                    }
                    crate::$variable::add_affine(result.expose_mut(), selected.expose());
                }
                *result.expose()
            }

            pub(crate) fn sign(d: &NonZeroScalar, prehash: &[u8]) -> ecdsa::Signature<$name> {
                let order = $name::ORDER;
                let repr = Secret::new(d.to_repr());
                let mut nonces = rfc6979::KGenerator::<
                    <$name as ecdsa::DigestAlgorithm>::Digest,
                    <$name as Curve>::Uint,
                >::new(repr.expose(), prehash, &[], &order);
                sign_with(d, prehash, |bytes| nonces.fill_next_k(bytes))
            }

            pub(super) fn sign_with(
                d: &NonZeroScalar,
                prehash: &[u8],
                mut nonce: impl FnMut(&mut FieldBytes),
            ) -> ecdsa::Signature<$name> {
                let reduce = |bytes: &[u8]| {
                    <Scalar as Reduce<<$name as Curve>::Uint>>::reduce(
                        &<$name as Curve>::Uint::from_be_slice_truncated(bytes, $bytes * 8),
                    )
                };
                let z = reduce(&prehash[..prehash.len().min($bytes)]);
                loop {
                    let mut bytes = Secret::new(FieldBytes::default());
                    nonce(bytes.expose_mut());
                    let Some(k) = NonZeroScalar::from_repr(*bytes.expose()).into_option() else {
                        continue;
                    };
                    let k = Secret::new(k);
                    let inverse = Secret::new(k.expose().invert());
                    let r = reduce(&mul(k.expose()).to_affine().x());
                    let product = Secret::new(r * **d);
                    let s = Secret::new(**inverse.expose() * (z + product.expose()));
                    // Match upstream retries and preserve Brainpool's high-S signatures.
                    if let Ok(signature) = ecdsa::Signature::from_scalars(r, *s.expose()) {
                        return signature;
                    }
                }
            }
        }
    };
}

brainpool!(
    p256,
    bp256,
    BrainpoolP256r1,
    32,
    "/gen_comb_bp256.rs",
    ecdh_bp256
);
brainpool!(
    p384,
    bp384,
    BrainpoolP384r1,
    48,
    "/gen_comb_bp384.rs",
    ecdh_bp384
);

#[cfg(test)]
#[path = "comb_brainpool_tests.rs"]
mod tests;
