// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

macro_rules! cases {
    ($tests:ident, $module:ident, $curve:ident, $name:ident, $bytes:literal) => {
        mod $tests {
            use super::$module::{mul, sign_with};
            use $curve::elliptic_curve::{
                Curve, PrimeField, ops::Reduce, point::AffineCoordinates,
            };
            use $curve::r1::{NonZeroScalar, ProjectivePoint, Scalar};
            use $curve::$name;

            fn check(scalar: Scalar) {
                assert_eq!(mul(&scalar), ProjectivePoint::GENERATOR * scalar);
            }

            #[test]
            fn every_bit_and_dense_scalars_match_upstream() {
                for bit in 0..$bytes * 8 {
                    let mut bytes = [0; $bytes];
                    bytes[$bytes - 1 - bit / 8] = 1 << (bit % 8);
                    check(Option::from(Scalar::from_repr(bytes.into())).unwrap());
                }
                check(Scalar::ZERO);
                check(Scalar::ONE);
                check(-Scalar::ONE);
                for byte in [0x11, 0x33, 0x55, 0x77, 0x88, 0xaa, 0xcc, 0xee] {
                    check(<Scalar as Reduce<<$name as Curve>::Uint>>::reduce(
                        &<$name as Curve>::Uint::from_be_slice(&[byte; $bytes]),
                    ));
                }
            }

            #[test]
            fn each_comb_digit_at_both_round_edges_matches_upstream() {
                let rounds = $bytes * 8 / 4;
                for round in [0, rounds - 1] {
                    for digit in 0..16u8 {
                        let mut bytes = [0; $bytes];
                        for column in 0..4 {
                            let bit = column * rounds + round;
                            bytes[$bytes - 1 - bit / 8] |= ((digit >> column) & 1) << (bit % 8);
                        }
                        if let Some(scalar) = Scalar::from_repr(bytes.into()).into_option() {
                            check(scalar);
                        }
                    }
                }
            }

            #[test]
            fn invalid_nonces_and_zero_s_retry_before_returning_a_signature() {
                let d = NonZeroScalar::new(Scalar::ONE).unwrap();
                let r = <Scalar as Reduce<<$name as Curve>::Uint>>::reduce(
                    &<$name as Curve>::Uint::from_be_slice(
                        &ProjectivePoint::GENERATOR.to_affine().x(),
                    ),
                );
                let digest = (-r).to_repr();
                let good = NonZeroScalar::new(Scalar::from(2u32)).unwrap();
                let expected = ecdsa::hazmat::sign_prehashed(&d, &good, &digest).unwrap().0;
                let nonces = [
                    Scalar::ZERO.to_repr(),
                    [0xff; $bytes].into(),
                    d.to_repr(),
                    good.to_repr(),
                ];
                let mut count = 0;
                let actual = sign_with(&d, &digest, |bytes| {
                    bytes.copy_from_slice(&nonces[count]);
                    count += 1;
                });
                assert_eq!(count, nonces.len());
                assert_eq!(actual, expected);
            }
        }
    };
}

cases!(bp256_cases, p256, bp256, BrainpoolP256r1, 32);
cases!(bp384_cases, p384, bp384, BrainpoolP384r1, 48);
