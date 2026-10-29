// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use elliptic_curve::FieldBytes;
use elliptic_curve::ops::{Double, Reduce};

#[test]
fn point_wipe_clears_every_coordinate() {
    let mut point = Secret::new(scaled(&AffinePoint::GENERATOR, 7));
    point.wipe();
    assert_eq!(point.expose().x, FieldElement::ZERO);
    assert_eq!(point.expose().y, FieldElement::ZERO);
    assert_eq!(point.expose().z, FieldElement::ZERO);
}

fn reference(peer: &AffinePoint, scalar: &Scalar) -> AffinePoint {
    (ProjectivePoint::from(*peer) * scalar).to_affine()
}

fn coordinates(point: &AffinePoint) -> Coordinates {
    [
        FieldElement::from_repr(point.x()).unwrap(),
        FieldElement::from_repr(point.y()).unwrap(),
    ]
}

fn scaled(point: &AffinePoint, scale: u64) -> Jacobian {
    let z = FieldElement::from(scale);
    let zz = z.square();
    let [x, y] = coordinates(point);
    Jacobian {
        x: x * zz,
        y: y * zz * z,
        z,
    }
}

#[test]
fn matches_full_points_at_signed_window_carries_and_order_boundaries() {
    let mut scalars = [Scalar::ZERO; 52];
    for (i, scalar) in scalars.iter_mut().take(20).enumerate() {
        *scalar = Scalar::from(i as u64);
    }
    for (out, value) in scalars[20..36].iter_mut().zip(1..=16u64) {
        *out = -Scalar::from(value);
    }
    for (out, bit) in scalars[36..].iter_mut().zip([
        4, 7, 8, 15, 31, 63, 95, 127, 159, 191, 223, 255, 287, 319, 335, 383,
    ]) {
        let mut repr = FieldBytes::<Curve>::default();
        let bit = bit % SCALAR_BITS;
        repr[SCALAR_BITS / 8 - 1 - bit / 8] = 1 << (bit % 8);
        *out = Scalar::from_repr(repr).unwrap();
    }
    for base_scalar in [Scalar::ONE, Scalar::from(17u64), -Scalar::from(6u64)] {
        let peer = (ProjectivePoint::GENERATOR * base_scalar).to_affine();
        let public = PublicKey::from_affine(peer).unwrap();
        for scalar in scalars {
            assert_eq!(
                *mul(&public, &scalar).unwrap().expose(),
                reference(&peer, &scalar)
            );
        }
    }
}

#[test]
fn negative_equal_point_fallback_preserves_y_as_well_as_shared_x() {
    let peer = AffinePoint::GENERATOR;
    let public = PublicKey::from_affine(peer).unwrap();
    let last = (-Scalar::ONE).to_repr();
    let multiple = 2 * u64::from(last[last.len() - 1].wrapping_add(1) & 15);
    let scalar = -Scalar::from(multiple);
    let result = mul(&public, &scalar).unwrap();
    let wrong_sign = reference(&peer, &Scalar::from(multiple));
    assert_eq!(result.expose().x(), wrong_sign.x());
    assert_ne!(result.expose().y(), wrong_sign.y());
    assert_eq!(*result.expose(), -wrong_sign);
}

#[test]
fn complete_mixed_add_handles_identity_equality_opposites_and_zero() {
    for multiple in [1u64, 3, 8] {
        let point = reference(&AffinePoint::GENERATOR, &Scalar::from(multiple));
        for point in [point, -point] {
            let twice = ProjectivePoint::from(point).double().to_affine();
            let p = coordinates(&point);
            let p2 = coordinates(&twice);
            for scale in [1, 7] {
                let mut q = scaled(&point, scale);
                q.add_mixed(&p, &p2, Choice::from(0));
                assert_eq!(q.affine().unwrap(), twice);
                let mut q = scaled(&-point, scale);
                q.add_mixed(&p, &p2, Choice::from(0));
                assert_eq!(q.affine().unwrap(), AffinePoint::IDENTITY);
                q.double();
                assert_eq!(q.affine().unwrap(), AffinePoint::IDENTITY);
                q.add_mixed(&p, &p2, Choice::from(0));
                assert_eq!(q.affine().unwrap(), point);
                let mut q = scaled(&point, scale);
                q.add_mixed(&p, &p2, Choice::from(1));
                assert_eq!(q.affine().unwrap(), point);
                q.add_mixed(
                    &[FieldElement::ZERO; 2],
                    &[FieldElement::ZERO; 2],
                    Choice::from(1),
                );
                assert_eq!(q.affine().unwrap(), point);
            }
        }
    }
}

#[test]
fn matches_every_single_bit_and_dense_scalar_on_multiple_peers() {
    let peers = [1u64, 17, 0x1234abcd].map(|scalar| {
        PublicKey::from_affine(reference(&AffinePoint::GENERATOR, &Scalar::from(scalar))).unwrap()
    });
    let check = |scalar| {
        for peer in &peers {
            assert_eq!(
                *mul(peer, &scalar).unwrap().expose(),
                reference(peer.as_affine(), &scalar)
            );
        }
    };
    for bit in 0..SCALAR_BITS {
        let mut repr = FieldBytes::<Curve>::default();
        repr[SCALAR_BITS / 8 - 1 - bit / 8] = 1 << (bit % 8);
        check(Scalar::from_repr(repr).unwrap());
    }
    let mut state = 0x5a17842fc3906be1u64;
    for _ in 0..128 {
        let mut repr = FieldBytes::<Curve>::default();
        for bytes in repr.chunks_exact_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            bytes.copy_from_slice(&state.to_be_bytes());
        }
        check(
            <Scalar as Reduce<<Curve as elliptic_curve::Curve>::Uint>>::reduce(
                &<Curve as elliptic_curve::Curve>::Uint::from_be_slice(&repr),
            ),
        );
    }
}

#[test]
fn general_a_doubling_matches_full_points_with_non_unit_z() {
    for multiple in [1u64, 7, 19] {
        let point = reference(&AffinePoint::GENERATOR, &Scalar::from(multiple));
        let expected = ProjectivePoint::from(point).double().to_affine();
        for scale in [1, 7] {
            let mut actual = scaled(&point, scale);
            actual.double();
            assert_eq!(actual.affine().unwrap(), expected);
        }
    }
}
