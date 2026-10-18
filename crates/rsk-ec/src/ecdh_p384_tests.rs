// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use p384::elliptic_curve::ops::Double;

#[test]
fn point_wipe_clears_every_coordinate() {
    let mut point = Secret::new(scaled(&p384::AffinePoint::GENERATOR, 7));
    point.wipe();
    assert_eq!(point.expose().x, FieldElement::ZERO);
    assert_eq!(point.expose().y, FieldElement::ZERO);
    assert_eq!(point.expose().z, FieldElement::ZERO);
}

fn reference(peer: &p384::AffinePoint, scalar: &p384::Scalar) -> p384::AffinePoint {
    (p384::ProjectivePoint::from(*peer) * scalar).to_affine()
}

fn coordinates(point: &p384::AffinePoint) -> Coordinates {
    [
        FieldElement::from_repr(point.x()).unwrap(),
        FieldElement::from_repr(point.y()).unwrap(),
    ]
}

fn scaled(point: &p384::AffinePoint, scale: u64) -> Jacobian {
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
    let mut scalars = [p384::Scalar::ZERO; 52];
    for (i, scalar) in scalars.iter_mut().take(20).enumerate() {
        *scalar = p384::Scalar::from(i as u64);
    }
    for (out, value) in scalars[20..36].iter_mut().zip(1..=16u64) {
        *out = -p384::Scalar::from(value);
    }
    for (out, bit) in scalars[36..].iter_mut().zip([
        4, 7, 8, 15, 31, 63, 95, 127, 159, 191, 223, 255, 287, 319, 335, 383,
    ]) {
        let mut repr = p384::FieldBytes::default();
        repr[47 - bit / 8] = 1 << (bit % 8);
        *out = p384::Scalar::from_repr(repr).unwrap();
    }
    for base_scalar in [
        p384::Scalar::ONE,
        p384::Scalar::from(17u64),
        -p384::Scalar::from(6u64),
    ] {
        let peer = (p384::ProjectivePoint::GENERATOR * base_scalar).to_affine();
        let public = p384::PublicKey::from_affine(peer).unwrap();
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
    let peer = p384::AffinePoint::GENERATOR;
    let public = p384::PublicKey::from_affine(peer).unwrap();
    let scalar = -p384::Scalar::from(6u64);
    let result = mul(&public, &scalar).unwrap();
    let wrong_sign = reference(&peer, &p384::Scalar::from(6u64));
    assert_eq!(result.expose().x(), wrong_sign.x());
    assert_ne!(result.expose().y(), wrong_sign.y());
    assert_eq!(*result.expose(), -wrong_sign);
}

#[test]
fn complete_mixed_add_handles_identity_equality_opposites_and_zero() {
    for multiple in [1u64, 3, 8] {
        let point = reference(&p384::AffinePoint::GENERATOR, &p384::Scalar::from(multiple));
        for point in [point, -point] {
            let twice = p384::ProjectivePoint::from(point).double().to_affine();
            let p = coordinates(&point);
            let p2 = coordinates(&twice);
            for scale in [1, 7] {
                let mut q = scaled(&point, scale);
                q.add_mixed(&p, &p2, Choice::from(0));
                assert_eq!(q.affine().unwrap(), twice);
                let mut q = scaled(&-point, scale);
                q.add_mixed(&p, &p2, Choice::from(0));
                assert_eq!(q.affine().unwrap(), p384::AffinePoint::IDENTITY);
                q.double();
                assert_eq!(q.affine().unwrap(), p384::AffinePoint::IDENTITY);
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
        p384::PublicKey::from_affine(reference(
            &p384::AffinePoint::GENERATOR,
            &p384::Scalar::from(scalar),
        ))
        .unwrap()
    });
    let check = |scalar| {
        for peer in &peers {
            assert_eq!(
                *mul(peer, &scalar).unwrap().expose(),
                reference(peer.as_affine(), &scalar)
            );
        }
    };
    for bit in 0..384 {
        let mut repr = p384::FieldBytes::default();
        repr[47 - bit / 8] = 1 << (bit % 8);
        check(p384::Scalar::from_repr(repr).unwrap());
    }
    let mut state = 0x5a17842fc3906be1u64;
    for _ in 0..128 {
        let mut repr = p384::FieldBytes::default();
        for bytes in repr.chunks_exact_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            bytes.copy_from_slice(&state.to_be_bytes());
        }
        check(p384::Scalar::from_repr(repr).unwrap());
    }
}
