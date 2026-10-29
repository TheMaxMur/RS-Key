// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use p521::elliptic_curve::{ops::Double, sec1::ToSec1Point};

#[test]
fn point_wipe_clears_every_coordinate() {
    let mut point = Secret::new(scaled(&p521::AffinePoint::GENERATOR, 7));
    point.wipe();
    assert_eq!(point.expose().x, FieldElement::ZERO);
    assert_eq!(point.expose().y, FieldElement::ZERO);
    assert_eq!(point.expose().z, FieldElement::ZERO);
}

fn reference(peer: &p521::AffinePoint, scalar: &p521::Scalar) -> p521::AffinePoint {
    (p521::ProjectivePoint::from(*peer) * scalar).to_affine()
}

fn coordinates(point: &p521::AffinePoint) -> Coordinates {
    [
        FieldElement::from_repr(point.x()).unwrap(),
        FieldElement::from_repr(point.y()).unwrap(),
    ]
}

fn scaled(point: &p521::AffinePoint, scale: u64) -> Jacobian {
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
    let mut scalars = [p521::Scalar::ZERO; 52];
    for (i, scalar) in scalars.iter_mut().take(20).enumerate() {
        *scalar = p521::Scalar::from(i as u64);
    }
    for (out, value) in scalars[20..36].iter_mut().zip(1..=16u64) {
        *out = -p521::Scalar::from(value);
    }
    for (out, bit) in scalars[36..].iter_mut().zip([
        4, 7, 8, 15, 31, 63, 127, 255, 383, 511, 515, 516, 517, 518, 519, 520,
    ]) {
        let mut repr = p521::FieldBytes::default();
        repr[65 - bit / 8] = 1 << (bit % 8);
        *out = p521::Scalar::from_repr(repr).unwrap();
    }
    for base_scalar in [
        p521::Scalar::ONE,
        p521::Scalar::from(17u64),
        -p521::Scalar::from(6u64),
    ] {
        let peer = (p521::ProjectivePoint::GENERATOR * base_scalar).to_affine();
        let public = p521::PublicKey::from_affine(peer).unwrap();
        for scalar in scalars {
            for scalar in [
                scalar - p521::Scalar::ONE,
                scalar,
                scalar + p521::Scalar::ONE,
            ] {
                assert_eq!(
                    *mul(&public, &scalar).unwrap().expose(),
                    reference(&peer, &scalar)
                );
            }
        }
    }
}

#[test]
fn carry_into_the_top_digit_preserves_the_full_point() {
    let peer = p521::PublicKey::from_affine(p521::AffinePoint::GENERATOR).unwrap();
    for byte in [0x80, 0x90, 0xf0] {
        let mut repr = p521::FieldBytes::default();
        repr[0] = 1;
        repr[1] = byte;
        let scalar = p521::Scalar::from_repr(repr).unwrap();
        assert_eq!(
            mul(&peer, &scalar).map(|point| *point.expose()),
            Ok(reference(peer.as_affine(), &scalar))
        );
    }
}

#[test]
fn negative_equal_point_fallback_preserves_y_as_well_as_shared_x() {
    let peer = p521::AffinePoint::GENERATOR;
    let public = p521::PublicKey::from_affine(peer).unwrap();
    let scalar = -p521::Scalar::from(6u64);
    let result = mul(&public, &scalar).unwrap();
    let wrong_sign = reference(&peer, &p521::Scalar::from(6u64));
    assert_eq!(result.expose().x(), wrong_sign.x());
    assert_ne!(result.expose().y(), wrong_sign.y());
    assert_eq!(*result.expose(), -wrong_sign);
}

#[test]
fn complete_mixed_add_handles_identity_equality_opposites_and_zero() {
    for multiple in [1u64, 3, 8] {
        let point = reference(&p521::AffinePoint::GENERATOR, &p521::Scalar::from(multiple));
        for point in [point, -point] {
            let twice = p521::ProjectivePoint::from(point).double().to_affine();
            let p = coordinates(&point);
            let p2 = coordinates(&twice);
            for scale in [1, 7] {
                let mut q = scaled(&point, scale);
                q.add_mixed(&p, &p2, Choice::from(0));
                assert_eq!(q.affine().unwrap(), twice);
                let mut q = scaled(&-point, scale);
                q.add_mixed(&p, &p2, Choice::from(0));
                assert_eq!(q.affine().unwrap(), p521::AffinePoint::IDENTITY);
                q.double();
                assert_eq!(q.affine().unwrap(), p521::AffinePoint::IDENTITY);
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
        p521::PublicKey::from_affine(reference(
            &p521::AffinePoint::GENERATOR,
            &p521::Scalar::from(scalar),
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
    for bit in 0..521 {
        let mut repr = p521::FieldBytes::default();
        repr[65 - bit / 8] = 1 << (bit % 8);
        check(p521::Scalar::from_repr(repr).unwrap());
    }
    let mut state = 0x5a17842fc3906be1u64;
    for _ in 0..128 {
        let mut repr = p521::FieldBytes::default();
        for bytes in repr.chunks_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            bytes.copy_from_slice(&state.to_be_bytes()[..bytes.len()]);
        }
        repr[0] &= 1;
        check(p521::Scalar::from_repr(repr).unwrap());
    }
}

#[test]
fn affine_conversion_refuses_off_curve_coordinates() {
    let corrupt = Jacobian {
        x: FieldElement::ZERO,
        y: FieldElement::ZERO,
        z: FieldElement::ONE,
    };
    assert!(bool::from(corrupt.affine().is_none()));
}

#[test]
fn private_key_ecdh_matches_upstream_and_preserves_output_canaries() {
    let mut top = p521::FieldBytes::default();
    top[0] = 1;
    let top = p521::Scalar::from_repr(top).unwrap();
    for scalar in [
        p521::Scalar::ONE,
        p521::Scalar::from(17u64),
        -p521::Scalar::ONE,
        top - p521::Scalar::ONE,
        top,
        top + p521::Scalar::ONE,
    ] {
        let bytes = scalar.to_repr();
        let key = crate::PrivKey::from_scalar(crate::Curve::P521, bytes.as_slice()).unwrap();
        let reference_key = p521::SecretKey::from_bytes(&bytes).unwrap();
        for peer_scalar in [
            p521::Scalar::ONE,
            p521::Scalar::from(17u64),
            -p521::Scalar::from(6u64),
        ] {
            let peer = p521::PublicKey::from_affine(reference(
                &p521::AffinePoint::GENERATOR,
                &peer_scalar,
            ))
            .unwrap();
            let encoded = peer.to_sec1_point(false);
            let expected =
                p521::ecdh::diffie_hellman(reference_key.to_nonzero_scalar(), peer.as_affine());
            let mut out = [0xa5; 72];
            assert_eq!(key.ecdh(encoded.as_bytes(), &mut out[2..70]), Ok(66));
            assert_eq!(&out[2..68], expected.raw_secret_bytes().as_slice());
            assert_eq!(&out[..2], &[0xa5; 2]);
            assert_eq!(&out[68..], &[0xa5; 4]);
        }
    }
}

#[test]
fn private_key_ecdh_preserves_validation_order_errors_and_output() {
    let key = crate::PrivKey::from_scalar(crate::Curve::P521, &[1]).unwrap();
    let point = p521::AffinePoint::GENERATOR.to_sec1_point(false);
    let compressed = p521::AffinePoint::GENERATOR.to_sec1_point(true);
    let mut off_curve = point.as_bytes().to_vec();
    *off_curve.last_mut().unwrap() ^= 1;
    let mut past_field = point.as_bytes().to_vec();
    past_field[1..67].fill(0xff);
    for (peer, error) in [
        (&[][..], EcError::BadPoint),
        (&[0][..], EcError::BadPoint),
        (&[4][..], EcError::BadPoint),
        (compressed.as_bytes(), EcError::BadPoint),
        (off_curve.as_slice(), EcError::RejectedPoint),
        (past_field.as_slice(), EcError::RejectedPoint),
    ] {
        let mut out = [0xa5; 72];
        assert_eq!(key.ecdh(peer, &mut out), Err(error));
        assert_eq!(out, [0xa5; 72]);
    }

    fn increment(bytes: &mut [u8]) {
        for byte in bytes.iter_mut().rev() {
            let (next, carry) = byte.overflowing_add(1);
            *byte = next;
            if !carry {
                break;
            }
        }
    }

    let mut order = (-p521::Scalar::ONE).to_repr();
    increment(&mut order);
    let mut above_order = order;
    increment(&mut above_order);
    for scalar in [
        p521::FieldBytes::default(),
        order,
        above_order,
        p521::FieldBytes::from([0xff; 66]),
    ] {
        let key = crate::PrivKey::from_scalar(crate::Curve::P521, scalar.as_slice()).unwrap();
        for peer in [point.as_bytes(), &[][..]] {
            let mut out = [0xa5; 72];
            assert_eq!(key.ecdh(peer, &mut out), Err(EcError::Failed));
            assert_eq!(out, [0xa5; 72]);
        }
    }
}

#[test]
fn one_double_matches_upstream_for_scaled_nonidentity_points() {
    for scalar in [
        p521::Scalar::ONE,
        p521::Scalar::from(3u64),
        p521::Scalar::from(8u64),
        -p521::Scalar::from(6u64),
    ] {
        let point = reference(&p521::AffinePoint::GENERATOR, &scalar);
        let expected = p521::ProjectivePoint::from(point).double().to_affine();
        for scale in [1, 7] {
            let mut actual = scaled(&point, scale);
            actual.double();
            assert_eq!(actual.affine().unwrap(), expected);
        }
    }
}

#[test]
fn table_coordinates_and_equality_fallback_match_upstream_multiples() {
    for scalar in [
        p521::Scalar::ONE,
        p521::Scalar::from(17u64),
        -p521::Scalar::from(6u64),
    ] {
        let peer = reference(&p521::AffinePoint::GENERATOR, &scalar);
        for (index, (point, twice)) in table(&peer).unwrap().iter().enumerate() {
            let multiple = p521::Scalar::from(index as u64 + 1);
            let expected = reference(&peer, &multiple);
            let expected_twice = reference(&peer, &(multiple + multiple));
            assert_eq!(*point, coordinates(&expected));
            assert_eq!(*twice, coordinates(&expected_twice));
            let mut equal = scaled(&expected, 7);
            equal.add_mixed(point, twice, Choice::from(0));
            assert_eq!(equal.affine().unwrap(), expected_twice);
        }
    }
}
