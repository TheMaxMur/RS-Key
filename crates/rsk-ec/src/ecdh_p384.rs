// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use p384::elliptic_curve::{
    PrimeField,
    hazmat::FieldArithmetic,
    point::{AffineCoordinates, BatchNormalize},
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
};
use rsk_secret::Secret;
use zeroize::Zeroize;

use crate::EcError;

type FieldElement = <p384::NistP384 as FieldArithmetic>::FieldElement;
type Coordinates = [FieldElement; 2];
const WIDTH: usize = 4;
const ENTRIES: usize = 1 << (WIDTH - 1);
const DIGITS: usize = 384 / WIDTH + 1;
type Table = [(Coordinates, Coordinates); ENTRIES];

#[derive(Clone, Copy)]
struct Jacobian {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
}

impl Zeroize for Jacobian {
    #[expect(
        clippy::disallowed_methods,
        reason = "Jacobian's wipe names every coordinate"
    )]
    fn zeroize(&mut self) {
        let Self { x, y, z } = self;
        x.zeroize();
        y.zeroize();
        z.zeroize();
    }
}

impl ConditionallySelectable for Jacobian {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
            z: FieldElement::conditional_select(&a.z, &b.z, choice),
        }
    }
}

impl Jacobian {
    const IDENTITY: Self = Self {
        x: FieldElement::ONE,
        y: FieldElement::ONE,
        z: FieldElement::ZERO,
    };

    fn from_affine(point: &Coordinates) -> Self {
        Self {
            x: point[0],
            y: point[1],
            z: FieldElement::ONE,
        }
    }

    // EFD dbl-2001-b: x=X/Z², y=Y/Z³, a=-3.
    fn double(&mut self) {
        let delta = self.z.square();
        let gamma = self.y.square();
        let beta = self.x * gamma;
        let alpha = (self.x - delta) * (self.x + delta);
        let alpha = alpha.double() + alpha;
        let x = alpha.square() - beta.double().double().double();
        // The bilinear Z-coordinate formula avoids the expanded cross term.
        let z = (self.y * self.z).double();
        let y = alpha * (beta.double().double() - x) - gamma.square().double().double().double();
        self.x = x;
        self.y = y;
        self.z = z;
    }

    // EFD madd-2007-bl, completed with masked equality/infinity/zero cases.
    fn add_mixed(&mut self, point: &Coordinates, twice: &Coordinates, zero: Choice) {
        let zz = self.z.square();
        let u = point[0] * zz;
        let s = point[1] * self.z * zz;
        let h = u - self.x;
        let hh = h.square();
        let i = hh.double().double();
        let j = h * i;
        let r = (s - self.y).double();
        let v = self.x * i;
        let x = r.square() - j - v.double();
        let y = r * (v - x) - (self.y * j).double();
        let z = (self.z * h).double();
        let mut sum = Secret::new(Self { x, y, z });
        let doubled = Secret::new(Self::from_affine(twice));
        let base = Secret::new(Self::from_affine(point));
        sum.expose_mut()
            .conditional_assign(doubled.expose(), h.is_zero() & r.is_zero());
        sum.expose_mut()
            .conditional_assign(base.expose(), self.z.is_zero());
        self.conditional_assign(sum.expose(), !zero);
    }

    fn affine(&self) -> CtOption<p384::AffinePoint> {
        let inv = Secret::new(self.z.invert().unwrap_or(FieldElement::ZERO));
        let inv2 = Secret::new(inv.expose().square());
        let xy = Secret::new([
            (self.x * inv2.expose()).to_repr(),
            (self.y * inv2.expose() * inv.expose()).to_repr(),
        ]);
        let point = p384::AffinePoint::from_coordinates(&xy.expose()[0], &xy.expose()[1]);
        let identity = self.z.is_zero();
        CtOption::new(
            p384::AffinePoint::conditional_select(
                &point.unwrap_or(p384::AffinePoint::IDENTITY),
                &p384::AffinePoint::IDENTITY,
                identity,
            ),
            point.is_some() | identity,
        )
    }
}

fn table(peer: &p384::AffinePoint) -> Result<Table, EcError> {
    let base = p384::ProjectivePoint::from(*peer);
    let mut multiples = [base; 2 * ENTRIES];
    for i in 1..multiples.len() {
        multiples[i] = multiples[i - 1] + base;
    }
    let affine = p384::ProjectivePoint::batch_normalize(&multiples);
    let mut table = [([FieldElement::ZERO; 2], [FieldElement::ZERO; 2]); ENTRIES];
    for (i, (point, twice)) in table.iter_mut().enumerate() {
        for (out, input) in [(point, &affine[i]), (twice, &affine[2 * i + 1])] {
            *out = [
                Option::from(FieldElement::from_repr(input.x())).ok_or(EcError::Failed)?,
                Option::from(FieldElement::from_repr(input.y())).ok_or(EcError::Failed)?,
            ];
        }
    }
    Ok(table)
}

// Keep the P-384 table frame out of the other PrivKey::ecdh arms.
#[inline(never)]
pub(super) fn mul(
    peer: &p384::PublicKey,
    scalar: &p384::Scalar,
) -> Result<Secret<p384::AffinePoint>, EcError> {
    let table = table(peer.as_affine())?;
    let repr = Secret::new(scalar.to_repr());
    let mut digits = Secret::new([0i8; DIGITS]);
    for (byte, pair) in repr
        .expose()
        .iter()
        .rev()
        .zip(digits.expose_mut().chunks_exact_mut(2))
    {
        pair[0] = i8::from_ne_bytes([byte & ((1 << WIDTH) - 1)]);
        pair[1] = i8::from_ne_bytes([byte >> WIDTH]);
    }
    for i in 0..DIGITS - 1 {
        let carry = (digits.expose()[i] + (1 << (WIDTH - 1))) >> WIDTH;
        digits.expose_mut()[i] -= carry << WIDTH;
        digits.expose_mut()[i + 1] += carry;
    }
    let mut q = Secret::new(Jacobian::IDENTITY);
    for digit in digits.expose().iter().rev() {
        for _ in 0..WIDTH {
            q.expose_mut().double();
        }
        let mask = digit >> 7;
        let magnitude = u8::from_ne_bytes(((digit + mask) ^ mask).to_ne_bytes());
        let sign = Choice::from(u8::from_ne_bytes(mask.to_ne_bytes()) & 1);
        let mut selected = Secret::new([[FieldElement::ZERO; 2]; 2]);
        for (index, (point, twice)) in (1u8..).zip(&table) {
            let choose = index.ct_eq(&magnitude);
            for (out, value) in selected.expose_mut().iter_mut().zip([point, twice]) {
                for (out, value) in out.iter_mut().zip(value) {
                    out.conditional_assign(value, choose);
                }
            }
        }
        for point in selected.expose_mut() {
            point[1].conditional_assign(&-point[1], sign);
        }
        q.expose_mut().add_mixed(
            &selected.expose()[0],
            &selected.expose()[1],
            magnitude.ct_eq(&0),
        );
    }
    Ok(Secret::new(
        Option::from(q.expose().affine()).ok_or(EcError::Failed)?,
    ))
}

#[cfg(test)]
#[path = "ecdh_p384_tests.rs"]
mod tests;
