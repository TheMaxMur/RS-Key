//! [`BoxedUint`] modular multiplication operations.

use crate::{
    BoxedUint, ConcatenatingMul, ConcatenatingSquare, Limb, MulMod, NonZero, SquareMod, UintRef,
    div_limb::mul_rem,
};

impl BoxedUint {
    /// Computes `self * rhs mod p` for non-zero `p`.
    #[must_use]
    pub fn mul_mod(&self, rhs: &BoxedUint, p: &NonZero<BoxedUint>) -> BoxedUint {
        self.concatenating_mul(rhs).rem(p)
    }

    /// Computes `self * rhs mod p` for the special modulus
    /// `p = MAX+1-c` where `c` is small enough to fit in a single [`Limb`].
    ///
    /// When `c` is zero, `p = MAX+1` and the result is wrapping multiplication.
    ///
    /// For the modulus reduction, this function implements Algorithm 14.47 from
    /// the "Handbook of Applied Cryptography", by A. Menezes, P. van Oorschot,
    /// and S. Vanstone, CRC Press, 1996.
    #[must_use]
    pub fn mul_mod_special(&self, rhs: &Self, c: Limb) -> Self {
        debug_assert_eq!(self.bits_precision(), rhs.bits_precision());

        if self.nlimbs() == 1 {
            let a = self.limbs[0];
            let b = rhs.limbs[0];

            // For c = 0, use a nonzero placeholder divisor and select the
            // wrapping product in constant time.
            let (p, c_is_nonzero) = Limb::ZERO.wrapping_sub(c).to_nz_or_one();
            let reduced = mul_rem(a, b, p);
            let reduced = Limb::select(a.wrapping_mul(b), reduced, c_is_nonzero);
            return Self::from(reduced);
        }

        let product = self.concatenating_mul(rhs);
        let (lo, hi) = product.as_uint_ref().split_at(self.nlimbs());

        // Now use Algorithm 14.47 for the reduction
        let (mut lo, carry) = mac_by_limb(lo, hi, c, Limb::ZERO);

        let carry = {
            // Compute (carry + 1) * c without overflowing when carry is Limb::MAX.
            let rhs = carry.carrying_mul_add(c, c, Limb::ZERO);
            lo.carrying_add_assign(UintRef::new(&[rhs.0, rhs.1]), Limb::ZERO)
        };

        {
            let rhs = carry.wrapping_sub(Limb::ONE) & c;
            lo.borrowing_sub_assign(rhs, Limb::ZERO);
        }

        lo
    }

    /// Computes `self * self mod p`.
    #[must_use]
    pub fn square_mod(&self, p: &NonZero<BoxedUint>) -> Self {
        self.concatenating_square().rem(p)
    }

    /// Computes `self * self mod p` in variable time with respect to `p`.
    #[must_use]
    pub fn square_mod_vartime(&self, p: &NonZero<BoxedUint>) -> Self {
        self.concatenating_square().rem_vartime(p)
    }
}

impl MulMod for BoxedUint {
    type Output = Self;

    fn mul_mod(&self, rhs: &Self, p: &NonZero<Self>) -> Self {
        self.mul_mod(rhs, p)
    }
}

impl SquareMod for BoxedUint {
    type Output = Self;

    fn square_mod(&self, p: &NonZero<Self>) -> Self {
        self.square_mod(p)
    }
}

/// Computes `a + (b * c) + carry`, returning the result along with the new carry.
fn mac_by_limb(a: &UintRef, b: &UintRef, c: Limb, carry: Limb) -> (BoxedUint, Limb) {
    let mut res = BoxedUint::zero_with_precision(a.bits_precision());
    let mut carry = carry;

    for i in 0..a.nlimbs() {
        (res.limbs[i], carry) = b.limbs[i].carrying_mul_add(c, a.limbs[i], carry);
    }

    (res, carry)
}

#[cfg(all(test, feature = "rand_core"))]
mod tests {
    use crate::{BoxedUint, ConcatenatingMul, Limb, NonZero, Random, RandomMod, Resize};
    use rand_core::SeedableRng;

    #[test]
    fn mul_mod_special_zero_c() {
        for size in [1, 2, 3, 4] {
            let bits = size * Limb::BITS;
            let zero = BoxedUint::zero_with_precision(bits);
            let one = BoxedUint::one_with_precision(bits);
            let max = zero.wrapping_sub(&one);

            for a in [&zero, &one, &max] {
                for b in [&zero, &one, &max] {
                    assert_eq!(a.mul_mod_special(b, Limb::ZERO), a.wrapping_mul(b));
                }
            }
        }
    }

    #[test]
    fn mul_mod_special_max_c() {
        for size in [3, 4] {
            let bits = size * Limb::BITS;
            let c = BoxedUint::from(Limb::MAX).resize(bits);
            let p = NonZero::new(BoxedUint::zero_with_precision(bits).wrapping_sub(&c)).unwrap();
            let a = p.wrapping_sub(&c);

            // (p - c)^2 mod p = c^2. With at least three limbs, the first
            // reduction produces a carry of Limb::MAX, so carry + 1 overflows.
            let expected = c.wrapping_mul(&c);
            assert_eq!(a.mul_mod_special(&a, Limb::MAX), expected);
            assert_eq!(a.mul_mod(&a, &p), expected);
        }
    }

    #[test]
    fn mul_mod_special() {
        let mut rng = chacha20::ChaCha8Rng::seed_from_u64(1);
        let moduli = [
            NonZero::<Limb>::random_from_rng(&mut rng),
            NonZero::<Limb>::random_from_rng(&mut rng),
        ];
        let sizes = if cfg!(miri) {
            &[1, 2, 3][..]
        } else {
            &[1, 2, 3, 4, 8, 16][..]
        };

        for size in sizes.iter().copied() {
            let bits = size * Limb::BITS;

            for special in &moduli {
                let zero = BoxedUint::zero_with_precision(bits);
                let one = BoxedUint::one_with_precision(bits);
                let p = NonZero::new(zero.wrapping_sub(special.get())).unwrap();
                let minus_one = p.wrapping_sub(Limb::ONE);

                let base_cases = [
                    (&zero, &zero, &zero),
                    (&one, &zero, &zero),
                    (&zero, &one, &zero),
                    (&one, &one, &one),
                    (&minus_one, &minus_one, &one),
                    (&minus_one, &one, &minus_one),
                    (&one, &minus_one, &minus_one),
                ];
                for (a, b, c) in base_cases {
                    let x = a.mul_mod_special(b, *special.as_ref());
                    assert_eq!(&x, c, "{} * {} mod {} = {} != {}", a, b, p, x, c);
                }

                for _i in 0..100 {
                    let a = BoxedUint::random_mod_vartime(&mut rng, &p);
                    let b = BoxedUint::random_mod_vartime(&mut rng, &p);

                    let c = a.mul_mod_special(&b, *special.as_ref());
                    assert!(c < p.as_ref(), "not reduced: {} >= {} ", c, p);

                    let expected = {
                        let prod = a.concatenating_mul(&b);
                        prod.rem_vartime(&p)
                    };
                    assert_eq!(c, expected, "incorrect result");
                }
            }
        }
    }
}
