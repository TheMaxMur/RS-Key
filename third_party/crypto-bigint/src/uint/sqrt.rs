//! [`Uint`] square root operations.

use ctutils::Choice;

use crate::{CheckedSquareRoot, CtOption, FloorSquareRoot, NonZero, Uint};

impl<const LIMBS: usize> Uint<LIMBS> {
    /// Computes `floor(√(self))` in constant time.
    ///
    /// Callers can check if `self` is a square by squaring the result.
    #[deprecated(since = "0.7.0", note = "please use `floor_sqrt` instead")]
    #[must_use]
    pub const fn sqrt(&self) -> Self {
        self.floor_sqrt()
    }

    /// Computes `floor(√(self))` in constant time.
    ///
    /// Callers can check if `self` is a square by squaring the result, or use
    /// `checked_sqrt`.
    #[must_use]
    pub const fn floor_sqrt(&self) -> Self {
        let mut root = *self;
        root.floor_sqrt_assign();
        root
    }

    /// Computes `floor(√(self))`.
    ///
    /// Callers can check if `self` is a square by squaring the result.
    ///
    /// Variable time with respect to `self`.
    #[deprecated(since = "0.7.0", note = "please use `floor_sqrt_vartime` instead")]
    #[must_use]
    pub const fn sqrt_vartime(&self) -> Self {
        self.floor_sqrt_vartime()
    }

    /// Computes `floor(√(self))`.
    ///
    /// Callers can check if `self` is a square by squaring the result.
    ///
    /// Variable time with respect to `self`.
    #[must_use]
    pub const fn floor_sqrt_vartime(&self) -> Self {
        let mut root = *self;
        root.floor_sqrt_assign_vartime();
        root
    }

    /// Wrapped sqrt is just `floor(√(self))`.
    /// There’s no way wrapping could ever happen.
    /// This function exists so that all operations are accounted for in the wrapping operations.
    #[must_use]
    pub const fn wrapping_sqrt(&self) -> Self {
        self.floor_sqrt()
    }

    /// Wrapped sqrt is just `floor(√(self))`.
    /// There’s no way wrapping could ever happen.
    /// This function exists so that all operations are accounted for in the wrapping operations.
    ///
    /// Variable time with respect to `self`.
    #[must_use]
    pub const fn wrapping_sqrt_vartime(&self) -> Self {
        self.floor_sqrt_vartime()
    }

    /// Perform checked sqrt, returning a [`CtOption`] which `is_some`
    /// only if the square root is exact.
    #[must_use]
    pub fn checked_sqrt(&self) -> CtOption<Self> {
        let mut root = *self;
        let exact = root.floor_sqrt_assign();
        CtOption::new(root, exact)
    }

    /// Perform checked sqrt, returning an [`Option`] which `is_some`
    /// only if the square root is exact.
    ///
    /// Variable time with respect to `self`.
    #[must_use]
    pub fn checked_sqrt_vartime(&self) -> Option<Self> {
        let mut root = *self;
        if root.floor_sqrt_assign_vartime() {
            Some(root)
        } else {
            None
        }
    }

    /// Assigns `floor(√(self))` to `self` and returns a [`Choice`] indicating
    /// whether the square root is exact.
    const fn floor_sqrt_assign(&mut self) -> Choice {
        let mut buf = (Uint::<LIMBS>::ZERO, Uint::<LIMBS>::ZERO);
        self.as_mut_uint_ref()
            .sqrt_assign((buf.0.as_mut_uint_ref(), buf.1.as_mut_uint_ref()))
    }

    /// Assigns `floor(√(self))` to `self` and returns a [`bool`] indicating
    /// whether the square root is exact.
    ///
    /// Variable time with respect to `self`.
    const fn floor_sqrt_assign_vartime(&mut self) -> bool {
        let mut buf = (Uint::<LIMBS>::ZERO, Uint::<LIMBS>::ZERO);
        self.as_mut_uint_ref()
            .sqrt_assign_vartime((buf.0.as_mut_uint_ref(), buf.1.as_mut_uint_ref()))
    }
}

impl<const LIMBS: usize> NonZero<Uint<LIMBS>> {
    /// Computes `floor(√(self))` in constant time.
    ///
    /// Callers can check if `self` is a square by squaring the result, or
    /// use `checked_sqrt`.
    #[must_use]
    pub const fn floor_sqrt(&self) -> Self {
        NonZero::new_unchecked(self.as_ref().floor_sqrt())
    }

    /// Computes `floor(√(self))`.
    ///
    /// Callers can check if `self` is a square by squaring the result, or
    /// use `checked_sqrt_vartime`.
    ///
    /// Variable time with respect to `self`.
    #[must_use]
    pub const fn floor_sqrt_vartime(&self) -> Self {
        NonZero::new_unchecked(self.as_ref().floor_sqrt_vartime())
    }

    /// Perform checked sqrt, returning a [`CtOption`] which `is_some`
    /// only if the square root is exact.
    #[must_use]
    pub fn checked_sqrt(&self) -> CtOption<Self> {
        self.as_ref().checked_sqrt().map(NonZero::new_unchecked)
    }

    /// Perform checked sqrt, returning an [`Option`] which `is_some`
    /// only if the square root is exact.
    #[must_use]
    pub fn checked_sqrt_vartime(&self) -> Option<Self> {
        self.as_ref()
            .checked_sqrt_vartime()
            .map(NonZero::new_unchecked)
    }
}

impl<const LIMBS: usize> CheckedSquareRoot for Uint<LIMBS> {
    type Output = Self;

    fn checked_sqrt(&self) -> CtOption<Self> {
        self.checked_sqrt()
    }

    fn checked_sqrt_vartime(&self) -> Option<Self> {
        self.checked_sqrt_vartime()
    }
}

impl<const LIMBS: usize> FloorSquareRoot for Uint<LIMBS> {
    fn floor_sqrt(&self) -> Self {
        self.floor_sqrt()
    }

    fn floor_sqrt_vartime(&self) -> Self {
        self.floor_sqrt_vartime()
    }
}

impl<const LIMBS: usize> CheckedSquareRoot for NonZero<Uint<LIMBS>> {
    type Output = Self;

    fn checked_sqrt(&self) -> CtOption<Self> {
        self.checked_sqrt()
    }

    fn checked_sqrt_vartime(&self) -> Option<Self> {
        self.checked_sqrt_vartime()
    }
}

impl<const LIMBS: usize> FloorSquareRoot for NonZero<Uint<LIMBS>> {
    fn floor_sqrt(&self) -> Self {
        self.floor_sqrt()
    }

    fn floor_sqrt_vartime(&self) -> Self {
        self.floor_sqrt_vartime()
    }
}

#[cfg(test)]
#[allow(clippy::integer_division_remainder_used, reason = "test")]
mod tests {
    use crate::{Limb, U192, U256};

    #[cfg(feature = "rand_core")]
    use {
        crate::{CheckedAdd, CheckedSquareRoot, Concat, FloorSquareRoot, Random, RandomBits, Uint},
        chacha20::ChaCha8Rng,
        rand_core::SeedableRng,
    };

    #[test]
    fn edge() {
        assert_eq!(U256::ZERO.floor_sqrt(), U256::ZERO);
        assert_eq!(U256::ONE.floor_sqrt(), U256::ONE);
        let mut half = U256::ZERO;
        for i in 0..half.limbs.len() / 2 {
            half.limbs[i] = Limb::MAX;
        }
        assert_eq!(U256::MAX.floor_sqrt(), half);

        // Test edge cases that use up the maximum number of iterations.

        // `x = (r + 1)^2 - 583`, where `r` is the expected square root.
        assert_eq!(
            U192::from_be_hex("055fa39422bd9f281762946e056535badbf8a6864d45fa3d").floor_sqrt(),
            U192::from_be_hex("0000000000000000000000002516f0832a538b2d98869e21")
        );
        assert_eq!(
            U192::from_be_hex("055fa39422bd9f281762946e056535badbf8a6864d45fa3d")
                .floor_sqrt_vartime(),
            U192::from_be_hex("0000000000000000000000002516f0832a538b2d98869e21")
        );

        // `x = (r + 1)^2 - 205`, where `r` is the expected square root.
        assert_eq!(
            U256::from_be_hex("4bb750738e25a8f82940737d94a48a91f8cd918a3679ff90c1a631f2bd6c3597")
                .floor_sqrt(),
            U256::from_be_hex("000000000000000000000000000000008b3956339e8315cff66eb6107b610075")
        );
        assert_eq!(
            U256::from_be_hex("4bb750738e25a8f82940737d94a48a91f8cd918a3679ff90c1a631f2bd6c3597")
                .floor_sqrt_vartime(),
            U256::from_be_hex("000000000000000000000000000000008b3956339e8315cff66eb6107b610075")
        );
    }

    #[test]
    fn edge_vartime() {
        assert_eq!(U256::ZERO.floor_sqrt_vartime(), U256::ZERO);
        assert_eq!(U256::ONE.floor_sqrt_vartime(), U256::ONE);
        let mut half = U256::ZERO;
        for i in 0..half.limbs.len() / 2 {
            half.limbs[i] = Limb::MAX;
        }
        assert_eq!(U256::MAX.floor_sqrt_vartime(), half);
    }

    #[test]
    fn simple() {
        let tests = [
            (4u8, 2u8),
            (9, 3),
            (16, 4),
            (25, 5),
            (36, 6),
            (49, 7),
            (64, 8),
            (81, 9),
            (100, 10),
            (121, 11),
            (144, 12),
            (169, 13),
        ];
        for (a, e) in &tests {
            let l = U256::from(*a);
            let r = U256::from(*e);
            assert_eq!(l.floor_sqrt(), r);
            assert_eq!(l.floor_sqrt_vartime(), r);
            assert!(l.checked_sqrt().is_some().to_bool());
            assert!(l.checked_sqrt_vartime().is_some());
        }
    }

    #[test]
    fn nonsquares() {
        assert_eq!(U256::from(2u8).floor_sqrt(), U256::from(1u8));
        assert!(!U256::from(2u8).checked_sqrt().is_some().to_bool());
        assert_eq!(U256::from(3u8).floor_sqrt(), U256::from(1u8));
        assert!(!U256::from(3u8).checked_sqrt().is_some().to_bool());
        assert_eq!(U256::from(5u8).floor_sqrt(), U256::from(2u8));
        assert_eq!(U256::from(6u8).floor_sqrt(), U256::from(2u8));
        assert_eq!(U256::from(7u8).floor_sqrt(), U256::from(2u8));
        assert_eq!(U256::from(8u8).floor_sqrt(), U256::from(2u8));
        assert_eq!(U256::from(10u8).floor_sqrt(), U256::from(3u8));
    }

    #[test]
    fn nonsquares_vartime() {
        assert_eq!(U256::from(2u8).floor_sqrt_vartime(), U256::from(1u8));
        assert!(U256::from(2u8).checked_sqrt_vartime().is_none());
        assert_eq!(U256::from(3u8).floor_sqrt_vartime(), U256::from(1u8));
        assert!(U256::from(3u8).checked_sqrt_vartime().is_none());
        assert_eq!(U256::from(5u8).floor_sqrt_vartime(), U256::from(2u8));
        assert_eq!(U256::from(6u8).floor_sqrt_vartime(), U256::from(2u8));
        assert_eq!(U256::from(7u8).floor_sqrt_vartime(), U256::from(2u8));
        assert_eq!(U256::from(8u8).floor_sqrt_vartime(), U256::from(2u8));
        assert_eq!(U256::from(10u8).floor_sqrt_vartime(), U256::from(3u8));
    }

    #[cfg(feature = "rand_core")]
    #[test]
    fn sqrt_fuzz() {
        fn check_size<const LIMBS: usize, const DOUBLE: usize>()
        where
            Uint<LIMBS>: Concat<LIMBS, Output = Uint<DOUBLE>>,
        {
            let mut rng = ChaCha8Rng::from_seed([7u8; 32]);
            for _ in 0..5000 {
                let s = Uint::<LIMBS>::random_bits(&mut rng, Uint::<LIMBS>::BITS / 2);
                let s2 = s.checked_square().unwrap();
                assert_eq!(FloorSquareRoot::floor_sqrt(&s2), s);
                assert_eq!(FloorSquareRoot::floor_sqrt_vartime(&s2), s);
                assert!(CheckedSquareRoot::checked_sqrt(&s2).is_some().to_bool());
                assert!(CheckedSquareRoot::checked_sqrt_vartime(&s2).is_some());

                if let Some(nz) = s2.to_nz().into_option() {
                    assert_eq!(FloorSquareRoot::floor_sqrt(&nz).get(), s);
                    assert_eq!(FloorSquareRoot::floor_sqrt_vartime(&nz).get(), s);
                    assert!(CheckedSquareRoot::checked_sqrt(&nz).is_some().to_bool());
                    assert!(CheckedSquareRoot::checked_sqrt_vartime(&nz).is_some());
                }

                if let Some(sx) = s2.checked_add(&Uint::ONE).into_option() {
                    assert_eq!(FloorSquareRoot::floor_sqrt(&sx), s);
                    assert_eq!(FloorSquareRoot::floor_sqrt_vartime(&sx), s);
                    assert!(CheckedSquareRoot::checked_sqrt(&sx).is_none().to_bool());
                    assert!(CheckedSquareRoot::checked_sqrt_vartime(&sx).is_none());
                }
            }

            for _ in 0..50 {
                let s = Uint::<LIMBS>::random_from_rng(&mut rng);
                let mut s2 = Uint::<DOUBLE>::ZERO;
                s2.limbs[..s.limbs.len()].copy_from_slice(&s.limbs);
                assert_eq!(s.concatenating_square().floor_sqrt(), s2);
                assert_eq!(s.concatenating_square().floor_sqrt_vartime(), s2);
            }
        }

        check_size::<1, 2>();
        check_size::<2, 4>();
        cpubits::cpubits! {
            64 => {
                check_size::<3, 6>();
            }
        }
        check_size::<4, 8>();
        check_size::<12, 24>();
    }
}
