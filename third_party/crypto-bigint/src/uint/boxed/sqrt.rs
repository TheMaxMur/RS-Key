//! [`BoxedUint`] square root operations.

use crate::{BoxedUint, CheckedSquareRoot, Choice, CtOption, FloorSquareRoot, NonZero};

impl BoxedUint {
    /// Computes `floor(√(self))` in constant time.
    ///
    /// Callers can check if `self` is a square by squaring the result.
    #[deprecated(since = "0.7.0", note = "please use `floor_sqrt` instead")]
    #[must_use]
    pub fn sqrt(&self) -> Self {
        self.floor_sqrt()
    }

    /// Computes √(`self`) in constant time.
    ///
    /// Callers can check if `self` is a square by squaring the result, or use
    /// `checked_sqrt`.
    #[must_use]
    pub fn floor_sqrt(&self) -> Self {
        let mut root = self.clone();
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
    pub fn sqrt_vartime(&self) -> Self {
        self.floor_sqrt_vartime()
    }

    /// Computes √(`self`).
    ///
    /// Callers can check if `self` is a square by squaring the result, or use
    /// `checked_sqrt_vartime`.
    ///
    /// Variable time with respect to `self`.
    #[must_use]
    pub fn floor_sqrt_vartime(&self) -> Self {
        let mut root = self.clone();
        root.floor_sqrt_assign_vartime();
        root
    }

    /// Wrapped sqrt is just `floor(√(self))`.
    /// There’s no way wrapping could ever happen.
    /// This function exists so that all operations are accounted for in the wrapping operations.
    #[must_use]
    pub fn wrapping_sqrt(&self) -> Self {
        self.floor_sqrt()
    }

    /// Wrapped sqrt is just `floor(√(self))`.
    /// There’s no way wrapping could ever happen.
    /// This function exists so that all operations are accounted for in the wrapping operations.
    ///
    /// Variable time with respect to `self`.
    #[must_use]
    pub fn wrapping_sqrt_vartime(&self) -> Self {
        self.floor_sqrt_vartime()
    }

    /// Perform checked sqrt, returning a [`CtOption`] which `is_some`
    /// only if the square root is exact.
    #[must_use]
    pub fn checked_sqrt(&self) -> CtOption<Self> {
        let mut root = self.clone();
        let exact = root.floor_sqrt_assign();
        CtOption::new(root, exact)
    }

    /// Perform checked sqrt, returning an [`Option`] which `is_some`
    /// only if the square root is exact.
    ///
    /// Variable time with respect to `self`.
    #[must_use]
    pub fn checked_sqrt_vartime(&self) -> Option<Self> {
        let mut root = self.clone();
        if root.floor_sqrt_assign_vartime() {
            Some(root)
        } else {
            None
        }
    }

    /// Assigns `floor(√(self))` to `self` in constant time, and returns a [`Choice`]
    /// indicating whether the square root is exact.
    fn floor_sqrt_assign(&mut self) -> Choice {
        let size = self.nlimbs();
        let mut buf = Self::zero_with_precision(self.bits_precision() * 2);
        self.as_mut_uint_ref()
            .sqrt_assign(buf.as_mut_uint_ref().split_at_mut(size))
    }

    /// Assigns `floor(√(self))` to `self`, and returns a [`bool`]
    /// indicating whether the square root is exact.
    ///
    /// Variable time with respect to `self`.
    pub fn floor_sqrt_assign_vartime(&mut self) -> bool {
        let size = self.nlimbs();
        let mut buf = Self::zero_with_precision(self.bits_precision() * 2);
        self.as_mut_uint_ref()
            .sqrt_assign_vartime(buf.as_mut_uint_ref().split_at_mut(size))
    }
}

impl CheckedSquareRoot for BoxedUint {
    type Output = Self;

    fn checked_sqrt(&self) -> CtOption<Self::Output> {
        self.checked_sqrt()
    }

    fn checked_sqrt_vartime(&self) -> Option<Self::Output> {
        self.checked_sqrt_vartime()
    }
}

impl FloorSquareRoot for BoxedUint {
    fn floor_sqrt(&self) -> Self {
        self.floor_sqrt()
    }

    fn floor_sqrt_vartime(&self) -> Self {
        self.floor_sqrt_vartime()
    }
}

impl CheckedSquareRoot for NonZero<BoxedUint> {
    type Output = Self;

    fn checked_sqrt(&self) -> CtOption<Self> {
        self.as_ref().checked_sqrt().map(NonZero::new_unchecked)
    }

    fn checked_sqrt_vartime(&self) -> Option<Self> {
        self.as_ref()
            .checked_sqrt_vartime()
            .map(NonZero::new_unchecked)
    }
}

impl FloorSquareRoot for NonZero<BoxedUint> {
    fn floor_sqrt(&self) -> Self {
        NonZero::new_unchecked(self.as_ref().floor_sqrt())
    }

    fn floor_sqrt_vartime(&self) -> Self {
        NonZero::new_unchecked(self.as_ref().floor_sqrt_vartime())
    }
}

#[cfg(test)]
#[allow(clippy::integer_division_remainder_used, reason = "test")]
mod tests {
    use crate::{BoxedUint, CheckedSquareRoot, FloorSquareRoot, Limb};

    #[cfg(feature = "rand_core")]
    use {
        crate::{ConcatenatingSquare, RandomBits},
        chacha20::ChaCha8Rng,
        rand_core::{Rng, SeedableRng},
    };

    #[test]
    fn edge() {
        assert_eq!(
            BoxedUint::zero_with_precision(256).floor_sqrt(),
            BoxedUint::zero_with_precision(256)
        );
        assert_eq!(
            BoxedUint::one_with_precision(256).floor_sqrt(),
            BoxedUint::one_with_precision(256)
        );
        let mut half = BoxedUint::zero_with_precision(256);
        for i in 0..half.limbs.len() / 2 {
            half.limbs[i] = Limb::MAX;
        }
        let u256_max = BoxedUint::max(256);
        assert_eq!(u256_max.floor_sqrt(), half);

        // Test edge cases that use up the maximum number of iterations.

        // `x = (r + 1)^2 - 583`, where `r` is the expected square root.
        assert_eq!(
            BoxedUint::from_be_hex("055fa39422bd9f281762946e056535badbf8a6864d45fa3d", 192)
                .unwrap()
                .floor_sqrt(),
            BoxedUint::from_be_hex("0000000000000000000000002516f0832a538b2d98869e21", 192)
                .unwrap(),
        );
        assert_eq!(
            BoxedUint::from_be_hex("055fa39422bd9f281762946e056535badbf8a6864d45fa3d", 192)
                .unwrap()
                .floor_sqrt_vartime(),
            BoxedUint::from_be_hex("0000000000000000000000002516f0832a538b2d98869e21", 192)
                .unwrap()
        );

        // `x = (r + 1)^2 - 205`, where `r` is the expected square root.
        assert_eq!(
            BoxedUint::from_be_hex(
                "4bb750738e25a8f82940737d94a48a91f8cd918a3679ff90c1a631f2bd6c3597",
                256
            )
            .unwrap()
            .floor_sqrt(),
            BoxedUint::from_be_hex(
                "000000000000000000000000000000008b3956339e8315cff66eb6107b610075",
                256
            )
            .unwrap()
        );
        assert_eq!(
            BoxedUint::from_be_hex(
                "4bb750738e25a8f82940737d94a48a91f8cd918a3679ff90c1a631f2bd6c3597",
                256
            )
            .unwrap()
            .floor_sqrt_vartime(),
            BoxedUint::from_be_hex(
                "000000000000000000000000000000008b3956339e8315cff66eb6107b610075",
                256
            )
            .unwrap()
        );
    }

    #[test]
    fn edge_vartime() {
        assert_eq!(
            BoxedUint::zero_with_precision(256).floor_sqrt_vartime(),
            BoxedUint::zero_with_precision(256)
        );
        assert_eq!(
            BoxedUint::one_with_precision(256).floor_sqrt_vartime(),
            BoxedUint::one_with_precision(256)
        );
        let mut half = BoxedUint::zero_with_precision(256);
        for i in 0..half.limbs.len() / 2 {
            half.limbs[i] = Limb::MAX;
        }
        let u256_max = !BoxedUint::zero_with_precision(256);
        assert_eq!(u256_max.floor_sqrt_vartime(), half);
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
            let l = BoxedUint::from(*a);
            let r = BoxedUint::from(*e);
            assert_eq!(l.floor_sqrt(), r);
            assert_eq!(l.floor_sqrt_vartime(), r);
            assert_eq!(
                CheckedSquareRoot::checked_sqrt(&l).into_option().as_ref(),
                Some(&r)
            );
            assert_eq!(
                CheckedSquareRoot::checked_sqrt_vartime(&l).as_ref(),
                Some(&r)
            );
            let nz_l = l.as_nz_vartime().unwrap();
            let nz_r = r.to_nz().unwrap();
            assert_eq!(FloorSquareRoot::floor_sqrt(nz_l), nz_r);
            assert_eq!(FloorSquareRoot::floor_sqrt_vartime(nz_l), nz_r);
            assert_eq!(
                CheckedSquareRoot::checked_sqrt(nz_l).into_option().as_ref(),
                Some(&nz_r)
            );
            assert_eq!(
                CheckedSquareRoot::checked_sqrt_vartime(nz_l).as_ref(),
                Some(&nz_r)
            );
        }
    }

    #[test]
    fn nonsquares() {
        assert_eq!(BoxedUint::from(2u8).floor_sqrt(), BoxedUint::from(1u8));
        assert!(!BoxedUint::from(2u8).checked_sqrt().is_some().to_bool());
        assert_eq!(BoxedUint::from(3u8).floor_sqrt(), BoxedUint::from(1u8));
        assert!(!BoxedUint::from(3u8).checked_sqrt().is_some().to_bool());
        assert_eq!(BoxedUint::from(5u8).floor_sqrt(), BoxedUint::from(2u8));
        assert_eq!(BoxedUint::from(6u8).floor_sqrt(), BoxedUint::from(2u8));
        assert_eq!(BoxedUint::from(7u8).floor_sqrt(), BoxedUint::from(2u8));
        assert_eq!(BoxedUint::from(8u8).floor_sqrt(), BoxedUint::from(2u8));
        assert_eq!(BoxedUint::from(10u8).floor_sqrt(), BoxedUint::from(3u8));
    }

    #[test]
    fn nonsquares_vartime() {
        assert_eq!(
            BoxedUint::from(2u8).floor_sqrt_vartime(),
            BoxedUint::from(1u8)
        );
        assert!(BoxedUint::from(2u8).checked_sqrt_vartime().is_none());
        assert_eq!(
            BoxedUint::from(3u8).floor_sqrt_vartime(),
            BoxedUint::from(1u8)
        );
        assert!(BoxedUint::from(3u8).checked_sqrt_vartime().is_none());
        assert_eq!(
            BoxedUint::from(5u8).floor_sqrt_vartime(),
            BoxedUint::from(2u8)
        );
        assert_eq!(
            BoxedUint::from(6u8).floor_sqrt_vartime(),
            BoxedUint::from(2u8)
        );
        assert_eq!(
            BoxedUint::from(7u8).floor_sqrt_vartime(),
            BoxedUint::from(2u8)
        );
        assert_eq!(
            BoxedUint::from(8u8).floor_sqrt_vartime(),
            BoxedUint::from(2u8)
        );
        assert_eq!(
            BoxedUint::from(10u8).floor_sqrt_vartime(),
            BoxedUint::from(3u8)
        );
    }

    #[cfg(feature = "rand_core")]
    #[test]
    fn fuzz() {
        let mut rng = ChaCha8Rng::from_seed([7u8; 32]);
        let rounds = if cfg!(miri) { 10 } else { 50 };
        for _ in 0..rounds {
            let t = u64::from(rng.next_u32());
            let s = BoxedUint::from(t);
            let s2 = s.checked_mul(&s).unwrap();
            assert_eq!(s2.floor_sqrt(), s);
            assert_eq!(s2.floor_sqrt_vartime(), s);
            assert!(CheckedSquareRoot::checked_sqrt(&s2).is_some().to_bool());
            assert!(CheckedSquareRoot::checked_sqrt_vartime(&s2).is_some());
        }

        for _ in 0..rounds {
            let s = BoxedUint::random_bits(&mut rng, 512);
            let mut s2 = BoxedUint::zero_with_precision(512);
            s2.limbs[..s.limbs.len()].copy_from_slice(&s.limbs);
            assert_eq!(s.concatenating_square().floor_sqrt(), s2);
            assert_eq!(s.concatenating_square().floor_sqrt_vartime(), s2);
        }
    }

    #[test]
    // test input from issue #1303
    fn sqrt_edge() {
        let sq = BoxedUint::from_be_hex(
            "0000000000000AB88E41D05334F646EE1B715C614C81DCE1C46E2E021EF2E7FA45E5DD2CC670725E52B091A0E08B1E9E6C43262581226A7BFDE534F704D6DC6C1FD5C93B3AE4FB73C9D26EBC09DB83040C2CD157884532EB5578CEF2BA95E87C7F6E328F062BB20D3C95D122EB4D26727901A424AF14143EBCEFE5D5958E9EDEA73649F5C76932D491C4A51C370F51E6DBEB66D56D7FB51A",
            1216,
        ).unwrap();
        let expect = BoxedUint::from_be_hex(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000346375360711FDFC13BE3CF276FCC535C2E29164A842D3B71E2C7DFA60AE0E24CD0CC65AD7A3B626E03DAC8260D921AB8E16C6757D2CA8DEE5DFA62E5C1CB3C90A49B9F1A192498905",
                1216,
            ).unwrap();
        assert_eq!(sq.floor_sqrt(), expect);
        assert_eq!(sq.floor_sqrt_vartime(), expect);
    }
}
