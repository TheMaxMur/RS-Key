//! This module implements Least common multiple (LCM) for [`Uint`].

use crate::{Concat, Lcm, Uint};

impl<const LIMBS: usize> Uint<LIMBS> {
    /// Compute the least common multiple of `self` and `rhs`.
    #[must_use]
    pub const fn lcm<const WIDE_LIMBS: usize>(&self, rhs: &Self) -> Uint<WIDE_LIMBS>
    where
        Self: Concat<LIMBS, Output = Uint<WIDE_LIMBS>>,
    {
        let (lhs_nz, _) = self.to_nz_or_one();
        let gcd_nz = lhs_nz.gcd_unsigned(rhs);
        self.div_exact(&gcd_nz)
            .expect_copied("invalid gcd")
            .concatenating_mul(rhs)
    }

    /// Compute the least common multiple of `self` and `rhs`.
    ///
    /// This method is variable time with respect to `self` and `rhs`.
    #[must_use]
    pub const fn lcm_vartime<const WIDE_LIMBS: usize>(&self, rhs: &Self) -> Uint<WIDE_LIMBS>
    where
        Self: Concat<LIMBS, Output = Uint<WIDE_LIMBS>>,
    {
        let (Some(lhs_nz), false) = (self.as_nz_vartime(), rhs.is_zero_vartime()) else {
            return Uint::ZERO;
        };
        let gcd_nz = lhs_nz.gcd_unsigned_vartime(rhs);
        self.div_exact_vartime(&gcd_nz)
            .expect_copied("invalid gcd")
            .concatenating_mul(rhs)
    }
}

impl<const LIMBS: usize, const WIDE_LIMBS: usize> Lcm for Uint<LIMBS>
where
    Self: Concat<LIMBS, Output = Uint<WIDE_LIMBS>>,
{
    type Output = Uint<WIDE_LIMBS>;

    fn lcm(&self, rhs: &Self) -> Self::Output {
        self.lcm(rhs)
    }

    fn lcm_vartime(&self, rhs: &Self) -> Self::Output {
        self.lcm_vartime(rhs)
    }
}

#[cfg(test)]
mod tests {
    mod lcm {
        use crate::{Concat, Lcm, U64, U128, U512, U1024, U4096, U8192, Uint};

        fn test<const LIMBS: usize, const WIDE_LIMBS: usize>(
            lhs: Uint<LIMBS>,
            rhs: Uint<LIMBS>,
            target: Uint<WIDE_LIMBS>,
        ) where
            Uint<LIMBS>: Concat<LIMBS, Output = Uint<WIDE_LIMBS>>,
        {
            assert_eq!(lhs.lcm(&rhs), target);
            assert_eq!(lhs.lcm_vartime(&rhs), target);
            assert_eq!(Lcm::lcm(&lhs, &rhs), target);
            assert_eq!(Lcm::lcm_vartime(&lhs, &rhs), target);
        }

        fn run_tests<const LIMBS: usize, const WIDE_LIMBS: usize>()
        where
            Uint<LIMBS>: Concat<LIMBS, Output = Uint<WIDE_LIMBS>>,
        {
            test(Uint::<LIMBS>::ZERO, Uint::ZERO, Uint::<WIDE_LIMBS>::ZERO);
            test(Uint::<LIMBS>::ZERO, Uint::ONE, Uint::<WIDE_LIMBS>::ZERO);
            test(Uint::<LIMBS>::ZERO, Uint::MAX, Uint::<WIDE_LIMBS>::ZERO);
            test(Uint::<LIMBS>::ONE, Uint::ZERO, Uint::<WIDE_LIMBS>::ZERO);
            test(Uint::<LIMBS>::ONE, Uint::ONE, Uint::<WIDE_LIMBS>::ONE);
            test(
                Uint::<LIMBS>::ONE,
                Uint::MAX,
                Uint::<LIMBS>::MAX.resize::<WIDE_LIMBS>(),
            );
            test(Uint::<LIMBS>::MAX, Uint::ZERO, Uint::<WIDE_LIMBS>::ZERO);
            test(
                Uint::<LIMBS>::MAX,
                Uint::ONE,
                Uint::<LIMBS>::MAX.resize::<WIDE_LIMBS>(),
            );
            test(
                Uint::<LIMBS>::MAX,
                Uint::MAX,
                Uint::<LIMBS>::MAX.resize::<WIDE_LIMBS>(),
            );
        }

        #[test]
        fn lcm_sizes() {
            run_tests::<{ U64::LIMBS }, { U128::LIMBS }>();
            run_tests::<{ U512::LIMBS }, { U1024::LIMBS }>();
            if cfg!(not(miri)) {
                run_tests::<{ U4096::LIMBS }, { U8192::LIMBS }>();
            }
        }
    }
}
