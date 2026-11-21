//! This module implements Least common multiple (LCM) for [`BoxedUint`].

use crate::{BoxedUint, ConcatenatingMul, Gcd, Lcm};

impl Lcm for BoxedUint {
    type Output = Self;

    fn lcm(&self, rhs: &Self) -> Self {
        let (lhs_nz, _) = self.to_nz_or_one();
        let gcd_nz = lhs_nz.gcd(rhs);
        self.div_exact(&gcd_nz)
            .expect("invalid gcd")
            .concatenating_mul(rhs)
    }

    fn lcm_vartime(&self, rhs: &Self) -> Self {
        let (Some(lhs_nz), false) = (self.as_nz_vartime(), rhs.is_zero_vartime()) else {
            return BoxedUint::zero_with_precision(self.bits_precision() + rhs.bits_precision());
        };
        let gcd_nz = lhs_nz.gcd_vartime(rhs);
        self.div_exact_vartime(&gcd_nz)
            .expect("invalid gcd")
            .concatenating_mul(rhs)
    }
}

#[cfg(test)]
mod tests {
    mod lcm {
        use crate::{BoxedUint, Lcm};

        fn test(lhs: &BoxedUint, rhs: &BoxedUint, target: &BoxedUint) {
            assert_eq!(lhs.lcm(rhs), target);
            assert_eq!(lhs.lcm_vartime(rhs), target);
        }

        #[test]
        fn lcm_sizes() {
            let sizes = [128, 256];
            for size in sizes {
                test(
                    &BoxedUint::zero_with_precision(size),
                    &BoxedUint::zero_with_precision(size),
                    &BoxedUint::zero(),
                );
                test(
                    &BoxedUint::zero_with_precision(size),
                    &BoxedUint::one_with_precision(size),
                    &BoxedUint::zero(),
                );
                test(
                    &BoxedUint::zero_with_precision(size),
                    &BoxedUint::max(size),
                    &BoxedUint::zero(),
                );
                test(
                    &BoxedUint::one_with_precision(size),
                    &BoxedUint::zero_with_precision(size),
                    &BoxedUint::zero(),
                );
                test(
                    &BoxedUint::one_with_precision(size),
                    &BoxedUint::one_with_precision(size),
                    &BoxedUint::one(),
                );
                test(
                    &BoxedUint::one_with_precision(size),
                    &BoxedUint::max(size),
                    &BoxedUint::max(size),
                );
                test(
                    &BoxedUint::max(size),
                    &BoxedUint::zero_with_precision(size),
                    &BoxedUint::zero(),
                );
                test(
                    &BoxedUint::max(size),
                    &BoxedUint::one_with_precision(size),
                    &BoxedUint::max(size),
                );
                test(
                    &BoxedUint::max(size),
                    &BoxedUint::max(size),
                    &BoxedUint::max(size),
                );
            }
        }
    }
}
