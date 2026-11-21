use super::UintRef;
use crate::{Limb, Odd, primitives};

impl Odd<UintRef> {
    /// Returns the multiplicative inverse of the argument modulo 2^N, where 2^N
    /// is the capacity of a [`Limb`].
    #[must_use]
    pub(crate) const fn invert_mod_limb(&self) -> Limb {
        Odd::new_unchecked(self.as_ref().limbs[0]).multiplicative_inverse()
    }

    /// Returns the multiplicative inverse of the argument modulo 2^64.
    #[must_use]
    pub const fn invert_mod_u64(&self) -> u64 {
        let value = self.as_ref().lowest_u64();
        primitives::u64_invert_odd(value)
    }
}

#[cfg(test)]
mod tests {
    use crate::U128;

    #[test]
    fn invert_mod_u64() {
        let q = U128::ONE.to_odd().unwrap();
        let inv = q.as_uint_ref().invert_mod_u64();
        assert_eq!(inv, 0x1);

        let q = U128::from(3u64).to_odd().unwrap();
        let inv = q.as_uint_ref().invert_mod_u64();
        assert_eq!(inv, 0xaaaaaaaaaaaaaaab);

        let q = U128::from_be_hex("AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD")
            .to_odd()
            .unwrap();
        let inv = q.as_uint_ref().invert_mod_u64();
        assert_eq!(inv, 0xa6a0916b76276275);
    }
}
