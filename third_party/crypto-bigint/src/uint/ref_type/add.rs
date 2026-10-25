use super::UintRef;
use crate::{Choice, Limb};

impl UintRef {
    /// Perform an in-place carrying add of a limb, returning the carried limb value.
    #[inline]
    pub const fn add_assign_limb(&mut self, mut rhs: Limb) -> Limb {
        let mut i = 0;
        while i < self.limbs.len() {
            (self.limbs[i], rhs) = self.limbs[i].overflowing_add(rhs);
            i += 1;
        }
        rhs
    }

    /// Perform an in-place carrying add of another [`UintRef`], returning the carried limb value.
    ///
    /// # Panics
    /// If `self` is shorter than `rhs`.
    #[inline]
    #[track_caller]
    pub const fn carrying_add_assign(&mut self, rhs: &Self, carry: Limb) -> Limb {
        self.carrying_add_assign_slice(&rhs.limbs, carry)
    }

    /// Perform an in-place carrying add of another limb slice, returning the carried limb value.
    ///
    /// # Panics
    /// If `self` is shorter than `rhs`.
    #[inline]
    #[track_caller]
    pub const fn carrying_add_assign_slice(&mut self, rhs: &[Limb], mut carry: Limb) -> Limb {
        assert!(
            self.limbs.len() >= rhs.len(),
            "length mismatch in carrying_add_assign_slice"
        );
        let mut i = 0;
        while i < rhs.len() {
            (self.limbs[i], carry) = self.limbs[i].carrying_add(rhs[i], carry);
            i += 1;
        }
        while i < self.limbs.len() {
            (self.limbs[i], carry) = self.limbs[i].overflowing_add(carry);
            i += 1;
        }
        carry
    }

    /// Perform an in-place carrying add of another limb slice, returning the carried limb value.
    ///
    /// # Panics
    /// If `self` is shorter than `rhs`.
    #[inline]
    #[track_caller]
    pub const fn conditional_add_assign(
        &mut self,
        rhs: &Self,
        carry: Limb,
        choice: Choice,
    ) -> Limb {
        self.conditional_add_assign_slice(rhs.as_limbs(), carry, choice)
    }

    /// Perform an in-place carrying add of another limb slice, returning the carried limb value.
    ///
    /// # Panics
    /// If `self` is shorter than `rhs`.
    #[inline]
    #[track_caller]
    pub const fn conditional_add_assign_slice(
        &mut self,
        rhs: &[Limb],
        mut carry: Limb,
        choice: Choice,
    ) -> Limb {
        assert!(
            self.limbs.len() >= rhs.len(),
            "length mismatch in conditional_add_assign_slice"
        );
        let mut i = 0;
        while i < rhs.len() {
            (self.limbs[i], carry) =
                self.limbs[i].carrying_add(Limb::select(Limb::ZERO, rhs[i], choice), carry);
            i += 1;
        }
        while i < self.limbs.len() {
            (self.limbs[i], carry) = self.limbs[i].overflowing_add(carry);
            i += 1;
        }
        carry
    }

    /// Perform an in-place carrying add of another [`UintRef`] multiplied by
    /// a limb, returning the carried limb value.
    ///
    /// # Panics
    /// If `self` is shorter than `rhs`.
    #[inline]
    #[track_caller]
    pub const fn carrying_add_assign_mul_limb(
        &mut self,
        rhs: &Self,
        rhs_mul: Limb,
        mut carry: Limb,
    ) -> Limb {
        assert!(
            self.limbs.len() >= rhs.limbs.len(),
            "length mismatch in carrying_add_assign_mul_limb"
        );
        let mut i = 0;
        while i < rhs.limbs.len() {
            (self.limbs[i], carry) = rhs.limbs[i].carrying_mul_add(rhs_mul, self.limbs[i], carry);
            i += 1;
        }
        self.trailing_mut(i).add_assign_limb(carry)
    }
}

#[cfg(test)]
mod tests {
    use crate::{Choice, Limb, UintRef, Unsigned};

    #[test]
    fn carrying_add_assign_mixed() {
        let mut a = [Limb::MAX];
        let carry =
            UintRef::new_mut(&mut a).carrying_add_assign(Limb::ONE.as_uint_ref(), Limb::ZERO);
        assert_eq!((a, carry), ([Limb::ZERO], Limb::ONE));

        let mut a = [Limb::MAX];
        let carry = UintRef::new_mut(&mut a).conditional_add_assign(
            Limb::ONE.as_uint_ref(),
            Limb::ZERO,
            Choice::FALSE,
        );
        assert_eq!((a, carry), ([Limb::MAX], Limb::ZERO));

        let mut a = [Limb::MAX];
        let carry = UintRef::new_mut(&mut a).conditional_add_assign(
            Limb::ONE.as_uint_ref(),
            Limb::ZERO,
            Choice::TRUE,
        );
        assert_eq!((a, carry), ([Limb::ZERO], Limb::ONE));

        let mut a = [Limb::MAX, Limb::MAX];
        let carry =
            UintRef::new_mut(&mut a).carrying_add_assign(Limb::ZERO.as_uint_ref(), Limb::ONE);
        assert_eq!((a, carry), ([Limb::ZERO, Limb::ZERO], Limb::ONE));

        let mut a = [Limb::MAX, Limb::MAX];
        let carry = UintRef::new_mut(&mut a).conditional_add_assign(
            Limb::MAX.as_uint_ref(),
            Limb::ONE,
            Choice::TRUE,
        );
        assert_eq!((a, carry), ([Limb::MAX, Limb::ZERO], Limb::ONE));
    }
}
