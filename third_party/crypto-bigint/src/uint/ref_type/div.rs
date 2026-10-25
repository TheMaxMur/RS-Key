//! In-place integer division
//!
//! Based on Section 4.3.1, of The Art of Computer Programming, Volume 2, by Donald E. Knuth.
//! Further explanation at <https://janmr.com/blog/2014/04/basic-multiple-precision-long-division/>

use super::UintRef;
use crate::{
    Choice, Limb, NonZero, Odd, bitlen,
    div_limb::{Reciprocal, div2by1, div3by2},
    primitives::{u32_min, usize_lt},
    word,
};

// TODO(tarcieri): make `rhs` into `NonZeroUintRef` then make currently panicking functions `pub`
impl UintRef {
    /// Computes `self` / `rhs`, returning the quotient in `self` and the remainder in `rhs`.
    ///
    /// # Panics
    /// If the divisor is zero.
    #[inline(always)]
    pub(crate) const fn div_rem(&mut self, rhs: &mut Self) {
        let (x, y) = (self, rhs);

        // Short circuit for single-word divisor
        if y.nlimbs() == 1 {
            y.limbs[0] = x.div_rem_limb(y.limbs[0].to_nz().expect_copied("zero divisor"));
            return;
        }

        // Compute the size of the divisor
        let ybits = y.bits();
        assert!(ybits > 0, "zero divisor");
        let ywords = bitlen::to_limbs_u32(ybits);

        // Shift the entire divisor such that the high bit is set
        let yz = y.bits_precision() - ybits;
        y.unbounded_shl_assign(yz);

        // Shift the dividend to align the words
        let lshift = yz & (Limb::BITS - 1);
        let x_hi = x.shl_assign_limb(lshift);

        Self::div_rem_shifted(x, x_hi, y, ywords);

        x.unbounded_shr_assign_by_limbs(ywords - 1);
        y.shr_assign_limb(lshift);
    }

    /// Computes `self` / `rhs`, returning the quotient in `self` and the remainder in `rhs`.
    ///
    /// This function operates in variable-time with respect to `rhs`. For a fixed divisor,
    /// it operates in constant-time
    ///
    /// # Panics
    /// If the divisor is zero.
    pub(crate) const fn div_rem_vartime(&mut self, rhs: &mut Self) {
        let (x, y) = (self, rhs);
        let xsize = x.nlimbs();
        let ywords = bitlen::to_limbs(y.bits_vartime());

        match (xsize, ywords) {
            (_, 0) => panic!("zero divisor"),
            (0, _) => {
                // If the quotient is empty, set the remainder to zero and return.
                y.fill(Limb::ZERO);
                return;
            }
            (_, 1) => {
                // Perform limb division
                let rem_limb = x.div_rem_limb(y.limbs[0].to_nz().expect_copied("zero divisor"));
                y.fill(Limb::ZERO);
                y.limbs[0] = rem_limb;
                return;
            }
            _ if ywords > xsize => {
                // Divisor is greater than dividend. Return zero and the dividend as the
                // quotient and remainder
                y.leading_mut(xsize).copy_from(x.leading(xsize));
                y.trailing_mut(xsize).fill(Limb::ZERO);
                x.fill(Limb::ZERO);
                return;
            }
            _ => (),
        }

        x.div_rem_large_vartime(y.leading_mut(ywords));

        // Shift the quotient to the low limbs within dividend
        #[allow(clippy::cast_possible_truncation, reason = "TODO")]
        x.unbounded_shr_assign_by_limbs_vartime((ywords - 1) as u32);
    }

    /// Computes `x_lower_upper` % `rhs`, returning the remainder in `rhs`.
    ///
    /// The `x_lower_upper` tuple represents a wide integer. The size of `x_lower_upper.1` must be
    /// at least as large as `rhs`. `x_lower_upper` is left in an indeterminate state.
    ///
    /// # Panics
    /// If the divisor is zero.
    #[inline(always)]
    pub(crate) const fn rem_wide(x_lower_upper: (&mut Self, &mut Self), rhs: &mut Self) {
        let (x_lo, x) = x_lower_upper;
        let y = rhs;

        // Short circuit for single-word divisor
        if y.nlimbs() == 1 {
            let reciprocal = Reciprocal::new(y.limbs[0].to_nz().expect_copied("zero divisor"));
            let carry = x.rem_limb_with_reciprocal(&reciprocal, Limb::ZERO);
            y.limbs[0] = x_lo.rem_limb_with_reciprocal(&reciprocal, carry);
            return;
        }

        // Compute the size of the divisor
        let ybits = y.bits();
        assert!(ybits > 0, "zero divisor");
        let ywords = bitlen::to_limbs_u32(ybits);

        // Shift the entire divisor such that the high bit is set
        let yz = y.bits_precision() - ybits;
        y.unbounded_shl_assign(yz);

        // Shift the dividend to align the words
        let lshift = yz & (Limb::BITS - 1);
        let x_lo_carry = x_lo.shl_assign_limb(lshift);
        let x_hi = x.shl_assign_limb(lshift);
        x.limbs[0] = x.limbs[0].bitor(x_lo_carry);

        // Perform the core division algorithm
        Self::rem_wide_shifted((x_lo, x), x_hi, y, ywords);

        // Unshift the remainder from the earlier adjustment
        y.shr_assign_limb(lshift);
    }

    /// Computes `x_lower_upper` % `rhs`, returning the remainder in `rhs`.
    ///
    /// This function operates in variable-time with respect to `rhs`. For a fixed divisor,
    /// it operates in constant-time.
    ///
    /// The `x_lower_upper` tuple represents a wide integer. The size of `x_lower_upper.1`
    /// must be at least as large as `rhs`. `x_lower_upper` is left in an indeterminate state.
    ///
    /// # Panics
    /// If the divisor is zero.
    #[inline(always)]
    pub(crate) const fn rem_wide_vartime(x_lower_upper: (&mut Self, &mut Self), rhs: &mut Self) {
        let (x_lo, x) = x_lower_upper;
        let xsize = x.nlimbs();
        let ysize = bitlen::to_limbs(rhs.bits_vartime());
        let y = rhs.leading_mut(ysize);

        match (xsize, ysize) {
            (_, 0) => panic!("zero divisor"),
            (0, _) => {
                // If the quotient is empty, set the remainder to zero and return.
                y.fill(Limb::ZERO);
                return;
            }
            (_, 1) => {
                // Short circuit for single-word divisor
                let reciprocal = Reciprocal::new(y.limbs[0].to_nz().expect_copied("zero divisor"));
                y.fill(Limb::ZERO);
                let carry = x.rem_limb_with_reciprocal(&reciprocal, Limb::ZERO);
                y.limbs[0] = x_lo.rem_limb_with_reciprocal(&reciprocal, carry);
                return;
            }
            _ if ysize > xsize => {
                panic!("divisor too large");
            }
            _ => (),
        }

        let lshift = y.limbs[ysize - 1].leading_zeros();

        // Shift divisor such that it has no leading zeros
        // This means that div2by1 requires no extra shifts, and ensures that the high word >= b/2
        y.shl_assign_limb_vartime(lshift);

        // Shift the dividend to align the words
        let x_lo_carry = x_lo.shl_assign_limb_vartime(lshift);
        let mut x_hi = x.shl_assign_limb_vartime(lshift);
        x.limbs[0] = x.limbs[0].bitor(x_lo_carry);

        // Calculate a reciprocal from the highest word of the divisor
        let reciprocal = Reciprocal::new(y.limbs[ysize - 1].to_nz().expect_copied("zero divisor"));

        // Perform the core division algorithm
        x_hi = Self::rem_wide_large_shifted::<true>(
            (x_lo, x),
            x_hi,
            y,
            #[allow(clippy::cast_possible_truncation, reason = "TODO")]
            {
                ysize as u32
            },
            reciprocal,
        );

        // Copy the remainder to the divisor
        y.leading_mut(ysize - 1).copy_from(x.leading(ysize - 1));
        y.limbs[ysize - 1] = x_hi;

        // Unshift the remainder from the earlier adjustment
        y.shr_assign_limb_vartime(lshift);
    }

    /// Perform in-place division (`self` / `y`) for a pre-shifted dividend and divisor.
    ///
    /// The dividend and divisor must be left-shifted such that the high bit of the divisor
    /// is set, and `x_hi` holds the top bits of the dividend.
    ///
    /// The quotient is returned in `self` and the remainder in `y`, but these values require
    /// additional correction. This is left to the caller for performance reasons.
    #[inline(always)]
    #[allow(clippy::cast_possible_truncation)]
    pub(crate) const fn div_rem_shifted(&mut self, mut x_hi: Limb, y: &mut Self, ywords: u32) {
        let x = self;

        // Calculate a reciprocal from the highest word of the divisor
        let reciprocal = Reciprocal::new(
            y.limbs[y.nlimbs() - 1]
                .to_nz()
                .expect_copied("zero divisor"),
        );
        debug_assert!(reciprocal.shift() == 0);

        // Perform the core division algorithm
        x_hi = Self::div_rem_large_shifted::<false>(x, x_hi, y, ywords, reciprocal);

        // Calculate quotient and remainder for the case where the divisor is a single word.
        let limb_div = Choice::from_u32_eq(1, ywords);
        // Note that `div2by1()` will panic if `x_hi >= reciprocal.divisor_normalized`,
        // but this can only be the case if `limb_div` is falsy, in which case we discard
        // the result anyway, so we conditionally set `x_hi` to zero for this branch.
        let x_hi_adjusted = Limb::select(Limb::ZERO, x_hi, limb_div);
        let (quo2, rem2) = div2by1(x.limbs[0].0, x_hi_adjusted.0, &reciprocal);

        // Adjust the quotient for single limb division
        x.limbs[0] = Limb::select(x.limbs[0], Limb(quo2), limb_div);
        // Copy out the low limb of the remainder
        y.limbs[0] = Limb::select(x.limbs[0], Limb(rem2), limb_div);

        // Adjust the remainder, copying `x_hi` to the appropriate position and clearing
        // any extra limbs.
        // Note: branching only based on the size of the operands, which is not secret.
        let min = if x.nlimbs() < y.nlimbs() {
            x.nlimbs()
        } else {
            y.nlimbs()
        };
        let hi_pos = u32_min(x.nlimbs() as u32, ywords - 1);
        let mut i = 1;
        while i < min {
            y.limbs[i] = Limb::select(
                Limb::ZERO,
                x.limbs[i],
                Choice::from_u32_lt(i as u32, ywords),
            );
            y.limbs[i] = Limb::select(y.limbs[i], x_hi, Choice::from_u32_eq(i as u32, hi_pos));
            i += 1;
        }
        while i < y.nlimbs() {
            y.limbs[i] = Limb::select(Limb::ZERO, x_hi, Choice::from_u32_eq(i as u32, hi_pos));
            i += 1;
        }
    }

    /// Computes `self` / `y` for a "large" divisor (>1 limbs), returning the quotient and
    /// the remainder in `self`.
    ///
    /// While the divisor may only be a single limb, additional corrections to the result are
    /// required in this case.
    ///
    /// The dividend and divisor must be left-shifted such that the high bit of the divisor
    /// is set, and `x_hi` holds the top bits of the dividend.
    #[inline(always)]
    #[allow(clippy::cast_possible_truncation)]
    pub(crate) const fn div_rem_large_shifted<const VARTIME: bool>(
        &mut self,
        mut x_hi: Limb,
        y: &Self,
        ywords: u32,
        reciprocal: Reciprocal,
    ) -> Limb {
        let x = self;
        let xsize = x.nlimbs();
        let ysize = y.nlimbs();

        let mut xi = xsize - 1;
        let mut x_xi = x.limbs[xi];
        let mut i;
        let mut carry;

        // Compute the adjusted reciprocal
        let v = reciprocal.reciprocal_3by2(y.limbs[ysize - 2].0, y.limbs[ysize - 1].0);

        while xi > 0 {
            // Divide high dividend words by the high divisor word to estimate the quotient word
            let (mut quo, _) = div3by2(
                (x.limbs[xi - 1].0, x_xi.0, x_hi.0),
                (y.limbs[ysize - 2].0, y.limbs[ysize - 1].0),
                v,
            );

            // This loop is a no-op once xi is smaller than the number of words in the divisor
            let done = Choice::from_u32_lt(xi as u32, ywords - 1);
            if VARTIME && done.to_bool() {
                break;
            }
            quo = word::select(quo, 0, done);

            // Subtract q*divisor from the dividend
            let borrow = {
                carry = Limb::ZERO;
                let mut borrow = Limb::ZERO;
                let mut tmp;
                i = (xi + 1).saturating_sub(ysize);
                while i <= xi {
                    (tmp, carry) =
                        y.limbs[ysize + i - xi - 1].carrying_mul_add(Limb(quo), carry, Limb::ZERO);
                    (x.limbs[i], borrow) = x.limbs[i].borrowing_sub(tmp, borrow);
                    i += 1;
                }
                (_, borrow) = x_hi.borrowing_sub(carry, borrow);
                borrow
            };

            // If the subtraction borrowed, then decrement quo and add back the divisor
            // The probability of this being needed is very low, about 2/(Limb::MAX+1)
            quo = {
                carry = Limb::ZERO;
                i = (xi + 1).saturating_sub(ysize);
                while i <= xi {
                    (x.limbs[i], carry) =
                        x.limbs[i].carrying_add(y.limbs[ysize + i - xi - 1].bitand(borrow), carry);
                    i += 1;
                }
                quo.wrapping_sub(borrow.0 & word::choice_to_mask(word::choice_from_nz(quo)) & 1)
            };

            // Store the quotient within dividend and set x_hi to the current highest word
            x_hi = Limb::select(x.limbs[xi], x_hi, done);
            x.limbs[xi] = Limb::select(Limb(quo), x.limbs[xi], done);
            x_xi = Limb::select(x.limbs[xi - 1], x_xi, done);
            xi -= 1;
        }

        x_hi
    }

    /// Perform in-place variable-time division for a "large" divisor (>1 limbs). The
    /// quotient is returned in `self` and the remainder in `rhs`.
    #[inline(always)]
    #[allow(clippy::cast_possible_truncation)]
    pub(crate) const fn div_rem_large_vartime(&mut self, rhs: &mut Self) {
        let (x, y) = (self, rhs);
        let ysize = y.nlimbs();
        debug_assert!(ysize > 1);
        let lshift = y.limbs[ysize - 1].leading_zeros();

        // Shift divisor such that it has no leading zeros
        // This means that div2by1 requires no extra shifts, and ensures that the high word >= b/2
        y.shl_assign_limb_vartime(lshift);

        // Shift the dividend to match
        let mut x_hi = x.shl_assign_limb_vartime(lshift);

        // Calculate a reciprocal from the highest word of the divisor
        let reciprocal = Reciprocal::new(y.limbs[ysize - 1].to_nz().expect_copied("zero divisor"));

        // Perform the core division algorithm
        x_hi = Self::div_rem_large_shifted::<true>(x, x_hi, y, ysize as u32, reciprocal);

        // Copy the remainder to divisor
        y.leading_mut(ysize - 1).copy_from(x.leading(ysize - 1));
        y.limbs[ysize - 1] = x_hi;

        // Unshift the remainder from the earlier adjustment
        y.shr_assign_limb_vartime(lshift);
    }

    /// Perform in-place division (`x` / `y`) for a pre-shifted dividend and divisor,
    /// tracking only the remainder.
    ///
    /// The dividend and divisor must be left-shifted such that the high bit of the divisor
    /// is set, and `x_hi` holds the top bits of the dividend.
    ///
    /// The shifted remainder is returned in `y`, and must be unshifted by the caller.
    /// `x` is left in an indeterminate state.
    #[inline(always)]
    #[allow(clippy::cast_possible_truncation)]
    const fn rem_wide_shifted(
        x: (&mut Self, &mut Self),
        mut x_hi: Limb,
        y: &mut Self,
        ywords: u32,
    ) {
        let (x_lo, x) = x;
        let ysize = y.nlimbs();

        // Calculate a reciprocal from the highest word of the divisor
        let reciprocal = Reciprocal::new(y.limbs[ysize - 1].to_nz().expect_copied("zero divisor"));
        debug_assert!(reciprocal.shift() == 0);

        // Perform the core division algorithm
        x_hi = Self::rem_wide_large_shifted::<false>((x_lo, x), x_hi, y, ywords, reciprocal);

        // Calculate remainder for the case where the divisor is a single word.
        let limb_div = Choice::from_u32_eq(1, ywords);
        // Note that `div2by1()` will panic if `x_hi >= reciprocal.divisor_normalized`,
        // but this can only be the case if `limb_div` is falsy, in which case we discard
        // the result anyway, so we conditionally set `x_hi` to zero for this branch.
        let x_hi_adjusted = Limb::select(Limb::ZERO, x_hi, limb_div);
        let (_, rem2) = div2by1(x.limbs[0].0, x_hi_adjusted.0, &reciprocal);

        // Copy out the low limb of the remainder
        y.limbs[0] = Limb::select(x.limbs[0], Limb(rem2), limb_div);

        // Copy the remainder to divisor
        let mut i = 1;
        while i < ysize {
            y.limbs[i] = Limb::select(
                Limb::ZERO,
                x.limbs[i],
                Choice::from_u32_lt(i as u32, ywords),
            );
            y.limbs[i] = Limb::select(y.limbs[i], x_hi, Choice::from_u32_eq(i as u32, ywords - 1));
            i += 1;
        }
    }

    /// Computes `x % y` for a "large" divisor (>1 limbs), returning the remainder in `x.1`.
    ///
    /// While the divisor may only be a single limb, additional corrections to the result are
    /// required in this case.
    ///
    /// The dividend and divisor must be left-shifted such that the high bit of the divisor
    /// is set, and `x_hi` holds the top bits of the dividend.
    #[inline(always)]
    #[allow(clippy::cast_possible_truncation)]
    const fn rem_wide_large_shifted<const VARTIME: bool>(
        x: (&Self, &mut Self),
        mut x_hi: Limb,
        y: &Self,
        ywords: u32,
        reciprocal: Reciprocal,
    ) -> Limb {
        assert!(
            y.nlimbs() <= x.1.nlimbs(),
            "invalid input sizes for rem_wide_large_shifted"
        );

        let (x_lo, x) = x;
        let xsize = x.nlimbs();
        let ysize = y.nlimbs();
        let mut extra_limbs = x_lo.nlimbs();

        let mut xi = xsize - 1;
        let mut x_xi = x.limbs[xi];
        let mut i;
        let mut carry;

        // Compute the adjusted reciprocal
        let v = reciprocal.reciprocal_3by2(y.limbs[ysize - 2].0, y.limbs[ysize - 1].0);

        // We proceed similarly to `div_rem_large_shifted()` applied to the high half of
        // the dividend, fetching the limbs from the lower part as we go.

        while xi > 0 {
            // Divide high dividend words by the high divisor word to estimate the quotient word
            let (mut quo, _) = div3by2(
                (x.limbs[xi - 1].0, x_xi.0, x_hi.0),
                (y.limbs[ysize - 2].0, y.limbs[ysize - 1].0),
                v,
            );

            // This loop is a no-op once xi is smaller than the number of words in the divisor
            let done = Choice::from_u32_lt(xi as u32, ywords - 1);
            if VARTIME && done.to_bool() {
                break;
            }
            quo = word::select(quo, 0, done);

            // Subtract q*divisor from the dividend
            let borrow = {
                carry = Limb::ZERO;
                let mut borrow = Limb::ZERO;
                let mut tmp;
                i = (xi + 1).saturating_sub(ysize);
                while i <= xi {
                    (tmp, carry) =
                        y.limbs[ysize + i - xi - 1].carrying_mul_add(Limb(quo), carry, Limb::ZERO);
                    (x.limbs[i], borrow) = x.limbs[i].borrowing_sub(tmp, borrow);
                    i += 1;
                }
                (_, borrow) = x_hi.borrowing_sub(carry, borrow);
                borrow
            };

            // If the subtraction borrowed, then add back the divisor
            // The probability of this being needed is very low, about 2/(Limb::MAX+1)
            {
                carry = Limb::ZERO;
                i = (xi + 1).saturating_sub(ysize);
                while i <= xi {
                    (x.limbs[i], carry) =
                        x.limbs[i].carrying_add(y.limbs[ysize + i - xi - 1].bitand(borrow), carry);
                    i += 1;
                }
            }

            // If we have lower limbs remaining, shift the dividend words one word left
            if extra_limbs > 0 {
                x_hi = x.limbs[xi];
                x_xi = x.limbs[xi - 1];
                extra_limbs -= 1;
                i = xi;
                while i > 0 {
                    x.limbs[i] = x.limbs[i - 1];
                    i -= 1;
                }
                x.limbs[0] = x_lo.limbs[extra_limbs];
            } else {
                x_hi = Limb::select(x.limbs[xi], x_hi, done);
                x_xi = Limb::select(x.limbs[xi - 1], x_xi, done);
                xi -= 1;
            }
        }

        x_hi
    }

    /// Divides `self` by the divisor encoded in the `reciprocal`, setting `self`
    /// to the quotient and returning the remainder.
    #[inline(always)]
    pub(crate) const fn div_rem_limb(&mut self, rhs: NonZero<Limb>) -> Limb {
        self.div_rem_limb_with_reciprocal(&Reciprocal::new(rhs))
    }

    /// Divides `self` by the divisor encoded in the `reciprocal`, setting `self`
    /// to the quotient and returning the remainder.
    #[inline(always)]
    pub(crate) const fn div_rem_limb_with_reciprocal(&mut self, reciprocal: &Reciprocal) -> Limb {
        let hi = self.shl_assign_limb(reciprocal.shift());
        self.div_rem_limb_with_reciprocal_shifted(hi, reciprocal)
    }

    /// Divides `self` by the divisor encoded in the `reciprocal`, setting `self`
    /// to the quotient and returning the remainder.
    #[inline(always)]
    pub(crate) const fn div_rem_limb_with_reciprocal_shifted(
        &mut self,
        mut hi: Limb,
        reciprocal: &Reciprocal,
    ) -> Limb {
        let mut j = self.limbs.len();
        while j > 0 {
            j -= 1;
            (self.limbs[j].0, hi.0) = div2by1(self.limbs[j].0, hi.0, reciprocal);
        }
        hi.shr(reciprocal.shift())
    }

    /// Divides `self` by the divisor encoded in the `reciprocal`, returning the remainder.
    #[inline(always)]
    pub(crate) const fn rem_limb(&self, rhs: NonZero<Limb>) -> Limb {
        self.rem_limb_with_reciprocal(&Reciprocal::new(rhs), Limb::ZERO)
    }

    /// Divides `self` by the divisor encoded in the `reciprocal`, and returns the remainder.
    pub(crate) const fn rem_limb_with_reciprocal(
        &self,
        reciprocal: &Reciprocal,
        carry: Limb,
    ) -> Limb {
        let nlimbs = self.nlimbs();
        if nlimbs == 0 {
            return carry;
        }
        let lshift = reciprocal.shift();
        let lshift_nz = Choice::from_u32_nz(lshift);
        let lo_mask = Limb(word::choice_to_mask(lshift_nz));
        let rshift = lshift_nz.select_u32(0, Limb::BITS - lshift);
        let mut hi = carry
            .shl(lshift)
            .bitor(self.limbs[nlimbs - 1].bitand(lo_mask).shr(rshift));
        let mut lo;
        let mut j = nlimbs;
        while j > 1 {
            j -= 1;
            lo = self.limbs[j]
                .shl(lshift)
                .bitor(self.limbs[j - 1].bitand(lo_mask).shr(rshift));
            (_, hi.0) = div2by1(lo.0, hi.0, reciprocal);
        }
        (_, hi.0) = div2by1(self.limbs[0].shl(lshift).0, hi.0, reciprocal);
        hi.shr(lshift)
    }

    /// Exactly divides `self` by `rhs`, returning `Choice::FALSE` if `self` is not divisible by `rhs`.
    ///
    /// If the division is not exact then `self` is left in an indeterminate state.
    /// The divisor `rhs` is right-shifted to produce an odd integer.
    ///
    /// # Panics
    /// If the divisor is zero.
    #[inline(always)]
    pub(crate) const fn div_exact(&mut self, rhs: &mut UintRef) -> Choice {
        let y_bits = rhs.bits();
        assert!(y_bits > 0, "zero divisor");

        let x_tz = self.trailing_zeros();
        let x_zero = Choice::from_u32_eq(x_tz, self.bits_precision());
        let y_tz = rhs.trailing_zeros();

        // Shift the divisor such that it is odd
        rhs.shr_assign(y_tz);

        // Check that the dividend evenly divides by 2^y+tz, and shift it to match the divisor
        let div2s_exact = Choice::from_u32_le(y_tz, x_tz).or(x_zero);
        self.unbounded_shr_assign(y_tz);

        let y = Odd::new_ref_unchecked(rhs);
        let y_inv = y.invert_mod_limb();
        let ywords = bitlen::to_limbs(y_bits - y_tz);
        let is_exact =
            Self::div_exact_odd_with_inverse::<false>(self, y, y_inv, ywords).and(div2s_exact);

        // Restore the divisor
        rhs.shl_assign(y_tz);

        is_exact
    }

    /// Exactly divides `self` by `rhs`, returning `Choice::FALSE` if `self` is not divisible by `rhs`.
    ///
    /// The quotient is left in `self`, but is not guaranteed to be in a usable state unless
    /// the return value is `Choice::TRUE`.
    ///
    /// # Panics
    /// If the divisor is zero.
    #[inline(always)]
    pub(crate) const fn div_exact_vartime(&mut self, rhs: &mut UintRef) -> Choice {
        let y_bits = rhs.bits_vartime();
        assert!(y_bits > 0, "zero divisor");

        let x_tz = self.trailing_zeros();
        let x_zero = Choice::from_u32_eq(x_tz, self.bits_precision());
        let y_tz = rhs.trailing_zeros_vartime();

        // Shift the divisor to be odd
        rhs.unbounded_shr_assign_vartime(y_tz);

        // Check that the dividend evenly divides by 2^y_tz, and shift it to match the divisor
        let div2s_exact = Choice::from_u32_le(y_tz, x_tz).or(x_zero);
        self.unbounded_shr_assign_vartime(y_tz);

        let ywords = bitlen::to_limbs(y_bits - y_tz);
        let y = Odd::new_ref_unchecked(rhs.leading_mut(ywords));
        let y_inv = y.invert_mod_limb();
        let is_exact =
            Self::div_exact_odd_with_inverse::<true>(self, y, y_inv, ywords).and(div2s_exact);

        // Restore the divisor
        rhs.unbounded_shl_assign_vartime(y_tz);

        is_exact
    }

    /// Exactly divides `x` by `y`, returning `Choice::FALSE` if `x` is not divisible by `y`.
    ///
    /// The quotient is left in `self`, but is not guaranteed to be in a usable state unless
    /// the return value is `Choice::TRUE`.
    ///
    /// This method performs a Hensel division, subtracting from the least significant bits
    /// and calculating an LSB quotient and remainder `(q,r) s.t. x = qy + r•2^N`. When the remainder
    /// is zero, the calculated quotient corresponds to the traditional division quotient.
    ///
    /// For constant-time operation, this acts as if the divisor `y` is as small as one limb,
    /// performing loops without updates to the quotient for larger divisors when vartime operation
    /// is not specified.
    #[inline(always)]
    const fn div_exact_odd_with_inverse<const VARTIME: bool>(
        x: &mut UintRef,
        y: &Odd<UintRef>,
        y_inv: Limb,
        ywords: usize,
    ) -> Choice {
        let xc = x.nlimbs();
        let y = y.as_ref();
        let yc = y.nlimbs();
        let mut meta_carry = Limb::ZERO;
        let mut zero_hi = Choice::TRUE;
        let mut xi = 0;

        while xi < xc {
            let y_remain = if yc < (xc - xi) { yc } else { xc - xi };
            // This loop is a no-op once there are fewer words remaining than the size of the divisor
            let done = usize_lt(y_remain, ywords);
            if VARTIME && done.to_bool() {
                zero_hi = x.trailing(xi).is_zero();
                break;
            }

            // Compute the quotient limb that will clear the low dividend limb
            let quo = Limb::select(x.limbs[xi].wrapping_mul(y_inv), x.limbs[xi], done);
            x.limbs[xi] = quo;

            if !VARTIME {
                zero_hi = zero_hi.and(Limb::select(Limb::ZERO, quo, done).is_zero());
            }

            let (_, mut carry) = quo.widening_mul(y.limbs[0]);
            let mut sub;
            let mut borrow = Limb::ZERO;
            let mut yi = 1;

            while yi < y_remain {
                (sub, carry) = quo.carrying_mul_add(y.limbs[yi], Limb::ZERO, carry);
                (x.limbs[xi + yi], borrow) = x.limbs[xi + yi].borrowing_sub(sub, borrow);
                yi += 1;
            }

            meta_carry = meta_carry.wrapping_add(carry);

            if xi + yi < xc {
                (x.limbs[xi + yi], borrow) = x.limbs[xi + yi].borrowing_sub(meta_carry, borrow);
                meta_carry = borrow.wrapping_neg();
            } else {
                meta_carry = meta_carry.wrapping_sub(borrow);
            }

            xi += 1;
        }

        meta_carry.is_zero().and(zero_hi)
    }
}

#[cfg(test)]
mod tests {
    use crate::{U64, U128, U192, Uint};

    #[test]
    fn div_exact_inexact() {
        fn check<const L: usize, const R: usize>(lhs: Uint<L>, rhs: Uint<R>, exact: bool) {
            let (mut q, mut r) = (lhs, rhs);
            let actual = q.as_mut_uint_ref().div_exact(r.as_mut_uint_ref()).to_bool();
            assert_eq!(actual, exact, "{lhs} / {rhs}: exact={actual}");
            let (mut q, mut r) = (lhs, rhs);
            let actual = q
                .as_mut_uint_ref()
                .div_exact_vartime(r.as_mut_uint_ref())
                .to_bool();
            assert_eq!(actual, exact, "{lhs} / {rhs}: exact={actual}");
        }

        check(
            U64::from_be_hex("0000000000000010"),
            U64::from_be_hex("0000000000000010"),
            true,
        );
        check(
            U64::from_be_hex("0000000000000010"),
            U128::from_be_hex("00000000000000000000000000000001"),
            true,
        );
        check(
            U64::from_be_hex("0000000000000000"),
            U128::from_be_hex("10000000000000000000000000000000"),
            true,
        );
        check(
            U64::from_be_hex("0000000000000001"),
            U64::from_be_hex("0000000000000010"),
            false,
        );
        check(
            U64::from_be_hex("0000000000000001"),
            U128::from_be_hex("00000000000000100000000000000000"),
            false,
        );
        check(
            U192::from_be_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000"),
            U192::from_be_hex("000000000000000100000000000000003ACEDC010F13471D"),
            false,
        );
    }
}
