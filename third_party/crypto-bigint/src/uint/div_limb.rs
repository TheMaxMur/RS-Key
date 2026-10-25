//! Implementation of constant-time division via reciprocal precomputation, as described in
//! "Improved Division by Invariant Integers" by Niels Möller and Torbjorn Granlund
//! (DOI: 10.1109/TC.2010.143, <https://gmplib.org/~tege/division-paper.pdf>).

use crate::{
    Choice, CtSelect, Limb, NonZero, Uint, WideWord, Word, primitives::widening_mul, word,
};

cpubits::cpubits! {
    32 => {
        /// Calculates the reciprocal of the given 32-bit divisor with the highmost bit set.
        ///
        /// This method corresponds to Algorithm 3
        pub const fn reciprocal(d: Word) -> Word {
            debug_assert!(d >= (1 << (Word::BITS - 1)));

            let d0 = d & 1;
            let d10 = d >> 22;
            let d21 = (d >> 11) + 1;
            let d31 = (d >> 1) + d0;
            let v0 = short_div((1 << 24) - (1 << 14) + (1 << 9), 24, d10, 10);
            let (_lo, hi) = widening_mul(v0 * v0, d21);
            let v1 = (v0 << 4) - hi - 1;

            // Checks that the expression for `e` can be simplified in the way we did below.
            debug_assert!(widening_mul(v1, d31).1 == (1 << 16) - 1);
            let e = v1.wrapping_mul(d31).wrapping_neg() + (v1 >> 1) * d0;

            let (_lo, hi) = widening_mul(v1, e);
            // Note: the paper does not mention a wrapping add here,
            // but the 64-bit version has it at this stage, and the function panics without it
            // when calculating a reciprocal for `Word::MAX`.
            let v2 = (v1 << 15).wrapping_add(hi >> 1);

            // The paper has `(v2 + 1) * d / 2^32` (there's another 2^32, but it's accounted for later).
            // If `v2 == 2^32-1` this should give `d`, but we can't achieve this in our wrapping arithmetic.
            // Hence the `word::select()`.
            let x = v2.wrapping_add(1);
            let (_lo, hi) = widening_mul(x, d);
            let hi = word::select(d, hi, Choice::from_u32_nz(x));

            v2.wrapping_sub(hi).wrapping_sub(d)
        }
    }
    64 => {
        /// Calculates the reciprocal of the given 64-bit divisor with the highmost bit set.
        ///
        /// This method corresponds to Algorithm 2
        pub const fn reciprocal(d: Word) -> Word {
            debug_assert!(d >= (1 << (Word::BITS - 1)));

            let d0 = d & 1;
            let d9 = d >> 55;
            let d40 = (d >> 24) + 1;
            let d63 = (d >> 1) + d0;
            let v0 = short_div((1 << 19) - 3 * (1 << 8), 19, d9 as u32, 9) as u64;
            let v1 = (v0 << 11) - ((v0 * v0 * d40) >> 40) - 1;
            let v2 = (v1 << 13) + ((v1 * ((1 << 60) - v1 * d40)) >> 47);

            // Checks that the expression for `e` can be simplified in the way we did below.
            debug_assert!(widening_mul(v2, d63).1 == (1 << 32) - 1);
            let e = v2.wrapping_mul(d63).wrapping_neg() + (v2 >> 1) * d0;

            let (_lo, hi) = widening_mul(v2, e);
            let v3 = (v2 << 31).wrapping_add(hi >> 1);

            // The paper has `(v3 + 1) * d / 2^64` (there's another 2^64, but it's accounted for later).
            // If `v3 == 2^64-1` this should give `d`, but we can't achieve this in our wrapping arithmetic.
            // Hence the `word::select()`.
            let x = v3.wrapping_add(1);
            let (_lo, hi) = widening_mul(x, d);
            let hi = word::select(d, hi, word::choice_from_nz(x));

            v3.wrapping_sub(hi).wrapping_sub(d)
        }
    }
}

/// Calculates `dividend / divisor`, given `dividend` and `divisor`
/// along with their maximum bitsizes.
#[inline(always)]
const fn short_div(mut dividend: u32, dividend_bits: u32, divisor: u32, divisor_bits: u32) -> u32 {
    // TODO: this may be sped up even more using the fact that `dividend` is a known constant.

    // In the paper this is a table lookup, but since we want it to be constant-time,
    // we have to access all the elements of the table, which is quite large.
    // So this shift-and-subtract approach is actually faster.

    // Passing `dividend_bits` and `divisor_bits` because calling `.leading_zeros()`
    // causes a significant slowdown, and we know those values anyway.

    let mut divisor = divisor << (dividend_bits - divisor_bits);
    let mut quotient: u32 = 0;
    let mut i = dividend_bits - divisor_bits + 1;

    while i > 0 {
        i -= 1;
        let bit = Choice::from_u32_lt(dividend, divisor);
        dividend = bit.select_u32(dividend.wrapping_sub(divisor), dividend);
        divisor >>= 1;
        quotient |= bit.not().select_u32(0, 1 << i);
    }

    quotient
}

/// Calculate the quotient and the remainder of the division of a wide word
/// (supplied as high and low words) by `d`, with a precalculated reciprocal `v`.
///
/// This method corresponds to Algorithm 4
#[inline(always)]
pub(crate) const fn div2by1(u0: Word, u1: Word, reciprocal: &Reciprocal) -> (Word, Word) {
    let d = reciprocal.divisor_normalized;
    let v = reciprocal.reciprocal;

    debug_assert!(d >= (1 << (Word::BITS - 1)), "divisor top bit unset");
    debug_assert!(u1 < d, "dividend >= divisor");

    let q = (v as WideWord * u1 as WideWord) + word::join(u0, u1);
    let (q0, q1) = word::split_wide(q);
    let q1 = q1.wrapping_add(1);
    let r = u0.wrapping_sub(q1.wrapping_mul(d));

    let r_gt_q0 = word::choice_to_mask(word::choice_from_lt(q0, r));
    let q1 = q1.wrapping_sub(r_gt_q0 & 1);
    let r = r.wrapping_add(r_gt_q0 & d);

    // If this was a normal `if`, we wouldn't need wrapping ops, because there would be no overflow.
    // But since we calculate both results either way, we have to wrap.
    // Added an assert to still check the lack of overflow in debug mode.
    debug_assert!(r < d || q1 < Word::MAX);
    let r_ge_d = word::choice_to_mask(word::choice_from_le(d, r));
    let q1 = q1.wrapping_add(r_ge_d & 1);
    let r = r.wrapping_sub(r_ge_d & d);

    (q1, r)
}

/// Given two long integers `u = (..., u0, u1, u2)` and `v = (..., v0, v1)`
/// (where `u2` and `v1` are the most significant limbs), where `floor(u / v) <= Limb::MAX`,
/// calculates `q` such that `q - 1 <= floor(u / v) <= q`.
/// In place of `v1` takes its reciprocal, and assumes that `v` was already pre-shifted
/// so that v1 has its most significant bit set (that is, the reciprocal's `shift` is 0).
///
// This method corresponds to Algorithm 5
#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
pub(crate) const fn div3by2(
    (u0, u1, u2): (Word, Word, Word),
    (d0, d1): (Word, Word),
    v: Word,
) -> (Word, WideWord) {
    let d = word::join(d0, d1);
    let u_hi = word::join(u1, u2);

    debug_assert!(d >= (1 << (WideWord::BITS - 1)), "divisor top bit unset");
    debug_assert!(u_hi <= d, "dividend > divisor");

    let q = (v as WideWord * u2 as WideWord) + u_hi;
    let (q0, q1) = word::split_wide(q);
    let r1 = u1.wrapping_sub(q1.wrapping_mul(d1));
    let t = d0 as WideWord * q1 as WideWord;
    let r = word::join(u0, r1).wrapping_sub(t).wrapping_sub(d);

    let r1_ge_q0 = word::choice_to_wide_mask(word::choice_from_le(q0, (r >> Word::BITS) as Word));
    let q1 = q1.wrapping_add(!(r1_ge_q0 as Word) & 1);
    let r = r.wrapping_add(r1_ge_q0 & d);

    let r_ge_d = word::choice_to_wide_mask(word::choice_from_wide_le(d, r));
    let q1 = q1.wrapping_add(r_ge_d as Word & 1);
    let r = r.wrapping_sub(r_ge_d & d);

    // When the leading dividend word equals the leading divisor word, cap the quotient
    // at Word::MAX and update the remainder. This differs from the original algorithm
    // but is required for multi-word division.
    let maxed = word::choice_from_wide_eq(u_hi, d);
    let q1 = q1 | word::choice_to_mask(maxed);
    let r = word::select_wide(r, d.saturating_add(u0 as WideWord), maxed);

    (q1, r)
}

/// A pre-calculated reciprocal for division by a single limb.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Reciprocal {
    divisor_normalized: Word,
    shift: u32,
    reciprocal: Word,
}

impl Reciprocal {
    /// Pre-calculates a reciprocal for a known divisor,
    /// to be used in the single-limb division later.
    #[must_use]
    pub const fn new(divisor: NonZero<Limb>) -> Self {
        let divisor = divisor.get_copy();

        let shift = divisor.leading_zeros();

        // Will not panic since divisor is non-zero
        let divisor_normalized = divisor.0 << shift;

        Self {
            divisor_normalized,
            shift,
            reciprocal: reciprocal(divisor_normalized),
        }
    }

    /// Returns a default instance of this object.
    /// It is a self-consistent `Reciprocal` that will not cause panics in functions that take it.
    ///
    /// NOTE: intended for using it as a placeholder during compile-time array generation,
    /// don't rely on the contents.
    #[must_use]
    pub const fn default() -> Self {
        Self {
            divisor_normalized: Word::MAX,
            shift: 0,
            // The result of calling `reciprocal(Word::MAX)`
            // This holds both for 32- and 64-bit versions.
            reciprocal: 1,
        }
    }

    /// Get the shift value
    #[must_use]
    pub const fn shift(&self) -> u32 {
        self.shift
    }

    /// Adjusted reciprocal for 3x2 division
    ///
    /// This method corresponds to Algorithm 6
    #[must_use]
    pub const fn reciprocal_3by2(&self, d0: Word, d1: Word) -> Word {
        debug_assert!(self.shift == 0 && d1 == self.divisor_normalized);

        let v = self.reciprocal;
        let p = d1.wrapping_mul(v).wrapping_add(d0);

        let p_lt_d0 = word::choice_from_lt(p, d0);
        let v = word::select(v, v.wrapping_sub(1), p_lt_d0);

        let p_ge_d1 = word::choice_from_le(d1, p).and(p_lt_d0);
        let v = word::select(v, v.wrapping_sub(1), p_ge_d1);
        let p = word::select(p, p.wrapping_sub(d1), p_ge_d1);
        let p = word::select(p, p.wrapping_sub(d1), p_lt_d0);

        let (t0, t1) = widening_mul(v, d0);
        let p = p.wrapping_add(t1);

        let p_lt_t1 = word::choice_from_lt(p, t1);
        let v = word::select(v, v.wrapping_sub(1), p_lt_t1);
        let d = word::join(d0, d1);
        let t0p = word::join(t0, p);
        let t0p_ge_d = word::choice_from_wide_le(d, t0p).and(p_lt_t1);
        word::select(v, v.wrapping_sub(1), t0p_ge_d)
    }
}

impl CtSelect for Reciprocal {
    fn ct_select(&self, other: &Self, choice: Choice) -> Self {
        Self {
            divisor_normalized: Word::ct_select(
                &self.divisor_normalized,
                &other.divisor_normalized,
                choice,
            ),
            shift: u32::ct_select(&self.shift, &other.shift, choice),
            reciprocal: Word::ct_select(&self.reciprocal, &other.reciprocal, choice),
        }
    }
}

// `CtOption.map()` needs this; for some reason it doesn't use the value it already has
// for the `None` branch.
impl Default for Reciprocal {
    fn default() -> Self {
        Self::default()
    }
}

/// Divides `u` by the divisor encoded in the `reciprocal`, and returns the remainder.
#[inline(always)]
pub(crate) const fn rem_limb_with_reciprocal<const L: usize>(
    u: &Uint<L>,
    reciprocal: &Reciprocal,
) -> Limb {
    let (u_shifted, u_hi) = u.shl_limb_with_carry(reciprocal.shift, Limb::ZERO);
    let mut r = u_hi.0;

    let mut j = L;
    while j > 0 {
        j -= 1;
        let (_, rj) = div2by1(u_shifted.as_limbs()[j].0, r, reciprocal);
        r = rj;
    }
    Limb(r >> reciprocal.shift)
}

/// Computes `(a * b) % d`.
#[inline(always)]
pub(crate) const fn mul_rem(a: Limb, b: Limb, d: NonZero<Limb>) -> Limb {
    let rec = Reciprocal::new(d);
    let (lo, hi) = widening_mul(a.0, b.0);
    rem_limb_with_reciprocal(&Uint::from_words([lo, hi]), &rec)
}

#[cfg(test)]
mod tests {
    use super::{Reciprocal, div2by1, reciprocal};
    use crate::{Limb, NonZero, Uint, WideWord, Word, word};

    #[test]
    fn reciprocal_valid() {
        #![allow(clippy::integer_division_remainder_used, reason = "test")]
        fn test(d: Word) {
            let v = reciprocal(d);

            // the reciprocal must be equal to floor((β^2 - 1) / d) - β
            // v = floor((β^2 - 1) / d) - β = floor((β - 1 - d)*β + β - 1>/d)
            let expected = WideWord::MAX / WideWord::from(d) - WideWord::from(Word::MAX) - 1;
            assert_eq!(WideWord::from(v), expected);
        }

        test(Word::MAX);
        test(1 << (Word::BITS - 1));
        test((1 << (Word::BITS - 1)) | 1);
    }

    #[test]
    fn reciprocal_3by2_valid() {
        fn test(d: WideWord) {
            let (d0, d1) = word::split_wide(d);
            let v0 = Reciprocal::new(NonZero::<Limb>::new_unwrap(Limb(d1)));
            let v = v0.reciprocal_3by2(d0, d1);

            // the reciprocal must be equal to v = floor((β^3 − 1)/d) − β
            // (β^3 − βd - 1)/d - 1 < v <= (β^3 − βd - 1)/d
            // β^3 − βd - 1 - d < v*d <= β^3 − βd - 1
            // β^3-1 - d < (v+β)d <= β^3-1
            let actual = (Uint::<3>::from_word(v)
                + Uint::<3>::ZERO.set_bit_vartime(Word::BITS, true))
            .checked_mul(&Uint::<3>::from_wide_word(d))
            .expect("overflow");
            let min = Uint::<3>::MAX - Uint::<3>::from_wide_word(d);
            assert!(actual > min, "{actual} <= {min}");
        }

        test(WideWord::MAX);
        test(1 << (WideWord::BITS - 1));
        test((1 << (WideWord::BITS - 1)) | 1);
    }

    #[test]
    fn div2by1_overflow() {
        // A regression test for a situation when in div2by1() an operation (`q1 + 1`)
        // that is protected from overflowing by a condition in the original paper (`r >= d`)
        // still overflows because we're calculating the results for both branches.
        let r = Reciprocal::new(NonZero::new(Limb(Word::MAX - 1)).unwrap());
        assert_eq!(
            div2by1(Word::MAX - 63, Word::MAX - 2, &r),
            (Word::MAX, Word::MAX - 65)
        );
    }
}
