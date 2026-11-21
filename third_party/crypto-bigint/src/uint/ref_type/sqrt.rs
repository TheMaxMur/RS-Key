//! Square root calculation.

use super::UintRef;
use crate::{Choice, Limb, NonZero, Uint, WideWord, Word, word};

impl UintRef {
    #[inline]
    pub(crate) const fn sqrt_assign(&mut self, buf: (&mut UintRef, &mut UintRef)) -> Choice {
        let len = self.nlimbs();
        assert!(buf.0.nlimbs() >= len && buf.1.nlimbs() >= len);

        match len {
            0 => Choice::TRUE,
            1 => {
                let rem;
                (self.limbs[0].0, rem) = sqrt_rem_word(self.limbs[0].0);
                Limb(rem).is_zero()
            }
            _ => {
                let mut bits = self.bits();
                let is_zero = Choice::from_u32_nz(bits).not();
                // Set first limb to 1 if the input is zero
                self.limbs[0] = Limb::select(self.limbs[0], Limb::ONE, is_zero);
                bits = is_zero.select_u32(bits, 1);

                // Shift such that at least one of the top two bits are non-zero
                let s_shift = (self.bits_precision() - bits) >> 1;
                self.shl_assign(s_shift * 2);

                // Compute root and uncorrected remainder, placing them in buf.0 and buf.1
                self.sqrt_rem_normalized::<false>(buf.0, buf.1);

                // Copy the shifted root to self and correct it
                self.copy_from(buf.0.leading(self.nlimbs()));
                self.shr_assign(s_shift);

                // Set root to zero if self was zero
                self.limbs[0] = Limb::select(self.limbs[0], Limb::ZERO, is_zero);

                // Check if there is a remainder
                buf.1.is_zero()
            }
        }
    }

    #[inline]
    pub(crate) const fn sqrt_assign_vartime(&mut self, buf: (&mut UintRef, &mut UintRef)) -> bool {
        let bits = self.bits_vartime();
        if bits == 0 {
            return true;
        }

        let words = bits.div_ceil(Limb::BITS);
        assert!(buf.0.nlimbs() >= words as usize && buf.1.nlimbs() >= words as usize);

        // Only consider the populated limbs
        let out = self.leading_mut(words as usize);

        if words <= 2 {
            // No shifts needed
            sqrt_rem_small::<true>(out.as_limbs(), buf.0.as_mut_limbs(), buf.1.as_mut_limbs());
            out.copy_from(buf.0.leading(out.nlimbs()));
        } else {
            // Shift such that at least one of the top two bits are non-zero
            let lz = words * Limb::BITS - bits;
            let s_shift = lz >> 1;
            out.shl_assign_limb_vartime(s_shift * 2);

            // Compute root and uncorrected remainder, placing them in buf.0 and buf.1
            out.sqrt_rem_normalized::<true>(buf.0, buf.1);

            // Copy the shifted root to self and correct it
            out.copy_from(buf.0.leading(out.nlimbs()));
            out.shr_assign_limb_vartime(s_shift);
        }

        // Check if there is a remainder
        buf.1.is_zero_vartime()
    }

    /// Corresponds to Brent & Zimmermann, Modern Computer Arithmetic, v0.5.9, Algorithm 1.12
    #[allow(clippy::cast_possible_truncation)]
    const fn sqrt_rem_normalized<const VARTIME: bool>(&self, s: &mut UintRef, r: &mut UintRef) {
        let len = self.nlimbs();

        // Handle base case of a square root < 4 limbs
        // Unlike the source material, we do not handle 4 limbs in the base case sqrt function
        if len < 4 {
            sqrt_rem_small::<VARTIME>(self.as_limbs(), s.as_mut_limbs(), r.as_mut_limbs());
            return;
        }

        let l = len >> 2;
        let rt_len = (len - l * 2).div_ceil(2);
        let (a_lo, a_hi) = self.split_at(l * 2);
        let (a0, a1) = a_lo.split_at(l);

        // (s', r') = SqrtRem(a3•B + a2), leaving `l` spare low limbs in each
        a_hi.sqrt_rem_normalized::<VARTIME>(s.trailing_mut(l), r.trailing_mut(l));

        // Split up buffers
        let (s, s_tail) = s.split_at_mut(l + rt_len);
        let (s_lo, s_hi) = s.split_at_mut(l);
        let (r, r_tail) = r.split_at_mut(l + rt_len + 1);

        // Set r = r'B + a1
        r.leading_mut(l).copy_from(a1);
        // Set u = s'
        let u = s_tail.leading_mut(rt_len);
        u.copy_from(s_hi);

        // We wish to divide r/2s', setting r to the quotient and u to the remainder, but
        // 2s' doesn't fit within the available buffer. Compute r/s' and adjust the result
        r.div_rem(u);
        // Adjust the result for divisor 2s'
        let r_mod2 = r.shr1_assign();
        let u_hi = u.conditional_add_assign(s_hi, Limb::ZERO, r_mod2.is_nonzero());

        let (r_lo, r_hi) = r.split_at_mut(l);

        // s = s'B + q
        s_lo.copy_from(r_lo);
        let q_hi = r_hi.limbs[0];
        s_hi.add_assign_limb(q_hi);
        debug_assert!(q_hi.0 & !1 == 0);

        // r = uB + a0
        r_lo.copy_from(a0);
        r_hi.leading_mut(rt_len).copy_from(u);
        r_hi.limbs[rt_len] = u_hi;

        // Compute q^2
        let q2 = s_tail.leading_mut(l * 2);
        q2.fill(Limb::ZERO);
        s_lo.wrapping_square(q2);

        // r -= q^2, producing a borrow if r < 0
        let (r0, r1) = r.split_at_mut(l * 2);
        let borrow = r0.borrowing_sub_assign(q2, Limb::ZERO);
        let swap = r1.borrowing_sub_assign_limb(q_hi, borrow).lsb_to_choice();
        let s_carry = Limb::select(Limb::ZERO, Limb::ONE, swap);

        // s -= 1 if r < 0
        s.borrowing_sub_assign_limb(s_carry, Limb::ZERO);

        // r += 2s + 1 if r < 0
        let s_mul = s_carry.shl(1);
        r.carrying_add_assign_mul_limb(s, s_mul, s_carry);

        // Clear upper limbs of the result buffers
        s_tail.fill(Limb::ZERO);
        r_tail.fill(Limb::ZERO);
    }
}

/// Compute the square root and remainder of a [`Word`].
///
/// Adapted from Hacker's Delight 2E by Henry S. Warren Jr.,
/// Fig. 11-4, "Integer square root, hardware algorithm"
/// based on Toepler's algorithm.
#[inline]
const fn sqrt_rem_word(value: Word) -> (Word, Word) {
    let mut m = 1 << (Word::BITS - 2);
    let mut x = value;
    let mut y = 0;
    while m != 0 {
        let b = y | m;
        y >>= 1;
        let mask = word::choice_to_mask(word::choice_from_le(b, x));
        x = x.wrapping_sub(b & mask);
        y |= m & mask;
        m >>= 2;
    }
    (y, x)
}

/// Compute the root and remainder for `n+1` limbs, given the root and remainder
/// for `n` limbs (n=1 or 2). The input value must be normalized such that at least one of the
/// top two bits is set, producing an `s1` with at least `Word::BITS/2` bits.
///
/// This is essentially a specialized version of the root expansion portion of `sqrt_rem_normalized`.
#[allow(clippy::cast_possible_truncation)]
#[inline]
const fn sqrt_rem_expand_by_word(s1: Word, r1: WideWord, next: Word) -> (WideWord, WideWord) {
    const HALF_WIDTH: u32 = Word::BITS >> 1;
    debug_assert!((s1 >> (HALF_WIDTH - 1)) > 0);

    // Split the lower word into lower and upper halves
    let (a0, a1) = (
        (next & ((1 << HALF_WIDTH) - 1)) as WideWord,
        (next >> HALF_WIDTH) as WideWord,
    );
    let d = (r1 << HALF_WIDTH) | a1;

    // Divide by (r1B + a1) by s1 (not 2s1 which could overflow a limb)
    let (q, _) = Uint::<2>::from_wide_word(d).div_rem_limb(NonZero::<Limb>::new_unwrap(Limb(s1)));
    // Correct the quotient
    let q = (q.limbs[0].0 >> 1) as WideWord;
    // Recompute the remainder u
    let u = d - (q << 1) * s1 as WideWord;
    // Set s = s1B + q
    let s = ((s1 as WideWord) << HALF_WIDTH) + q;

    // Set r' = uB + a0
    let r_pre = (u << HALF_WIDTH) | a0;
    let q2 = q.pow(2);
    let swap = word::choice_to_wide_mask(word::choice_from_wide_lt(r_pre, q2));

    // Subtract 1 from s if r' < q^2
    let s = s - (swap & 1);
    // Set r = r' - q2, adding back 2s + 1 if r would be negative
    let r = r_pre.wrapping_add(((s << 1) | 1) & swap) - q2;

    (s, r)
}

/// Compute the square root and remainder for a 1 to 3 limb input, which must be normalized.
/// This is the base case square root calculation.
#[allow(clippy::cast_possible_truncation)]
#[inline]
const fn sqrt_rem_small<const VARTIME: bool>(value: &[Limb], s: &mut [Limb], r: &mut [Limb]) {
    let len = value.len();
    assert!(len < 4, "value exceeds maximum size for sqrt_rem_small");

    if len == 0 {
        return;
    }

    if len == 1 {
        let base = value[0].0;
        (s[0].0, r[0].0) = if VARTIME {
            let root = base.isqrt();
            (root, base.wrapping_sub(root.wrapping_pow(2)))
        } else {
            sqrt_rem_word(base)
        };
        return;
    }

    // Compute root, remainder for two words
    let (s1, r1) = {
        if VARTIME {
            let base = word::join(value[len - 2].0, value[len - 1].0);
            let root = base.isqrt();
            (root as Word, base.wrapping_sub(root.wrapping_pow(2)))
        } else {
            let (s0, r0) = sqrt_rem_word(value[len - 1].0);
            let (s1, r1) = sqrt_rem_expand_by_word(s0, r0 as WideWord, value[len - 2].0);
            (s1 as Word, r1)
        }
    };
    if len == 2 {
        s[0].0 = s1;
        (r[0].0, r[1].0) = word::split_wide(r1);
        return;
    }

    // Expand to root, remainder for three words
    let (s1, r1) = sqrt_rem_expand_by_word(s1, r1, value[len - 3].0);
    (s[0].0, s[1].0) = word::split_wide(s1);
    (r[0].0, r[1].0) = word::split_wide(r1);
}

#[cfg(test)]
mod tests {
    use super::{sqrt_rem_expand_by_word, sqrt_rem_word};
    use crate::{WideWord, Word, word};

    #[test]
    fn sqrt_rem_word_expected() {
        fn check(val: Word) {
            let (root, rem) = sqrt_rem_word(val);
            let check = root.pow(2) + rem;
            assert_eq!(check, val, "val: {val}, root: {root}, rem: {rem}");
        }

        check(0);
        check(1);
        check(2);
        check(Word::MAX);
    }

    #[test]
    fn sqrt_rem_expand_by_word_expected() {
        fn check(val: WideWord) {
            let (lo, hi) = word::split_wide(val);
            let s1 = hi.isqrt();
            let r1 = WideWord::from(hi - s1.pow(2));
            let (s, r) = sqrt_rem_expand_by_word(s1, r1, lo);
            assert_eq!(s, val.isqrt());
            assert_eq!(r, val - s.pow(2));
        }

        check(1 << (WideWord::BITS - 1));
        check(2 << (WideWord::BITS - 2));
        check(WideWord::MAX);
    }
}
