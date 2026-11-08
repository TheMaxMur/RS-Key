//! Integer primitives for cryptographic arithmetic.

use crate::{Choice, WideWord, Word};
use core::hint::black_box;

/// Computes `lhs + rhs + carry`, returning the result along with the new carry (0, 1, or 2).
#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
pub(crate) const fn carrying_add(lhs: Word, rhs: Word, carry: Word) -> (Word, Word) {
    // We could use `Word::overflowing_add()` here analogous to `overflowing_add()`,
    // but this version seems to produce a slightly better assembly.
    let a = lhs as WideWord;
    let b = rhs as WideWord;
    let carry = carry as WideWord;
    let ret = a + b + carry;
    (ret as Word, (ret >> Word::BITS) as Word)
}

/// Computes `lhs + rhs`, returning the result along with the carry (0 or 1).
#[inline(always)]
pub(crate) const fn overflowing_add(lhs: Word, rhs: Word) -> (Word, Word) {
    let (res, carry) = lhs.overflowing_add(rhs);
    (res, carry as Word)
}

/// Computes `lhs - rhs - borrow`, using word-sized borrow masks.
///
/// The incoming borrow is the most significant bit of `borrow`; all other bits are ignored.
/// The outgoing borrow is `Word::MAX` if the subtraction underflows, or zero otherwise.
#[inline]
pub(crate) const fn borrowing_sub(lhs: Word, rhs: Word, borrow: Word) -> (Word, Word) {
    // Keep all arithmetic in Word: widening can trigger incorrect optimization on older compilers:
    // https://github.com/rust-lang/rust/issues/149522
    let difference = lhs
        .wrapping_sub(rhs)
        .wrapping_sub(borrow >> (Word::BITS - 1));

    // See "Hacker's Delight", 2nd edition, section 2-13 (Overflow detection).
    let borrow = ((!lhs & rhs) | ((!lhs | rhs) & difference)) >> (Word::BITS - 1);

    // Keep the full-width bit opaque before forming a mask, so a caller's masked addend can't be
    // folded into a secret-dependent branch.
    (difference, black_box(borrow).wrapping_neg())
}

/// Computes `lhs * rhs`, returning the low and the high words of the result.
#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
pub(crate) const fn widening_mul(lhs: Word, rhs: Word) -> (Word, Word) {
    let a = lhs as WideWord;
    let b = rhs as WideWord;
    let ret = a * b;
    (ret as Word, (ret >> Word::BITS) as Word)
}

/// Computes `(lhs * rhs) + addend + carry`, returning the result along with the new carry.
#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
pub(crate) const fn carrying_mul_add(
    lhs: Word,
    rhs: Word,
    addend: Word,
    carry: Word,
) -> (Word, Word) {
    let lhs = lhs as WideWord;
    let rhs = rhs as WideWord;
    let addend = addend as WideWord;
    let carry = carry as WideWord;

    // Cannot overflow:
    // lhs      * rhs      + addend   + carry
    // (2^64-1) * (2^64-1) + (2^64-1) + (2^64-1) =
    // 2^128 - 2^65 + 1 + 2^64 - 1 + 2^64 - 1 =
    // 2^128 - 2^65 + 2*2^64 - 1 =
    // 2^128 - 1 = u128::MAX
    let ret = ((lhs * rhs) + addend) + carry;
    (ret as Word, (ret >> Word::BITS) as Word)
}

/// Count leading zero bits, returning `Word::BITS` if `value` is zero.
#[inline]
#[allow(clippy::cast_possible_truncation)]
pub(crate) const fn leading_zeros(value: Word) -> u32 {
    if cfg!(any(target_arch = "aarch64", target_arch = "x86_64")) {
        value.leading_zeros()
    } else {
        cpubits::cpubits! {
            32 => { leading_zeros_u32(value) }
            64 => {
                let hi = (value >> 32) as u32;
                let lo = value as u32;
                let mask = Choice::from_u32_nz(hi).not().to_u32_mask();
                leading_zeros_u32(hi).wrapping_add(mask & leading_zeros_u32(lo))
            }
        }
    }
}

/// Count leading zero bits, using native instructions where supported.
#[inline]
const fn leading_zeros_u32(value: u32) -> u32 {
    if cfg!(any(
        target_arch = "aarch64",
        target_arch = "x86",
        target_arch = "x86_64",
        target_feature = "thumb2",
        target_feature = "zbb"
    )) {
        value.leading_zeros()
    } else {
        leading_zeros_u32_soft(value)
    }
}

/// Fixed-stage binary search for the highest set bit, including the zero case.
#[inline]
const fn leading_zeros_u32_soft(mut value: u32) -> u32 {
    let mut count = 0u32;
    let mut shift = 16;

    while shift != 0 {
        let mask = Choice::from_u32_nz(value >> (u32::BITS - shift))
            .not()
            .to_u32_mask();
        value ^= mask & (value ^ (value << shift));
        count = count.wrapping_add(mask & shift);
        shift >>= 1;
    }

    count.wrapping_add(Choice::from_u32_nz(value).not().to_u32_mask() & 1)
}

/// Count trailing zero bits, returning `Word::BITS` if `value` is zero.
#[inline]
#[allow(clippy::cast_possible_truncation)]
pub(crate) const fn trailing_zeros(value: Word) -> u32 {
    if cfg!(any(target_arch = "aarch64", target_arch = "x86_64")) {
        value.trailing_zeros()
    } else {
        cpubits::cpubits! {
            32 => { trailing_zeros_u32(value) }
            64 => {
                let hi = (value >> 32) as u32;
                let lo = value as u32;
                let mask = Choice::from_u32_nz(lo).not().to_u32_mask();
                trailing_zeros_u32(lo).wrapping_add(mask & trailing_zeros_u32(hi))
            }
        }
    }
}

/// Count trailing zero bits, using native instructions where supported.
#[inline]
const fn trailing_zeros_u32(value: u32) -> u32 {
    if cfg!(any(
        target_arch = "aarch64",
        target_arch = "x86",
        target_arch = "x86_64",
        target_feature = "thumb2",
        target_feature = "zbb"
    )) {
        value.trailing_zeros()
    } else {
        // Reversing bits uses fixed shifts and masks when RBIT is unavailable.
        leading_zeros_u32_soft(value.reverse_bits())
    }
}

/// `const fn` equivalent of `u32::max(a, b)`.
#[inline]
pub(crate) const fn u32_max(a: u32, b: u32) -> u32 {
    Choice::from_u32_lt(a, b).select_u32(a, b)
}

/// `const` equivalent of `u32::min(a, b)`.
#[inline]
pub(crate) const fn u32_min(a: u32, b: u32) -> u32 {
    Choice::from_u32_lt(a, b).select_u32(b, a)
}

/// Remainder calculation, constant time for a given divisor `d`.
/// Based on "Faster Remainder by Direct Computation: Applications to Compilers and Software Libraries"
/// by Daniel Lemire, Owen Kaser, and Nathan Kurz., Fig. 1.
#[inline(never)]
#[allow(clippy::cast_possible_truncation, reason = "needs triage")]
#[allow(clippy::integer_division_remainder_used, reason = "needs triage")]
pub(crate) const fn u32_rem(n: u32, d: u32) -> u32 {
    assert!(d > 0, "divisor must be nonzero");
    let c = u64::MAX / (d as u64) + 1;
    (((c.wrapping_mul(n as u64) as u128) * d as u128) >> 64) as u32
}

/// Compute the number of bits needed to represent `n`.
#[inline(always)]
pub(crate) const fn u32_bits(n: u32) -> u32 {
    u32::BITS - n.leading_zeros()
}

/// Return a `Choice` representing whether `a < b`.
#[allow(clippy::cast_possible_truncation)]
#[cfg(target_pointer_width = "32")]
#[inline]
pub(crate) const fn usize_lt(a: usize, b: usize) -> Choice {
    Choice::from_u32_lt(a as u32, b as u32)
}

/// Return a `Choice` representing whether `a < b`.
#[allow(clippy::cast_possible_truncation)]
#[cfg(target_pointer_width = "64")]
#[inline]
pub(crate) const fn usize_lt(a: usize, b: usize) -> Choice {
    Choice::from_u64_lt(a as u64, b as u64)
}

cpubits::cpubits! {
    32 => {
        /// Returns the multiplicative inverse of the argument modulo 2^32.
        ///
        /// For correct results, the input `value` must be odd.
        #[must_use]
        pub(crate) const fn u32_invert_odd(value: u32) -> u32 {
            debug_assert!(value & 1 == 1, "value must be odd");
            let x = value.wrapping_mul(3) ^ 2;
            let y = 1u32.wrapping_sub(x.wrapping_mul(value));
            let (x, y) = (x.wrapping_mul(y.wrapping_add(1)), y.wrapping_mul(y));
            let (x, y) = (x.wrapping_mul(y.wrapping_add(1)), y.wrapping_mul(y));
            x.wrapping_mul(y.wrapping_add(1))
        }
    }
}

/// Returns the multiplicative inverse of the argument modulo 2^64. The implementation is based
/// on Hurchalla's method for computing the multiplicative inverse modulo a power of two, and
/// is essentially an optimized Newton iteration.
///
/// For correct results, the input `value` must be odd.
///
/// For better understanding the implementation, the following paper is recommended:
/// J. Hurchalla, "An Improved Integer Multiplicative Inverse (modulo 2^w)",
/// <https://arxiv.org/abs/2204.04342>
#[must_use]
pub(crate) const fn u64_invert_odd(value: u64) -> u64 {
    debug_assert!(value & 1 == 1, "value must be odd");
    let x = value.wrapping_mul(3) ^ 2;
    let y = 1u64.wrapping_sub(x.wrapping_mul(value));
    let (x, y) = (x.wrapping_mul(y.wrapping_add(1)), y.wrapping_mul(y));
    let (x, y) = (x.wrapping_mul(y.wrapping_add(1)), y.wrapping_mul(y));
    let (x, y) = (x.wrapping_mul(y.wrapping_add(1)), y.wrapping_mul(y));
    x.wrapping_mul(y.wrapping_add(1))
}

#[cfg(test)]
mod tests {
    use super::{u32_max, u32_min, u32_rem, usize_lt};
    use crate::Word;

    // These primitives must remain usable by const callers.
    const _: () = {
        assert!(super::borrowing_sub(0, 0, Word::MAX).0 == Word::MAX);
        assert!(super::borrowing_sub(0, 0, Word::MAX).1 == Word::MAX);
        assert!(super::borrowing_sub(1, 0, Word::MAX).1 == 0);
        assert!(super::leading_zeros(0) == Word::BITS);
        assert!(super::trailing_zeros(0) == Word::BITS);
        assert!(super::leading_zeros_u32_soft(0) == u32::BITS);
    };

    #[test]
    fn zero_counts() {
        for bit in 0..Word::BITS {
            for value in [0, 1 << bit, !(1 << bit), Word::MAX >> bit] {
                assert_eq!(super::leading_zeros(value), value.leading_zeros());
                assert_eq!(super::trailing_zeros(value), value.trailing_zeros());
            }
        }
    }

    #[test]
    fn zero_counts_u32() {
        for bit in 0..u32::BITS {
            for value in [0, 1 << bit, !(1 << bit), u32::MAX >> bit] {
                assert_eq!(super::leading_zeros_u32(value), value.leading_zeros());
                assert_eq!(super::trailing_zeros_u32(value), value.trailing_zeros());
                // Exercise the software fallback even on hosts with native instructions.
                assert_eq!(super::leading_zeros_u32_soft(value), value.leading_zeros());
                assert_eq!(
                    super::leading_zeros_u32_soft(value.reverse_bits()),
                    value.trailing_zeros()
                );
            }
        }
    }

    #[test]
    fn carrying_mul_add_cannot_overflow() {
        let lhs = Word::MAX;
        let rhs = Word::MAX;
        let addend = Word::MAX;
        let carry_in = Word::MAX;
        let (result, carry_out) = super::carrying_mul_add(lhs, rhs, addend, carry_in);
        assert_eq!(result, Word::MAX);
        assert_eq!(carry_out, Word::MAX);
    }

    #[test]
    fn test_u32_const_min() {
        assert_eq!(u32_min(0, 5), 0);
        assert_eq!(u32_min(7, 0), 0);
        assert_eq!(u32_min(7, 5), 5);
        assert_eq!(u32_min(7, 7), 7);
    }

    #[test]
    fn test_u32_const_max() {
        assert_eq!(u32_max(0, 5), 5);
        assert_eq!(u32_max(7, 0), 7);
        assert_eq!(u32_max(7, 5), 7);
        assert_eq!(u32_max(7, 7), 7);
    }

    #[test]
    fn test_u32_const_rem() {
        assert_eq!(u32_rem(0, 5), 0);
        assert_eq!(u32_rem(4, 5), 4);
        assert_eq!(u32_rem(7, 5), 2);
        assert_eq!(u32_rem(101, 5), 1);
    }

    #[test]
    fn test_usize_const_lt() {
        assert!(usize_lt(0, 5).to_bool());
        assert!(!usize_lt(7, 0).to_bool());
        assert!(!usize_lt(7, 5).to_bool());
        assert!(!usize_lt(7, 7).to_bool());
    }

    cpubits::cpubits! {
        32 => {
            #[test]
            fn test_u32_invert_odd() {
                use super::u32_invert_odd;

                assert_eq!(u32_invert_odd(1), 1);
                assert_eq!(u32_invert_odd(5).wrapping_mul(5), 1);
                assert_eq!(u32_invert_odd(u32::MAX).wrapping_mul(u32::MAX), 1);
            }
        }
    }
}
