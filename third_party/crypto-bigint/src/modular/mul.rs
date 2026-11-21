use super::reduction::montgomery_reduction;
use crate::{CtLt, Limb, Odd, Uint, UintRef, WideWord, Word, word};

/// Computes an "almost" Montgomery multiplication of `x` and `y` into `out`, that is
/// `out = x * y * 2^(-n*W) mod m + am` assuming `k = -1/m mod 2^W`,
/// where `W` is the bit size of the limb, and `n * W` is the full bit size of the integer.
///
/// NOTE: `out` is assumed to be pre-zeroized.
///
/// Unlike the standard Montgomery multiplication, we are reducing the final result only if
/// it overflows `2^(n*W)`, not when it overflows `m`.
///
/// This means that this function does not assume `x` and `y` are reduced `mod m`,
/// and the result will be correct `mod m`, but potentially greater than `m`,
/// and smaller than `2^(n * W) + m`.
/// See "Efficient Software Implementations of Modular Exponentiation" by S. Gueron for details
/// (<https://eprint.iacr.org/2011/239.pdf>).
///
/// This function exhibits certain properties which were discovered via randomized tests,
/// but (to my knowledge at this moment) have not been proven formally.
/// Hereinafter we denote `f(x) = floor(x / m)`, that is `f` is the number of subtractions
/// of the modulus required to fully reduce `x`.
///
/// 1. In general, if `f(x) = k` and `f(y) = n`, then `f(AMM(x, y)) <= min(k, n) + 1`.
///    That is the "reduction error" grows with every operation,
///    but is determined by the argument with the lower error.
/// 2. To retrieve the number from Montgomery form we MM it by 1. In this case `f(AMM(x, 1)) = 0`,
///    that is the result is always fully reduced regardless of `f(x)`.
/// 3. `f(AMM(x, x)) <= 1` regardless of `f(x)`. That is, squaring resets the error to at most 1.
#[inline]
pub(crate) fn almost_montgomery_mul(
    x: &UintRef,
    y: &UintRef,
    out: &mut UintRef,
    modulus: &UintRef,
    mod_neg_inv: Limb,
) {
    let overflow = montgomery_multiply_inner(
        x.as_limbs(),
        y.as_limbs(),
        out.as_mut_limbs(),
        modulus.as_limbs(),
        mod_neg_inv,
    );
    let overflow = word::choice_from_lsb(overflow.0);
    out.conditional_borrowing_sub_assign(modulus, overflow);
}

/// Ensure the output of an "almost" Montgomery multiplication is properly reduced.
///
/// Using the properties of `almost_montgomery_mul()` (see its documentation):
/// - We have an incoming `x` which is fully reduced (`floor(x / modulus) = 0`).
/// - We build an array of `powers` which are produced by multiplying the previous power by
///   `x`, so for each power `floor(power / modulus) <= 1`.
/// - Then we take turns squaring the accumulator `z` (bringing `floor(z / modulus)` to 1
///   regardless of the previous reduction level) and multiplying by a power of `x`
///   (bringing `floor(z / modulus)` to at most 2).
/// - Then we either exit the loop, or square again, which brings `floor(z / modulus)` back
///   to 1.
///
/// We now need to reduce `z` at most twice to bring it within `[0, modulus)`.
pub(crate) fn almost_montgomery_reduce(z: &mut UintRef, modulus: &UintRef) {
    z.conditional_borrowing_sub_assign(modulus, !z.ct_lt(modulus));
    z.conditional_borrowing_sub_assign(modulus, !z.ct_lt(modulus));
}

/// Based on Algorithm 14.36 in Handbook of Applied Cryptography
/// <https://cacr.uwaterloo.ca/hac/about/chap14.pdf>
///
/// Multiply `x` and `y` in Montgomery form, producing `x•y•R^-1 mod modulus + a•modulus`.
///
/// This algorithm roughly corresponds to the Finely Integrated Operand Scanning (FIOS)
/// method of "Analyzing and Comparing Montgomery Multiplication Algorithms" by Koc et al
/// <https://www.microsoft.com/en-us/research/wp-content/uploads/1996/01/j37acmon.pdf>
/// but using wide words to track the intermediate products and carry.
///
/// The final conditional subtraction of the modulus to produce a result in the range
/// `[0, modulus)` is not performed here, and must be performed by the caller. In some
/// cases this may be deferred, as demonstrated by the `almost_montgomery_mul` method.
#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
pub const fn montgomery_multiply_inner(
    x: &[Limb],
    y: &[Limb],
    out: &mut [Limb],
    modulus: &[Limb],
    mod_neg_inv: Limb,
) -> Limb {
    let nlimbs = modulus.len();
    assert!(nlimbs == x.len() && nlimbs == y.len() && nlimbs == out.len());

    let mut meta_carry = 0;

    let mut i = 0;
    while i < nlimbs {
        let xi = x[i];
        // Write B = 2^Word::BITS. Then axy <= (B - 1)^2 + (B - 1) = B^2 - B.
        let axy = (xi.0 as WideWord) * (y[0].0 as WideWord) + out[0].0 as WideWord;
        let u = (axy as Word).wrapping_mul(mod_neg_inv.0);

        // Add the low halves separately: lo <= 2B - 2 fits in WideWord. This keeps
        // the carry in arithmetic form without a double-width overflow flag.
        let um = (u as WideWord) * (modulus[0].0 as WideWord);
        let lo = (axy as Word as WideWord) + (um as Word as WideWord);
        // floor((axy + um) / B) <= 2B - 2, including any carry from the low halves.
        let mut carry = (axy >> Word::BITS) + (um >> Word::BITS) + (lo >> Word::BITS);

        let mut j = 1;
        while j < nlimbs {
            // axy <= B^2 - B.
            let axy = (xi.0 as WideWord) * (y[j].0 as WideWord) + out[j].0 as WideWord;
            // umc <= (B - 1)^2 + (2B - 2) = B^2 - 1.
            let umc = (u as WideWord) * (modulus[j].0 as WideWord) + carry;
            let lo = (axy as Word as WideWord) + (umc as Word as WideWord);
            out[j - 1] = Limb(lo as Word);
            // floor((axy + umc) / B) <= floor((2B^2 - B - 1) / B) = 2B - 2.
            carry = (axy >> Word::BITS) + (umc >> Word::BITS) + (lo >> Word::BITS);
            j += 1;
        }

        // meta_carry <= 1, so this sum is at most 2B - 1 and still fits in WideWord.
        carry += meta_carry;
        (out[nlimbs - 1], meta_carry) = (Limb(carry as Word), carry >> Word::BITS);

        i += 1;
    }

    Limb(meta_carry as Word)
}

/// Computes the Montgomery product of `a` and `b` modulo `modulus`, where
/// `a` and `b` are in Montgomery form.
pub(crate) const fn mul_montgomery_form<const LIMBS: usize>(
    a: &Uint<LIMBS>,
    b: &Uint<LIMBS>,
    modulus: &Odd<Uint<LIMBS>>,
    mod_neg_inv: Limb,
) -> Uint<LIMBS> {
    let mut out = Uint::<LIMBS>::ZERO;
    let carry = montgomery_multiply_inner(
        &a.limbs,
        &b.limbs,
        &mut out.limbs,
        &modulus.as_ref().limbs,
        mod_neg_inv,
    );
    out.try_sub_with_carry(carry, modulus.as_ref()).0
}

/// Computes the Montgomery squaring of `a` modulo `modulus` where
/// `a` is in Montgomery form.
pub(crate) const fn square_montgomery_form<const LIMBS: usize>(
    a: &Uint<LIMBS>,
    modulus: &Odd<Uint<LIMBS>>,
    mod_neg_inv: Limb,
) -> Uint<LIMBS> {
    // One case in which it appears to be more efficient to perform a wide squaring and reduction.
    if LIMBS == 4 {
        let lower_upper = a.widening_square();
        return montgomery_reduction(&lower_upper, modulus, mod_neg_inv);
    }

    let mut out = Uint::<LIMBS>::ZERO;
    let carry = montgomery_multiply_inner(
        &a.limbs,
        &a.limbs,
        &mut out.limbs,
        &modulus.as_ref().limbs,
        mod_neg_inv,
    );
    out.try_sub_with_carry(carry, modulus.as_ref()).0
}

/// Computes a repeated Montgomery squaring of `a` modulo `modulus` where
/// `a` is in Montgomery form.
///
/// This method is variable time in `n`.
///
/// Assumes `a` is fully reduced, i.e. `a < modulus`.
#[inline(always)]
pub(crate) const fn square_repeat_montgomery_form<const LIMBS: usize>(
    a: &Uint<LIMBS>,
    n: u32,
    modulus: &Odd<Uint<LIMBS>>,
    mod_neg_inv: Limb,
) -> Uint<LIMBS> {
    if n == 0 {
        return *a;
    }
    if n == 1 {
        return square_montgomery_form(a, modulus, mod_neg_inv);
    }

    let mut i = 0;
    let mut out = *a;
    let mut base;

    while i != n {
        (base, out) = (out, Uint::ZERO);
        let carry = montgomery_multiply_inner(
            &base.limbs,
            &base.limbs,
            &mut out.limbs,
            &modulus.as_ref().limbs,
            mod_neg_inv,
        );
        // Because `base < modulus` here, the raw product is below `2 * modulus` and a single
        // conditional subtraction suffices.
        out = out.try_sub_with_carry(carry, modulus.as_ref()).0;
        i += 1;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::montgomery_multiply_inner;
    use crate::{Limb, Uint, Word, modular::FixedMontyParams};
    use num_bigint::BigUint;

    fn to_biguint(limbs: &[Limb]) -> BigUint {
        limbs.iter().rev().fold(BigUint::from(0u8), |value, limb| {
            (value << Word::BITS) + BigUint::from(limb.0)
        })
    }

    fn check_product<const N: usize>(x: [Limb; N], y: [Limb; N], modulus: [Limb; N]) {
        let modulus = Uint::new(modulus).to_odd().unwrap();
        let params = FixedMontyParams::new_vartime(modulus);
        let m = to_biguint(modulus.as_ref().as_limbs());

        // An unbounded REDC reference checks the complete result, including the
        // final carry, without reproducing the limb-wise additions under test.
        let mut expected = to_biguint(&x) * to_biguint(&y);
        let mask = BigUint::from(Word::MAX);
        let inverse = BigUint::from(params.mod_neg_inv().0);
        for _ in 0..N {
            let u = (&expected * &inverse) & &mask;
            expected = (expected + u * &m) >> Word::BITS;
        }

        let mut out = [Limb::ZERO; N];
        let carry = montgomery_multiply_inner(
            &x,
            &y,
            &mut out,
            modulus.as_ref().as_limbs(),
            params.mod_neg_inv(),
        );
        let actual = to_biguint(&out) + (BigUint::from(carry.0) << (N * Limb::BITS as usize));
        assert_eq!(actual, expected, "x={x:?}, y={y:?}, modulus={modulus:?}");
    }

    #[test]
    fn multiply_carry_boundaries() {
        fn check<const N: usize>() {
            let values = [
                [Limb::ZERO; N],
                Uint::<N>::ONE.to_limbs(),
                [Limb::MAX; N],
                [Limb(Word::MAX - 1); N],
                [Limb(1 << (Word::BITS - 1)); N],
                core::array::from_fn(|i| if i & 1 == 0 { Limb::MAX } else { Limb::ZERO }),
            ];
            for mut modulus in values {
                modulus[0].0 |= 1;
                for x in values {
                    for y in values {
                        check_product(x, y, modulus);
                    }
                }
            }
        }
        check::<1>();
        check::<2>();
        check::<3>();
        check::<4>();
        check::<16>();
    }

    #[test]
    fn multiply_matches_biguint() {
        use chacha20::ChaCha8Rng;
        use rand_core::{Rng, SeedableRng};

        let mut rng = ChaCha8Rng::from_seed([42; 32]);
        let mut limb = || {
            let mut bytes = [0u8; Limb::BYTES];
            rng.fill_bytes(&mut bytes);
            Limb(Word::from_le_bytes(bytes))
        };
        for _ in 0..1024 {
            let x = core::array::from_fn(|_| limb());
            let y = core::array::from_fn(|_| limb());
            let mut modulus: [Limb; 4] = core::array::from_fn(|_| limb());
            modulus[0].0 |= 1;
            check_product(x, y, modulus);
        }
    }
}
