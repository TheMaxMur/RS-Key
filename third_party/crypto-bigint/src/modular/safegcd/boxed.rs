//! Implementation of Bernstein-Yang modular inversion and GCD algorithm (a.k.a. safegcd)
//! as described in: <https://eprint.iacr.org/2019/266>.
//!
//! See parent module for more information.

use super::{GCD_BATCH_SIZE, Matrix, iterations, jump};
use crate::{
    BoxedUint, Choice, ConcatenatingMul, CtAssign, CtOption, CtSelect, I64, Int, Limb, NonZero,
    Odd, Resize, U64, Uint,
    primitives::{u32_max, u32_min},
};
use core::fmt;

/// Modular multiplicative inverter based on the Bernstein-Yang method.
///
/// See [`super::SafeGcdInverter`] for more information.
#[derive(Clone, Debug)]
pub(crate) struct BoxedSafeGcdInverter {
    /// Modulus
    pub(crate) modulus: Odd<BoxedUint>,

    /// Multiplicative inverse of the modulus modulo 2^62
    inverse: u64,

    /// Adjusting parameter (see toplevel documentation).
    adjuster: BoxedUint,
}

impl BoxedSafeGcdInverter {
    /// Creates the inverter for specified modulus and adjusting parameter.
    ///
    /// Modulus must be odd. Returns `None` if it is not.
    #[cfg(test)]
    pub fn new(modulus: Odd<BoxedUint>, adjuster: BoxedUint) -> Self {
        let inverse = U64::from_u64(modulus.as_uint_ref().invert_mod_u64());
        Self::new_with_inverse(modulus, inverse, adjuster)
    }

    /// Creates the inverter for specified modulus and adjusting parameter.
    ///
    /// Modulus must be odd. Returns `None` if it is not.
    pub(crate) fn new_with_inverse(
        modulus: Odd<BoxedUint>,
        inverse: U64,
        mut adjuster: BoxedUint,
    ) -> Self {
        adjuster = adjuster.resize(modulus.bits_precision());
        Self {
            modulus,
            inverse: inverse.as_uint_ref().lowest_u64(),
            adjuster,
        }
    }

    /// Perform constant-time modular inversion.
    pub(crate) fn invert(&self, value: &BoxedUint) -> CtOption<BoxedUint> {
        invert_odd_mod_precomp::<false>(
            value,
            &self.modulus,
            self.inverse,
            Some(self.adjuster.clone()),
        )
    }

    /// Perform variable-time modular inversion.
    pub(crate) fn invert_vartime(&self, value: &BoxedUint) -> CtOption<BoxedUint> {
        invert_odd_mod_precomp::<true>(
            value,
            &self.modulus,
            self.inverse,
            Some(self.adjuster.clone()),
        )
    }
}

#[inline]
pub fn invert_odd_mod<const VARTIME: bool>(
    a: &BoxedUint,
    m: &Odd<BoxedUint>,
) -> CtOption<BoxedUint> {
    let mi = m.as_uint_ref().invert_mod_u64();
    invert_odd_mod_precomp::<VARTIME>(a, m, mi, None)
}

/// Calculate the multiplicative inverse of `a` modulo `m`.
///
fn invert_odd_mod_precomp<const VARTIME: bool>(
    a: &BoxedUint,
    m: &Odd<BoxedUint>,
    mi: u64,
    e: Option<BoxedUint>,
) -> CtOption<BoxedUint> {
    let a_nonzero = a.is_nonzero();
    let bits_precision = u32_max(a.bits_precision(), m.as_ref().bits_precision());
    let m = m.as_ref().resize(bits_precision);
    let (mut f, mut g) = (
        SignedBoxedInt::from_uint(m.clone()),
        SignedBoxedInt::from_uint_with_precision(a, bits_precision),
    );
    let (mut d, mut e) = (
        SignedBoxedInt::zero_with_precision(bits_precision),
        SignedBoxedInt::from_uint(e.map_or_else(
            || BoxedUint::one_with_precision(bits_precision),
            |e| e.resize(bits_precision),
        )),
    );
    let mut steps = iterations(bits_precision);
    let mut delta = 1;
    let mut t;

    while steps > 0 {
        if VARTIME && g.is_zero_vartime() {
            break;
        }
        let batch = u32_min(steps, GCD_BATCH_SIZE);
        (delta, t) = jump::<VARTIME>(f.lowest(), g.lowest(), delta, batch);
        (f, g) = update_fg(&f, &g, t, batch);
        (d, e) = update_de(&d, &e, &m, mi, t, batch);
        steps -= batch;
    }

    let d = d.norm(f.is_negative(), &m);
    CtOption::new(d, f.magnitude().is_one() & a_nonzero)
}

/// Calculate the greatest common denominator of `f` and `g`.
pub fn gcd<const VARTIME: bool>(f: &BoxedUint, g: &BoxedUint) -> BoxedUint {
    if VARTIME {
        if let Some(f_nz) = f.as_nz_vartime() {
            gcd_nz::<VARTIME>(f_nz, g).get()
        } else {
            // gcd of (0, g) is g
            g.resize(u32_max(f.bits_precision(), g.bits_precision()))
        }
    } else {
        let (f_nz, f_is_nonzero) = f.to_nz_or_one();
        let mut r = gcd_nz::<VARTIME>(&f_nz, g).get();
        r.ct_assign(g, !f_is_nonzero);
        r
    }
}

/// Calculate the greatest common denominator of nonzero `f`, and `g`.
pub fn gcd_nz<const VARTIME: bool>(f: &NonZero<BoxedUint>, g: &BoxedUint) -> NonZero<BoxedUint> {
    if VARTIME {
        if let Some(f_odd) = f.as_odd_vartime() {
            return gcd_odd::<VARTIME>(f_odd, g).into_nz();
        }
    }

    // Note the following two GCD identity rules:
    // 1) gcd(2f, 2g) = 2•gcd(f, g), and
    // 2) gcd(a, 2g) = gcd(f, g) if f is odd.
    //
    // Combined, these rules imply that
    // 3) gcd(2^i•f, 2^j•g) = 2^k•gcd(f, g), with k = min(i, j).
    //
    // However, to save ourselves having to divide out 2^j, we also note that
    // 4) 2^k•gcd(f, g) = 2^k•gcd(a, 2^j•b)

    let i = f.as_ref().trailing_zeros();
    let j = g
        .is_nonzero()
        .select_u32(f.bits_precision(), g.trailing_zeros());
    let k = u32_min(i, j);

    let f_odd = Odd::new_unchecked(f.as_ref().shr(i));
    let mut r = gcd_odd::<VARTIME>(&f_odd, g).get();
    r.shl_assign(k);
    NonZero::new_unchecked(r)
}

/// Calculate the greatest common denominator of odd `f`, and `g`.
pub fn gcd_odd<const VARTIME: bool>(f: &Odd<BoxedUint>, g: &BoxedUint) -> Odd<BoxedUint> {
    let bits_precision = u32_max(f.as_ref().bits_precision(), g.bits_precision());
    let (mut f, mut g) = (
        SignedBoxedInt::from_uint_with_precision(f.as_ref(), bits_precision),
        SignedBoxedInt::from_uint_with_precision(g, bits_precision),
    );
    let mut steps = iterations(bits_precision);
    let mut delta = 1;
    let mut t;

    while steps > 0 {
        if VARTIME && g.is_zero_vartime() {
            break;
        }
        let batch = u32_min(steps, GCD_BATCH_SIZE);
        (delta, t) = jump::<VARTIME>(f.lowest(), g.lowest(), delta, batch);
        (f, g) = update_fg(&f, &g, t, batch);
        steps -= batch;
    }

    f.magnitude()
        .resize_unchecked(bits_precision)
        .to_odd()
        .expect("odd by construction")
}

#[inline]
fn update_fg(
    a: &SignedBoxedInt,
    b: &SignedBoxedInt,
    t: Matrix,
    shift: u32,
) -> (SignedBoxedInt, SignedBoxedInt) {
    (
        SignedBoxedInt::lincomb_int_reduce_shift(
            a,
            b,
            &I64::from_i64(t[0][0]),
            &I64::from_i64(t[0][1]),
            shift,
        ),
        SignedBoxedInt::lincomb_int_reduce_shift(
            a,
            b,
            &I64::from_i64(t[1][0]),
            &I64::from_i64(t[1][1]),
            shift,
        ),
    )
}

#[inline]
fn update_de(
    d: &SignedBoxedInt,
    e: &SignedBoxedInt,
    m: &BoxedUint,
    mi: u64,
    t: Matrix,
    shift: u32,
) -> (SignedBoxedInt, SignedBoxedInt) {
    (
        SignedBoxedInt::lincomb_int_reduce_shift_mod(
            d,
            e,
            &Int::from_i64(t[0][0]),
            &Int::from_i64(t[0][1]),
            shift,
            m,
            U64::from_u64(mi),
        ),
        SignedBoxedInt::lincomb_int_reduce_shift_mod(
            d,
            e,
            &Int::from_i64(t[1][0]),
            &Int::from_i64(t[1][1]),
            shift,
            m,
            U64::from_u64(mi),
        ),
    )
}

/// A `Uint` which carries a separate sign in order to maintain the same range.
#[derive(Clone)]
struct SignedBoxedInt {
    sign: Choice,
    magnitude: BoxedUint,
}

impl SignedBoxedInt {
    pub fn zero_with_precision(bits_precision: u32) -> Self {
        Self::from_uint(BoxedUint::zero_with_precision(bits_precision))
    }

    /// Construct a new `SignedInt` from a `Uint`.
    pub const fn from_uint(uint: BoxedUint) -> Self {
        Self {
            sign: Choice::FALSE,
            magnitude: uint,
        }
    }

    /// Construct a new `SignedInt` from a `Uint`.
    pub fn from_uint_with_precision(uint: &BoxedUint, bits_precision: u32) -> Self {
        Self {
            sign: Choice::FALSE,
            magnitude: uint.resize(bits_precision),
        }
    }

    /// Construct a new `SignedInt` from a `Uint` and a sign flag.
    pub const fn from_uint_sign(magnitude: BoxedUint, sign: Choice) -> Self {
        Self { sign, magnitude }
    }

    /// Obtain the magnitude of the `SignedInt`, i.e. its absolute value.
    pub const fn magnitude(&self) -> &BoxedUint {
        &self.magnitude
    }

    /// Determine if the `SignedInt` is non-zero.
    pub fn is_nonzero(&self) -> Choice {
        self.magnitude.is_nonzero()
    }

    /// Determine if the `SignedInt` is zero in variable time.
    pub fn is_zero_vartime(&self) -> bool {
        self.magnitude.is_zero_vartime()
    }

    /// Determine if the `SignedInt` is negative.
    /// Note: `-0` is representable in this type, so it may be necessary
    /// to check `self.is_nonzero()` as well.
    pub const fn is_negative(&self) -> Choice {
        self.sign
    }

    /// Extract the lowest 63 bits and convert to its signed representation.
    #[allow(clippy::cast_possible_wrap)]
    pub fn lowest(&self) -> i64 {
        let mag = (self.magnitude.as_uint_ref().lowest_u64() & (u64::MAX >> 1)) as i64;
        self.sign.select_i64(mag, mag.wrapping_neg())
    }

    /// Compute the linear combination `a•b + c•d`, returning a widened result.
    #[inline]
    pub(crate) fn lincomb_int<const RHS: usize>(
        a: &Self,
        b: &Self,
        c: &Int<RHS>,
        d: &Int<RHS>,
    ) -> Self {
        debug_assert!(a.magnitude.bits_precision() == b.magnitude.bits_precision());
        let (c, c_sign) = c.abs_sign();
        let (d, d_sign) = d.abs_sign();
        // Each SignedBoxedInt • abs(Int) product leaves an empty upper bit.
        let mut x = a.magnitude.concatenating_mul(c);
        let x_neg = a.sign.xor(c_sign);
        let mut y = b.magnitude.concatenating_mul(d);
        let y_neg = b.sign.xor(d_sign);
        let odd_neg = x_neg.xor(y_neg);

        // Negate y if none or both of the multiplication results are negative.
        y.conditional_wrapping_neg_assign(odd_neg.not());

        let borrow;
        (x, borrow) = x.borrowing_sub(&y, Limb::ZERO);
        let swap = borrow.is_nonzero().and(odd_neg);

        // Negate the result if we did not negate y and there was a borrow,
        // indicating that |y| > |x|.
        x.conditional_wrapping_neg_assign(swap);

        let sign = x_neg.and(swap.not()).or(y_neg.and(swap));
        Self::from_uint_sign(x, sign)
    }

    /// Compute the linear combination `a•b + c•d`, and shift the result
    /// `shift` bits to the right, returning a signed value in the same range
    /// as the `SignedInt` inputs.
    pub(crate) fn lincomb_int_reduce_shift<const S: usize>(
        a: &Self,
        b: &Self,
        c: &Int<S>,
        d: &Int<S>,
        shift: u32,
    ) -> Self {
        debug_assert!(shift < Uint::<S>::BITS);
        let SignedBoxedInt {
            sign,
            mut magnitude,
        } = Self::lincomb_int(a, b, c, d);
        magnitude.shr_assign(shift);
        Self::from_uint_sign(
            magnitude.resize_unchecked(a.magnitude.bits_precision()),
            sign,
        )
    }

    /// Compute the linear combination `a•b + c•d`, and shift the result
    /// `shift` bits to the right modulo `m`, returning a signed value in the
    /// same range as the `SignedInt` inputs.
    pub(crate) fn lincomb_int_reduce_shift_mod<const S: usize>(
        a: &Self,
        b: &Self,
        c: &Int<S>,
        d: &Int<S>,
        shift: u32,
        m: &BoxedUint,
        mi: Uint<S>,
    ) -> Self {
        debug_assert!(shift < Uint::<S>::BITS);
        let SignedBoxedInt {
            sign: mut x_sign,
            magnitude: mut x,
        } = Self::lincomb_int(a, b, c, d);

        // Compute the multiple of m that will clear the low N bits of x.
        let mut xs = Uint::<S>::ZERO;
        xs.limbs.copy_from_slice(&x.limbs[..S]);
        let mut mf = xs.wrapping_mul(&mi);
        mf = mf.bitand(&Uint::MAX.shr_vartime(Uint::<S>::BITS - shift));
        let xa = m.concatenating_mul(mf);

        // Subtract the adjustment from x potentially producing a borrow.
        let borrow = x.borrowing_sub_assign(&xa, Limb::ZERO);

        // Negate x if the subtraction borrowed.
        let swap = borrow.is_nonzero();
        x.conditional_wrapping_neg_assign(swap);
        x_sign = x_sign.xor(swap);

        // Shift the result, eliminating the trailing zeros.
        x.shr_assign(shift);

        // The magnitude x is now in the range [0, 2m). We conditionally subtract
        // m in order to keep the output in (-m, m).
        let x_hi = x.limbs[m.nlimbs()];
        x = x.resize_unchecked(m.bits_precision());
        x.sub_assign_mod_with_carry(x_hi, m, m);

        Self::from_uint_sign(x, x_sign)
    }

    /// Normalize the value to a `BoxedUint` in the range `[0, m)`.
    fn norm(&self, f_sign: Choice, m: &BoxedUint) -> BoxedUint {
        let swap = f_sign.xor(self.sign) & self.is_nonzero();
        BoxedUint::ct_select(&self.magnitude, &m.wrapping_sub(&self.magnitude), swap)
    }
}

impl fmt::Debug for SignedBoxedInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!(
            "{}0x{}",
            if self.sign.to_bool() { "-" } else { "+" },
            self.magnitude
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{BoxedSafeGcdInverter, gcd_odd, invert_odd_mod};
    use crate::{BoxedUint, Odd, Resize};
    use num_bigint::BigUint;
    use num_integer::Integer;

    /// The smallest precision at which `45907 * bits + 30179` no longer fits in `u32`.
    const LARGE_BITS: u32 = 93_568;

    /// A deterministic, odd, full-width `BoxedUint` of `bits` bits; different seeds give
    /// unrelated values.
    fn large_odd(bits: u32, seed: u32) -> BoxedUint {
        let mut bytes: alloc::vec::Vec<u8> = (0..bits >> 3)
            .map(|i| {
                let h = (i ^ seed.wrapping_mul(0x9E37_79B9)).wrapping_mul(0x85EB_CA6B);
                let h = (h ^ (h >> 13)).wrapping_mul(0xC2B2_AE35);
                (h ^ (h >> 16)).to_le_bytes()[0]
            })
            .collect();
        bytes[0] |= 0x80;
        *bytes.last_mut().unwrap() |= 1;
        BoxedUint::from_be_slice(&bytes, bits).unwrap()
    }

    fn to_big(x: &BoxedUint) -> BigUint {
        BigUint::from_bytes_be(&x.to_be_bytes())
    }

    #[test]
    fn invert_odd_mod_large_precision() {
        let m = large_odd(LARGE_BITS, 1);
        let a = BoxedUint::from(65537u32).resize(LARGE_BITS);
        assert_eq!(to_big(&a).gcd(&to_big(&m)), BigUint::from(1u32));
        let m = Odd::new(m).unwrap();

        for inv in [
            invert_odd_mod::<false>(&a, &m).unwrap(),
            invert_odd_mod::<true>(&a, &m).unwrap(),
        ] {
            assert_eq!(
                (to_big(&a) * to_big(&inv)) % to_big(m.as_ref()),
                BigUint::from(1u32)
            );
        }
    }

    #[test]
    fn gcd_odd_large_precision() {
        // Two unrelated full-width values: the reduction needs the whole iteration budget,
        // unlike a pair with a large common factor and small cofactors.
        let f = Odd::new(large_odd(LARGE_BITS, 2)).unwrap();
        let g = large_odd(LARGE_BITS, 4);
        let expected = to_big(f.as_ref()).gcd(&to_big(&g));

        assert_eq!(to_big(gcd_odd::<false>(&f, &g).as_ref()), expected);
        assert_eq!(to_big(gcd_odd::<true>(&f, &g).as_ref()), expected);
    }

    #[test]
    fn invert() {
        let g = BoxedUint::from_be_hex(
            "00000000CBF9350842F498CE441FC2DC23C7BF47D3DE91C327B2157C5E4EED77",
            256,
        )
        .unwrap();
        let modulus = BoxedUint::from_be_hex(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
            256,
        )
        .unwrap()
        .to_odd()
        .unwrap();
        let inverter = BoxedSafeGcdInverter::new(modulus, BoxedUint::one());
        let result = inverter.invert(&g).unwrap();
        assert_eq!(
            BoxedUint::from_be_hex(
                "FB668F8F509790BC549B077098918604283D42901C92981062EB48BC723F617B",
                256
            )
            .unwrap(),
            result
        );
    }
}
