//! Equivalence tests between `crypto_bigint::BoxedUint` and `num_bigint::BigUint`.

#![cfg(all(any(unix, windows), feature = "alloc"))]
#![allow(clippy::integer_division_remainder_used, reason = "test")]

mod common;

use common::to_biguint;
use core::ops::Range;
use crypto_bigint::{
    BitOps, BoxedUint, CheckedAdd, ConcatenatingMul, ConcatenatingSquare, Gcd, Integer, Limb,
    NonZero, Odd, Resize, Word,
};
use num_bigint::BigUint;
use num_integer::Integer as _;
use num_modular::ModularUnaryOps;
use num_traits::{Zero, identities::One};
use proptest::collection::vec as propvec;
use proptest::prelude::*;

#[allow(clippy::cast_possible_truncation)]
fn to_uint(big_uint: BigUint) -> BoxedUint {
    let bytes = big_uint.to_bytes_be();
    let pad_count = Limb::BYTES - (bytes.len() % Limb::BYTES);
    let mut padded_bytes = vec![0u8; pad_count];
    padded_bytes.extend_from_slice(&bytes);
    BoxedUint::from_be_slice(&padded_bytes, padded_bytes.len() as u32 * 8).unwrap()
}

fn reduce(x: &BoxedUint, n: &NonZero<BoxedUint>) -> BoxedUint {
    x.rem_vartime(n)
}

fn uint() -> impl Strategy<Value = BoxedUint> {
    prop_oneof![
        9 => uint_bits(1..1024),
        1 => uint_bits(1024..8192),
    ]
}

fn uint_bits(bits_range: Range<u32>) -> impl Strategy<Value = BoxedUint> {
    let min_limbs = bits_range.start.max(1).div_ceil(Limb::BITS) as usize;
    let max_limbs = bits_range.end.div_ceil(Limb::BITS) as usize;
    uint_limbs(min_limbs..max_limbs)
}

#[allow(clippy::cast_possible_truncation)]
fn uint_limbs(limbs_range: Range<usize>) -> impl Strategy<Value = BoxedUint> {
    let random_words = || propvec(any::<Word>(), limbs_range.clone());

    let random = random_words().prop_map(BoxedUint::from_words);
    let zero = limbs_range
        .clone()
        .prop_map(|l| BoxedUint::zero_with_precision(l as u32 * Limb::BITS));
    let single_bit = (limbs_range.clone(), any::<u32>()).prop_map(|(l, bit)| {
        let mut uint = BoxedUint::zero_with_precision(l as u32 * Limb::BITS);
        uint.set_bit_vartime(bit % uint.bits_precision(), true);
        uint
    });
    let low_bits = (random_words(), any::<u32>()).prop_map(|(words, bit)| {
        let mut uint = BoxedUint::from_words(words);
        uint.wrapping_shr_assign(bit);
        uint
    });
    let high_bits = (random_words(), any::<u32>()).prop_map(|(words, bit)| {
        let mut uint = BoxedUint::from_words(words);
        uint.wrapping_shl_assign(bit);
        uint
    });

    prop_oneof![
        6 => random,
        1 => zero,
        2 => single_bit,
        2 => low_bits,
        2 => high_bits,
    ]
}

prop_compose! {
    fn nonzero_uint()(mut val in uint()) -> NonZero<BoxedUint> {
        if val.is_zero().to_bool() {
            val.set_one();
        }
        val.into_nz().unwrap()
    }
}

prop_compose! {
    fn odd_uint()(mut val in uint()) -> Odd<BoxedUint> {
        val.set_bit_vartime(0, true);
        val.into_odd().unwrap()
    }
}

prop_compose! {
    /// Generate a pair of random `BoxedUint`s with the same precision.
    fn uint_pair()(a in uint(), b in uint()) -> (BoxedUint, BoxedUint) {
        let bits_precision = core::cmp::max(a.bits_precision(), b.bits_precision());
        (a.resize(bits_precision), b.resize(bits_precision))
    }
}

proptest! {
    #[test]
    fn roundtrip(a in uint()) {
        prop_assert_eq!(&a, &to_uint(to_biguint(&a)));
    }

    #[test]
    fn bits(a in uint()) {
        #[allow(clippy::cast_possible_truncation)]
        let expected = to_biguint(&a).bits() as u32;
        prop_assert_eq!(expected, a.bits());
        prop_assert_eq!(expected, a.bits_vartime());
    }

    #[test]
    fn checked_add(a in uint(), b in uint()) {
        let a_bi = to_biguint(&a);
        let b_bi = to_biguint(&b);
        let expected = a_bi + b_bi;

        match Option::<BoxedUint>::from(a.checked_add(&b)) {
            Some(actual) => prop_assert_eq!(expected, to_biguint(&actual)),
            None => {
                let max = BoxedUint::max(a.bits_precision());
                prop_assert!(expected > to_biguint(&max));
            }
        }
    }

    #[test]
    fn checked_div(a in uint(), b in uint()) {
        let actual = a.checked_div(&b);

        if b.is_zero().into() {
            prop_assert!(bool::from(actual.is_none()));
        } else {
            let a_bi = to_biguint(&a);
            let b_bi = to_biguint(&b);
            let expected = &a_bi / &b_bi;
            prop_assert_eq!(expected, to_biguint(&actual.unwrap()));
        }
    }

    #[test]
    fn concatenating_add(a in uint(), b in uint()) {
        let a_bi = to_biguint(&a);
        let b_bi = to_biguint(&b);

        let expected = a_bi + b_bi;
        let actual = a.concatenating_add(&b);

        prop_assert_eq!(expected, to_biguint(&actual));
    }

    #[test]
    fn div_rem(a in uint(), b in nonzero_uint()) {
        let a_bi = to_biguint(&a);
        let b_bi = to_biguint(b.as_ref());
        let (expected_quotient, expected_remainder) = a_bi.div_rem(&b_bi);

        let (actual_quotient, actual_remainder) = a.div_rem(&b);
        prop_assert_eq!(expected_quotient, to_biguint(&actual_quotient));
        prop_assert_eq!(expected_remainder, to_biguint(&actual_remainder));

        let (quotient_vartime, remainder_vartime) = a.div_rem_vartime(&b);
        prop_assert_eq!(actual_quotient, quotient_vartime);
        prop_assert_eq!(actual_remainder, remainder_vartime);
    }

    #[test]
    fn div_exact(a in uint(), b in nonzero_uint()) {
        let a_bi = to_biguint(&a);
        let b_bi = to_biguint(b.as_ref());
        let (expected_quotient, expected_remainder) = a_bi.div_rem(&b_bi);
        let expected = if expected_remainder.is_zero() { Some(expected_quotient) } else { None };

        let actual = a.div_exact(&b).into_option();
        prop_assert_eq!(&expected, &actual.as_ref().map(to_biguint));
        let actual_vartime = a.div_exact_vartime(&b).into_option();
        prop_assert_eq!(expected, actual_vartime.as_ref().map(to_biguint));
    }

    #[test]
    // TODO: expand to f in uint(), g in uint()
    fn gcd((f, g) in uint_pair()) {
        let f_bi = to_biguint(&f);
        let g_bi = to_biguint(&g);

        let expected = to_uint(f_bi.gcd(&g_bi));
        let actual = f.gcd(&g);
        prop_assert_eq!(expected, actual);
    }

    #[test]
    fn invert_mod2k(a in odd_uint(), k in any::<u32>()) {
        let k = k % (a.bits() + 1);
        let a_bi = to_biguint(&a);
        let m_bi = BigUint::one() << k as usize;

        let actual = a.invert_mod2k(k).0;
        let (actual_vartime, exists) = a.invert_mod2k_vartime(k);
        prop_assert!(bool::from(exists));
        prop_assert_eq!(&actual, &actual_vartime);

        if k == 0 {
            prop_assert_eq!(&actual, &BoxedUint::zero_with_precision(a.bits_precision()));
        }
        else {
            let inv_bi = to_biguint(&actual);
            let res = (inv_bi * a_bi) % m_bi;
            prop_assert_eq!(res, BigUint::one());
        }
    }

    #[test]
    fn mod_invert((mut a, mut b) in uint_pair()) {
        if a.is_zero().into() {
            // we disagree on whether the inverse of zero exists
            a = BoxedUint::one_with_precision(a.bits_precision());
        }
        if b.is_even().into() {
            b = b.wrapping_add(Limb::ONE);
        }

        let b = b.to_odd().unwrap();

        let a_bi = to_biguint(&a);
        let b_bi = to_biguint(&b);
        let expected = a_bi.invm(&b_bi);
        let actual = Option::<BoxedUint>::from(a.invert_odd_mod(&b));

        match (expected, actual) {
            (Some(exp), Some(act)) => prop_assert_eq!(exp, to_biguint(&act)),
            (None, None) => (),
            (_, _) => panic!("disagreement on if modular inverse exists")
        }
    }

    #[test]
    fn mul_mod(a in uint(), b in uint(), n in odd_uint()) {
        let a = reduce(&a, n.as_nz_ref());
        let b = reduce(&b, n.as_nz_ref());

        let a_bi = to_biguint(&a);
        let b_bi = to_biguint(&b);
        let n_bi = to_biguint(&n);

        let expected = to_uint((a_bi * b_bi) % n_bi);
        let actual = a.mul_mod(&b, n.as_nz_ref());
        prop_assert_eq!(expected, actual);
    }

    #[test]
    fn wrapping_pow(a in uint(), b in uint_bits(1..1024)) {
        let a_bi = to_biguint(&a);
        let b_bi = to_biguint(&b);
        let p_bi = to_biguint(&BoxedUint::max(a.bits_precision())) + 1u32;

        let expected = to_uint(a_bi.modpow(&b_bi, &p_bi));

        let actual = a.wrapping_pow(&b);

        prop_assert_eq!(expected, actual);
    }

    #[test]
    fn pow_mod(a in uint(), b in uint_bits(1..1024), n in odd_uint()) {
        let a = reduce(&a, n.as_nz_ref());

        let a_bi = to_biguint(&a);
        let b_bi = to_biguint(&b);
        let n_bi = to_biguint(&n);

        let expected = to_uint(a_bi.modpow(&b_bi, &n_bi));
        let actual = a.pow_mod(&b, &n);
        prop_assert_eq!(expected, actual);
    }

    #[test]
    fn widening_mul(a in uint(), b in uint()) {
        let a_bi = to_biguint(&a);
        let b_bi = to_biguint(&b);

        let expected = a_bi * b_bi;
        let actual = a.concatenating_mul(&b);

        prop_assert_eq!(expected, to_biguint(&actual));
    }

    #[test]
    fn widening_square(a in uint()) {
        let a_bi = to_biguint(&a);

        let expected = a_bi.pow(2);
        let actual = a.concatenating_square();

        prop_assert_eq!(expected, to_biguint(&actual));
    }

    #[test]
    fn wrapping_mul(a in uint(), b in uint()) {
        let a_bi = to_biguint(&a);
        let b_bi = to_biguint(&b);

        let cap = BigUint::from(2u32).pow(a.bits_precision());
        let expected = (a_bi * b_bi) % cap;
        let actual = a.wrapping_mul(&b);

        prop_assert_eq!(expected, to_biguint(&actual));
    }

    #[test]
    fn wrapping_square(a in uint()) {
        let a_bi = to_biguint(&a);

        let cap = BigUint::from(2u32).pow(a.bits_precision());
        let expected = a_bi.pow(2) % cap;
        let actual = a.wrapping_square();

        prop_assert_eq!(expected, to_biguint(&actual));
    }

    #[test]
    fn rem(a in uint(), b in nonzero_uint()) {
        let a_bi = to_biguint(&a);
        let b_bi = to_biguint(b.as_ref());

        let expected = a_bi % b_bi;
        let actual = a.rem(&b);

        prop_assert_eq!(expected, to_biguint(&actual));
    }

    #[test]
    fn rem_vartime(a in uint(), b in nonzero_uint()) {
        prop_assume!(b.is_nonzero().to_bool());

        let a_bi = to_biguint(&a);
        let b_bi = to_biguint(b.as_ref());

        let expected = a_bi % b_bi;
        let actual = a.rem_vartime(&b);

        prop_assert_eq!(expected, to_biguint(&actual));
    }

    #[test]
    fn unbounded_shl(a in uint(), shift in any::<u16>()) {
        let a_bi = to_biguint(&a);

        // Add a 50% probability of overflow.
        let shift = u32::from(shift) % (a.bits_precision() * 2);

        let expected = to_uint((a_bi << shift as usize) & ((BigUint::one() << a.bits_precision() as usize) - BigUint::one()));
        let actual_ct = a.unbounded_shl(shift);
        prop_assert_eq!(&expected, &actual_ct);

        let actual_vartime = a.unbounded_shl_vartime(shift);
        prop_assert_eq!(&expected, &actual_vartime);
    }

    #[test]
    fn unbounded_shr(a in uint(), shift in any::<u16>()) {
        let a_bi = to_biguint(&a);

        // Add a 50% probability of overflow.
        let shift = u32::from(shift) % (a.bits_precision() * 2);

        let expected = to_uint(a_bi >> shift as usize);
        let actual_ct = a.unbounded_shr(shift);
        prop_assert_eq!(&expected, &actual_ct);

        let actual_vartime = a.unbounded_shr_vartime(shift);
        prop_assert_eq!(&expected, &actual_vartime);
    }

    #[test]
    fn shl_vartime(a in uint(), shift in any::<u16>()) {
        let a_bi = to_biguint(&a);

        // Add a 50% probability of overflow.
        let shift = u32::from(shift) % (a.bits_precision() * 2);

        let expected = to_uint((a_bi << shift as usize) & ((BigUint::one() << a.bits_precision() as usize) - BigUint::one()));
        let actual = a.shl_vartime(shift);

        if shift >= a.bits_precision() {
            prop_assert!(actual.is_none());
        }
        else {
            prop_assert_eq!(expected, actual.unwrap());
        }
    }

    #[test]
    fn shr_vartime(a in uint(), shift in any::<u16>()) {
        let a_bi = to_biguint(&a);

        // Add a 50% probability of overflow.
        let shift = u32::from(shift) % (a.bits_precision() * 2);

        let expected = to_uint(a_bi >> shift as usize);
        let actual = a.shr_vartime(shift);

        if shift >= a.bits_precision() {
            prop_assert!(actual.is_none());
        }
        else {
            prop_assert_eq!(expected, actual.unwrap());
        }
    }

    #[test]
    fn radix_encode_vartime(a in uint(), radix in 2u32..=36) {
        let a_bi = to_biguint(&a);

        let expected_enc = a_bi.to_str_radix(radix);
        let actual_enc = a.to_string_radix_vartime(radix);
        prop_assert_eq!(&expected_enc, &actual_enc);

        let decoded = BoxedUint::from_str_radix_vartime(&actual_enc, radix).expect("decoding error");
        let dec_bi = to_biguint(&decoded);
        prop_assert_eq!(dec_bi, a_bi);

    }

    #[test]
    fn from_be_slice_vartime(a in uint()) {
        let a_bytes = a.to_be_bytes_trimmed_vartime();
        let b = BoxedUint::from_be_slice_vartime(&a_bytes);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn from_le_slice_vartime(a in uint()) {
        let a_bytes = a.to_le_bytes_trimmed_vartime();
        let b = BoxedUint::from_le_slice_vartime(&a_bytes);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn floor_sqrt(a in uint()) {
        let root = a.floor_sqrt();
        prop_assert_eq!(&root, &a.floor_sqrt_vartime());
        let checked_square = root.checked_square().into_option();
        prop_assert!(checked_square.is_some());
        prop_assert!(checked_square.unwrap() <= a);
        let rtp = (root + Limb::ONE).saturating_square();
        prop_assert!(rtp > a || a.wrapping_add(Limb::ONE).is_zero().to_bool());
    }
}
