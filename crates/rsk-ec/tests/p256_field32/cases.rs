// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors
use super::*;
use crate::bigint::{Limb, U256};
use p256::elliptic_curve::bigint::{NonZero, Odd, U256 as Big, U512};
use p256::elliptic_curve::{PrimeField, hazmat::FieldArithmetic};

type Field64 = <p256::NistP256 as FieldArithmetic>::FieldElement;
const P: Big = Big::from_be_hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");

struct Oracle {
    modulus: NonZero<Big>,
    inverse_r: Big,
    field_inverse_r: Field64,
}

fn field(value: Big) -> Field64 {
    Option::from(Field64::from_repr(value.to_be_bytes().into())).unwrap()
}

fn field_bytes(value: Field64) -> [u8; 32] {
    value.to_repr().into()
}

fn adapter(value: Big) -> U256 {
    let bytes = value.to_be_bytes();
    U256::new(core::array::from_fn(|i| {
        let j = 28 - 4 * i;
        Limb(u32::from_be_bytes(bytes[j..j + 4].try_into().unwrap()))
    }))
}

fn big(value: U256) -> Big {
    let mut bytes = [0u8; 32];
    for (i, limb) in value.as_limbs().iter().enumerate() {
        bytes[28 - 4 * i..32 - 4 * i].copy_from_slice(&limb.0.to_be_bytes());
    }
    Big::from_be_slice(&bytes)
}

fn wide9(words: [Limb; 9]) -> U512 {
    let mut bytes = [0u8; 64];
    for (i, limb) in words.iter().enumerate() {
        bytes[60 - 4 * i..64 - 4 * i].copy_from_slice(&limb.0.to_be_bytes());
    }
    U512::from_be_slice(&bytes)
}

impl Oracle {
    fn new() -> Self {
        assert_eq!(usize::BITS, 64, "oracle must exercise independent field64");
        assert_eq!(core::mem::size_of::<Limb>(), 4);
        assert_eq!(core::mem::size_of::<U256>(), 32);
        let modulus = NonZero::new(P).unwrap();
        assert_eq!(big(crate::bigint::MODULUS), P);
        let r = (U512::ONE << 256u32).rem_vartime(&modulus);
        let inverse_r = r.invert_odd_mod(&Odd::new(P).unwrap()).unwrap();
        let field_inverse_r = Option::<Field64>::from(field(r).invert()).unwrap();
        assert_eq!(
            field_bytes(field_inverse_r).as_slice(),
            inverse_r.to_be_bytes().as_ref()
        );
        assert_eq!(Self::product_mod(r, inverse_r, &modulus), Big::ONE);
        Self {
            modulus,
            inverse_r,
            field_inverse_r,
        }
    }

    fn product_mod(a: Big, b: Big, modulus: &NonZero<Big>) -> Big {
        let product = a.resize::<8>() * b.resize::<8>();
        product.rem_vartime(modulus)
    }

    fn check_pair(&self, a: Big, b: Big) {
        let (aa, bb) = (adapter(a), adapter(b));
        let add = (a.resize::<8>() + b.resize::<8>()).rem_vartime(&self.modulus);
        let sub = (a.resize::<8>() + P.resize::<8>() - b.resize::<8>()).rem_vartime(&self.modulus);
        assert_eq!(
            field_bytes(field(a) + field(b)).as_slice(),
            add.to_be_bytes().as_ref()
        );
        assert_eq!(
            field_bytes(field(a) - field(b)).as_slice(),
            sub.to_be_bytes().as_ref()
        );
        assert_eq!(big(candidate::add(&aa, &bb)), add, "candidate add");
        assert_eq!(big(candidate::sub(&aa, &bb)), sub, "candidate sub");
        let product: U512 = a.resize::<8>() * b.resize::<8>();
        let lo: Big = product.resize();
        let hi: Big = (product >> 256u32).resize();
        self.check_reduce(lo, hi);
        let sq: U512 = a.resize::<8>() * a.resize::<8>();
        self.check_reduce(sq.resize(), (sq >> 256u32).resize());
        let square_mod = sq.rem_vartime(&self.modulus);
        let square = Self::product_mod(square_mod, self.inverse_r, &self.modulus);
        assert_eq!(big(candidate::square(&aa)), square, "candidate square");
        self.check_reduce(a, Big::ZERO);
        let canonical = Self::product_mod(a, self.inverse_r, &self.modulus);
        assert_eq!(
            big(candidate::to_canonical(&aa)),
            canonical,
            "candidate canonical"
        );
    }

    fn check_reduce(&self, lo: Big, hi: Big) {
        assert!(hi < P, "REDC domain requires input below p*R");
        let reduced = (hi.resize::<8>() << 256u32 | lo.resize::<8>()).rem_vartime(&self.modulus);
        let expected = Self::product_mod(reduced, self.inverse_r, &self.modulus);
        let flo = field(lo.rem_vartime(&self.modulus));
        let expected_field = field(hi) + flo * self.field_inverse_r;
        assert_eq!(
            field_bytes(expected_field).as_slice(),
            expected.to_be_bytes().as_ref(),
            "independent REDC oracles"
        );
        assert_eq!(
            big(candidate::montgomery_reduce(&adapter(lo), &adapter(hi))),
            expected,
            "candidate REDC"
        );
    }
}

fn next_word(state: &mut u64) -> u32 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    (*state >> 17) as u32
}

fn next_big(state: &mut u64) -> Big {
    big(U256::new(core::array::from_fn(|_| Limb(next_word(state)))))
}

fn check_nine(l: [Limb; 9], r: [Limb; 9]) {
    let left = wide9(l);
    let right = wide9(r);
    let underflow = left < right;
    let difference = left.wrapping_sub(&right);
    let adjusted = if underflow {
        difference.wrapping_add(&P.resize::<8>())
    } else {
        difference
    };
    let expected_low: Big = adjusted.resize();
    let expected_mask = Limb(0u32.wrapping_sub(u32::from(underflow)));
    let changed = candidate::sub_inner(l, r);
    assert_eq!(changed.1, expected_mask, "candidate ninth-limb borrow");
    assert_eq!(
        big(U256::new(changed.0)),
        expected_low,
        "candidate add-back"
    );
}

#[test]
fn adapter_primitives_match_wide_integer_arithmetic() {
    let values = [0, 1, 2, 0x7fff_ffff, 0x8000_0000, u32::MAX - 1, u32::MAX];
    for a in values {
        for b in values {
            for c in values {
                let sum = a as u128 + b as u128 + c as u128;
                assert_eq!(
                    Limb(a).carrying_add(Limb(b), Limb(c)),
                    (Limb(sum as u32), Limb((sum >> 32) as u32))
                );
                let product = a as u128 * b as u128 + c as u128 + u32::MAX as u128;
                assert_eq!(
                    Limb(a).carrying_mul_add(Limb(b), Limb(c), Limb(u32::MAX)),
                    (Limb(product as u32), Limb((product >> 32) as u32))
                );
                let difference = a as i64 - b as i64 - (c >> 31) as i64;
                assert_eq!(
                    Limb(a).borrowing_sub(Limb(b), Limb(c)),
                    (
                        Limb(difference as u32),
                        Limb(0u32.wrapping_sub(u32::from(difference < 0)))
                    )
                );
            }
        }
    }
}

#[test]
fn nine_limb_borrow_every_start_and_stop() {
    let zero = [Limb::ZERO; 9];
    check_nine(zero, zero);
    check_nine(zero, [Limb(u32::MAX); 9]);
    check_nine([Limb(u32::MAX); 9], zero);
    for start in 0..9 {
        let mut rhs = zero;
        rhs[start] = Limb(1);
        check_nine(zero, rhs);
        for stop in start..9 {
            for word in [1, 2, 0x8000_0000, u32::MAX] {
                let mut lhs = zero;
                lhs[stop] = Limb(word);
                check_nine(lhs, rhs);
                check_nine(rhs, lhs);
            }
        }
    }
}

#[test]
fn nine_limb_dense_independent_512bit_oracle() {
    let mut state = 0x71f4_9923_0cde_6a57;
    for _ in 0..8192 {
        let l = core::array::from_fn(|_| Limb(next_word(&mut state)));
        let r = core::array::from_fn(|_| Limb(next_word(&mut state)));
        check_nine(l, r);
    }
}

#[test]
fn field_boundaries_match_two_independent_oracles() {
    let oracle = Oracle::new();
    let mut values = vec![
        Big::ZERO,
        Big::ONE,
        Big::from_u32(2),
        P - Big::ONE,
        P - Big::from_u32(2),
    ];
    for bit in [
        0u32, 1, 30, 31, 32, 33, 63, 64, 95, 96, 127, 128, 159, 160, 191, 192, 223, 224, 254, 255,
    ] {
        values.push(Big::ONE << bit);
    }
    for word in [0x5555_5555, 0xaaaa_aaaa, 0xffff_ffff] {
        values.push(big(U256::new([Limb(word); 8])).rem_vartime(&oracle.modulus));
    }
    for a in &values {
        for b in &values {
            oracle.check_pair(*a, *b);
        }
    }
    println!("field boundary pairs={}", values.len() * values.len());
}

#[test]
fn field_dense_match_two_independent_oracles() {
    let oracle = Oracle::new();
    let mut state = 0xb10f_3219_6a58_77d3;
    for _ in 0..2048 {
        let a = next_big(&mut state).rem_vartime(&oracle.modulus);
        let b = next_big(&mut state).rem_vartime(&oracle.modulus);
        oracle.check_pair(a, b);
    }
}

#[test]
fn redc_full_input_domain_and_high_carry() {
    let oracle = Oracle::new();
    for lo in [Big::ZERO, Big::ONE, Big::MAX] {
        for hi in [Big::ZERO, Big::ONE, P - Big::ONE] {
            oracle.check_reduce(lo, hi);
        }
    }
    for bit in 0u32..512 {
        let value = U512::ONE << bit;
        oracle.check_reduce(value.resize(), (value >> 256u32).resize());
    }
    let mut state = 0x996e_15db_e1f0_3387;
    for _ in 0..2048 {
        let lo = next_big(&mut state);
        let hi = next_big(&mut state).rem_vartime(&oracle.modulus);
        oracle.check_reduce(lo, hi);
    }
}
