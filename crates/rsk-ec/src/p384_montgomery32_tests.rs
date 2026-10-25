// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::p384_montgomery32::multiply;
use p384::elliptic_curve::bigint::{Encoding, U384, const_monty_params, modular::ConstMontyForm};

const MODULUS_HEX: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff";
const MODULUS: U384 = U384::from_be_hex(MODULUS_HEX);
const_monty_params!(FieldModulus, U384, MODULUS_HEX);
type Monty = ConstMontyForm<FieldModulus, { U384::LIMBS }>;

fn words(value: U384) -> [u32; 12] {
    let mut out = [0; 12];
    for (word, bytes) in out.iter_mut().zip(value.to_le_bytes().as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*bytes);
    }
    out
}

fn product(x: U384, y: U384) -> U384 {
    let mut bytes = [0; 48];
    for (bytes, word) in bytes
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip(multiply(words(x), words(y)))
    {
        *bytes = word.to_le_bytes();
    }
    let actual = U384::from_le_bytes(bytes.into());
    let expected = Monty::from_montgomery(x).mul(&Monty::from_montgomery(y));
    assert_eq!(
        actual,
        *expected.as_montgomery(),
        "incorrect Montgomery product"
    );
    assert!(actual < MODULUS, "non-canonical Montgomery product");
    actual
}

#[test]
fn p384_u32_products_match_independent_host_word_arithmetic() {
    let one = U384::ONE;
    let last = MODULUS.wrapping_sub(&one);
    let boundaries = [
        U384::ZERO,
        one,
        U384::from(2u32),
        U384::from(u32::MAX),
        one.shl_vartime(32),
        one.shl_vartime(96).wrapping_sub(&one),
        one.shl_vartime(128),
        one.shl_vartime(383),
        last.wrapping_sub(&one),
        last,
    ];
    for x in boundaries {
        for y in boundaries {
            product(x, y);
        }
    }
    for bit in 0..384 {
        let x = one.shl_vartime(bit);
        product(x, x);
        product(x, last);
        product(last.wrapping_sub(&x), x);
    }
    let mut state = 0x78af_62d1_04ec_539bu64;
    for _ in 0..1024 {
        let mut values = [U384::ZERO; 2];
        for value in &mut values {
            let mut bytes = [0; 48];
            for chunk in bytes.as_chunks_mut::<8>().0 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *chunk = state.to_le_bytes();
            }
            *value = U384::from_le_bytes(bytes.into());
            if *value >= MODULUS {
                *value = value.wrapping_sub(&MODULUS);
            }
        }
        product(values[0], values[1]);
    }
}

#[test]
fn p384_u32_subtracts_modulus_without_a_high_carry() {
    // For c=R-p, (2c)((p+1)/2) reduces first to p+1, with no R carry.
    let c = U384::ZERO.wrapping_sub(&MODULUS);
    assert_eq!(
        product(
            c.wrapping_add(&c),
            MODULUS.wrapping_add(&U384::ONE).shr_vartime(1)
        ),
        U384::ONE,
    );
}

#[test]
fn p384_u32_preserves_the_high_carry_before_subtraction() {
    let last = MODULUS.wrapping_sub(&U384::ONE);
    product(last, last);
}

#[test]
fn p384_u32_squares_match_independent_host_word_arithmetic() {
    use super::p384_montgomery32::square;

    let check = |value: U384| {
        let mut bytes = [0; 48];
        for (bytes, word) in bytes
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(square(words(value)))
        {
            *bytes = word.to_le_bytes();
        }
        let actual = U384::from_le_bytes(bytes.into());
        let expected = Monty::from_montgomery(value).square();
        assert_eq!(
            actual,
            *expected.as_montgomery(),
            "incorrect Montgomery square"
        );
        assert!(actual < MODULUS, "non-canonical Montgomery square");
    };
    for value in [
        U384::ZERO,
        U384::ONE,
        U384::from(2u32),
        MODULUS.wrapping_sub(&U384::ONE),
    ] {
        check(value);
    }
    for bit in 0..384 {
        let value = U384::ONE.shl_vartime(bit);
        check(value);
        check(value.wrapping_sub(&U384::ONE));
        check(MODULUS.wrapping_sub(&value));
    }
    let mut state = 0x1ec9_a540_38d6_72bfu64;
    for _ in 0..1024 {
        let mut bytes = [0; 48];
        for chunk in bytes.as_chunks_mut::<8>().0 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *chunk = state.to_le_bytes();
        }
        let mut value = U384::from_le_bytes(bytes.into());
        if value >= MODULUS {
            value = value.wrapping_sub(&MODULUS);
        }
        check(value);
    }
}
