// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Check the shared fixed-width subtraction with an independent addition oracle.

use elliptic_curve::bigint::{Limb, Uint, Word};

const MSB: Word = 1 << (Word::BITS - 1);
const BOUNDARIES: [Word; 7] = [0, 1, MSB - 1, MSB, MSB + 1, Word::MAX - 1, Word::MAX];

fn check<const N: usize>(lhs: [Word; N], rhs: [Word; N], incoming: Word) {
    let a = Uint::new(lhs.map(Limb));
    let b = Uint::new(rhs.map(Limb));
    let (actual, borrow) = a.borrowing_sub(&b, Limb(incoming));
    let mut expected = [Limb::ZERO; N];
    let mut carry = u128::from((incoming >> (Word::BITS - 1)) ^ 1);
    for ((out, left), right) in expected.iter_mut().zip(lhs).zip(rhs) {
        let sum = u128::from(left) + u128::from(!right) + carry;
        *out = Limb(Word::try_from(sum & u128::from(Word::MAX)).unwrap());
        carry = sum >> Word::BITS;
    }
    let expected_borrow = if N == 0 {
        incoming
    } else if carry == 0 {
        Word::MAX
    } else {
        0
    };
    assert_eq!(
        actual.as_limbs(),
        &expected,
        "subtraction words, N={N}, incoming={incoming:x}"
    );
    assert_eq!(
        borrow.0, expected_borrow,
        "final borrow mask, N={N}, incoming={incoming:x}"
    );
}

#[test]
fn requested_word_width_is_exercised() {
    let expected = option_env!("RSK_TEST_WORD_BITS")
        .map(|bits| bits.parse::<u32>().unwrap())
        .unwrap_or(usize::BITS);
    assert_eq!(Word::BITS, expected);
    assert_eq!(u32::try_from(size_of::<Limb>() * 8).unwrap(), expected);
}

#[test]
fn zero_width_preserves_arbitrary_incoming_borrow() {
    for incoming in BOUNDARIES {
        check::<0>([], [], incoming);
    }
}

#[test]
fn boundary_words_interpret_only_the_incoming_msb() {
    for left in BOUNDARIES {
        for right in BOUNDARIES {
            for incoming in BOUNDARIES {
                check([left], [right], incoming);
                check([left, right], [right, left], incoming);
            }
        }
    }
}

fn chains<const N: usize>() {
    for incoming in BOUNDARIES {
        check([0; N], [0; N], incoming);
        check([Word::MAX; N], [Word::MAX; N], incoming);
        check([0; N], [Word::MAX; N], incoming);
        check([Word::MAX; N], [0; N], incoming);
        for pivot in 0..N {
            let mut one = [0; N];
            one[pivot] = 1;
            check([0; N], one, incoming);
            check(one, [0; N], incoming);
            let mut top = [0; N];
            top[N - 1] = 1;
            check(top, one, incoming);
        }
    }
}

#[test]
fn borrow_propagates_across_every_limb() {
    chains::<2>();
    chains::<4>();
    chains::<6>();
    chains::<8>();
    chains::<12>();
    chains::<17>();
    chains::<32>();
}

fn dense<const N: usize>() {
    let mut state = 0x243f_6a88_85a3_08d3_u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        Word::try_from(u128::from(state) & u128::from(Word::MAX)).unwrap()
    };
    for _ in 0..2048 {
        let lhs = core::array::from_fn(|_| next());
        let rhs = core::array::from_fn(|_| next());
        check::<N>(lhs, rhs, next());
    }
}

#[test]
fn dense_multiwidth_subtraction_matches_addition_oracle() {
    dense::<1>();
    dense::<2>();
    dense::<4>();
    dense::<6>();
    dense::<8>();
    dense::<12>();
    dense::<17>();
    dense::<32>();
}

#[test]
fn borrowing_sub_remains_const_evaluable() {
    const EMPTY: (Uint<0>, Limb) = Uint::new([]).borrowing_sub(&Uint::new([]), Limb(1));
    const CHAIN: (Uint<2>, Limb) =
        Uint::new([Limb::ZERO; 2]).borrowing_sub(&Uint::new([Limb(1), Limb::ZERO]), Limb::ZERO);
    const NON_MASK: (Uint<1>, Limb) =
        Uint::new([Limb(1)]).borrowing_sub(&Uint::new([Limb::ZERO]), Limb(MSB + 1));
    const P521_CHAIN: (Uint<17>, Limb) = {
        let mut one = [Limb::ZERO; 17];
        one[0] = Limb(1);
        Uint::new([Limb::ZERO; 17]).borrowing_sub(&Uint::new(one), Limb::ZERO)
    };
    assert_eq!(P521_CHAIN.0.as_limbs(), &[Limb::MAX; 17]);
    assert_eq!(P521_CHAIN.1, Limb::MAX);
    assert_eq!(EMPTY.1, Limb(1));
    assert_eq!(CHAIN.0.as_limbs(), &[Limb::MAX; 2]);
    assert_eq!(CHAIN.1, Limb::MAX);
    assert_eq!(NON_MASK.0.as_limbs(), &[Limb::ZERO]);
    assert_eq!(NON_MASK.1, Limb::ZERO);
}
