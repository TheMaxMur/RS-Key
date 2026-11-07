// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::Rng;
use crate::fixtures::{P_HEX, Q_HEX, SeqRng, hex};
use num_bigint_dig::prime::probably_prime_lucas;

pub(super) fn observe_residues(vk: &BigUint, vk1: &BigUint, modulus: &BigUint) {
    assert!(
        vk < modulus && vk1 < modulus,
        "Lucas state left the canonical residue range"
    );
}

fn uncancelled(n: &BigUint) -> bool {
    let mut polls = 0;
    passes_lucas(n, &mut || {
        polls += 1;
        assert!(
            polls <= n.bits() + 64,
            "Lucas search stopped making progress"
        );
        false
    })
}

#[test]
fn small_odd_inputs_match_the_library_and_independent_trial_division() {
    for n in (3u64..16_384).step_by(2) {
        let number = BigUint::from(n);
        let accepted = uncancelled(&number);
        assert_eq!(accepted, probably_prime_lucas(&number), "n={n}");
        let prime = (3..)
            .step_by(2)
            .take_while(|d| d * d <= n)
            .all(|d| n % d != 0);
        if prime {
            assert!(accepted, "prime {n} was refused");
        }
    }
    for n in [0u8, 1, 2, 4, 16] {
        assert!(!uncancelled(&BigUint::from(n)));
    }
}

#[test]
fn full_width_sequences_and_squares_match_the_library() {
    let mut rng = SeqRng(42);
    for bytes in [32, 64, 128, 192, 256] {
        let mut input = [0u8; 256];
        for _ in 0..8 {
            rng.fill(&mut input[..bytes]);
            input[0] |= 1;
            input[bytes - 1] |= 0xc0;
            let n = BigUint::from_bytes_le(&input[..bytes]);
            assert_eq!(uncancelled(&n), probably_prime_lucas(&n));
        }
    }
    for vector in [P_HEX, Q_HEX] {
        let prime = BigUint::from_bytes_be(&hex(vector));
        assert!(uncancelled(&prime));
        let square = &prime * &prime;
        assert!(!uncancelled(&square));
    }
}

#[test]
fn pseudoprimes_keep_the_two_baillie_psw_halves_distinct() {
    use num_bigint_dig::prime::{probably_prime, probably_prime_miller_rabin};

    // Go math/big's extra-strong Lucas pseudoprimes (prime_test.go).
    for n in [
        989u64, 3239, 5777, 10877, 27971, 29681, 30739, 31631, 39059, 72389, 73919, 75077,
    ] {
        let number = BigUint::from(n);
        assert!(uncancelled(&number));
        assert!(!probably_prime(&number, 0));
    }
    for n in [
        2047u64, 3277, 4033, 4681, 8321, 15841, 29341, 42799, 49141, 52633, 65281, 74665,
    ] {
        let number = BigUint::from(n);
        assert!(probably_prime_miller_rabin(&number, 1, true));
        assert!(!uncancelled(&number));
    }
    for n in [
        3673744903u64,
        3281593591,
        2385076987,
        2738053141,
        2009621503,
        1502682721,
        255866131,
        117987841,
        587861,
        6368689,
        8725753,
        80579735209,
        105919633,
    ] {
        let number = BigUint::from(n);
        assert_eq!(uncancelled(&number), probably_prime_lucas(&number));
        assert!(!probably_prime(&number, 0));
    }
}

#[test]
fn a_large_square_does_not_exhaust_the_parameter_search() {
    let prime = BigUint::from_bytes_be(&hex(P_HEX));
    let square = &prime * &prime;
    let mut polls = 0;
    assert!(!passes_lucas(&square, &mut || {
        polls += 1;
        assert!(
            polls <= 40,
            "square detection fell back to the parameter limit"
        );
        false
    }));
}

#[test]
fn every_lucas_progress_boundary_refuses_a_cancelled_prime() {
    for prime in [
        BigUint::from_bytes_be(&hex(P_HEX)),
        (BigUint::from(1u8) << 521usize) - BigUint::from(1u8),
        BigUint::from(7u8),
    ] {
        let mut total = 0;
        assert!(passes_lucas(&prime, &mut || {
            total += 1;
            false
        }));
        assert!(total > 1, "control did not enter the Lucas sequence");
        for cancel_at in 1..=total {
            let mut polls = 0;
            assert!(
                !passes_lucas(&prime, &mut || {
                    polls += 1;
                    polls >= cancel_at
                }),
                "cancel at {cancel_at} accepted a prime"
            );
            assert_eq!(polls, cancel_at, "work continued after cancellation");
        }
    }
}
