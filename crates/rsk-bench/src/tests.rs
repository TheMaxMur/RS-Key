// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn warm_median_and_mad_over_a_known_run() {
    // cold = 10; warm = [12, 11, 13, 10] -> sorted [10,11,12,13], upper median 12,
    // min 10; deviations |x-12| = [0,1,1,2] -> median 1.
    let mut s = [10, 12, 11, 13, 10];
    let sum = summarize(&mut s, 1);
    assert_eq!(
        sum,
        Summary {
            n: 4,
            cold: 10,
            min: 10,
            median: 12,
            mad: 1
        }
    );
}

#[test]
fn constant_run_has_zero_spread() {
    let mut s = [5, 5, 5, 5];
    let sum = summarize(&mut s, 1);
    assert_eq!(sum.mad, 0);
    assert_eq!(sum.min, 5);
    assert_eq!(sum.median, 5);
    assert_eq!(sum.cold, 5);
    assert_eq!(sum.n, 3);
}

#[test]
fn warmup_zero_keeps_the_cold_sample_in_the_warm_set() {
    // warm = [3,1,2] -> sorted [1,2,3], median 2, min 1; devs [1,1,0] -> median 1.
    let mut s = [3, 1, 2];
    let sum = summarize(&mut s, 0);
    assert_eq!(sum.cold, 3);
    assert_eq!(sum.median, 2);
    assert_eq!(sum.min, 1);
    assert_eq!(sum.mad, 1);
    assert_eq!(sum.n, 3);
}

#[test]
fn empty_warm_range_collapses_onto_cold() {
    let mut s = [7];
    let sum = summarize(&mut s, 1);
    assert_eq!(
        sum,
        Summary {
            n: 0,
            cold: 7,
            min: 7,
            median: 7,
            mad: 0
        }
    );
    // warmup past the end is clamped, not a panic.
    let mut s2 = [7, 8, 9];
    assert_eq!(summarize(&mut s2, 99).n, 0);
}

#[test]
fn empty_input_does_not_panic() {
    let mut s: [u32; 0] = [];
    let sum = summarize(&mut s, 0);
    assert_eq!(sum.n, 0);
    assert_eq!(sum.cold, 0);
}

#[test]
fn a_single_cache_refill_outlier_moves_the_mean_but_not_the_median() {
    // 8 tight warm samples around 100 plus one 400 µs refill spike: the mean would
    // jump ~33 µs, the median barely moves — exactly why the harness reports median.
    let mut s = [999, 100, 101, 99, 100, 102, 98, 100, 400];
    let sum = summarize(&mut s, 1);
    assert_eq!(sum.median, 100);
    assert!(sum.mad <= 2, "mad should stay tight, got {}", sum.mad);
}

#[test]
fn summary_round_trips_through_le_bytes() {
    let sum = Summary {
        n: 63,
        cold: 152_000,
        min: 104_800,
        median: 106_000,
        mad: 300,
    };
    assert_eq!(Summary::from_le_bytes(&sum.to_le_bytes()), sum);
}
