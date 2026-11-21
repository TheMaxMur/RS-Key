// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn at(cycle: u64) -> MmioCtx<'static> {
    let mut ctx = MmioCtx::default();
    ctx.cycle = cycle;
    ctx
}

/// Enable the source at cycle 0 and read the first block once it is valid.
fn first_block(seed: &[u8]) -> Vec<u32> {
    let mut t = Trng::new(seed);
    t.write(RND_SOURCE_ENABLE, 1, 4, 0, &mut at(0));
    let done = t.sample_cycles();
    assert_eq!(
        t.read(TRNG_VALID, 4, &mut at(done - 1)),
        0,
        "still sampling"
    );
    assert_eq!(t.read(TRNG_VALID, 4, &mut at(done)), 1);
    (0..6)
        .map(|i| t.read(EHR_DATA0 + 4 * i, 4, &mut at(done)))
        .collect()
}

#[test]
fn a_block_takes_its_sampling_time_and_reading_data5_starts_the_next() {
    let mut t = Trng::new(b"s");
    t.write(RND_SOURCE_ENABLE, 1, 4, 0, &mut at(0));
    let done = t.sample_cycles();
    assert_eq!(
        t.read(RNG_ISR, 4, &mut at(done)) & ISR_EHR_VALID,
        ISR_EHR_VALID
    );
    let first = t.read(EHR_DATA5, 4, &mut at(done));
    assert_eq!(t.read(TRNG_VALID, 4, &mut at(done)), 0, "consumed");
    assert_eq!(
        t.read(TRNG_BUSY, 4, &mut at(done)),
        1,
        "the next block is sampling"
    );
    assert_eq!(t.read(TRNG_VALID, 4, &mut at(2 * done)), 1);
    assert_ne!(t.read(EHR_DATA5, 4, &mut at(2 * done)), first);
}

#[test]
fn the_bits_follow_the_seed() {
    assert_eq!(first_block(b"seed"), first_block(b"seed"));
    assert_ne!(first_block(b"seed"), first_block(b"other"));
}

#[test]
fn successive_boots_use_distinct_reproducible_entropy_streams() {
    let second = next_boot_seed(b"seed");
    let third = next_boot_seed(&second);
    assert_eq!(second, next_boot_seed(b"seed"));
    assert_eq!(third, next_boot_seed(&next_boot_seed(b"seed")));
    assert_ne!(first_block(b"seed"), first_block(&second));
    assert_ne!(first_block(&second), first_block(&third));
    assert_ne!(first_block(&next_boot_seed(b"other")), first_block(&second));
}

#[test]
fn a_disabled_source_samples_nothing() {
    let mut t = Trng::new(b"s");
    assert_eq!(t.read(TRNG_VALID, 4, &mut at(1_000_000)), 0);
    assert_eq!(t.read(EHR_DATA0, 4, &mut at(1_000_000)), 0);
}
