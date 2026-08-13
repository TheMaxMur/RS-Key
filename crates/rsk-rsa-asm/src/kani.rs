// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// `mod_small` never panics and its result stays `< m`, for EVERY input up
/// to 8 bytes and every valid modulus — the property the sieve's indexing
/// and the `r + 2` headroom in `step` rely on. (The exact value it returns
/// is proven separately by `mod_small_matches_value`.)
#[kani::proof]
#[kani::unwind(10)]
fn mod_small_in_range() {
    const N: usize = 8;
    let bytes: [u8; N] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N);
    let m: u32 = kani::any();
    kani::assume(m != 0 && m < (1 << 23));
    assert!(mod_small(&bytes[..len], m) < m);
}

/// `mod_small` computes `n mod m` *exactly* — proven against the language's
/// own `%` for EVERY little-endian `n` up to [`FN_BYTES`] bytes and EVERY
/// valid modulus. Genuine functional coverage, not a range check.
///
/// The width is bounded by the solver, not by the type. A functional
/// equality between two division circuits — `mod_small`'s byte-wise Horner
/// reduction vs a single wide `%` — is exactly the shape resolution-based
/// SAT handles worst: 2 bytes discharge in ~100 s, and the cost climbs
/// steeply with each added byte (4 bytes, a full `u32` dividend, does not
/// converge — see the lesson in docs/testing.md). So this pins the Horner
/// step's modular arithmetic exhaustively at the widths CBMC can swallow,
/// where any indexing or carry bug already shows; the full 8-byte path is
/// held by `mod_small_in_range` (panic-free, `< m`) plus the 32-byte
/// BigUint differential in the unit tests. The dividend is bounded by
/// *length* — `n` stays `&[u8]`, `m` a full 23-bit `u32`, the arithmetic
/// `u64` — never by narrowing the function's own types.
#[kani::proof]
#[kani::unwind(10)]
fn mod_small_matches_value() {
    const FN_BYTES: usize = 2;
    let bytes: [u8; FN_BYTES] = kani::any();
    let m: u32 = kani::any();
    kani::assume(m != 0 && m < (1 << 23));
    let mut padded = [0u8; 8];
    padded[..FN_BYTES].copy_from_slice(&bytes);
    let value = u64::from_le_bytes(padded);
    assert_eq!(mod_small(&bytes, m) as u64, value % m as u64);
}

/// The incremental sieve's core invariant: after a `step`, every stored
/// residue still equals `cand mod pᵢ`, and the verdict is exactly "some
/// residue hit zero" — i.e. identical to re-deriving from scratch like
/// [`has_small_factor`] does. Proved for EVERY seed of a 2-byte window
/// (the carry/residue arithmetic is width-agnostic; wider windows are
/// covered by the `incremental_matches_flat` differential test).
///
/// Both residue clauses sit inside the `Some` arm *and* the residue loop, and
/// the verdict clause goes trivially true at `cnt == 0`, so a sieve that never
/// steps or tracks no primes passes all three — measured: with `step` stubbed to
/// `None` this harness still reported SUCCESSFUL. [`sieve_really_steps`] rules
/// that out, and only while this harness stays `assume`-free at the same `half`.
#[kani::proof]
#[kani::unwind(258)]
fn sieve_step_keeps_residues() {
    let seed: [u8; 2] = kani::any();
    let mut s = IncrementalSieve::new();
    s.reseed(2, &seed);
    if let Some(pass) = s.step() {
        let mut composite = false;
        for k in 0..s.cnt {
            let r = mod_small(&s.cand[..s.half], SMALL_PRIMES[k]);
            assert_eq!(s.res[k], r);
            composite |= r == 0;
        }
        assert_eq!(pass, !composite);
    }
}

/// Non-vacuity for [`sieve_step_keeps_residues`], asserted rather than covered.
/// A `kani::cover!` would be the idiomatic way to say this and it does not work:
/// on 0.67.0 an unsatisfiable cover prints "0 of 1 cover properties satisfied"
/// and the harness still reports SUCCESSFUL, so it is a note, not a guard
/// (`crates/rsk-device/src/presence_kani.rs` measured the same thing).
///
/// Concrete seed, so this is 143 s against its neighbour's ~24 min.
#[kani::proof]
// 256 residues at `half = 2` (`sieve_count`), +1 for the unwinding assertion.
#[kani::unwind(258)]
fn sieve_really_steps() {
    let mut s = IncrementalSieve::new();
    s.reseed(2, &[0x00, 0x00]);
    assert!(s.step().is_some(), "the window ended before the first step");
    assert!(s.cnt > 0, "no primes tracked: the residue loop is empty");
}
