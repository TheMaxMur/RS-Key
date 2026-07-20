// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// `summarize` never panics for any samples/warmup, and its warm statistics obey
/// the ordering invariants a downstream A/B comparison relies on: `min` is the
/// true warm minimum, the median sits inside `[min, max]`, and the MAD cannot
/// exceed the warm span. Also pins the `cold`/`n` contract.
#[kani::proof]
fn summarize_holds_its_invariants() {
    const N: usize = 4;
    let mut s: [u32; N] = kani::any();
    let warmup: usize = kani::any();
    kani::assume(warmup <= N);

    // Reference bounds over the warm range, computed before `summarize` reorders it.
    let s0 = s[0];
    let w = warmup; // already <= N
    let mut mn = u32::MAX;
    let mut mx = 0u32;
    for &x in &s[w..] {
        if x < mn {
            mn = x;
        }
        if x > mx {
            mx = x;
        }
    }
    let warm_len = (N - w) as u32;

    let sum = summarize(&mut s, warmup);

    assert!(sum.cold == s0);
    assert!(sum.n == warm_len);
    if warm_len > 0 {
        assert!(sum.min == mn);
        assert!(sum.median >= mn && sum.median <= mx);
        // mx >= mn over a non-empty set, so the subtraction cannot underflow.
        assert!(sum.mad <= mx - mn);
    }
}
