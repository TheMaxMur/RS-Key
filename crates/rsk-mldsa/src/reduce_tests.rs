// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn full_reduce_is_canonical() {
    assert_eq!(full_reduce32(0), 0);
    assert_eq!(full_reduce32(Q), 0);
    assert_eq!(full_reduce32(-1), Q - 1);
    assert_eq!(full_reduce32(Q + 5), 5);
    assert_eq!(full_reduce32(2 * Q - 1), Q - 1);
    for a in [-8_000_000i32, -1, 1, 12_345, 8_000_000, 2_143_289_343] {
        let r = full_reduce32(a);
        assert!((0..Q).contains(&r), "full_reduce32({a}) = {r} out of [0,q)");
        assert_eq!(r, a.rem_euclid(Q));
    }
}

#[test]
fn partial_reduce32_bounds() {
    for a in [-2_000_000_000i32, -1, 0, 1, 8_380_416, 2_143_289_343] {
        let r = partial_reduce32(a);
        assert!(
            r.unsigned_abs() < Q as u32,
            "partial_reduce32({a}) = {r} not in (−q,q)"
        );
        assert_eq!(r.rem_euclid(Q), a.rem_euclid(Q));
    }
}

#[test]
fn center_mod_in_symmetric_range() {
    for a in [0i32, 1, Q / 2, Q / 2 + 1, Q - 1, -1, 5_000_000, -5_000_000] {
        let c = center_mod(a);
        assert!(
            c > -(Q / 2) - 1 && c <= Q / 2,
            "center_mod({a}) = {c} out of range"
        );
        assert_eq!(c.rem_euclid(Q), a.rem_euclid(Q));
    }
}

#[test]
fn to_mont_then_mont_reduce_is_identity() {
    // to_mont lifts x → x·2^32; a single mont_reduce brings it back to x mod q.
    let mut p = Poly::zero();
    p.0[0] = 12_345;
    p.0[1] = -6_789;
    p.0[2] = Q - 1;
    p.0[3] = 1;
    let m = to_mont(&p);
    for n in 0..4 {
        let back = mont_reduce(i64::from(m.0[n]));
        assert_eq!(
            full_reduce32(back),
            full_reduce32(p.0[n]),
            "mont roundtrip coeff {n}"
        );
    }
}

#[test]
fn to_mont_inplace_is_to_mont() {
    let mut p = Poly::zero();
    for n in 0..crate::params::N {
        // Inputs across (−q, q); the body is `to_mont`'s, expression for expression.
        p.0[n] = match n % 4 {
            0 => (n as i32) * 32_749,
            1 => crate::params::Q - 1 - n as i32,
            2 => -(n as i32) * 12_345,
            _ => (n as i32) << 13,
        };
    }
    let want = to_mont(&p);
    to_mont_inplace(&mut p);
    assert_eq!(p.0, want.0);
}
