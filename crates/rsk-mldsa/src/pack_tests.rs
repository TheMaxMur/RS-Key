// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::params::{D, ML_DSA_44, ML_DSA_65};
use crate::testutil::{Rng, rand_poly_range};

#[test]
fn unsigned_unpack_refuses_unused_bit_patterns_for_a_partial_width_range() {
    let b = 5;
    let valid = vec![0; 32 * bit_length(b)];
    assert_eq!(simple_bit_unpack(&valid, b).unwrap().0, [0; 256]);
    let invalid = vec![0xff; valid.len()];
    assert!(simple_bit_unpack(&invalid, b).is_err());
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "bit_pack input out of [-a,b]")]
fn signed_pack_refuses_a_coefficient_below_its_declared_range() {
    let mut poly = Poly::zero();
    poly.0[0] = -6;
    bit_pack(&poly, 5, 5, &mut vec![0; 32 * bit_length(10)]);
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "bit_pack input out of [-a,b]")]
fn signed_pack_refuses_a_coefficient_above_its_declared_range() {
    let mut poly = Poly::zero();
    poly.0[0] = 6;
    bit_pack(&poly, 5, 5, &mut vec![0; 32 * bit_length(10)]);
}

#[test]
fn bit_pack_roundtrip_s_vectors() {
    for p in [ML_DSA_44, ML_DSA_65] {
        let mut rng = Rng::new(p.eta as u64);
        let len = 32 * bit_length(2 * p.eta);
        for _ in 0..40 {
            let w = rand_poly_range(&mut rng, -p.eta, p.eta);
            let mut buf = vec![0u8; len];
            bit_pack(&w, p.eta, p.eta, &mut buf);
            assert_eq!(w.0, bit_unpack(&buf, p.eta, p.eta).unwrap().0);
        }
    }
}

#[test]
fn bit_pack_roundtrip_t0() {
    let top = 1 << (D - 1);
    let mut rng = Rng::new(13);
    let len = 32 * D as usize;
    for _ in 0..40 {
        let w = rand_poly_range(&mut rng, -(top - 1), top);
        let mut buf = vec![0u8; len];
        bit_pack(&w, top - 1, top, &mut buf);
        assert_eq!(w.0, bit_unpack(&buf, top - 1, top).unwrap().0);
    }
}

#[test]
fn simple_bit_pack_roundtrip_t1() {
    let b = (1 << 10) - 1;
    let mut rng = Rng::new(5);
    let len = 32 * bit_length(b);
    for _ in 0..40 {
        let w = rand_poly_range(&mut rng, 0, b);
        let mut buf = vec![0u8; len];
        simple_bit_pack(&w, b, &mut buf);
        assert_eq!(w.0, simple_bit_unpack(&buf, b).unwrap().0);
    }
}

#[test]
fn hint_pack_roundtrip() {
    const K: usize = 6;
    let omega = 55;
    let mut h = crate::poly::zero_vec::<K>();
    let mut rng = Rng::new(42);
    let mut total = 0;
    for row in h.iter_mut() {
        let mut pos = 0u32;
        for _ in 0..3 {
            pos += 1 + (rng.next_u32() % 40);
            if pos < 256 && total < omega {
                row.0[pos as usize] = 1;
                total += 1;
            }
        }
    }
    let mut buf = vec![0u8; omega as usize + K];
    hint_bit_pack::<K>(omega, &h, &mut buf);
    let back = hint_bit_unpack::<K>(omega, &buf).unwrap();
    for i in 0..K {
        assert_eq!(h[i].0, back[i].0);
    }
}

#[test]
fn hint_row_limits_cannot_go_backwards_or_exceed_the_capacity() {
    let mut buf = [0; 84];
    buf[80] = 1;
    assert!(hint_bit_unpack::<4>(80, &buf).is_err());
    buf[81] = 81;
    assert!(hint_bit_unpack::<4>(80, &buf).is_err());
    buf[80..].fill(1);
    assert!(hint_bit_unpack::<4>(80, &buf).is_ok());
}

#[test]
fn hint_unpack_rejects_nonzero_padding() {
    const K: usize = 4;
    let omega = 80;
    let mut buf = vec![0u8; omega as usize + K];
    // All per-row counts (last K bytes) are zero, so Index never advances; a
    // stray nonzero in the first-ω region must be rejected as malformed.
    buf[0] = 5;
    assert!(hint_bit_unpack::<K>(omega, &buf).is_err());
}

#[test]
fn hint_unpack_rejects_overlarge_count() {
    const K: usize = 4;
    let omega = 80;
    let mut buf = vec![0u8; omega as usize + K];
    buf[omega as usize] = (omega + 1) as u8; // row-0 count > omega
    assert!(hint_bit_unpack::<K>(omega, &buf).is_err());
}

#[test]
fn signed_unpack_reads_the_entire_encoded_range_without_clamping() {
    for (a, b, bits) in [(2, 2, 3), (4, 4, 4), (4095, 4096, 13)] {
        for byte in [0, 1, 0x55, 0xaa, 0xff] {
            let encoded = vec![byte; 32 * bits];
            let decoded = bit_unpack(&encoded, a, b).unwrap();
            for i in 0..crate::params::N {
                let raw: i32 = (0..bits)
                    .map(|bit| {
                        let position = i * bits + bit;
                        i32::from((encoded[position / 8] >> (position % 8)) & 1) << bit
                    })
                    .sum();
                assert_eq!(
                    decoded.0[i],
                    b - raw,
                    "a={a} b={b} byte={byte} coefficient={i}"
                );
            }
        }
    }
}

#[test]
fn hint_positions_must_increase_strictly_within_each_row() {
    for positions in [[7, 7], [8, 7]] {
        let mut encoded = [0; 84];
        encoded[..2].copy_from_slice(&positions);
        encoded[80..].fill(2);
        assert!(
            hint_bit_unpack::<4>(80, &encoded).is_err(),
            "accepted {positions:?}"
        );
    }
    let mut encoded = [0; 84];
    encoded[..2].copy_from_slice(&[7, 8]);
    encoded[80..].fill(2);
    let decoded = hint_bit_unpack::<4>(80, &encoded).unwrap();
    assert_eq!(decoded[0].0[7], 1);
    assert_eq!(decoded[0].0[8], 1);
    assert_eq!(decoded[0].0.iter().sum::<i32>(), 2);
}
