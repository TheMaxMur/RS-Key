// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

const MODULUS: [u32; 12] = [
    0xffff_ffff,
    0,
    0,
    0xffff_ffff,
    0xffff_fffe,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
];

// Canonical inputs x,y<p give T<2p, so one final subtraction suffices.
// CIOS keeps each MAC below 2^64; p[0] = -1 gives n0' = 1.
pub(super) const fn multiply(x: [u32; 12], y: [u32; 12]) -> [u32; 12] {
    let mut out = [0u32; 12];
    let mut meta = 0u64;
    let mut i = 0;
    while i < 12 {
        let xi = x[i] as u64;
        let mut carry = 0u64;
        macro_rules! product {
            ($j:literal) => {{
                let sum = xi * y[$j] as u64 + out[$j] as u64 + carry;
                out[$j] = sum as u32;
                carry = sum >> 32;
            }};
        }
        product!(0);
        product!(1);
        product!(2);
        product!(3);
        product!(4);
        product!(5);
        product!(6);
        product!(7);
        product!(8);
        product!(9);
        product!(10);
        product!(11);
        let top = meta + carry;
        let u = out[0] as u64;
        carry = u;
        macro_rules! reduction {
            ($j:literal) => {{
                let sum = u * MODULUS[$j] as u64 + out[$j] as u64 + carry;
                out[$j - 1] = sum as u32;
                carry = sum >> 32;
            }};
        }
        reduction!(1);
        reduction!(2);
        reduction!(3);
        reduction!(4);
        reduction!(5);
        reduction!(6);
        reduction!(7);
        reduction!(8);
        reduction!(9);
        reduction!(10);
        reduction!(11);
        let top = top + carry;
        out[11] = top as u32;
        meta = top >> 32;
        i += 1;
    }
    let mut reduced = [0u32; 12];
    let mut borrow = 0u64;
    let mut i = 0;
    while i < 12 {
        let difference = (out[i] as u64).wrapping_sub(MODULUS[i] as u64 + borrow);
        reduced[i] = difference as u32;
        borrow = difference >> 63;
        i += 1;
    }
    let mask = 0u32.wrapping_sub(meta as u32 | (borrow as u32 ^ 1));
    let mut i = 0;
    while i < 12 {
        out[i] ^= (out[i] ^ reduced[i]) & mask;
        i += 1;
    }
    out
}

// Symmetry leaves 66 cross products and 12 diagonal products.
pub(super) const fn square(x: [u32; 12]) -> [u32; 12] {
    let mut product = [0u32; 24];
    macro_rules! cross_row {
        ($i:literal; $($j:literal),+) => {{
            let mut carry = 0u64;
            $(
                let sum = x[$i] as u64 * x[$j] as u64
                    + product[$i + $j] as u64 + carry;
                product[$i + $j] = sum as u32;
                carry = sum >> 32;
            )+
            product[2 * $i] = carry as u32;
        }};
    }
    cross_row!(1; 0);
    cross_row!(2; 0, 1);
    cross_row!(3; 0, 1, 2);
    cross_row!(4; 0, 1, 2, 3);
    cross_row!(5; 0, 1, 2, 3, 4);
    cross_row!(6; 0, 1, 2, 3, 4, 5);
    cross_row!(7; 0, 1, 2, 3, 4, 5, 6);
    cross_row!(8; 0, 1, 2, 3, 4, 5, 6, 7);
    cross_row!(9; 0, 1, 2, 3, 4, 5, 6, 7, 8);
    cross_row!(10; 0, 1, 2, 3, 4, 5, 6, 7, 8, 9);
    cross_row!(11; 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10);

    let mut carry = 0u32;
    let mut i = 0;
    while i < 23 {
        let next = product[i] >> 31;
        product[i] = (product[i] << 1) | carry;
        carry = next;
        i += 1;
    }
    product[23] = carry;
    let mut carry = 0u64;
    let mut i = 0;
    while i < 12 {
        let sum = x[i] as u64 * x[i] as u64 + product[2 * i] as u64 + carry;
        product[2 * i] = sum as u32;
        let sum = product[2 * i + 1] as u64 + (sum >> 32);
        product[2 * i + 1] = sum as u32;
        carry = sum >> 32;
        i += 1;
    }

    // The previous high carry belongs to the next iteration's top word.
    // Each reduction MAC fits u64; x²<p² leaves the result below 2p.
    let mut meta = 0u64;
    let mut i = 0;
    while i < 12 {
        let u = product[i] as u64;
        let mut carry = u;
        macro_rules! reduction {
            ($j:literal) => {{
                let sum = u * MODULUS[$j] as u64 + product[i + $j] as u64 + carry;
                product[i + $j] = sum as u32;
                carry = sum >> 32;
            }};
        }
        reduction!(1);
        reduction!(2);
        reduction!(3);
        reduction!(4);
        reduction!(5);
        reduction!(6);
        reduction!(7);
        reduction!(8);
        reduction!(9);
        reduction!(10);
        reduction!(11);
        let top = product[i + 12] as u64 + carry + meta;
        product[i + 12] = top as u32;
        meta = top >> 32;
        i += 1;
    }
    let mut reduced = [0u32; 12];
    let mut borrow = 0u64;
    let mut i = 0;
    while i < 12 {
        let difference = (product[i + 12] as u64).wrapping_sub(MODULUS[i] as u64 + borrow);
        reduced[i] = difference as u32;
        borrow = difference >> 63;
        i += 1;
    }
    let mask = 0u32.wrapping_sub(meta as u32 | (borrow as u32 ^ 1));
    let mut out = [0u32; 12];
    let mut i = 0;
    while i < 12 {
        out[i] = product[i + 12] ^ ((product[i + 12] ^ reduced[i]) & mask);
        i += 1;
    }
    out
}
