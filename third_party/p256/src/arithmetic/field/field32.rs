//! 32-bit secp256r1 field element algorithms.

use elliptic_curve::bigint::{
    Limb, U256,
    ctutils::{Choice, primitives::borrowing_sub_u32},
    modular::ConstMontyParams,
};

const MODULUS: &[Limb; 8] = super::FieldParams::PARAMS.modulus().as_ref().as_limbs();

pub(super) const fn add(a: &U256, b: &U256) -> U256 {
    let a = a.as_limbs();
    let b = b.as_limbs();

    // Bit 256 of p is set, so addition can result in nine words.
    // let (w0, carry) = carrying_add(a[0], b[0], 0);
    let (w0, carry) = a[0].carrying_add(b[0], Limb::ZERO);
    let (w1, carry) = a[1].carrying_add(b[1], carry);
    let (w2, carry) = a[2].carrying_add(b[2], carry);
    let (w3, carry) = a[3].carrying_add(b[3], carry);
    let (w4, carry) = a[4].carrying_add(b[4], carry);
    let (w5, carry) = a[5].carrying_add(b[5], carry);
    let (w6, carry) = a[6].carrying_add(b[6], carry);
    let (w7, w8) = a[7].carrying_add(b[7], carry);

    // Attempt to subtract the modulus, to ensure the result is in the field.
    let (result, _) = sub_inner(
        [w0, w1, w2, w3, w4, w5, w6, w7, w8],
        [
            MODULUS[0],
            MODULUS[1],
            MODULUS[2],
            MODULUS[3],
            MODULUS[4],
            MODULUS[5],
            MODULUS[6],
            MODULUS[7],
            Limb::ZERO,
        ],
    );

    U256::new([
        result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7],
    ])
}

pub(super) const fn sub(a: &U256, b: &U256) -> U256 {
    let a = a.as_limbs();
    let b = b.as_limbs();

    let (result, _) = sub_inner(
        [a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], Limb::ZERO],
        [b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], Limb::ZERO],
    );

    U256::new([
        result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7],
    ])
}

// Fixed indices avoid the generic square kernel's low/high split per product.
#[inline(always)]
pub(super) const fn square(a: &U256) -> U256 {
    let a = a.as_limbs();
    let mut product = [Limb::ZERO; 16];
    macro_rules! cross_row {
        ($i:literal; $($j:literal),+) => {{
            let mut carry = Limb::ZERO;
            $(
                (product[$i + $j], carry) =
                    a[$i].carrying_mul_add(a[$j], product[$i + $j], carry);
            )+
            product[2 * $i] = carry;
        }};
    }
    cross_row!(1; 0);
    cross_row!(2; 0, 1);
    cross_row!(3; 0, 1, 2);
    cross_row!(4; 0, 1, 2, 3);
    cross_row!(5; 0, 1, 2, 3, 4);
    cross_row!(6; 0, 1, 2, 3, 4, 5);
    cross_row!(7; 0, 1, 2, 3, 4, 5, 6);

    let mut carry = Limb::ZERO;
    let mut i = 0;
    while i < product.len() - 1 {
        let next = Limb(product[i].0 >> (u32::BITS - 1));
        product[i] = Limb((product[i].0 << 1) | carry.0);
        carry = next;
        i += 1;
    }
    product[product.len() - 1] = carry;

    let mut carry = Limb::ZERO;
    let mut i = 0;
    while i < a.len() {
        (product[2 * i], carry) = a[i].carrying_mul_add(a[i], product[2 * i], carry);
        (product[2 * i + 1], carry) = product[2 * i + 1].carrying_add(carry, Limb::ZERO);
        i += 1;
    }
    let lo = U256::new([
        product[0], product[1], product[2], product[3], product[4], product[5], product[6],
        product[7],
    ]);
    let hi = U256::new([
        product[8],
        product[9],
        product[10],
        product[11],
        product[12],
        product[13],
        product[14],
        product[15],
    ]);
    montgomery_reduce(&lo, &hi)
}

#[inline]
pub(super) const fn to_canonical(a: &U256) -> U256 {
    montgomery_reduce(a, &U256::ZERO)
}

/// Montgomery Reduction
///
/// The general algorithm is:
/// ```text
/// A <- input (2n b-limbs)
/// for i in 0..n {
///     k <- A[i] p' mod b
///     A <- A + k p b^i
/// }
/// A <- A / b^n
/// if A >= p {
///     A <- A - p
/// }
/// ```
///
/// For secp256r1, with a 32-bit arithmetic, we have the following
/// simplifications:
///
/// - `p'` is 1, so our multiplicand is simply the first limb of the intermediate A.
///
/// - The first limb of p is 2^32 - 1; multiplications by this limb can be simplified
///   to a shift and subtraction:
///   ```text
///       a_i * (2^32 - 1) = a_i * 2^32 - a_i = (a_i << 32) - a_i
///   ```
///   However, because `p' = 1`, the first limb of p is multiplied by limb i of the
///   intermediate A and then immediately added to that same limb, so we simply
///   initialize the carry to limb i of the intermediate.
///
///   The same applies for the second and third limb.
///
/// - The fourth limb of p is zero, so we can ignore any multiplications by it and just
///   add the carry.
///
///   The same applies for the fifth and sixth limb.
///
/// - The seventh limb of p is one, so we can substitute a `mac` operation with a `carrying_add` one.
///
/// References:
/// - Handbook of Applied Cryptography, Chapter 14
///   Algorithm 14.32
///   http://cacr.uwaterloo.ca/hac/about/chap14.pdf
///
/// - Efficient and Secure Elliptic Curve Cryptography Implementation of Curve P-256
///   Algorithm 7) Montgomery Word-by-Word Reduction
///   https://csrc.nist.gov/csrc/media/events/workshop-on-elliptic-curve-cryptography-standards/documents/papers/session6-adalier-mehmet.pdf
#[inline]
#[allow(clippy::too_many_arguments)]
pub(super) const fn montgomery_reduce(lo: &U256, hi: &U256) -> U256 {
    let lo = lo.as_limbs();
    let hi = hi.as_limbs();

    let a0 = lo[0];
    let a1 = lo[1];
    let a2 = lo[2];
    let a3 = lo[3];
    let a4 = lo[4];
    let a5 = lo[5];
    let a6 = lo[6];
    let a7 = lo[7];
    let a8 = hi[0];
    let a9 = hi[1];
    let a10 = hi[2];
    let a11 = hi[3];
    let a12 = hi[4];
    let a13 = hi[5];
    let a14 = hi[6];
    let a15 = hi[7];

    let (a3, carry) = a3.carrying_add(Limb::ZERO, a0);
    let (a4, carry) = a4.carrying_add(Limb::ZERO, carry);
    let (a5, carry) = a5.carrying_add(Limb::ZERO, carry);
    let (a6, carry) = a6.carrying_add(a0, carry);

    // NOTE `MODULUS[7]` is 2^32 - 1, this could be optimized to `carrying_add` and `borrowing_sub`
    // but multiplication costs 1 clock-cycle on several architectures,
    // thanks to parallelization
    let (a7, carry) = a0.carrying_mul_add(MODULUS[7], a7, carry);

    // optimization with only carrying_add and borrowing_sub
    let (a8, carry2) = a8.carrying_add(Limb::ZERO, carry);

    let (a4, carry) = a4.carrying_add(Limb::ZERO, a1);
    let (a5, carry) = a5.carrying_add(Limb::ZERO, carry);
    let (a6, carry) = a6.carrying_add(Limb::ZERO, carry);
    let (a7, carry) = a7.carrying_add(a1, carry);
    let (a8, carry) = a1.carrying_mul_add(MODULUS[7], a8, carry);
    let (a9, carry2) = a9.carrying_add(carry2, carry);

    let (a5, carry) = a5.carrying_add(Limb::ZERO, a2);
    let (a6, carry) = a6.carrying_add(Limb::ZERO, carry);
    let (a7, carry) = a7.carrying_add(Limb::ZERO, carry);
    let (a8, carry) = a8.carrying_add(a2, carry);
    let (a9, carry) = a2.carrying_mul_add(MODULUS[7], a9, carry);
    let (a10, carry2) = a10.carrying_add(carry2, carry);

    let (a6, carry) = a6.carrying_add(Limb::ZERO, a3);
    let (a7, carry) = a7.carrying_add(Limb::ZERO, carry);
    let (a8, carry) = a8.carrying_add(Limb::ZERO, carry);
    let (a9, carry) = a9.carrying_add(a3, carry);
    let (a10, carry) = a3.carrying_mul_add(MODULUS[7], a10, carry);
    let (a11, carry2) = a11.carrying_add(carry2, carry);

    let (a7, carry) = a7.carrying_add(Limb::ZERO, a4);
    let (a8, carry) = a8.carrying_add(Limb::ZERO, carry);
    let (a9, carry) = a9.carrying_add(Limb::ZERO, carry);
    let (a10, carry) = a10.carrying_add(a4, carry);
    let (a11, carry) = a4.carrying_mul_add(MODULUS[7], a11, carry);
    let (a12, carry2) = a12.carrying_add(carry2, carry);

    let (a8, carry) = a8.carrying_add(Limb::ZERO, a5);
    let (a9, carry) = a9.carrying_add(Limb::ZERO, carry);
    let (a10, carry) = a10.carrying_add(Limb::ZERO, carry);
    let (a11, carry) = a11.carrying_add(a5, carry);
    let (a12, carry) = a5.carrying_mul_add(MODULUS[7], a12, carry);
    let (a13, carry2) = a13.carrying_add(carry2, carry);

    let (a9, carry) = a9.carrying_add(Limb::ZERO, a6);
    let (a10, carry) = a10.carrying_add(Limb::ZERO, carry);
    let (a11, carry) = a11.carrying_add(Limb::ZERO, carry);
    let (a12, carry) = a12.carrying_add(a6, carry);
    let (a13, carry) = a6.carrying_mul_add(MODULUS[7], a13, carry);
    let (a14, carry2) = a14.carrying_add(carry2, carry);

    let (a10, carry) = a10.carrying_add(Limb::ZERO, a7);
    let (a11, carry) = a11.carrying_add(Limb::ZERO, carry);
    let (a12, carry) = a12.carrying_add(Limb::ZERO, carry);
    let (a13, carry) = a13.carrying_add(a7, carry);
    let (a14, carry) = a7.carrying_mul_add(MODULUS[7], a14, carry);
    let (a15, a16) = a15.carrying_add(carry2, carry);

    // Result may be within MODULUS of the correct value
    let (result, _) = sub_inner(
        [a8, a9, a10, a11, a12, a13, a14, a15, a16],
        [
            MODULUS[0],
            MODULUS[1],
            MODULUS[2],
            MODULUS[3],
            MODULUS[4],
            MODULUS[5],
            MODULUS[6],
            MODULUS[7],
            Limb::ZERO,
        ],
    );

    U256::new([
        result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7],
    ])
}

// Keep constant modulus operands visible and avoid passing three limb arrays.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub(super) const fn sub_inner(l: [Limb; 9], r: [Limb; 9]) -> ([Limb; 8], Limb) {
    let (w0, borrow) = borrowing_sub_u32(l[0].0, r[0].0, Choice::FALSE);
    let (w1, borrow) = borrowing_sub_u32(l[1].0, r[1].0, borrow);
    let (w2, borrow) = borrowing_sub_u32(l[2].0, r[2].0, borrow);
    let (w3, borrow) = borrowing_sub_u32(l[3].0, r[3].0, borrow);
    let (w4, borrow) = borrowing_sub_u32(l[4].0, r[4].0, borrow);
    let (w5, borrow) = borrowing_sub_u32(l[5].0, r[5].0, borrow);
    let (w6, borrow) = borrowing_sub_u32(l[6].0, r[6].0, borrow);
    let (w7, borrow) = borrowing_sub_u32(l[7].0, r[7].0, borrow);
    let (_, borrow) = borrowing_sub_u32(l[8].0, r[8].0, borrow);
    let borrow = Limb(borrow.to_u32_mask());

    // If underflow occurred on the final limb, borrow = 0xfff...fff, otherwise
    // borrow = 0x000...000. Thus, we use it as a mask to conditionally add
    // the MODULUS.

    let (w0, carry) = Limb(w0).carrying_add(MODULUS[0].bitand(borrow), Limb::ZERO);
    let (w1, carry) = Limb(w1).carrying_add(MODULUS[1].bitand(borrow), carry);
    let (w2, carry) = Limb(w2).carrying_add(MODULUS[2].bitand(borrow), carry);
    let (w3, carry) = Limb(w3).carrying_add(MODULUS[3].bitand(borrow), carry);
    let (w4, carry) = Limb(w4).carrying_add(MODULUS[4].bitand(borrow), carry);
    let (w5, carry) = Limb(w5).carrying_add(MODULUS[5].bitand(borrow), carry);
    let (w6, carry) = Limb(w6).carrying_add(MODULUS[6].bitand(borrow), carry);
    let (w7, _) = Limb(w7).carrying_add(MODULUS[7].bitand(borrow), carry);

    ([w0, w1, w2, w3, w4, w5, w6, w7], borrow)
}
