//! Regression test for P-521 scalar parameter evaluation on 32-bit targets.

#![deny(long_running_const_eval)]

use crypto_bigint::{const_prime_monty_params, modular::ConstPrimeMontyParams};

crypto_bigint::cpubits! {
    32 => {
        use crypto_bigint::U544 as Uint;
        const ORDER_HEX: &str =
            "000001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
    }
    64 => {
        use crypto_bigint::U576 as Uint;
        const ORDER_HEX: &str =
            "00000000000001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";
    }
}

const_prime_monty_params!(P521Order, Uint, ORDER_HEX, 3);

#[test]
fn p521_scalar_params() {
    // Evaluating PRIME_PARAMS computes a root of unity by modular exponentiation.
    // This must remain below the default const-evaluation limit on the MSRV.
    assert_eq!(P521Order::PRIME_PARAMS.s().get(), 3);
    assert_eq!(P521Order::PRIME_PARAMS.generator().get(), 3);
}
