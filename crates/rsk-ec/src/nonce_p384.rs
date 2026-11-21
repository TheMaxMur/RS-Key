// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use p384::elliptic_curve::{
    Curve, PrimeField,
    bigint::{CtLt, U384},
    ops::Reduce,
};
use rfc6979::hmac::{KeyInit, SimpleHmac, digest::Mac};
use rsk_secret::Secret;

type Sha384 = <p384::NistP384 as ecdsa::DigestAlgorithm>::Digest;

fn hmac(key: &[u8; 48], inputs: &[&[u8]]) -> Secret<[u8; 48]> {
    let mut mac = SimpleHmac::<Sha384>::new_from_slice(key).expect("HMAC accepts any key length");
    for input in inputs {
        mac.update(input);
    }
    Secret::new(mac.finalize().into_bytes().into())
}

fn acceptable(bytes: &[u8; 48]) -> bool {
    let value = Secret::new(U384::from_be_slice(bytes));
    let order = p384::NistP384::ORDER;
    #[cfg(test)]
    let order = tests::candidate_order(*order);
    ((!value.expose().is_zero()) & value.expose().ct_lt(&order)).to_bool()
}

pub(super) fn fill_nonce(d: &p384::Scalar, prehash: &[u8; 48], out: &mut [u8; 48]) {
    let private = Secret::new(d.to_repr());
    let hash = Secret::new(
        <p384::Scalar as Reduce<U384>>::reduce(&U384::from_be_slice(prehash)).to_repr(),
    );
    let mut k = Secret::zeroed();
    let mut v = Secret::new([1; 48]);
    for separator in [0, 1] {
        k = hmac(
            k.expose(),
            &[
                v.expose(),
                &[separator],
                &private.expose()[..],
                &hash.expose()[..],
            ],
        );
        v = hmac(k.expose(), &[v.expose()]);
    }
    loop {
        v = hmac(k.expose(), &[v.expose()]);
        let accepted = acceptable(v.expose());
        #[cfg(test)]
        let accepted = tests::accept_candidate(accepted);
        if accepted {
            out.copy_from_slice(v.expose());
            return;
        }
        // RFC 6979 section 3.2.h: only rejected candidates need another K/V update.
        k = hmac(k.expose(), &[v.expose(), &[0]]);
        v = hmac(k.expose(), &[v.expose()]);
    }
}

#[cfg(test)]
#[path = "nonce_p384_tests.rs"]
mod tests;
