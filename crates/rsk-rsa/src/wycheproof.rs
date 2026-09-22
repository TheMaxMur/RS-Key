// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors
//! Wycheproof's RSA PKCS#1 v1.5 vectors: cases built to break an implementation
//! rather than confirm it — bad padding in every position, special-case and
//! malformed ciphertexts, weak parameters. They live in `third_party/wycheproof/`
//! under Apache-2.0, written by `scripts/wycheproof_vectors.py`, whose header
//! lines name the upstream commit and what was kept. Dev-only, like
//! [`crate::vectors`]: this crate's tests sign with them and `rsk-openpgp`'s
//! decipher with them.
//!
//! `include_str!` makes a missing file a build error rather than zero cases, and
//! the tests assert the counts, so a case lost in a refresh is red too.

use alloc::vec::Vec;

/// Wycheproof's verdict on a case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Valid,
    Invalid,
    /// Correct, but over parameters Wycheproof calls weak (SHA-1, a small modulus).
    Acceptable,
}

/// One decryption case. Hex throughout; `crt` is `P ‖ Q ‖ dP ‖ dQ ‖ qInv`, each at
/// the prime width, so it concatenates into the blob the card seals.
pub struct Decrypt {
    pub bits: u16,
    pub tc_id: &'static str,
    pub result: Outcome,
    pub crt: [&'static str; 5],
    pub ct: &'static str,
    pub msg: &'static str,
    pub comment: &'static str,
}

/// One signing case: the DigestInfo a host sends, and the signature it must get.
pub struct Sign {
    pub bits: u16,
    pub tc_id: &'static str,
    pub result: Outcome,
    pub hash: &'static str,
    pub crt: [&'static str; 5],
    pub digest_info: &'static str,
    pub sig: &'static str,
    pub comment: &'static str,
}

/// Every decryption case, RSA-2048 to -4096.
pub fn decrypt() -> Vec<Decrypt> {
    cases(include_str!(
        "../../../third_party/wycheproof/rsa-pkcs1-decrypt.txt"
    ))
    .map(
        |[bits, tc_id, result, p, q, dp, dq, qinv, ct, msg, comment]| Decrypt {
            bits: number(bits),
            tc_id,
            result: outcome(result),
            crt: [p, q, dp, dq, qinv],
            ct,
            msg,
            comment,
        },
    )
    .collect()
}

/// Every signing case the card's signer takes, RSA-1024 to -4096.
pub fn sign() -> Vec<Sign> {
    cases(include_str!(
        "../../../third_party/wycheproof/rsa-pkcs1-sign.txt"
    ))
    .map(
        |[
            bits,
            tc_id,
            result,
            hash,
            p,
            q,
            dp,
            dq,
            qinv,
            digest_info,
            sig,
            comment,
        ]| Sign {
            bits: number(bits),
            tc_id,
            result: outcome(result),
            hash,
            crt: [p, q, dp, dq, qinv],
            digest_info,
            sig,
            comment,
        },
    )
    .collect()
}

/// The data lines of a vector file, each split into its `N` fields. The last one
/// keeps its spaces, because a comment is prose; `-` stands for empty.
fn cases<const N: usize>(text: &'static str) -> impl Iterator<Item = [&'static str; N]> {
    text.lines().filter(|l| !l.starts_with('#')).map(|line| {
        let fields: Vec<&'static str> = line
            .splitn(N, ' ')
            .map(|f| if f == "-" { "" } else { f })
            .collect();
        fields
            .try_into()
            .unwrap_or_else(|f: Vec<_>| panic!("{} of {N} fields: {line:.60}", f.len()))
    })
}

fn number(field: &str) -> u16 {
    field.parse().expect("a key size in bits")
}

fn outcome(field: &str) -> Outcome {
    match field {
        "valid" => Outcome::Valid,
        "invalid" => Outcome::Invalid,
        "acceptable" => Outcome::Acceptable,
        v => panic!("a Wycheproof result of {v:?}"),
    }
}
