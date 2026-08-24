#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Regenerate crates/rsk-rsa/src/vectors.rs from OpenSSL.

`rsk-rsa` has no second RSA implementation to check itself against — the `rsa`
crate that used to serve as one left the tree with RUSTSEC-2023-0071. So the
ground truth is frozen here instead: python-cryptography's OpenSSL signs and
encrypts under fixed keys, and the host tests must reproduce it byte for byte.
Run inside `nix develop`.

The keys are hardcoded, not generated: a fresh key every run would rewrite the
whole file and the diff would say nothing. Encryption padding is random, so its
ciphertexts do move on a regeneration — they are a freeze, not a fingerprint.
"""

import hashlib
import math
import pathlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

OUT = pathlib.Path(__file__).resolve().parent.parent / "crates/rsk-rsa/src/vectors.rs"

E = 65537

# The RSA-2048 key every sign/decipher test drives (openssl genrsa).
P = int(
    "f05c23060effc422e4310c13b5aecda74744925c97c17d202aa9ed306941fa1e"
    "942e61c8d9c80961cf90459af36b9e7d529610f5165d60836de5aef2aeb47ea5"
    "00c5a61bb96fd3bb4aca36d45464cce24ff0b67bb3ba382d9bdd95b7133eab86"
    "125800f10b0627fe1bd7689802d767dd9911eefb60d76e2ec860163f3077a5bd", 16)
Q = int(
    "c6a96b4a9b7bdd654152f3302dd23bd7b18e62f999cf0d44d01c6ce18cfdfb1c"
    "29e523edebe5e6df8967f49afe38d6a9345bc6f4f966e0de2902bddc7caf5a4a"
    "1761d18b070cd4cda287388cbdf523c39e246c220af3292fee181b4bb1c3f533"
    "b74de89c586e6f9d47ae4bb7f8735d3f0b377a76a7ca6c81324833c2b78b737d", 16)

# RSA-1024: the smallest size the OpenPGP card advertises, and the only width
# where a 5-field CRT blob (5x64) collides with a `P||Q` one (2x160).
P1024 = int(
    "efb80954c7388f28b0a5a9ea244eab0bc4189272b4ab7ad98808e34167002e9a"
    "d20ab9fb62f05625c9f72e8448105439dbdd9502a8b9f7d5798fc1dc8be43cab", 16)
Q1024 = int(
    "ed764fec2f76eb5ac58a8d99c6075e8d5f8647e801f25665d187ccad0841e2c6"
    "edfee5c3969de9ee4801043b4c2130d98397ba2b5d948070f67b35a87deb1c5f", 16)

# RSA-640: 40-byte primes, the width the asm CRT core refuses (not a multiple
# of 32). Below what OpenSSL will even generate, so these were sieved by hand.
P640 = int(
    "ffe2e4a07c75787c7b8b5b902633f9495f8daf04cd3b6930c04b5879ad1e9122"
    "91f7f41bcbfe0c57", 16)
Q640 = int(
    "e7c7fbc88104db940a479edc7152958e2f11e0d9dee0891942407246eb9b8642"
    "b8fc53d5ecde86a7", 16)

ENC_MSGS = [b"", b"x", b"a-32-byte-openpgp-session-key!!!"]
SIG_MSGS = [b"", b"rs-key", b"the quick brown fox"]


def key(p, q):
    n = p * q
    lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
    d = pow(E, -1, lam)
    pub = rsa.RSAPublicNumbers(E, n)
    return rsa.RSAPrivateNumbers(p, q, d, d % (p - 1), d % (q - 1), pow(q, -1, p), pub).private_key()


def table(pairs):
    """Emit the shape rustfmt settles on, so regenerating never reopens a fmt diff."""
    return "\n".join(f'    (\n        "{a}",\n        "{b}",\n    ),' for a, b in pairs)


def const_str(name, value, doc):
    """One `pub const NAME: &str = "…";`, wrapped where rustfmt would wrap it.

    rustfmt breaks after the `=` when the one-line form passes max_width and the
    indented string then fits; a string too long for either stays put. Getting
    this wrong is not cosmetic — it reopens a fmt diff on every regeneration.
    """
    one = f'pub const {name}: &str = "{value}";'
    indented = f'    "{value}";'
    if len(one) > 100 and len(indented) <= 100:
        one = f"pub const {name}: &str =\n{indented}"
    return f"{doc}\n{one}"


def main():
    k = key(P, Q)
    enc = []
    for m in ENC_MSGS:
        ct = k.public_key().encrypt(m, padding.PKCS1v15())
        assert k.decrypt(ct, padding.PKCS1v15()) == m
        enc.append((m.hex(), ct.hex()))
    sig = [
        (hashlib.sha256(m).hexdigest(), k.sign(m, padding.PKCS1v15(), hashes.SHA256()).hex())
        for m in SIG_MSGS
    ]

    OUT.write_text(f"""// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! OpenSSL Known-Answer-Test vectors for RSA PKCS#1 v1.5 — the independent
//! ground truth the host tests check this crate against, so the suite needs no
//! second RSA *implementation* linked into the tree.
//!
//! Source: OpenSSL 3.6.2 via python-cryptography 48.0.0. Regenerate with
//! `scripts/rsa_vectors.py`. **Generated — edit the script, not this file.**
//!
//! Encryption is randomised, so a ciphertext is frozen here and we have to
//! decrypt it back; signing is deterministic, so ours must match byte for byte.

use alloc::vec::Vec;

{const_str("P_HEX", f"{P:x}", "/// The RSA-2048 key's primes and modulus, big-endian hex. Public exponent 65537.")}
{const_str("Q_HEX", f"{Q:x}", "/// See [`P_HEX`].")}
{const_str("N_HEX", f"{P * Q:x}", "/// See [`P_HEX`].")}

{const_str("P1024_HEX", f"{P1024:x}", "/// An RSA-1024 key: the smallest size the OpenPGP card advertises, and the one\n/// width whose 5-field CRT blob (5x64) collides with a `P‖Q` one (2x160).")}
{const_str("Q1024_HEX", f"{Q1024:x}", "/// See [`P1024_HEX`].")}
{const_str("N1024_HEX", f"{P1024 * Q1024:x}", "/// See [`P1024_HEX`].")}

{const_str("P640_HEX", f"{P640:x}", "/// An RSA-640 key: 40-byte primes, the width the asm CRT core refuses because\n/// it is not a multiple of 32.")}
{const_str("Q640_HEX", f"{Q640:x}", "/// See [`P640_HEX`].")}

/// `(plaintext, ciphertext)` under the [`P_HEX`] key — OpenSSL built the padded
/// block, so our unpad has to accept exactly what a conforming encrypter emits.
pub const ENCRYPT: &[(&str, &str)] = &[
{table(enc)}
];

/// `(SHA-256 digest, signature)` under the [`P_HEX`] key — RSASSA-PKCS1-v1_5.
/// The digest is what a host sends as a bare hash; prefixed with the SHA-256
/// DigestInfo header it is what gpg sends. Both spellings owe this signature.
pub const SIGN_SHA256: &[(&str, &str)] = &[
{table(sig)}
];

/// Decode a big-endian hex constant from this module.
pub fn hex(s: &str) -> Vec<u8> {{
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("vectors are hex"))
        .collect()
}}
""")
    print(f"wrote {OUT.relative_to(pathlib.Path.cwd())}: {len(enc)} encrypt, {len(sig)} sign")


if __name__ == "__main__":
    main()
