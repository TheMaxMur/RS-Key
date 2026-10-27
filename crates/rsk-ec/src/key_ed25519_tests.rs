// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn ed25519_public_points_and_signatures_match_rfc8032() {
    // RFC 8032 §7.1: fixed bytes independently check both base-point multiplications.
    for (seed, public, message, signature) in [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            concat!(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f",
                "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            ),
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            concat!(
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
            ),
        ),
    ] {
        let key = PrivKey::from_scalar(Curve::Ed25519, &hex(seed)).unwrap();
        let mut out = [0x55; MAX_EC_POINT];
        let n = key.public_point(&mut out).unwrap();
        assert_eq!(&out[..n], hex(public));
        assert!(out[n..].iter().all(|&byte| byte == 0x55));
        let mut sig = [0x55; MAX_EC_SIG];
        let n = key.sign(&hex(message), &mut sig).unwrap();
        assert_eq!(&sig[..n], hex(signature));
        assert!(sig[n..].iter().all(|&byte| byte == 0x55));
    }
}
