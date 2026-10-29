// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use hmac::{Hmac, Mac};
use sha2::Digest;

#[test]
fn hash_hmac_and_hkdf_match_rustcrypto_across_block_and_padding_boundaries() {
    let mut random = 0xd061_5e72_4ba8_139fu64;
    let mut bytes = |len| {
        (0..len)
            .map(|_| {
                random ^= random << 13;
                random ^= random >> 7;
                random ^= random << 17;
                random.to_le_bytes()[0]
            })
            .collect::<std::vec::Vec<_>>()
    };
    for length in [
        0, 1, 7, 31, 32, 33, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 140, 204, 255, 256,
        257, 511, 512, 1024, 4096,
    ] {
        let message = bytes(length);
        let expected = sha2::Sha256::digest(&message);
        for stride in [1, 7, 32, 63, 64, 65, 127, 256] {
            let mut hash = Sha256::default();
            for part in message.chunks(stride) {
                Digest::update(&mut hash, part);
            }
            let clone = hash.clone();
            assert_eq!(
                hash.finalize_reset(),
                expected,
                "hash len={length} stride={stride}"
            );
            assert_eq!(clone.finalize(), expected);
            Digest::update(&mut hash, &message);
            assert_eq!(hash.finalize(), expected);
        }
        for key_length in [0, 1, 31, 32, 63, 64, 65, 127, 128, 129, 256] {
            let key = bytes(key_length);
            let mut actual = Hmac::<Sha256>::new_from_slice(&key).unwrap();
            let mut reference = Hmac::<sha2::Sha256>::new_from_slice(&key).unwrap();
            for part in message.chunks(17) {
                Mac::update(&mut actual, part);
                Mac::update(&mut reference, part);
            }
            assert_eq!(
                actual.finalize().into_bytes(),
                reference.finalize().into_bytes(),
                "HMAC len={length} key={key_length}"
            );
            let (mut output, mut wanted) = ([0; 97], [0; 97]);
            hkdf::Hkdf::<Sha256>::new(Some(&key), &message)
                .expand(b"partial-round differential", &mut output)
                .unwrap();
            hkdf::Hkdf::<sha2::Sha256>::new(Some(&key), &message)
                .expand(b"partial-round differential", &mut wanted)
                .unwrap();
            assert_eq!(output, wanted, "HKDF len={length} key={key_length}");
        }
    }
}

#[test]
fn long_hashes_preserve_block_counts_clones_and_reset() {
    for length in [8191, 8192, 8193, 1 << 20] {
        let message = std::vec![0xa3; length];
        let expected = sha2::Sha256::digest(&message);
        let mut hash = Sha256::default();
        for part in message.chunks(257) {
            Digest::update(&mut hash, part);
        }
        assert_eq!(hash.clone().finalize(), expected, "clone len={length}");
        assert_eq!(hash.finalize_reset(), expected, "reset len={length}");
        Digest::update(&mut hash, &message[..129]);
        assert_eq!(hash.finalize(), sha2::Sha256::digest(&message[..129]));
    }
}

#[test]
fn public_block_suffix_counts_the_prefix_in_every_padding_boundary() {
    for seed in [0u8, 0x36, 0x5c, 0xff] {
        let block = core::array::from_fn::<_, 64, _>(|i| seed.wrapping_add(i as u8));
        let mut state = INITIAL;
        compress(&mut state, (&block).into());
        for length in 0..=512 {
            let suffix: std::vec::Vec<_> = (0..length).map(|i| (i * 73 + 19) as u8).collect();
            let mut reference = sha2::Sha256::new();
            Digest::update(&mut reference, block);
            Digest::update(&mut reference, &suffix);
            assert_eq!(
                digest_after_public_block(state, &suffix).as_slice(),
                reference.finalize().as_slice(),
                "seed={seed} suffix={length}"
            );
        }
    }
}
