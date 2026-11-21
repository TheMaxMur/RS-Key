// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn hex(bytes: &[u8]) -> std::string::String {
    use core::fmt::Write;
    let mut s = std::string::String::new();
    for b in bytes {
        write!(s, "{b:02x}").unwrap();
    }
    s
}

#[test]
fn sha256_vectors() {
    // NIST / FIPS 180-4 examples.
    assert_eq!(
        hex(&sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hex(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn streaming_sha256_preserves_block_and_padding_boundaries() {
    let bytes = [0xa5; 1025];
    for length in [0, 1, 55, 56, 63, 64, 65, 255, 256, 1025] {
        for chunk in [1, 7, 64, 256] {
            let mut state = Sha256State::new();
            for part in bytes[..length].chunks(chunk) {
                state.update(part);
            }
            assert_eq!(state.finish(), sha256(&bytes[..length]));
        }
    }
    assert_eq!(Sha256State::default().finish(), sha256(b""));
}

#[test]
fn cloned_public_sha256_prefixes_extend_independently() {
    let prefix = [0xa5; 257];
    for length in [0, 1, 55, 56, 63, 64, 65, 255, 256, 257] {
        let mut state = Sha256State::new();
        state.update(&prefix[..length]);
        for suffix in [b"".as_slice(), b"append", &[0xff; 129]] {
            let mut branch = state.clone();
            branch.update(suffix);
            assert_eq!(
                branch.finish(),
                sha256(&[&prefix[..length], suffix].concat())
            );
            let (blocks, tail) = state.clone().into_prefix();
            assert_eq!(tail, length % 64);
            let mut resumed = blocks.resume(&prefix[length - tail..length]);
            resumed.update(suffix);
            assert_eq!(
                resumed.finish(),
                sha256(&[&prefix[..length], suffix].concat())
            );
        }
        assert_eq!(state.finish(), sha256(&prefix[..length]));
    }
}

#[test]
fn sha1_vectors() {
    // FIPS 180-1 examples.
    assert_eq!(
        hex(&sha1(b"abc")),
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
}

#[test]
fn sha384_vectors() {
    // FIPS 180-4 examples.
    assert_eq!(
        hex(&sha384(b"abc")),
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
         8086072ba1e7cc2358baeca134c825a7"
    );
}

#[test]
fn sha512_vectors() {
    assert_eq!(
        hex(&sha512(b"abc")),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    );
}
