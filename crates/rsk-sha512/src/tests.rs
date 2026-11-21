// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Byte-identity gate for the SHA-512/384 core. Three layers: fixed published
//! KATs (catch a bug shared by both this crate and `sha2`), a randomized
//! differential against `sha2`/`hmac`/`hkdf` over block-boundary lengths (the
//! wide net — the exact HMAC/HKDF shapes the FIDO ratchet drives), and the
//! finalization edge cases. This is what guarantees the digest is byte-for-byte
//! what `sha2` produced, so no stored credential key changes.

use super::*;

use digest::Digest;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// -------------------------------------------------------------- fixed KATs ---

#[test]
fn sha512_nist_vectors() {
    // FIPS 180-4 §D examples plus the empty string.
    let cases: [(&[u8], &str); 3] = [
        (b"", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
        (b"abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
        // 112 bytes → padding spills into a second block.
        (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
         "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"),
    ];
    for (msg, want) in cases {
        assert_eq!(hex(&Sha512::digest(msg)), want, "SHA-512({msg:?})");
    }
}

#[test]
fn sha384_nist_vectors() {
    let cases: [(&[u8], &str); 3] = [
        (b"", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"),
        (b"abc", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"),
        (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
         "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"),
    ];
    for (msg, want) in cases {
        assert_eq!(hex(&Sha384::digest(msg)), want, "SHA-384({msg:?})");
    }
}

#[test]
fn reset_and_finalize_reset_remove_both_partial_and_complete_blocks() {
    for length in [0, 1, 111, 112, 127, 128, 129, 256] {
        let message = vec![0xA5; length];
        let mut sha512 = Sha512::new();
        let mut sha384 = Sha384::new();
        sha512.update(&message);
        sha384.update(&message);
        assert_eq!(
            sha512.finalize_reset()[..],
            sha2::Sha512::digest(&message)[..]
        );
        assert_eq!(
            sha384.finalize_reset()[..],
            sha2::Sha384::digest(&message)[..]
        );
        assert_eq!(sha512.finalize_reset()[..], sha2::Sha512::digest([])[..]);
        assert_eq!(sha384.finalize_reset()[..], sha2::Sha384::digest([])[..]);
        sha512.update(&message);
        sha384.update(&message);
        Digest::reset(&mut sha512);
        Digest::reset(&mut sha384);
        sha512.update(b"abc");
        sha384.update(b"abc");
        assert_eq!(sha512.finalize()[..], sha2::Sha512::digest(b"abc")[..]);
        assert_eq!(sha384.finalize()[..], sha2::Sha384::digest(b"abc")[..]);
    }
}

#[test]
fn debug_output_does_not_disclose_the_chaining_state() {
    let mut sha512 = Sha512Core::default();
    let mut sha384 = Sha384Core::default();
    sha512.state.fill(0x0123_4567_89AB_CDEF);
    sha384.state.fill(0x0123_4567_89AB_CDEF);
    for text in [
        format!("{sha512:?}"),
        format!("{sha384:?}"),
        format!("{:?}", Sha512::new()),
        format!("{:?}", Sha384::new()),
    ] {
        assert!(text.starts_with("Sha"));
        assert!(!text.contains("0123456789"));
        assert!(!text.contains("81985529216486895"));
    }
}

#[test]
fn hmac_sha512_rfc4231() {
    // RFC 4231 test case 2 (short key) and case 6 (131-byte key > block size, so
    // the key is itself hashed first — exercises the HMAC key-reduction path).
    let key2 = b"Jefe";
    let data2 = b"what do ya want for nothing?";
    let want2 = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737";
    let mut m = Hmac::<Sha512>::new_from_slice(key2).unwrap();
    m.update(data2);
    assert_eq!(hex(&m.finalize().into_bytes()), want2, "RFC 4231 case 2");

    let key6 = [0xaau8; 131];
    let data6 = b"Test Using Larger Than Block-Size Key - Hash Key First";
    let want6 = "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598";
    let mut m = Hmac::<Sha512>::new_from_slice(&key6).unwrap();
    m.update(data6);
    assert_eq!(hex(&m.finalize().into_bytes()), want6, "RFC 4231 case 6");
}

// ---------------------------------------- differential vs sha2/hmac/hkdf -----
//
// The real byte-identity guarantee: for the same input our types must produce
// the exact bytes the shipping `sha2`/`hmac`/`hkdf` do — that is what keeps the
// FIDO ratchet output (every credential key) unchanged. A cheap deterministic
// PRNG walks lengths across the 128-byte block boundary and the padding edges.

struct Lcg(u64);
impl Lcg {
    fn next_u64(&mut self) -> u64 {
        // SplitMix64.
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u64() as u8).collect()
    }
    /// A random-length (0..max) random byte string.
    fn rand_bytes(&mut self, max: u64) -> Vec<u8> {
        let n = (self.next_u64() % max) as usize;
        self.bytes(n)
    }
}

/// Lengths that bracket every block/padding boundary SHA-512 has.
const EDGE_LENS: &[usize] = &[
    0, 1, 55, 111, 112, 113, 127, 128, 129, 200, 239, 240, 241, 255, 256, 257, 300,
];

#[test]
fn sha512_matches_sha2_over_edge_and_random_lengths() {
    let mut rng = Lcg(0x0123_4567_89ab_cdef);
    let mut lens: Vec<usize> = EDGE_LENS.to_vec();
    for _ in 0..1000 {
        lens.push((rng.next_u64() % 600) as usize);
    }
    for len in lens {
        let msg = rng.bytes(len);
        assert_eq!(
            Sha512::digest(&msg)[..],
            sha2::Sha512::digest(&msg)[..],
            "sha512 len {len}"
        );
        assert_eq!(
            Sha384::digest(&msg)[..],
            sha2::Sha384::digest(&msg)[..],
            "sha384 len {len}"
        );
    }
}

#[test]
fn hmac_sha512_matches_sha2() {
    let mut rng = Lcg(0xdead_beef_cafe_f00d);
    for _ in 0..500 {
        let key = rng.rand_bytes(200);
        let msg = rng.rand_bytes(300);
        let ours = {
            let mut m = Hmac::<Sha512>::new_from_slice(&key).unwrap();
            m.update(&msg);
            m.finalize().into_bytes()
        };
        let theirs = {
            let mut m = Hmac::<sha2::Sha512>::new_from_slice(&key).unwrap();
            m.update(&msg);
            m.finalize().into_bytes()
        };
        assert_eq!(
            ours[..],
            theirs[..],
            "hmac-sha512 key {} msg {}",
            key.len(),
            msg.len()
        );
    }
}

#[test]
fn hkdf_sha512_matches_sha2() {
    let mut rng = Lcg(0xf00d_1234_5678_9abc);
    for _ in 0..500 {
        let salt = rng.rand_bytes(64);
        let ikm = rng.rand_bytes(80);
        let info = rng.rand_bytes(80);
        let out_len = 1 + (rng.next_u64() % 600) as usize;

        let mut ours = vec![0u8; out_len];
        Hkdf::<Sha512>::new(Some(&salt), &ikm)
            .expand(&info, &mut ours)
            .unwrap();
        let mut theirs = vec![0u8; out_len];
        Hkdf::<sha2::Sha512>::new(Some(&salt), &ikm)
            .expand(&info, &mut theirs)
            .unwrap();
        assert_eq!(ours, theirs, "hkdf-sha512 out_len {out_len}");
    }
}

/// The exact shape the FIDO ratchet drives (salt=4B, ikm=32B, info=32B, okm=66B),
/// pinned so a regression fails here at the primitive, not just in the fuzz loop.
#[test]
fn hkdf_sha512_ratchet_shape_matches_sha2() {
    let salt = [0x80u8, 0x27, 0x00, 0x00];
    let ikm = [0x11u8; 32];
    let info = [0x22u8; 32];
    let mut ours = [0u8; 66];
    let mut theirs = [0u8; 66];
    Hkdf::<Sha512>::new(Some(&salt), &ikm)
        .expand(&info, &mut ours)
        .unwrap();
    Hkdf::<sha2::Sha512>::new(Some(&salt), &ikm)
        .expand(&info, &mut theirs)
        .unwrap();
    assert_eq!(ours, theirs);
}
