// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
extern crate std;
use std::string::String;
use std::vec::Vec;

#[test]
fn wordlist_is_exactly_2048_and_endpoints_match() {
    assert_eq!(WORDS.len(), 2048);
    assert_eq!(WORDS[0], "abandon");
    assert_eq!(WORDS[2047], "zoo");
    assert!(WORDS.iter().all(|w| w.len() <= 8 && w.is_ascii()));
}

/// Pin the embedded list to the canonical BIP-39 english.txt by re-hashing it: the
/// newline-joined words (trailing newline) must match the published checksum, so a
/// single transposed/edited word can never slip in unnoticed.
#[test]
fn wordlist_matches_the_canonical_checksum() {
    let mut joined = String::new();
    for w in WORDS {
        joined.push_str(w);
        joined.push('\n');
    }
    let digest = rsk_crypto::sha256(joined.as_bytes());
    let mut hex = String::new();
    for b in digest {
        hex.push_str(&std::format!("{b:02x}"));
    }
    assert_eq!(
        hex,
        "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
    );
}

fn phrase(entropy: &[u8; 32]) -> String {
    entropy_to_indices(entropy)
        .expose()
        .iter()
        .map(|&i| word(i))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Authoritative 256-bit vectors generated from the same `mnemonic` library the host
/// `rsk backup` uses, so on-device encode == host decode (interop).
#[test]
fn matches_host_bip39_vectors() {
    assert_eq!(
        phrase(&[0x00; 32]),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon art"
    );
    assert_eq!(
        phrase(&[0xff; 32]),
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo \
         zoo zoo zoo zoo vote"
    );
    assert_eq!(
        phrase(&[0x80; 32]),
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage \
         absurd amount doctor acoustic avoid letter advice cage absurd amount doctor \
         acoustic bless"
    );
    let mut seq = [0u8; 32];
    for (i, b) in seq.iter_mut().enumerate() {
        *b = (i + 1) as u8;
    }
    assert_eq!(
        phrase(&seq),
        "absurd avoid scissors anxiety gather lottery category door army half long \
         cage bachelor another expect people blade school educate curtain scrub \
         monitor lady beyond"
    );
}

#[test]
fn always_24_words_and_in_range() {
    let idx = entropy_to_indices(&[0x5a; 32]);
    assert_eq!(idx.expose().len(), WORD_COUNT);
    assert!(idx.expose().iter().all(|&i| (i as usize) < WORDS.len()));
}
