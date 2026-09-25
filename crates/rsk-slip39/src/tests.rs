// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Host-vector + round-trip tests for the SLIP-39 generator.
//!
//! The golden mnemonics are produced by the same `shamir_mnemonic` library the host
//! `rsk backup` uses, driven by a deterministic byte source (a 0,1,2,… counter), so
//! on-device generate == host generate **byte-for-byte**. The round-trip test recombines
//! the raw shares back to the secret (the inverse the host runs on restore).

use super::*;
extern crate std;
use std::string::String;
use std::vec::Vec;

/// A deterministic byte source matching the Python test's `Counter(0)`: a continuous
/// 0,1,2,…,255,0,… stream, independent of how the consumer chunks its reads.
fn counter(start: u8) -> impl FnMut(&mut [u8]) {
    let mut n = start;
    move |buf: &mut [u8]| {
        for b in buf.iter_mut() {
            *b = n;
            n = n.wrapping_add(1);
        }
    }
}

fn mnemonic(w: &ShareWords) -> String {
    w.iter().map(|&i| word(i)).collect::<Vec<_>>().join(" ")
}

fn seq_secret() -> [u8; 32] {
    let mut s = [0u8; 32];
    for (i, b) in s.iter_mut().enumerate() {
        *b = i as u8;
    }
    s
}

#[test]
fn wordlist_is_exactly_1024_and_endpoints_match() {
    assert_eq!(WORDS.len(), 1024);
    assert_eq!(WORDS[0], "academic");
    assert_eq!(WORDS[1023], "zero");
    assert!(WORDS.iter().all(|w| w.len() <= 8 && w.is_ascii()));
}

/// Pin the embedded list to the canonical SLIP-0039 wordlist by re-hashing it: the
/// newline-joined words (trailing newline) must match the source checksum, so a single
/// transposed/edited word can never slip in unnoticed.
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
        "bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3"
    );
}

/// Authoritative 2-of-3 vector: `generate_mnemonics(1, [(2,3)], seq, b"", 0)` under the
/// 0,1,2,… counter (identifier 1). On-device generate must reproduce it exactly.
#[test]
fn matches_host_2_of_3() {
    let mut out = [[0u16; WORDS_PER_SHARE]; MAX_SHARES];
    let mut rng = counter(0);
    generate(&seq_secret(), 2, 3, &mut rng, &mut out).unwrap();
    assert_eq!(
        mnemonic(&out[0]),
        "academic always academic acid alpha costume ajar peasant boring grasp review \
         geology relate merit civil alto agency lecture painting arena unfold require \
         employer oasis venture process have solution remember olympic avoid wildlife believe"
    );
    assert_eq!(
        mnemonic(&out[1]),
        "academic always academic agency adequate scholar valid purchase artwork laundry \
         shrimp cradle judicial thunder percent sack destroy cylinder iris username else \
         crisis mobile prune story clogs seafood beam privacy royal slice expand ajar"
    );
    assert_eq!(
        mnemonic(&out[2]),
        "academic always academic always artist race vocal ultimate declare miracle fatal \
         usual luxury dramatic diagnose memory squeeze numerous blessing necklace predator \
         fortune vegan piece album juice cover easel coding clogs lobe duckling invasion"
    );
}

/// Authoritative 3-of-5 vector (a `threshold-2 = 1` random member share is drawn, then the
/// random part), exercising the random-share branch of the split.
#[test]
fn matches_host_3_of_5() {
    let mut out = [[0u16; WORDS_PER_SHARE]; MAX_SHARES];
    let mut rng = counter(0);
    generate(&seq_secret(), 3, 5, &mut rng, &mut out).unwrap();
    let expected = [
        "academic always academic acne academic leaves again biology garlic safari amount \
         corner public advance aspect dream acrobat emerald benefit extra failure lizard \
         branch graduate parcel season camera item vanish always luck craft unfold",
        "academic always academic agree alpha unkind pecan beard jewelry society frozen \
         thank impact ladybug plan junior demand theater threaten crystal wealthy capacity \
         union slim maiden employer military divorce tolerate freshman infant beaver require",
        "academic always academic amazing aunt antenna nail expand stadium floral founder \
         withdraw hybrid category screw civil grocery aluminum alto spill elder airline \
         relate upstairs hospital cage unhappy snapshot wolf squeeze famous terminal adapt",
        "academic always academic arcade analysis graduate dining eraser smith erode arcade \
         diminish pupal friendly genius gravity finger process upstairs pink trip order \
         explain force enemy ounce glance mixed trial length parcel sugar fiction",
        "academic always academic axle armed flip desert fancy envy amuse husband equip \
         national webcam security math sunlight skin mixture roster marathon material adorn \
         library tidy skunk artist fiction retailer peanut mother join density",
    ];
    for (i, e) in expected.iter().enumerate() {
        assert_eq!(&mnemonic(&out[i]), e, "share {i} mismatch");
    }
}

/// Authoritative 1-of-1 vector (`threshold == 1`: the secret share verbatim, no digest).
#[test]
fn matches_host_1_of_1() {
    let mut out = [[0u16; WORDS_PER_SHARE]; MAX_SHARES];
    let mut rng = counter(0);
    generate(&[0u8; 32], 1, 1, &mut rng, &mut out).unwrap();
    assert_eq!(
        mnemonic(&out[0]),
        "academic always academic academic aquatic smart enforce diploma hobo grownup \
         exchange junction amuse insect sidewalk intimate civil exceed adapt voice superior \
         flash lobe intimate desert burden escape glance predator dragon capture knife clock"
    );
}

#[test]
fn every_share_is_33_words_in_range() {
    let mut out = [[0u16; WORDS_PER_SHARE]; MAX_SHARES];
    let mut rng = counter(99);
    generate(&[0x5au8; 32], 3, 5, &mut rng, &mut out).unwrap();
    for share in out.iter().take(5) {
        assert_eq!(share.len(), WORDS_PER_SHARE);
        assert!(share.iter().all(|&i| (i as usize) < WORDS.len()));
    }
}

#[test]
fn rejects_bad_parameters() {
    let mut out = [[0u16; WORDS_PER_SHARE]; MAX_SHARES];
    let mut rng = counter(0);
    assert_eq!(
        generate(&[0u8; 32], 0, 3, &mut rng, &mut out),
        Err(Error::BadThreshold)
    );
    assert_eq!(
        generate(&[0u8; 32], 4, 3, &mut rng, &mut out),
        Err(Error::BadThreshold)
    );
    assert_eq!(
        generate(&[0u8; 32], 1, 0, &mut rng, &mut out),
        Err(Error::BadCount)
    );
    assert_eq!(
        generate(&[0u8; 32], 1, (MAX_SHARES + 1) as u8, &mut rng, &mut out),
        Err(Error::BadCount)
    );
}

// === Round-trip (the inverse the host runs on restore) ===

fn cipher_decrypt(ct: &[u8; 32], identifier: u16) -> [u8; 32] {
    let salt = salt_of(identifier);
    let mut l = [0u8; 16];
    let mut r = [0u8; 16];
    l.copy_from_slice(&ct[..16]);
    r.copy_from_slice(&ct[16..]);
    for i in (0..ROUNDS as u8).rev() {
        let f = round_function(i, &salt, &r);
        let mut new_r = l;
        for (a, b) in new_r.iter_mut().zip(f.expose().iter()) {
            *a ^= *b;
        }
        l = r;
        r = new_r;
    }
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&r);
    out[16..].copy_from_slice(&l);
    out
}

fn recover_secret(threshold: u8, shares: &[Point]) -> [u8; 32] {
    if threshold == 1 {
        return shares[0].1;
    }
    let secret = interpolate(shares, SECRET_X);
    let digest_share = interpolate(shares, DIGEST_X);
    let mut digest = [0u8; DIGEST_LEN];
    digest.copy_from_slice(&digest_share[..DIGEST_LEN]);
    let mut rp = [0u8; RANDOM_PART_LEN];
    rp.copy_from_slice(&digest_share[DIGEST_LEN..]);
    assert_eq!(create_digest(&rp, &secret), digest, "digest mismatch");
    secret
}

#[test]
fn cipher_round_trips() {
    let s = seq_secret();
    for id in [0u16, 1, 0x1234, 0x7fff] {
        assert_eq!(cipher_decrypt(cipher_encrypt(&s, id).expose(), id), s);
    }
}

/// Split 3-of-5, then recombine three different subsets — each must recover the ciphertext,
/// and decrypting it must yield the original secret (what `combine_mnemonics` does on restore).
#[test]
fn shamir_round_trips_any_threshold_subset() {
    let secret = [0x42u8; 32];
    let mut rng = counter(7);
    let mut idb = [0u8; 2];
    rng(&mut idb);
    let identifier = (((idb[0] as u16) << 8) | idb[1] as u16) & 0x7fff;
    let ems = cipher_encrypt(&secret, identifier);
    let mut data = [[0u8; 32]; MAX_SHARES];
    split_secret(3, 5, ems.expose(), &mut rng, &mut data);

    for subset in [[0usize, 1, 2], [0, 2, 4], [1, 3, 4]] {
        let shares: Vec<Point> = subset.iter().map(|&i| (i as u8, data[i])).collect();
        let rec_ems = recover_secret(3, &shares);
        assert_eq!(
            &rec_ems,
            ems.expose(),
            "subset {subset:?} ciphertext mismatch"
        );
        assert_eq!(
            cipher_decrypt(&rec_ems, identifier),
            secret,
            "subset {subset:?} secret mismatch"
        );
    }
}

#[test]
fn one_of_one_round_trips() {
    let secret = [0x11u8; 32];
    let mut rng = counter(3);
    let mut idb = [0u8; 2];
    rng(&mut idb);
    let identifier = (((idb[0] as u16) << 8) | idb[1] as u16) & 0x7fff;
    let ems = cipher_encrypt(&secret, identifier);
    let mut data = [[0u8; 32]; MAX_SHARES];
    split_secret(1, 1, ems.expose(), &mut rng, &mut data);
    let shares = [(0u8, data[0])];
    assert_eq!(
        cipher_decrypt(&recover_secret(1, &shares), identifier),
        secret
    );
}
