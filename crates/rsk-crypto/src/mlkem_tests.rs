// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

const SEED: [u8; MLKEM768_SEED_LEN] = [0x42; MLKEM768_SEED_LEN];

#[test]
fn keygen_is_deterministic_and_seed_sensitive() {
    let a = MlKem768Pair::from_seed(&SEED);
    let b = MlKem768Pair::from_seed(&SEED);
    assert_eq!(a.encapsulation_key(), b.encapsulation_key());

    let mut other = SEED;
    other[0] ^= 1;
    let c = MlKem768Pair::from_seed(&other);
    assert_ne!(a.encapsulation_key(), c.encapsulation_key());
}

#[test]
fn encaps_decaps_roundtrip() {
    let pair = MlKem768Pair::from_seed(&SEED);
    let (ct, ss_peer) = mlkem768_encapsulate(&pair.encapsulation_key(), &[7u8; 32]).unwrap();
    let ss_own = pair.decapsulate(&ct);
    assert_eq!(ss_peer, ss_own);
}

#[test]
fn fixed_m_reproducible() {
    let pair = MlKem768Pair::from_seed(&SEED);
    let ek = pair.encapsulation_key();
    let (ct1, ss1) = mlkem768_encapsulate(&ek, &[9u8; 32]).unwrap();
    let (ct2, ss2) = mlkem768_encapsulate(&ek, &[9u8; 32]).unwrap();
    assert_eq!(ct1, ct2);
    assert_eq!(ss1, ss2);
}

#[test]
fn corrupted_ciphertext_implicitly_rejects() {
    let pair = MlKem768Pair::from_seed(&SEED);
    let (mut ct, ss_peer) = mlkem768_encapsulate(&pair.encapsulation_key(), &[7u8; 32]).unwrap();
    ct[0] ^= 1;
    // No panic, no error — just a shared secret that matches nothing.
    assert_ne!(pair.decapsulate(&ct), ss_peer);
}

#[test]
fn malformed_ek_rejected() {
    // An all-0xFF key has non-reduced coefficients → InvalidKey.
    assert!(mlkem768_encapsulate(&[0xFF; MLKEM768_EK_LEN], &[0u8; 32]).is_err());
}

fn hex(value: &str) -> std::vec::Vec<u8> {
    assert!(value.len().is_multiple_of(2));
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn acvp_keygen_matches_nists_encapsulation_keys() {
    let mut seen = 0;
    for line in include_str!("../../../third_party/acvp/mlkem-keygen.txt").lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let fields: std::vec::Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[1], "keyGen");
        let seed = hex(fields[2]).try_into().unwrap();
        let pair = MlKem768Pair::from_seed(&seed);
        assert_eq!(
            pair.encapsulation_key().as_slice(),
            hex(fields[3]),
            "tcId {}",
            fields[0]
        );
        seen += 1;
    }
    assert!(seen > 0, "no ACVP keyGen cases ran");
}

#[test]
#[expect(
    deprecated,
    reason = "ACVP decapsulation vectors supply expanded keys, not seeds"
)]
fn acvp_encapsulation_and_decapsulation_match_nist_including_implicit_rejection() {
    let mut seen = [0; 2];
    for line in include_str!("../../../third_party/acvp/mlkem-encapdecap.txt").lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let fields: std::vec::Vec<_> = line.split_whitespace().collect();
        match fields[1] {
            "encapsulation" => {
                assert_eq!(fields.len(), 6);
                let ek = hex(fields[2]).try_into().unwrap();
                let m = hex(fields[3]).try_into().unwrap();
                let (ct, ss) = mlkem768_encapsulate(&ek, &m).unwrap();
                assert_eq!(
                    ct.as_slice(),
                    hex(fields[4]),
                    "tcId {} ciphertext",
                    fields[0]
                );
                assert_eq!(ss.as_slice(), hex(fields[5]), "tcId {} secret", fields[0]);
                seen[0] += 1;
            }
            "decapsulation" => {
                assert_eq!(fields.len(), 5);
                let expanded = ml_kem::ExpandedDecapsulationKey::<MlKem768>::try_from(
                    hex(fields[2]).as_slice(),
                )
                .unwrap();
                let pair = MlKem768Pair {
                    dk: DecapsulationKey::from_expanded(&expanded).unwrap(),
                };
                let ct = hex(fields[3]).try_into().unwrap();
                assert_eq!(
                    pair.decapsulate(&ct).as_slice(),
                    hex(fields[4]),
                    "tcId {}",
                    fields[0]
                );
                seen[1] += 1;
            }
            _ => panic!("unknown ACVP function"),
        }
    }
    assert!(
        seen.into_iter().all(|count| count > 0),
        "an ACVP operation ran no cases"
    );
}

#[test]
fn encapsulation_key_modulus_check_refuses_the_first_unreduced_coefficient() {
    let mut ek = [0; MLKEM768_EK_LEN];
    ek[..2].copy_from_slice(&[0x00, 0x0d]);
    assert!(mlkem768_encapsulate(&ek, &[0; 32]).is_ok());
    ek[0] = 1;
    assert_eq!(mlkem768_encapsulate(&ek, &[0; 32]), Err(Error::Pqc));
}

/// Emit a deterministic KAT (fixed `d‖z` seed + fixed `m`) so the host
/// toolchain's ML-KEM-768 (OpenSSL, via `cryptography`) can be cross-checked
/// against this RustCrypto implementation off-device: same seed must give the
/// same `ek`, and the host must decapsulate this `ct` back to this `ss`. Run:
/// `cargo test -p rsk-crypto --target <host> --ignored mlkem_interop_kat -- --nocapture`
#[test]
#[ignore = "prints an interop KAT for the host ML-KEM cross-check"]
fn mlkem_interop_kat() {
    fn hex(b: &[u8]) -> std::string::String {
        let mut s = std::string::String::new();
        for x in b {
            s.push_str(&std::format!("{x:02x}"));
        }
        s
    }
    let seed = [0x5Au8; MLKEM768_SEED_LEN];
    let m = [0x3Cu8; 32];
    let pair = MlKem768Pair::from_seed(&seed);
    let ek = pair.encapsulation_key();
    let (ct, ss) = mlkem768_encapsulate(&ek, &m).unwrap();
    std::println!("SEED {}", hex(&seed));
    std::println!("EK {}", hex(&ek));
    std::println!("CT {}", hex(&ct));
    std::println!("SS {}", hex(&ss));
}
