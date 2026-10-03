// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn hex(value: &str) -> Vec<u8> {
    let value = if value == "-" { "" } else { value };
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn cases(text: &str) -> impl Iterator<Item = Vec<&str>> {
    text.lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(|line| line.split_whitespace().collect())
}

#[test]
fn wycheproof_aes256_gcm_authenticates_and_matches_ciphertexts() {
    let mut valid = 0;
    let mut invalid = 0;
    for fields in cases(include_str!(
        "../../../third_party/wycheproof/aes256-gcm.txt"
    )) {
        let key: [u8; 32] = hex(fields[3]).try_into().unwrap();
        let nonce: [u8; 12] = hex(fields[4]).try_into().unwrap();
        let aad = hex(fields[5]);
        let message = hex(fields[6]);
        let ciphertext = hex(fields[7]);
        let tag: [u8; 16] = hex(fields[8]).try_into().unwrap();
        let mut decrypted = ciphertext.clone();
        let result = aes256gcm_decrypt(&key, &nonce, &aad, &mut decrypted, &tag);
        match fields[2] {
            "valid" => {
                valid += 1;
                assert_eq!(result, Ok(()), "tcId {}", fields[1]);
                assert_eq!(decrypted, message, "tcId {} plaintext", fields[1]);
                let mut encrypted = message;
                assert_eq!(
                    aes256gcm_encrypt(&key, &nonce, &aad, &mut encrypted),
                    tag,
                    "tcId {} tag",
                    fields[1]
                );
                assert_eq!(encrypted, ciphertext, "tcId {} ciphertext", fields[1]);
            }
            "invalid" => {
                invalid += 1;
                assert_eq!(
                    result,
                    Err(Error::Decrypt),
                    "tcId {} accepted forgery",
                    fields[1]
                );
            }
            result => panic!("unknown Wycheproof result {result}"),
        }
    }
    assert!(valid > 0 && invalid > 0);
}

#[test]
fn wycheproof_hmac_matches_valid_tags_and_refuses_forged_tags() {
    for (text, hash) in [
        (
            include_str!("../../../third_party/wycheproof/hmac-sha1.txt"),
            1,
        ),
        (
            include_str!("../../../third_party/wycheproof/hmac-sha256.txt"),
            256,
        ),
        (
            include_str!("../../../third_party/wycheproof/hmac-sha512.txt"),
            512,
        ),
    ] {
        let mut valid = 0;
        let mut invalid = 0;
        for fields in cases(text) {
            let key = hex(fields[3]);
            let message = hex(fields[4]);
            let tag = hex(fields[5]);
            let actual = match hash {
                1 => hmac_sha1(&key, &message).to_vec(),
                256 => hmac_sha256(&key, &message).to_vec(),
                512 => hmac_sha512(&key, &message).to_vec(),
                _ => unreachable!(),
            };
            match fields[2] {
                "valid" => {
                    valid += 1;
                    assert!(ct_eq(&actual, &tag), "{} tcId {}", fields[0], fields[1]);
                }
                "invalid" => {
                    invalid += 1;
                    assert!(
                        !ct_eq(&actual, &tag),
                        "{} tcId {} accepted forgery",
                        fields[0],
                        fields[1]
                    );
                }
                result => panic!("unknown Wycheproof result {result}"),
            }
        }
        assert!(valid > 0 && invalid > 0);
    }
}

#[test]
fn wycheproof_hkdf_matches_outputs_and_refuses_length_overflow() {
    for (text, sha512) in [
        (
            include_str!("../../../third_party/wycheproof/hkdf-sha256.txt"),
            false,
        ),
        (
            include_str!("../../../third_party/wycheproof/hkdf-sha512.txt"),
            true,
        ),
    ] {
        let mut valid = 0;
        let mut invalid = 0;
        for fields in cases(text) {
            let ikm = hex(fields[3]);
            let salt = hex(fields[4]);
            let info = hex(fields[5]);
            let mut out = vec![0u8; fields[6].parse().unwrap()];
            let result = if sha512 {
                hkdf_sha512(&salt, &ikm, &info, &mut out)
            } else {
                hkdf_sha256(&salt, &ikm, &info, &mut out)
            };
            match fields[2] {
                "valid" => {
                    valid += 1;
                    assert_eq!(result, Ok(()), "{} tcId {}", fields[0], fields[1]);
                    assert_eq!(out, hex(fields[7]), "{} tcId {}", fields[0], fields[1]);
                }
                "invalid" => {
                    invalid += 1;
                    assert_eq!(
                        result,
                        Err(Error::BadLength),
                        "{} tcId {} accepted overflow",
                        fields[0],
                        fields[1]
                    );
                }
                result => panic!("unknown Wycheproof result {result}"),
            }
        }
        assert!(valid > 0 && invalid > 0);
    }
}
