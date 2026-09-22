// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::crt::crt_from_plain;
use crate::fixtures::SeqRng;
use crate::keygen::rsa_from_pqe;
use crate::vectors::hex;
use crate::verify::verify_pkcs1v15;
use crate::wycheproof::{Outcome, Sign, sign};

/// Every Wycheproof signing case through both of the card's PKCS#1 v1.5 signers —
/// the asm CRT one OpenPGP signs with, fed the DigestInfo a host sends, and the
/// full-key one PIV certificates use, fed that and the bare hash it infers the
/// DigestInfo from — byte for byte. The acceptable cases are a small modulus or
/// SHA-1, which the card signs, so they are held to the same bytes.
#[test]
fn wycheproof_signatures_are_byte_exact() {
    let cases = sign();
    assert_eq!(cases.len(), 152, "Wycheproof RSA signing cases");
    for case in &cases {
        let at = name(case);
        assert_ne!(
            case.result,
            Outcome::Invalid,
            "{at}: a signing case to refuse"
        );
        let blob: Vec<u8> = case.crt.iter().flat_map(|f| hex(f)).collect();
        let crt = crt_from_plain(&blob).unwrap_or_else(|e| panic!("{at}: CRT blob {e:?}"));
        let key = rsa_from_pqe(crate::RSA_PUB_EXP_BE, &hex(case.crt[0]), &hex(case.crt[1]))
            .unwrap_or_else(|| panic!("{at}: the key"));
        let di = hex(case.digest_info);
        let bare = &di[di.len() - hash_len(case.hash)..];
        let want = hex(case.sig);
        let mut out = [0u8; MAX_RSA_BYTES];
        let n = rsa_sign_crt(&crt, &di, &mut SeqRng(1), &mut out)
            .unwrap_or_else(|e| panic!("{at}: the CRT signer: {e:?}"));
        assert!(out[..n] == want[..], "{at}: the CRT signer");
        for (input, data) in [("DigestInfo", &di[..]), ("bare hash", bare)] {
            let n = rsa_sign(&key, data, &mut SeqRng(2), &mut out)
                .unwrap_or_else(|e| panic!("{at}: the full-key signer over the {input}: {e:?}"));
            assert!(
                out[..n] == want[..],
                "{at}: the full-key signer over the {input}"
            );
        }
    }
}

/// The type-1 limit the OpenPGP signer holds, at every width Wycheproof has a key
/// for: `k − 11` bytes sign as themselves, one more is `BadWidth`. A YubiKey 5.8.0
/// was measured at 2048 only; the arithmetic is the same at every size.
#[test]
fn wycheproof_keys_sign_up_to_k_minus_11_bytes_at_every_width() {
    let cases = sign();
    for bits in [1024u16, 1536, 2048, 3072, 4096] {
        let case = cases
            .iter()
            .find(|c| c.bits == bits)
            .expect("a key of that size");
        let blob: Vec<u8> = case.crt.iter().flat_map(|f| hex(f)).collect();
        let crt = crt_from_plain(&blob).unwrap();
        let mut n = [0u8; MAX_RSA_BYTES];
        let k = crate::modulus_be(&hex(case.crt[0]), &hex(case.crt[1]), &mut n).unwrap();
        assert_eq!(k, usize::from(bits) / 8, "RSA-{bits}: the modulus width");
        let most = vec![0x5Au8; k - PKCS1_V15_OVERHEAD];
        let mut out = [0u8; MAX_RSA_BYTES];
        let len = rsa_sign_crt(&crt, &most, &mut SeqRng(3), &mut out).unwrap();
        let (n, e) = (&n[..k], crate::RSA_PUB_EXP_BE);
        assert!(
            verify_pkcs1v15(n, e, &most, &out[..len]),
            "RSA-{bits}: k − 11 bytes"
        );
        let past = vec![0x5Au8; k - PKCS1_V15_OVERHEAD + 1];
        let got = rsa_sign_crt(&crt, &past, &mut SeqRng(4), &mut out);
        assert_eq!(got, Err(RsaError::BadWidth), "RSA-{bits}: one byte past it");
    }
}

fn name(case: &Sign) -> String {
    let (bits, tc, hash, comment) = (case.bits, case.tc_id, case.hash, case.comment);
    format!("RSA-{bits} {hash} tcId {tc} ({comment})")
}

fn hash_len(hash: &str) -> usize {
    match hash {
        "SHA-1" => 20,
        "SHA-224" => 28,
        "SHA-256" => 32,
        "SHA-384" => 48,
        "SHA-512" => 64,
        h => panic!("a hash the signer does not recognise: {h}"),
    }
}
