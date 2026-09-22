// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::crt::crt_from_plain;
use crate::fixtures::SeqRng;
use crate::keygen::rsa_from_pqe;
use crate::vectors::hex;
use crate::wycheproof::{Outcome, Sign, sign};

/// Every Wycheproof signing case through both of the card's PKCS#1 v1.5 signers —
/// the asm CRT one OpenPGP signs with and the full-key one PIV certificates use —
/// fed the DigestInfo a host sends and the bare hash alike, byte for byte. Its
/// acceptable cases are a small modulus or SHA-1, which the card signs, so they
/// are held to the same bytes.
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
        for (input, data) in [("DigestInfo", &di[..]), ("bare hash", bare)] {
            let n = rsa_sign_crt(&crt, data, &mut SeqRng(1), &mut out)
                .unwrap_or_else(|e| panic!("{at}: the CRT signer over the {input}: {e:?}"));
            assert!(
                out[..n] == want[..],
                "{at}: the CRT signer over the {input}"
            );
            let n = rsa_sign(&key, data, &mut SeqRng(2), &mut out)
                .unwrap_or_else(|e| panic!("{at}: the full-key signer over the {input}: {e:?}"));
            assert!(
                out[..n] == want[..],
                "{at}: the full-key signer over the {input}"
            );
        }
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
