// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn attest_cannot_certify_zero_padded_damaged_subject_fields() {
    for (fid, width) in [
        (EF_UIF_SIG, 2),
        (EF_SIG_COUNT, 3),
        (EF_FP_SIG, FP_LEN),
        (EF_TS_SIG, TS_LEN),
    ] {
        for len in [0, width - 1, width + 1] {
            with_card(|app, fs| {
                verify(app, fs, PW3_MODE83);
                generate(app, fs, CRT_SIG, P256);
                verify(app, fs, PW1_MODE81);
                fs.put(fid, &vec![0; len]).unwrap();
                let generation = fs.write_gen();
                assert_eq!(
                    attest(app, fs, KEY_REF_SIG),
                    Sw::MEMORY_FAILURE,
                    "FID {fid:04x}, width {len}"
                );
                assert_eq!(fs.write_gen(), generation);
                assert!(occurrence(app, fs, 2).is_empty());
            });
        }
    }
}

#[test]
fn an_unrelated_damaged_signature_counter_cannot_block_dec_or_aut_attestation() {
    for (crt, algorithm, key_ref, occurrence_index) in [
        (CRT_DEC, P256_ECDH, KEY_REF_DEC, 1),
        (CRT_AUT, P256, KEY_REF_AUT, 0),
    ] {
        with_card(|app, fs| {
            verify(app, fs, PW3_MODE83);
            generate(app, fs, crt, algorithm);
            verify(app, fs, PW1_MODE81);
            fs.put(EF_SIG_COUNT, &[]).unwrap();
            assert_eq!(attest(app, fs, key_ref), Sw::OK);
            assert!(!occurrence(app, fs, occurrence_index).is_empty());
            assert_eq!(fs.read(EF_SIG_COUNT, &mut [0; 3]), Some(0));
        });
    }
}
