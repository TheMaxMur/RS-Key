// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn a_supported_algorithm_can_precede_duplicates_and_other_offers() {
    let algs = enc(|e| {
        e.array(3)
            .unwrap()
            .i64(ALG_ESP256_SPLIT_ARKG)
            .unwrap()
            .i64(ALG_ESP256_SPLIT_ARKG)
            .unwrap()
            .i64(ALG_ES256)
            .unwrap();
    });
    let input = McInput {
        present: true,
        algs: Some(&algs),
        flags: None,
    };
    let selected = negotiate(&input, ALG_ES256).unwrap().unwrap();
    assert_eq!(selected.alg, ALG_ESP256_SPLIT_ARKG);
    assert_eq!(selected.flags, FLAGS_REQUIRE_UP);
}

#[test]
fn direct_key_generation_and_signing_refuse_inconsistent_arguments() {
    for request in [
        KeyRequest { alg: 0, flags: 1 },
        KeyRequest {
            alg: ALG_ESP256_SPLIT_ARKG,
            flags: 24,
        },
    ] {
        assert_eq!(
            generate(
                &[0x43; 32],
                b"credential",
                &[0x4B; 32],
                request,
                &mut SeqRng(7)
            )
            .err(),
            Some(CtapError::Other)
        );
    }
    for (kh, tbs) in [
        (None, Some(&[0xA6; PREHASH_LEN][..])),
        (Some(&[0; HANDLE_LEN][..]), None),
        (None, None),
    ] {
        let input = GaInput {
            present: true,
            kh,
            tbs,
            args: None,
        };
        assert_eq!(
            sign(&input, &[0x43; 32], b"credential", &[0x4B; 32], true, false).err(),
            Some(CtapError::InvalidOption)
        );
    }
}

#[test]
fn a_valid_mac_does_not_authorize_the_wrong_parameter_array_count() {
    let secret = credential_secret(&[0x43; 32], b"credential");
    let rp = [0x4B; 32];
    let original = enc(|e| {
        e.array(3)
            .unwrap()
            .i64(ALG_ESP256_SPLIT_ARKG)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&[7; AUX_IKM_LEN])
            .unwrap();
    });
    for count in [2, 4] {
        let mut params = original.clone();
        params[0] = 0x80 | count;
        let mut handle = handle_mac(&secret, &params, &rp).unwrap().to_vec();
        handle.extend_from_slice(&params);
        assert_eq!(handle.len(), HANDLE_LEN);
        assert_eq!(
            open_handle(&secret, &handle, &rp).err(),
            Some(CtapError::InvalidCredential)
        );
    }
}

#[test]
fn unknown_nested_make_credential_options_preserve_the_following_preview_fields() {
    let algs = enc(|e| {
        e.array(1).unwrap().i64(ALG_ESP256_SPLIT_ARKG).unwrap();
    });
    let body = enc(|e| {
        e.map(3).unwrap().i64(99).unwrap();
        e.array(2).unwrap().null().unwrap().map(0).unwrap();
        e.i64(KEY_ALG)
            .unwrap()
            .array(1)
            .unwrap()
            .i64(ALG_ESP256_SPLIT_ARKG)
            .unwrap();
        e.i64(KEY_FLAGS).unwrap().u8(1).unwrap();
    });
    let mut decoder = Decoder::new(&body);
    let input = parse_mc(&mut decoder).unwrap();
    assert!(input.present);
    assert_eq!(input.algs, Some(algs.as_slice()));
    assert_eq!(input.flags, Some(1));
    assert_eq!(decoder.position(), body.len());
}

#[test]
fn unknown_nested_assertion_options_preserve_the_following_preview_fields() {
    let body = enc(|e| {
        e.map(4).unwrap().i64(99).unwrap();
        e.array(2).unwrap().null().unwrap().map(0).unwrap();
        e.i64(KEY_KH).unwrap().bytes(b"kh").unwrap();
        e.i64(KEY_TBS).unwrap().bytes(b"tbs").unwrap();
        e.i64(KEY_ARGS).unwrap().bytes(b"args").unwrap();
    });
    let mut decoder = Decoder::new(&body);
    let input = parse_ga(&mut decoder).unwrap();
    assert!(input.present);
    assert_eq!(input.kh, Some(&b"kh"[..]));
    assert_eq!(input.tbs, Some(&b"tbs"[..]));
    assert_eq!(input.args, Some(&b"args"[..]));
    assert_eq!(decoder.position(), body.len());
}

#[test]
fn a_truncated_unknown_preview_option_is_invalid_cbor_in_both_commands() {
    let body = b"\xa1\x18\x63\x82\xf6";
    assert_eq!(
        parse_mc(&mut Decoder::new(body)).err(),
        Some(CtapError::InvalidCbor)
    );
    assert_eq!(
        parse_ga(&mut Decoder::new(body)).err(),
        Some(CtapError::InvalidCbor)
    );
}
