// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn register<S: Storage>(fs: &mut Fs<S>, rng: &mut SeqRng, request: &[u8]) -> Vec<u8> {
    let mut state = crate::FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs,
        rng,
        state: &mut state,
        now_ms: 1000,
    };
    let mut out = [0; 1024];
    let n = make_credential(&mut ctx, request, &mut out).unwrap();
    let mut decoder = Decoder::new(&out[..n]);
    decoder.map().unwrap();
    assert_eq!(decoder.u8().unwrap(), 1);
    assert_eq!(decoder.str().unwrap(), "packed");
    assert_eq!(decoder.u8().unwrap(), 2);
    let ad = decoder.bytes().unwrap();
    let len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    ad[55..55 + len].to_vec()
}

#[test]
fn the_exclude_list_finds_a_resident_id_in_the_second_slot() {
    let mut fs = Fs::new(RamStorage::new());
    crate::tests::uv_optional(&mut fs);
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let mut foreign = build_request(true);
    let at = foreign
        .windows(11)
        .position(|v| v == b"example.com")
        .unwrap();
    foreign[at..at + 11].copy_from_slice(b"foreign.com");
    register(&mut fs, &mut rng, &foreign);
    let id = register(&mut fs, &mut rng, &build_request(true));
    assert!(fs.has_data(crate::consts::EF_CRED + 1));
    let mut state = crate::FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 1000,
    };
    assert_eq!(
        make_credential(
            &mut ctx,
            &mc_build_exclude(&[("public-key", &id)]),
            &mut [0; 1024]
        ),
        Err(CtapError::CredentialExcluded)
    );
}

#[test]
fn a_matching_truncated_prefix_cannot_hide_an_unread_excluded_passkey() {
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    crate::tests::uv_optional(&mut fs);
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    for uid in [1, 2] {
        let mut request = build_request(true);
        let at = request
            .windows(5)
            .position(|v| v == [0x44, 1, 2, 3, 4])
            .unwrap();
        request[at + 1] = uid;
        register(&mut fs, &mut rng, &request);
    }
    let fid = crate::consts::EF_CRED;
    let first = medium.value(fid).unwrap();
    fs.put(fid, &first[..32]).unwrap();
    crate::credmgmt::settle_rp_records(&mut fs).unwrap();
    assert_eq!(
        crate::credential::rp_count(&mut fs, &sha256(b"example.com")),
        Ok(1)
    );
    medium.stick(Some(fid + 1));
    let generation = fs.write_gen();
    let mut state = crate::FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 1000,
    };
    assert_eq!(
        make_credential(
            &mut ctx,
            &mc_build_exclude(&[("public-key", &[0x77; 42])]),
            &mut [0; 1024]
        ),
        Err(CtapError::Other)
    );
    assert_eq!(fs.write_gen(), generation);
    medium.stick(None);
    assert!(!fs.has_data(fid + 2));
}

#[test]
#[cfg(not(feature = "largeblob-ext"))]
fn the_unadvertised_large_blob_extension_is_skipped_at_any_type() {
    let mut request = build_request(false);
    request[0] += 1;
    request.extend_from_slice(b"\x06\xa1\x69largeBlob\xf6");
    assert!(!run(&request).0.is_empty());
}

#[test]
#[cfg(not(feature = "largeblob-ext"))]
fn a_resident_registration_emits_a_large_blob_key_only_when_requested() {
    for resident in [false, true] {
        for requested in [false, true] {
            let mut request = build_request(false);
            if requested {
                request[0] += 1;
                request.extend_from_slice(b"\x06\xa1\x6clargeBlobKey\xf5");
            }
            if resident {
                request[0] += 1;
                request.extend_from_slice(b"\x07\xa1\x62rk\xf5");
            }
            if requested && !resident {
                assert_eq!(run_err(&request), CtapError::InvalidOption);
                continue;
            }
            let (response, _) = run(&request);
            let mut decoder = Decoder::new(&response);
            let mut key = None;
            for _ in 0..decoder.map().unwrap().unwrap() {
                if decoder.u8().unwrap() == 5 {
                    key = Some(decoder.bytes().unwrap().len());
                } else {
                    decoder.skip().unwrap();
                }
            }
            assert_eq!(key, (resident && requested).then_some(32));
        }
    }
}

#[test]
fn one_missing_hmac_salt_is_refused_before_pin_authentication() {
    for missing in [2, 3] {
        let mut request = build_request(false);
        request[0] += 3;
        let mut extra = [0; 128];
        let mut encoder = Encoder::new(Cursor::new(&mut extra[..]));
        encoder.u8(6).unwrap().map(2).unwrap();
        encoder.str("hmac-secret").unwrap().bool(true).unwrap();
        encoder.str("hmac-secret-mc").unwrap().map(2).unwrap();
        encoder.u8(if missing == 2 { 3 } else { 2 }).unwrap();
        encoder.bytes(&[0; 32]).unwrap();
        encoder.u8(4).unwrap().u8(2).unwrap();
        encoder.u8(8).unwrap().bytes(&[0; 32]).unwrap();
        encoder.u8(9).unwrap().u8(2).unwrap();
        let extra_len = encoder.writer().position();
        request.extend_from_slice(&extra[..extra_len]);
        assert_eq!(run_err(&request), CtapError::MissingParameter);
    }
}
