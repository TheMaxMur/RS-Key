// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn update_refuses_a_record_that_disappears_or_shortens_after_lookup() {
    use rsk_fs::read_change::ChangingRead;
    for (replacement, expected) in [
        (None, CtapError::NoCredentials),
        (Some(&[0; RECORD_PREFIX - 1][..]), CtapError::NotAllowed),
    ] {
        let (backend, control) = ChangingRead::new();
        let mut fs = Fs::new(backend);
        fs.scan();
        let mut rng = SeqRng(1);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        let (id, ..) = register(&mut fs, &mut rng, "example.com", &[1], "alice");
        let mut original = [0; CRED_REC_MAX];
        let n = fs.read(EF_CRED, &mut original).unwrap();
        let tag = crate::credential::cred_store_state(&mut fs).unwrap();
        let generation = fs.write_gen();
        control.replace_on_read(EF_CRED, 1, replacement);
        let request = cm_request(
            0x07,
            Some(&subpara_update(&id, &[1], "changed", "Changed")),
            &TOKEN,
        );
        let mut out = [0xa5; 512];
        let mut state = armed(PERM_CM);
        assert_eq!(run(&mut fs, &mut state, &request, &mut out), Err(expected));
        assert!(control.served());
        assert_eq!(out, [0xa5; 512]);
        assert_eq!(fs.write_gen(), generation);
        assert_eq!(crate::credential::cred_store_state(&mut fs).unwrap(), tag);
        let mut physical = [0; CRED_REC_MAX];
        assert_eq!(fs.into_storage().value(EF_CRED, &mut physical), Some(n));
        assert_eq!(physical, original);
        assert!(state.paut.in_use);
    }
}

#[test]
fn enumeration_does_not_publish_a_record_that_disappears_after_its_snapshot() {
    use rsk_fs::read_change::ChangingRead;
    for (fid, skip, subcommand) in [(EF_RP, 0, 0x02), (EF_CRED, 1, 0x04)] {
        let (backend, control) = ChangingRead::new();
        let mut fs = Fs::new(backend);
        fs.scan();
        let mut rng = SeqRng(1);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        register(&mut fs, &mut rng, "example.com", &[1], "alice");
        let tag = crate::credential::cred_store_state(&mut fs).unwrap();
        let generation = fs.write_gen();
        let para = subpara_rpidhash(&sha256(b"example.com"));
        let request = cm_request(
            subcommand,
            if subcommand == 0x04 {
                Some(&para)
            } else {
                None
            },
            &TOKEN,
        );
        control.replace_on_read(fid, skip, None);
        let mut out = [0xa5; 512];
        assert_eq!(
            run(&mut fs, &mut armed(PERM_CM), &request, &mut out),
            Err(CtapError::NoCredentials)
        );
        assert!(control.served());
        assert_eq!(out, [0xa5; 512]);
        assert_eq!(fs.write_gen(), generation);
        assert_eq!(crate::credential::cred_store_state(&mut fs).unwrap(), tag);
    }
}

#[test]
fn short_records_do_not_decrement_or_invent_relying_party_counts() {
    let (mut fs, mut rng) = setup();
    register(&mut fs, &mut rng, "example.com", &[1], "alice");
    let hash = sha256(b"example.com");
    let short_rp = [1; RP_PREFIX - 1];
    fs.put(EF_RP + 1, &short_rp).unwrap();
    fs.put(EF_CRED + 1, &[0; RECORD_PREFIX - 1]).unwrap();
    let mut original = [0; RP_REC_MAX];
    let n = fs.read(EF_RP, &mut original).unwrap();
    let generation = fs.write_gen();
    assert_eq!(decrement_rp(&mut fs, &sha256(b"absent.com")), Ok(()));
    assert_eq!(fs.write_gen(), generation);
    assert_eq!(settle_rp_records(&mut fs), Ok(()));
    assert_eq!(crate::credential::rp_count(&mut fs, &hash), Ok(1));
    let mut after = [0; RP_REC_MAX];
    assert_eq!(fs.read(EF_RP, &mut after), Some(n));
    assert_eq!(after, original);
    let mut short = [0; RP_PREFIX];
    assert_eq!(fs.read(EF_RP + 1, &mut short), Some(short_rp.len()));
    assert_eq!(&short[..short_rp.len()], short_rp);
}

#[test]
fn relying_parties_with_the_same_index_prefix_keep_distinct_enumerations() {
    let domains = ["coverage-24020.example", "coverage-105130.example"];
    let hashes = domains.map(|name| sha256(name.as_bytes()));
    assert_eq!(&hashes[0][..4], &hashes[1][..4]);
    assert_ne!(hashes[0], hashes[1]);
    let (mut fs, mut rng) = setup();
    let ids = [
        register(&mut fs, &mut rng, domains[0], &[1], "alice").0,
        register(&mut fs, &mut rng, domains[1], &[2], "bob").0,
    ];
    let generation = fs.write_gen();
    for i in 0..domains.len() {
        let mut out = [0; 512];
        let mut state = armed(PERM_CM);
        let request = cm_request(0x04, Some(&subpara_rpidhash(&hashes[i])), &TOKEN);
        let n = run(&mut fs, &mut state, &request, &mut out).unwrap();
        assert_eq!(enumerated_cred_id(&out[..n]), ids[i]);
        assert_eq!(parse_cred(&out[..n], true).0, vec![i as u8 + 1]);
        assert_eq!(parse_cred(&out[..n], true).3, Some(1));
        assert_eq!(
            run(&mut fs, &mut state, &cm_next(0x05), &mut out),
            Err(CtapError::NotAllowed)
        );
        assert_eq!(fs.write_gen(), generation);
    }
}

#[test]
fn deleting_a_nonresident_length_id_changes_neither_store_nor_grant() {
    let (mut fs, mut rng) = setup();
    register(&mut fs, &mut rng, "example.com", &[1], "alice");
    let generation = fs.write_gen();
    let tag = crate::credential::cred_store_state(&mut fs).unwrap();
    for width in [0, 1, CRED_RESIDENT_LEN - 1, CRED_RESIDENT_LEN + 1] {
        let request = cm_request(0x06, Some(&subpara_cred(&vec![0x55; width])), &TOKEN);
        let mut state = armed(PERM_CM);
        let mut out = [0xa5; 512];
        assert_eq!(
            run(&mut fs, &mut state, &request, &mut out),
            Err(CtapError::NoCredentials)
        );
        assert_eq!(out, [0xa5; 512]);
        assert_eq!(fs.write_gen(), generation);
        assert_eq!(crate::credential::cred_store_state(&mut fs).unwrap(), tag);
        assert!(state.paut.in_use);
        assert_eq!(state.paut.token, TOKEN);
    }
}

#[test]
fn enumeration_derives_an_uncached_point_and_omits_absent_user_fields() {
    use crate::credential::{CredExt, CredInput, credential_create, credential_store};
    use p256::elliptic_curve::sec1::ToSec1Point;

    for (uid, name, display) in [
        (&[1][..], "", ""),
        (&[1][..], "", "Alice"),
        (&[][..], "", ""),
    ] {
        let (mut fs, mut rng) = setup();
        let seed = crate::seed::load_keydev(&dev(), &mut fs).unwrap();
        let hash = sha256(b"example.com");
        let input = CredInput {
            rp_id: "example.com",
            user_id: uid,
            user_name: name,
            user_display_name: display,
            use_sign_count: false,
            rk: true,
            created_ms: 1,
            alg: ALG_ES256,
            curve: crate::consts::CURVE_P256 as i64,
            ext: CredExt::default(),
        };
        let mut boxed = [0; 512];
        let n = credential_create(
            seed.expose(),
            &dev(),
            &input,
            &hash,
            &[0x11; 12],
            &mut boxed,
        )
        .unwrap();
        credential_store(
            seed.expose(),
            &dev(),
            &mut fs,
            &mut rng,
            &boxed[..n],
            &hash,
            input.rp_id,
            uid,
            &[],
        )
        .unwrap();
        let id = crate::credential::derive_resident(&boxed[..n], &dev());
        let scalar = crate::keyderiv::fido_load_key(seed.expose(), &id).unwrap();
        let point = p256::SecretKey::from_slice(&scalar.expose()[..32])
            .unwrap()
            .public_key()
            .to_sec1_point(false);
        let mut out = [0; 512];
        let request = cm_request(0x04, Some(&subpara_rpidhash(&hash)), &TOKEN);
        let n = run(&mut fs, &mut armed(PERM_CM), &request, &mut out).unwrap();
        let mut d = Decoder::new(&out[..n]);
        d.map().unwrap();
        assert_eq!(d.u8().unwrap(), 6);
        assert_eq!(
            d.map().unwrap(),
            Some(u64::from(!uid.is_empty()) + u64::from(!display.is_empty()))
        );
        if !uid.is_empty() {
            assert_eq!(d.str().unwrap(), "id");
            assert_eq!(d.bytes().unwrap(), uid);
        }
        if !display.is_empty() {
            assert_eq!(d.str().unwrap(), "displayName");
            assert_eq!(d.str().unwrap(), display);
        }
        assert_eq!(d.u8().unwrap(), 7);
        d.skip().unwrap();
        assert_eq!(d.u8().unwrap(), 8);
        assert_eq!(d.map().unwrap(), Some(5));
        for _ in 0..3 {
            d.skip().unwrap();
            d.skip().unwrap();
        }
        assert_eq!(d.i8().unwrap(), -2);
        assert_eq!(d.bytes().unwrap(), point.x().unwrap().as_slice());
        assert_eq!(d.i8().unwrap(), -3);
        assert_eq!(d.bytes().unwrap(), point.y().unwrap().as_slice());
    }
}

#[test]
fn updating_an_unauthentic_credential_preserves_its_record_and_store_tag() {
    let (mut fs, mut rng) = setup();
    let (id, ..) = register(&mut fs, &mut rng, "example.com", &[1], "alice");
    let mut record = [0; CRED_REC_MAX];
    let length = fs.read(EF_CRED, &mut record).unwrap();
    let original = record[..length].to_vec();
    let boxed = cred_record_box(&original);
    assert!(boxed.len() > crate::credential::IV_LEN);
    assert!(cred_record_pubkey(&original).is_some());
    let ciphertext = length - boxed.len() + crate::credential::IV_LEN;
    record[ciphertext] ^= 1;
    let corrupt = &record[..length];
    assert_eq!(&corrupt[..RECORD_PREFIX], &original[..RECORD_PREFIX]);
    assert_eq!(cred_record_pubkey(corrupt), cred_record_pubkey(&original));
    fs.put(EF_CRED, corrupt).unwrap();
    let tag = crate::credential::cred_store_state(&mut fs).unwrap();
    let generation = fs.write_gen();
    let request = cm_request(
        0x07,
        Some(&subpara_update(&id, &[1], "alice2", "Alice Two")),
        &TOKEN,
    );
    let mut state = armed(PERM_CM);
    let mut out = [0xa5; 512];
    assert_eq!(
        run(&mut fs, &mut state, &request, &mut out),
        Err(CtapError::NotAllowed)
    );
    assert_eq!(out, [0xa5; 512]);
    let mut after = [0; CRED_REC_MAX];
    assert_eq!(fs.read(EF_CRED, &mut after), Some(length));
    assert_eq!(&after[..length], corrupt);
    assert_eq!(fs.write_gen(), generation);
    assert_eq!(crate::credential::cred_store_state(&mut fs).unwrap(), tag);

    fs.put(EF_CRED, &original).unwrap();
    assert_eq!(run(&mut fs, &mut armed(PERM_CM), &request, &mut out), Ok(0));
    let n = run(
        &mut fs,
        &mut armed(PERM_CM),
        &cm_request(
            0x04,
            Some(&subpara_rpidhash(&sha256(b"example.com"))),
            &TOKEN,
        ),
        &mut out,
    )
    .unwrap();
    assert_eq!(enumerated_cred_id(&out[..n]), id);
    assert_eq!(cred_user_name(&out[..n]), "alice2");
    assert_ne!(crate::credential::cred_store_state(&mut fs).unwrap(), tag);
}

#[test]
fn an_unopenable_relying_party_cannot_enter_the_authenticated_response() {
    let (mut fs, mut rng) = setup();
    register(&mut fs, &mut rng, "example.com", &[1], "alice");
    register(&mut fs, &mut rng, "other.com", &[2], "bob");
    let mut record = [0; RP_REC_MAX];
    let length = fs.read(EF_RP, &mut record).unwrap();
    let original = record[..length].to_vec();
    let mut corrupt = original[..RP_PREFIX].to_vec();
    corrupt.push(0xff);
    fs.put(EF_RP, &corrupt).unwrap();
    let tag = crate::credential::cred_store_state(&mut fs).unwrap();
    let generation = fs.write_gen();
    let request = cm_request(0x02, None, &TOKEN);
    let mut out = [0xa5; 512];
    assert_eq!(
        run(&mut fs, &mut armed(PERM_CM), &request, &mut out),
        Err(CtapError::Other)
    );
    assert_eq!(out, [0xa5; 512]);
    let mut after = [0; RP_REC_MAX];
    assert_eq!(fs.read(EF_RP, &mut after), Some(corrupt.len()));
    assert_eq!(&after[..corrupt.len()], corrupt);
    assert_eq!(fs.write_gen(), generation);
    assert_eq!(crate::credential::cred_store_state(&mut fs).unwrap(), tag);

    fs.put(EF_RP, &original).unwrap();
    let mut state = armed(PERM_CM);
    let n = run(&mut fs, &mut state, &request, &mut out).unwrap();
    assert_eq!(
        parse_rp(&out[..n], true),
        ("example.com".into(), sha256(b"example.com"), Some(2))
    );
    let n = run(&mut fs, &mut state, &cm_next(0x03), &mut out).unwrap();
    assert_eq!(
        parse_rp(&out[..n], false),
        ("other.com".into(), sha256(b"other.com"), None)
    );
    assert_eq!(crate::credential::cred_store_state(&mut fs).unwrap(), tag);
}

#[test]
fn malformed_request_ordering_preserves_the_authorized_walk_and_store() {
    let (mut fs, mut rng) = setup();
    register(&mut fs, &mut rng, "example.com", &[1], "alice");
    register(&mut fs, &mut rng, "other.com", &[2], "bob");
    let mut state = armed(PERM_CM);
    let mut out = [0u8; 512];
    run(
        &mut fs,
        &mut state,
        &cm_request(0x02, None, &TOKEN),
        &mut out,
    )
    .unwrap();
    let walk = (
        state.cm.rp_counter,
        state.cm.rp_total,
        state.cm.rp_next_slot,
        state.cm.last_leg_ms,
    );
    let generation = fs.write_gen();
    for (req, error) in [
        (&[0xA1, 2, 0xA0][..], CtapError::MissingParameter),
        (&[0xA2, 1, 2, 1, 2], CtapError::InvalidCbor),
        (&[0xA2, 1, 2, 0, 0], CtapError::InvalidCbor),
        (&[0xA3, 1, 2, 4, 0x40, 3, 2], CtapError::InvalidCbor),
    ] {
        out.fill(0xA5);
        assert_eq!(run(&mut fs, &mut state, req, &mut out), Err(error));
        assert_eq!(out, [0xA5; 512]);
        assert_eq!(
            (
                state.cm.rp_counter,
                state.cm.rp_total,
                state.cm.rp_next_slot,
                state.cm.last_leg_ms
            ),
            walk
        );
        assert_eq!(fs.write_gen(), generation);
        assert_eq!(state.paut.token, TOKEN);
        assert!(state.paut.in_use);
    }
    let n = run(&mut fs, &mut state, &cm_next(0x03), &mut out).unwrap();
    assert_eq!(parse_rp(&out[..n], false).0, "other.com");
}

#[test]
fn oversized_authenticated_subparameters_never_mutate_credentials() {
    let (mut fs, mut rng) = setup();
    let (id, ..) = register(&mut fs, &mut rng, "example.com", &[1], "alice");
    let hash = sha256(b"example.com");
    let generation = fs.write_gen();
    let tag = crate::credential::cred_store_state(&mut fs).unwrap();
    for (subcommand, mut para) in [
        (0x04, subpara_rpidhash(&hash)),
        (0x06, subpara_cred(&id)),
        (0x07, subpara_update(&id, &[1], "alice2", "Alice Two")),
    ] {
        para[0] += 1;
        let mut extra = [0u8; MAX_RAW_SUBPARA + 16];
        let n = {
            let mut enc = Encoder::new(Cursor::new(&mut extra[..]));
            enc.u8(99).unwrap().bytes(&[0; MAX_RAW_SUBPARA]).unwrap();
            enc.writer().position()
        };
        para.extend_from_slice(&extra[..n]);
        let mut state = armed(PERM_CM);
        let mut out = [0xA5; 512];
        assert_eq!(
            run(
                &mut fs,
                &mut state,
                &cm_request(subcommand, Some(&para), &TOKEN),
                &mut out
            ),
            Err(CtapError::RequestTooLarge)
        );
        assert_eq!(out, [0xA5; 512]);
        assert_eq!(fs.write_gen(), generation);
        assert_eq!(crate::credential::cred_store_state(&mut fs).unwrap(), tag);
    }
    let mut state = armed(PERM_CM);
    let mut out = [0u8; 512];
    let n = run(
        &mut fs,
        &mut state,
        &cm_request(0x04, Some(&subpara_rpidhash(&hash)), &TOKEN),
        &mut out,
    )
    .unwrap();
    assert_eq!(enumerated_cred_id(&out[..n]), id);
    assert_eq!(cred_user_name(&out[..n]), "alice");
}

#[test]
fn short_and_zero_count_records_do_not_enter_authorized_lists() {
    let (mut fs, mut rng) = setup();
    let (id, ..) = register(&mut fs, &mut rng, "example.com", &[1], "alice");
    let hash = sha256(b"example.com");
    fs.put(EF_RP + 1, &[1]).unwrap();
    fs.put(EF_RP + 2, &[0; RP_PREFIX]).unwrap();
    fs.put(EF_CRED + 1, &hash).unwrap();
    fs.put(EF_CRED + 2, &[1, 2, 3]).unwrap();
    let generation = fs.write_gen();
    let mut state = armed(PERM_CM);
    let mut out = [0u8; 512];
    let n = run(
        &mut fs,
        &mut state,
        &cm_request(0x02, None, &TOKEN),
        &mut out,
    )
    .unwrap();
    assert_eq!(
        parse_rp(&out[..n], true),
        ("example.com".into(), hash, Some(1))
    );
    assert_eq!(
        run(&mut fs, &mut state, &cm_next(0x03), &mut out),
        Err(CtapError::NotAllowed)
    );
    let n = run(
        &mut fs,
        &mut state,
        &cm_request(0x04, Some(&subpara_rpidhash(&hash)), &TOKEN),
        &mut out,
    )
    .unwrap();
    assert_eq!(enumerated_cred_id(&out[..n]), id);
    assert_eq!(parse_cred(&out[..n], true).3, Some(1));
    assert_eq!(
        run(&mut fs, &mut state, &cm_next(0x05), &mut out),
        Err(CtapError::NotAllowed)
    );
    assert_eq!(fs.write_gen(), generation);
}

#[test]
fn a_short_occupied_record_is_not_a_resident_id_match() {
    for n in [0, 1, RECORD_PREFIX - 1, RECORD_PREFIX] {
        let mut fs = Fs::new(RamStorage::new());
        fs.put(EF_CRED, &vec![0; n]).unwrap();
        let generation = fs.write_gen();
        assert_eq!(find_resident(&mut fs, &[0x42; CRED_RESIDENT_LEN]), Ok(None));
        assert_eq!(fs.write_gen(), generation);
    }
}
