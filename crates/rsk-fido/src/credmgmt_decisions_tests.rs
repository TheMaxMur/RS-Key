// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

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
