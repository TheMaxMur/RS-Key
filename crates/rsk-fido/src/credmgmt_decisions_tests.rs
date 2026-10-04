// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

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
