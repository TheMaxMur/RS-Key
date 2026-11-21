// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn both_discovery_legs_sign_the_combined_large_extension_map() {
    use rsk_crypto::pinproto::{authenticate, ecdh, encrypt, public_xy};

    let (mut fs, mut rng) = setup();
    let mut state = crate::FidoState::new();
    state.regenerate(&mut rng);
    let (ax, ay) = state.ephemeral_public().unwrap();
    let mut public = Vec::new();
    for uid in [1, 2] {
        let mut request = mc_request_hmac_user(&[uid]);
        let at = request
            .windows(3)
            .position(|v| v == [6, 0xa1, 0x6b])
            .unwrap();
        request[at + 1] = 0xa3;
        let mut extra = [0; 192];
        let mut encoder = Encoder::new(Cursor::new(&mut extra[..]));
        encoder
            .str("credBlob")
            .unwrap()
            .bytes(&[0x5a; 128])
            .unwrap();
        encoder
            .str("thirdPartyPayment")
            .unwrap()
            .bool(true)
            .unwrap();
        let extra_len = encoder.writer().position();
        let options = request.len() - 6;
        request
            .splice(options..options, extra[..extra_len].iter().copied())
            .for_each(drop);
        let mut out = [0; 1024];
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: u64::from(uid) * 10,
        };
        let n = make_credential(&mut ctx, &request, &mut out).unwrap();
        let (_, x, y) = parse_mc(&out[..n]);
        public.push((x, y));
    }
    let platform = [0x11; 32];
    let (px, py) = public_xy(&platform).unwrap();
    let mut shared = [0; 64];
    let shared_len = ecdh(PinProto::Two, &platform, &ax, &ay, &mut shared).unwrap();
    let mut encrypted = [0; 80];
    let encrypted_len = encrypt(
        PinProto::Two,
        &shared[..shared_len],
        &[1; 16],
        &[0x77; 64],
        &mut encrypted,
    )
    .unwrap();
    let mut mac = [0; 32];
    let mac_len = authenticate(
        PinProto::Two,
        &shared[..shared_len],
        &encrypted[..encrypted_len],
        &mut mac,
    )
    .unwrap();
    let mut request =
        ga_request_hmac_discovery(&px, &py, &encrypted[..encrypted_len], &mac[..mac_len]);
    let at = request
        .windows(3)
        .position(|v| v == [4, 0xa1, 0x6b])
        .unwrap();
    request[at + 1] = 0xa4;
    let mut extra = [0; 64];
    let mut encoder = Encoder::new(Cursor::new(&mut extra[..]));
    for name in ["uvm", "credBlob", "thirdPartyPayment"] {
        encoder.str(name).unwrap().bool(true).unwrap();
    }
    let extra_len = encoder.writer().position();
    request.extend_from_slice(&extra[..extra_len]);
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 30,
    };
    let mut out = [0; 1024];
    for (leg, &(x, y)) in public.iter().rev().enumerate() {
        let n = if leg == 0 {
            get_assertion(&mut ctx, &request, &mut out).unwrap()
        } else {
            get_next_assertion(&mut ctx, &mut out).unwrap()
        };
        let ad = assertion_auth_data(&out[..n]);
        assert!(ad.len() > 37 + 256);
        assert_eq!(ad[32] & 0x80, 0x80);
        verify_assertion(&out[..n], &x, &y);
    }
}

#[test]
fn discovery_keeps_the_newest_credential_even_when_its_slot_is_visited_first() {
    let (mut fs, mut rng) = setup();
    let mut state = crate::FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut out = [0; 1024];
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 20,
    };
    for (uid, time) in [(1, 20), (2, 10)] {
        ctx.now_ms = time;
        make_credential(&mut ctx, &mc_request_user(&[uid]), &mut out).unwrap();
    }
    ctx.now_ms = 30;
    let n = get_assertion(&mut ctx, &ga_request(None), &mut out).unwrap();
    assert_eq!(user_and_count(&out[..n]), (vec![1], Some(2)));
    let n = get_next_assertion(&mut ctx, &mut out).unwrap();
    assert_eq!(user_and_count(&out[..n]), (vec![2], None));
    let ad = assertion_auth_data(&out[..n]);
    assert_eq!(ad.len(), 37);
    assert_eq!(ad[32] & 0x80, 0);
}

#[test]
fn a_single_discovered_passkey_leaves_no_assertion_walk_armed() {
    let (mut fs, mut rng) = setup();
    let mut state = crate::FidoState::new();
    run_mc_state(&mut fs, &mut rng, &mut state, &mc_request(true));
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 20,
    };
    let mut out = [0; 1024];
    let n = get_assertion(&mut ctx, &ga_request(None), &mut out).unwrap();
    assert_eq!(user_and_count(&out[..n]), (vec![9, 8, 7, 6], None));
    assert!(!ctx.state.gna.active);
    assert_eq!(
        get_next_assertion(&mut ctx, &mut out),
        Err(CtapError::NotAllowed)
    );
}

#[test]
fn a_short_matching_record_retires_the_walk_even_if_the_record_is_restored() {
    let (mut fs, mut rng) = setup();
    let mut state = crate::FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 10,
    };
    let mut out = [0; 1024];
    for uid in [1, 2] {
        ctx.now_ms = u64::from(uid) * 10;
        make_credential(&mut ctx, &mc_request_user(&[uid]), &mut out).unwrap();
    }
    ctx.now_ms = 30;
    get_assertion(&mut ctx, &ga_request(None), &mut out).unwrap();
    assert!(ctx.state.gna.active);
    let fid = EF_CRED + ctx.state.gna.slots[usize::from(ctx.state.gna.counter)];
    let mut original = [0; CRED_REC_MAX];
    let length = ctx.fs.read(fid, &mut original).unwrap();
    assert!(length > RECORD_PREFIX);
    ctx.fs.put(fid, &original[..32]).unwrap();
    assert!(get_next_assertion(&mut ctx, &mut out).is_err());
    ctx.fs.put(fid, &original[..length]).unwrap();
    assert_eq!(
        get_next_assertion(&mut ctx, &mut out),
        Err(CtapError::NotAllowed)
    );
}

#[test]
fn verified_discovery_omits_empty_names_on_both_assertion_legs() {
    let (mut fs, mut rng) = setup();
    let mut state = crate::FidoState::new();
    for uid in [1, 2] {
        let mut request = mc_request_user(&[uid]);
        let name = request.windows(5).position(|v| v == b"\x64user").unwrap();
        request.splice(name..name + 5, [0x60]);
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: u64::from(uid) * 10,
        };
        make_credential(&mut ctx, &request, &mut [0; 1024]).unwrap();
    }
    let token = arm_pin(&mut fs, &mut state);
    let mut mac = [0; 32];
    let n = rsk_crypto::pinproto::authenticate(PinProto::Two, &token, &CDH, &mut mac).unwrap();
    let mut request = ga_request(None);
    request[0] += 2;
    let mut extra = [0; 64];
    let mut encoder = Encoder::new(Cursor::new(&mut extra[..]));
    encoder.u8(6).unwrap().bytes(&mac[..n]).unwrap();
    encoder.u8(7).unwrap().u8(2).unwrap();
    let extra_len = encoder.writer().position();
    request.extend_from_slice(&extra[..extra_len]);
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 20,
    };
    let mut out = [0; 1024];
    let mut users = Vec::new();
    for first in [true, false] {
        let n = if first {
            get_assertion(&mut ctx, &request, &mut out).unwrap()
        } else {
            get_next_assertion(&mut ctx, &mut out).unwrap()
        };
        assert_eq!(assertion_auth_data(&out[..n])[32] & 4, 4);
        let mut decoder = Decoder::new(&out[..n]);
        let mut user = None;
        for _ in 0..decoder.map().unwrap().unwrap() {
            if decoder.u8().unwrap() == 4 {
                assert_eq!(decoder.map().unwrap(), Some(1));
                assert_eq!(decoder.str().unwrap(), "id");
                let id = decoder.bytes().unwrap();
                assert_eq!(id.len(), 1);
                user = Some(id[0]);
            } else {
                decoder.skip().unwrap();
            }
        }
        users.push(user.expect("a verified discovered credential includes its user"));
    }
    users.sort_unstable();
    assert_eq!(users, [1, 2]);
}

#[test]
#[cfg(not(feature = "largeblob-ext"))]
fn the_unadvertised_large_blob_extension_is_skipped_at_any_type() {
    let (mut fs, mut rng) = setup();
    let response = run_mc(&mut fs, &mut rng, &mc_request(true));
    let (id, _, _) = parse_mc(&response);
    let mut request = ga_request(Some(&id));
    request[0] += 1;
    request.extend_from_slice(b"\x04\xa1\x69largeBlob\xf6");
    assert!(run_ga(&mut fs, &mut rng, &request).is_ok());
}

#[test]
fn an_authenticated_legacy_allowlist_box_at_748_bytes_still_asserts() {
    let (mut fs, mut rng) = setup();
    let seed = crate::seed::load_keydev(&dev(), &mut fs).unwrap();
    let boxed = crate::credential::legacy_box_at_limit(seed.expose(), &dev());
    let mut request = [0; 1024];
    let mut encoder = Encoder::new(Cursor::new(&mut request[..]));
    encoder
        .map(3)
        .unwrap()
        .u8(1)
        .unwrap()
        .str("example.com")
        .unwrap();
    encoder.u8(2).unwrap().bytes(&CDH).unwrap();
    encoder.u8(3).unwrap().array(1).unwrap().map(2).unwrap();
    encoder.str("type").unwrap().str("public-key").unwrap();
    encoder.str("id").unwrap().bytes(&boxed).unwrap();
    let request_len = encoder.writer().position();
    let mut state = crate::FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 20,
    };
    let mut out = [0; 1024];
    let n = get_assertion(&mut ctx, &request[..request_len], &mut out).unwrap();
    let mut decoder = Decoder::new(&out[..n]);
    decoder.map().unwrap();
    assert_eq!(decoder.u8().unwrap(), 1);
    assert_eq!(decoder.map().unwrap(), Some(2));
    assert_eq!(decoder.str().unwrap(), "id");
    assert_eq!(decoder.bytes().unwrap(), boxed);
}

#[test]
fn an_absent_hmac_salt_outranks_the_silent_probe_refusal() {
    let (mut fs, mut rng) = setup();
    let mut state = crate::FidoState::new();
    let mc = run_mc_state(&mut fs, &mut rng, &mut state, &mc_request_lbk_hmac());
    let (id, _, _) = parse_mc(&mc);
    let (x, y) = rsk_crypto::pinproto::public_xy(&[0x11; 32]).unwrap();
    for (encrypted, authenticated) in [(None, Some(&[0; 32][..])), (Some(&[0; 32][..]), None)] {
        let mut req = ga_request_hmac_raw(&id, &x, &y, encrypted, authenticated, 2);
        assert_eq!(req[0], 0xa4);
        req[0] += 1;
        req.extend_from_slice(&[5, 0xa1, 0x62, b'u', b'p', 0xf4]);
        let mut out = [0; 1024];
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 20,
        };
        assert_eq!(
            get_assertion(&mut ctx, &req, &mut out),
            Err(CtapError::MissingParameter)
        );
    }
}

#[test]
#[cfg(not(feature = "largeblob-ext"))]
fn large_blob_key_requires_both_the_stored_opt_in_and_the_request() {
    for stored in [false, true] {
        for requested in [false, true] {
            let (mut fs, mut rng) = setup();
            let mut state = crate::FidoState::new();
            let mc = if stored {
                mc_request_lbk_hmac()
            } else {
                mc_request(true)
            };
            let mc = run_mc_state(&mut fs, &mut rng, &mut state, &mc);
            let (id, _, _) = parse_mc(&mc);
            let mut req = ga_request(Some(&id));
            if requested {
                let mut extra = [0; 32];
                let mut encoder = Encoder::new(Cursor::new(&mut extra[..]));
                encoder
                    .u8(4)
                    .unwrap()
                    .map(1)
                    .unwrap()
                    .str("largeBlobKey")
                    .unwrap()
                    .bool(true)
                    .unwrap();
                let n = encoder.writer().position();
                req[0] += 1;
                req.extend_from_slice(&extra[..n]);
            }
            let mut out = [0; 1024];
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 20,
            };
            let n = get_assertion(&mut ctx, &req, &mut out).unwrap();
            let mut decoder = Decoder::new(&out[..n]);
            let fields = decoder.map().unwrap().unwrap();
            let mut key = None;
            for _ in 0..fields {
                if decoder.u8().unwrap() == 7 {
                    key = Some(decoder.bytes().unwrap().to_vec());
                } else {
                    decoder.skip().unwrap();
                }
            }
            if stored && requested {
                let (_, seed) = stored_box_and_seed(&mut fs);
                let expected = crate::credential::derive_large_blob_key(&seed, &id);
                assert_eq!(key.as_deref(), Some(&expected[..]));
            } else {
                assert_eq!(key, None, "stored={stored}, requested={requested}");
            }
        }
    }
}
