// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn invalid_public_walk_counters_cannot_select_a_credential_or_write_output() {
    for (counter, total) in [(2, 2), (3, 2), (MAX_ASSERTION_CREDS as u8, 255)] {
        let (mut fs, mut rng, mut state) = open_walk();
        state.gna.counter = counter;
        state.gna.total = total;
        let generation = fs.write_gen();
        let entropy = rng.0;
        let mut presence = crate::AlwaysConfirm;
        let mut out = [0xa5; 1024];
        let mut ctx = Ctx {
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 31,
            presence: &mut presence,
        };
        assert_eq!(
            get_next_assertion(&mut ctx, &mut out),
            Err(CtapError::NotAllowed)
        );
        assert_eq!(out, [0xa5; 1024]);
        assert_eq!(fs.write_gen(), generation);
        assert_eq!(rng.0, entropy);
    }
}

#[test]
fn invalid_public_carried_salt_lengths_never_yield_a_signature() {
    for (enc, auth) in [(SALT_ENC_MAX as u8 + 1, 16), (32, SALT_AUTH_MAX as u8 + 1)] {
        let (mut fs, mut rng, mut state) = open_walk();
        state.gna.hmac_present = true;
        state.gna.hmac_salt_enc_len = enc;
        state.gna.hmac_salt_auth_len = auth;
        let generation = fs.write_gen();
        let entropy = rng.0;
        let mut presence = crate::AlwaysConfirm;
        let mut out = [0xa5; 1024];
        let mut ctx = Ctx {
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 31,
            presence: &mut presence,
        };
        assert_eq!(
            get_next_assertion(&mut ctx, &mut out),
            Err(CtapError::InvalidLength)
        );
        assert_eq!(out, [0xa5; 1024]);
        assert_eq!(fs.write_gen(), generation);
        assert_eq!(rng.0, entropy);
    }
}

fn open_walk() -> (Fs<RamStorage>, SeqRng, crate::FidoState) {
    let (mut fs, mut rng) = setup();
    let mut state = crate::FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut out = [0; 1024];
    for (user, now_ms) in [(&[1][..], 10), (&[2][..], 20)] {
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms,
        };
        make_credential(&mut ctx, &mc_request_user(user), &mut out).unwrap();
    }
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 30,
    };
    let n = get_assertion(&mut ctx, &ga_request(None), &mut out).unwrap();
    assert_eq!(user_and_count(&out[..n]), (vec![2], Some(2)));
    assert!(state.gna.active);
    (fs, rng, state)
}

#[test]
fn a_disappearing_or_replaced_credential_disarms_the_open_walk() {
    for replacement in [
        None,
        Some(vec![0; RECORD_PREFIX - 1]),
        Some(vec![0; RECORD_PREFIX]),
    ] {
        let (mut fs, mut rng, mut state) = open_walk();
        let fid = EF_CRED + state.gna.slots[state.gna.counter as usize];
        match replacement {
            None => fs.delete(fid).unwrap(),
            Some(record) => fs.put(fid, &record).unwrap(),
        }
        let mut presence = crate::AlwaysConfirm;
        let mut out = [0x55; 1024];
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 31,
        };
        assert_eq!(
            get_next_assertion(&mut ctx, &mut out),
            Err(CtapError::NoCredentials)
        );
        assert!(!ctx.state.gna.active);
        assert_eq!(out, [0x55; 1024]);
        assert_eq!(
            get_next_assertion(&mut ctx, &mut out),
            Err(CtapError::NotAllowed)
        );
    }
}

#[test]
fn a_corrupt_box_in_the_next_slot_never_yields_a_signature() {
    let (mut fs, mut rng, mut state) = open_walk();
    let fid = EF_CRED + state.gna.slots[state.gna.counter as usize];
    let mut rec = [0; CRED_REC_MAX];
    let n = fs.read(fid, &mut rec).unwrap();
    let box_start = n - cred_record_box(&rec[..n]).len();
    rec[box_start] ^= 1;
    fs.put(fid, &rec[..n]).unwrap();
    let counter = state.gna.counter;
    let mut presence = crate::AlwaysConfirm;
    let mut out = [0x55; 1024];
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 31,
    };
    assert_eq!(
        get_next_assertion(&mut ctx, &mut out),
        Err(CtapError::NoCredentials)
    );
    assert_eq!(ctx.state.gna.counter, counter);
    assert_eq!(out, [0x55; 1024]);
}

#[test]
fn assertion_refuses_whitespace_in_the_relying_party_before_a_touch() {
    struct Touches(u32);
    impl crate::UserPresence for Touches {
        fn request(&mut self, _: crate::Confirm<'_>) -> crate::Presence {
            self.0 += 1;
            crate::Presence::Confirmed
        }
    }
    let (mut fs, mut rng) = setup();
    let mut state = crate::FidoState::new();
    let mut presence = Touches(0);
    let mut out = [0x55; 1024];
    for rp in [
        "example.com ",
        " example.com",
        "example.\tcom",
        "example.com\n",
    ] {
        let mut request = [0; 128];
        let mut e = Encoder::new(Cursor::new(&mut request[..]));
        e.map(2).unwrap().u8(1).unwrap().str(rp).unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        let n = e.writer().position();
        let before = fs.write_gen();
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        assert_eq!(
            get_assertion(&mut ctx, &request[..n], &mut out),
            Err(CtapError::InvalidParameter)
        );
        assert_eq!(ctx.fs.write_gen(), before);
        assert_eq!(out, [0x55; 1024]);
    }
    assert_eq!(presence.0, 0);
}

#[test]
fn an_allowlisted_resident_record_missing_after_snapshot_cannot_yield_an_assertion() {
    let (backend, control) = rsk_fs::read_change::ChangingRead::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    crate::tests::uv_optional(&mut fs);
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let mut state = crate::FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 1000,
        presence: &mut presence,
    };
    let mut output = [0; 1024];
    let n = make_credential(&mut ctx, &mc_request(true), &mut output).unwrap();
    let (id, ..) = parse_mc(&output[..n]);
    control.replace_on_read(EF_CRED, 0, None);
    let generation = ctx.fs.write_gen();
    output.fill(0xa5);
    assert_eq!(
        get_assertion(&mut ctx, &ga_request(Some(&id)), &mut output),
        Err(CtapError::NoCredentials)
    );
    assert!(control.served());
    assert_eq!(output, [0xa5; 1024]);
    assert_eq!(ctx.fs.write_gen(), generation);
}
