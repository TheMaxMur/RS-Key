// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

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
