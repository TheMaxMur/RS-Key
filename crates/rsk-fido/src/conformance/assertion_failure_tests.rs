// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::super::{Ctx, FidoState, Resp, SeqRng, dev};
use super::*;
use crate::consts::{EF_CRED, EF_CRED_CTR, EF_KEY_DEV, STATEFUL_WALK_IDLE_MS};
use crate::credential::{CRED_REC_MAX, cred_record_box};
use crate::state::AssertionState;
use rsk_fs::storage::ram::RamStorage;
use rsk_fs::{Fs, Storage};

type Registration = (Vec<u8>, ([u8; 32], [u8; 32]));

fn fixture() -> (RamStorage, Vec<Registration>) {
    let mut a = Authr::fresh();
    let registered = ACCOUNTS
        .iter()
        .map(|(uid, name, display)| {
            let r = a.send(CTAP_MAKE_CREDENTIAL, &mc_rk_account(uid, name, display));
            assert_ok(&r);
            super::registered(&r.body)
        })
        .collect();
    (a.fs.into_storage(), registered)
}

fn restore(storage: &RamStorage) -> Authr {
    let mut a = Authr::fresh();
    a.fs = Fs::new(storage.clone());
    a.fs.scan();
    a.clock = 4000;
    a
}

fn records<S: Storage>(fs: &mut Fs<S>) -> Vec<(u16, Vec<u8>)> {
    let mut keys = Vec::new();
    assert!(fs.for_each_key(&mut |fid| keys.push(fid)));
    keys.sort_unstable();
    keys.into_iter()
        .map(|fid| {
            let mut value = vec![0; rsk_fs::MAX_VALUE_BYTES];
            let n = fs.try_read(fid, &mut value).unwrap().unwrap();
            value.truncate(n);
            (fid, value)
        })
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
struct WalkPosition {
    active: bool,
    counter: u8,
    total: u8,
    started_ms: u64,
    channel: u32,
    slots: Vec<u16>,
    rp_id_hash: [u8; 32],
    client_data_hash: [u8; 32],
}

fn position(g: &AssertionState) -> WalkPosition {
    WalkPosition {
        active: g.active,
        counter: g.counter,
        total: g.total,
        started_ms: g.started_ms,
        channel: g.channel,
        slots: g.slots.to_vec(),
        rp_id_hash: g.rp_id_hash,
        client_data_hash: g.client_data_hash,
    }
}

fn send_bounded(a: &mut Authr, command: u8, params: &[u8], capacity: usize) -> Resp {
    let mut data = vec![command];
    data.extend_from_slice(params);
    let mut out = [0xA5; 1024];
    let mut presence = crate::AlwaysConfirm;
    a.clock += 1;
    let n = crate::process_cbor(
        &mut Ctx {
            dev: dev(),
            fs: &mut a.fs,
            rng: &mut a.rng,
            state: &mut a.state,
            now_ms: a.clock,
            presence: &mut presence,
        },
        &data,
        &mut out[..capacity],
    );
    assert!((1..=capacity).contains(&n));
    assert!(out[capacity..].iter().all(|&byte| byte == 0xA5));
    if out[0] != crate::CTAP2_OK {
        assert_eq!(n, 1, "an error must not publish a partial assertion");
    }
    Resp {
        status: out[0],
        body: out[1..n].to_vec(),
    }
}

fn verify_leg(r: &Resp, registration: &Registration, user: &[u8], counter: u32) {
    assert_ok(r);
    assert_eq!(asserted_id(&r.body), registration.0);
    assert_eq!(assertion_user_id(&r.body), user);
    let ad = field_at(&r.body, 2).unwrap().bytes().unwrap().to_vec();
    assert_eq!(&ad[..32], &sha256(RP_ID.as_bytes()));
    assert_eq!(u32::from_be_bytes(ad[33..37].try_into().unwrap()), counter);
    let sig = field_at(&r.body, 3).unwrap().bytes().unwrap().to_vec();
    let mut signed = ad;
    signed.extend_from_slice(&[0xCD; 32]);
    super::super::verify_p256(&registration.1.0, &registration.1.1, &signed, &sig);
}

fn open(a: &mut Authr, uv: bool) {
    let token = uv.then(|| a.arm_token(PERM_GA));
    let r = a.send(CTAP_GET_ASSERTION, &ga_with(None, token.as_ref()));
    assert_ok(&r);
    assert_eq!(field_at(&r.body, 5).unwrap().u32().unwrap(), 3);
    assert!(a.state.gna.active);
}

#[test]
fn every_truncated_resident_record_is_skipped_without_widening_the_allowlist() {
    let (storage, registered) = fixture();
    let mut clean = restore(&storage);
    let mut record = [0; CRED_REC_MAX];
    let len = clean.fs.read(EF_CRED, &mut record).unwrap();
    for end in 0..len {
        let mut a = restore(&storage);
        a.fs.put(EF_CRED, &record[..end]).unwrap();
        let before = records(&mut a.fs);
        let generation = a.fs.write_gen();
        let r = a.send(
            CTAP_GET_ASSERTION,
            &ga_with(Some(&[&registered[0].0]), None),
        );
        assert_eq!(
            r.status,
            CtapError::NoCredentials.as_u8(),
            "prefix {end}/{len}"
        );
        assert!(r.body.is_empty());
        assert!(!a.state.gna.active);
        assert_eq!(a.fs.write_gen(), generation);
        assert_eq!(records(&mut a.fs), before);

        let first = a.send(CTAP_GET_ASSERTION, &ga_with(None, None));
        verify_leg(&first, &registered[2], ACCOUNTS[2].0, 1);
        assert_eq!(field_at(&first.body, 5).unwrap().u32().unwrap(), 2);
        let next = a.send(CTAP_GET_NEXT_ASSERTION, &[]);
        verify_leg(&next, &registered[1], ACCOUNTS[1].0, 1);
        assert!(!a.state.gna.active);
        let mixed = a.send(
            CTAP_GET_ASSERTION,
            &ga_with(Some(&[&registered[0].0, &registered[1].0]), None),
        );
        verify_leg(&mixed, &registered[1], ACCOUNTS[1].0, 2);
        assert!(field_at(&mixed.body, 5).is_none());
        assert!(!a.state.gna.active);
    }
}

#[test]
fn a_foreign_rp_prefix_never_enters_discovery_or_allowlist_selection() {
    let (storage, registered) = fixture();
    let mut a = restore(&storage);
    let mut record = [0; CRED_REC_MAX];
    let n = a.fs.read(EF_CRED, &mut record).unwrap();
    record[..32].copy_from_slice(&sha256(b"foreign.example"));
    a.fs.put(EF_CRED, &record[..n]).unwrap();
    let r = a.send(
        CTAP_GET_ASSERTION,
        &ga_with(Some(&[&registered[0].0]), None),
    );
    assert_eq!(r.status, CtapError::NoCredentials.as_u8());
    let first = a.send(CTAP_GET_ASSERTION, &ga_with(None, None));
    verify_leg(&first, &registered[2], ACCOUNTS[2].0, 1);
    assert_eq!(field_at(&first.body, 5).unwrap().u32().unwrap(), 2);
    let next = a.send(CTAP_GET_NEXT_ASSERTION, &[]);
    verify_leg(&next, &registered[1], ACCOUNTS[1].0, 1);
    assert!(!a.state.gna.active);
}

#[test]
fn short_getassertion_outputs_never_advance_counters_or_leave_a_walk() {
    let (storage, registered) = fixture();
    for uv in [false, true] {
        let mut clean = restore(&storage);
        let token = uv.then(|| clean.arm_token(PERM_GA));
        let r = clean.send(CTAP_GET_ASSERTION, &ga_with(None, token.as_ref()));
        assert_ok(&r);
        let capacity = 1 + r.body.len();
        for size in 1..capacity {
            let mut a = restore(&storage);
            let token = uv.then(|| a.arm_token(PERM_GA));
            let before = records(&mut a.fs);
            let generation = a.fs.write_gen();
            let r = send_bounded(
                &mut a,
                CTAP_GET_ASSERTION,
                &ga_with(None, token.as_ref()),
                size,
            );
            assert_eq!(
                r.status,
                CtapError::Other.as_u8(),
                "uv={uv}, capacity={size}"
            );
            assert!(!a.state.gna.active);
            assert_eq!(a.fs.write_gen(), generation);
            assert_eq!(records(&mut a.fs), before);
            assert_eq!(
                a.send(CTAP_GET_NEXT_ASSERTION, &[]).status,
                CtapError::NotAllowed.as_u8()
            );
            let token = uv.then(|| a.arm_token(PERM_GA));
            let retry = a.send(CTAP_GET_ASSERTION, &ga_with(None, token.as_ref()));
            verify_leg(&retry, &registered[2], ACCOUNTS[2].0, 1);
        }
    }
}

#[test]
fn short_getnext_outputs_preserve_the_leg_timer_and_persistent_counter() {
    let (storage, registered) = fixture();
    for uv in [false, true] {
        let mut clean = restore(&storage);
        open(&mut clean, uv);
        let r = clean.send(CTAP_GET_NEXT_ASSERTION, &[]);
        assert_ok(&r);
        let capacity = 1 + r.body.len();
        for size in 1..capacity {
            let mut a = restore(&storage);
            open(&mut a, uv);
            let walk = position(&a.state.gna);
            let before = records(&mut a.fs);
            let generation = a.fs.write_gen();
            let r = send_bounded(&mut a, CTAP_GET_NEXT_ASSERTION, &[], size);
            assert_eq!(
                r.status,
                CtapError::Other.as_u8(),
                "uv={uv}, capacity={size}"
            );
            assert_eq!(position(&a.state.gna), walk);
            assert_eq!(a.fs.write_gen(), generation);
            assert_eq!(records(&mut a.fs), before);
            let retry = a.send(CTAP_GET_NEXT_ASSERTION, &[]);
            verify_leg(&retry, &registered[1], ACCOUNTS[1].0, 1);
            assert_eq!(a.state.gna.counter, 2);
            assert_eq!(a.state.gna.started_ms, a.clock);
            let last = a.send(CTAP_GET_NEXT_ASSERTION, &[]);
            verify_leg(&last, &registered[0], ACCOUNTS[0].0, 1);
            assert!(!a.state.gna.active);
        }
    }
}

#[test]
fn a_corrupt_next_box_can_retry_the_same_leg_after_record_repair() {
    let (storage, registered) = fixture();
    let mut a = restore(&storage);
    open(&mut a, false);
    let fid = EF_CRED + a.state.gna.slots[a.state.gna.counter as usize];
    let mut record = [0; CRED_REC_MAX];
    let n = a.fs.read(fid, &mut record).unwrap();
    let original = record[..n].to_vec();
    let box_start = n - cred_record_box(&record[..n]).len();
    record[box_start] ^= 1;
    a.fs.put(fid, &record[..n]).unwrap();
    let walk = position(&a.state.gna);
    let before = records(&mut a.fs);
    let r = a.send(CTAP_GET_NEXT_ASSERTION, &[]);
    assert_eq!(r.status, CtapError::NoCredentials.as_u8());
    assert!(r.body.is_empty());
    assert_eq!(position(&a.state.gna), walk);
    assert_eq!(records(&mut a.fs), before);
    a.fs.put(fid, &original).unwrap();
    let retry = a.send(CTAP_GET_NEXT_ASSERTION, &[]);
    verify_leg(&retry, &registered[1], ACCOUNTS[1].0, 1);
}

#[test]
fn refused_next_channel_does_not_extend_the_owner_idle_window() {
    let (storage, registered) = fixture();
    let mut a = restore(&storage);
    a.state.channel = 7;
    open(&mut a, false);
    let walk = position(&a.state.gna);
    let before = records(&mut a.fs);
    a.state.channel = 8;
    a.clock = a.state.gna.started_ms + STATEFUL_WALK_IDLE_MS - 1001;
    let r = a.send(CTAP_GET_NEXT_ASSERTION, &[]);
    assert_eq!(r.status, CtapError::NotAllowed.as_u8());
    assert_eq!(position(&a.state.gna), walk);
    assert_eq!(records(&mut a.fs), before);
    a.state.channel = 7;
    let retry = send_bounded(&mut a, CTAP_GET_NEXT_ASSERTION, &[], 1024);
    verify_leg(&retry, &registered[1], ACCOUNTS[1].0, 1);
    let start = a.state.gna.started_ms;
    a.clock = start + STATEFUL_WALK_IDLE_MS;
    let expired = send_bounded(&mut a, CTAP_GET_NEXT_ASSERTION, &[], 1024);
    assert_eq!(expired.status, CtapError::NotAllowed.as_u8());
    assert!(!a.state.gna.active);
}

fn wire<S: Storage>(
    fs: &mut Fs<S>,
    state: &mut FidoState,
    rng: &mut SeqRng,
    now_ms: u64,
    command: u8,
    params: &[u8],
) -> Resp {
    let mut data = vec![command];
    data.extend_from_slice(params);
    let mut out = [0xA5; 1024];
    let mut presence = crate::AlwaysConfirm;
    let n = crate::process_cbor(
        &mut Ctx {
            dev: dev(),
            fs,
            state,
            rng,
            now_ms,
            presence: &mut presence,
        },
        &data,
        &mut out,
    );
    assert!((1..=out.len()).contains(&n));
    if out[0] != crate::CTAP2_OK {
        assert_eq!(n, 1);
    }
    Resp {
        status: out[0],
        body: out[1..n].to_vec(),
    }
}

#[test]
fn next_seed_and_counter_read_faults_preserve_a_retriable_leg() {
    use rsk_fs::storage::faults::ProbeStuck;

    let (storage, registered) = fixture();
    let image = records(&mut restore(&storage).fs);
    for fid in [EF_KEY_DEV.get(), EF_CRED_CTR.get()] {
        for persistent in [false, true] {
            let (backend, medium) = ProbeStuck::new();
            let mut fs = Fs::new(backend);
            for (key, value) in &image {
                fs.put(*key, value).unwrap();
            }
            let mut state = FidoState::new();
            let mut rng = SeqRng(2);
            let first = wire(
                &mut fs,
                &mut state,
                &mut rng,
                5000,
                CTAP_GET_ASSERTION,
                &ga_with(None, None),
            );
            verify_leg(&first, &registered[2], ACCOUNTS[2].0, 1);
            let walk = position(&state.gna);
            let before = records(&mut fs);
            let generation = fs.write_gen();
            if persistent {
                medium.stick(Some(fid));
            } else {
                medium.stick_once(fid);
            }
            let refused = wire(
                &mut fs,
                &mut state,
                &mut rng,
                5001,
                CTAP_GET_NEXT_ASSERTION,
                &[],
            );
            assert_eq!(
                refused.status,
                CtapError::Other.as_u8(),
                "fid={fid:#06x}, persistent={persistent}"
            );
            assert_eq!(position(&state.gna), walk);
            assert_eq!(fs.write_gen(), generation);
            medium.stick(None);
            assert_eq!(records(&mut fs), before);
            let retry = wire(
                &mut fs,
                &mut state,
                &mut rng,
                5002,
                CTAP_GET_NEXT_ASSERTION,
                &[],
            );
            verify_leg(&retry, &registered[1], ACCOUNTS[1].0, 1);
            let last = wire(
                &mut fs,
                &mut state,
                &mut rng,
                5003,
                CTAP_GET_NEXT_ASSERTION,
                &[],
            );
            verify_leg(&last, &registered[0], ACCOUNTS[0].0, 1);
            assert!(!state.gna.active);
        }
    }
}

#[test]
fn a_cut_before_next_counter_persistence_never_publishes_or_skips_the_leg() {
    use rsk_fs::storage::faults::Cut;

    let (storage, registered) = fixture();
    let image = records(&mut restore(&storage).fs);
    let (backend, medium) = Cut::new();
    let mut fs = Fs::new(backend);
    for (key, value) in &image {
        fs.put(*key, value).unwrap();
    }
    let mut state = FidoState::new();
    let mut rng = SeqRng(2);
    assert_ok(&wire(
        &mut fs,
        &mut state,
        &mut rng,
        5000,
        CTAP_GET_ASSERTION,
        &ga_with(None, None),
    ));
    let before = records(&mut fs);
    let walk = position(&state.gna);
    medium.clear_ops();
    medium.arm(0);
    let refused = wire(
        &mut fs,
        &mut state,
        &mut rng,
        5001,
        CTAP_GET_NEXT_ASSERTION,
        &[],
    );
    assert_eq!(refused.status, CtapError::Other.as_u8());
    assert!(refused.body.is_empty());
    assert_eq!(position(&state.gna), walk);
    assert!(medium.ops().is_empty());
    assert_eq!(records(&mut fs), before);
    medium.arm(u32::MAX);
    let retry = wire(
        &mut fs,
        &mut state,
        &mut rng,
        5002,
        CTAP_GET_NEXT_ASSERTION,
        &[],
    );
    verify_leg(&retry, &registered[1], ACCOUNTS[1].0, 1);
    let last = wire(
        &mut fs,
        &mut state,
        &mut rng,
        5003,
        CTAP_GET_NEXT_ASSERTION,
        &[],
    );
    verify_leg(&last, &registered[0], ACCOUNTS[0].0, 1);
    assert!(!state.gna.active);
}

#[test]
fn an_oversized_allowlist_candidate_cannot_hide_a_later_resident_match() {
    let (storage, registered) = fixture();
    let oversized = vec![0xA5; crate::consts::MAX_CRED_ID_LENGTH as usize + 1];
    for valid in [false, true] {
        let mut a = restore(&storage);
        let mut bytes = vec![0; oversized.len() + 512];
        let mut e = Encoder::new(Cursor::new(&mut bytes[..]));
        e.map(3).unwrap().u8(1).unwrap().str(RP_ID).unwrap();
        e.u8(2).unwrap().bytes(&[0xCD; 32]).unwrap();
        e.u8(3).unwrap().array(if valid { 2 } else { 1 }).unwrap();
        descriptor(&mut e, &oversized);
        if valid {
            descriptor(&mut e, &registered[1].0);
        }
        let n = e.writer().position();
        let r = a.send(CTAP_GET_ASSERTION, &bytes[..n]);
        if valid {
            verify_leg(&r, &registered[1], ACCOUNTS[1].0, 1);
        } else {
            assert_eq!(r.status, CtapError::NoCredentials.as_u8());
            assert!(r.body.is_empty());
        }
        assert!(!a.state.gna.active);
    }
}

#[test]
fn optional_with_list_visibility_changes_independently_with_uv_and_allowlist() {
    let (storage, plain) = fixture();
    let mut a = restore(&storage);
    let uid = &[0xD0, 4];
    let request = enc(|e| {
        e.map(6).unwrap().u8(1).unwrap().bytes(&[0xCD; 32]).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str(RP_ID)
            .unwrap();
        e.u8(3)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .bytes(uid)
            .unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str(PUBLIC_KEY_TYPE).unwrap();
        e.u8(6)
            .unwrap()
            .map(1)
            .unwrap()
            .str("credProtect")
            .unwrap()
            .u64(crate::consts::CRED_PROT_UV_OPTIONAL_WITH_LIST)
            .unwrap();
        e.u8(7)
            .unwrap()
            .map(1)
            .unwrap()
            .str("rk")
            .unwrap()
            .bool(true)
            .unwrap();
    });
    let created = a.send(CTAP_MAKE_CREDENTIAL, &request);
    assert_ok(&created);
    let protected = super::registered(&created.body);
    let storage = a.fs.into_storage();
    for uv in [false, true] {
        for allow in [false, true] {
            let mut a = restore(&storage);
            let token = uv.then(|| a.arm_token(PERM_GA));
            let ids = [&protected.0[..]];
            let r = a.send(
                CTAP_GET_ASSERTION,
                &ga_with(allow.then_some(&ids), token.as_ref()),
            );
            if uv || allow {
                verify_leg(&r, &protected, uid, 1);
            } else {
                verify_leg(&r, &plain[2], ACCOUNTS[2].0, 1);
            }
            assert_eq!(
                asserted_flags(&r.body) & FLAG_UV,
                if uv { FLAG_UV } else { 0 }
            );
            if allow {
                assert!(field_at(&r.body, 5).is_none());
                assert!(!a.state.gna.active);
            } else {
                assert_eq!(
                    field_at(&r.body, 5).unwrap().u32().unwrap(),
                    if uv { 4 } else { 3 }
                );
            }
        }
    }
}

#[test]
fn a_silent_discovery_remains_without_up_or_uv_through_every_next_leg() {
    let (storage, registered) = fixture();
    let mut a = restore(&storage);
    let request = enc(|e| {
        e.map(3).unwrap().u8(1).unwrap().str(RP_ID).unwrap();
        e.u8(2).unwrap().bytes(&[0xCD; 32]).unwrap();
        e.u8(5)
            .unwrap()
            .map(1)
            .unwrap()
            .str("up")
            .unwrap()
            .bool(false)
            .unwrap();
    });
    for (leg, account) in [2, 1, 0].into_iter().enumerate() {
        let r = if leg == 0 {
            a.send(CTAP_GET_ASSERTION, &request)
        } else {
            a.send(CTAP_GET_NEXT_ASSERTION, &[])
        };
        verify_leg(&r, &registered[account], ACCOUNTS[account].0, 1);
        assert_eq!(asserted_flags(&r.body) & (FLAG_UP | FLAG_UV), 0);
        assert_eq!(user_entity(&r.body), entity(&[("id", ACCOUNTS[account].0)]));
    }
    assert!(!a.state.gna.active);
    assert_eq!(
        a.send(CTAP_GET_NEXT_ASSERTION, &[]).status,
        CtapError::NotAllowed.as_u8()
    );
}
