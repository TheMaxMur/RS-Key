// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn equal_creation_times_return_each_discovered_credential_once() {
    assert_discovery_walk(&[10, 10], &[1, 0]);
}

#[test]
fn a_full_discovery_queue_keeps_the_newest_credentials_including_the_first_reply() {
    let times: Vec<_> = (0..=MAX_ASSERTION_CREDS).map(|i| i as u64).collect();
    let expected: Vec<_> = (1..=MAX_ASSERTION_CREDS).rev().collect();
    assert_discovery_walk(&times, &expected);
}

#[test]
fn a_full_discovery_queue_keeps_earlier_slots_when_they_are_newer() {
    let times: Vec<_> = (0..=MAX_ASSERTION_CREDS).rev().map(|i| i as u64).collect();
    let expected: Vec<_> = (0..MAX_ASSERTION_CREDS).collect();
    assert_discovery_walk(&times, &expected);
}

#[test]
fn a_full_discovery_queue_breaks_creation_time_ties_consistently_with_the_first_reply() {
    let times = [10; MAX_ASSERTION_CREDS + 1];
    let expected: Vec<_> = (1..=MAX_ASSERTION_CREDS).rev().collect();
    assert_discovery_walk(&times, &expected);
}

#[test]
fn equal_creation_times_preserve_allow_list_order_without_arming_a_walk() {
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
        now_ms: 10,
    };
    let mut credentials = Vec::new();
    for user in [1, 2] {
        let n = make_credential(&mut ctx, &mc_request_user(&[user]), &mut out).unwrap();
        credentials.push(parse_mc(&out[..n]));
    }
    for order in [[0, 1], [1, 0]] {
        let request = ga_request_list(&[
            ("public-key", &credentials[order[0]].0),
            ("public-key", &credentials[order[1]].0),
        ]);
        let n = get_assertion(&mut ctx, &request, &mut out).unwrap();
        let (id, x, y) = &credentials[order[1]];
        assert_eq!(cred_id_of(&out[..n]), *id);
        assert_eq!(user_and_count(&out[..n]).1, None);
        verify_assertion(&out[..n], x, y);
        assert!(!ctx.state.gna.active);
        assert_eq!(
            get_next_assertion(&mut ctx, &mut out),
            Err(CtapError::NotAllowed)
        );
    }
}

fn assert_discovery_walk(times: &[u64], expected: &[usize]) {
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
        now_ms: 0,
    };
    let mut credentials = Vec::new();
    for (slot, &time) in times.iter().enumerate() {
        ctx.now_ms = time;
        let user = u8::try_from(slot + 1).unwrap();
        let n = make_credential(&mut ctx, &mc_request_user(&[user]), &mut out).unwrap();
        credentials.push(parse_mc(&out[..n]));
    }
    ctx.now_ms = times.iter().copied().max().unwrap() + 1;
    let mut returned = Vec::new();
    for (leg, &slot) in expected.iter().enumerate() {
        let n = if leg == 0 {
            get_assertion(&mut ctx, &ga_request(None), &mut out).unwrap()
        } else {
            get_next_assertion(&mut ctx, &mut out).unwrap()
        };
        let response = &out[..n];
        let (user, count) = user_and_count(response);
        assert_eq!(
            user,
            [u8::try_from(slot + 1).unwrap()],
            "discovery leg {leg}"
        );
        assert_eq!(count, (leg == 0).then_some(expected.len() as u32));
        let (id, x, y) = &credentials[slot];
        assert_eq!(cred_id_of(response), *id);
        assert!(!returned.contains(id), "a credential must not be repeated");
        returned.push(id.clone());
        verify_assertion(response, x, y);
    }
    assert_eq!(
        get_next_assertion(&mut ctx, &mut out),
        Err(CtapError::NotAllowed)
    );
}
