// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[kani::proof]
fn reset_invalidates_a_reply_at_every_dispatch_stage() {
    let stage: u8 = kani::any();
    kani::assume(stage <= 2);
    let mut session = Session::new();
    let ticket = session.submit().unwrap();
    if stage > 0 {
        assert_eq!(session.next_job(), Some(Job::Dispatch(ticket)));
    }
    if stage == 2 {
        assert!(session.finish(ticket));
    }
    session.reset();
    assert!(session.is_revoked());
    assert_eq!(session.poll(ticket), Poll::Abandoned);
    assert_eq!(session.submit(), None);
    if stage == 1 {
        assert!(!session.finish(ticket));
    }
    assert_eq!(session.next_job(), Some(Job::Discard(ticket)));
    assert!(session.release(ticket));
    assert_eq!(session.submit(), None);
    assert_eq!(session.next_job(), Some(Job::Reset));
    assert!(session.is_revoked());
    assert_eq!(session.submit(), None);
    let second: bool = kani::any();
    if second {
        session.reset();
    }
    session.reset_complete();
    assert_eq!(session.is_revoked(), second);
    if second {
        assert_eq!(session.next_job(), Some(Job::Reset));
        assert!(session.is_revoked());
        session.reset_complete();
    }
    assert!(!session.is_revoked());
    let new = session.submit().unwrap();
    assert_ne!(new, ticket);
    session.abandon(ticket);
    assert_eq!(session.next_job(), Some(Job::Dispatch(new)));
    assert!(session.finish(new));
    assert_eq!(session.poll(new), Poll::Ready);
}

#[kani::proof]
fn a_foreign_ticket_cannot_take_or_abandon_the_current_reply() {
    let mut session = Session::new();
    let ticket = session.submit().unwrap();
    let foreign: u32 = kani::any();
    kani::assume(foreign != ticket);
    assert_eq!(session.next_job(), Some(Job::Dispatch(ticket)));
    assert!(session.finish(ticket));
    session.abandon(foreign);
    assert!(!session.release(foreign));
    assert_eq!(session.poll(foreign), Poll::Abandoned);
    assert_eq!(session.poll(ticket), Poll::Ready);
}
