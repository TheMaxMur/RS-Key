// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn completing_a_reset_outside_scrubbing_preserves_the_current_request() {
    for stage in 0..7 {
        let mut session = Session::new();
        let id = if stage == 0 {
            0
        } else {
            session.submit().unwrap()
        };
        if matches!(stage, 2 | 3 | 5 | 6) {
            assert_eq!(session.next_job(), Some(Job::Dispatch(id)));
        }
        if matches!(stage, 3 | 6) {
            assert!(session.finish(id));
        }
        if stage >= 4 {
            session.abandon(id);
        }
        let before = (session.state, session.next_ticket, session.reset_pending);
        session.reset_complete();
        assert_eq!(
            (session.state, session.next_ticket, session.reset_pending),
            before,
            "stage {stage}: a completion without a reset lost work"
        );
        assert_eq!(
            session.poll(id),
            match stage {
                1 | 2 => Poll::Pending,
                3 => Poll::Ready,
                _ => Poll::Abandoned,
            }
        );
    }
}

#[test]
fn idle_has_no_work_and_ticket_exhaustion_never_reuses_an_old_ticket() {
    let mut session = Session::new();
    assert_eq!(session.next_job(), None);
    session.next_ticket = u32::MAX - 3;
    let last = session.submit().unwrap();
    assert_eq!(last, u32::MAX - 3);
    session.abandon(last);
    assert!(session.release(last));
    assert_eq!(session.submit(), None);
    assert_eq!(session.next_job(), None);
}

#[test]
fn a_foreign_ticket_cannot_finish_poll_release_or_abandon_any_active_stage() {
    for stage in 0..4 {
        let mut session = Session::new();
        let id = session.submit().unwrap();
        if stage > 0 {
            assert_eq!(session.next_job(), Some(Job::Dispatch(id)));
        }
        if stage == 2 {
            assert!(session.finish(id));
        } else if stage == 3 {
            session.abandon(id);
        }
        let before = session.state;
        assert!(!session.finish(id + 1));
        assert_eq!(session.poll(id + 1), Poll::Abandoned);
        assert!(!session.release(id + 1));
        session.abandon(id + 1);
        assert_eq!(session.state, before);
        assert_eq!(
            session.poll(id),
            match stage {
                2 => Poll::Ready,
                3 => Poll::Abandoned,
                _ => Poll::Pending,
            }
        );
    }
}

#[test]
fn reset_during_work_discards_before_clearing_auth_and_accepting_a_new_request() {
    let mut session = Session::new();
    let old = session.submit().unwrap();
    assert_eq!(session.next_job(), Some(Job::Dispatch(old)));
    session.reset();
    assert_eq!(session.poll(old), Poll::Abandoned);
    assert_eq!(session.submit(), None);
    assert!(!session.release(old));
    assert!(!session.finish(old));
    assert_eq!(session.next_job(), Some(Job::Discard(old)));
    assert!(session.release(old));
    assert_eq!(session.submit(), None);
    assert_eq!(session.next_job(), Some(Job::Reset));
    assert_eq!(session.submit(), None);
    session.reset_complete();
    let new = session.submit().unwrap();
    assert_ne!(new, old);
    assert_eq!(session.poll(old), Poll::Abandoned);
    session.abandon(old);
    assert_eq!(session.next_job(), Some(Job::Dispatch(new)));
    assert!(session.finish(new));
    assert_eq!(session.poll(new), Poll::Ready);
    assert!(!session.release(old));
    assert!(session.release(new));
}

#[test]
fn dropped_future_is_reclaimed_before_or_after_dispatch_and_after_reply() {
    for stage in 0..3 {
        let mut session = Session::new();
        let id = session.submit().unwrap();
        if stage > 0 {
            assert_eq!(session.next_job(), Some(Job::Dispatch(id)));
        }
        if stage == 2 {
            assert!(session.finish(id));
        }
        session.abandon(id);
        assert_eq!(session.poll(id), Poll::Abandoned);
        assert_eq!(session.submit(), None);
        if stage == 1 {
            assert!(!session.finish(id));
        }
        assert_eq!(session.next_job(), Some(Job::Discard(id)));
        assert!(session.release(id));
        assert!(session.submit().is_some());
    }
}

#[test]
fn a_second_reset_during_scrubbing_is_serviced_before_any_new_request() {
    let mut session = Session::new();
    session.reset();
    assert_eq!(session.next_job(), Some(Job::Reset));
    session.reset();
    session.reset_complete();
    assert_eq!(session.submit(), None);
    assert_eq!(session.next_job(), Some(Job::Reset));
    session.reset_complete();
    assert!(session.submit().is_some());
}

#[test]
fn auxiliary_output_stays_revoked_until_the_last_reset_cleanup_finishes() {
    for stage in 0..3 {
        let mut session = Session::new();
        let ticket = session.submit().unwrap();
        if stage > 0 {
            assert_eq!(session.next_job(), Some(Job::Dispatch(ticket)));
        }
        if stage == 2 {
            assert!(session.finish(ticket));
        }
        assert!(!session.is_revoked());
        session.reset();
        assert!(
            session.is_revoked(),
            "reset did not revoke auxiliary output immediately"
        );
        if stage == 1 {
            assert!(!session.finish(ticket));
        }
        assert_eq!(session.next_job(), Some(Job::Discard(ticket)));
        assert!(session.release(ticket));
        assert_eq!(session.next_job(), Some(Job::Reset));
        assert!(session.is_revoked(), "scrubbing reopened auxiliary output");
        session.reset();
        session.reset_complete();
        assert!(session.is_revoked(), "a second reset was skipped");
        assert_eq!(session.next_job(), Some(Job::Reset));
        session.reset_complete();
        assert!(!session.is_revoked());
    }
}

#[test]
fn control_ticket_exhaustion_never_returns_a_usb_status_or_reopens_on_reset() {
    let mut session = Session::with_ticket_limit(rsk_usb::usb_abi::OVERFLOW);
    session.next_ticket = rsk_usb::usb_abi::OVERFLOW - 1;
    let last = session.submit().unwrap();
    assert_eq!(last, rsk_usb::usb_abi::OVERFLOW - 1);
    assert_eq!(session.next_job(), Some(Job::Dispatch(last)));
    assert!(session.finish(last));
    assert!(session.release(last));
    assert_eq!(session.submit(), None);
    session.reset();
    assert_eq!(session.next_job(), Some(Job::Reset));
    session.reset_complete();
    assert_eq!(session.submit(), None);
}
