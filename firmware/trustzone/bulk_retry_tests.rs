// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn run(results: &[u32], observations: &[Observation], start: u32, endpoint_us: u32) -> u32 {
    MODEL.set(Model {
        results: results.iter().copied().collect(),
        observations: observations.iter().copied().collect(),
        endpoint_us,
        ..Model::default()
    });
    CLOCK.set(start);
    FAULT.set(false);
    LOCKED.set(false);
    CONTROLLER.with_borrow_mut(|state| *state = controller());
    let epoch = CONTROLLER.with_borrow(|state| state.bus_epoch.current());
    let mut packet = [0xa5; 64];
    secure::rsk_tz_usb_impl(
        abi::EP_WRITE | (0x82 << abi::ADDRESS_SHIFT),
        epoch,
        &mut packet,
        64,
    )
}

fn checked(expected_calls: usize, expected_commits: usize, notify: bool) {
    MODEL.with_borrow(|model| {
        assert_eq!(model.endpoint_calls, expected_calls, "HAL poll count");
        assert_eq!(model.commits, expected_commits, "accepted packet count");
        assert!(
            !model.bad_packet,
            "each retry must use the same complete Secure snapshot"
        );
        assert_eq!(
            model
                .events
                .iter()
                .filter(|event| matches!(event, Event::Wipe(_)))
                .count(),
            1
        );
        let wipe = model
            .events
            .iter()
            .position(|event| *event == Event::Wipe(true))
            .expect("full live Packet64 wipe");
        let unlock = model
            .events
            .iter()
            .position(|event| *event == Event::Unlock)
            .expect("SERIAL release");
        assert!(wipe < unlock, "packet wipe must precede SERIAL release");
        let notifications: Vec<_> = model
            .events
            .iter()
            .enumerate()
            .filter(|(_, event)| matches!(event, Event::Notify { .. }))
            .collect();
        assert_eq!(
            notifications.len(),
            usize::from(notify),
            "Pending alone must not notify"
        );
        for (index, event) in notifications {
            assert_eq!(
                *event,
                Event::Notify {
                    locked: false,
                    wiped: true
                },
                "notification must follow Packet64 wipe and SERIAL release"
            );
            assert!(unlock < index, "notification must follow SERIAL release");
        }
    });
}

#[test]
fn quiet_pending_has_eight_additional_polls_full_cleanup_and_no_selfwake() {
    assert_eq!(run(&[], &[], 100, 0), PENDING);
    checked(9, 0, false);
}

#[test]
fn success_commits_once_and_errors_stop_without_another_poll() {
    assert_eq!(run(&[0, 0], &[], 0, 0), 0);
    checked(1, 1, false);
    assert_eq!(run(&[PENDING, 0, 0], &[], 0, 0), 0);
    checked(2, 1, false);
    for error in [INVALID, abi::DISABLED, abi::OVERFLOW] {
        assert_eq!(run(&[PENDING, error, 0], &[], 0, 0), error);
        checked(2, 0, false);
    }
}

#[test]
fn deadline_and_wrap_bound_real_loop_admission() {
    assert_eq!(run(&[], &[], 100, 64), PENDING);
    checked(1, 0, false);
    assert_eq!(run(&[], &[], u32::MAX - 20, 32), PENDING);
    checked(2, 0, false);
}

#[test]
fn each_repeat_keeps_pre_and_post_observers() {
    assert_eq!(run(&[PENDING, 0], &[], 0, 0), 0);
    MODEL.with_borrow(|model| {
        let polls: Vec<_> = model
            .events
            .iter()
            .filter(|event| matches!(event, Event::Observe | Event::Endpoint))
            .cloned()
            .collect();
        assert_eq!(
            polls,
            [
                Event::Observe,
                Event::Endpoint,
                Event::Observe,
                Event::Observe,
                Event::Endpoint,
                Event::Observe
            ]
        );
    });
    checked(2, 1, false);
}

#[test]
fn late_reset_in_first_post_repeat_pre_or_repeat_post_refuses_captured_epoch() {
    for index in [1, 2, 3] {
        let mut observations = vec![Observation::Quiet; index];
        observations.push(Observation::Reset);
        assert_eq!(
            run(&[], &observations, 0, 0),
            abi::DISABLED,
            "reset observer index {index}"
        );
        checked(if index == 3 { 2 } else { 1 }, 0, true);
    }
}

#[test]
fn setup_and_resume_progress_break_pending_and_notify_once_after_cleanup() {
    for action in [Observation::Setup, Observation::Resume] {
        for index in [2, 3] {
            let mut observations = vec![Observation::Quiet; index];
            observations.push(action);
            assert_eq!(run(&[], &observations, 0, 0), PENDING);
            checked(if index == 3 { 2 } else { 1 }, 0, true);
        }
    }
}

#[test]
fn fault_after_repeat_observer_prevents_a_new_hal_poll() {
    assert_eq!(
        run(
            &[],
            &[Observation::Quiet, Observation::Quiet, Observation::Fault],
            0,
            0
        ),
        INVALID
    );
    checked(1, 0, false);
}

#[test]
fn endpoint_retry_eligibility_keeps_bulk_bounds_and_blocked_states() {
    let mut state = controller();
    let operation = abi::EP_WRITE | (0x82 << abi::ADDRESS_SHIFT);
    assert!(endpoints::retry_eligible(&state, operation, &[1; 64]));
    for index in [0u32, 16, 127] {
        assert!(!endpoints::retry_eligible(
            &state,
            abi::EP_WRITE | ((0x80 | index) << abi::ADDRESS_SHIFT),
            &[1]
        ));
    }
    assert!(!endpoints::retry_eligible(&state, operation, &[]));
    state.bulk_retiring = 1 << 2;
    assert!(!endpoints::retry_eligible(&state, operation, &[1]));
    state.bulk_retiring = 0;
    state.bulk_zlp = 1 << 2;
    assert!(!endpoints::retry_eligible(&state, operation, &[1]));
    state.bulk_zlp = 0;
    state.input[2] = Some(Endpoint(EndpointInfo {
        ep_type: EndpointType::Interrupt,
    }));
    assert!(!endpoints::retry_eligible(&state, operation, &[1]));
    state.input[2] = None;
    assert!(!endpoints::retry_eligible(&state, operation, &[1]));
}
