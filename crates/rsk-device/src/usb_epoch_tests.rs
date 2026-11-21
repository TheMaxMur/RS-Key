// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn only_an_accepted_configuration_opens_the_bus() {
    let mut bus = BusEpoch::new();
    let epoch = bus.current();
    assert!(!bus.exhausted());
    assert!(!bus.accepts(epoch));
    assert!(bus.configure());
    assert!(bus.accepts(epoch));
    assert!(!bus.accepts(epoch + 1));
}

#[test]
fn reset_and_configuration_loss_do_not_restore_a_previous_epoch() {
    for reason in [Revocation::Reset, Revocation::ConfigurationLoss] {
        let mut bus = BusEpoch::new();
        assert!(bus.configure());
        let old = bus.current();
        bus.revoke(reason);
        assert_eq!(bus.current(), old + 1);
        assert!(!bus.accepts(old));
        assert!(!bus.accepts(bus.current()));
        bus.resume();
        assert!(!bus.accepts(bus.current()));
        assert!(bus.configure());
        assert!(bus.accepts(bus.current()));
        assert!(!bus.accepts(old));
    }
}

#[test]
fn resume_keeps_configuration_but_never_the_old_epoch() {
    let mut bus = BusEpoch::new();
    assert!(bus.configure());
    let old = bus.current();
    bus.revoke(Revocation::Suspend);
    assert!(!bus.accepts(old));
    assert!(!bus.accepts(bus.current()));
    assert!(!bus.configure());
    bus.revoke(Revocation::Suspend);
    bus.resume();
    assert!(bus.accepts(bus.current()));
    assert!(!bus.accepts(old));
}

#[test]
fn resume_without_configuration_and_reset_while_suspended_stay_closed() {
    let mut bus = BusEpoch::new();
    bus.revoke(Revocation::Suspend);
    bus.resume();
    assert!(!bus.accepts(bus.current()));
    assert!(bus.configure());
    bus.revoke(Revocation::Suspend);
    bus.revoke(Revocation::Reset);
    bus.resume();
    assert!(!bus.accepts(bus.current()));
}

#[test]
fn exhaustion_is_terminal_even_after_configuration_and_resume() {
    let mut bus = BusEpoch {
        epoch: rsk_usb::usb_abi::OVERFLOW - 2,
        state: State::Configured,
    };
    bus.revoke(Revocation::Reset);
    assert_eq!(bus.current(), rsk_usb::usb_abi::OVERFLOW - 1);
    assert!(bus.configure());
    assert!(bus.accepts(rsk_usb::usb_abi::OVERFLOW - 1));
    bus.revoke(Revocation::Suspend);
    assert!(bus.exhausted());
    assert!(!bus.accepts(LAST_EPOCH));
    assert!(!bus.configure());
    bus.resume();
    assert!(bus.exhausted());
    for reason in [
        Revocation::Reset,
        Revocation::Suspend,
        Revocation::ConfigurationLoss,
    ] {
        bus.revoke(reason);
    }
    assert_eq!(bus.current(), rsk_usb::usb_abi::OVERFLOW - 1);
    assert!(!bus.accepts(LAST_EPOCH));
}

#[test]
fn hal_observes_events_arriving_after_the_raw_snapshot() {
    for reason in [Revocation::Reset, Revocation::Suspend] {
        let mut events = BusEvents::new();
        assert_eq!(events.begin(false, false), None);
        assert!(events.observe_hal(reason));
        assert!(events.observe_hal(reason));
    }
}

#[test]
fn raw_and_hal_report_each_hardware_event_once() {
    for (reset, suspended, reason) in [
        (true, false, Revocation::Reset),
        (false, true, Revocation::Suspend),
    ] {
        let mut events = BusEvents::new();
        assert_eq!(events.begin(reset, suspended), Some(reason));
        assert!(!events.observe_hal(reason));
        assert!(events.observe_hal(reason));
        events.finish(false, false);
        assert_eq!(events.begin(reset, suspended), Some(reason));
    }
}

#[test]
fn an_undrained_raw_event_is_not_revoked_again_on_the_next_poll() {
    let mut events = BusEvents::new();
    assert_eq!(events.begin(true, false), Some(Revocation::Reset));
    events.finish(true, false);
    assert_eq!(events.begin(true, false), None);
    assert!(!events.observe_hal(Revocation::Reset));
}

#[test]
fn the_final_snapshot_does_not_hide_a_new_unhandled_event() {
    let mut events = BusEvents::new();
    assert_eq!(events.begin(false, false), None);
    events.finish(true, true);
    assert_eq!(events.begin(true, true), Some(Revocation::Reset));
    assert!(!events.observe_hal(Revocation::Reset));
    assert!(events.observe_hal(Revocation::Suspend));
    assert_eq!(events.begin(false, false), None);
}

#[test]
fn reset_does_not_cover_a_distinct_suspend_or_configuration_loss() {
    let mut events = BusEvents::new();
    assert_eq!(events.begin(true, true), Some(Revocation::Reset));
    assert!(events.observe_hal(Revocation::Suspend));
    assert!(!events.observe_hal(Revocation::Reset));
    assert!(events.observe_hal(Revocation::ConfigurationLoss));
}

#[test]
fn an_acknowledged_suspend_level_is_not_a_new_event_on_every_poll() {
    let mut events = BusEvents::new();
    assert_eq!(events.begin(false, true), Some(Revocation::Suspend));
    assert!(!events.observe_hal(Revocation::Suspend));
    for _ in 0..4 {
        events.finish(false, true);
        assert_eq!(events.begin(false, true), None);
    }
    assert!(events.observe_hal(Revocation::Suspend));
    events.finish(false, false);
    assert_eq!(events.begin(false, true), Some(Revocation::Suspend));
}

#[test]
fn an_undrained_suspend_level_covers_its_later_hal_receipt_once() {
    let mut events = BusEvents::new();
    assert_eq!(events.begin(false, true), Some(Revocation::Suspend));
    events.finish(false, true);
    assert_eq!(events.begin(false, true), None);
    assert!(!events.observe_hal(Revocation::Suspend));
    assert!(events.observe_hal(Revocation::Suspend));
}
