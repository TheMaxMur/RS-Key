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
