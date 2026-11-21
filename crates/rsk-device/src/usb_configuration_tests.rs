// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::usb_epoch::{BusEpoch, Revocation};

#[test]
fn status_requires_its_own_arm_and_is_acknowledged_once() {
    let mut status = Configuration::new();
    assert!(!status.acknowledge());
    status.queue(3);
    assert!(!status.acknowledge());
    assert!(!status.arm(2));
    assert!(!status.acknowledge());
    assert!(status.arm(3));
    assert!(!status.arm(3));
    assert!(status.acknowledge());
    assert!(!status.acknowledge());
}

#[test]
fn ack_before_next_setup_preserves_the_accepted_configuration() {
    let mut status = Configuration::new();
    let mut bus = BusEpoch::new();
    status.queue(7);
    assert!(status.arm(7));
    if status.acknowledge() {
        bus.configure();
    }
    status.reset();
    assert!(bus.accepts(bus.current()));
}

#[test]
fn new_setup_without_ack_cannot_configure_the_bus() {
    for armed in [false, true] {
        let mut status = Configuration::new();
        status.queue(7);
        if armed {
            assert!(status.arm(7));
        }
        status.reset();
        assert!(!status.acknowledge());
        assert!(!status.arm(7));
    }
}

#[test]
fn reset_revokes_even_when_the_old_status_completed() {
    let mut status = Configuration::new();
    let mut bus = BusEpoch::new();
    status.queue(7);
    assert!(status.arm(7));
    let old = bus.current();
    bus.revoke(Revocation::Reset);
    status.reset();
    assert!(!status.acknowledge());
    assert!(!bus.accepts(old));
    assert!(!bus.accepts(bus.current()));
}

#[test]
fn an_old_drop_or_poll_cannot_take_over_the_next_status() {
    let mut status = Configuration::new();
    status.queue(7);
    assert!(status.arm(7));
    status.reset();
    status.queue(8);
    status.abandon(7);
    assert!(!status.arm(7));
    assert!(status.arm(8));
    status.abandon(7);
    assert!(status.acknowledge());
    for armed in [false, true] {
        status.queue(9);
        if armed {
            assert!(status.arm(9));
        }
        status.abandon(9);
        assert!(!status.acknowledge());
        assert!(!status.arm(9));
    }
}

#[test]
fn completed_configuration_survives_suspend_in_the_new_epoch() {
    let mut status = Configuration::new();
    let mut bus = BusEpoch::new();
    let old = bus.current();
    status.queue(7);
    assert!(status.arm(7));
    assert!(status.acknowledge());
    assert!(bus.configure());
    bus.revoke(Revocation::Suspend);
    status.reset();
    assert!(!bus.accepts(bus.current()));
    bus.resume();
    assert!(!bus.accepts(old));
    assert!(bus.accepts(bus.current()));
    assert!(!status.acknowledge());
}
