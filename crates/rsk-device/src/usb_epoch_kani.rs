// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[kani::proof]
fn revocation_never_restores_the_old_epoch() {
    let epoch: u32 = kani::any();
    kani::assume(epoch > 0 && epoch <= LAST_EPOCH);
    let mut bus = BusEpoch {
        epoch,
        state: State::Configured,
    };
    let reason = match kani::any::<u8>() {
        0 => Revocation::Reset,
        1 => Revocation::Suspend,
        _ => Revocation::ConfigurationLoss,
    };
    bus.revoke(reason);
    assert!(!bus.accepts(epoch));
    bus.resume();
    bus.configure();
    assert!(!bus.accepts(epoch));
    assert!(bus.current() >= epoch);
}

#[kani::proof]
fn exhausted_bus_cannot_reopen() {
    let mut bus = BusEpoch {
        epoch: LAST_EPOCH,
        state: State::Configured,
    };
    bus.revoke(Revocation::Reset);
    assert!(bus.exhausted());
    bus.resume();
    assert!(!bus.configure());
    bus.revoke(Revocation::Suspend);
    bus.revoke(Revocation::ConfigurationLoss);
    assert!(bus.exhausted());
    assert_eq!(bus.current(), LAST_EPOCH);
    assert!(!bus.accepts(kani::any()));
}
