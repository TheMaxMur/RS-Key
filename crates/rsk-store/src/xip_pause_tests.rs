// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn only_the_requested_park_can_be_released_and_reused_after_acknowledged_resume() {
    let pause = Pause::new();
    assert!(!pause.acknowledge());
    assert!(!pause.cancel());
    assert!(!pause.release());
    assert!(!pause.finish());
    assert!(pause.request_park());
    assert!(!pause.request_park());
    assert!(!pause.release());
    assert!(!pause.finish());
    assert!(pause.acknowledge());
    assert!(pause.is_parked());
    assert!(!pause.request_park());
    assert!(!pause.cancel());
    assert!(!pause.acknowledge());
    assert!(!pause.finish());
    assert!(pause.release());
    assert!(!pause.is_parked());
    assert!(!pause.request_park());
    assert!(!pause.cancel());
    assert!(!pause.acknowledge());
    assert!(!pause.release());
    assert!(pause.finish());
    assert!(pause.request_park());
}

#[test]
fn a_timeout_cannot_cancel_a_park_acknowledged_at_the_deadline() {
    let pause = Pause::new();
    assert!(pause.request_park());
    assert!(pause.cancel());
    assert!(
        !pause.acknowledge(),
        "a late ACK must not resurrect the cancelled request"
    );
    assert!(pause.request_park());
    assert!(pause.acknowledge());
    assert!(
        !pause.cancel(),
        "an acknowledged park must instead be released"
    );
    assert!(pause.is_parked());
    assert!(pause.release());
    assert!(pause.finish());
}
