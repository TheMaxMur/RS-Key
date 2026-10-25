// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::worker_abi::INVALID;

const BULK_IN: u32 = abi::EP_WRITE | (0x82 << abi::ADDRESS_SHIFT);

#[test]
fn only_allocated_nonempty_bulk_in_writes_are_eligible() {
    assert!(eligible(BULK_IN, 64, Some(EndpointType::Bulk), false));
    assert!(eligible(BULK_IN, 1, Some(EndpointType::Bulk), false));
    for operation in [
        abi::EP_READ | (0x82 << abi::ADDRESS_SHIFT),
        abi::EP_WRITE | (2 << abi::ADDRESS_SHIFT),
        abi::EP_WRITE | (0x80 << abi::ADDRESS_SHIFT),
        abi::CTRL_IN,
        BULK_IN | (1 << 31),
    ] {
        assert!(!eligible(operation, 64, Some(EndpointType::Bulk), false));
    }
    assert!(!eligible(BULK_IN, 0, Some(EndpointType::Bulk), false));
    assert!(!eligible(BULK_IN, 65, Some(EndpointType::Bulk), false));
    assert!(!eligible(BULK_IN, 64, None, false));
    assert!(!eligible(BULK_IN, 64, Some(EndpointType::Interrupt), false));
    assert!(!eligible(BULK_IN, 64, Some(EndpointType::Control), false));
    assert!(!eligible(BULK_IN, 64, Some(EndpointType::Bulk), true));
}

#[test]
fn stopped_clock_still_admits_only_eight_additional_polls() {
    let mut retry = Retry::new(100);
    for _ in 0..8 {
        assert!(retry.next(PENDING, 100, false));
    }
    assert!(!retry.next(PENDING, 100, false));
    assert!(!retry.next(PENDING, 100, false));
}

#[test]
fn deadline_and_low_timer_wrap_are_checked_before_retry() {
    let mut retry = Retry::new(u32::MAX - 20);
    assert!(retry.next(PENDING, u32::MAX, false));
    assert!(retry.next(PENDING, 42, false));
    assert!(!retry.next(PENDING, 43, false));
    assert!(!Retry::new(100).next(PENDING, 164, false));
    assert!(Retry::new(100).next(PENDING, 163, false));
}

#[test]
fn terminal_result_or_lifecycle_progress_permanently_ends_retry() {
    for terminal in [0, 1, INVALID, abi::DISABLED, abi::OVERFLOW] {
        let mut retry = Retry::new(0);
        assert!(retry.next(PENDING, 1, false));
        assert!(!retry.next(terminal, 2, false));
        assert!(!retry.next(PENDING, 3, false));
    }
    let mut retry = Retry::new(0);
    assert!(!retry.next(PENDING, 1, true));
    assert!(!retry.next(PENDING, 2, false));
}
