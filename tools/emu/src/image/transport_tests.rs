// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn hid_timing_keeps_packet_times_after_host_delay_and_ignores_other_channels() {
    let mut trace = Trace::default();
    trace.hid_out(&[0, 0, 0, 1, CTAPHID_CBOR], 100);
    assert!(trace.report().is_err());
    trace.arm();
    trace.hid_out(&[0, 0, 0, 1, CTAPHID_CBOR], 200);
    trace.hid_out(&[0, 0, 0, 1, 0], 250);
    trace.hid_in(&[0, 0, 0, 2, CTAPHID_KEEPALIVE], 300);
    trace.hid_in(&[0, 0, 0, 1, CTAPHID_KEEPALIVE], 400);
    assert!(trace.report().is_err());
    trace.hid_in(&[0, 0, 0, 1, CTAPHID_KEEPALIVE], 600);
    trace.hid_in(&[0, 0, 0, 1, CTAPHID_CBOR], 700);
    trace.hid_in(&[0, 0, 0, 1, 0], 1_000_000);
    assert_eq!(
        trace.report(),
        Ok("elapsed_ns=500 keepalives=2 max_gap_ns=200".into())
    );
}

#[test]
fn ccid_timing_does_not_count_another_sequence_or_the_get_response_transaction() {
    let mut trace = Trace::default();
    trace.arm();
    trace.ccid_out(&[0x6F, 0, 0, 0, 0, 0, 7, 0, 0, 0], 100);
    trace.ccid_in(&[0x80, 0, 0, 0, 0, 0, 8, 0x80, 0, 0], 200);
    trace.ccid_in(&[0x80, 0, 0, 0, 0, 0, 7, 0x80, 0, 0], 300);
    trace.ccid_in(&[0x80, 0, 0, 0, 0, 0, 7, 0, 0, 0], 350);
    trace.ccid_out(&[0x6F, 0, 0, 0, 0, 0, 8, 0, 0, 0], 1000);
    trace.ccid_in(&[0x80, 0, 0, 0, 0, 0, 8, 0, 0, 0], 1500);
    assert_eq!(
        trace.report(),
        Ok("elapsed_ns=250 keepalives=1 max_gap_ns=200".into())
    );
    trace.arm();
    trace.ccid_out(&[0x6F, 0, 0, 0, 0, 0, 9, 0, 0, 0], 2000);
    trace.ccid_in(&[0x80, 0, 0, 0, 0, 0, 9, 0, 0, 0], 3000);
    assert_eq!(
        trace.report(),
        Ok("elapsed_ns=1000 keepalives=0 max_gap_ns=1000".into())
    );
}

#[test]
fn ccid_slot_status_also_completes_the_next_transaction_measurement() {
    let mut trace = Trace::default();
    trace.arm();
    trace.ccid_out(&[0x65, 0, 0, 0, 0, 0, 1, 0, 0, 0], 100);
    trace.ccid_in(&[0x81, 0, 0, 0, 0, 0, 1, 0, 0, 0], 150);
    assert_eq!(
        trace.report(),
        Ok("elapsed_ns=50 keepalives=0 max_gap_ns=50".into())
    );
}
