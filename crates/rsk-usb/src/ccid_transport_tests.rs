// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    reason = "a test's fixture is its own bound, and a panic is its failure report"
)]

use super::*;
use crate::test_driver::{Read, TestDriver, Trace, Write, drain_ready};
use core::task::Poll;
use embassy_futures::block_on;
use embassy_usb::driver::EndpointType;

#[derive(Default)]
struct Handler {
    requests: Vec<Vec<u8>>,
    resets: usize,
    reply_len: Option<usize>,
    pad_error: u8,
    wait_for_wtx: Option<Trace>,
}

impl Handler {
    async fn reply(&mut self, data: &[u8], out: &mut [u8]) -> usize {
        self.requests.push(data.to_vec());
        if let Some(trace) = &self.wait_for_wtx {
            core::future::poll_fn(|cx| {
                if trace
                    .borrow()
                    .packets
                    .iter()
                    .any(|(_, packet)| packet.get(7) == Some(&STATUS_TIMEEXT))
                {
                    Poll::Ready(())
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            })
            .await;
        }
        out.fill(0xA5);
        out[..2].copy_from_slice(&[0x90, 0x00]);
        self.reply_len.unwrap_or(2)
    }
}

impl ApduHandler for Handler {
    async fn handle_apdu(&mut self, data: &[u8], out: &mut [u8]) -> usize {
        self.reply(data, out).await
    }

    async fn handle_secure(&mut self, data: &[u8], out: &mut [u8]) -> SecureResult {
        SecureResult {
            len: self.reply(data, out).await,
            status: if self.pad_error == 0 {
                SECURE_STATUS_OK
            } else {
                SECURE_STATUS_FAILED
            },
            error: self.pad_error,
        }
    }

    async fn reset_card(&mut self) {
        self.resets += 1;
    }
}

fn message(kind: u8, seq: u8, body: &[u8]) -> Vec<u8> {
    let mut message = vec![0; HEADER + body.len()];
    put_header(&mut message, kind, body.len() as u32, seq, 0);
    message[HEADER..].copy_from_slice(body);
    message
}

fn with_ccid(
    pin_support: u8,
    reads: impl IntoIterator<Item = Read>,
    test: impl FnOnce(&mut Ccid<'_, TestDriver, Handler>, &Trace),
) -> [u8; 256] {
    let trace = Trace::default();
    trace.borrow_mut().reads.extend(reads);
    let mut config = [0; 256];
    let mut bos = [0; 256];
    let mut msos = [0; 256];
    let mut control = [0; 64];
    let mut builder = Builder::new(
        TestDriver::new(&trace),
        embassy_usb::Config::new(0x1209, 0xF1D2),
        &mut config,
        &mut bos,
        &mut msos,
        &mut control,
    );
    let mut ccid = Ccid::new(&mut builder, Handler::default(), ATR_RSKEY, pin_support);
    test(&mut ccid, &trace);
    drop(ccid);
    drop(builder);
    config
}

fn bulk_packets(trace: &Trace) -> Vec<Vec<u8>> {
    trace
        .borrow()
        .packets
        .iter()
        .filter(|(address, _)| address.index() == 1)
        .map(|(_, packet)| packet.clone())
        .collect()
}

fn complete<T>(future: impl core::future::Future<Output = T>) -> T {
    match block_on(select(future, Timer::after_millis(2 * RX_TIMEOUT_MS))) {
        Either::First(value) => value,
        Either::Second(()) => panic!("CCID operation did not complete"),
    }
}

#[test]
fn the_constructor_publishes_pin_support_and_three_endpoints() {
    for pin_support in [0, 1] {
        let config = with_ccid(pin_support, [], |_, trace| {
            let endpoints = &trace.borrow().allocated;
            assert_eq!(endpoints.len(), 3);
            assert_eq!(endpoints[0].ep_type, EndpointType::Bulk);
            assert!(endpoints[0].addr.is_out());
            assert_eq!(endpoints[1].ep_type, EndpointType::Bulk);
            assert!(endpoints[1].addr.is_in());
            assert_eq!(endpoints[2].ep_type, EndpointType::Interrupt);
            assert_eq!(endpoints[2].interval_ms, 10);
            assert!(
                endpoints
                    .iter()
                    .all(|ep| ep.max_packet_size == EP_PACKET_SIZE)
            );
        });
        let descriptor = config
            .windows(CCID_FUNCTIONAL_DESC.len() + 2)
            .find(|d| d[0] as usize == d.len() && d[1] == CCID_DESC_TYPE)
            .expect("CCID functional descriptor");
        assert_eq!(descriptor[52], pin_support);
    }
}

#[test]
fn bulk_reads_assemble_fragmented_headers_and_maximum_messages() {
    for body_len in [0, 4, 100, MAX_CCID_MSG - HEADER] {
        let request = message(CCID_XFR_BLOCK, 0x37, &vec![0x3C; body_len]);
        let reads = request[..3]
            .chunks(3)
            .chain(request[3..].chunks(usize::from(EP_PACKET_SIZE)))
            .map(|packet| Read::Packet(packet.to_vec()));
        with_ccid(0, reads, |ccid, _| {
            assert_eq!(complete(ccid.read_message()), Some(request.len()));
            assert_eq!(&ccid.rx[..request.len()], request);
        });
    }
}

#[test]
fn a_bus_reset_discards_the_partial_message_before_the_next_header() {
    let old = message(CCID_XFR_BLOCK, 1, &[0x3C; 100]);
    let next = message(CCID_POWER_ON, 9, &[]);
    with_ccid(
        0,
        [
            Read::Packet(old[..64].to_vec()),
            Read::Error(EndpointError::Disabled),
            Read::Packet(next.clone()),
        ],
        |ccid, _| {
            assert_eq!(complete(ccid.read_message()), Some(next.len()));
            assert_eq!(&ccid.rx[..next.len()], next);
        },
    );
}

#[test]
fn a_receive_timeout_discards_the_partial_message_before_the_next_header() {
    let old = message(CCID_XFR_BLOCK, 1, &[0x3C; 100]);
    let next = message(CCID_POWER_ON, 9, &[]);
    with_ccid(
        0,
        [
            Read::Packet(old[..64].to_vec()),
            Read::Stall,
            Read::Packet(next.clone()),
        ],
        |ccid, _| {
            assert_eq!(complete(ccid.read_message()), Some(next.len()));
            assert_eq!(&ccid.rx[..next.len()], next);
        },
    );
}

#[test]
fn an_oversized_message_echoes_its_sequence_and_the_reader_recovers() {
    let mut bad = message(CCID_XFR_BLOCK, 0xA7, &[]);
    bad[1..5].copy_from_slice(&(MAX_CCID_MSG as u32).to_le_bytes());
    with_ccid(
        0,
        [bad, message(CCID_POWER_ON, 9, &[])].map(Read::Packet),
        |ccid, trace| {
            drain_ready(ccid.run());
            let packets = bulk_packets(trace);
            assert_eq!(packets[0], [0x80, 2, 0, 0, 0, 0, 0xA7, 1, 0, 0, 0x6F, 0]);
            assert_eq!(&packets[1][HEADER..], ATR_RSKEY);
            assert_eq!(packets[1][6], 9);
            assert_eq!(ccid.handler.resets, 1);
        },
    );
}

#[test]
fn endpoint_overflow_is_a_framing_error() {
    with_ccid(
        0,
        [Read::Error(EndpointError::BufferOverflow)],
        |ccid, _| {
            assert_eq!(complete(ccid.read_message()), None);
        },
    );
}

#[test]
fn the_bulk_loop_routes_commands_and_resets_the_card_at_each_power_transition() {
    let apdu = [0, 0xA4, 4, 0];
    with_ccid(
        0,
        [
            message(CCID_POWER_ON, 1, &[]),
            message(CCID_XFR_BLOCK, 2, &[0, 0xA4]),
            message(CCID_XFR_BLOCK, 3, &apdu),
            message(CCID_SECURE, 4, &[0x55; 24]),
            message(0xFF, 5, &[]),
            message(CCID_POWER_OFF, 6, &[]),
        ]
        .map(Read::Packet),
        |ccid, trace| {
            drain_ready(ccid.run());
            let packets = bulk_packets(trace);
            assert_eq!(packets.len(), 5);
            assert_eq!(
                packets[1],
                [0x81, 0, 0, 0, 0, 0, 2, 0x40, ERR_BAD_DWLENGTH, 0]
            );
            assert_eq!(packets[2], [0x80, 2, 0, 0, 0, 0, 3, 0, 0, 0, 0x90, 0]);
            assert_eq!(packets[3], [0x80, 2, 0, 0, 0, 0, 4, 0, 0, 0, 0x90, 0]);
            assert_eq!(packets[4], [0x81, 0, 0, 0, 0, 0, 6, 1, 0, 0]);
            assert_eq!(ccid.handler.requests, [apdu.to_vec(), vec![0x55; 24]]);
            assert_eq!(ccid.handler.resets, 2);
            assert_eq!(ccid.status, STATUS_INACTIVE);
        },
    );
}

#[test]
fn apdu_replies_are_clamped_terminated_and_wiped_even_when_the_endpoint_fails() {
    for fail in [false, true] {
        with_ccid(0, [], |ccid, trace| {
            let request = message(CCID_XFR_BLOCK, 0x31, &[0x3C; 4]);
            ccid.rx[..request.len()].copy_from_slice(&request);
            ccid.handler.reply_len = Some(usize::MAX);
            if fail {
                trace.borrow_mut().writes.push_back(Write::Error);
            }
            complete(ccid.run_xfr(HEADER, request.len()));
            assert!(ccid.rx[HEADER..request.len()].iter().all(|byte| *byte == 0));
            assert!(ccid.tx.iter().all(|byte| *byte == 0));
            let packets = bulk_packets(trace);
            if fail {
                assert!(packets.is_empty());
            } else {
                assert_eq!(
                    packets.len(),
                    MAX_CCID_MSG / usize::from(EP_PACKET_SIZE) + 1
                );
                assert!(
                    packets.last().unwrap().is_empty(),
                    "missing terminating ZLP"
                );
                assert_eq!(packets[0][6], 0x31);
                assert_eq!(packets[0][7], STATUS_INACTIVE);
                assert_eq!(
                    u32::from_le_bytes(packets[0][1..5].try_into().unwrap()) as usize,
                    MAX_CCID_MSG - HEADER
                );
            }
        });
    }
}

#[test]
fn secure_replies_preserve_card_status_and_report_pad_errors() {
    for error in [0, SECURE_ERR_CANCELLED, SECURE_ERR_TIMEOUT] {
        with_ccid(1, [], |ccid, trace| {
            let request = message(CCID_SECURE, 0x71, &[0x3C; 24]);
            ccid.rx[..request.len()].copy_from_slice(&request);
            ccid.handler.pad_error = error;
            ccid.handler.reply_len = Some(usize::from(EP_PACKET_SIZE) - HEADER);
            complete(ccid.run_secure(HEADER, request.len()));
            let packets = bulk_packets(trace);
            assert_eq!(packets.len(), 2);
            assert!(packets[1].is_empty(), "missing terminating ZLP");
            assert_eq!(packets[0][6], 0x71);
            assert_eq!(
                packets[0][7],
                if error == 0 {
                    STATUS_INACTIVE
                } else {
                    SECURE_STATUS_FAILED
                }
            );
            assert_eq!(packets[0][8], error);
            assert!(ccid.rx[HEADER..request.len()].iter().all(|byte| *byte == 0));
            assert!(
                ccid.tx[..usize::from(EP_PACKET_SIZE)]
                    .iter()
                    .all(|byte| *byte == 0)
            );
        });
    }
}

#[test]
fn slow_apdu_and_secure_handlers_stream_time_extensions() {
    for secure in [false, true] {
        with_ccid(1, [], |ccid, trace| {
            ccid.rx[6] = 0x71;
            ccid.rx[HEADER..HEADER + 4].fill(0x3C);
            ccid.handler.wait_for_wtx = Some(trace.clone());
            if secure {
                complete(ccid.run_secure(HEADER, HEADER + 4));
            } else {
                complete(ccid.run_xfr(HEADER, HEADER + 4));
            }
            let packets = bulk_packets(trace);
            assert_eq!(
                packets[0],
                [0x80, 0, 0, 0, 0, 0, 0x71, STATUS_TIMEEXT, 0, 0]
            );
            assert_eq!(packets[1], [0x80, 2, 0, 0, 0, 0, 0x71, 1, 0, 0, 0x90, 0]);
        });
    }
}

#[test]
fn a_stalled_response_is_abandoned_and_its_buffers_are_wiped() {
    with_ccid(0, [], |ccid, trace| {
        ccid.rx[HEADER..HEADER + 4].fill(0x3C);
        trace.borrow_mut().writes.push_back(Write::Stall);
        complete(ccid.run_xfr(HEADER, HEADER + 4));
        assert!(bulk_packets(trace).is_empty());
        assert!(ccid.rx[HEADER..HEADER + 4].iter().all(|byte| *byte == 0));
        assert!(ccid.tx[..HEADER + 2].iter().all(|byte| *byte == 0));
        complete(ccid.run_xfr(HEADER, HEADER));
        assert_eq!(
            bulk_packets(trace).len(),
            1,
            "the next response stayed blocked"
        );
    });
}
