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
use core::cell::Cell;
use core::task::{Context, Poll, Waker};
use embassy_futures::block_on;
use embassy_usb::class::hid::{Config, HidBootProtocol, HidReaderWriter, HidSubclass, State};

const OWNER: u32 = 0x1122_3344;
const OTHER: u32 = 0x5566_7788;

thread_local! {
    static CANCELS: Cell<usize> = const { Cell::new(0) };
    static PENDING_POLLS: Cell<usize> = const { Cell::new(0) };
}

fn release_presence() -> bool {
    PENDING_POLLS.with(|polls| {
        let n = polls.get();
        polls.set(n + 1);
        n == 0
    })
}

fn cancel() {
    CANCELS.with(|count| count.set(count.get() + 1));
}

#[derive(Default)]
struct Handler {
    requests: Vec<(u32, u8, Vec<u8>)>,
    resets: usize,
    has_wink: bool,
    winks: usize,
    vendor_supported: bool,
    wait_for_keepalive: Option<Trace>,
    wait_for_cancel: bool,
    reply_delay_ms: Option<u64>,
}

impl Handler {
    async fn reply(&self, out: &mut [u8]) -> usize {
        if let Some(ms) = self.reply_delay_ms {
            Timer::after_millis(ms).await;
        }
        if self.wait_for_cancel {
            core::future::poll_fn(|cx| {
                if CANCELS.with(|count| count.get() > 0) {
                    Poll::Ready(())
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            })
            .await;
            out[0] = 0x2D; // CTAP2_ERR_KEEPALIVE_CANCEL from the stand-in worker.
            return 1;
        }
        if let Some(trace) = &self.wait_for_keepalive {
            core::future::poll_fn(|cx| {
                if trace
                    .borrow()
                    .packets
                    .iter()
                    .any(|(_, packet)| packet.get(4) == Some(&CTAPHID_KEEPALIVE))
                {
                    Poll::Ready(())
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            })
            .await;
        }
        out[..2].copy_from_slice(&[0x90, 0x00]);
        2
    }
}

impl MsgHandler for Handler {
    async fn handle_msg(&mut self, cid: u32, data: &[u8], out: &mut [u8]) -> usize {
        self.requests.push((cid, CTAPHID_MSG, data.to_vec()));
        self.reply(out).await
    }

    async fn handle_cbor(&mut self, cid: u32, data: &[u8], out: &mut [u8]) -> usize {
        self.requests.push((cid, CTAPHID_CBOR, data.to_vec()));
        self.reply(out).await
    }

    async fn handle_vendor(
        &mut self,
        cid: u32,
        cmd: u8,
        data: &[u8],
        out: &mut [u8],
    ) -> Option<usize> {
        self.requests.push((cid, cmd, data.to_vec()));
        if self.vendor_supported {
            Some(self.reply(out).await)
        } else {
            None
        }
    }

    fn reset_app_selection(&mut self) {
        self.resets += 1;
    }

    fn can_wink(&self) -> bool {
        self.has_wink
    }

    fn wink(&mut self) {
        self.winks += 1;
    }
}

fn frames(cid: u32, cmd: u8, body: &[u8]) -> Vec<Read> {
    TxFrames::new(cid, cmd, body)
        .map(|frame| Read::Packet(frame.to_vec()))
        .collect()
}

fn with_hid(
    reads: impl IntoIterator<Item = Read>,
    test: impl FnOnce(&mut CtapHid<'_, TestDriver, Handler>, &Trace),
) {
    CANCELS.with(|count| count.set(0));
    let trace = Trace::default();
    trace.borrow_mut().reads.extend(reads);
    let mut state = State::new();
    let mut config = [0; 256];
    let mut bos = [0; 256];
    let mut msos = [0; 256];
    let mut control = [0; 64];
    let mut builder = embassy_usb::Builder::new(
        TestDriver::new(&trace),
        embassy_usb::Config::new(0x1209, 0xF1D2),
        &mut config,
        &mut bos,
        &mut msos,
        &mut control,
    );
    let io = HidReaderWriter::<_, HID_RPT_SIZE, HID_RPT_SIZE>::new(
        &mut builder,
        &mut state,
        Config {
            report_descriptor: FIDO_REPORT_DESCRIPTOR,
            request_handler: None,
            poll_ms: 5,
            max_packet_size: HID_RPT_SIZE as u16,
            hid_subclass: HidSubclass::No,
            hid_boot_protocol: HidBootProtocol::None,
        },
    );
    let (reader, writer) = io.split();
    let mut hid = CtapHid::new(reader, writer, Handler::default(), || false, cancel);
    test(&mut hid, &trace);
}

fn responses(trace: &Trace) -> Vec<(u32, u8, Vec<u8>)> {
    let mut assembler = Reassembler::new();
    let mut messages = Vec::new();
    for (_, packet) in &trace.borrow().packets {
        assert_eq!(packet.len(), HID_RPT_SIZE);
        match assembler.feed(packet.as_slice().try_into().unwrap()) {
            Outcome::None => {}
            Outcome::Message(cid, cmd) => messages.push((cid, cmd, assembler.message().to_vec())),
            Outcome::Error(cid, code) => panic!("invalid outgoing frame: {cid:x}, {code}"),
        }
    }
    assert!(!assembler.in_progress(), "incomplete outgoing message");
    messages
}

fn complete<T>(future: impl Future<Output = T>) -> T {
    match block_on(select(future, Timer::after_millis(2 * RX_TIMEOUT_MS))) {
        Either::First(value) => value,
        Either::Second(()) => panic!("CTAPHID operation did not complete"),
    }
}

#[test]
fn init_allocates_distinct_channels_and_resynchronizes_the_existing_one() {
    let nonce = [0xA5; 8];
    let reads = frames(CID_BROADCAST, CTAPHID_INIT, &nonce)
        .into_iter()
        .chain(frames(CID_BROADCAST, CTAPHID_INIT, &nonce))
        .chain(frames(OWNER, CTAPHID_INIT, &nonce));
    with_hid(reads, |hid, trace| {
        drain_ready(hid.run());
        let replies = responses(trace);
        assert_eq!(replies.len(), 3);
        let mut assigned = Vec::new();
        for (cid, cmd, body) in &replies {
            assert_eq!(*cmd, CTAPHID_INIT);
            assert_eq!(body.len(), 17);
            assert_eq!(&body[..8], nonce);
            assert_eq!(
                &body[12..],
                [
                    CTAPHID_IF_VERSION,
                    VERSION_MAJOR,
                    VERSION_MINOR,
                    VERSION_BUILD,
                    CAPFLAG_CBOR
                ]
            );
            let channel = u32::from_le_bytes(body[8..12].try_into().unwrap());
            assert!(!matches!(channel, 0 | CID_BROADCAST));
            if *cid == OWNER {
                assert_eq!(channel, OWNER);
            } else {
                assert_eq!(*cid, CID_BROADCAST);
            }
            assigned.push(channel);
        }
        assert_ne!(assigned[0], assigned[1]);
        assert_eq!(hid.handler.resets, 3);
    });
}

#[test]
fn wink_capabilities_match_the_dispatched_indicator() {
    for has_wink in [false, true] {
        with_hid(
            frames(OWNER, CTAPHID_INIT, &[0; 8])
                .into_iter()
                .chain(frames(OWNER, CTAPHID_WINK, &[])),
            |hid, trace| {
                hid.handler.has_wink = has_wink;
                drain_ready(hid.run());
                let replies = responses(trace);
                assert_eq!(
                    replies[0].2[16],
                    CAPFLAG_CBOR | if has_wink { CAPFLAG_WINK } else { 0 }
                );
                assert_eq!(hid.handler.winks, usize::from(has_wink));
                assert_eq!(
                    replies[1],
                    if has_wink {
                        (OWNER, CTAPHID_WINK, vec![])
                    } else {
                        (OWNER, CTAPHID_ERROR, vec![ERR_INVALID_CMD])
                    }
                );
            },
        );
    }
}

#[test]
fn native_commands_reply_without_calling_an_applet() {
    let body = vec![0xA5; INIT_DATA + CONT_DATA + 3];
    let reads = frames(OWNER, CTAPHID_PING, &body)
        .into_iter()
        .chain(frames(OWNER, CTAPHID_SYNC, &[1, 2, 3]))
        .chain(frames(OWNER, CTAPHID_VERSION, &[]))
        .chain(frames(OWNER, CTAPHID_UUID, &[]))
        .chain(frames(OWNER, CTAPHID_CANCEL, &[]));
    with_hid(reads, |hid, trace| {
        drain_ready(hid.run());
        assert_eq!(
            responses(trace),
            [
                (OWNER, CTAPHID_PING, body),
                (OWNER, CTAPHID_SYNC, vec![1, 2, 3]),
                (
                    OWNER,
                    CTAPHID_VERSION,
                    vec![VERSION_MAJOR, VERSION_MINOR, VERSION_BUILD, 0]
                ),
                (OWNER, CTAPHID_UUID, DEVICE_UUID.to_vec()),
            ]
        );
        assert!(hid.handler.requests.is_empty());
        assert_eq!(CANCELS.with(Cell::get), 0);
    });
}

#[test]
fn lock_refuses_a_stranger_but_allows_broadcast_init_and_the_owners_release() {
    let reads = frames(OWNER, CTAPHID_LOCK, &[LOCK_MAX_SECONDS])
        .into_iter()
        .chain(frames(OTHER, CTAPHID_PING, &[1]))
        .chain(frames(OTHER, CTAPHID_INIT, &[0; 8]))
        .chain(frames(CID_BROADCAST, CTAPHID_INIT, &[0; 8]))
        .chain(frames(OWNER, CTAPHID_PING, &[2]))
        .chain(frames(OWNER, CTAPHID_LOCK, &[0]))
        .chain(frames(OTHER, CTAPHID_PING, &[3]));
    with_hid(reads, |hid, trace| {
        drain_ready(hid.run());
        let replies = responses(trace);
        assert_eq!(replies[0], (OWNER, CTAPHID_LOCK, vec![]));
        assert_eq!(replies[1], (OTHER, CTAPHID_ERROR, vec![ERR_CHANNEL_BUSY]));
        assert_eq!(replies[2], (OTHER, CTAPHID_ERROR, vec![ERR_CHANNEL_BUSY]));
        assert_eq!(replies[3].0, CID_BROADCAST);
        assert_eq!(replies[3].1, CTAPHID_INIT);
        assert_eq!(replies[4], (OWNER, CTAPHID_PING, vec![2]));
        assert_eq!(replies[5], (OWNER, CTAPHID_LOCK, vec![]));
        assert_eq!(replies[6], (OTHER, CTAPHID_PING, vec![3]));
    });
}

#[test]
fn invalid_commands_and_lengths_are_refused_without_app_dispatch() {
    let reads = frames(OWNER, CTAPHID_LOCK, &[])
        .into_iter()
        .chain(frames(OWNER, CTAPHID_LOCK, &[1, 2]))
        .chain(frames(OWNER, CTAPHID_LOCK, &[LOCK_MAX_SECONDS + 1]))
        .chain(frames(OWNER, CTAPHID_CBOR, &[]))
        .chain(frames(OWNER, TYPE_INIT | 0x20, &[]));
    with_hid(reads, |hid, trace| {
        drain_ready(hid.run());
        let errors: Vec<_> = responses(trace)
            .into_iter()
            .map(|(_, cmd, body)| {
                assert_eq!(cmd, CTAPHID_ERROR);
                body
            })
            .collect();
        assert_eq!(
            errors,
            [
                vec![ERR_INVALID_LEN],
                vec![ERR_INVALID_LEN],
                vec![ERR_INVALID_PAR],
                vec![ERR_INVALID_LEN],
                vec![ERR_INVALID_CMD],
            ]
        );
        assert!(hid.handler.requests.is_empty());
    });
}

#[test]
fn app_commands_preserve_the_channel_and_wipe_request_and_response() {
    for (wire_cmd, logical_cmd) in [
        (CTAPHID_MSG, CTAPHID_MSG),
        (CTAPHID_CBOR, CTAPHID_CBOR),
        (CTAPHID_VENDOR_FIRST, CTAPHID_VENDOR_FIRST & !TYPE_INIT),
    ] {
        with_hid(frames(OWNER, wire_cmd, &[0xA5; 4]), |hid, trace| {
            hid.handler.vendor_supported = true;
            drain_ready(hid.run());
            assert_eq!(hid.handler.requests, [(OWNER, logical_cmd, vec![0xA5; 4])]);
            assert_eq!(responses(trace), [(OWNER, wire_cmd, vec![0x90, 0])]);
            assert!(hid.asm.msg.iter().all(|byte| *byte == 0));
            assert!(hid.scratch.iter().all(|byte| *byte == 0));
            assert!(!hid.asm.in_progress());
        });
    }
}

#[test]
fn a_rejected_vendor_command_still_scrubs_the_request() {
    with_hid(
        frames(OWNER, CTAPHID_VENDOR_FIRST, &[0xA5; 4]),
        |hid, trace| {
            drain_ready(hid.run());
            assert_eq!(
                responses(trace),
                [(OWNER, CTAPHID_ERROR, vec![ERR_INVALID_CMD])]
            );
            assert!(hid.asm.msg.iter().all(|byte| *byte == 0));
        },
    );
}

#[test]
fn processing_keepalives_do_not_consume_the_pipelined_next_command() {
    let reads =
        frames(OWNER, CTAPHID_CBOR, &[1])
            .into_iter()
            .chain(frames(OTHER, CTAPHID_CBOR, &[2]));
    with_hid(reads, |hid, trace| {
        hid.handler.wait_for_keepalive = Some(trace.clone());
        let _ = block_on(select(hid.run(), Timer::after_millis(3 * KEEPALIVE_MS)));
        assert_eq!(
            hid.handler.requests,
            [
                (OWNER, CTAPHID_CBOR, vec![1]),
                (OTHER, CTAPHID_CBOR, vec![2]),
            ]
        );
        assert_eq!(
            responses(trace),
            [
                (OWNER, CTAPHID_KEEPALIVE, vec![STATUS_PROCESSING]),
                (OWNER, CTAPHID_CBOR, vec![0x90, 0]),
                (OTHER, CTAPHID_CBOR, vec![0x90, 0]),
            ]
        );
    });
}

#[test]
fn a_touch_wait_streams_upneeded_keepalives() {
    with_hid([], |hid, trace| {
        hid.up_pending = || true;
        hid.handler.wait_for_keepalive = Some(trace.clone());
        hid.asm
            .feed(&TxFrames::new(OWNER, CTAPHID_CBOR, &[1]).next().unwrap());
        complete(hid.run_with_keepalive(OWNER, Call::Cbor));
        assert_eq!(
            responses(trace),
            [
                (OWNER, CTAPHID_KEEPALIVE, vec![STATUS_UPNEEDED]),
                (OWNER, CTAPHID_CBOR, vec![0x90, 0]),
            ]
        );
    });
}

#[test]
fn only_the_active_channels_cancel_can_abort_the_touch_wait() {
    let reads = frames(OTHER, CTAPHID_CANCEL, &[])
        .into_iter()
        .chain(frames(OWNER, CTAPHID_PING, &[0]))
        .chain([
            Read::Packet(vec![0; 3]),
            Read::Error(embassy_usb::driver::EndpointError::Disabled),
        ]);
    with_hid(reads, |hid, trace| {
        hid.up_pending = || true;
        hid.handler.wait_for_cancel = true;
        hid.asm
            .feed(&TxFrames::new(OWNER, CTAPHID_CBOR, &[1]).next().unwrap());
        {
            let mut future = core::pin::pin!(hid.run_with_keepalive(OWNER, Call::Cbor));
            let mut cx = Context::from_waker(Waker::noop());
            let progress = future.as_mut().poll(&mut cx);
            assert_eq!(
                CANCELS.with(Cell::get),
                0,
                "a stranger or malformed CANCEL was accepted"
            );
            assert!(progress.is_pending());
            trace
                .borrow_mut()
                .reads
                .extend(frames(OWNER, CTAPHID_CANCEL, &[]));
            assert!(future.as_mut().poll(&mut cx).is_ready());
        }
        assert_eq!(CANCELS.with(Cell::get), 1);
        assert_eq!(responses(trace), [(OWNER, CTAPHID_CBOR, vec![0x2D])]);
        assert!(hid.asm.msg.iter().all(|byte| *byte == 0));
        assert!(hid.scratch.iter().all(|byte| *byte == 0));
    });
}

#[test]
fn incomplete_requests_time_out_and_the_next_request_still_runs() {
    let partial = TxFrames::new(OWNER, CTAPHID_CBOR, &[0xA5; INIT_DATA + 1])
        .next()
        .unwrap();
    let reads = [Read::Packet(partial.to_vec()), Read::Stall]
        .into_iter()
        .chain(frames(OTHER, CTAPHID_PING, &[3]));
    with_hid(reads, |hid, trace| {
        let _ = block_on(select(
            hid.run(),
            Timer::after_millis(RX_TIMEOUT_MS + KEEPALIVE_MS),
        ));
        assert_eq!(
            responses(trace),
            [
                (OWNER, CTAPHID_ERROR, vec![ERR_MSG_TIMEOUT]),
                (OTHER, CTAPHID_PING, vec![3]),
            ]
        );
        assert!(hid.handler.requests.is_empty());
    });
}

#[test]
fn bad_sequences_and_short_reports_never_reach_the_applet() {
    let body = [0xA5; INIT_DATA + 1];
    let mut request = TxFrames::new(OWNER, CTAPHID_CBOR, &body);
    let first = request.next().unwrap();
    let mut bad = request.next().unwrap();
    bad[4] = 1;
    let reads = [
        Read::Packet(vec![0; 3]),
        Read::Packet(first.to_vec()),
        Read::Packet(bad.to_vec()),
    ]
    .into_iter()
    .chain(frames(OTHER, CTAPHID_PING, &[3]));
    with_hid(reads, |hid, trace| {
        drain_ready(hid.run());
        assert_eq!(
            responses(trace),
            [
                (OWNER, CTAPHID_ERROR, vec![ERR_INVALID_SEQ]),
                (OTHER, CTAPHID_PING, vec![3]),
            ]
        );
        assert!(hid.handler.requests.is_empty());
    });
}

#[test]
fn short_reads_and_endpoint_errors_do_not_finish_an_incomplete_request() {
    let body = [0xA5; INIT_DATA + 1];
    let mut request = frames(OWNER, CTAPHID_CBOR, &body).into_iter();
    let reads = [
        request.next().unwrap(),
        Read::Packet(vec![0; 3]),
        Read::Error(embassy_usb::driver::EndpointError::Disabled),
        request.next().unwrap(),
    ];
    with_hid(reads, |hid, trace| {
        drain_ready(hid.run());
        assert_eq!(hid.handler.requests, [(OWNER, CTAPHID_CBOR, body.to_vec())]);
        assert_eq!(responses(trace), [(OWNER, CTAPHID_CBOR, vec![0x90, 0])]);
    });
}

#[test]
fn a_slow_msg_or_vendor_call_has_no_processing_keepalive_after_presence_ends() {
    for vendor in [false, true] {
        for pending in [false, true] {
            with_hid([], |hid, trace| {
                PENDING_POLLS.with(|polls| polls.set(0));
                hid.up_pending = if pending { release_presence } else { || false };
                hid.handler.reply_delay_ms = Some(2 * KEEPALIVE_MS);
                hid.handler.vendor_supported = true;
                let cmd = if vendor {
                    TYPE_INIT | 0x40
                } else {
                    CTAPHID_MSG
                };
                hid.asm
                    .feed(&TxFrames::new(OWNER, cmd, &[1]).next().unwrap());
                complete(
                    hid.run_with_keepalive(
                        OWNER,
                        if vendor { Call::Vendor(cmd) } else { Call::Msg },
                    ),
                );
                assert_eq!(responses(trace), [(OWNER, cmd, vec![0x90, 0])]);
            });
        }
    }
}

#[test]
fn a_stalled_response_is_abandoned_without_blocking_the_next_command() {
    with_hid([], |hid, trace| {
        hid.asm
            .feed(&TxFrames::new(OWNER, CTAPHID_CBOR, &[1]).next().unwrap());
        trace.borrow_mut().writes.push_back(Write::Stall);
        complete(hid.run_with_keepalive(OWNER, Call::Cbor));
        assert!(responses(trace).is_empty());
        assert!(hid.scratch.iter().all(|byte| *byte == 0));
        assert!(hid.asm.msg.iter().all(|byte| *byte == 0));
        trace
            .borrow_mut()
            .reads
            .extend(frames(OTHER, CTAPHID_PING, &[3]));
        drain_ready(hid.run());
        assert_eq!(responses(trace), [(OTHER, CTAPHID_PING, vec![3])]);
    });
}
