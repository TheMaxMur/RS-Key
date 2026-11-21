// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::usbip::tests::{dev, ifaces, op_req, submit_bytes};
use crate::usbip::{
    BUSID_LEN, CMD_UNLINK, DIR_OUT, ECONNRESET, EPIPE, OP_REQ_DEVLIST, OP_REQ_IMPORT,
    USB_DEVICE_LEN, USB_INTERFACE_LEN,
};

/// A sink that only records: the transport hands URBs over and walks away, so
/// what it does with them is the driver's business, not the framing's.
#[derive(Default)]
struct Record {
    seen: Vec<Urb>,
    /// Sequence numbers this sink claims are still in flight.
    pending: Vec<u32>,
    detached: bool,
    rets: Option<std::sync::mpsc::Sender<Ret>>,
}

impl UrbSink for Record {
    fn attach(&mut self, rets: std::sync::mpsc::Sender<Ret>) {
        self.rets = Some(rets);
    }
    fn submit(&mut self, urb: Urb) {
        self.seen.push(urb);
    }
    fn unlink(&mut self, seqnum: u32) -> bool {
        self.pending.contains(&seqnum)
    }
    fn detach(&mut self) {
        self.detached = true;
        self.rets = None;
    }
}

/// Feed a script through the attached phase and collect both halves: what the
/// sink was handed, and what the transport put on the completion channel.
fn attached(script: Vec<u8>, sink: &mut Record) -> Vec<Ret> {
    let (tx, rx) = std::sync::mpsc::channel();
    let mut input = std::io::Cursor::new(script);
    serve_attached(&mut input, sink, tx).unwrap();
    rx.into_iter().collect()
}

/// An IN submit reaches the sink with the host's buffer size and consumes no
/// payload — an IN URB is header-only on the wire.
#[test]
fn an_in_submit_reaches_the_sink_with_its_length() {
    let mut sink = Record::default();
    let rets = attached(submit_bytes(DIR_IN, 1, 8, [0; 8]).to_vec(), &mut sink);
    assert_eq!(sink.seen.len(), 1);
    assert_eq!(sink.seen[0].ep, 1);
    assert!(sink.seen[0].dir_in);
    assert_eq!(sink.seen[0].want, 8);
    assert!(sink.seen[0].out.is_empty());
    assert!(rets.is_empty(), "the transport answers nothing by itself");
}

/// An OUT submit's payload must be consumed from the stream and handed over
/// whole; the driver is what packetises it.
#[test]
fn an_out_submit_carries_its_payload_to_the_sink() {
    let mut script = submit_bytes(DIR_OUT, 1, 4, [0; 8]).to_vec();
    script.extend_from_slice(&[1, 2, 3, 4]);
    let mut sink = Record::default();
    attached(script, &mut sink);
    assert_eq!(sink.seen.len(), 1);
    assert!(!sink.seen[0].dir_in);
    assert_eq!(sink.seen[0].out, vec![1, 2, 3, 4]);
}

/// Two URBs back to back: the second is only framed correctly if the first
/// consumed exactly its own payload.
#[test]
fn back_to_back_submits_stay_framed() {
    let mut script = submit_bytes(DIR_OUT, 1, 2, [0; 8]).to_vec();
    script.extend_from_slice(&[7, 8]);
    script.extend_from_slice(&submit_bytes(DIR_OUT, 2, 1, [0; 8]));
    script.extend_from_slice(&[9]);
    let mut sink = Record::default();
    attached(script, &mut sink);
    let seen: Vec<(u8, Vec<u8>)> = sink.seen.iter().map(|u| (u.ep, u.out.clone())).collect();
    assert_eq!(seen, vec![(1, vec![7, 8]), (2, vec![9])]);
}

/// The point of the split: a URB the device has not answered must not stop the
/// next one from being read. A sink that never completes anything still sees
/// every submit.
#[test]
fn an_unanswered_urb_does_not_block_the_next() {
    let mut script = submit_bytes(DIR_IN, 1, 64, [0; 8]).to_vec();
    script.extend_from_slice(&submit_bytes(DIR_IN, 0, 18, [0x80, 6, 0, 1, 0, 0, 18, 0]));
    let mut sink = Record::default();
    attached(script, &mut sink);
    assert_eq!(sink.seen.len(), 2);
    assert_eq!(sink.seen[1].ep, 0, "the control transfer got through");
}

/// A control transfer is routed by endpoint, not by guessing from the setup
/// packet, and the SETUP bytes reach the sink intact.
#[test]
fn ep0_routes_to_control_with_its_setup() {
    let setup = [0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00];
    let mut sink = Record::default();
    attached(submit_bytes(DIR_IN, 0, 18, setup).to_vec(), &mut sink);
    assert_eq!(sink.seen[0].ep, 0);
    assert_eq!(sink.seen[0].setup, setup);
}

/// An endpoint number outside USB's four bits names nothing we have. It must
/// halt rather than alias onto a real endpoint — and its payload still has to
/// leave the stream, or every URB after it lands in the wrong place.
#[test]
fn an_impossible_endpoint_halts_without_desyncing() {
    let mut script = submit_bytes(DIR_OUT, 99, 2, [0; 8]).to_vec();
    script.extend_from_slice(&[0xAA, 0xBB]);
    script.extend_from_slice(&submit_bytes(DIR_OUT, 1, 1, [0; 8]));
    script.extend_from_slice(&[0xCC]);
    let mut sink = Record::default();
    let rets = attached(script, &mut sink);
    assert_eq!(rets, vec![Ret::stall(7)]);
    assert_eq!(sink.seen.len(), 1, "only the real endpoint was routed");
    assert_eq!(sink.seen[0].out, vec![0xCC]);
}

/// An unlink of a URB the device still holds is `-ECONNRESET`; one that has
/// already completed is a plain 0. Answering both the same way makes the host
/// wait out its own timeout on a URB that is never coming back.
#[test]
fn unlink_distinguishes_in_flight_from_already_done() {
    let mut b = [0u8; CMD_HEADER_LEN];
    b[0..4].copy_from_slice(&CMD_UNLINK.to_be_bytes());
    b[4..8].copy_from_slice(&9u32.to_be_bytes());
    b[20..24].copy_from_slice(&7u32.to_be_bytes());

    let mut sink = Record {
        pending: vec![7],
        ..Record::default()
    };
    assert_eq!(
        attached(b.to_vec(), &mut sink),
        vec![Ret::Unlink {
            seqnum: 9,
            status: ECONNRESET
        }]
    );

    let mut sink = Record::default();
    assert_eq!(
        attached(b.to_vec(), &mut sink),
        vec![Ret::Unlink {
            seqnum: 9,
            status: 0
        }]
    );
}

/// The sink is told when the host leaves, so it can fail what is still pending
/// instead of holding endpoints open for a peer that is gone.
#[test]
fn the_sink_is_told_the_host_left() {
    let mut sink = Record::default();
    attached(Vec::new(), &mut sink);
    assert!(sink.detached);
}

/// An IN completion is a header *and* its data; the length in the header must
/// match the bytes that follow, or the host mis-slices the stream.
#[test]
fn an_in_completion_encodes_its_data_after_the_header() {
    let b = Ret::in_data(7, vec![0xAA, 0xBB, 0xCC]).encode();
    assert_eq!(b.len(), CMD_HEADER_LEN + 3);
    assert_eq!(i32::from_be_bytes([b[24], b[25], b[26], b[27]]), 3);
    assert_eq!(&b[CMD_HEADER_LEN..], &[0xAA, 0xBB, 0xCC]);
}

/// An OUT completion reports how much the device took and carries no payload —
/// writing data back would desynchronise the host.
#[test]
fn an_out_completion_is_header_only() {
    let b = Ret::out_done(7, 64).encode();
    assert_eq!(b.len(), CMD_HEADER_LEN);
    assert_eq!(i32::from_be_bytes([b[24], b[25], b[26], b[27]]), 64);
}

#[test]
fn a_stall_is_reported_as_epipe_with_no_data() {
    let b = Ret::stall(7).encode();
    assert_eq!(b.len(), CMD_HEADER_LEN);
    assert_eq!(i32::from_be_bytes([b[20], b[21], b[22], b[23]]), EPIPE);
}

/// The completions go out in the order the device produced them, back to back.
#[test]
fn the_writer_drains_completions_in_order() {
    let (tx, rx) = std::sync::mpsc::channel();
    tx.send(Ret::in_data(1, vec![0xAA])).unwrap();
    tx.send(Ret::out_done(2, 4)).unwrap();
    drop(tx);
    let mut out = Vec::new();
    pump_rets(&mut out, &rx).unwrap();
    assert_eq!(out.len(), 2 * CMD_HEADER_LEN + 1);
    assert_eq!(&out[4..8], &1u32.to_be_bytes());
    assert_eq!(out[CMD_HEADER_LEN], 0xAA);
    assert_eq!(
        &out[CMD_HEADER_LEN + 1 + 4..CMD_HEADER_LEN + 1 + 8],
        &2u32.to_be_bytes()
    );
}

fn op(script: Vec<u8>) -> (bool, Vec<u8>) {
    struct Pipe {
        input: std::io::Cursor<Vec<u8>>,
        out: Vec<u8>,
    }
    impl std::io::Read for Pipe {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(b)
        }
    }
    impl std::io::Write for Pipe {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.out.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut p = Pipe {
        input: std::io::Cursor::new(script),
        out: Vec::new(),
    };
    let attached = serve_op(&mut p, &dev(), &ifaces()).unwrap();
    (attached, p.out)
}

/// A client may list and leave without importing; that is the `usbip list -r`
/// case and must not be mistaken for an attach.
#[test]
fn a_listing_client_is_served_and_released() {
    let (attached, out) = op(op_req(OP_REQ_DEVLIST, &[]));
    assert!(!attached);
    assert_eq!(out.len(), 12 + USB_DEVICE_LEN + 3 * USB_INTERFACE_LEN);
}

/// Two op requests on one connection: a list, then an import. The second is only
/// framed correctly if the first read exactly its own (empty) body.
#[test]
fn a_list_then_import_stays_framed() {
    let mut busid = [0u8; BUSID_LEN];
    busid[..BUSID.len()].copy_from_slice(BUSID.as_bytes());
    let mut script = op_req(OP_REQ_DEVLIST, &[]);
    script.extend_from_slice(&op_req(OP_REQ_IMPORT, &busid));
    let (attached, out) = op(script);
    assert!(attached);
    assert_eq!(
        out.len(),
        12 + USB_DEVICE_LEN + 3 * USB_INTERFACE_LEN + OP_HEADER_LEN + USB_DEVICE_LEN
    );
}

/// A refused import leaves the connection in the op phase, not attached — the
/// next bytes are another op request, not URBs.
#[test]
fn a_refused_import_does_not_switch_phase() {
    let mut busid = [0u8; BUSID_LEN];
    busid[..3].copy_from_slice(b"9-9");
    let mut script = op_req(OP_REQ_IMPORT, &busid);
    script.extend_from_slice(&op_req(OP_REQ_DEVLIST, &[]));
    let (attached, out) = op(script);
    assert!(!attached);
    // The refusal, then a full devlist reply — so the second request was read as
    // an op request and not as a URB header.
    assert_eq!(
        out.len(),
        OP_HEADER_LEN + 12 + USB_DEVICE_LEN + 3 * USB_INTERFACE_LEN
    );
}
