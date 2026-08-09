// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// The struct sizes are the protocol's, not ours. The peer is the Linux kernel,
/// and a field that drifts by a byte does not fail loudly — it desynchronises the
/// stream and every URB after it lands in the wrong place.
#[test]
fn struct_sizes_are_the_kernels() {
    assert_eq!(OP_HEADER_LEN, 8);
    assert_eq!(USB_DEVICE_LEN, 312);
    assert_eq!(USB_INTERFACE_LEN, 4);
    assert_eq!(CMD_HEADER_LEN, 48);
}

#[test]
fn op_header_round_trips() {
    let h = OpHeader {
        version: VERSION,
        code: OP_REP_IMPORT,
        status: 0,
    };
    assert_eq!(OpHeader::parse(&h.encode()), Some(h));
}

/// Everything in the op phase is network byte order; a little-endian slip would
/// still parse locally and be nonsense on the wire.
#[test]
fn op_header_is_big_endian() {
    let b = OpHeader {
        version: 0x0111,
        code: 0x8003,
        status: 1,
    }
    .encode();
    assert_eq!(&b[..], &[0x01, 0x11, 0x80, 0x03, 0x00, 0x00, 0x00, 0x01]);
}

#[test]
fn op_header_refuses_a_short_read() {
    assert_eq!(OpHeader::parse(&[0x01, 0x11, 0x80]), None);
}

fn dev() -> UsbDeviceInfo {
    UsbDeviceInfo {
        path: "/sys/devices/rsk-emu/1-1",
        busid: "1-1",
        busnum: 1,
        devnum: 1,
        speed: 2,
        id_vendor: 0x1209,
        id_product: 0x000d,
        bcd_device: 0x0877,
        device_class: 0,
        device_subclass: 0,
        device_protocol: 0,
        configuration_value: 1,
        num_configurations: 1,
        num_interfaces: 3,
    }
}

#[test]
fn device_info_lands_in_the_kernels_field_offsets() {
    let b = dev().encode();
    assert_eq!(b.len(), 312);
    assert!(b.starts_with(b"/sys/devices/rsk-emu/1-1\0"));
    assert_eq!(&b[256..259], b"1-1");
    assert_eq!(b[256 + 3], 0, "busid must be NUL-padded, not left dirty");
    // busnum / devnum / speed
    assert_eq!(&b[288..292], &1u32.to_be_bytes());
    assert_eq!(&b[292..296], &1u32.to_be_bytes());
    assert_eq!(&b[296..300], &2u32.to_be_bytes());
    // idVendor / idProduct / bcdDevice
    assert_eq!(&b[300..302], &0x1209u16.to_be_bytes());
    assert_eq!(&b[302..304], &0x000du16.to_be_bytes());
    assert_eq!(&b[304..306], &0x0877u16.to_be_bytes());
    // the six trailing bytes
    assert_eq!(&b[306..312], &[0, 0, 0, 1, 1, 3]);
}

/// A path longer than the field must truncate, and must still leave a terminator
/// — the kernel reads these as C strings.
#[test]
fn over_long_strings_truncate_and_stay_terminated() {
    let long = Box::leak("x".repeat(400).into_boxed_str());
    let mut d = dev();
    d.path = long;
    let b = d.encode();
    assert_eq!(b[DEV_PATH_LEN - 1], 0);
    assert!(b[..DEV_PATH_LEN - 1].iter().all(|&c| c == b'x'));
}

#[test]
fn import_busid_stops_at_the_nul() {
    let mut b = [0u8; BUSID_LEN];
    b[..3].copy_from_slice(b"1-1");
    assert_eq!(parse_import_busid(&b), Some("1-1"));
}

/// An unpadded, fully-used field has no NUL to stop at.
#[test]
fn import_busid_handles_a_full_field() {
    let b = [b'a'; BUSID_LEN];
    assert_eq!(parse_import_busid(&b), Some("a".repeat(BUSID_LEN).as_str()));
}

#[test]
fn import_busid_refuses_a_short_read() {
    assert_eq!(parse_import_busid(&[0u8; 8]), None);
}

fn submit_bytes(direction: u32, ep: u32, len: i32, setup: [u8; 8]) -> [u8; CMD_HEADER_LEN] {
    let mut b = [0u8; CMD_HEADER_LEN];
    b[0..4].copy_from_slice(&CMD_SUBMIT.to_be_bytes());
    b[4..8].copy_from_slice(&7u32.to_be_bytes()); // seqnum
    b[8..12].copy_from_slice(&2u32.to_be_bytes()); // devid
    b[12..16].copy_from_slice(&direction.to_be_bytes());
    b[16..20].copy_from_slice(&ep.to_be_bytes());
    b[24..28].copy_from_slice(&len.to_be_bytes());
    b[40..48].copy_from_slice(&setup);
    b
}

#[test]
fn submit_parses() {
    let setup = [0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00];
    let c = parse_command(&submit_bytes(DIR_IN, 0, 18, setup)).unwrap();
    let Command::Submit(s) = c else {
        panic!("expected a submit")
    };
    assert_eq!(s.seqnum, 7);
    assert_eq!(s.devid, 2);
    assert_eq!(s.direction, DIR_IN);
    assert_eq!(s.ep, 0);
    assert_eq!(s.transfer_buffer_length, 18);
    assert_eq!(s.setup, setup);
}

/// The payload rule decides how many bytes to read off the socket next. Getting
/// it wrong by even one desynchronises everything after it, so both directions
/// are pinned.
#[test]
fn only_an_out_submit_carries_a_payload() {
    let out = parse_command(&submit_bytes(DIR_OUT, 1, 64, [0; 8])).unwrap();
    let Command::Submit(s) = out else { panic!() };
    assert_eq!(s.out_payload_len(), 64);

    let inn = parse_command(&submit_bytes(DIR_IN, 129, 64, [0; 8])).unwrap();
    let Command::Submit(s) = inn else { panic!() };
    assert_eq!(s.out_payload_len(), 0, "an IN submit is header-only");

    let empty = parse_command(&submit_bytes(DIR_OUT, 1, 0, [0; 8])).unwrap();
    let Command::Submit(s) = empty else { panic!() };
    assert_eq!(s.out_payload_len(), 0);
}

#[test]
fn unlink_parses() {
    let mut b = [0u8; CMD_HEADER_LEN];
    b[0..4].copy_from_slice(&CMD_UNLINK.to_be_bytes());
    b[4..8].copy_from_slice(&9u32.to_be_bytes());
    b[20..24].copy_from_slice(&7u32.to_be_bytes());
    assert_eq!(
        parse_command(&b),
        Some(Command::Unlink {
            seqnum: 9,
            unlink_seqnum: 7
        })
    );
}

/// An unknown command is not something to skip past: the stream is only
/// self-framing while both ends agree, so the caller must drop the connection.
#[test]
fn an_unknown_command_is_refused() {
    let mut b = [0u8; CMD_HEADER_LEN];
    b[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    assert_eq!(parse_command(&b), None);
    assert_eq!(parse_command(&[0u8; 12]), None);
}

#[test]
fn ret_submit_carries_status_and_length() {
    let b = encode_ret_submit(7, 0, 18);
    assert_eq!(&b[0..4], &RET_SUBMIT.to_be_bytes());
    assert_eq!(&b[4..8], &7u32.to_be_bytes());
    assert_eq!(&b[20..24], &0i32.to_be_bytes());
    assert_eq!(&b[24..28], &18i32.to_be_bytes());
}

/// A STALL is reported as `-EPIPE`, and the sign has to survive the encoding.
#[test]
fn ret_submit_reports_a_stall_as_negative_epipe() {
    let b = encode_ret_submit(7, -32, 0);
    assert_eq!(i32::from_be_bytes([b[20], b[21], b[22], b[23]]), -32);
}

#[test]
fn ret_unlink_reports_econnreset() {
    let b = encode_ret_unlink(9, -104);
    assert_eq!(&b[0..4], &RET_UNLINK.to_be_bytes());
    assert_eq!(i32::from_be_bytes([b[20], b[21], b[22], b[23]]), -104);
}

fn ifaces() -> Vec<[u8; 3]> {
    // kbd/OTP, FIDO, CCID — the order issue #55 was about.
    vec![[0x03, 0x01, 0x01], [0x03, 0x00, 0x00], [0x0b, 0x00, 0x00]]
}

fn op_req(code: u16, body: &[u8]) -> Vec<u8> {
    let mut v = OpHeader {
        version: VERSION,
        code,
        status: 0,
    }
    .encode()
    .to_vec();
    v.extend_from_slice(body);
    v
}

#[test]
fn devlist_reports_one_device_and_its_interfaces() {
    let r = handle_op_request(&op_req(OP_REQ_DEVLIST, &[]), &dev(), &ifaces()).unwrap();
    assert!(!r.attached, "a listing must not attach anything");
    let h = OpHeader::parse(&r.bytes).unwrap();
    assert_eq!(h.code, OP_REP_DEVLIST);
    assert_eq!(h.status, 0);
    assert_eq!(&r.bytes[8..12], &1u32.to_be_bytes());
    assert_eq!(r.bytes.len(), 12 + USB_DEVICE_LEN + 3 * USB_INTERFACE_LEN);
    // The interface order is the wire's, and it is the thing issue #55 turned on.
    let base = 12 + USB_DEVICE_LEN;
    assert_eq!(r.bytes[base], 0x03);
    assert_eq!(r.bytes[base + USB_INTERFACE_LEN], 0x03);
    assert_eq!(r.bytes[base + 2 * USB_INTERFACE_LEN], 0x0b);
}

#[test]
fn import_of_our_busid_attaches() {
    let mut body = [0u8; BUSID_LEN];
    body[..BUSID.len()].copy_from_slice(BUSID.as_bytes());
    let r = handle_op_request(&op_req(OP_REQ_IMPORT, &body), &dev(), &ifaces()).unwrap();
    assert!(r.attached);
    assert_eq!(OpHeader::parse(&r.bytes).unwrap().status, 0);
    assert_eq!(r.bytes.len(), OP_HEADER_LEN + USB_DEVICE_LEN);
}

/// A busid we do not have must be refused outright — answering with our device
/// anyway would attach the wrong thing under a name the client asked for.
#[test]
fn import_of_a_foreign_busid_is_refused() {
    let mut body = [0u8; BUSID_LEN];
    body[..3].copy_from_slice(b"9-9");
    let r = handle_op_request(&op_req(OP_REQ_IMPORT, &body), &dev(), &ifaces()).unwrap();
    assert!(!r.attached);
    assert_ne!(OpHeader::parse(&r.bytes).unwrap().status, 0);
    assert_eq!(r.bytes.len(), OP_HEADER_LEN, "a refusal carries no device");
}

/// A version mismatch is answered with a status, not ignored: the client prints
/// it and gives up, which beats a hung attach.
#[test]
fn a_version_mismatch_is_answered() {
    let mut req = op_req(OP_REQ_DEVLIST, &[]);
    req[0..2].copy_from_slice(&0x0102u16.to_be_bytes());
    let r = handle_op_request(&req, &dev(), &ifaces()).unwrap();
    assert_ne!(OpHeader::parse(&r.bytes).unwrap().status, 0);
    assert_eq!(r.bytes.len(), OP_HEADER_LEN);
    assert!(!r.attached);
}

#[test]
fn an_unknown_op_code_is_refused() {
    assert!(handle_op_request(&op_req(0x8099, &[]), &dev(), &ifaces()).is_none());
}

/// The op phase is not length-prefixed, so the caller needs to know how much
/// body to read before it can dispatch.
#[test]
fn op_body_len_frames_each_code() {
    assert_eq!(op_body_len(OP_REQ_IMPORT), BUSID_LEN);
    assert_eq!(op_body_len(OP_REQ_DEVLIST), 0);
}

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
