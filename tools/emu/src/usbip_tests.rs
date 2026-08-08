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
        bcd_device: 0x0874,
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
    assert_eq!(&b[304..306], &0x0874u16.to_be_bytes());
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
    assert!(s.is_control());
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
