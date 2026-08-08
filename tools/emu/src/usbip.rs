// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The USB/IP wire protocol — the codec half.
//!
//! USB/IP is how the emulator can be a *real* USB device without any USB
//! hardware: the kernel's `vhci_hcd` attaches a TCP peer as a virtual host
//! controller, so a Linux box (an OrbStack VM on a Mac will do) sees a genuine
//! device — `/dev/hidraw*`, a PC/SC reader, something a browser can talk to —
//! while the device itself is this process.
//!
//! Two phases on one connection. First the *op* phase, in network byte order
//! throughout: the client asks for a device list or to import one, and the
//! server answers. After a successful import the socket switches to the *command*
//! phase and carries URBs — submit in, reply out — until it closes.
//!
//! This module is only the encoding. It has no sockets and no USB stack, which
//! is why it can be tested exhaustively on the host; the endpoint plumbing that
//! sits on top of it is separate.

// The codec is complete and tested; the socket loop that consumes it is the next
// step, so most of this surface has no caller yet. Scoped to this module so a
// genuinely unused item elsewhere still fails the gate.
#![allow(dead_code)]

/// Protocol version, in every op-phase header (`0x0111` = 1.1.1).
pub const VERSION: u16 = 0x0111;

/// Op-phase codes. The request codes have the top bit set; the reply is the same
/// number without it.
pub const OP_REQ_DEVLIST: u16 = 0x8005;
pub const OP_REP_DEVLIST: u16 = 0x0005;
pub const OP_REQ_IMPORT: u16 = 0x8003;
pub const OP_REP_IMPORT: u16 = 0x0003;

/// Command-phase codes.
pub const CMD_SUBMIT: u32 = 1;
pub const CMD_UNLINK: u32 = 2;
pub const RET_SUBMIT: u32 = 3;
pub const RET_UNLINK: u32 = 4;

/// `usbip_header_basic.direction`.
pub const DIR_OUT: u32 = 0;
pub const DIR_IN: u32 = 1;

/// Sizes the protocol fixes. They are asserted rather than derived because the
/// peer is the Linux kernel: a struct that drifts by one byte does not fail
/// loudly, it desynchronises the stream.
pub const OP_HEADER_LEN: usize = 8;
pub const BUSID_LEN: usize = 32;
pub const DEV_PATH_LEN: usize = 256;
/// `struct usbip_usb_device`.
pub const USB_DEVICE_LEN: usize = DEV_PATH_LEN + BUSID_LEN + 3 * 4 + 3 * 2 + 6;
/// `struct usbip_usb_interface`, one per interface, appended to a devlist entry.
pub const USB_INTERFACE_LEN: usize = 4;
/// `usbip_header_basic` + the submit/reply body — the same 48 both ways.
pub const CMD_HEADER_LEN: usize = 48;

/// The op-phase header: version, code, status. `status` is 0 on success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpHeader {
    pub version: u16,
    pub code: u16,
    pub status: u32,
}

impl OpHeader {
    pub fn encode(&self) -> [u8; OP_HEADER_LEN] {
        let mut b = [0u8; OP_HEADER_LEN];
        b[0..2].copy_from_slice(&self.version.to_be_bytes());
        b[2..4].copy_from_slice(&self.code.to_be_bytes());
        b[4..8].copy_from_slice(&self.status.to_be_bytes());
        b
    }

    /// `None` for anything shorter than the header — a short read is a truncated
    /// stream, not a request with defaults.
    pub fn parse(b: &[u8]) -> Option<Self> {
        if b.len() < OP_HEADER_LEN {
            return None;
        }
        Some(Self {
            version: u16::from_be_bytes([b[0], b[1]]),
            code: u16::from_be_bytes([b[2], b[3]]),
            status: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
        })
    }
}

/// What the client is told about the device it is importing — `struct
/// usbip_usb_device`. The descriptor fields are the ones `rsk-usb` already
/// declares; they are repeated here because the kernel reads them *before* it
/// ever issues a GET_DESCRIPTOR, to size its own device model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbDeviceInfo {
    pub path: &'static str,
    pub busid: &'static str,
    pub busnum: u32,
    pub devnum: u32,
    /// `USB_SPEED_*`; 2 = full, 3 = high.
    pub speed: u32,
    pub id_vendor: u16,
    pub id_product: u16,
    pub bcd_device: u16,
    pub device_class: u8,
    pub device_subclass: u8,
    pub device_protocol: u8,
    pub configuration_value: u8,
    pub num_configurations: u8,
    pub num_interfaces: u8,
}

/// Copy `s` into a fixed, NUL-padded field, truncating rather than overflowing.
fn put_str(dst: &mut [u8], s: &str) {
    let n = s.len().min(dst.len().saturating_sub(1));
    dst[..n].copy_from_slice(&s.as_bytes()[..n]);
}

impl UsbDeviceInfo {
    pub fn encode(&self) -> [u8; USB_DEVICE_LEN] {
        let mut b = [0u8; USB_DEVICE_LEN];
        put_str(&mut b[0..DEV_PATH_LEN], self.path);
        let i = DEV_PATH_LEN;
        put_str(&mut b[i..i + BUSID_LEN], self.busid);
        let i = i + BUSID_LEN;
        b[i..i + 4].copy_from_slice(&self.busnum.to_be_bytes());
        b[i + 4..i + 8].copy_from_slice(&self.devnum.to_be_bytes());
        b[i + 8..i + 12].copy_from_slice(&self.speed.to_be_bytes());
        let i = i + 12;
        b[i..i + 2].copy_from_slice(&self.id_vendor.to_be_bytes());
        b[i + 2..i + 4].copy_from_slice(&self.id_product.to_be_bytes());
        b[i + 4..i + 6].copy_from_slice(&self.bcd_device.to_be_bytes());
        let i = i + 6;
        b[i] = self.device_class;
        b[i + 1] = self.device_subclass;
        b[i + 2] = self.device_protocol;
        b[i + 3] = self.configuration_value;
        b[i + 4] = self.num_configurations;
        b[i + 5] = self.num_interfaces;
        b
    }
}

/// One `struct usbip_usb_interface`, appended per interface to a DEVLIST entry.
/// The kernel only reads these for the listing; the real descriptors still come
/// over the control pipe.
pub fn encode_interface(class: u8, subclass: u8, protocol: u8) -> [u8; USB_INTERFACE_LEN] {
    [class, subclass, protocol, 0]
}

/// The busid an `OP_REQ_IMPORT` names, trimmed of its NUL padding.
pub fn parse_import_busid(b: &[u8]) -> Option<&str> {
    if b.len() < BUSID_LEN {
        return None;
    }
    let end = b[..BUSID_LEN]
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(BUSID_LEN);
    core::str::from_utf8(&b[..end]).ok()
}

/// A URB the client submitted, or asked to cancel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Submit(Submit),
    /// Cancel the URB with this sequence number.
    Unlink {
        seqnum: u32,
        unlink_seqnum: u32,
    },
}

/// `USBIP_CMD_SUBMIT` — one URB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submit {
    pub seqnum: u32,
    pub devid: u32,
    /// [`DIR_IN`] or [`DIR_OUT`], from the *host's* point of view.
    pub direction: u32,
    pub ep: u32,
    pub transfer_flags: u32,
    /// For IN, how much the host will accept; for OUT, how much follows.
    pub transfer_buffer_length: i32,
    pub number_of_packets: i32,
    pub interval: i32,
    /// The 8-byte SETUP packet, all zero for a non-control transfer.
    pub setup: [u8; 8],
}

impl Submit {
    /// Whether this URB carries an OUT payload after the header, and how much.
    pub fn out_payload_len(&self) -> usize {
        if self.direction == DIR_OUT && self.transfer_buffer_length > 0 {
            self.transfer_buffer_length as usize
        } else {
            0
        }
    }

    /// Whether this is a control transfer (endpoint 0 always is).
    pub fn is_control(&self) -> bool {
        self.ep == 0
    }
}

fn be32(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

/// Parse one command-phase header. `None` on a short read or an unknown command
/// — the caller must drop the connection rather than guess, because the stream
/// is self-framing only while both ends agree on the command.
pub fn parse_command(b: &[u8]) -> Option<Command> {
    if b.len() < CMD_HEADER_LEN {
        return None;
    }
    let command = be32(b, 0);
    let seqnum = be32(b, 4);
    match command {
        CMD_SUBMIT => {
            let mut setup = [0u8; 8];
            setup.copy_from_slice(&b[40..48]);
            Some(Command::Submit(Submit {
                seqnum,
                devid: be32(b, 8),
                direction: be32(b, 12),
                ep: be32(b, 16),
                transfer_flags: be32(b, 20),
                transfer_buffer_length: be32(b, 24) as i32,
                number_of_packets: be32(b, 32) as i32,
                interval: be32(b, 36) as i32,
                setup,
            }))
        }
        CMD_UNLINK => Some(Command::Unlink {
            seqnum,
            unlink_seqnum: be32(b, 20),
        }),
        _ => None,
    }
}

/// `USBIP_RET_SUBMIT` for a URB that completed. `status` is 0 on success and a
/// negative errno otherwise (`-EPIPE` = -32 is how a device says STALL).
pub fn encode_ret_submit(seqnum: u32, status: i32, actual_length: i32) -> [u8; CMD_HEADER_LEN] {
    let mut b = [0u8; CMD_HEADER_LEN];
    b[0..4].copy_from_slice(&RET_SUBMIT.to_be_bytes());
    b[4..8].copy_from_slice(&seqnum.to_be_bytes());
    // devid / direction / ep are echoed as zero: the kernel matches on seqnum.
    b[20..24].copy_from_slice(&status.to_be_bytes());
    b[24..28].copy_from_slice(&actual_length.to_be_bytes());
    b
}

/// `USBIP_RET_UNLINK`. `status` is `-ECONNRESET` (-104) when the URB was still
/// in flight and got cancelled, 0 when it had already completed.
pub fn encode_ret_unlink(seqnum: u32, status: i32) -> [u8; CMD_HEADER_LEN] {
    let mut b = [0u8; CMD_HEADER_LEN];
    b[0..4].copy_from_slice(&RET_UNLINK.to_be_bytes());
    b[4..8].copy_from_slice(&seqnum.to_be_bytes());
    b[20..24].copy_from_slice(&status.to_be_bytes());
    b
}

/// What the op phase decided: the bytes to write back, and whether the socket now
/// belongs to the command phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpReply {
    pub bytes: Vec<u8>,
    /// The client imported our device; every byte after this is URBs.
    pub attached: bool,
}

/// The busid this emulator answers to. One device, one bus, so it is fixed —
/// `usbip attach -r <host> -b rsk-emu`.
pub const BUSID: &str = "rsk-emu";

/// Answer one op-phase request.
///
/// Kept a pure function over buffers so the framing — which is the whole of what
/// can go wrong before a single URB flows — is testable without a socket or a
/// kernel. The caller owns the stream; this owns the protocol.
pub fn handle_op_request(req: &[u8], dev: &UsbDeviceInfo, ifaces: &[[u8; 3]]) -> Option<OpReply> {
    let h = OpHeader::parse(req)?;
    // A version mismatch is answered, not ignored: the client prints the status
    // and gives up, which is a far better failure than a hung attach.
    let bad_version = h.version != VERSION;
    let body = &req[OP_HEADER_LEN..];
    match h.code {
        OP_REQ_DEVLIST => {
            let mut out = OpHeader {
                version: VERSION,
                code: OP_REP_DEVLIST,
                status: u32::from(bad_version),
            }
            .encode()
            .to_vec();
            if bad_version {
                return Some(OpReply {
                    bytes: out,
                    attached: false,
                });
            }
            out.extend_from_slice(&1u32.to_be_bytes()); // exactly one device
            out.extend_from_slice(&dev.encode());
            for i in ifaces {
                out.extend_from_slice(&encode_interface(i[0], i[1], i[2]));
            }
            Some(OpReply {
                bytes: out,
                attached: false,
            })
        }
        OP_REQ_IMPORT => {
            // An import naming a busid we do not have is a refusal, not a
            // silently-substituted device.
            let ours = !bad_version && parse_import_busid(body) == Some(BUSID);
            let mut out = OpHeader {
                version: VERSION,
                code: OP_REP_IMPORT,
                status: u32::from(!ours),
            }
            .encode()
            .to_vec();
            if ours {
                out.extend_from_slice(&dev.encode());
            }
            Some(OpReply {
                bytes: out,
                attached: ours,
            })
        }
        _ => None,
    }
}

/// How many more bytes the caller must read for `req` to be a whole op request.
/// The op phase is not length-prefixed, so the framing is per-code.
pub fn op_body_len(code: u16) -> usize {
    match code {
        OP_REQ_IMPORT => BUSID_LEN,
        _ => 0,
    }
}

#[cfg(test)]
#[path = "usbip_tests.rs"]
mod tests;
