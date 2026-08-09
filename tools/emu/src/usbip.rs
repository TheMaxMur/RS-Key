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

/// One URB the host has submitted and not yet had answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Urb {
    pub seqnum: u32,
    /// Endpoint *number* (0..=15). The direction is [`Self::dir_in`], not the
    /// address's 0x80 bit — the wire carries the two separately.
    pub ep: u8,
    pub dir_in: bool,
    /// The SETUP packet. Meaningful on endpoint 0 only.
    pub setup: [u8; 8],
    /// The OUT data stage, whole; empty for an IN transfer.
    pub out: Vec<u8>,
    /// How many bytes the host will accept back (IN) or has sent (OUT).
    pub want: usize,
}

/// What goes back on the wire once the device has answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ret {
    Submit {
        seqnum: u32,
        /// 0, or a negative errno — [`EPIPE`] for a STALL.
        status: i32,
        /// What the device transferred. For an IN URB this is `data.len()`; for
        /// an OUT one it is the count the device consumed, and nothing follows
        /// the header.
        actual_length: usize,
        data: Vec<u8>,
    },
    Unlink {
        seqnum: u32,
        status: i32,
    },
}

impl Ret {
    /// The endpoint halted.
    pub fn stall(seqnum: u32) -> Self {
        Self::Submit {
            seqnum,
            status: EPIPE,
            actual_length: 0,
            data: Vec::new(),
        }
    }

    pub fn in_data(seqnum: u32, data: Vec<u8>) -> Self {
        Self::Submit {
            seqnum,
            status: 0,
            actual_length: data.len(),
            data,
        }
    }

    pub fn out_done(seqnum: u32, len: usize) -> Self {
        Self::Submit {
            seqnum,
            status: 0,
            actual_length: len,
            data: Vec::new(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Submit {
                seqnum,
                status,
                actual_length,
                data,
            } => {
                let mut v = encode_ret_submit(*seqnum, *status, *actual_length as i32).to_vec();
                v.extend_from_slice(data);
                v
            }
            Self::Unlink { seqnum, status } => encode_ret_unlink(*seqnum, *status).to_vec(),
        }
    }
}

/// What answers URBs once a client has imported the device.
///
/// The seam the USB stack plugs into: everything above is framing, everything
/// below this is USB. It is deliberately *not* request/response. A real host
/// keeps several URBs in flight — an interrupt IN sits pending on every HID
/// endpoint at all times, waiting for a report that may be minutes away — so a
/// sink that had to answer one URB before the transport read the next would
/// wedge the device the moment a host behaved normally.
pub trait UrbSink {
    /// A host imported the device; completions go on `rets` until [`Self::detach`].
    fn attach(&mut self, rets: Sender<Ret>);

    /// Take one URB. Returns at once — the answer travels back on the channel
    /// whenever the device produces it.
    fn submit(&mut self, urb: Urb);

    /// The host gave up on `seqnum`. `true` if it was still pending: that is the
    /// difference between `-ECONNRESET` and a plain 0 on the wire.
    fn unlink(&mut self, seqnum: u32) -> bool;

    /// The host went away. Fail anything still pending and forget the channel.
    fn detach(&mut self);
}

/// `-EPIPE`, how USB/IP spells a STALL.
pub const EPIPE: i32 = -32;

/// `-ECONNRESET`, how it reports a URB cancelled while still in flight.
pub const ECONNRESET: i32 = -104;

/// Take URBs off an imported connection until the peer goes away.
///
/// Every read is exact-length because the stream is not self-describing — the
/// header says how much payload follows, and a short read here silently shifts
/// every URB after it. Nothing is written back from this side: completions leave
/// through `rets`, which [`pump_rets`] drains onto the same socket.
pub fn serve_attached<R: Read>(
    sock: &mut R,
    sink: &mut dyn UrbSink,
    rets: Sender<Ret>,
) -> std::io::Result<()> {
    sink.attach(rets.clone());
    let r = read_urbs(sock, sink, &rets);
    sink.detach();
    r
}

fn read_urbs<R: Read>(
    sock: &mut R,
    sink: &mut dyn UrbSink,
    rets: &Sender<Ret>,
) -> std::io::Result<()> {
    let mut hdr = [0u8; CMD_HEADER_LEN];
    loop {
        if sock.read_exact(&mut hdr).is_err() {
            return Ok(()); // the client detached
        }
        let Some(cmd) = parse_command(&hdr) else {
            // Not something we can frame past — the only safe move is to stop.
            return Ok(());
        };
        match cmd {
            Command::Unlink {
                seqnum,
                unlink_seqnum,
            } => {
                let status = if sink.unlink(unlink_seqnum) {
                    ECONNRESET
                } else {
                    0
                };
                if rets.send(Ret::Unlink { seqnum, status }).is_err() {
                    return Ok(());
                }
            }
            Command::Submit(s) => {
                let mut out = vec![0u8; s.out_payload_len()];
                if !out.is_empty() {
                    sock.read_exact(&mut out)?;
                }
                // A USB endpoint number is four bits wide. Anything else names no
                // endpoint we have, so it halts rather than aliasing onto a real
                // one — the payload is consumed first, or the stream desyncs.
                match u8::try_from(s.ep) {
                    Ok(ep) if ep < 16 => sink.submit(Urb {
                        seqnum: s.seqnum,
                        ep,
                        dir_in: s.direction == DIR_IN,
                        setup: s.setup,
                        out,
                        want: s.transfer_buffer_length.max(0) as usize,
                    }),
                    _ if rets.send(Ret::stall(s.seqnum)).is_err() => return Ok(()),
                    _ => {}
                }
            }
        }
    }
}

/// Write completions onto the socket until the sink hangs up or the peer goes.
///
/// Its own loop, on its own thread, because reads and writes are genuinely
/// concurrent once a device is attached: the answer to a control transfer has to
/// go out while an interrupt IN URB is still pending, and one thread doing both
/// would have to finish the wait before it could notice the next submit.
pub fn pump_rets<W: Write>(sock: &mut W, rets: &Receiver<Ret>) -> std::io::Result<()> {
    while let Ok(ret) = rets.recv() {
        sock.write_all(&ret.encode())?;
    }
    Ok(())
}

/// The port `vhci_hcd`'s userspace expects a USB/IP server on.
pub const PORT: u16 = 3240;

/// Run the op phase to its end: `false` if the client listed and left, `true` if
/// it imported the device — after which every byte on this socket is a URB.
///
/// Split from [`serve_attached`] because they are different protocols on one
/// socket, and split from the listener because only the listener holds a real
/// `TcpStream` to hand the write half of.
pub fn serve_op<S: Read + Write>(
    sock: &mut S,
    dev: &UsbDeviceInfo,
    ifaces: &[[u8; 3]],
) -> std::io::Result<bool> {
    loop {
        let mut head = [0u8; OP_HEADER_LEN];
        if sock.read_exact(&mut head).is_err() {
            return Ok(false); // the client hung up between requests
        }
        let Some(h) = OpHeader::parse(&head) else {
            return Ok(false);
        };
        // The op phase has no length prefix, so the code says how much follows.
        let mut req = head.to_vec();
        let n = op_body_len(h.code);
        if n > 0 {
            let mut body = vec![0u8; n];
            sock.read_exact(&mut body)?;
            req.extend_from_slice(&body);
        }
        let Some(reply) = handle_op_request(&req, dev, ifaces) else {
            return Ok(false); // unknown code: the stream is no longer framable
        };
        sock.write_all(&reply.bytes)?;
        if reply.attached {
            return Ok(true);
        }
    }
}

/// Accept USB/IP clients forever, one at a time. A second client while one holds
/// the device waits its turn: there is one device here, and letting two hosts
/// import it would give both a half-working one.
pub fn listen(
    addr: &str,
    dev: &UsbDeviceInfo,
    ifaces: &[[u8; 3]],
    sink: &mut dyn UrbSink,
) -> std::io::Result<()> {
    let l = std::net::TcpListener::bind(addr)?;
    eprintln!("emu: USB/IP on {addr} (attach: usbip attach -r <host> -b {BUSID})");
    for stream in l.incoming() {
        let Ok(mut s) = stream else { continue };
        let _ = s.set_nodelay(true);
        match serve_op(&mut s, dev, ifaces) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(e) => {
                eprintln!("emu: USB/IP client dropped: {e}");
                continue;
            }
        }
        // Attached. Reads and writes are independent from here, so the socket is
        // split in two: this thread keeps taking URBs in while another pushes
        // completions out.
        let Ok(mut w) = s.try_clone() else { continue };
        let (tx, rx) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            if let Err(e) = pump_rets(&mut w, &rx) {
                eprintln!("emu: USB/IP write failed: {e}");
            }
        });
        eprintln!("emu: USB/IP attached");
        if let Err(e) = serve_attached(&mut s, sink, tx) {
            eprintln!("emu: USB/IP client dropped: {e}");
        }
        // `serve_attached` dropped both ends of the channel, so the writer is on
        // its way out; joining it is what stops the next client's first bytes
        // from racing this one's last.
        let _ = writer.join();
        eprintln!("emu: USB/IP detached");
    }
    Ok(())
}

use std::io::{Read, Write};
use std::sync::mpsc::{Receiver, Sender};

#[cfg(test)]
#[path = "usbip_tests.rs"]
mod tests;
