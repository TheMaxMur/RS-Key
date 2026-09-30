// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The USB/IP server: a connection's op phase, then its URBs, for whichever
//! [`Backend`] answers them. [`crate::usbip`] is the wire codec underneath, and
//! the device behind a backend is none of this module's business.

use std::io::{Read, Write};
use std::sync::mpsc::{Receiver, Sender};

use crate::usbip::{
    BUSID, CMD_HEADER_LEN, Command, DIR_IN, ECONNRESET, OP_HEADER_LEN, OpHeader, Ret, Urb,
    UsbDeviceInfo, handle_op_request, op_body_len, parse_command,
};

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

/// A device the server can offer: what a DEVLIST or IMPORT reports about it,
/// and the sink its URBs go to once a client has imported it.
pub trait Backend: UrbSink {
    fn device(&self) -> UsbDeviceInfo;

    /// Each interface's class, subclass and protocol, in descriptor order.
    fn interfaces(&self) -> Vec<[u8; 3]>;
}

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
pub fn listen(addr: &str, backend: &mut dyn Backend) -> std::io::Result<()> {
    let l = std::net::TcpListener::bind(addr)?;
    eprintln!("emu: USB/IP on {addr} (attach: usbip attach -r <host> -b {BUSID})");
    for stream in l.incoming() {
        let Ok(mut s) = stream else { continue };
        let _ = s.set_nodelay(true);
        match serve_op(&mut s, &backend.device(), &backend.interfaces()) {
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
        if let Err(e) = serve_attached(&mut s, backend, tx) {
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

#[cfg(test)]
#[path = "usbip_server_tests.rs"]
mod tests;
