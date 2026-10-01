// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! What stands in front of the emulated chip: `tests/emu.py`'s two ports, framed as
//! `hid.rs` and `ccid.rs` frame them, the terminal's touch, and USB/IP — each one
//! turning its traffic into [`Request`]s for the chip thread to put on the bus.

use std::io::{self, BufRead, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Sender};

use rsk_usb::ccid::MAX_CCID_MSG;
use rsk_usb::ctaphid::HID_RPT_SIZE;

use crate::ccid::{OP_CCID, OP_REPLUG, send};
use crate::usbip::{Ret, Urb, UsbDeviceInfo};
use crate::usbip_server::{Backend, UrbSink};

pub type Report = [u8; HID_RPT_SIZE];

/// What the transports ask of the chip thread.
pub enum Request {
    Inspect {
        command: super::inspect::Command,
        reply: Sender<Result<String, String>>,
    },
    HidOpen {
        conn: u64,
        reports: Sender<Report>,
    },
    HidReport {
        conn: u64,
        report: Report,
    },
    HidClose {
        conn: u64,
    },
    /// One whole `PC_to_RDR` message; every answer to it comes back on `reply`.
    Ccid {
        msg: Vec<u8>,
        reply: Sender<CcidReply>,
    },
    /// A power cycle; `done` once the device is back, or known not to be.
    Replug {
        done: Sender<()>,
    },
    /// A line on the terminal: the BOOTSEL button, pressed.
    Touch,
    UsbipAttach {
        rets: Sender<Ret>,
    },
    Urb(Urb),
    Unlink {
        seqnum: u32,
        pending: Sender<bool>,
    },
    UsbipDetach,
}

pub enum CcidReply {
    /// A time extension: the answer is still coming.
    Wtx(Vec<u8>),
    Final(Vec<u8>),
    /// The device left the message unanswered, as it does an unknown type.
    Unanswered,
    /// The reader went away under it: a reboot, a power cycle, or USB/IP.
    Gone,
}

fn chip_gone<T>(_: T) -> io::Error {
    io::Error::other("the chip thread is gone")
}

pub fn listen_hid(listener: TcpListener, chip: Sender<Request>) {
    for (conn, stream) in (1u64..).zip(listener.incoming()) {
        let Ok(stream) = stream else { continue };
        let chip = chip.clone();
        std::thread::spawn(move || {
            if let Err(e) = serve_hid(stream, conn, &chip) {
                eprintln!("emu: fido client: {e}");
            }
            let _ = chip.send(Request::HidClose { conn });
        });
    }
}

/// Reports in go to the bus in arrival order; reports out come back through the
/// chip thread, which routes them by channel id the way a host's HID stack hands
/// each process the replies to its own channel.
fn serve_hid(mut stream: TcpStream, conn: u64, chip: &Sender<Request>) -> io::Result<()> {
    let (reports, rx) = mpsc::channel::<Report>();
    chip.send(Request::HidOpen { conn, reports })
        .map_err(chip_gone)?;
    let mut w = stream.try_clone()?;
    std::thread::spawn(move || {
        for r in rx {
            if w.write_all(&r).is_err() {
                return;
            }
        }
    });
    let mut report = [0u8; HID_RPT_SIZE];
    loop {
        match stream.read_exact(&mut report) {
            Ok(()) => chip
                .send(Request::HidReport { conn, report })
                .map_err(chip_gone)?,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
    }
}

pub fn listen_ccid(listener: TcpListener, chip: Sender<Request>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let chip = chip.clone();
        std::thread::spawn(move || {
            if let Err(e) = serve_ccid(stream, &chip) {
                eprintln!("emu: ccid client: {e}");
            }
        });
    }
}

/// One request at a time, as the applet backend serves them, but the answers are
/// the device's own: its time extensions, its framing errors, its silence.
fn serve_ccid(mut stream: TcpStream, chip: &Sender<Request>) -> io::Result<()> {
    loop {
        let mut hdr = [0u8; 5];
        match stream.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
        if len > MAX_CCID_MSG {
            return Err(io::Error::other(
                "request longer than dwMaxCCIDMessageLength",
            ));
        }
        let mut msg = vec![0u8; len];
        stream.read_exact(&mut msg)?;
        match hdr[0] {
            OP_REPLUG => {
                let (done, rx) = mpsc::channel();
                chip.send(Request::Replug { done }).map_err(chip_gone)?;
                let _ = rx.recv();
                send(&mut stream, &[])?;
            }
            OP_CCID => {
                let (reply, rx) = mpsc::channel();
                chip.send(Request::Ccid { msg, reply }).map_err(chip_gone)?;
                loop {
                    match rx.recv() {
                        Ok(CcidReply::Wtx(m)) => send(&mut stream, &m)?,
                        Ok(CcidReply::Final(m)) => {
                            send(&mut stream, &m)?;
                            break;
                        }
                        Ok(CcidReply::Unanswered) => break,
                        // The reader is gone, so the connection goes with it.
                        Ok(CcidReply::Gone) | Err(_) => return Ok(()),
                    }
                }
            }
            op => return Err(io::Error::other(format!("unknown opcode {op:#04x}"))),
        }
    }
}

/// Each line on the terminal presses the button once.
pub fn read_touches(chip: Sender<Request>) {
    std::thread::spawn(move || {
        for _ in io::stdin().lock().lines().map_while(Result::ok) {
            if chip.send(Request::Touch).is_err() {
                return;
            }
        }
    });
}

/// The USB/IP side: URBs to the chip thread, which answers them off the bus.
pub struct UsbipPort {
    pub chip: Sender<Request>,
    pub device: UsbDeviceInfo,
    pub interfaces: Vec<[u8; 3]>,
}

impl Backend for UsbipPort {
    fn device(&self) -> UsbDeviceInfo {
        self.device.clone()
    }

    fn interfaces(&self) -> Vec<[u8; 3]> {
        self.interfaces.clone()
    }
}

impl UrbSink for UsbipPort {
    fn attach(&mut self, rets: Sender<Ret>) {
        let _ = self.chip.send(Request::UsbipAttach { rets });
    }

    fn submit(&mut self, urb: Urb) {
        let _ = self.chip.send(Request::Urb(urb));
    }

    fn unlink(&mut self, seqnum: u32) -> bool {
        let (pending, rx) = mpsc::channel();
        let _ = self.chip.send(Request::Unlink { seqnum, pending });
        rx.recv().unwrap_or(false)
    }

    fn detach(&mut self) {
        let _ = self.chip.send(Request::UsbipDetach);
    }
}
