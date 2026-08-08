// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The card side over a TCP socket, one length-prefixed APDU at a time:
//!
//! ```text
//! request   op:u8 | len:u32 BE | payload
//! response         len:u32 BE | payload
//! ```
//!
//! Requests carry **APDUs**, not CCID messages: a PC/SC client hands the reader
//! an APDU and the CCID block framing happens below it, so the emulator starts
//! where `SCardTransmit` does. The consequence is that `rsk_usb::ccid` — the
//! block framing, its chaining and the time extensions — is the one transport
//! this does not exercise; ISO 7816 chaining, which lives in the dispatcher, is.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::mpsc;

use rsk_usb::ccid::ATR_RSKEY;

use crate::device::{Job, Req};

/// Transmit an APDU.
const OP_XFR: u8 = 0x00;
/// Power on the card: answers the ATR. Resets the security status, like a real
/// `SCardConnect` after a reset would.
const OP_POWER_ON: u8 = 0x01;
/// Power off: answers empty, and likewise resets.
const OP_POWER_OFF: u8 = 0x02;
/// Unplug and plug back in — what a test harness sends where an operator would
/// pull the key out. Answers empty. It is on this socket and not the CTAPHID one
/// because that stream carries nothing but 64-byte reports.
const OP_REPLUG: u8 = 0x03;

/// Refuse an absurd length before allocating for it.
const MAX_REQUEST: usize = 64 * 1024;

pub fn serve(mut stream: TcpStream, jobs: mpsc::Sender<Req>) -> io::Result<()> {
    loop {
        let mut hdr = [0u8; 5];
        match stream.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let op = hdr[0];
        let len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
        if len > MAX_REQUEST {
            return Err(io::Error::other("request too long"));
        }
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload)?;

        let resp = match op {
            OP_XFR => run(&jobs, Job::Apdu(payload))?,
            OP_POWER_ON => {
                run(&jobs, Job::ResetCard)?;
                ATR_RSKEY.to_vec()
            }
            OP_POWER_OFF => {
                run(&jobs, Job::ResetCard)?;
                Vec::new()
            }
            OP_REPLUG => {
                run(&jobs, Job::Replug)?;
                Vec::new()
            }
            _ => return Err(io::Error::other(format!("unknown opcode {op:#04x}"))),
        };
        stream.write_all(&(resp.len() as u32).to_be_bytes())?;
        stream.write_all(&resp)?;
        stream.flush()?;
    }
}

fn run(jobs: &mpsc::Sender<Req>, job: Job) -> io::Result<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    jobs.send(Req { job, reply: tx })
        .map_err(|_| io::Error::other("the device thread is gone"))?;
    match rx.recv() {
        Ok(out) => Ok(out.unwrap_or_default()),
        Err(_) => Err(io::Error::other("the device thread dropped the job")),
    }
}

/// Accept forever, one thread per client.
pub fn listen(listener: std::net::TcpListener, jobs: mpsc::Sender<Req>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let jobs = jobs.clone();
        std::thread::spawn(move || {
            if let Err(e) = serve(stream, jobs) {
                eprintln!("emu: ccid client: {e}");
            }
        });
    }
}
