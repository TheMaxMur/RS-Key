// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The card side over a TCP socket, one CCID message at a time:
//!
//! ```text
//! request   op:u8 | len:u32 BE | payload
//! response         len:u32 BE | payload
//! ```
//!
//! `op` is `00` for a CCID message and `03` for a replug (a power cycle, which
//! CCID has no message for — the emulator's stand-in for pulling the key out).
//! The payload of a `00` is a **whole `PC_to_RDR` message**, header and all, and
//! the answer is a whole `RDR_to_PC` — the same bytes a USB CCID host puts on the
//! bulk endpoints. One request may draw several responses, exactly as a bulk-IN
//! stream does: a slow `XfrBlock` gets time-extensions before its DataBlock.
//!
//! Serving bare APDUs would have been simpler and would have left
//! `rsk_usb::ccid` — the block framing, its length validation, the WTX cadence —
//! exercised by nothing but its own unit tests. That layer is where the no-`Le`
//! chaining bug that made PIV certificates invisible to `age-plugin` lived.
//!
//! This module is the transport, so it owns what the firmware's transport owns:
//! the slot status, the framing and the time extensions. The applet dispatch
//! stays with the device thread, the way it stays with the worker on the device.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::mpsc;
use std::time::Duration;

use rsk_usb::ccid::{
    CCID_DATA_BLOCK_RET, CCID_POWER_OFF, CCID_POWER_ON, HEADER, MAX_CCID_MSG, SECURE_STATUS_FAILED,
    STATUS_INACTIVE, STATUS_TIMEEXT, WTX_INTERVAL_MS, process_message, put_header, secure_apdu,
    xfr_apdu,
};

use crate::device::{Job, Jobs};

/// A CCID message.
const OP_CCID: u8 = 0x00;
/// Unplug and plug back in — what a test harness sends where an operator would
/// pull the key out. Answers empty. CCID has no message for it: a power cycle is
/// not a card reset, and only one of the two reopens the CTAP 2.1 §6.6 window.
const OP_REPLUG: u8 = 0x03;

/// Refuse an absurd length before allocating for it: a real message can never
/// exceed the class descriptor's `dwMaxCCIDMessageLength`.
const MAX_REQUEST: usize = MAX_CCID_MSG;

pub fn serve(mut stream: TcpStream, jobs: Jobs, atr: &'static [u8]) -> io::Result<()> {
    // Slot status is transport state — a field of `Ccid` on the device, so one
    // per connection here, a connection being one host's handle on the card.
    let mut status = STATUS_INACTIVE;
    let mut out = vec![0u8; MAX_CCID_MSG];
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
            return Err(io::Error::other(
                "request longer than dwMaxCCIDMessageLength",
            ));
        }
        let mut msg = vec![0u8; len];
        stream.read_exact(&mut msg)?;

        match op {
            OP_REPLUG => {
                run(&jobs, Job::Replug)?;
                status = STATUS_INACTIVE; // the card comes back unpowered
                send(&mut stream, &[])?;
            }
            OP_CCID => serve_message(&mut stream, &jobs, &msg, atr, &mut status, &mut out)?,
            _ => return Err(io::Error::other(format!("unknown opcode {op:#04x}"))),
        }
    }
}

/// Answer one CCID message, mirroring `Ccid::run`'s arms: `XfrBlock` and `Secure`
/// go to the device, a power transition resets the card first, everything else is
/// [`process_message`]'s to answer, and bad framing gets the `6F 00` resync.
#[allow(clippy::too_many_arguments)] // one call site; every argument is state it needs
fn serve_message(
    stream: &mut TcpStream,
    jobs: &Jobs,
    msg: &[u8],
    atr: &[u8],
    status: &mut u8,
    out: &mut [u8],
) -> io::Result<()> {
    let seq = msg.get(6).copied().unwrap_or(0);
    if !framed(msg) {
        // A length it cannot trust gets `6F 00` and a resync, echoing the sequence
        // so a host that validates it (libccid does) accepts the one reply whose
        // whole job is to resynchronise.
        put_header(out, CCID_DATA_BLOCK_RET, 2, seq, *status);
        out[HEADER] = 0x6F;
        out[HEADER + 1] = 0x00;
        return send(stream, &out[..HEADER + 2]);
    }

    if let Some((a, b)) = xfr_apdu(msg) {
        let body = run_with_wtx(stream, jobs, Job::Apdu(msg[a..b].to_vec()), seq, *status)?;
        let n = body.len().min(out.len() - HEADER);
        put_header(out, CCID_DATA_BLOCK_RET, n as u32, seq, *status);
        out[HEADER..HEADER + n].copy_from_slice(&body[..n]);
        return send(stream, &out[..HEADER + n]);
    }

    if secure_apdu(msg).is_some() {
        // No on-device pad here, so this is `ApduHandler::handle_secure`'s default:
        // an empty, failed DataBlock. Answering anything else would advertise a PIN
        // entry path that collects the PIN nowhere.
        put_header(out, CCID_DATA_BLOCK_RET, 0, seq, SECURE_STATUS_FAILED);
        return send(stream, &out[..HEADER]);
    }

    // A power transition is the host asking for a clean card; clear the applet
    // security status before answering, so the ATR really does describe a fresh
    // session.
    if matches!(msg.first(), Some(&CCID_POWER_ON | &CCID_POWER_OFF)) {
        run(jobs, Job::ResetCard)?;
    }
    let n = process_message(msg, atr, status, out);
    if n > 0 {
        send(stream, &out[..n])
    } else {
        Ok(())
    }
}

/// Whether the message's own `dwLength` agrees with how many bytes arrived. The
/// device reaches the same verdict by accumulating bulk-OUT packets until
/// `HEADER + dwLength`; over a socket the envelope already delivered the whole
/// message, so the check is the comparison rather than the wait.
fn framed(msg: &[u8]) -> bool {
    if msg.len() < HEADER {
        return false;
    }
    let dw = u32::from_le_bytes([msg[1], msg[2], msg[3], msg[4]]) as usize;
    dw <= MAX_CCID_MSG - HEADER && msg.len() >= HEADER + dw
}

/// Hand a job to the device thread, emitting a time-extension `DataBlock` every
/// [`WTX_INTERVAL_MS`] until it answers — the cadence the firmware's transport
/// streams while its worker blocks in on-card RSA keygen or a flash GC, and the
/// reason the host's transaction survives either.
fn run_with_wtx(
    stream: &mut TcpStream,
    jobs: &Jobs,
    job: Job,
    seq: u8,
    status: u8,
) -> io::Result<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    jobs.send(job, tx)
        .map_err(|_| io::Error::other("the device thread is gone"))?;
    loop {
        match rx.recv_timeout(Duration::from_millis(WTX_INTERVAL_MS)) {
            Ok(out) => return Ok(out.unwrap_or_default()),
            // A time extension carries its own status byte, not the slot's: it
            // says "still working", and the live `status` rides on the DataBlock
            // that finally answers.
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let _ = status;
                let mut wtx = [0u8; HEADER];
                put_header(&mut wtx, CCID_DATA_BLOCK_RET, 0, seq, STATUS_TIMEEXT);
                send(stream, &wtx)?;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(io::Error::other("the device thread dropped the job"));
            }
        }
    }
}

fn run(jobs: &Jobs, job: Job) -> io::Result<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    jobs.send(job, tx)
        .map_err(|_| io::Error::other("the device thread is gone"))?;
    match rx.recv() {
        Ok(out) => Ok(out.unwrap_or_default()),
        Err(_) => Err(io::Error::other("the device thread dropped the job")),
    }
}

fn send(stream: &mut TcpStream, payload: &[u8]) -> io::Result<()> {
    stream.write_all(&(payload.len() as u32).to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()
}

/// Accept forever, one thread per client.
pub fn listen(listener: std::net::TcpListener, jobs: Jobs, atr: &'static [u8]) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let jobs = jobs.clone();
        std::thread::spawn(move || {
            if let Err(e) = serve(stream, jobs, atr) {
                eprintln!("emu: ccid client: {e}");
            }
        });
    }
}
