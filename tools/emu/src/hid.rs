// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAPHID over a TCP socket: the stream carries the same 64-byte reports the
//! USB HID interface would, in both directions, so a client is a `send(64)` /
//! `recv(64)` shim away from talking to the emulator.
//!
//! Framing and the native commands come from `rsk_usb::ctaphid` — the same
//! [`Reassembler`], [`TxFrames`] and command constants the firmware transport
//! uses. What is re-implemented here is the dispatch *arm order* (the async
//! `CtapHid::run` cannot drive a socket), so this is where CTAPHID behaviour can
//! drift from the device.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rsk_usb::ctaphid::{
    CID_BROADCAST, CTAPHID_CANCEL, CTAPHID_CBOR, CTAPHID_ERROR, CTAPHID_IF_VERSION, CTAPHID_INIT,
    CTAPHID_KEEPALIVE, CTAPHID_LOCK, CTAPHID_MSG, CTAPHID_PING, CTAPHID_SYNC, CTAPHID_UUID,
    CTAPHID_VENDOR_FIRST, CTAPHID_VERSION, CTAPHID_WINK, ChannelLock, CidAllocator, DEVICE_UUID,
    ERR_CHANNEL_BUSY, ERR_INVALID_CMD, ERR_INVALID_LEN, ERR_INVALID_PAR, ERR_MSG_TIMEOUT,
    HID_RPT_SIZE, KEEPALIVE_MS, LOCK_MAX_SECONDS, Outcome, RX_TIMEOUT_MS, Reassembler, TxFrames,
    init_capabilities, is_cancel_frame, keepalive_status,
};

use crate::device::{Job, Req};
use crate::signals::Signals;

/// The emulator prints its wink to the terminal, so it really does have an
/// indicator to flash and may claim the capability.
const CAN_WINK: bool = true;

pub struct Shared {
    pub jobs: mpsc::Sender<Req>,
    pub signals: Arc<Signals>,
    /// Channel ids are device-wide, not per-connection: two client processes
    /// sharing one key must not be handed the same channel (§11.2.9.1.3).
    pub cids: Mutex<CidAllocator>,
    pub lock: Mutex<ChannelLock>,
    pub boot: Instant,
}

pub fn serve(mut stream: TcpStream, shared: Arc<Shared>) -> io::Result<()> {
    let mut asm = Reassembler::new();
    let mut rx = FrameRx::default();
    loop {
        match rx.next(&stream, asm.in_progress())? {
            Rx::Eof => return Ok(()),
            // A host that sends frame 1 and walks away otherwise keeps the
            // reassembler for the life of the connection, and one connection is one
            // HID interface: every other channel is answered `CHANNEL_BUSY` until a
            // `CTAPHID_INIT` on the abandoned one. `CtapHid::run` recovers by racing
            // its read against the same deadline.
            Rx::Timeout => {
                let cid = asm.current_cid();
                asm.abort();
                write_msg(&mut stream, cid, CTAPHID_ERROR, &[ERR_MSG_TIMEOUT])?;
            }
            Rx::Frame => {
                let now_ms = shared.boot.elapsed().as_millis() as u64;
                match asm.feed(&rx.frame) {
                    Outcome::None => {}
                    Outcome::Error(cid, code) => {
                        write_msg(&mut stream, cid, CTAPHID_ERROR, &[code])?
                    }
                    Outcome::Message(cid, cmd)
                        if shared.lock.lock().unwrap().refuses(cid, cmd, now_ms) =>
                    {
                        write_msg(&mut stream, cid, CTAPHID_ERROR, &[ERR_CHANNEL_BUSY])?
                    }
                    Outcome::Message(cid, cmd) => {
                        dispatch(&mut stream, &shared, &mut asm, cid, cmd, now_ms)?
                    }
                }
            }
        }
    }
}

/// What [`FrameRx::next`] came back with.
enum Rx {
    /// A whole 64-byte report is in [`FrameRx::frame`].
    Frame,
    /// The deadline passed with the report still incomplete.
    Timeout,
    /// The peer closed.
    Eof,
}

/// The RX half of the connection: whole 64-byte reports, deadlined while a
/// multi-frame message is mid-reassembly.
///
/// The bytes of a half-arrived report are carried across the deadline rather than
/// dropped — TCP may split a report, and half a frame discarded here misaligns
/// every frame behind it. The device transport needs none of that: USB delivers
/// whole reports, so its `select` can simply abandon the read.
struct FrameRx {
    frame: [u8; HID_RPT_SIZE],
    have: usize,
}

impl Default for FrameRx {
    fn default() -> Self {
        Self {
            frame: [0; HID_RPT_SIZE],
            have: 0,
        }
    }
}

impl FrameRx {
    /// The next whole report. `bounded` is "a message is mid-reassembly", and only
    /// then is the wait finite — an idle transport waits for its next client as
    /// long as it takes, exactly as `CtapHid::run` does.
    fn next(&mut self, mut stream: &TcpStream, bounded: bool) -> io::Result<Rx> {
        let deadline = Instant::now() + Duration::from_millis(RX_TIMEOUT_MS);
        loop {
            let left = if bounded {
                let left = deadline.saturating_duration_since(Instant::now());
                // A zero read timeout means "no timeout" to the socket layer.
                if left.is_zero() {
                    return Ok(Rx::Timeout);
                }
                Some(left)
            } else {
                None
            };
            stream.set_read_timeout(left)?;
            match stream.read(&mut self.frame[self.have..]) {
                Ok(0) => return Ok(Rx::Eof),
                Ok(n) => {
                    self.have += n;
                    if self.have == HID_RPT_SIZE {
                        self.have = 0;
                        return Ok(Rx::Frame);
                    }
                }
                // An expired read timeout arrives as one or the other by platform.
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(Rx::Timeout);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
}

fn dispatch(
    stream: &mut TcpStream,
    shared: &Arc<Shared>,
    asm: &mut Reassembler,
    cid: u32,
    cmd: u8,
    now_ms: u64,
) -> io::Result<()> {
    match cmd {
        CTAPHID_INIT => {
            // A fresh session drops anything selected over MSG, so U2F (which has
            // no SELECT) cannot inherit it.
            run_job(shared, Job::DeselectMsg, false, None)?;
            // nonce(8) | newcid(4) | iface | major | minor | build | caps
            let nonce = asm.message();
            let mut resp = [0u8; 17];
            let k = nonce.len().min(8);
            resp[..k].copy_from_slice(&nonce[..k]);
            let assigned = if cid == CID_BROADCAST {
                shared.cids.lock().unwrap().allocate()
            } else {
                cid
            };
            resp[8..12].copy_from_slice(&assigned.to_le_bytes());
            resp[12] = CTAPHID_IF_VERSION;
            resp[13] = rsk_sdk::FIRMWARE_VERSION.0;
            resp[14] = rsk_sdk::FIRMWARE_VERSION.1;
            resp[15] = rsk_sdk::FIRMWARE_VERSION.2;
            resp[16] = init_capabilities(CAN_WINK);
            write_msg(stream, cid, CTAPHID_INIT, &resp)
        }
        CTAPHID_PING | CTAPHID_SYNC => {
            let echo = asm.message().to_vec();
            write_msg(stream, cid, cmd, &echo)
        }
        CTAPHID_WINK => {
            eprintln!("emu: ✨ wink");
            write_msg(stream, cid, CTAPHID_WINK, &[])
        }
        CTAPHID_LOCK => match asm.message() {
            [secs] if *secs <= LOCK_MAX_SECONDS => {
                shared.lock.lock().unwrap().arm(cid, *secs, now_ms);
                write_msg(stream, cid, CTAPHID_LOCK, &[])
            }
            [_] => write_msg(stream, cid, CTAPHID_ERROR, &[ERR_INVALID_PAR]),
            _ => write_msg(stream, cid, CTAPHID_ERROR, &[ERR_INVALID_LEN]),
        },
        CTAPHID_VERSION => {
            let v = rsk_sdk::FIRMWARE_VERSION;
            write_msg(stream, cid, CTAPHID_VERSION, &[v.0, v.1, v.2, 0])
        }
        CTAPHID_UUID => write_msg(stream, cid, CTAPHID_UUID, &DEVICE_UUID),
        // Never acknowledged; it aborts an in-flight touch on this channel only.
        CTAPHID_CANCEL => {
            shared.signals.request_cancel(cid);
            Ok(())
        }
        CTAPHID_MSG => {
            let data = asm.message().to_vec();
            let out = run_job(shared, Job::Msg(data), false, Some((stream, cid)))?;
            match out {
                Some(body) => write_msg(stream, cid, CTAPHID_MSG, &body),
                None => write_msg(stream, cid, CTAPHID_ERROR, &[ERR_INVALID_CMD]),
            }
        }
        CTAPHID_CBOR => {
            let data = asm.message().to_vec();
            if data.is_empty() {
                return write_msg(stream, cid, CTAPHID_ERROR, &[ERR_INVALID_LEN]);
            }
            let out = run_job(shared, Job::Cbor { cid, data }, true, Some((stream, cid)))?;
            match out {
                Some(body) => write_msg(stream, cid, CTAPHID_CBOR, &body),
                None => write_msg(stream, cid, CTAPHID_ERROR, &[ERR_INVALID_CMD]),
            }
        }
        cmd if cmd >= CTAPHID_VENDOR_FIRST => {
            let data = asm.message().to_vec();
            let job = Job::Vendor {
                cmd: cmd & !0x80,
                data,
            };
            match run_job(shared, job, false, Some((stream, cid)))? {
                Some(body) => write_msg(stream, cid, cmd, &body),
                None => write_msg(stream, cid, CTAPHID_ERROR, &[ERR_INVALID_CMD]),
            }
        }
        _ => write_msg(stream, cid, CTAPHID_ERROR, &[ERR_INVALID_CMD]),
    }
}

/// Hand a job to the device thread, streaming `CTAPHID_KEEPALIVE` on `channel`
/// while it runs — the frames that make a client show "touch your security key"
/// instead of timing out — and watching that same channel for the
/// `CTAPHID_CANCEL` that ends the touch wait. Pass `channel = None` for a job
/// whose answer nobody waits on.
fn run_job(
    shared: &Arc<Shared>,
    job: Job,
    is_cbor: bool,
    channel: Option<(&mut TcpStream, u32)>,
) -> io::Result<Option<Vec<u8>>> {
    let (tx, rx) = mpsc::channel();
    if shared.jobs.send(Req { job, reply: tx }).is_err() {
        return Err(io::Error::other("the device thread is gone"));
    }
    let Some((stream, cid)) = channel else {
        let _ = rx.recv();
        return Ok(None);
    };
    let mut watch = CancelWatch::default();
    loop {
        match rx.recv_timeout(Duration::from_millis(KEEPALIVE_MS)) {
            Ok(out) => return Ok(out),
            Err(RecvTimeoutError::Timeout) => {
                let up = shared.signals.up_pending_for(crate::signals::SCOPE_FIDO);
                if let Some(status) = keepalive_status(is_cbor, up) {
                    write_msg(stream, cid, CTAPHID_KEEPALIVE, &[status])?;
                }
                // Only during the touch wait, exactly as `CtapHid::run_with_keepalive`
                // watches only then: off it the platform pipelines its next request,
                // and a frame consumed here would be that request swallowed.
                if up && poll_cancel(stream, &mut watch, cid)? {
                    shared.signals.request_cancel(cid);
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(io::Error::other("the device thread dropped the job"));
            }
        }
    }
}

/// The `CTAPHID_CANCEL` that arrives mid-ceremony, on a socket nobody else is
/// reading.
///
/// `serve` is parked inside `run_job` for the whole of a command, so a cancel
/// frame would otherwise sit in the receive buffer until the touch wait it was
/// sent to abort had already ended — the wait is the only thing worth cancelling,
/// so the command would always answer as if no cancel had come. The device
/// transport races this read in its `select3` instead; this is the socket's
/// version of the same watch.
///
/// The partial frame is carried between polls: TCP may split a 64-byte report
/// across segments, and half a frame dropped here would misalign every frame
/// after it.
struct CancelWatch {
    frame: [u8; HID_RPT_SIZE],
    have: usize,
}

impl Default for CancelWatch {
    fn default() -> Self {
        Self {
            frame: [0; HID_RPT_SIZE],
            have: 0,
        }
    }
}

impl CancelWatch {
    /// Consume whatever has already arrived, without blocking; `true` once a whole
    /// frame proves to be a CANCEL for `cid`. Any other frame is dropped, as the
    /// device transport drops it.
    fn poll<R: Read>(&mut self, mut src: R, cid: u32) -> io::Result<bool> {
        loop {
            match src.read(&mut self.frame[self.have..]) {
                // The peer closed. `serve`'s own read reports that; here it just
                // means no cancel is coming.
                Ok(0) => return Ok(false),
                Ok(n) => {
                    self.have += n;
                    if self.have < HID_RPT_SIZE {
                        continue;
                    }
                    self.have = 0;
                    if is_cancel_frame(&self.frame, HID_RPT_SIZE, cid) {
                        return Ok(true);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

/// [`CancelWatch::poll`] over the connection, which has to leave blocking mode for
/// it and be back in it before `serve` reads the next frame.
fn poll_cancel(stream: &TcpStream, watch: &mut CancelWatch, cid: u32) -> io::Result<bool> {
    stream.set_nonblocking(true)?;
    let seen = watch.poll(stream, cid);
    stream.set_nonblocking(false)?;
    seen
}

fn write_msg(stream: &mut TcpStream, cid: u32, cmd: u8, data: &[u8]) -> io::Result<()> {
    for f in TxFrames::new(cid, cmd, data) {
        stream.write_all(&f)?;
    }
    stream.flush()
}

#[cfg(test)]
#[path = "hid_tests.rs"]
mod tests;
