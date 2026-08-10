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
    ERR_CHANNEL_BUSY, ERR_INVALID_CMD, ERR_INVALID_LEN, ERR_INVALID_PAR, HID_RPT_SIZE,
    KEEPALIVE_MS, LOCK_MAX_SECONDS, Outcome, Reassembler, TxFrames, init_capabilities,
    keepalive_status,
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
    let mut frame = [0u8; HID_RPT_SIZE];
    loop {
        match stream.read_exact(&mut frame) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let now_ms = shared.boot.elapsed().as_millis() as u64;
        match asm.feed(&frame) {
            Outcome::None => {}
            Outcome::Error(cid, code) => write_msg(&mut stream, cid, CTAPHID_ERROR, &[code])?,
            Outcome::Message(cid, cmd) if shared.lock.lock().unwrap().refuses(cid, cmd, now_ms) => {
                write_msg(&mut stream, cid, CTAPHID_ERROR, &[ERR_CHANNEL_BUSY])?
            }
            Outcome::Message(cid, cmd) => {
                dispatch(&mut stream, &shared, &mut asm, cid, cmd, now_ms)?
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
/// instead of timing out. Pass `channel = None` for a job whose answer nobody
/// waits on.
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
    loop {
        match rx.recv_timeout(Duration::from_millis(KEEPALIVE_MS)) {
            Ok(out) => return Ok(out),
            Err(RecvTimeoutError::Timeout) => {
                if let Some(status) = keepalive_status(
                    is_cbor,
                    shared.signals.up_pending_for(crate::signals::SCOPE_FIDO),
                ) {
                    write_msg(stream, cid, CTAPHID_KEEPALIVE, &[status])?;
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(io::Error::other("the device thread dropped the job"));
            }
        }
    }
}

fn write_msg(stream: &mut TcpStream, cid: u32, cmd: u8, data: &[u8]) -> io::Result<()> {
    for f in TxFrames::new(cid, cmd, data) {
        stream.write_all(&f)?;
    }
    stream.flush()
}
