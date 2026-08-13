// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use std::net::TcpListener;

use rsk_usb::ctaphid::{CID_BROADCAST, STATUS_UPNEEDED};

use super::*;
use crate::signals::SCOPE_FIDO;

const CID: u32 = 0x0100_0000;

fn frame(cid: u32, cmd: u8) -> [u8; HID_RPT_SIZE] {
    let mut f = [0u8; HID_RPT_SIZE];
    f[0..4].copy_from_slice(&cid.to_le_bytes());
    f[4] = cmd;
    f
}

/// An init-type frame declaring `bcnt` payload bytes, carrying as much of `data`
/// as fits.
fn init_frame(cid: u32, cmd: u8, bcnt: usize, data: &[u8]) -> [u8; HID_RPT_SIZE] {
    let mut f = frame(cid, cmd);
    f[5..7].copy_from_slice(&(bcnt as u16).to_be_bytes());
    let n = data.len().min(HID_RPT_SIZE - 7);
    f[7..7 + n].copy_from_slice(&data[..n]);
    f
}

/// `serve` on the far end of a real socket, with a stub device thread behind it,
/// so a test drives the loop the way a client does rather than its pieces.
fn serve_on_a_socket() -> TcpStream {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();

    let (jobs, requests) = crate::device::job_queue();
    std::thread::spawn(move || {
        while let Ok(req) = requests.next() {
            let _ = req.reply.send(Some(Vec::new()));
        }
    });
    let shared = Arc::new(Shared {
        jobs,
        signals: Arc::new(Signals::default()),
        cids: Mutex::new(CidAllocator::new()),
        lock: Mutex::new(ChannelLock::default()),
        boot: Instant::now(),
    });
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let _ = serve(stream, shared);
    });

    let client = TcpStream::connect(address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client
}

fn read_frame(client: &mut TcpStream) -> [u8; HID_RPT_SIZE] {
    let mut f = [0u8; HID_RPT_SIZE];
    client.read_exact(&mut f).unwrap();
    f
}

/// A `CTAPHID_INIT` on the broadcast channel; returns the channel it hands out.
fn allocate(client: &mut TcpStream, nonce: u8) -> u32 {
    let f = init_frame(CID_BROADCAST, CTAPHID_INIT, 8, &[nonce; 8]);
    client.write_all(&f).unwrap();
    let r = read_frame(client);
    u32::from_le_bytes([r[15], r[16], r[17], r[18]])
}

/// A socket that hands out scripted chunks and then says "nothing yet", the way a
/// non-blocking `TcpStream` does — that `WouldBlock` is what ends a poll, so it
/// has to be in the fake or the loop under test never returns.
struct Chunks(Vec<Vec<u8>>);

impl Read for Chunks {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.0.is_empty() {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let chunk = self.0.remove(0);
        let n = chunk.len().min(buf.len());
        buf[..n].copy_from_slice(&chunk[..n]);
        Ok(n)
    }
}

#[test]
fn a_whole_cancel_frame_is_seen() {
    let mut w = CancelWatch::default();
    let mut src = Chunks(vec![frame(CID, CTAPHID_CANCEL).to_vec()]);
    assert!(w.poll(&mut src, CID).unwrap());
}

/// TCP is a byte stream, so a 64-byte report can arrive in pieces across two
/// polls. Dropping the first piece would both lose this cancel and misalign every
/// frame behind it.
#[test]
fn a_cancel_split_across_polls_is_reassembled() {
    let f = frame(CID, CTAPHID_CANCEL).to_vec();
    let mut w = CancelWatch::default();
    let mut first = Chunks(vec![f[..30].to_vec()]);
    assert!(
        !w.poll(&mut first, CID).unwrap(),
        "half a frame decides nothing"
    );
    let mut rest = Chunks(vec![f[30..].to_vec()]);
    assert!(w.poll(&mut rest, CID).unwrap());
}

/// Anything else mid-ceremony is dropped, exactly as the device transport drops
/// it — but dropped by whole frames, so the cancel behind it still lands.
#[test]
fn an_unrelated_frame_is_dropped_without_losing_the_cancel_behind_it() {
    let mut w = CancelWatch::default();
    let mut src = Chunks(vec![
        frame(CID, CTAPHID_PING).to_vec(),
        frame(CID, CTAPHID_CANCEL).to_vec(),
    ]);
    assert!(w.poll(&mut src, CID).unwrap());
}

/// A second process cancelling on its own channel is not this ceremony's answer —
/// the scoping `Signals::cancelled` enforces, checked here at the frame.
#[test]
fn another_channels_cancel_is_not_ours() {
    let mut w = CancelWatch::default();
    let mut src = Chunks(vec![frame(0x0200_0000, CTAPHID_CANCEL).to_vec()]);
    assert!(!w.poll(&mut src, CID).unwrap());
}

/// A closed peer reads as `Ok(0)` forever; the poll has to end on it rather than
/// spin, since the job it is waiting on can still be running.
#[test]
fn a_closed_connection_ends_the_poll() {
    let mut w = CancelWatch::default();
    let mut src = Chunks(vec![Vec::new()]);
    assert!(!w.poll(&mut src, CID).unwrap());
}

/// The whole path over a real socket, with a stand-in device thread: a pending
/// touch streams `UPNEEDED`, another channel's CANCEL is ignored, and this
/// channel's — split across two writes — ends the ceremony.
///
/// The tests above pin the framing rule; this one pins the wiring, which is what
/// was actually broken. The poll runs only inside the touch wait, so a watch that
/// never reached it would still satisfy every assertion above.
#[test]
fn a_cancel_reaches_a_job_waiting_for_a_touch() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();

    let signals = Arc::new(Signals::default());
    signals.set_wait_scope(SCOPE_FIDO);
    signals.begin(CID);
    signals.set_up_pending(true);

    let (jobs, requests) = crate::device::job_queue();
    let shared = Arc::new(Shared {
        jobs,
        signals: signals.clone(),
        cids: Mutex::new(CidAllocator::new()),
        lock: Mutex::new(ChannelLock::default()),
        boot: Instant::now(),
    });

    // Stands in for the device thread: holds the ceremony until the cancel lands,
    // as `EmuPresence` does, then answers KEEPALIVE_CANCEL.
    let device = signals.clone();
    std::thread::spawn(move || {
        let req = requests.next().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !device.cancelled() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let _ = req.reply.send(Some(vec![0x2d]));
    });

    let (done_tx, done) = mpsc::channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let job = Job::Cbor {
            cid: CID,
            data: vec![0x0b],
        };
        let out = run_job(&shared, job, true, Some((&mut stream, CID)));
        done_tx.send(out.unwrap()).unwrap();
    });

    let mut client = TcpStream::connect(address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut msg = [0u8; HID_RPT_SIZE];
    client.read_exact(&mut msg).unwrap();
    assert_eq!(msg[4], CTAPHID_KEEPALIVE);
    assert_eq!(msg[7], STATUS_UPNEEDED, "a pending touch reports UPNEEDED");

    // Someone else's cancel is not this ceremony's answer: the keepalives go on.
    let mut cancel = frame(0x0506_0708, CTAPHID_CANCEL);
    client.write_all(&cancel).unwrap();
    client.read_exact(&mut msg).unwrap();
    assert_eq!(msg[4], CTAPHID_KEEPALIVE);

    // Ours, in two writes, so the poll has to reassemble it off the wire.
    cancel[..4].copy_from_slice(&CID.to_le_bytes());
    client.write_all(&cancel[..13]).unwrap();
    client.write_all(&cancel[13..]).unwrap();

    assert_eq!(
        done.recv_timeout(Duration::from_secs(5)).unwrap(),
        Some(vec![0x2d])
    );
    assert!(signals.cancelled());
}

/// An abandoned multi-frame message must not own the reassembler for the life of
/// the connection. Measured on the emulator before this: after frame 1 of a
/// 200-byte PING the client got no MSG_TIMEOUT at all, and a complete PING on a
/// second channel answered `CHANNEL_BUSY` at t+0.6 s, t+2 s and t+5 s alike —
/// only a `CTAPHID_INIT` on the stuck channel ever cleared it. One TCP connection
/// is one HID interface, so there is nowhere else for the session to escape to.
#[test]
fn an_abandoned_message_times_out_instead_of_wedging_the_session() {
    let mut client = serve_on_a_socket();
    let stuck = allocate(&mut client, 0x01);
    let other = allocate(&mut client, 0x11);

    // Frame 1 of 200 bytes, then silence.
    client
        .write_all(&init_frame(stuck, CTAPHID_PING, 200, &[0xa5; 57]))
        .unwrap();

    let r = read_frame(&mut client);
    assert_eq!(u32::from_le_bytes([r[0], r[1], r[2], r[3]]), stuck);
    assert_eq!(r[4], CTAPHID_ERROR);
    assert_eq!(
        r[7], ERR_MSG_TIMEOUT,
        "the late message is dropped, and said so"
    );

    // And the session is usable again without a client having to guess that an
    // INIT on someone else's channel is the way out.
    client
        .write_all(&init_frame(other, CTAPHID_PING, 2, &[0xab, 0xcd]))
        .unwrap();
    let r = read_frame(&mut client);
    assert_eq!(r[4], CTAPHID_PING, "not {:#04x}", r[7]);
    assert_eq!(&r[7..9], &[0xab, 0xcd]);
}

/// The deadline is per frame, not per message: continuations 300 ms apart are
/// each inside `RX_TIMEOUT_MS` and the message completes, though it takes 900 ms
/// end to end. Without this a timeout could be turned into a cap on how long a
/// large message may take, which is the same wedge with a slower trigger.
#[test]
fn continuations_that_keep_arriving_are_not_timed_out() {
    let mut client = serve_on_a_socket();
    let cid = allocate(&mut client, 0x02);

    let body: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
    client
        .write_all(&init_frame(cid, CTAPHID_PING, body.len(), &body))
        .unwrap();
    for (seq, chunk) in body[57..].chunks(HID_RPT_SIZE - 5).enumerate() {
        std::thread::sleep(Duration::from_millis(300));
        let mut f = frame(cid, seq as u8);
        f[5..5 + chunk.len()].copy_from_slice(chunk);
        client.write_all(&f).unwrap();
    }

    let mut echo = Vec::new();
    let r = read_frame(&mut client);
    assert_eq!(r[4], CTAPHID_PING, "not {:#04x}", r[7]);
    echo.extend_from_slice(&r[7..]);
    while echo.len() < body.len() {
        echo.extend_from_slice(&read_frame(&mut client)[5..]);
    }
    assert_eq!(&echo[..body.len()], &body[..]);
}
