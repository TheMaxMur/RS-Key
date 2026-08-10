// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use std::net::TcpListener;

use rsk_usb::ctaphid::STATUS_UPNEEDED;

use super::*;
use crate::signals::SCOPE_FIDO;

const CID: u32 = 0x0100_0000;

fn frame(cid: u32, cmd: u8) -> [u8; HID_RPT_SIZE] {
    let mut f = [0u8; HID_RPT_SIZE];
    f[0..4].copy_from_slice(&cid.to_le_bytes());
    f[4] = cmd;
    f
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

    let (jobs, requests) = mpsc::channel();
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
        let req = requests.recv().unwrap();
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
