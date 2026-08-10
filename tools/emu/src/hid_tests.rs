// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

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
