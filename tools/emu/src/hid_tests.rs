// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use rsk_usb::ctaphid::{
    CTAPHID_CANCEL, CTAPHID_KEEPALIVE, ChannelLock, CidAllocator, HID_RPT_SIZE,
};

use super::{Shared, run_active_job};
use crate::signals::{SCOPE_FIDO, Signals};

#[test]
fn active_job_streams_upneeded_and_reads_fragmented_scoped_cancel() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let signals = Arc::new(Signals::default());
    signals.set_wait_scope(SCOPE_FIDO);
    let cid = 0x0102_0304;
    signals.begin(cid);
    signals.set_up_pending(true);
    let (jobs, _requests) = mpsc::channel();
    let shared = Arc::new(Shared {
        jobs,
        signals: signals.clone(),
        cids: Mutex::new(CidAllocator::new()),
        lock: Mutex::new(ChannelLock::default()),
        boot: Instant::now(),
    });
    let (reply, replies) = mpsc::channel();
    let worker_signals = signals.clone();
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !worker_signals.cancelled() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        reply.send(Some(vec![0x2d])).unwrap();
    });

    let (server_result, result) = mpsc::channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        server_result
            .send(run_active_job(&mut stream, &shared, &replies, cid, true))
            .unwrap();
    });

    let mut client = TcpStream::connect(address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut keepalive = [0u8; HID_RPT_SIZE];
    client.read_exact(&mut keepalive).unwrap();
    assert_eq!(keepalive[4], CTAPHID_KEEPALIVE);
    assert_eq!(keepalive[7], 0x02, "presence must report UPNEEDED");

    let mut cancel = [0u8; HID_RPT_SIZE];
    cancel[..4].copy_from_slice(&0x0506_0708u32.to_le_bytes());
    cancel[4] = CTAPHID_CANCEL;
    client.write_all(&cancel).unwrap();
    client.read_exact(&mut keepalive).unwrap();

    cancel[..4].copy_from_slice(&cid.to_le_bytes());
    client.write_all(&cancel[..13]).unwrap();
    client.write_all(&cancel[13..]).unwrap();

    assert_eq!(
        result
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap(),
        Some(vec![0x2d])
    );
    assert!(signals.cancelled());
}
