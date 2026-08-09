// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use std::sync::mpsc::Receiver;

const MPS: usize = 64;
const EP: usize = 1;

/// A driver wired to a live completion channel, with endpoint 1 allocated in both
/// directions and enabled — the state the stack leaves behind once a host has
/// selected a configuration.
fn wired() -> (Arc<Mutex<Shared>>, Port, Receiver<Ret>) {
    let (mut driver, mut port) = new();
    let _ = <UsbIpDriver as Driver>::alloc_endpoint_in(
        &mut driver,
        EndpointType::Interrupt,
        None,
        MPS as u16,
        1,
    )
    .unwrap();
    let _ = <UsbIpDriver as Driver>::alloc_endpoint_out(
        &mut driver,
        EndpointType::Interrupt,
        None,
        MPS as u16,
        1,
    )
    .unwrap();
    let shared = driver.shared.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    port.attach(tx);
    {
        let mut s = shared.lock().unwrap();
        s.ep_in[EP].enabled = true;
        s.ep_out[EP].enabled = true;
    }
    (shared, port, rx)
}

fn out_urb(seqnum: u32, data: &[u8]) -> Urb {
    Urb {
        seqnum,
        ep: EP as u8,
        dir_in: false,
        setup: [0; 8],
        out: data.to_vec(),
        want: data.len(),
    }
}

fn in_urb(seqnum: u32, want: usize) -> Urb {
    Urb {
        seqnum,
        ep: EP as u8,
        dir_in: true,
        setup: [0; 8],
        out: Vec::new(),
        want,
    }
}

fn ctrl_urb(seqnum: u32, setup: [u8; 8], out: &[u8], want: usize) -> Urb {
    Urb {
        seqnum,
        ep: 0,
        dir_in: want > 0,
        setup,
        out: out.to_vec(),
        want,
    }
}

/// Poll one of the driver's futures once, with a waker that records nothing —
/// every operation here either completes in a single poll or parks, and which of
/// the two it did is the thing under test.
fn poll_once<T>(f: impl FnOnce(&Context<'_>) -> Poll<T>) -> Poll<T> {
    let waker = Waker::noop();
    f(&Context::from_waker(waker))
}

fn read(shared: &Mutex<Shared>, buf: &mut [u8]) -> Poll<Result<usize, EndpointError>> {
    poll_once(|cx| shared.lock().unwrap().ep_read(EP, MPS, buf, cx))
}

fn write(shared: &Mutex<Shared>, data: &[u8]) -> Poll<Result<(), EndpointError>> {
    poll_once(|cx| shared.lock().unwrap().ep_write(EP, MPS, data, cx))
}

/// An OUT URB is one transfer on the wire and several packets to the stack. It
/// must be cut at the endpoint's packet size, and completed exactly once —
/// answering it on the first packet would let the host retire a transfer the
/// device has not finished reading.
#[test]
fn an_out_transfer_is_cut_into_packets_and_completed_once() {
    let (shared, mut port, rets) = wired();
    port.submit(out_urb(7, &[0xAB; 130]));

    let mut buf = [0u8; MPS];
    for expect in [MPS, MPS] {
        assert_eq!(read(&shared, &mut buf), Poll::Ready(Ok(expect)));
        assert!(rets.try_recv().is_err(), "the transfer is not over yet");
    }
    assert_eq!(read(&shared, &mut buf), Poll::Ready(Ok(2)));
    assert_eq!(rets.try_recv().unwrap(), Ret::out_done(7, 130));
    assert!(matches!(read(&shared, &mut buf), Poll::Pending));
}

/// A zero-length OUT URB is the host's ZLP: one read of nothing, and the transfer
/// is over. Treating it as "no data yet" would park a reader on a transfer that
/// has already fully arrived.
#[test]
fn a_zero_length_out_transfer_completes_on_the_first_read() {
    let (shared, mut port, rets) = wired();
    port.submit(out_urb(7, &[]));
    let mut buf = [0u8; MPS];
    assert_eq!(read(&shared, &mut buf), Poll::Ready(Ok(0)));
    assert_eq!(rets.try_recv().unwrap(), Ret::out_done(7, 0));
}

/// The stack's buffer is smaller than a packet: the packet cannot be delivered,
/// and silently handing over a prefix would corrupt the message rather than fail.
#[test]
fn a_packet_too_large_for_the_stacks_buffer_is_an_overflow() {
    let (shared, mut port, _rets) = wired();
    port.submit(out_urb(7, &[0xAB; MPS]));
    let mut small = [0u8; 8];
    assert_eq!(
        read(&shared, &mut small),
        Poll::Ready(Err(EndpointError::BufferOverflow))
    );
}

/// The completion rule on the way back: a full packet leaves the transfer open, a
/// short one ends it. Getting this backwards is the classic USB stall — the host
/// waits for bytes the device thinks it already sent.
#[test]
fn an_in_transfer_ends_on_a_short_packet() {
    let (shared, mut port, rets) = wired();
    port.submit(in_urb(7, 512));

    assert_eq!(write(&shared, &[0xAA; MPS]), Poll::Ready(Ok(())));
    assert!(rets.try_recv().is_err(), "a full packet is not the end");
    assert_eq!(write(&shared, &[0xBB; 4]), Poll::Ready(Ok(())));
    match rets.try_recv().unwrap() {
        Ret::Submit { seqnum, data, .. } => {
            assert_eq!(seqnum, 7);
            assert_eq!(data.len(), MPS + 4);
            assert_eq!(data[MPS], 0xBB);
        }
        other => panic!("expected a submit completion, got {other:?}"),
    }
}

/// A zero-length packet is a short packet, and is how a class terminates a
/// transfer whose length is an exact multiple of the packet size — the ZLP
/// `write_transfer` appends, and the case `rsk-usb`'s CCID keeps in lockstep with
/// its endpoint size.
#[test]
fn a_zero_length_packet_terminates_an_exact_multiple() {
    let (shared, mut port, rets) = wired();
    port.submit(in_urb(7, 512));
    assert_eq!(write(&shared, &[0xAA; MPS]), Poll::Ready(Ok(())));
    assert!(rets.try_recv().is_err());
    assert_eq!(write(&shared, &[]), Poll::Ready(Ok(())));
    assert_eq!(rets.try_recv().unwrap(), Ret::in_data(7, vec![0xAA; MPS]));
}

/// The host's buffer is the ceiling. A 64-byte report against a 64-byte IN URB —
/// what a HID host submits — completes on that one packet without waiting for a
/// short one that will never come.
#[test]
fn a_full_host_buffer_ends_the_transfer_too() {
    let (shared, mut port, rets) = wired();
    port.submit(in_urb(7, MPS));
    assert_eq!(write(&shared, &[0xAA; MPS]), Poll::Ready(Ok(())));
    assert_eq!(rets.try_recv().unwrap(), Ret::in_data(7, vec![0xAA; MPS]));
}

/// With no URB pending there is nothing to write into, so the class parks — it
/// does not fail, and it does not invent a buffer. This is the interrupt IN that
/// sits idle until the host asks.
#[test]
fn a_write_with_no_pending_urb_parks() {
    let (shared, _port, rets) = wired();
    assert!(matches!(write(&shared, &[0xAA; 8]), Poll::Pending));
    assert!(rets.try_recv().is_err());
}

/// URBs are answered in the order the host submitted them: a HID host keeps
/// several IN URBs queued, and reordering their completions reorders the reports.
#[test]
fn queued_in_urbs_are_answered_in_order() {
    let (shared, mut port, rets) = wired();
    port.submit(in_urb(1, MPS));
    port.submit(in_urb(2, MPS));
    assert_eq!(write(&shared, &[0x11; 4]), Poll::Ready(Ok(())));
    assert_eq!(write(&shared, &[0x22; 4]), Poll::Ready(Ok(())));
    assert_eq!(rets.try_recv().unwrap(), Ret::in_data(1, vec![0x11; 4]));
    assert_eq!(rets.try_recv().unwrap(), Ret::in_data(2, vec![0x22; 4]));
}

/// An endpoint the descriptors never declared halts. A URB queued against it
/// would sit there for ever, because nothing is reading it.
#[test]
fn an_undeclared_endpoint_halts() {
    let (_shared, mut port, rets) = wired();
    port.submit(Urb {
        ep: 9,
        ..in_urb(7, MPS)
    });
    assert_eq!(rets.try_recv().unwrap(), Ret::stall(7));
}

/// Halting an endpoint answers what is already queued on it. Leaving those URBs
/// pending makes the host wait out its own timeout for a transfer the device has
/// already decided will not happen.
#[test]
fn halting_an_endpoint_answers_its_queue() {
    let (shared, mut port, rets) = wired();
    port.submit(in_urb(7, MPS));
    let mut bus = UsbIpBus {
        shared: shared.clone(),
    };
    bus.endpoint_set_stalled(EndpointAddress::from_parts(EP, Direction::In), true);
    assert_eq!(rets.try_recv().unwrap(), Ret::stall(7));
    assert!(bus.endpoint_is_stalled(EndpointAddress::from_parts(EP, Direction::In)));
    // …and one submitted while it is halted is refused on arrival.
    port.submit(in_urb(8, MPS));
    assert_eq!(rets.try_recv().unwrap(), Ret::stall(8));
}

/// A control transfer arrives whole and is handed to the stack in packets, the
/// same as a data endpoint — `data_out_transfer` chunks by `max_packet_size` and
/// would otherwise read one packet and call the stage done.
#[test]
fn a_control_out_stage_is_handed_over_in_packets() {
    let (shared, mut port, rets) = wired();
    port.submit(ctrl_urb(
        7,
        [0x21, 0x09, 0, 0, 0, 0, 100, 0],
        &[0xCD; 100],
        0,
    ));

    let mut s = shared.lock().unwrap();
    assert!(matches!(poll_once(|cx| s.ctrl_setup(cx)), Poll::Ready(_)));
    let mut buf = [0u8; MPS];
    assert_eq!(s.ctrl_data_out(&mut buf, MPS), Ok(MPS));
    assert_eq!(s.ctrl_data_out(&mut buf, MPS), Ok(36));
    assert!(rets.try_recv().is_err(), "the status stage has not run");
    s.ctrl_accept();
    // The host counts the bytes it sent as transferred, and nothing comes back.
    assert_eq!(rets.try_recv().unwrap(), Ret::out_done(7, 100));
}

/// A control read is reassembled and answered by `data_in(last = true)` — there
/// is no `accept()` on that path, so a driver that waits for one never answers.
#[test]
fn a_control_in_stage_is_reassembled_and_answered_by_its_last_packet() {
    let (shared, mut port, rets) = wired();
    port.submit(ctrl_urb(7, [0x80, 0x06, 0, 1, 0, 0, 18, 0], &[], 18));

    let mut s = shared.lock().unwrap();
    assert_eq!(
        poll_once(|cx| s.ctrl_setup(cx)),
        Poll::Ready([0x80, 0x06, 0, 1, 0, 0, 18, 0])
    );
    assert_eq!(s.ctrl_data_in(&[0xAA; 8], false), Ok(()));
    assert!(rets.try_recv().is_err());
    assert_eq!(s.ctrl_data_in(&[0xBB; 10], true), Ok(()));
    match rets.try_recv().unwrap() {
        Ret::Submit { data, .. } => assert_eq!(data.len(), 18),
        other => panic!("expected a submit completion, got {other:?}"),
    }
}

/// A control read the device answers with more than the host asked for is cut to
/// the host's buffer: `wLength` is a ceiling, and the descriptor reads that walk
/// it up from 8 bytes depend on the short answer being short.
#[test]
fn a_control_read_is_cut_to_the_hosts_length() {
    let (shared, mut port, rets) = wired();
    port.submit(ctrl_urb(7, [0x80, 0x06, 0, 2, 0, 0, 9, 0], &[], 9));
    let mut s = shared.lock().unwrap();
    let _ = poll_once(|cx| s.ctrl_setup(cx));
    assert_eq!(s.ctrl_data_in(&[0xAA; 64], true), Ok(()));
    assert_eq!(rets.try_recv().unwrap(), Ret::in_data(7, vec![0xAA; 9]));
}

/// A rejected request halts the pipe, which is how a device says "no such
/// descriptor" — the host reads `-EPIPE` and moves on instead of retrying.
#[test]
fn a_rejected_control_request_halts_the_pipe() {
    let (shared, mut port, rets) = wired();
    port.submit(ctrl_urb(7, [0x80, 0x06, 0, 0x22, 0, 0, 64, 0], &[], 64));
    let mut s = shared.lock().unwrap();
    let _ = poll_once(|cx| s.ctrl_setup(cx));
    s.ctrl_reject();
    assert_eq!(rets.try_recv().unwrap(), Ret::stall(7));
}

/// A second SETUP while one is still open abandons the first. Every URB owes
/// exactly one answer, and a host that has moved on is not waiting for the old
/// one — but it *is* waiting to stop tracking it.
#[test]
fn a_new_setup_abandons_an_unfinished_one() {
    let (shared, mut port, rets) = wired();
    port.submit(ctrl_urb(1, [0x80, 0x06, 0, 1, 0, 0, 18, 0], &[], 18));
    port.submit(ctrl_urb(2, [0x80, 0x06, 0, 2, 0, 0, 64, 0], &[], 64));
    let mut s = shared.lock().unwrap();
    let _ = poll_once(|cx| s.ctrl_setup(cx));
    assert!(rets.try_recv().is_err());
    let _ = poll_once(|cx| s.ctrl_setup(cx));
    assert_eq!(rets.try_recv().unwrap(), Ret::stall(1));
}

/// An attach is a plug-in: power, then reset. `UsbDevice::run` enables the bus on
/// the first and rebuilds its device state on the second, and without them it
/// never answers a descriptor read at all.
#[test]
fn an_attach_reports_power_then_reset() {
    let (shared, _port, _rets) = wired();
    let mut s = shared.lock().unwrap();
    assert_eq!(s.events.pop_front(), Some(Event::PowerDetected));
    assert_eq!(s.events.pop_front(), Some(Event::Reset));
    assert_eq!(s.events.pop_front(), None);
}

/// A detach drops what was in flight and reports the unplug. Answering those URBs
/// instead would push completions at a kernel that has already forgotten their
/// sequence numbers.
#[test]
fn a_detach_drops_what_was_in_flight() {
    let (shared, mut port, rets) = wired();
    port.submit(in_urb(7, MPS));
    port.submit(ctrl_urb(8, [0x80, 0x06, 0, 1, 0, 0, 18, 0], &[], 18));
    port.detach();

    let mut s = shared.lock().unwrap();
    assert!(s.ep_in[EP].queue.is_empty());
    assert!(s.ctrl_queue.is_empty());
    assert!(!s.ep_in[EP].enabled, "the next host configures us afresh");
    assert_eq!(s.events.pop_back(), Some(Event::PowerRemoved));
    drop(s);
    assert!(rets.try_recv().is_err());
}

/// An unlink is only `-ECONNRESET` if the URB really was still here, and the
/// transport asks the driver rather than assuming. A wrong answer either way
/// leaves the host's URB accounting off by one.
#[test]
fn unlink_reports_whether_the_urb_was_still_held() {
    let (_shared, mut port, _rets) = wired();
    port.submit(in_urb(7, MPS));
    assert!(port.unlink(7));
    assert!(!port.unlink(7), "it is gone now");
    assert!(!port.unlink(99));
}

/// The same for a control transfer, in both of its states: queued, and open.
#[test]
fn unlink_finds_a_control_transfer_in_either_state() {
    let (shared, mut port, _rets) = wired();
    port.submit(ctrl_urb(1, [0; 8], &[], 8));
    assert!(port.unlink(1));

    port.submit(ctrl_urb(2, [0; 8], &[], 8));
    let _ = poll_once(|cx| shared.lock().unwrap().ctrl_setup(cx));
    assert!(port.unlink(2), "an open transfer is still cancellable");
}

/// Every endpoint gets its own address, and endpoint 0 is never handed out —
/// it is the control pipe, and an interface that landed on it would answer
/// descriptor reads with its own data.
#[test]
fn endpoints_are_allocated_from_one_upwards() {
    let (mut driver, _port) = new();
    let a =
        <UsbIpDriver as Driver>::alloc_endpoint_in(&mut driver, EndpointType::Bulk, None, 64, 0)
            .unwrap();
    let b =
        <UsbIpDriver as Driver>::alloc_endpoint_in(&mut driver, EndpointType::Bulk, None, 64, 0)
            .unwrap();
    let c =
        <UsbIpDriver as Driver>::alloc_endpoint_out(&mut driver, EndpointType::Bulk, None, 64, 0)
            .unwrap();
    assert_eq!(a.info.addr.index(), 1);
    assert_eq!(b.info.addr.index(), 2);
    assert_eq!(c.info.addr.index(), 1, "IN and OUT number separately");
    assert!(a.info.addr.is_in());
    assert!(!c.info.addr.is_in());
}

/// The same address twice is a build-time mistake in the descriptors, and it must
/// fail there rather than at the second reader of one queue.
#[test]
fn an_address_cannot_be_handed_out_twice() {
    let (mut driver, _port) = new();
    let pinned = Some(EndpointAddress::from_parts(3, Direction::In));
    assert!(
        <UsbIpDriver as Driver>::alloc_endpoint_in(&mut driver, EndpointType::Bulk, pinned, 64, 0)
            .is_ok()
    );
    assert!(
        <UsbIpDriver as Driver>::alloc_endpoint_in(&mut driver, EndpointType::Bulk, pinned, 64, 0)
            .is_err()
    );
}
