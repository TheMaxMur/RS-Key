// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! An `embassy_usb::driver::Driver` over USB/IP.
//!
//! This is what makes the emulator a *device* rather than a socket that happens
//! to speak CTAPHID: the same `embassy_usb::Builder`, the same `rsk-usb` classes
//! and the same descriptors the firmware ships, with the RP2350's USB peripheral
//! replaced by [`crate::usbip`]'s transport. What a Linux host enumerates is
//! therefore the device's own descriptor set — interface order included — and not
//! a second description of it that could drift from the first.
//!
//! The join is not free, because the two sides disagree about what a transfer is.
//! USB/IP moves whole transfers: one URB carries a control request's entire data
//! stage, or as many bytes as a bulk read is willing to take. `embassy-usb` moves
//! packets, and reads the end of a transfer off a *short* one. So a URB is cut
//! into `max_packet_size` pieces on the way in and reassembled on the way out,
//! and the reassembly's completion rule — the host's buffer filled, or a short
//! packet — is the rule the USB spec gives a host controller.
//!
//! Two threads meet here: the USB/IP socket owns one, the USB stack the other.
//! Everything they share sits behind one mutex, and every endpoint future does
//! its whole mutation inside a single `poll` — so dropping one mid-`select`,
//! which both `Ccid` and `CtapHid` do, can never leave a URB half-consumed.

// The driver is complete and tested; the `Builder` that stands on it is the next
// step, so from the binary's point of view nothing here is reached yet. Scoped to
// this module so a genuinely unused item elsewhere still fails the gate.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::future::poll_fn;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use embassy_usb::driver::{
    Bus, ControlPipe, Direction, Driver, Endpoint, EndpointAddress, EndpointAllocError,
    EndpointError, EndpointIn, EndpointInfo, EndpointOut, EndpointType, Event, Unsupported,
};

use crate::usbip::{Ret, Urb, UrbSink};

/// A USB endpoint number is four bits wide, and 0 is the control pipe.
const MAX_EP: usize = 16;

/// One URB in flight on a data endpoint.
struct Pending {
    seqnum: u32,
    /// OUT: what the host sent. IN: what [`EndpointIn::write`] has accumulated.
    buf: Vec<u8>,
    /// OUT only: how much of `buf` has been handed to the stack.
    read: usize,
    /// IN: how many bytes the host will take. OUT: how many it sent.
    want: usize,
}

#[derive(Default)]
struct Ep {
    /// The host has selected a configuration that includes this endpoint.
    enabled: bool,
    /// Halted by SET_FEATURE(ENDPOINT_HALT) or by the class.
    stalled: bool,
    /// Zero until the endpoint is allocated — which is how a URB for an endpoint
    /// the descriptors never declared is told from one nobody is reading yet.
    max_packet_size: usize,
    queue: VecDeque<Pending>,
}

/// One control transfer in flight. USB/IP delivers it whole — SETUP plus the
/// entire OUT stage — so the packetisation the stack expects is produced here.
struct Ctrl {
    seqnum: u32,
    setup: [u8; 8],
    out: Vec<u8>,
    read: usize,
    reply: Vec<u8>,
    /// The host's IN buffer size; 0 for a control write.
    want: usize,
}

#[derive(Default)]
struct Shared {
    /// Where completions go while a host holds the device.
    rets: Option<Sender<Ret>>,
    events: VecDeque<Event>,
    ctrl_queue: VecDeque<Ctrl>,
    ctrl: Option<Ctrl>,
    ep_in: [Ep; MAX_EP],
    ep_out: [Ep; MAX_EP],
    /// Futures parked on any of the above. One list, woken on every change: there
    /// are a handful of them, each re-checks its own condition, and a per-endpoint
    /// wake would be bookkeeping for no gain.
    wakers: Vec<Waker>,
}

impl Shared {
    fn park(&mut self, cx: &Context<'_>) {
        if !self.wakers.iter().any(|w| w.will_wake(cx.waker())) {
            self.wakers.push(cx.waker().clone());
        }
    }

    fn wake(&mut self) {
        for w in self.wakers.drain(..) {
            w.wake();
        }
    }

    /// Answer one URB. A closed channel means the writer thread is gone, which
    /// the socket's read loop is about to notice on its own.
    fn finish(&self, ret: Ret) {
        if let Some(rets) = &self.rets {
            let _ = rets.send(ret);
        }
    }

    /// Drop every URB in flight without answering it.
    ///
    /// Called on both edges of an attach. The host is either gone or about to
    /// enumerate from scratch, and in both cases a `RET` for a URB it has already
    /// forgotten is noise — the kernel matches on a sequence number it no longer
    /// has.
    fn clear(&mut self) {
        self.ctrl = None;
        self.ctrl_queue.clear();
        for ep in self.ep_in.iter_mut().chain(self.ep_out.iter_mut()) {
            ep.queue.clear();
            ep.stalled = false;
            ep.enabled = false;
        }
    }

    fn submit(&mut self, urb: Urb) {
        let seqnum = urb.seqnum;
        if urb.ep == 0 {
            self.ctrl_queue.push_back(Ctrl {
                seqnum,
                setup: urb.setup,
                out: urb.out,
                read: 0,
                reply: Vec::new(),
                want: if urb.dir_in { urb.want } else { 0 },
            });
            self.wake();
            return;
        }
        let idx = urb.ep as usize;
        let ep = if urb.dir_in {
            &mut self.ep_in[idx]
        } else {
            &mut self.ep_out[idx]
        };
        // An endpoint no descriptor declared, or one the host itself halted, is a
        // STALL — not a URB queued against a reader that will never come.
        if ep.max_packet_size == 0 || ep.stalled {
            self.finish(Ret::stall(seqnum));
            return;
        }
        ep.queue.push_back(Pending {
            want: if urb.dir_in { urb.want } else { urb.out.len() },
            buf: if urb.dir_in { Vec::new() } else { urb.out },
            read: 0,
            seqnum,
        });
        self.wake();
    }

    fn unlink(&mut self, seqnum: u32) -> bool {
        if self.ctrl.as_ref().is_some_and(|c| c.seqnum == seqnum) {
            self.ctrl = None;
            return true;
        }
        if drop_seq(&mut self.ctrl_queue, |c| c.seqnum == seqnum) {
            return true;
        }
        self.ep_in
            .iter_mut()
            .chain(self.ep_out.iter_mut())
            .any(|ep| drop_seq(&mut ep.queue, |p| p.seqnum == seqnum))
    }

    /// Hand the stack one OUT packet, completing the URB once it is drained.
    fn ep_read(
        &mut self,
        idx: usize,
        mps: usize,
        buf: &mut [u8],
        cx: &Context<'_>,
    ) -> Poll<Result<usize, EndpointError>> {
        let ep = &mut self.ep_out[idx];
        let Some(p) = ep.queue.front_mut() else {
            self.park(cx);
            return Poll::Pending;
        };
        let n = (p.buf.len() - p.read).min(mps);
        if n > buf.len() {
            return Poll::Ready(Err(EndpointError::BufferOverflow));
        }
        buf[..n].copy_from_slice(&p.buf[p.read..p.read + n]);
        p.read += n;
        // The transfer ends when its buffer is exhausted; a zero-length URB is the
        // host's ZLP and ends on the first read.
        if p.read < p.buf.len() {
            return Poll::Ready(Ok(n));
        }
        let done = ep.queue.pop_front().expect("front_mut just succeeded");
        self.finish(Ret::out_done(done.seqnum, done.read));
        Poll::Ready(Ok(n))
    }

    /// Take one IN packet, completing the URB when the transfer ends.
    fn ep_write(
        &mut self,
        idx: usize,
        mps: usize,
        data: &[u8],
        cx: &Context<'_>,
    ) -> Poll<Result<(), EndpointError>> {
        let ep = &mut self.ep_in[idx];
        let Some(p) = ep.queue.front_mut() else {
            self.park(cx);
            return Poll::Pending;
        };
        // The host's buffer is the ceiling: a controller could not have sent more
        // than it asked for either.
        let n = data.len().min(p.want.saturating_sub(p.buf.len()));
        p.buf.extend_from_slice(&data[..n]);
        // The rule a host reads the end of a transfer off: a short packet, or its
        // buffer full. `write_transfer` produces exactly that, ZLP included, so
        // nothing here has to know how long a message was.
        if data.len() >= mps && p.buf.len() < p.want {
            return Poll::Ready(Ok(()));
        }
        let done = ep.queue.pop_front().expect("front_mut just succeeded");
        self.finish(Ret::in_data(done.seqnum, done.buf));
        Poll::Ready(Ok(()))
    }

    fn ctrl_setup(&mut self, cx: &Context<'_>) -> Poll<[u8; 8]> {
        let Some(c) = self.ctrl_queue.pop_front() else {
            self.park(cx);
            return Poll::Pending;
        };
        let setup = c.setup;
        // A transfer the stack never finished is abandoned here rather than left
        // to rot: every URB owes exactly one answer, and the host has moved on.
        if let Some(stale) = self.ctrl.replace(c) {
            self.finish(Ret::stall(stale.seqnum));
        }
        Poll::Ready(setup)
    }

    /// One OUT packet of the data stage. Synchronous: the whole stage arrived with
    /// the SETUP, so there is nothing to wait for — only to slice.
    fn ctrl_data_out(&mut self, buf: &mut [u8], mps: usize) -> Result<usize, EndpointError> {
        let Some(c) = &mut self.ctrl else {
            return Err(EndpointError::Disabled);
        };
        let n = (c.out.len() - c.read).min(mps).min(buf.len());
        buf[..n].copy_from_slice(&c.out[c.read..c.read + n]);
        c.read += n;
        Ok(n)
    }

    /// One IN packet of the data stage. `last` is the stack's own signal that the
    /// status stage follows, which is what completes the URB — there is no
    /// separate `accept` on this path.
    fn ctrl_data_in(&mut self, data: &[u8], last: bool) -> Result<(), EndpointError> {
        let Some(c) = &mut self.ctrl else {
            return Err(EndpointError::Disabled);
        };
        let n = data.len().min(c.want.saturating_sub(c.reply.len()));
        c.reply.extend_from_slice(&data[..n]);
        if !last {
            return Ok(());
        }
        let c = self.ctrl.take().expect("checked above");
        self.finish(Ret::in_data(c.seqnum, c.reply));
        Ok(())
    }

    fn ctrl_accept(&mut self) {
        if let Some(c) = self.ctrl.take() {
            // A control write's status stage: the host counts the OUT bytes it
            // sent as transferred, and nothing comes back.
            self.finish(Ret::out_done(c.seqnum, c.out.len()));
        }
    }

    fn ctrl_reject(&mut self) {
        if let Some(c) = self.ctrl.take() {
            self.finish(Ret::stall(c.seqnum));
        }
    }
}

/// Remove the first matching entry; `true` if there was one.
fn drop_seq<T>(q: &mut VecDeque<T>, pred: impl Fn(&T) -> bool) -> bool {
    match q.iter().position(pred) {
        Some(i) => {
            q.remove(i);
            true
        }
        None => false,
    }
}

/// The USB/IP transport's handle on the device. Lives on the socket thread.
pub struct Port(Arc<Mutex<Shared>>);

impl UrbSink for Port {
    fn attach(&mut self, rets: Sender<Ret>) {
        let mut s = self.0.lock().unwrap();
        s.clear();
        s.rets = Some(rets);
        // Power, then reset — the two things a device sees when it is plugged in,
        // and what `UsbDevice::run` waits for before it will answer a descriptor
        // read.
        s.events.push_back(Event::PowerDetected);
        s.events.push_back(Event::Reset);
        s.wake();
    }

    fn submit(&mut self, urb: Urb) {
        self.0.lock().unwrap().submit(urb);
    }

    fn unlink(&mut self, seqnum: u32) -> bool {
        self.0.lock().unwrap().unlink(seqnum)
    }

    fn detach(&mut self) {
        let mut s = self.0.lock().unwrap();
        s.clear();
        s.rets = None;
        s.events.push_back(Event::PowerRemoved);
        s.wake();
    }
}

/// The `embassy_usb::driver::Driver` half. Handed to `embassy_usb::Builder`, and
/// consumed by it.
pub struct UsbIpDriver {
    shared: Arc<Mutex<Shared>>,
    next_in: usize,
    next_out: usize,
}

/// Build the two halves of one emulated USB device: the driver the stack is built
/// on, and the port the USB/IP transport hands URBs to.
pub fn new() -> (UsbIpDriver, Port) {
    let shared = Arc::new(Mutex::new(Shared::default()));
    (
        UsbIpDriver {
            shared: shared.clone(),
            // Endpoint 0 is the control pipe; data endpoints start at 1.
            next_in: 1,
            next_out: 1,
        },
        Port(shared),
    )
}

impl UsbIpDriver {
    fn alloc(
        &mut self,
        dir: Direction,
        ep_addr: Option<EndpointAddress>,
        ep_type: EndpointType,
        max_packet_size: u16,
        interval_ms: u8,
    ) -> Result<EndpointInfo, EndpointAllocError> {
        let next = match dir {
            Direction::In => &mut self.next_in,
            Direction::Out => &mut self.next_out,
        };
        let index = match ep_addr {
            Some(a) => a.index(),
            None => {
                let i = *next;
                *next += 1;
                i
            }
        };
        if index == 0 || index >= MAX_EP {
            return Err(EndpointAllocError);
        }
        let mut s = self.shared.lock().unwrap();
        let ep = match dir {
            Direction::In => &mut s.ep_in[index],
            Direction::Out => &mut s.ep_out[index],
        };
        if ep.max_packet_size != 0 {
            return Err(EndpointAllocError); // already handed out
        }
        ep.max_packet_size = max_packet_size as usize;
        Ok(EndpointInfo {
            addr: EndpointAddress::from_parts(index, dir),
            ep_type,
            max_packet_size,
            interval_ms,
        })
    }
}

impl<'a> Driver<'a> for UsbIpDriver {
    type EndpointOut = EpOut;
    type EndpointIn = EpIn;
    type ControlPipe = Control;
    type Bus = UsbIpBus;

    fn alloc_endpoint_out(
        &mut self,
        ep_type: EndpointType,
        ep_addr: Option<EndpointAddress>,
        max_packet_size: u16,
        interval_ms: u8,
    ) -> Result<EpOut, EndpointAllocError> {
        let info = self.alloc(
            Direction::Out,
            ep_addr,
            ep_type,
            max_packet_size,
            interval_ms,
        )?;
        Ok(EpOut {
            shared: self.shared.clone(),
            info,
        })
    }

    fn alloc_endpoint_in(
        &mut self,
        ep_type: EndpointType,
        ep_addr: Option<EndpointAddress>,
        max_packet_size: u16,
        interval_ms: u8,
    ) -> Result<EpIn, EndpointAllocError> {
        let info = self.alloc(
            Direction::In,
            ep_addr,
            ep_type,
            max_packet_size,
            interval_ms,
        )?;
        Ok(EpIn {
            shared: self.shared.clone(),
            info,
        })
    }

    fn start(self, control_max_packet_size: u16) -> (UsbIpBus, Control) {
        (
            UsbIpBus {
                shared: self.shared.clone(),
            },
            Control {
                shared: self.shared,
                max_packet_size: control_max_packet_size as usize,
            },
        )
    }
}

pub struct UsbIpBus {
    shared: Arc<Mutex<Shared>>,
}

impl Bus for UsbIpBus {
    /// There is no peripheral to power: an attach is the whole of "enabled", and
    /// [`Port::attach`] is what reports it.
    async fn enable(&mut self) {}
    async fn disable(&mut self) {}

    async fn poll(&mut self) -> Event {
        poll_fn(|cx| {
            let mut s = self.shared.lock().unwrap();
            match s.events.pop_front() {
                Some(e) => Poll::Ready(e),
                None => {
                    s.park(cx);
                    Poll::Pending
                }
            }
        })
        .await
    }

    fn endpoint_set_enabled(&mut self, ep_addr: EndpointAddress, enabled: bool) {
        let mut s = self.shared.lock().unwrap();
        let i = ep_addr.index();
        if i >= MAX_EP {
            return;
        }
        if ep_addr.is_in() {
            s.ep_in[i].enabled = enabled;
        } else {
            s.ep_out[i].enabled = enabled;
        }
        s.wake();
    }

    fn endpoint_set_stalled(&mut self, ep_addr: EndpointAddress, stalled: bool) {
        let mut s = self.shared.lock().unwrap();
        let i = ep_addr.index();
        if i >= MAX_EP {
            return;
        }
        let ep = if ep_addr.is_in() {
            &mut s.ep_in[i]
        } else {
            &mut s.ep_out[i]
        };
        ep.stalled = stalled;
        // A halted endpoint owes its queued URBs an answer, and that answer is the
        // halt: leaving them pending makes the host wait out its own timeout for a
        // transfer that is never coming.
        let halted: Vec<u32> = if stalled {
            ep.queue.drain(..).map(|p| p.seqnum).collect()
        } else {
            Vec::new()
        };
        for seqnum in halted {
            s.finish(Ret::stall(seqnum));
        }
        s.wake();
    }

    fn endpoint_is_stalled(&mut self, ep_addr: EndpointAddress) -> bool {
        let s = self.shared.lock().unwrap();
        let i = ep_addr.index();
        i < MAX_EP
            && if ep_addr.is_in() {
                s.ep_in[i].stalled
            } else {
                s.ep_out[i].stalled
            }
    }

    /// A device on the far end of a TCP socket cannot pull the host's bus out of
    /// suspend, and USB/IP has no message for it.
    async fn remote_wakeup(&mut self) -> Result<(), Unsupported> {
        Err(Unsupported)
    }
}

pub struct EpIn {
    shared: Arc<Mutex<Shared>>,
    info: EndpointInfo,
}

pub struct EpOut {
    shared: Arc<Mutex<Shared>>,
    info: EndpointInfo,
}

/// Wait until the host's chosen configuration includes this endpoint.
///
/// Parking rather than failing is what hardware does: an endpoint that is not
/// enabled yet has nothing to say, and the transfer the class is waiting on is
/// still the transfer it will get once the host configures us.
async fn wait_enabled(shared: &Mutex<Shared>, idx: usize, is_in: bool) {
    poll_fn(|cx| {
        let mut s = shared.lock().unwrap();
        let on = if is_in {
            s.ep_in[idx].enabled
        } else {
            s.ep_out[idx].enabled
        };
        if on {
            Poll::Ready(())
        } else {
            s.park(cx);
            Poll::Pending
        }
    })
    .await
}

impl Endpoint for EpIn {
    fn info(&self) -> &EndpointInfo {
        &self.info
    }
    async fn wait_enabled(&mut self) {
        wait_enabled(&self.shared, self.info.addr.index(), true).await
    }
}

impl Endpoint for EpOut {
    fn info(&self) -> &EndpointInfo {
        &self.info
    }
    async fn wait_enabled(&mut self) {
        wait_enabled(&self.shared, self.info.addr.index(), false).await
    }
}

impl EndpointIn for EpIn {
    async fn write(&mut self, buf: &[u8]) -> Result<(), EndpointError> {
        let idx = self.info.addr.index();
        let mps = self.info.max_packet_size as usize;
        poll_fn(|cx| self.shared.lock().unwrap().ep_write(idx, mps, buf, cx)).await
    }
}

impl EndpointOut for EpOut {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, EndpointError> {
        let idx = self.info.addr.index();
        let mps = self.info.max_packet_size as usize;
        poll_fn(|cx| self.shared.lock().unwrap().ep_read(idx, mps, buf, cx)).await
    }
}

pub struct Control {
    shared: Arc<Mutex<Shared>>,
    max_packet_size: usize,
}

impl ControlPipe for Control {
    fn max_packet_size(&self) -> usize {
        self.max_packet_size
    }

    async fn setup(&mut self) -> [u8; 8] {
        poll_fn(|cx| self.shared.lock().unwrap().ctrl_setup(cx)).await
    }

    /// `first`/`last` are the stack telling itself where it is in the stage; the
    /// stage is already here in one piece, so the cursor is enough.
    async fn data_out(
        &mut self,
        buf: &mut [u8],
        _first: bool,
        _last: bool,
    ) -> Result<usize, EndpointError> {
        let mps = self.max_packet_size;
        self.shared.lock().unwrap().ctrl_data_out(buf, mps)
    }

    async fn data_in(
        &mut self,
        data: &[u8],
        _first: bool,
        last: bool,
    ) -> Result<(), EndpointError> {
        self.shared.lock().unwrap().ctrl_data_in(data, last)
    }

    async fn accept(&mut self) {
        self.shared.lock().unwrap().ctrl_accept();
    }

    async fn reject(&mut self) {
        self.shared.lock().unwrap().ctrl_reject();
    }

    /// Unreachable in practice: `vhci_hcd` answers SET_ADDRESS itself and never
    /// puts it on the wire, because the address it would assign is its own.
    async fn accept_set_address(&mut self, _addr: u8) {
        self.shared.lock().unwrap().ctrl_accept();
    }
}

#[cfg(test)]
#[path = "usbip_driver_tests.rs"]
mod tests;
