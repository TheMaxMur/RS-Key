// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use core::future::{Future, pending};
use core::task::{Context, Waker};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use embassy_usb::driver::{
    Bus, ControlPipe, Direction, Driver, Endpoint, EndpointAddress, EndpointAllocError,
    EndpointError, EndpointIn, EndpointInfo, EndpointOut, EndpointType, Event, Unsupported,
};

pub enum Read {
    Packet(Vec<u8>),
    Error(EndpointError),
    Stall,
}

pub enum Write {
    Error,
    Stall,
}

#[derive(Default)]
pub struct Wire {
    pub reads: VecDeque<Read>,
    pub writes: VecDeque<Write>,
    pub packets: Vec<(EndpointAddress, Vec<u8>)>,
    pub allocated: Vec<EndpointInfo>,
}

pub type Trace = Rc<RefCell<Wire>>;

pub struct TestDriver {
    trace: Trace,
    next_in: usize,
    next_out: usize,
}

impl TestDriver {
    pub fn new(trace: &Trace) -> Self {
        Self {
            trace: trace.clone(),
            next_in: 1,
            next_out: 1,
        }
    }
}

pub struct TestEndpoint {
    trace: Trace,
    info: EndpointInfo,
}

impl Endpoint for TestEndpoint {
    fn info(&self) -> &EndpointInfo {
        &self.info
    }

    async fn wait_enabled(&mut self) {}
}

impl EndpointOut for TestEndpoint {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, EndpointError> {
        let next = core::future::poll_fn(|_| {
            self.trace
                .borrow_mut()
                .reads
                .pop_front()
                .map_or(core::task::Poll::Pending, core::task::Poll::Ready)
        })
        .await;
        match next {
            Read::Packet(packet) => {
                let dst = buf
                    .get_mut(..packet.len())
                    .ok_or(EndpointError::BufferOverflow)?;
                dst.copy_from_slice(&packet);
                Ok(packet.len())
            }
            Read::Error(error) => Err(error),
            Read::Stall => pending().await,
        }
    }
}

impl EndpointIn for TestEndpoint {
    async fn write(&mut self, buf: &[u8]) -> Result<(), EndpointError> {
        let next = self.trace.borrow_mut().writes.pop_front();
        match next {
            Some(Write::Error) => Err(EndpointError::Disabled),
            Some(Write::Stall) => pending().await,
            None => {
                self.trace
                    .borrow_mut()
                    .packets
                    .push((self.info.addr, buf.to_vec()));
                Ok(())
            }
        }
    }
}

impl<'a> Driver<'a> for TestDriver {
    type EndpointOut = TestEndpoint;
    type EndpointIn = TestEndpoint;
    type ControlPipe = TestControl;
    type Bus = TestBus;

    fn alloc_endpoint_out(
        &mut self,
        ep_type: EndpointType,
        ep_addr: Option<EndpointAddress>,
        max_packet_size: u16,
        interval_ms: u8,
    ) -> Result<TestEndpoint, EndpointAllocError> {
        let addr =
            ep_addr.unwrap_or_else(|| EndpointAddress::from_parts(self.next_out, Direction::Out));
        self.next_out += 1;
        let info = EndpointInfo {
            addr,
            ep_type,
            max_packet_size,
            interval_ms,
        };
        self.trace.borrow_mut().allocated.push(info);
        Ok(TestEndpoint {
            trace: self.trace.clone(),
            info,
        })
    }

    fn alloc_endpoint_in(
        &mut self,
        ep_type: EndpointType,
        ep_addr: Option<EndpointAddress>,
        max_packet_size: u16,
        interval_ms: u8,
    ) -> Result<TestEndpoint, EndpointAllocError> {
        let addr =
            ep_addr.unwrap_or_else(|| EndpointAddress::from_parts(self.next_in, Direction::In));
        self.next_in += 1;
        let info = EndpointInfo {
            addr,
            ep_type,
            max_packet_size,
            interval_ms,
        };
        self.trace.borrow_mut().allocated.push(info);
        Ok(TestEndpoint {
            trace: self.trace.clone(),
            info,
        })
    }

    fn start(self, _control_max_packet_size: u16) -> (TestBus, TestControl) {
        (TestBus, TestControl)
    }
}

pub struct TestBus;

impl Bus for TestBus {
    async fn enable(&mut self) {}
    async fn disable(&mut self) {}
    async fn poll(&mut self) -> Event {
        pending().await
    }
    fn endpoint_set_enabled(&mut self, _ep_addr: EndpointAddress, _enabled: bool) {}
    fn endpoint_set_stalled(&mut self, _ep_addr: EndpointAddress, _stalled: bool) {}
    fn endpoint_is_stalled(&mut self, _ep_addr: EndpointAddress) -> bool {
        false
    }
    async fn remote_wakeup(&mut self) -> Result<(), Unsupported> {
        Err(Unsupported)
    }
}

pub struct TestControl;

impl ControlPipe for TestControl {
    fn max_packet_size(&self) -> usize {
        64
    }
    async fn setup(&mut self) -> [u8; 8] {
        pending().await
    }
    async fn data_out(
        &mut self,
        _buf: &mut [u8],
        _first: bool,
        _last: bool,
    ) -> Result<usize, EndpointError> {
        Err(EndpointError::Disabled)
    }
    async fn data_in(
        &mut self,
        _data: &[u8],
        _first: bool,
        _last: bool,
    ) -> Result<(), EndpointError> {
        Err(EndpointError::Disabled)
    }
    async fn accept(&mut self) {}
    async fn reject(&mut self) {}
    async fn accept_set_address(&mut self, _addr: u8) {}
}

pub fn drain_ready(future: impl Future) {
    let mut future = core::pin::pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(future.as_mut().poll(&mut cx).is_pending());
}
