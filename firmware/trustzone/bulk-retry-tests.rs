// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors
#![allow(
    dead_code,
    reason = "the included production APIs retain unused items in this focused fixture"
)]
extern crate self as embassy_usb;
extern crate self as rsk_usb;
use driver::{EndpointAddress, EndpointType};
pub use embassy_usb_driver as driver;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
};
#[path = "../../crates/rsk-usb/src/bulk_retry.rs"]
mod bulk_retry;
#[path = "../../crates/rsk-usb/src/usb_abi.rs"]
mod usb_abi;
#[path = "../../crates/rsk-usb/src/worker_abi.rs"]
mod worker_abi;
use usb_abi as abi;
use worker_abi::{INVALID, PENDING};
#[path = "../src/sweep/buffer.rs"]
mod sweep;
#[path = "../../crates/rsk-device/src/usb_epoch.rs"]
mod usb_epoch;
use usb_epoch::{BusEpoch, Revocation};

#[derive(Clone, Copy)]
enum Observation {
    Quiet,
    Setup,
    Reset,
    Resume,
    Fault,
}
#[derive(Clone, Debug, PartialEq)]
enum Event {
    Lock,
    Observe,
    Endpoint,
    Wipe(bool),
    Unlock,
    Notify { locked: bool, wiped: bool },
}
#[derive(Default)]
struct Model {
    observations: VecDeque<Observation>,
    results: VecDeque<u32>,
    events: Vec<Event>,
    endpoint_calls: usize,
    commits: usize,
    endpoint_us: u32,
    bad_packet: bool,
}
struct EndpointInfo {
    ep_type: EndpointType,
}
struct Endpoint(EndpointInfo);
impl Endpoint {
    fn info(&self) -> &EndpointInfo {
        &self.0
    }
}
struct Controller {
    bus_epoch: BusEpoch,
    input: [Option<Endpoint>; endpoints::ENDPOINTS],
    bulk_retiring: u16,
    bulk_zlp: u16,
}
fn controller() -> Controller {
    let mut state = Controller {
        bus_epoch: BusEpoch::new(),
        input: [const { None }; endpoints::ENDPOINTS],
        bulk_retiring: 0,
        bulk_zlp: 0,
    };
    state.bus_epoch.configure();
    state.input[2] = Some(Endpoint(EndpointInfo {
        ep_type: EndpointType::Bulk,
    }));
    state
}
thread_local! {
    static MODEL: RefCell<Model> = RefCell::new(Model::default());
    static CONTROLLER: RefCell<Controller> = RefCell::new(controller());
    static CLOCK: Cell<u32> = const { Cell::new(0) };
    static FAULT: Cell<bool> = const { Cell::new(false) };
    static LOCKED: Cell<bool> = const { Cell::new(false) };
}
fn record(event: Event) {
    MODEL.with_borrow_mut(|model| model.events.push(event));
}
fn with_controller<T>(f: impl FnOnce(&mut Controller) -> T) -> T {
    CONTROLLER.with_borrow_mut(f)
}
fn serialized<T>(f: impl FnOnce() -> T) -> T {
    LOCKED.set(true);
    record(Event::Lock);
    let result = f();
    LOCKED.set(false);
    record(Event::Unlock);
    result
}
fn observed_wipe(bytes: &[u8]) {
    record(Event::Wipe(
        bytes.len() == 64 && bytes.iter().all(|byte| *byte == 0),
    ));
}
fn notify_nonsecure() {
    let wiped =
        MODEL.with_borrow(|model| model.events.iter().any(|event| *event == Event::Wipe(true)));
    record(Event::Notify {
        locked: LOCKED.get(),
        wiped,
    });
}
fn rsk_tz_writable_impl(bytes: &mut [u8], len: u32) -> u32 {
    u32::from(usize::try_from(len).is_ok_and(|len| len <= bytes.len()))
}
fn rsk_tz_readable_impl(bytes: &[u8], len: u32) -> u32 {
    u32::from(usize::try_from(len).is_ok_and(|len| len <= bytes.len()))
}
mod fault {
    pub fn failed() -> bool {
        super::FAULT.get()
    }
}
mod rp_pac {
    pub struct Timer;
    pub const TIMER0: Timer = Timer;
    impl Timer {
        pub fn timerawl(&self) -> Self {
            Timer
        }
        pub fn read(&self) -> u32 {
            super::CLOCK.get()
        }
    }
}
fn observe_locked(state: &mut Controller) -> bool {
    record(Event::Observe);
    let observation =
        MODEL.with_borrow_mut(|model| model.observations.pop_front().unwrap_or(Observation::Quiet));
    match observation {
        Observation::Quiet => false,
        Observation::Setup => true,
        Observation::Reset => {
            state.bus_epoch.revoke(Revocation::Reset);
            true
        }
        Observation::Resume => {
            state.bus_epoch.resume();
            true
        }
        Observation::Fault => {
            FAULT.set(true);
            false
        }
    }
}
mod endpoints {
    use super::*;
    include!(env!("RSK_BULK_RETRY_ENDPOINT_SOURCE"));
    pub fn operate(state: &mut Controller, _: u32, data: &mut [u8]) -> u32 {
        record(Event::Endpoint);
        if !state.bus_epoch.accepts(state.bus_epoch.current()) {
            return abi::DISABLED;
        }
        MODEL.with_borrow_mut(|model| {
            model.endpoint_calls += 1;
            model.bad_packet |= data != [0xa5; 64];
            CLOCK.set(CLOCK.get().wrapping_add(model.endpoint_us));
            let result = model.results.pop_front().unwrap_or(PENDING);
            model.commits += usize::from(result == 0);
            result
        })
    }
}

mod secure {
    include!(env!("RSK_BULK_RETRY_SOURCE"));
}
#[cfg(test)]
#[path = "bulk_retry_tests.rs"]
mod integration;
