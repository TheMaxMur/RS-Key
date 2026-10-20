// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use core::{
    cell::RefCell,
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use embassy_rp::{
    interrupt::{self, InterruptExt, Priority, typelevel::Handler},
    peripherals::USB,
    usb::{self, In, Out},
};
use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};
use embassy_usb::driver::{Bus as _, Driver as _, Endpoint as _, EndpointError, Event};
use rsk_device::usb_epoch::{BusEpoch, BusEvents, Revocation};
use rsk_usb::{
    usb_abi as abi,
    worker_abi::{INVALID, PENDING},
};

mod bulk;
mod control;
mod endpoints;

type Driver = usb::Driver<'static, USB>;
type Bus = usb::Bus<'static, USB>;
type Pipe = usb::ControlPipe<'static, USB>;
type EndpointIn = usb::Endpoint<'static, USB, In>;
type EndpointOut = usb::Endpoint<'static, USB, Out>;
pub use crate::usb_fence::disconnect_after_fault;
use crate::usb_fence::{ENDPOINTS, clear_packets};

struct Packet64([u8; abi::PACKET_SIZE]);

impl zeroize::Zeroize for Packet64 {
    fn zeroize(&mut self) {
        let Self(bytes) = self;
        crate::sweep::wipe_bytes(bytes);
    }
}

struct Controller {
    driver: Option<Driver>,
    bus: Option<Bus>,
    input: [Option<EndpointIn>; ENDPOINTS],
    output: [Option<EndpointOut>; ENDPOINTS],
    bus_epoch: BusEpoch,
    configuration: rsk_device::usb_configuration::Configuration,
    bulk_zlp: u16,
    bulk_retiring: u16,
    events: u8,
    observer: BusEvents,
    setup_seen: bool,
    setup: [u8; 8],
}

static CONTROLLER: Mutex<CriticalSectionRawMutex, RefCell<Controller>> =
    Mutex::new(RefCell::new(Controller {
        driver: None,
        bus: None,
        input: [const { None }; ENDPOINTS],
        output: [const { None }; ENDPOINTS],
        bus_epoch: BusEpoch::new(),
        configuration: rsk_device::usb_configuration::Configuration::new(),
        bulk_zlp: 0,
        bulk_retiring: 0,
        events: 0,
        observer: BusEvents::new(),
        setup_seen: false,
        setup: [0; 8],
    }));

static IDENTITY: Mutex<CriticalSectionRawMutex, RefCell<Option<rsk_usb::identity::Identity>>> =
    Mutex::new(RefCell::new(None));

pub fn set_identity(identity: rsk_usb::identity::Identity) {
    IDENTITY.lock(|cell| *cell.borrow_mut() = Some(identity));
}

static SERIAL: Mutex<CriticalSectionRawMutex, ()> = Mutex::new(());

pub fn serialized<T>(f: impl FnOnce() -> T) -> T {
    SERIAL.lock(|_| f())
}

fn once<F: Future>(future: F) -> Poll<F::Output> {
    let mut future = pin!(future);
    future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
}

fn with_controller<T>(f: impl FnOnce(&mut Controller) -> T) -> T {
    CONTROLLER.lock(|cell| f(&mut cell.borrow_mut()))
}
pub struct InterruptHandler;
impl Handler<interrupt::typelevel::USBCTRL_IRQ> for InterruptHandler {
    unsafe fn on_interrupt() {
        observe();
        super::notify_nonsecure();
    }
}

pub fn init(usb: embassy_rp::Peri<'static, USB>) {
    interrupt::USBCTRL_IRQ.set_priority(Priority::P0);
    control::init();
    with_controller(|state| state.driver = Some(Driver::new(usb, crate::Irqs)));
}

fn revoke(state: &mut Controller, reason: Revocation) {
    state.bus_epoch.revoke(reason);
    state.configuration.reset();
    if reason == Revocation::Reset {
        state.setup_seen = false;
    }
    clear_packets();
    rp_pac::USB.ep_abort().write(|value| value.0 = 0);
    rp_pac::USB
        .ep_abort_done()
        .write(|value| value.0 = u32::MAX);
    state.bulk_zlp = 0;
    state.bulk_retiring = 0;
    crate::worker::revoke_transport();
    control::reset();
}

fn read_setup() -> [u8; 8] {
    let mut setup = [0; 8];
    let (low, high) = setup.split_at_mut(4);
    low.copy_from_slice(&rp_pac::USB_DPRAM.setup_packet_low().read().0.to_le_bytes());
    high.copy_from_slice(&rp_pac::USB_DPRAM.setup_packet_high().read().0.to_le_bytes());
    setup
}

fn observe_locked(state: &mut Controller) {
    if state.bus.is_none() {
        return;
    }
    let status = rp_pac::USB.sie_status().read();
    let fresh = state.observer.begin(status.bus_reset(), status.suspended());
    // A completed configuration survives suspend; a bus reset always wins.
    if !status.bus_reset()
        && rp_pac::USB.buff_status().read().ep_in(0)
        && state.configuration.acknowledge()
    {
        state.bus_epoch.configure();
    }
    if let Some(reason) = fresh {
        revoke(state, reason);
    }
    if status.setup_rec() {
        let setup = read_setup();
        if !state.setup_seen || setup != state.setup {
            state.configuration.reset();
            state.setup_seen = true;
            state.setup = setup;
            if setup == [0, 9, 0, 0, 0, 0, 0, 0] {
                revoke(state, Revocation::ConfigurationLoss);
            } else {
                control::new_setup();
            }
        }
    }
    for _ in 0..4 {
        let Some(bus) = state.bus.as_mut() else {
            break;
        };
        let Poll::Ready(event) = once(bus.poll()) else {
            break;
        };
        let code = match event {
            Event::PowerDetected => abi::POWER_DETECTED,
            Event::PowerRemoved => {
                revoke(state, Revocation::ConfigurationLoss);
                abi::POWER_REMOVED
            }
            Event::Reset => {
                if state.observer.observe_hal(Revocation::Reset) {
                    revoke(state, Revocation::Reset);
                }
                abi::RESET
            }
            Event::Suspend => {
                if state.observer.observe_hal(Revocation::Suspend) {
                    revoke(state, Revocation::Suspend);
                }
                abi::SUSPEND
            }
            Event::Resume => {
                state.bus_epoch.resume();
                for (index, endpoint) in state.output.iter().enumerate().skip(1) {
                    if let Some(endpoint) = endpoint
                        && rp_pac::USB_DPRAM.ep_out_control(index - 1).read().enable()
                    {
                        rp_pac::USB_DPRAM
                            .ep_out_buffer_control(index)
                            .modify(|v| v.set_length(0, endpoint.info().max_packet_size));
                        cortex_m::asm::delay(12);
                        rp_pac::USB_DPRAM
                            .ep_out_buffer_control(index)
                            .modify(|v| v.set_available(0, true));
                    }
                }
                abi::RESUME
            }
        };
        state.events |= 1 << code;
    }
    bulk::observe(state);
    let status = rp_pac::USB.sie_status().read();
    state
        .observer
        .finish(status.bus_reset(), status.suspended());
}

pub fn observe() {
    with_controller(observe_locked);
}
pub fn admitted() -> bool {
    if super::fault::failed() {
        return false;
    }
    with_controller(|state| {
        observe_locked(state);
        state.bus_epoch.accepts(state.bus_epoch.current())
    })
}

fn outcome(value: Poll<Result<usize, EndpointError>>) -> u32 {
    match value {
        Poll::Pending => PENDING,
        Poll::Ready(Ok(length)) => u32::try_from(length).unwrap_or(INVALID),
        Poll::Ready(Err(EndpointError::Disabled)) => abi::DISABLED,
        Poll::Ready(Err(EndpointError::BufferOverflow)) => abi::OVERFLOW,
    }
}

pub fn operate(operation: u32, argument: u32, data: &mut [u8]) -> u32 {
    with_controller(|state| {
        observe_locked(state);
        let action = operation & 0xff;
        if action == abi::EPOCH && operation == action && data.is_empty() {
            return state.bus_epoch.current();
        }
        if operation == abi::IDENTITY {
            return IDENTITY.lock(|cell| {
                let identity = cell.borrow();
                let Some(identity) = identity.as_ref() else {
                    return INVALID;
                };
                let Ok(offset) = usize::try_from(argument) else {
                    return INVALID;
                };
                let Some(end) = offset.checked_add(data.len()) else {
                    return INVALID;
                };
                let Some(source) = identity.bytes().get(offset..end) else {
                    return INVALID;
                };
                data.copy_from_slice(source);
                u32::try_from(data.len()).unwrap_or(INVALID)
            });
        }
        if matches!(action, abi::ALLOC_IN | abi::ALLOC_OUT) && operation == action {
            return endpoints::allocate(state, action == abi::ALLOC_IN, data);
        }
        if action == abi::START
            && operation == action
            && data.is_empty()
            && argument == u32::from(abi::PACKET_SIZE_U16)
        {
            let Some(driver) = state.driver.take() else {
                return INVALID;
            };
            let (bus, pipe) = driver.start(abi::PACKET_SIZE_U16);
            state.bus = Some(bus);
            if !control::start(pipe) {
                rp_pac::USB.sie_ctrl().modify(|v| v.set_pullup_en(false));
                state.bus = None;
                return INVALID;
            }
            return 0;
        }
        if action == abi::BUS_POLL && operation == action && data.is_empty() {
            for code in abi::POWER_DETECTED..=abi::RESUME {
                if state.events & (1 << code) != 0 {
                    state.events &= !(1 << code);
                    return code;
                }
            }
            return PENDING;
        }
        if action == abi::CTRL_ABANDON && operation == action && data.is_empty() {
            state.configuration.abandon(argument);
            control::abandon(argument);
            return 0;
        }
        if action == abi::CTRL_POLL && operation == action {
            return control::poll(argument, data);
        }

        if argument != state.bus_epoch.current() || state.bus_epoch.exhausted() {
            return abi::DISABLED;
        }
        if matches!(action, abi::CTRL_SETUP..=abi::CTRL_ADDRESS) {
            let ticket = control::queue(operation, data);
            if operation == abi::CTRL_ACCEPT
                && state.setup == [0, 9, 1, 0, 0, 0, 0, 0]
                && ticket < abi::OVERFLOW
            {
                state.configuration.queue(ticket);
            }
            return ticket;
        }
        if matches!(action, abi::BUS_ENABLE | abi::BUS_DISABLE)
            && operation == action
            && data.is_empty()
        {
            if action == abi::BUS_DISABLE {
                revoke(state, Revocation::ConfigurationLoss);
            }
            return 0;
        }
        if operation & !(0xffff | abi::FLAG) != 0 {
            return INVALID;
        }
        let value = endpoints::operate(state, operation, data);
        observe_locked(state);
        if argument != state.bus_epoch.current() {
            abi::DISABLED
        } else {
            value
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rsk_tz_usb_impl(
    operation: u32,
    argument: u32,
    buffer: *mut u8,
    length: u32,
) -> u32 {
    if super::fault::failed() {
        return INVALID;
    }
    let supplied_length = length;
    let Ok(length) = usize::try_from(length) else {
        return INVALID;
    };
    if length > abi::PACKET_SIZE {
        return INVALID;
    }
    let action = operation & 0xff;
    let input = matches!(
        action,
        abi::ALLOC_IN | abi::ALLOC_OUT | abi::EP_WRITE | abi::CTRL_IN | abi::CTRL_OUT
    );
    let output = matches!(action, abi::EP_READ | abi::CTRL_POLL | abi::IDENTITY);
    if !input && !output && length != 0 {
        return INVALID;
    }
    if length != 0 {
        let valid = if output {
            super::rsk_tz_writable_impl(buffer, supplied_length)
        } else {
            super::rsk_tz_readable_impl(buffer.cast_const(), supplied_length)
        };
        if valid == 0 {
            return INVALID;
        }
    }
    let result = serialized(|| {
        let mut packet = rsk_secret::Secret::new(Packet64([0; abi::PACKET_SIZE]));
        let Some(data) = packet.expose_mut().0.get_mut(..length) else {
            return INVALID;
        };
        if input && length != 0 {
            // SAFETY: the TT span check above validated this bounded NS RAM input.
            let source = unsafe { core::slice::from_raw_parts(buffer.cast_const(), length) };
            data.copy_from_slice(source);
        }
        let result = operate(operation, argument, data);
        if output && result <= supplied_length && result != 0 {
            let Ok(count) = usize::try_from(result) else {
                return INVALID;
            };
            let Some(source) = data.get(..count) else {
                return INVALID;
            };
            // SAFETY: CMSE checked the complete NS RAM output span; only the successful packet is copied.
            let target = unsafe { core::slice::from_raw_parts_mut(buffer, count) };
            target.copy_from_slice(source);
        }
        result
    });
    if result == 0
        && matches!(
            operation & 0xff,
            abi::EP_ENABLE | abi::EP_STALL | abi::BUS_DISABLE
        )
    {
        super::notify_nonsecure();
    }
    result
}
