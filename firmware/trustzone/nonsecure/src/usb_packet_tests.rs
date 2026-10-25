// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use std::{
    cell::RefCell,
    collections::VecDeque,
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointError {
    Disabled,
    BufferOverflow,
}
#[derive(Clone, Copy)]
pub struct EndpointAddress(pub u8);
impl From<EndpointAddress> for u8 {
    fn from(value: EndpointAddress) -> u8 {
        value.0
    }
}
pub struct EndpointInfo {
    pub addr: EndpointAddress,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Event {
    Construct,
    Wipe(Vec<u8>, Vec<u8>),
    Sg(u32, u32, Vec<u8>),
}
struct Response {
    operation: u32,
    argument: u32,
    result: u32,
}
#[derive(Default)]
struct Model {
    responses: VecDeque<Response>,
    events: Vec<Event>,
    generation: u32,
}
thread_local! { static MODEL: RefCell<Model> = RefCell::new(Model::default()); }

pub fn constructed(bytes: &mut [u8]) {
    assert_eq!(bytes.len(), abi::PACKET_SIZE);
    assert!(
        bytes.iter().all(|byte| *byte == 0),
        "the complete packet must start initialized"
    );
    // Dirty the unused tail too, so a prefix-only cleanup cannot pass.
    bytes.fill(0xa5);
    MODEL.with(|model| model.borrow_mut().events.push(Event::Construct));
}
pub fn wiped(before: Vec<u8>, after: Vec<u8>) {
    MODEL.with(|model| model.borrow_mut().events.push(Event::Wipe(before, after)));
}
pub fn generation() -> u32 {
    MODEL.with(|model| model.borrow().generation)
}
pub async fn wait(observed: u32) {
    std::future::poll_fn(|_| {
        if generation() != observed {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await
}
pub fn transfer(operation: u32, argument: u32, buffer: &mut [u8]) -> u32 {
    MODEL.with(|model| {
        let mut model = model.borrow_mut();
        model
            .events
            .push(Event::Sg(operation, argument, buffer.to_vec()));
        let expected = model.responses.pop_front().expect("unexpected SG");
        assert_eq!(
            (operation, argument),
            (expected.operation, expected.argument),
            "SG selector, epoch or ticket changed"
        );
        expected.result
    })
}
fn response(operation: u32, argument: u32, result: u32) -> Response {
    Response {
        operation,
        argument,
        result,
    }
}
const EPOCH: u32 = 41;
const TICKET: u32 = 7;
const ADDRESS: u8 = 0x83;
const WRITE: u32 = abi::EP_WRITE | ((ADDRESS as u32) << abi::ADDRESS_SHIFT);
const CONTROL: u32 = abi::CTRL_IN | abi::FIRST | abi::LAST;
#[derive(Clone, Copy)]
enum Action {
    Pending,
    Ready(Result<(), EndpointError>),
    Advance,
    Rebind,
}

fn run(control: bool, length: usize, responses: Vec<Response>, actions: &[Action]) -> Vec<Event> {
    MODEL.with(|model| {
        *model.borrow_mut() = Model {
            responses: responses.into(),
            ..Model::default()
        }
    });
    usb::bind_response_epoch(usb::Transport::Ccid, EPOCH);
    let data = vec![0x69; length];
    let mut endpoint = usb::Endpoint {
        info: EndpointInfo {
            addr: EndpointAddress(ADDRESS),
        },
        transport: usb::Transport::Ccid,
    };
    let mut pipe = usb::ControlPipe;
    let mut future: Pin<Box<dyn Future<Output = Result<(), EndpointError>> + '_>> = if control {
        Box::pin(pipe.data_in(&data, true, true))
    } else {
        Box::pin(endpoint.write(&data))
    };
    let mut context = Context::from_waker(Waker::noop());
    for action in actions {
        match *action {
            Action::Pending => assert_eq!(future.as_mut().poll(&mut context), Poll::Pending),
            Action::Ready(expected) => {
                assert_eq!(future.as_mut().poll(&mut context), Poll::Ready(expected))
            }
            Action::Advance => MODEL.with(|model| model.borrow_mut().generation += 1),
            Action::Rebind => usb::bind_response_epoch(usb::Transport::Ccid, EPOCH + 1),
        }
    }
    drop(future);
    MODEL.with(|model| {
        let model = model.borrow();
        assert!(model.responses.is_empty(), "expected SG never executed");
        model.events.clone()
    })
}
fn full_wipe(events: &[Event]) {
    let wipes: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            Event::Wipe(before, after) => Some((before, after)),
            _ => None,
        })
        .collect();
    assert_eq!(
        wipes.len(),
        1,
        "the caller must drop its complete packet guard"
    );
    assert_eq!(wipes[0].0.len(), abi::PACKET_SIZE);
    assert_eq!(
        wipes[0].1,
        &vec![0; abi::PACKET_SIZE],
        "the complete live span must be cleared"
    );
}
fn abandon_before_wipe(events: &[Event]) {
    let abandon = events
        .iter()
        .position(|event| {
            matches!(event, Event::Sg(op, arg, _)
        if *op == abi::CTRL_ABANDON && *arg == TICKET)
        })
        .expect("queued control must abandon");
    let wipe = events
        .iter()
        .position(|event| matches!(event, Event::Wipe(..)))
        .expect("guard must wipe");
    assert!(abandon < wipe, "CTRL_ABANDON must precede packet cleanup");
}
fn dirty_tail(events: &[Event]) {
    let before = events
        .iter()
        .find_map(|event| match event {
            Event::Wipe(before, _) => Some(before),
            _ => None,
        })
        .unwrap();
    assert_eq!(&before[1..], &[0xa5; abi::PACKET_SIZE - 1]);
}

#[test]
fn endpoint_results_keep_snapshot_and_full_wipe() {
    for length in [0, 1, 31, 63, 64] {
        for (result, expected) in [
            (0, Ok(())),
            (abi::OVERFLOW, Err(EndpointError::BufferOverflow)),
            (INVALID, Err(EndpointError::Disabled)),
        ] {
            let events = run(
                false,
                length,
                vec![response(WRITE, EPOCH, result)],
                &[Action::Ready(expected)],
            );
            full_wipe(&events);
            assert!(events.contains(&Event::Sg(WRITE, EPOCH, vec![0x69; length])));
        }
    }
}
#[test]
fn oversized_packets_wipe_without_sg() {
    for control in [false, true] {
        let events = run(
            control,
            abi::PACKET_SIZE + 1,
            vec![],
            &[Action::Ready(Err(EndpointError::BufferOverflow))],
        );
        full_wipe(&events);
        assert!(!events.iter().any(|event| matches!(event, Event::Sg(..))));
    }
}
#[test]
fn endpoint_cancellation_and_reset_keep_full_wipe_and_bound_epoch() {
    let events = run(
        false,
        1,
        vec![response(WRITE, EPOCH, PENDING)],
        &[Action::Pending],
    );
    full_wipe(&events);
    dirty_tail(&events);
    let responses = vec![
        response(WRITE, EPOCH, PENDING),
        response(WRITE, EPOCH, abi::DISABLED),
        response(abi::EPOCH, 0, EPOCH + 1),
    ];
    full_wipe(&run(
        false,
        1,
        responses,
        &[
            Action::Pending,
            Action::Rebind,
            Action::Advance,
            Action::Ready(Err(EndpointError::Disabled)),
        ],
    ));
}
#[test]
fn endpoint_disabled_in_same_epoch_retries() {
    for first in [PENDING, abi::DISABLED] {
        let mut responses = vec![response(WRITE, EPOCH, first)];
        if first == abi::DISABLED {
            responses.push(response(abi::EPOCH, 0, EPOCH));
        }
        responses.push(response(WRITE, EPOCH, 1));
        full_wipe(&run(
            false,
            1,
            responses,
            &[Action::Pending, Action::Advance, Action::Ready(Ok(()))],
        ));
    }
}
#[test]
fn control_results_and_cancellation_abandon_before_wipe() {
    for (result, actions) in [
        (0, vec![Action::Ready(Ok(()))]),
        (
            abi::OVERFLOW,
            vec![Action::Ready(Err(EndpointError::BufferOverflow))],
        ),
        (
            abi::DISABLED,
            vec![Action::Ready(Err(EndpointError::Disabled))],
        ),
        (INVALID, vec![Action::Ready(Err(EndpointError::Disabled))]),
        (PENDING, vec![Action::Pending]),
    ] {
        let responses = vec![
            response(abi::EPOCH, 0, EPOCH),
            response(CONTROL, EPOCH, TICKET),
            response(abi::CTRL_POLL, TICKET, result),
            response(abi::CTRL_ABANDON, TICKET, 0),
        ];
        let events = run(true, 1, responses, &actions);
        assert!(events.contains(&Event::Sg(CONTROL, EPOCH, vec![0x69])));
        full_wipe(&events);
        dirty_tail(&events);
        abandon_before_wipe(&events);
    }
}
#[test]
fn control_before_ticket_cancellation_and_errors() {
    for (result, action) in [
        (PENDING, Action::Pending),
        (INVALID, Action::Ready(Err(EndpointError::Disabled))),
        (abi::DISABLED, Action::Ready(Err(EndpointError::Disabled))),
    ] {
        let events = run(
            true,
            1,
            vec![
                response(abi::EPOCH, 0, EPOCH),
                response(CONTROL, EPOCH, result),
            ],
            &[action],
        );
        full_wipe(&events);
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::Sg(op, _, _) if *op == abi::CTRL_ABANDON))
        );
    }
}
#[test]
fn control_queue_and_poll_retries_keep_epoch_and_ticket() {
    let responses = vec![
        response(abi::EPOCH, 0, EPOCH),
        response(CONTROL, EPOCH, PENDING),
        response(CONTROL, EPOCH, TICKET),
        response(abi::CTRL_POLL, TICKET, PENDING),
        response(abi::CTRL_POLL, TICKET, 0),
        response(abi::CTRL_ABANDON, TICKET, 0),
    ];
    let events = run(
        true,
        abi::PACKET_SIZE,
        responses,
        &[
            Action::Pending,
            Action::Advance,
            Action::Pending,
            Action::Advance,
            Action::Ready(Ok(())),
        ],
    );
    full_wipe(&events);
    abandon_before_wipe(&events);
}
#[test]
fn unpolled_futures_have_no_packet_or_sg() {
    for control in [false, true] {
        assert!(run(control, abi::PACKET_SIZE, vec![], &[]).is_empty());
    }
}
