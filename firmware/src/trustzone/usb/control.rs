// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::{Pipe, abi, observe, outcome, serialized, with_controller};
use core::{
    cell::RefCell,
    future::{Future, poll_fn},
    pin::pin,
    task::Poll,
};
use embassy_executor::InterruptExecutor;
use embassy_rp::interrupt::{self, InterruptExt, Priority};
use embassy_sync::{
    blocking_mutex::{Mutex, raw::CriticalSectionRawMutex},
    signal::Signal,
    waitqueue::AtomicWaker,
};
use embassy_usb::driver::ControlPipe as _;
use rsk_device::transport_session::{Job, Poll as SessionPoll, Session};
use rsk_usb::worker_abi::{ABANDONED, INVALID, PENDING};

pub(super) fn init() {
    interrupt::SWI_IRQ_2.set_priority(Priority::P1);
    EXECUTOR.start(interrupt::SWI_IRQ_2);
}
pub(super) fn start(pipe: Pipe) -> bool {
    let Ok(task) = control_task(SendPipe(pipe)) else {
        return false;
    };
    EXECUTOR.spawner().spawn(task);
    true
}
pub(super) fn reset() {
    with_command(|command| command.session.reset());
    wake_control();
}
pub(super) fn new_setup() {
    with_command(|command| {
        if command.operation & 0xff != abi::CTRL_SETUP {
            command.session.reset();
        }
    });
    wake_control();
}
pub(super) fn abandon(ticket: u32) {
    with_command(|command| command.session.abandon(ticket));
    wake_control();
}

struct Command {
    session: Session,
    operation: u32,
    length: usize,
    packet: [u8; abi::PACKET_SIZE],
    result: u32,
}
static COMMAND: Mutex<CriticalSectionRawMutex, RefCell<Command>> =
    Mutex::new(RefCell::new(Command {
        session: Session::with_ticket_limit(abi::OVERFLOW),
        operation: 0,
        length: 0,
        packet: [0; abi::PACKET_SIZE],
        result: 0,
    }));
static COMMAND_READY: Signal<CriticalSectionRawMutex, ()> = Signal::new();
static COMMAND_WAKER: AtomicWaker = AtomicWaker::new();
static EXECUTOR: InterruptExecutor = InterruptExecutor::new();

fn wake_control() {
    COMMAND_READY.signal(());
    COMMAND_WAKER.wake();
}

fn with_command<T>(f: impl FnOnce(&mut Command) -> T) -> T {
    COMMAND.lock(|cell| f(&mut cell.borrow_mut()))
}

#[embassy_rp::interrupt]
fn SWI_IRQ_2() {
    // SAFETY: startup binds this Secure interrupt to the controller executor once.
    unsafe {
        EXECUTOR.on_interrupt();
    }
}

pub(super) fn queue(operation: u32, input: &[u8]) -> u32 {
    let action = operation & 0xff;
    let valid = match action {
        abi::CTRL_SETUP | abi::CTRL_ACCEPT | abi::CTRL_REJECT => {
            input.is_empty() && operation == action
        }
        abi::CTRL_IN => operation & !(0xff | abi::FIRST | abi::LAST) == 0,
        abi::CTRL_OUT => {
            matches!(input, [capacity] if usize::from(*capacity) <= abi::PACKET_SIZE)
                && operation & !(0xff | abi::FIRST | abi::LAST) == 0
        }
        abi::CTRL_ADDRESS => input.is_empty() && operation & !0x7fff == 0,
        _ => false,
    };
    if !valid {
        return INVALID;
    }
    with_command(|command| {
        let Some(ticket) = command.session.submit() else {
            return PENDING;
        };
        command.operation = operation;
        command.length = input.len();
        let Some(buffer) = command.packet.get_mut(..input.len()) else {
            return INVALID;
        };
        buffer.copy_from_slice(input);
        wake_control();
        ticket
    })
}

fn scrub_command(command: &mut Command) {
    use zeroize::Zeroize;
    let Command {
        session: _session,
        operation,
        length,
        packet,
        result,
    } = command;
    #[expect(
        clippy::disallowed_methods,
        reason = "the static control packet is wiped at completion, abandonment and reset"
    )]
    packet.zeroize();
    *operation = 0;
    *length = 0;
    *result = 0;
}

struct SendPipe(Pipe);
// SAFETY: ownership moves once to the Secure controller executor on core0.
unsafe impl Send for SendPipe {}

#[embassy_executor::task]
async fn control_task(mut pipe: SendPipe) {
    loop {
        let job = with_command(|command| command.session.next_job());
        match job {
            Some(Job::Discard(ticket)) => with_command(|command| {
                scrub_command(command);
                command.session.release(ticket);
            }),
            Some(Job::Reset) => with_command(|command| {
                scrub_command(command);
                command.session.reset_complete();
            }),
            Some(Job::Dispatch(ticket)) => {
                let mut packet = [0; abi::PACKET_SIZE];
                let mut packet = rsk_secret::WipeGuard::new(&mut packet);
                let (operation, length) = with_command(|command| {
                    packet.copy_from_slice(&command.packet);
                    (command.operation, command.length)
                });
                let mut reply_len = 0;
                let result = {
                    let future = async {
                        match operation & 0xff {
                            abi::CTRL_SETUP => {
                                let setup = pipe.0.setup().await;
                                let Some(output) = packet.get_mut(..8) else {
                                    return INVALID;
                                };
                                output.copy_from_slice(&setup);
                                reply_len = 8;
                                8
                            }
                            abi::CTRL_IN => {
                                let Some(input) = packet.get(..length) else {
                                    return INVALID;
                                };
                                outcome(Poll::Ready(
                                    pipe.0
                                        .data_in(
                                            input,
                                            operation & abi::FIRST != 0,
                                            operation & abi::LAST != 0,
                                        )
                                        .await
                                        .map(|()| 0),
                                ))
                            }
                            abi::CTRL_OUT => {
                                let Some(capacity) = packet.first().copied() else {
                                    return INVALID;
                                };
                                let Some(output) = packet.get_mut(..usize::from(capacity)) else {
                                    return INVALID;
                                };
                                let result = pipe
                                    .0
                                    .data_out(
                                        output,
                                        operation & abi::FIRST != 0,
                                        operation & abi::LAST != 0,
                                    )
                                    .await;
                                if let Ok(length) = result {
                                    reply_len = length;
                                }
                                outcome(Poll::Ready(result))
                            }
                            abi::CTRL_ACCEPT => {
                                pipe.0.accept().await;
                                0
                            }
                            abi::CTRL_REJECT => {
                                pipe.0.reject().await;
                                0
                            }
                            abi::CTRL_ADDRESS => {
                                let Ok(address) = u8::try_from(operation >> abi::ADDRESS_SHIFT)
                                else {
                                    return INVALID;
                                };
                                pipe.0.accept_set_address(address).await;
                                0
                            }
                            _ => INVALID,
                        }
                    };
                    let mut future = pin!(future);
                    poll_fn(|cx| {
                        serialized(|| {
                            observe();
                            COMMAND_WAKER.register(cx.waker());
                            if with_command(|command| command.session.poll(ticket))
                                != SessionPoll::Pending
                            {
                                return Poll::Ready(ABANDONED);
                            }
                            with_controller(|state| {
                                if state.configuration.arm(ticket) {
                                    rp_pac::USB
                                        .buff_status()
                                        .write(|value| value.set_ep_in(0, true));
                                }
                            });
                            let value = future.as_mut().poll(cx);
                            observe();
                            if with_command(|command| command.session.poll(ticket))
                                != SessionPoll::Pending
                            {
                                Poll::Ready(ABANDONED)
                            } else {
                                value
                            }
                        })
                    })
                    .await
                };
                serialized(|| {
                    observe();
                    if result != ABANDONED && operation & 0xff == abi::CTRL_SETUP {
                        with_controller(|state| state.setup_seen = false);
                    }
                    with_command(|command| {
                        if command.session.finish(ticket) {
                            scrub_command(command);
                            command.packet.copy_from_slice(&packet);
                            command.length = reply_len;
                            command.result = result;
                        }
                    });
                });
            }
            None => COMMAND_READY.wait().await,
        }
    }
}

pub(super) fn poll(ticket: u32, data: &mut [u8]) -> u32 {
    with_command(|command| match command.session.poll(ticket) {
        SessionPoll::Pending => PENDING,
        SessionPoll::Abandoned => abi::DISABLED,
        SessionPoll::Ready => {
            if command.length > data.len() {
                return abi::OVERFLOW;
            }
            let Some(output) = data.get_mut(..command.length) else {
                return INVALID;
            };
            let Some(input) = command.packet.get(..command.length) else {
                return INVALID;
            };
            output.copy_from_slice(input);
            let result = command.result;
            scrub_command(command);
            command.session.release(ticket);
            result
        }
    })
}
