// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use std::sync::mpsc;
use std::time::Duration;

/// Run `f` on its own thread and fail rather than hang if it does not finish.
///
/// Every failure this file is about is a *sleep that never ends*, so a plain
/// assertion would wedge the test run instead of reporting anything.
fn within<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || tx.send(f()));
    rx.recv_timeout(Duration::from_secs(5))
        .expect("block_on never returned — a wake was lost")
}

#[test]
fn a_ready_future_returns_at_once() {
    assert_eq!(within(|| block_on(std::future::ready(7))), 7);
}

/// The whole point: a future that parks must be woken back up, from wherever the
/// wake comes from — here another thread, as the USB/IP socket wakes an endpoint.
#[test]
fn a_wake_from_another_thread_ends_the_sleep() {
    let value = within(|| {
        let flag = Arc::new(Mutex::new(false));
        let f = flag.clone();
        block_on(std::future::poll_fn(move |cx| {
            if *f.lock().unwrap() {
                return Poll::Ready(9);
            }
            let waker = cx.waker().clone();
            let f = f.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                *f.lock().unwrap() = true;
                waker.wake();
            });
            Poll::Pending
        }))
    });
    assert_eq!(value, 9);
}

/// A wake that lands *during* the poll — the common case, since a future usually
/// arms whatever will wake it while it is being polled — must not fall into the
/// gap between polling and sleeping. Arming after the poll instead of before it
/// loses exactly this one, and the loop then sleeps forever.
#[test]
fn a_wake_during_the_poll_is_not_lost() {
    let value = within(|| {
        let mut first = true;
        block_on(std::future::poll_fn(move |cx| {
            if !first {
                return Poll::Ready(4);
            }
            first = false;
            cx.waker().wake_by_ref();
            Poll::Pending
        }))
    });
    assert_eq!(value, 4);
}

/// A `Timer` is the other half of what the emulator awaits, and it is woken by
/// embassy-time's own alarm thread rather than by anything here.
#[test]
fn an_embassy_timer_still_fires() {
    within(|| block_on(embassy_time::Timer::after_millis(30)));
}
