// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `block_on`, asleep between wakes.
//!
//! `embassy_futures::block_on` re-polls in a tight loop and its waker does
//! nothing — right on a microcontroller with nothing else to do, and rude on a
//! laptop that is also running the browser this emulator exists to be talked to
//! by. Two of these threads idled at 200% CPU.
//!
//! Everything the emulator awaits registers a real waker — the USB/IP driver's
//! endpoints, and `embassy-time`'s std driver — so a condvar is all it takes to
//! idle properly. The only busy-waiting left is inside the display's synchronous
//! modals, which are running only while someone is holding a finger on the panel.

use std::future::Future;
use std::pin::pin;
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Context, Poll, Wake, Waker};

#[derive(Default)]
struct Signal {
    woken: Mutex<bool>,
    ready: Condvar,
}

impl Wake for Signal {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        *self.woken.lock().expect("signal mutex poisoned") = true;
        self.ready.notify_one();
    }
}

/// Drive `fut` to completion, sleeping whenever it has nothing to do.
pub fn block_on<F: Future>(fut: F) -> F::Output {
    let signal = Arc::new(Signal::default());
    let waker = Waker::from(signal.clone());
    let mut cx = Context::from_waker(&waker);
    let mut fut = pin!(fut);
    loop {
        // Armed BEFORE the poll, never after: a wake that lands *during* the poll
        // — which is most of them, since a future usually wakes itself from
        // whatever it registered with — would otherwise fall in the gap between
        // the two, and the sleep below would never end.
        *signal.woken.lock().expect("signal mutex poisoned") = false;
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
        let mut woken = signal.woken.lock().expect("signal mutex poisoned");
        while !*woken {
            woken = signal.ready.wait(woken).expect("signal mutex poisoned");
        }
    }
}

#[cfg(test)]
#[path = "park_tests.rs"]
mod tests;
