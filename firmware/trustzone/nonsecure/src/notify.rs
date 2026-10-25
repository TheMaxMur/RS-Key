// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use core::sync::atomic::{AtomicU32, Ordering};
use core::{cell::RefCell, future::Future, future::poll_fn, pin::pin, task::Poll};
use embassy_rp::interrupt::{self, InterruptExt, Priority};
use embassy_sync::{
    blocking_mutex::{Mutex, raw::CriticalSectionRawMutex},
    waitqueue::MultiWakerRegistration,
};
use embassy_time::Timer;

const WAITERS: usize = 8;
const FALLBACK_POLL_MS: u64 = 16;
static GENERATION: AtomicU32 = AtomicU32::new(0);
static WAKERS: Mutex<CriticalSectionRawMutex, RefCell<MultiWakerRegistration<WAITERS>>> =
    Mutex::new(RefCell::new(MultiWakerRegistration::new()));

pub fn init() {
    interrupt::SWI_IRQ_4.set_priority(Priority::P2);
    interrupt::SWI_IRQ_4.unpend();
    // SAFETY: NS startup has initialized the local state and installed this vector.
    unsafe { interrupt::SWI_IRQ_4.enable() }
}

pub fn generation() -> u32 {
    GENERATION.load(Ordering::Acquire)
}

pub async fn wait(observed: u32) {
    let mut timeout = pin!(Timer::after_millis(FALLBACK_POLL_MS));
    poll_fn(|cx| {
        WAKERS.lock(|wakers| wakers.borrow_mut().register(cx.waker()));
        if generation() != observed {
            Poll::Ready(())
        } else {
            timeout.as_mut().poll(cx)
        }
    })
    .await;
}

#[unsafe(no_mangle)]
extern "C" fn SWI_IRQ_4() {
    GENERATION.fetch_add(1, Ordering::AcqRel);
    WAKERS.lock(|wakers| wakers.borrow_mut().wake());
}
