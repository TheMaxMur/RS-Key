// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use core::cell::RefCell;
use core::task::Waker;
use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};
use embassy_time_driver::Driver;
use embassy_time_queue_utils::Queue;

struct Time {
    queue: Mutex<CriticalSectionRawMutex, RefCell<Queue>>,
}

embassy_time_driver::time_driver_impl!(static DRIVER: Time = Time {
    queue: Mutex::new(RefCell::new(Queue::new()))
});

impl Driver for Time {
    fn now(&self) -> u64 {
        loop {
            let hi = rp_pac::TIMER1.timerawh().read();
            let lo = rp_pac::TIMER1.timerawl().read();
            if hi == rp_pac::TIMER1.timerawh().read() {
                return (u64::from(hi) << 32) | u64::from(lo);
            }
        }
    }

    fn schedule_wake(&self, at: u64, waker: &Waker) {
        self.queue.lock(|queue| {
            let mut queue = queue.borrow_mut();
            queue.schedule_wake(at, waker);
            arm(&mut queue);
        });
    }
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "the hardware comparator is the low timer word; the now check handles wrap"
)]
fn arm(queue: &mut Queue) {
    loop {
        let at = queue.next_expiration(DRIVER.now());
        rp_pac::TIMER1.alarm(0).write_value(at as u32);
        if at > DRIVER.now() {
            break;
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn TIMER1_IRQ_0() {
    rp_pac::TIMER1.intr().write(|v| v.set_alarm(0, true));
    DRIVER.queue.lock(|queue| arm(&mut queue.borrow_mut()));
}

pub fn init() {
    use embassy_rp::interrupt::InterruptExt;
    rp_pac::TIMER1.inte().write(|v| v.set_alarm(0, true));
    // SAFETY: the handler above services Non-secure TIMER1, configured by Secure boot.
    unsafe {
        embassy_rp::interrupt::TIMER1_IRQ_0.enable();
    }
}
