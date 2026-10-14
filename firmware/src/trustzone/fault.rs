// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use core::sync::atomic::{AtomicBool, Ordering};

static FAILED: AtomicBool = AtomicBool::new(false);

pub fn failed() -> bool {
    FAILED.load(Ordering::Acquire)
}

pub fn halt() -> ! {
    if !FAILED.swap(true, Ordering::AcqRel) {
        crate::trustzone::usb::disconnect_after_fault();
    }
    rsk_tz_fault_stop()
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn rsk_tz_fault_stop() -> ! {
    loop {
        cortex_m::asm::wfi();
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    halt()
}

// SAFETY: fatal exceptions never return or borrow interrupted worker/driver state.
#[cortex_m_rt::exception]
unsafe fn HardFault(_frame: &cortex_m_rt::ExceptionFrame) -> ! {
    halt()
}
