// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use core::sync::atomic::{AtomicU32, Ordering};

include!(concat!(env!("OUT_DIR"), "/probe_address.rs"));

#[unsafe(no_mangle)]
static RSK_NS_PROBE_PROGRESS: AtomicU32 = AtomicU32::new(0);

pub fn enabled() -> bool {
    RSK_NS_PROBE_PROGRESS.load(Ordering::Acquire) == 0
}

pub fn run() -> ! {
    RSK_NS_PROBE_PROGRESS.store(1, Ordering::Release);
    // SAFETY: this disposable hostile image disables its own MPU and deliberately probes denied MMIO/RAM.
    unsafe {
        (0xe000_ed94 as *mut u32).write_volatile(0);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        let _ = (PROBE_ADDRESS as *const u32).read_volatile();
    }
    RSK_NS_PROBE_PROGRESS.store(2, Ordering::Release);
    loop {
        cortex_m::asm::wfi();
    }
}
