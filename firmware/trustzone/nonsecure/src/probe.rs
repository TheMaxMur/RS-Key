// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use core::sync::atomic::{AtomicU32, Ordering};

include!(concat!(env!("OUT_DIR"), "/probe_address.rs"));

// An allowed USBCTRL write leaves a distinct device address in the emulator log.
const PROBE_WRITE_VALUE: u32 = 0x7f;

#[unsafe(no_mangle)]
static RSK_NS_PROBE_PROGRESS: AtomicU32 = AtomicU32::new(0);
#[unsafe(no_mangle)]
static RSK_NS_PROBE_TARGET: AtomicU32 = AtomicU32::new(PROBE_ADDRESS);

#[embassy_executor::task]
pub async fn after_usb() {
    use rsk_usb::usb_abi;
    let mut marker = [0xa5; 8];
    loop {
        let epoch = super::usb::epoch();
        let operation = usb_abi::EP_WRITE | (0x81 << usb_abi::ADDRESS_SHIFT);
        if super::usb::transfer(operation, epoch, &mut marker) == 0 {
            break;
        }
        embassy_time::Timer::after_millis(1).await;
    }
    RSK_NS_PROBE_PROGRESS.store(1, Ordering::Release);
    while RSK_NS_PROBE_TARGET.load(Ordering::Acquire) == 0 {
        embassy_time::Timer::after_millis(1).await;
    }
    run();
}

#[inline(never)]
pub fn run() -> ! {
    RSK_NS_PROBE_PROGRESS.store(1, Ordering::Release);
    let address = loop {
        let address = RSK_NS_PROBE_TARGET.load(Ordering::Acquire);
        if address != 0 {
            break address;
        }
        core::hint::spin_loop();
    };
    // SAFETY: this disposable hostile image disables its own MPU and deliberately probes denied MMIO/RAM.
    unsafe {
        (0xe000_ed94 as *mut u32).write_volatile(0);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
        if PROBE_WRITE {
            core::arch::asm!(
                ".global RSK_NS_PROBE_ACCESS",
                ".set RSK_NS_PROBE_ACCESS, .",
                "str {value}, [{address}]",
                address = in(reg) address,
                value = inout(reg) PROBE_WRITE_VALUE => _,
                options(nostack, preserves_flags),
            );
        } else {
            core::arch::asm!(
                ".global RSK_NS_PROBE_ACCESS",
                ".set RSK_NS_PROBE_ACCESS, .",
                "ldr {value}, [{address}]",
                address = in(reg) address,
                value = out(reg) _,
                options(nostack, preserves_flags),
            );
        }
        cortex_m::asm::dsb();
    }
    RSK_NS_PROBE_PROGRESS.store(2, Ordering::Release);
    loop {
        cortex_m::asm::wfi();
    }
}
