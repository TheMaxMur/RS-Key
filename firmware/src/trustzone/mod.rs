// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

pub mod usb;

use cortex_m::peripheral::sau::{SauRegion, SauRegionAttribute};
use embassy_executor::InterruptExecutor;
use embassy_rp::interrupt;
use embassy_rp::interrupt::{InterruptExt, Priority};

#[unsafe(no_mangle)]
pub extern "C" fn rsk_tz_readable_impl(ptr: *const u8, len: u32) -> u32 {
    use cortex_m::cmse::{AccessType, TestTarget};
    if !data_span(ptr as usize, len) {
        return 0;
    }
    let Ok(len) = usize::try_from(len) else {
        return 0;
    };
    u32::from(
        TestTarget::check_range(ptr.cast_mut().cast(), len, AccessType::Current)
            .is_some_and(|t| !t.secure() && t.ns_readable()),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn rsk_tz_writable_impl(ptr: *mut u8, len: u32) -> u32 {
    use cortex_m::cmse::{AccessType, TestTarget};
    if !data_span(ptr as usize, len) {
        return 0;
    }
    let Ok(len) = usize::try_from(len) else {
        return 0;
    };
    u32::from(
        TestTarget::check_range(ptr.cast(), len, AccessType::Current)
            .is_some_and(|t| !t.secure() && t.ns_read_and_writable()),
    )
}

const NS_FLASH: u32 = 0x1020_0000;
const NS_RAM: u32 = 0x2007_0000;
const NSC_FLASH: u32 = 0x101f_f000;
const NS_RAM_END: usize = 0x2008_0000;

fn data_span(address: usize, length: u32) -> bool {
    let Ok(length) = usize::try_from(length) else {
        return false;
    };
    address >= NS_RAM as usize
        && length != 0
        && address
            .checked_add(length)
            .is_some_and(|end| end <= NS_RAM_END)
}
static EXECUTOR: InterruptExecutor = InterruptExecutor::new();

struct SendWorker(&'static mut crate::worker::Worker<'static>);
// SAFETY: ownership moves once to core0's Secure executor; boot no longer accesses its RefCells.
unsafe impl Send for SendWorker {}

#[embassy_executor::task]
async fn run(worker: SendWorker) {
    worker.0.run().await;
}

pub fn start_worker(worker: &'static mut crate::worker::Worker<'static>) {
    embassy_rp::interrupt::SWI_IRQ_0.set_priority(Priority::P3);
    EXECUTOR
        .start(embassy_rp::interrupt::SWI_IRQ_0)
        .spawn(run(SendWorker(worker)).unwrap());
}

#[embassy_rp::interrupt]
fn SWI_IRQ_0() {
    // SAFETY: the executor was bound to this Secure interrupt at startup.
    unsafe { EXECUTOR.on_interrupt() }
}

#[embassy_executor::task]
pub async fn launch() {
    // Reclaim main's initialization frame before the worker can do crypto.
    embassy_time::Timer::after_millis(1).await;
    // SAFETY: runs once after storage and the Secure worker are initialized.
    unsafe { launch_nonsecure() }
}

unsafe fn launch_nonsecure() -> ! {
    // SAFETY: startup owns the security attribution and interrupt routing.
    let mut core = unsafe { cortex_m::Peripherals::steal() };
    // Embassy configures TIMER0's tick source; the NS queue owns TIMER1.
    rp_pac::TICKS
        .timer1_cycles()
        .write(|v| v.0 = rp_pac::TICKS.timer0_cycles().read().0);
    rp_pac::TICKS.timer1_ctrl().write(|v| v.set_enable(true));
    // SAFETY: clear inherited bootrom regions before assigning the prototype map.
    unsafe {
        (0xe000_edd0 as *mut u32).write_volatile(0);
        for index in 0u8..8 {
            core.SAU
                .rnr
                .write(cortex_m::peripheral::sau::Rnr(u32::from(index)));
            core.SAU.rlar.write(cortex_m::peripheral::sau::Rlar(0));
        }
    }
    for (index, base, limit, attribute) in [
        (0, NS_FLASH, 0x1027_ffff, SauRegionAttribute::NonSecure),
        (1, NS_RAM, 0x2007_ffff, SauRegionAttribute::NonSecure),
        (
            2,
            NSC_FLASH,
            NS_FLASH - 1,
            SauRegionAttribute::NonSecureCallable,
        ),
    ] {
        core.SAU
            .set_region(
                index,
                SauRegion {
                    base_address: base,
                    limit_address: limit,
                    attribute,
                },
            )
            .unwrap();
    }
    core.SAU.enable();
    let permissions = 0xacce_003a;
    rp_pac::ACCESSCTRL.usbctrl().write(|v| v.0 = 0xacce_0018);
    rp_pac::ACCESSCTRL.timer1().write(|v| v.0 = permissions);
    // SAFETY: ITNS, VTOR_NS and MSP_NS are the architectural Non-secure launch controls.
    unsafe {
        let aircr = 0xe000_ed0c as *mut u32;
        aircr.write_volatile(0x05fa_0000 | ((aircr.read_volatile() & 0x0000_bfff) | (1 << 3)));
        for word in 0..2 {
            (0xe000_e380 as *mut u32).add(word).write_volatile(0);
        }
        for irq in [
            rp_pac::Interrupt::SWI_IRQ_1,
            rp_pac::Interrupt::TIMER1_IRQ_0,
        ] {
            let n = irq as u32;
            let itns = (0xe000_e380 + (n / 32) * 4) as *mut u32;
            itns.write_volatile(itns.read_volatile() | (1 << (n % 32)));
        }
        // PRIS remains clear: the higher-priority NS USB IRQ must preempt Secure work.
        crate::usb_attach::mark();
        let vectors = NS_FLASH as *const u32;
        (0xe002_ed08 as *mut u32).write_volatile(NS_FLASH);
        cortex_m::register::msp::write_ns(vectors.read_volatile());
        core::arch::asm!("msr MSPLIM_NS, {floor}", floor = in(reg) NS_RAM, options(nostack, preserves_flags));
        cortex_m::asm::bx_ns(vectors.add(1).read_volatile() & !1);
    }
    loop {
        cortex_m::asm::wfe();
    }
}
