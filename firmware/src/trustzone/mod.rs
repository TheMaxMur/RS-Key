// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

pub mod fault;
pub mod mpu;
mod security_policy;
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

pub const NS_FLASH: u32 = crate::env_u32(env!("PK_TZ_NS_FLASH"));
pub const NS_FLASH_END: u32 = crate::env_u32(env!("PK_TZ_NS_FLASH_END"));
pub const FLASH_END: u32 = crate::env_u32(env!("PK_TZ_FLASH_END"));
const NS_RAM: u32 = 0x2007_0000;
const NSC_FLASH: u32 = crate::env_u32(env!("PK_TZ_NSC_FLASH"));
unsafe extern "C" {
    fn rsk_tz_enter_ns(entry: u32) -> !;
}

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

static READY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub fn notify_nonsecure() {
    if READY.load(core::sync::atomic::Ordering::Acquire) {
        cortex_m::asm::dmb();
        interrupt::SWI_IRQ_4.pend();
    }
}

#[embassy_executor::task]
async fn boot() {
    // SAFETY: this task is polled only by Embassy's Secure interrupt executor.
    let spawner = unsafe { embassy_executor::Spawner::for_current_executor().await };
    spawner.spawn(crate::main(spawner).unwrap());
}

fn initialize_scratch_code() {
    unsafe extern "C" {
        static __rsk_scratch_exec_start: u8;
        static __rsk_scratch_exec_end: u8;
        static __rsk_scratch_exec_load: u8;
    }
    let start = core::ptr::addr_of!(__rsk_scratch_exec_start);
    let end = core::ptr::addr_of!(__rsk_scratch_exec_end) as usize;
    let length = end.checked_sub(start as usize).unwrap();
    // SAFETY: the linker bounds disjoint flash/RAM sections including zero padding.
    // Startup calls this once, before tasks, core1, NS or any scratch-code caller.
    unsafe {
        core::ptr::copy_nonoverlapping(
            core::ptr::addr_of!(__rsk_scratch_exec_load),
            start.cast_mut(),
            length,
        );
    }
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
}

pub fn start() {
    initialize_scratch_code();
    interrupt::SWI_IRQ_4.disable();
    interrupt::SWI_IRQ_4.unpend();
    interrupt::DMA_IRQ_0.set_priority(Priority::P1);
    interrupt::PIO0_IRQ_0.set_priority(Priority::P1);
    embassy_rp::interrupt::SWI_IRQ_0.set_priority(Priority::P3);
    EXECUTOR
        .start(embassy_rp::interrupt::SWI_IRQ_0)
        .spawn(boot().unwrap());
}

pub fn idle() -> ! {
    loop {
        if READY.load(core::sync::atomic::Ordering::Acquire) {
            // SAFETY: Secure boot has returned its initialization frame and installed every owner.
            unsafe { launch_nonsecure() }
        }
        cortex_m::asm::wfi();
    }
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
    READY.store(true, core::sync::atomic::Ordering::Release);
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
        (0, NS_FLASH, NS_FLASH_END - 1, SauRegionAttribute::NonSecure),
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
    security_policy::configure_bus_masters();
    mpu::secure();
    mpu::nonsecure();
    // SAFETY: ITNS, VTOR_NS and MSP_NS are the architectural Non-secure launch controls.
    unsafe {
        let nsacr = 0xe000_ed8c as *mut u32;
        nsacr.write_volatile((1 << 10) | (1 << 11));
        let fpccr = 0xe000_ef34 as *mut u32;
        fpccr.write_volatile(fpccr.read_volatile() | (1 << 26) | (1 << 27) | (1 << 28) | (1 << 29));
        let aircr = 0xe000_ed0c as *mut u32;
        aircr.write_volatile(0x05fa_0000 | ((aircr.read_volatile() & 0x0000_9fff) | (1 << 3)));
        for word in 0..2 {
            (0xe000_e380 as *mut u32).add(word).write_volatile(0);
        }
        for irq in [
            rp_pac::Interrupt::SWI_IRQ_1,
            rp_pac::Interrupt::SWI_IRQ_4,
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
        let stack = vectors.read_volatile();
        let entry = vectors.add(1).read_volatile();
        assert!(stack > NS_RAM && stack <= NS_RAM_END as u32 && stack.is_multiple_of(8));
        assert!(entry & 1 == 1 && (NS_FLASH..NS_FLASH_END).contains(&entry));
        core::arch::asm!(
            "msr CONTROL_NS, {zero}", "msr PRIMASK_NS, {zero}",
            "msr BASEPRI_NS, {zero}", "msr FAULTMASK_NS, {zero}",
            zero = in(reg) 0u32, options(nostack, preserves_flags),
        );
        cortex_m::register::msp::write_ns(stack);
        core::arch::asm!("msr MSPLIM_NS, {floor}", floor = in(reg) NS_RAM, options(nostack, preserves_flags));
        rsk_tz_enter_ns(entry & !1);
    }
}

#[cfg(not(led_kind = "none"))]
static LED_EXECUTOR: InterruptExecutor = InterruptExecutor::new();

#[cfg(not(led_kind = "none"))]
pub fn led_spawner() -> embassy_executor::SendSpawner {
    interrupt::SWI_IRQ_3.set_priority(Priority::P2);
    LED_EXECUTOR.start(interrupt::SWI_IRQ_3)
}

#[cfg(not(led_kind = "none"))]
#[embassy_rp::interrupt]
fn SWI_IRQ_3() {
    // SAFETY: this interrupt owns only the Secure LED executor installed at boot.
    unsafe { LED_EXECUTOR.on_interrupt() }
}
