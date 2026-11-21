// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use core::cell::RefCell;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use embassy_rp::{Peri, peripherals::WATCHDOG, watchdog::Watchdog};
use embassy_sync::blocking_mutex::{Mutex, raw::CriticalSectionRawMutex};

include!("hardware_constants.rs");

static TIMER: Mutex<CriticalSectionRawMutex, RefCell<Option<Watchdog>>> =
    Mutex::new(RefCell::new(None));
static SAVED: [AtomicU32; 4] = [const { AtomicU32::new(0) }; 4];
static RECORD: [AtomicU32; 3] = [const { AtomicU32::new(0) }; 3];
static TARGET: AtomicU32 = AtomicU32::new(0);
static RUN: AtomicU32 = AtomicU32::new(0);
static CORE1_READY: AtomicBool = AtomicBool::new(false);
static COPY: AtomicU32 = AtomicU32::new(0);
static LAUNCH: AtomicU32 = AtomicU32::new(0);
static NS_ENTRY: AtomicU32 = AtomicU32::new(0);
static BOOT_AUTH: AtomicU32 = AtomicU32::new(u32::MAX);
static CURRENT_AUTH: AtomicU32 = AtomicU32::new(u32::MAX);
static PERSISTED: AtomicU32 = AtomicU32::new(0);
static FLASH_WINDOW: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    static __rsk_scratch_exec_start: u8;
    static __rsk_scratch_exec_end: u8;
    static __rsk_scratch_exec_load: u8;
}

fn read(address: u32) -> u32 {
    // SAFETY: the fixture's callers select public core/MMIO registers or its linker-bounded code.
    unsafe { (address as *const u32).read_volatile() }
}

fn scratch() -> (&'static [u8], &'static [u8]) {
    let start = core::ptr::addr_of!(__rsk_scratch_exec_start);
    let length = core::ptr::addr_of!(__rsk_scratch_exec_end) as usize - start as usize;
    // SAFETY: the fixture reads the disjoint immutable intervals the combined linker bounds.
    unsafe {
        (
            core::slice::from_raw_parts(start, length),
            core::slice::from_raw_parts(core::ptr::addr_of!(__rsk_scratch_exec_load), length),
        )
    }
}

fn copy_matches() -> bool {
    let (actual, expected) = scratch();
    actual == expected
}

pub fn boot() {
    for (slot, value) in SAVED.iter().zip([
        rp_pac::WATCHDOG.scratch0().read(),
        rp_pac::WATCHDOG.scratch1().read(),
        rp_pac::WATCHDOG.scratch3().read(),
        rp_pac::WATCHDOG.reason().read().0,
    ]) {
        slot.store(value, Ordering::Relaxed);
    }
}

pub fn initialized() {
    COPY.store(rsk_crypto::crc::crc32(scratch().0), Ordering::Relaxed);
}

pub fn init(peripheral: Peri<'static, WATCHDOG>) {
    TIMER.lock(|timer| *timer.borrow_mut() = Some(Watchdog::new(peripheral)));
}

pub fn authority(value: u32) {
    BOOT_AUTH.store(value, Ordering::Release);
    observe_authority(value);
}

pub fn observe_authority(value: u32) {
    CURRENT_AUTH.store(value, Ordering::Release);
}

fn flags(mode: Mode) -> u32 {
    let mut flags = if copy_matches() { COPY_MATCH } else { 0 };
    if rp_pac::SIO.cpuid().read() == 1 {
        flags |= CORE1;
    }
    if mode.write() {
        flags |= WRITE;
    }
    flags
}

fn publish(stage: u32, flags: u32, cause: u32, address: u32, sfsr: u32) {
    RECORD[1].store(cause, Ordering::Relaxed);
    RECORD[2].store(address, Ordering::Relaxed);
    let case = (RUN.load(Ordering::Acquire) >> 8) & 255;
    let header = MAGIC | case << 20 | (sfsr & 255) << 12 | stage << 8 | flags;
    RECORD[0].store(header, Ordering::Release);
    if rp_pac::SIO.cpuid().read() == 0 {
        persist();
    }
}

fn persist() {
    let header = RECORD[0].load(Ordering::Acquire);
    if (header >> 8) & 15 < FAULT || header == PERSISTED.load(Ordering::Relaxed) {
        return;
    }
    rp_pac::WATCHDOG.scratch0().write_value(0);
    rp_pac::WATCHDOG
        .scratch1()
        .write_value(RECORD[1].load(Ordering::Relaxed));
    rp_pac::WATCHDOG
        .scratch3()
        .write_value(RECORD[2].load(Ordering::Relaxed));
    cortex_m::asm::dsb();
    rp_pac::WATCHDOG.scratch0().write_value(header);
    PERSISTED.store(header, Ordering::Relaxed);
}

fn current() -> Option<Mode> {
    Mode::decode(RUN.load(Ordering::Acquire) & 255)
}

pub fn control(action: u32, argument: u32) -> u32 {
    match action {
        GET => match argument {
            0..=3 => SAVED
                .get(argument as usize)
                .map_or(u32::MAX, |slot| slot.load(Ordering::Relaxed)),
            4 => COPY.load(Ordering::Relaxed),
            5 => LAUNCH.load(Ordering::Relaxed),
            6 => rsk_crypto::crc::crc32(scratch().1),
            7 => NS_ENTRY.load(Ordering::Relaxed),
            8 => BUILD_ID,
            9 => crate::trustzone::fault::rsk_tz_fault_stop as *const () as u32,
            10 => TARGET.load(Ordering::Relaxed),
            11 => BOOT_AUTH.load(Ordering::Acquire),
            12 => CURRENT_AUTH.load(Ordering::Acquire),
            _ => u32::MAX,
        },
        SET_TARGET => {
            TARGET.store(argument, Ordering::Release);
            0
        }
        ENTRY => {
            NS_ENTRY.store(argument, Ordering::Release);
            0
        }
        ARM => {
            if RUN.load(Ordering::Acquire) != 0 {
                return u32::MAX;
            }
            if argument & !0x1ffff != 0 || (argument >> 8) & 255 == 0 {
                return u32::MAX;
            }
            let Some(mode) = Mode::decode(argument & 255) else {
                return u32::MAX;
            };
            let target = TARGET.load(Ordering::Acquire);
            if !matches!(mode, Mode::NsRead | Mode::NsWrite | Mode::Locks)
                && !matches!(target, 0x2008_0000 | 0x2008_0100 | 0x2008_1ffc)
            {
                return u32::MAX;
            }
            RUN.store(argument, Ordering::Release);
            RECORD[1].store(0, Ordering::Relaxed);
            RECORD[2].store(TARGET.load(Ordering::Relaxed), Ordering::Relaxed);
            RECORD[0].store(
                MAGIC | ((argument >> 8) & 255) << 20 | ARMED << 8 | flags(mode),
                Ordering::Release,
            );
            rp_pac::WATCHDOG
                .scratch0()
                .write_value(RECORD[0].load(Ordering::Acquire));
            rp_pac::WATCHDOG.scratch1().write_value(0);
            rp_pac::WATCHDOG
                .scratch3()
                .write_value(TARGET.load(Ordering::Relaxed));
            let started = TIMER.lock(|timer| {
                let mut timer = timer.borrow_mut();
                let Some(timer) = timer.as_mut() else {
                    return false;
                };
                timer.pause_on_debug(false);
                timer.start(embassy_time::Duration::from_millis(WATCHDOG_MS.into()));
                true
            });
            if !started {
                return u32::MAX;
            }
            // The pinned HAL's RP2040 mask omits RP2350's processor and ACCESSCTRL reset bits.
            rp_pac::PSM
                .wdsel()
                .write_value(rp_pac::psm::regs::Wdsel(WATCHDOG_DOMAINS));
            0
        }
        PREPARE => {
            if (RECORD[0].load(Ordering::Acquire) >> 8) & 15 != ARMED {
                return u32::MAX;
            }
            let Some(mode) = current() else {
                return u32::MAX;
            };
            let buffer = rp_pac::USB_DPRAM
                .ep_in_buffer_control(BULK_ENDPOINT as usize & 15)
                .read();
            let offset = u32::from(
                rp_pac::USB_DPRAM
                    .ep_in_control((BULK_ENDPOINT as usize & 15) - 1)
                    .read()
                    .buffer_address(),
            );
            let payload = (0x100..=0x1000 - MARKER.len() as u32).contains(&offset)
                && offset & 3 == 0
                && MARKER
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .enumerate()
                    .all(|(index, expected)| {
                        read(0x5010_0000 + offset + index as u32 * 4)
                            == u32::from_le_bytes(*expected)
                    });
            let prepared = buffer.available(0)
                && buffer.full(0)
                && usize::from(buffer.length(0)) == MARKER.len()
                && payload;
            let flags = flags(mode) | if prepared { PACKET } else { 0 };
            let header = RECORD[0].load(Ordering::Acquire);
            RECORD[0].store((header & !0xfff) | flags | PROBING << 8, Ordering::Release);
            if !prepared {
                publish(FAILED, flags, 0, TARGET.load(Ordering::Relaxed), 0);
                return u32::MAX;
            }
            if RUN.load(Ordering::Acquire) & AUTH_REQUIRED != 0
                && CURRENT_AUTH.load(Ordering::Acquire) & 3 != 3
            {
                publish(
                    FAILED,
                    flags,
                    CURRENT_AUTH.load(Ordering::Acquire),
                    TARGET.load(Ordering::Relaxed),
                    0,
                );
                return u32::MAX;
            }
            if mode.core1() {
                if mode.flash() {
                    crate::trustzone::mpu::with_flash_code(|| {
                        observe_flash_window();
                        CORE1_READY.store(true, Ordering::Release);
                        cortex_m::asm::sev();
                        while (RECORD[0].load(Ordering::Acquire) >> 8) & 15 < FAULT {
                            core::hint::spin_loop();
                        }
                        while (RECORD[0].load(Ordering::Acquire) >> 8) & 15 == FAULT {
                            persist();
                            core::hint::spin_loop();
                        }
                        persist();
                    });
                } else {
                    CORE1_READY.store(true, Ordering::Release);
                    cortex_m::asm::sev();
                }
            } else if !matches!(mode, Mode::NsRead | Mode::NsWrite) {
                execute(mode);
            }
            0
        }
        COMPLETE => {
            if (RECORD[0].load(Ordering::Acquire) >> 8) & 15 != PROBING {
                return u32::MAX;
            }
            let Some(mode) = current() else {
                return u32::MAX;
            };
            publish(
                COMPLETED,
                flags(mode) | PACKET,
                argument,
                TARGET.load(Ordering::Relaxed),
                0,
            );
            0
        }
        _ => u32::MAX,
    }
}

#[embassy_executor::task]
pub async fn monitor() {
    loop {
        persist();
        embassy_time::Timer::after_millis(1).await;
    }
}

pub fn core1_poll() {
    if CORE1_READY.swap(false, Ordering::AcqRel) {
        if let Some(mode) = current() {
            execute(mode);
        }
    }
}

#[inline(never)]
fn load(address: u32) -> u32 {
    let value;
    // SAFETY: a disposable test deliberately executes one selected load, including denied controls.
    unsafe {
        core::arch::asm!(".global RSK_HW_S_READ", ".set RSK_HW_S_READ, .", "ldr {value}, [{address}]", value = out(reg) value, address = in(reg) address, options(nostack));
    }
    cortex_m::asm::dsb();
    value
}

#[inline(never)]
fn store(address: u32) -> u32 {
    // SAFETY: a disposable test deliberately executes one selected store, including denied controls.
    unsafe {
        core::arch::asm!(".global RSK_HW_S_WRITE", ".set RSK_HW_S_WRITE, .", "str {value}, [{address}]", value = in(reg) WRITE_VALUE, address = in(reg) address, options(nostack));
    }
    cortex_m::asm::dsb();
    WRITE_VALUE
}

#[unsafe(link_section = ".rsk_hw_scratch")]
#[inline(never)]
fn execute_scratch() -> u32 {
    core::hint::black_box(EXECUTED)
}

fn locks() -> u32 {
    let mut failures = 0;
    for channel in 0..16 {
        let register = rp_pac::DMA.seccfg_ch(channel);
        let before = register.read();
        register.write(|value| value.0 = 0);
        if !before.s() || !before.p() || !before.lock() || register.read().0 != before.0 {
            failures |= 1 << channel;
        }
    }
    let access = rp_pac::ACCESSCTRL;
    let before = access.usbctrl().read().0;
    access.usbctrl().write(|value| value.0 = 0xacce_0000);
    if access.lock().read().0 & 15 != 15 || access.usbctrl().read().0 != before {
        failures |= 1 << 16;
    }
    failures
}

fn select_mpu_region(region: u32) {
    // SAFETY: inspect this core's MPU region selectors without changing its permissions.
    unsafe {
        (0xe000_ed98 as *mut u32).write_volatile(region);
    }
}

fn observe_flash_window() {
    let selected = read(0xe000_ed98);
    select_mpu_region(6);
    let extra = read(0xe000_eda0) & 1 != 0;
    select_mpu_region(7);
    let scratch = read(0xe000_ed9c) == 0x2008_0104 && read(0xe000_eda0) == 0x2008_1fe1;
    select_mpu_region(selected);
    FLASH_WINDOW.store(
        extra && scratch && read(0xe000_ed94) == 7,
        Ordering::Release,
    );
}

fn context_observed(mode: Mode) -> bool {
    !mode.flash() || FLASH_WINDOW.load(Ordering::Acquire)
}

fn execute(mode: Mode) {
    let operation = || {
        if mode.execute() {
            execute_scratch()
        } else if mode == Mode::Locks {
            locks()
        } else if mode.write() {
            store(TARGET.load(Ordering::Relaxed));
            load(TARGET.load(Ordering::Relaxed))
        } else {
            load(TARGET.load(Ordering::Relaxed))
        }
    };
    let result = if mode.flash() && !mode.core1() {
        crate::trustzone::mpu::with_flash_code(|| {
            observe_flash_window();
            operation()
        })
    } else {
        operation()
    };
    let good = copy_matches()
        && context_observed(mode)
        && (!mode.execute() || result == EXECUTED)
        && (mode != Mode::Locks || result == 0);
    publish(
        if good { COMPLETED } else { FAILED },
        flags(mode) | PACKET,
        result,
        TARGET.load(Ordering::Relaxed),
        0,
    );
}

pub fn entered() {
    let Some(mode) = current() else {
        return;
    };
    let cfsr = read(0xe000_ed28);
    let sfsr = read(0xe000_ede4);
    let address = if sfsr & 0x40 != 0 {
        read(0xe000_ede8)
    } else if cfsr & 0x80 != 0 {
        read(0xe000_ed34)
    } else {
        read(0xe000_ed38)
    };
    let flags = (RECORD[0].load(Ordering::Acquire) & PACKET) | flags(mode);
    publish(FAULT, flags, cfsr, address, sfsr);
}

pub fn fenced() {
    let Some(mode) = current() else {
        return;
    };
    let mut flags = (RECORD[0].load(Ordering::Acquire) & PACKET) | flags(mode);
    if crate::worker::rsk_tz_control_impl(rsk_usb::worker_abi::CAN_WINK, 0)
        == rsk_usb::worker_abi::INVALID
    {
        flags |= GATES;
    }
    if rp_pac::USB.inte().read().0 == 0 && !rp_pac::USB.sie_ctrl().read().pullup_en() {
        flags |= DETACHED;
    }
    let buffers = (0..16).all(|index| {
        [
            rp_pac::USB_DPRAM.ep_in_buffer_control(index).read(),
            rp_pac::USB_DPRAM.ep_out_buffer_control(index).read(),
        ]
        .iter()
        .all(|v| {
            (0..2).all(|buffer| !v.available(buffer) && !v.full(buffer) && v.length(buffer) == 0)
        })
    });
    if buffers {
        flags |= BUFFERS;
    }
    if (0x5010_0100..0x5010_1000)
        .step_by(4)
        .all(|address| read(address) == 0)
    {
        flags |= PAYLOAD;
    }
    let cause = RECORD[1].load(Ordering::Relaxed);
    let address = RECORD[2].load(Ordering::Relaxed);
    let sfsr = (RECORD[0].load(Ordering::Acquire) >> 12) & 255;
    publish(
        if context_observed(mode) {
            FENCED
        } else {
            FAILED
        },
        flags,
        cause,
        address,
        sfsr,
    );
}

pub fn wait() -> ! {
    loop {
        cortex_m::asm::wfe();
    }
}

pub fn launch() {
    let mut result = 0;
    let mut expected = [0u32; 2];
    for irq in [
        rp_pac::Interrupt::SWI_IRQ_1,
        rp_pac::Interrupt::SWI_IRQ_4,
        rp_pac::Interrupt::TIMER1_IRQ_0,
    ] {
        let n = irq as usize;
        let Some(word) = expected.get_mut(n / 32) else {
            return;
        };
        *word |= 1 << (n % 32);
    }
    if read(0xe000_e380) == expected[0] {
        result |= 1;
    }
    if read(0xe000_e384) == expected[1] {
        result |= 2;
    }
    if read(0xe002_ed08) == super::NS_FLASH {
        result |= 4;
    }
    if cortex_m::register::msp::read_ns() == read(super::NS_FLASH) {
        result |= 8;
    }
    let (control, primask, basepri, faultmask, limit): (u32, u32, u32, u32, u32);
    // SAFETY: the Secure launch fixture reads the banked controls immediately before BXNS.
    unsafe {
        core::arch::asm!("mrs {a}, CONTROL_NS", "mrs {b}, PRIMASK_NS", "mrs {c}, BASEPRI_NS", "mrs {d}, FAULTMASK_NS", "mrs {e}, MSPLIM_NS", a=out(reg) control, b=out(reg) primask, c=out(reg) basepri, d=out(reg) faultmask, e=out(reg) limit, options(nostack));
    }
    if limit == 0x2007_0000 {
        result |= 16;
    }
    if control | primask | basepri | faultmask == 0 {
        result |= 32;
    }
    if read(0xe000_ed8c) & 0xc00 == 0xc00 {
        result |= 64;
    }
    if read(0xe000_ef34) & 0x3c00_0000 == 0x3c00_0000 && read(0xe000_ed0c) & 0x6008 == 8 {
        result |= 128;
    }
    let selected = read(0xe000_edd8);
    let mut sau = read(0xe000_edd0) & 1 != 0;
    let regions = [
        (super::NS_FLASH, (super::NS_FLASH_END - 1) & !31 | 1),
        (0x2007_0000, 0x2007_ffe1),
        (super::NSC_FLASH, (super::NS_FLASH - 1) & !31 | 3),
    ];
    for index in 0..8 {
        // SAFETY: this startup-only observation restores SAU_RNR and changes no attribution.
        unsafe {
            (0xe000_edd8 as *mut u32).write_volatile(index);
        }
        if let Some(&(base, limit)) = regions.get(index as usize) {
            sau &= read(0xe000_eddc) == base && read(0xe000_ede0) == limit;
        } else {
            sau &= read(0xe000_ede0) == 0;
        }
    }
    // SAFETY: restore the region selector saved above before entering NS.
    unsafe {
        (0xe000_edd8 as *mut u32).write_volatile(selected);
    }
    if sau {
        result |= 256;
    }
    if read(0xe002_ed94) == 3 {
        result |= 512;
    }
    if read(0xe000_ed94) == 7 {
        result |= 1024;
    }
    LAUNCH.store(result, Ordering::Release);
}
