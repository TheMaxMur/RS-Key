// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

unsafe extern "C" {
    static __rsk_exec_start: u8;
    static __rsk_exec_end: u8;
}

const SECURE_MPU: usize = 0xe000_ed90;
const NONSECURE_MPU: usize = 0xe002_ed90;
const ENABLE_BACKGROUND: u32 = 1 | 2 | 4;
const ENABLE: u32 = 1 | 2;
const READ_ONLY: u32 = 2 << 1;
const EXECUTE_NEVER: u32 = 1;
const DEVICE: u32 = 1 << 1;
use rsk_device::mpu_layout::{Permission, RamCode, Region};
static CORE0_CONFIGURED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

fn configure(base: usize, regions: &[(u32, u32, u32, u32)], control: u32) {
    // SAFETY: each core configures its own MPU while still in Secure startup, before NS entry.
    unsafe {
        let register = base as *mut u32;
        register.add(1).write_volatile(0);
        register.add(12).write_volatile(0x44);
        for index in 0..8 {
            register.add(2).write_volatile(index);
            register.add(3).write_volatile(0);
            register.add(4).write_volatile(0);
        }
        for (index, &(start, end, permissions, attribute)) in regions.iter().enumerate() {
            assert_eq!(start & 31, 0);
            assert_eq!(end & 31, 0);
            assert!(start < end);
            register
                .add(2)
                .write_volatile(u32::try_from(index).unwrap());
            register.add(3).write_volatile(start | permissions);
            register
                .add(4)
                .write_volatile((end - 1) & !31 | attribute | 1);
        }
        cortex_m::asm::dsb();
        register.add(1).write_volatile(control);
        cortex_m::asm::dsb();
        cortex_m::asm::isb();
    }
}

fn ram_code() -> RamCode {
    RamCode::new(
        core::ptr::addr_of!(__rsk_exec_start) as u32,
        core::ptr::addr_of!(__rsk_exec_end) as u32,
    )
    .unwrap()
}

fn ram_region(region: Region) -> (u32, u32, u32, u32) {
    let permissions = match region.permission {
        Permission::Data => EXECUTE_NEVER,
        Permission::Code => READ_ONLY,
        Permission::FlashStackCode => 0,
    };
    (region.start, region.end, permissions, 0)
}

pub fn secure() {
    let [before, code, after] = ram_code().regions().map(ram_region);
    configure(
        SECURE_MPU,
        &[
            (0x1000_0000, super::NS_FLASH, READ_ONLY, 0),
            (
                super::NS_FLASH,
                super::FLASH_END,
                READ_ONLY | EXECUTE_NEVER,
                0,
            ),
            before,
            code,
            after,
        ],
        ENABLE_BACKGROUND,
    );
    if rp_pac::SIO.cpuid().read() == 0 {
        CORE0_CONFIGURED.store(true, core::sync::atomic::Ordering::Release);
    }
}

pub fn nonsecure() {
    let timer = rp_pac::TIMER1.as_ptr() as u32;
    configure(
        NONSECURE_MPU,
        &[
            (super::NS_FLASH, super::NS_FLASH_END, READ_ONLY, 0),
            (0x2007_0000, 0x2008_0000, EXECUTE_NEVER, 0),
            (timer, timer + 0x4000, EXECUTE_NEVER, DEVICE),
            (0xe000_0000, 0xe010_0000, EXECUTE_NEVER, DEVICE),
        ],
        ENABLE,
    );
}

pub fn with_flash_code<T>(operation: impl FnOnce() -> T) -> T {
    if !CORE0_CONFIGURED.load(core::sync::atomic::Ordering::Acquire) {
        return operation();
    }
    cortex_m::interrupt::free(|_| {
        let [a, b, c, d, e] = ram_code()
            .flash_stack_regions(cortex_m::register::msp::read())
            .unwrap()
            .map(ram_region);
        configure(
            SECURE_MPU,
            &[
                (0x1000_0000, super::NS_FLASH, READ_ONLY, 0),
                (
                    super::NS_FLASH,
                    super::FLASH_END,
                    READ_ONLY | EXECUTE_NEVER,
                    0,
                ),
                a,
                b,
                c,
                d,
                e,
            ],
            ENABLE_BACKGROUND,
        );
        struct Restore;
        impl Drop for Restore {
            fn drop(&mut self) {
                secure();
            }
        }
        let _restore = Restore;
        operation()
    })
}
