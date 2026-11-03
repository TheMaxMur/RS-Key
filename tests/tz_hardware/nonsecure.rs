// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use core::sync::atomic::{AtomicU32, Ordering};
include!("hardware_constants.rs");
static ARMED: AtomicU32 = AtomicU32::new(0);
static ALLOWED: AtomicU32 = AtomicU32::new(READ_VALUE);
static ENTRY_REGISTERS: [AtomicU32; 4] = [const { AtomicU32::new(0) }; 4];

pub fn entry() {
    let (control, primask, basepri, faultmask, stack, limit): (u32, u32, u32, u32, u32, u32);
    // SAFETY: the fixture observes its own banked registers before NS initialization.
    unsafe {
        core::arch::asm!("mrs {a}, CONTROL", "mrs {b}, PRIMASK", "mrs {c}, BASEPRI", "mrs {d}, FAULTMASK", "mrs {e}, MSP", "mrs {f}, MSPLIM", a=out(reg) control, b=out(reg) primask, c=out(reg) basepri, d=out(reg) faultmask, e=out(reg) stack, f=out(reg) limit, options(nostack));
    }
    for (slot, value) in ENTRY_REGISTERS.iter().zip([control, primask, basepri, faultmask]) {
        slot.store(value, Ordering::Relaxed);
    }
    let flags = u32::from(control | primask | basepri | faultmask == 0)
        | (u32::from(stack > 0x2007_0000 && stack <= 0x2008_0000 && stack & 7 == 0) << 1)
        | (u32::from(limit == 0x2007_0000) << 2);
    super::session::control(ENTRY, flags);
}

pub fn reply(data: &[u8], out: &mut [u8]) -> Option<usize> {
    let data = data.strip_prefix(b"hw")?;
    let &[action_bytes, argument_bytes] = data.as_chunks::<4>().0 else {
        return None;
    };
    if data.len() != 8 {
        return None;
    }
    let action = u32::from_le_bytes(action_bytes);
    let argument = u32::from_le_bytes(argument_bytes);
    let value = if action == GET && argument == 30 {
        core::ptr::addr_of!(ALLOWED) as u32
    } else if action == GET && argument == 31 {
        ALLOWED.load(Ordering::Relaxed)
    } else if action == GET && argument == 32 {
        load as *const () as u32
    } else if action == GET && argument == 33 {
        store as *const () as u32
    } else if action == GET && (34..=37).contains(&argument) {
        ENTRY_REGISTERS.get((argument - 34) as usize).map_or(u32::MAX, |slot| slot.load(Ordering::Relaxed))
    } else {
        super::session::control(action, argument)
    };
    if action == ARM && value == 0 {
        ARMED.store(argument, Ordering::Release);
    }
    out.get_mut(..4)?.copy_from_slice(&value.to_le_bytes());
    Some(4)
}

#[inline(never)]
fn load(address: u32) -> u32 {
    let value;
    // SAFETY: the disposable NS fixture deliberately tests one selected access with its MPU off.
    unsafe {
        core::arch::asm!(".global RSK_HW_NS_READ", ".set RSK_HW_NS_READ, .", "ldr {value}, [{address}]", value=out(reg) value, address=in(reg) address, options(nostack));
    }
    cortex_m::asm::dsb();
    value
}

#[inline(never)]
fn store(address: u32) -> u32 {
    // SAFETY: the disposable NS fixture deliberately tests one selected access with its MPU off.
    unsafe {
        core::arch::asm!(".global RSK_HW_NS_WRITE", ".set RSK_HW_NS_WRITE, .", "str {value}, [{address}]", value=in(reg) WRITE_VALUE, address=in(reg) address, options(nostack));
    }
    cortex_m::asm::dsb();
    WRITE_VALUE
}

#[embassy_executor::task]
pub async fn after_usb() {
    use rsk_usb::usb_abi;
    while ARMED.load(Ordering::Acquire) == 0 {
        embassy_time::Timer::after_millis(1).await;
    }
    embassy_time::Timer::after_millis(100).await;
    let mut marker = MARKER;
    loop {
        let operation = usb_abi::EP_WRITE | (BULK_ENDPOINT << usb_abi::ADDRESS_SHIFT);
        if super::usb::transfer(operation, super::usb::epoch(), &mut marker) == 0 {
            break;
        }
        embassy_time::Timer::after_millis(1).await;
    }
    let mode = Mode::decode(ARMED.load(Ordering::Acquire) & 255);
    let address = super::session::control(GET, 10);
    if super::session::control(PREPARE, 0) == 0 {
        if let Some(mode @ (Mode::NsRead | Mode::NsWrite)) = mode {
            // SAFETY: only the disposable hostile NS image disables its own MPU.
            unsafe {
                (0xe000_ed94 as *mut u32).write_volatile(0);
            }
            cortex_m::asm::dsb();
            cortex_m::asm::isb();
            let value = if mode == Mode::NsWrite {
                store(address);
                load(address)
            } else {
                load(address)
            };
            let public = if (0x2007_0000..0x2008_0000).contains(&address) {
                value
            } else {
                0
            };
            super::session::control(COMPLETE, public);
        }
    }
    loop {
        embassy_time::Timer::after_millis(1).await;
    }
}
