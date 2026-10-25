// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

pub const ENDPOINTS: usize = 16;

#[inline(always)]
pub fn clear_packets() {
    for index in 0..ENDPOINTS {
        rp_pac::USB_DPRAM.ep_in_buffer_control(index).modify(|v| {
            for buffer in 0..2 {
                v.set_available(buffer, false);
                v.set_full(buffer, false);
                v.set_length(buffer, 0);
            }
        });
        rp_pac::USB_DPRAM.ep_out_buffer_control(index).modify(|v| {
            for buffer in 0..2 {
                v.set_available(buffer, false);
                v.set_full(buffer, false);
                v.set_length(buffer, 0);
            }
        });
    }
    // SAFETY: S owns DPRAM; all buffers are unavailable before their payloads are wiped.
    unsafe {
        let data = (rp_pac::USB_DPRAM.as_ptr() as *mut u32).add(0x100 / 4);
        for offset in 0..(4096 - 0x100) / 4 {
            data.add(offset).write_volatile(0);
        }
    }
}

#[inline(always)]
pub fn disconnect_after_fault() {
    // A fault can interrupt an owner with its lock held; touch only S-owned MMIO.
    rp_pac::USB.inte().write(|value| value.0 = 0);
    rp_pac::USB
        .sie_ctrl()
        .modify(|value| value.set_pullup_en(false));
    clear_packets();
}
