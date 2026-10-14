/* SPDX-License-Identifier: AGPL-3.0-only */
/* Copyright (C) 2026 RS-Key contributors */

#include <stdint.h>

extern uint32_t rsk_tz_submit_impl(uint32_t, uint32_t, const uint8_t *, uint32_t);
extern uint32_t rsk_tz_poll_impl(uint32_t, uint8_t *, uint32_t);
extern uint32_t rsk_tz_control_impl(uint32_t, uint32_t);
extern uint32_t rsk_tz_readable_impl(const uint8_t *, uint32_t);
extern uint32_t rsk_tz_writable_impl(uint8_t *, uint32_t);

__attribute__((cmse_nonsecure_entry))
uint32_t rsk_tz_submit(uint32_t kind, uint32_t cid,
                       const uint8_t *request, uint32_t length) {
    if (length && !rsk_tz_readable_impl(request, length))
        return UINT32_MAX;
    return rsk_tz_submit_impl(kind, cid, request, length);
}

__attribute__((cmse_nonsecure_entry))
uint32_t rsk_tz_poll(uint32_t ticket, uint8_t *response, uint32_t capacity) {
    if (!capacity || !rsk_tz_writable_impl(response, capacity))
        return UINT32_MAX;
    return rsk_tz_poll_impl(ticket, response, capacity);
}

__attribute__((cmse_nonsecure_entry))
uint32_t rsk_tz_control(uint32_t action, uint32_t ticket) {
    return rsk_tz_control_impl(action, ticket);
}

extern uint32_t rsk_tz_usb_impl(uint32_t, uint32_t, uint8_t *, uint32_t);

__attribute__((cmse_nonsecure_entry))
uint32_t rsk_tz_usb(uint32_t operation, uint32_t argument, uint8_t *buffer, uint32_t length) {
    return rsk_tz_usb_impl(operation, argument, buffer, length);
}

/* No boot/worker value in a shared register is handed to the untrusted entry. */
__attribute__((naked, noreturn))
void rsk_tz_enter_ns(uint32_t entry __attribute__((unused))) {
    __asm__ volatile(
        "mov lr, r0\n"
        "movs r0, #0\n"
        "mov r1, r0\n"
        "mov r2, r0\n"
        "mov r3, r0\n"
        "mov r4, r0\n"
        "mov r5, r0\n"
        "mov r6, r0\n"
        "mov r7, r0\n"
        "mov r8, r0\n"
        "mov r9, r0\n"
        "mov r10, r0\n"
        "mov r11, r0\n"
        "mov r12, r0\n"
        "vmov s0, r0\n"
        "vmov s1, r0\n"
        "vmov s2, r0\n"
        "vmov s3, r0\n"
        "vmov s4, r0\n"
        "vmov s5, r0\n"
        "vmov s6, r0\n"
        "vmov s7, r0\n"
        "vmov s8, r0\n"
        "vmov s9, r0\n"
        "vmov s10, r0\n"
        "vmov s11, r0\n"
        "vmov s12, r0\n"
        "vmov s13, r0\n"
        "vmov s14, r0\n"
        "vmov s15, r0\n"
        "vmov s16, r0\n"
        "vmov s17, r0\n"
        "vmov s18, r0\n"
        "vmov s19, r0\n"
        "vmov s20, r0\n"
        "vmov s21, r0\n"
        "vmov s22, r0\n"
        "vmov s23, r0\n"
        "vmov s24, r0\n"
        "vmov s25, r0\n"
        "vmov s26, r0\n"
        "vmov s27, r0\n"
        "vmov s28, r0\n"
        "vmov s29, r0\n"
        "vmov s30, r0\n"
        "vmov s31, r0\n"
        "vmsr fpscr, r0\n"
        "msr APSR_nzcvqg, r0\n"
        "bxns lr\n"
    );
}
