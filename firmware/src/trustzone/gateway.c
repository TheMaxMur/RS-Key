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
