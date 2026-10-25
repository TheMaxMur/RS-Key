// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::Controller;
use embassy_usb::driver::{Endpoint as _, EndpointType};

pub(super) fn request_waiting(state: &Controller) -> bool {
    state.output.iter().enumerate().any(|(index, endpoint)| {
        endpoint.as_ref().is_some_and(|endpoint| {
            let buffer = rp_pac::USB_DPRAM.ep_out_buffer_control(index).read();
            endpoint.info().ep_type == EndpointType::Bulk && buffer.full(0) && buffer.length(0) != 0
        })
    })
}

pub(super) fn observe(state: &mut Controller) {
    if state.bulk_zlp == 0 {
        return;
    }
    let request = request_waiting(state);
    for index in 1..super::ENDPOINTS {
        let bit = 1 << index;
        if state.bulk_zlp & bit == 0 {
            continue;
        }
        let mask = 1 << (index * 2);
        let buffer = rp_pac::USB_DPRAM.ep_in_buffer_control(index).read();
        if state.bulk_retiring & bit == 0 {
            if !buffer.available(0) {
                state.bulk_zlp &= !bit;
                continue;
            }
            if !request {
                continue;
            }
            // A new command proves the host finished its previous read without the ZLP.
            rp_pac::USB.ep_abort().modify(|value| value.0 |= mask);
            state.bulk_retiring |= bit;
        }
        if rp_pac::USB.ep_abort_done().read().0 & mask == 0 {
            continue;
        }
        let buffer = rp_pac::USB_DPRAM.ep_in_buffer_control(index).read();
        if buffer.available(0) {
            // An unconsumed packet must not advance the data toggle.
            rp_pac::USB_DPRAM
                .ep_in_buffer_control(index)
                .write(|value| {
                    value.set_pid(0, !buffer.pid(0));
                });
        }
        rp_pac::USB.ep_abort_done().write(|value| value.0 = mask);
        rp_pac::USB.ep_abort().modify(|value| value.0 &= !mask);
        state.bulk_zlp &= !bit;
        state.bulk_retiring &= !bit;
    }
}
