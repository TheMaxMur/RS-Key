// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

pub(crate) const COMMAND: u8 = 0x7e;
const LEGACY_RESET_SESSION: u32 = 7;
static GATEWAYS_CHECKED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

pub(crate) fn gateways_checked() {
    GATEWAYS_CHECKED.store(true, core::sync::atomic::Ordering::Release);
}

pub(crate) fn reply(data: &[u8], out: &mut [u8]) -> Option<usize> {
    let value = match data {
        b"gateways" => u32::from(GATEWAYS_CHECKED.load(core::sync::atomic::Ordering::Acquire)),
        b"epoch" => super::usb::epoch(),
        b"reset" => {
            super::session::late_reset_callback();
            super::usb::epoch()
        }
        b"legacy-reset" => super::session::control(LEGACY_RESET_SESSION, 0),
        b"arm-abort" => u32::from(super::session::probe_abort(true)),
        b"abort" => u32::from(super::session::probe_abort(false)),
        _ => return None,
    };
    let bytes = value.to_le_bytes();
    out.get_mut(..bytes.len())?.copy_from_slice(&bytes);
    Some(bytes.len())
}
