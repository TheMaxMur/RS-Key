// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::{Controller, ENDPOINTS, abi, bulk, once, outcome};
use embassy_usb::driver::{
    Bus as _, Direction, Driver as _, Endpoint as _, EndpointAddress, EndpointIn as _,
    EndpointOut as _, EndpointType,
};
use rsk_usb::worker_abi::INVALID;

pub(super) fn allocate(state: &mut Controller, incoming: bool, data: &[u8]) -> u32 {
    let [ty, addr, lo, hi, interval] = data else {
        return INVALID;
    };
    let ty = match *ty {
        2 => EndpointType::Bulk,
        3 => EndpointType::Interrupt,
        _ => return INVALID,
    };
    let size = u16::from_le_bytes([*lo, *hi]);
    if size == 0 || size > abi::PACKET_SIZE_U16 {
        return INVALID;
    }
    let direction = if incoming {
        Direction::In
    } else {
        Direction::Out
    };
    let address = if *addr == 0 {
        None
    } else {
        let address = EndpointAddress::from(*addr);
        if address.index() == 0 || address.index() >= ENDPOINTS || address.direction() != direction
        {
            return INVALID;
        }
        Some(address)
    };
    let Some(driver) = state.driver.as_mut() else {
        return INVALID;
    };
    if incoming {
        let Ok(endpoint) = driver.alloc_endpoint_in(ty, address, size, *interval) else {
            return INVALID;
        };
        let addr = endpoint.info().addr;
        let Some(slot) = state.input.get_mut(addr.index()) else {
            return INVALID;
        };
        *slot = Some(endpoint);
        u32::from(u8::from(addr))
    } else {
        let Ok(endpoint) = driver.alloc_endpoint_out(ty, address, size, *interval) else {
            return INVALID;
        };
        let addr = endpoint.info().addr;
        let Some(slot) = state.output.get_mut(addr.index()) else {
            return INVALID;
        };
        *slot = Some(endpoint);
        u32::from(u8::from(addr))
    }
}

pub(super) fn retry_eligible(state: &Controller, operation: u32, data: &[u8]) -> bool {
    let Ok(address) = u8::try_from((operation >> abi::ADDRESS_SHIFT) & 0xff) else {
        return false;
    };
    let index = EndpointAddress::from(address).index();
    if index >= ENDPOINTS {
        return false;
    }
    let endpoint_type = state
        .input
        .get(index)
        .and_then(Option::as_ref)
        .map(|endpoint| endpoint.info().ep_type);
    rsk_usb::bulk_retry::eligible(
        operation,
        data.len(),
        endpoint_type,
        (state.bulk_retiring | state.bulk_zlp) & (1 << index) != 0,
    )
}

pub(super) fn operate(state: &mut Controller, operation: u32, data: &mut [u8]) -> u32 {
    let Ok(byte) = u8::try_from((operation >> abi::ADDRESS_SHIFT) & 0xff) else {
        return INVALID;
    };
    let addr = EndpointAddress::from(byte);
    let index = addr.index();
    if index >= ENDPOINTS {
        return INVALID;
    }
    let allocated = if addr.is_in() {
        state.input.get(index).is_some_and(Option::is_some)
    } else {
        state.output.get(index).is_some_and(Option::is_some)
    };
    let action = operation & 0xff;
    if !(allocated || (index == 0 && matches!(action, abi::EP_STALL | abi::EP_STALLED))) {
        return INVALID;
    }
    let request_waiting =
        action == abi::EP_WRITE && data.is_empty() && bulk::request_waiting(state);
    let Some(bus) = state.bus.as_mut() else {
        return INVALID;
    };
    match action {
        abi::EP_ENABLE => {
            bus.endpoint_set_enabled(addr, operation & abi::FLAG != 0);
            0
        }
        abi::EP_STALL => {
            bus.endpoint_set_stalled(addr, operation & abi::FLAG != 0);
            0
        }
        abi::EP_STALLED => u32::from(bus.endpoint_is_stalled(addr)),
        abi::EP_READY | abi::EP_READ | abi::EP_WRITE => {
            if !state.bus_epoch.accepts(state.bus_epoch.current()) {
                return if action == abi::EP_READY {
                    0
                } else {
                    abi::DISABLED
                };
            }
            if addr.is_in() {
                let Some(endpoint) = state.input.get_mut(index).and_then(Option::as_mut) else {
                    return INVALID;
                };
                if once(endpoint.wait_enabled()).is_pending() {
                    return if action == abi::EP_READY {
                        0
                    } else {
                        abi::DISABLED
                    };
                }
                match action {
                    abi::EP_READY => 1,
                    abi::EP_WRITE => {
                        if state.bulk_retiring & (1 << index) != 0 {
                            return rsk_usb::worker_abi::PENDING;
                        }
                        let zlp = data.is_empty() && endpoint.info().ep_type == EndpointType::Bulk;
                        if zlp && request_waiting {
                            return 0;
                        }
                        let value = outcome(once(async { endpoint.write(data).await.map(|()| 0) }));
                        if zlp && value == 0 {
                            state.bulk_zlp |= 1 << index;
                        }
                        value
                    }
                    _ => INVALID,
                }
            } else {
                let Some(endpoint) = state.output.get_mut(index).and_then(Option::as_mut) else {
                    return INVALID;
                };
                if once(endpoint.wait_enabled()).is_pending() {
                    return if action == abi::EP_READY {
                        0
                    } else {
                        abi::DISABLED
                    };
                }
                match action {
                    abi::EP_READY => 1,
                    abi::EP_READ => outcome(once(endpoint.read(data))),
                    _ => INVALID,
                }
            }
        }
        _ => INVALID,
    }
}
