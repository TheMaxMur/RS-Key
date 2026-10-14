// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use embassy_time::Timer;
use embassy_usb::driver::{
    self, EndpointAddress, EndpointAllocError, EndpointError, EndpointInfo, EndpointType, Event,
    Unsupported,
};
use rsk_usb::{
    usb_abi as abi,
    worker_abi::{INVALID, PENDING},
};

unsafe extern "C" {
    fn rsk_tz_usb(operation: u32, epoch_or_ticket: u32, buffer: *mut u8, length: u32) -> u32;
}

fn call(operation: u32, argument: u32) -> u32 {
    // SAFETY: operations without payload use no pointer; S validates every selector and argument.
    unsafe { rsk_tz_usb(operation, argument, core::ptr::null_mut(), 0) }
}

fn transfer(operation: u32, argument: u32, buffer: &mut [u8]) -> u32 {
    let Ok(length) = u32::try_from(buffer.len()) else {
        return INVALID;
    };
    // SAFETY: S checks the complete NS RAM span and copies the bounded packet; no pointer is retained.
    unsafe { rsk_tz_usb(operation, argument, buffer.as_mut_ptr(), length) }
}

pub(crate) fn identity() -> Option<rsk_usb::identity::Identity> {
    let mut bytes = [0; rsk_usb::identity::SIZE];
    for (index, chunk) in bytes.chunks_mut(abi::PACKET_SIZE).enumerate() {
        let offset = u32::try_from(index * abi::PACKET_SIZE).ok()?;
        if transfer(abi::IDENTITY, offset, chunk) != u32::try_from(chunk.len()).ok()? {
            return None;
        }
    }
    rsk_usb::identity::Identity::from_bytes(bytes)
}

pub(crate) fn epoch() -> u32 {
    call(abi::EPOCH, 0)
}
fn endpoint(operation: u32, addr: EndpointAddress) -> u32 {
    operation | (u32::from(u8::from(addr)) << abi::ADDRESS_SHIFT)
}
fn result(value: u32) -> Result<usize, EndpointError> {
    match value {
        abi::OVERFLOW => Err(EndpointError::BufferOverflow),
        INVALID | abi::DISABLED => Err(EndpointError::Disabled),
        n => usize::try_from(n).map_err(|_| EndpointError::BufferOverflow),
    }
}
async fn tick() {
    Timer::after_millis(1).await;
}

#[derive(Clone, Copy)]
pub enum Transport {
    Keyboard = 0,
    Fido = 1,
    Ccid = 2,
}
static ALLOCATING: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
static TX_EPOCHS: [core::sync::atomic::AtomicU32; 3] =
    [const { core::sync::atomic::AtomicU32::new(0) }; 3];

pub fn allocate_for(transport: Transport) {
    ALLOCATING.store(transport as u8, core::sync::atomic::Ordering::Relaxed);
}
pub fn bind_response_epoch(transport: Transport, epoch: u32) {
    if let Some(cell) = TX_EPOCHS.get(transport as usize) {
        cell.store(epoch, core::sync::atomic::Ordering::Relaxed);
    }
}
fn tx_epoch(transport: Transport) -> u32 {
    TX_EPOCHS
        .get(transport as usize)
        .map_or(0, |cell| cell.load(core::sync::atomic::Ordering::Relaxed))
}

pub struct Driver;
pub struct Bus;
pub struct Endpoint {
    info: EndpointInfo,
    transport: Transport,
}
pub struct ControlPipe;

impl Driver {
    fn allocate(
        &mut self,
        operation: u32,
        ep_type: EndpointType,
        addr: Option<EndpointAddress>,
        max_packet_size: u16,
        interval_ms: u8,
    ) -> Result<Endpoint, EndpointAllocError> {
        let [lo, hi] = max_packet_size.to_le_bytes();
        let mut config = [ep_type as u8, addr.map_or(0, u8::from), lo, hi, interval_ms];
        let value = transfer(operation, 0, &mut config);
        let address = u8::try_from(value).map_err(|_| EndpointAllocError)?;
        let transport = match ALLOCATING.load(core::sync::atomic::Ordering::Relaxed) {
            0 => Transport::Keyboard,
            1 => Transport::Fido,
            2 => Transport::Ccid,
            _ => return Err(EndpointAllocError),
        };
        Ok(Endpoint {
            transport,
            info: EndpointInfo {
                addr: address.into(),
                ep_type,
                max_packet_size,
                interval_ms,
            },
        })
    }
}
impl<'a> driver::Driver<'a> for Driver {
    type EndpointOut = Endpoint;
    type EndpointIn = Endpoint;
    type ControlPipe = ControlPipe;
    type Bus = Bus;
    fn alloc_endpoint_in(
        &mut self,
        ty: EndpointType,
        addr: Option<EndpointAddress>,
        size: u16,
        interval: u8,
    ) -> Result<Endpoint, EndpointAllocError> {
        self.allocate(abi::ALLOC_IN, ty, addr, size, interval)
    }
    fn alloc_endpoint_out(
        &mut self,
        ty: EndpointType,
        addr: Option<EndpointAddress>,
        size: u16,
        interval: u8,
    ) -> Result<Endpoint, EndpointAllocError> {
        self.allocate(abi::ALLOC_OUT, ty, addr, size, interval)
    }
    fn start(self, max_packet_size: u16) -> (Bus, ControlPipe) {
        call(abi::START, u32::from(max_packet_size));
        (Bus, ControlPipe)
    }
}
impl driver::Bus for Bus {
    async fn enable(&mut self) {
        call(abi::BUS_ENABLE, epoch());
    }
    async fn disable(&mut self) {
        call(abi::BUS_DISABLE, epoch());
    }
    async fn poll(&mut self) -> Event {
        loop {
            match call(abi::BUS_POLL, 0) {
                abi::POWER_DETECTED => return Event::PowerDetected,
                abi::POWER_REMOVED => return Event::PowerRemoved,
                abi::RESET => return Event::Reset,
                abi::SUSPEND => return Event::Suspend,
                abi::RESUME => return Event::Resume,
                _ => tick().await,
            }
        }
    }
    fn endpoint_set_enabled(&mut self, addr: EndpointAddress, enabled: bool) {
        call(
            endpoint(abi::EP_ENABLE, addr) | if enabled { abi::FLAG } else { 0 },
            epoch(),
        );
    }
    fn endpoint_set_stalled(&mut self, addr: EndpointAddress, stalled: bool) {
        call(
            endpoint(abi::EP_STALL, addr) | if stalled { abi::FLAG } else { 0 },
            epoch(),
        );
    }
    fn endpoint_is_stalled(&mut self, addr: EndpointAddress) -> bool {
        call(endpoint(abi::EP_STALLED, addr), epoch()) == 1
    }
    async fn remote_wakeup(&mut self) -> Result<(), Unsupported> {
        Err(Unsupported)
    }
}
impl driver::Endpoint for Endpoint {
    fn info(&self) -> &EndpointInfo {
        &self.info
    }
    async fn wait_enabled(&mut self) {
        while call(endpoint(abi::EP_READY, self.info.addr), epoch()) != 1 {
            tick().await;
        }
    }
}
impl driver::EndpointOut for Endpoint {
    async fn read(&mut self, buffer: &mut [u8]) -> Result<usize, EndpointError> {
        let epoch = epoch();
        let capacity = buffer.len().min(abi::PACKET_SIZE);
        let Some(packet) = buffer.get_mut(..capacity) else {
            return Err(EndpointError::BufferOverflow);
        };
        loop {
            let value = transfer(endpoint(abi::EP_READ, self.info.addr), epoch, packet);
            if value == abi::DISABLED && call(abi::EPOCH, 0) == epoch {
                tick().await;
                continue;
            }
            if value != PENDING {
                return result(value);
            }
            tick().await;
        }
    }
}
impl driver::EndpointIn for Endpoint {
    async fn write(&mut self, data: &[u8]) -> Result<(), EndpointError> {
        let epoch = tx_epoch(self.transport);
        let mut packet = [0; abi::PACKET_SIZE];
        let mut packet = rsk_secret::WipeGuard::new(&mut packet);
        let Some(buffer) = packet.get_mut(..data.len()) else {
            return Err(EndpointError::BufferOverflow);
        };
        buffer.copy_from_slice(data);
        loop {
            let value = transfer(endpoint(abi::EP_WRITE, self.info.addr), epoch, buffer);
            if value == abi::DISABLED && call(abi::EPOCH, 0) == epoch {
                tick().await;
                continue;
            }
            if value != PENDING {
                return result(value).map(|_| ());
            }
            tick().await;
        }
    }
}

struct Pending(u32);
impl Drop for Pending {
    fn drop(&mut self) {
        call(abi::CTRL_ABANDON, self.0);
    }
}

async fn control(
    operation: u32,
    input: &mut [u8],
    output: &mut [u8],
) -> Result<usize, EndpointError> {
    let epoch = epoch();
    let ticket = loop {
        let value = transfer(operation, epoch, input);
        if value == PENDING {
            tick().await;
            continue;
        }
        if value == INVALID || value == abi::DISABLED {
            return Err(EndpointError::Disabled);
        }
        break value;
    };
    let _pending = Pending(ticket);
    loop {
        let value = transfer(abi::CTRL_POLL, ticket, output);
        if value != PENDING {
            return result(value);
        }
        tick().await;
    }
}
impl driver::ControlPipe for ControlPipe {
    fn max_packet_size(&self) -> usize {
        abi::PACKET_SIZE
    }
    async fn setup(&mut self) -> [u8; 8] {
        loop {
            let mut setup = [0; 8];
            if control(abi::CTRL_SETUP, &mut [], &mut setup).await.is_ok() {
                return setup;
            }
            tick().await;
        }
    }
    async fn data_out(
        &mut self,
        buffer: &mut [u8],
        first: bool,
        last: bool,
    ) -> Result<usize, EndpointError> {
        let mut capacity = [u8::try_from(buffer.len()).map_err(|_| EndpointError::BufferOverflow)?];
        control(
            abi::CTRL_OUT | if first { abi::FIRST } else { 0 } | if last { abi::LAST } else { 0 },
            &mut capacity,
            buffer,
        )
        .await
    }
    async fn data_in(&mut self, data: &[u8], first: bool, last: bool) -> Result<(), EndpointError> {
        let mut packet = [0; abi::PACKET_SIZE];
        let mut packet = rsk_secret::WipeGuard::new(&mut packet);
        let Some(buffer) = packet.get_mut(..data.len()) else {
            return Err(EndpointError::BufferOverflow);
        };
        buffer.copy_from_slice(data);
        control(
            abi::CTRL_IN | if first { abi::FIRST } else { 0 } | if last { abi::LAST } else { 0 },
            buffer,
            &mut [],
        )
        .await
        .map(|_| ())
    }
    async fn accept(&mut self) {
        let _ = control(abi::CTRL_ACCEPT, &mut [], &mut []).await;
    }
    async fn reject(&mut self) {
        let _ = control(abi::CTRL_REJECT, &mut [], &mut []).await;
    }
    async fn accept_set_address(&mut self, addr: u8) {
        let _ = control(
            abi::CTRL_ADDRESS | (u32::from(addr) << abi::ADDRESS_SHIFT),
            &mut [],
            &mut [],
        )
        .await;
    }
}
