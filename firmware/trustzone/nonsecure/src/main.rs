// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_std]
#![no_main]
#![expect(unsafe_code, reason = "NS board glue; docs/unsafe.md lists every site")]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use rsk_usb::worker_abi as abi;
#[cfg(feature = "test-gateway-probes")]
mod diagnostics;
mod keyboard;
mod notify;
#[cfg(feature = "test-hostile-access")]
mod probe;
mod reply;
mod session;
#[path = "../../../src/sweep/buffer.rs"]
mod sweep_buffer;
mod time;
mod usb;

use embassy_executor::InterruptExecutor;
use embassy_rp::{
    interrupt,
    interrupt::{InterruptExt, Priority},
};
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, mutex::Mutex};
use embassy_usb::{
    Builder, Config, UsbDevice,
    class::hid::{self, HidReaderWriter, HidWriter, State},
};
use panic_halt as _;
use rsk_usb::{
    ccid::{ApduHandler, Ccid, SecureResult},
    ctaphid::{CtapHid, MsgHandler},
};
use static_cell::StaticCell;

type Drv = usb::Driver;

struct LocalCriticalSection;
critical_section::set_impl!(LocalCriticalSection);
// SAFETY: transport tasks run on core0 only; this masks their NS interrupts without sharing Secure's spinlock.
unsafe impl critical_section::Impl for LocalCriticalSection {
    unsafe fn acquire() -> bool {
        let enabled = cortex_m::register::primask::read().is_active();
        cortex_m::interrupt::disable();
        enabled
    }
    unsafe fn release(enabled: bool) {
        if enabled {
            // SAFETY: restore the interrupt state saved by acquire on this same NS core.
            unsafe {
                cortex_m::interrupt::enable();
            }
        }
    }
}

unsafe extern "C" {
    fn rsk_tz_submit(kind: u32, cid: u32, request: *const u8, length: u32) -> u32;
    fn rsk_tz_poll(ticket: u32, response: *mut u8, capacity: u32) -> u32;
    fn rsk_tz_control(action: u32, ticket: u32) -> u32;
}

static LOCK: Mutex<CriticalSectionRawMutex, ()> = Mutex::new(());
const FIDO_REPLY_BYTES: usize = rsk_usb::ctaphid::CTAP_MAX_MESSAGE + abi::REPLY_HEADER;
const CCID_REPLY_BYTES: usize =
    rsk_usb::ccid::MAX_CCID_MSG - rsk_usb::ccid::HEADER + abi::REPLY_HEADER;

struct Reply {
    len: usize,
    vendor_ok: bool,
    status: u8,
    error: u8,
}

#[expect(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "rsk-usb bounds host slices; checked SG sentinel/length replies are Secure ABI invariants"
)]
async fn exchange<const REPLY_BYTES: usize>(
    kind: u32,
    cid: u32,
    data: &[u8],
    out: &mut [u8],
) -> Reply {
    let _lock = LOCK.lock().await;
    let epoch = session::epoch();
    let length = u32::try_from(data.len()).unwrap();
    let ticket = loop {
        let observed = notify::generation();
        // SAFETY: SG validates the slice range and copies it into Secure-owned storage.
        let status = unsafe { rsk_tz_submit(kind, cid, data.as_ptr(), length) };
        if status != abi::PENDING && status != abi::INVALID {
            break status;
        }
        assert_eq!(status, abi::PENDING);
        if session::epoch() != epoch {
            return Reply::abandoned();
        }
        notify::wait(observed).await;
    };
    let _pending = session::Pending::new(ticket, kind);
    let mut buffer = [0u8; REPLY_BYTES];
    let mut reply = reply::ReplyGuard::new(&mut buffer);
    let len = loop {
        let observed = notify::generation();
        // SAFETY: the whole output slice is valid NS RAM for the gateway to fill.
        let n = unsafe {
            rsk_tz_poll(
                ticket,
                reply.as_mut_ptr(),
                u32::try_from(reply.len()).unwrap(),
            )
        };
        if n == abi::ABANDONED || session::epoch() != epoch {
            return Reply::abandoned();
        }
        if n != abi::PENDING {
            assert_ne!(n, abi::INVALID);
            break usize::try_from(n).unwrap();
        }
        notify::wait(observed).await;
    };
    let body = &reply[abi::REPLY_HEADER..len];
    assert!(body.len() <= out.len());
    out[..body.len()].copy_from_slice(body);
    Reply {
        len: body.len(),
        vendor_ok: reply[0] != 0,
        status: reply[1],
        error: reply[2],
    }
}

impl Reply {
    fn abandoned() -> Self {
        Self {
            len: 0,
            vendor_ok: false,
            status: rsk_usb::ccid::STATUS_FAILED,
            error: rsk_usb::ccid::CMD_ABORTED,
        }
    }
}

fn up_pending() -> bool {
    // SAFETY: this SG entry exposes only a presence-status bit.
    session::control(abi::UP_PENDING, 0) != 0
}
fn cancel() {
    // SAFETY: Secure permits cancellation only of the active FIDO wait.
    session::cancel_fido();
}

struct CtapClient;
impl MsgHandler for CtapClient {
    fn bind_response_epoch(epoch: u32) {
        usb::bind_response_epoch(usb::Transport::Fido, epoch);
    }
    fn session_epoch() -> u32 {
        session::epoch()
    }
    fn cancel_processing() -> bool {
        true
    }
    fn reset_app_selection(&mut self) {
        // SAFETY: the gateway only queues the Secure worker's deselection flag.
        session::control(abi::DESELECT_MSG, 0);
    }
    async fn handle_cbor(&mut self, cid: u32, data: &[u8], out: &mut [u8]) -> usize {
        exchange::<FIDO_REPLY_BYTES>(abi::CBOR, cid, data, out)
            .await
            .len
    }
    async fn handle_msg(&mut self, cid: u32, data: &[u8], out: &mut [u8]) -> usize {
        exchange::<FIDO_REPLY_BYTES>(abi::MSG, cid, data, out)
            .await
            .len
    }
    async fn handle_vendor(
        &mut self,
        _: u32,
        cmd: u8,
        data: &[u8],
        out: &mut [u8],
    ) -> Option<usize> {
        #[cfg(feature = "test-gateway-probes")]
        if cmd == diagnostics::COMMAND {
            return diagnostics::reply(data, out);
        }
        let r =
            exchange::<FIDO_REPLY_BYTES>(abi::VENDOR | (u32::from(cmd) << 8), 0, data, out).await;
        r.vendor_ok.then_some(r.len)
    }
    fn can_wink(&self) -> bool {
        session::control(abi::CAN_WINK, 0) != 0
    }
    fn wink(&mut self) {
        session::control(abi::WINK, 0);
    }
}

struct CcidClient;
impl ApduHandler for CcidClient {
    fn bind_response_epoch(epoch: u32) {
        usb::bind_response_epoch(usb::Transport::Ccid, epoch);
    }
    fn session_epoch() -> u32 {
        session::epoch()
    }
    fn abort_requested(sequence: u8) -> bool {
        session::abort(sequence)
    }
    fn abort_pending() -> bool {
        session::abort_pending()
    }
    fn acknowledge_abort(sequence: u8) -> Option<bool> {
        session::acknowledge_abort(sequence)
    }
    async fn handle_apdu(&mut self, data: &[u8], out: &mut [u8]) -> usize {
        exchange::<CCID_REPLY_BYTES>(abi::APDU, 0, data, out)
            .await
            .len
    }
    async fn reset_card(&mut self) {
        exchange::<{ abi::REPLY_HEADER }>(abi::RESET_CARD, 0, &[], &mut []).await;
    }
    async fn handle_secure(&mut self, data: &[u8], out: &mut [u8]) -> SecureResult {
        let r = exchange::<CCID_REPLY_BYTES>(abi::SECURE_PIN, 0, data, out).await;
        SecureResult {
            len: r.len,
            status: r.status,
            error: r.error,
        }
    }
}

static EXECUTOR: InterruptExecutor = InterruptExecutor::new();
#[unsafe(no_mangle)]
extern "C" fn SWI_IRQ_1() {
    // SAFETY: this is the interrupt assigned to the NS transport executor.
    unsafe {
        EXECUTOR.on_interrupt();
    }
}

struct SendUsb(UsbDevice<'static, Drv>);
// SAFETY: moved once to the NS interrupt executor; all handlers use NS-local synchronization.
unsafe impl Send for SendUsb {}
#[embassy_executor::task]
async fn usb_task(mut usb: SendUsb) {
    usb.0.run().await;
}
#[embassy_executor::task]
async fn ctap_task(ctap: &'static mut CtapHid<'static, Drv, CtapClient>) {
    ctap.run().await;
}
#[embassy_executor::task]
async fn ccid_task(ccid: &'static mut Ccid<'static, Drv, CcidClient>) {
    ccid.run().await;
}
#[cortex_m_rt::entry]
fn main() -> ! {
    cortex_m::interrupt::free(|_| init());
    loop {
        cortex_m::asm::wfi();
    }
}

// Return the startup frame before transport tasks and USB IRQs use the NS stack.
#[inline(never)]
#[allow(
    clippy::unwrap_used,
    reason = "one-time startup consumes fixed resources"
)]
fn init() {
    assert!(!embassy_rp::rom_data::is_secure_mode());
    #[cfg(feature = "test-gateway-probes")]
    gateway_probes();
    time::init();
    let driver = usb::Driver;
    static IDENTITY: StaticCell<rsk_usb::identity::Identity> = StaticCell::new();
    let identity = IDENTITY.init(usb::identity().unwrap());
    let mut config = Config::new(identity.vid().unwrap(), identity.pid().unwrap());
    config.manufacturer = identity.manufacturer();
    config.product = identity.product();
    config.serial_number = identity.serial();
    config.device_release = identity.release().unwrap();
    config.max_power = 100;
    config.max_packet_size_0 = 64;
    static DESCRIPTORS: StaticCell<[u8; 256]> = StaticCell::new();
    static BOS: StaticCell<[u8; 256]> = StaticCell::new();
    static MSOS: StaticCell<[u8; 64]> = StaticCell::new();
    static CONTROL: StaticCell<[u8; 64]> = StaticCell::new();
    let mut builder = Builder::new(
        driver,
        config,
        DESCRIPTORS.init([0; 256]),
        BOS.init([0; 256]),
        MSOS.init([0; 64]),
        CONTROL.init([0; 64]),
    );
    static KEYBOARD: StaticCell<State> = StaticCell::new();
    static KEYBOARD_HANDLER: StaticCell<keyboard::Handler> = StaticCell::new();
    usb::allocate_for(usb::Transport::Keyboard);
    let keyboard = (identity.interfaces() & rsk_phy::USB_ITF_KB != 0).then(|| {
        HidWriter::<_, 8>::new(
            &mut builder,
            KEYBOARD.init(State::new()),
            hid::Config {
                report_descriptor: rsk_usb::kbd::KEYBOARD_REPORT_DESCRIPTOR,
                request_handler: Some(KEYBOARD_HANDLER.init(keyboard::Handler)),
                poll_ms: 10,
                max_packet_size: 8,
                hid_subclass: hid::HidSubclass::No,
                hid_boot_protocol: hid::HidBootProtocol::None,
            },
        )
    });
    static HID: StaticCell<State> = StaticCell::new();
    usb::allocate_for(usb::Transport::Fido);
    let hid = (identity.interfaces() & rsk_phy::USB_ITF_HID != 0).then(|| {
        HidReaderWriter::<_, 64, 64>::new(
            &mut builder,
            HID.init(State::new()),
            hid::Config {
                report_descriptor: rsk_usb::ctaphid::FIDO_REPORT_DESCRIPTOR,
                request_handler: None,
                poll_ms: 1,
                max_packet_size: 64,
                hid_subclass: hid::HidSubclass::No,
                hid_boot_protocol: hid::HidBootProtocol::None,
            },
        )
    });
    static CCID: StaticCell<Ccid<'static, Drv, CcidClient>> = StaticCell::new();
    usb::allocate_for(usb::Transport::Ccid);
    let ccid = (identity.interfaces() & rsk_phy::USB_ITF_CCID != 0).then(|| {
        let atr = if identity.yubico_atr() {
            rsk_usb::ccid::ATR_YUBIKEY
        } else {
            rsk_usb::ccid::ATR_RSKEY
        };
        CCID.init_with(|| {
            Ccid::new(
                &mut builder,
                CcidClient,
                atr,
                u8::from(identity.pinpad_verify()),
            )
        })
    });
    static USB_HANDLER: StaticCell<session::UsbHandler> = StaticCell::new();
    builder.handler(USB_HANDLER.init(session::UsbHandler {
        ccid_interface: ccid.as_ref().map(|ccid| ccid.interface_number()),
    }));
    let usb = builder.build();
    static CTAP: StaticCell<CtapHid<'static, Drv, CtapClient>> = StaticCell::new();
    let ctap = hid.map(|hid| {
        let (reader, writer) = hid.split();
        CTAP.init_with(|| CtapHid::new(reader, writer, CtapClient, up_pending, cancel))
    });
    notify::init();
    interrupt::SWI_IRQ_1.set_priority(Priority::P2);
    let spawner = EXECUTOR.start(interrupt::SWI_IRQ_1);
    spawner.spawn(usb_task(SendUsb(usb)).unwrap());
    #[cfg(feature = "test-hostile-access")]
    spawner.spawn(probe::after_usb().unwrap());
    if let Some(ctap) = ctap {
        spawner.spawn(ctap_task(ctap).unwrap());
    }
    if let Some(ccid) = ccid {
        spawner.spawn(ccid_task(ccid).unwrap());
    }
    if let Some(keyboard) = keyboard {
        spawner.spawn(keyboard::run(keyboard).unwrap());
        spawner.spawn(keyboard::commands().unwrap());
    }
}

#[cfg(feature = "test-gateway-probes")]
fn gateway_probes() {
    let probe = [0u8; 32];
    // SAFETY: invalid pointers are intentional probes of the hardware-checked SG entries.
    unsafe {
        assert_eq!(
            rsk_tz_submit(abi::CBOR, 0, 0x2000_0000 as *const u8, 32),
            abi::INVALID
        );
        assert_eq!(rsk_tz_poll(1, 0x2000_0000 as *mut u8, 32), abi::INVALID);
        assert_eq!(
            rsk_tz_submit(abi::CBOR, 0, 0x2007_fff0 as *const u8, 32),
            abi::INVALID
        );
        assert_eq!(rsk_tz_submit(0xff, 0, probe.as_ptr(), 32), abi::INVALID);
    }
}
