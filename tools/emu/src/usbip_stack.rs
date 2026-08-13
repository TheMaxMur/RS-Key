// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The device's own USB stack, run over USB/IP.
//!
//! `--usbip` builds what the firmware builds — the same `embassy_usb::Builder`,
//! the same three interfaces in the same order, the same `rsk_usb::ctaphid` and
//! `rsk_usb::ccid` transports — on top of [`crate::usbip_driver`]. So a Linux
//! host that attaches gets `/dev/hidraw*` and a PC/SC reader, and what it reads
//! out of them is the device's description of itself, not a second one written
//! for the emulator.
//!
//! The two socket transports (`hid.rs`, `ccid.rs`) stay: they need no kernel and
//! no root, and they are what `tests/emu.py` drives. This is the path for what a
//! socket cannot be — a browser, `ykman`, `gpg`, and the interface order issue
//! #55 turned on.
//!
//! It runs on its own thread with its own executor, the way the board runs its
//! transports on the interrupt executor and its applets on the thread executor:
//! the classes keep streaming keepalives while the device thread sits inside slow
//! crypto, because their handlers only queue a job and then yield.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::mpsc::{self, Sender};

use embassy_usb::class::hid::{
    Config as HidConfig, HidBootProtocol, HidReaderWriter, HidSubclass, HidWriter,
    State as HidState,
};
use embassy_usb::{Builder, Config as UsbConfig};

use rsk_usb::ccid::{ApduHandler, Ccid};
use rsk_usb::ctaphid::{CtapHid, FIDO_REPORT_DESCRIPTOR, HID_RPT_SIZE, MsgHandler};

use crate::device::{Job, Jobs, Unplug};
use crate::signals::Signals;
use crate::usbip::{Ret, Urb, UrbSink, UsbDeviceInfo};
use crate::usbip_driver::UsbIpDriver;

/// The USB identity a default firmware build carries (`VIDPID=RSKey`), because
/// the point of this path is that a host treats the emulator the way it treats a
/// device: udev rules, browser allow-lists and `ykman` all key off the pair. The
/// product string says which it is, and the serial (`RSKEMU\0\1`) already makes
/// every value derived from it recognisably the emulator's.
const VID: u16 = 0x1209;
const PID: u16 = 0x0001;
const MANUFACTURER: &str = "RS-Key";
/// Deliberately not a board serial: everything derived from it is the
/// emulator's, and the Yubico identity keeps it so a masquerade still says which
/// device answered.
const SERIAL: &str = "rs-key-emu";
const PRODUCT: &str = "RS-Key Security Key (emulator)";

/// The Yubico interop identity, matching the firmware's `VIDPID=Yubikey5` build.
///
/// `--yubico` is one identity or none: `ykman` and Yubico Authenticator find a
/// device by the Yubico VID and read its PID from the PC/SC reader name, so a
/// build that answers with the Yubico ATR under a pid.codes VID is a card those
/// tools cannot see at all. The firmware ties the ATR, the OpenPGP AID vendor and
/// the descriptor strings to one effective VID for exactly this reason.
const YUBICO_VID: u16 = 0x1050;
const YUBICO_PID: u16 = 0x0407;
const YUBICO_MANUFACTURER: &str = "Yubico";
const YUBICO_PRODUCT: &str = "YubiKey RSK OTP+FIDO+CCID";

/// The four descriptor fields that follow the effective VID.
const fn identity(yubico: bool) -> (u16, u16, &'static str, &'static str) {
    if yubico {
        (YUBICO_VID, YUBICO_PID, YUBICO_MANUFACTURER, YUBICO_PRODUCT)
    } else {
        (VID, PID, MANUFACTURER, PRODUCT)
    }
}

/// Descriptor scratch, sized as the firmware sizes it.
const CONFIG_DESC_LEN: usize = 256;
const BOS_DESC_LEN: usize = 256;
const MSOS_DESC_LEN: usize = 64;
const CONTROL_BUF_LEN: usize = 64;

/// A descriptor string has to fit the control buffer, and `embassy-usb` finds out
/// the hard way: it *asserts* mid-transfer, which here kills the USB thread and on
/// a device would be `panic_halt` with the host still waiting. `USB_STR_MAX` is
/// exactly what [`CONTROL_BUF_LEN`] allows (2 header bytes + 2 per UTF-16 unit),
/// which is why the phy record clamps to it — so the emulator borrows the same
/// ceiling and the same compile-time check the firmware has, rather than
/// discovering it from a host that stopped enumerating.
const _: () = assert!(PRODUCT.len() <= rsk_rescue::phy::USB_STR_MAX);
const _: () = assert!(YUBICO_PRODUCT.len() <= rsk_rescue::phy::USB_STR_MAX);
const _: () = assert!(MANUFACTURER.len() <= rsk_rescue::phy::USB_STR_MAX);
const _: () = assert!(YUBICO_MANUFACTURER.len() <= rsk_rescue::phy::USB_STR_MAX);
const _: () = assert!(SERIAL.len() <= rsk_rescue::phy::USB_STR_MAX);

/// The keyboard interface's report size (the boot-keyboard 8-byte report).
const KBD_RPT_SIZE: usize = 8;

/// The FIDO transport's touch and cancel hooks are `fn()` pointers — they carry
/// no state here for the same reason they carry none on the device.
static SIGNALS: OnceLock<Arc<Signals>> = OnceLock::new();

fn up_pending() -> bool {
    SIGNALS
        .get()
        .is_some_and(|s| s.up_pending_for(crate::signals::SCOPE_FIDO))
}

/// `CtapHid` only calls this for a `CTAPHID_CANCEL` whose channel is the one in
/// flight — it checks the frame's cid first — so cancelling "the active command"
/// is the same scoping the per-channel form gives.
fn request_cancel() {
    if let Some(s) = SIGNALS.get() {
        s.cancel_active();
    }
}

/// Hand a job to the device thread and wait for its answer without blocking the
/// executor.
///
/// The polling is the point: this future is what `CtapHid` races its keepalive
/// against, so a blocking `recv` would stop the keepalives for the whole length
/// of a makeCredential and the host would give up mid-ceremony.
pub async fn run_job(jobs: &Jobs, job: Job) -> Option<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    jobs.send(job, tx).ok()?;
    loop {
        match rx.try_recv() {
            Ok(out) => return out,
            Err(mpsc::TryRecvError::Empty) => embassy_time::Timer::after_millis(1).await,
            Err(mpsc::TryRecvError::Disconnected) => return None,
        }
    }
}

fn copy_out(body: &[u8], out: &mut [u8]) -> usize {
    let n = body.len().min(out.len());
    out[..n].copy_from_slice(&body[..n]);
    n
}

/// The FIDO interface's half: it runs no applet, it queues one — the same split
/// the firmware has between its transport executor and its worker.
struct HidJobs(Jobs);

impl MsgHandler for HidJobs {
    async fn handle_msg(&mut self, cid: u32, apdu: &[u8], out: &mut [u8]) -> usize {
        let job = Job::Msg {
            cid,
            data: apdu.to_vec(),
        };
        match run_job(&self.0, job).await {
            Some(body) => copy_out(&body, out),
            None => 0,
        }
    }

    async fn handle_cbor(&mut self, cid: u32, data: &[u8], out: &mut [u8]) -> usize {
        let job = Job::Cbor {
            cid,
            data: data.to_vec(),
        };
        match run_job(&self.0, job).await {
            Some(body) => copy_out(&body, out),
            None => 0,
        }
    }

    async fn handle_vendor(&mut self, cmd: u8, data: &[u8], out: &mut [u8]) -> Option<usize> {
        let job = Job::Vendor {
            cmd,
            data: data.to_vec(),
        };
        run_job(&self.0, job).await.map(|body| copy_out(&body, out))
    }

    /// The terminal is this build's indicator, the same one the socket transport
    /// claims — so the capability bit is honest and `CTAPHID_WINK` does something
    /// visible, rather than the two transports disagreeing about whether the same
    /// emulator has anything to flash.
    fn can_wink(&self) -> bool {
        true
    }

    fn wink(&mut self) {
        eprintln!("emu: ✨ wink");
    }

    fn reset_app_selection(&mut self) {
        // Synchronous, so there is nothing to await the answer with; the queue is
        // one queue, so the device thread still runs it before the next command.
        let (tx, _rx) = mpsc::channel();
        let _ = self.0.send(Job::DeselectMsg, tx);
    }
}

/// The card interface's half. `handle_secure` keeps the trait's default: there is
/// no on-device pad on this path, and `bPINSupport` below says so.
struct CardJobs(Jobs);

impl ApduHandler for CardJobs {
    async fn handle_apdu(&mut self, apdu: &[u8], out: &mut [u8]) -> usize {
        match run_job(&self.0, Job::Apdu(apdu.to_vec())).await {
            Some(body) => copy_out(&body, out),
            None => 0,
        }
    }

    async fn reset_card(&mut self) {
        run_job(&self.0, Job::ResetCard).await;
    }
}

/// The device this emulator presents to a USB/IP client, matching the descriptors
/// [`declare`] builds. The kernel reads these *before* it issues a single
/// GET_DESCRIPTOR, to size its own model of the device.
pub fn device_info(yubico: bool) -> UsbDeviceInfo {
    let (vid, pid, _, _) = identity(yubico);
    UsbDeviceInfo {
        path: "/sys/devices/rsk-emu/usb1/1-1",
        busid: crate::usbip::BUSID,
        busnum: 1,
        devnum: 1,
        speed: 2, // full speed, like the RP2350
        id_vendor: vid,
        id_product: pid,
        bcd_device: crate::bcd::BCD_DEVICE,
        device_class: 0,
        device_subclass: 0,
        device_protocol: 0,
        configuration_value: 1,
        num_configurations: 1,
        num_interfaces: INTERFACES.len() as u8,
    }
}

/// The interface list, in the order [`declare`] builds them: keyboard/OTP, FIDO,
/// CCID. The ORDER is the point — issue #55 was a host going blind when it
/// changed — and `the_devlist_matches_the_descriptors` holds this against the
/// config descriptor itself rather than against a second reading of the intent.
pub const INTERFACES: [[u8; 3]; 3] = [
    // The keyboard declares NO boot subclass or protocol — the device does not
    // either (`HidSubclass::No` / `HidBootProtocol::None`), so it is `03/00/00`
    // and not the `03/01/01` a boot keyboard would be. `ykpers`/`ykcore` finds it
    // by interface *number*, which is the whole reason the order matters.
    [0x03, 0x00, 0x00], // HID — keyboard / OTP
    [0x03, 0x00, 0x00], // HID — FIDO
    [0x0b, 0x00, 0x00], // smart card — CCID
];

/// Declare the device on `builder`, in the firmware's order.
///
/// The keyboard (OTP) interface is built FIRST so it lands on interface 0 like a
/// stock YubiKey: the libusb backend `ykpers`/`ykcore` ships — KeePassXC,
/// `ykchalresp`, `pam_yubico` — claims interface 0 and sends the OTP frame
/// reports there blind. That reorder is what fixed issue #55, and it is only real
/// if it is the order the descriptors carry.
#[allow(clippy::type_complexity)] // three classes, returned once, to one caller
fn declare<'d>(
    builder: &mut Builder<'d, UsbIpDriver>,
    kbd_state: &'d mut HidState<'d>,
    fido_state: &'d mut HidState<'d>,
    otp: Option<&'d mut crate::otp_kbd::OtpHandler>,
    jobs: &Jobs,
    atr: &'static [u8],
) -> (
    HidWriter<'d, UsbIpDriver, KBD_RPT_SIZE>,
    HidReaderWriter<'d, UsbIpDriver, HID_RPT_SIZE, HID_RPT_SIZE>,
    Ccid<'d, UsbIpDriver, CardJobs>,
) {
    let kbd = HidWriter::new(
        builder,
        kbd_state,
        HidConfig {
            report_descriptor: rsk_usb::kbd::KEYBOARD_REPORT_DESCRIPTOR,
            // The OTP frame protocol — the `ykman otp` transport — rides this
            // interface's feature reports, exactly as on the board.
            request_handler: otp.map(|h| h as &'d mut dyn embassy_usb::class::hid::RequestHandler),
            poll_ms: 10,
            max_packet_size: KBD_RPT_SIZE as u16,
            hid_subclass: HidSubclass::No,
            hid_boot_protocol: HidBootProtocol::None,
        },
    );
    let fido = HidReaderWriter::new(
        builder,
        fido_state,
        HidConfig {
            report_descriptor: FIDO_REPORT_DESCRIPTOR,
            request_handler: None,
            poll_ms: 1,
            max_packet_size: HID_RPT_SIZE as u16,
            hid_subclass: HidSubclass::No,
            hid_boot_protocol: HidBootProtocol::None,
        },
    );
    // `bPINSupport = 0`: no pad. `--display` does give the emulator a touchscreen,
    // but the card interface would then have to collect the PIN on it and does
    // not — advertising VERIFY would light up a host flow that collects nothing.
    let ccid = Ccid::new(builder, CardJobs(jobs.clone()), atr, 0x00);
    (kbd, fido, ccid)
}

fn usb_config(yubico: bool) -> UsbConfig<'static> {
    let (vid, pid, manufacturer, product) = identity(yubico);
    let mut config = UsbConfig::new(vid, pid);
    config.manufacturer = Some(manufacturer);
    config.product = Some(product);
    config.serial_number = Some(SERIAL);
    config.max_power = 100;
    config.max_packet_size_0 = 64;
    config.device_release = crate::bcd::BCD_DEVICE;
    config
}

/// The USB/IP port, plus the one thing a real key does that the transport cannot
/// express: an attach is a power-up.
///
/// The CTAP 2.1 §6.6 reset window runs from the moment the device could answer at
/// all, and on a board that is boot. Here the process can have been running for
/// hours before a host imports it, so measuring from process start would leave the
/// window already shut the first time anyone looked — `authenticatorReset` would
/// answer `NOT_ALLOWED` forever. An attach is also the only analogue this build has
/// of `tests/replug.py`'s physical unplug, and it is what the socket transport's
/// own replug opcode already means: RAM state goes, the card is reset, the clock
/// restarts.
struct PoweredPort {
    inner: crate::usbip_driver::Port,
    jobs: Jobs,
}

impl UrbSink for PoweredPort {
    fn attach(&mut self, rets: Sender<Ret>) {
        // A host's, not an operator's: `listen` accepts imports in an unbounded
        // loop, so this is repeatable at TCP-connect rate and must not be the
        // un-floored kind an open modal yields to at once.
        let (tx, _rx) = mpsc::channel();
        let _ = self.jobs.send(Job::Replug(Unplug::Host), tx);
        self.inner.attach(rets);
    }
    fn submit(&mut self, urb: Urb) {
        self.inner.submit(urb);
    }
    fn unlink(&mut self, seqnum: u32) -> bool {
        self.inner.unlink(seqnum)
    }
    fn detach(&mut self) {
        self.inner.detach();
    }
}

/// Build the device, then serve USB/IP on `addr` for as long as the process runs.
///
/// Two threads: this one runs the USB stack's executor, the listener's runs the
/// socket. They meet only in `usbip_driver`'s shared state.
// The three futures below never resolve, so neither does `block_on` and neither
// does this function; `!` is not writable as a return type on stable, so the
// unreachable end has to be allowed rather than declared away.
#[allow(unreachable_code)]
pub fn serve(addr: String, jobs: Jobs, signals: Arc<Signals>, yubico: bool) {
    let _ = SIGNALS.set(signals.clone());
    let atr: &'static [u8] = if yubico {
        rsk_usb::ccid::ATR_YUBIKEY
    } else {
        rsk_usb::ccid::ATR_RSKEY
    };

    // Leaked, not stack-held: `Builder` hands `&'d` out to the classes, and the
    // device outlives every frame here. `StaticCell` is where the board puts it.
    let (driver, port) = crate::usbip_driver::new();
    let mut builder = Builder::new(
        driver,
        usb_config(yubico),
        Box::leak(Box::new([0u8; CONFIG_DESC_LEN])),
        Box::leak(Box::new([0u8; BOS_DESC_LEN])),
        Box::leak(Box::new([0u8; MSOS_DESC_LEN])),
        Box::leak(Box::new([0u8; CONTROL_BUF_LEN])),
    );
    let otp = crate::otp_kbd::OtpKbd::new();
    let (_kbd, fido, mut ccid) = declare(
        &mut builder,
        Box::leak(Box::new(HidState::new())),
        Box::leak(Box::new(HidState::new())),
        Some(Box::leak(Box::new(otp.handler(signals.clone())))),
        &jobs,
        atr,
    );
    let mut usb = builder.build();
    let (reader, writer) = fido.split();
    let mut ctap = CtapHid::new(
        reader,
        writer,
        HidJobs(jobs.clone()),
        up_pending,
        request_cancel,
    );

    let mut port = PoweredPort {
        inner: port,
        jobs: jobs.clone(),
    };
    std::thread::spawn(move || {
        if let Err(e) = crate::usbip::listen(&addr, &device_info(yubico), &INTERFACES, &mut port) {
            eprintln!("emu: cannot serve USB/IP on {addr}: {e}");
        }
    });

    // One executor, four futures, the way the board arranges them — except that
    // the board's applets sit on a second executor and here they sit on a second
    // thread. `_kbd` is only held: a ticket is typed by a button gesture and this
    // build has no button, so the keyboard's IN endpoint stays silent while its
    // feature reports carry the frame protocol.
    crate::park::block_on(embassy_futures::join::join4(
        usb.run(),
        ctap.run(),
        ccid.run(),
        crate::otp_kbd::run(otp, jobs, signals),
    ));
}

#[cfg(test)]
#[path = "usbip_stack_tests.rs"]
mod tests;
