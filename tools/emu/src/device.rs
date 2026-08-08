// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The emulated device: one thread that owns the file system, the applets and
//! the cross-message FIDO state, and answers one job at a time.
//!
//! This mirrors `firmware/src/{handler,ccid_handler}.rs`, which are the parts of
//! the key that do **not** live in a crate — so this file is the emulator's real
//! divergence risk. Everything it calls into (`process_cbor`, `process_u2f`, the
//! applets, `Fs`) is the same code the device runs; the wiring around them is a
//! second implementation, and a bug that lives in the firmware's wiring will not
//! show up here.
//!
//! Deliberately absent, because there is no hardware under them: the LED, the
//! OTP keyboard interface, the firmware-local vendor applet (LED/bench/reboot),
//! the dual-core RSA keygen fast path (the applets' own single-core path runs
//! instead) and the clientPIN soft-lock's warm-boot canary.

use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender};
use std::time::Instant;

use rsk_crypto::Device;
use rsk_fs::Fs;
use rsk_mgmt::ManagementApplet;
use rsk_oath::OathApplet;
use rsk_openpgp::OpenpgpApplet;
use rsk_otp::OtpApplet;
use rsk_piv::PivApplet;
use rsk_rescue::RescueApplet;
use rsk_sdk::apdu::Apdu;
use rsk_sdk::{Applet, Dispatcher, ResBuf, Sw};

use crate::platform::EmuPlatform;
use crate::presence::EmuPresence;
use crate::rng::EmuRng;
use crate::signals::Signals;
use crate::store::FileStore;

pub type Store = Fs<FileStore>;

/// Response ceiling, sized like the transports': CTAPHID's maximum message for
/// the FIDO side, one CCID frame's payload for the card side.
const CBOR_CAP: usize = rsk_usb::ctaphid::CTAP_MAX_MESSAGE;
const APDU_CAP: usize = 2038;

/// Registration order of the CCID applets and the capability bit that gates each.
/// `0` = never gated: management is the way back from a `ykman config usb
/// --disable`, and rescue is the recovery interface.
///
/// The firmware's array starts with its LED/bench/reboot vendor applet, which is
/// firmware-local and has nothing to drive here — so the indices are the
/// emulator's own, not the device's.
const APPLET_CAPS: [u16; 6] = [
    rsk_mgmt::CAP_OPENPGP,
    0,
    rsk_mgmt::CAP_OATH,
    rsk_mgmt::CAP_OTP,
    rsk_mgmt::CAP_PIV,
    0,
];

pub struct Config {
    pub store: Option<PathBuf>,
    pub touch: bool,
    pub seed: Option<Vec<u8>>,
    pub serial: [u8; 8],
    pub kv_total: u32,
    pub flash_size: u32,
    pub trace: bool,
}

/// One unit of work for the device thread.
pub enum Job {
    /// CTAPHID_CBOR: a CTAP2 message on channel `cid`.
    Cbor { cid: u32, data: Vec<u8> },
    /// CTAPHID_MSG: a U2F APDU.
    Msg(Vec<u8>),
    /// A CTAPHID vendor command (the ykman Management reads).
    Vendor { cmd: u8, data: Vec<u8> },
    /// A CCID APDU.
    Apdu(Vec<u8>),
    /// CTAPHID_INIT: drop anything selected over the MSG transport.
    DeselectMsg,
    /// The card was reset (PC/SC would have re-powered it): drop the selected
    /// applet's security status, so a reconnect really does re-authenticate.
    ResetCard,
    /// The device was unplugged and plugged back in.
    Replug,
}

pub struct Req {
    pub job: Job,
    /// `None` means "no response" (an unsupported vendor command).
    pub reply: Sender<Option<Vec<u8>>>,
}

/// Build the device and answer jobs until every sender is gone.
///
/// Everything lives in this one frame because the applets borrow the `RefCell`s
/// for their whole life — the same shape `firmware`'s worker has, for the same
/// reason.
pub fn run(
    cfg: Config,
    jobs: Receiver<Req>,
    signals: Arc<Signals>,
    lines: Option<Receiver<String>>,
) {
    let store = match FileStore::open(cfg.store.clone()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("emu: cannot open store: {e}");
            return;
        }
    };
    let records = store.len();

    let fs = RefCell::new(Fs::new(store));
    let rng = RefCell::new(match &cfg.seed {
        Some(s) => EmuRng::from_seed(s),
        None => match EmuRng::from_os() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("emu: no entropy from /dev/urandom: {e}");
                return;
            }
        },
    });
    let presence = RefCell::new(EmuPresence::new(cfg.touch, lines, signals.clone()));
    let platform = RefCell::new(EmuPlatform::new());

    let serial_id = cfg.serial;
    let serial_hash = rsk_crypto::sha256(&serial_id);
    // No OTP block and no device key: an emulator has no fuses to hold them, so
    // records are sealed under the chip-serial-only root — the same context a
    // device that has never been provisioned uses.
    let otp_key: Option<[u8; 32]> = None;
    let devk: Option<[u8; 32]> = None;
    let dev = || Device {
        serial_hash: &serial_hash,
        serial_id: &serial_id,
        otp_key: None,
    };

    let mut fido_state = rsk_fido::FidoState::new();
    {
        let mut fsb = fs.borrow_mut();
        let mut rngb = rng.borrow_mut();
        if let Err(e) = rsk_fido::seed::ensure_seed(&dev(), &mut fsb, &mut *rngb) {
            eprintln!("emu: cannot provision the device seed: {e:?}");
            return;
        }
        fido_state.ensure_initialized(&mut *rngb);
    }

    let mut openpgp = OpenpgpApplet::new(serial_id, serial_hash, otp_key, &rng, &presence);
    let mut management = ManagementApplet::new(serial_id, &presence);
    let mut oath = OathApplet::new(serial_id, serial_hash, otp_key, &rng, &presence);
    let mut otp = OtpApplet::new(serial_id, serial_hash, otp_key, &rng, &presence);
    let mut piv = PivApplet::new(serial_id, serial_hash, otp_key, &rng, &presence);
    let mut rescue = RescueApplet::new(
        serial_id,
        serial_hash,
        otp_key,
        devk,
        &rng,
        &platform,
        &presence,
        cfg.kv_total,
        cfg.flash_size,
    );

    // Two dispatchers, because the two transports select independently: a SELECT
    // over CCID must not decide where a U2F command arriving over CTAPHID lands.
    let mut disp_ccid = Dispatcher::new();
    let mut disp_msg = Dispatcher::new();
    let mut enabled_caps = rsk_mgmt::read_enabled_caps(&mut fs.borrow_mut());

    // Time is measured from the USB *attach*, not from process start: the CTAP 2.1
    // §6.6 reset window a host has to hit runs from the moment the device could
    // answer at all, so a replug has to restart it (`usb_attach::elapsed_ms`).
    let mut attach = Instant::now();
    let mut cbor_buf = vec![0u8; CBOR_CAP];
    let mut apdu_buf = vec![0u8; APDU_CAP];

    eprintln!(
        "emu: device ready — serial {}, {records} record(s) in the store",
        hex(&serial_id)
    );

    while let Ok(req) = jobs.recv() {
        let now_ms = attach.elapsed().as_millis() as u64;
        let out = match req.job {
            Job::Cbor { cid, data } => {
                signals.begin(cid);
                fido_state.channel = cid;
                let n = {
                    let mut fsb = fs.borrow_mut();
                    let mut rngb = rng.borrow_mut();
                    let mut presb = presence.borrow_mut();
                    let mut ctx = rsk_fido::Ctx {
                        dev: dev(),
                        fs: &mut fsb,
                        rng: &mut *rngb,
                        state: &mut fido_state,
                        now_ms,
                        presence: &mut *presb,
                    };
                    rsk_fido::process_cbor(&mut ctx, &data, &mut cbor_buf)
                };
                if cfg.trace {
                    eprintln!(
                        "emu: cbor cmd={:#04x} ({} B) -> status={:#04x} ({} B) @{now_ms} ms",
                        data.first().copied().unwrap_or(0),
                        data.len(),
                        cbor_buf.first().copied().unwrap_or(0),
                        n
                    );
                }
                // A phy write changes the USB identity, which a real key only reads
                // at boot; say so instead of silently doing nothing.
                if rsk_fido::vendor::take_phy_written() {
                    eprintln!("emu: phy record written (a real device would re-enumerate now)");
                }
                signals.end();
                Some(cbor_buf[..n].to_vec())
            }
            Job::Msg(data) => {
                signals.begin(0);
                let out = handle_msg(
                    &data,
                    &mut disp_msg,
                    &fs,
                    &rng,
                    &presence,
                    &mut fido_state,
                    dev(),
                    now_ms,
                    &mut apdu_buf,
                );
                signals.end();
                Some(out)
            }
            Job::Vendor { cmd, data } => ctap_mgmt(cmd, &data, &mut management, &fs, &mut apdu_buf),
            Job::Apdu(data) => {
                let mut applets: [&mut dyn Applet<Store>; 6] = [
                    &mut openpgp,
                    &mut management,
                    &mut oath,
                    &mut otp,
                    &mut piv,
                    &mut rescue,
                ];
                disp_ccid.set_enabled(enable_mask(enabled_caps));
                let (sw, n) = {
                    let mut res = ResBuf::new(&mut apdu_buf[..APDU_CAP - 2]);
                    let mut fsb = fs.borrow_mut();
                    let sw = disp_ccid.process(&data, &mut applets, &mut fsb, &mut res);
                    (sw, res.len())
                };
                apdu_buf[n..n + 2].copy_from_slice(&sw.to_bytes());
                if cfg.trace {
                    eprintln!(
                        "emu: apdu {} B -> sw={:02x}{:02x} ({n} B)",
                        data.len(),
                        sw.to_bytes()[0],
                        sw.to_bytes()[1]
                    );
                }
                // A config write flips the dirty latch; the next gated command has
                // to see the new set, exactly as on the device.
                if rsk_mgmt::take_dev_conf_dirty() {
                    enabled_caps = rsk_mgmt::read_enabled_caps(&mut fs.borrow_mut());
                }
                if let Some(bootsel) = platform.borrow_mut().reboot_requested.take() {
                    eprintln!(
                        "emu: host asked for a reboot ({}); the emulator stays up",
                        if bootsel { "to BOOTSEL" } else { "warm" }
                    );
                }
                Some(apdu_buf[..n + 2].to_vec())
            }
            Job::DeselectMsg => {
                disp_msg.clear_selection();
                Some(Vec::new())
            }
            Job::ResetCard => {
                let mut applets: [&mut dyn Applet<Store>; 6] = [
                    &mut openpgp,
                    &mut management,
                    &mut oath,
                    &mut otp,
                    &mut piv,
                    &mut rescue,
                ];
                disp_ccid.reset_card(&mut applets, &mut fs.borrow_mut());
                Some(Vec::new())
            }
            // A power cycle: the store is flash and survives, everything in RAM
            // does not, and the attach clock restarts — which is what reopens the
            // §6.6 reset window that a warm reboot deliberately does not.
            Job::Replug => {
                let mut applets: [&mut dyn Applet<Store>; 6] = [
                    &mut openpgp,
                    &mut management,
                    &mut oath,
                    &mut otp,
                    &mut piv,
                    &mut rescue,
                ];
                disp_ccid.reset_card(&mut applets, &mut fs.borrow_mut());
                disp_msg.clear_selection();
                fido_state = rsk_fido::FidoState::new();
                fido_state.ensure_initialized(&mut *rng.borrow_mut());
                enabled_caps = rsk_mgmt::read_enabled_caps(&mut fs.borrow_mut());
                attach = Instant::now();
                eprintln!("emu: replugged — fresh session, reset window open");
                Some(Vec::new())
            }
        };
        // A disconnected client is not an error: it just stopped listening.
        let _ = req.reply.send(out);
    }
}

/// The `Dispatcher::set_enabled` mask for the current capability set: bit `i` set
/// → applet `i` (in [`APPLET_CAPS`] order) is selectable. A disabled application
/// is invisible, not merely unreported.
fn enable_mask(caps: u16) -> u32 {
    let mut mask = 0u32;
    for (i, &cap) in APPLET_CAPS.iter().enumerate() {
        if rsk_mgmt::cap_enabled(caps, cap) {
            mask |= 1 << i;
        }
    }
    mask
}

/// CTAPHID_MSG: U2F when nothing is selected, mirroring `handler.rs`.
///
/// U2F/CTAP1 has no SELECT of its own, so an unselected non-SELECT APDU is a U2F
/// command. A SELECT can only be for the firmware's vendor AID, which the
/// emulator does not have — so it answers the same "no such applet" the device's
/// dispatcher would.
#[allow(clippy::too_many_arguments)] // one call site; the firmware's twin is a method on a struct
fn handle_msg(
    data: &[u8],
    disp: &mut Dispatcher,
    fs: &RefCell<Store>,
    rng: &RefCell<EmuRng>,
    presence: &RefCell<EmuPresence>,
    state: &mut rsk_fido::FidoState,
    dev: Device<'_>,
    now_ms: u64,
    buf: &mut [u8],
) -> Vec<u8> {
    const INS_SELECT: u8 = 0xA4;
    let Ok(parsed) = Apdu::parse(data) else {
        return Sw::WRONG_LENGTH.to_bytes().to_vec();
    };
    if disp.current().is_some() || parsed.ins == INS_SELECT {
        return Sw::FILE_NOT_FOUND.to_bytes().to_vec();
    }
    let cap = buf.len() - 2;
    let (sw, n) = {
        let mut fsb = fs.borrow_mut();
        let mut rngb = rng.borrow_mut();
        let mut presb = presence.borrow_mut();
        let mut ctx = rsk_fido::Ctx {
            dev,
            fs: &mut fsb,
            rng: &mut *rngb,
            state,
            now_ms,
            presence: &mut *presb,
        };
        rsk_fido::u2f::process_u2f(&mut ctx, &parsed, &mut buf[..cap])
    };
    buf[n..n + 2].copy_from_slice(&sw.to_bytes());
    buf[..n + 2].to_vec()
}

/// The YubiKey Management commands `ykman` sends over the FIDO interface. Only
/// the read is served: WRITE CONFIG over CTAPHID is the firmware's parity arm for
/// a real ykman flow, and an emulator that accepted it would be persisting a
/// device configuration nothing here enumerates from.
fn ctap_mgmt(
    cmd: u8,
    _data: &[u8],
    management: &mut ManagementApplet<'_>,
    fs: &RefCell<Store>,
    buf: &mut [u8],
) -> Option<Vec<u8>> {
    const CTAP_READ_CONFIG: u8 = 0x42;
    if cmd != CTAP_READ_CONFIG {
        return None;
    }
    let n = {
        let mut res = ResBuf::new(buf);
        let mut fsb = fs.borrow_mut();
        management.read_config(&mut fsb, &mut res);
        res.len()
    };
    Some(buf[..n].to_vec())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
