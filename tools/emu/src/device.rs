// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The emulated device: one thread that owns the file system, the applet wiring
//! and the cross-message FIDO state, and answers one job at a time.
//!
//! The wiring is `rsk-device` — the same `AppletHandler` and `CcidApplets` the
//! firmware runs, not a second implementation of them. What is left here is this
//! build's half: the store, the DRBG, the presence prompt, and the [`Hooks`] that
//! answer for hardware it does not have. The worker's own sequencing (refresh the
//! capability set when the dirty latch is up, run a queued reboot only after the
//! response is out) is mirrored from `firmware/src/worker.rs` and is the one thing
//! still written twice.
//!
//! Deliberately absent, because there is no hardware under them: the LED, the OTP
//! keyboard interface, the vendor applet's LED / core1 / bench arms, the dual-core
//! RSA keygen accelerator (the applets' own single-core path runs instead) and the
//! watchdog register that carries the clientPIN soft lock across a warm reset.

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender};
use std::time::Instant;

use rsk_crypto::Device;
use rsk_device::{AppletHandler, BootState, CcidApplets, Hooks};
use rsk_fs::Fs;

use crate::platform::EmuPlatform;
use crate::presence::EmuPresence;
use crate::rng::EmuRng;
use crate::signals::Signals;
use crate::store::FileStore;

/// The OpenPGP AID's manufacturer field, chosen by the same rule the firmware
/// applies to its effective VID (`openpgp_mfr_for`): the Yubico identity is a
/// whole identity, not just an ATR, and a half-applied one would answer as two
/// different cards depending on which DO you read.
fn openpgp_mfr(yubico: bool) -> u16 {
    if yubico {
        rsk_openpgp::consts::OPGP_MFR_YUBICO
    } else {
        rsk_openpgp::consts::OPGP_MFR_UNMANAGED
    }
}

/// What the vendor applet can reach here. The counter is portable and runs; the
/// LED, the second core and the timing benches are hardware this has none of, so
/// they keep the trait's "not supported". The warm reboot is real — RAM state is
/// dropped — but there is no bootloader to fall into, so `bootsel` is refused
/// rather than answered with an OK for a step that never happened.
#[derive(Clone, Default)]
pub struct EmuVendorPlatform {
    reboot: Rc<Cell<bool>>,
}

impl rsk_vendor::Platform for EmuVendorPlatform {
    fn request_reboot(&mut self, bootsel: bool) -> bool {
        if bootsel {
            return false;
        }
        self.reboot.set(true);
        true
    }
}

/// What `rsk-device` reaches back into the board for. The emulator has none of
/// that hardware, so every method keeps the trait's default — except the warm
/// boot, which it *can* report, because a warm reboot is a thing it really does.
#[derive(Default)]
pub struct EmuHooks {
    warm: bool,
}

impl Hooks<FileStore> for EmuHooks {
    /// The phy record was rewritten. A real key re-enumerates under its new USB
    /// identity here; this one can only say so.
    fn request_reboot(&mut self) {
        eprintln!("emu: phy record written (a real device would re-enumerate now)");
    }

    fn boot_state(&mut self) -> BootState {
        // The soft lock stays default: there is no register here that survives a
        // reset, so every boot starts the PIN batch clean. A device carries it.
        BootState {
            warm: self.warm,
            ..BootState::default()
        }
    }
}

pub struct Config {
    pub store: Option<PathBuf>,
    pub touch: bool,
    pub seed: Option<Vec<u8>>,
    pub serial: [u8; 8],
    pub kv_total: u32,
    pub flash_size: u32,
    pub trace: bool,
    /// Present the Yubico card identity — the ATR and the OpenPGP AID's
    /// manufacturer — as a build carrying the Yubico VID does.
    pub yubico: bool,
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
        // `main.rs`'s boot block, in its order. The seal migrations are no-ops
        // without an OTP root, but they are what a device runs and cost nothing
        // here; `scan_files` is not optional at all — it lays down the OpenPGP
        // data objects, and without it the applet answers SELECT and then serves
        // an empty PW-status DO.
        let _ = rsk_fido::seed::migrate_keydev_boot(&dev(), &mut fsb);
        rsk_rescue::keydev::migrate_kbase(&dev(), &mut fsb, &mut *rngb);
        rsk_piv::migrate_kbase(&dev(), &mut fsb, &mut *rngb);
        rsk_oath::migrate_seal(&dev(), &mut fsb, &mut *rngb);
        rsk_otp::migrate_seal(&dev(), &mut fsb, &mut *rngb);
        rsk_fido::credential::migrate_rp_seal(&dev(), &mut fsb);
        if let Err(e) = rsk_fido::seed::ensure_seed(&dev(), &mut fsb, &mut *rngb) {
            eprintln!("emu: cannot provision the device seed: {e:?}");
            return;
        }
        let _ = rsk_openpgp::scan_files(&dev(), &mut fsb, &mut *rngb);
        fido_state.ensure_initialized(&mut *rngb);
    }

    // The wiring itself: the same two handlers `firmware`'s worker owns. One vendor
    // platform handle, cloned into both, because the reboot they queue is the same
    // device's — one static there, one `Rc<Cell>` here.
    let hooks = RefCell::new(EmuHooks::default());
    let vendor_platform = EmuVendorPlatform::default();
    let reboot_requested = vendor_platform.reboot.clone();
    let mut ctap = AppletHandler::new(
        &fs,
        &rng,
        &hooks,
        &presence,
        vendor_platform.clone(),
        serial_id,
        serial_hash,
        otp_key,
        devk,
    );
    let mut ccid = CcidApplets::new(
        &fs,
        &rng,
        &hooks,
        &presence,
        &platform,
        vendor_platform,
        serial_id,
        serial_hash,
        otp_key,
        devk,
        cfg.kv_total,
        cfg.flash_size,
        openpgp_mfr(cfg.yubico),
    );

    // Time is measured from the USB *attach*, not from process start: the CTAP 2.1
    // §6.6 reset window a host has to hit runs from the moment the device could
    // answer at all, so a replug has to restart it (`usb_attach::elapsed_ms`).
    let mut attach = Instant::now();

    eprintln!(
        "emu: device ready — serial {}, {records} record(s) in the store",
        hex(&serial_id)
    );

    while let Ok(req) = jobs.recv() {
        let now_ms = attach.elapsed().as_millis() as u64;
        let out = match req.job {
            Job::Cbor { cid, data } => {
                signals.begin(cid);
                let body = ctap.handle_cbor(cid, &data, now_ms).to_vec();
                signals.end();
                // The response buffer can hold a PIN token; the device scrubs it
                // once the worker has handed the bytes off, so do it here.
                ctap.scrub();
                if cfg.trace {
                    eprintln!(
                        "emu: cbor cmd={:#04x} ({} B) -> status={:#04x} ({} B) @{now_ms} ms",
                        data.first().copied().unwrap_or(0),
                        data.len(),
                        body.first().copied().unwrap_or(0),
                        body.len()
                    );
                }
                Some(body)
            }
            Job::Msg(data) => {
                signals.begin(0);
                let body = ctap.handle_msg(&data, now_ms).to_vec();
                signals.end();
                ctap.scrub();
                Some(body)
            }
            Job::Vendor { cmd, data } => {
                let body = ccid.ctap_mgmt(cmd, &data).map(<[u8]>::to_vec);
                ccid.scrub();
                body
            }
            Job::Apdu(data) => {
                let body = ccid.handle_apdu(&data).to_vec();
                ccid.scrub();
                if cfg.trace {
                    eprintln!(
                        "emu: apdu {} B -> sw={:02x}{:02x} ({} B)",
                        data.len(),
                        body[body.len() - 2],
                        body[body.len() - 1],
                        body.len() - 2
                    );
                }
                Some(body)
            }
            Job::DeselectMsg => {
                ctap.deselect_msg();
                Some(Vec::new())
            }
            Job::ResetCard => {
                ccid.reset_card();
                Some(Vec::new())
            }
            // A power cycle: the store is flash and survives, everything in RAM
            // does not, and the attach clock restarts — which is what reopens the
            // §6.6 reset window that a warm reboot deliberately does not.
            Job::Replug => {
                ccid.reset_card();
                hooks.borrow_mut().warm = false;
                ctap = AppletHandler::new(
                    &fs,
                    &rng,
                    &hooks,
                    &presence,
                    EmuVendorPlatform {
                        reboot: reboot_requested.clone(),
                    },
                    serial_id,
                    serial_hash,
                    otp_key,
                    devk,
                );
                ccid.refresh_enabled();
                attach = Instant::now();
                eprintln!("emu: replugged — fresh session, reset window open");
                Some(Vec::new())
            }
        };
        // A disconnected client is not an error: it just stopped listening.
        let _ = req.reply.send(out);

        // The worker's own sequencing, mirrored: a config write flips the dirty
        // latch and every gate has to see the new set before the next request.
        if rsk_mgmt::take_dev_conf_dirty() {
            ccid.refresh_enabled();
        }
        // Both reboot paths — the vendor applet's INS_REBOOT and the rescue
        // applet's twin — land in one queue on the device, and both run only after
        // the response is out. A warm reboot drops RAM state and leaves the attach
        // clock alone: only a power cycle reopens the §6.6 window, which is the
        // whole distinction `Job::Replug` carries.
        let rescue_reboot = platform.borrow_mut().reboot_requested.take();
        if let Some(true) = rescue_reboot {
            eprintln!("emu: host asked for BOOTSEL; there is no bootloader to fall into");
        }
        if reboot_requested.replace(false) || rescue_reboot == Some(false) {
            ccid.reset_card();
            hooks.borrow_mut().warm = true;
            ctap = AppletHandler::new(
                &fs,
                &rng,
                &hooks,
                &presence,
                EmuVendorPlatform {
                    reboot: reboot_requested.clone(),
                },
                serial_id,
                serial_hash,
                otp_key,
                devk,
            );
            ccid.refresh_enabled();
            eprintln!("emu: warm reboot — RAM state dropped, the reset window stays shut");
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
