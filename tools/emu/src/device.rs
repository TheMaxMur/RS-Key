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
use std::sync::atomic::{AtomicU32, Ordering};
#[cfg(test)]
use std::sync::mpsc::RecvError;
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::time::Instant;

use rsk_crypto::Device;
use rsk_device::{AppletHandler, BootState, CcidApplets, Hooks};
use rsk_fs::Fs;

use crate::platform::EmuPlatform;
use crate::presence::{EmuPresence, PresenceMode};
use crate::rng::EmuRng;
use crate::signals::{self, Signals};
use crate::store::EmuStore;

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
/// boot, which it *can* report, because a warm reboot is a thing it really does,
/// and the panel's PIN signal, which it can report on a `--display` run.
pub struct EmuHooks {
    warm: bool,
    /// Set by `EmuDisplayHooks` when the panel re-keyed or refused the clientPIN.
    local_pin: Rc<Cell<bool>>,
}

impl Hooks<EmuStore> for EmuHooks {
    /// Consumed once, exactly as the firmware swaps its `LOCAL_PIN_CHANGED`: the
    /// token dies before the next CBOR command, not before every later one.
    fn local_pin_changed(&mut self) -> bool {
        self.local_pin.replace(false)
    }

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
    pub presence: PresenceMode,
    /// Serve the trusted display in a window; presence becomes an on-screen hold.
    pub display: bool,
    /// Serve USB/IP on this address, so a Linux host sees a real USB device.
    pub usbip: Option<String>,
    pub seed: Option<Vec<u8>>,
    pub serial: [u8; 8],
    pub kv_total: u32,
    pub flash_size: u32,
    pub trace: bool,
    /// Present the Yubico identity: the USB VID/PID and descriptor strings over
    /// `--usbip`, the ATR, and the OpenPGP AID's manufacturer — as the
    /// `VIDPID=Yubikey5` build does. One identity or none: `ykman` finds a device
    /// by the Yubico VID and reads its PID out of the PC/SC reader name.
    pub yubico: bool,
    /// Cut the power after this many bytes of flash writes — `MockFlashBase`'s
    /// own injector, the same one the `power_cut` fuzz target arms.
    pub power_cut: Option<u32>,
}

/// One unit of work for the device thread.
pub enum Job {
    /// CTAPHID_CBOR: a CTAP2 message on channel `cid`.
    Cbor { cid: u32, data: Vec<u8> },
    /// CTAPHID_MSG: a U2F APDU on channel `cid`.
    ///
    /// The channel is carried for the same reason [`Job::Cbor`] carries it: a U2F
    /// REGISTER or AUTHENTICATE waits for a touch, and only the owning channel's
    /// `CTAPHID_CANCEL` may end that wait (CTAP 2.1 §11.2.9.1.4).
    Msg { cid: u32, data: Vec<u8> },
    /// A CTAPHID vendor command (the ykman Management reads).
    Vendor { cmd: u8, data: Vec<u8> },
    /// A CCID APDU.
    Apdu(Vec<u8>),
    /// One keyboard-interface OTP frame: `slot` is the command, `payload` its
    /// 64 bytes. Answers `status_frame(8) ‖ body` — one channel, and the status
    /// frame is fixed-width, so the split is unambiguous.
    OtpHid { slot: u8, payload: Vec<u8> },
    /// The OTP applet's 7-byte status record, for seeding the idle status frame
    /// before the host's first poll.
    OtpStatus,
    /// CTAPHID_INIT: drop anything selected over the MSG transport.
    DeselectMsg,
    /// The card was reset (PC/SC would have re-powered it): drop the selected
    /// applet's security status, so a reconnect really does re-authenticate.
    ResetCard,
    /// The device was unplugged and plugged back in.
    Replug,
}

impl Job {
    /// Whether this is one of the transport requests `firmware/src/worker.rs`
    /// signals `REQ` for — the set an on-panel modal yields to. The keyboard
    /// interface's OTP frames are that worker's separate `OTP_REQ` and the
    /// `CTAPHID_INIT` deselect is an atomic there, so neither closes a modal on a
    /// board; the status read and the replug have no host request behind them.
    /// The board's sixth `REQ` member, a CCID pinpad `Secure`, has no [`Job`]
    /// here — there is no pad to collect on — so it belongs in this set the day
    /// one appears.
    fn is_host_request(&self) -> bool {
        matches!(
            self,
            Job::Cbor { .. } | Job::Msg { .. } | Job::Vendor { .. } | Job::Apdu(_) | Job::ResetCard
        )
    }
}

pub struct Req {
    pub job: Job,
    /// `None` means "no response" (an unsupported vendor command).
    pub reply: Sender<Option<Vec<u8>>>,
}

/// How many host requests are queued for the device thread but not picked up yet.
///
/// The board reads the same fact off `firmware/src/worker.rs`'s `REQ.signaled()`,
/// and an on-panel modal polls it to hand the parked worker its executor back
/// (`rsk_display::Hooks::host_request_pending`). An `mpsc::Receiver` cannot be
/// peeked, so the count is kept by the queue itself rather than by each of the
/// four transports — a fifth one cannot forget what it never had to remember.
#[derive(Clone, Default)]
pub struct Queued(Arc<AtomicU32>);

impl Queued {
    pub fn any(&self) -> bool {
        self.0.load(Ordering::Acquire) > 0
    }

    fn claim(&self) {
        self.0.fetch_add(1, Ordering::Release);
    }

    /// Saturating: a release with nothing outstanding would wrap the count and
    /// leave every modal closing the moment it opened.
    fn release(&self) {
        let _ = self
            .0
            .fetch_update(Ordering::Release, Ordering::Acquire, |n| {
                Some(n.saturating_sub(1))
            });
    }
}

/// The two handles the panel and the worker hold jointly, where a board has two
/// globals: the local-PIN event `EmuHooks` consumes before the next CBOR command
/// (`firmware/src/handler.rs`'s `LOCAL_PIN_CHANGED`), and the USB attach clock a
/// power cycle restarts (`crate::usb_attach`). One clock, not two, is what stops a
/// panel-originated audit entry and a host-originated one from being stamped on
/// different ones — which is the whole point of `Hooks::attach_elapsed_ms`.
#[derive(Clone)]
pub struct PanelLinks {
    pub local_pin: Rc<Cell<bool>>,
    pub attach: Rc<Cell<Instant>>,
}

impl Default for PanelLinks {
    fn default() -> Self {
        Self {
            local_pin: Rc::new(Cell::new(false)),
            attach: Rc::new(Cell::new(Instant::now())),
        }
    }
}

/// The transports' end of the device thread's queue.
#[derive(Clone)]
pub struct Jobs {
    tx: Sender<Req>,
    queued: Queued,
}

impl Jobs {
    /// Queue `job`, to be answered on `reply`. `Err` once the device thread is
    /// gone, which is the only way a send fails.
    pub fn send(&self, job: Job, reply: Sender<Option<Vec<u8>>>) -> Result<(), ()> {
        let counted = job.is_host_request();
        if counted {
            self.queued.claim();
        }
        self.tx.send(Req { job, reply }).map_err(|_| {
            if counted {
                self.queued.release();
            }
        })
    }
}

/// The device thread's end.
pub struct JobSource {
    rx: Receiver<Req>,
    queued: Queued,
}

impl JobSource {
    /// The next queued job, if one is waiting.
    pub fn try_next(&self) -> Result<Req, TryRecvError> {
        self.rx.try_recv().map(|req| self.took(req))
    }

    /// The next queued job, waiting for one. The device loop uses
    /// [`Self::try_next`] because it has a panel loop to interleave with; a
    /// transport's own test has nothing to do between jobs and blocks instead.
    #[cfg(test)]
    pub fn next(&self) -> Result<Req, RecvError> {
        self.rx.recv().map(|req| self.took(req))
    }

    /// Taking a job drops its claim on [`Queued`] — the pickup that clears `REQ`
    /// on the board.
    fn took(&self, req: Req) -> Req {
        if req.job.is_host_request() {
            self.queued.release();
        }
        req
    }

    pub fn queued(&self) -> Queued {
        self.queued.clone()
    }
}

/// The two ends of the device thread's queue, sharing one [`Queued`]. There is no
/// other way to build either, which is what makes the count structural rather than
/// a convention every transport has to keep.
pub fn job_queue() -> (Jobs, JobSource) {
    let (tx, rx) = std::sync::mpsc::channel();
    let queued = Queued::default();
    (
        Jobs {
            tx,
            queued: queued.clone(),
        },
        JobSource { rx, queued },
    )
}

/// Build the device and answer jobs until every sender is gone.
///
/// Everything lives in this one frame because the applets borrow the `RefCell`s
/// for their whole life — the same shape `firmware`'s worker has, for the same
/// reason.
pub fn run(
    cfg: Config,
    jobs: JobSource,
    signals: Arc<Signals>,
    lines: Option<Receiver<String>>,
    taps: Option<crate::taps::TapPad>,
) {
    let store = match crate::store::open(cfg.store.clone(), cfg.power_cut) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("emu: cannot mount the flash image: {e}");
            return;
        }
    };
    // `Box::leak`, not a local: `AppletHandler` requires `PR: 'static`, and the
    // display's `TouchPresence` borrows the store and the DRBG — so those must
    // outlive it. `firmware` reaches the same place with `StaticCell`; either way
    // the process owns them for its whole life.
    let fs: &'static RefCell<Fs<crate::store::EmuStore>> =
        Box::leak(Box::new(RefCell::new(Fs::new(store))));
    let rng: &'static RefCell<EmuRng> = Box::leak(Box::new(RefCell::new(match &cfg.seed {
        Some(s) => EmuRng::from_seed(s),
        None => match EmuRng::from_os() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("emu: no entropy from /dev/urandom: {e}");
                return;
            }
        },
    })));

    // The presence backend is the one thing the two builds disagree about, and it
    // is a *type*, not a value — so the split is here and everything below is
    // generic over it. With `--display` it is the trusted screen in a window,
    // driven by the same `rsk_display` flow the board runs.
    if cfg.display {
        let (parts, quit) = crate::display::open(taps, jobs.queued(), signals.clone());
        let _ = quit;
        serve_display(cfg, jobs, signals, fs, rng, parts);
    } else {
        let presence = RefCell::new(EmuPresence::new(cfg.presence, lines, signals.clone()));
        let links = PanelLinks::default();
        crate::park::block_on(serve(cfg, jobs, signals, links, fs, rng, &presence));
    }
}

/// The `--display` build's wiring: the panel's own loop and the host's, on one
/// executor — the same shape the firmware has, and the reason neither needs a
/// lock: they only ever interleave where the other is not holding a borrow.
///
/// Generic over the panel and the pad because that is what the emulator's own
/// tests substitute (a recording panel, a scripted finger) — the wiring itself,
/// including the `EmuDisplayHooks` → `EmuHooks` PIN signal, stays the one a
/// `--display` run uses.
pub fn serve_display<P, T>(
    cfg: Config,
    jobs: JobSource,
    signals: Arc<Signals>,
    fs: &'static RefCell<Fs<crate::store::EmuStore>>,
    rng: &'static RefCell<EmuRng>,
    parts: crate::display::PanelParts<P, T>,
) where
    P: embedded_graphics::draw_target::DrawTarget<Color = embedded_graphics::pixelcolor::Rgb565>
        + 'static,
    T: rsk_display::TouchPad + 'static,
{
    // Read off the hooks, not passed in beside them: the panel and the worker must
    // hold one pair, and two that do not match fail nothing.
    let links = parts.hooks.links();
    let ui = Box::leak(Box::new(RefCell::new(rsk_display::Ui::new(
        parts.panel,
        parts.touch,
        parts.hooks,
        rsk_display::DeviceInfo {
            version: crate::bcd::BCD_DEVICE,
            chipid: u64::from_le_bytes(cfg.serial),
        },
        fs,
        rsk_display::DeviceKeys {
            serial_id: cfg.serial,
            serial_hash: rsk_crypto::sha256(&cfg.serial),
            mkek_source: None,
        },
        rng,
    ))));
    let presence = RefCell::new(rsk_display::TouchPresence::new(ui));
    crate::park::block_on(embassy_futures::select::select(
        rsk_display::status_loop(ui),
        serve(cfg, jobs, signals, links, fs, rng, &presence),
    ));
}

/// Everything downstream of the presence backend, generic over it.
///
/// Async, and polling rather than blocking on the channel, so the trusted
/// display's ambient loop can share this thread the way `status_task` shares the
/// firmware's thread executor — two futures, one executor, interleaving at each
/// other's await points.
async fn serve<PR: rsk_device::UserPresence + 'static>(
    cfg: Config,
    jobs: JobSource,
    signals: Arc<Signals>,
    links: PanelLinks,
    fs: &'static RefCell<Fs<crate::store::EmuStore>>,
    rng: &'static RefCell<EmuRng>,
    presence: &RefCell<PR>,
) {
    let platform = RefCell::new(EmuPlatform::new());

    let serial_id = cfg.serial;
    let serial_hash = rsk_crypto::sha256(&serial_id);
    // No OTP block and no device key: an emulator has no fuses to hold them, so
    // records are sealed under the chip-serial-only root — the same context a
    // device that has never been provisioned uses.
    let mkek_source: Option<rsk_crypto::FusedKey> = None;
    let devk_source: Option<rsk_crypto::FusedKey> = None;
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

    // The other half of `main.rs`'s boot, and the half a warm reboot must not
    // repeat: advance every plain Yubico-OTP slot's use counter, so the
    // `(use, session)` pair a validation server orders OTPs by cannot recur —
    // the session half restarts at 0 on every power-up. The emulator's power-ups
    // are process start and `Job::Replug`; the warm reboot below skips this, as
    // `!pin_lock::was_warm_boot()` makes the device skip it.
    let power_up_bump = || {
        rsk_otp::power_up_bump(&dev(), &mut fs.borrow_mut(), &mut *rng.borrow_mut());
    };
    power_up_bump();

    // The wiring itself: the same two handlers `firmware`'s worker owns. One vendor
    // platform handle, cloned into both, because the reboot they queue is the same
    // device's — one static there, one `Rc<Cell>` here.
    let hooks = RefCell::new(EmuHooks {
        warm: false,
        local_pin: links.local_pin,
    });
    let vendor_platform = EmuVendorPlatform::default();
    let reboot_requested = vendor_platform.reboot.clone();
    let mut ctap = AppletHandler::new(
        fs,
        rng,
        &hooks,
        presence,
        vendor_platform.clone(),
        serial_id,
        serial_hash,
        mkek_source,
        devk_source,
    );
    let mut ccid = CcidApplets::new(
        fs,
        rng,
        &hooks,
        presence,
        &platform,
        vendor_platform,
        serial_id,
        serial_hash,
        mkek_source,
        devk_source,
        cfg.kv_total,
        cfg.flash_size,
        openpgp_mfr(cfg.yubico),
    );

    // Time is measured from the USB *attach*, not from process start: the CTAP 2.1
    // §6.6 reset window a host has to hit runs from the moment the device could
    // answer at all, so a replug has to restart it (`usb_attach::elapsed_ms`).
    links.attach.set(Instant::now());

    eprintln!("emu: device ready — serial {}", hex(&serial_id));

    loop {
        let req = match jobs.try_next() {
            Ok(req) => req,
            // Nothing queued: yield, so a display loop selected against this one
            // gets to run. 1 ms keeps the socket latency invisible.
            Err(TryRecvError::Empty) => {
                embassy_time::Timer::after_millis(1).await;
                continue;
            }
            Err(TryRecvError::Disconnected) => break,
        };
        let now_ms = links.attach.get().elapsed().as_millis() as u64;
        // Whose a touch wait this job starts would be. One presence backend serves
        // every transport, so without this the FIDO keepalive and the OTP status
        // frame both announce whichever wait is running — `firmware/src/worker.rs`
        // sets the same scope per job kind, for the same reason.
        signals.set_wait_scope(match req.job {
            Job::Cbor { .. } | Job::Msg { .. } | Job::Vendor { .. } => signals::SCOPE_FIDO,
            Job::Apdu(_) | Job::ResetCard => signals::SCOPE_CCID,
            Job::OtpHid { .. } => signals::SCOPE_OTP,
            Job::OtpStatus | Job::DeselectMsg | Job::Replug => signals::SCOPE_NONE,
        });
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
            Job::Msg { cid, data } => {
                signals.begin(cid);
                let body = ctap.handle_msg(&data, now_ms).to_vec();
                signals.end();
                ctap.scrub();
                Some(body)
            }
            // No `begin`/`end`: a vendor command cannot start a touch wait, and
            // `rsk_usb::ctaphid::run_vendor` streams no keepalive and watches for no
            // CANCEL either — so a board cannot cancel one, and bracketing it here
            // would make the emulator answer a cancel the device ignores.
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
            Job::OtpHid { slot, payload } => {
                let mut p = [0u8; 64];
                let n = payload.len().min(64);
                p[..n].copy_from_slice(&payload[..n]);
                let (body, len, status) = ccid.handle_otp_hid(slot, &p);
                ccid.scrub();
                let mut out = status.to_vec();
                out.extend_from_slice(&body[..len]);
                if cfg.trace {
                    eprintln!("emu: otp frame slot={slot:#04x} -> {len} B + status");
                }
                Some(out)
            }
            Job::OtpStatus => Some(ccid.otp_status_record().to_vec()),
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
                power_up_bump();
                hooks.borrow_mut().warm = false;
                ctap = AppletHandler::new(
                    fs,
                    rng,
                    &hooks,
                    presence,
                    EmuVendorPlatform {
                        reboot: reboot_requested.clone(),
                    },
                    serial_id,
                    serial_hash,
                    mkek_source,
                    devk_source,
                );
                ccid.refresh_enabled();
                links.attach.set(Instant::now());
                eprintln!("emu: replugged — fresh session, reset window open");
                Some(Vec::new())
            }
        };
        // Nothing is in flight again, so a wait started from here on is an on-panel
        // flow, which no host may claim or cancel. `firmware/src/worker.rs` lowers
        // the scope at the same point and for the same reason.
        signals.set_wait_scope(signals::SCOPE_NONE);
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
                fs,
                rng,
                &hooks,
                presence,
                EmuVendorPlatform {
                    reboot: reboot_requested.clone(),
                },
                serial_id,
                serial_hash,
                mkek_source,
                devk_source,
            );
            ccid.refresh_enabled();
            eprintln!("emu: warm reboot — RAM state dropped, the reset window stays shut");
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
#[path = "device_tests.rs"]
mod tests;
