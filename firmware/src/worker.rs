// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Cross-executor compute worker: the slow, *synchronous* applet dispatch (FIDO
//! crypto, flash GC, on-card RSA keygen) runs here on the low-priority thread
//! executor. A transport hands a request over via [`EXCHANGE`] + [`REQ`], `.await`s
//! [`DONE`] (streaming a keepalive meanwhile, on its high-priority task), then reads
//! the response back; [`WORKER_LOCK`] serializes the two transports, so the worker
//! is the single point of flash access and only one request is ever in flight.

use core::cell::RefCell;

use embassy_futures::select::{Either3, select3};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_sync::signal::Signal;
use embassy_time::{Duration, Instant};
use zeroize::Zeroize;

use rsk_crypto::FusedKey;
use rsk_device::click::Clicks;
use rsk_usb::ccid::{ApduHandler, SecureResult};
use rsk_usb::ctaphid::{CTAP_MAX_MESSAGE, MsgHandler};

use crate::handler::{Ccid, Ctap, DeviceHooks, FidoRng, Store};
use crate::otp_kbd;
use crate::presence::Presence;

/// A worker request carries a full CTAPHID message at most; responses match —
/// an ML-DSA-44 makeCredential response runs ~4 KB, and getInfo advertises
/// `maxMsgSize` = the transport maximum.
const REQ_CAP: usize = CTAP_MAX_MESSAGE;
const RESP_CAP: usize = CTAP_MAX_MESSAGE;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Cbor,
    Msg,
    Apdu,
    /// A CCID `PC_to_RDR_Secure` (pinpad VERIFY): the PIN is collected on the
    /// device's screen, the VERIFY runs internally, only the status word returns.
    /// `Exchange::sec_status`/`sec_error` carry the CCID `bStatus`/`bError` back.
    Secure,
    /// A CTAPHID vendor command (YubiKey Management read) — `Exchange::vcmd` holds
    /// the logical command number.
    Vendor,
    /// An ICC power transition: drop the CCID applet selection and its security
    /// status. Carries no payload and returns none — the dispatcher state it clears
    /// lives on the worker, which is why it needs a round-trip at all.
    ResetCard,
}

/// The shared request/response buffer the transport fills and the worker drains.
struct Exchange {
    kind: Kind,
    /// CTAPHID channel the request arrived on (`Cbor` only); 0 for the transports
    /// with no channel concept. Cross-message FIDO state that another channel must
    /// not be able to hijack — the seed-backup MSE key — binds to it.
    cid: u32,
    /// Logical vendor command number when `kind == Vendor`.
    vcmd: u8,
    /// Worker → transport: whether the vendor command was supported (`Vendor` only).
    vendor_ok: bool,
    /// Worker → transport: CCID `bStatus`/`bError` for the reply (`Secure` only).
    sec_status: u8,
    sec_error: u8,
    req_len: usize,
    req: [u8; REQ_CAP],
    resp_len: usize,
    resp: [u8; RESP_CAP],
}

type Cs = CriticalSectionRawMutex;

static EXCHANGE: Mutex<Cs, Exchange> = Mutex::new(Exchange {
    kind: Kind::Cbor,
    cid: 0,
    vcmd: 0,
    vendor_ok: false,
    sec_status: 0,
    sec_error: 0,
    req_len: 0,
    req: [0; REQ_CAP],
    resp_len: 0,
    resp: [0; RESP_CAP],
});
/// Serializes the two transports — only one request is processed at a time.
static WORKER_LOCK: Mutex<Cs, ()> = Mutex::new(());
/// Transport → worker: a request is ready in [`EXCHANGE`].
static REQ: Signal<Cs, ()> = Signal::new();
/// Worker → transport: the response is ready in [`EXCHANGE`].
static DONE: Signal<Cs, ()> = Signal::new();
/// Transport → worker: a CTAPHID_INIT started a fresh session, so the worker must
/// drop any applet selected over the MSG transport before the next U2F/CTAP1
/// command (U2F has no SELECT and must not inherit a sticky vendor selection).
/// Set on the high-priority transport, consumed by the worker; the INIT→next-MSG
/// ordering (the client waits for the INIT reply) makes Relaxed sufficient.
static MSG_DESELECT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Whether host work is queued for the worker but not yet picked up. The
/// trusted-display browse modals (Passkeys / Settings) poll this: while one is open
/// the worker is parked on the single thread executor, so a host command would wait
/// behind it — yielding back to idle the instant one arrives lets the worker run,
/// which is a precise alternative to capping the wait with a blind inactivity timeout.
///
/// **Every host-request source [`Worker::run`] races belongs here**, not only the
/// transports': `rsk_display::tests::every_worker_wake_source_is_classified` holds
/// the two lists together. The INIT deselect is an atomic; the tick is our own.
#[cfg(feature = "display")]
pub(crate) fn host_request_pending() -> bool {
    REQ.signaled() || otp_kbd::OTP_REQ.signaled()
}

/// [`host_request_pending`], but only once the UI has been idle for
/// [`crate::display::UI_YIELD_FLOOR_MS`] — pass the modal's last-touch instant.
///
/// The floor is the whole point and every modal exit poll must use this form. A
/// bare `host_request_pending()` lets a host close the screen on its FIRST poll,
/// so an unprivileged process looping an ungated `authenticatorGetInfo` denies the
/// owner the entire on-device browse and menu layer (audit run-35). The floor was
/// written for exactly that and had been applied at 2 of 26 sites.
#[cfg(feature = "display")]
pub(crate) fn host_request_pending_after(since: embassy_time::Instant) -> bool {
    host_request_pending()
        && since.elapsed() >= embassy_time::Duration::from_millis(crate::display::UI_YIELD_FLOOR_MS)
}

/// Hand `data` to the worker as `kind`, await its response, copy it into `out`,
/// return the length. The caller (a transport on the high-priority executor) wraps
/// the `DONE.wait()` in a keepalive `select`, so keepalives keep flowing while the
/// worker is blocked in synchronous crypto / flash.
async fn roundtrip(kind: Kind, cid: u32, data: &[u8], out: &mut [u8]) -> usize {
    let _serialize = WORKER_LOCK.lock().await;
    {
        let mut ex = EXCHANGE.lock().await;
        let n = data.len().min(REQ_CAP);
        ex.kind = kind;
        ex.cid = cid;
        ex.req_len = n;
        ex.req[..n].copy_from_slice(&data[..n]);
    }
    REQ.signal(());
    DONE.wait().await;
    let mut ex = EXCHANGE.lock().await;
    let n = ex.resp_len.min(out.len());
    out[..n].copy_from_slice(&ex.resp[..n]);
    // The response can carry secrets (PIN tokens, deciphered session keys);
    // don't leave them in the static exchange buffer.
    let m = ex.resp_len;
    ex.resp[..m].zeroize();
    ex.resp_len = 0;
    n
}

/// Hand a vendor command to the worker and await its response. Like [`roundtrip`]
/// but carries the logical command number and returns `None` when the worker
/// reports the command unsupported (so the transport replies `CTAPHID_ERROR`).
async fn roundtrip_vendor(cmd: u8, data: &[u8], out: &mut [u8]) -> Option<usize> {
    let _serialize = WORKER_LOCK.lock().await;
    {
        let mut ex = EXCHANGE.lock().await;
        let n = data.len().min(REQ_CAP);
        ex.kind = Kind::Vendor;
        ex.vcmd = cmd;
        ex.vendor_ok = true;
        ex.req_len = n;
        ex.req[..n].copy_from_slice(&data[..n]);
    }
    REQ.signal(());
    DONE.wait().await;
    let mut ex = EXCHANGE.lock().await;
    if !ex.vendor_ok {
        ex.resp_len = 0;
        return None;
    }
    let n = ex.resp_len.min(out.len());
    out[..n].copy_from_slice(&ex.resp[..n]);
    let m = ex.resp_len;
    ex.resp[..m].zeroize();
    ex.resp_len = 0;
    Some(n)
}

/// Hand a CCID `PC_to_RDR_Secure` payload to the worker and await its response.
/// Like [`roundtrip`] but returns the [`SecureResult`] (the CCID `bStatus`/`bError`
/// the worker chose for a card result vs. a pad cancel/timeout) alongside the body.
async fn roundtrip_secure(data: &[u8], out: &mut [u8]) -> SecureResult {
    let _serialize = WORKER_LOCK.lock().await;
    {
        let mut ex = EXCHANGE.lock().await;
        let n = data.len().min(REQ_CAP);
        ex.kind = Kind::Secure;
        ex.req_len = n;
        ex.req[..n].copy_from_slice(&data[..n]);
    }
    REQ.signal(());
    DONE.wait().await;
    let mut ex = EXCHANGE.lock().await;
    let n = ex.resp_len.min(out.len());
    out[..n].copy_from_slice(&ex.resp[..n]);
    let (status, error) = (ex.sec_status, ex.sec_error);
    // The response holds only a status word, but wipe it from the static buffer
    // along with the rest of the roundtrip discipline.
    let m = ex.resp_len;
    ex.resp[..m].zeroize();
    ex.resp_len = 0;
    SecureResult {
        len: n,
        status,
        error,
    }
}

/// CTAPHID client handler (runs on the high-priority executor) — forwards to the
/// worker. Holds no state; the applet layer + flash live in the [`Worker`].
pub struct ClientCtap;

impl MsgHandler for ClientCtap {
    async fn handle_cbor(&mut self, cid: u32, data: &[u8], out: &mut [u8]) -> usize {
        roundtrip(Kind::Cbor, cid, data, out).await
    }
    async fn handle_msg(&mut self, cid: u32, data: &[u8], out: &mut [u8]) -> usize {
        roundtrip(Kind::Msg, cid, data, out).await
    }
    fn reset_app_selection(&mut self) {
        MSG_DESELECT.store(true, core::sync::atomic::Ordering::Release);
    }
    async fn handle_vendor(&mut self, cmd: u8, data: &[u8], out: &mut [u8]) -> Option<usize> {
        roundtrip_vendor(cmd, data, out).await
    }
    /// Only a build with an indicator claims WINK; a `LED_KIND=none` board (and the
    /// display build, which the panel forces to that) has nothing to flash, so it
    /// leaves the bit clear rather than answering an invisible wink.
    fn can_wink(&self) -> bool {
        cfg!(not(led_kind = "none"))
    }
    /// Straight to the LED atomics — the burst is rendered by the blink task on the
    /// high-priority executor, so this never parks the transport.
    fn wink(&mut self) {
        #[cfg(not(led_kind = "none"))]
        crate::led::wink();
    }
}

/// CCID client handler (high-priority executor) — forwards to the worker.
pub struct ClientCcid;

impl ApduHandler for ClientCcid {
    async fn handle_apdu(&mut self, apdu: &[u8], out: &mut [u8]) -> usize {
        roundtrip(Kind::Apdu, 0, apdu, out).await
    }
    async fn handle_secure(&mut self, data: &[u8], out: &mut [u8]) -> SecureResult {
        roundtrip_secure(data, out).await
    }
    async fn reset_card(&mut self) {
        let mut sink = [0u8; 2];
        roundtrip(Kind::ResetCard, 0, &[], &mut sink).await;
    }
}

/// The on-screen title + the policy minimum PIN length for a pinpad VERIFY,
/// chosen from the template's `P2` (which PIN the host is verifying). The minimum
/// is the universal floor of 6 for every reference — never higher than the
/// shortest PIN a user could have set, so the pad can't lock out a valid PIN; the
/// applet enforces its own real minimum and reports a wrong/blocked status word.
#[cfg(feature = "display")]
fn secure_pin_meta(p2: u8) -> Option<(&'static str, usize)> {
    // No generic "Enter PIN" fallback: a reference no applet here implements gets
    // refused rather than painted under a label that names nothing (audit run-36).
    let title = match p2 {
        rsk_openpgp::consts::PW1_MODE81 => "OpenPGP Sign PIN",
        rsk_openpgp::consts::PW1_MODE82 => "OpenPGP PIN",
        rsk_openpgp::consts::PW3_MODE83 => "OpenPGP Admin PIN",
        rsk_usb::secure_pin::PIV_PIN_P2 => crate::display::piv_ref_title(rsk_piv::PinRef::Pin),
        _ => return None,
    };
    Some((title, 6))
}

/// The compute worker (low-priority thread executor): owns the applet layer and
/// the shared flash `Fs` / TRNG (through `'static` `RefCell`s, borrowed only inside
/// one synchronous dispatch), and runs each request to completion while the
/// high-priority transports stream keepalives.
pub struct Worker<'a> {
    ctap: Ctap<'a>,
    ccid: Ccid<'a>,
    /// The TRNG/DRBG, kept for the secure-reboot wipe (the DRBG state is the one
    /// long-lived RAM secret outside the applet layer).
    rng: &'a RefCell<FidoRng>,
    /// The presence backend (BOOTSEL button, or the screen on a `display` build),
    /// for the typed-ticket press watcher and the same backend the applets borrow
    /// for touch confirmation, behind the shared `RefCell`.
    presence: &'a RefCell<Presence>,
    /// The idle click gesture. Host-tested in `rsk_device::click`, because its one
    /// load-bearing rule — a press a ceremony consumed is not a click — is pure
    /// logic over a level and a clock.
    clicks: Clicks,
    /// CTAPHID channel the last `Kind::Msg` arrived on. The MSG applet selection is
    /// one global for every channel and U2F has no SELECT of its own, so a change
    /// of channel drops it — otherwise another process's SELECT of the vendor AID
    /// silently redirected the victim's REGISTER/AUTHENTICATE (audit run-34 #27).
    last_msg_cid: Option<u32>,
}

/// Button-watcher poll cadence; also the idle tick that lets the
/// worker re-arm the press timer between requests.
const BTN_POLL_MS: u64 = 16;

impl<'a> Worker<'a> {
    /// `presence` is the one BOOTSEL button, shared (through its `RefCell`) by the
    /// FIDO handler (CTAP user presence), the OpenPGP applet (the UIF DOs), the
    /// OTP applet (CHAL_BTN_TRIG) and the OATH applet (PROP_TOUCH credentials) —
    /// the `&RefCell<ButtonPresence>` coerces to each applet's `UserPresence`
    /// trait.
    #[allow(clippy::too_many_arguments)] // one-time wiring from main
    pub fn new(
        fs: &'a RefCell<Store>,
        rng: &'a RefCell<FidoRng>,
        presence: &'a RefCell<Presence>,
        platform: &'a RefCell<crate::rescue_platform::RescuePlatform>,
        hooks: &'a RefCell<DeviceHooks>,
        // The device's one FIDO session state. Both handlers below borrow it: two
        // copies would give a host two per-boot PIN-mismatch budgets.
        fido_state: &'a RefCell<rsk_fido::FidoState>,
        serial_id: [u8; 8],
        serial_hash: [u8; 32],
        mkek_source: Option<FusedKey>,
        devk_source: Option<FusedKey>,
        kv_total: u32,
        openpgp_mfr: u16,
    ) -> Self {
        Self {
            ctap: Ctap::new(
                fs,
                rng,
                hooks,
                presence,
                fido_state,
                crate::vendor::VendorPlatform,
                serial_id,
                serial_hash,
                mkek_source,
                devk_source,
            ),
            ccid: Ccid::new(
                fs,
                rng,
                hooks,
                presence,
                fido_state,
                platform,
                crate::vendor::VendorPlatform,
                serial_id,
                serial_hash,
                mkek_source,
                devk_source,
                kv_total,
                crate::flash_storage::FLASH_SIZE as u32,
                openpgp_mfr,
            ),
            rng,
            presence,
            clicks: Clicks::new(),
            last_msg_cid: None,
        }
    }

    /// Process work forever. Three sources race: a CTAPHID/CCID transport request
    /// ([`REQ`]), a keyboard-interface OTP frame ([`otp_kbd::OTP_REQ`]), and a
    /// periodic tick that polls the button for typed-ticket presses. All flash
    /// access stays on this single task.
    pub async fn run(&mut self) -> ! {
        // Seed the keyboard status frame so a host poll before any command reads
        // the real version + slot bits.
        otp_kbd::set_status(otp_kbd::make_status_frame(self.ccid.otp_status_record()));
        loop {
            match select3(
                REQ.wait(),
                otp_kbd::OTP_REQ.wait(),
                embassy_time::Timer::after(Duration::from_millis(BTN_POLL_MS)),
            )
            .await
            {
                Either3::First(_) => {
                    self.handle_transport().await;
                    // A vendor reboot command takes effect only after its SW_OK has
                    // been sent (the reset can't run mid-dispatch).
                    if let Some(mode) = crate::vendor::take_reboot() {
                        self.reboot(mode).await;
                    }
                    // A Management factory reset (DEFAULT build) likewise runs after
                    // its SW_OK: wipe all flash but the attestation, then reboot to
                    // re-provision a fresh seed.
                    // Reboot only on a completed wipe: coming up fresh after a failed
                    // one is what makes a half-erased device look factory-clean.
                    #[cfg(not(feature = "strict-config"))]
                    if rsk_mgmt::take_device_reset() && self.ccid.factory_wipe() {
                        self.reboot(1).await;
                    }
                }
                Either3::Second(_) => self.handle_otp_hid(),
                Either3::Third(_) => {
                    self.button_tick();
                    // A reboot queued off-transport — the display's Settings → Firmware
                    // "Verify & install" — is serviced on this idle tick so it lands within a
                    // button-poll period instead of waiting on the next host APDU. The
                    // worker owns the live RAM secrets, so the scrub-then-reset in `reboot`
                    // runs here, not from the display task.
                    if let Some(mode) = crate::vendor::take_reboot() {
                        self.reboot(mode).await;
                    }
                }
            }
        }
    }

    /// One transport (CTAPHID/CCID) request: run the synchronous dispatch and
    /// signal the response. Holding the `EXCHANGE` lock across the (possibly
    /// multi-second) dispatch is fine — the requesting transport only re-locks
    /// `EXCHANGE` after `DONE`, and the lock's critical section is momentary, so
    /// the high-priority executor is never blocked.
    async fn handle_transport(&mut self) {
        // A config write since the last request may have changed the enabled set;
        // reload it before any gate consults it.
        self.refresh_caps_if_dirty();
        // Show the processing status for the dispatch; the first request also
        // flips the boot status to idle for good.
        crate::led::set_status(crate::led::STATUS_PROCESSING);
        {
            let mut ex = EXCHANGE.lock().await;
            // Scope any touch wait this dispatch starts to the transport that asked
            // for it: a cancel must only end its own transport's ceremony, and the
            // FIDO keepalive must not advertise somebody else's pending touch.
            crate::presence::set_wait_scope(match ex.kind {
                Kind::Cbor | Kind::Msg | Kind::Vendor => crate::presence::SCOPE_FIDO,
                Kind::Apdu | Kind::Secure | Kind::ResetCard => crate::presence::SCOPE_CCID,
            });
            // A CCID pinpad VERIFY collects the PIN on the screen and runs the
            // VERIFY itself, so it needs both `self.presence` and `self.ccid`; keep
            // it out of the borrow-the-whole-Exchange match below.
            if ex.kind == Kind::Secure {
                self.handle_secure_req(&mut ex);
            } else {
                // FIDO2 (CBOR) / U2F (MSG) disabled via `ykman config usb` answer a
                // deny; the interface stays enumerated (descriptor fixed at boot) but
                // does nothing until re-enabled. The re-enable path — CCID management
                // and the FIDO Management vendor command (`Kind::Vendor`) — is never
                // gated, so a disable is always reversible.
                let fido2_on = self.ccid.caps_enabled(rsk_mgmt::CAP_FIDO2);
                let u2f_on = self.ccid.caps_enabled(rsk_mgmt::CAP_U2F);
                let cbor_denied = [rsk_fido::CtapError::OperationDenied as u8];
                let u2f_denied = rsk_sdk::Sw::CONDITIONS_NOT_SATISFIED.to_bytes();
                let Exchange {
                    kind,
                    cid,
                    vcmd,
                    vendor_ok,
                    req_len,
                    req,
                    resp,
                    resp_len,
                    ..
                } = &mut *ex;
                let r: &[u8] = match *kind {
                    Kind::Cbor if !fido2_on => &cbor_denied,
                    Kind::Cbor => self.ctap.handle_cbor(
                        *cid,
                        &req[..*req_len],
                        crate::usb_attach::elapsed_ms(),
                    ),
                    Kind::Msg if !u2f_on => &u2f_denied,
                    Kind::Msg => {
                        // A CTAPHID_INIT since the last MSG drops the applet
                        // selection so U2F isn't hijacked by a sticky vendor SELECT.
                        // So does a change of channel: the selection is one global
                        // for every CTAPHID channel, and U2F has no SELECT of its
                        // own, so another process's SELECT of the vendor AID used to
                        // send the victim's REGISTER/AUTHENTICATE to `INS_INCREMENT`
                        // / `INS_GET` instead (audit run-34 #27).
                        // Both operands must run: `replace` is the ONLY thing that
                        // records which channel this MSG arrived on, and `||` skipped
                        // it whenever MSG_DESELECT was already set — which every
                        // CTAPHID_INIT sets, including the attacker's own. That left
                        // `last_msg_cid` holding the victim's channel and voided the
                        // scoping entirely (audit run-35).
                        let forced = MSG_DESELECT.swap(false, core::sync::atomic::Ordering::AcqRel);
                        let changed = self.last_msg_cid.replace(*cid) != Some(*cid);
                        if forced || changed {
                            self.ctap.deselect_msg();
                        }
                        self.ctap
                            .handle_msg(&req[..*req_len], crate::usb_attach::elapsed_ms())
                    }
                    Kind::Apdu => self
                        .ccid
                        .handle_apdu(&req[..*req_len], crate::usb_attach::elapsed_ms()),
                    Kind::ResetCard => {
                        self.ccid.reset_card();
                        &[]
                    }
                    Kind::Vendor => {
                        *vendor_ok = true;
                        match self.ccid.ctap_mgmt(*vcmd, &req[..*req_len]) {
                            Some(b) => b,
                            None => {
                                *vendor_ok = false;
                                &[]
                            }
                        }
                    }
                    Kind::Secure => &[], // handled above
                };
                let n = r.len().min(resp.len());
                resp[..n].copy_from_slice(&r[..n]);
                *resp_len = n;
            }
            // The request can carry secrets (a VERIFY PIN, an imported
            // private key); wipe it as soon as the dispatch is done. The
            // handlers' own response buffers held the same bytes as `resp`.
            let rl = ex.req_len;
            ex.req[..rl].zeroize();
            ex.req_len = 0;
            self.ctap.scrub();
            self.ccid.scrub();
        }
        // Nothing is in flight again: a wait started from here on is an on-panel
        // flow, which no host may cancel.
        crate::presence::set_wait_scope(crate::presence::SCOPE_NONE);
        self.forget_pending_click();
        crate::led::set_status(crate::led::STATUS_IDLE);
        DONE.signal(());
    }

    /// A dispatch may have consumed a button press for touch confirmation; forget
    /// any pending click so it isn't mistaken for a typed-ticket gesture, and hand
    /// over whether that press is *still* down — its release is the ceremony's.
    ///
    /// Every dispatch arm must call this — but NOT `button_tick`, whose whole job is
    /// to accumulate the gesture across the click window.
    fn forget_pending_click(&mut self) {
        let held = self.presence.borrow_mut().poll_pressed();
        self.clicks.consumed_by_ceremony(held);
    }

    /// Handle a CCID `PC_to_RDR_Secure` (pinpad VERIFY). Parse the request, collect
    /// the PIN on the trusted screen, assemble the real VERIFY APDU on-device, run it
    /// through the normal applet dispatch, and report the card's status word — the PIN
    /// never leaves the device. Writes the reply body into `ex.resp` and the CCID
    /// `bStatus`/`bError` into `ex.sec_status`/`ex.sec_error`.
    ///
    /// Ordering matters: the worker holds the shared `fs` borrowed for the whole
    /// dispatch, and `collect_pin` runs on the same thread executor, so anything the
    /// pad needs from `fs` (here: nothing — the per-PIN minimum is a fixed policy by
    /// `P2`) must be read into locals *before* `collect_pin`, never inside it — a
    /// re-borrow would panic. `collect_pin` touches only the panel's own `RefCell`,
    /// so it is borrow-disjoint from `self.ccid`/`fs`.
    #[cfg(feature = "display")]
    fn handle_secure_req(&mut self, ex: &mut Exchange) {
        use rsk_fido::UserPresence as _;
        use rsk_usb::ccid::{SECURE_ERR_CANCELLED, SECURE_ERR_TIMEOUT, SECURE_STATUS_FAILED};
        let failed = |ex: &mut Exchange, err: u8| {
            ex.resp_len = 0;
            ex.sec_status = SECURE_STATUS_FAILED;
            ex.sec_error = err;
        };
        let Some(req) = rsk_usb::secure_pin::parse_secure(&ex.req[..ex.req_len]) else {
            return failed(ex, 0);
        };
        // Only VERIFY (bPINOperation 0x00) is advertised (bPINSupport=0x01); refuse
        // a MODIFY or anything else rather than feed it to the pad.
        if req.operation != 0x00 {
            return failed(ex, 0);
        }
        // The pad is a trusted-display ceremony, so it gets the contract the rest of
        // them have. Its direct twin — clientPIN built-in UV, the other way a host
        // makes this panel paint a PIN pad — runs a readiness check that refuses
        // WITHOUT painting and then an explicit "Allow host access?" hold, and audit
        // run-28 already ruled a bare host-raised prompt a defect. This path had
        // neither: any local PC/SC client could raise "OpenPGP Admin PIN" at a moment
        // of its choosing, and OpenPGP's UIF default is touch-off, so a typed PW3 was
        // spendable from the attacker's own session with no further prompt.
        let p2 = req.apdu_template.get(3).copied().unwrap_or(0);
        if !self.ccid.pin_ref_ready(p2) {
            return failed(ex, 0);
        }
        let Some((title, min_len)) = secure_pin_meta(p2) else {
            return failed(ex, 0);
        };
        if !matches!(
            self.presence
                .borrow_mut()
                .request(rsk_fido::Confirm::titled("Allow host PIN entry?")),
            rsk_fido::Presence::Confirmed
        ) {
            return failed(ex, SECURE_ERR_CANCELLED);
        }
        let mut pin = [0u8; rsk_usb::secure_pin::MAX_PIN];
        let entry = self
            .presence
            .borrow_mut()
            .collect_pin_titled(title, min_len, &mut pin);
        match entry {
            rsk_fido::PinEntry::Entered(n) => {
                let mut apdu = [0u8; 5 + rsk_usb::secure_pin::MAX_PIN];
                if let Some(len) =
                    rsk_usb::secure_pin::assemble_verify(req.apdu_template, &pin[..n], &mut apdu)
                {
                    // Ensure the pad VERIFY dispatches as a standalone command — a prior
                    // host chaining segment must not concatenate the PIN onto itself.
                    self.ccid.reset_chaining();
                    let body = self
                        .ccid
                        .handle_apdu(&apdu[..len], crate::usb_attach::elapsed_ms());
                    let m = body.len().min(ex.resp.len());
                    ex.resp[..m].copy_from_slice(&body[..m]);
                    ex.resp_len = m;
                    ex.sec_status = rsk_usb::ccid::SECURE_STATUS_OK;
                    ex.sec_error = 0;
                } else {
                    failed(ex, 0);
                }
                apdu.zeroize();
            }
            rsk_fido::PinEntry::Cancelled | rsk_fido::PinEntry::Declined => {
                failed(ex, SECURE_ERR_CANCELLED)
            }
            rsk_fido::PinEntry::Timeout => failed(ex, SECURE_ERR_TIMEOUT),
            rsk_fido::PinEntry::Unsupported => failed(ex, 0),
        }
        pin.zeroize();
    }

    /// No on-device pad on a button build — `bPINSupport` is 0, so the host never
    /// sends `PC_to_RDR_Secure`; a stray one is reported as a failed command.
    #[cfg(not(feature = "display"))]
    fn handle_secure_req(&mut self, ex: &mut Exchange) {
        ex.resp_len = 0;
        ex.sec_status = rsk_usb::ccid::SECURE_STATUS_FAILED;
        ex.sec_error = 0;
    }

    /// One keyboard-interface OTP frame command: run it against flash and stash
    /// the response for the GET_REPORT poller. A CHAL_BTN_TRIG slot blocks here in
    /// a touch wait; the high-priority GET_REPORT polls report `0x20` meanwhile.
    /// Reload the cached enabled-applications mask if a config write flipped the
    /// dirty latch, so the CCID / FIDO2 / U2F / OTP gates all act on the new set
    /// before the next request. Cheap (one relaxed atomic) on the common no-change
    /// path; a flash re-read only right after `ykman config usb` changed it.
    fn refresh_caps_if_dirty(&mut self) {
        if rsk_mgmt::take_dev_conf_dirty() {
            self.ccid.refresh_enabled();
        }
    }

    fn handle_otp_hid(&mut self) {
        let Some((slot, payload)) = otp_kbd::take_request() else {
            return;
        };
        self.refresh_caps_if_dirty();
        crate::led::set_status(crate::led::STATUS_PROCESSING);
        // Scope any touch wait this command starts to the OTP transport, so a host
        // that aborts it cannot also abandon a FIDO ceremony on the same button.
        crate::presence::set_wait_scope(crate::presence::SCOPE_OTP);
        let (body, n, status) = self.ccid.handle_otp_hid(slot, &payload);
        crate::presence::set_wait_scope(crate::presence::SCOPE_NONE);
        otp_kbd::finish_response(status, &body[..n]);
        self.ccid.scrub();
        // This path runs the CFG_CHAL_BTN_TRIG touch wait too, and `ButtonPresence`
        // confirms on an already-held button — so without this the release edge of
        // the press just consumed is counted as a click and types a ticket as well.
        self.forget_pending_click();
        crate::led::set_status(crate::led::STATUS_IDLE);
    }

    /// Sample the button and run the click-counter state machine; on a completed
    /// gesture, type slot `n`'s ticket.
    fn button_tick(&mut self) {
        let now = Instant::now().as_millis();
        let cur = self.presence.borrow_mut().poll_pressed();
        let Some(slot) = self.clicks.tick(now, cur) else {
            return;
        };
        let ts = (now / 1000) as u32;
        if let Some((buf, len, encode)) = self.ccid.otp_button_ticket(slot, ts) {
            otp_kbd::enqueue(&buf[..len], encode);
        }
    }

    /// Secure reboot. The SW_OK has already been signalled; give it ~200 ms to
    /// flush over USB, wipe the live RAM key material (the FIDO auth state and the
    /// DRBG — per-dispatch buffers are already zeroized), then reset. `mode` 2
    /// drops to the BOOTSEL bootloader so a reflash can't recover those secrets
    /// from RAM; `mode` 1 is a warm reboot. Flash-at-rest secrets are out of
    /// scope for this path.
    ///
    /// The stack is deliberately not scrubbed. `tests/54_sram_residue.py` measured
    /// the premise on RP2350 A4: after the drop, all 520 KiB of SRAM read as zeros
    /// while a pattern written through picoboot read straight back, so the platform
    /// clears it and there is nothing there to reach.
    async fn reboot(&mut self, mode: u8) -> ! {
        embassy_time::Timer::after(Duration::from_millis(200)).await;
        self.ctap.scrub_secrets();
        self.ccid.scrub();
        self.rng.borrow_mut().scrub();
        // The keyboard transport's statics are outside the per-dispatch buffers: the
        // frame reassembly buffer, the taken request and a queued ticket can each hold
        // a slot's AES key, private UID, access code or static password.
        otp_kbd::scrub();
        // Core1's mailbox keeps an RSA prime and the keygen DRBG seed from the last
        // on-card keygen — factors of a live modulus, in plain SRAM. The sieves are
        // scrubbed by their owning core (issuing that from core0 would alias a live
        // `&mut` across cores); `scrub` now waits, bounded, for core1 to reach that
        // point. A core1 that never answers is faulted — which is what latches
        // `DEGRADED` — and its window stays resident (audit run-34 #23).
        crate::core1::scrub();
        if mode == 2 {
            embassy_rp::rom_data::reset_to_usb_boot(0, 0);
        } else {
            cortex_m::peripheral::SCB::sys_reset();
        }
        // reset_to_usb_boot returns only on failure; park.
        loop {
            cortex_m::asm::nop();
        }
    }
}
