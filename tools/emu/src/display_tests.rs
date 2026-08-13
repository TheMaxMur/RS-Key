// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The panel's PIN signal, end to end: a wrong clientPIN typed on the trusted
//! display's own pad must end the `pinUvAuthToken` the host is holding (CTAP 2.1
//! §6.5.5.6 — the pad's current-PIN prompt is `changePIN`'s old-PIN check, and
//! over USB that check drops the token).
//!
//! `crates/rsk-display/src/gates_tests.rs` pins the *signal* against a test
//! double; what is pinned here is the other half — that it reaches the worker and
//! the token really stops authorizing. So this runs `serve_display`'s own wiring,
//! the real `rsk_display` flow over a scripted finger and real CBOR on the real
//! `AppletHandler`; the panel is a sink instead of an SDL window and the finger a
//! script instead of a mouse, which is what the wiring is generic over.

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::time::{Duration, Instant};

use rsk_crypto::pinproto::{self, PinProto};
use rsk_fido::CtapError;
use rsk_fido::consts::{
    CTAP_CLIENT_PIN, CTAP_CREDENTIAL_MGMT, CTAP_GET_INFO, CTAP_SELECTION, MAX_PIN_RETRIES,
    PUAT_INITIAL_USAGE_LIMIT_MS,
};

use super::*;
use crate::device::{Config, Job, Jobs, PanelLinks, job_queue, serve_display};
use crate::presence::PresenceMode;
use crate::signals::Signals;
use crate::taps::{Tap, TapPad};

/// The clientPIN the host sets, and the one typed at the pad instead.
const PIN: &[u8] = b"1234";
const WRONG_PIN: &[u8] = b"9999";

/// pinUvAuthProtocol 2 — the one a current platform picks, and the one whose
/// 16-byte IV and 32-byte MAC make every length below explicit. The wire byte is
/// the same fact twice, so `drive` checks the two agree before using either.
const PROTO: PinProto = PinProto::Two;
const PROTO_WIRE: u8 = 2;

/// `credentialManagement/getCredsMetadata`: the cheapest command that consumes a
/// `pinUvAuthToken` and asks for nothing else — no touch, no user presence — so
/// what it answers is the token's own health and nothing more.
const CM_GET_CREDS_METADATA: u8 = 0x01;
const CTAP2_OK: u8 = 0x00;

/// A CTAPHID channel to be the host on.
const CID: u32 = 0x0102_0304;

/// How long the panel may take to answer a job. The display flow holds the single
/// executor while a modal is open, so a queued command waits for it — bounded
/// past `MENU_INACTIVITY_MS` (60 s) so a screen that never yields fails on the
/// bound below with its real figure rather than on a receive timeout.
const REPLY_TIMEOUT: Duration = Duration::from_secs(90);

/// What a queued command may wait for an open menu. A board hands the executor
/// over on the first `TOUCH_POLL_MS` (16 ms) poll past `UI_YIELD_FLOOR_MS`; a
/// screen that does not yield at all makes it wait out `MENU_INACTIVITY_MS`
/// (60 s), so anything between the two separates them.
const MENU_YIELD_BOUND: Duration = Duration::from_secs(20);
// The bound only separates the two while it sits strictly between them. The lower
// end is public and checked here; `MENU_INACTIVITY_MS` is private to `rsk-display`,
// so the upper end is prose until it is not.
const _: () = assert!(rsk_display::UI_YIELD_FLOOR_MS < 20_000);

/// What the same command takes with the panel idle — the control that says the
/// figure above is a modal holding the executor and not the emulator being slow.
const IDLE_REPLY_BOUND: Duration = Duration::from_secs(1);

/// How long the keepalive may wait to hear that a touch is pending. The ceremony
/// starts within a poll or two of the dispatch; this is long enough to be sure and
/// short enough to leave the 30 s presence timeout for the cancel below.
const UP_PENDING_BOUND: Duration = Duration::from_secs(10);

/// What a `CTAPHID_CANCEL` on the owning channel may take to end the ceremony. The
/// wait polls every `TOUCH_POLL_MS`; one that cannot see the cancel at all runs to
/// `presence_timeout_ms` (30 s) and then answers the wrong code.
const CANCEL_BOUND: Duration = Duration::from_secs(5);

/// Lifted samples before the consent hold, so the ambient status loop — which
/// polls the pad every 100 ms while idle — cannot swallow the contact before the
/// host command that needs it has started its confirm wait. Belt to `settle`'s
/// braces: the gap clock starts on whichever poll takes the tap, so a lead alone
/// is a race rather than a barrier.
const CONSENT_LEAD_MS: u64 = 400;
/// …and then a finger that stays down past three things it has to outlast: the
/// 800 ms hold-to-approve, the 400 ms `AMBIENT_QUIET_MS` the ceremony's exit
/// blocks the idle loop for, and the repaint after it that disarms the touch. It
/// is the lift at the *end* of this hold that re-arms the loop for the next tap.
const CONSENT_HOLD_MS: u64 = 2_500;

/// How long a scripted gesture may wait for the panel to take it.
const TAP_TIMEOUT: Duration = Duration::from_secs(30);

/// The panel, as a sink. What the flow paints is `rsk-display`'s own tests'
/// business; this one is about the signal that leaves the panel.
struct NullPanel;

impl Dimensions for NullPanel {
    fn bounding_box(&self) -> Rectangle {
        Rectangle::new(
            EgPoint::new(0, 0),
            Size::new(rsk_ui::PANEL_W as u32, rsk_ui::PANEL_H as u32),
        )
    }
}

impl DrawTarget for NullPanel {
    type Color = Rgb565;
    type Error = Infallible;

    fn draw_iter<I: IntoIterator<Item = Pixel<Rgb565>>>(
        &mut self,
        _pixels: I,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// The centre of the control `hit` accepts, taken from `rsk-ui`'s own hit test
/// rather than from copied coordinates — so a layout change moves the tap with it
/// instead of silently making the script miss.
fn target(hit: impl Fn(rsk_ui::Point) -> bool) -> rsk_ui::Point {
    let (mut sx, mut sy, mut n) = (0u32, 0u32, 0u32);
    for y in 0..rsk_ui::PANEL_H {
        for x in 0..rsk_ui::PANEL_W {
            if hit(rsk_ui::Point::new(x, y)) {
                sx += x as u32;
                sy += y as u32;
                n += 1;
            }
        }
    }
    assert!(n > 0, "no pixel of the panel reaches this control");
    let centre = rsk_ui::Point::new((sx / n) as u16, (sy / n) as u16);
    assert!(hit(centre), "the control's centroid is outside it");
    centre
}

fn nav_tab(want: rsk_ui::NavTab) -> rsk_ui::Point {
    target(|p| rsk_ui::hit_nav(p) == Some(want))
}

fn pin_key(want: rsk_ui::PinKey) -> rsk_ui::Point {
    target(|p| rsk_ui::hit_pin(p) == Some(want))
}

/// A contact every screen's hit test misses, so it is a no-op wherever it lands.
fn nowhere() -> rsk_ui::Point {
    let miss = |p| {
        rsk_ui::hit_nav(p).is_none()
            && rsk_ui::hit_pin(p).is_none()
            && rsk_ui::hit_settings_root(p).is_none()
            && rsk_ui::hit_security(p).is_none()
            && rsk_ui::hit_onboard(p).is_none()
            && !rsk_ui::hit_title_back(p)
            && !rsk_ui::ALLOW_RECT.contains(p)
            && !rsk_ui::DENY_RECT.contains(p)
    };
    (0..rsk_ui::PANEL_H)
        .flat_map(|y| (0..rsk_ui::PANEL_W).map(move |x| rsk_ui::Point::new(x, y)))
        .find(|&p| miss(p))
        .expect("every pixel of the panel is a control")
}

/// Queue one gesture, waiting for the pad to have room.
///
/// The channel holds a single tap, so the script can never run ahead of the pad
/// by more than one contact. That bounds it; it does not sequence it — a sample
/// can still be eaten by a release wait rather than by a hit test, which is what
/// `LIFT_MS` is sized against.
fn push(taps: &SyncSender<Tap>, mut tap: Tap) {
    let deadline = Instant::now() + TAP_TIMEOUT;
    loop {
        match taps.try_send(tap) {
            Ok(()) => return,
            Err(TrySendError::Full(t)) => tap = t,
            Err(TrySendError::Disconnected(_)) => panic!("the panel stopped reading its pad"),
        }
        assert!(
            Instant::now() < deadline,
            "the panel never took the gesture"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Drain the pad to a known state before the next real gesture.
///
/// The slot runs one tap ahead of the pad, so two no-op contacts put the last
/// real one at least two reads behind. They are contacts *the flow ignores*, so
/// whichever poll consumes them — a hit test or a release wait — the panel ends
/// up idle either way, which is the only property the callers need.
fn settle(taps: &SyncSender<Tap>) {
    let p = nowhere();
    push(taps, Tap::at(p.x, p.y));
    push(taps, Tap::at(p.x, p.y));
}

// --- the platform half of the pin protocol ---------------------------------

struct Platform {
    x: [u8; 32],
    y: [u8; 32],
    shared: [u8; 64],
    slen: usize,
}

impl Platform {
    /// Agree a shared secret with the authenticator's `getKeyAgreement` key. The
    /// platform scalar is fixed: nothing here needs a fresh key, and a
    /// deterministic one makes a failing run reproducible.
    fn agree(peer_x: &[u8; 32], peer_y: &[u8; 32]) -> Self {
        let mut scalar = [0u8; 32];
        scalar[0] = 0x13;
        scalar[31] = 0x42;
        let (x, y) = pinproto::public_xy(&scalar).expect("a valid P-256 scalar");
        let mut shared = [0u8; 64];
        let slen = pinproto::ecdh(PROTO, &scalar, peer_x, peer_y, &mut shared)
            .expect("the authenticator's key agreement point is on the curve");
        Self { x, y, shared, slen }
    }

    fn secret(&self) -> &[u8] {
        &self.shared[..self.slen]
    }

    fn enc(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut out = [0u8; 128];
        let n = pinproto::encrypt(PROTO, self.secret(), &[0x55; 16], plaintext, &mut out)
            .expect("the buffer holds an IV and 64 padded bytes");
        out[..n].to_vec()
    }

    fn mac(&self, data: &[u8]) -> Vec<u8> {
        mac_under(self.secret(), data)
    }

    fn key_agreement(&self) -> Vec<u8> {
        cose_ecdh(&self.x, &self.y)
    }
}

fn mac_under(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = [0u8; 32];
    let n = pinproto::authenticate(PROTO, key, data, &mut out).expect("a 32-byte MAC fits");
    out[..n].to_vec()
}

/// `{1:2, 3:-25, -1:1, -2:x, -3:y}` — the COSE ECDH key both sides put on the
/// wire. Written out because the emulator does not depend on a CBOR encoder.
fn cose_ecdh(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
    let mut v = vec![
        0xA5, 0x01, 0x02, 0x03, 0x38, 0x18, 0x20, 0x01, 0x21, 0x58, 0x20,
    ];
    v.extend_from_slice(x);
    v.extend_from_slice(&[0x22, 0x58, 0x20]);
    v.extend_from_slice(y);
    v
}

/// A CBOR byte string. Every one here is 32 bytes or more, so the one-byte-length
/// form is also the canonical one.
fn bstr(b: &[u8]) -> Vec<u8> {
    assert!((24..=255).contains(&b.len()), "not the 0x58 length form");
    let mut v = vec![0x58, b.len() as u8];
    v.extend_from_slice(b);
    v
}

/// A CBOR map with small unsigned keys and pre-encoded values.
fn map(entries: &[(u8, Vec<u8>)]) -> Vec<u8> {
    assert!(entries.len() < 24, "not the single-byte map header");
    let mut v = vec![0xA0 | entries.len() as u8];
    for (k, val) in entries {
        assert!(*k < 24, "not a single-byte key");
        v.push(*k);
        v.extend_from_slice(val);
    }
    v
}

/// A CBOR unsigned small enough to be its own header.
fn u(n: u8) -> Vec<u8> {
    assert!(n < 24, "not a single-byte unsigned");
    vec![n]
}

// --- the requests ----------------------------------------------------------

fn get_key_agreement_req() -> Vec<u8> {
    let mut v = vec![CTAP_CLIENT_PIN];
    v.extend(map(&[(1, u(PROTO_WIRE)), (2, u(2))]));
    v
}

/// The cheapest ungated command there is — no PIN, no touch, no state. It is also
/// the one audit run-35 named: a host looping it is what [`UI_YIELD_FLOOR_MS`]
/// stops from holding the owner's screen shut.
///
/// [`UI_YIELD_FLOOR_MS`]: rsk_display::UI_YIELD_FLOOR_MS
fn get_info_req() -> Vec<u8> {
    vec![CTAP_GET_INFO]
}

/// `authenticatorSelection` — the one command that is nothing *but* a presence
/// request, so what it answers is the ceremony's verdict and nothing else
/// (`crates/rsk-fido/src/selection.rs`).
fn selection_req() -> Vec<u8> {
    vec![CTAP_SELECTION]
}

fn get_pin_retries_req() -> Vec<u8> {
    let mut v = vec![CTAP_CLIENT_PIN];
    v.extend(map(&[(1, u(PROTO_WIRE)), (2, u(1))]));
    v
}

fn set_pin_req(plat: &Platform, pin: &[u8]) -> Vec<u8> {
    let mut padded = [0u8; 64];
    padded[..pin.len()].copy_from_slice(pin);
    let new_pin_enc = plat.enc(&padded);
    let puap = plat.mac(&new_pin_enc);
    let mut v = vec![CTAP_CLIENT_PIN];
    v.extend(map(&[
        (1, u(PROTO_WIRE)),
        (2, u(3)),
        (3, plat.key_agreement()),
        (4, bstr(&puap)),
        (5, bstr(&new_pin_enc)),
    ]));
    v
}

/// getPinUvAuthTokenUsingPinWithPermissions (subCommand 9) for `cm`.
fn get_token_req(plat: &Platform, pin: &[u8]) -> Vec<u8> {
    let h = rsk_crypto::sha256(pin);
    let pin_hash_enc = plat.enc(&h[..16]);
    let mut v = vec![CTAP_CLIENT_PIN];
    v.extend(map(&[
        (1, u(PROTO_WIRE)),
        (2, u(9)),
        (3, plat.key_agreement()),
        (6, bstr(&pin_hash_enc)),
        (9, u(rsk_fido::state::PERM_CM)),
    ]));
    v
}

fn spend_token_req(token: &[u8; 32]) -> Vec<u8> {
    let puap = mac_under(token, &[CM_GET_CREDS_METADATA]);
    let mut v = vec![CTAP_CREDENTIAL_MGMT];
    v.extend(map(&[
        (1, u(CM_GET_CREDS_METADATA)),
        (3, u(PROTO_WIRE)),
        (4, bstr(&puap)),
    ]));
    v
}

// --- the responses ---------------------------------------------------------

/// `{1: COSE key}` — the authenticator's ephemeral public point.
fn parse_key_agreement(body: &[u8]) -> ([u8; 32], [u8; 32]) {
    assert_eq!(body[0], CTAP2_OK, "getKeyAgreement");
    let head: &[u8] = &[
        0xA1, 0x01, 0xA5, 0x01, 0x02, 0x03, 0x38, 0x18, 0x20, 0x01, 0x21, 0x58, 0x20,
    ];
    assert_eq!(&body[1..1 + head.len()], head, "COSE ECDH key layout moved");
    let xs = 1 + head.len();
    let mut x = [0u8; 32];
    x.copy_from_slice(&body[xs..xs + 32]);
    assert_eq!(&body[xs + 32..xs + 35], &[0x22, 0x58, 0x20]);
    let mut y = [0u8; 32];
    y.copy_from_slice(&body[xs + 35..xs + 67]);
    (x, y)
}

/// `{2: encrypted pinUvAuthToken}` — 16 bytes of IV plus the 32-byte token.
fn parse_token(plat: &Platform, body: &[u8]) -> [u8; 32] {
    assert_eq!(body[0], CTAP2_OK, "getPinUvAuthToken");
    assert_eq!(
        &body[1..4],
        &[0xA1, 0x02, 0x58],
        "token response layout moved"
    );
    let n = body[4] as usize;
    let mut token = [0u8; 32];
    let len = pinproto::decrypt(PROTO, plat.secret(), &body[5..5 + n], &mut token)
        .expect("the token decrypts under the shared secret");
    assert_eq!(len, 32);
    token
}

/// `{3: retries}` — the clientPIN budget, which is this test's control: it says
/// the pad really compared a PIN rather than being navigated past.
fn parse_pin_retries(body: &[u8]) -> u8 {
    assert_eq!(body[0], CTAP2_OK, "getPINRetries");
    assert_eq!(&body[1..3], &[0xA1, 0x03], "getPINRetries layout moved");
    body[3]
}

// --- the run ---------------------------------------------------------------

fn ask(jobs: &Jobs, data: Vec<u8>) -> Vec<u8> {
    let (reply, answer) = mpsc::channel();
    jobs.send(Job::Cbor { cid: CID, data }, reply)
        .expect("the device thread is alive");
    answered(&answer)
}

/// The body of an already-queued command, bounded.
fn answered(answer: &mpsc::Receiver<Option<Vec<u8>>>) -> Vec<u8> {
    answer
        .recv_timeout(REPLY_TIMEOUT)
        .expect("the device answered within the bound")
        .expect("a CBOR command always has a body")
}

/// The host and the finger, from a thread of their own: `serve_display` owns the
/// caller's thread the way `device::run` owns the process's.
fn drive(jobs: Jobs, taps: SyncSender<Tap>, _signals: Arc<Signals>) {
    assert_eq!(
        PinProto::from_u64(PROTO_WIRE as u64),
        Some(PROTO),
        "the wire byte and the protocol below it are the same fact"
    );
    // Dismiss the first-run onboarding offer first, so the panel is on Home and
    // the nav bar is what a tap hits — and so this contact cannot be swallowed by
    // the consent screen below.
    let skip = target(|p| rsk_ui::hit_onboard(p) == Some(rsk_ui::OnboardChoice::Skip));
    push(&taps, Tap::at(skip.x, skip.y));
    settle(&taps);

    let (ax, ay) = parse_key_agreement(&ask(&jobs, get_key_agreement_req()));
    let plat = Platform::agree(&ax, &ay);
    assert_eq!(
        ask(&jobs, set_pin_req(&plat, PIN))[0],
        CTAP2_OK,
        "setPIN over the wire"
    );

    // A trusted display owes a consent screen for a permissioned token
    // (§6.5.5.7), so the hold is queued before the command that waits on it —
    // behind a lead of lifted samples the idle loop cannot mistake for a nav tap.
    let allow = target(|p| rsk_ui::ALLOW_RECT.contains(p));
    // The pad is drained to a known state first, so the hold below is queued
    // against a panel that is idle rather than mid-gesture.
    settle(&taps);
    push(
        &taps,
        Tap {
            gap: Duration::from_millis(CONSENT_LEAD_MS),
            hold: Duration::from_millis(CONSENT_HOLD_MS),
            ..Tap::at(allow.x, allow.y)
        },
    );
    let token = parse_token(&plat, &ask(&jobs, get_token_req(&plat, PIN)));

    // The control that makes the rest mean something: the token authorizes a
    // command *before* the panel is touched.
    let first_spend = Instant::now();
    assert_eq!(
        ask(&jobs, spend_token_req(&token))[0],
        CTAP2_OK,
        "the freshly minted token must authorize credentialManagement"
    );

    // Settings → Security → FIDO PIN, then the wrong current PIN. The gate
    // re-prompts after a refusal, so Cancel closes it; Back and Home then return
    // the panel to idle rather than leaving it holding the executor.
    let security = target(|p| rsk_ui::hit_settings_root(p) == Some(rsk_ui::RootEntry::Security));
    let fido_pin = target(|p| rsk_ui::hit_security(p) == Some(rsk_ui::SecurityEntry::FidoPin));
    let mut script = vec![nav_tab(rsk_ui::NavTab::Settings), security, fido_pin];
    for d in WRONG_PIN {
        script.push(pin_key(rsk_ui::PinKey::Digit(d - b'0')));
    }
    script.extend([
        pin_key(rsk_ui::PinKey::Ok),
        pin_key(rsk_ui::PinKey::Cancel),
        target(rsk_ui::hit_title_back),
        nav_tab(rsk_ui::NavTab::Home),
    ]);
    for p in script {
        push(&taps, Tap::at(p.x, p.y));
    }
    settle(&taps);

    assert_eq!(
        parse_pin_retries(&ask(&jobs, get_pin_retries_req())),
        MAX_PIN_RETRIES - 1,
        "the control: the pad really compared a clientPIN and spent an attempt"
    );

    // E66. The same token, the same command, after a refused PIN at the pad.
    let refused = ask(&jobs, spend_token_req(&token));
    // `expire_stale_token` retires an unused token after
    // `PUAT_INITIAL_USAGE_LIMIT_MS` and answers with the SAME error, so without
    // this the headline assertion passes on a slow machine whatever the panel did.
    // The window runs from the spend above; measured at ~1.5 s of 30 s.
    let idle = first_spend.elapsed();
    assert!(
        idle < Duration::from_millis(PUAT_INITIAL_USAGE_LIMIT_MS),
        "the token sat idle for {idle:?} — its own inactivity timer could have killed it"
    );
    assert_eq!(
        refused[0],
        CtapError::PinAuthInvalid.as_u8(),
        "a wrong clientPIN at the panel must have ended the host's pinUvAuthToken"
    );
}

/// `serve_display`'s own wiring, headless: the panel is a sink and the pad a
/// script, which is what it is generic over. `host` is the platform, on a thread
/// of its own — `serve_display` owns the caller's thread the way `device::run`
/// owns the process's, and returns when the driver drops its sender, so a driver
/// panic ends the run and `join` re-raises it.
fn panel_bench(
    host: impl FnOnce(Jobs, SyncSender<Tap>, Arc<Signals>) + Send + 'static,
) -> PanelLinks {
    let store = crate::store::open(None, None).expect("a memory-backed store");
    let fs: &'static RefCell<rsk_fs::Fs<crate::store::EmuStore>> =
        Box::leak(Box::new(RefCell::new(rsk_fs::Fs::new(store))));
    let rng: &'static RefCell<crate::rng::EmuRng> = Box::leak(Box::new(RefCell::new(
        crate::rng::EmuRng::from_seed(&[0x5e; 32]),
    )));

    let cfg = Config {
        store: None,
        presence: PresenceMode::Instant,
        display: true,
        usbip: None,
        seed: None,
        serial: crate::DEFAULT_SERIAL,
        kv_total: crate::KV_TOTAL,
        flash_size: crate::FLASH_SIZE,
        trace: false,
        yubico: false,
        power_cut: None,
    };

    let (jobs_tx, jobs_rx) = job_queue();
    let queued = jobs_rx.queued();
    let signals = Arc::new(Signals::default());
    let links = PanelLinks::default();
    // One slot, which is what makes the script self-pacing — see `push`.
    let (taps_tx, taps_rx) = mpsc::sync_channel(1);
    let driver = {
        let signals = signals.clone();
        std::thread::spawn(move || host(jobs_tx, taps_tx, signals))
    };

    serve_display(
        cfg,
        jobs_rx,
        signals.clone(),
        fs,
        rng,
        PanelParts {
            panel: NullPanel,
            touch: TapPad::new(taps_rx),
            // The backlight and wake handles are the window's; a headless run
            // simply does not share them with one.
            hooks: EmuDisplayHooks::new(
                Rc::new(Cell::new(rsk_display::BL_TOP)),
                Rc::new(Cell::new(false)),
                queued,
                signals,
                links.clone(),
            ),
        },
        links.clone(),
    );
    driver.join().expect("the host thread");
    links
}

/// The other half of the same executor: an open menu must hand it back when a
/// host command lands, and not before [`UI_YIELD_FLOOR_MS`] has passed.
///
/// [`UI_YIELD_FLOOR_MS`]: rsk_display::UI_YIELD_FLOOR_MS
fn drive_menu_yield(jobs: Jobs, taps: SyncSender<Tap>, _signals: Arc<Signals>) {
    let skip = target(|p| rsk_ui::hit_onboard(p) == Some(rsk_ui::OnboardChoice::Skip));
    push(&taps, Tap::at(skip.x, skip.y));
    settle(&taps);

    let idle = Instant::now();
    assert_eq!(ask(&jobs, get_info_req())[0], CTAP2_OK, "getInfo");
    let idle = idle.elapsed();
    assert!(
        idle < IDLE_REPLY_BOUND,
        "an idle panel answered in {idle:?} — the figure below would mean nothing"
    );

    // Open Settings, then queue the same command behind it. `settle` returns only
    // once the panel has read the contact and taken another behind it — which the
    // menu's own release wait is what took — so the modal is open and holding the
    // executor before the clock below starts.
    let settings = nav_tab(rsk_ui::NavTab::Settings);
    push(&taps, Tap::at(settings.x, settings.y));
    settle(&taps);
    let opened = Instant::now();
    assert_eq!(ask(&jobs, get_info_req())[0], CTAP2_OK, "getInfo");
    let waited = opened.elapsed();
    assert!(
        waited >= Duration::from_millis(rsk_display::UI_YIELD_FLOOR_MS),
        "the menu yielded after {waited:?}, inside the floor — a host repeating an \
         ungated command can hold the owner's screen shut (audit run-35)"
    );
    assert!(
        waited < MENU_YIELD_BOUND,
        "the menu made a queued host command wait {waited:?}; a board yields on the \
         first 16 ms poll past the floor"
    );
}

#[test]
fn a_wrong_clientpin_at_the_panel_ends_the_hosts_pin_token() {
    let _ = panel_bench(drive);
}

#[test]
fn an_open_menu_hands_the_executor_back_when_a_host_command_lands() {
    let _ = panel_bench(drive_menu_yield);
}

/// How long the driver below spends before the replug, and how fresh the clock
/// must read afterwards. The gap between them is what says the clock restarted
/// rather than having been running all along.
const PRE_REPLUG_MS: u64 = 600;
const FRESH_CLOCK_MS: u128 = 250;

/// Burn a measurable amount of the attach clock, then power-cycle.
fn drive_replug(jobs: Jobs, _taps: SyncSender<Tap>, _signals: Arc<Signals>) {
    assert_eq!(ask(&jobs, get_info_req())[0], CTAP2_OK, "getInfo");
    std::thread::sleep(Duration::from_millis(PRE_REPLUG_MS));
    let (reply, answer) = mpsc::channel();
    jobs.send(Job::Replug, reply)
        .expect("the device thread is alive");
    answered(&answer);
}

/// A power cycle restarts the clock the panel stamps with, because it is the
/// worker's clock and not one of the panel's own. `Job::Replug` reopens the CTAP
/// 2.1 §6.6 reset window by restarting it; a panel measuring from process start
/// would go on stamping audit entries against a window that had already moved.
#[test]
fn a_replug_restarts_the_clock_the_panel_stamps_with() {
    let links = panel_bench(drive_replug);
    let since = links.attach.get().elapsed().as_millis();
    assert!(
        since < FRESH_CLOCK_MS,
        "the attach clock reads {since} ms after a replug — it never restarted"
    );
}

/// …and the panel really reads that cell. One line each side, and the whole point
/// of `Hooks::attach_elapsed_ms` is that both sides read one clock.
#[test]
fn the_panel_reads_the_workers_attach_clock() {
    let links = PanelLinks::default();
    let hooks = EmuDisplayHooks::new(
        Rc::new(Cell::new(rsk_display::BL_TOP)),
        Rc::new(Cell::new(false)),
        crate::device::Queued::default(),
        Arc::new(Signals::default()),
        links.clone(),
    );
    std::thread::sleep(Duration::from_millis(FRESH_CLOCK_MS as u64));
    assert!(
        rsk_display::Hooks::attach_elapsed_ms(&hooks) >= FRESH_CLOCK_MS as u64,
        "the panel's clock is not running"
    );
    // What `serve` does on `Job::Replug`.
    links.attach.set(Instant::now());
    assert!(
        rsk_display::Hooks::attach_elapsed_ms(&hooks) < FRESH_CLOCK_MS as u64,
        "the worker restarted the clock and the panel did not notice"
    );
}

/// The smallest RSA modulus the PIV and OpenPGP keygen screens offer, so the test
/// runs the real search at the size a person is most likely to pick.
const RSA_BITS: usize = 2048;

/// The panel can generate an RSA key, which is the whole of E152: the hook was
/// left at `rsk_display::Hooks`'s default `None`, and *that* trait reads `None` as
/// "no accelerator **and** no key", so `piv_store_generated` reported a failure on
/// a build where the same generate over the wire succeeded. `rsk_device::Hooks`'s
/// identically-named default means the opposite — fall through to the applet's own
/// single-core path — which is exactly the path this now runs.
#[test]
fn the_panel_generates_the_rsa_key_the_wire_can() {
    let mut hooks = EmuDisplayHooks::new(
        Rc::new(Cell::new(rsk_display::BL_TOP)),
        Rc::new(Cell::new(false)),
        crate::device::Queued::default(),
        Arc::new(Signals::default()),
        PanelLinks::default(),
    );
    let mut rng = crate::rng::EmuRng::from_seed(&[0xa7; 32]);
    let mut ticks = 0usize;

    let key =
        rsk_display::Hooks::rsa_search_progress(&mut hooks, RSA_BITS, &mut rng, &mut || ticks += 1)
            .expect("the panel has a single-core path to fall through to, as the wire does");

    // The applet's own encoder taking the key is what says it is a usable one of
    // the size asked for, without this test learning the `rsa` crate's API.
    let mut out = [0u8; 1024];
    let n = rsk_openpgp::keys::make_rsa_response(&key, &mut out);
    assert!(
        n > RSA_BITS / 8,
        "the response carries no {RSA_BITS}-bit modulus ({n} bytes)"
    );
    assert!(
        ticks > 1,
        "the search ticked {ticks} times — the on-screen spinner would read as hung"
    );
}

/// Poll `ready` until it holds or `bound` runs out; `false` says it never did.
fn wait_until(bound: Duration, ready: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + bound;
    while Instant::now() < deadline {
        if ready() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}

/// The panel's presence flags are the transports', not the panel's own: the
/// CTAPHID keepalive reports `UPNEEDED` off the same object a `CTAPHID_CANCEL`
/// writes, which is what a board gets from `presence::ARBITER`.
fn drive_panel_presence(jobs: Jobs, taps: SyncSender<Tap>, signals: Arc<Signals>) {
    let skip = target(|p| rsk_ui::hit_onboard(p) == Some(rsk_ui::OnboardChoice::Skip));
    push(&taps, Tap::at(skip.x, skip.y));
    settle(&taps);

    // Queued without waiting on it: both halves below are about what the transport
    // can see while the ceremony is still on screen.
    let (reply, answer) = mpsc::channel();
    jobs.send(
        Job::Cbor {
            cid: CID,
            data: selection_req(),
        },
        reply,
    )
    .expect("the device thread is alive");

    let seen_up = wait_until(UP_PENDING_BOUND, || {
        signals.up_pending_for(crate::signals::SCOPE_FIDO)
    });
    // What `hid.rs` does with a `CTAPHID_CANCEL` whose channel owns the command.
    signals.request_cancel(CID);
    let sent = Instant::now();
    let body = answered(&answer);
    let took = sent.elapsed();

    assert_eq!(
        body[0],
        CtapError::KeepAliveCancel.as_u8(),
        "a cancel on the owning channel must end the on-panel ceremony as \
         KEEPALIVE_CANCEL, not run the presence timeout out into another code"
    );
    assert!(
        took < CANCEL_BOUND,
        "the ceremony took {took:?} to notice the cancel — the host has been told \
         nothing on a channel it believes it cancelled"
    );
    assert!(
        seen_up,
        "the keepalive never saw a touch pending, so a FIDO client is told \
         PROCESSING while the device is asking a human to touch it"
    );
}

#[test]
fn the_panels_presence_flags_are_the_transports() {
    let _ = panel_bench(drive_panel_presence);
}
