// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The shared test harness — a panel, a touch pad, a board and a store the flow
//! runs against on the host — plus the crate root's own unit tests.
//!
//! [`Ui`] is generic over exactly the four things a host cannot supply (the panel,
//! the touch controller, the board verbs, the flash backend), which is what makes
//! this possible at all: the doubles below are the emulator's `--display` wiring,
//! reduced to what an assertion needs. Every sibling `*_tests.rs` builds its case
//! from [`Env`].
//!
//! It also holds the census over `firmware/src/worker.rs`: the firmware side of
//! [`Hooks::host_request_pending`] is four lines of glue over statics that no host
//! build can link, so what this crate's browse loops depend on is asserted by
//! reading that source, the way `rsk_ui`'s ceremony-title census reads the tree.

use std::collections::VecDeque;
use std::sync::{Mutex, MutexGuard};
use std::vec;
use std::vec::Vec;

use embedded_graphics::geometry::OriginDimensions;
use rsk_fs::storage::ram::RamStorage;

use super::*;

/// The panel this crate paints, as a recorder. The flow only ever *writes* to a
/// panel, so what a test can check is that a frame was painted and that it stayed
/// inside the glass — the pair the real ST7789 cannot report back.
pub struct Panel {
    px: Vec<Rgb565>,
    /// Full-frame repaints since construction. `rsk_ui::render` opens every screen
    /// with a `clear`, so this counts screens painted — including the ones a modal
    /// paints and then forgets by clearing `shown`.
    pub frames: usize,
    /// A pixel was addressed outside the panel.
    pub oob: bool,
}

impl Panel {
    fn new() -> Self {
        Self {
            px: vec![Rgb565::BLACK; rsk_ui::PANEL_W as usize * rsk_ui::PANEL_H as usize],
            frames: 0,
            oob: false,
        }
    }
}

impl OriginDimensions for Panel {
    fn size(&self) -> Size {
        Size::new(rsk_ui::PANEL_W as u32, rsk_ui::PANEL_H as u32)
    }
}

impl DrawTarget for Panel {
    type Color = Rgb565;
    type Error = core::convert::Infallible;

    fn draw_iter<I: IntoIterator<Item = Pixel<Rgb565>>>(
        &mut self,
        pixels: I,
    ) -> Result<(), Self::Error> {
        let (w, h) = (rsk_ui::PANEL_W as i32, rsk_ui::PANEL_H as i32);
        for Pixel(p, c) in pixels {
            if p.x >= 0 && p.y >= 0 && p.x < w && p.y < h {
                self.px[p.y as usize * w as usize + p.x as usize] = c;
            } else {
                self.oob = true;
            }
        }
        Ok(())
    }

    fn clear(&mut self, color: Rgb565) -> Result<(), Self::Error> {
        self.px.fill(color);
        self.frames += 1;
        Ok(())
    }
}

/// A scripted touch controller: each `read` hands back the next sample, then
/// `tail` for ever. Level, not edges — the same contract the CST328 has, so the
/// debounce waits under test see what the real pad gives them.
pub struct Pad {
    script: VecDeque<Option<rsk_ui::Point>>,
    tail: Option<rsk_ui::Point>,
    pub reads: usize,
}

impl Pad {
    fn from(script: Vec<Option<rsk_ui::Point>>, tail: Option<rsk_ui::Point>) -> Self {
        Self {
            script: script.into(),
            tail,
            reads: 0,
        }
    }

    /// Nothing ever touches the panel.
    pub fn idle() -> Self {
        Self::from(Vec::new(), None)
    }

    /// A finger that is already down and never lifts — what a modal opening behind
    /// a still-held button sees.
    pub fn held(p: rsk_ui::Point) -> Self {
        Self::from(Vec::new(), Some(p))
    }

    /// A finger down for `polls` samples, then gone. `polls` × [`TOUCH_POLL_MS`] is
    /// how long a release wait spends on it.
    pub fn held_for(p: rsk_ui::Point, polls: usize) -> Self {
        Self::from(vec![Some(p); polls], None)
    }

    /// Discrete taps, in order — a user lifting between them.
    ///
    /// Two untouched samples separate one tap from the next, which is what makes a
    /// script line up with any flow rather than only with the one it was written
    /// for. A gesture boundary consumes one untouched sample per release wait, and
    /// the flows nest them: a modal debounces the tap that opened it, then the pad
    /// inside it debounces again. One spare sample absorbs the difference — an
    /// unclaimed one is read by a poll and costs a [`TOUCH_POLL_MS`] tick.
    pub fn taps(points: &[rsk_ui::Point]) -> Self {
        const GAP: usize = 2;
        let mut script = vec![None; GAP];
        for &p in points {
            script.push(Some(p));
            script.extend([None; GAP]);
        }
        Self::from(script, None)
    }

    /// An untouched sample — so the modal's opening release wait returns at once —
    /// and then a finger that stays down on `p`: a deliberate hold.
    pub fn hold(p: rsk_ui::Point) -> Self {
        Self::from(vec![None], Some(p))
    }

    /// The exact sample sequence, for a case the shapes above do not describe.
    pub fn script(samples: &[Option<rsk_ui::Point>]) -> Self {
        Self::from(samples.to_vec(), None)
    }
}

impl TouchPad for Pad {
    fn read(&mut self) -> Option<rsk_ui::Point> {
        self.reads += 1;
        self.script.pop_front().unwrap_or(self.tail)
    }
}

/// A pad that stays touched for ever but *records* the deadline a release wait
/// computed instead of blocking on it — so [`TouchPad::wait_release_ceremony`]'s
/// floor can be asserted without spending three seconds of it.
#[derive(Default)]
pub struct DeadlinePad {
    pub deadline: Option<Instant>,
}

impl TouchPad for DeadlinePad {
    fn read(&mut self) -> Option<rsk_ui::Point> {
        Some(rsk_ui::Point::new(0, 0))
    }

    fn wait_release_until(&mut self, deadline: Instant) {
        self.deadline = Some(deadline);
    }
}

/// The board verbs and firmware globals, as recorded state a test can set before a
/// flow and read after it.
pub struct Board {
    pub backlight: u16,
    pub led: u8,
    /// How many more polls the wake button reports pressed. A press is *spent* as
    /// it is read, so the bounded release waits return on their next poll rather
    /// than running their two-second bound out.
    pub wake_polls: core::cell::Cell<u32>,
    pub up_pending: bool,
    pub cancel: bool,
    /// A host `CTAPHID_CANCEL` landing mid-wait, after this many polls of the flag.
    /// Every ceremony clears `cancel` on entry — deliberately, so a stale cancel
    /// cannot abort the next one — so this is the only way a test can deliver one.
    pub cancel_in: core::cell::Cell<Option<u32>>,
    /// A host command is queued — what makes a modal yield the executor.
    pub host_pending: bool,
    pub reboot: Option<bool>,
    pub presence_ms: u32,
    pub secure_boot: bool,
    pub attach_ms: u64,
    /// How many times a panel-set PIN told the host side to end its sessions.
    pub pin_changed: usize,
    /// …and how many times a failed clientPIN comparison at the pad did.
    pub pin_failed: usize,
}

impl Board {
    fn new() -> Self {
        Self {
            backlight: 0,
            led: rsk_led::STATUS_IDLE,
            wake_polls: core::cell::Cell::new(0),
            up_pending: false,
            cancel: false,
            cancel_in: core::cell::Cell::new(None),
            host_pending: false,
            reboot: None,
            // Short enough that a flow which blocks to its presence timeout ends
            // inside a test rather than the device's 30 s.
            presence_ms: 400,
            secure_boot: false,
            attach_ms: 0,
            pin_changed: 0,
            pin_failed: 0,
        }
    }

    /// Press the wake button for the next `polls` samples of it.
    pub fn press_wake(&mut self, polls: u32) {
        self.wake_polls.set(polls);
    }
}

impl Hooks for Board {
    fn set_backlight(&mut self, duty: u16) {
        self.backlight = duty;
    }
    fn wake_pressed(&self) -> bool {
        let left = self.wake_polls.get();
        self.wake_polls.set(left.saturating_sub(1));
        left > 0
    }
    fn led_status(&self) -> u8 {
        self.led
    }
    fn set_led_status(&mut self, status: u8) {
        self.led = status;
    }
    fn attach_elapsed_ms(&self) -> u64 {
        self.attach_ms
    }
    fn host_request_pending_after(&self, _since: Instant) -> bool {
        self.host_pending
    }
    fn host_request_pending(&self) -> bool {
        self.host_pending
    }
    fn request_reboot(&mut self, bootsel: bool) {
        self.reboot = Some(bootsel);
    }
    fn reboot_pending(&self) -> bool {
        self.reboot.is_some()
    }
    fn note_local_pin_changed(&mut self) {
        self.pin_changed += 1;
    }
    fn note_local_pin_failed(&mut self) {
        self.pin_failed += 1;
    }
    fn secure_boot_enabled(&self) -> bool {
        self.secure_boot
    }
    fn set_up_pending(&mut self, pending: bool) {
        self.up_pending = pending;
    }
    fn set_cancel_requested(&mut self, requested: bool) {
        self.cancel = requested;
    }
    fn cancel_requested(&self) -> bool {
        match self.cancel_in.get() {
            Some(0) => true,
            Some(n) => {
                self.cancel_in.set(Some(n - 1));
                false
            }
            None => self.cancel,
        }
    }
    fn presence_timeout_ms(&self) -> u32 {
        self.presence_ms
    }
    fn set_presence_timeout_ms(&mut self, ms: u32) {
        self.presence_ms = ms;
    }
}

/// A deterministic stand-in for the device DRBG (xorshift64*). Nothing under test
/// consumes randomness for a decision — it is drawn only by the SLIP-39 split —
/// so a fixed stream is enough and keeps every run identical.
pub struct TestRng(u64);

impl TestRng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

impl rsk_sdk::Rng for TestRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let n = self.next().to_le_bytes();
            let len = chunk.len();
            chunk.copy_from_slice(&n[..len]);
        }
    }
}

/// The device identity every test seals against. Fixed, so a record written by one
/// helper unseals for another.
pub const SERIAL_ID: [u8; 8] = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18];
pub const SERIAL_HASH: [u8; 32] = [0x5A; 32];

/// The `Device` derivation context matching [`keys`], for a test that has to write
/// a sealed record (a PIN verifier) the flow will later read.
pub fn dev() -> rsk_crypto::Device<'static> {
    rsk_crypto::Device {
        serial_hash: &SERIAL_HASH,
        serial_id: &SERIAL_ID,
        otp_key: None,
    }
}

fn keys() -> DeviceKeys {
    DeviceKeys {
        serial_id: SERIAL_ID,
        serial_hash: SERIAL_HASH,
        mkek_source: None,
    }
}

/// A PIN that satisfies every build's floor — four code points by default, six
/// under `fips-profile` / `strong-pin` — and is not one of the guessable runs
/// those builds also reject.
pub const PIN: &[u8] = b"481629";
/// Same length, different digits: the wrong-PIN half of a retry-ladder test.
pub const WRONG_PIN: &[u8] = b"481620";
/// A third, equally valid PIN — what a change flow replaces [`PIN`] with.
pub const NEW_PIN: &[u8] = b"739154";

/// The crate's globals — the sleep timeout, the two activity stamps, the
/// ambient-quiet window — are `static`s the device has exactly one of, and a test
/// binary runs its cases on parallel threads. Every case that touches one takes
/// this lock through [`Env`], which also resets them, so a case starts from the
/// boot state instead of from whatever ran before it.
static GLOBALS: Mutex<()> = Mutex::new(());

/// The store, the DRBG and the globals lock a [`Ui`] borrows for its lifetime.
///
/// **One at a time.** The lock is not re-entrant, so a case that builds a second
/// `Env` while the first is alive hangs rather than fails — split it into two
/// cases instead, which is the shape they wanted anyway.
pub struct Env {
    pub fs: RefCell<Fs<RamStorage>>,
    pub rng: RefCell<TestRng>,
    // A failed assertion unwinds while this is held, which poisons the mutex; the
    // guard is taken with the poison ignored, so one failing case reports its own
    // failure instead of turning every later one into a `PoisonError`.
    _globals: MutexGuard<'static, ()>,
}

impl Default for Env {
    fn default() -> Self {
        Self::new()
    }
}

impl Env {
    pub fn new() -> Self {
        let guard = GLOBALS.lock().unwrap_or_else(|e| e.into_inner());
        SLEEP_TIMEOUT_MS.store(DEFAULT_SLEEP_MS, Ordering::Relaxed);
        AMBIENT_QUIET_UNTIL_MS.store(0, Ordering::Relaxed);
        // `status_loop` stamps the boot as local activity before its first frame;
        // start where it does, so a deadline test measures from a known zero.
        note_local_activity();
        Self {
            fs: RefCell::new(Fs::new(RamStorage::new())),
            rng: RefCell::new(TestRng(0x0DDB_A11C_0FFE_E1E5)),
            _globals: guard,
        }
    }

    /// Provision the device PIN the local gates verify against, as a host or an
    /// earlier on-device set would have left it.
    pub fn set_device_pin(&self, pin: &[u8]) {
        rsk_fido::passkeys::store_device_pin(&dev(), &mut self.fs.borrow_mut(), pin)
            .expect("the fixture PIN must satisfy the build's floor");
    }

    /// The flow, wired to `pad` — panel, board and store as a fresh boot sees them.
    pub fn ui(&self, pad: Pad) -> TestUi<'_> {
        Ui::new(
            Panel::new(),
            pad,
            Board::new(),
            DeviceInfo {
                version: 0x0875,
                chipid: 0x0123_4567_89AB_CDEF,
            },
            &self.fs,
            keys(),
            &self.rng,
        )
    }
}

pub type TestUi<'a> = Ui<'a, Panel, Pad, Board, RamStorage, TestRng>;

/// The middle of a control, so a tap is expressed as the thing it lands on rather
/// than as a pair of numbers that have to be kept in step with `rsk-ui`.
pub fn center(r: rsk_ui::Rect) -> rsk_ui::Point {
    rsk_ui::Point::new(r.x + r.w / 2, r.y + r.h / 2)
}

/// A point on no control at all — the top-right corner sits above every screen's
/// controls and clear of the nav bar, so a tap that must be a miss is one.
pub fn nowhere() -> rsk_ui::Point {
    rsk_ui::Point::new(rsk_ui::PANEL_W - 1, 0)
}

/// The pad key that produces `key`, found through `rsk-ui`'s own grid — so a
/// layout change moves these tests with it instead of past them.
pub fn pin_key(key: rsk_ui::PinKey) -> rsk_ui::Point {
    for row in 0..rsk_ui::PIN_ROWS {
        for col in 0..rsk_ui::PIN_COLS {
            if rsk_ui::pin_grid_key(col, row) == key {
                return center(rsk_ui::pin_key_rect(col, row));
            }
        }
    }
    panic!("the pad has no {key:?} key");
}

/// The taps that type `pin` and commit it with OK.
pub fn pin_entry(pin: &[u8]) -> Vec<rsk_ui::Point> {
    let mut taps: Vec<_> = pin
        .iter()
        .map(|&b| pin_key(rsk_ui::PinKey::Digit(b - b'0')))
        .collect();
    taps.push(pin_key(rsk_ui::PinKey::Ok));
    taps
}

/// Backdate both activity stamps by `ms`, through the same wrapping arithmetic the
/// deadline checks use — so a test reaches a sixty-second deadline without waiting
/// one, and the wrap-safety is exercised rather than assumed.
pub fn backdate(ms: u32) {
    let now = Instant::now().as_millis() as u32;
    LAST_ACTIVITY_MS.store(now.wrapping_sub(ms), Ordering::Relaxed);
    LAST_LOCAL_MS.store(now.wrapping_sub(ms), Ordering::Relaxed);
}

/// Backdate only the *local* stamp: what the panel looks like after a long run of
/// host ceremonies with nobody touching it.
pub fn backdate_local(ms: u32) {
    LAST_LOCAL_MS.store(
        (Instant::now().as_millis() as u32).wrapping_sub(ms),
        Ordering::Relaxed,
    );
}

// --- the crate root's own logic --------------------------------------------

#[test]
fn every_brightness_level_lights_the_panel() {
    // Level 0 does not exist; the clamp must not let it through as a 0 duty, which
    // is what `sleep` uses to blank the glass.
    for level in 0..=BRIGHTNESS_LEVELS + 3 {
        assert!(level_duty(level) > 0, "level {level} blanked the panel");
        assert!(level_duty(level) <= BL_TOP);
    }
    assert_eq!(level_duty(BRIGHTNESS_LEVELS), BL_TOP);
    assert_eq!(level_duty(0), level_duty(1));
    assert_eq!(level_duty(BRIGHTNESS_LEVELS + 1), BL_TOP);
}

#[test]
fn brightness_levels_are_ordered() {
    for level in 1..BRIGHTNESS_LEVELS {
        assert!(level_duty(level) < level_duty(level + 1));
    }
}

#[test]
fn the_marquee_buffer_preserves_partial_coverage() {
    let band = rsk_ui::PIN_TITLE_BAND;
    let mut coverage = [0u8; MARQUEE_COVERAGE_BYTES];
    let partial = rsk_ui::aa::blend_coverage(rsk_ui::theme::TEXT, rsk_ui::theme::PANEL_BG, 7);
    {
        let mut target = BandCoverage::new(&mut coverage, band);
        let at = |x: u16, y: u16| EgPoint::new(x as i32, y as i32);
        target
            .draw_iter([
                Pixel(at(band.x, band.y), partial),
                Pixel(at(band.x + 1, band.y), rsk_ui::theme::PANEL_BG),
            ])
            .unwrap();
    }
    assert_eq!(
        rsk_ui::aa::blend_coverage(
            rsk_ui::theme::TEXT,
            rsk_ui::theme::PANEL_BG,
            packed_coverage(&coverage, 0),
        ),
        partial
    );
    assert_eq!(packed_coverage(&coverage, 1), 0);
}

#[test]
fn the_marquee_buffer_keeps_antialiased_title_edges() {
    let band = rsk_ui::PIN_TITLE_BAND;
    let mut coverage = [0u8; MARQUEE_COVERAGE_BYTES];
    let mut target = BandCoverage::new(&mut coverage, band);
    rsk_ui::render_pin_title(&mut target, "OpenPGP Sign PIN", 7).unwrap();
    assert!(
        (0..usize::from(band.w) * usize::from(band.h))
            .map(|index| packed_coverage(&coverage, index))
            .any(|value| value > 0 && value < rsk_ui::aa::COVERAGE_MAX)
    );
}

/// The band buffer used to refuse any colour it could not place on the TEXT/PANEL_BG
/// ramp, and `render_marquee_frame` answered that refusal by zeroing the buffer -- so
/// one off-ramp pixel blanked the whole title. The 1-bit mask this replaced took the
/// tolerant rule instead: not the background means ink. Keep that rule.
#[test]
fn an_off_ramp_colour_lands_as_ink_rather_than_refusing_the_frame() {
    let band = rsk_ui::PIN_TITLE_BAND;
    let mut coverage = [0u8; MARQUEE_COVERAGE_BYTES];
    {
        let mut target = BandCoverage::new(&mut coverage, band);
        let at = |x: u16, y: u16| EgPoint::new(x as i32, y as i32);
        target
            .draw_iter([
                Pixel(at(band.x, band.y), rsk_ui::theme::ACCENT),
                Pixel(at(band.x + 1, band.y), rsk_ui::theme::PANEL_BG),
            ])
            .unwrap();
    }
    assert_eq!(packed_coverage(&coverage, 0), rsk_ui::aa::COVERAGE_MAX);
    assert_eq!(packed_coverage(&coverage, 1), 0);
}

/// The band target cannot fail, and that is the point: an error type here is a way for
/// a future frame to come back empty. `Infallible` is what removes the branch. Checked
/// at compile time -- the body type-checks whether or not the test is run.
#[test]
fn the_band_target_has_no_way_to_fail() {
    fn infallible<D: DrawTarget<Error = core::convert::Infallible>>() {}
    infallible::<BandCoverage<'static>>();
}

#[test]
fn the_marquee_buffer_drops_a_pixel_outside_the_band() {
    let band = rsk_ui::PIN_TITLE_BAND;
    let mut coverage = [0u8; MARQUEE_COVERAGE_BYTES];
    {
        let mut target = BandCoverage::new(&mut coverage, band);
        let out = [
            EgPoint::new(band.x as i32 - 1, band.y as i32),
            EgPoint::new(band.x as i32, band.y as i32 - 1),
            EgPoint::new(band.x as i32 + band.w as i32, band.y as i32),
            EgPoint::new(band.x as i32, band.y as i32 + band.h as i32),
        ];
        target
            .draw_iter(out.map(|p| Pixel(p, rsk_ui::theme::TEXT)))
            .unwrap();
    }
    assert!(
        coverage.iter().all(|&value| value == 0),
        "a pixel outside the band reached the buffer"
    );
}

#[test]
fn a_fresh_device_boots_onto_the_onboarding_offer() {
    let env = Env::new();
    let ui = env.ui(Pad::idle());
    assert!(ui.onboarding);
    assert!(!ui.locked, "there is no PIN to unlock with");
}

#[test]
fn a_device_with_a_pin_boots_locked() {
    let env = Env::new();
    env.set_device_pin(PIN);
    let ui = env.ui(Pad::idle());
    assert!(ui.locked);
    assert!(!ui.onboarding, "locked and onboarding are exclusive");
    assert!(ui.home_pin_set, "the Home card's PIN bit is seeded at boot");
}

#[test]
fn a_declined_pin_offer_is_not_made_twice() {
    let env = Env::new();
    let cfg = rsk_ui::DisplayConfig {
        pin_declined: true,
        ..Default::default()
    };
    env.fs
        .borrow_mut()
        .put(EF_DISPLAY, &cfg.encode())
        .expect("EF_DISPLAY");
    let ui = env.ui(Pad::idle());
    assert!(!ui.onboarding);
    assert!(!ui.locked);
}

#[test]
fn boot_restores_the_saved_display_settings() {
    let env = Env::new();
    let cfg = rsk_ui::DisplayConfig {
        brightness: 2,
        sleep_secs: 15,
        pin_declined: false,
    };
    env.fs
        .borrow_mut()
        .put(EF_DISPLAY, &cfg.encode())
        .expect("EF_DISPLAY");
    let ui = env.ui(Pad::idle());
    assert_eq!(ui.brightness, cfg.brightness);
    assert_eq!(
        SLEEP_TIMEOUT_MS.load(Ordering::Relaxed),
        cfg.sleep_secs as u32 * 1000
    );
    // The backlight comes up at the saved level, not full — no bright flash to dim.
    assert_eq!(ui.hooks.backlight, level_duty(cfg.brightness));
}

#[test]
fn boot_clamps_a_corrupt_brightness_byte() {
    let env = Env::new();
    let cfg = rsk_ui::DisplayConfig {
        brightness: 0,
        ..Default::default()
    };
    env.fs
        .borrow_mut()
        .put(EF_DISPLAY, &cfg.encode())
        .expect("EF_DISPLAY");
    let ui = env.ui(Pad::idle());
    assert_eq!(ui.brightness, 1, "a 0 byte must not blank the panel");
    assert!(ui.hooks.backlight > 0);
}

#[test]
fn a_host_ceremony_does_not_postpone_the_lock() {
    // The whole point of the second stamp (audit run-34 #15): a host may hold the
    // backlight awake, but nothing a host does may push the auto-lock out.
    let _env = Env::new();
    backdate(10_000);
    let local_before = LAST_LOCAL_MS.load(Ordering::Relaxed);
    note_activity();
    assert_eq!(LAST_LOCAL_MS.load(Ordering::Relaxed), local_before);
    note_local_activity();
    assert_ne!(LAST_LOCAL_MS.load(Ordering::Relaxed), local_before);
}

/// `Worker::run` races several wake sources and `host_request_pending` decides
/// which of them an open modal must yield to. Nothing but this test links the two
/// lists, and a source added to one and forgotten in the other starves silently
/// behind a menu for a minute — which is what the OTP keyboard frame did (E190).
///
/// It compares the two *sets of receivers*, both parsed the same way, rather than
/// asking whether each name appears: `REQ` is a suffix of `otp_kbd::OTP_REQ`, so a
/// substring test passed a predicate that had dropped the transports entirely.
#[test]
fn every_worker_wake_source_is_classified() {
    let raw = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../firmware/src/worker.rs"),
    )
    .expect("firmware/src/worker.rs");
    // Every assertion below reads source text, so a comment naming the token it
    // looks for would satisfy it (the class `bbc506c` fixed in the gate scripts).
    let worker = strip_line_comments(&raw);

    // A fourth source means `select4`: the moment to classify it, here and in
    // `host_request_pending` — not to widen this assertion.
    assert_eq!(
        worker.matches("match select3(").count(),
        1,
        "the worker no longer races exactly three sources in exactly one place"
    );
    let raced = receivers(select3_args(&worker), ".wait()");
    assert_eq!(
        raced,
        ["REQ", "otp_kbd::OTP_REQ"],
        "the worker's wake sources moved"
    );

    let pending = fn_body(&worker, "pub(crate) fn host_request_pending()");
    assert_eq!(
        receivers(pending, ".signaled()"),
        raced,
        "`host_request_pending` consults a different set than the worker races; \
         work from a source it omits starves behind an open modal"
    );

    // Nearly every browse loop takes the floor variant, so a second copy of the
    // list there is the copy that would decide. It must delegate, not repeat.
    let after = fn_body(&worker, "pub(crate) fn host_request_pending_after(");
    assert!(
        after.contains("host_request_pending()"),
        "`host_request_pending_after` no longer delegates"
    );
    assert!(
        receivers(after, ".signaled()").is_empty(),
        "`host_request_pending_after` keeps its own source list; delegate instead"
    );
    // What makes it safe to let one more transport close the owner's screen
    // (audit run-35): without the floor, one queued command latches the yield.
    assert!(
        after.contains("UI_YIELD_FLOOR_MS"),
        "the floor variant no longer applies the floor"
    );
}

/// Drop `//` comments, so an assertion below cannot be satisfied by a comment that
/// names the token it looks for. Block comments are refused rather than parsed —
/// a naive `/*` scan is what swallowed a whole file in `bbc506c`.
fn strip_line_comments(src: &str) -> String {
    assert!(
        !src.contains("/*"),
        "worker.rs grew a block comment; this parser only handles `//`"
    );
    src.lines()
        .map(|l| l.split_once("//").map_or(l, |(code, _)| code))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The argument list of `Worker::run`'s `select3`.
fn select3_args(worker: &str) -> &str {
    let at = worker.find("match select3(").expect("the worker's select3");
    let arms = &worker[at..];
    let end = arms
        .find("\n            )")
        .expect("the select3 argument list");
    &arms[..end]
}

/// Every path receiving `suffix` in `text`, in source order — `REQ.wait()` yields
/// `REQ`, `otp_kbd::OTP_REQ.signaled()` yields the whole path. The `select3` timer
/// arm receives neither and is deliberately not one of them.
fn receivers(text: &str, suffix: &str) -> Vec<String> {
    text.match_indices(suffix)
        .map(|(at, _)| {
            text[..at]
                .chars()
                .rev()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == ':')
                .collect::<String>()
                .chars()
                .rev()
                .collect()
        })
        .collect()
}

/// The body of the function whose signature line is `sig`, by brace matching.
fn fn_body<'a>(src: &'a str, sig: &str) -> &'a str {
    assert_eq!(src.matches(sig).count(), 1, "{sig} is gone, or duplicated");
    let at = src.find(sig).expect("checked above");
    let open = at + src[at..].find('{').expect("a body");
    let mut depth = 0usize;
    for (i, c) in src[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    // The two bodies this is used on are boolean expressions; a
                    // string literal in one could carry a brace past the match.
                    let body = &src[open..open + i];
                    assert!(!body.contains('"'), "{sig}'s body grew a string literal");
                    return body;
                }
            }
            _ => {}
        }
    }
    panic!("{sig} has no closing brace");
}
