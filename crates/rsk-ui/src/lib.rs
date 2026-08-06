// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The hardware-agnostic UI model for the trusted-display build (`--features
//! display`): what to show on the ST7789 panel and how to interpret a CST328
//! touch. It owns no hardware — the firmware's `display.rs` (the ST7789/CST328
//! task) drives the panel and asks this crate *what* to draw and *which* button a
//! tap landed on. Keeping the model here (pure, no `embassy`/HAL) makes the
//! security-critical parts — above all the untrusted-string [`Label::clamp`] that
//! sanitizes relying-party text before it reaches the framebuffer — unit-testable
//! on the host and provable under Kani, exactly like `rsk-led`'s codec.
//!
//! The button geometry ([`ALLOW_RECT`] / [`DENY_RECT`] and [`hit_confirm`]) is the
//! single source of truth shared by the renderer and the hit-test, so a tap can
//! never approve a region the screen didn't actually paint as "Allow".

#![cfg_attr(not(test), no_std)]

pub mod aa;
pub mod font;
pub mod glyph;
pub mod render;
pub mod settings_store;
pub mod theme;
pub mod touch;
pub use glyph::Glyph;
pub use render::{
    PIN_TITLE_BAND, SEED_WORDS_PER_PAGE, STATUS_ARC_START, pin_title_overflows, render,
    render_add_passkey, render_apps, render_audit_log, render_backup, render_backup_format,
    render_confirm_delete, render_confirm_factory_reset, render_erasing, render_firmware,
    render_hold_button, render_hold_fill, render_locked_breathe, render_oath, render_oath_cred,
    render_openpgp, render_openpgp_cardholder, render_openpgp_key, render_passkeys_list,
    render_pin_blocked, render_pin_dots, render_pin_title, render_piv, render_piv_extra,
    render_piv_keygen_confirm, render_piv_keygen_pick, render_piv_keygen_rsa_pick,
    render_piv_keygen_working, render_piv_pin_menu, render_piv_protect_confirm, render_piv_slot,
    render_rebooting, render_rename, render_rename_field, render_rename_keys,
    render_reveal_warning, render_seal_confirm, render_seed_phrase, render_service,
    render_share_picker, render_slip39_share, render_status_arc, render_success,
    render_success_circle, render_wipe_failed,
};
pub use settings_store::{CONF_LEN as DISPLAY_CONF_LEN, DisplayConfig};

/// Panel geometry (Waveshare RP2350-Touch-LCD-2.8, ST7789T3, portrait).
pub const PANEL_W: u16 = 240;
/// Panel height in pixels.
pub const PANEL_H: u16 = 320;

/// A touch coordinate in panel pixels (CST328 reports the same axes the ST7789 is
/// addressed in; the firmware driver normalizes any rotation before it gets here).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Point {
    pub x: u16,
    pub y: u16,
}

impl Point {
    pub const fn new(x: u16, y: u16) -> Self {
        Self { x, y }
    }
}

/// An axis-aligned rectangle in panel pixels. Used both to paint a control and to
/// hit-test a tap against it, so the two can never disagree.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

impl Rect {
    pub const fn new(x: u16, y: u16, w: u16, h: u16) -> Self {
        Self { x, y, w, h }
    }

    /// Is `p` inside this rectangle? Left/top inclusive, right/bottom exclusive,
    /// so abutting rectangles never both claim a point. Saturating arithmetic
    /// keeps an absurd `x+w` from wrapping.
    pub const fn contains(&self, p: Point) -> bool {
        p.x >= self.x
            && p.y >= self.y
            && p.x < self.x.saturating_add(self.w)
            && p.y < self.y.saturating_add(self.h)
    }
}

/// Maximum sanitized label length (bytes == printable-ASCII chars) kept for a
/// relying-party id or account name. Sized so the renderer can wrap it across at
/// most a couple of lines on the 240px-wide panel; anything longer is truncated
/// (with [`Label::truncated`] set) so a padded look-alike id can't push the real
/// suffix off-screen unnoticed.
pub const LABEL_MAX: usize = 48;

/// A relying-party-supplied string, sanitized for safe display. RP text is
/// **untrusted**: it can carry control bytes, terminal escapes, non-UTF-8, or be
/// arbitrarily long. [`Label::clamp`] reduces it to bounded printable 7-bit ASCII
/// before it can ever reach the framebuffer, so the renderer only handles a known,
/// fixed alphabet and [`as_str`](Label::as_str) is always valid UTF-8.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Label {
    buf: [u8; LABEL_MAX],
    len: usize,
    /// The source was longer than [`LABEL_MAX`] and got cut — the renderer should
    /// mark it so a padded look-alike can't hide its tail.
    pub truncated: bool,
}

impl Default for Label {
    fn default() -> Self {
        Self {
            buf: [0; LABEL_MAX],
            len: 0,
            truncated: false,
        }
    }
}

impl Label {
    /// Sanitize untrusted bytes into a bounded printable-ASCII label. Every byte
    /// outside `0x20..=0x7E` (controls, DEL, the whole high half — including
    /// UTF-8 continuation bytes) becomes `'?'`, so terminal escapes and bidi /
    /// homoglyph tricks can't survive. The result is at most [`LABEL_MAX`] bytes;
    /// a longer source sets [`truncated`](Label::truncated). Total function — no
    /// input panics.
    pub fn clamp(src: &[u8]) -> Self {
        let mut out = Label::default();
        for &b in src.iter() {
            if out.len == LABEL_MAX {
                out.truncated = true;
                break;
            }
            out.buf[out.len] = if (0x20..=0x7E).contains(&b) { b } else { b'?' };
            out.len += 1;
        }
        out
    }

    /// Like [`clamp`](Label::clamp) but for a **domain** (relying-party id): keep the
    /// **tail**, not the head. A domain's security-relevant part is its registrable
    /// suffix (`attacker.com` in `accounts.google.com.attacker.com`), which is the
    /// rightmost labels — so an over-long id must drop the head (the subdomains a
    /// look-alike pads with), never the suffix. Same per-byte sanitization; keeps at
    /// most the last [`LABEL_MAX`] bytes and sets [`truncated`](Label::truncated)
    /// when it cut. Renderers pair this with a *head* ellipsis so the suffix stays
    /// visible. (A precise eTLD+1 needs a public-suffix list we don't ship on-device;
    /// the fixed-size tail always contains the registrable domain.) Total function.
    pub fn clamp_domain(src: &[u8]) -> Self {
        let mut out = Label::default();
        // Each source byte maps to exactly one output byte, so the last LABEL_MAX
        // input bytes are the last LABEL_MAX sanitized bytes.
        let start = src.len().saturating_sub(LABEL_MAX);
        out.truncated = start > 0;
        for &b in src[start..].iter() {
            out.buf[out.len] = if (0x20..=0x7E).contains(&b) { b } else { b'?' };
            out.len += 1;
        }
        out
    }

    /// The sanitized text. Always valid UTF-8 (it is 7-bit ASCII by construction),
    /// so this never returns the error branch — but we fall back to empty rather
    /// than `unwrap` to stay panic-free even if the invariant were ever broken.
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }

    /// Is the label empty (no source text)?
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// The content of a trusted Allow/Deny prompt: the device-controlled operation
/// title plus up to two sanitized relying-party fields (e.g. rp id and account).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ConfirmPrompt {
    /// Trusted, device-controlled prompt header (e.g. `"Sign in?"`), supplied by
    /// the firmware applet via `rsk_sdk::Confirm`. Never relying-party text — that
    /// goes in the sanitized [`Label`]s below.
    pub title: &'static str,
    /// Primary subject — the relying-party id for FIDO, or a key label.
    pub primary: Label,
    /// Secondary subject — the account / user name, when the request carries one.
    pub secondary: Label,
}

impl ConfirmPrompt {
    /// Build a prompt from a trusted title, sanitizing both untrusted fields. Pass
    /// empty slices for fields the request doesn't carry.
    pub fn new(title: &'static str, primary: &[u8], secondary: &[u8]) -> Self {
        Self {
            title,
            // The primary is the relying-party id (a domain) — keep its registrable
            // suffix, not the head a look-alike would pad. The secondary (account
            // name) keeps the head, like every other user-chosen label.
            primary: Label::clamp_domain(primary),
            secondary: Label::clamp(secondary),
        }
    }
}

/// The two outcomes a confirmation tap can select.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Button {
    Allow,
    Deny,
}

/// Approve-screen button geometry: a narrow **Deny** on the left (a single tap, the
/// safe default) and a wider **Hold-to-approve** on the right (a deliberate sustained
/// press — the firmware fills it as you hold, so a brush can't approve). Both float
/// above the bottom edge; the space around them is security margin, so a tap in a
/// margin or the gap selects *nothing* ([`hit_confirm`] → `None`).
pub const BTN_H: u16 = 56;
/// Inset from the left/right panel edges.
const BTN_SIDE: u16 = 14;
/// Gap between the Deny and Hold-to-approve buttons.
const BTN_GAP: u16 = 12;
/// Float above the bottom panel edge.
const BTN_BOTTOM: u16 = 16;
/// Deny button width (narrow — the safe action needs no emphasis; the design makes
/// the hold the wider of the two). Sized to fit "Cancel"; the rest of the row goes to
/// the hold so "Hold to approve" sits comfortably inside it.
const DENY_W: u16 = 72;
/// Hold-to-approve width (the rest of the row — the wider, deliberate action).
const ALLOW_W: u16 = PANEL_W - 2 * BTN_SIDE - DENY_W - BTN_GAP;
/// Top of the button row; the trusted prompt fills the space above it.
pub const BTN_BAND_TOP: u16 = PANEL_H - BTN_H - BTN_BOTTOM;
/// Deny on the left (the safe default), a single tap.
pub const DENY_RECT: Rect = Rect::new(BTN_SIDE, BTN_BAND_TOP, DENY_W, BTN_H);
/// Hold-to-approve on the right, wider; a full [`BTN_GAP`] separates it from Deny.
pub const ALLOW_RECT: Rect = Rect::new(BTN_SIDE + DENY_W + BTN_GAP, BTN_BAND_TOP, ALLOW_W, BTN_H);

// Compile-time layout invariants (paint and hit-test share these rects): the two
// floating buttons are disjoint with a real gap between them, and both sit fully
// inside the panel below the prompt area. A bad edit to the geometry fails the build.
const _: () = {
    assert!(DENY_RECT.x + DENY_RECT.w < ALLOW_RECT.x);
    assert!(DENY_RECT.x > 0 && ALLOW_RECT.x + ALLOW_RECT.w < PANEL_W);
    assert!(DENY_RECT.y > BTN_BAND_TOP - 1 && ALLOW_RECT.y + ALLOW_RECT.h < PANEL_H);
};

/// Which button, if any, a tap at `p` selects on the confirm screen. A tap in the
/// prompt area above the button band returns `None` (no accidental approval from a
/// stray touch). The two rectangles are disjoint by construction, so at most one
/// matches.
pub fn hit_confirm(p: Point) -> Option<Button> {
    if ALLOW_RECT.contains(p) {
        Some(Button::Allow)
    } else if DENY_RECT.contains(p) {
        Some(Button::Deny)
    } else {
        None
    }
}

/// The first-run onboarding choice on the [`Screen::Onboard`] screen: set a device
/// PIN now, or continue without one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OnboardChoice {
    /// Open the on-screen PIN set flow.
    SetPin,
    /// Continue without a device PIN (a deliberate, remembered choice).
    Skip,
}

/// Onboarding button geometry: two full-width stacked buttons, so the long
/// "Continue without PIN" label fits without scrolling. The primary **Set a PIN**
/// sits above the secondary **Skip**, which shares the bottom band the confirm
/// screens use ([`BTN_BAND_TOP`]). A tap outside both selects nothing.
const ONBOARD_BTN_W: u16 = PANEL_W - 2 * BTN_SIDE;
/// Vertical gap between the two stacked onboarding buttons.
const ONBOARD_BTN_GAP: u16 = 12;
/// **Set a PIN** (primary, filled): one row above the bottom band.
pub const ONBOARD_SET_RECT: Rect = Rect::new(
    BTN_SIDE,
    BTN_BAND_TOP - BTN_H - ONBOARD_BTN_GAP,
    ONBOARD_BTN_W,
    BTN_H,
);
/// **Continue without PIN** (secondary, outlined): the bottom band.
pub const ONBOARD_SKIP_RECT: Rect = Rect::new(BTN_SIDE, BTN_BAND_TOP, ONBOARD_BTN_W, BTN_H);

// Compile-time layout invariants: the two stacked buttons are disjoint with a real
// gap, and both sit fully inside the panel.
const _: () = {
    assert!(ONBOARD_SET_RECT.y + ONBOARD_SET_RECT.h < ONBOARD_SKIP_RECT.y);
    assert!(ONBOARD_SKIP_RECT.y + ONBOARD_SKIP_RECT.h < PANEL_H);
    assert!(ONBOARD_SET_RECT.x > 0 && ONBOARD_SET_RECT.x + ONBOARD_SET_RECT.w < PANEL_W);
};

/// Which onboarding button, if any, a tap at `p` selects. The two rectangles are
/// disjoint by construction, so at most one matches; a tap elsewhere returns `None`.
pub fn hit_onboard(p: Point) -> Option<OnboardChoice> {
    if ONBOARD_SET_RECT.contains(p) {
        Some(OnboardChoice::SetPin)
    } else if ONBOARD_SKIP_RECT.contains(p) {
        Some(OnboardChoice::Skip)
    } else {
        None
    }
}

// --- PIN pad (built-in user verification) ----------------------------------

/// A key on the on-screen numeric PIN pad (the trusted-display built-in-UV input).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PinKey {
    /// A digit 0–9.
    Digit(u8),
    /// Backspace — drop the last entered digit.
    Del,
    /// Commit the entered PIN.
    Ok,
    /// Abandon entry — a deliberate decline.
    Cancel,
    /// Toggle the entry between masked dots and the typed digits — so the user can check
    /// what they typed before committing.
    Reveal,
}

/// The line shown under the pad: either a danger-coloured rejection (a wrong PIN is not
/// a silent re-prompt) or a muted informational hint (the design's `enterpin` /
/// `createpin` / `confirmpin` sub-labels). Distinct from the header `title`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PinCaption {
    /// The entered PIN was wrong; `retries_left` attempts remain before the hard lock.
    WrongPin { retries_left: u8 },
    /// The two new-PIN entries didn't match (the set/change confirm step).
    Mismatch,
    /// Up-front on the unlock pad: how many attempts remain before the hard lock
    /// (the design's `enterpin` "N tries remaining"). Muted, not a rejection.
    TriesRemaining { left: u8 },
    /// The set flow's first step (`createpin`): a muted "Choose a PIN" prompt.
    ChoosePin,
    /// The set flow's second step (`confirmpin`): a muted "Re-enter to confirm" prompt.
    Reenter,
    /// The set flow refused a trivially guessable PIN (the `strong-pin` / `fips-profile`
    /// policy): a danger-coloured re-prompt.
    TooWeak,
}

impl PinCaption {
    /// Whether this caption is a rejection (danger-coloured) rather than an informational
    /// hint (muted) — the renderer colours the line by this.
    pub const fn is_rejection(self) -> bool {
        matches!(self, Self::WrongPin { .. } | Self::Mismatch | Self::TooWeak)
    }
}

/// What the PIN screen shows: how many digits have been entered (rendered as masked
/// dots — never the digits themselves, which the firmware keeps and never paints), a
/// short header naming the step ("Enter PIN", "New PIN", "Confirm PIN", …) so the same
/// pad serves built-in UV, the unlock/delete gates, and the on-device set/change flow,
/// an `expected` count of placeholder dots (the policy minimum, so the row reads as the
/// design's fixed indicator rather than a growing run), and an optional [`PinCaption`]
/// feedback / hint line.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PinPad {
    /// Count of digits entered so far (shown masked).
    pub entered: usize,
    /// The header caption — a trusted, firmware-supplied `&'static str`, never RP data.
    pub title: &'static str,
    /// Placeholder dots to outline before any are filled (the minimum PIN length). `0`
    /// shows only the filled dots — a growing run with no placeholders.
    pub expected: u8,
    /// Feedback / hint under the pad; `None` on a bare prompt.
    pub caption: Option<PinCaption>,
}

impl PinPad {
    /// The default pad header ("Enter PIN") — built-in UV and the local verify gates.
    pub const fn new(entered: usize) -> Self {
        Self::with_title(entered, "Enter PIN")
    }

    /// A pad with a custom header (the set/change flow's "New PIN" / "Confirm PIN" /
    /// "Current PIN" steps). `title` must be a trusted constant, not untrusted RP text.
    pub const fn with_title(entered: usize, title: &'static str) -> Self {
        Self {
            entered,
            title,
            expected: 0,
            caption: None,
        }
    }

    /// A pad with a header and a feedback / hint caption.
    pub const fn with_caption(
        entered: usize,
        title: &'static str,
        caption: Option<PinCaption>,
    ) -> Self {
        Self {
            entered,
            title,
            expected: 0,
            caption,
        }
    }

    /// Set the number of placeholder dots (the policy minimum), so the entry row reads as
    /// the design's fixed indicator. The filled dots still grow past it for a longer PIN.
    pub const fn expecting(mut self, expected: u8) -> Self {
        self.expected = expected;
        self
    }
}

/// PIN-pad grid: 3 columns. The bottom row is Del / 0 / OK.
pub const PIN_COLS: u16 = 3;
/// PIN-pad grid rows (1–9, then Del / 0 / OK).
pub const PIN_ROWS: u16 = 4;
/// Key width.
pub const PIN_KEY_W: u16 = 64;
/// Key height.
pub const PIN_KEY_H: u16 = 48;
// Origin recomputed to keep the grid horizontally centred at the design's 7px gap:
// X0 = (PANEL_W − (3·PIN_KEY_W + 2·PIN_GAP_X)) / 2 = (240 − 206) / 2 = 17, so the left and
// right margins match (a `pin_grid_is_horizontally_centred` test guards it).
const PIN_GRID_X0: u16 = 17;
const PIN_GRID_Y0: u16 = 84;
const PIN_GAP_X: u16 = 7;
const PIN_GAP_Y: u16 = 7;
/// Cancel target, in the header above the grid — kept clear of the digit keys so a
/// digit tap can never abandon entry.
pub const PIN_CANCEL_RECT: Rect = Rect::new(8, 6, 40, 34);

/// The reveal (eye) toggle, at the right of the masked-entry band — between the header
/// and the grid, so it can never be confused with a digit, Cancel, or OK. Tapping it
/// flips the entry between dots and the typed digits, on every PIN screen (the entry pad
/// is shared by built-in UV, the unlock/delete/factory-reset gates, and set/change PIN).
/// `y` is chosen so the glyph centres on the dot row (centre y 60), not 2px below it.
pub const PIN_EYE_RECT: Rect = Rect::new(204, 42, 36, 36);

/// The rectangle of the key at grid position `(col, row)` — the single source of
/// truth shared by the renderer and [`hit_pin`], so paint and hit-test can never
/// disagree (the Allow/Deny contract, extended to the pad).
pub const fn pin_key_rect(col: u16, row: u16) -> Rect {
    Rect::new(
        PIN_GRID_X0 + col * (PIN_KEY_W + PIN_GAP_X),
        PIN_GRID_Y0 + row * (PIN_KEY_H + PIN_GAP_Y),
        PIN_KEY_W,
        PIN_KEY_H,
    )
}

/// The key at grid position `(col, row)`: rows 0–2 hold digits 1–9 in reading
/// order; the bottom row is Del / 0 / OK.
pub const fn pin_grid_key(col: u16, row: u16) -> PinKey {
    match (col, row) {
        (0, 3) => PinKey::Del,
        (1, 3) => PinKey::Digit(0),
        (2, 3) => PinKey::Ok,
        _ => PinKey::Digit((row * PIN_COLS + col + 1) as u8),
    }
}

// Compile-time layout invariants: positive gaps (rows/columns disjoint), the whole
// grid fits below the header, and the Cancel target sits entirely above the grid.
// A bad geometry edit fails the build.
const _: () = {
    assert!(PIN_GAP_X > 0 && PIN_GAP_Y > 0);
    let last = pin_key_rect(PIN_COLS - 1, PIN_ROWS - 1);
    assert!(last.x + last.w <= PANEL_W && last.y + last.h <= PANEL_H);
    assert!(PIN_CANCEL_RECT.y + PIN_CANCEL_RECT.h <= PIN_GRID_Y0);
    assert!(PIN_CANCEL_RECT.x + PIN_CANCEL_RECT.w <= PANEL_W);
    // The eye toggle sits in the band between the header and the grid, inside the panel.
    assert!(PIN_EYE_RECT.x + PIN_EYE_RECT.w <= PANEL_W);
    assert!(PIN_EYE_RECT.y >= PIN_CANCEL_RECT.y + PIN_CANCEL_RECT.h);
    assert!(PIN_EYE_RECT.y + PIN_EYE_RECT.h <= PIN_GRID_Y0);
};

/// Which PIN-pad key, if any, a tap at `p` selects. Cancel (header) is tested first,
/// then the 3×4 grid. The rects are disjoint by construction, so at most one matches;
/// a tap in a gap or margin selects nothing.
pub fn hit_pin(p: Point) -> Option<PinKey> {
    if PIN_CANCEL_RECT.contains(p) {
        return Some(PinKey::Cancel);
    }
    if PIN_EYE_RECT.contains(p) {
        return Some(PinKey::Reveal);
    }
    let mut row = 0;
    while row < PIN_ROWS {
        let mut col = 0;
        while col < PIN_COLS {
            if pin_key_rect(col, row).contains(p) {
                return Some(pin_grid_key(col, row));
            }
            col += 1;
        }
        row += 1;
    }
    None
}

// --- Settings menu (interactive idle) --------------------------------------

/// Which settings page is on screen.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SettingsPage {
    /// The top-level list: Display / Security / Firmware — three domains (the title-bar is
    /// gone here; the bottom nav, Settings active, is the way out).
    Root,
    /// The Display sub-page: Brightness / Display sleep / Touch timeout. Reached from the
    /// Root "Display" row; its back chevron returns to Root, and each row drills into an
    /// adjust page that backs out to *this* page.
    Display,
    /// Backlight-level adjust (−/+/Back).
    Brightness,
    /// Touch-timeout adjust (−/+/Back).
    Timeout,
    /// Display-sleep timeout adjust (−/+/Back) — blanks the panel after inactivity to
    /// stop image retention on the IPS glass.
    Sleep,
    /// The Security sub-page: device + FIDO PIN, the audit log, the backup status, and the
    /// (danger) Factory reset. Reached from the Root "Security" row; the title-bar back
    /// chevron returns to Root.
    Security,
}

/// Discrete backlight steps the brightness page cycles through (1 = dimmest kept on,
/// never 0 — the menu never blanks the panel you're navigating).
pub const BRIGHTNESS_LEVELS: u8 = 5;
/// Touch-timeout choices in seconds the timeout page steps between.
pub const TIMEOUT_CHOICES: [u16; 5] = [10, 20, 30, 60, 120];
/// Display-sleep choices in seconds the sleep page steps between; the final `0` is the
/// "Off" sentinel (never blank). Kept ascending by wake-awake time so `+` lengthens it
/// up to Off.
pub const SLEEP_CHOICES: [u16; 6] = [15, 30, 60, 120, 300, 0];

/// The settings view model: the current page plus the live values its pages show.
/// Carried in [`Screen::Settings`] so the renderer paints the current brightness
/// level, timeout and device identity without reaching into the firmware.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SettingsView {
    pub page: SettingsPage,
    /// Backlight level `1..=BRIGHTNESS_LEVELS`.
    pub brightness: u8,
    /// Current presence/touch timeout, seconds.
    pub timeout_secs: u16,
    /// Current display-sleep timeout, seconds (`0` = Off, never blanks).
    pub sleep_secs: u16,
    /// bcdDevice firmware build counter, shown in hex on the Firmware row + screen.
    pub version: u16,
    /// RP2350 chip serial, shown in hex on the Firmware screen.
    pub chipid: u64,
    /// Whether the device PIN is set — the Security page's Device-PIN row shows "Change
    /// PIN" if so, else "Set PIN". The device PIN gates the on-device UI (lock, delete,
    /// factory reset), independent of the FIDO clientPIN.
    pub device_pin_set: bool,
    /// Whether the FIDO clientPIN is set — the Security page's FIDO-PIN row label.
    pub fido_pin_set: bool,
    /// Whether the seed-backup export window is sealed — the Security page's Backup row
    /// shows "Sealed" (the seed is backed up) or "Review" (the window is still open).
    pub backup_sealed: bool,
}

/// An entry on the settings Root list — the three domains, in display order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RootEntry {
    /// Drill into the Display sub-page ([`SettingsPage::Display`]) — brightness, display
    /// sleep, and the touch timeout (all the panel/interaction knobs).
    Display,
    /// Drill into the Security sub-page ([`SettingsPage::Security`]) — device + FIDO PIN,
    /// the audit log, the backup status, and the (danger) Factory reset.
    Security,
    /// The Firmware screen: the installed build version and the (hold-to-confirm)
    /// reboot-to-update-over-USB action. Last on the list — a rarely-touched maintenance
    /// action. A drill-in that runs its own hold sub-flow.
    Firmware,
}

/// An entry on the Display sub-page list.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DisplayEntry {
    /// Backlight-level adjust.
    Brightness,
    /// Display-sleep timeout — blank the panel after inactivity (image-retention guard).
    Sleep,
    /// Touch / presence-confirm timeout — how long a touch request waits for a tap (and how
    /// long a revealed PIN stays lit).
    Timeout,
}

/// An entry on the Security sub-page list.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SecurityEntry {
    /// Set / change the **device PIN** — gates the on-device UI (unlock, delete, factory
    /// reset). A change verifies the current device PIN first.
    DevicePin,
    /// Set / change the **FIDO clientPIN** — the WebAuthn/built-in-UV PIN, independent of
    /// the device PIN. A change verifies the current FIDO PIN first.
    FidoPin,
    /// Manage the **PIV application PIN / PUK** — opens a sub-menu (change PIN, change PUK,
    /// or unblock a blocked PIN with the PUK). Independent of the device and FIDO PINs; each
    /// op is gated by knowledge of the current PIN/PUK, exactly like the host APDU path.
    PivPin,
    /// Open the read-only on-device audit log (the recent journal events).
    AuditLog,
    /// Open the read-only seed-backup status screen (whether the recovery seed is present
    /// and the export window has been sealed).
    Backup,
    /// Erase every applet's data and return to a fresh device (danger-styled, gated by a
    /// hold-to-confirm and the device PIN if one is set).
    FactoryReset,
}

/// A control on an adjust page (brightness / timeout / sleep).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AdjustKey {
    Minus,
    Plus,
    Back,
}

/// Settings list rows, shared by the Root list and its Display / Security sub-pages — each
/// is a full-width row in `settings_row_rect(i)`. The Root has three (Display / Security /
/// Firmware); Security has the most (six). Sized so the longest list (Security) fits below
/// the chrome and above the panel bottom (a const-assert validates it) at a touch-comfortable
/// row height, with a clear gap below the title-bar back chevron so a stray reach for it can't
/// land on the first row.
const ROW_X: u16 = 13;
const ROW_W: u16 = PANEL_W - 2 * ROW_X;
const ROW_H: u16 = 36;
const ROW_GAP: u16 = 6;
const ROW_Y0: u16 = CONTENT_TOP + CONTENT_GAP;
/// Number of Root list rows (Display / Security / Firmware).
pub const SETTINGS_ROWS: u16 = 3;

/// The rectangle of settings list row `i` — single source of truth for the Root,
/// [`hit_settings_root`], the Display sub-page ([`hit_display`]) and the Security sub-page
/// ([`hit_security`]).
pub const fn settings_row_rect(i: u16) -> Rect {
    Rect::new(ROW_X, ROW_Y0 + i * (ROW_H + ROW_GAP), ROW_W, ROW_H)
}

/// The Root entry painted on row `i`, in list order (Firmware last — a rare maintenance
/// action).
pub const fn settings_row_entry(i: u16) -> RootEntry {
    match i {
        0 => RootEntry::Display,
        1 => RootEntry::Security,
        _ => RootEntry::Firmware,
    }
}

/// Number of Display sub-page rows (Brightness / Display sleep / Touch timeout).
pub const DISPLAY_ROWS: u16 = 3;

/// The Display entry on row `i`, in list order (the two screen-output knobs first, then the
/// touch timeout).
pub const fn display_row_entry(i: u16) -> DisplayEntry {
    match i {
        0 => DisplayEntry::Brightness,
        1 => DisplayEntry::Sleep,
        _ => DisplayEntry::Timeout,
    }
}

/// Which Display entry, if any, a tap at `p` selects. Reuses [`settings_row_rect`] for the
/// first [`DISPLAY_ROWS`] rows (disjoint by construction).
pub fn hit_display(p: Point) -> Option<DisplayEntry> {
    let mut i = 0;
    while i < DISPLAY_ROWS {
        if settings_row_rect(i).contains(p) {
            return Some(display_row_entry(i));
        }
        i += 1;
    }
    None
}

/// Number of Security sub-page rows (Device PIN, FIDO PIN, PIV PIN, Audit log, Backup,
/// Factory reset) — the longest settings list, so the shared row geometry is sized to fit it.
pub const SECURITY_ROWS: u16 = 6;

/// The Security entry on row `i`, in list order (the three credential PINs first, the danger
/// Factory reset stays last).
pub const fn security_row_entry(i: u16) -> SecurityEntry {
    match i {
        0 => SecurityEntry::DevicePin,
        1 => SecurityEntry::FidoPin,
        2 => SecurityEntry::PivPin,
        3 => SecurityEntry::AuditLog,
        4 => SecurityEntry::Backup,
        _ => SecurityEntry::FactoryReset,
    }
}

/// Which Security entry, if any, a tap at `p` selects. Reuses [`settings_row_rect`] for
/// the first [`SECURITY_ROWS`] rows (disjoint by construction).
pub fn hit_security(p: Point) -> Option<SecurityEntry> {
    let mut i = 0;
    while i < SECURITY_ROWS {
        if settings_row_rect(i).contains(p) {
            return Some(security_row_entry(i));
        }
        i += 1;
    }
    None
}

/// Adjust-page controls: a big −/+ pair. Back is the shared title-bar chevron
/// ([`TITLE_BACK_RECT`]) like every other screen — no bottom Back slab.
const ADJ_W: u16 = 88;
const ADJ_H: u16 = 80;
const ADJ_Y: u16 = 150;
/// Decrement target (left).
pub const ADJ_MINUS_RECT: Rect = Rect::new(16, ADJ_Y, ADJ_W, ADJ_H);
/// Increment target (right).
pub const ADJ_PLUS_RECT: Rect = Rect::new(PANEL_W - 16 - ADJ_W, ADJ_Y, ADJ_W, ADJ_H);

// Compile-time layout invariants (paint and hit-test share these rects): the longest
// settings list (Security, six rows) fits on-panel; the −/+ controls are disjoint with a gap
// and sit above Back. A bad geometry edit fails the build. The Root page paints the four-tab
// nav (its peer tabs do) and the no-nav sub-pages reuse the same rows below a back chevron —
// so the Root list is bounded by `NAV_TOP` (clear of the nav) while the no-nav Security list,
// the longest, is bounded by the panel bottom (`PANEL_H`).
const _: () = {
    assert!(ROW_GAP > 0);
    // At least one brightness step (the level-bar math would underflow at 0).
    assert!(BRIGHTNESS_LEVELS >= 1);
    assert!(SETTINGS_ROWS <= SECURITY_ROWS && DISPLAY_ROWS <= SECURITY_ROWS);
    // The settings sub-pages (Display / Security) are no-nav — a back chevron, no bottom
    // nav bar — so the longest list (Security) is bounded by the panel bottom, not NAV_TOP.
    // The Root settings list IS a nav tab, so it must still clear the nav bar.
    let root_last = settings_row_rect(SETTINGS_ROWS - 1);
    assert!(root_last.y + root_last.h <= NAV_TOP);
    let last = settings_row_rect(SECURITY_ROWS - 1);
    assert!(last.x + last.w <= PANEL_W && last.y + last.h <= PANEL_H);
    assert!(ADJ_MINUS_RECT.x + ADJ_MINUS_RECT.w < ADJ_PLUS_RECT.x);
    assert!(ADJ_PLUS_RECT.x + ADJ_PLUS_RECT.w <= PANEL_W);
    assert!(ADJ_MINUS_RECT.y + ADJ_MINUS_RECT.h <= PANEL_H);
};

/// Which Root entry, if any, a tap at `p` selects. Rows are disjoint by
/// construction, so at most one matches; a tap in a gap selects nothing.
pub fn hit_settings_root(p: Point) -> Option<RootEntry> {
    let mut i = 0;
    while i < SETTINGS_ROWS {
        if settings_row_rect(i).contains(p) {
            return Some(settings_row_entry(i));
        }
        i += 1;
    }
    None
}

/// Which adjust control, if any, a tap at `p` selects on the brightness / timeout / sleep
/// adjust pages (−/+/Back). Disjoint by construction.
pub fn hit_adjust(p: Point) -> Option<AdjustKey> {
    if ADJ_MINUS_RECT.contains(p) {
        Some(AdjustKey::Minus)
    } else if ADJ_PLUS_RECT.contains(p) {
        Some(AdjustKey::Plus)
    } else if TITLE_BACK_RECT.contains(p) {
        Some(AdjustKey::Back)
    } else {
        None
    }
}

/// Step the brightness level by `delta` (+1/−1), clamped to `1..=BRIGHTNESS_LEVELS`.
/// The display task applies the result to the backlight PWM; the menu only models it.
pub fn step_brightness(level: u8, delta: i8) -> u8 {
    (level as i16 + delta as i16).clamp(1, BRIGHTNESS_LEVELS as i16) as u8
}

/// Step the touch timeout to the next/previous [`TIMEOUT_CHOICES`] entry by `delta`
/// (+1/−1), snapping a non-listed current value (e.g. a phy-record override that
/// isn't one of the menu's choices) to the nearest choice first. Returns seconds.
pub fn step_timeout(cur_secs: u16, delta: i8) -> u16 {
    let mut idx = 0;
    let mut best = u16::MAX;
    let mut i = 0;
    while i < TIMEOUT_CHOICES.len() {
        let d = cur_secs.abs_diff(TIMEOUT_CHOICES[i]);
        if d < best {
            best = d;
            idx = i;
        }
        i += 1;
    }
    let ni = (idx as i32 + delta as i32).clamp(0, TIMEOUT_CHOICES.len() as i32 - 1) as usize;
    TIMEOUT_CHOICES[ni]
}

/// Step the display-sleep timeout to the next/previous [`SLEEP_CHOICES`] entry by
/// `delta` (+1/−1). The trailing `0` ("Off") sentinel sits at the top, so `+` from the
/// longest duration reaches Off and `−` from Off returns to the longest; a current value
/// not in the list snaps to the nearest real duration first. Returns seconds (`0` = Off).
pub fn step_sleep(cur_secs: u16, delta: i8) -> u16 {
    let real = SLEEP_CHOICES.len() - 1; // index of the "Off" sentinel
    let idx = if cur_secs == 0 {
        real
    } else {
        let mut best = u16::MAX;
        let mut bi = 0;
        let mut i = 0;
        while i < real {
            let d = cur_secs.abs_diff(SLEEP_CHOICES[i]);
            if d < best {
                best = d;
                bi = i;
            }
            i += 1;
        }
        bi
    };
    let ni = (idx as i32 + delta as i32).clamp(0, SLEEP_CHOICES.len() as i32 - 1) as usize;
    SLEEP_CHOICES[ni]
}

/// Lowercase-hex nibble (`0-9a-f`).
const fn hex_nibble(n: u8) -> u8 {
    if n < 10 { b'0' + n } else { b'a' + (n - 10) }
}

/// Lowercase-hex a `u16` into a fixed 4-byte buffer — no alloc, for the Info screen.
/// Always printable ASCII, so [`core::str::from_utf8`] on it never fails.
pub fn hex_u16(v: u16) -> [u8; 4] {
    let mut out = [0u8; 4];
    let mut i = 0;
    while i < 4 {
        out[i] = hex_nibble(((v >> ((3 - i) * 4)) & 0xF) as u8);
        i += 1;
    }
    out
}

/// Lowercase-hex a `u64` into a fixed 16-byte buffer — no alloc, for the Info screen.
pub fn hex_u64(v: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut i = 0;
    while i < 16 {
        out[i] = hex_nibble(((v >> ((15 - i) * 4)) & 0xF) as u8);
        i += 1;
    }
    out
}

// --- Design-system widgets (the re-skin layout) ----------------------------

/// Legacy single-strip header height — still used by the full-screen approve modal
/// ([`Screen::Confirm`]); the tab screens use the two-tier chrome below instead.
pub const HEADER_H: u16 = 30;

/// The persistent top **status bar**: a mono "RS-Key" wordmark at the left and the USB
/// power indicator at the right. Present on every tab screen (the design's framing
/// chrome).
pub const STATUS_BAR_H: u16 = 24;
/// The **title bar** below the status bar: an optional back chevron plus the screen
/// title.
pub const TITLE_BAR_H: u16 = 30;
/// Top of a tab screen's content, below both chrome strips.
pub const CONTENT_TOP: u16 = STATUS_BAR_H + TITLE_BAR_H;
/// Uniform gap between the title bar and the first content row (list, settings, etc.).
pub const CONTENT_GAP: u16 = 10;

/// The title-bar back affordance (a pushed screen's "return to parent" chevron), in the
/// title bar below the status bar. Distinct from [`PK_BACK_RECT`] — the chrome-less
/// destructive modals keep their chevron in the very top-left, but a tab screen's status
/// bar occupies that corner, so its back moves one strip down.
pub const TITLE_BACK_RECT: Rect = Rect::new(4, STATUS_BAR_H, 44, TITLE_BAR_H);

/// Did a tap at `p` hit the title-bar back chevron?
pub fn hit_title_back(p: Point) -> bool {
    TITLE_BACK_RECT.contains(p)
}

/// The title-bar **edit** affordance — the service detail's pencil, mirroring the back
/// chevron at the right edge of the title strip. A tap here opens the rename screen.
pub const TITLE_EDIT_RECT: Rect = Rect::new(PANEL_W - 4 - 44, STATUS_BAR_H, 44, TITLE_BAR_H);

/// Did a tap at `p` hit the title-bar edit (rename) affordance?
pub fn hit_title_edit(p: Point) -> bool {
    TITLE_EDIT_RECT.contains(p)
}

// Compile-time: the edit affordance sits in the title strip, clear of (right of) the
// back chevron, so a back tap and a rename tap can never collide.
const _: () = {
    assert!(TITLE_EDIT_RECT.y >= STATUS_BAR_H);
    assert!(TITLE_EDIT_RECT.y + TITLE_EDIT_RECT.h <= CONTENT_TOP);
    assert!(TITLE_BACK_RECT.x + TITLE_BACK_RECT.w < TITLE_EDIT_RECT.x);
    assert!(TITLE_EDIT_RECT.x + TITLE_EDIT_RECT.w <= PANEL_W);
};

/// Bottom navigation-bar height.
pub const NAV_H: u16 = 36;
/// Top edge of the bottom nav bar.
pub const NAV_TOP: u16 = PANEL_H - NAV_H;

/// A bottom-nav destination (the three top-level tabs).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NavTab {
    Home,
    Passkeys,
    /// The applet hub: a chooser for the OpenPGP / PIV / OATH read-only screens.
    Apps,
    Settings,
}

impl NavTab {
    /// The short caption shown under the tab glyph.
    pub const fn label(self) -> &'static str {
        match self {
            NavTab::Home => "Home",
            NavTab::Passkeys => "Passkeys",
            NavTab::Apps => "Apps",
            NavTab::Settings => "Settings",
        }
    }
}

/// The nav tabs in display (left-to-right) order.
pub const NAV_TABS: [NavTab; 4] = [
    NavTab::Home,
    NavTab::Passkeys,
    NavTab::Apps,
    NavTab::Settings,
];
const NAV_CELL_W: u16 = PANEL_W / NAV_TABS.len() as u16;

/// The rect of nav tab `i` (`0..3`) — single source of truth for the renderer and
/// [`hit_nav`].
pub const fn nav_tab_rect(i: u16) -> Rect {
    Rect::new(i * NAV_CELL_W, NAV_TOP, NAV_CELL_W, NAV_H)
}

/// Which nav tab a tap selects, or `None` if it lands above the nav bar.
pub fn hit_nav(p: Point) -> Option<NavTab> {
    if p.y < NAV_TOP {
        return None;
    }
    let i = (p.x / NAV_CELL_W).min(NAV_TABS.len() as u16 - 1);
    Some(NAV_TABS[i as usize])
}

/// List-row height (a lifted card holding icon + label + trailing + chevron).
pub const LIST_ROW_H: u16 = 34;
const LIST_ROW_GAP: u16 = 2;
const LIST_ROW_X: u16 = 8;
/// List-row width, inset from both panel edges.
pub const LIST_ROW_W: u16 = PANEL_W - 2 * LIST_ROW_X;

/// The rect of list row `i`, for a list whose first row starts at `y0`. Screen-
/// supplied `y0` lets Home (rows low, under the status block) and Settings (rows
/// from the top) share one row geometry. Single source of truth for paint + hit.
pub const fn row_rect(y0: u16, i: u16) -> Rect {
    Rect::new(
        LIST_ROW_X,
        y0 + i * (LIST_ROW_H + LIST_ROW_GAP),
        LIST_ROW_W,
        LIST_ROW_H,
    )
}

/// Which list row (`0..n`) a tap selects, for a list of `n` rows starting at `y0`.
/// Rows are disjoint by construction, so at most one matches.
pub fn hit_list(p: Point, y0: u16, n: u16) -> Option<u16> {
    let mut i = 0;
    while i < n {
        if row_rect(y0, i).contains(p) {
            return Some(i);
        }
        i += 1;
    }
    None
}

// Compile-time: the nav tiles the width and sits on-panel; rows keep a real gap; the
// two chrome strips stack inside the top of the panel and the title-bar back chevron
// sits entirely within the title strip, clear of (above) any content.
const _: () = {
    assert!(NAV_CELL_W * NAV_TABS.len() as u16 <= PANEL_W);
    assert!(NAV_TOP + NAV_H <= PANEL_H);
    assert!(LIST_ROW_GAP > 0 && LIST_ROW_X > 0 && HEADER_H < NAV_TOP);
    assert!(TITLE_BACK_RECT.y >= STATUS_BAR_H);
    assert!(TITLE_BACK_RECT.y + TITLE_BACK_RECT.h <= CONTENT_TOP);
    assert!(CONTENT_TOP <= PK_LIST_TOP && CONTENT_TOP <= ROW_Y0);
};

/// The device's current status, mirrored from the LED status engine so the panel
/// can show the same idle/working/touch state the onboard LED would.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StatusKind {
    Boot,
    Idle,
    Processing,
    Touch,
}

impl StatusKind {
    /// A short status caption for the idle screen.
    pub const fn label(self) -> &'static str {
        match self {
            StatusKind::Boot => "Starting...",
            StatusKind::Idle => "Ready",
            StatusKind::Processing => "Working...",
            StatusKind::Touch => "Touch to confirm",
        }
    }
}

/// What the Home tab shows: the device status (mirrored from the LED engine) plus the two
/// live facts the status card states — whether a device PIN is set and how many resident
/// passkeys are stored. The firmware fills `pin_set` / `passkeys` from a cached
/// enumeration refreshed at modal boundaries (never per idle frame).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HomeView {
    pub status: StatusKind,
    pub pin_set: bool,
    pub passkeys: u16,
}

// --- Passkeys list + service detail ----------------------------------------

/// Rows shown per page on a scrollable list (Passkeys, accounts, audit log). A longer
/// set is paged — the [pager band](PAGER_PREV_RECT) sits in the row slot just below
/// these, so the count must leave room for it above the nav bar. The footer shows the
/// true total on a single page; the pager shows "page / pages" when there is more.
pub const PK_ROWS_MAX: usize = 5;
/// Top of the first passkey row — below the status + title bars, clear of the nav bar
/// and footer.
pub const PK_LIST_TOP: u16 = CONTENT_TOP + CONTENT_GAP;

/// One relying-party row on the Passkeys list: a sanitized rpId, an optional device-local
/// nickname ([`render_passkeys_list`] shows it instead of the rpId when set), and how many
/// resident credentials it holds. The firmware fills these from `rsk_fido::passkeys`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct RpRow {
    pub id: Label,
    /// The device-local nickname, or empty for none (then the rpId `id` shows).
    pub nick: Label,
    pub accounts: u8,
}

impl RpRow {
    /// The label to show: the nickname if one is set, else the rpId.
    pub fn shown(&self) -> &str {
        if self.nick.is_empty() {
            self.id.as_str()
        } else {
            self.nick.as_str()
        }
    }
}

/// One account row on the per-RP service detail: a sanitized account label and whether
/// the credential is UV-gated (credProtect ≥ 2).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct AccountRow {
    pub name: Label,
    pub protected: bool,
}

/// The service-detail back affordance: the header's top-left, so a tap there returns
/// to the Passkeys list. In the header strip, clear of the rows and the nav bar.
pub const PK_BACK_RECT: Rect = Rect::new(8, 6, 42, 34);

// Compile-time: the back chevron sits in the header above the first row, and the
// visible rows *plus the pager band* (one more slot) fit between the list top and the
// nav bar.
const _: () = {
    assert!(PK_BACK_RECT.y + PK_BACK_RECT.h <= PK_LIST_TOP);
    assert!(PK_LIST_TOP + (PK_ROWS_MAX as u16 + 1) * (LIST_ROW_H + LIST_ROW_GAP) <= NAV_TOP);
};

// --- List pager (Prev / Next, for any list longer than one page) -----------

/// The pager band: the row slot directly below the last list row ([`PK_ROWS_MAX`]), so
/// a paged list keeps its row geometry and the band still clears the nav bar.
const PAGER_BAND: Rect = row_rect(PK_LIST_TOP, PK_ROWS_MAX as u16);
/// Width of each pager arrow tap target (the centre is the non-tappable page indicator).
const PAGER_BTN_W: u16 = 64;
/// Previous-page tap target (left end of the band).
pub const PAGER_PREV_RECT: Rect = Rect::new(PAGER_BAND.x, PAGER_BAND.y, PAGER_BTN_W, PAGER_BAND.h);
/// Next-page tap target (right end of the band).
pub const PAGER_NEXT_RECT: Rect = Rect::new(
    PAGER_BAND.x + PAGER_BAND.w - PAGER_BTN_W,
    PAGER_BAND.y,
    PAGER_BTN_W,
    PAGER_BAND.h,
);

// Compile-time: the two arrows are disjoint with a real gap (the indicator) between
// them, and the whole band clears the nav bar.
const _: () = {
    assert!(PAGER_PREV_RECT.x + PAGER_PREV_RECT.w < PAGER_NEXT_RECT.x);
    assert!(PAGER_BAND.y + PAGER_BAND.h <= NAV_TOP);
};

/// A pager arrow.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PagerKey {
    Prev,
    Next,
}

/// Which pager arrow, if any, a tap at `p` selects. The firmware clamps the resulting
/// page to `0..page_count`, so a tap on a dimmed end-arrow is a harmless no-op.
pub fn hit_pager(p: Point) -> Option<PagerKey> {
    if PAGER_PREV_RECT.contains(p) {
        Some(PagerKey::Prev)
    } else if PAGER_NEXT_RECT.contains(p) {
        Some(PagerKey::Next)
    } else {
        None
    }
}

/// Number of pages for `total` items at [`PK_ROWS_MAX`] per page — always ≥ 1, so an
/// empty list is "page 1 / 1". Single source of truth for the renderer and the firmware
/// modals, so a Next tap and the painted indicator can never disagree.
pub fn page_count(total: u16) -> u16 {
    total.max(1).div_ceil(PK_ROWS_MAX as u16)
}

/// Did a tap at `p` hit the service-detail back chevron?
pub fn hit_pk_back(p: Point) -> bool {
    PK_BACK_RECT.contains(p)
}

// --- Confirm-delete (a destructive Passkeys mutation) ----------------------

/// The full-width **Hold to delete** button on the Confirm-Delete screen. There is
/// no tap-able Deny — the header [`PK_BACK_RECT`] chevron cancels, and the delete
/// itself is a single deliberate hold (the firmware fills it as you hold, so a brush
/// can't delete). It shares the approve-screen button band so the destructive action
/// sits where the eye expects the primary control, but spans the full width (it is
/// alone there) and is painted / filled in [`theme::DENY`].
pub const DEL_HOLD_RECT: Rect = Rect::new(BTN_SIDE, BTN_BAND_TOP, PANEL_W - 2 * BTN_SIDE, BTN_H);

// Compile-time: the hold button sits fully inside the panel and below the header
// back chevron, so a cancel tap and a delete hold can never overlap.
const _: () = {
    assert!(DEL_HOLD_RECT.x > 0 && DEL_HOLD_RECT.x + DEL_HOLD_RECT.w <= PANEL_W);
    assert!(DEL_HOLD_RECT.y > PK_BACK_RECT.y + PK_BACK_RECT.h);
    assert!(DEL_HOLD_RECT.y + DEL_HOLD_RECT.h <= PANEL_H);
};

/// Did a tap at `p` hit the Confirm-Delete hold button?
pub fn hit_del_hold(p: Point) -> bool {
    DEL_HOLD_RECT.contains(p)
}

// --- Rename (set a device-local RP nickname via a T9 phone-style keypad) -----

/// T9 key groups: each press cycles to the next character in the group.
/// Order: digit first, then letters, then symbols (like old phone keypads).
pub const T9_GROUPS: &[&[u8]] = &[
    b"1.-_",  // key (0,0)
    b"2abc",  // key (0,1)
    b"3def",  // key (0,2)
    b"4ghi",  // key (1,0)
    b"5jkl",  // key (1,1)
    b"6mno",  // key (1,2)
    b"7pqrs", // key (2,0)
    b"8tuv",  // key (2,1)
    b"9wxyz", // key (2,2)
    b"0 ",    // key (3,1)
];

// hit_rename returns Char(0..=9), so the index-based groups[] access in
// run_rename is sound only while T9_GROUPS holds exactly 10 entries.
const _: () = assert!(
    T9_GROUPS.len() == 10,
    "hit_rename assumes T9_GROUPS.len() == 10; out-of-range => panic on device"
);

/// Labels shown on the T9 keypad keys: (digit, letters).
pub const T9_KEY_LABELS: &[(&str, &str)] = &[
    ("1", ".-_"),
    ("2", "ABC"),
    ("3", "DEF"),
    ("4", "GHI"),
    ("5", "JKL"),
    ("6", "MNO"),
    ("7", "PQRS"),
    ("8", "TUV"),
    ("9", "WXYZ"),
    ("0", "\u{2423}"),
];

/// A key on the T9 rename keypad.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RenameKey {
    /// A character-group key (index into [`T9_GROUPS`]).
    Char(usize),
    /// Delete the last character.
    Backspace,
    /// Commit the nickname.
    Save,
}

/// T9 keypad grid dimensions.
const T9_COLS: u16 = 3;
const T9_ROWS: u16 = 4;
const T9_KEY_W: u16 = 70;
const T9_KEY_H: u16 = 40;
const T9_GAP_X: u16 = 4;
const T9_GAP_Y: u16 = 4;
const T9_LEFT: u16 = (PANEL_W - T9_COLS * T9_KEY_W - (T9_COLS - 1) * T9_GAP_X) / 2;
pub const T9_TOP: u16 = 116;

/// The rect of the T9 key at (row, col).
pub const fn t9_key_rect(row: u16, col: u16) -> Rect {
    Rect::new(
        T9_LEFT + col * (T9_KEY_W + T9_GAP_X),
        T9_TOP + row * (T9_KEY_H + T9_GAP_Y),
        T9_KEY_W,
        T9_KEY_H,
    )
}

/// Which T9 key, if any, a tap at `p` selects.
pub fn hit_rename(p: Point) -> Option<RenameKey> {
    let mut row = 0;
    while row < T9_ROWS {
        let mut col = 0;
        while col < T9_COLS {
            if t9_key_rect(row, col).contains(p) {
                return Some(match (row, col) {
                    (3, 0) => RenameKey::Backspace,
                    (3, 2) => RenameKey::Save,
                    _ => {
                        let idx = if row < 3 {
                            (row * T9_COLS + col) as usize
                        } else {
                            9 // (3, 1) = 0/space group
                        };
                        RenameKey::Char(idx)
                    }
                });
            }
            col += 1;
        }
        row += 1;
    }
    None
}

/// The nickname value field (shows the current text + pending char).
pub const RN_FIELD_RECT: Rect = Rect::new(12, CONTENT_TOP + 22, 216, 34);

// Compile-time: the T9 keypad fits between the text field and the panel bottom,
// all keys are on-panel, and the grid has real gaps.
const _: () = {
    assert!(RN_FIELD_RECT.y >= CONTENT_TOP);
    assert!(RN_FIELD_RECT.y + RN_FIELD_RECT.h + 6 <= T9_TOP); // field clear of keypad
    let last = t9_key_rect(T9_ROWS - 1, T9_COLS - 1);
    assert!(last.y + last.h <= PANEL_H); // keypad on panel
    assert!(T9_LEFT > 0 && T9_KEY_W > 0 && T9_GAP_X > 0 && T9_GAP_Y > 0);
    assert!(T9_LEFT + T9_COLS * T9_KEY_W + (T9_COLS - 1) * T9_GAP_X <= PANEL_W);
};

// --- Success screens (the design's "pop" confirmation moments) --------------

/// Which celebratory success screen to paint — a successful approve, an on-device
/// passkey delete, or a completed factory wipe. Each has its own glyph, colour, and
/// wording (a green check for approve/delete; the grey [`Glyph::Rotate`] for the
/// wipe, which restarts the device). The screen is a full-frame standalone like
/// [`render_confirm_delete`] / [`render_pin_blocked`], not a `Screen` variant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SuccessKind {
    /// A host ceremony's trusted approval was granted (any applet).
    Approved,
    /// A resident passkey was deleted on-device.
    Deleted,
    /// The device was factory-wiped (about to reboot into a fresh state).
    Wiped,
    /// An EC key was generated on-device into a retired PIV slot.
    Generated,
}

/// Did a tap at `p` hit the success screen's **Done** button? It shares the
/// destructive-flow button band ([`DEL_HOLD_RECT`]), so no new geometry is
/// introduced — the same disjointness invariants apply.
pub fn hit_success_done(p: Point) -> bool {
    DEL_HOLD_RECT.contains(p)
}

// --- Audit log (read-only journal viewer) ----------------------------------

/// The class of a journal event, for the on-device audit log — it sets the row's
/// status-dot colour and label. The firmware maps each `rsk_fido::journal::EV_*` code
/// onto one of these at the boundary (rsk-ui has no dependency on rsk-fido), the way it
/// clamps an rpId into a [`Label`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum AuditKind {
    /// A credential was used to sign in (FIDO getAssertion / U2F auth) — green dot.
    Login,
    /// A credential was created (FIDO makeCredential / U2F register) — blue dot.
    Register,
    /// The device PIN was set or changed — grey dot.
    Pin,
    /// A PIN lockout: too many wrong PINs — red dot.
    Denied,
    /// A power-cycle boundary (the first entry of each boot) — grey dot.
    Boot,
    /// A factory reset — red dot.
    Reset,
    /// The operation-lock was engaged or released — grey dot.
    Lock,
    /// A configuration change (minPINLength, alwaysUv, enterprise attestation) — grey dot.
    Config,
    /// A seed-backup export / load / finalize — blue dot.
    Backup,
    /// Any other recorded event — grey dot.
    #[default]
    Other,
}

impl AuditKind {
    /// The row label — static, so it is decided (and host-tested) here, not in the
    /// firmware glue.
    pub const fn label(self) -> &'static str {
        match self {
            AuditKind::Login => "Signed in",
            AuditKind::Register => "Passkey added",
            AuditKind::Pin => "PIN changed",
            AuditKind::Denied => "PIN blocked",
            AuditKind::Boot => "Powered on",
            AuditKind::Reset => "Factory reset",
            AuditKind::Lock => "Lock changed",
            AuditKind::Config => "Setting changed",
            AuditKind::Backup => "Backup",
            AuditKind::Other => "Event",
        }
    }
}

/// One row of the on-device audit log: the event class (its dot colour + label) and how
/// long ago it happened, if known. `secs_ago` is `None` for entries from an earlier
/// power cycle — there is no wall clock, so cross-boot deltas are not computed and the
/// row then shows no time. Firmware builds these from `rsk_fido::journal::EventView`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct AuditRow {
    pub kind: AuditKind,
    pub secs_ago: Option<u32>,
}

/// The seed-backup status the read-only Backup screen ([`render_backup`]) paints —
/// the bits the device genuinely tracks, mirroring `rsk_fido`'s `BackupStatus`. There
/// is no fictional "N of M shares" state: backup is a one-time seed export over USB,
/// then sealed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BackupView {
    /// The one-time export *window* has been sealed (a `BACKUP_FINALIZE` closed it). This is
    /// a window-state fact, **not** proof a recovery copy exists — the device cannot verify an
    /// export happened — so the screen states the window state, not "backed up". A factory
    /// reset / host authenticatorReset reopens it.
    pub sealed: bool,
    /// A device master seed is present (something to back up / recover).
    pub has_seed: bool,
    /// This build can export the seed at all — `false` on a `fips-profile` device, where
    /// the seed is non-exportable and recovery is restore-only.
    pub exportable: bool,
    /// The on-device recovery-phrase reveal + seal actions are offered — true only while the
    /// backup window is open and the seed is readable (`has_seed && exportable && !sealed &&
    /// !locked`). When false the screen is status-only.
    pub can_reveal: bool,
}

/// A tappable action on the Backup screen, present only when [`BackupView::can_reveal`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BackupKey {
    /// Show the 24-word recovery phrase on the trusted display (device-PIN + hold gated).
    Reveal,
    /// Seal the backup window — close it so the seed can no longer be exported or shown
    /// (hold gated). A factory reset reopens it.
    Seal,
}

/// The primary "Show recovery phrase" button on the Backup screen (shown only when
/// [`BackupView::can_reveal`]).
pub const BACKUP_REVEAL_RECT: Rect = Rect::new(16, 224, PANEL_W - 32, 40);
/// The "Seal backup" button below it.
pub const BACKUP_SEAL_RECT: Rect = Rect::new(16, 268, PANEL_W - 32, 40);

const _: () = {
    // Both action buttons sit in the content area, below the fact rows, disjoint, on-panel.
    assert!(BACKUP_REVEAL_RECT.y > CONTENT_TOP);
    assert!(BACKUP_REVEAL_RECT.y + BACKUP_REVEAL_RECT.h <= BACKUP_SEAL_RECT.y);
    assert!(BACKUP_SEAL_RECT.y + BACKUP_SEAL_RECT.h <= PANEL_H);
    assert!(BACKUP_REVEAL_RECT.x + BACKUP_REVEAL_RECT.w <= PANEL_W);
    // Clear of the title-bar back chevron (the screen's other tap target).
    assert!(BACKUP_REVEAL_RECT.y > TITLE_BACK_RECT.y + TITLE_BACK_RECT.h);
};

/// Which Backup action, if any, a tap at `p` selects. Only meaningful when the screen was
/// drawn with [`BackupView::can_reveal`]; the caller gates on that.
pub fn hit_backup(p: Point) -> Option<BackupKey> {
    if BACKUP_REVEAL_RECT.contains(p) {
        Some(BackupKey::Reveal)
    } else if BACKUP_SEAL_RECT.contains(p) {
        Some(BackupKey::Seal)
    } else {
        None
    }
}

// === Recovery reveal: format chooser, SLIP-39 T/N picker, share display ===

/// The recovery format chosen on [`render_backup_format`] — a single BIP-39 phrase, or
/// SLIP-39 Shamir shares. Both reveal the master secret on the trusted screen (never USB).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BackupFormat {
    /// One 24-word BIP-39 phrase.
    Phrase,
    /// `T`-of-`N` SLIP-39 Shamir shares.
    Shares,
}

/// The "Single phrase" choice card on the format chooser.
pub const FMT_PHRASE_RECT: Rect = Rect::new(16, 92, PANEL_W - 32, 60);
/// The "Shamir shares" choice card, below it.
pub const FMT_SHARES_RECT: Rect = Rect::new(16, 164, PANEL_W - 32, 60);

const _: () = {
    // Both cards sit below the chrome-less back chevron, stacked and disjoint, on-panel.
    assert!(FMT_PHRASE_RECT.y > PK_BACK_RECT.y + PK_BACK_RECT.h);
    assert!(FMT_PHRASE_RECT.y + FMT_PHRASE_RECT.h <= FMT_SHARES_RECT.y);
    assert!(FMT_SHARES_RECT.y + FMT_SHARES_RECT.h <= PANEL_H);
};

/// Which recovery-format card a tap at `p` selects; the chrome-less [`PK_BACK_RECT`] chevron
/// cancels (handled by [`hit_pk_back`]).
pub fn hit_backup_format(p: Point) -> Option<BackupFormat> {
    if FMT_PHRASE_RECT.contains(p) {
        Some(BackupFormat::Phrase)
    } else if FMT_SHARES_RECT.contains(p) {
        Some(BackupFormat::Shares)
    } else {
        None
    }
}

/// The smallest / largest share counts the on-device picker offers. A meaningful Shamir
/// split needs ≥ 2 shares (1-of-1 is just the seed); 5 keeps the written-down set practical
/// on paper, while the crate itself supports up to `rsk_slip39::MAX_SHARES`.
pub const SHARE_MIN: u8 = 2;
/// See [`SHARE_MIN`].
pub const SHARE_MAX: u8 = 5;

/// A control on the SLIP-39 share picker ([`render_share_picker`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ShareAdjust {
    /// Lower the recovery threshold `T`.
    TMinus,
    /// Raise the recovery threshold `T`.
    TPlus,
    /// Lower the total share count `N`.
    NMinus,
    /// Raise the total share count `N`.
    NPlus,
    /// Proceed to reveal the shares.
    Continue,
}

const PICK_STEP: u16 = 46;
/// Threshold `T` stepper (decrement / increment).
pub const PICK_T_MINUS_RECT: Rect = Rect::new(16, 86, PICK_STEP, PICK_STEP);
/// See [`PICK_T_MINUS_RECT`].
pub const PICK_T_PLUS_RECT: Rect = Rect::new(PANEL_W - 16 - PICK_STEP, 86, PICK_STEP, PICK_STEP);
/// Total `N` stepper (decrement / increment).
pub const PICK_N_MINUS_RECT: Rect = Rect::new(16, 162, PICK_STEP, PICK_STEP);
/// See [`PICK_N_MINUS_RECT`].
pub const PICK_N_PLUS_RECT: Rect = Rect::new(PANEL_W - 16 - PICK_STEP, 162, PICK_STEP, PICK_STEP);
/// The full-width Continue button (shares the destructive-band geometry).
pub const PICK_CONTINUE_RECT: Rect =
    Rect::new(BTN_SIDE, BTN_BAND_TOP, PANEL_W - 2 * BTN_SIDE, BTN_H);

const _: () = {
    // Each stepper's −/+ are disjoint with a gap; the two rows and the Continue button stack
    // on-panel below the chrome.
    assert!(PICK_T_MINUS_RECT.x + PICK_T_MINUS_RECT.w < PICK_T_PLUS_RECT.x);
    assert!(PICK_N_MINUS_RECT.x + PICK_N_MINUS_RECT.w < PICK_N_PLUS_RECT.x);
    assert!(PICK_T_MINUS_RECT.y > CONTENT_TOP);
    assert!(PICK_T_MINUS_RECT.y + PICK_T_MINUS_RECT.h <= PICK_N_MINUS_RECT.y);
    assert!(PICK_N_MINUS_RECT.y + PICK_N_MINUS_RECT.h <= PICK_CONTINUE_RECT.y);
    assert!(PICK_CONTINUE_RECT.y + PICK_CONTINUE_RECT.h <= PANEL_H);
    assert!(SHARE_MIN >= 2 && SHARE_MAX <= rsk_slip39_max());
};

/// `rsk_slip39::MAX_SHARES` as a const, kept local so the picker bound can be const-asserted
/// without a cross-crate const dependency (the two are pinned equal by the firmware's use).
const fn rsk_slip39_max() -> u8 {
    16
}

/// Which picker control a tap at `p` selects; the chrome-less top-left [`PK_BACK_RECT`] chevron
/// ([`hit_pk_back`]) returns to the format chooser.
pub fn hit_share_picker(p: Point) -> Option<ShareAdjust> {
    if PICK_T_MINUS_RECT.contains(p) {
        Some(ShareAdjust::TMinus)
    } else if PICK_T_PLUS_RECT.contains(p) {
        Some(ShareAdjust::TPlus)
    } else if PICK_N_MINUS_RECT.contains(p) {
        Some(ShareAdjust::NMinus)
    } else if PICK_N_PLUS_RECT.contains(p) {
        Some(ShareAdjust::NPlus)
    } else if PICK_CONTINUE_RECT.contains(p) {
        Some(ShareAdjust::Continue)
    } else {
        None
    }
}

/// Apply a `±1` step to the `(threshold, total)` pair, preserving `SHARE_MIN ≤ T ≤ N ≤
/// SHARE_MAX`: raising `T` past `N` raises `N` with it; lowering `N` below `T` lowers `T`
/// with it — so the pair is always a valid `T`-of-`N` split. [`ShareAdjust::Continue`] is a
/// no-op here (the caller acts on it).
pub fn step_share_params(threshold: u8, total: u8, key: ShareAdjust) -> (u8, u8) {
    let (mut t, mut n) = (threshold, total);
    match key {
        ShareAdjust::TMinus => t = t.saturating_sub(1).max(SHARE_MIN),
        ShareAdjust::TPlus => {
            t = t.saturating_add(1).min(SHARE_MAX);
            if t > n {
                n = t;
            }
        }
        ShareAdjust::NMinus => {
            n = n.saturating_sub(1).max(SHARE_MIN);
            if t > n {
                t = n;
            }
        }
        ShareAdjust::NPlus => n = n.saturating_add(1).min(SHARE_MAX),
        ShareAdjust::Continue => {}
    }
    (t, n)
}

/// What the [`render_reveal_warning`] gate is about to show, so its copy names the right
/// secret (a phrase, or shares).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RevealKind {
    /// The 24-word BIP-39 phrase.
    Phrase,
    /// The SLIP-39 Shamir shares.
    Shares,
}

// --- Applet hub (OpenPGP / PIV / OATH) --------------------------------------

/// An entry on the Apps chooser list (the unified applet launcher).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AppEntry {
    OpenPgp,
    Piv,
    Oath,
}

/// Number of Apps chooser rows.
pub const APP_ROWS: u16 = 3;
const _: () = assert!(APP_ROWS <= PK_ROWS_MAX as u16);

/// Top of the on-device PIV key-generate algorithm chooser (its two rows sit below a
/// one-line slot caption, so it starts lower than the tab lists).
pub const PIV_KEYGEN_PICK_TOP: u16 = CONTENT_TOP + 34;

/// OpenPGP overview rows: the three key slots + the card-holder row.
pub const OPENPGP_ROWS: u16 = 4;
/// PIV overview rows: the four primary slots + the "Retired & F9" row.
pub const PIV_ROWS: u16 = 5;
// Both lists share the tab-modal row band, which holds at most `PK_ROWS_MAX` rows
// above the footer; the const-asserts here keep the footer (`NAV_TOP - 10`) clear.
const _: () = assert!(OPENPGP_ROWS <= PK_ROWS_MAX as u16);
const _: () = assert!(PIV_ROWS <= PK_ROWS_MAX as u16);
const _: () = assert!(PK_LIST_TOP + PIV_ROWS * (LIST_ROW_H + LIST_ROW_GAP) <= NAV_TOP - 10);

/// PIV keygen algorithm-chooser rows (the four curves + the RSA drill-in row);
/// paint and the firmware hit-test share this count.
pub const PIV_KEYGEN_PICK_ROWS: u16 = 5;
/// RSA size sub-picker rows (2048 / 3072 / 4096).
pub const PIV_RSA_PICK_ROWS: u16 = 3;
/// PIV PIN menu rows (change PIN / change PUK / unblock PIN / protect mgmt key).
pub const PIV_PIN_MENU_ROWS: u16 = 4;
const _: () = assert!(PIV_KEYGEN_PICK_ROWS <= PK_ROWS_MAX as u16);
const _: () = assert!(PIV_RSA_PICK_ROWS <= PK_ROWS_MAX as u16);
const _: () = assert!(PIV_PIN_MENU_ROWS <= PK_ROWS_MAX as u16);

/// Which applet, if any, a tap selects on the Apps chooser. The chooser reuses the
/// tab-list row geometry ([`row_rect`] from [`PK_LIST_TOP`]), so paint + hit share it.
pub fn hit_apps(p: Point) -> Option<AppEntry> {
    hit_list(p, PK_LIST_TOP, APP_ROWS).map(|i| match i {
        0 => AppEntry::OpenPgp,
        1 => AppEntry::Piv,
        _ => AppEntry::Oath,
    })
}

/// The Apps chooser's per-applet item counts, shown as each row's trailing value.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct AppsView {
    pub openpgp_keys: u8,
    pub piv_slots: u8,
    pub oath_codes: u16,
}

/// One OpenPGP slot row on the overview (SIG / DEC / AUT).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PgpSlotRow {
    pub present: bool,
    /// Algorithm label (e.g. "Ed25519"); empty when the slot holds no key.
    pub algo: Label,
    pub touch: bool,
}

/// The OpenPGP overview: the three key slots, a card-holder row (its name as the
/// trailing value), the signature counter, and the PW1 / PW3 remaining-attempts footer.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct OpenpgpView {
    pub slots: [PgpSlotRow; 3],
    /// The cardholder name shown on the "Card holder" row (empty → "Not set").
    pub cardholder_name: Label,
    pub sig_count: u32,
    pub pw1: u8,
    pub pw3: u8,
}

/// The OpenPGP card-holder detail (back-only): the public cardholder data objects —
/// name, login, URL and language — read without a PIN. An empty card shows a hint.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CardholderView {
    pub name: Label,
    pub login: Label,
    pub url: Label,
    pub lang: Label,
    /// Whether the card carries any cardholder data at all.
    pub any: bool,
}

/// One OpenPGP key's detail: its slot (`0`=SIG, `1`=DEC, `2`=AUT), whether a key is
/// present, algorithm, touch policy, whether a generation time is recorded, and the
/// SHA-1 fingerprint. An empty slot is still drillable — the screen explains the slot.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PgpKeyView {
    pub slot: u8,
    pub present: bool,
    pub algo: Label,
    pub touch: bool,
    pub created: bool,
    pub fingerprint: [u8; 20],
    pub has_fp: bool,
}

/// One PIV slot row on the overview (9A / 9C / 9D / 9E).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PivSlotRow {
    pub slot: u8,
    pub present: bool,
    pub cert: bool,
    /// Algorithm label; empty when the slot holds no key.
    pub algo: Label,
}

/// The PIV overview: the four primary slots, a "Retired & F9" row (its populated count
/// as the trailing value), and the PIN / PUK remaining attempts.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PivView {
    pub slots: [PivSlotRow; 4],
    /// Populated retired slots + F9, shown on the "Retired & F9" row.
    pub extra: u8,
    pub pin: u8,
    pub puk: u8,
}

/// One row on the "Retired & F9" screen: either a populated slot (retired 82–95 or the
/// F9 attestation slot) or the trailing "Generate key" action. Slot rows drill into the
/// shared slot-detail; the action row starts the on-device generate flow.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PivExtraRow {
    /// Wire slot (`0xF9` / `0x82..=0x95`); unused for the action row.
    pub slot: u8,
    pub present: bool,
    pub cert: bool,
    /// Algorithm label; empty when only a certificate is stored.
    pub algo: Label,
    /// `true` for the "Generate key" action row (not a slot).
    pub generate: bool,
}

/// One PIV slot's detail: algorithm, PIN / touch policy, key origin, cert presence.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PivSlotView {
    pub slot: u8,
    pub present: bool,
    pub cert: bool,
    pub algo: Label,
    pub pin_policy: Label,
    pub touch_policy: Label,
    pub origin: Label,
}

/// One OATH credential row: its (sanitized) label, whether it is HOTP (else TOTP),
/// and whether it is touch-gated. No code is shown (the device has no clock).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct OathRow {
    pub name: Label,
    pub hotp: bool,
    pub touch: bool,
}

/// One OATH credential's detail (back-only): type, HMAC algorithm, digit count, TOTP
/// step and touch gate. No code is computed (the device has no clock for TOTP).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct OathDetailView {
    pub name: Label,
    pub hotp: bool,
    pub algo: Label,
    pub digits: u8,
    /// TOTP step in seconds; `0` for HOTP (counter-based).
    pub period: u16,
    pub touch: bool,
}

/// Top-level screen the display task renders. The three top-level **tabs** (Home,
/// Passkeys, Settings) carry the bottom nav bar and are shown by the idle loop; the
/// **modals** (Splash, Confirm, Pin) are full-screen and shown by the worker.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Screen {
    /// One-time boot splash.
    Splash,
    /// The device-locked screen: a padlock, "Locked", and a "touch to unlock" hint. The
    /// whole screen is the unlock affordance (any tap starts the on-screen PIN entry).
    /// Gates only the on-device UI — host CTAP ceremonies are unaffected.
    Locked,
    /// The first-run onboarding prompt shown on a fresh, PIN-less device: offers to
    /// set a device PIN ([`ONBOARD_SET_RECT`]) or continue without one
    /// ([`ONBOARD_SKIP_RECT`], a remembered choice). Host ceremonies paint over it.
    Onboard,
    /// The Home tab — status indicator + bottom nav.
    Home(HomeView),
    /// A pending trusted Deny / Hold-to-approve decision.
    Confirm(ConfirmPrompt),
    /// The built-in-UV PIN pad, showing how many digits have been entered (masked).
    Pin(PinPad),
    /// The on-device settings menu (Root list or one of its sub-pages) + bottom nav.
    Settings(SettingsView),
}

#[cfg(kani)]
#[path = "kani.rs"]
mod proofs;

#[cfg(test)]
mod tests;
