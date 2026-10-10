// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The no-host idle menu of the `display-keys` build: when no USB host has
//! configured the device for the persisted entry delay ([`entry_delay_ms`],
//! SETTINGS option, 30 s by default) the panel stops breathing STARTING and
//! shows a single-button browse of the device's own metadata — slot counts and
//! states, credential lists (never secrets), backup state and firmware
//! identity, plus a SETTINGS page. Everything it shows comes from the
//! applets' public info readers over the shared flash — the same data the
//! touch build's browse screens use. Nothing here writes flash, needs a PIN,
//! or opens a session; the only non-flash write is the SETTINGS record, and
//! the only other non-flash read is the one fused-key window that unseals the
//! OATH/passkey listings, zeroized before paging starts.
//!
//! Navigation is a **ring** of pages ending in the SETTINGS section. Three
//! gestures on the single key drive it: a tap steps next, a double-tap steps
//! back (both directions wrap, so SETTINGS is one double from the OVERVIEW),
//! and a hold enters a level: on the SETTINGS overview it opens the select
//! mode (taps then walk the rows, a hold on the selected row opens its option
//! editor, where a hold confirms); on a PIV / PASSKEYS directory page it
//! starts the pick on that page's first expandable row, whose own hold opens a
//! read-only detail page (a slot's policy, a relying party's credential list —
//! a double returns from either level); anywhere else it is inert. A hold
//! fires the moment it reaches its threshold, without waiting for the key's
//! release; the recognizer's next pass re-arms on the up edge, so the release
//! is consumed, never re-read as a tap. There is deliberately no gesture back
//! to the STARTING wash — under a charger the menu is the useful screen — and
//! the loop returns only when a host configures the device (the status task
//! then repaints the live status).
//! While the loop runs it holds the thread executor (like a confirm wait), so
//! the worker is parked and the interrupt executor's USB answers the host;
//! nothing the menu consumes can leak into the worker's idle-click counter (a
//! host-config exit drains the key first).
//!
//! The rows are captured **once** on entry into a stack arena (single flash
//! borrow, single fused-key window) and pages render from RAM afterwards, so
//! paging never re-reads flash. A picked detail page is the one exception: its
//! rows are read on demand — a PIV policy read, or a per-page credential
//! enumeration under a short fused-key window — so the arena never carries it.
//! Layout lives in `rsk_ui` (its
//! `render_keys_menu_page`); this module formats the metadata into its rows.
//! Row text is sanitized to printable ASCII here (every byte outside
//! `0x20..=0x7E` becomes `?`), so a `—` fallback from an applet name mapper or
//! a raw OATH name byte can never reach the renderer.

use core::cell::RefCell;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use rsk_crypto::{Device, FusedKey, FusedRead, read_fused};
// `Button`'s sampling methods come from this trait; bring it into scope for the
// raw polls in the browse loop (same import `display_keys` uses).
use rsk_device::presence::Board as _;
use rsk_ui::Tone;

use crate::display_panel::Panel;
use crate::handler::Store;
use crate::led;
use crate::presence;
use rsk_ui::menu_conf::{DEFAULT_DELAY_IDX, DELAY_OPTIONS_S, EF_MENU_CONF, MenuConf};

/// How long the STARTING wash must go uninterrupted (no host configure) before
/// the idle menu opens — the SETTINGS option, persisted in flash (the status
/// task starts counting from the first Boot tick it sees, i.e. from the moment
/// the panel shows STARTING). The live value rides a static that the SETTINGS
/// page updates on a confirmed change, so the status loop never reads flash;
/// the boot path loads it once ([`load_menu_conf`]), and the static's seed and
/// the no-record fallback both derive from the default option index so a fresh
/// device and a stored record can never disagree about the default.
const DEFAULT_ENTRY_MS: u32 = DELAY_OPTIONS_S[DEFAULT_DELAY_IDX] as u32 * 1000;
static MENU_ENTRY_MS: AtomicU32 = AtomicU32::new(DEFAULT_ENTRY_MS);

/// Whether the panel is flipped 180° (the reversible USB-C plug) — the second
/// SETTINGS option, same record. The boot path applies it to the panel; the
/// SETTINGS editor applies it live.
static MENU_FLIP: AtomicBool = AtomicBool::new(false);

/// The screen-direction options, in degrees (SETTINGS → SCREEN DIRECTION).
const SCREEN_FLIP_OPTIONS_DEG: [u16; 2] = [0, 180];

/// The live entry delay the status task times against.
pub(crate) fn entry_delay_ms() -> u64 {
    u64::from(MENU_ENTRY_MS.load(Ordering::Relaxed))
}

/// Whether the panel should be flipped 180° (applied at boot and on change).
pub(crate) fn screen_flip() -> bool {
    MENU_FLIP.load(Ordering::Relaxed)
}

/// Read the persisted menu config once, at boot, into the statics. The record
/// and its decoding rules are `rsk_ui::menu_conf`'s; a missing, short or
/// out-of-range record keeps the corresponding default (30 s delay, no flip).
pub(crate) fn load_menu_conf(fs: &mut Store) {
    let mut rec = [0u8; 2];
    let n = fs.read(EF_MENU_CONF, &mut rec).unwrap_or(0);
    let conf = MenuConf::decode(&rec, n);
    MENU_ENTRY_MS.store(conf.delay_ms(), Ordering::Relaxed);
    MENU_FLIP.store(conf.flip, Ordering::Relaxed);
}

/// Persist both record fields from the live statics — the statics are the
/// authority (loaded at boot, updated on every confirmed change, and the
/// editor is the only writer), so a save never needs to read the record back.
fn save_menu_conf(fs: &mut Store) {
    let conf = MenuConf {
        delay_idx: current_delay_idx() as u8,
        flip: screen_flip(),
    };
    let _ = fs.put(EF_MENU_CONF, &conf.encode());
}

/// Apply a confirmed delay option: persist it and update the live static.
fn apply_entry_delay(fs: &mut Store, idx: usize) {
    if idx >= DELAY_OPTIONS_S.len() {
        return;
    }
    MENU_ENTRY_MS.store(u32::from(DELAY_OPTIONS_S[idx]) * 1000, Ordering::Relaxed);
    save_menu_conf(fs);
}

/// Apply a confirmed screen-direction option: persist it, update the live
/// static, and flip the panel now (the caller repaints the next frame).
fn apply_screen_flip(fs: &mut Store, panel: &mut Panel, idx: usize) {
    if idx >= SCREEN_FLIP_OPTIONS_DEG.len() {
        return;
    }
    MENU_FLIP.store(idx != 0, Ordering::Relaxed);
    panel.set_scan_flip(idx != 0);
    save_menu_conf(fs);
}

/// The stored delay option index (from the live static; falls back to the
/// default when a newer build wrote a value this one does not list).
fn current_delay_idx() -> usize {
    DELAY_OPTIONS_S
        .iter()
        .position(|&s| u64::from(s) * 1000 == entry_delay_ms())
        .unwrap_or(DEFAULT_DELAY_IDX)
}

/// Rows per menu page, from the renderer (single source of truth for paging).
const ROWS_PER_PAGE: usize = rsk_ui::KEYS_MENU_ROWS_PER_PAGE;

/// How many OATH rows are kept as pages; any spill becomes a "+N more" tail
/// row and the OVERVIEW count always shows the true total.
const OATH_PAGE_CAP: usize = 60;

/// The row arena layout: fixed per-section offsets (the OVERVIEW section sits
/// first on screen but is captured last — its counts need every other section
/// filled first), sizes sized to each section's worst case: PIV holds the four
/// primary-slot one-liners, the summary rows (retries / certificates / retired
/// count) and every occupied retired/F9 slot (a picked row's policy page is
/// read on demand, not stored); OATH caps at [`OATH_PAGE_CAP`] rows plus a
/// tail; PASSKEYS holds its two counters, up to [`RP_PAGE_CAP`] relying-party
/// rows plus a tail.
const ARENA_CAP: usize = 156;
const OV_OFF: usize = 0; // ≤ 7 (one summary row per info section)
const PIV_OFF: usize = 7; // ≤ slots + summary + MAX_EXTRA_SLOTS
const PGP_OFF: usize = 36; // ≤ 3 + 1 + 4
const OATH_OFF: usize = 44; // ≤ 1 + OATH_PAGE_CAP
const PK_OFF: usize = 105; // ≤ 4 (counters screen) + RP_PAGE_CAP + 1
const BACKUP_OFF: usize = 130; // ≤ 4
const FW_OFF: usize = 134; // ≤ 3
const OTP_OFF: usize = 137; // ≤ 4 (Yubico-OTP slots)
/// Passkeys: how many relying-party rows are kept as pages; a longer set gets
/// a truthful "+N more" tail row (the counters above always carry the totals).
const RP_PAGE_CAP: usize = 20;
const _: () = {
    assert!(OV_OFF + 7 <= PIV_OFF, "overview summary rows overflow");
    assert!(
        PIV_OFF + PIV_PRIMARY_ROWS + PIV_SUMMARY_ROWS + rsk_piv::info::MAX_EXTRA_SLOTS <= PGP_OFF,
        "PIV rows overflow (slots + summary + retired/F9)"
    );
    assert!(
        PK_OFF + 4 + RP_PAGE_CAP < BACKUP_OFF,
        "passkey rows overflow (counters screen + RPs + tail)"
    );
    assert!(
        PK_COUNTERS <= ROWS_PER_PAGE,
        "passkey counters fill more than one screen"
    );
    assert!(OTP_OFF + 4 <= ARENA_CAP, "menu arena layout overflows");
    assert!(
        core::mem::size_of::<RowBuf>() * ARENA_CAP <= 10_240,
        "menu row arena exceeds its stack budget"
    );
};

/// The two sections whose [`RowBuf::exp`] rows open a read-only detail page on
/// a hold (a PIV slot's policy page, a relying party's credential list).
const SEC_PIV: usize = 1;
const SEC_PASSKEYS: usize = 4;
/// The PIV directory's shape: the four primary slots (9A/9C/9D/9E), then the
/// summary rows (PIN/PUK retries, certificates, retired count). The expandable
/// retired/F9 rows follow at [`PIV_RETIRED_ROW0`].
const PIV_PRIMARY_ROWS: usize = 4;
const PIV_SUMMARY_ROWS: usize = 4;
/// In-section row indices where each section's expandable rows start: the
/// primary-slot rows in PIV, and the first relying party after PASSKEYS's
/// counters — the counters own the first screen alone (padded to the page
/// boundary), so the list starts on the next page.
const PIV_RETIRED_ROW0: usize = PIV_PRIMARY_ROWS + PIV_SUMMARY_ROWS;
const PK_COUNTERS: usize = 2; // SERVICES + CREDENTIALS
const PK_RP_ROW0: usize = ROWS_PER_PAGE;

/// The settings section's place in the browse strip. It is the last section
/// and holds no arena rows — its pages are assembled on paint from the live
/// config ([`entry_delay_ms`] / the option rows), so it can grow a settings
/// page without touching the capture.
const SEC_SETTINGS: usize = 8;

/// Section titles, in browse order (the arena section order by offset, with
/// SETTINGS last and arena-free).
const TITLES: [&str; 9] = [
    "OVERVIEW", "PIV", "OPENPGP", "OATH", "PASSKEYS", "BACKUP", "FIRMWARE", "YUBI OTP", "SETTINGS",
];

/// Device key material the menu's read-only enumerations need (OATH creds,
/// passkey seed) — the same identity the worker carries, copied like the touch
/// build's `DeviceKeys`: the serials are owned copies, the MKEK is a *way to
/// read* the fuses, so the menu holds neither the seed nor the root key (see
/// `rsk_crypto::kdf`).
#[derive(Clone, Copy)]
pub(crate) struct DeviceKeys {
    pub(crate) serial_id: [u8; 8],
    pub(crate) serial_hash: [u8; 32],
    pub(crate) mkek_source: Option<FusedKey>,
    /// The build's `bcdDevice` — shown on the FIRMWARE page.
    pub(crate) release: u16,
}

impl DeviceKeys {
    fn device<'k>(&'k self, mkek: &'k FusedRead) -> Device<'k> {
        Device {
            serial_hash: &self.serial_hash,
            serial_id: &self.serial_id,
            otp_key: mkek.as_deref(),
        }
    }
}

/// The row label/value column widths in bytes — shared by the arena rows and
/// the detail pages' scratch rows.
const ROW_LEFT_MAX: usize = 40;
const ROW_RIGHT_MAX: usize = 20;

/// One formatted menu row: sanitized-ASCII label and value plus the value's
/// tone. Zero-length fields render as empty columns. `exp` marks a row a hold
/// can open a read-only detail page for (a PIV slot, a passkey relying party).
#[derive(Clone, Copy)]
struct RowBuf {
    left: [u8; ROW_LEFT_MAX],
    ll: u8,
    right: [u8; ROW_RIGHT_MAX],
    rl: u8,
    tone: Tone,
    exp: bool,
}

impl RowBuf {
    const fn empty() -> Self {
        Self {
            left: [0; ROW_LEFT_MAX],
            ll: 0,
            right: [0; ROW_RIGHT_MAX],
            rl: 0,
            tone: Tone::Plain,
            exp: false,
        }
    }

    /// Fill the row (also used by the on-demand detail pages, which reuse a
    /// row array across loads, so every field is reset here): label and value
    /// sanitized, `tone` kept only alongside a value (an empty value stays
    /// plain), `exp` as the struct documents.
    fn set(&mut self, left: &[u8], right: &str, tone: Tone, exp: bool) {
        put_ascii(&mut self.left, &mut self.ll, left);
        self.exp = exp;
        self.rl = 0;
        self.tone = Tone::Plain;
        if !right.is_empty() {
            put_ascii(&mut self.right, &mut self.rl, right.as_bytes());
            self.tone = tone;
        }
    }
}

/// The menu's page content: the row arena, each section's row count and offset.
/// Rendered exclusively from RAM after capture.
struct Menu {
    arena: [RowBuf; ARENA_CAP],
    sec_rows: [usize; 9],
    sec_off: [usize; 9],
}

impl Menu {
    fn new() -> Self {
        Self {
            arena: [RowBuf::empty(); ARENA_CAP],
            sec_rows: [0; 9],
            sec_off: [
                OV_OFF, PIV_OFF, PGP_OFF, OATH_OFF, PK_OFF, BACKUP_OFF, FW_OFF, OTP_OFF, 0,
            ],
        }
    }
}

/// An append cursor over one section's arena slice.
struct Cursor<'a> {
    rows: &'a mut [RowBuf],
    next: usize,
}

impl<'a> Cursor<'a> {
    fn put(&mut self, left: &[u8], right: &str, tone: Tone) {
        self.push(left, right, tone, false);
    }

    /// A row a hold opens a detail page for (see [`RowBuf::exp`]).
    fn put_exp(&mut self, left: &[u8], right: &str, tone: Tone) {
        self.push(left, right, tone, true);
    }

    fn push(&mut self, left: &[u8], right: &str, tone: Tone, exp: bool) {
        if self.next >= self.rows.len() {
            return; // the caller sized its slice to the section's worst case
        }
        let row = &mut self.rows[self.next];
        self.next += 1;
        row.set(left, right, tone, exp);
    }
}

/// Copy `src` into `dst` as printable ASCII — every byte outside `0x20..=0x7E`
/// becomes `?` — truncating at the buffer. All menu text passes through here.
fn put_ascii(dst: &mut [u8], len: &mut u8, src: &[u8]) {
    *len = 0;
    for &b in src {
        if *len as usize == dst.len() {
            break;
        }
        dst[*len as usize] = if (0x20..=0x7E).contains(&b) { b } else { b'?' };
        *len += 1;
    }
}

// ---------------------------------------------------------------------------
// Capture: one flash borrow + one fused-key window, on menu entry

/// Snapshot every section's rows into `menu`. Synchronous; called once under a
/// single `fs.borrow_mut()` and `read_fused` window that ends before paging.
fn capture(fs: &mut Store, dev: &DeviceKeys, device: &Device<'_>, menu: &mut Menu) {
    // Each section captures under its own arena borrow (one slice at a time),
    // writing its row count back before the next borrow starts. The fixed
    // offsets and worst-case sizes are asserted in the arena constants above.
    let piv_used = {
        let mut c = Cursor {
            rows: &mut menu.arena[PIV_OFF..PGP_OFF],
            next: 0,
        };
        let used = cap_piv(fs, &mut c);
        menu.sec_rows[1] = c.next;
        used
    };
    let pgp_keys = {
        let mut c = Cursor {
            rows: &mut menu.arena[PGP_OFF..OATH_OFF],
            next: 0,
        };
        let keys = cap_openpgp(fs, &mut c);
        menu.sec_rows[2] = c.next;
        keys
    };
    let oath_total = {
        let mut c = Cursor {
            rows: &mut menu.arena[OATH_OFF..PK_OFF],
            next: 0,
        };
        let total = cap_oath(fs, device, &mut c);
        menu.sec_rows[3] = c.next;
        total
    };
    let passkeys = {
        let mut c = Cursor {
            rows: &mut menu.arena[PK_OFF..BACKUP_OFF],
            next: 0,
        };
        let counts = cap_passkeys(fs, device, &mut c);
        menu.sec_rows[4] = c.next;
        counts
    };
    let backup = {
        let mut c = Cursor {
            rows: &mut menu.arena[BACKUP_OFF..FW_OFF],
            next: 0,
        };
        let b = cap_backup(fs, &mut c);
        menu.sec_rows[5] = c.next;
        b
    };
    menu.sec_rows[6] = 3;
    cap_firmware(dev, menu);
    let yubi_used = {
        let mut c = Cursor {
            rows: &mut menu.arena[OTP_OFF..ARENA_CAP],
            next: 0,
        };
        let used = cap_yubiotp(fs, device, &mut c);
        menu.sec_rows[7] = c.next;
        used
    };
    cap_overview(
        menu, dev, piv_used, pgp_keys, oath_total, passkeys, backup, yubi_used,
    );
    // The SETTINGS section has no arena rows: one page per setting, each
    // assembled on paint from the live config (each setting owns its page).
    menu.sec_rows[SEC_SETTINGS] = SETTINGS_LIST.len();
}

/// PIV rows, in browse order: the four primary-slot one-liners, the summary
/// rows (retries / certificates / retired count), then one row per occupied
/// retired/F9 slot. A populated primary slot and every retired/F9 row are
/// expandable ([`RowBuf::exp`]): a hold opens their policy page, read on
/// demand (never stored — see `piv_detail`). Returns the "slots used" figure
/// the OVERVIEW counts: populated primary slots plus occupied retired/F9 slots.
fn cap_piv(fs: &mut Store, c: &mut Cursor<'_>) -> usize {
    use rsk_piv::info::read_info;
    let info = read_info(fs);
    let tags = ["9A AUTH", "9C SIG", "9D MGM", "9E CARD"];
    for (i, slot) in info.slots.iter().enumerate() {
        if slot.present {
            c.put_exp(tags[i].as_bytes(), algo_name_ascii(slot.algo), Tone::Plain);
        } else {
            c.put(tags[i].as_bytes(), "EMPTY", Tone::Plain);
        }
    }
    let certs = info.slots.iter().filter(|s| s.cert).count();
    let mut extra = [rsk_piv::info::PivSlot::default(); rsk_piv::info::MAX_EXTRA_SLOTS];
    let extra_n = rsk_piv::info::read_extra(fs, &mut extra);
    let mut n = [0u8; 6];
    c.put(
        b"PIN RETRIES",
        write_dec(&mut n, u16::from(info.pin_retries)),
        retry_tone(info.pin_retries),
    );
    c.put(
        b"PUK RETRIES",
        write_dec(&mut n, u16::from(info.puk_retries)),
        retry_tone(info.puk_retries),
    );
    c.put(
        b"CERTIFICATES",
        write_dec(&mut n, certs as u16),
        Tone::Plain,
    );
    c.put(b"RETIRED", write_dec(&mut n, extra_n as u16), Tone::Plain);
    // Occupied retired / F9 slots, one row each, named so a bare wire
    // reference cannot puzzle the reader: 0xF9 is the *attestation* slot (the
    // hardware self-signed device certificate), 0x82–0x95 are the retired key
    // slots. A certificate for one is implied by it being occupied.
    for slot in extra.iter().take(extra_n) {
        if !slot.present {
            continue;
        }
        let [hi, lo] = hex_byte_tag(slot.slot);
        let mut tag = [0u8; 16];
        let mut len = 0;
        if slot.slot == 0xF9 {
            for &b in b"F9 ATTESTATION".iter() {
                tag[len] = b;
                len += 1;
            }
        } else {
            tag[len] = hi;
            tag[len + 1] = lo;
            len += 2;
            tag[len] = b' ';
            len += 1;
            for &b in b"RETIRED".iter() {
                tag[len] = b;
                len += 1;
            }
        }
        let algo = algo_name_ascii(slot.algo);
        c.put_exp(&tag[..len], algo, Tone::Plain);
    }
    info.populated() as usize + extra_n
}

/// The two-hex-digit wire reference of a retired/F9 slot ("F9", "82", …).
fn hex_byte_tag(v: u8) -> [u8; 2] {
    [hex_digit(v >> 4), hex_digit(v & 0xF)]
}

/// `algo_name` sanitized: its unknown-algorithm fallback is a non-ASCII dash
/// that must never reach the renderer.
fn algo_name_ascii(algo: u8) -> &'static str {
    ascii_name(rsk_piv::info::algo_name(algo))
}

/// An applet name mapper whose fallback can be non-ASCII (`—`) collapses to
/// `--`: "not recorded / unknown" must read as a calm dash, never as a
/// question-marked error. `put` would sanitize it byte-wise anyway, but a
/// whole-field `--` reads clearer than a mid-word one.
fn ascii_name(s: &'static str) -> &'static str {
    if s.as_bytes().iter().all(|b| (0x20..=0x7E).contains(b)) {
        s
    } else {
        "--"
    }
}

fn retry_tone(left: u8) -> Tone {
    // A pristine device reports the default 3; anything below is spent.
    if left < 3 { Tone::Bad } else { Tone::Plain }
}

/// OpenPGP: SIG/DEC/AUT slots, then holder + PW1/PW3 retries + signature
/// count. A `*` on a present slot marks touch protection (UIF).
fn cap_openpgp(fs: &mut Store, c: &mut Cursor<'_>) -> usize {
    use rsk_openpgp::info::read_info;
    let info = read_info(fs);
    let tags = ["SIG", "DEC", "AUT"];
    for (i, slot) in info.slots.iter().enumerate() {
        if slot.present {
            let mut value = [0u8; 20];
            let mut len = 0;
            let algo = slot_algo_ascii(&slot.algo);
            for &b in algo.as_bytes() {
                if len == value.len() {
                    break;
                }
                value[len] = b;
                len += 1;
            }
            if slot.touch && len < value.len() {
                value[len] = b'*';
                len += 1;
            }
            c.put(tags[i].as_bytes(), str_ascii(&value[..len]), Tone::Plain);
        } else {
            c.put(tags[i].as_bytes(), "EMPTY", Tone::Plain);
        }
    }
    // The signing slot's key fingerprint, first eight hex digits — enough to
    // tell two keys apart at a glance, none of the key material itself.
    if let Some(fp) = info.slots[0].fingerprint {
        let mut hex = [0u8; 10];
        let mut len = 0;
        for &b in fp.iter().take(4) {
            hex[len] = hex_digit(b >> 4);
            hex[len + 1] = hex_digit(b & 0xF);
            len += 2;
        }
        hex[len] = b'.';
        hex[len + 1] = b'.';
        c.put(b"SIG FP", str_ascii(&hex[..len + 2]), Tone::Plain);
    }
    // The cardholder name is stored verbatim (raw bytes); sanitize it into the
    // bounded right column before it reaches the row.
    let ch = rsk_openpgp::info::read_cardholder(fs);
    if !ch.name().is_empty() {
        let mut buf = [0u8; 20];
        let mut len = 0u8;
        put_ascii(&mut buf, &mut len, ch.name());
        c.put(b"HOLDER", str_ascii(&buf[..len as usize]), Tone::Plain);
    }
    let mut n = [0u8; 12];
    c.put(
        b"PW1 RETRIES",
        write_dec(&mut n, u16::from(info.pw1_retries)),
        retry_tone(info.pw1_retries),
    );
    c.put(
        b"PW3 RETRIES",
        write_dec(&mut n, u16::from(info.pw3_retries)),
        retry_tone(info.pw3_retries),
    );
    c.put(
        b"SIGNATURES",
        write_dec_u32(&mut n, info.sig_count),
        Tone::Plain,
    );
    info.key_count() as usize
}

/// A slot's algorithm label, ASCII-safe (the `None`/unknown fallbacks in the
/// mapper are non-ASCII and are replaced by `?`).
fn slot_algo_ascii(algo: &rsk_openpgp::info::SlotAlgo) -> &'static str {
    let label = algo.label();
    if label.as_bytes().iter().all(|b| (0x20..=0x7E).contains(b)) {
        label
    } else {
        "--"
    }
}

/// OATH: one row per credential — name | HOTP/TOTP + digits (never a code),
/// `*` marking a touch-gated credential. Capped at [`OATH_PAGE_CAP`] rows with
/// a truthful "+N more" tail; the OVERVIEW count carries the true total.
fn cap_oath(fs: &mut Store, dev: &Device<'_>, c: &mut Cursor<'_>) -> usize {
    let mut total = 0usize;
    rsk_oath::for_each_cred(dev, fs, |cred| {
        total += 1;
        if c.next < OATH_PAGE_CAP {
            // "TOTP 6" / "HOTP 8"; a non-default hash is spelled out, and a
            // touch-gated credential carries a `*`. Deliberately no code, no
            // secret: the menu's rows are public metadata only.
            let mut value = [0u8; 20];
            let mut len = 0;
            for &b in (if cred.hotp { "HOTP" } else { "TOTP" }).as_bytes() {
                value[len] = b;
                len += 1;
            }
            if len < value.len() {
                value[len] = b' ';
                len += 1;
            }
            let mut d = [0u8; 4];
            let digits = write_dec(&mut d, u16::from(cred.digits));
            for &b in digits.as_bytes() {
                if len == value.len() {
                    break;
                }
                value[len] = b;
                len += 1;
            }
            // SHA-1 is the default and unmarked; SHA-256/512 spell out.
            let algo = rsk_oath::algo_name(cred.algo);
            if algo != "SHA1" {
                if len < value.len() {
                    value[len] = b' ';
                    len += 1;
                }
                for &b in algo.as_bytes() {
                    if len == value.len() {
                        break;
                    }
                    value[len] = b;
                    len += 1;
                }
            }
            if cred.touch && len < value.len() {
                value[len] = b'*';
                len += 1;
            }
            // `cred.name` borrows the unseal scratch; `Cursor::put` copies it
            // (and sanitizes) before `for_each_cred` zeroizes the scratch.
            c.put(cred.name, str_ascii(&value[..len]), Tone::Plain);
        }
    });
    if total == 0 {
        c.put(b"NO CREDENTIALS", "", Tone::Plain);
    } else if total > c.next {
        put_more(c, total - c.next);
    }
    total
}

/// A row tailing a capped list, so the visible rows never lie about the rest:
/// "+N more". Used by the OATH and passkey lists (whose totals are also shown
/// in the OVERVIEW counts).
fn put_more(c: &mut Cursor<'_>, more: usize) {
    let mut row = [0u8; ROW_LEFT_MAX];
    let mut len = 0;
    for &b in b"+ MORE: ".iter() {
        row[len] = b;
        len += 1;
    }
    let mut n = [0u8; 12];
    let rest = write_dec(&mut n, more as u16);
    for &b in rest.as_bytes() {
        if len == row.len() {
            break;
        }
        row[len] = b;
        len += 1;
    }
    c.put(&row[..len], "", Tone::Plain);
}

/// Passkeys rows: the two counters alone on the first screen, then one row per
/// relying party (its display name — the nickname when one is set, else the
/// rpId — and how many resident credentials it holds), capped at
/// [`RP_PAGE_CAP`] with a truthful "+N more" tail. Every relying-party row is
/// expandable ([`RowBuf::exp`]): a hold opens its credential list (see
/// `pk_detail_load`). The seed must be unsealed, so this needs the device
/// identity — the same enumeration the touch build's Home card uses. Two
/// passes: the first counts (and decides the tail), the second writes the
/// visible rows; a single pass cannot, because the counter rows come first in
/// the section and the visitor borrows its fields from internal scratch.
fn cap_passkeys(fs: &mut Store, dev: &Device<'_>, c: &mut Cursor<'_>) -> (u16, u16) {
    let mut rps = 0u16;
    let mut creds = 0u16;
    rsk_fido::passkeys::for_each_rp(dev, fs, |rp| {
        rps = rps.saturating_add(1);
        creds = creds.saturating_add(u16::from(rp.count));
    });
    let mut n = [0u8; 6];
    c.put(b"SERVICES", write_dec(&mut n, rps), Tone::Plain);
    c.put(b"CREDENTIALS", write_dec(&mut n, creds), Tone::Plain);
    // The counters own the first screen alone: pad to the page boundary so the
    // relying-party list starts on its own page, with no counters on it.
    for _ in PK_COUNTERS..ROWS_PER_PAGE {
        c.put(b"", "", Tone::Plain);
    }
    let cap = RP_PAGE_CAP as u16;
    if rps > 0 {
        let mut shown = 0u16;
        rsk_fido::passkeys::for_each_rp(dev, fs, |rp| {
            if shown >= cap {
                return;
            }
            let mut d = [0u8; 4];
            let count = write_dec(&mut d, u16::from(rp.count));
            c.put_exp(
                rp.nickname.unwrap_or(rp.rp_id).as_bytes(),
                count,
                Tone::Plain,
            );
            shown += 1;
        });
        if rps > cap {
            put_more(c, usize::from(rps - cap));
        }
    }
    (rps, creds)
}

/// Backup state rows — plain flash probes, no PIN. The state also feeds the
/// OVERVIEW's BACKUP line.
fn cap_backup(fs: &mut Store, c: &mut Cursor<'_>) -> rsk_fido::vendor::BackupStatus {
    let b = rsk_fido::vendor::backup_status(fs);
    c.put(
        b"SEED STORED",
        if b.has_seed { "YES" } else { "NO" },
        if b.has_seed { Tone::Good } else { Tone::Plain },
    );
    let (tone, window) = if !b.has_seed {
        (Tone::Plain, "NONE")
    } else if b.sealed {
        (Tone::Good, "SEALED")
    } else {
        (Tone::Warn, "OPEN")
    };
    c.put(b"EXPORT WINDOW", window, tone);
    c.put(
        b"EXPORTABLE",
        if b.exportable { "YES" } else { "NO" },
        Tone::Plain,
    );
    c.put(
        b"SOFT LOCKED",
        if b.locked { "YES" } else { "NO" },
        if b.locked { Tone::Bad } else { Tone::Plain },
    );
    b
}

/// Yubico-OTP slots, one row per slot: the kind read from the config's flag
/// bits ([`rsk_otp::slot_status`]) — never the slot secrets, which stay in
/// the unseal scratch. An unprogrammed slot reads EMPTY, so empty slots are
/// checkable at a glance too; a `*` marks a slot that demands the press.
/// Returns how many slots are programmed, for the OVERVIEW summary.
fn cap_yubiotp(fs: &mut Store, device: &Device<'_>, c: &mut Cursor<'_>) -> usize {
    let status = rsk_otp::slot_status(device, fs);
    const TAGS: [&str; 4] = ["SLOT 1", "SLOT 2", "SLOT 3", "SLOT 4"];
    for (i, slot) in status.iter().enumerate() {
        let kind = match slot.kind {
            rsk_otp::SlotKind::Empty => "EMPTY",
            rsk_otp::SlotKind::YubicoOtp => "YUBICO OTP",
            rsk_otp::SlotKind::StaticPassword => "STATIC",
            rsk_otp::SlotKind::ChallengeResponse => "CHAL RESP",
            rsk_otp::SlotKind::OathHotp => "OATH HOTP",
        };
        if slot.touch {
            let mut v = [0u8; 12];
            let mut len = 0;
            for &b in kind.as_bytes() {
                v[len] = b;
                len += 1;
            }
            if len < v.len() {
                v[len] = b'*';
                len += 1;
            }
            c.put(TAGS[i].as_bytes(), str_ascii(&v[..len]), Tone::Plain);
        } else {
            c.put(TAGS[i].as_bytes(), kind, Tone::Plain);
        }
    }
    status
        .iter()
        .filter(|s| s.kind != rsk_otp::SlotKind::Empty)
        .count()
}

/// Firmware identity rows: version (bcdDevice), chip id, secure boot (pure
/// OTP read, no flash borrow).
fn cap_firmware(dev: &DeviceKeys, menu: &mut Menu) {
    let mut c = Cursor {
        rows: &mut menu.arena[FW_OFF..FW_OFF + 3],
        next: 0,
    };
    let mut v = [0u8; 6];
    c.put(b"VERSION", hex_u16(dev.release, &mut v), Tone::Plain);
    let mut chip = [0u8; 17];
    hex_bytes(&dev.serial_id, &mut chip);
    c.put(b"CHIP ID", str_ascii(&chip[..16]), Tone::Plain);
    let sb = secure_boot_enabled();
    c.put(
        b"SECURE BOOT",
        if sb { "ON" } else { "OFF" },
        if sb { Tone::Good } else { Tone::Warn },
    );
}

/// OVERVIEW counts — filled last, from the section captures.
#[allow(clippy::too_many_arguments)]
fn cap_overview(
    menu: &mut Menu,
    dev: &DeviceKeys,
    piv_used: usize,
    pgp_keys: usize,
    oath_total: usize,
    passkeys: (u16, u16),
    backup: rsk_fido::vendor::BackupStatus,
    yubi_used: usize,
) {
    let mut c = Cursor {
        rows: &mut menu.arena[OV_OFF..OV_OFF + 7],
        next: 0,
    };
    let mut n = [0u8; 6];
    c.put(b"PIV", write_dec(&mut n, piv_used as u16), Tone::Plain);
    c.put(b"OPENPGP", write_dec(&mut n, pgp_keys as u16), Tone::Plain);
    c.put(b"OATH", write_dec(&mut n, oath_total as u16), Tone::Plain);
    // A count, like every other count row — never green (the touch Home card's
    // passkey count is grey too); tone is reserved for status rows.
    let right = if passkeys.1 == 0 {
        "NONE"
    } else {
        write_dec(&mut n, passkeys.1)
    };
    c.put(b"PASSKEYS", right, Tone::Plain);
    let (tone, right) = if !backup.has_seed {
        (Tone::Plain, "NONE")
    } else if backup.sealed {
        (Tone::Good, "SEALED")
    } else {
        (Tone::Warn, "OPEN")
    };
    c.put(b"BACKUP", right, tone);
    // One summary row per remaining info section, so the OVERVIEW really is
    // the whole menu on two pages.
    let mut v = [0u8; 6];
    let release = hex_u16(dev.release, &mut v);
    c.put(b"FIRMWARE", release, Tone::Plain);
    c.put(
        b"YUBI OTP",
        write_dec(&mut n, yubi_used as u16),
        Tone::Plain,
    );
    menu.sec_rows[0] = c.next;
}

// ---------------------------------------------------------------------------
// Small formatters (no_std, no alloc)

/// Decimal-format `v` into `out`, returning the used prefix.
fn write_dec(out: &mut [u8], v: u16) -> &str {
    write_dec_u32(out, u32::from(v))
}

fn write_dec_u32(out: &mut [u8], mut v: u32) -> &str {
    let mut i = out.len();
    loop {
        i -= 1;
        out[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 || i == 0 {
            break;
        }
    }
    str_ascii(&out[i..])
}

/// `0x` + hex of `v` into `out` (6 bytes).
fn hex_u16(v: u16, out: &mut [u8]) -> &str {
    out[0] = b'0';
    out[1] = b'x';
    out[2] = hex_digit((v >> 12) as u8);
    out[3] = hex_digit((v >> 8) as u8);
    out[4] = hex_digit((v >> 4) as u8);
    out[5] = hex_digit(v as u8);
    str_ascii(&out[..6])
}

fn hex_digit(v: u8) -> u8 {
    let v = v & 0xF;
    if v < 10 { b'0' + v } else { b'A' + (v - 10) }
}

/// Uppercase hex of the 8 chip-id bytes into a 16-char + NUL buffer.
fn hex_bytes(bs: &[u8], out: &mut [u8; 17]) {
    for (i, b) in bs.iter().enumerate() {
        out[i * 2] = hex_digit(b >> 4);
        out[i * 2 + 1] = hex_digit(b & 0xF);
    }
    out[16] = 0;
}

fn secure_boot_enabled() -> bool {
    use rsk_rescue::Platform as _;
    crate::rescue_platform::RescuePlatform
        .secure_boot_status()
        .enabled
}

/// `&str` over an ASCII-filled buffer — always valid UTF-8 by construction.
fn str_ascii(b: &[u8]) -> &str {
    core::str::from_utf8(b).unwrap_or("?")
}

// ---------------------------------------------------------------------------
// The browse loop

/// Poll and busy-block helper used by the gesture loop.
const POLL_MS: u64 = 16;

/// At or past this many milliseconds a press is a *hold*: it enters a level
/// (the settings select, a PIV/PASSKEYS pick) or confirms in an option editor.
/// Matches `GestureWait`'s HOLD_MS.
const HOLD_MS: u64 = 800;

/// How long after a short press the recognizer keeps the door open for a
/// second press: a second tap inside this window turns the pair into a double
/// (back); a lone tap fires as a next only when the window closes. This is the
/// delay a single next tap pays — the price of one-key double-click
/// navigation, accepted by design.
const DOUBLE_WINDOW_MS: u64 = 300;

/// True while a host has configured the device. The USB handler flips the LED
/// status on the interrupt executor, so this is visible from any thread and
/// menu polls pick it up within one 16 ms tick.
fn configured() -> bool {
    led::status() != rsk_led::STATUS_BOOT
}

/// One recognised gesture of the three-gesture scheme (menu layer only; the
/// host-session confirm page keeps its press/hold approve/decline semantics).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Gesture {
    /// A lone short press — next (page, option).
    Tap,
    /// Two short presses inside the double window — back / leave the menu.
    Double,
    /// A press held past [`HOLD_MS`] — confirm (only settings own a confirm).
    Hold,
}

/// Wait for the key to go up, bounded so a stuck key cannot wedge the menu;
/// used on entry and on configured exits so the worker's idle-click counter
/// never wakes to a still-down key.
#[cfg(not(feature = "no-touch"))]
fn wait_key_up(button: &mut presence::Button, fs: &'static RefCell<Store>) {
    let start = embassy_time::Instant::now();
    while button.pressed() {
        if configured() {
            return;
        }
        if start.elapsed() >= embassy_time::Duration::from_millis(2000) {
            return;
        }
        block_ms(POLL_MS);
    }
    let _ = fs;
}

/// Recognise one complete gesture. A hold fires the moment it reaches
/// [`HOLD_MS`] — the key need not be released for a confirm to run (the
/// caller's next recognizer pass re-arms on the up edge, so the eventual
/// release is consumed, never re-read as a tap). A press released earlier is
/// a tap, and a second tap landing within [`DOUBLE_WINDOW_MS`] of the first
/// release turns the pair into a double. `None` means a host configured (or a
/// stuck key past a bound); the caller re-polls.
#[cfg(not(feature = "no-touch"))]
fn gesture(button: &mut presence::Button) -> Option<Gesture> {
    let start = embassy_time::Instant::now();
    // Re-arm: wait for the key to be up, then for a fresh press edge.
    loop {
        if configured() {
            return None;
        }
        if !button.pressed() {
            break;
        }
        if start.elapsed() >= embassy_time::Duration::from_millis(2000) {
            return None;
        }
        block_ms(POLL_MS);
    }
    loop {
        if configured() {
            return None;
        }
        if button.pressed() {
            break;
        }
        block_ms(POLL_MS);
    }
    let down = embassy_time::Instant::now();
    loop {
        if configured() {
            return None;
        }
        if !button.pressed() {
            break; // released before the hold threshold — tap path below
        }
        if down.elapsed().as_millis() >= HOLD_MS {
            // A hold fires on the threshold, while the key is still down.
            return Some(Gesture::Hold);
        }
        block_ms(POLL_MS);
    }
    // A tap: keep the double window open for a second press.
    let window_start = embassy_time::Instant::now();
    let mut second_down: Option<embassy_time::Instant> = None;
    loop {
        if configured() {
            return None;
        }
        if button.pressed() {
            second_down = Some(embassy_time::Instant::now());
            break;
        }
        if window_start.elapsed() >= embassy_time::Duration::from_millis(DOUBLE_WINDOW_MS) {
            break;
        }
        block_ms(POLL_MS);
    }
    let Some(down2) = second_down else {
        return Some(Gesture::Tap);
    };
    loop {
        if configured() {
            return None;
        }
        if !button.pressed() {
            break; // released before the hold threshold — a double
        }
        if down2.elapsed().as_millis() >= HOLD_MS {
            // A hold as the second press still reads as a hold (confirm).
            return Some(Gesture::Hold);
        }
        block_ms(POLL_MS);
    }
    Some(Gesture::Double)
}

/// The settings the SETTINGS section lists — one row each on its overview
/// page. A hold on the overview starts the row select; a hold on the selected
/// row opens its option editor, where taps cycle and a hold confirms.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Setting {
    MenuDelay,
    /// 180° screen flip for the reversible USB-C plug.
    ScreenFlip,
}

const SETTINGS_LIST: [Setting; 2] = [Setting::MenuDelay, Setting::ScreenFlip];

impl Setting {
    fn name(self) -> &'static str {
        match self {
            Setting::MenuDelay => "MENU DELAY",
            Setting::ScreenFlip => "SCREEN DIRECTION",
        }
    }

    /// The option table the editor cycles (per-setting units).
    fn options(self) -> &'static [u16] {
        match self {
            Setting::MenuDelay => &DELAY_OPTIONS_S,
            Setting::ScreenFlip => &SCREEN_FLIP_OPTIONS_DEG,
        }
    }

    /// The option index the setting's unit is written in (0-based).
    fn value_index(self, idx: usize) -> u16 {
        let opts = self.options();
        let fallback = match self {
            Setting::MenuDelay => DELAY_OPTIONS_S[DEFAULT_DELAY_IDX],
            Setting::ScreenFlip => 0,
        };
        opts.get(idx).copied().unwrap_or(fallback)
    }

    /// The currently stored option index; a stored value that matches no
    /// option (a newer build's record) falls back to the default index.
    fn current_index(self) -> usize {
        match self {
            Setting::MenuDelay => {
                let ms = entry_delay_ms();
                DELAY_OPTIONS_S
                    .iter()
                    .position(|&s| u64::from(s) * 1000 == ms)
                    .unwrap_or(DEFAULT_DELAY_IDX)
            }
            Setting::ScreenFlip => usize::from(screen_flip()),
        }
    }

    /// Write one option as the directory row's current value ("30S" / "180")
    /// into `buf`, returning its length.
    fn fill_value(self, idx: usize, buf: &mut [u8]) -> usize {
        let mut i = fill_number(self.value_index(idx), buf);
        if let Setting::MenuDelay = self {
            buf[i] = b'S';
            i += 1;
        }
        i
    }

    /// Write one option as an editor row label ("5 SECONDS" / "180 DEG") into
    /// `buf`, returning its length.
    fn fill_option(self, idx: usize, buf: &mut [u8]) -> usize {
        let mut i = fill_number(self.value_index(idx), buf);
        let suffix: &[u8] = match self {
            Setting::MenuDelay => b" SECONDS",
            Setting::ScreenFlip => b" DEG",
        };
        for &b in suffix {
            buf[i] = b;
            i += 1;
        }
        i
    }

    /// Persist a confirmed option and update the live value.
    fn apply(self, fs: &mut Store, panel: &mut Panel, idx: usize) {
        match self {
            Setting::MenuDelay => apply_entry_delay(fs, idx),
            Setting::ScreenFlip => apply_screen_flip(fs, panel, idx),
        }
    }
}

/// Decimal-format `v` into `buf`, returning the used length.
fn fill_number(v: u16, buf: &mut [u8]) -> usize {
    let mut n = [0u8; 4];
    let dec = write_dec(&mut n, v);
    let mut i = 0;
    for &b in dec.as_bytes() {
        buf[i] = b;
        i += 1;
    }
    i
}

/// Paint the SETTINGS **overview** page: one row per setting — name + current
/// value — assembled from the live config, never the arena. With `cursor`
/// set (the page's select mode) the cursor row's **value reads green**, the
/// others stay secondary — the green current-value tone doubles as the row
/// cursor, so no extra marker is needed. The overview holds at most one page
/// of settings (four today, two of them listed); a fifth setting needs an
/// overview pager and a section-level cursor, deliberately out of scope
/// until a setting wants it.
fn paint_settings_overview(panel: &mut Panel, cursor: Option<usize>) {
    // Two stages so no row borrows outlive its buffer's fill: first write the
    // value texts into a flat block, then assemble the row structs from it.
    // (The names are `&'static` — no buffer needed.)
    const ROWS: usize = rsk_ui::KEYS_MENU_ROWS_PER_PAGE;
    const VAL_MAX: usize = 8;
    let mut vals = [0u8; ROWS * VAL_MAX];
    let mut vlens = [0u8; ROWS];
    let mut count = 0usize;
    for (slot, item) in SETTINGS_LIST.iter().enumerate().take(ROWS) {
        vlens[slot] = item.fill_value(
            item.current_index(),
            &mut vals[slot * VAL_MAX..(slot + 1) * VAL_MAX],
        ) as u8;
        count += 1;
    }
    let mut rows = [rsk_ui::KeysMenuRow {
        emph: false,
        left: "",
        right: "",
        tone: Tone::Plain,
    }; ROWS];
    for (i, item) in SETTINGS_LIST.iter().enumerate().take(ROWS) {
        rows[i] = rsk_ui::KeysMenuRow {
            emph: cursor == Some(i),
            left: item.name(),
            right: str_ascii(&vals[i * VAL_MAX..i * VAL_MAX + vlens[i] as usize]),
            // Outside the select mode every value is the "current value" tone
            // (green); in the select mode only the cursor row keeps it, which
            // is how the row cursor reads.
            tone: if cursor.is_none() || cursor == Some(i) {
                Tone::Good
            } else {
                Tone::Plain
            },
        };
    }
    let _ = rsk_ui::render_keys_menu_page(panel, TITLES[SEC_SETTINGS], 0, 1, &rows[..count]);
}

/// Paint the option editor of `item`: the option list with the cursor row
/// marked. Four options fit one page.
fn paint_editor(panel: &mut Panel, item: Setting, cursor: usize) {
    // Two stages (see `paint_settings_overview`): fill the option labels into
    // a flat block first, then assemble the rows from it.
    const ROWS: usize = rsk_ui::KEYS_MENU_ROWS_PER_PAGE;
    const LABEL_MAX: usize = 12;
    let mut labels = [0u8; ROWS * LABEL_MAX];
    let mut lens = [0u8; ROWS];
    let mut count = 0usize;
    for idx in 0..item.options().len() {
        if count == ROWS {
            break;
        }
        lens[count] =
            item.fill_option(idx, &mut labels[count * LABEL_MAX..(count + 1) * LABEL_MAX]) as u8;
        count += 1;
    }
    let mut rows = [rsk_ui::KeysMenuRow {
        emph: false,
        left: "",
        right: "",
        tone: Tone::Plain,
    }; ROWS];
    for idx in 0..count {
        rows[idx] = rsk_ui::KeysMenuRow {
            emph: false,
            left: str_ascii(&labels[idx * LABEL_MAX..idx * LABEL_MAX + lens[idx] as usize]),
            right: if idx == cursor { "*" } else { "" },
            tone: if idx == cursor {
                Tone::Good
            } else {
                Tone::Plain
            },
        };
    }
    let _ = rsk_ui::render_keys_menu_page(panel, item.name(), 0, 1, &rows[..count]);
}

/// Paint the linear `page`: resolve it into (section, page-in-section), slice
/// the section's rows for this page, and draw the menu frame. The SETTINGS
/// section draws from the live config instead of the arena.
fn paint_page(panel: &mut Panel, menu: &Menu, sec_pages: &[usize; 9], page: usize) {
    let mut linear = page;
    let mut sec = 0usize;
    while linear >= sec_pages[sec] && sec + 1 < 9 {
        linear -= sec_pages[sec];
        sec += 1;
    }
    if sec == SEC_SETTINGS {
        paint_settings_overview(panel, None);
        return;
    }
    let off = menu.sec_off[sec];
    let rows_n = menu.sec_rows[sec];
    let (start, count) = rsk_ui::keys_menu_page_slice(rows_n, linear);
    let mut rows = [rsk_ui::KeysMenuRow {
        emph: false,
        left: "",
        right: "",
        tone: Tone::Plain,
    }; rsk_ui::KEYS_MENU_ROWS_PER_PAGE];
    for (i, row) in menu.arena[off + start..off + start + count]
        .iter()
        .enumerate()
    {
        rows[i] = row_view(row);
    }
    let _ = rsk_ui::render_keys_menu_page(
        panel,
        TITLES[sec],
        linear as u16,
        sec_pages[sec] as u16,
        &rows[..count],
    );
}

/// A borrow view of one stored row for the renderer.
fn row_view(row: &RowBuf) -> rsk_ui::KeysMenuRow<'_> {
    let left = if row.ll == 0 {
        ""
    } else {
        core::str::from_utf8(&row.left[..row.ll as usize]).unwrap_or("?")
    };
    let right = if row.rl == 0 {
        ""
    } else {
        core::str::from_utf8(&row.right[..row.rl as usize]).unwrap_or("?")
    };
    rsk_ui::KeysMenuRow {
        emph: false,
        left,
        right,
        tone: row.tone,
    }
}

// ---------------------------------------------------------------------------
// Detail pages: read on demand, never stored in the arena

/// A strip position inside a section's directory page, plus the in-section
/// arena row of the picked object (the pick cursor).
#[derive(Clone, Copy)]
struct Pick {
    sec: usize,
    page: usize, // page-in-section
    row: usize,  // in-section arena row
}

/// Which object a detail page shows. Kept (rather than the loaded rows) so a
/// page turn can re-read it.
#[derive(Clone, Copy)]
enum DetailSrc {
    /// Primary slot 0..=3, in the 9A/9C/9D/9E order `read_info` reports.
    PivPrimary { idx: usize },
    /// The `nth` occupied retired/F9 slot, in `read_extra` order.
    PivRetired { nth: usize },
    /// The `nth` relying party, in `for_each_rp` order. The rpId hash is
    /// re-derived from that position on every load — it is never stored.
    PkRp { nth: usize },
}

/// One open detail page group: the object's title (copied from its arena row —
/// already sanitized there) and the current page's rows, loaded on open and on
/// every page turn.
#[derive(Clone, Copy)]
struct Detail {
    src: DetailSrc,
    /// Where a double returns to (the pick the page was opened from).
    back: Pick,
    title: [u8; 40],
    tl: u8,
    page: usize,
    pages: usize,
    rows: [RowBuf; ROWS_PER_PAGE],
    n_rows: usize,
}

/// The `(start, count)` in-section rows a menu page shows.
fn page_rows(menu: &Menu, sec: usize, page: usize) -> (usize, usize) {
    rsk_ui::keys_menu_page_slice(menu.sec_rows[sec], page)
}

/// The first expandable row on `page`, if the page has one (a hold elsewhere
/// has nothing to open).
fn first_exp_row(menu: &Menu, sec: usize, page: usize) -> Option<usize> {
    let (start, count) = page_rows(menu, sec, page);
    let off = menu.sec_off[sec];
    (start..start + count).find(|&r| menu.arena[off + r].exp)
}

/// The next expandable row after `row` on the same page, wrapping within the
/// page; a page with a single expandable row keeps the cursor put.
fn next_exp_row(menu: &Menu, sec: usize, page: usize, row: usize) -> usize {
    let (start, count) = page_rows(menu, sec, page);
    let off = menu.sec_off[sec];
    (1..=count)
        .map(|d| start + (row - start + d) % count)
        .find(|&r| menu.arena[off + r].exp)
        .unwrap_or(row)
}

/// Paint a PIV / PASSKEYS directory page with the pick cursor on `p.row` — the
/// whole row emphasised, the SETTINGS select mode's visual.
fn paint_pick(panel: &mut Panel, menu: &Menu, sec_pages: &[usize; 9], p: Pick) {
    let off = menu.sec_off[p.sec];
    let (start, count) = page_rows(menu, p.sec, p.page);
    let mut rows = [rsk_ui::KeysMenuRow {
        emph: false,
        left: "",
        right: "",
        tone: Tone::Plain,
    }; ROWS_PER_PAGE];
    for (i, row) in menu.arena[off + start..off + start + count]
        .iter()
        .enumerate()
    {
        let mut v = row_view(row);
        if start + i == p.row {
            // The cursor takes the whole row green, the SETTINGS select mode's
            // visual — the row's own tone is `Plain` (a grey value).
            v.emph = true;
            v.tone = Tone::Good;
        }
        rows[i] = v;
    }
    let _ = rsk_ui::render_keys_menu_page(
        panel,
        TITLES[p.sec],
        p.page as u16,
        sec_pages[p.sec] as u16,
        &rows[..count],
    );
}

/// Paint an open detail page group (title = the object's name, the page
/// indicator = the group's own pages).
fn paint_detail(panel: &mut Panel, d: &Detail) {
    let mut rows = [rsk_ui::KeysMenuRow {
        emph: false,
        left: "",
        right: "",
        tone: Tone::Plain,
    }; ROWS_PER_PAGE];
    for (i, row) in d.rows.iter().take(d.n_rows).enumerate() {
        rows[i] = row_view(row);
    }
    let _ = rsk_ui::render_keys_menu_page(
        panel,
        str_ascii(&d.title[..d.tl as usize]),
        d.page as u16,
        d.pages as u16,
        &rows[..d.n_rows],
    );
}

/// The four policy rows shared by every PIV slot detail page — the label and
/// algorithm already sit on the directory row.
fn piv_policy_rows(rows: &mut [RowBuf; ROWS_PER_PAGE], slot: &rsk_piv::info::PivSlot) -> usize {
    use rsk_piv::info::{origin_name, pin_policy_name, touch_policy_name};
    rows[0].set(
        b"PIN POLICY",
        ascii_name(pin_policy_name(slot.pin_policy)),
        Tone::Plain,
        false,
    );
    rows[1].set(
        b"TOUCH POLICY",
        ascii_name(touch_policy_name(slot.touch_policy)),
        Tone::Plain,
        false,
    );
    rows[2].set(
        b"ORIGIN",
        ascii_name(origin_name(slot.origin)),
        Tone::Plain,
        false,
    );
    rows[3].set(
        b"CERTIFICATE",
        if slot.cert { "YES" } else { "NO" },
        Tone::Plain,
        false,
    );
    ROWS_PER_PAGE
}

/// Fill `rows` with a PIV slot's policy page. Returns the rows written — 0
/// when the slot is no longer there (a race with the worker between the
/// capture and the hold).
fn piv_detail_load(fs: &mut Store, src: DetailSrc, rows: &mut [RowBuf; ROWS_PER_PAGE]) -> usize {
    use rsk_piv::info::{MAX_EXTRA_SLOTS, PivSlot, read_extra, read_info};
    match src {
        DetailSrc::PivPrimary { idx } => {
            let info = read_info(fs);
            match info.slots.get(idx) {
                Some(slot) if slot.present => piv_policy_rows(rows, slot),
                _ => 0,
            }
        }
        DetailSrc::PivRetired { nth } => {
            // Count present slots exactly as `cap_piv` lists them: `read_extra`
            // also yields cert-only slots, which have no directory row.
            let mut extra = [PivSlot::default(); MAX_EXTRA_SLOTS];
            let n = read_extra(fs, &mut extra);
            let mut seen = 0usize;
            for slot in extra.iter().take(n) {
                if !slot.present {
                    continue;
                }
                if seen == nth {
                    return piv_policy_rows(rows, slot);
                }
                seen += 1;
            }
            0
        }
        DetailSrc::PkRp { .. } => 0,
    }
}

/// Load one page of a relying party's credentials: the label chain the touch
/// build's service screen uses — user name, then display name, then a literal
/// "(no name)" (the binary user id is never legible); a "UV" value marks a
/// user-verification-protected credential. The seed is unsealed inside this
/// call only. Returns `(rows written, total pages)`.
fn pk_detail_load(
    dev: &DeviceKeys,
    fs: &mut Store,
    nth: usize,
    page: usize,
    rows: &mut [RowBuf; ROWS_PER_PAGE],
) -> (usize, usize) {
    use rsk_fido::passkeys::{for_each_cred, for_each_rp};
    let mkek = read_fused(dev.mkek_source);
    let d = dev.device(&mkek);
    let mut hash = None;
    let mut i = 0usize;
    for_each_rp(&d, fs, |rp| {
        if i == nth {
            hash = Some(rp.rp_id_hash);
        }
        i += 1;
    });
    let Some(hash) = hash else {
        return (0, 1);
    };
    let mut total = 0usize;
    let mut n = 0usize;
    let skip = page * ROWS_PER_PAGE;
    for_each_cred(&d, fs, &hash, |a| {
        let idx = total;
        total += 1;
        if idx < skip || n >= ROWS_PER_PAGE {
            return;
        }
        let label = if !a.user_name.is_empty() {
            a.user_name
        } else if !a.user_display_name.is_empty() {
            a.user_display_name
        } else {
            "(no name)"
        };
        let uv = if a.cred_protect >= 2 { "UV" } else { "" };
        rows[n].set(label.as_bytes(), uv, Tone::Plain, false);
        n += 1;
    });
    (n, total.div_ceil(ROWS_PER_PAGE).max(1))
}

/// Open the detail page of the object at `back`. `None` when the object
/// vanished between the capture and the hold — the pick then simply stays.
fn detail_open(menu: &Menu, back: Pick, fs: &mut Store, dev: &DeviceKeys) -> Option<Detail> {
    let src = match (back.sec, back.row) {
        (SEC_PIV, r) if r < PIV_PRIMARY_ROWS => DetailSrc::PivPrimary { idx: r },
        (SEC_PIV, r) if r >= PIV_RETIRED_ROW0 => DetailSrc::PivRetired {
            nth: r - PIV_RETIRED_ROW0,
        },
        (SEC_PASSKEYS, r) if r >= PK_RP_ROW0 => DetailSrc::PkRp {
            nth: r - PK_RP_ROW0,
        },
        _ => return None,
    };
    let mut rows = [RowBuf::empty(); ROWS_PER_PAGE];
    let (n_rows, pages) = match src {
        DetailSrc::PkRp { nth } => pk_detail_load(dev, fs, nth, 0, &mut rows),
        _ => (piv_detail_load(fs, src, &mut rows), 1),
    };
    if n_rows == 0 {
        return None;
    }
    let row = &menu.arena[menu.sec_off[back.sec] + back.row];
    let mut title = [0u8; ROW_LEFT_MAX];
    let mut tl = 0u8;
    put_ascii(&mut title, &mut tl, &row.left[..row.ll as usize]);
    Some(Detail {
        src,
        back,
        title,
        tl,
        page: 0,
        pages,
        rows,
        n_rows,
    })
}

/// A configured host is leaving: drain a still-held key and report the exit.
#[cfg(not(feature = "no-touch"))]
fn leave_configured(button: &mut presence::Button, fs: &'static RefCell<Store>) {
    wait_key_up(button, fs);
}

/// The single-button browse: holds the thread executor like a confirm wait and
/// paints one menu page per recognised gesture, 16 ms key/status polls
/// between. Three gestures (tap = next page, double = back, hold = enter) drive
/// a **ring** of pages ending in the SETTINGS section: the SETTINGS editor
/// pages own a confirmed write, and the PIV / PASSKEYS directory pages open a
/// read-only detail page on a hold (`Pick` / `Detail` below). Forward past the
/// last page and back past the first both wrap, so SETTINGS is reachable from
/// anywhere by doubling back to the start. There is deliberately no gesture
/// back to the STARTING wash — under a charger the menu is the useful screen;
/// the loop returns only when a host configures the device (the status task
/// then repaints the live status).
#[cfg(not(feature = "no-touch"))]
pub(crate) fn browse(
    panel: &mut Panel,
    button: &mut presence::Button,
    fs: &'static RefCell<Store>,
    dev: &DeviceKeys,
) {
    // A key still held when the menu opens (the tail of an earlier gesture)
    // must not read as a press on the first page.
    wait_key_up(button, fs);

    // One capture: a single flash borrow and fused-key window. The window ends
    // here — `mkek` drops (zeroized) at the closing brace.
    let mut menu = Menu::new();
    {
        let mkek = read_fused(dev.mkek_source);
        let d = dev.device(&mkek);
        capture(&mut fs.borrow_mut(), dev, &d, &mut menu);
    }

    // Pages per section, and the linear total for wrap-around navigation.
    // SETTINGS counts its rows like any section (its overview page lists the
    // settings; a hold on it enters the select mode below).
    let mut sec_pages = [0usize; 9];
    let mut total_pages = 0usize;
    for (i, rows) in menu.sec_rows.iter().enumerate() {
        sec_pages[i] = rows.div_ceil(ROWS_PER_PAGE).max(1);
        total_pages += sec_pages[i];
    }

    let mut page = 0usize; // linear page index over the whole strip
    // The mode above the strip: `None` browses the ring; `Select` walks the
    // SETTINGS overview's rows with taps (a hold on the overview enters it);
    // `Edit` cycles one setting's options (a hold confirms — see below);
    // `Pick` walks a PIV / PASSKEYS directory page's expandable rows (a hold
    // opens the row's read-only detail page); `Detail` pages through that
    // page — nothing writes there, and a double returns to the pick.
    // `large_enum_variant`: the detail page's 4-row buffer dominates the enum
    // by design — these are stack values (no allocator), and only one mode is
    // ever live.
    #[derive(Clone, Copy)]
    #[allow(clippy::large_enum_variant)]
    enum Mode {
        Select { cursor: usize },
        Edit { item: Setting, cursor: usize },
        Pick(Pick),
        Detail(Detail),
    }
    let mut mode: Option<Mode> = None;
    loop {
        if configured() {
            leave_configured(button, fs);
            return;
        }
        match mode {
            Some(Mode::Select { cursor }) => paint_settings_overview(panel, Some(cursor)),
            Some(Mode::Edit { item, cursor }) => paint_editor(panel, item, cursor),
            Some(Mode::Pick(p)) => paint_pick(panel, &menu, &sec_pages, p),
            Some(Mode::Detail(d)) => paint_detail(panel, &d),
            None => paint_page(panel, &menu, &sec_pages, page),
        }
        let Some(g) = gesture(button) else {
            if configured() {
                leave_configured(button, fs);
                return;
            }
            continue; // stuck key past a bound — re-poll
        };
        match (mode, g) {
            // -- settings select mode: taps walk the rows, a hold opens the
            // selected setting's editor, a double leaves back to the strip.
            (Some(Mode::Select { cursor }), Gesture::Tap) => {
                let n = SETTINGS_LIST.len();
                mode = Some(Mode::Select {
                    cursor: (cursor + 1) % n,
                });
            }
            (Some(Mode::Select { cursor }), Gesture::Hold) => {
                let item = SETTINGS_LIST[cursor.min(SETTINGS_LIST.len() - 1)];
                mode = Some(Mode::Edit {
                    item,
                    cursor: item.current_index(),
                });
            }
            (Some(Mode::Select { .. }), Gesture::Double) => {
                mode = None; // leave the overview back to the strip
            }
            // -- option editor: taps cycle, a hold confirms, a double leaves.
            (Some(Mode::Edit { item, cursor }), Gesture::Tap) => {
                let n = item.options().len();
                mode = Some(Mode::Edit {
                    item,
                    cursor: (cursor + 1) % n,
                });
            }
            (Some(Mode::Edit { item, cursor }), Gesture::Hold) => {
                // A confirmed choice: persist it under one short flash borrow
                // (a screen-direction change also flips the panel now), flash
                // an APPLIED page, then return to the overview's select mode
                // with the edited setting still marked.
                item.apply(&mut fs.borrow_mut(), panel, cursor);
                let mut rows = [rsk_ui::KeysMenuRow {
                    emph: false,
                    left: "",
                    right: "",
                    tone: Tone::Plain,
                }; 1];
                rows[0] = rsk_ui::KeysMenuRow {
                    emph: false,
                    left: "APPLIED",
                    right: "",
                    tone: Tone::Good,
                };
                let _ = rsk_ui::render_keys_menu_page(panel, item.name(), 0, 1, &rows);
                block_ms(600);
                mode = Some(Mode::Select {
                    cursor: setting_index(item),
                });
            }
            (Some(Mode::Edit { item, .. }), Gesture::Double) => {
                // Leave the editor without writing, back to the select mode.
                mode = Some(Mode::Select {
                    cursor: setting_index(item),
                });
            }
            // -- pick mode: taps walk this page's expandable rows, a hold opens
            // the picked object's read-only detail page, a double leaves back
            // to the strip at the same page.
            (Some(Mode::Pick(p)), Gesture::Tap) => {
                mode = Some(Mode::Pick(Pick {
                    row: next_exp_row(&menu, p.sec, p.page, p.row),
                    ..p
                }));
            }
            (Some(Mode::Pick(p)), Gesture::Hold) => {
                // The object can vanish between the capture and this hold (the
                // worker shares flash): the pick then simply stays put.
                mode = Some(match detail_open(&menu, p, &mut fs.borrow_mut(), dev) {
                    Some(d) => Mode::Detail(d),
                    None => Mode::Pick(p),
                });
            }
            (Some(Mode::Pick(_)), Gesture::Double) => {
                mode = None; // back to the strip, same page
            }
            // -- read-only detail: taps turn its pages, a double returns to the
            // pick; a hold has nothing to confirm here.
            (Some(Mode::Detail(d)), Gesture::Tap) => match (d.src, d.pages) {
                // Only a relying party's credential list can run past one page;
                // a PIV policy page is always a single frame.
                (DetailSrc::PkRp { nth }, pages) if pages > 1 => {
                    let page = (d.page + 1) % pages;
                    let mut rows = [RowBuf::empty(); ROWS_PER_PAGE];
                    let (n_rows, pages) =
                        pk_detail_load(dev, &mut fs.borrow_mut(), nth, page, &mut rows);
                    mode = Some(Mode::Detail(Detail {
                        page,
                        pages,
                        rows,
                        n_rows,
                        ..d
                    }));
                }
                _ => {}
            },
            (Some(Mode::Detail(d)), Gesture::Double) => {
                mode = Some(Mode::Pick(d.back));
            }
            (Some(Mode::Detail(_)), Gesture::Hold) => {}
            // -- strip browsing.
            (None, Gesture::Tap) => {
                page = (page + 1) % total_pages;
            }
            (None, Gesture::Double) => {
                // The strip is a ring in both directions: back from the first
                // page wraps to the last (SETTINGS) — the fast way to the
                // settings after a long forward browse. No gesture leaves the
                // menu (under a charger the menu is the useful screen; only a
                // host configure exits).
                page = if page == 0 { total_pages - 1 } else { page - 1 };
            }
            (None, Gesture::Hold) => {
                // A hold on the SETTINGS overview enters the select mode; on a
                // PIV / PASSKEYS page that has an expandable row it starts the
                // pick on that row; anywhere else it has nothing to do.
                let mut linear = page;
                let mut sec = 0usize;
                while linear >= sec_pages[sec] && sec + 1 < 9 {
                    linear -= sec_pages[sec];
                    sec += 1;
                }
                if sec == SEC_SETTINGS {
                    mode = Some(Mode::Select { cursor: 0 });
                } else if sec == SEC_PIV || sec == SEC_PASSKEYS {
                    // A page with expandable rows starts the pick on its first
                    // one; a page without any (the PIV summary rows) stays put.
                    // `mode` is already `None` on this arm, so a `None` from the
                    // lookup assigns the same state.
                    mode = first_exp_row(&menu, sec, linear).map(|row| {
                        Mode::Pick(Pick {
                            sec,
                            page: linear,
                            row,
                        })
                    });
                }
            }
        }
    }
}

/// The place of `item` in the SETTINGS list (its overview row).
fn setting_index(item: Setting) -> usize {
    SETTINGS_LIST.iter().position(|&s| s == item).unwrap_or(0)
}

fn block_ms(ms: u64) {
    embassy_time::block_for(embassy_time::Duration::from_millis(ms));
}
