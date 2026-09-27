// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The `phy` device-configuration blob: a TLV record in `EF_PHY` holding USB
//! identity (VID/PID, product & manufacturer strings), LED wiring and options.
//! The rescue applet reads/writes it verbatim; at boot the firmware applies the
//! USB identity AND the LED hardware — pin (`led_gpio`), driver (`led_driver`),
//! brightness/steady, and the WS2812 wire order (`led_order`). The tags below
//! match PicoForge; `led_order` (`0x0D`), `led_num` (`0x0E`) and
//! `usb_manufacturer` (`0x0F`) are RS-Key extensions PicoForge skips as unknown.
//!
//! Its own crate, like `rsk-led`'s `EF_LED_CONF`, because five callers across
//! three tiers read it — the rescue and FIDO applets, `rsk-device`'s CTAPHID
//! reset gate, `rsk-display`'s settings flow, and the firmware's boot path.

#![cfg_attr(not(test), no_std)]
// Host-written and boot-read bytes: a panic here is a board that never comes up.
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use rsk_fs::{Fs, Storage};

/// The phy record file. Outside every applet reset scope — it survives FIDO
/// reset / OpenPGP TERMINATE / PIV reset, like the device key.
pub const EF_PHY: u16 = 0xE020;

// Wire format: one-byte tag, one-byte length. VIDPID = VID ‖ PID big-endian;
// USB_PRODUCT counts a trailing NUL in its length.
const TAG_VIDPID: u8 = 0x0;
const TAG_LED_GPIO: u8 = 0x4;
const TAG_LED_BRIGHTNESS: u8 = 0x5;
const TAG_OPTS: u8 = 0x6;
// Tag `0x08` matches PicoForge `PresenceTimeout`: the touch-wait
// timeout in seconds. (RS-Key once read this as a presence-button GPIO, but the
// button is always BOOTSEL, so that was never used — realigned to PicoForge.)
const TAG_PRESENCE_TIMEOUT: u8 = 0x8;
const TAG_USB_PRODUCT: u8 = 0x9;
const TAG_ENABLED_CURVES: u8 = 0xA;
const TAG_ENABLED_USB_ITF: u8 = 0xB;
const TAG_LED_DRIVER: u8 = 0xC;
// RS-Key vendor tag: WS2812 wire byte order — 0 = rgb (passthrough), 1 = grb
// (red/green swapped). A host that omits it on a write no longer loses it:
// `merge_save` re-emits every tag this parser knows — one it does not, it drops.
const TAG_LED_ORDER: u8 = 0xD;
// RS-Key vendor tag: number of physically-connected addressable LEDs.
// 0 = unset (use the build's MAX_LEDS default).
const TAG_LED_NUM: u8 = 0xE;
// RS-Key vendor tag: USB iManufacturer string, NUL-terminated exactly like
// USB_PRODUCT (0x09). PicoForge skips it as unknown, so `merge_save` preserves it.
const TAG_USB_MANUFACTURER: u8 = 0xF;

/// `led_order` wire value: a standard WS2812B (GRB) part, red↔green swapped.
pub const LED_ORDER_GRB: u8 = 1;

pub const OPT_WCID: u16 = 0x1;
pub const OPT_DIMM: u16 = 0x2;
pub const OPT_DISABLE_POWER_RESET: u16 = 0x4;
pub const OPT_LED_STEADY: u16 = 0x8;

pub const USB_ITF_CCID: u8 = 0x1;
pub const USB_ITF_WCID: u8 = 0x2;
pub const USB_ITF_HID: u8 = 0x4;
pub const USB_ITF_KB: u8 = 0x8;
pub const USB_ITF_LWIP: u8 = 0x10;
pub const USB_ITF_ALL: u8 = USB_ITF_CCID | USB_ITF_WCID | USB_ITF_HID | USB_ITF_KB | USB_ITF_LWIP;

/// The interfaces this firmware can instantiate (WCID/LWIP are not built).
pub const USB_ITF_SUPPORTED: u8 = USB_ITF_CCID | USB_ITF_HID | USB_ITF_KB;

/// The interfaces over which the phy record can be rewritten — CCID (rescue applet)
/// and HID (FIDO vendor `0x41` config). If a stored mask leaves *neither* enabled,
/// no software path can undo it, so the device would be permanently bricked
/// (BOOTSEL reflash only) — even when a "supported" but management-incapable
/// interface like the OTP keyboard survives.
pub const USB_ITF_MANAGEABLE: u8 = USB_ITF_CCID | USB_ITF_HID;

/// The boot-effective interface mask. A stored mask that leaves no
/// management-capable interface (CCID or HID) would strand the device with no way
/// to rewrite the record — so the only way back would be a full flash reflash. Such
/// a mask falls back to ALL. (Checking `USB_ITF_SUPPORTED` here is not enough: a
/// keyboard-only mask is "supported" yet cannot manage the device.)
pub fn effective_usb_itf(phy: &PhyData) -> u8 {
    let mask = phy.enabled_usb_itf.unwrap_or(USB_ITF_ALL);
    if mask & USB_ITF_MANAGEABLE == 0 {
        USB_ITF_ALL
    } else {
        mask
    }
}

/// Largest serialized record (every TLV present, 32-byte product & manufacturer).
/// The trailing `(2 + 1) × 2` covers the RS-Key `led_order` / `led_num` tags and
/// `(2 + 33)` the RS-Key `usb_manufacturer` string.
pub const PHY_MAX_SIZE: usize = (2 + 4)
    + (2 + 1)
    + (2 + 1)
    + (2 + 2)
    + (2 + 1)
    + (2 + 33)
    + (2 + 4)
    + (2 + 1)
    + (2 + 1)
    + (2 + 1)
    + (2 + 1) // led_num
    + (2 + 33); // usb_manufacturer

const PRODUCT_CAP: usize = 32;

/// The USB string-descriptor ceiling, in UTF-16 code units.
///
/// embassy-usb encodes every string descriptor into the 64-byte control buffer
/// under `assert!(pos + 2 < buf.len())`, starting at `pos = 2` and stepping by 2 —
/// so the 31st code unit panics. That panic fires during enumeration, before any
/// command can be served, and `panic_halt` spins in the USB interrupt: no host
/// path (factory reset, rescue wipe) can reach the device afterwards, and a
/// firmware reflash does not clear the record. Every string that reaches
/// `UsbConfig` MUST be clamped to this.
pub const USB_STR_MAX: usize = 30;

/// Byte length of the longest prefix of `s` that fits both `max_units` UTF-16 code
/// units and `max_bytes` bytes, cut on a char boundary.
fn clamped_len(s: &[u8], max_units: usize, max_bytes: usize) -> usize {
    let Ok(t) = core::str::from_utf8(s) else {
        // Not UTF-8. Unreachable from `Product::as_str`, but the API takes bytes;
        // a byte cap may split a char, and the caller falls back to its default.
        return s.len().min(max_bytes);
    };
    let mut units = 0usize;
    for (i, c) in t.char_indices() {
        if units + c.len_utf16() > max_units || i + c.len_utf8() > max_bytes {
            return i;
        }
        units += c.len_utf16();
    }
    t.len()
}

/// Copy `s` into `out`, truncated on a char boundary to [`USB_STR_MAX`] code
/// units. Returns the byte length written.
pub fn clamp_usb_string(s: &[u8], out: &mut [u8]) -> usize {
    let n = clamped_len(s, USB_STR_MAX, out.len());
    if let (Some(dst), Some(src)) = (out.get_mut(..n), s.get(..n)) {
        dst.copy_from_slice(src);
    }
    n
}

/// The USB product string: raw bytes as stored on the wire, NUL excluded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Product {
    buf: [u8; PRODUCT_CAP],
    len: u8,
}

impl Product {
    pub fn new(s: &[u8]) -> Option<Self> {
        if s.is_empty() || s.len() > PRODUCT_CAP {
            return None;
        }
        let mut buf = [0u8; PRODUCT_CAP];
        buf.get_mut(..s.len())?.copy_from_slice(s);
        Some(Product {
            buf,
            len: u8::try_from(s.len()).ok()?,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.buf.get(..self.len as usize).unwrap_or_default()
    }

    pub fn as_str(&self) -> Option<&str> {
        core::str::from_utf8(self.as_bytes()).ok()
    }
}

/// The first `N` bytes of a TLV value the caller's length match sized to `N`.
fn head<const N: usize>(v: &[u8]) -> [u8; N] {
    v.first_chunk().copied().unwrap_or([0; N])
}

/// The value a product / manufacturer string TLV carries: `Some(None)` is the
/// explicit clear (an empty value), and `None` means malformed — a length the
/// `1..=33` arm admits but [`Product`] rejects, i.e. 33 bytes with no terminating
/// NUL. `overlay` leaves the stored string alone for that: clearing a name the host
/// never asked to change is a silent loss, not the merge the write claims to be.
///
/// The TLV length counts a trailing NUL; the string also stops at an embedded one.
fn parse_string_tlv(v: &[u8]) -> Option<Option<Product>> {
    let end = v.iter().position(|&b| b == 0).unwrap_or(v.len());
    let s = v.get(..end).unwrap_or(v);
    if s.is_empty() {
        return Some(None);
    }
    Product::new(s).map(Some)
}

/// The parsed phy record; absent TLVs are `None`. `opts` has no presence
/// flag — absent means 0.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PhyData {
    pub vid_pid: Option<(u16, u16)>,
    pub led_gpio: Option<u8>,
    pub led_brightness: Option<u8>,
    pub opts: u16,
    /// Touch-wait timeout in seconds (tag `0x08`, PicoForge `PresenceTimeout`);
    /// `None` / `0` keeps the firmware's built-in 30 s default.
    pub presence_timeout: Option<u8>,
    pub usb_product: Option<Product>,
    /// USB iManufacturer string (tag `0x0F`, RS-Key extension). Absent ⇒ the
    /// firmware falls back to the VID-derived default, then the build default.
    pub usb_manufacturer: Option<Product>,
    pub enabled_curves: Option<u32>,
    pub enabled_usb_itf: Option<u8>,
    pub led_driver: Option<u8>,
    /// RS-Key WS2812 wire order (tag `0x0D`): `0` = rgb, `1` = grb.
    pub led_order: Option<u8>,
    /// Number of physically connected addressable LEDs (tag `0x0E`);
    /// `None` / `0` = use the build's `MAX_LEDS` default.
    pub led_num: Option<u8>,
}

impl PhyData {
    /// Parse a full phy record: overlay every TLV onto a default record, then
    /// materialize the ENABLED_USB_ITF default (a record without it gets ALL) —
    /// the boot path relies on that. Unknown tags are skipped; a TLV running past
    /// the end ends the parse (the parser must never overread).
    pub fn parse(data: &[u8]) -> PhyData {
        let mut phy = PhyData::default().overlay(data);
        if phy.enabled_usb_itf.is_none() {
            phy.enabled_usb_itf = Some(USB_ITF_ALL);
        }
        phy
    }

    /// Overlay only the TLV tags physically present in `data` onto `self`, leaving
    /// every untouched field at its current value — the read-modify-write half of
    /// `merge_save`. Unlike `parse` it neither starts from a default record nor
    /// forces ENABLED_USB_ITF to ALL, so a partial host write preserves the stored
    /// VID/PID, product, LED order/count and interface mask it did not carry (a tag
    /// is cleared only by an explicit zero/empty TLV, never by omission). Unknown
    /// tags are skipped; a TLV running past the end ends the walk (never overread).
    pub fn overlay(&self, data: &[u8]) -> PhyData {
        let mut phy = *self;
        let mut p = data;
        while let (Some(&tag), Some(&tlen)) = (p.first(), p.get(1)) {
            let end = 2 + usize::from(tlen);
            let Some(v) = p.get(2..end) else {
                break;
            };
            match (tag, v.len()) {
                (TAG_VIDPID, 4) => {
                    let [v0, v1, p0, p1] = head(v);
                    let vid = u16::from_be_bytes([v0, v1]);
                    let pid = u16::from_be_bytes([p0, p1]);
                    phy.vid_pid = Some((vid, pid));
                }
                (TAG_LED_GPIO, 1) => phy.led_gpio = Some(u8::from_be_bytes(head(v))),
                (TAG_LED_BRIGHTNESS, 1) => phy.led_brightness = Some(u8::from_be_bytes(head(v))),
                (TAG_OPTS, 2) => phy.opts = u16::from_be_bytes(head(v)),
                (TAG_PRESENCE_TIMEOUT, 1) => {
                    phy.presence_timeout = Some(u8::from_be_bytes(head(v)))
                }
                (TAG_USB_PRODUCT, 1..=33) => {
                    if let Some(p) = parse_string_tlv(v) {
                        phy.usb_product = p;
                    }
                }
                (TAG_USB_MANUFACTURER, 1..=33) => {
                    if let Some(m) = parse_string_tlv(v) {
                        phy.usb_manufacturer = m;
                    }
                }
                (TAG_ENABLED_CURVES, 4) => phy.enabled_curves = Some(u32::from_be_bytes(head(v))),
                (TAG_ENABLED_USB_ITF, 1) => phy.enabled_usb_itf = Some(u8::from_be_bytes(head(v))),
                (TAG_LED_DRIVER, 1) => phy.led_driver = Some(u8::from_be_bytes(head(v))),
                (TAG_LED_ORDER, 1) => phy.led_order = Some(u8::from_be_bytes(head(v))),
                (TAG_LED_NUM, 1) => phy.led_num = Some(u8::from_be_bytes(head(v))),
                _ => {}
            }
            p = p.get(end..).unwrap_or_default();
        }
        phy
    }

    /// Emit a TLV per present field; OPTS always. Returns the length, or `None`
    /// if `out` is too small (`PHY_MAX_SIZE` always fits).
    pub fn serialize(&self, out: &mut [u8]) -> Option<usize> {
        let mut w = Writer { out, len: 0 };
        if let Some((vid, pid)) = self.vid_pid {
            let ([v0, v1], [p0, p1]) = (vid.to_be_bytes(), pid.to_be_bytes());
            w.tlv(TAG_VIDPID, &[v0, v1, p0, p1])?;
        }
        if let Some(g) = self.led_gpio {
            w.tlv(TAG_LED_GPIO, &[g])?;
        }
        if let Some(b) = self.led_brightness {
            w.tlv(TAG_LED_BRIGHTNESS, &[b])?;
        }
        w.tlv(TAG_OPTS, &self.opts.to_be_bytes())?;
        if let Some(t) = self.presence_timeout {
            w.tlv(TAG_PRESENCE_TIMEOUT, &[t])?;
        }
        if let Some(p) = &self.usb_product {
            let s = p.as_bytes();
            #[expect(
                clippy::cast_possible_truncation,
                reason = "a `Product` holds at most `PRODUCT_CAP` (32) bytes; `Writer::tlv` \
                          says why this is not a `try_from`"
            )]
            let len = (s.len() + 1) as u8;
            w.raw(&[TAG_USB_PRODUCT, len])?;
            w.raw(s)?;
            w.raw(&[0])?;
        }
        if let Some(m) = &self.usb_manufacturer {
            let s = m.as_bytes();
            #[expect(
                clippy::cast_possible_truncation,
                reason = "a `Product` holds at most `PRODUCT_CAP` (32) bytes; `Writer::tlv` \
                          says why this is not a `try_from`"
            )]
            let len = (s.len() + 1) as u8;
            w.raw(&[TAG_USB_MANUFACTURER, len])?;
            w.raw(s)?;
            w.raw(&[0])?;
        }
        if let Some(c) = self.enabled_curves {
            w.tlv(TAG_ENABLED_CURVES, &c.to_be_bytes())?;
        }
        if let Some(i) = self.enabled_usb_itf {
            w.tlv(TAG_ENABLED_USB_ITF, &[i])?;
        }
        if let Some(d) = self.led_driver {
            w.tlv(TAG_LED_DRIVER, &[d])?;
        }
        if let Some(o) = self.led_order {
            w.tlv(TAG_LED_ORDER, &[o])?;
        }
        if let Some(n) = self.led_num {
            w.tlv(TAG_LED_NUM, &[n])?;
        }
        Some(w.len)
    }
}

struct Writer<'a> {
    out: &'a mut [u8],
    len: usize,
}

impl Writer<'_> {
    fn raw(&mut self, b: &[u8]) -> Option<()> {
        let dst = self.out.get_mut(self.len..self.len + b.len())?;
        dst.copy_from_slice(b);
        self.len += b.len();
        Some(())
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "callers pass fixed arrays of at most 4 bytes; each checked form tried \
                  here cost a round-trip proof 17-37% (measured side by side)"
    )]
    fn tlv(&mut self, tag: u8, v: &[u8]) -> Option<()> {
        let len = v.len() as u8;
        self.raw(&[tag, len])?;
        self.raw(v)
    }
}

/// Load the phy record; `None` when none was ever written — **or when the backend
/// could not answer**. Use [`try_load`] wherever the two must not share an arm.
pub fn load<S: Storage>(fs: &mut Fs<S>) -> Option<PhyData> {
    try_load(fs).ok().flatten()
}

/// [`load`] with the failed probe kept apart from the absence: `Ok(None)` is a
/// confirmed "never written", `Err` is "the backend could not answer".
///
/// The distinction is the whole of [`update`]: this record holds the USB identity
/// and the LED wiring, and a caller that reads a fault as "never written" edits the
/// defaults and stores *those* — see there.
pub fn try_load<S: Storage>(fs: &mut Fs<S>) -> rsk_sdk::error::Result<Option<PhyData>> {
    let mut buf = [0u8; PHY_MAX_SIZE];
    // Fs::try_read returns the value's full stored length; clamp before slicing so
    // an over-long EF_PHY record can never push the slice past the fixed buffer.
    Ok(fs
        .try_read(EF_PHY, &mut buf)?
        .map(|n| PhyData::parse(buf.get(..n.min(PHY_MAX_SIZE)).unwrap_or_default())))
}

/// What a boot probe of `EF_PHY` found, with the two answers `load` folds kept
/// apart. `NeverWritten` is a device nobody has configured; `Unreadable` is a
/// medium that would not say — and handing the second one the build defaults gives
/// the boot an interface mask the owner may have narrowed away.
pub enum PhyBoot {
    Loaded(PhyData),
    NeverWritten,
    Unreadable,
}

/// How many times the boot re-probes before calling the record unreadable. `Fs`
/// does not memoise a failed read, so a transient fault clears on the next probe
/// and only a standing one reaches `Unreadable`. Three is the whole budget: this
/// runs before USB attach, and a medium refusing three times is not answering on
/// the fourth.
const BOOT_LOAD_TRIES: usize = 3;

/// [`try_load`] with that retry, for the one caller that cannot report an error to
/// anybody — the boot.
pub fn boot_load<S: Storage>(fs: &mut Fs<S>) -> PhyBoot {
    for _ in 0..BOOT_LOAD_TRIES {
        match try_load(fs) {
            Ok(Some(phy)) => return PhyBoot::Loaded(phy),
            Ok(None) => return PhyBoot::NeverWritten,
            Err(_) => continue,
        }
    }
    PhyBoot::Unreadable
}

impl PhyBoot {
    /// The record, for the identity fields a fault may safely default.
    pub fn record(&self) -> Option<&PhyData> {
        match self {
            Self::Loaded(phy) => Some(phy),
            _ => None,
        }
    }

    /// The boot-effective interface mask.
    ///
    /// `Unreadable` opens the manageable pair and nothing else. Not ALL: that
    /// re-opens an interface the owner disabled, for a whole boot, off a flash
    /// fault. Not narrower either — one management-capable interface has to
    /// survive or the record can never be rewritten, and WHICH one the owner kept
    /// is exactly what could not be read. The price is the keyboard: an OTP slot
    /// does not type on a boot whose `EF_PHY` would not read.
    pub fn usb_itf(&self) -> u8 {
        match self {
            Self::Loaded(phy) => effective_usb_itf(phy),
            Self::NeverWritten => USB_ITF_ALL,
            Self::Unreadable => USB_ITF_MANAGEABLE,
        }
    }
}

/// Persist the phy record.
pub fn save<S: Storage>(fs: &mut Fs<S>, phy: &PhyData) -> rsk_sdk::error::Result<()> {
    let mut buf = [0u8; PHY_MAX_SIZE];
    let record = phy
        .serialize(&mut buf)
        .and_then(|n| buf.get(..n))
        .ok_or(rsk_sdk::error::Error::NoMemory)?;
    fs.put(EF_PHY, record)
}

/// Persist a host-written phy blob as a read-modify-write: overlay only the tags
/// present in `data` onto the stored record, then save. The durability-safe write
/// shared by the FIDO `CONFIG_WRITE` and CCID `WRITE 0x1C` paths — a host tool that
/// sends only the fields it changed (as PicoForge does) can no longer wipe the
/// VID/PID, product, LED order/count or any *known* tag it omitted — a tag this
/// parser does not know is not re-emitted either, so that one does not survive.
/// A tag is cleared only by an explicit zero/empty TLV; `rsk` and PicoForge upsert
/// full records, so nothing regresses. (This closes picoforge#102 / RS-Key#33 on
/// the firmware side.)
pub fn merge_save<S: Storage>(fs: &mut Fs<S>, data: &[u8]) -> rsk_sdk::error::Result<()> {
    update(fs, |phy| *phy = phy.overlay(data))
}

/// Read-modify-write the phy record: apply `f` to the stored record — or to the
/// defaults on a device that never wrote one — and save the result.
///
/// The one definition of that sequence, because three callers each had their own
/// copy and each read a probe the backend could not answer as "never written". That
/// turns an edit of one field into a blind write of the DEFAULT record, wiping the
/// VID/PID, product and LED wiring the caller never meant to touch — the same loss
/// [`merge_save`] exists to prevent, arriving through the flash instead of the host.
/// `Err` is a refusal: nothing is stored.
pub fn update<S: Storage>(
    fs: &mut Fs<S>,
    f: impl FnOnce(&mut PhyData),
) -> rsk_sdk::error::Result<()> {
    let mut phy = try_load(fs)?.unwrap_or_default();
    f(&mut phy);
    save(fs, &phy)
}

/// The smartcard interface-token suffix a real YubiKey carries in its USB product
/// string. `normalize_usb_product` appends it to a YubiKey-masquerade product
/// that lacks a token.
const YK_TOKEN_SUFFIX: &[u8] = b" OTP+FIDO+CCID";

/// Case-sensitive substring test (no_std, no alloc).
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && needle.len() <= hay.len()
        && hay.windows(needle.len()).any(|w| w == needle)
}

/// ASCII-case-insensitive substring test; `needle` must be ASCII-lowercase.
fn contains_ci(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && needle.len() <= hay.len()
        && hay.windows(needle.len()).any(|w| {
            w.iter()
                .zip(needle)
                .all(|(a, b)| a.to_ascii_lowercase() == *b)
        })
}

/// Normalize the effective USB product string so RS-Key can never present a
/// YubiKey-masquerade name that crashes `ykman` / Yubico Authenticator on Windows.
///
/// ykman derives a YubiKey PID purely from the PC/SC reader name (`_pid_from_name`):
/// a name containing `yubico yubikey` but none of the uppercase interface tokens
/// `OTP`/`FIDO`/`CCID`/`U2F` yields an empty interface set, and `PID.of` then builds
/// the non-existent enum key `YK4_` → `KeyError('YK4_')` aborts the whole card scan.
/// When `name` looks like a YubiKey (contains `yubikey`, any case) but lacks the
/// `CCID` token, append `YK_TOKEN_SUFFIX`; otherwise copy verbatim. Writes into
/// `out`, returns the length written.
///
/// The result is always clamped to [`USB_STR_MAX`] code units. When the token
/// would not otherwise fit, the *name* is truncated to make room rather than the
/// token being dropped: dropping it re-opens the ykman crash above, while
/// overrunning the descriptor limit bricks enumeration outright. An `out` too
/// small for even the bare token gets nothing written, and `0` back.
pub fn normalize_usb_product(name: &[u8], out: &mut [u8]) -> usize {
    let cap = out.len().min(USB_STR_MAX);
    if contains_ci(name, b"yubikey") && !contains(name, b"CCID") {
        // Too small to hold the token means there is no safe answer to give: a
        // truncated masquerade name without it is the ykman crash this exists to
        // prevent, so write nothing and leave the caller on its default.
        let Some(room) = cap.checked_sub(YK_TOKEN_SUFFIX.len()) else {
            return 0;
        };
        let n = clamped_len(name, room, room);
        let end = n + YK_TOKEN_SUFFIX.len();
        let (Some(dst), Some(src)) = (out.get_mut(..end), name.get(..n)) else {
            return 0;
        };
        let (head, token) = dst.split_at_mut(n);
        head.copy_from_slice(src);
        token.copy_from_slice(YK_TOKEN_SUFFIX);
        return end;
    }
    let n = clamped_len(name, USB_STR_MAX, cap);
    if let (Some(dst), Some(src)) = (out.get_mut(..n), name.get(..n)) {
        dst.copy_from_slice(src);
    }
    n
}

/// Kani proof harnesses (`cargo kani -p rsk-phy`): the phy record is parsed
/// from flash at every boot and round-trips through the rescue applet's
/// read-modify-write — both directions are small total functions over
/// attacker-/corruption-reachable bytes, so prove them outright (the house
/// rule from docs/testing.md).
#[cfg(kani)]
#[path = "kani.rs"]
mod proofs;

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    reason = "a test's fixture is its own bound, and a panic is its failure report"
)]
mod tests;
