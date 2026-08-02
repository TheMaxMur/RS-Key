// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Build script: generates `memory.x` from the flash size, resolves the
//! compile-time USB identity (see [`resolve_identity`]), the XOSC startup-delay
//! multiplier, and the WS2812 LED pin, and bakes them in as `PK_*` env vars /
//! `cfg`s that `main.rs` reads with `env!` / `#[cfg]`.
use std::env;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

/// The Waveshare RP2350-One's flash, and the layout the checked-in `memory.x`
/// encodes. A `FLASH_SIZE` equal to this (with the default `KVMAIN`) writes that
/// file byte-for-byte.
const DEFAULT_FLASH_SIZE: u32 = 4 * 1024 * 1024;

/// Default KVMAIN — the rsk-fs main partition (creds/keys/DOs) the checked-in
/// `memory.x` encodes. `KVMAIN` overrides it (shrink it to free code space on a
/// small flash). Must match `flash_storage.rs` `MAIN_LEN`, which reads back the
/// same baked `PK_KVMAIN_LEN`.
const DEFAULT_KVMAIN: u32 = 1408 * 1024;

/// KVCNT — the counter partition. Fixed across flash sizes and NOT overridable:
/// the hot per-operation counters need their own churn-isolated pages regardless
/// of board (see `flash_storage.rs` `COUNTER_LEN`).
const KVCNT_LEN: u32 = 128 * 1024;

/// Smallest code region the flash/KVMAIN split may leave. The shipping image is
/// ~900 KiB; anything under this can't link, so [`assert_layout_fits`] rejects the
/// split here with a fix hint instead of leaving a cryptic linker overflow.
const MIN_CODE: u32 = 1024 * 1024;

// --- Board config (BOARD=<name> -> firmware/boards/<name>.toml) ---
struct BoardConfig {
    vidpid: Option<String>,
    usb_vid: Option<u16>,
    usb_pid: Option<u16>,
    usb_manufacturer: Option<String>,
    usb_product: Option<String>,
    led_kind: Option<String>,
    led_pin: Option<u8>,
    led_order: Option<String>,
    led_power_pin: Option<u8>,
    max_leds: Option<u32>,
    presence_source: Option<String>,
    presence_pin: Option<u8>,
    presence_active_high: Option<bool>,
    usr_led_pin: Option<u8>,
    usr_led_active_high: Option<bool>,
    flash_size_mb: Option<u32>,
    kvmain_kb: Option<u32>,
    // display
    display_spi_freq_hz: Option<u32>,
    display_cs: Option<u8>,
    display_dc: Option<u8>,
    display_rst: Option<u8>,
    display_bl_pin: Option<u8>,
    display_bl_pwm_slice: Option<u8>,
    display_bl_pwm_channel: Option<u8>,
    display_tp_rst: Option<u8>,
    display_wake_pin: Option<u8>,
    display_wake_active_high: Option<bool>,
    display_i2c_freq_hz: Option<u32>,
    display_invert_colors: Option<bool>,
    display_color_order: Option<String>,
}

fn read_board() -> Option<BoardConfig> {
    let name = env::var("BOARD").ok()?;
    let path = format!("boards/{name}.toml");
    let raw =
        fs::read_to_string(&path).unwrap_or_else(|_| panic!("BOARD={name:?}: cannot read {path}"));
    println!("cargo:rerun-if-changed={path}");
    Some(parse_toml(&raw))
}

fn parse_toml(raw: &str) -> BoardConfig {
    let mut c = BoardConfig {
        vidpid: None,
        usb_vid: None,
        usb_pid: None,
        usb_manufacturer: None,
        usb_product: None,
        led_kind: None,
        led_pin: None,
        led_order: None,
        led_power_pin: None,
        max_leds: None,
        presence_source: None,
        presence_pin: None,
        presence_active_high: None,
        usr_led_pin: None,
        usr_led_active_high: None,
        flash_size_mb: None,
        kvmain_kb: None,
        display_spi_freq_hz: None,
        display_cs: None,
        display_dc: None,
        display_rst: None,
        display_bl_pin: None,
        display_bl_pwm_slice: None,
        display_bl_pwm_channel: None,
        display_tp_rst: None,
        display_wake_pin: None,
        display_wake_active_high: None,
        display_i2c_freq_hz: None,
        display_invert_colors: None,
        display_color_order: None,
    };
    let mut sec = "";
    fn strip_comment(s: &str) -> &str {
        // Strip a trailing `# ...` from a value, outside a quoted string.
        // (TOML's comment char everywhere except inside a "..."; the boards
        // never quote values with `#` inside, so a simple state toggle is enough.)
        let mut in_q = false;
        for (i, &b) in s.as_bytes().iter().enumerate() {
            match b {
                b'"' => in_q = !in_q,
                b'#' if !in_q => return s[..i].trim_end(),
                _ => {}
            }
        }
        s
    }
    fn u(s: &str) -> &str {
        s.trim().trim_matches('"')
    }
    fn u8(s: &str) -> u8 {
        // Reject, never truncate: `as u8` would wrap a typo like `pin = 258` down to a
        // *plausible* pin (2) before any resolver's `assert!(v <= 29)` could see it, and
        // a value >= 128 aliases into a real GPIO through embassy's bit-7-banked
        // `AnyPin` — so a nonsense number would silently drive the wrong pad.
        u32(s)
            .try_into()
            .unwrap_or_else(|_| panic!("value out of range for a byte-sized board key: {s}"))
    }
    fn u32(s: &str) -> u32 {
        let clean: String = u(s).chars().filter(|c| *c != '_').collect();
        u32::from_str_radix(
            clean.trim_start_matches("0x"),
            if clean.starts_with("0x") { 16 } else { 10 },
        )
        .unwrap_or_else(|_| panic!("bad u32: {}", s))
    }
    fn b(s: &str) -> bool {
        // Mirror the env-var resolvers (`resolve_*_active_high`) exactly, and panic on
        // anything else. Silently reading an unrecognised spelling as `false` is the
        // dangerous shape: `active_high = yes` — a spelling those resolvers document as
        // *true* — would ship the opposite presence polarity, and a pad that then reads
        // permanently asserted confirms the first ceremony of every power cycle with no
        // human action. A board file is build-time input; failing loudly is free.
        match u(s).to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => true,
            "false" | "0" | "no" | "off" => false,
            other => panic!("bad boolean in board file: {other:?}"),
        }
    }
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(s) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            sec = s.trim();
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim(), strip_comment(v).trim());
        match (sec, k) {
            ("usb", "vidpid") => c.vidpid = Some(u(v).to_string()),
            ("usb", "vid") => c.usb_vid = Some(u32(v) as u16),
            ("usb", "pid") => c.usb_pid = Some(u32(v) as u16),
            ("usb", "manufacturer") => c.usb_manufacturer = Some(u(v).to_string()),
            ("usb", "product") => c.usb_product = Some(u(v).to_string()),
            ("led", "kind") => c.led_kind = Some(u(v).to_string()),
            ("led", "pin") => c.led_pin = Some(u8(v)),
            ("led", "order") => c.led_order = Some(u(v).to_string()),
            ("led", "power_pin") => c.led_power_pin = Some(u8(v)),
            ("led", "max_leds") => c.max_leds = Some(u32(v)),
            ("presence", "source") => c.presence_source = Some(u(v).to_string()),
            ("presence", "pin") => c.presence_pin = Some(u8(v)),
            ("presence", "active_high") => c.presence_active_high = Some(b(v)),
            ("usr_led", "pin") => c.usr_led_pin = Some(u8(v)),
            ("usr_led", "active_high") => c.usr_led_active_high = Some(b(v)),
            ("flash", "size_mb") => c.flash_size_mb = Some(u32(v)),
            ("flash", "kvmain_kb") => c.kvmain_kb = Some(u32(v)),
            ("display", "spi_freq_hz") => c.display_spi_freq_hz = Some(u32(v)),
            ("display", "cs") => c.display_cs = Some(u8(v)),
            ("display", "dc") => c.display_dc = Some(u8(v)),
            ("display", "rst") => c.display_rst = Some(u8(v)),
            ("display", "bl_pin") => c.display_bl_pin = Some(u8(v)),
            ("display", "bl_pwm_slice") => c.display_bl_pwm_slice = Some(u8(v)),
            ("display", "bl_pwm_channel") => {
                let ch = u(v);
                c.display_bl_pwm_channel = Some(match ch {
                    "A" | "a" | "0" => 0,
                    "B" | "b" | "1" => 1,
                    _ => panic!("bl_pwm_channel: {ch}"),
                });
            }
            ("display", "tp_rst") => c.display_tp_rst = Some(u8(v)),
            ("display", "wake_pin") => c.display_wake_pin = Some(u8(v)),
            ("display", "wake_active_high") => c.display_wake_active_high = Some(b(v)),
            ("display", "i2c_freq_hz") => c.display_i2c_freq_hz = Some(u32(v)),
            ("display", "invert_colors") => c.display_invert_colors = Some(b(v)),
            ("display", "color_order") => c.display_color_order = Some(u(v).to_string()),
            _ => {}
        }
    }
    c
}

/// Highest GPIO an RP2350A exposes. Every pin a board file or env var can name is
/// bounded by it; `rp-pac`'s own accessor only asserts the RP2350B's 48, so an
/// out-of-range pin would otherwise reach a register with no pad behind it.
const MAX_GPIO: u8 = 29;

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    println!("cargo:rerun-if-env-changed=BOARD");
    let board = read_board();
    if let Some(ref b) = board {
        let set = |k: &str, v: &str| {
            if env::var(k).is_err() {
                unsafe { env::set_var(k, v) }
            }
        };
        if let Some(ref v) = b.vidpid {
            set("VIDPID", v);
        }
        if let Some(v) = b.usb_vid {
            set("USB_VID", &v.to_string());
        }
        if let Some(v) = b.usb_pid {
            set("USB_PID", &v.to_string());
        }
        if let Some(ref v) = b.usb_manufacturer {
            set("USB_MANUFACTURER", v);
        }
        if let Some(ref v) = b.usb_product {
            set("USB_PRODUCT", v);
        }
        if let Some(ref v) = b.led_kind {
            set("LED_KIND", v);
        }
        if let Some(v) = b.led_pin {
            set("LED_PIN", &v.to_string());
        }
        if let Some(ref v) = b.led_order {
            set("LED_ORDER", v);
        }
        if let Some(v) = b.led_power_pin {
            set("LED_POWER_PIN", &v.to_string());
        }
        if let Some(v) = b.max_leds {
            set("MAX_LEDS", &v.to_string());
        }
        // Case-insensitive, like every env resolver: a `source = "GPIO"` that silently
        // dropped the whole block (pin and polarity with it) would fall back to BOOTSEL
        // on a board that has no BOOTSEL button wired for presence.
        if b.presence_source
            .as_deref()
            .map(str::to_ascii_lowercase)
            .as_deref()
            == Some("gpio")
        {
            if let Some(v) = b.presence_pin {
                set("PRESENCE_PIN", &v.to_string());
            }
            if let Some(v) = b.presence_active_high {
                set("PRESENCE_ACTIVE_HIGH", if v { "1" } else { "0" });
            }
        }
        if let Some(v) = b.usr_led_pin {
            set("USR_LED_PIN", &v.to_string());
        }
        if let Some(v) = b.usr_led_active_high {
            set("USR_LED_ACTIVE_HIGH", if v { "1" } else { "0" });
        }
        if let Some(v) = b.flash_size_mb {
            set("FLASH_SIZE", &format!("{}M", v));
        }
        if let Some(v) = b.kvmain_kb {
            set("KVMAIN", &format!("{}K", v));
        }
        if let Some(v) = b.display_wake_pin {
            set("WAKE_PIN", &v.to_string());
        }
        if let Some(v) = b.display_wake_active_high {
            set("WAKE_ACTIVE_HIGH", if v { "1" } else { "0" });
        }
    }

    // memory.x: the checked-in script is the default 4 MB / 1408K-KVMAIN layout;
    // for any other FLASH_SIZE or KVMAIN we splice a recomputed MEMORY block
    // (code = flash − KVMAIN − KVCNT) into it and keep the rest verbatim.
    let flash_size = resolve_flash_size();
    let kvmain_len = resolve_kvmain_len();
    assert_layout_fits(flash_size, kvmain_len);
    let template = std::fs::read_to_string("memory.x").expect("read memory.x");
    let memory_x = if flash_size == DEFAULT_FLASH_SIZE && kvmain_len == DEFAULT_KVMAIN {
        template
    } else {
        splice_memory_block(&template, flash_size, kvmain_len)
    };
    File::create(out.join("memory.x"))
        .unwrap()
        .write_all(memory_x.as_bytes())
        .unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-env=PK_FLASH_SIZE={flash_size}");
    println!("cargo:rerun-if-env-changed=FLASH_SIZE");
    println!("cargo:rustc-env=PK_KVMAIN_LEN={kvmain_len}");
    println!("cargo:rerun-if-env-changed=KVMAIN");

    let (vid, pid, manufacturer, product) = resolve_identity();
    println!("cargo:rustc-env=PK_USB_VID={vid}");
    println!("cargo:rustc-env=PK_USB_PID={pid}");
    println!("cargo:rustc-env=PK_USB_MANUFACTURER={manufacturer}");
    println!("cargo:rustc-env=PK_USB_PRODUCT={product}");
    println!("cargo:rerun-if-env-changed=VIDPID");
    println!("cargo:rerun-if-env-changed=USB_VID");
    println!("cargo:rerun-if-env-changed=USB_PID");
    println!("cargo:rerun-if-env-changed=USB_MANUFACTURER");
    println!("cargo:rerun-if-env-changed=USB_PRODUCT");

    println!(
        "cargo:rustc-env=PK_XOSC_DELAY_MULT={}",
        resolve_xosc_delay_mult()
    );
    println!("cargo:rerun-if-env-changed=XOSC_DELAY_MULT");

    // WS2812/gpio data pin (`LED_PIN`, default GPIO16). The pin is chosen at
    // RUNTIME from the phy record — `main` selects the concrete embassy pin via a
    // `match` over GPIO 0..=29 — so this is only the BOOT DEFAULT used when the phy
    // record carries no `led_gpio`. Baked as an env the firmware reads with `env!`.
    let led_pin = resolve_led_pin();
    println!("cargo:rustc-env=PK_LED_PIN={led_pin}");
    println!("cargo:rerun-if-env-changed=LED_PIN");

    // Optional LED power-enable GPIO (`LED_POWER_PIN`): a pin driven HIGH at boot to
    // power a gated LED rail (e.g. the Seeed XIAO RP2350's WS2812, powered by GP23).
    // Encoded as an enabled flag + pin so `main` decodes both with its const parser.
    let (led_power_enabled, led_power_pin) = resolve_led_power_pin();
    println!(
        "cargo:rustc-env=PK_LED_POWER_ENABLED={}",
        if led_power_enabled { 1 } else { 0 }
    );
    println!("cargo:rustc-env=PK_LED_POWER_PIN={led_power_pin}");
    println!("cargo:rerun-if-env-changed=LED_POWER_PIN");

    // Optional user/status-LED-off GPIO (`USR_LED_PIN`): a plain pin some boards
    // wire to a nuisance onboard LED (the Seeed XIAO RP2350's active-low USR LED on
    // GP25 lights by default). Driven to its OFF level at boot and held. Encoded as
    // enabled + pin + polarity so `main` decodes all three with its const parser.
    let (usr_led_enabled, usr_led_pin) = resolve_usr_led_pin();
    println!(
        "cargo:rustc-env=PK_USR_LED_ENABLED={}",
        if usr_led_enabled { 1 } else { 0 }
    );
    println!("cargo:rustc-env=PK_USR_LED_PIN={usr_led_pin}");
    println!("cargo:rerun-if-env-changed=USR_LED_PIN");
    println!(
        "cargo:rustc-env=PK_USR_LED_ACTIVE_HIGH={}",
        if resolve_usr_led_active_high() { 1 } else { 0 }
    );
    println!("cargo:rerun-if-env-changed=USR_LED_ACTIVE_HIGH");

    // User-presence source: default BOOTSEL, or `PRESENCE_PIN=<gpio>` for an
    // active-low GPIO button (internal pull-up). Encoded as two numeric envs so
    // `main` can parse them with the existing const decimal parser.
    let (presence_is_gpio, presence_pin) = resolve_presence_pin();
    println!(
        "cargo:rustc-env=PK_PRESENCE_IS_GPIO={}",
        if presence_is_gpio { 1 } else { 0 }
    );
    println!("cargo:rustc-env=PK_PRESENCE_PIN={presence_pin}");
    println!("cargo:rerun-if-env-changed=PRESENCE_PIN");

    // GPIO presence polarity: default active-low (button to ground, internal pull-up).
    // `PRESENCE_ACTIVE_HIGH=1` flips it to active-high (pull-down, pressed = high) for
    // a touch sensor / button to VCC. Only meaningful with a GPIO `PRESENCE_PIN`.
    println!(
        "cargo:rustc-env=PK_PRESENCE_ACTIVE_HIGH={}",
        if resolve_presence_active_high() { 1 } else { 0 }
    );
    println!("cargo:rerun-if-env-changed=PRESENCE_ACTIVE_HIGH");

    // Display-sleep wake button (the `display` build only): default the BAT_PWR button
    // (GPIO25), `WAKE_PIN=none` for touch-only wake, or any GPIO. Polarity via
    // `WAKE_ACTIVE_HIGH` (default active-low). Baked as env consts read in `display.rs`.
    let (wake_enabled, wake_pin) = resolve_wake_pin();
    println!(
        "cargo:rustc-env=PK_WAKE_ENABLED={}",
        if wake_enabled { 1 } else { 0 }
    );
    println!("cargo:rustc-env=PK_WAKE_PIN={wake_pin}");
    println!("cargo:rerun-if-env-changed=WAKE_PIN");
    println!(
        "cargo:rustc-env=PK_WAKE_ACTIVE_HIGH={}",
        if resolve_wake_active_high() { 1 } else { 0 }
    );
    println!("cargo:rerun-if-env-changed=WAKE_ACTIVE_HIGH");

    // LED backend (default `ws2812`, the Waveshare RP2350-One). Selected at
    // compile time so only the chosen driver — and its dependencies (PIO, PWM) —
    // is built. `gpio` = a plain on/off indicator, `pimoroni` = a 3-pin PWM RGB
    // (Pimoroni Tiny 2350), `none` = headless.
    let led_kind = resolve_led_kind();
    println!("cargo:rustc-cfg=led_kind=\"{led_kind}\"");
    println!(
        "cargo:rustc-check-cfg=cfg(led_kind, values(\"ws2812\", \"gpio\", \"pimoroni\", \"none\"))"
    );
    println!("cargo:rerun-if-env-changed=LED_KIND");

    // WS2812 wire byte order (the `ws2812` backend only): `rgb` (default — the
    // Waveshare RP2350-One is unusually RGB) or `grb` (the WS2812B standard, e.g.
    // the TenStar RP2350-USB). The wrong order swaps red↔green (blue is fine).
    let led_order = resolve_led_order();
    println!("cargo:rustc-cfg=led_order=\"{led_order}\"");
    println!("cargo:rustc-check-cfg=cfg(led_order, values(\"rgb\", \"grb\"))");
    println!("cargo:rerun-if-env-changed=LED_ORDER");

    // Maximum number of addressable LEDs the binary can drive. The PIO state
    // machine and frame buffers are sized to this ceiling; the actual number
    // of connected LEDs is set at **runtime** via the phy record (`rsk hw
    // --led-num`), which must be ≤ MAX_LEDS. Default 1 (a single onboard
    // LED); a board with a chain of N addressable LEDs builds `MAX_LEDS=N` (≤64).
    let max_leds = resolve_max_leds();
    println!("cargo:rustc-env=PK_MAX_LEDS={max_leds}");
    println!("cargo:rerun-if-env-changed=MAX_LEDS");

    // Bake fake OTP keys into the image instead of reading the fuses — exercises
    // the kbase migration + boot path without an irreversible OTP write.
    // TEST BUILDS ONLY; never set for a shipped image.
    // Display pin defaults (board config or env var or hardcoded).
    macro_rules! disp {
        ($key:expr, $val:expr) => {
            if env::var($key).is_err() {
                println!("cargo:rustc-env={}={}", $key, $val);
            }
        };
    }
    // Same range check the LED / presence / wake resolvers apply. The compile-time
    // collision block in `main.rs` only tests pins against *each other* and against the
    // hard-wired buses, so without this an out-of-range control pin reaches
    // `AnyPin::steal` and drives whatever pad it aliases onto.
    macro_rules! disp_pin {
        ($key:expr, $val:expr) => {{
            let v: u8 = $val;
            assert!(
                v <= MAX_GPIO,
                "{} must be a GPIO 0..={}: {}",
                $key,
                MAX_GPIO,
                v
            );
            disp!($key, v);
        }};
    }
    let b = board.as_ref();
    // A board config only counts as a display board once it sets `display_cs` —
    // the chip-select is the semantic gate pin, so a `[display]` section it
    // under-specifies is dropped here. The knobs below then fall back to the
    // Waveshare RP2350-Touch-LCD defaults.
    let disp_cfg = b.and_then(|b| b.display_cs.map(|_| b));
    disp!(
        "PK_DISPLAY_SPI_FREQ_HZ",
        disp_cfg
            .and_then(|b| b.display_spi_freq_hz)
            .unwrap_or(62_500_000)
    );
    disp_pin!(
        "PK_DISPLAY_CS",
        disp_cfg.and_then(|b| b.display_cs).unwrap_or(13)
    );
    disp_pin!(
        "PK_DISPLAY_DC",
        disp_cfg.and_then(|b| b.display_dc).unwrap_or(14)
    );
    disp_pin!(
        "PK_DISPLAY_RST",
        disp_cfg.and_then(|b| b.display_rst).unwrap_or(15)
    );
    disp_pin!(
        "PK_DISPLAY_BL_PIN",
        disp_cfg.and_then(|b| b.display_bl_pin).unwrap_or(16)
    );
    disp!(
        "PK_DISPLAY_BL_PWM_SLICE",
        disp_cfg.and_then(|b| b.display_bl_pwm_slice).unwrap_or(0)
    );
    disp!(
        "PK_DISPLAY_BL_PWM_CHANNEL",
        disp_cfg.and_then(|b| b.display_bl_pwm_channel).unwrap_or(0)
    );
    disp_pin!(
        "PK_DISPLAY_TP_RST",
        disp_cfg.and_then(|b| b.display_tp_rst).unwrap_or(17)
    );
    disp!(
        "PK_DISPLAY_I2C_FREQ_HZ",
        disp_cfg
            .and_then(|b| b.display_i2c_freq_hz)
            .unwrap_or(400_000)
    );
    {
        let v = if disp_cfg
            .and_then(|b| b.display_invert_colors)
            .unwrap_or(true)
        {
            "1"
        } else {
            "0"
        };
        if env::var("PK_DISPLAY_INVERT_COLORS").is_err() {
            println!("cargo:rustc-env=PK_DISPLAY_INVERT_COLORS={}", v);
        }
    }
    {
        let v = if disp_cfg
            .and_then(|b| b.display_color_order.as_deref())
            .unwrap_or("rgb")
            == "bgr"
        {
            "1"
        } else {
            "0"
        };
        if env::var("PK_DISPLAY_COLOR_ORDER").is_err() {
            println!("cargo:rustc-env=PK_DISPLAY_COLOR_ORDER={}", v);
        }
    }

    // Display knobs flow from `board.toml`/env var into PK_DISPLAY_*; any change
    // lets `env!("PK_DISPLAY_*")` go stale and bake the wrong pins into the
    // firmware image — re-rustc on any of them.
    println!("cargo:rerun-if-env-changed=PK_DISPLAY_SPI_FREQ_HZ");
    println!("cargo:rerun-if-env-changed=PK_DISPLAY_CS");
    println!("cargo:rerun-if-env-changed=PK_DISPLAY_DC");
    println!("cargo:rerun-if-env-changed=PK_DISPLAY_RST");
    println!("cargo:rerun-if-env-changed=PK_DISPLAY_BL_PIN");
    println!("cargo:rerun-if-env-changed=PK_DISPLAY_BL_PWM_SLICE");
    println!("cargo:rerun-if-env-changed=PK_DISPLAY_BL_PWM_CHANNEL");
    println!("cargo:rerun-if-env-changed=PK_DISPLAY_TP_RST");
    println!("cargo:rerun-if-env-changed=PK_DISPLAY_I2C_FREQ_HZ");
    println!("cargo:rerun-if-env-changed=PK_DISPLAY_INVERT_COLORS");
    println!("cargo:rerun-if-env-changed=PK_DISPLAY_COLOR_ORDER");

    for (env_var, baked) in [("FAKE_MKEK", "PK_FAKE_MKEK"), ("FAKE_DEVK", "PK_FAKE_DEVK")] {
        if let Some(hex) = resolve_fake_key(env_var) {
            println!("cargo:rustc-env={baked}={hex}");
            println!("cargo:warning={env_var} baked into this image — TEST BUILD ONLY, never ship");
        }
        println!("cargo:rerun-if-env-changed={env_var}");
    }
}

/// Resolve `FLASH_SIZE` to a byte count. Accepts a decimal byte count, `0xHEX`,
/// or a `<n>K`/`<n>KB`/`<n>M`/`<n>MB` suffix; defaults to 4 MB. Must be
/// sector-aligned and within 16 MB; [`assert_layout_fits`] then checks it leaves
/// room for KVMAIN + KVCNT + code.
fn resolve_flash_size() -> u32 {
    let raw = env::var("FLASH_SIZE").unwrap_or_else(|_| DEFAULT_FLASH_SIZE.to_string());
    let bytes = parse_size(raw.trim())
        .unwrap_or_else(|| panic!("FLASH_SIZE={raw:?} — use a byte count, 0xHEX, or <n>K / <n>M"));
    assert!(
        bytes.is_multiple_of(4096),
        "FLASH_SIZE={bytes} must be a multiple of 4096 (the QSPI erase sector)"
    );
    assert!(
        bytes <= 16 * 1024 * 1024,
        "FLASH_SIZE={bytes} exceeds the supported 16 MiB"
    );
    bytes
}

/// Resolve `KVMAIN` — the KV main-partition size (creds/keys/OpenPGP DOs). Same
/// syntax as `FLASH_SIZE` (bytes, `0xHEX`, `<n>K`/`<n>M`); defaults to 1408K, the
/// checked-in layout. Shrink it to free code space on a small flash (a 2 MB Seeed
/// XIAO RP2350 / Waveshare Zero-CM wants `FLASH_SIZE=2M KVMAIN=896K`). Sector-
/// aligned; the baked `PK_KVMAIN_LEN` must equal `flash_storage.rs` `MAIN_LEN`,
/// which reads it back.
fn resolve_kvmain_len() -> u32 {
    let raw = env::var("KVMAIN").unwrap_or_else(|_| DEFAULT_KVMAIN.to_string());
    let bytes = parse_size(raw.trim())
        .unwrap_or_else(|| panic!("KVMAIN={raw:?} — use a byte count, 0xHEX, or <n>K / <n>M"));
    assert!(
        bytes.is_multiple_of(4096),
        "KVMAIN={bytes} must be a multiple of 4096 (the QSPI erase sector)"
    );
    assert!(
        bytes >= 128 * 1024,
        "KVMAIN={bytes} too small; the KV ring needs room to migrate (min 128K)"
    );
    bytes
}

/// Reject a flash / KVMAIN split that leaves too little room for code BEFORE the
/// linker does, with a message that names the fix. KVCNT is fixed at the top;
/// KVMAIN and the code region share what is left below it.
fn assert_layout_fits(flash_size: u32, kvmain_len: u32) {
    let kv = kvmain_len + KVCNT_LEN;
    assert!(
        flash_size > kv,
        "FLASH_SIZE={flash_size} too small for KVMAIN + KVCNT ({kv} bytes)"
    );
    let code = flash_size - kv;
    assert!(
        code >= MIN_CODE,
        "this FLASH_SIZE / KVMAIN split leaves only {code} bytes for code (< {MIN_CODE}); \
         the firmware image is ~900K — reduce KVMAIN or raise FLASH_SIZE \
         (a 2 MB board wants FLASH_SIZE=2M KVMAIN=896K)"
    );
}

/// Parse `123`, `0x10000`, `512K`, `4M`, `4MB`, … into a byte count.
fn parse_size(s: &str) -> Option<u32> {
    let lower = s.to_ascii_lowercase();
    let (digits, mult) = if let Some(n) = lower.strip_suffix("mb").or(lower.strip_suffix('m')) {
        (n, 1024 * 1024)
    } else if let Some(n) = lower.strip_suffix("kb").or(lower.strip_suffix('k')) {
        (n, 1024)
    } else {
        (lower.as_str(), 1)
    };
    let digits = digits.trim();
    let base = match digits.strip_prefix("0x") {
        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
        None => digits.parse::<u32>().ok()?,
    };
    base.checked_mul(mult)
}

/// Recompute the `MEMORY { … }` block for a non-default flash size or KVMAIN and
/// splice it into the template, keeping the rest (KV symbols, SECTIONS) verbatim.
/// KVCNT stays fixed at the top; KVMAIN sits below it; the code region is the rest.
fn splice_memory_block(template: &str, flash_size: u32, kvmain_len: u32) -> String {
    let code = flash_size - kvmain_len - KVCNT_LEN;
    let kvmain = 0x1000_0000 + code;
    let kvcnt = kvmain + kvmain_len;
    let block = format!(
        "MEMORY {{\n    \
         FLASH  : ORIGIN = 0x10000000, LENGTH = {}K\n    \
         KVMAIN : ORIGIN = {:#010X}, LENGTH = {}K\n    \
         KVCNT  : ORIGIN = {:#010X}, LENGTH = {}K\n    \
         RAM    : ORIGIN = 0x20000000, LENGTH = 512K\n}}",
        code / 1024,
        kvmain,
        kvmain_len / 1024,
        kvcnt,
        KVCNT_LEN / 1024,
    );
    let start = template
        .find("MEMORY {")
        .expect("memory.x: no MEMORY block");
    let close = template[start..]
        .find('}')
        .expect("memory.x: unterminated MEMORY");
    format!(
        "{}{}{}",
        &template[..start],
        block,
        &template[start + close + 1..]
    )
}

/// Resolve `LED_PIN` (the WS2812 data GPIO) to a number; defaults to 16. Limited
/// to the RP2350A range; point it at a free GPIO to keep the indicator off a pin
/// your board needs.
fn resolve_led_pin() -> u8 {
    let raw = env::var("LED_PIN").unwrap_or_else(|_| "16".into());
    let v = raw
        .trim()
        .parse::<u8>()
        .unwrap_or_else(|_| panic!("LED_PIN={raw:?} must be a GPIO number 0..=29"));
    assert!(
        v <= MAX_GPIO,
        "LED_PIN={v} out of range 0..={MAX_GPIO} (RP2350A GPIOs)"
    );
    v
}

/// Resolve `LED_POWER_PIN` — an optional GPIO driven HIGH at boot to enable a
/// gated LED power rail (e.g. the Seeed XIAO RP2350's onboard WS2812, whose power
/// sits behind GP23). Unset / empty / `none` = no such pin (the default); any
/// `0..=29` selects one. `main` rejects a collision with the LED or presence pin
/// at compile time. Returns `(enabled, pin)`.
fn resolve_led_power_pin() -> (bool, u8) {
    let raw = env::var("LED_POWER_PIN").unwrap_or_default();
    let v = raw.trim().to_ascii_lowercase();
    if v.is_empty() || v == "none" {
        return (false, 0);
    }
    let pin = v
        .parse::<u8>()
        .unwrap_or_else(|_| panic!("LED_POWER_PIN={raw:?} must be `none` or a GPIO number 0..=29"));
    assert!(
        pin <= MAX_GPIO,
        "LED_POWER_PIN={pin} out of range 0..=29 (RP2350A GPIOs)"
    );
    (true, pin)
}

/// Resolve `USR_LED_PIN` — an optional GPIO wired to a nuisance onboard user/status
/// LED that the firmware drives to its OFF level at boot and holds (the Seeed XIAO
/// RP2350's USR LED on GP25 is active-low, so it lights by default). Unset / empty /
/// `none` = no such pin (the default); any `0..=29` selects one. `main` rejects a
/// collision with the LED data pin, its power pin, a GPIO presence pin, or the
/// display wake button at compile time. Returns `(enabled, pin)`.
fn resolve_usr_led_pin() -> (bool, u8) {
    let raw = env::var("USR_LED_PIN").unwrap_or_default();
    let v = raw.trim().to_ascii_lowercase();
    if v.is_empty() || v == "none" {
        return (false, 0);
    }
    let pin = v
        .parse::<u8>()
        .unwrap_or_else(|_| panic!("USR_LED_PIN={raw:?} must be `none` or a GPIO number 0..=29"));
    assert!(
        pin <= MAX_GPIO,
        "USR_LED_PIN={pin} out of range 0..=29 (RP2350A GPIOs)"
    );
    (true, pin)
}

/// Resolve `USR_LED_ACTIVE_HIGH` — the polarity of the `USR_LED_PIN` LED. Default
/// `false` (active-low: off = drive HIGH, e.g. the XIAO's USR LED). `1`/`true`
/// flips to active-high (off = drive LOW). Ignored without a `USR_LED_PIN`.
fn resolve_usr_led_active_high() -> bool {
    let raw = env::var("USR_LED_ACTIVE_HIGH").unwrap_or_default();
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "no" | "off" => false,
        "1" | "true" | "yes" | "on" => true,
        other => panic!("USR_LED_ACTIVE_HIGH={other:?} must be a boolean (0/1, true/false)"),
    }
}

/// Resolve `PRESENCE_PIN` to either BOOTSEL (unset / `bootsel`) or a GPIO
/// number `0..=29` for an active-low button with internal pull-up.
fn resolve_presence_pin() -> (bool, u8) {
    let raw = env::var("PRESENCE_PIN").unwrap_or_default();
    let v = raw.trim().to_ascii_lowercase();
    if v.is_empty() || v == "bootsel" {
        return (false, 0);
    }
    let pin = v.parse::<u8>().unwrap_or_else(|_| {
        panic!("PRESENCE_PIN={raw:?} must be `bootsel` or a GPIO number 0..=29")
    });
    assert!(
        pin <= MAX_GPIO,
        "PRESENCE_PIN={pin} out of range 0..=29 (RP2350A GPIOs)"
    );
    (true, pin)
}

/// Resolve `PRESENCE_ACTIVE_HIGH` to a bool — default `false` (active-low). Accepts
/// `1`/`true`/`yes`/`on` for true and `0`/`false`/`no`/`off`/empty for false.
fn resolve_presence_active_high() -> bool {
    let raw = env::var("PRESENCE_ACTIVE_HIGH").unwrap_or_default();
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "no" | "off" => false,
        "1" | "true" | "yes" | "on" => true,
        other => panic!("PRESENCE_ACTIVE_HIGH={other:?} must be a boolean (0/1, true/false)"),
    }
}

/// Resolve `WAKE_PIN` — the GPIO of the button that wakes the panel from display
/// sleep (the trusted-display build only). Default `25` (the board's BAT_PWR /
/// `KEY_BAT` button on the Waveshare RP2350-Touch-LCD-2.8); `none` disables the
/// button so only a touch wakes; any `0..=29` selects another GPIO. Returns
/// `(enabled, pin)`.
fn resolve_wake_pin() -> (bool, u8) {
    let raw = env::var("WAKE_PIN").unwrap_or_default();
    let v = raw.trim().to_ascii_lowercase();
    if v.is_empty() {
        return (true, 25); // default: the BAT_PWR button (GPIO25)
    }
    if v == "none" {
        return (false, 0);
    }
    let pin = v
        .parse::<u8>()
        .unwrap_or_else(|_| panic!("WAKE_PIN={raw:?} must be `none` or a GPIO number 0..=29"));
    assert!(
        pin <= MAX_GPIO,
        "WAKE_PIN={pin} out of range 0..=29 (RP2350A GPIOs)"
    );
    (true, pin)
}

/// Resolve `WAKE_ACTIVE_HIGH` to a bool — default `false` (active-low, button to
/// ground with internal pull-up). `1`/`true` flips to active-high (pull-down).
fn resolve_wake_active_high() -> bool {
    let raw = env::var("WAKE_ACTIVE_HIGH").unwrap_or_default();
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "no" | "off" => false,
        "1" | "true" | "yes" | "on" => true,
        other => panic!("WAKE_ACTIVE_HIGH={other:?} must be a boolean (0/1, true/false)"),
    }
}

/// Resolve `LED_KIND` (the LED driver backend) to a known value; defaults to
/// `ws2812`. One of: `ws2812` (addressable RGB on `LED_PIN`), `gpio` (a plain
/// on/off LED on `LED_PIN`), `pimoroni` (3-pin PWM RGB, Pimoroni Tiny 2350), or
/// `none` (no indicator).
fn resolve_led_kind() -> String {
    let raw = env::var("LED_KIND").unwrap_or_default();
    let v = raw.trim().to_ascii_lowercase();
    match v.as_str() {
        "" | "ws2812" => "ws2812".into(), // unset / empty → the default backend
        "gpio" | "pimoroni" | "none" => v,
        _ => panic!("LED_KIND={raw:?} must be one of: ws2812, gpio, pimoroni, none"),
    }
}

/// Resolve `MAX_LEDS` (the PIO/array ceiling for addressable LEDs) to a
/// positive integer; defaults to 1 (a single onboard LED). The runtime count
/// (`rsk hw --led-num`) must be ≤ this value.
fn resolve_max_leds() -> u32 {
    let raw = env::var("MAX_LEDS").unwrap_or_else(|_| "1".into());
    let v = raw
        .trim()
        .parse::<u32>()
        .unwrap_or_else(|_| panic!("MAX_LEDS={raw:?} must be a positive integer"));
    assert!(v >= 1, "MAX_LEDS must be >= 1, got {v}");
    assert!(v <= 64, "MAX_LEDS={v} is unreasonably large; max 64");
    v
}

/// Resolve `LED_ORDER` (the WS2812 wire byte order) to `rgb` or `grb`; defaults
/// to `rgb` (the Waveshare RP2350-One). `grb` is the WS2812B standard — pick it
/// on boards whose red/green come out swapped (e.g. the TenStar RP2350-USB).
fn resolve_led_order() -> String {
    let raw = env::var("LED_ORDER").unwrap_or_default();
    let v = raw.trim().to_ascii_lowercase();
    match v.as_str() {
        "" | "rgb" => "rgb".into(), // unset / empty → the Waveshare default
        "grb" => v,
        _ => panic!("LED_ORDER={raw:?} must be rgb or grb"),
    }
}

/// Validate a fake-OTP-key env var: exactly 64 hex chars (32 bytes), returned
/// lowercased. Anything else fails the build — a silently truncated key would
/// "work" while sealing data under the wrong root.
fn resolve_fake_key(var: &str) -> Option<String> {
    let v = env::var(var).ok()?;
    if v.len() != 64 || !v.chars().all(|c| c.is_ascii_hexdigit()) {
        panic!("{var} must be exactly 64 hex chars (32 bytes), got {v:?}");
    }
    Some(v.to_ascii_lowercase())
}

/// Resolve the XOSC startup-delay multiplier (`XOSC_DELAY_MULT`, default 128 =
/// the embassy default). A larger multiplier lengthens the crystal-oscillator
/// settle wait before the chip runs from it, hardening the early-boot /
/// clock-switch window against glitch / fault injection. Range 1..=1024: embassy
/// stores the derived startup count as a `u16`, which a larger multiplier would
/// overflow for the 12 MHz crystal.
fn resolve_xosc_delay_mult() -> u32 {
    let raw = env::var("XOSC_DELAY_MULT").unwrap_or_else(|_| "128".into());
    let v = raw
        .trim()
        .parse::<u32>()
        .unwrap_or_else(|_| panic!("XOSC_DELAY_MULT={raw:?} is not a positive integer"));
    assert!(
        (1..=1024).contains(&v),
        "XOSC_DELAY_MULT={v} out of range 1..=1024"
    );
    v
}

/// Resolve the full USB identity `(VID, PID, manufacturer, product)`.
///
/// `VIDPID=<preset>` picks a named VID/PID pair; the default `RSKey` is this
/// project's own pid.codes identity (`0x1209:0x0001`). `USB_VID` / `USB_PID`
/// (`0xHHHH` or decimal) override either half, and `USB_MANUFACTURER` /
/// `USB_PRODUCT` override the descriptor strings.
///
/// The descriptor strings follow the resolved VID: the default build presents
/// this project's own identity (manufacturer `RS-Key`, product `RS-Key Security
/// Key`) and is NOT a masquerade. The Yubico VID (`0x1050`) instead swaps in the
/// `Yubico` / `YubiKey …` strings, because `ykman` / Yubico Authenticator derive
/// the device's PID *purely from the PC/SC reader name* (it must contain "Yubico
/// YubiKey"). That is an opt-in local-interop flavor — built by the interop suite
/// / CI matrix only — never for distribution.
///
/// NOTE: these are the *build-time* defaults. At runtime the manufacturer string
/// and OpenPGP AID vendor follow the effective (phy-overridden) VID (see `main`),
/// so a phy write that sets the Yubico VID presents the Yubico identity even on a
/// default build. The USB/smartcard identity is cosmetic, never a security control.
fn resolve_identity() -> (u16, u16, String, String) {
    let preset = env::var("VIDPID").unwrap_or_else(|_| "RSKey".into());
    let (mut vid, mut pid) = match preset.as_str() {
        // This project's own pid.codes identity — the default.
        "RSKey" => (0x1209, 0x0001),
        // Vendor-mimicking interop presets (opt-in; local interop only, never
        // distributed). Only the Yubico VID also swaps the descriptor strings.
        "NitroHSM" => (0x20A0, 0x4230),
        "NitroFIDO2" => (0x20A0, 0x42B1),
        "NitroStart" => (0x20A0, 0x4211),
        "NitroPro" => (0x20A0, 0x4108),
        "Nitro3" => (0x20A0, 0x42B2),
        "Yubikey5" => (0x1050, 0x0407),
        "YubikeyNeo" => (0x1050, 0x0116),
        "YubiHSM" => (0x1050, 0x0030),
        "Gnuk" => (0x234B, 0x0000),
        "GnuPG" => (0x1209, 0x2440),
        // Raspberry Pi VID fallback and a non-colliding dev placeholder.
        "Pico" => (0x2E8A, 0x10FD),
        "Dev" => (0xFEFF, 0xFCFD),
        other => panic!(
            "unknown VIDPID preset {other:?}; known: RSKey, NitroHSM, NitroFIDO2, \
             NitroStart, NitroPro, Nitro3, Yubikey5, YubikeyNeo, YubiHSM, Gnuk, GnuPG, \
             Pico, Dev (or set USB_VID / USB_PID directly)"
        ),
    };
    if let Ok(v) = env::var("USB_VID") {
        vid = parse_u16(&v, "USB_VID");
    }
    if let Ok(p) = env::var("USB_PID") {
        pid = parse_u16(&p, "USB_PID");
    }

    // Descriptor strings track the resolved VID: this project's own identity by
    // default; the Yubico VID gets the masquerade strings so the PC/SC reader
    // name carries "Yubico YubiKey" for ykman / Yubico Authenticator.
    let (mut manufacturer, mut product) = if vid == 0x1050 {
        (
            "Yubico".to_string(),
            "YubiKey RSK OTP+FIDO+CCID".to_string(),
        )
    } else {
        ("RS-Key".to_string(), "RS-Key Security Key".to_string())
    };
    if let Ok(m) = env::var("USB_MANUFACTURER") {
        manufacturer = m;
    }
    if let Ok(p) = env::var("USB_PRODUCT") {
        product = p;
    }
    (vid, pid, manufacturer, product)
}

/// Parse a `0xHHHH` (or decimal) 16-bit value from an env override.
fn parse_u16(s: &str, var: &str) -> u16 {
    let s = s.trim();
    let parsed = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => s.parse::<u32>(),
    };
    let v = parsed.unwrap_or_else(|_| panic!("{var}={s:?} is not a 0xHHHH or decimal number"));
    assert!(v <= 0xFFFF, "{var}={s:?} exceeds 16 bits");
    v as u16
}
