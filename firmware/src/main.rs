// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Composite USB device: FIDO CTAPHID + CCID smart-card + emulated keyboard.
//! Two-executor split: USB + the transports run on a high-priority interrupt
//! executor, the [`worker::Worker`] (slow synchronous applet dispatch) on the
//! thread executor — so keepalives keep flowing during long crypto. The second
//! core joins in for RSA keygen only ([`core1`]): both cores race the prime
//! search while the transports keep the host alive.
#![no_std]
#![no_main]

use core::cell::RefCell;

use embassy_executor::{InterruptExecutor, Spawner};
use embassy_rp::bind_interrupts;
use embassy_rp::dma::InterruptHandler as DmaIrq;
use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::interrupt;
use embassy_rp::interrupt::{InterruptExt, Priority};
use embassy_rp::peripherals::{DMA_CH0, PIO0, TRNG, USB};
use embassy_rp::pio::InterruptHandler as PioIrq;
// The `ws2812` LED backend drives the addressable LED over the PIO. Any non-`none`
// build compiles all three hardware backends so the driver is runtime-selectable
// from the phy record (PicoForge); a `none` build pulls in none of them. DMA_CH0
// and the PIO0/DMA IRQs stay bound unconditionally (the type is used by
// `bind_interrupts!` below — harmless when no backend uses it).
#[cfg(not(led_kind = "none"))]
use embassy_rp::pio::Pio;
#[cfg(not(led_kind = "none"))]
use embassy_rp::pio_programs::ws2812::{PioWs2812, PioWs2812Program};
use embassy_rp::trng::{Config as TrngConfig, InterruptHandler as TrngIrq, Trng};
use embassy_rp::usb::{Driver as UsbDriver, InterruptHandler as UsbIrq};
use embassy_time::Timer;
use embassy_usb::class::hid::{
    Config as HidConfig, HidBootProtocol, HidReaderWriter, HidSubclass, HidWriter,
    State as HidState,
};
use embassy_usb::{Builder, Config as UsbConfig, UsbDevice};
use static_cell::StaticCell;

use rsk_crypto::Device;
use rsk_fs::Fs;
use rsk_usb::ccid::{ATR_FIDO, Ccid};
use rsk_usb::ctaphid::{CtapHid, FIDO_REPORT_DESCRIPTOR};

mod ccid_handler;
mod core1;
#[cfg(feature = "display")]
mod display;
mod flash_storage;
mod handler;
mod led;
mod otp_kbd;
mod otp_keys;
mod presence;
mod rescue_platform;
mod vendor;
mod worker;

// The `display` build turns the ST7789 panel into the status indicator, and its
// backlight sits on GPIO16 — the default addressable-LED pin. So the panel and the
// LED can't coexist: the flavor must be built `LED_KIND=none` (which also frees
// GPIO16). Fail loudly at compile time rather than silently double-claim the pin.
#[cfg(all(feature = "display", not(led_kind = "none")))]
compile_error!(
    "the `display` build requires LED_KIND=none (the ST7789 panel replaces the LED \
     and its backlight uses GPIO16); build with `LED_KIND=none ... --features \
     display` — the `firmware-display` nix flavor sets this for you"
);

use flash_storage::{FLASH_SIZE, FlashStorage};
use handler::{FidoRng, Store};
#[cfg(not(feature = "display"))]
use presence::ButtonPresence;
use worker::{ClientCcid, ClientCtap, Worker};

use panic_halt as _;

use embedded_alloc::LlffHeap as Heap;

#[global_allocator]
static HEAP: Heap = Heap::empty();

const HEAP_SIZE: usize = 128 * 1024;

#[unsafe(link_section = ".start_block")]
#[used]
static IMAGE_DEF: embassy_rp::block::ImageDef = embassy_rp::block::ImageDef::secure_exe();

bind_interrupts!(struct Irqs {
    PIO0_IRQ_0 => PioIrq<PIO0>;
    DMA_IRQ_0 => DmaIrq<DMA_CH0>;
    USBCTRL_IRQ => UsbIrq<USB>;
    TRNG_IRQ => TrngIrq<TRNG>;
});

const fn env_u16(s: &str) -> u16 {
    let b = s.as_bytes();
    let mut acc = 0u16;
    let mut i = 0;
    while i < b.len() {
        acc = acc * 10 + (b[i] - b'0') as u16;
        i += 1;
    }
    acc
}
const USB_VID: u16 = env_u16(env!("PK_USB_VID"));
const USB_PID: u16 = env_u16(env!("PK_USB_PID"));
const USB_MANUFACTURER: &str = env!("PK_USB_MANUFACTURER");
const USB_PRODUCT: &str = env!("PK_USB_PRODUCT");

/// The Yubico USB identity presented when the effective VID is Yubico's and the
/// phy record carries no explicit string override — so a runtime VID-only repoint
/// to Yubico still "just works" for ykman / Yubico Authenticator, which key off
/// this reader name (manufacturer + product). An explicit phy `usb_manufacturer`
/// (`0x0F`) or `usb_product` (`0x09`) tag always wins over these defaults.
const YUBICO_VID: u16 = 0x1050;
const YUBICO_MANUFACTURER: &str = "Yubico";
const YUBICO_PRODUCT: &str = "YubiKey RSK OTP+FIDO+CCID";

/// OpenPGP AID manufacturer id for an effective USB VID: the Yubico id when the
/// key presents the Yubico VID (so hosts show the same vendor as a real YubiKey),
/// else the unmanaged range. Keyed on the EFFECTIVE (phy-overridden) VID, not the
/// build VID, so a runtime Yubico repoint is internally consistent.
/// ⚠ this lets a phy-repointed default key present a full Yubico identity at
/// runtime — a deliberate masquerade capability (see docs/threat-model.md).
fn openpgp_mfr_for(vid: u16) -> u16 {
    if vid == YUBICO_VID {
        rsk_openpgp::consts::OPGP_MFR_YUBICO
    } else {
        rsk_openpgp::consts::OPGP_MFR_UNMANAGED
    }
}

const fn env_u32(s: &str) -> u32 {
    let b = s.as_bytes();
    let mut acc = 0u32;
    let mut i = 0;
    while i < b.len() {
        acc = acc * 10 + (b[i] - b'0') as u32;
        i += 1;
    }
    acc
}
const XOSC_DELAY_MULT: u32 = env_u32(env!("PK_XOSC_DELAY_MULT"));

// Build-time LED defaults. The runtime `EF_PHY` record (PicoForge / `rsk hw`)
// overrides each at boot; absent that, the LED behaves exactly as the build
// flags say. Only a non-`none` build renders an LED, so these exist only there.
// The wire-order default lives in `led` (the `LED_RG_SWAP` atomic seeds from the
// `led_order` cfg). `BUILD_DRIVER` maps the build LED_KIND onto the phy driver
// numbering (1=gpio, 2=pimoroni, 3=ws2812).
#[cfg(not(led_kind = "none"))]
const BUILD_LED_PIN: u8 = env_u16(env!("PK_LED_PIN")) as u8;
// Optional LED power-enable pin: a GPIO driven high at boot to power a gated LED
// rail (the Seeed XIAO RP2350's WS2812 sits behind GP23). Off unless `LED_POWER_PIN`
// is set; the LED block claims and holds it. Only a rendered LED needs a rail.
#[cfg(not(led_kind = "none"))]
const BUILD_LED_POWER_ENABLED: bool = env_u16(env!("PK_LED_POWER_ENABLED")) != 0;
#[cfg(not(led_kind = "none"))]
const BUILD_LED_POWER_PIN: u8 = env_u16(env!("PK_LED_POWER_PIN")) as u8;
const BUILD_PRESENCE_IS_GPIO: bool = env_u16(env!("PK_PRESENCE_IS_GPIO")) != 0;
#[cfg(not(feature = "display"))]
const BUILD_PRESENCE_PIN: u8 = env_u16(env!("PK_PRESENCE_PIN")) as u8;
#[cfg(not(feature = "display"))]
const BUILD_PRESENCE_ACTIVE_HIGH: bool = env_u16(env!("PK_PRESENCE_ACTIVE_HIGH")) != 0;

// Active-high polarity only applies to a GPIO presence button (BOOTSEL has a fixed
// sense); flag a stray `PRESENCE_ACTIVE_HIGH` set without a GPIO `PRESENCE_PIN`.
#[cfg(not(feature = "display"))]
const _: () = assert!(
    !BUILD_PRESENCE_ACTIVE_HIGH || BUILD_PRESENCE_IS_GPIO,
    "PRESENCE_ACTIVE_HIGH only applies with a GPIO PRESENCE_PIN"
);

// A `display` build takes user presence from the touchscreen, not a GPIO button, so a
// `PRESENCE_PIN` would be silently ignored — fail the build loudly instead (mirrors
// the LED_KIND guard above). The non-display path consumes both consts directly.
#[cfg(feature = "display")]
const _: () = assert!(
    !BUILD_PRESENCE_IS_GPIO,
    "PRESENCE_PIN has no effect on a `display` build (presence is the touchscreen); \
     drop PRESENCE_PIN, or build without --features display"
);

// Display-sleep wake button (the `display` build only): build.rs bakes the GPIO
// (default 25 = the BAT_PWR / KEY_BAT button on the Waveshare RP2350-Touch-LCD-2.8),
// whether it is enabled (`WAKE_PIN=none` disables it for touch-only wake) and its
// polarity. `main` claims the pin and hands an `Input` to `display::Ui::build`.
#[cfg(feature = "display")]
const BUILD_WAKE_ENABLED: bool = env_u16(env!("PK_WAKE_ENABLED")) != 0;
#[cfg(feature = "display")]
const BUILD_WAKE_PIN: u8 = env_u16(env!("PK_WAKE_PIN")) as u8;
#[cfg(feature = "display")]
const BUILD_WAKE_ACTIVE_HIGH: bool = env_u16(env!("PK_WAKE_ACTIVE_HIGH")) != 0;

// The wake button must not collide with the LCD/touch GPIOs (10..=18) the display build
// already drives — catch a bad `WAKE_PIN` at compile time rather than double-claim a pad.
#[cfg(feature = "display")]
const _: () = assert!(
    !BUILD_WAKE_ENABLED || BUILD_WAKE_PIN < 10 || BUILD_WAKE_PIN > 18,
    "WAKE_PIN collides with an LCD/touch GPIO (10..=18) owned by the display build"
);

// Optional nuisance user/status LED to hold OFF at boot (`USR_LED_PIN`): a plain
// GPIO some boards wire to an onboard LED that lights by default (the Seeed XIAO
// RP2350's active-low USR LED on GP25). Independent of the addressable status LED,
// so it applies on a `none` build too; driven to its OFF level and held for the
// device's lifetime. Off unless `USR_LED_PIN` is set.
const BUILD_USR_LED_ENABLED: bool = env_u16(env!("PK_USR_LED_ENABLED")) != 0;
const BUILD_USR_LED_PIN: u8 = env_u16(env!("PK_USR_LED_PIN")) as u8;
const BUILD_USR_LED_ACTIVE_HIGH: bool = env_u16(env!("PK_USR_LED_ACTIVE_HIGH")) != 0;

// USR_LED_PIN must own its pad — reject a build that aims it at any pin another
// driver already claims, each check gated to where that pin exists.
#[cfg(not(feature = "display"))]
const _: () = assert!(
    !(BUILD_USR_LED_ENABLED && BUILD_PRESENCE_IS_GPIO && BUILD_USR_LED_PIN == BUILD_PRESENCE_PIN),
    "USR_LED_PIN must not equal a GPIO PRESENCE_PIN"
);
#[cfg(not(led_kind = "none"))]
const _: () = assert!(
    !(BUILD_USR_LED_ENABLED && BUILD_USR_LED_PIN == BUILD_LED_PIN),
    "USR_LED_PIN must not equal LED_PIN"
);
#[cfg(not(led_kind = "none"))]
const _: () = assert!(
    !(BUILD_USR_LED_ENABLED && BUILD_LED_POWER_ENABLED && BUILD_USR_LED_PIN == BUILD_LED_POWER_PIN),
    "USR_LED_PIN must not equal LED_POWER_PIN"
);
// A display build has no onboard nuisance LED to silence — the panel replaces the
// LED and already drives the LCD/touch GPIOs (10..=18) plus the GP25 wake button —
// so USR_LED_PIN there is only a chance to double-claim a panel pad; refuse it.
#[cfg(feature = "display")]
const _: () = assert!(
    !BUILD_USR_LED_ENABLED,
    "USR_LED_PIN is not supported on a display build (the panel replaces the onboard LED)"
);

#[cfg(led_kind = "ws2812")]
const BUILD_DRIVER: u8 = 3;
#[cfg(led_kind = "gpio")]
const BUILD_DRIVER: u8 = 1;
#[cfg(led_kind = "pimoroni")]
const BUILD_DRIVER: u8 = 2;

type Drv = UsbDriver<'static, USB>;

static EXECUTOR_HIGH: InterruptExecutor = InterruptExecutor::new();

#[interrupt]
unsafe fn SWI_IRQ_1() {
    unsafe { EXECUTOR_HIGH.on_interrupt() }
}

static CONFIG_DESC: StaticCell<[u8; 256]> = StaticCell::new();
static BOS_DESC: StaticCell<[u8; 256]> = StaticCell::new();
static MSOS_DESC: StaticCell<[u8; 64]> = StaticCell::new();
static CONTROL_BUF: StaticCell<[u8; 64]> = StaticCell::new();
static HID_STATE: StaticCell<HidState> = StaticCell::new();
static KBD_STATE: StaticCell<HidState> = StaticCell::new();
static OTP_HID_HANDLER: StaticCell<otp_kbd::OtpHidHandler> = StaticCell::new();
static USB_HANDLER: StaticCell<led::StatusHandler> = StaticCell::new();
// Holds the LED power-enable `Output` for the device's lifetime; dropping it would
// release the pad and let the gated LED rail fall (see the LED block below).
#[cfg(not(led_kind = "none"))]
static LED_PWR: StaticCell<embassy_rp::gpio::Output<'static>> = StaticCell::new();
// Holds the USR-LED-off `Output` for the device's lifetime; dropping it would
// release the pad and let a pulled nuisance LED light again (see the boot block).
static USR_LED: StaticCell<embassy_rp::gpio::Output<'static>> = StaticCell::new();
static FS: StaticCell<RefCell<Store>> = StaticCell::new();
static FLASH_CELL: StaticCell<RefCell<flash_storage::AsyncFlash>> = StaticCell::new();
static RNG_CELL: StaticCell<RefCell<FidoRng>> = StaticCell::new();
static PRESENCE: StaticCell<RefCell<presence::Presence>> = StaticCell::new();
static RESCUE_PLATFORM: StaticCell<RefCell<rescue_platform::RescuePlatform>> = StaticCell::new();
// Sized for a 32-byte phy product plus the appended YubiKey interface-token
// suffix (`normalize_usb_product`), so a masquerade name is never truncated.
static PHY_PRODUCT: StaticCell<[u8; 64]> = StaticCell::new();
// Holds a phy-provided iManufacturer string (`0x0F`) for the device's lifetime so
// the descriptor's `&'static str` outlives the embassy Builder. 32-byte phy cap.
static PHY_MANUFACTURER: StaticCell<[u8; 64]> = StaticCell::new();
// The mipidsi SPI pixel-batch buffer for the `display` build: bigger = fewer SPI
// transactions per fill. 4 KiB ≈ 8 full panel rows per chunk.
#[cfg(feature = "display")]
const DISPLAY_BUF_LEN: usize = 4096;
#[cfg(feature = "display")]
static DISPLAY_BUF: StaticCell<[u8; DISPLAY_BUF_LEN]> = StaticCell::new();
/// The trusted-display panel + touch, shared by `status_task` (ambient status) and
/// the `TouchPresence` backend (the confirm prompt) on the thread executor.
#[cfg(feature = "display")]
static UI: StaticCell<RefCell<display::Ui>> = StaticCell::new();

struct SendUsb(UsbDevice<'static, Drv>);
unsafe impl Send for SendUsb {}

#[embassy_executor::task]
async fn usb_task(mut device: SendUsb) {
    device.0.run().await;
}

#[embassy_executor::task]
async fn ctap_task(mut ctap: CtapHid<'static, Drv, ClientCtap>) {
    ctap.run().await;
}

#[embassy_executor::task]
async fn ccid_task(mut ccid: Ccid<'static, Drv, ClientCcid>) {
    ccid.run().await;
}

// The worker is spawned, not awaited at the tail of `main`, so `main` returns and
// its ~95 KiB one-time init stack frame is reclaimed off the shared MSP before any
// crypto runs. Awaiting it inline kept that frame live under every dispatch, which
// left ML-DSA-65 keygen flush against the stack ceiling (it halted on the next
// interrupt). Must stay on the thread executor, never `hp`, so keepalives keep flowing.
#[embassy_executor::task]
async fn worker_task(mut worker: Worker<'static>) {
    worker.run().await;
}

unsafe extern "C" {
    static __kvmain_start: u32;
    static __kvmain_end: u32;
    static __kvcnt_start: u32;
    static __kvcnt_end: u32;
}

fn kvmain_range() -> core::ops::Range<u32> {
    let start = core::ptr::addr_of!(__kvmain_start) as u32;
    let end = core::ptr::addr_of!(__kvmain_end) as u32;
    start..end
}

fn kvcnt_range() -> core::ops::Range<u32> {
    let start = core::ptr::addr_of!(__kvcnt_start) as u32;
    let end = core::ptr::addr_of!(__kvcnt_end) as u32;
    start..end
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let mut config = embassy_rp::config::Config::default();
    if let Some(xosc) = config.clocks.xosc.as_mut() {
        xosc.delay_multiplier = XOSC_DELAY_MULT;
    }
    let p = embassy_rp::init(config);

    {
        use core::mem::MaybeUninit;
        static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
        unsafe { HEAP.init(core::ptr::addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE) }
    }

    let serial_id = embassy_rp::otp::get_chipid().unwrap_or(0).to_le_bytes();
    let serial_hash = rsk_crypto::sha256(&serial_id);

    let (otp_mkek, otp_devk) = otp_keys::read_keys();
    otp_keys::sw_lock_key_page();

    let flash = Flash::<_, Blocking, FLASH_SIZE>::new_blocking(p.FLASH);
    let flash_cell = FLASH_CELL.init(RefCell::new(flash_storage::wrap_flash(flash)));
    let storage = FlashStorage::new(flash_cell, kvmain_range(), kvcnt_range());
    let mut fs = Fs::new(storage);
    fs.scan(); // recover dynamic files (counter, resident creds) from flash

    let mut usb_vid = USB_VID;
    let mut usb_pid = USB_PID;
    let mut usb_itf = rsk_rescue::phy::USB_ITF_ALL;
    // Explicit phy string overrides; `None` ⇒ the VID-derived default, then the
    // build const, are chosen at the identity assembly below. The product is
    // normalized against the ykman YK4_ crash; the manufacturer is copied verbatim
    // (that crash is a product/reader-name concern only). Both need a StaticCell so
    // the descriptor's `&'static str` outlives the USB Builder. The phy record also
    // drives the LED hardware, applied at the spawn site below.
    let mut phy_product: Option<&str> = None;
    let mut phy_manufacturer: Option<&str> = None;
    let phy = rsk_rescue::phy::load(&mut fs);
    if let Some(phy) = &phy {
        if let Some((vid, pid)) = phy.vid_pid {
            (usb_vid, usb_pid) = (vid, pid);
        }
        if let Some(s) = phy.usb_product.as_ref().and_then(|prod| prod.as_str()) {
            let buf = PHY_PRODUCT.init([0; 64]);
            let n = rsk_rescue::phy::normalize_usb_product(s.as_bytes(), buf);
            phy_product = core::str::from_utf8(&buf[..n]).ok();
        }
        if let Some(s) = phy.usb_manufacturer.as_ref().and_then(|m| m.as_str()) {
            let sb = s.as_bytes(); // Product caps at 32 bytes, so it always fits 64
            let buf = PHY_MANUFACTURER.init([0; 64]);
            buf[..sb.len()].copy_from_slice(sb);
            phy_manufacturer = core::str::from_utf8(&buf[..sb.len()]).ok();
        }
        usb_itf = rsk_rescue::phy::effective_usb_itf(phy);
        // Touch-wait timeout (phy tag 0x08, seconds; 0/absent = default).
        presence::set_timeout_secs(phy.presence_timeout.unwrap_or(0));
    }

    // Provision/recover all persistent state BEFORE attaching to USB. `builder.build()`
    // below asserts the bus pull-up (embassy `driver.start` -> `set_pullup_en`), so the
    // host starts enumerating the instant we attach. The task that answers control
    // transfers (`usb_task` -> `device.run()`) must then be spawned with no blocking
    // work in between — otherwise the host enumerates into a device that is attached
    // but mute and times out the first descriptor request. That window (heaviest on a
    // fresh device: seed + attestation cert + OpenPGP DEK + flash writes) was the
    // "blink red / not recognised until several replugs" report on a Waveshare RP2350.
    let mut trng_cfg = TrngConfig::default();
    // The default sample_count (25) is too low for some RP2350 ROSC units: the
    // TRNG's autocorrelation health-check fails, the hardware soft-resets and
    // re-samples in a loop, so seeding the DRBG (48 B, `FidoRng::new`) blocked
    // ~90 s on EVERY boot on one Waveshare RP2350 unit (variable 30–105 s). A
    // higher sample_count decorrelates consecutive ROSC samples so the check
    // passes the first time (~1.5 s boot, HW-verified). Entropy quality is
    // unchanged — the NIST health checks stay enabled, the source is unchanged.
    trng_cfg.sample_count = 1000;
    let trng = Trng::new(p.TRNG, Irqs, trng_cfg);
    let mut rng = FidoRng::new(trng);

    let dev = Device {
        serial_hash: &serial_hash,
        serial_id: &serial_id,
        otp_key: otp_mkek.as_ref(),
    };
    let _ = rsk_fido::seed::migrate_keydev_boot(&dev, &mut fs);
    rsk_rescue::keydev::migrate_kbase(&dev, &mut fs, &mut rng);
    rsk_piv::migrate_kbase(&dev, &mut fs, &mut rng);
    rsk_oath::migrate_seal(&dev, &mut fs, &mut rng);
    rsk_otp::migrate_seal(&dev, &mut fs, &mut rng);
    rsk_fido::credential::migrate_rp_seal(&dev, &mut fs);
    let _ = rsk_fido::seed::ensure_seed(&dev, &mut fs, &mut rng);
    let _ = rsk_openpgp::scan_files(&dev, &mut fs, &mut rng);
    // One-shot at-rest hardening. The seal migrations above re-key every secret
    // from the chip-serial root to the OTP root, but the log-structured store
    // keeps the superseded chip-serial-sealed copies (notably the pre-OTP seed)
    // recoverable from a flash dump until the page is reclaimed. Scrub them with
    // a full GC lap the first time we boot with the OTP key present. Gated on a
    // flash marker so it runs once and crash-safely: an interrupted lap leaves
    // `EF_HARDENED` unset and re-runs next boot (the lap is idempotent), and a
    // device provisioned OTP-first pays it once with nothing to scrub. It is a
    // multi-second stall — deliberately before USB attach, at an attended
    // provisioning boot. See `flash_storage::FlashStorage::compact`.
    if otp_mkek.is_some() && !fs.has_data(rsk_fido::consts::EF_HARDENED) && fs.compact().is_ok() {
        let _ = fs.put(rsk_fido::consts::EF_HARDENED, &[1u8]);
    }
    // PHY carries the boot-default LED brightness + steady (PicoForge's global LED
    // knobs) and the RS-Key wire-order tag. Apply them BEFORE `load_led_config` so
    // a per-status `EF_LED_CONF` (set via `rsk led`) overrides brightness/steady;
    // the wire order is not in EF_LED_CONF, so it stands.
    #[cfg(not(led_kind = "none"))]
    if let Some(phy) = &phy {
        // OPT_DIMM ("LED Dimmable") gates the global brightness override: without
        // it, the boot brightness is not forced and the per-status EF_LED_CONF /
        // defaults stand, so the toggle actually means something.
        if phy.opts & rsk_rescue::phy::OPT_DIMM != 0
            && let Some(b) = phy.led_brightness
        {
            led::set_all_brightness(b);
        }
        led::set_steady(phy.opts & rsk_rescue::phy::OPT_LED_STEADY != 0);
        if let Some(order) = phy.led_order {
            led::set_rg_swap(order != 0);
        }
        // Runtime LED count from phy; 0 or None means "use the build default"
        // (already set as `RUNTIME_LEDS = MAX_LEDS` at init).
        if let Some(n) = phy.led_num.filter(|&n| n > 0) {
            led::set_runtime_leds(n);
        }
    }
    vendor::load_led_config(&mut fs);
    rsk_otp::power_up_bump(&dev, &mut fs, &mut rng);

    let fs_ref = FS.init(RefCell::new(fs));
    let rng_ref = RNG_CELL.init(RefCell::new(rng));

    let driver = UsbDriver::new(p.USB, Irqs);
    Timer::after_millis(200).await;

    // Manufacturer + product strings and the OpenPGP AID vendor follow the
    // EFFECTIVE (phy-overridden) VID, so a runtime Yubico VID yields a consistent
    // Yubico identity that ykman / Yubico Authenticator recognize. Precedence per
    // string: an explicit phy override > the VID-derived default > the build const.
    // ⚠ a phy-repointed key can thus present a full Yubico identity at runtime —
    // a deliberate masquerade capability (docs/threat-model).
    let (vid_manufacturer, vid_product) = if usb_vid == YUBICO_VID {
        (YUBICO_MANUFACTURER, YUBICO_PRODUCT)
    } else {
        (USB_MANUFACTURER, USB_PRODUCT)
    };
    let usb_manufacturer = phy_manufacturer.unwrap_or(vid_manufacturer);
    let usb_product = phy_product.unwrap_or(vid_product);
    let openpgp_mfr = openpgp_mfr_for(usb_vid);

    let mut config = UsbConfig::new(usb_vid, usb_pid);
    config.manufacturer = Some(usb_manufacturer);
    config.product = Some(usb_product);
    config.serial_number = Some("rs-key-0001");
    config.max_power = 100;
    config.max_packet_size_0 = 64;
    // bcdDevice build counter; also surfaced on the trusted-display Firmware screen.
    let device_release: u16 = 0x083E;
    config.device_release = device_release;

    let mut builder = Builder::new(
        driver,
        config,
        CONFIG_DESC.init([0; 256]),
        BOS_DESC.init([0; 256]),
        MSOS_DESC.init([0; 64]),
        CONTROL_BUF.init([0; 64]),
    );

    let hid = (usb_itf & rsk_rescue::phy::USB_ITF_HID != 0).then(|| {
        HidReaderWriter::<_, 64, 64>::new(
            &mut builder,
            HID_STATE.init(HidState::new()),
            HidConfig {
                report_descriptor: FIDO_REPORT_DESCRIPTOR,
                request_handler: None,
                // 1 ms HID interval: a credMgmt/getAssertion response is several
                // 64-byte IN frames; at 5 ms/frame that framing dominated once the
                // per-call flash scan was removed. Full-speed floor is 1 ms.
                poll_ms: 1,
                max_packet_size: 64,
                hid_subclass: HidSubclass::No,
                hid_boot_protocol: HidBootProtocol::None,
            },
        )
    });

    // Advertise CCID secure PIN entry (bPINSupport = VERIFY) only on the display
    // build, where the trusted touchscreen can collect the PIN; a button build has
    // no pad and leaves it off. The byte is the single switch every host CCID stack
    // reads to drive on-device PIN entry.
    let ccid_pin_support: u8 = if cfg!(feature = "display") {
        0x01
    } else {
        0x00
    };
    let ccid = (usb_itf & rsk_rescue::phy::USB_ITF_CCID != 0)
        .then(|| Ccid::new(&mut builder, ClientCcid, ATR_FIDO, ccid_pin_support));

    let kbd = (usb_itf & rsk_rescue::phy::USB_ITF_KB != 0).then(|| {
        HidWriter::<_, 8>::new(
            &mut builder,
            KBD_STATE.init(HidState::new()),
            HidConfig {
                report_descriptor: otp_kbd::KEYBOARD_REPORT_DESCRIPTOR,
                request_handler: Some(OTP_HID_HANDLER.init(otp_kbd::OtpHidHandler)),
                poll_ms: 10,
                max_packet_size: 8,
                hid_subclass: HidSubclass::No,
                hid_boot_protocol: HidBootProtocol::None,
            },
        )
    });

    // Go green (idle) the moment the host configures us, not on the first applet
    // command — a healthy, enumerated key with no PC/SC client talking to it would
    // otherwise sit on the red boot status. (See `led::StatusHandler`.)
    builder.handler(USB_HANDLER.init(led::StatusHandler));

    // Attach to the host (pull-up) and immediately start servicing it: no blocking
    // work between `build()` and the `usb_task` spawn (see the init note above).
    let usb = builder.build();
    let ctap = hid.map(|h| {
        let (reader, writer) = h.split();
        CtapHid::new(
            reader,
            writer,
            ClientCtap,
            presence::up_pending,
            presence::request_cancel,
        )
    });

    interrupt::SWI_IRQ_1.set_priority(Priority::P2);
    let hp = EXECUTOR_HIGH.start(interrupt::SWI_IRQ_1);
    hp.spawn(usb_task(SendUsb(usb)).unwrap());
    if let Some(ctap) = ctap {
        hp.spawn(ctap_task(ctap).unwrap());
    }
    if let Some(ccid) = ccid {
        hp.spawn(ccid_task(ccid).unwrap());
    }
    if let Some(kbd) = kbd {
        hp.spawn(otp_kbd::kbd_task(kbd).unwrap());
    }

    // Hold a nuisance onboard user LED off (`USR_LED_PIN`), independent of the
    // addressable status LED so it also applies on a `none` build. Drive the pad to
    // the LED's OFF level and park the `Output` for the device's lifetime — dropping
    // it would release the pad back to its (pulled) reset state and relight the LED.
    if BUILD_USR_LED_ENABLED {
        use embassy_rp::gpio::{Level, Output};
        // Active-low LED (default) is off when HIGH; active-high is off when LOW.
        let off = if BUILD_USR_LED_ACTIVE_HIGH {
            Level::Low
        } else {
            Level::High
        };
        // Safety: this runs only when USR_LED is enabled, which the const asserts
        // above forbid on a display build; on every other build they prove the pin
        // collides with no LED data/power pin nor a GPIO presence pin.
        let any = unsafe { embassy_rp::gpio::AnyPin::steal(BUILD_USR_LED_PIN) };
        USR_LED.init(Output::new(any, off));
    }

    // LED backend, selected at runtime from the phy record (PicoForge-compatible),
    // defaulting to the build LED_KIND / LED_PIN. A non-`none` build compiles all
    // three hardware backends so the driver + pin can change without reflashing; a
    // `none` build is headless (the status engine still runs — vendor SET/GET LED
    // keep working — but nothing renders it). The runtime pin reaches the PIO state
    // machine via a `match` that moves the shared `sm0`/`DMA_CH0` across its
    // mutually-exclusive arms (every `PioWs2812` erases the pin type, so all arms
    // share one type) — embassy has no `PioPin for AnyPin`, but it doesn't need one.
    #[cfg(not(led_kind = "none"))]
    {
        use embassy_rp::gpio::{Level, Output};
        use embassy_rp::pwm::Pwm;

        // A build whose default LED pin collides with a GPIO presence pin is a
        // configuration error — reject it at compile time, never at runtime on the
        // boot path (a host-written phy record must not be able to reach a panic).
        const _: () = assert!(
            !(BUILD_PRESENCE_IS_GPIO && BUILD_PRESENCE_PIN == BUILD_LED_PIN),
            "PK_PRESENCE_PIN must not equal PK_LED_PIN on a GPIO-presence build"
        );
        // A power-enable pin (`LED_POWER_PIN`) must own its own pad — reject a build
        // that points it at the LED data pin or a GPIO presence pin, same as above.
        const _: () = assert!(
            !BUILD_LED_POWER_ENABLED || BUILD_LED_POWER_PIN != BUILD_LED_PIN,
            "PK_LED_POWER_PIN must not equal PK_LED_PIN"
        );
        const _: () = assert!(
            !BUILD_LED_POWER_ENABLED
                || !BUILD_PRESENCE_IS_GPIO
                || BUILD_LED_POWER_PIN != BUILD_PRESENCE_PIN,
            "PK_LED_POWER_PIN must not equal a GPIO PK_PRESENCE_PIN"
        );
        // Some boards gate the LED's power rail behind an enable GPIO (the Seeed XIAO
        // RP2350's WS2812 is powered by GP23, driven high). Raise the rail BEFORE the
        // driver below clocks data into an otherwise-unpowered LED. The `Output` is
        // parked in a StaticCell for the device's lifetime — a dropped one would
        // release the pad and drop the rail.
        if BUILD_LED_POWER_ENABLED {
            // Safety: the const asserts above guarantee this pin is handed to no other
            // driver (never the LED data pin nor the GPIO presence pin).
            let any = unsafe { embassy_rp::gpio::AnyPin::steal(BUILD_LED_POWER_PIN) };
            LED_PWR.init(Output::new(any, Level::High));
        }
        // PHY led_gpio overrides the build LED_PIN; an out-of-range pin is ignored,
        // and a host-written pin that collides with the GPIO presence pin is dropped
        // (they would fight over one pin) so it falls back to the build default rather
        // than bricking the boot into a panic loop.
        let led_gpio = phy
            .as_ref()
            .and_then(|p| p.led_gpio)
            .filter(|&g| g <= 29)
            .filter(|&g| !(BUILD_PRESENCE_IS_GPIO && g == BUILD_PRESENCE_PIN))
            .unwrap_or(BUILD_LED_PIN);
        // PHY led_driver (1=gpio, 2=pimoroni, 3=ws2812) overrides the build kind;
        // anything else (unset, or the N/A esp32 value) keeps the build default.
        let led_driver = match phy.as_ref().and_then(|p| p.led_driver) {
            Some(d @ 1..=3) => d,
            _ => BUILD_DRIVER,
        };

        match led_driver {
            1 => {
                // `gpio`: a plain on/off LED on `led_gpio`. `Output<'static>` erases
                // the pin, so every arm is the same type.
                macro_rules! gpio_pin {
                    ($pin:expr) => {
                        Output::new($pin, Level::Low)
                    };
                }
                let led = match led_gpio {
                    0 => gpio_pin!(p.PIN_0),
                    1 => gpio_pin!(p.PIN_1),
                    2 => gpio_pin!(p.PIN_2),
                    3 => gpio_pin!(p.PIN_3),
                    4 => gpio_pin!(p.PIN_4),
                    5 => gpio_pin!(p.PIN_5),
                    6 => gpio_pin!(p.PIN_6),
                    7 => gpio_pin!(p.PIN_7),
                    8 => gpio_pin!(p.PIN_8),
                    9 => gpio_pin!(p.PIN_9),
                    10 => gpio_pin!(p.PIN_10),
                    11 => gpio_pin!(p.PIN_11),
                    12 => gpio_pin!(p.PIN_12),
                    13 => gpio_pin!(p.PIN_13),
                    14 => gpio_pin!(p.PIN_14),
                    15 => gpio_pin!(p.PIN_15),
                    16 => gpio_pin!(p.PIN_16),
                    17 => gpio_pin!(p.PIN_17),
                    18 => gpio_pin!(p.PIN_18),
                    19 => gpio_pin!(p.PIN_19),
                    20 => gpio_pin!(p.PIN_20),
                    21 => gpio_pin!(p.PIN_21),
                    22 => gpio_pin!(p.PIN_22),
                    23 => gpio_pin!(p.PIN_23),
                    24 => gpio_pin!(p.PIN_24),
                    25 => gpio_pin!(p.PIN_25),
                    26 => gpio_pin!(p.PIN_26),
                    27 => gpio_pin!(p.PIN_27),
                    28 => gpio_pin!(p.PIN_28),
                    _ => gpio_pin!(p.PIN_29),
                };
                hp.spawn(led::gpio_task(led).unwrap());
            }
            2 => {
                // `pimoroni`: a 3-pin PWM RGB on fixed pins (Pimoroni Tiny 2350) —
                // R=GPIO18 (slice1·A), G=GPIO19 (slice1·B), B=GPIO20 (slice2·A);
                // common-anode polarity is in `led::pimoroni_cfg`. led_gpio is N/A.
                let rg = Pwm::new_output_ab(p.PWM_SLICE1, p.PIN_18, p.PIN_19, led::pimoroni_cfg());
                let b = Pwm::new_output_a(p.PWM_SLICE2, p.PIN_20, led::pimoroni_cfg());
                hp.spawn(led::pimoroni_task(rg, b).unwrap());
            }
            _ => {
                // `ws2812` (driver 3, and the safe fallback): the single addressable
                // RGB LED on `led_gpio`. Wire order is a software r/g swap in the
                // task (`led::set_rg_swap`), so embassy's color order stays `Rgb`.
                let Pio {
                    mut common, sm0, ..
                } = Pio::new(p.PIO0, Irqs);
                let program = PioWs2812Program::new(&mut common);
                macro_rules! ws2812_pin {
                    ($pin:expr) => {
                        PioWs2812::with_color_order(
                            &mut common,
                            sm0,
                            p.DMA_CH0,
                            Irqs,
                            $pin,
                            &program,
                        )
                    };
                }
                let ws2812 = match led_gpio {
                    0 => ws2812_pin!(p.PIN_0),
                    1 => ws2812_pin!(p.PIN_1),
                    2 => ws2812_pin!(p.PIN_2),
                    3 => ws2812_pin!(p.PIN_3),
                    4 => ws2812_pin!(p.PIN_4),
                    5 => ws2812_pin!(p.PIN_5),
                    6 => ws2812_pin!(p.PIN_6),
                    7 => ws2812_pin!(p.PIN_7),
                    8 => ws2812_pin!(p.PIN_8),
                    9 => ws2812_pin!(p.PIN_9),
                    10 => ws2812_pin!(p.PIN_10),
                    11 => ws2812_pin!(p.PIN_11),
                    12 => ws2812_pin!(p.PIN_12),
                    13 => ws2812_pin!(p.PIN_13),
                    14 => ws2812_pin!(p.PIN_14),
                    15 => ws2812_pin!(p.PIN_15),
                    16 => ws2812_pin!(p.PIN_16),
                    17 => ws2812_pin!(p.PIN_17),
                    18 => ws2812_pin!(p.PIN_18),
                    19 => ws2812_pin!(p.PIN_19),
                    20 => ws2812_pin!(p.PIN_20),
                    21 => ws2812_pin!(p.PIN_21),
                    22 => ws2812_pin!(p.PIN_22),
                    23 => ws2812_pin!(p.PIN_23),
                    24 => ws2812_pin!(p.PIN_24),
                    25 => ws2812_pin!(p.PIN_25),
                    26 => ws2812_pin!(p.PIN_26),
                    27 => ws2812_pin!(p.PIN_27),
                    28 => ws2812_pin!(p.PIN_28),
                    _ => ws2812_pin!(p.PIN_29),
                };
                hp.spawn(led::ws2812_task(ws2812).unwrap());
            }
        }
    }

    // Trusted display (the `display` build — always `LED_KIND=none` per the guard
    // above, so the LED block compiled out and SPI1/I2C1/GPIO16 are free). Build the
    // panel + touch here, after the USB task is spawned, so its ~200 ms reset runs
    // while the interrupt executor enumerates — never delaying it. `status_task`
    // mirrors the device status; the `TouchPresence` backend (the `presence::Presence`
    // below) paints the confirm prompt. Both share the panel via the `UI` cell on the
    // thread executor.
    #[cfg(feature = "display")]
    let display_ui = {
        use embassy_rp::gpio::{Level, Output};
        use embassy_rp::i2c::{Config as I2cConfig, I2c};
        use embassy_rp::pwm::Pwm;
        use embassy_rp::spi::{Config as SpiConfig, Spi};

        let mut spi_cfg = SpiConfig::default();
        // The ST7789 tops out at 62.5 MHz; running there (vs the 40 MHz bringup value)
        // cuts a full-frame repaint ~35% for snappier screen transitions. If the panel's
        // flex cable ever shows tearing/garbling, drop back toward 40 MHz.
        spi_cfg.frequency = 62_500_000;
        let spi = Spi::new_blocking(p.SPI1, p.PIN_10, p.PIN_11, p.PIN_12, spi_cfg);

        let mut i2c_cfg = I2cConfig::default();
        i2c_cfg.frequency = 400_000;
        let i2c = I2c::new_blocking(p.I2C1, p.PIN_7, p.PIN_6, i2c_cfg);

        let cs = Output::new(p.PIN_13, Level::High);
        let dc = Output::new(p.PIN_14, Level::Low);
        let rst = Output::new(p.PIN_15, Level::High);
        // Display-sleep wake button (default the BAT_PWR / KEY_BAT button on GPIO25).
        // Active-low with an internal pull-up by default (`WAKE_ACTIVE_HIGH` flips it);
        // `WAKE_PIN=none` leaves it unwired so only a touch wakes. Stealing the pin is
        // sound: it is never handed to another driver, and a compile-time assert rejects
        // a `WAKE_PIN` in the LCD/touch range.
        let wake_btn = if BUILD_WAKE_ENABLED {
            use embassy_rp::gpio::{AnyPin, Input, Pull};
            let pull = if BUILD_WAKE_ACTIVE_HIGH {
                Pull::Down
            } else {
                Pull::Up
            };
            Some((
                Input::new(unsafe { AnyPin::steal(BUILD_WAKE_PIN) }, pull),
                BUILD_WAKE_ACTIVE_HIGH,
            ))
        } else {
            None
        };
        // Backlight on GPIO16 as PWM (slice 0, channel A) at zero duty — dark until
        // `Ui::build` raises it to full after the first render (no white flash).
        let bl = Pwm::new_output_a(p.PWM_SLICE0, p.PIN_16, display::backlight_cfg(0));
        let tp_rst = Output::new(p.PIN_17, Level::High);

        let buf = DISPLAY_BUF.init([0u8; DISPLAY_BUF_LEN]);
        let panel = display::PanelHw {
            spi,
            cs,
            dc,
            rst,
            bl,
            buf,
        };
        let touch = display::TouchHw { i2c, rst: tp_rst };
        let info = display::DeviceInfo {
            version: device_release,
            chipid: u64::from_le_bytes(serial_id),
        };
        // The device key material the read-only Passkeys tab needs to unbox the
        // resident-credential seed on demand (the same identity the worker's `Ctx`
        // carries). Copied — these are all `Copy`, so the worker below still gets them.
        let keys = display::DeviceKeys {
            serial_id,
            serial_hash,
            otp_mkek,
        };
        // Reborrow the `&'static mut` from the cell as a shared `&'static` so both
        // `status_task` and the `TouchPresence` backend can hold it (a shared
        // reference is `Copy`; the `RefCell` provides the interior mutability). The
        // panel also shares the worker's `fs_ref` to enumerate resident credentials.
        let ui: &'static RefCell<display::Ui> = UI.init(RefCell::new(display::Ui::build(
            panel, touch, info, fs_ref, keys, rng_ref, wake_btn,
        )));
        spawner.spawn(display::status_task(ui).unwrap());
        ui
    };
    core1::spawn(p.CORE1);

    // Standard key: BOOTSEL by default, or a dedicated `PRESENCE_PIN` GPIO button.
    // Display build: the touchscreen is the presence source (a `PRESENCE_PIN` is
    // rejected at compile time — see the `BUILD_PRESENCE_IS_GPIO` assert above).
    #[cfg(not(feature = "display"))]
    let presence_ref = {
        let presence = if BUILD_PRESENCE_IS_GPIO {
            ButtonPresence::new_gpio(BUILD_PRESENCE_PIN, BUILD_PRESENCE_ACTIVE_HIGH)
        } else {
            ButtonPresence::new_bootsel(p.BOOTSEL)
        };
        PRESENCE.init(RefCell::new(presence))
    };
    #[cfg(feature = "display")]
    let presence_ref = PRESENCE.init(RefCell::new(display::TouchPresence::new(display_ui)));
    let platform_ref = RESCUE_PLATFORM.init(RefCell::new(rescue_platform::RescuePlatform));
    let (kvm, kvc) = (kvmain_range(), kvcnt_range());
    let kv_total = (kvm.end - kvm.start) + (kvc.end - kvc.start);
    let worker = Worker::new(
        fs_ref,
        rng_ref,
        presence_ref,
        platform_ref,
        serial_id,
        serial_hash,
        otp_mkek,
        otp_devk,
        kv_total,
        openpgp_mfr,
    );
    spawner.spawn(worker_task(worker).unwrap());
}
