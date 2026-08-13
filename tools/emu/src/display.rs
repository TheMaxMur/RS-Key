// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The trusted display, in a window.
//!
//! [`rsk_display`] holds the flow — which screen is shown when, and what a tap on
//! it does — generic over the panel and the touch controller. The firmware fills
//! those in with an ST7789 and a CST328; here they are an SDL2 window and a mouse.
//! Nothing in between is re-implemented: the pixels come from the same
//! `rsk_ui::render` the board runs, and a click enters the flow through the same
//! `TouchPad::read` a finger does.
//!
//! Level, not edges. A real panel reports contact *continuously* while touched,
//! which is what the flow's debounce and its 800 ms hold-to-approve are built on,
//! so `Touch::read` reports the mouse button as held rather than as a click
//! event — press, hold, release maps onto press, hold, lift.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;

use crate::device::{PanelLinks, Queued};
use crate::signals::Signals;
use crate::taps::TapPad;

use embedded_graphics::geometry::{Dimensions, Point as EgPoint, Size};
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::Rectangle;
use embedded_graphics_simulator::sdl2::{Keycode, MouseButton};
use embedded_graphics_simulator::{
    OutputSettingsBuilder, SimulatorDisplay, SimulatorEvent, Window,
};

/// How much bigger than the panel the window is drawn. 240×320 is postage-stamp
/// sized on a modern display, and the point of this window is that a person can
/// read the relying party on it.
const SCALE: u32 = 2;

/// The panel, shared between the flow (which draws into it) and the window (which
/// shows it). `Ui` takes its panel by value, so the two ends share one buffer
/// through this handle rather than one of them owning it.
#[derive(Clone)]
pub struct Panel(Rc<RefCell<SimulatorDisplay<Rgb565>>>);

impl Panel {
    fn new() -> Self {
        Self(Rc::new(RefCell::new(SimulatorDisplay::new(Size::new(
            rsk_ui::PANEL_W as u32,
            rsk_ui::PANEL_H as u32,
        )))))
    }
}

impl Dimensions for Panel {
    fn bounding_box(&self) -> Rectangle {
        self.0.borrow().bounding_box()
    }
}

impl DrawTarget for Panel {
    type Color = Rgb565;
    type Error = core::convert::Infallible;

    fn draw_iter<I: IntoIterator<Item = Pixel<Rgb565>>>(
        &mut self,
        pixels: I,
    ) -> Result<(), Self::Error> {
        self.0.borrow_mut().draw_iter(pixels)
    }

    fn fill_contiguous<I: IntoIterator<Item = Rgb565>>(
        &mut self,
        area: &Rectangle,
        colors: I,
    ) -> Result<(), Self::Error> {
        self.0.borrow_mut().fill_contiguous(area, colors)
    }

    fn fill_solid(&mut self, area: &Rectangle, color: Rgb565) -> Result<(), Self::Error> {
        self.0.borrow_mut().fill_solid(area, color)
    }

    fn clear(&mut self, color: Rgb565) -> Result<(), Self::Error> {
        self.0.borrow_mut().clear(color)
    }
}

/// The mouse, presented as the panel's touch controller — and the window's pump.
///
/// Every wait in the flow polls `read()` on a ~16 ms cadence, so this is the one
/// place guaranteed to be reached often enough to both repaint the window and
/// drain SDL's event queue. Doing it here rather than on a timer is what keeps the
/// emulator single-threaded, exactly like the firmware's thread executor.
pub struct Touch {
    win: Window,
    panel: Panel,
    /// Where the button is currently held, or `None` when lifted.
    held: Option<EgPoint>,
    /// The window's close button was used; the caller ends the process.
    quit: Rc<Cell<bool>>,
    /// The backlight the flow has asked for. There is no lamp to dim, so the
    /// pixels are scaled by it on the way to the window instead — otherwise the
    /// brightness setting is a number that changes nothing you can see, and
    /// display sleep looks identical to a black screen.
    duty: Rc<Cell<u16>>,
    /// The wake button, held. A board has a real one (BAT_PWR); here it is the
    /// space bar, so the "power button sleeps from any screen" behaviour is
    /// reachable at all.
    wake: Rc<Cell<bool>>,
    /// `--taps`: a scripted finger *instead of* the mouse, so a flow behind the
    /// keypad can be driven without a person. The window still repaints and still
    /// takes its quit and wake keys, so the script is watchable.
    taps: Option<TapPad>,
}

impl Touch {
    fn new(
        panel: Panel,
        quit: Rc<Cell<bool>>,
        duty: Rc<Cell<u16>>,
        wake: Rc<Cell<bool>>,
        taps: Option<TapPad>,
    ) -> Self {
        let out = OutputSettingsBuilder::new().scale(SCALE).build();
        Self {
            win: Window::new("RS-Key", &out),
            panel,
            held: None,
            quit,
            duty,
            wake,
            taps,
        }
    }

    /// Push the panel to the window, scaled by the backlight.
    fn present(&mut self) {
        let duty = self.duty.get();
        if duty >= rsk_display::BL_TOP {
            self.win.update(&self.panel.0.borrow());
            return;
        }
        let src = self.panel.0.borrow();
        let mut dim: SimulatorDisplay<Rgb565> =
            SimulatorDisplay::new(Size::new(rsk_ui::PANEL_W as u32, rsk_ui::PANEL_H as u32));
        let scale = |v: u8, bits: u8| -> u8 {
            let max = (1u32 << bits) - 1;
            ((v as u32 * duty as u32) / rsk_display::BL_TOP as u32).min(max) as u8
        };
        for y in 0..rsk_ui::PANEL_H as i32 {
            for x in 0..rsk_ui::PANEL_W as i32 {
                let p = EgPoint::new(x, y);
                let c = src.get_pixel(p);
                let d = Rgb565::new(scale(c.r(), 5), scale(c.g(), 6), scale(c.b(), 5));
                let _ = dim.draw_iter([Pixel(p, d)]);
            }
        }
        drop(src);
        self.win.update(&dim);
    }
}

impl rsk_display::TouchPad for Touch {
    fn read(&mut self) -> Option<rsk_ui::Point> {
        self.present();
        for ev in self.win.events() {
            match ev {
                SimulatorEvent::MouseButtonDown {
                    mouse_btn: MouseButton::Left,
                    point,
                } => self.held = Some(point),
                // Track the drag: the flow's hold-to-approve keeps checking that
                // the contact is still inside the button, so a slip off it must
                // read as a slip, not as a finger that never moved.
                SimulatorEvent::MouseMove { point } if self.held.is_some() => {
                    self.held = Some(point)
                }
                SimulatorEvent::MouseButtonUp {
                    mouse_btn: MouseButton::Left,
                    ..
                } => self.held = None,
                SimulatorEvent::KeyDown {
                    keycode: Keycode::Space,
                    ..
                } => self.wake.set(true),
                SimulatorEvent::KeyUp {
                    keycode: Keycode::Space,
                    ..
                } => self.wake.set(false),
                SimulatorEvent::Quit => self.quit.set(true),
                _ => {}
            }
        }
        if let Some(taps) = &mut self.taps {
            return taps.read();
        }
        self.held.map(|p| rsk_ui::Point {
            x: p.x as u16,
            y: p.y as u16,
        })
    }
}

/// Every [`rsk_display::Hooks`] method this build leaves at the trait's default,
/// and why that is the right answer here rather than an oversight.
///
/// The trait's defaults are exact no-ops, so a method nobody implements diverges
/// from `firmware/src/display.rs` in silence — which is what E150–E153 each were.
/// `every_display_hook_is_accounted_for` refuses a hook in neither column; it is
/// this list's only reader, so the list is gated to a test build.
#[cfg(test)]
const DEFAULTED_HOOKS: &[(&str, &str)] = &[(
    "secure_boot_enabled",
    "read from OTP; there are no fuses here, and `false` is what a device without \
     secure boot reports",
)];

/// The board verbs, for a board that is a window.
///
/// Most are honest no-ops: there is no backlight to dim, no wake button, no OTP
/// to read a secure-boot bit out of. The ones that are not — the LED status a
/// ceremony borrows, the presence flags it shares with the transport — are real
/// state here, because the flow reads back what it writes.
pub struct EmuDisplayHooks {
    /// Shared with [`Touch`], which is what actually applies it.
    duty: Rc<Cell<u16>>,
    wake: Rc<Cell<bool>>,
    led: Cell<u8>,
    timeout_ms: Cell<u32>,
    reboot: Cell<bool>,
    /// The local-PIN event and the attach clock, both shared with the worker half
    /// — a board reaches the same two through `crate::handler` and
    /// `crate::usb_attach`.
    links: PanelLinks,
    /// Host requests the device thread has not picked up. A modal holds the single
    /// executor, so this is the only way the flow can learn one is waiting.
    queued: Queued,
    /// The presence flags the ceremonies share with the transports — the same
    /// object `hid.rs`'s keepalive reads and its `CTAPHID_CANCEL` writes. A board
    /// routes the three hooks below into `presence::ARBITER` for the same reason:
    /// a panel that keeps them to itself is a second copy nobody can see.
    signals: Arc<Signals>,
}

impl EmuDisplayHooks {
    pub fn new(
        duty: Rc<Cell<u16>>,
        wake: Rc<Cell<bool>>,
        queued: Queued,
        signals: Arc<Signals>,
    ) -> Self {
        Self {
            duty,
            wake,
            led: Cell::default(),
            timeout_ms: Cell::new(30_000),
            reboot: Cell::new(false),
            links: PanelLinks::default(),
            queued,
            signals,
        }
    }

    /// The two cells the worker half shares with the panel. Read from here rather
    /// than passed in beside the panel, so the two ends cannot be handed different
    /// ones — a pair that does not match is the defect this seam exists to prevent,
    /// and it fails nothing.
    pub fn links(&self) -> PanelLinks {
        self.links.clone()
    }
}

impl rsk_display::Hooks for EmuDisplayHooks {
    fn set_backlight(&mut self, duty: u16) {
        self.duty.set(duty);
    }
    fn wake_pressed(&self) -> bool {
        self.wake.get()
    }
    fn led_status(&self) -> u8 {
        self.led.get()
    }
    fn set_led_status(&mut self, status: u8) {
        self.led.set(status);
    }
    /// The worker's clock, not one of the panel's own: `Job::Replug` restarts it,
    /// and an audit entry stamped here has to sort against a host-stamped one.
    fn attach_elapsed_ms(&self) -> u64 {
        self.links.attach.get().elapsed().as_millis() as u64
    }
    fn host_request_pending(&self) -> bool {
        self.queued.any()
    }
    /// The floor is the whole point and every modal exit poll uses this form: a
    /// bare [`rsk_display::Hooks::host_request_pending`] lets a host close a screen on
    /// its first poll, so a loop of any ungated command denies the on-device
    /// browse layer entirely (audit run-35).
    fn host_request_pending_after(&self, since: embassy_time::Instant) -> bool {
        self.queued.any()
            && since.elapsed()
                >= embassy_time::Duration::from_millis(rsk_display::UI_YIELD_FLOOR_MS)
    }
    fn request_reboot(&mut self, _bootsel: bool) {
        self.reboot.set(true);
    }
    fn reboot_pending(&self) -> bool {
        self.reboot.get()
    }
    fn note_local_pin_changed(&mut self) {
        self.links.local_pin.set(true);
    }
    /// Both events mean the same thing to the worker — end the RAM
    /// `pinUvAuthToken` before the next CBOR command — so they share one flag, as
    /// `firmware/src/display.rs` maps them to one signal.
    fn note_local_pin_failed(&mut self) {
        self.links.local_pin.set(true);
    }
    fn set_up_pending(&mut self, pending: bool) {
        self.signals.set_up_pending(pending);
    }
    /// `rsk_display` only ever clears it; `true` is the transport's own verb, and
    /// [`Signals::cancel_active`] is the scoping `hid.rs` already applies to a
    /// `CTAPHID_CANCEL` — cancel what is in flight, and nothing when nothing is.
    fn set_cancel_requested(&mut self, requested: bool) {
        if requested {
            self.signals.cancel_active();
        } else {
            self.signals.clear_cancel();
        }
    }
    fn cancel_requested(&self) -> bool {
        self.signals.cancelled()
    }
    fn presence_timeout_ms(&self) -> u32 {
        self.timeout_ms.get()
    }
    fn set_presence_timeout_ms(&mut self, ms: u32) {
        self.timeout_ms.set(ms);
    }
    /// There is no accelerator here, but this trait's `None` means "no accelerator
    /// **and** no key" — where `rsk_device::Hooks::rsa_search`'s `None` means "fall
    /// through to the applet's own single-core path", which is why a generate over
    /// the wire works on this build. Run that same path, one candidate per tick.
    ///
    /// The spinner those ticks paint does NOT reach the window: `Touch::present` is
    /// only called from `TouchPad::read`, and this span never reads. A board writes
    /// the panel directly, so there the arc really turns.
    fn rsa_search_progress(
        &mut self,
        nbits: usize,
        rng: &mut dyn rsk_openpgp::Rng,
        on_tick: &mut dyn FnMut(),
    ) -> Option<Box<rsk_openpgp::keys::RsaPrivateKey>> {
        let mut keygen = rsk_openpgp::keys::RsaKeygen::new(nbits);
        let mut sieve = rsk_rsa_asm::IncrementalSieve::new();
        let found = loop {
            on_tick();
            match keygen.step(&mut sieve, rng) {
                rsk_openpgp::keys::RsaStep::Done(key) => break Some(key),
                rsk_openpgp::keys::RsaStep::Failed => break None,
                rsk_openpgp::keys::RsaStep::More => {}
            }
        };
        // The window still holds the last accepted candidate — a prime of the key
        // just minted. `firmware/src/core1.rs` scrubs its own for the same reason.
        sieve.scrub();
        found
    }
}

/// The three pieces `rsk_display::Ui::new` takes from a board, as one handle: a
/// panel to draw on, a pad to read, and the verbs neither of them covers. Kept
/// together because they are substituted together — a window and a mouse here, a
/// sink and a script under test.
pub struct PanelParts<P, T> {
    pub panel: P,
    pub touch: T,
    pub hooks: EmuDisplayHooks,
}

/// Open the window and hand back those pieces, plus the quit flag the caller
/// polls. `taps` replaces the mouse when a script was given.
pub fn open(
    taps: Option<TapPad>,
    queued: Queued,
    signals: Arc<Signals>,
) -> (PanelParts<Panel, Touch>, Rc<Cell<bool>>) {
    let panel = Panel::new();
    let quit = Rc::new(Cell::new(false));
    let duty = Rc::new(Cell::new(rsk_display::BL_TOP));
    let wake = Rc::new(Cell::new(false));
    let touch = Touch::new(
        panel.clone(),
        quit.clone(),
        duty.clone(),
        wake.clone(),
        taps,
    );
    (
        PanelParts {
            panel,
            touch,
            hooks: EmuDisplayHooks::new(duty, wake, queued, signals),
        },
        quit,
    )
}

#[cfg(test)]
#[path = "display_tests.rs"]
mod tests;
