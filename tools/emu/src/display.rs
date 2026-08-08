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
//! so [`Touch::read`] reports the mouse button as held rather than as a click
//! event — press, hold, release maps onto press, hold, lift.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use embedded_graphics::geometry::{Dimensions, Point as EgPoint, Size};
use embedded_graphics::pixelcolor::Rgb565;
use embedded_graphics::prelude::*;
use embedded_graphics::primitives::Rectangle;
use embedded_graphics_simulator::sdl2::MouseButton;
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
}

impl Touch {
    fn new(panel: Panel, quit: Rc<Cell<bool>>) -> Self {
        let out = OutputSettingsBuilder::new().scale(SCALE).build();
        Self {
            win: Window::new("RS-Key", &out),
            panel,
            held: None,
            quit,
        }
    }
}

impl rsk_display::TouchPad for Touch {
    fn read(&mut self) -> Option<rsk_ui::Point> {
        self.win.update(&self.panel.0.borrow());
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
                SimulatorEvent::Quit => self.quit.set(true),
                _ => {}
            }
        }
        self.held.map(|p| rsk_ui::Point {
            x: p.x as u16,
            y: p.y as u16,
        })
    }
}

/// The board verbs, for a board that is a window.
///
/// Most are honest no-ops: there is no backlight to dim, no wake button, no OTP
/// to read a secure-boot bit out of. The ones that are not — the LED status a
/// ceremony borrows, the presence flags it shares with the transport — are real
/// state here, because the flow reads back what it writes.
#[derive(Default)]
pub struct EmuDisplayHooks {
    led: Cell<u8>,
    up_pending: Cell<bool>,
    cancel: Cell<bool>,
    timeout_ms: Cell<u32>,
    reboot: Cell<bool>,
    pin_changed: Cell<bool>,
    started: Option<std::time::Instant>,
}

impl EmuDisplayHooks {
    fn new() -> Self {
        Self {
            timeout_ms: Cell::new(30_000),
            started: Some(std::time::Instant::now()),
            ..Default::default()
        }
    }
}

impl rsk_display::Hooks for EmuDisplayHooks {
    fn led_status(&self) -> u8 {
        self.led.get()
    }
    fn set_led_status(&mut self, status: u8) {
        self.led.set(status);
    }
    fn attach_elapsed_ms(&self) -> u64 {
        self.started
            .map(|s| s.elapsed().as_millis() as u64)
            .unwrap_or(0)
    }
    fn request_reboot(&mut self, _bootsel: bool) {
        self.reboot.set(true);
    }
    fn reboot_pending(&self) -> bool {
        self.reboot.get()
    }
    fn note_local_pin_changed(&mut self) {
        self.pin_changed.set(true);
    }
    fn set_up_pending(&mut self, pending: bool) {
        self.up_pending.set(pending);
    }
    fn set_cancel_requested(&mut self, requested: bool) {
        self.cancel.set(requested);
    }
    fn cancel_requested(&self) -> bool {
        self.cancel.get()
    }
    fn presence_timeout_ms(&self) -> u32 {
        self.timeout_ms.get()
    }
    fn set_presence_timeout_ms(&mut self, ms: u32) {
        self.timeout_ms.set(ms);
    }
}

/// Open the window and hand back the three pieces `rsk_display::Ui::new` wants,
/// plus the quit flag the caller polls.
pub fn open() -> (Panel, Touch, EmuDisplayHooks, Rc<Cell<bool>>) {
    let panel = Panel::new();
    let quit = Rc::new(Cell::new(false));
    let touch = Touch::new(panel.clone(), quit.clone());
    (panel, touch, EmuDisplayHooks::new(), quit)
}
