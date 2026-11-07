// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Present captured panel pixels and drive the board's physical inputs.

use super::chip::Chip;
use super::panel::{HEIGHT, WIDTH};
use embedded_graphics::{
    Pixel,
    draw_target::DrawTarget,
    geometry::{Point, Size},
    pixelcolor::Rgb565,
};
use embedded_graphics_simulator::sdl2::{Keycode, MouseButton};
use embedded_graphics_simulator::{
    OutputSettingsBuilder, SimulatorDisplay, SimulatorEvent, Window,
};
use std::time::{Duration, Instant};

pub struct View {
    window: Window,
    pixels: SimulatorDisplay<Rgb565>,
    refreshed: Instant,
    held: bool,
}

impl View {
    pub fn new() -> Self {
        let settings = OutputSettingsBuilder::new().scale(2).build();
        Self {
            window: Window::new("RS-Key", &settings),
            pixels: SimulatorDisplay::new(Size::new(WIDTH as u32, HEIGHT as u32)),
            refreshed: Instant::now() - Duration::from_secs(1),
            held: false,
        }
    }

    pub fn pump(&mut self, chip: &mut Chip) -> bool {
        if self.refreshed.elapsed() < Duration::from_millis(16) {
            return true;
        }
        let duty = chip.backlight();
        if let Some(panel) = &chip.panel {
            let lit = panel.enabled && !panel.sleeping;
            self.pixels
                .draw_iter(panel.pixels.iter().enumerate().map(|(i, color)| {
                    let scale = |value: u16| {
                        if lit {
                            (u32::from(value) * duty.0 / duty.1.max(1)) as u8
                        } else {
                            0
                        }
                    };
                    Pixel(
                        Point::new((i % WIDTH) as i32, (i / WIDTH) as i32),
                        Rgb565::new(
                            scale(color >> 11),
                            scale((color >> 5) & 63),
                            scale(color & 31),
                        ),
                    )
                }))
                .unwrap();
        }
        self.window.update(&self.pixels);
        for event in self.window.events() {
            match event {
                SimulatorEvent::Quit => return false,
                SimulatorEvent::MouseButtonDown {
                    mouse_btn: MouseButton::Left,
                    point,
                } => {
                    self.held = true;
                    Self::contact(chip, Some(point));
                }
                SimulatorEvent::MouseMove { point } if self.held => {
                    Self::contact(chip, Some(point))
                }
                SimulatorEvent::MouseButtonUp {
                    mouse_btn: MouseButton::Left,
                    ..
                } => {
                    self.held = false;
                    Self::contact(chip, None);
                }
                SimulatorEvent::KeyDown {
                    keycode: Keycode::Space,
                    ..
                } => chip.press_wake(true),
                SimulatorEvent::KeyUp {
                    keycode: Keycode::Space,
                    ..
                } => chip.press_wake(false),
                _ => {}
            }
        }
        self.refreshed = Instant::now();
        true
    }

    fn contact(chip: &mut Chip, point: Option<Point>) {
        if let Some(touch) = &chip.touch {
            let mut touch = touch.lock().unwrap();
            if touch.pad.is_some() {
                return;
            }
            touch.point = point.and_then(|p| {
                let x = u16::try_from(p.x).ok()?;
                let y = u16::try_from(p.y).ok()?;
                (usize::from(x) < WIDTH && usize::from(y) < HEIGHT).then_some((x, y))
            });
            touch.until_ns = u64::MAX;
        }
    }
}
