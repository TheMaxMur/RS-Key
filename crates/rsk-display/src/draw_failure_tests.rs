// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use core::cell::Cell;
use rsk_ui::scene::{DamageKey, FrameTarget, Scene};

pub(crate) struct FaultPanel {
    inner: Panel,
    pub remaining: Rc<Cell<usize>>,
    pub calls: Rc<Cell<usize>>,
}

impl FaultPanel {
    pub fn new() -> Self {
        Self {
            inner: Panel::new(),
            remaining: Rc::new(Cell::new(usize::MAX)),
            calls: Rc::new(Cell::new(0)),
        }
    }
}
impl OriginDimensions for FaultPanel {
    fn size(&self) -> Size {
        self.inner.size()
    }
}
impl DrawTarget for FaultPanel {
    type Color = Rgb565;
    type Error = ();
    fn draw_iter<I: IntoIterator<Item = Pixel<Rgb565>>>(
        &mut self,
        pixels: I,
    ) -> Result<(), Self::Error> {
        self.calls.set(self.calls.get() + 1);
        let remaining = self.remaining.get();
        if remaining == 0 {
            return Err(());
        }
        self.remaining.set(remaining - 1);
        self.inner.draw_iter(pixels).map_err(|_| ())
    }
}
impl FrameTarget for FaultPanel {
    fn damage_key(&self) -> DamageKey {
        self.inner.damage_key()
    }
    fn present_scene(&mut self, scene: &Scene) -> bool {
        self.inner.present_scene(scene)
    }
    fn present_damage(&mut self, scene: &Scene, rects: &[rsk_ui::Rect]) -> bool {
        self.inner.present_damage(scene, rects)
    }
}

pub(crate) fn fault_ui<'a, T: TouchPad>(env: &'a Env, pad: T) -> Ui<'a, FaultPanel, T, Board> {
    Ui::new(
        FaultPanel::new(),
        pad,
        Board::new(),
        DeviceInfo {
            version: 0x0875,
            chipid: 1,
        },
        env.cells(),
    )
}

#[test]
#[should_panic(expected = "direct display presentation failed")]
fn a_failed_marquee_blit_is_reported() {
    let env = Env::new();
    let mut ui = fault_ui(&env, Pad::idle());
    ui.panel.remaining.set(0);
    ui.render_marquee_frame("A title wider than the panel title band", 1);
}
