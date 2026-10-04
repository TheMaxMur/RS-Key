// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use embedded_graphics::{
    Pixel,
    geometry::{OriginDimensions, Size},
};

struct Panel {
    pixels: std::vec::Vec<Rgb565>,
    fail: bool,
}

impl Panel {
    fn new() -> Self {
        Self {
            pixels: std::vec![theme::BG; usize::from(crate::PANEL_W) * usize::from(crate::PANEL_H)],
            fail: false,
        }
    }
    fn at(&self, x: u16, y: u16) -> Rgb565 {
        self.pixels[usize::from(y) * usize::from(crate::PANEL_W) + usize::from(x)]
    }
}

impl OriginDimensions for Panel {
    fn size(&self) -> Size {
        Size::new(u32::from(crate::PANEL_W), u32::from(crate::PANEL_H))
    }
}

impl DrawTarget for Panel {
    type Color = Rgb565;
    type Error = &'static str;
    fn draw_iter<I: IntoIterator<Item = Pixel<Rgb565>>>(
        &mut self,
        pixels: I,
    ) -> Result<(), Self::Error> {
        if self.fail {
            return Err("panel refused");
        }
        for Pixel(at, color) in pixels {
            assert!((0..i32::from(crate::PANEL_W)).contains(&at.x));
            assert!((0..i32::from(crate::PANEL_H)).contains(&at.y));
            self.pixels[at.y as usize * usize::from(crate::PANEL_W) + at.x as usize] = color;
        }
        Ok(())
    }
}

#[test]
fn cards_keep_their_padding_and_render_title_rows_values_and_chevrons() {
    let mut panel = Panel::new();
    let height = card_h(true, 2);
    assert_eq!(height, 2 * PAD + 3 * ROW_H + ROW_GAP);
    assert_eq!(card_h(false, 0), 2 * PAD);
    card(&mut panel, 40, height).unwrap();
    assert_eq!(
        panel.at(crate::PANEL_W / 2, 40 + height / 2),
        theme::SURFACE
    );
    card_title(&mut panel, 40, Glyph::Key, "Passkeys").unwrap();
    card_row(&mut panel, 40, 0, Glyph::Globe, "Service", None).unwrap();
    card_row_chevron(
        &mut panel,
        40,
        1,
        Glyph::Lock,
        "PIN",
        Some(("Set", theme::ACCENT)),
    )
    .unwrap();
    assert!(panel.pixels.contains(&theme::ACCENT));
    assert!(panel.pixels.contains(&theme::TEXT));
    assert_eq!(panel.at(0, 100), theme::BG);
}

#[test]
fn arbitrary_rows_clip_long_labels_and_preserve_the_trailing_value() {
    for trailing in [None, Some(("Ready", theme::ACCENT))] {
        for chevron in [false, true] {
            let mut panel = Panel::new();
            let rect = Rect::new(6, 40, 228, 44);
            rect_card(&mut panel, rect).unwrap();
            rect_row(
                &mut panel,
                rect,
                Glyph::Key,
                "An unusually long display label that must be clipped",
                trailing,
                chevron,
            )
            .unwrap();
            assert_eq!(panel.at(0, 60), theme::BG);
            assert_eq!(panel.at(100, 100), theme::BG);
            assert!(panel.pixels.contains(&theme::TEXT));
            if trailing.is_some() {
                assert!(panel.pixels.contains(&theme::ACCENT));
            }
        }
    }
}

#[test]
fn an_empty_state_centers_its_icon_and_text_inside_the_card() {
    let mut panel = Panel::new();
    empty_state(&mut panel, 40, 150, Glyph::Key, "No passkeys").unwrap();
    assert!(panel.pixels.iter().any(|&color| color != theme::BG));
    assert_eq!(panel.at(0, 100), theme::BG);
    assert_eq!(panel.at(120, 220), theme::BG);
}

#[test]
fn every_component_propagates_a_panel_error() {
    let mut panel = Panel::new();
    panel.fail = true;
    let err = Err("panel refused");
    assert_eq!(card(&mut panel, 40, 100), err);
    assert_eq!(card_title(&mut panel, 40, Glyph::Key, "Keys"), err);
    assert_eq!(card_row(&mut panel, 40, 0, Glyph::Key, "Keys", None), err);
    assert_eq!(
        card_row_chevron(&mut panel, 40, 0, Glyph::Key, "Keys", None),
        err
    );
    assert_eq!(rect_card(&mut panel, Rect::new(6, 40, 228, 44)), err);
    assert_eq!(
        rect_row(
            &mut panel,
            Rect::new(6, 40, 228, 44),
            Glyph::Key,
            "Keys",
            None,
            false
        ),
        err
    );
    assert_eq!(empty_state(&mut panel, 40, 150, Glyph::Key, "Empty"), err);
}
