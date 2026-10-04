// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use core::convert::Infallible;
use embedded_graphics::{
    Pixel,
    draw_target::DrawTarget,
    geometry::{OriginDimensions, Size},
    pixelcolor::{IntoStorage, Rgb565, RgbColor},
};
use rsk_ui::*;

pub(super) fn render<D: DrawTarget<Color = Rgb565>>(
    sink: &mut D,
    route: u8,
    data: &[u8],
    name: Label,
    domain: Label,
) -> Result<(), D::Error> {
    let byte = |at| data.get(at).copied().unwrap_or(0);
    let flags = byte(1);
    let enabled = flags & 1 != 0;
    let page = u16::from(byte(2));
    match route {
        8 => render::render(sink, &Screen::Splash),
        9 => render::render(sink, &Screen::Onboard),
        10 => render::render(sink, &Screen::Locked),
        11 => render::render(
            sink,
            &Screen::Home(HomeView {
                status: [
                    StatusKind::Boot,
                    StatusKind::Idle,
                    StatusKind::Processing,
                    StatusKind::Touch,
                ][usize::from(flags % 4)],
                pin_set: enabled,
                passkeys: u16::from(byte(2)),
            }),
        ),
        12 => {
            let mut pad = PinPad::with_title(usize::from(byte(2)), "Device PIN");
            pad.expected = flags % 9;
            pad.caption = if enabled {
                Some(PinCaption::WrongPin {
                    retries_left: flags % 9,
                })
            } else {
                None
            };
            render::render(sink, &Screen::Pin(pad))
        }
        13 => render::render(
            sink,
            &Screen::Settings(SettingsView {
                page: [
                    SettingsPage::Root,
                    SettingsPage::Display,
                    SettingsPage::Security,
                    SettingsPage::Brightness,
                    SettingsPage::Timeout,
                    SettingsPage::Sleep,
                ][usize::from(flags % 6)],
                brightness: byte(2) % BRIGHTNESS_LEVELS + 1,
                timeout_secs: TIMEOUT_CHOICES[usize::from(byte(4)) % TIMEOUT_CHOICES.len()],
                sleep_secs: SLEEP_CHOICES[usize::from(byte(5)) % SLEEP_CHOICES.len()],
                version: u16::from(byte(6)),
                chipid: u64::from(byte(7)),
                device_pin_set: enabled,
                fido_pin_set: flags & 2 != 0,
                backup_sealed: flags & 4 != 0,
                scramble_pin: flags & 8 != 0,
            }),
        ),
        14 => render_rename(
            sink,
            name.as_str(),
            if enabled {
                Some(b'a' + byte(4) % 26)
            } else {
                None
            },
            Some(usize::from(byte(5) % 10)),
        ),
        15 => render_add_passkey(sink, &domain, &name),
        16 => render_confirm_delete(sink, &domain, &name),
        17 => render_confirm_factory_reset(sink),
        18 => render_success(
            sink,
            [
                SuccessKind::Approved,
                SuccessKind::Deleted,
                SuccessKind::Wiped,
                SuccessKind::Generated,
            ][usize::from(flags % 4)],
            enabled,
        ),
        19 => render_pin_blocked(sink),
        20 => render::render_erasing(sink),
        21 => render::render_wipe_failed(sink),
        22 => render_backup(
            sink,
            &BackupView {
                sealed: flags & 1 != 0,
                has_seed: flags & 2 != 0,
                exportable: flags & 4 != 0,
                can_reveal: flags & 8 != 0,
            },
        ),
        23 => render::render_backup_format(sink),
        24 => {
            let total = SHARE_MIN + flags % (SHARE_MAX - SHARE_MIN + 1);
            let threshold = SHARE_MIN + byte(2) % (total - SHARE_MIN + 1);
            render_share_picker(sink, threshold, total)
        }
        25 => render_reveal_warning(
            sink,
            if enabled {
                RevealKind::Phrase
            } else {
                RevealKind::Shares
            },
        ),
        26 => render_seal_confirm(sink),
        27 => render_seed_phrase(sink, &["abandon"; 24], page % 2, 2),
        28 => render_slip39_share(sink, &["academic"; 33], page / 3 % 5, 5, page % 15, 15),
        29 => render::render_firmware(sink, u16::from(byte(2)), u64::from(byte(4)), enabled),
        30 => render::render_piv_keygen_pick(sink, 0x82 + flags % 20),
        _ => {
            let rows = [AuditRow {
                kind: [AuditKind::Login, AuditKind::Register, AuditKind::Boot]
                    [usize::from(flags % 3)],
                secs_ago: if enabled {
                    Some(u32::from(byte(4)) * 86400)
                } else {
                    None
                },
            }; PK_ROWS_MAX];
            let total = u16::from(byte(2));
            let page = page % page_count(total).max(1);
            let count =
                usize::from(total.saturating_sub(page * PK_ROWS_MAX as u16)).min(PK_ROWS_MAX);
            render_audit_log(sink, &rows[..count], page, total, enabled)
        }
    }
}

struct Canvas(Vec<Rgb565>);

impl Canvas {
    fn new() -> Self {
        Self(vec![
            Rgb565::BLACK;
            usize::from(PANEL_W) * usize::from(PANEL_H)
        ])
    }
}

impl OriginDimensions for Canvas {
    fn size(&self) -> Size {
        Size::new(u32::from(PANEL_W), u32::from(PANEL_H))
    }
}

impl DrawTarget for Canvas {
    type Color = Rgb565;
    type Error = Infallible;

    fn draw_iter<I: IntoIterator<Item = Pixel<Rgb565>>>(
        &mut self,
        pixels: I,
    ) -> Result<(), Infallible> {
        for Pixel(point, color) in pixels {
            assert!((0..i32::from(PANEL_W)).contains(&point.x));
            assert!((0..i32::from(PANEL_H)).contains(&point.y));
            self.0[point.y as usize * usize::from(PANEL_W) + point.x as usize] = color;
        }
        Ok(())
    }
}

pub(super) fn assert_retained(data: &[u8], name: Label, domain: Label) {
    let mut direct = Canvas::new();
    super::render_public_view(&mut direct, data, name, domain).unwrap();
    let mut scene = scene::Scene::default();
    super::render_public_view(&mut scene, data, name, domain).unwrap();
    let key = [u64::from(data.get(4).copied().unwrap_or(0)), 0x52534b];
    scene.finalize(key).unwrap();
    let mut retained = Canvas::new();
    scene.replay(&mut retained).unwrap();
    assert_eq!(
        direct.0, retained.0,
        "retained scene differs from direct drawing"
    );

    let y = u16::from(data.get(5).copied().unwrap_or(0));
    let mut band = [0; scene::BAND_BYTES];
    scene.raster_band(Rect::new(0, y, PANEL_W, 1), y, 1, &mut band);
    for (x, bytes) in band[..usize::from(PANEL_W) * 2].chunks_exact(2).enumerate() {
        assert_eq!(
            u16::from_be_bytes([bytes[0], bytes[1]]),
            direct.0[usize::from(y) * usize::from(PANEL_W) + x].into_storage()
        );
    }
}
