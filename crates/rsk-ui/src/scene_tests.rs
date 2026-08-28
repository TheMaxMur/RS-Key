// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use core::convert::Infallible;
use core::sync::atomic::{AtomicUsize, Ordering};
use embedded_graphics::{geometry::OriginDimensions, pixelcolor::RgbColor};

const DAMAGE_KEY: DamageKey = [0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210];

struct Canvas {
    pixels: std::vec::Vec<Rgb565>,
}

impl Canvas {
    fn new() -> Self {
        Self::filled(Rgb565::BLACK)
    }

    fn filled(color: Rgb565) -> Self {
        Self {
            pixels: std::vec![color; PANEL_W as usize * PANEL_H as usize],
        }
    }

    fn pixel(&self, x: u16, y: u16) -> Rgb565 {
        self.pixels[usize::from(y) * PANEL_W as usize + usize::from(x)]
    }
}

impl OriginDimensions for Canvas {
    fn size(&self) -> Size {
        Size::new(PANEL_W.into(), PANEL_H.into())
    }
}

impl DrawTarget for Canvas {
    type Color = Rgb565;
    type Error = Infallible;

    fn draw_iter<I: IntoIterator<Item = Pixel<Rgb565>>>(
        &mut self,
        pixels: I,
    ) -> Result<(), Self::Error> {
        for Pixel(point, color) in pixels {
            if point.x >= 0
                && point.y >= 0
                && point.x < i32::from(PANEL_W)
                && point.y < i32::from(PANEL_H)
            {
                self.pixels[point.y as usize * PANEL_W as usize + point.x as usize] = color;
            }
        }
        Ok(())
    }
}

struct DamageSink {
    canvas: Canvas,
    rects: std::vec::Vec<Rect>,
    presentations: usize,
    succeed: bool,
}

impl DamageSink {
    fn filled(color: Rgb565) -> Self {
        Self {
            canvas: Canvas::filled(color),
            rects: std::vec::Vec::new(),
            presentations: 0,
            succeed: true,
        }
    }
}

impl OriginDimensions for DamageSink {
    fn size(&self) -> Size {
        self.canvas.size()
    }
}

impl DrawTarget for DamageSink {
    type Color = Rgb565;
    type Error = Infallible;

    fn draw_iter<I: IntoIterator<Item = Pixel<Rgb565>>>(
        &mut self,
        pixels: I,
    ) -> Result<(), Self::Error> {
        self.canvas.draw_iter(pixels)
    }
}

impl FrameTarget for DamageSink {
    fn damage_key(&self) -> DamageKey {
        DAMAGE_KEY
    }

    fn present_scene(&mut self, scene: &Scene) -> bool {
        self.succeed && scene.replay(self).is_ok()
    }

    fn present_damage(&mut self, scene: &Scene, rects: &[Rect]) -> bool {
        self.presentations += 1;
        self.rects.extend_from_slice(rects);
        if !self.succeed {
            return false;
        }
        for rect in rects {
            if scene.replay_rect(self, *rect).is_err() {
                return false;
            }
        }
        true
    }
}

#[derive(Default)]
struct SemanticDamageSink {
    rectangle_counts: std::vec::Vec<usize>,
}

impl OriginDimensions for SemanticDamageSink {
    fn size(&self) -> Size {
        Size::new(PANEL_W.into(), PANEL_H.into())
    }
}

impl DrawTarget for SemanticDamageSink {
    type Color = Rgb565;
    type Error = Infallible;

    fn draw_iter<I: IntoIterator<Item = Pixel<Rgb565>>>(
        &mut self,
        _pixels: I,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl FrameTarget for SemanticDamageSink {
    fn damage_key(&self) -> DamageKey {
        panic!("semantic damage must not request a damage key")
    }

    fn present_scene(&mut self, _scene: &Scene) -> bool {
        panic!("semantic damage must not present a complete scene")
    }

    fn present_damage(&mut self, _scene: &Scene, rects: &[Rect]) -> bool {
        self.rectangle_counts.push(rects.len());
        true
    }
}

#[test]
fn empty_damage_frame_does_not_present() {
    let marker = Rgb565::BLUE;
    let mut sink = DamageSink::filled(marker);
    drop(DamageFrame::new(&mut sink));

    assert_eq!(sink.presentations, 0);
    assert!(sink.canvas.pixels.iter().all(|pixel| *pixel == marker));
}

#[test]
fn clear_damage_frame_presents_the_whole_panel() {
    let marker = Rgb565::BLUE;
    let mut sink = DamageSink::filled(marker);
    {
        let mut frame = DamageFrame::new(&mut sink);
        frame.clear(Rgb565::RED).unwrap();
    }

    assert_eq!(sink.presentations, 1);
    assert_eq!(sink.rects, [Rect::new(0, 0, PANEL_W, PANEL_H)]);
    assert!(sink.canvas.pixels.iter().all(|pixel| *pixel == Rgb565::RED));
}

#[test]
fn incomplete_raster_damage_does_not_erase_its_unwritten_gap() {
    let marker = Rgb565::BLUE;
    let mut sink = DamageSink::filled(marker);
    {
        let mut frame = DamageFrame::new(&mut sink);
        frame
            .fill_contiguous(
                &Rectangle::new(Point::new(10, 20), Size::new(4, 2)),
                core::iter::repeat_n(Rgb565::RED, 6),
            )
            .unwrap();
    }

    assert_eq!(sink.presentations, 1);
    assert_eq!(sink.rects.len(), 2);
    assert!(sink.rects.contains(&Rect::new(10, 20, 4, 1)));
    assert!(sink.rects.contains(&Rect::new(10, 21, 2, 1)));
    assert_eq!(sink.canvas.pixel(10, 20), Rgb565::RED);
    assert_eq!(sink.canvas.pixel(11, 21), Rgb565::RED);
    assert_eq!(sink.canvas.pixel(12, 21), marker);
    assert_eq!(sink.canvas.pixel(13, 21), marker);
}

#[test]
fn connected_semantic_damage_matches_a_complete_frame() {
    let old = crate::HomeView {
        status: crate::StatusKind::Idle,
        pin_set: false,
        passkeys: 7,
    };
    let next = crate::HomeView {
        pin_set: true,
        ..old
    };
    let mut before = Canvas::new();
    crate::render(&mut before, &crate::Screen::Home(old)).unwrap();
    let mut expected = Canvas::new();
    crate::render(&mut expected, &crate::Screen::Home(next)).unwrap();
    let mut sink = DamageSink {
        canvas: before,
        rects: std::vec::Vec::new(),
        presentations: 0,
        succeed: true,
    };

    {
        let mut frame = DamageFrame::new(&mut sink);
        crate::render_home_change(&mut frame, &old, &next).unwrap();
    }

    assert_eq!(sink.canvas.pixels, expected.pixels);
    assert_eq!(sink.presentations, 1);
    assert_eq!(sink.rects.len(), 1);
}

#[test]
fn semantic_damage_finalization_does_not_request_a_damage_key() {
    let mut sink = SemanticDamageSink::default();
    {
        let mut frame = DamageFrame::new(&mut sink);
        frame
            .fill_solid(
                &Rectangle::new(Point::new(10, 20), Size::new(8, 3)),
                Rgb565::GREEN,
            )
            .unwrap();
    }

    assert_eq!(sink.rectangle_counts, [1]);
}

#[test]
fn retained_commands_replay_in_order() {
    let mut scene = Scene::default();
    scene.clear(Rgb565::BLACK).unwrap();
    scene
        .fill_solid(
            &Rectangle::new(Point::new(10, 12), Size::new(20, 8)),
            Rgb565::RED,
        )
        .unwrap();
    scene.finalize(DAMAGE_KEY).unwrap();
    let mut band = [0u8; BAND_BYTES];
    scene.raster_band(Rect::new(0, 12, PANEL_W, BAND_H), 12, BAND_H, &mut band);
    let red = Rgb565::RED.into_storage().to_be_bytes();
    let index = 10 * 2;
    assert_eq!(&band[index..index + 2], &red);
}

#[test]
fn tile_tag_changes_only_where_a_command_lands() {
    let mut a = Scene::default();
    let mut b = Scene::default();
    a.clear(Rgb565::BLACK).unwrap();
    b.clear(Rgb565::BLACK).unwrap();
    b.fill_solid(
        &Rectangle::new(Point::new(2, 2), Size::new(3, 3)),
        Rgb565::WHITE,
    )
    .unwrap();
    a.finalize(DAMAGE_KEY).unwrap();
    b.finalize(DAMAGE_KEY).unwrap();
    assert_ne!(a.tile_tag(0, 0), b.tile_tag(0, 0));
    assert_eq!(a.tile_tag(1, 0), b.tile_tag(1, 0));
}

#[test]
fn tile_tags_are_keyed_and_domain_separated() {
    let mut a = Scene::default();
    let mut b = Scene::default();
    a.clear(Rgb565::BLACK).unwrap();
    b.clear(Rgb565::BLACK).unwrap();
    a.finalize(DAMAGE_KEY).unwrap();
    b.finalize([DAMAGE_KEY[0] ^ 1, DAMAGE_KEY[1]]).unwrap();

    assert_ne!(a.tile_tag(0, 0), b.tile_tag(0, 0));
    assert_ne!(a.tile_tag(0, 0), a.tile_tag(1, 0));
}

#[test]
fn damage_tiles_merge_and_unchanged_frames_are_skipped() {
    let mut scene = Scene::default();
    scene.clear(Rgb565::BLACK).unwrap();
    scene.finalize(DAMAGE_KEY).unwrap();
    let mut tags = [0; DAMAGE_TILES];
    let mut damage = [Rect::new(0, 0, 0, 0); DAMAGE_TILES];

    let count = scene.damage_rects(&[0; DAMAGE_TILES], false, &mut tags, &mut damage);
    assert_eq!(count, 1);
    assert_eq!(damage[0], Rect::new(0, 0, PANEL_W, PANEL_H));

    let previous = tags;
    let count = scene.damage_rects(&previous, true, &mut tags, &mut damage);
    assert_eq!(count, 0);

    scene
        .fill_solid(
            &Rectangle::new(Point::new(2, 2), Size::new(3, 3)),
            Rgb565::WHITE,
        )
        .unwrap();
    scene.finalize(DAMAGE_KEY).unwrap();
    let count = scene.damage_rects(&previous, true, &mut tags, &mut damage);
    assert_eq!(count, 1);
    assert_eq!(damage[0], Rect::new(0, 0, DAMAGE_TILE, DAMAGE_TILE));
}

#[test]
fn direct_band_raster_matches_retained_replay() {
    let mut scene = Scene::default();
    scene.clear(Rgb565::new(3, 17, 9)).unwrap();
    let colors = (0..440).map(|index| {
        if index < 300 {
            Rgb565::RED
        } else {
            RawU16::new((index as u16).wrapping_mul(7919)).into()
        }
    });
    scene
        .fill_contiguous(&Rectangle::new(Point::new(7, 5), Size::new(40, 11)), colors)
        .unwrap();
    scene
        .fill_solid(
            &Rectangle::new(Point::new(13, 9), Size::new(19, 3)),
            Rgb565::GREEN,
        )
        .unwrap();
    scene
        .fill_contiguous(
            &Rectangle::new(Point::new(80, 200), Size::new(20, 2)),
            (0..40).map(|index| RawU16::new(index * 997).into()),
        )
        .unwrap();
    scene.finalize(DAMAGE_KEY).unwrap();

    let mut replay = Canvas::new();
    scene.replay(&mut replay).unwrap();
    let mut bytes = [0u8; BAND_BYTES];
    let mut y = 0;
    while y < PANEL_H {
        let height = BAND_H.min(PANEL_H - y);
        scene.raster_band(Rect::new(0, y, PANEL_W, height), y, height, &mut bytes);
        for row in 0..height {
            for x in 0..PANEL_W {
                let expected = replay.pixels
                    [usize::from(y + row) * PANEL_W as usize + usize::from(x)]
                .into_storage()
                .to_be_bytes();
                let index = (usize::from(row) * PANEL_W as usize + usize::from(x)) * 2;
                assert_eq!(&bytes[index..index + 2], &expected);
            }
        }
        y += height;
    }
}

#[test]
fn clear_replaces_prior_records_and_authenticates_the_background() {
    let background = Rgb565::new(7, 23, 11);
    let mut cleared = Scene::default();
    cleared
        .fill_solid(
            &Rectangle::new(Point::zero(), Size::new(20, 20)),
            Rgb565::RED,
        )
        .unwrap();
    cleared
        .fill_contiguous(
            &Rectangle::new(Point::new(4, 4), Size::new(4, 24)),
            core::iter::repeat_n(Rgb565::GREEN, 4 * 24),
        )
        .unwrap();
    assert_ne!(cleared.stream_len, 0);
    cleared.clear(background).unwrap();
    assert_eq!(cleared.stream_len, 0);
    assert_eq!(cleared.checkpoint_len, 0);
    assert_eq!(cleared.command_count(), 0);
    cleared.finalize(DAMAGE_KEY).unwrap();

    let mut replay = Canvas::new();
    cleared.replay(&mut replay).unwrap();
    assert!(replay.pixels.iter().all(|pixel| *pixel == background));
    let mut band = [0u8; BAND_BYTES];
    cleared.raster_band(Rect::new(0, 80, PANEL_W, BAND_H), 80, BAND_H, &mut band);
    let expected = background.into_storage().to_be_bytes();
    assert!(
        band.as_chunks::<2>()
            .0
            .iter()
            .all(|pixel| pixel == &expected)
    );

    let mut black = Scene::default();
    black.clear(Rgb565::BLACK).unwrap();
    black.finalize(DAMAGE_KEY).unwrap();
    for row in 0..DAMAGE_ROWS {
        for column in 0..DAMAGE_COLS {
            assert_ne!(cleared.tile_tag(column, row), black.tile_tag(column, row));
        }
    }
}

#[test]
fn background_tag_has_a_distinct_opcode() {
    let mut background = Scene::default();
    background.clear(Rgb565::RED).unwrap();
    background.finalize(DAMAGE_KEY).unwrap();

    let mut command = Scene::default();
    command.clear(Rgb565::BLACK).unwrap();
    command
        .fill_solid(&command.bounding_box(), Rgb565::RED)
        .unwrap();
    command.finalize(DAMAGE_KEY).unwrap();

    assert_ne!(background.tile_tag(0, 0), command.tile_tag(0, 0));
}

#[test]
fn late_raster_band_starts_at_its_checkpoint() {
    let mut scene = Scene::default();
    scene.clear(Rgb565::BLACK).unwrap();
    scene
        .fill_contiguous(
            &Rectangle::new(Point::zero(), Size::new(4, 24)),
            core::iter::repeat_n(Rgb565::RED, 4 * 24),
        )
        .unwrap();
    scene.finalize(DAMAGE_KEY).unwrap();

    assert_eq!(scene.checkpoint_len, 2);
    let bytes = &scene.stream[..usize::from(scene.stream_len)];
    let palette_len = usize::from(bytes[8]);
    let token_start = RASTER_HEADER + palette_len * 2;
    let checkpoint_start = u16::from_le_bytes([bytes[11], bytes[12]]);
    let (token, position) = scene.raster_seek(checkpoint_start, token_start, 4, 16 * 4);
    assert_eq!(position, 16 * 4);
    assert_eq!(
        token,
        token_start + usize::from(scene.checkpoints[usize::from(checkpoint_start) + 1])
    );
    assert!(token > token_start);

    // A malformed skipped prefix must not affect a later checkpoint.
    scene.stream[token_start] = 0xFF;
    let mut band = [0u8; BAND_BYTES];
    scene.raster_band(Rect::new(0, 16, 4, BAND_H), 16, BAND_H, &mut band);
    let red = Rgb565::RED.into_storage().to_be_bytes();
    assert!(
        band[..4 * BAND_H as usize * 2]
            .as_chunks::<2>()
            .0
            .iter()
            .all(|pixel| pixel == &red)
    );
}

#[test]
fn vertical_band_index_skips_earlier_records() {
    let mut scene = Scene::default();
    scene.clear(Rgb565::BLACK).unwrap();
    scene
        .fill_solid(
            &Rectangle::new(Point::new(0, 0), Size::new(4, 4)),
            Rgb565::RED,
        )
        .unwrap();
    scene
        .fill_solid(
            &Rectangle::new(Point::new(0, 300), Size::new(4, 4)),
            Rgb565::GREEN,
        )
        .unwrap();
    scene.finalize(DAMAGE_KEY).unwrap();

    let late = 300usize / BAND_H as usize;
    assert_eq!(scene.band_first[late], SOLID_BYTES as u16);
    assert_eq!(scene.band_end[late], (SOLID_BYTES * 2) as u16);
    scene.stream[0] = u8::MAX;
    let mut band = [0u8; BAND_BYTES];
    scene.raster_band(Rect::new(0, 296, 4, BAND_H), 296, BAND_H, &mut band);
    let green = Rgb565::GREEN.into_storage().to_be_bytes();
    let index = 4 * 4 * 2;
    assert_eq!(&band[index..index + 2], &green);
}

#[test]
fn raster_failure_rolls_back_checkpoint_state_and_clear_cannot_hide_it() {
    let mut scene = Scene::default();
    let stream_len = STREAM_CAPACITY - RASTER_HEADER - 3;
    scene.stream_len = stream_len as u16;
    scene.command_count = 9;
    let result = scene.push_raster(
        &Rectangle::new(Point::zero(), Size::new(1, 17)),
        core::iter::repeat_n(Rgb565::RED, 17),
    );
    assert_eq!(result, Err(SceneError::Capacity));
    assert_eq!(scene.stream_len, stream_len as u16);
    assert_eq!(scene.command_count, 9);
    assert_eq!(scene.checkpoint_len, 0);

    let background = scene.background;
    assert_eq!(scene.clear(Rgb565::BLUE), Err(SceneError::Capacity));
    assert_eq!(scene.background, background);
    assert_eq!(scene.stream_len, stream_len as u16);
    assert_eq!(scene.checkpoint_len, 0);
}

#[test]
fn scene_memory_stays_within_the_documented_stack_budget() {
    assert!(core::mem::size_of::<Scene>() <= 16 * 1024);
    eprintln!("Scene host size: {} bytes", core::mem::size_of::<Scene>());
}

#[test]
fn narrow_damage_uses_the_whole_fixed_dma_buffer() {
    assert_eq!(dma_band_height(0), 0);
    assert_eq!(dma_band_height(PANEL_W), BAND_H);
    assert_eq!(dma_band_height(32), 60);
    assert_eq!(dma_band_height(1), PANEL_H);
}

#[test]
fn semantic_damage_indexes_records_without_hashing_tiles() {
    let mut scene = Scene::default();
    scene
        .fill_solid(
            &Rectangle::new(Point::new(4, 12), Size::new(8, 3)),
            Rgb565::GREEN,
        )
        .unwrap();
    scene.finalize_records().unwrap();
    assert!(scene.records_valid);
    assert!(!scene.tags_valid);

    let mut band = [0u8; BAND_BYTES];
    scene.raster_band(Rect::new(0, 12, PANEL_W, BAND_H), 12, BAND_H, &mut band);
    let green = Rgb565::GREEN.into_storage().to_be_bytes();
    assert_eq!(&band[4 * 2..4 * 2 + 2], &green);
}

#[test]
fn a_complex_screen_fits_the_retained_capacity() {
    let mut scene = Scene::default();
    crate::render(
        &mut scene,
        &crate::Screen::Confirm(crate::ConfirmPrompt::new(
            "Approve sign-in",
            b"example.com",
            b"a.long.account.name@example.com",
        )),
    )
    .unwrap();
    assert_eq!(scene.error(), None, "{} commands", scene.command_count());
}

static CENSUS_MAX_STREAM: AtomicUsize = AtomicUsize::new(0);
static CENSUS_MAX_CHECKPOINTS: AtomicUsize = AtomicUsize::new(0);

fn retained_frame_fits(name: &str, draw: impl FnOnce(&mut Scene) -> Result<(), SceneError>) {
    let mut scene = Scene::default();
    draw(&mut scene).unwrap_or_else(|error| panic!("{name}: {error:?}"));
    scene
        .finalize(DAMAGE_KEY)
        .unwrap_or_else(|error| panic!("{name}: {error:?}"));
    CENSUS_MAX_STREAM.fetch_max(usize::from(scene.stream_len), Ordering::Relaxed);
    CENSUS_MAX_CHECKPOINTS.fetch_max(usize::from(scene.checkpoint_len), Ordering::Relaxed);
}

fn max_entropy_label() -> crate::Label {
    let mut bytes = [0u8; crate::LABEL_MAX];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = b'!' + ((index * 37) % 94) as u8;
    }
    crate::Label::clamp(&bytes)
}

fn alternate_max_entropy_label() -> crate::Label {
    let mut bytes = [0u8; crate::LABEL_MAX];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = b'~' - ((index * 41) % 94) as u8;
    }
    crate::Label::clamp(&bytes)
}

fn retained_damage_fits(
    name: &str,
    draw: impl FnOnce(&mut DamageFrame<'_, SemanticDamageSink>) -> Result<(), SceneError>,
) -> usize {
    let mut sink = SemanticDamageSink::default();
    {
        let mut frame = DamageFrame::new(&mut sink);
        draw(&mut frame).unwrap_or_else(|error| panic!("{name}: {error:?}"));
    }
    assert_eq!(sink.rectangle_counts.len(), 1, "{name}");
    let count = sink.rectangle_counts[0];
    assert!(count <= DAMAGE_RECT_CAPACITY, "{name}: {count} rectangles");
    eprintln!("{name}: {count} damage rectangles");
    count
}

#[test]
fn every_semantic_renderer_fits_the_damage_rectangle_capacity() {
    use crate::{
        AccountRow, AuditKind, AuditRow, HomeView, OathRow, PivExtraRow, RpRow, StatusKind,
    };

    let previous_label = max_entropy_label();
    let next_label = alternate_max_entropy_label();
    let previous_rps = [RpRow {
        id: previous_label,
        nick: previous_label,
        accounts: 1,
    }; crate::PK_ROWS_MAX];
    let next_rps = [RpRow {
        id: next_label,
        nick: next_label,
        accounts: u8::MAX,
    }; crate::PK_ROWS_MAX];
    retained_damage_fits("render_passkeys_page", |frame| {
        crate::render_passkeys_page(
            frame,
            &previous_rps,
            0,
            u16::MAX - 1,
            &next_rps,
            1,
            u16::MAX,
        )
    });

    let previous_accounts = [AccountRow {
        name: previous_label,
        protected: false,
    }; crate::PK_ROWS_MAX];
    let next_accounts = [AccountRow {
        name: next_label,
        protected: true,
    }; crate::PK_ROWS_MAX];
    retained_damage_fits("render_service_page", |frame| {
        crate::render_service_page(
            frame,
            &previous_accounts,
            0,
            u16::MAX - 1,
            &next_accounts,
            1,
            u16::MAX,
        )
    });

    let piv_rows: [PivExtraRow; crate::PK_ROWS_MAX] = core::array::from_fn(|index| PivExtraRow {
        slot: 0x82 + index as u8,
        present: true,
        cert: true,
        algo: next_label,
        generate: false,
    });
    retained_damage_fits("render_piv_extra_page", |frame| {
        crate::render_piv_extra_page(frame, &piv_rows, u16::MAX - 1, u16::MAX)
    });

    let oath_rows = [OathRow {
        name: next_label,
        hotp: true,
        touch: true,
    }; crate::PK_ROWS_MAX];
    retained_damage_fits("render_oath_page", |frame| {
        crate::render_oath_page(frame, &oath_rows, u16::MAX - 1, u16::MAX)
    });

    let audit_rows = [AuditRow {
        kind: AuditKind::Denied,
        secs_ago: Some(u32::MAX),
    }; crate::PK_ROWS_MAX];
    retained_damage_fits("render_audit_page", |frame| {
        crate::render_audit_page(frame, &audit_rows, u16::MAX - 1, u16::MAX, true)
    });

    let previous_home = HomeView {
        status: StatusKind::Idle,
        pin_set: false,
        passkeys: 0,
    };
    let next_home = HomeView {
        status: StatusKind::Idle,
        pin_set: true,
        passkeys: u16::MAX,
    };
    retained_damage_fits("render_home_change", |frame| {
        crate::render_home_change(frame, &previous_home, &next_home)
    });
}

#[test]
fn every_full_frame_renderer_fits_with_maximum_dynamic_text() {
    use crate::{
        AccountRow, AppsView, AuditKind, AuditRow, BackupView, CardholderView, ConfirmPrompt,
        HomeView, OathDetailView, OathRow, OpenpgpView, PgpKeyView, PgpSlotRow, PinCaption, PinPad,
        PivExtraRow, PivSlotRow, PivSlotView, PivView, RpRow, Screen, SettingsPage, SettingsView,
        StatusKind, SuccessKind,
    };

    CENSUS_MAX_STREAM.store(0, Ordering::Relaxed);
    CENSUS_MAX_CHECKPOINTS.store(0, Ordering::Relaxed);
    let label = max_entropy_label();
    let confirm = ConfirmPrompt {
        title: "Approve security operation",
        primary: label,
        secondary: label,
    };
    let settings = SettingsView {
        page: SettingsPage::Security,
        brightness: crate::BRIGHTNESS_LEVELS,
        timeout_secs: u16::MAX,
        sleep_secs: u16::MAX,
        version: u16::MAX,
        chipid: u64::MAX,
        device_pin_set: true,
        fido_pin_set: true,
        backup_sealed: true,
        scramble_pin: true,
    };
    let screens = [
        ("render splash", Screen::Splash),
        ("render locked", Screen::Locked),
        ("render onboard", Screen::Onboard),
        (
            "render home",
            Screen::Home(HomeView {
                status: StatusKind::Touch,
                pin_set: true,
                passkeys: u16::MAX,
            }),
        ),
        ("render confirm", Screen::Confirm(confirm)),
        (
            "render PIN",
            Screen::Pin(
                PinPad::with_caption(
                    63,
                    "Confirm new device PIN",
                    Some(PinCaption::WrongPin {
                        retries_left: u8::MAX,
                    }),
                )
                .expecting(63),
            ),
        ),
        ("render settings", Screen::Settings(settings)),
    ];
    for (name, screen) in screens {
        retained_frame_fits(name, |scene| crate::render(scene, &screen));
    }
    for page in [
        SettingsPage::Root,
        SettingsPage::Display,
        SettingsPage::Brightness,
        SettingsPage::Timeout,
        SettingsPage::Sleep,
        SettingsPage::Security,
    ] {
        let view = SettingsView { page, ..settings };
        retained_frame_fits("render settings", |scene| {
            crate::render(scene, &Screen::Settings(view))
        });
    }

    let rp_rows = [RpRow {
        id: label,
        nick: label,
        accounts: u8::MAX,
    }; crate::PK_ROWS_MAX];
    let account_rows = [AccountRow {
        name: label,
        protected: true,
    }; crate::PK_ROWS_MAX];
    retained_frame_fits("render_passkeys_list", |scene| {
        crate::render_passkeys_list(scene, &rp_rows, u16::MAX - 1, u16::MAX)
    });
    retained_frame_fits("render_service", |scene| {
        crate::render_service(scene, &label, true, &account_rows, u16::MAX - 1, u16::MAX)
    });
    retained_frame_fits("render_rename", |scene| {
        crate::render_rename(scene, label.as_str(), Some(b'Z'), Some(9))
    });
    retained_frame_fits("render_confirm_delete", |scene| {
        crate::render_confirm_delete(scene, &label, &label)
    });
    retained_frame_fits("render_add_passkey", |scene| {
        crate::render_add_passkey(scene, &label, &label)
    });

    retained_frame_fits("render_apps", |scene| {
        crate::render_apps(
            scene,
            &AppsView {
                openpgp_keys: u8::MAX,
                piv_slots: u8::MAX,
                oath_codes: u16::MAX,
            },
        )
    });
    let pgp_slot = PgpSlotRow {
        present: true,
        algo: label,
        touch: true,
    };
    retained_frame_fits("render_openpgp", |scene| {
        crate::render_openpgp(
            scene,
            &OpenpgpView {
                slots: [pgp_slot; 3],
                cardholder_name: label,
                sig_count: u32::MAX,
                pw1: u8::MAX,
                pw3: u8::MAX,
            },
        )
    });
    retained_frame_fits("render_openpgp_key", |scene| {
        crate::render_openpgp_key(
            scene,
            &PgpKeyView {
                slot: 2,
                present: true,
                algo: label,
                touch: true,
                created: true,
                fingerprint: [0xA5; 20],
                has_fp: true,
            },
        )
    });
    retained_frame_fits("render_openpgp_cardholder", |scene| {
        crate::render_openpgp_cardholder(
            scene,
            &CardholderView {
                name: label,
                login: label,
                url: label,
                lang: label,
                any: true,
            },
        )
    });

    let piv_slot = PivSlotRow {
        slot: 0x9A,
        present: true,
        cert: true,
        algo: label,
    };
    retained_frame_fits("render_piv", |scene| {
        crate::render_piv(
            scene,
            &PivView {
                slots: [piv_slot; 4],
                extra: u8::MAX,
                pin: u8::MAX,
                puk: u8::MAX,
            },
        )
    });
    retained_frame_fits("render_piv_slot", |scene| {
        crate::render_piv_slot(
            scene,
            &PivSlotView {
                slot: 0x9A,
                present: true,
                cert: true,
                algo: label,
                pin_policy: label,
                touch_policy: label,
                origin: label,
            },
        )
    });
    let extra_rows: [PivExtraRow; crate::PK_ROWS_MAX] = core::array::from_fn(|index| PivExtraRow {
        slot: 0x82 + index as u8,
        present: true,
        cert: true,
        algo: label,
        generate: false,
    });
    retained_frame_fits("render_piv_extra", |scene| {
        crate::render_piv_extra(scene, &extra_rows, u16::MAX - 1, u16::MAX)
    });

    let oath_rows = [OathRow {
        name: label,
        hotp: true,
        touch: true,
    }; crate::PK_ROWS_MAX];
    retained_frame_fits("render_oath", |scene| {
        crate::render_oath(scene, &oath_rows, u16::MAX - 1, u16::MAX)
    });
    retained_frame_fits("render_oath_cred", |scene| {
        crate::render_oath_cred(
            scene,
            &OathDetailView {
                name: label,
                hotp: false,
                algo: label,
                digits: u8::MAX,
                period: u16::MAX,
                touch: true,
            },
        )
    });

    let audit_rows = [AuditRow {
        kind: AuditKind::Denied,
        secs_ago: Some(u32::MAX),
    }; crate::PK_ROWS_MAX];
    retained_frame_fits("render_audit_log", |scene| {
        crate::render_audit_log(scene, &audit_rows, u16::MAX - 1, u16::MAX, true)
    });
    retained_frame_fits("render_backup", |scene| {
        crate::render_backup(
            scene,
            &BackupView {
                sealed: false,
                has_seed: true,
                exportable: true,
                can_reveal: true,
            },
        )
    });
    retained_frame_fits("render_backup_format", crate::render_backup_format);
    retained_frame_fits("render_share_picker", |scene| {
        crate::render_share_picker(scene, crate::SHARE_MAX, crate::SHARE_MAX)
    });
    retained_frame_fits("render_reveal_warning", |scene| {
        crate::render_reveal_warning(scene, crate::RevealKind::Shares)
    });
    retained_frame_fits("render_seal_confirm", crate::render_seal_confirm);
    // Both firmware wordlists assert an eight-byte ASCII maximum.
    let words = ["wildlife"; crate::SEED_WORDS_PER_PAGE];
    retained_frame_fits("render_seed_phrase", |scene| {
        crate::render_seed_phrase(scene, &words, u16::MAX - 1, u16::MAX)
    });
    retained_frame_fits("render_slip39_share", |scene| {
        crate::render_slip39_share(scene, &words, u16::MAX, u16::MAX, u16::MAX - 1, u16::MAX)
    });

    retained_frame_fits(
        "render_confirm_factory_reset",
        crate::render_confirm_factory_reset,
    );
    retained_frame_fits("render_erasing", crate::render_erasing);
    retained_frame_fits("render_pin_blocked", crate::render_pin_blocked);
    retained_frame_fits("render_wipe_failed", crate::render_wipe_failed);
    for kind in [
        SuccessKind::Approved,
        SuccessKind::Deleted,
        SuccessKind::Wiped,
        SuccessKind::Generated,
    ] {
        retained_frame_fits("render_success", |scene| {
            crate::render_success(scene, kind, true)
        });
    }
    retained_frame_fits("render_firmware", |scene| {
        crate::render_firmware(scene, u16::MAX, u64::MAX, false)
    });
    retained_frame_fits("render_rebooting", crate::render_rebooting);
    retained_frame_fits("render_piv_keygen_pick", |scene| {
        crate::render_piv_keygen_pick(scene, u8::MAX)
    });
    retained_frame_fits("render_piv_keygen_rsa_pick", |scene| {
        crate::render_piv_keygen_rsa_pick(scene, u8::MAX)
    });
    retained_frame_fits("render_piv_pin_menu", crate::render_piv_pin_menu);
    retained_frame_fits(
        "render_piv_protect_confirm",
        crate::render_piv_protect_confirm,
    );
    retained_frame_fits("render_piv_keygen_confirm", |scene| {
        crate::render_piv_keygen_confirm(scene, u8::MAX, label.as_str())
    });
    retained_frame_fits(
        "render_piv_keygen_working",
        crate::render_piv_keygen_working,
    );

    // Partial animation and page-body renderers do not own a complete Scene. Their
    // parent frame is covered above; direct panel tests cover their clipped writes.
    let max_stream = CENSUS_MAX_STREAM.load(Ordering::Relaxed);
    let max_checkpoints = CENSUS_MAX_CHECKPOINTS.load(Ordering::Relaxed);
    assert!(max_stream <= STREAM_CAPACITY);
    assert!(max_checkpoints <= CHECKPOINT_CAPACITY);
    eprintln!("renderer census maximum: {max_stream} stream bytes, {max_checkpoints} checkpoints");
}

const FULL_FRAME_RENDERERS: &[&str] = &[
    "render",
    "render_add_passkey",
    "render_apps",
    "render_audit_log",
    "render_backup",
    "render_backup_format",
    "render_confirm_delete",
    "render_confirm_factory_reset",
    "render_erasing",
    "render_firmware",
    "render_oath",
    "render_oath_cred",
    "render_openpgp",
    "render_openpgp_cardholder",
    "render_openpgp_key",
    "render_passkeys_list",
    "render_pin_blocked",
    "render_piv",
    "render_piv_extra",
    "render_piv_keygen_confirm",
    "render_piv_keygen_pick",
    "render_piv_keygen_rsa_pick",
    "render_piv_keygen_working",
    "render_piv_pin_menu",
    "render_piv_protect_confirm",
    "render_piv_slot",
    "render_rebooting",
    "render_rename",
    "render_reveal_warning",
    "render_seal_confirm",
    "render_seed_phrase",
    "render_service",
    "render_share_picker",
    "render_slip39_share",
    "render_success",
    "render_wipe_failed",
];

const PARTIAL_RENDERERS: &[&str] = &[
    "render_audit_page",
    "render_header",
    "render_hold_button",
    "render_hold_fill",
    "render_home_change",
    "render_locked_breathe",
    "render_nav",
    "render_oath_page",
    "render_passkeys_page",
    "render_pin_dots",
    "render_pin_title",
    "render_piv_extra_page",
    "render_rename_field",
    "render_rename_keys",
    "render_service_page",
    "render_status_arc",
    "render_success_circle",
];

#[test]
fn full_frame_capacity_census_names_every_exported_renderer() {
    fn scan(path: &std::path::Path, found: &mut std::vec::Vec<std::string::String>) {
        if path.is_dir() {
            for entry in std::fs::read_dir(path).unwrap().flatten() {
                scan(&entry.path(), found);
            }
            return;
        }
        if path.extension().and_then(|value| value.to_str()) != Some("rs") {
            return;
        }
        let source = std::fs::read_to_string(path).unwrap();
        for line in source.lines() {
            let Some(rest) = line.trim_start().strip_prefix("pub fn render") else {
                continue;
            };
            let suffix = rest
                .split(['<', '('])
                .next()
                .expect("render function suffix");
            found.push(format!("render{suffix}"));
        }
    }

    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/render.rs");
    let modules = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/render");
    let mut found = std::vec::Vec::new();
    scan(&source, &mut found);
    scan(&modules, &mut found);
    found.sort_unstable();
    found.dedup();

    let mut expected = FULL_FRAME_RENDERERS
        .iter()
        .chain(PARTIAL_RENDERERS)
        .copied()
        .collect::<std::vec::Vec<_>>();
    expected.sort_unstable();
    assert_eq!(found, expected);
}

struct Sink {
    presented: bool,
}

impl OriginDimensions for Sink {
    fn size(&self) -> Size {
        Size::new(PANEL_W.into(), PANEL_H.into())
    }
}

impl DrawTarget for Sink {
    type Color = Rgb565;
    type Error = Infallible;

    fn draw_iter<I: IntoIterator<Item = Pixel<Rgb565>>>(
        &mut self,
        _pixels: I,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl FrameTarget for Sink {
    fn damage_key(&self) -> DamageKey {
        DAMAGE_KEY
    }

    fn present_scene(&mut self, _scene: &Scene) -> bool {
        self.presented = true;
        true
    }
}

#[test]
fn capacity_error_panics_before_a_partial_scene_is_presented() {
    let mut sink = Sink { presented: false };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut frame = Frame::new(&mut sink);
        for index in 0..=STREAM_CAPACITY / SOLID_BYTES {
            let color = RawU16::new(index as u16).into();
            let result =
                frame.fill_solid(&Rectangle::new(Point::new(0, 0), Size::new(1, 1)), color);
            if index == STREAM_CAPACITY / SOLID_BYTES {
                assert_eq!(result, Err(SceneError::Capacity));
            } else {
                result.unwrap();
            }
        }
    }));

    assert!(result.is_err());
    assert!(!sink.presented);
}

#[test]
fn transport_failure_panics_before_a_frame_drop_returns() {
    let mut full = DamageSink::filled(Rgb565::BLACK);
    full.succeed = false;
    let full_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut frame = Frame::new(&mut full);
        frame
            .fill_solid(
                &Rectangle::new(Point::zero(), Size::new(1, 1)),
                Rgb565::WHITE,
            )
            .unwrap();
    }));
    assert!(full_result.is_err());

    let mut damage = DamageSink::filled(Rgb565::BLACK);
    damage.succeed = false;
    let damage_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut frame = DamageFrame::new(&mut damage);
        frame
            .fill_solid(
                &Rectangle::new(Point::zero(), Size::new(1, 1)),
                Rgb565::WHITE,
            )
            .unwrap();
    }));
    assert!(damage_result.is_err());
    assert_eq!(damage.presentations, 1);
}
