// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::*;
use embedded_graphics::{Pixel, geometry::OriginDimensions};

struct Panel {
    fail_at: usize,
    calls: usize,
    failed: bool,
}

impl OriginDimensions for Panel {
    fn size(&self) -> Size {
        Size::new(PANEL_W as u32, PANEL_H as u32)
    }
}

impl DrawTarget for Panel {
    type Color = Rgb565;
    type Error = usize;

    fn draw_iter<I: IntoIterator<Item = Pixel<Rgb565>>>(
        &mut self,
        pixels: I,
    ) -> Result<(), Self::Error> {
        assert!(!self.failed, "drawing continued after a panel error");
        let call = self.calls;
        self.calls += 1;
        if call == self.fail_at {
            self.failed = true;
            return Err(call);
        }
        for Pixel(p, _) in pixels {
            assert!(p.x >= 0 && p.x < PANEL_W as i32);
            assert!(p.y >= 0 && p.y < PANEL_H as i32);
        }
        Ok(())
    }
}

fn every_draw_failure(draw: impl Fn(&mut Panel) -> Result<(), usize>) {
    let mut panel = Panel {
        fail_at: usize::MAX,
        calls: 0,
        failed: false,
    };
    assert_eq!(draw(&mut panel), Ok(()));
    assert!(panel.calls > 0);
    for fail_at in 0..panel.calls {
        let mut broken = Panel {
            fail_at,
            calls: 0,
            failed: false,
        };
        assert_eq!(draw(&mut broken), Err(fail_at));
        assert!(broken.failed);
        assert_eq!(broken.calls, fail_at + 1);
    }
}

#[test]
fn top_level_frames_and_pin_updates_propagate_every_panel_error() {
    for screen in [Screen::Splash, Screen::Locked, Screen::Onboard] {
        every_draw_failure(|d| render(d, &screen));
    }
    every_draw_failure(|d| render_locked_breathe(d, 3));
    let prompt = ConfirmPrompt::new("Sign in?", b"example.org", b"alice");
    every_draw_failure(|d| render(d, &Screen::Confirm(prompt)));
    for caption in [
        None,
        Some(PinCaption::Mismatch),
        Some(PinCaption::ChoosePin),
    ] {
        let mut pad = PinPad::with_title(11, "OpenPGP Admin PIN");
        pad.expected = 4;
        pad.caption = caption;
        every_draw_failure(|d| render(d, &Screen::Pin(pad)));
    }
    for title in ["Device PIN", "OpenPGP Admin PIN"] {
        every_draw_failure(|d| render_pin_title(d, title, 47));
    }
    for reveal in [None, Some(b"123456789012".as_slice())] {
        every_draw_failure(|d| render_pin_dots(d, 12, 4, reveal));
    }
}

#[test]
fn home_and_settings_updates_propagate_every_panel_error() {
    let idle = HomeView {
        status: StatusKind::Idle,
        pin_set: false,
        passkeys: 0,
    };
    for status in [
        StatusKind::Boot,
        StatusKind::Idle,
        StatusKind::Processing,
        StatusKind::Touch,
    ] {
        let home = HomeView {
            status,
            pin_set: true,
            passkeys: 7,
        };
        every_draw_failure(|d| render(d, &Screen::Home(home)));
        every_draw_failure(|d| render_home_change(d, &idle, &home));
        every_draw_failure(|d| render_home_change(d, &home, &idle));
        every_draw_failure(|d| render_status_arc(d, status, -90));
    }
    for page in [
        SettingsPage::Root,
        SettingsPage::Display,
        SettingsPage::Security,
        SettingsPage::Brightness,
        SettingsPage::Timeout,
        SettingsPage::Sleep,
    ] {
        for enabled in [false, true] {
            let v = SettingsView {
                page,
                brightness: 3,
                timeout_secs: 30,
                sleep_secs: if enabled { 60 } else { 0 },
                version: 0x1234,
                chipid: 1234,
                device_pin_set: enabled,
                fido_pin_set: enabled,
                backup_sealed: enabled,
                scramble_pin: enabled,
            };
            every_draw_failure(|d| render(d, &Screen::Settings(v)));
        }
    }
    every_draw_failure(|d| render_firmware(d, 0x1234, u64::MAX, true));
    every_draw_failure(render_rebooting);
}

#[test]
fn passkey_lists_details_and_rename_propagate_every_panel_error() {
    let label = Label::clamp(b"alice");
    let rp = Label::clamp_domain(b"example.org");
    let rows = [RpRow {
        id: rp,
        nick: label,
        accounts: 2,
    }];
    let accounts = [AccountRow {
        name: label,
        protected: true,
    }];
    for total in [1, 7] {
        every_draw_failure(|d| render_passkeys_list(d, &rows, 0, total));
        every_draw_failure(|d| render_passkeys_page(d, &[], 0, 0, &rows, 0, total));
        for title_is_rp in [false, true] {
            every_draw_failure(|d| render_service(d, &rp, title_is_rp, &accounts, 0, total));
        }
        every_draw_failure(|d| render_service_page(d, &[], 0, 0, &accounts, 0, total));
    }
    every_draw_failure(|d| render_passkeys_page(d, &rows, 0, 7, &[], 1, 7));
    every_draw_failure(|d| render_service_page(d, &accounts, 0, 7, &[], 1, 7));
    every_draw_failure(|d| render_rename(d, "alice", Some(b'b'), Some(1)));
    every_draw_failure(|d| render_rename_field(d, "alice", Some(b' ')));
    every_draw_failure(|d| render_rename_keys(d, None));
    every_draw_failure(|d| render_confirm_delete(d, &rp, &label));
    every_draw_failure(|d| render_add_passkey(d, &rp, &label));
}

#[test]
fn applet_views_propagate_every_panel_error() {
    every_draw_failure(|d| render_apps(d, &AppsView::default()));
    every_draw_failure(|d| render_openpgp(d, &OpenpgpView::default()));
    every_draw_failure(|d| render_piv(d, &PivView::default()));
    for present in [false, true] {
        let pgp = PgpKeyView {
            present,
            has_fp: present,
            created: present,
            ..PgpKeyView::default()
        };
        every_draw_failure(|d| render_openpgp_key(d, &pgp));
        let cardholder = CardholderView {
            any: present,
            name: Label::clamp(b"alice"),
            ..CardholderView::default()
        };
        every_draw_failure(|d| render_openpgp_cardholder(d, &cardholder));
        for slot in [0x9a, 0xf9, 0xff] {
            let piv = PivSlotView {
                slot,
                present,
                cert: true,
                ..PivSlotView::default()
            };
            every_draw_failure(|d| render_piv_slot(d, &piv));
        }
    }
    let extra = [
        PivExtraRow {
            slot: 0x82,
            cert: true,
            ..PivExtraRow::default()
        },
        PivExtraRow {
            generate: true,
            ..PivExtraRow::default()
        },
    ];
    let oath = [OathRow {
        name: Label::clamp(b"bank:alice"),
        hotp: true,
        touch: true,
    }];
    for total in [2, 7] {
        every_draw_failure(|d| render_piv_extra(d, &extra, 0, total));
        every_draw_failure(|d| render_piv_extra_page(d, &extra, 0, total));
        every_draw_failure(|d| render_oath(d, &oath, 0, total));
        every_draw_failure(|d| render_oath_page(d, &oath, 0, total));
    }
    for hotp in [false, true] {
        let detail = OathDetailView {
            hotp,
            digits: 6,
            period: 30,
            ..OathDetailView::default()
        };
        every_draw_failure(|d| render_oath_cred(d, &detail));
    }
    every_draw_failure(|d| render_piv_keygen_pick(d, 0x82));
    every_draw_failure(|d| render_piv_keygen_rsa_pick(d, 0x82));
    every_draw_failure(render_piv_pin_menu);
    every_draw_failure(render_piv_protect_confirm);
    every_draw_failure(|d| render_piv_keygen_confirm(d, 0x82, "RSA-2048"));
    every_draw_failure(render_piv_keygen_working);
}

#[test]
fn backup_audit_and_reset_views_propagate_every_panel_error() {
    for sealed in [false, true] {
        let v = BackupView {
            sealed,
            has_seed: true,
            exportable: true,
            can_reveal: !sealed,
        };
        every_draw_failure(|d| render_backup(d, &v));
    }
    every_draw_failure(render_backup_format);
    every_draw_failure(|d| render_share_picker(d, 2, 3));
    for kind in [RevealKind::Phrase, RevealKind::Shares] {
        every_draw_failure(|d| render_reveal_warning(d, kind));
    }
    every_draw_failure(render_seal_confirm);
    let words = ["abandon"; 24];
    every_draw_failure(|d| render_seed_phrase(d, &words, 1, 2));
    every_draw_failure(|d| render_slip39_share(d, &words, 1, 3, 2, 6));
    for logging in [false, true] {
        let rows = [AuditRow {
            kind: AuditKind::Login,
            secs_ago: Some(90),
        }];
        every_draw_failure(|d| render_audit_log(d, &rows, 0, 7, logging));
        every_draw_failure(|d| render_audit_page(d, &rows, 0, 7, logging));
        every_draw_failure(|d| render_audit_page(d, &[], 0, 0, logging));
    }
    every_draw_failure(render_confirm_factory_reset);
    every_draw_failure(render_erasing);
    every_draw_failure(render_pin_blocked);
    every_draw_failure(render_wipe_failed);
    for kind in [
        SuccessKind::Approved,
        SuccessKind::Deleted,
        SuccessKind::Generated,
        SuccessKind::Wiped,
    ] {
        every_draw_failure(|d| render_success(d, kind, true));
        every_draw_failure(|d| render_success_circle(d, kind, 100));
    }
}
