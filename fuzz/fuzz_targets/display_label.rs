// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Fuzz the trusted-display trust boundary. `Label`
//! turns attacker-controlled relying-party text (rpId, account name) into the
//! printable ASCII shown on the on-device Allow/Deny screen. `Label::clamp` /
//! `clamp_domain` must be total (no input panics) and emit ONLY bytes in
//! `0x20..=0x7E` — the invariant that defeats terminal escapes and bidi /
//! homoglyph spoofing (audit run-11/run-12). Render the approval, passkey and
//! applet views that consume those fields. Check pixel bounds, panel-error
//! propagation and retained-scene pixels against direct rendering.

#![no_main]

use embedded_graphics::{
    Pixel,
    draw_target::DrawTarget,
    geometry::{OriginDimensions, Size},
    pixelcolor::Rgb565,
};
use libfuzzer_sys::fuzz_target;
use rsk_ui::{
    AccountRow, CardholderView, ConfirmPrompt, LABEL_MAX, Label, OathDetailView, OathRow,
    OpenpgpView, PANEL_H, PANEL_W, PK_ROWS_MAX, PgpKeyView, PgpSlotRow, PivSlotView, RpRow, Screen,
};

#[path = "display_label/views.rs"]
mod views;

/// Clipping on the real panel must not hide bad layout arithmetic in the oracle.
#[derive(Default)]
struct Sink {
    fail_at: Option<usize>,
    calls: usize,
    failed: Option<usize>,
}
impl OriginDimensions for Sink {
    fn size(&self) -> Size {
        Size::new(PANEL_W as u32, PANEL_H as u32)
    }
}
impl DrawTarget for Sink {
    type Color = Rgb565;
    type Error = usize;
    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        assert!(
            self.failed.is_none(),
            "drawing continued after a panel error"
        );
        let call = self.calls;
        self.calls += 1;
        if self.fail_at == Some(call) {
            self.failed = Some(call);
            return Err(call);
        }
        for Pixel(p, _) in pixels {
            assert!((0..i32::from(PANEL_W)).contains(&p.x));
            assert!((0..i32::from(PANEL_H)).contains(&p.y));
        }
        Ok(())
    }
}

fn render_public_view<D: DrawTarget<Color = Rgb565>>(
    sink: &mut D,
    data: &[u8],
    name: Label,
    domain: Label,
) -> Result<(), D::Error> {
    let selector = data.first().copied().unwrap_or(0);
    let flag = selector & 0x80 != 0;
    let total = u16::from(data.get(1).copied().unwrap_or(0));
    let page = u16::from(data.get(2).copied().unwrap_or(0)) % rsk_ui::page_count(total).max(1);
    let count = usize::from(total.saturating_sub(page * PK_ROWS_MAX as u16)).min(PK_ROWS_MAX);
    match selector % 32 {
        0 => {
            let rows = [RpRow {
                id: domain,
                nick: if flag { name } else { Label::default() },
                accounts: selector,
            }; PK_ROWS_MAX];
            rsk_ui::render_passkeys_list(sink, &rows[..count], page, total)
        }
        1 => {
            let rows = [AccountRow {
                name,
                protected: flag,
            }; PK_ROWS_MAX];
            rsk_ui::render_service(
                sink,
                if flag { &name } else { &domain },
                !flag,
                &rows[..count],
                page,
                total,
            )
        }
        2 => rsk_ui::render_openpgp_cardholder(
            sink,
            &CardholderView {
                name,
                login: name,
                url: domain,
                lang: name,
                any: !data.is_empty(),
            },
        ),
        3 => {
            let mut fingerprint = [0; 20];
            for (to, from) in fingerprint.iter_mut().zip(data) {
                *to = *from;
            }
            rsk_ui::render_openpgp_key(
                sink,
                &PgpKeyView {
                    slot: selector % 3,
                    present: flag,
                    algo: name,
                    touch: selector & 0x40 != 0,
                    created: selector & 0x20 != 0,
                    fingerprint,
                    has_fp: selector & 0x10 != 0,
                },
            )
        }
        4 => rsk_ui::render_piv_slot(
            sink,
            &PivSlotView {
                slot: selector,
                present: flag,
                cert: selector & 0x40 != 0,
                algo: name,
                pin_policy: name,
                touch_policy: name,
                origin: name,
            },
        ),
        5 => rsk_ui::render_oath_cred(
            sink,
            &OathDetailView {
                name,
                hotp: flag,
                algo: name,
                digits: selector,
                period: total,
                touch: selector & 0x40 != 0,
            },
        ),
        6 => {
            let rows = [OathRow {
                name,
                hotp: flag,
                touch: selector & 0x40 != 0,
            }; PK_ROWS_MAX];
            rsk_ui::render_oath(sink, &rows[..count], page, total)
        }
        7 => rsk_ui::render_openpgp(
            sink,
            &OpenpgpView {
                slots: [PgpSlotRow {
                    present: flag,
                    algo: name,
                    touch: selector & 0x40 != 0,
                }; 3],
                cardholder_name: name,
                sig_count: u32::from(total) * u32::from(selector),
                pw1: selector,
                pw3: selector.wrapping_add(1),
            },
        ),
        route => views::render(sink, route, data, name, domain),
    }
}

/// The sanitizer's post-condition: printable ASCII only, and bounded.
fn assert_sanitized(l: &Label) {
    assert!(l.as_str().bytes().all(|b| (0x20..=0x7E).contains(&b)));
    assert!(l.as_str().len() <= LABEL_MAX);
}

fuzz_target!(|data: &[u8]| {
    let (primary, secondary) = data.split_at(data.len() / 2);

    // 1) The sanitizer invariants: ASCII-only, bounded, exact length + truncated.
    let head = Label::clamp(primary);
    assert_sanitized(&head);
    assert_eq!(head.truncated, primary.len() > LABEL_MAX);
    assert_eq!(head.as_str().len(), primary.len().min(LABEL_MAX));

    let dom = Label::clamp_domain(primary);
    assert_sanitized(&dom);
    assert_eq!(dom.truncated, primary.len() > LABEL_MAX);
    assert_eq!(dom.as_str().len(), primary.len().min(LABEL_MAX));

    // 2) The confirm screen built from both untrusted fields must render clean.
    let prompt = ConfirmPrompt::new("Approve?", primary, secondary);
    assert_sanitized(&prompt.primary);
    assert_sanitized(&prompt.secondary);
    let mut sink = Sink::default();
    rsk_ui::render::render(&mut sink, &Screen::Confirm(prompt)).unwrap();
    let mut sink = Sink {
        fail_at: data
            .get(3)
            .filter(|byte| **byte & 0x80 != 0)
            .map(|byte| usize::from(*byte & 0x7f)),
        ..Sink::default()
    };
    let result = render_public_view(&mut sink, data, head, dom);
    assert_eq!(result, sink.failed.map_or(Ok(()), Err));
    views::assert_retained(data, head, dom);
});
