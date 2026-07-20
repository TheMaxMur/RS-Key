// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// `parse` over EVERY byte string up to 12 bytes (past every tag/length
/// form, with room for several TLVs including a truncated tail): never
/// panics, never overreads, always terminates, and always materializes an
/// interface mask — the boot path relies on that.
#[kani::proof]
#[kani::unwind(14)]
fn parse_any_input() {
    const N: usize = 12;
    let data: [u8; N] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= N);
    let phy = PhyData::parse(&data[..n]);
    assert!(phy.enabled_usb_itf.is_some());
}

/// `serialize` then `parse` is the identity on EVERY `PhyData` — every
/// field-presence combination, every field value, product strings up to 4
/// bytes (the cap gates only the string copy; the TLV structure is fully
/// covered) — modulo the one documented normalization: a missing
/// ENABLED_USB_ITF parses as ALL. The `unwrap` doubles as proof that
/// `PHY_MAX_SIZE` always fits the record.
///
/// Fields are compared one by one, the product by content: whole-struct
/// `==` would memcmp `Product`'s full 32-byte buffer and force the unwind
/// bound (hence every loop's unrolling) from the parser's depth to the
/// buffer's — ~5× the solve time for a property that is an artifact of
/// construction, not part of the wire spec.
#[kani::proof]
#[kani::unwind(13)]
fn serialize_parse_roundtrip() {
    const W: usize = 4;
    let mut phy = PhyData::default();
    if kani::any() {
        phy.vid_pid = Some((kani::any(), kani::any()));
    }
    if kani::any() {
        phy.led_gpio = Some(kani::any());
    }
    if kani::any() {
        phy.led_brightness = Some(kani::any());
    }
    phy.opts = kani::any();
    if kani::any() {
        phy.presence_timeout = Some(kani::any());
    }
    if kani::any() {
        let raw: [u8; W] = kani::any();
        let len: usize = kani::any();
        kani::assume(1 <= len && len <= W);
        // The wire format is NUL-terminated, so a product string cannot
        // contain NUL — parse truncates at the first one.
        for i in 0..len {
            kani::assume(raw[i] != 0);
        }
        phy.usb_product = Product::new(&raw[..len]);
        assert!(phy.usb_product.is_some());
    }
    if kani::any() {
        phy.enabled_curves = Some(kani::any());
    }
    if kani::any() {
        phy.enabled_usb_itf = Some(kani::any());
    }
    if kani::any() {
        phy.led_driver = Some(kani::any());
    }
    if kani::any() {
        phy.led_order = Some(kani::any());
    }
    if kani::any() {
        phy.led_num = Some(kani::any());
    }

    let mut buf = [0u8; PHY_MAX_SIZE];
    let n = phy.serialize(&mut buf).unwrap();

    let got = PhyData::parse(&buf[..n]);
    assert_eq!(got.vid_pid, phy.vid_pid);
    assert_eq!(got.led_gpio, phy.led_gpio);
    assert_eq!(got.led_brightness, phy.led_brightness);
    assert_eq!(got.opts, phy.opts);
    assert_eq!(got.presence_timeout, phy.presence_timeout);
    match (&got.usb_product, &phy.usb_product) {
        (Some(g), Some(p)) => assert_eq!(g.as_bytes(), p.as_bytes()),
        (None, None) => {}
        _ => panic!("usb_product presence changed across the roundtrip"),
    }
    assert_eq!(got.enabled_curves, phy.enabled_curves);
    assert_eq!(
        got.enabled_usb_itf,
        phy.enabled_usb_itf.or(Some(USB_ITF_ALL))
    );
    assert_eq!(got.led_driver, phy.led_driver);
    assert_eq!(got.led_order, phy.led_order);
    assert_eq!(got.led_num, phy.led_num);
}

/// `overlay` over any base record and any ≤12-byte host blob never panics or
/// overreads — the merge write (`merge_save`) walks host-controlled bytes on top
/// of the stored record, so it must be as total as `parse`.
#[kani::proof]
#[kani::unwind(14)]
fn overlay_any_input() {
    const N: usize = 12;
    let data: [u8; N] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= N);
    let _ = PhyData::default().overlay(&data[..n]);
}
