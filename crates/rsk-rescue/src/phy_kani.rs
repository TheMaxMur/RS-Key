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

/// A symbolic present-or-absent ≤4-byte, NUL-free string. The wire format is
/// NUL-terminated, so a stored string cannot contain NUL — parse truncates at
/// the first one, so the harness excludes it. The cap gates only the string
/// copy; the TLV structure (tag, length, content, terminator) is fully covered.
fn any_product() -> Option<Product> {
    const W: usize = 4;
    if kani::any() {
        let raw: [u8; W] = kani::any();
        let len: usize = kani::any();
        kani::assume(1 <= len && len <= W);
        for i in 0..len {
            kani::assume(raw[i] != 0);
        }
        let p = Product::new(&raw[..len]);
        assert!(p.is_some());
        p
    } else {
        None
    }
}

/// `serialize` then `parse` is the identity on every scalar-field-presence
/// combination plus the product string. Manufacturer stays absent here — it
/// serializes as an independent tag, so its own path is proved cheaply by
/// [`serialize_parse_manufacturer_roundtrip`] and the both-present buffer fit
/// by [`serialize_max_fits`], sparing this query a second symbolic string.
///
/// Fields are compared one by one, the product by content: whole-struct `==`
/// would memcmp `Product`'s full 32-byte buffer and force the unwind bound
/// from the parser's depth to the buffer's — ~5× the solve time for a property
/// that is an artifact of construction, not the wire spec. The `unwrap`
/// doubles as proof that `PHY_MAX_SIZE` always fits the record.
#[kani::proof]
#[kani::unwind(13)]
fn serialize_parse_roundtrip() {
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
    phy.usb_product = any_product();
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
    assert!(got.usb_manufacturer.is_none());
}

/// The manufacturer TLV — the field added this cycle — roundtrips on its own.
/// It serializes as an independent tag, so it needs no scalar-presence base
/// (that combinatorial cost lives once, in [`serialize_parse_roundtrip`],
/// whose multi-TLV adjacency already exercises the walker); this harness only
/// proves the new tag's own serialize/parse path, so it stays cheap.
#[kani::proof]
#[kani::unwind(13)]
fn serialize_parse_manufacturer_roundtrip() {
    let mut phy = PhyData::default();
    phy.usb_manufacturer = any_product();

    let mut buf = [0u8; PHY_MAX_SIZE];
    let n = phy.serialize(&mut buf).unwrap();

    let got = PhyData::parse(&buf[..n]);
    match (&got.usb_manufacturer, &phy.usb_manufacturer) {
        (Some(g), Some(p)) => assert_eq!(g.as_bytes(), p.as_bytes()),
        (None, None) => {}
        _ => panic!("usb_manufacturer presence changed across the roundtrip"),
    }
    assert!(got.usb_product.is_none());
}

/// The worst case for buffer sizing — every field present, BOTH strings at
/// the 4-byte cap — still serializes within `PHY_MAX_SIZE`. String lengths are
/// fixed (only content is symbolic) so this stays a cheap serialize-only query;
/// the roundtrip proofs carry at most one symbolic string each, so this is
/// where the both-present fit bound is checked.
#[kani::proof]
#[kani::unwind(14)]
fn serialize_max_fits() {
    const W: usize = 4;
    let a: [u8; W] = kani::any();
    let b: [u8; W] = kani::any();
    for i in 0..W {
        kani::assume(a[i] != 0);
        kani::assume(b[i] != 0);
    }
    let mut phy = PhyData::default();
    phy.vid_pid = Some((kani::any(), kani::any()));
    phy.led_gpio = Some(kani::any());
    phy.led_brightness = Some(kani::any());
    phy.opts = kani::any();
    phy.presence_timeout = Some(kani::any());
    phy.enabled_curves = Some(kani::any());
    phy.enabled_usb_itf = Some(kani::any());
    phy.led_driver = Some(kani::any());
    phy.led_order = Some(kani::any());
    phy.led_num = Some(kani::any());
    phy.usb_product = Product::new(&a);
    phy.usb_manufacturer = Product::new(&b);

    let mut buf = [0u8; PHY_MAX_SIZE];
    assert!(phy.serialize(&mut buf).is_some());
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
