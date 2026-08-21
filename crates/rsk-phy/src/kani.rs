// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// `parse` over EVERY byte string up to 12 bytes (past every tag/length
/// form, with room for several TLVs including a truncated tail): never
/// panics, never overreads, always terminates, always materializes an
/// interface mask — the boot path relies on that — and **always yields a record
/// that serializes back into `PHY_MAX_SIZE`**.
///
/// The round-trip half is the one that is not a restatement of the parser. The
/// rescue write is read-modify-write (`merge_save`): whatever `parse` returns
/// for a host blob is what `serialize` has to put back, and a `None` there is
/// a device that took a `PHY` write, answered, and stored nothing — or, on the
/// boot path, one that can no longer rewrite its own configuration. The buffer
/// is `PHY_MAX_SIZE` because that is the size the callers declare.
#[kani::proof]
#[kani::unwind(14)]
fn parse_any_input() {
    const N: usize = 12;
    let data: [u8; N] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= N);
    let phy = PhyData::parse(&data[..n]);
    assert!(
        phy.enabled_usb_itf.is_some(),
        "no interface mask materialized"
    );
    let mut buf = [0u8; PHY_MAX_SIZE];
    assert!(
        phy.serialize(&mut buf).is_some(),
        "a host blob parsed into a record that cannot be stored back"
    );
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
/// of the stored record, so it must be as total as `parse` — and, the claim its
/// doc comment makes and this harness used to leave to prose, **omission never
/// clears**: a blob that does not carry a tag leaves that field exactly as it
/// was, and no blob at all can turn a stored scalar back into "absent".
///
/// This is the data-loss property. A PicoForge `PHY` write that sets one field
/// sends one TLV; if the merge dropped the rest, a host that changes the LED
/// count would silently erase the stored VID/PID, the product string and the
/// interface mask — a bricked-looking key from a successful write. The two
/// string fields are the deliberate exception: an explicit empty value clears
/// them, so their clause is conditioned on the tag being absent from the blob
/// rather than on the blob's shape (a sufficient condition, and one that needs
/// no second TLV decoder to state).
#[kani::proof]
#[kani::unwind(14)]
fn overlay_never_drops_a_stored_field() {
    const N: usize = 12;
    let data: [u8; N] = kani::any();
    let n: usize = kani::any();
    kani::assume(n <= N);
    let blob = &data[..n];

    // Every optional field present. The strings are concrete: the claim is about
    // a field surviving, not about what it holds.
    let base = PhyData {
        vid_pid: Some((kani::any(), kani::any())),
        led_gpio: Some(kani::any()),
        led_brightness: Some(kani::any()),
        opts: kani::any(),
        presence_timeout: Some(kani::any()),
        usb_product: Product::new(b"p"),
        usb_manufacturer: Product::new(b"m"),
        enabled_curves: Some(kani::any()),
        enabled_usb_itf: Some(kani::any()),
        led_driver: Some(kani::any()),
        led_order: Some(kani::any()),
        led_num: Some(kani::any()),
    };
    // Without this the two string clauses below would hold vacuously.
    assert!(base.usb_product.is_some() && base.usb_manufacturer.is_some());

    let merged = base.overlay(blob);

    // No host blob can turn a stored scalar into "absent" — every arm that
    // touches one writes a value.
    assert!(merged.vid_pid.is_some(), "vid/pid cleared by a merge");
    assert!(merged.led_gpio.is_some(), "led gpio cleared by a merge");
    assert!(
        merged.led_brightness.is_some(),
        "led brightness cleared by a merge"
    );
    assert!(
        merged.presence_timeout.is_some(),
        "presence timeout cleared"
    );
    assert!(merged.enabled_curves.is_some(), "enabled curves cleared");
    assert!(merged.enabled_usb_itf.is_some(), "interface mask cleared");
    assert!(merged.led_driver.is_some(), "led driver cleared");
    assert!(merged.led_order.is_some(), "led order cleared");
    assert!(merged.led_num.is_some(), "led count cleared");

    // A tag whose byte never appears in the blob cannot have been parsed as a
    // TLV, so its field must come through untouched — value and all.
    let absent = |tag: u8| !blob.contains(&tag);
    assert!(
        !absent(TAG_VIDPID) || merged.vid_pid == base.vid_pid,
        "vid/pid moved"
    );
    assert!(
        !absent(TAG_LED_GPIO) || merged.led_gpio == base.led_gpio,
        "gpio moved"
    );
    assert!(
        !absent(TAG_LED_BRIGHTNESS) || merged.led_brightness == base.led_brightness,
        "brightness moved"
    );
    assert!(!absent(TAG_OPTS) || merged.opts == base.opts, "opts moved");
    assert!(
        !absent(TAG_PRESENCE_TIMEOUT) || merged.presence_timeout == base.presence_timeout,
        "presence timeout moved"
    );
    assert!(
        !absent(TAG_ENABLED_CURVES) || merged.enabled_curves == base.enabled_curves,
        "curves moved"
    );
    assert!(
        !absent(TAG_ENABLED_USB_ITF) || merged.enabled_usb_itf == base.enabled_usb_itf,
        "interface mask moved"
    );
    assert!(
        !absent(TAG_LED_DRIVER) || merged.led_driver == base.led_driver,
        "led driver moved"
    );
    assert!(
        !absent(TAG_LED_ORDER) || merged.led_order == base.led_order,
        "order moved"
    );
    assert!(
        !absent(TAG_LED_NUM) || merged.led_num == base.led_num,
        "led count moved"
    );

    // The strings are asserted present, not equal. `Product` derives `PartialEq`
    // over its full 32-byte buffer, so `==` on one is a 32-byte memcmp that
    // pushes the unwind bound off the parser's depth and onto the buffer's —
    // the cost `serialize_parse_roundtrip` documents, and measured here as no
    // verdict in 20 minutes against 30 s for this form. Clearing is what the
    // merge must not do by omission; which bytes survive is the round-trip
    // harness's question.
    assert!(
        !absent(TAG_USB_PRODUCT) || merged.usb_product.is_some(),
        "product string cleared without its tag"
    );
    assert!(
        !absent(TAG_USB_MANUFACTURER) || merged.usb_manufacturer.is_some(),
        "manufacturer string cleared without its tag"
    );
    kani::cover!(
        merged.led_num != base.led_num,
        "a blob that actually changed something"
    );
}
