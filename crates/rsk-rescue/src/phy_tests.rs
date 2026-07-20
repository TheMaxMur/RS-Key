// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn roundtrip_all_fields() {
    let phy = PhyData {
        vid_pid: Some((0x1050, 0x0407)),
        led_gpio: Some(16),
        led_brightness: Some(200),
        opts: OPT_LED_STEADY | OPT_DIMM,
        presence_timeout: Some(20),
        usb_product: Product::new(b"RSK Custom"),
        enabled_curves: Some(0x3FF),
        enabled_usb_itf: Some(USB_ITF_CCID | USB_ITF_HID),
        led_driver: Some(3),
        led_order: Some(LED_ORDER_GRB),
        led_num: Some(4),
    };
    let mut buf = [0u8; PHY_MAX_SIZE];
    let n = phy.serialize(&mut buf).unwrap();
    assert_eq!(PhyData::parse(&buf[..n]), phy);
}

#[test]
fn vidpid_wire_is_big_endian() {
    let phy = PhyData {
        vid_pid: Some((0x1050, 0x0407)),
        ..Default::default()
    };
    let mut buf = [0u8; PHY_MAX_SIZE];
    let n = phy.serialize(&mut buf).unwrap();
    // VIDPID TLV first: tag 0, len 4, VID be, PID be.
    assert_eq!(
        &buf[..n],
        &[
            0x00, 0x04, 0x10, 0x50, 0x04, 0x07, TAG_OPTS, 0x02, 0x00, 0x00
        ]
    );
}

#[test]
fn parse_defaults_usb_itf_to_all() {
    let phy = PhyData::parse(&[]);
    assert_eq!(phy.enabled_usb_itf, Some(USB_ITF_ALL));
    assert_eq!(phy.vid_pid, None);
    assert_eq!(phy.opts, 0);
}

#[test]
fn effective_usb_itf_applies_mask_but_guards_lockout() {
    let mut phy = PhyData::default();
    // No record / no TLV → ALL.
    assert_eq!(effective_usb_itf(&phy), USB_ITF_ALL);
    // Any mask keeping at least one management-capable interface (CCID or HID)
    // applies verbatim.
    phy.enabled_usb_itf = Some(USB_ITF_CCID | USB_ITF_HID);
    assert_eq!(effective_usb_itf(&phy), USB_ITF_CCID | USB_ITF_HID);
    phy.enabled_usb_itf = Some(USB_ITF_CCID | USB_ITF_KB);
    assert_eq!(effective_usb_itf(&phy), USB_ITF_CCID | USB_ITF_KB);
    // A mask that leaves NO management-capable interface would strand the device
    // with no software path to rewrite the record → falls back to ALL. A
    // keyboard-only mask is the key case: "supported" yet management-incapable.
    phy.enabled_usb_itf = Some(USB_ITF_KB);
    assert_eq!(effective_usb_itf(&phy), USB_ITF_ALL);
    phy.enabled_usb_itf = Some(0);
    assert_eq!(effective_usb_itf(&phy), USB_ITF_ALL);
    phy.enabled_usb_itf = Some(USB_ITF_WCID | USB_ITF_LWIP);
    assert_eq!(effective_usb_itf(&phy), USB_ITF_ALL);
}

#[test]
fn parse_skips_unknown_tags_and_truncation_is_safe() {
    // Unknown tag 0x7F (3 bytes), then a valid LED_GPIO, then a TLV whose
    // length runs past the input.
    let phy = PhyData::parse(&[0x7F, 3, 1, 2, 3, TAG_LED_GPIO, 1, 9, TAG_OPTS, 2, 0xAA]);
    assert_eq!(phy.led_gpio, Some(9));
    assert_eq!(phy.opts, 0); // truncated OPTS ignored
}

#[test]
fn product_string_stops_at_nul_and_caps_at_32() {
    let phy = PhyData::parse(&[TAG_USB_PRODUCT, 5, b'a', b'b', 0, b'c', 0]);
    assert_eq!(phy.usb_product.unwrap().as_bytes(), b"ab");
    assert!(Product::new(&[b'x'; 33]).is_none());
    assert!(Product::new(b"").is_none());
}

#[test]
fn save_and_load() {
    let mut fs = rsk_fs::Fs::new(rsk_fs::storage::ram::RamStorage::new());
    assert!(load(&mut fs).is_none());
    let phy = PhyData {
        led_brightness: Some(50),
        opts: OPT_LED_STEADY,
        ..Default::default()
    };
    save(&mut fs, &phy).unwrap();
    let got = load(&mut fs).unwrap();
    assert_eq!(got.led_brightness, Some(50));
    assert_eq!(got.opts, OPT_LED_STEADY);
    // The load-time default materializes ITF_ALL.
    assert_eq!(got.enabled_usb_itf, Some(USB_ITF_ALL));
}

#[test]
fn overlay_preserves_untouched_tags() {
    let base = PhyData {
        vid_pid: Some((0x1050, 0x0407)),
        usb_product: Product::new(b"Yubico YubiKey OTP+FIDO+CCID"),
        led_order: Some(LED_ORDER_GRB),
        led_num: Some(3),
        opts: OPT_LED_STEADY,
        enabled_usb_itf: Some(USB_ITF_ALL),
        ..Default::default()
    };
    // A partial write that changes only VID/PID (tag 0x00).
    let merged = base.overlay(&[TAG_VIDPID, 4, 0x12, 0x34, 0x56, 0x78]);
    assert_eq!(merged.vid_pid, Some((0x1234, 0x5678)));
    // Everything the host omitted survives — the picoforge#102 / RS-Key#33 bug.
    assert_eq!(
        merged.usb_product,
        Product::new(b"Yubico YubiKey OTP+FIDO+CCID")
    );
    assert_eq!(merged.led_order, Some(LED_ORDER_GRB));
    assert_eq!(merged.led_num, Some(3));
    assert_eq!(merged.opts, OPT_LED_STEADY);
}

#[test]
fn overlay_opts_only_changes_when_tag_present() {
    let base = PhyData {
        opts: OPT_LED_STEADY,
        ..Default::default()
    };
    // No OPTS tag → opts preserved (a full `parse` would zero it — that is the
    // reason overlay must key on physical tag presence, not the parsed struct).
    assert_eq!(base.overlay(&[TAG_LED_GPIO, 1, 7]).opts, OPT_LED_STEADY);
    // An explicit OPTS=0 TLV clears it.
    assert_eq!(base.overlay(&[TAG_OPTS, 2, 0, 0]).opts, 0);
}

#[test]
fn merge_save_does_not_wipe_stored_tags() {
    let mut fs = rsk_fs::Fs::new(rsk_fs::storage::ram::RamStorage::new());
    save(
        &mut fs,
        &PhyData {
            vid_pid: Some((0x1050, 0x0407)),
            usb_product: Product::new(b"Yubico YubiKey OTP+FIDO+CCID"),
            led_order: Some(LED_ORDER_GRB),
            ..Default::default()
        },
    )
    .unwrap();
    // A later VID/PID-only write must not reset the product or LED order.
    merge_save(&mut fs, &[TAG_VIDPID, 4, 0x00, 0x00, 0x00, 0x00]).unwrap();
    let got = load(&mut fs).unwrap();
    assert_eq!(got.vid_pid, Some((0x0000, 0x0000)));
    assert_eq!(
        got.usb_product,
        Product::new(b"Yubico YubiKey OTP+FIDO+CCID")
    );
    assert_eq!(got.led_order, Some(LED_ORDER_GRB));
}

#[test]
fn normalize_appends_ccid_token_to_tokenless_yubikey_name() {
    let mut out = [0u8; 64];
    let n = normalize_usb_product(b"Yubico YubiKey", &mut out);
    assert_eq!(&out[..n], b"Yubico YubiKey OTP+FIDO+CCID");
    // Case-insensitive "yubikey" match; a lowercase 'ccid' is not the token ykman
    // scans for, so the uppercase token is still appended.
    let n = normalize_usb_product(b"my yubikey", &mut out);
    assert_eq!(&out[..n], b"my yubikey OTP+FIDO+CCID");
}

#[test]
fn normalize_leaves_compliant_or_non_yubikey_names_untouched() {
    let mut out = [0u8; 64];
    let n = normalize_usb_product(b"Yubico YubiKey OTP+FIDO+CCID", &mut out);
    assert_eq!(&out[..n], b"Yubico YubiKey OTP+FIDO+CCID");
    let n = normalize_usb_product(b"RS-Key Security Key", &mut out);
    assert_eq!(&out[..n], b"RS-Key Security Key");
}
