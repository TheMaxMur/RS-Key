// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
#[test]
fn boot_identity_preserves_phy_values_and_yubico_atr() {
    let original =
        Identity::new(0x1050, 0x0407, 0x0aaa, 5, true, "Maker", "Key", "serial").unwrap();
    assert_eq!(original.bytes().len(), 171);
    assert_eq!(
        original.bytes().get(..11),
        Some([0x50, 0x10, 0x07, 0x04, 0xaa, 0x0a, 5, 1, 5, 3, 6].as_slice())
    );
    let identity = Identity::from_bytes(*original.bytes()).unwrap();
    assert_eq!(
        (identity.vid(), identity.pid(), identity.release()),
        (Some(0x1050), Some(0x0407), Some(0x0aaa))
    );
    assert_eq!(identity.interfaces(), 5);
    assert!(identity.yubico_atr());
    assert_eq!(identity.manufacturer(), Some("Maker"));
    assert_eq!(identity.product(), Some("Key"));
    assert_eq!(identity.serial(), Some("serial"));
    assert!(
        !Identity::new(0x1209, 0xf1d2, 0, 7, false, "", "", "")
            .unwrap()
            .yubico_atr()
    );
}
#[test]
fn invalid_string_lengths_and_utf8_are_refused() {
    assert!(Identity::new(0, 0, 0, 0, false, &"a".repeat(STRING_BYTES + 1), "", "").is_none());
    let identity = Identity::new(0, 0, 0, 0, false, "m", "p", "s").unwrap();
    for (index, capacity) in [(8, STRING_BYTES), (9, STRING_BYTES), (10, SERIAL_BYTES)] {
        let mut bytes = *identity.bytes();
        *bytes.get_mut(index).unwrap() = u8::try_from(capacity + 1).unwrap();
        assert!(Identity::from_bytes(bytes).is_none());
    }
    for offset in [HEADER, HEADER + STRING_BYTES, HEADER + 2 * STRING_BYTES] {
        let mut bytes = *identity.bytes();
        *bytes.get_mut(offset).unwrap() = 0xff;
        assert!(Identity::from_bytes(bytes).is_none());
    }
}

#[test]
fn descriptor_capacities_are_inclusive_and_padding_is_zero() {
    let manufacturer = "m".repeat(STRING_BYTES);
    let product = "p".repeat(STRING_BYTES);
    let serial = "s".repeat(SERIAL_BYTES);
    let identity = Identity::new(1, 2, 3, 4, false, &manufacturer, &product, &serial).unwrap();
    assert_eq!(identity.manufacturer(), Some(manufacturer.as_str()));
    assert_eq!(identity.product(), Some(product.as_str()));
    assert_eq!(identity.serial(), Some(serial.as_str()));
    assert!(Identity::new(1, 2, 3, 4, false, "", &(product + "p"), "").is_none());
    assert!(Identity::new(1, 2, 3, 4, false, "", "", &(serial + "s")).is_none());
    let short = Identity::new(0, 0, 0, 0, false, "", "", "").unwrap();
    assert_eq!(short.bytes(), &[0; SIZE]);
}

#[test]
fn pinpad_capability_and_atr_flags_are_independent() {
    for yubico in [false, true] {
        for pinpad in [false, true] {
            let identity = Identity::new(1, 2, 3, 4, yubico, "", "", "")
                .unwrap()
                .with_pinpad_verify(pinpad)
                .unwrap();
            assert_eq!(identity.yubico_atr(), yubico);
            assert_eq!(identity.pinpad_verify(), pinpad);
            let identity = identity.with_pinpad_verify(pinpad).unwrap();
            assert_eq!(identity.pinpad_verify(), pinpad);
            assert_eq!(identity.yubico_atr(), yubico);
            let identity = identity.with_pinpad_verify(false).unwrap();
            assert!(!identity.pinpad_verify());
            assert_eq!(identity.yubico_atr(), yubico);
        }
    }
}
