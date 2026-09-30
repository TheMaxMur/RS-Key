// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect()
}

/// The device descriptor and the 174-byte configuration a no-touch image served
/// an in-process host (bcdDevice 0x0A88).
fn image() -> (Vec<u8>, Vec<u8>) {
    let dd = hex("12 01 10 02 ef 02 01 40 09 12 01 00 88 0a 01 02 03 01");
    let cfg = hex(
        "09 02 ae 00 03 01 00 80 32 08 0b 00 01 03 00 00 00 09 04 00 00 01 03 00 00 00 09 21 \
         10 01 00 01 22 50 00 07 05 81 03 08 00 0a 08 0b 01 01 03 00 00 00 09 04 01 00 02 03 \
         00 00 00 09 21 10 01 00 01 22 22 00 07 05 82 03 40 00 01 07 05 01 03 40 00 01 08 0b \
         02 01 0b 00 00 00 09 04 02 00 03 0b 00 00 00 36 21 10 01 00 01 03 00 00 00 fc 0d 00 \
         00 fc 0d 00 00 00 80 25 00 00 80 25 00 00 00 fe 00 00 00 00 00 00 00 00 00 00 00 40 \
         08 04 00 00 0c 00 00 ff ff 00 00 00 01 07 05 02 02 40 00 00 07 05 83 02 40 00 00 07 \
         05 84 03 40 00 0a",
    );
    (dd, cfg)
}

#[test]
fn the_image_configuration_parses_into_its_three_interfaces() {
    let (dd, cfg) = image();
    assert_eq!(cfg.len(), 174);
    let d = Device::new(dd, cfg).unwrap();
    assert_eq!((d.vid(), d.pid(), d.bcd()), (0x1209, 0x0001, 0x0A88));
    assert_eq!(d.class(), [0xEF, 0x02, 0x01]);
    assert_eq!(d.configuration_value(), 1);
    let classes: Vec<[u8; 3]> = d.interfaces.iter().map(|i| i.class).collect();
    assert_eq!(classes, [[3, 0, 0], [3, 0, 0], [0x0B, 0, 0]]);
    assert_eq!(d.interfaces[0].report_len, Some(0x50));
    assert_eq!(d.interfaces[1].report_len, Some(0x22));
    assert_eq!(
        d.interfaces[2].report_len, None,
        "CCID's class descriptor is not HID's"
    );
    assert_eq!(d.interfaces[1].interrupt_pair(), Some((2, 1)));
    assert_eq!(
        d.interfaces[0].interrupt_pair(),
        None,
        "the keyboard has no OUT"
    );
    assert_eq!(d.ccid(), Some((2, 3)));
}

#[test]
fn endpoints_carry_kind_size_interval_and_interface() {
    let (dd, cfg) = image();
    let eps = Device::new(dd, cfg).unwrap().endpoints();
    let find = |k: (u8, bool)| eps.iter().find(|(key, _)| *key == k).unwrap().1;
    let ccid_int = find((4, true));
    assert_eq!(
        (
            ccid_int.kind,
            ccid_int.mps,
            ccid_int.interval,
            ccid_int.interface
        ),
        (Kind::Interrupt, 64, 10, 2)
    );
    assert_eq!(find((3, true)).kind, Kind::Bulk);
    assert_eq!(find((2, false)).kind, Kind::Bulk, "EP2 OUT is CCID's bulk");
    assert_eq!(find((2, true)).kind, Kind::Interrupt, "EP2 IN is FIDO's");
    assert_eq!(eps.len(), 6);
}

#[test]
fn fido_is_found_by_usage_page() {
    assert!(is_fido_report(&hex("06 d0 f1 09 01 a1 01")));
    assert!(!is_fido_report(&hex("05 01 09 06 a1 01")));
}

#[test]
fn malformed_descriptors_are_refused() {
    let (dd, mut cfg) = image();
    assert!(Device::new(dd[..17].to_vec(), cfg.clone()).is_err());
    cfg[9] = 0; // an IAD's bLength
    assert!(parse_config(&cfg).is_err());
    assert!(parse_config(&hex("07 05 81 03 08 00 0a")).is_err());
    let lone_endpoint = hex("09 02 10 00 01 01 00 80 32 07 05 81 03 08 00 0a");
    assert!(parse_config(&lone_endpoint).is_err());
}
