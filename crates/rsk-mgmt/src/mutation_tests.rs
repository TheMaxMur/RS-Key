// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn strict_request_bounds_precede_presence_without_writing_configuration() {
    let presence = RefCell::new(DenyPresence);
    let mut app = ManagementApplet::new([0; 8], &presence);
    let mut fs = fs();
    let original = [TAG_DEVICE_FLAGS, 1, 0x10];
    fs.put(EF_DEV_CONF, &original).unwrap();
    let generation = fs.write_gen();
    for (len, expected) in [
        (127, Sw::CONDITIONS_NOT_SATISFIED),
        (128, Sw::CONDITIONS_NOT_SATISFIED),
        (129, Sw::WRONG_DATA),
    ] {
        assert_eq!(write_config(&mut app, &mut fs, &vec![0; len]), expected);
        assert_eq!(fs.write_gen(), generation);
        let mut record = [0; 3];
        assert_eq!(fs.read(EF_DEV_CONF, &mut record), Some(3));
        assert_eq!(record, original);
    }
}

#[test]
fn strict_presence_declines_and_confirms_actual_configuration_writes() {
    let declined = RefCell::new(DenyPresence);
    let confirmed = RefCell::new(AlwaysConfirm);
    let cases: [(&RefCell<dyn UserPresence>, Sw); 2] = [
        (&declined, Sw::CONDITIONS_NOT_SATISFIED),
        (&confirmed, Sw::OK),
    ];
    for (presence, expected) in cases {
        let mut app = ManagementApplet::new([0; 8], presence);
        let mut fs = fs();
        let original = [TAG_DEVICE_FLAGS, 1, 0x10];
        let replacement = [TAG_DEVICE_FLAGS, 1, 0x20];
        fs.put(EF_DEV_CONF, &original).unwrap();
        let generation = fs.write_gen();
        assert_eq!(write_config(&mut app, &mut fs, &replacement), expected);
        let mut record = [0; 3];
        assert_eq!(fs.read(EF_DEV_CONF, &mut record), Some(3));
        if expected == Sw::OK {
            assert_eq!(record, replacement);
            assert_eq!(fs.write_gen(), generation + 1);
        } else {
            assert_eq!(record, original);
            assert_eq!(fs.write_gen(), generation);
        }
    }
}
