// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::cut::sweep_restarts;
use rsk_fs::storage::faults::Cut;

#[test]
fn save_merge_and_single_field_updates_preserve_the_declared_record_after_both_boots() {
    for operation in 0..3 {
        let old = PhyData {
            vid_pid: Some((0x1209, 0xF1D2)),
            led_gpio: Some(16),
            led_brightness: Some(63),
            usb_product: Product::new(b"Owner device"),
            enabled_usb_itf: Some(USB_ITF_ALL),
            ..Default::default()
        };
        let new = PhyData {
            led_brightness: Some(127),
            ..old
        };
        let command = |fs: &mut Fs<Cut>| match operation {
            0 => save(fs, &new),
            1 => merge_save(fs, &[TAG_LED_BRIGHTNESS, 1, 127]),
            _ => update(fs, |phy| phy.led_brightness = Some(127)),
        };
        assert!(!sweep_restarts(
            || {
                let (storage, medium) = Cut::new();
                let mut fs = Fs::new(storage);
                fs.scan();
                save(&mut fs, &old).unwrap();
                fs.put(0xB000, b"another applet").unwrap();
                (fs, medium)
            },
            |fs| command(fs).is_ok(),
            |_| {},
            |fs, _, _, completed, medium| {
                let value = try_load(fs).unwrap().unwrap();
                assert!(value == old || value == new);
                if completed {
                    assert_eq!(value, new);
                }
                assert_eq!(value.vid_pid, old.vid_pid);
                assert_eq!(value.led_gpio, old.led_gpio);
                assert_eq!(value.usb_product, old.usb_product);
                assert_eq!(
                    medium.value(0xB000).as_deref(),
                    Some(&b"another applet"[..])
                );
            }
        ));
    }
}
