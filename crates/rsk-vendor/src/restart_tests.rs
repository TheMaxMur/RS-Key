// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::cut::sweep_restarts;
use rsk_fs::storage::faults::{Cut, CutMedium};

fn fixture() -> (Fs<Cut>, CutMedium) {
    let (storage, medium) = Cut::new();
    let mut fs = Fs::new(storage);
    fs.scan();
    fs.put(0xB000, b"another applet").unwrap();
    fs.meta_add(0xB000, b"metadata").unwrap();
    (fs, medium)
}

fn command(fs: &mut Fs<Cut>, ins: u8) -> (Sw, Vec<u8>) {
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = VendorApplet::new(FullPlatform::default(), &presence);
    let raw = apdu(ins, 63, 0x23, &[1, 7]);
    let mut out = [0; 256];
    let mut result = ResBuf::new(&mut out);
    let sw = app.process(&Apdu::parse(&raw).unwrap(), fs, &mut result);
    (sw, result.as_slice().to_vec())
}

#[test]
fn counter_and_led_writes_keep_their_durable_value_after_both_boots() {
    for ins in [INS_INCREMENT, INS_SET_LED] {
        let provision = || {
            let (mut fs, medium) = fixture();
            fs.put_counter(COUNTER_FID, &73u32.to_be_bytes()).unwrap();
            fs.put(EF_LED_CONF, &[0; CONF_LEN]).unwrap();
            (fs, medium)
        };
        let (mut reference, medium) = provision();
        assert_eq!(command(&mut reference, ins).0, Sw::OK);
        let expected = medium
            .value(if ins == INS_INCREMENT {
                COUNTER_FID.get()
            } else {
                EF_LED_CONF
            })
            .unwrap();
        assert!(!sweep_restarts(
            provision,
            |fs| command(fs, ins).0 == Sw::OK,
            |fs| {
                let _ = load_or_seed_led_config(fs, &[0; CONF_LEN], &mut [0; CONF_LEN]);
            },
            |fs, _, _, completed, medium| {
                let now = medium
                    .value(if ins == INS_INCREMENT {
                        COUNTER_FID.get()
                    } else {
                        EF_LED_CONF
                    })
                    .unwrap();
                let before = if ins == INS_INCREMENT {
                    73u32.to_be_bytes().to_vec()
                } else {
                    vec![0; CONF_LEN]
                };
                assert!(now == before || now == expected);
                if completed {
                    assert_eq!(now, expected);
                }
                assert_eq!(
                    medium.value(0xB000).as_deref(),
                    Some(&b"another applet"[..])
                );
                let mut meta = [0; 8];
                assert_eq!(fs.meta_find(0xB000, &mut meta), Some(8));
                assert_eq!(&meta, b"metadata");
            }
        ));
    }
}

#[test]
fn boot_led_seeding_can_be_interrupted_in_both_initialization_passes() {
    assert!(sweep_restarts(
        fixture,
        |fs| load_or_seed_led_config(fs, &[0x11; CONF_LEN], &mut [0; CONF_LEN]).is_ok(),
        |fs| {
            let _ = load_or_seed_led_config(fs, &[0x11; CONF_LEN], &mut [0; CONF_LEN]);
        },
        |fs, _, _, _, medium| {
            assert_eq!(medium.value(EF_LED_CONF), Some(vec![0x11; CONF_LEN]));
            let generation = fs.write_gen();
            load_or_seed_led_config(fs, &[0; CONF_LEN], &mut [0; CONF_LEN]).unwrap();
            assert_eq!(fs.write_gen(), generation);
        }
    ));
}
