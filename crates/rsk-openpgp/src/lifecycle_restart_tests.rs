// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::cut::sweep_restarts;

#[test]
fn terminate_and_activate_survive_a_second_interrupted_activation() {
    for activating in [false, true] {
        assert!(sweep_restarts(
            || {
                let (storage, medium) = Cut::new();
                let mut fs = boot(storage);
                let rng = RefCell::new(CountRng(0));
                let presence = RefCell::new(crate::AlwaysConfirm);
                let mut card = Card::new(&rng, &presence);
                assert_eq!(card.send(&mut fs, SELECT).1, Sw::OK);
                assert_eq!(
                    card.send(&mut fs, &verify(consts::PW3_MODE83, consts::PW3_DEFAULT))
                        .1,
                    Sw::OK
                );
                assert_eq!(card.send(&mut fs, PUT_LOGIN).1, Sw::OK);
                let attr = &crate::dobj::ATTR_P256R1[1..];
                let mut put = vec![
                    0,
                    consts::INS_PUT_DATA,
                    0,
                    0xC1,
                    u8::try_from(attr.len()).unwrap(),
                ];
                put.extend(attr);
                assert_eq!(card.send(&mut fs, &put).1, Sw::OK);
                assert_eq!(
                    card.send(&mut fs, &[0, consts::INS_KEYPAIR_GEN, 0x80, 0, 2, 0xB6, 0])
                        .1,
                    Sw::OK
                );
                fs.put(0xB000, b"another applet").unwrap();
                fs.meta_add(0xB000, b"metadata").unwrap();
                if activating {
                    assert_eq!(card.send(&mut fs, TERMINATE).1, Sw::OK);
                }
                (fs, medium)
            },
            |fs| {
                let rng = RefCell::new(CountRng(71));
                let presence = RefCell::new(crate::AlwaysConfirm);
                let mut card = Card::new(&rng, &presence);
                let _ = card.send(fs, SELECT);
                if !activating
                    && card
                        .send(fs, &verify(consts::PW3_MODE83, consts::PW3_DEFAULT))
                        .1
                        != Sw::OK
                {
                    return false;
                }
                card.send(fs, if activating { ACTIVATE } else { TERMINATE })
                    .1
                    == Sw::OK
            },
            |fs| {
                let _ = scan_files(&dev(), fs, &mut CountRng(91));
                let rng = RefCell::new(CountRng(71));
                let presence = RefCell::new(crate::AlwaysConfirm);
                let mut card = Card::new(&rng, &presence);
                if fs.has_data(consts::EF_TERMINATED) {
                    assert_eq!(card.send(fs, SELECT).1, Sw::TERMINATED);
                    assert_eq!(card.send(fs, GET_LOGIN).1, Sw::TERMINATED);
                } else {
                    let _ = card.send(fs, SELECT);
                }
                let _ = card.send(fs, ACTIVATE);
            },
            |fs, _, _, completed, medium| {
                assert!(!fs.has_data(consts::EF_TERMINATED));
                let login = medium.value(consts::EF_LOGIN_DATA);
                assert!(login.is_none() || login.as_deref() == Some(&b"alice"[..]));
                if activating || completed {
                    assert!(login.is_none());
                    assert!(!fs.has_key(consts::EF_PK_SIG));
                }
                let rng = RefCell::new(CountRng(71));
                let presence = RefCell::new(crate::AlwaysConfirm);
                let mut card = Card::new(&rng, &presence);
                assert_eq!(card.send(fs, SELECT).1, Sw::OK);
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
