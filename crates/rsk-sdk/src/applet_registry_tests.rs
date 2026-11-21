// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn applets_beyond_the_enabled_mask_stay_selectable() {
    const MASK_APPLETS: usize = u32::BITS as usize;
    let mut slots: [Echo; MASK_APPLETS + 1] = core::array::from_fn(|_| Echo { selected: false });
    let mut applets: Vec<&mut dyn Applet<()>> = slots
        .iter_mut()
        .map(|slot| slot as &mut dyn Applet<()>)
        .collect();
    let mut disp = Dispatcher::new();
    disp.set_enabled(0);
    let mut out = [0; 16];
    let mut res = ResBuf::new(&mut out);
    let select = [0, 0xA4, 4, 0, 8, 0xA0, 0, 0, 6, 0x47, 0x2F, 0, 1];
    assert_eq!(
        disp.process(&select, &mut applets, &mut (), &mut res),
        Sw::OK
    );
    assert_eq!(disp.current(), Some(MASK_APPLETS));
    assert_eq!(
        disp.process(
            &[0, 0x10, 0, 0, 2, 0x73, 0x64],
            &mut applets,
            &mut (),
            &mut res
        ),
        Sw::OK
    );
    assert_eq!(res.as_slice(), &[0x73, 0x64]);
    assert!(!slots[..MASK_APPLETS].iter().any(|slot| slot.selected));
    assert!(slots[MASK_APPLETS].selected);
}

#[test]
fn resetting_an_unregistered_applet_still_scrubs_both_transport_buffers() {
    for incoming in [false, true] {
        let mut app = Chunky {
            body_len: 32,
            chain: true,
        };
        let mut applets: [&mut dyn Applet<()>; 1] = [&mut app];
        let mut disp = Dispatcher::new();
        let mut out = [0; 64];
        let mut res = ResBuf::new(&mut out);
        select_chunky(&mut disp, &mut applets, &mut res);
        if incoming {
            assert_eq!(
                disp.process(
                    &[0x10, 0xCA, 0, 0, 3, 0x71, 0x72, 0x73],
                    &mut applets,
                    &mut (),
                    &mut res
                ),
                Sw::OK
            );
            assert_eq!(&disp.chain[..3], &[0x71, 0x72, 0x73]);
        } else {
            assert_eq!(
                disp.process(&[0, 0xCA, 0, 0, 1], &mut applets, &mut (), &mut res),
                Sw::new(0x61, 31)
            );
            assert!(disp.pending.iter().any(|&byte| byte != 0));
        }
        disp.reset_card::<()>(&mut [], &mut ());
        assert_eq!(disp.current(), None);
        assert!(!disp.chaining && !disp.response_owed());
        assert_eq!(disp.chain_len, 0);
        assert_eq!((disp.pending_len, disp.pending_off), (0, 0));
        assert!(disp.chain.iter().all(|&byte| byte == 0));
        assert!(disp.pending.iter().all(|&byte| byte == 0));
        assert_eq!(
            disp.process(
                &[0, INS_GET_RESPONSE, 0, 0, 1],
                &mut applets,
                &mut (),
                &mut res
            ),
            Sw::INS_NOT_SUPPORTED
        );
        assert!(res.is_empty());
    }
}
