// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

struct ProprietaryEcho;

impl Applet<()> for ProprietaryEcho {
    fn aid(&self) -> &'static [u8] {
        &[0xa0, 0, 0, 6, 0x47, 0x2f, 0, 1]
    }
    fn select(&mut self, _: bool, _: &mut (), _: &mut ResBuf) -> Sw {
        Sw::OK
    }
    fn process(&mut self, apdu: &Apdu, _: &mut (), response: &mut ResBuf) -> Sw {
        if apdu.cla != 0x80 {
            return Sw::CLA_NOT_SUPPORTED;
        }
        assert!(response.extend(apdu.data));
        Sw::OK
    }
}

#[test]
fn a_proprietary_chain_preserves_its_class_and_resets_its_open_state() {
    let mut applet = ProprietaryEcho;
    let mut applets: [&mut dyn Applet<()>; 1] = [&mut applet];
    let mut dispatcher = Dispatcher::new();
    let mut out = [0; 64];
    let mut response = ResBuf::new(&mut out);
    let select = [0, 0xa4, 4, 0, 8, 0xa0, 0, 0, 6, 0x47, 0x2f, 0, 1];
    assert_eq!(
        dispatcher.process(&select, &mut applets, &mut (), &mut response),
        Sw::OK
    );
    let segment = [0x90, 0x10, 0, 0, 1, 0xaa];
    assert_eq!(
        dispatcher.process(&segment, &mut applets, &mut (), &mut response),
        Sw::OK
    );
    assert!(dispatcher.chain_open());
    assert_eq!(
        dispatcher.process(
            &[0x80, 0x10, 0, 0, 1, 0xbb],
            &mut applets,
            &mut (),
            &mut response
        ),
        Sw::OK
    );
    assert_eq!(response.as_slice(), &[0xaa, 0xbb]);
    assert!(!dispatcher.chain_open());
    assert_eq!(
        dispatcher.process(&segment, &mut applets, &mut (), &mut response),
        Sw::OK
    );
    dispatcher.clear_chaining();
    assert!(!dispatcher.chain_open());
    assert_eq!(
        dispatcher.process(&segment, &mut applets, &mut (), &mut response),
        Sw::OK
    );
    dispatcher.reset_card(&mut applets, &mut ());
    assert!(!dispatcher.chain_open());
}
