// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use minicbor::{Decoder, encode::write::Cursor};

#[test]
fn every_direct_verification_and_presence_combination_encodes_only_its_factors() {
    for (method, up, factors) in [
        (Method::None, false, &[0x0200_u32][..]),
        (Method::None, true, &[0x0001][..]),
        (Method::PasscodeExternal, false, &[0x0800][..]),
        (Method::PasscodeInternal, false, &[0x0004][..]),
        (Method::PasscodeExternal, true, &[0x0001, 0x0800][..]),
        (Method::PasscodeInternal, true, &[0x0001, 0x0004][..]),
    ] {
        let mut bytes = [0; 64];
        let written = {
            let mut enc = Encoder::new(Cursor::new(bytes.as_mut_slice()));
            write(&mut enc, method, up).unwrap();
            enc.writer().position()
        };
        let mut decoder = Decoder::new(bytes.get(..written).unwrap());
        assert_eq!(decoder.str().unwrap(), "uvm");
        assert_eq!(
            decoder.array().unwrap(),
            Some(u64::try_from(factors.len()).unwrap())
        );
        for &factor in factors {
            assert_eq!(decoder.array().unwrap(), Some(3));
            assert_eq!(decoder.u32().unwrap(), factor);
            assert_eq!(decoder.u16().unwrap(), 2);
            assert_eq!(decoder.u16().unwrap(), 4);
        }
        assert_eq!(decoder.position(), written);
    }
}
