// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn case1() {
    let a = Apdu::parse(&[0x00, 0xA4, 0x04, 0x00]).unwrap();
    assert_eq!((a.cla, a.ins, a.p1, a.p2), (0x00, 0xA4, 0x04, 0x00));
    assert_eq!(a.nc, 0);
    assert_eq!(a.ne, 256);
    assert!(a.data.is_empty());
}

#[test]
fn case2_short() {
    let a = Apdu::parse(&[0x00, 0xC0, 0x00, 0x00, 0x10]).unwrap();
    assert_eq!(a.nc, 0);
    assert_eq!(a.ne, 0x10);
}

#[test]
fn case3_short() {
    // SELECT by AID: CLA INS P1 P2 Lc=5 data...
    let raw = [0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x06, 0x47];
    let a = Apdu::parse(&raw).unwrap();
    assert_eq!(a.nc, 5);
    assert_eq!(a.data, &[0xA0, 0x00, 0x00, 0x06, 0x47]);
    assert_eq!(a.ne, 0);
}

#[test]
fn case4_short() {
    // Lc=2 data, then Le
    let raw = [0x00, 0x01, 0x00, 0x00, 0x02, 0xDE, 0xAD, 0x40];
    let a = Apdu::parse(&raw).unwrap();
    assert_eq!(a.nc, 2);
    assert_eq!(a.data, &[0xDE, 0xAD]);
    assert_eq!(a.ne, 0x40);
}

#[test]
fn case2_extended() {
    // 00 B0 0000 00 <Le16=0x0200>
    let raw = [0x00, 0xB0, 0x00, 0x00, 0x00, 0x02, 0x00];
    let a = Apdu::parse(&raw).unwrap();
    assert_eq!(a.nc, 0);
    assert_eq!(a.ne, 0x0200);
}

#[test]
fn case3_extended() {
    // 00 01 0000 00 <Lc16=0x0003> data[3]
    let raw = [0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC];
    let a = Apdu::parse(&raw).unwrap();
    assert_eq!(a.nc, 3);
    assert_eq!(a.data, &[0xAA, 0xBB, 0xCC]);
}

#[test]
fn case4_extended() {
    // 00 01 0000 00 <Lc16=2> AA BB <Le16=0x0100>
    let raw = [
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB, 0x01, 0x00,
    ];
    let a = Apdu::parse(&raw).unwrap();
    assert_eq!(a.nc, 2);
    assert_eq!(a.data, &[0xAA, 0xBB]);
    assert_eq!(a.ne, 0x0100);
}

#[test]
fn case2_extended_le_zero_is_65536() {
    // 00 B0 0000 00 <Le16=0> → Ne normalised to 65536.
    let a = Apdu::parse(&[0x00, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x00]).unwrap();
    assert_eq!(a.nc, 0);
    assert_eq!(a.ne, 65536);
}

#[test]
fn case2_short_le_zero_is_256() {
    // Le byte 0 → Ne 256.
    let a = Apdu::parse(&[0x00, 0xC0, 0x00, 0x00, 0x00]).unwrap();
    assert_eq!(a.ne, 256);
}

#[test]
fn extended_bad_lc() {
    // Extended Lc=16 but only 1 data byte present → WrongLength.
    let raw = [0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10, 0xAA];
    assert_eq!(Apdu::parse(&raw).err(), Some(Error::WrongLength));
}

#[test]
fn extended_marker_too_short_is_short_lc() {
    // Leading 0 but only 6 bytes: too short for extended, decoded as short Le.
    let a = Apdu::parse(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x10]).unwrap();
    assert_eq!(a.nc, 0);
    assert_eq!(a.ne, 0x10);
    assert!(a.data.is_empty());
}

#[test]
fn chaining_flag() {
    // CLA bit 0x10 marks a chaining segment.
    assert!(
        Apdu::parse(&[0x10, 0x01, 0x00, 0x00])
            .unwrap()
            .is_chaining()
    );
    assert!(
        !Apdu::parse(&[0x00, 0x01, 0x00, 0x00])
            .unwrap()
            .is_chaining()
    );
}

#[test]
fn too_short() {
    assert_eq!(Apdu::parse(&[0x00, 0x01]), Err(Error::WrongLength));
}

#[test]
fn bad_lc() {
    // Lc says 10 but only 1 data byte follows (size 6 → short-Lc branch)
    assert_eq!(
        Apdu::parse(&[0x00, 0x01, 0x00, 0x00, 0x0A, 0xAA]).err(),
        Some(Error::WrongLength)
    );
}

#[test]
fn an_extended_lc_is_the_whole_16_bit_value_never_its_low_byte() {
    // ⛔ Measured on a YubiKey 5.7.4, 3/3, writing a private-use DO: an extended
    // `Lc` is truncated **modulo 256** and the card still answers `9000` — 300
    // bytes store 44, 256 bytes store 0, while 200 and 254 are exact (the control
    // proving extended `Lc` is otherwise honoured on that path). That is silent
    // data loss, and the standing carve-out on the parity rule is that a YubiKey
    // behaviour which loses user data is never adopted. This test exists so a
    // later parity sweep cannot "fix" us into it: each row below is a length
    // whose low byte differs from the length itself.
    for nc in [200usize, 254, 255, 256, 300, 0x0100, 0x012C, 0x0200, 2038] {
        let mut raw = vec![0x00, 0xDA, 0x01, 0x01, 0x00];
        raw.extend_from_slice(&(nc as u16).to_be_bytes());
        raw.extend((0..nc).map(|i| i as u8));
        let a = Apdu::parse(&raw).unwrap();
        assert_eq!(a.nc, nc, "extended Lc {nc} decoded as {}", a.nc);
        assert_eq!(a.data.len(), nc);
        assert_eq!(a.data.last(), Some(&((nc - 1) as u8)), "body truncated");
    }
}
