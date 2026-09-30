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
fn a_two_byte_body_under_00_is_one_16_bit_le() {
    // Too short for an extended case, and no short one: a YubiKey 5.8.0 reads `00 xx`
    // as the Le `00xx` (measured 2026-09-30). `00 00` is 65536 by that reading, unmeasured.
    let a = Apdu::parse(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x10]).unwrap();
    assert_eq!((a.nc, a.ne, a.extended), (0, 0x10, true));
    assert!(a.data.is_empty());
    let a = Apdu::parse(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00]).unwrap();
    assert_eq!((a.nc, a.ne, a.extended), (0, 65536, true));
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

/// The classes a YubiKey 5.8.0's CCID layer passed on, read off it one by one:
/// `00`, `04`, `80`, `84`, and all 128 with the chaining bit.
#[test]
fn the_classes_served_over_ccid_are_a_yubikeys() {
    let served: std::vec::Vec<u8> = (0..=0xFFu8)
        .filter(|&cla| {
            Apdu::parse(&[cla, 0xA4, 0x04, 0x00])
                .unwrap()
                .is_served_over_ccid()
        })
        .collect();
    let chaining = (0..=0xFFu8).filter(|c| c & 0x10 != 0);
    let mut want: std::vec::Vec<u8> = [0x00, 0x04, 0x80, 0x84]
        .into_iter()
        .chain(chaining)
        .collect();
    want.sort_unstable();
    assert_eq!(served, want);
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

/// `extended` records the length ENCODING, which `ne` cannot say once `Le` is
/// absent: a short case 3 and an extended one both leave `ne` 0.
#[test]
fn extended_records_the_encoding_where_ne_cannot() {
    for (raw, extended, ne) in [
        (&[0x00, 0xA1, 0, 0][..], false, 256),
        (&[0x00, 0xA1, 0, 0, 0x00], false, 256),
        (&[0x00, 0xA4, 0, 1, 0x01, 0x74], false, 0),
        (&[0x00, 0xA4, 0, 1, 0x00, 0x00, 0x01, 0x74], true, 0),
        (&[0x00, 0xA1, 0, 0, 0x00, 0x00, 0x00], true, 65536),
        (
            &[0x00, 0xA4, 0, 1, 0x00, 0x00, 0x01, 0x74, 0x00, 0x10],
            true,
            16,
        ),
    ] {
        let a = Apdu::parse(raw).unwrap();
        assert_eq!((a.extended, a.ne), (extended, ne), "{raw:02X?}");
    }
}

/// `"00A4 0400 05"` → bytes; spaces are for the reader.
fn hex(s: &str) -> std::vec::Vec<u8> {
    let digits: std::vec::Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    digits
        .chunks(2)
        .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

/// YubiKey 5.8.0, measured 2026-09-30 over raw USB CCID: a body that fits no case
/// is `6700`, bytes past `Le` included. Two shapes outside ISO 7816-4 are read:
/// `00 xx` as one 16-bit Le, and a case 2E and two bytes as a case 4E with Lc 0.
#[test]
fn a_body_that_fits_no_case_is_refused_as_a_yubikey_refuses_it() {
    // `Some((Nc, Ne))` where the YubiKey ran the command, `None` for its `6700`.
    let rows: [(&str, Option<(usize, usize)>); 12] = [
        ("00A40400 07 A0000005272101 00", Some((7, 256))),
        ("00A40400 07 A0000005272101", Some((7, 0))),
        ("00A40400 07 A0000005272101 00 AA", None),
        ("00A40400 07 A0000005272101 00 AABB", None),
        ("00A40400 000007 A0000005272101 0000 AA", None),
        ("00CA006E 00", Some((0, 256))),
        ("00CA006E 00AA", Some((0, 0xAA))),
        ("00CA006E 10AA", None),
        ("00CA006E 000000", Some((0, 65536))),
        ("00CA006E 000000 AA", None),
        ("00CA006E 000000 AABB", Some((0, 0xAABB))),
        ("00A40400 05 A0", None),
    ];
    let wrong: std::vec::Vec<_> = rows
        .into_iter()
        .map(|(raw, want)| {
            let got = Apdu::parse(&hex(raw)).map(|a| (a.nc, a.ne));
            (raw, got, want.ok_or(Error::WrongLength))
        })
        .filter(|(_, got, want)| got != want)
        .collect();
    assert!(wrong.is_empty(), "(APDU, parsed, the YubiKey's): {wrong:?}");
}
