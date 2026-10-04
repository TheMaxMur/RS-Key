// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn walk_two_objects() {
    // 0x5A len2 [aa bb], 0x9F1F (2-byte tag) len1 [cc]
    let data = [0x5A, 0x02, 0xAA, 0xBB, 0x9F, 0x1F, 0x01, 0xCC];
    let items: Vec<_> = Tlv::new(&data).collect();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0], (0x5A, &[0xAA, 0xBB][..]));
    assert_eq!(items[1], (0x9F1F, &[0xCC][..]));
}

#[test]
fn find_and_long_len() {
    // tag 0x70, length 0x81 0x80 (128 bytes)
    let mut data = [0u8; 3 + 128];
    data[0] = 0x70;
    data[1] = 0x81;
    data[2] = 0x80;
    let v = find_tag(&data, 0x70).unwrap();
    assert_eq!(v.len(), 128);
    assert!(find_tag(&data, 0x71).is_none());
}

#[test]
fn truncated_is_none() {
    // claims 5 bytes but only 2 present
    let data = [0x5A, 0x05, 0x01, 0x02];
    assert_eq!(Tlv::new(&data).count(), 0);
}

#[test]
fn format_len_roundtrip() {
    let mut buf = [0u8; 3];
    assert_eq!(format_len(10, &mut buf), 1);
    assert_eq!(buf[0], 10);
    assert_eq!(format_len(200, &mut buf), 2);
    assert_eq!(&buf[..2], &[0x81, 200]);
    assert_eq!(format_len(0x1234, &mut buf), 3);
    assert_eq!(&buf[..3], &[0x82, 0x12, 0x34]);
}

#[test]
fn encoded_size_matches_the_wire_on_every_length_boundary() {
    for len in [0, 1, 127, 128, 255, 256, u16::MAX] {
        for tag in [0x5a_u16, 0x9f1f] {
            let mut wire = if tag > 255 {
                tag.to_be_bytes().to_vec()
            } else {
                vec![tag as u8]
            };
            let mut header = [0; 3];
            let size = format_len(len, &mut header);
            assert_eq!(format_len_size(std::hint::black_box(len)), size);
            wire.extend(&header[..size]);
            wire.extend(vec![0x55; usize::from(len)]);
            assert_eq!(len_tag(std::hint::black_box(tag), len), wire.len());
            assert_eq!(
                Tlv::new(&wire).collect::<Vec<_>>(),
                [(tag, &wire[wire.len() - usize::from(len)..])]
            );
        }
    }
}
