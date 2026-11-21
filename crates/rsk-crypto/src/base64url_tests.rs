// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn enc(src: &[u8]) -> std::string::String {
    let mut buf = [0u8; 256];
    let n = encode(&mut buf, src).unwrap();
    std::string::String::from_utf8(buf[..n].to_vec()).unwrap()
}

#[test]
fn rfc4648_vectors_no_pad() {
    assert_eq!(enc(b""), "");
    assert_eq!(enc(b"f"), "Zg");
    assert_eq!(enc(b"fo"), "Zm8");
    assert_eq!(enc(b"foo"), "Zm9v");
    assert_eq!(enc(b"foob"), "Zm9vYg");
    assert_eq!(enc(b"fooba"), "Zm9vYmE");
    assert_eq!(enc(b"foobar"), "Zm9vYmFy");
}

#[test]
fn url_alphabet() {
    // Bytes chosen to exercise indices 62 ('-') and 63 ('_').
    // 0xFB 0xF0 -> 111110 111111 000000 -> "-_A"
    assert_eq!(enc(&[0xFB, 0xF0]), "-_A");
    // 0xFF 0xFF 0xFF -> all ones -> "____"
    assert_eq!(enc(&[0xFF, 0xFF, 0xFF]), "____");
}

#[test]
fn roundtrip_all_lengths() {
    for len in 0..64usize {
        let src: std::vec::Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
        let mut e = [0u8; 128];
        let en = encode(&mut e, &src).unwrap();
        let mut d = [0u8; 64];
        let dn = decode(&mut d, &e[..en]).unwrap();
        assert_eq!(&d[..dn], &src[..], "len={len}");
    }
}

#[test]
fn decode_accepts_padding() {
    let mut d = [0u8; 8];
    // "Zm8=" and "Zm8" both decode to "fo".
    assert_eq!(decode(&mut d, b"Zm8=").unwrap(), 2);
    assert_eq!(&d[..2], b"fo");
    assert_eq!(decode(&mut d, b"Zm8").unwrap(), 2);
    assert_eq!(&d[..2], b"fo");
}

#[test]
fn decode_accepts_both_url_alphabet_symbols() {
    let mut out = [0xA5; 3];
    assert_eq!(decode(&mut out, b"-_A"), Ok(2));
    assert_eq!(out, [0xFB, 0xF0, 0xA5]);
}

#[test]
fn decode_rejects_bad() {
    let mut d = [0u8; 8];
    assert_eq!(decode(&mut d, b"AAAAA"), Err(Error::Base64)); // len % 4 == 1
    assert_eq!(decode(&mut d, b"Zm.v"), Err(Error::Base64)); // bad char
}

#[test]
fn decoded_len_matches() {
    assert_eq!(decoded_len(0).unwrap(), 0);
    assert_eq!(decoded_len(2).unwrap(), 1);
    assert_eq!(decoded_len(3).unwrap(), 2);
    assert_eq!(decoded_len(4).unwrap(), 3);
    assert_eq!(decoded_len(1), Err(Error::Base64));
}

#[test]
fn short_encoding_outputs_are_refused_before_any_write() {
    for (plain, encoded) in [(b"f".as_slice(), b"Zg".as_slice()), (b"foo", b"Zm9v")] {
        for capacity in 0..=encoded.len() + 1 {
            let mut out = [0xA5; 8];
            let result = encode(&mut out[..capacity], plain);
            if capacity < encoded.len() {
                assert_eq!(result, Err(Error::BadLength));
                assert_eq!(out, [0xA5; 8]);
            } else {
                assert_eq!(result, Ok(encoded.len()));
                assert_eq!(&out[..encoded.len()], encoded);
                assert!(out[encoded.len()..].iter().all(|&b| b == 0xA5));
            }
        }
    }
}

#[test]
fn short_decoding_outputs_are_refused_before_any_write() {
    for (encoded, plain) in [(b"Zg".as_slice(), b"f".as_slice()), (b"Zm9v", b"foo")] {
        for capacity in 0..=plain.len() + 1 {
            let mut out = [0xA5; 8];
            let result = decode(&mut out[..capacity], encoded);
            if capacity < plain.len() {
                assert_eq!(result, Err(Error::BadLength));
                assert_eq!(out, [0xA5; 8]);
            } else {
                assert_eq!(result, Ok(plain.len()));
                assert_eq!(&out[..plain.len()], plain);
                assert!(out[plain.len()..].iter().all(|&b| b == 0xA5));
            }
        }
    }
}
