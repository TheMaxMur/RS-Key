// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn aes128_block_fips197() {
    // FIPS-197 appendix C.1.
    let key: [u8; 16] = unhex("000102030405060708090a0b0c0d0e0f");
    let mut block: [u8; 16] = unhex("00112233445566778899aabbccddeeff");
    aes128_encrypt_block(&key, &mut block);
    assert_eq!(block, unhex::<16>("69c4e0d86a7b0430d8cdb78070b4c55a"));
}

#[test]
fn aes_ecb_block_fips197() {
    // FIPS-197 appendix C.1–C.3, encrypt + decrypt round-trips.
    let pt: [u8; 16] = unhex("00112233445566778899aabbccddeeff");
    for (key, ct) in [
        (
            &unhex::<16>("000102030405060708090a0b0c0d0e0f")[..],
            unhex::<16>("69c4e0d86a7b0430d8cdb78070b4c55a"),
        ),
        (
            &unhex::<24>("000102030405060708090a0b0c0d0e0f1011121314151617")[..],
            unhex::<16>("dda97ca4864cdfe06eaf70a0ec0d7191"),
        ),
        (
            &unhex::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")[..],
            unhex::<16>("8ea2b7ca516745bfeafc49904b496089"),
        ),
    ] {
        let mut block = pt;
        aes_ecb_encrypt_block(key, &mut block).unwrap();
        assert_eq!(block, ct);
        aes_ecb_decrypt_block(key, &mut block).unwrap();
        assert_eq!(block, pt);
    }
    assert!(aes_ecb_encrypt_block(&[0u8; 8], &mut [0u8; 16]).is_err());
    assert!(aes_ecb_decrypt_block(&[0u8; 8], &mut [0u8; 16]).is_err());
}

fn unhex<const N: usize>(s: &str) -> [u8; N] {
    let bytes = s.as_bytes();
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        let hi = (bytes[i * 2] as char).to_digit(16).unwrap() as u8;
        let lo = (bytes[i * 2 + 1] as char).to_digit(16).unwrap() as u8;
        *o = (hi << 4) | lo;
    }
    out
}

// NIST SP 800-38A, F.2.5 CBC-AES256.Encrypt (first block).
#[test]
fn cbc_aes256_nist() {
    let key: [u8; 32] = unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    let iv: [u8; 16] = unhex("000102030405060708090a0b0c0d0e0f");
    let mut data: [u8; 16] = unhex("6bc1bee22e409f96e93d7e117393172a");
    aes_encrypt(&key, &iv, Mode::Cbc, &mut data).unwrap();
    assert_eq!(data, unhex::<16>("f58c4c04d6e5f1ba779eabfb5f7bfbd6"));
    aes_decrypt(&key, &iv, Mode::Cbc, &mut data).unwrap();
    assert_eq!(data, unhex::<16>("6bc1bee22e409f96e93d7e117393172a"));
}

// NIST SP 800-38A, F.3.17 CFB128-AES256.Encrypt (first segment).
#[test]
fn cfb_aes256_nist() {
    let key: [u8; 32] = unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    let iv: [u8; 16] = unhex("000102030405060708090a0b0c0d0e0f");
    let mut data: [u8; 16] = unhex("6bc1bee22e409f96e93d7e117393172a");
    aes_encrypt_cfb_256(&key, &iv, &mut data).unwrap();
    assert_eq!(data, unhex::<16>("dc7e84bfda79164b7ecd8486985d3860"));
    aes_decrypt_cfb_256(&key, &iv, &mut data).unwrap();
    assert_eq!(data, unhex::<16>("6bc1bee22e409f96e93d7e117393172a"));
}

// CFB is a stream cipher: a non-block-multiple length must work.
#[test]
fn cfb_partial_block_roundtrip() {
    let key = [0x11u8; 32];
    let iv = [0x22u8; 16];
    let orig = *b"hello, cfb!"; // 11 bytes
    let mut data = orig;
    aes_encrypt_cfb_256(&key, &iv, &mut data).unwrap();
    assert_ne!(data, orig);
    aes_decrypt_cfb_256(&key, &iv, &mut data).unwrap();
    assert_eq!(data, orig);
}

#[test]
fn cbc_rejects_unaligned() {
    let key = [0u8; 32];
    let iv = [0u8; 16];
    let mut data = [0u8; 17]; // not a block multiple
    assert_eq!(
        aes_encrypt(&key, &iv, Mode::Cbc, &mut data),
        Err(Error::BadLength)
    );
}

#[test]
fn bad_key_len() {
    let iv = [0u8; 16];
    let mut data = [0u8; 16];
    assert_eq!(
        aes_encrypt(&[0u8; 20], &iv, Mode::Cbc, &mut data),
        Err(Error::BadLength)
    );
}

// NIST GCM test case 14: K=0^256, IV=0^96, A=empty, P=0^128.
#[test]
fn gcm_aes256_nist_case14() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let mut buf = [0u8; 16];
    let tag = aes256gcm_encrypt(&key, &nonce, &[], &mut buf);
    assert_eq!(buf, unhex::<16>("cea7403d4d606b6e074ec5d3baf39d18"));
    assert_eq!(tag, unhex::<16>("d0d1c8a799996bf0265b98b5d48ab919"));
    aes256gcm_decrypt(&key, &nonce, &[], &mut buf, &tag).unwrap();
    assert_eq!(buf, [0u8; 16]);
}

#[test]
fn gcm_aad_roundtrip_and_tamper() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"serial-hash-as-aad";
    let mut buf = *b"thirty-two-byte device key!! abcd"; // 33 bytes
    let plain = buf;
    let tag = aes256gcm_encrypt(&key, &nonce, aad, &mut buf);
    assert_ne!(buf, plain);
    // Wrong AAD must fail authentication.
    assert_eq!(
        aes256gcm_decrypt(&key, &nonce, b"wrong-aad", &mut buf.clone(), &tag),
        Err(Error::Decrypt)
    );
    // Correct AAD recovers the plaintext.
    aes256gcm_decrypt(&key, &nonce, aad, &mut buf, &tag).unwrap();
    assert_eq!(buf, plain);
}

#[test]
fn every_aes_key_width_uses_the_selected_mode() {
    let pt = unhex::<16>("00112233445566778899aabbccddeeff");
    for (key, cipher) in [
        (
            unhex::<16>("000102030405060708090a0b0c0d0e0f").to_vec(),
            unhex::<16>("69c4e0d86a7b0430d8cdb78070b4c55a"),
        ),
        (
            unhex::<24>("000102030405060708090a0b0c0d0e0f1011121314151617").to_vec(),
            unhex::<16>("dda97ca4864cdfe06eaf70a0ec0d7191"),
        ),
        (
            unhex::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .to_vec(),
            unhex::<16>("8ea2b7ca516745bfeafc49904b496089"),
        ),
    ] {
        let mut block = pt;
        aes_encrypt(&key, &[0; 16], Mode::Cbc, &mut block).unwrap();
        assert_eq!(block, cipher);
        aes_decrypt(&key, &[0; 16], Mode::Cbc, &mut block).unwrap();
        assert_eq!(block, pt);

        let mut stream = [0x55; 13];
        aes_encrypt(&key, &pt, Mode::Cfb, &mut stream).unwrap();
        assert_eq!(stream, core::array::from_fn(|i| cipher[i] ^ 0x55));
        aes_decrypt(&key, &pt, Mode::Cfb, &mut stream).unwrap();
        assert_eq!(stream, [0x55; 13]);
    }
}

#[test]
fn invalid_aes_lengths_leave_the_callers_bytes_unchanged() {
    for len in [0, 1, 15, 17, 23, 25, 31, 33] {
        let key = vec![0x11; len];
        for mode in [Mode::Cbc, Mode::Cfb] {
            let mut bytes = [0x55; 16];
            assert_eq!(
                aes_encrypt(&key, &[0; 16], mode, &mut bytes),
                Err(Error::BadLength)
            );
            assert_eq!(
                aes_decrypt(&key, &[0; 16], mode, &mut bytes),
                Err(Error::BadLength)
            );
            assert_eq!(bytes, [0x55; 16]);
        }
    }
    for len in [16, 24, 32] {
        let key = vec![0x11; len];
        let mut bytes = [0x55; 17];
        assert_eq!(
            aes_encrypt(&key, &[0; 16], Mode::Cbc, &mut bytes),
            Err(Error::BadLength)
        );
        assert_eq!(
            aes_decrypt(&key, &[0; 16], Mode::Cbc, &mut bytes),
            Err(Error::BadLength)
        );
        assert_eq!(bytes, [0x55; 17]);
    }
}
