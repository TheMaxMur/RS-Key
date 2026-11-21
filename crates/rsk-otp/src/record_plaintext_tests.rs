// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::faults::ProbeStuck;
use rsk_sdk::error::Error;

fn filled() -> SlotRecord {
    SlotRecord::from_bytes(&[0xD3; SLOT_SIZE]).unwrap()
}

#[test]
fn each_plaintext_length_preserves_its_bytes_and_clears_the_old_tail() {
    let mut fs = new_fs();
    for len in CONFIG_SIZE..=SLOT_SIZE {
        let bytes: Vec<u8> = (0..len).map(|i| i as u8).collect();
        fs.put(EF_OTP_SLOT1, &bytes).unwrap();
        let generation = fs.write_gen();
        let mut rec = filled();
        assert_eq!(rec.try_read_plaintext(&mut fs, EF_OTP_SLOT1), Ok(Some(len)));
        assert_eq!(rec.stored(), bytes);
        assert_eq!(&rec.expose()[len..], &vec![0; SLOT_SIZE - len]);
        assert_eq!(fs.write_gen(), generation);
        let mut raw = [0; seal::MAX_BLOB];
        assert_eq!(
            fs.try_read_key(KeyFid::new(EF_OTP_SLOT1), &mut raw),
            Ok(Some(len))
        );
        assert_eq!(&raw[..len], bytes);
    }
}

#[test]
fn malformed_plaintext_lengths_are_refused_without_rewriting_the_medium() {
    let mut fs = new_fs();
    for len in (0..CONFIG_SIZE)
        .chain(SLOT_SIZE + 1..=seal::MAX_BLOB)
        .chain([seal::MAX_BLOB + 1, seal::MAX_BLOB * 2])
    {
        let bytes = vec![0xA7; len];
        fs.put(EF_OTP_SLOT1, &bytes).unwrap();
        let generation = fs.write_gen();
        let mut rec = filled();
        assert_eq!(
            rec.try_read_plaintext(&mut fs, EF_OTP_SLOT1),
            Ok(None),
            "length {len}"
        );
        assert!(rec.stored().is_empty());
        assert_eq!(rec.expose(), &[0; SLOT_SIZE]);
        assert_eq!(fs.write_gen(), generation);
        let mut raw = vec![0; len];
        assert_eq!(
            fs.try_read_key(KeyFid::new(EF_OTP_SLOT1), &mut raw),
            Ok(Some(len))
        );
        assert_eq!(&raw[..len], bytes);
        fs.put(EF_OTP_SLOT1, &[0x39; CONFIG_SIZE]).unwrap();
        assert_eq!(
            rec.try_read_plaintext(&mut fs, EF_OTP_SLOT1),
            Ok(Some(CONFIG_SIZE))
        );
        assert_eq!(rec.stored(), &[0x39; CONFIG_SIZE]);
        assert_eq!(rec.expose()[CONFIG_SIZE..], [0; SLOT_SIZE - CONFIG_SIZE]);
    }
}

#[test]
fn repeated_plaintext_read_faults_scrub_the_scratch_and_allow_recovery() {
    let (storage, medium) = ProbeStuck::new();
    let mut fs = Fs::new(storage);
    fs.scan();
    fs.put(EF_OTP_SLOT1, &[0x39; CONFIG_SIZE]).unwrap();
    let generation = fs.write_gen();
    let mut rec = filled();
    medium.stick(Some(EF_OTP_SLOT1));
    for _ in 0..2 {
        assert_eq!(
            rec.try_read_plaintext(&mut fs, EF_OTP_SLOT1),
            Err(Error::MemoryFatal)
        );
        assert!(rec.stored().is_empty());
        assert_eq!(rec.expose(), &[0; SLOT_SIZE]);
        assert_eq!(medium.value(EF_OTP_SLOT1), Some(vec![0x39; CONFIG_SIZE]));
        assert_eq!(fs.write_gen(), generation);
    }
    medium.stick(None);
    assert_eq!(
        rec.try_read_plaintext(&mut fs, EF_OTP_SLOT1),
        Ok(Some(CONFIG_SIZE))
    );
    assert_eq!(rec.stored(), &[0x39; CONFIG_SIZE]);
    assert_eq!(rec.expose()[CONFIG_SIZE..], [0; SLOT_SIZE - CONFIG_SIZE]);
    assert_eq!(fs.write_gen(), generation);
}
