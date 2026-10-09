// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn an_empty_wrapped_seed_remains_locked_and_does_not_bootstrap_a_plain_seed() {
    let mut fs = fs();
    fs.put_key(EF_KEY_DEV_ENC, Sealed::wrap(&[])).unwrap();
    assert_eq!(lock_state(&mut fs), Ok(true));
    let _ = ensure_seed(&dev(), &mut fs, &mut NoMint);
    assert_eq!(fs.read_key(EF_KEY_DEV, &mut [0; 64]), None);
    assert_eq!(fs.read_key(EF_KEY_DEV_ENC, &mut [0; 64]), Some(0));
}

#[test]
fn an_empty_irreversible_backup_marker_does_not_reopen_export() {
    let mut fs = fs();
    fs.put(crate::consts::EF_BACKUP_SEALED, &[]).unwrap();
    assert_eq!(crate::vendor::try_backup_sealed(&mut fs), Ok(true));
}

struct NoMint;
impl Rng for NoMint {
    fn fill(&mut self, _: &mut [u8]) {
        panic!("corrupt stored material is not a confirmed first boot");
    }
}

#[test]
fn truncated_and_tampered_seed_records_never_mint_a_replacement_identity() {
    let mut reference = fs();
    ensure_seed(&dev(), &mut reference, &mut SeqRng(1)).unwrap();
    let mut blob = [0; 64];
    let n = reference.read_key(EF_KEY_DEV, &mut blob).unwrap();
    let storage = reference.into_storage();
    let mut variants: Vec<Vec<u8>> = (0..n).map(|len| blob[..len].to_vec()).collect();
    for index in 0..n {
        let mut altered = blob[..n].to_vec();
        altered[index] ^= 0x80;
        variants.push(altered);
    }
    for altered in variants {
        let mut fs = Fs::new(storage.clone());
        fs.scan();
        fs.put_key(EF_KEY_DEV, Sealed::wrap(&altered)).unwrap();
        let _ = ensure_seed(&dev(), &mut fs, &mut NoMint);
        let mut after = [0; 64];
        assert_eq!(fs.read_key(EF_KEY_DEV, &mut after), Some(altered.len()));
        assert_eq!(&after[..altered.len()], altered);
        assert!(load_keydev(&dev(), &mut fs).is_none());
    }
}

#[test]
fn malformed_global_counters_never_bootstrap_or_advance_a_lower_sequence() {
    let mut reference = fs();
    ensure_seed(&dev(), &mut reference, &mut SeqRng(1)).unwrap();
    let storage = reference.into_storage();
    for malformed in [
        &[][..],
        &[99][..],
        &[99, 0][..],
        &[99, 0, 0][..],
        &[99, 0, 0, 0, 0][..],
    ] {
        let mut fs = Fs::new(storage.clone());
        fs.scan();
        fs.put_counter(EF_COUNTER, malformed).unwrap();
        let generation = fs.write_gen();
        assert!(global_sign_counter(&mut fs).is_err());
        assert!(bump_sign_counter(&mut fs).is_err());
        ensure_seed(&dev(), &mut fs, &mut NoMint).unwrap();
        let mut after = [0; 8];
        assert_eq!(
            fs.read_counter(EF_COUNTER, &mut after),
            Some(malformed.len())
        );
        assert_eq!(&after[..malformed.len()], malformed);
        assert_eq!(fs.write_gen(), generation);
    }
}
