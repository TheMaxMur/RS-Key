// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_secret::Secret;

struct NoEntropy;

impl Rng for NoEntropy {
    fn fill(&mut self, _: &mut [u8]) {
        panic!("a surviving DEK must not be replaced with a new random key");
    }
}

fn stored(fs: &mut Fs<RamStorage>, fid: u16) -> Option<Vec<u8>> {
    let mut out = [0; rsk_fs::MAX_VALUE_BYTES];
    fs.read(fid, &mut out)
        .map(|n| out[..n.min(out.len())].to_vec())
}

fn setup() -> Fs<RamStorage> {
    let mut fs = fresh();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    fs
}

fn opens_the_original_key(fs: &mut Fs<RamStorage>, mode: u8, pin: &[u8]) {
    let mut sess = crate::pin::Session::new();
    assert_eq!(
        crate::pin::verify(&dev(), fs, &mut sess, &mut NoEntropy, 0, mode, pin),
        Sw::OK
    );
    let mut out = Secret::<[u8; DEK_SIZE]>::zeroed();
    crate::pin::load_dek(&dev(), fs, &sess, &mut out).unwrap();
    let mut expected = Secret::<[u8; DEK_SIZE]>::zeroed();
    for (i, byte) in expected.expose_mut().iter_mut().enumerate() {
        *byte = u8::try_from(i).unwrap();
    }
    assert_eq!(out.expose(), expected.expose());
}

#[test]
fn both_first_boot_copies_survive_when_the_pin_verifiers_have_not_landed() {
    let mut fs = setup();
    let pw1 = stored(&mut fs, EF_DEK_PW1.get());
    let pw3 = stored(&mut fs, EF_DEK_PW3.get());
    fs.delete(EF_PW1).unwrap();
    fs.delete(EF_PW3).unwrap();
    scan_files(&dev(), &mut fs, &mut NoEntropy).unwrap();
    assert_eq!(stored(&mut fs, EF_DEK_PW1.get()), pw1);
    assert_eq!(stored(&mut fs, EF_DEK_PW3.get()), pw3);
    opens_the_original_key(&mut fs, PW1_MODE81, PW1_DEFAULT);
    opens_the_original_key(&mut fs, PW3_MODE83, PW3_DEFAULT);
}

#[test]
fn either_standing_verifier_prevents_rekeying_after_the_other_copy_is_lost() {
    for (keep, lost, mode, pin) in [
        (EF_DEK_PW1, EF_DEK_PW3, PW1_MODE81, PW1_DEFAULT),
        (EF_DEK_PW3, EF_DEK_PW1, PW3_MODE83, PW3_DEFAULT),
    ] {
        let mut fs = setup();
        let copy = stored(&mut fs, keep.get());
        let removed = if lost == EF_DEK_PW1 { EF_PW1 } else { EF_PW3 };
        fs.delete(removed).unwrap();
        fs.delete_key(lost).unwrap();
        scan_files(&dev(), &mut fs, &mut NoEntropy).unwrap();
        assert_eq!(stored(&mut fs, keep.get()), copy);
        assert!(stored(&mut fs, lost.get()).is_none());
        opens_the_original_key(&mut fs, mode, pin);
    }
}

#[test]
fn orphan_records_at_rc_or_legacy_fids_inhibit_dek_generation() {
    for orphan in [EF_DEK_RC.get(), EF_DEK] {
        let mut fs = setup();
        let copy = stored(&mut fs, EF_DEK_PW3.get()).unwrap();
        fs.delete(EF_PW1).unwrap();
        fs.delete(EF_PW3).unwrap();
        fs.delete_key(EF_DEK_PW1).unwrap();
        fs.put(orphan, &copy).unwrap();
        scan_files(&dev(), &mut fs, &mut NoEntropy).unwrap();
        assert_eq!(stored(&mut fs, EF_DEK_PW3.get()).unwrap(), copy);
        assert_eq!(stored(&mut fs, orphan).unwrap(), copy);
        assert!(stored(&mut fs, EF_DEK_PW1.get()).is_none());
        opens_the_original_key(&mut fs, PW3_MODE83, PW3_DEFAULT);
    }
}
