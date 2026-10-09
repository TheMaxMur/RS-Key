// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

struct NoMint;
impl Rng for NoMint {
    fn fill(&mut self, _: &mut [u8]) {
        panic!("a damaged verifier cannot authorize a new DEK");
    }
}

#[test]
fn boot_never_reprovisions_empty_owner_security_records() {
    let mut reference = fresh();
    scan_files(&dev(), &mut reference, &mut CountRng(0)).unwrap();
    let storage = reference.into_storage();
    for damaged_fids in [
        vec![EF_PW1],
        vec![EF_PW3],
        vec![EF_PW1, EF_PW3],
        vec![EF_SIG_COUNT],
        vec![EF_PW_PRIV],
        vec![EF_PW_RETRIES],
        vec![EF_UIF_SIG],
        vec![EF_UIF_DEC],
        vec![EF_UIF_AUT],
        vec![EF_UIF_ATT],
        vec![EF_KDF],
        vec![EF_DEK_PW1.get()],
        vec![EF_DEK_PW3.get()],
    ] {
        let mut damaged = storage.clone();
        for &fid in &damaged_fids {
            damaged.write(fid, &[]).unwrap();
        }
        let mut fs = Fs::new(damaged);
        fs.scan();
        let _ = scan_files(&dev(), &mut fs, &mut NoMint);
        for &fid in &damaged_fids {
            assert_eq!(fs.read(fid, &mut [0; 128]), Some(0), "FID {fid:04x}");
        }
        if damaged_fids.contains(&EF_PW1) || damaged_fids.contains(&EF_PW3) {
            let p2 = if damaged_fids.contains(&EF_PW1) {
                0x81
            } else {
                0x83
            };
            let password = if p2 == 0x81 { PW1_DEFAULT } else { PW3_DEFAULT };
            let mut session = crate::pin::Session::default();
            assert_ne!(
                crate::pin::verify(&dev(), &mut fs, &mut session, &mut NoMint, 0, p2, password),
                Sw::OK
            );
            assert!(!session.has_pw1 && !session.has_pw3);
        }
    }
}
