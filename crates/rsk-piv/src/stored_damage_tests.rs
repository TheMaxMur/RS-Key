// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

struct NoMint;
impl Rng for NoMint {
    fn fill(&mut self, _: &mut [u8]) {
        panic!("a damaged provisioned record cannot authorize a factory identity");
    }
}

#[test]
fn select_never_reprovisions_an_empty_owner_security_record() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut reference = new_fs();
    select(
        &mut PivApplet::new(SERIAL, HASH, None, &rng, &presence),
        &mut reference,
    );
    let storage = reference.into_storage();
    for fid in [
        EF_PIN,
        EF_PUK,
        EF_RETRIES,
        key_fid(SLOT_CARDMGM).get(),
        key_fid(SLOT_ATTESTATION).get(),
    ] {
        let mut damaged = storage.clone();
        damaged.write(fid, &[]).unwrap();
        let mut fs = Fs::new(damaged);
        fs.scan();
        let no_mint = RefCell::new(NoMint);
        let mut app = PivApplet::new(SERIAL, HASH, None, &no_mint, &presence);
        let _ = Applet::select(&mut app, false, &mut fs, &mut ResBuf::new(&mut [0; 256]));
        assert_eq!(fs.read(fid, &mut [0; 128]), Some(0), "FID {fid:04x}");
        if fid == EF_PIN || fid == EF_RETRIES {
            assert_ne!(
                run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN).0,
                Sw::OK
            );
        } else {
            assert_eq!(
                run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN).0,
                Sw::OK
            );
        }
    }
}

#[test]
fn no_truncated_pin_or_retry_record_opens_the_factory_pin_after_select() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut reference = new_fs();
    select(
        &mut PivApplet::new(SERIAL, HASH, None, &rng, &presence),
        &mut reference,
    );
    let storage = reference.into_storage();
    for (fid, width) in [(EF_PIN, files::PIN_REC_LEN), (EF_RETRIES, 4)] {
        let mut original = storage.clone();
        let mut bytes = [0; files::PIN_REC_LEN];
        assert_eq!(original.read(fid, &mut bytes), Some(width));
        for len in 0..width {
            let mut damaged = storage.clone();
            damaged.write(fid, &bytes[..len]).unwrap();
            let mut fs = Fs::new(damaged);
            fs.scan();
            let no_mint = RefCell::new(NoMint);
            let mut app = PivApplet::new(SERIAL, HASH, None, &no_mint, &presence);
            select(&mut app, &mut fs);
            assert_ne!(
                run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN).0,
                Sw::OK
            );
            let mut after = [0; files::PIN_REC_LEN];
            assert_eq!(fs.read(fid, &mut after), Some(len));
            assert_eq!(&after[..len], &bytes[..len]);
            assert!(!app.sess.has_pin);
        }
    }
}
