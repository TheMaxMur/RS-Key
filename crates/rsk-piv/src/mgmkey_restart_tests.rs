// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn an_escrowed_management_change_and_its_owner_replay_revoke_the_flag() {
    let to = Mgm {
        algo: ALGO_AES256,
        touch: TOUCHPOLICY_ALWAYS,
        key: &AES256_KEY,
    };
    let admin = [
        PIVMAN_TAG,
        9,
        PIVMAN_FLAGS_TAG,
        1,
        PIVMAN_FLAG_MGM_PROTECTED | 0x40,
        PIVMAN_TS_TAG,
        4,
        1,
        2,
        3,
        4,
    ];
    let rotate = |fs: &mut Fs<Cut>| {
        if files::scan_files(&dev(), fs, &mut TestRng(91)) != Ok(true) {
            return false;
        }
        let key = files::mgm_read(&dev(), fs).unwrap();
        let from = if key.key() == to.key {
            to
        } else {
            assert_eq!(key.key(), FACTORY.key);
            assert!(
                mgm_is_protected(fs),
                "escrow was revoked before its key changed"
            );
            FACTORY
        };
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(Scripted { confirm: true });
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        select(&mut app, fs);
        if !authenticates(&mut app, fs, from) {
            return false;
        }
        let mut body = vec![to.algo, SLOT_CARDMGM, u8::try_from(to.key.len()).unwrap()];
        body.extend_from_slice(to.key);
        run(&mut app, fs, INS_SET_MGMKEY, 0xFF, 0xFE, &body).0 == Sw::OK
    };
    assert!(rsk_fs::cut::sweep_restarts(
        || {
            let (mut fs, medium) = new_cut_fs();
            files::scan_files(&dev(), &mut fs, &mut TestRng(91)).unwrap();
            fs.put(EF_PIVMAN_DATA, &admin).unwrap();
            fs.put(0xB000, b"another applet").unwrap();
            (fs, medium)
        },
        rotate,
        |fs| {
            let _ = rotate(fs);
        },
        |fs, _, _, _, medium| {
            assert_eq!(files::mgm_read(&dev(), fs).unwrap().key(), to.key);
            assert!(!mgm_is_protected(fs));
            let record = medium.value(EF_PIVMAN_DATA).unwrap();
            let fields = pivman_inner(&record);
            assert_eq!(
                find_tag(fields, PIVMAN_TS_TAG.into()),
                Some(&[1, 2, 3, 4][..])
            );
            assert_eq!(find_tag(fields, PIVMAN_FLAGS_TAG.into()), Some(&[0x40][..]));
            let rng = RefCell::new(TestRng(9));
            let pres = RefCell::new(Scripted { confirm: true });
            let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
            select(&mut app, fs);
            assert_eq!(touch_in_force(&mut app, fs, &pres, to), Some(to.touch));
            assert_eq!(metadata(&mut app, fs), (to.algo, to.touch));
            assert_eq!(
                medium.value(0xB000).as_deref(),
                Some(&b"another applet"[..])
            );
        }
    ));
}
