// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use std::rc::Rc;

struct RepeatedWalk {
    inner: RamStorage,
    removed: Rc<RefCell<Vec<u16>>>,
}

impl Storage for RepeatedWalk {
    fn read(&mut self, fid: u16, bytes: &mut [u8]) -> Option<usize> {
        self.inner.read(fid, bytes)
    }

    fn write(&mut self, fid: u16, bytes: &[u8]) -> rsk_sdk::error::Result<()> {
        self.inner.write(fid, bytes)
    }

    fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
        self.removed.borrow_mut().push(fid);
        self.inner.remove(fid)
    }

    fn size(&mut self, fid: u16) -> Option<usize> {
        self.inner.size(fid)
    }

    fn for_each_key(&mut self, callback: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(&mut |fid| {
            callback(fid);
            callback(fid);
        })
    }
}

#[test]
fn reset_removes_each_repeated_fid_once_across_multiple_batches() {
    const UNRELATED: u16 = 0x1234;
    let removed = Rc::new(RefCell::new(Vec::new()));
    let mut fs = Fs::new(RepeatedWalk {
        inner: RamStorage::new(),
        removed: removed.clone(),
    });
    fs.scan();
    fs.put(UNRELATED, b"sentinel").unwrap();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let count = u16::try_from(SWEEP_BATCH + 1).unwrap();
    for i in 0..count {
        assert_eq!(
            put(
                &mut app,
                &mut fs,
                &put_data(&i.to_be_bytes(), 0x21, 6, SECRET_SHA1, false, None)
            ),
            Sw::OK
        );
    }
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))
        ),
        (Sw::OK, vec![])
    );
    lock_with_code(&mut app, &mut fs);
    removed.borrow_mut().clear();
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_RESET, 0xDE, 0xAD, &[])),
        (Sw::OK, vec![])
    );
    for fid in (EF_OATH_CRED..EF_OATH_CRED + count).chain([EF_OATH_CODE.get(), EF_OTP_PIN]) {
        assert!(!fs.has_key(KeyFid::new(fid)));
        assert_eq!(
            removed.borrow().iter().filter(|&&seen| seen == fid).count(),
            1,
            "FID {fid:04x}"
        );
    }
    let mut sentinel = [0; 8];
    assert_eq!(fs.read(UNRELATED, &mut sentinel), Some(sentinel.len()));
    assert_eq!(&sentinel, b"sentinel");
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[])),
        (Sw::OK, vec![])
    );
}

#[test]
fn a_removed_value_with_unremoved_metadata_cannot_complete_either_wipe_phase() {
    use rsk_fs::storage::faults::MetaStuck;
    for fid in [EF_OATH_CRED, EF_OATH_CODE.get()] {
        let (backend, medium) = MetaStuck::new();
        let mut fs = Fs::new(backend);
        fs.scan();
        fs.put_key(KeyFid::new(fid), rsk_fs::Sealed::wrap(b"value"))
            .unwrap();
        fs.meta_add(fid, b"policy").unwrap();
        medium.stick(true);
        assert_eq!(wipe_oath(&mut fs), Err(Sw::MEMORY_FAILURE));
        assert!(!medium.live(fid));
        assert!(medium.live(rsk_fs::EF_META));
        medium.stick(false);
        let mut retained = [0; 6];
        assert_eq!(fs.meta_find(fid, &mut retained), Some(6));
        assert_eq!(&retained, b"policy");
    }
}
