// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

struct VanishOnSize {
    inner: RamStorage,
    target: Rc<Cell<Option<u16>>>,
}

impl Storage for VanishOnSize {
    fn read(&mut self, fid: u16, output: &mut [u8]) -> Option<usize> {
        self.inner.read(fid, output)
    }
    fn write(&mut self, fid: u16, value: &[u8]) -> rsk_sdk::error::Result<()> {
        self.inner.write(fid, value)
    }
    fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
        self.inner.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        let length = self.inner.size(fid);
        if self.target.get() == Some(fid) {
            self.target.set(None);
            self.inner.remove(fid).unwrap();
        }
        length
    }
    fn for_each_key(&mut self, visit: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(visit)
    }
}

#[test]
fn a_source_that_disappears_after_its_probe_cannot_be_moved() {
    let target = Rc::new(Cell::new(None));
    let mut fs = Fs::new(VanishOnSize {
        inner: RamStorage::new(),
        target: Rc::clone(&target),
    });
    fs.scan();
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            INS_ASYM_KEYGEN,
            0,
            SLOT_AUTHENTICATION,
            &gen_template(ALGO_ECCP256)
        )
        .0,
        Sw::OK
    );
    let mut head = [0; 128];
    let n = fs
        .meta_find(key_fid(SLOT_AUTHENTICATION).get(), &mut head)
        .unwrap();
    let generation = fs.write_gen();
    target.set(Some(key_fid(SLOT_AUTHENTICATION).get()));
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            INS_MOVE_KEY,
            0x82,
            SLOT_AUTHENTICATION,
            &[]
        ),
        (Sw::REFERENCE_NOT_FOUND, vec![])
    );
    assert_eq!(target.get(), None);
    assert_eq!(fs.write_gen(), generation);
    assert!(!fs.has_key(key_fid(0x82)));
    let mut retained = [0; 128];
    assert_eq!(
        fs.meta_find(key_fid(SLOT_AUTHENTICATION).get(), &mut retained),
        Some(n)
    );
    assert_eq!(&retained[..n], &head[..n]);
}

#[test]
fn a_source_head_read_refusal_after_copy_keeps_the_original_owner() {
    let (mut app, mut fs, medium, _, _) = moved_card();
    let fid = key_fid(SLOT_AUTHENTICATION).get();
    let owner = medium.value(fid).unwrap();
    medium.stick_after(rsk_fs::EF_META, 2);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            INS_MOVE_KEY,
            0x82,
            SLOT_AUTHENTICATION,
            &[]
        ),
        (Sw::MEMORY_FAILURE, vec![])
    );
    medium.stick(None);
    assert_eq!(medium.value(fid), Some(owner.clone()));
    assert_eq!(medium.value(key_fid(0x82).get()), Some(owner));
    assert_eq!(fs.meta_find(key_fid(0x82).get(), &mut [0; 128]), None);
    assert!(fs.meta_find(fid, &mut [0; 128]).is_some());
}
