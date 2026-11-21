// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use std::{cell::RefCell, rc::Rc};

struct ReadLog {
    inner: RamStorage,
    reads: Rc<RefCell<Vec<u16>>>,
}

impl Storage for ReadLog {
    fn read(&mut self, fid: u16, out: &mut [u8]) -> Option<usize> {
        self.reads.borrow_mut().push(fid);
        self.inner.read(fid, out)
    }

    fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
        self.inner.write(fid, data)
    }

    fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
        self.inner.remove(fid)
    }

    fn size(&mut self, fid: u16) -> Option<usize> {
        self.inner.size(fid)
    }

    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(f)
    }
}

#[test]
fn each_pw1_mode_selects_only_the_user_dek_and_logout_revokes_it() {
    for mode in [PW1_MODE81, PW1_MODE82] {
        let reads = Rc::new(RefCell::new(Vec::new()));
        let mut fs = Fs::new(ReadLog {
            inner: setup().into_storage(),
            reads: Rc::clone(&reads),
        });
        fs.scan();
        let mut sess = Session::new();
        let mut out = Secret::new([0xA5; DEK_SIZE]);
        let generation = fs.write_gen();
        reads.borrow_mut().clear();
        assert_eq!(
            load_dek(&dev(), &mut fs, &sess, &mut out),
            Err(Sw::CONDITIONS_NOT_SATISFIED)
        );
        assert!(reads.borrow().is_empty());
        assert_eq!(out.expose(), &[0xA5; DEK_SIZE]);
        assert_eq!(fs.write_gen(), generation);
        assert_eq!(
            verify(
                &dev(),
                &mut fs,
                &mut sess,
                &mut CountRng(7),
                0,
                mode,
                PW1_DEFAULT
            ),
            Sw::OK
        );
        assert_eq!(
            (sess.has_pw1, sess.has_pw2),
            (mode == PW1_MODE81, mode == PW1_MODE82)
        );
        assert!(!sess.has_pw3 && !sess.has_rc);
        let generation = fs.write_gen();
        reads.borrow_mut().clear();
        load_dek(&dev(), &mut fs, &sess, &mut out).unwrap();
        assert_eq!(reads.borrow().first(), Some(&EF_DEK_PW1.get()));
        assert!(!reads.borrow().contains(&EF_DEK_PW3.get()));
        assert!(!reads.borrow().contains(&EF_DEK_RC.get()));
        let mut expected = Secret::<[u8; DEK_SIZE]>::zeroed();
        for (i, byte) in expected.expose_mut().iter_mut().enumerate() {
            *byte = u8::try_from(i).unwrap();
        }
        assert_eq!(out.expose(), expected.expose());
        assert_eq!(fs.write_gen(), generation);
        assert_eq!(logout(&mut sess, mode, &[]), Sw::OK);
        assert!(!sess.has_pw1 && !sess.has_pw2 && !sess.has_pw3 && !sess.has_rc);
        out.expose_mut().fill(0xA5);
        reads.borrow_mut().clear();
        assert_eq!(
            load_dek(&dev(), &mut fs, &sess, &mut out),
            Err(Sw::CONDITIONS_NOT_SATISFIED)
        );
        assert!(reads.borrow().is_empty());
        assert_eq!(out.expose(), &[0xA5; DEK_SIZE]);
        assert_eq!(fs.write_gen(), generation);
    }
}
