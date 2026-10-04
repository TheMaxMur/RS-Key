// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use std::cell::Cell;
use std::rc::Rc;

fn record<S: Storage>(fs: &mut Fs<S>, fid: u16) -> Option<Vec<u8>> {
    let mut buf = [0; 256];
    fs.read(fid, &mut buf).map(|n| buf[..n].to_vec())
}

fn verify_ref<S: Storage>(fs: &mut Fs<S>, sess: &mut Session, p2: u8, pin: &[u8]) -> Sw {
    verify(&dev(), fs, sess, &mut CountRng(7), 0, p2, pin)
}

#[test]
fn a_retry_record_missing_the_addressed_slot_cannot_grant_access() {
    for (fid, mode, pin) in [
        (EF_PW1, PW1_MODE81, PW1_DEFAULT),
        (EF_PW1, PW1_MODE82, PW1_DEFAULT),
        (EF_PW3, PW3_MODE83, PW3_DEFAULT),
    ] {
        for len in [0, pw_retry_idx(fid)] {
            let mut fs = setup();
            let before = record(&mut fs, EF_PW_PRIV).unwrap();
            let verifier = record(&mut fs, fid);
            fs.put(EF_PW_PRIV, &before[..len]).unwrap();
            let mut sess = Session::new();
            assert_eq!(
                verify_ref(&mut fs, &mut sess, mode, pin),
                Sw::MEMORY_FAILURE
            );
            assert!(!sess.has_pw1 && !sess.has_pw2 && !sess.has_pw3);
            assert_eq!(record(&mut fs, EF_PW_PRIV).unwrap(), &before[..len]);
            assert_eq!(record(&mut fs, fid), verifier);
            fs.put(EF_PW_PRIV, &before).unwrap();
            assert_eq!(verify_ref(&mut fs, &mut sess, mode, pin), Sw::OK);
        }
    }
}

#[test]
fn an_unreadable_retry_maximum_leaves_the_successful_attempt_charged() {
    for (fid, mode, pin) in [
        (EF_PW1, PW1_MODE81, PW1_DEFAULT),
        (EF_PW3, PW3_MODE83, PW3_DEFAULT),
    ] {
        for len in [None, Some(0), Some((fid & 0xf) as usize)] {
            let mut fs = setup();
            let maximum = record(&mut fs, EF_PW_RETRIES).unwrap();
            let before = record(&mut fs, EF_PW_PRIV).unwrap();
            let verifier = record(&mut fs, fid);
            match len {
                None => fs.delete(EF_PW_RETRIES).unwrap(),
                Some(n) => fs.put(EF_PW_RETRIES, &maximum[..n]).unwrap(),
            }
            let mut sess = Session::new();
            let expected = if len.is_none() {
                Sw::REFERENCE_NOT_FOUND
            } else {
                Sw::MEMORY_FAILURE
            };
            assert_eq!(verify_ref(&mut fs, &mut sess, mode, pin), expected);
            assert!(!sess.has_pw1 && !sess.has_pw3);
            let mut charged = before.clone();
            charged[pw_retry_idx(fid)] -= 1;
            assert_eq!(record(&mut fs, EF_PW_PRIV).unwrap(), charged);
            assert_eq!(record(&mut fs, fid), verifier);
            fs.put(EF_PW_RETRIES, &maximum).unwrap();
            assert_eq!(verify_ref(&mut fs, &mut sess, mode, pin), Sw::OK);
            assert_eq!(record(&mut fs, EF_PW_PRIV).unwrap(), before);
        }
    }
}

struct ShortReadback {
    inner: RamStorage,
    armed: Rc<Cell<bool>>,
    pending: bool,
    hits: Rc<Cell<usize>>,
}

impl Storage for ShortReadback {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        if fid == EF_PW_PRIV && self.pending {
            self.pending = false;
            self.hits.set(self.hits.get() + 1);
            return Some(0);
        }
        self.inner.read(fid, buf)
    }

    fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
        self.inner.write(fid, data)?;
        self.pending |= fid == EF_PW_PRIV && self.armed.get();
        Ok(())
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
fn a_retry_readback_without_the_addressed_counter_cannot_grant_access() {
    for (fid, mode, pin) in [
        (EF_PW1, PW1_MODE81, PW1_DEFAULT),
        (EF_PW1, PW1_MODE82, PW1_DEFAULT),
        (EF_PW3, PW3_MODE83, PW3_DEFAULT),
    ] {
        let armed = Rc::new(Cell::new(false));
        let hits = Rc::new(Cell::new(0));
        let mut fs = Fs::new(ShortReadback {
            inner: RamStorage::new(),
            armed: armed.clone(),
            pending: false,
            hits: hits.clone(),
        });
        fs.scan();
        scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
        let before = record(&mut fs, EF_PW_PRIV).unwrap();
        let mut last_try = before.clone();
        last_try[pw_retry_idx(fid)] = 1;
        fs.put(EF_PW_PRIV, &last_try).unwrap();
        let mut sess = Session::new();
        armed.set(true);
        assert_eq!(
            verify_ref(&mut fs, &mut sess, mode, pin),
            Sw::MEMORY_FAILURE,
            "a short read-back must not authorize a correct PIN"
        );
        assert_eq!(hits.get(), 1);
        assert!(!sess.has_pw1 && !sess.has_pw2 && !sess.has_pw3);
        armed.set(false);
        let mut charged = last_try;
        charged[pw_retry_idx(fid)] = 0;
        assert_eq!(record(&mut fs, EF_PW_PRIV).unwrap(), charged);
        assert_eq!(verify_ref(&mut fs, &mut sess, mode, pin), Sw::PIN_BLOCKED);
        assert!(!sess.has_pw1 && !sess.has_pw2 && !sess.has_pw3);
        fs.put(EF_PW_PRIV, &before).unwrap();
        assert_eq!(verify_ref(&mut fs, &mut sess, mode, pin), Sw::OK);
        assert_eq!(record(&mut fs, EF_PW_PRIV).unwrap(), before);
    }
}

#[test]
fn unusable_verifier_shapes_never_spend_a_retry_or_change_a_dek() {
    for (fid, mode, pin, dek) in [
        (EF_PW1, PW1_MODE81, PW1_DEFAULT, EF_DEK_PW1),
        (EF_PW3, PW3_MODE83, PW3_DEFAULT, EF_DEK_PW3),
    ] {
        for len in [0, 1, 2, 3, 33, 35, 65] {
            let mut fs = setup();
            let valid = record(&mut fs, fid).unwrap();
            let mut malformed = valid.clone();
            malformed.resize(len, 0);
            fs.put(fid, &malformed).unwrap();
            let counters = record(&mut fs, EF_PW_PRIV);
            let copy = record(&mut fs, dek.get());
            let mut sess = Session::new();
            let expected = if len < 3 {
                Sw::REFERENCE_NOT_FOUND
            } else {
                Sw::CONDITIONS_NOT_SATISFIED
            };
            assert_eq!(
                verify_ref(&mut fs, &mut sess, mode, pin),
                expected,
                "stored length {len}"
            );
            assert!(!sess.has_pw1 && !sess.has_pw3);
            assert_eq!(record(&mut fs, EF_PW_PRIV), counters);
            assert_eq!(record(&mut fs, dek.get()), copy);
            assert_eq!(record(&mut fs, fid).unwrap(), malformed);
            fs.put(fid, &valid).unwrap();
            assert_eq!(verify_ref(&mut fs, &mut sess, mode, pin), Sw::OK);
        }
        let mut fs = setup();
        let mut malformed = record(&mut fs, fid).unwrap();
        malformed[0] = 0;
        fs.put(fid, &malformed).unwrap();
        let counters = record(&mut fs, EF_PW_PRIV);
        assert_eq!(
            verify_ref(&mut fs, &mut Session::new(), mode, pin),
            Sw::REFERENCE_NOT_FOUND
        );
        assert_eq!(record(&mut fs, EF_PW_PRIV), counters);
    }
}

fn activate_rc<S: Storage>(fs: &mut Fs<S>, sess: &mut Session) {
    assert_eq!(verify_ref(fs, sess, PW3_MODE83, PW3_DEFAULT), Sw::OK);
    assert_eq!(
        put_reset_code(&dev(), fs, sess, &mut CountRng(7), b"resetme0"),
        Sw::OK
    );
}

#[test]
fn a_reset_code_without_a_new_pin_is_not_an_attempt() {
    let mut fs = setup();
    let mut sess = Session::new();
    activate_rc(&mut fs, &mut sess);
    let counters = record(&mut fs, EF_PW_PRIV);
    let verifier = record(&mut fs, EF_PW1);
    let copy = record(&mut fs, EF_DEK_PW1.get());
    for len in 0..=b"resetme0".len() {
        assert_eq!(
            reset_retry(
                &dev(),
                &mut fs,
                &mut sess,
                &mut CountRng(7),
                0,
                PW1_MODE81,
                &b"resetme0"[..len]
            ),
            Sw::WRONG_LENGTH
        );
        assert!(sess.has_pw3 && !sess.has_rc);
        assert_eq!(record(&mut fs, EF_PW_PRIV), counters);
        assert_eq!(record(&mut fs, EF_PW1), verifier);
        assert_eq!(record(&mut fs, EF_DEK_PW1.get()), copy);
    }
    assert_eq!(
        reset_retry(
            &dev(),
            &mut fs,
            &mut sess,
            &mut CountRng(7),
            0,
            PW1_MODE81,
            b"resetme0654321"
        ),
        Sw::OK
    );
    sess.reset();
    assert_eq!(
        verify_ref(&mut fs, &mut sess, PW1_MODE81, b"654321"),
        Sw::OK
    );
}

#[test]
fn reset_retry_cannot_replace_pw1_when_the_rc_copy_does_not_open() {
    for malformed in [None, Some(&[DEK_FORMAT_V3, 0, 0][..])] {
        let mut fs = setup();
        let mut sess = Session::new();
        activate_rc(&mut fs, &mut sess);
        match malformed {
            None => fs.delete_key(EF_DEK_RC).unwrap(),
            Some(bytes) => fs.put_key(EF_DEK_RC, Sealed::wrap(bytes)).unwrap(),
        }
        let verifier = record(&mut fs, EF_PW1);
        let copy = record(&mut fs, EF_DEK_PW1.get());
        assert_eq!(
            reset_retry(
                &dev(),
                &mut fs,
                &mut sess,
                &mut CountRng(7),
                0,
                PW1_MODE81,
                b"resetme0654321"
            ),
            Sw::EXEC_ERROR
        );
        assert!(!sess.has_pw1 && !sess.has_pw2 && !sess.has_pw3 && sess.has_rc);
        assert_eq!(record(&mut fs, EF_PW1), verifier);
        assert_eq!(record(&mut fs, EF_DEK_PW1.get()), copy);
        assert!(!fs.has_key(EF_DEK_STAGE_PW1));
        sess.reset();
        assert_eq!(
            verify_ref(&mut fs, &mut sess, PW1_MODE81, PW1_DEFAULT),
            Sw::OK
        );
    }
}

#[test]
fn reset_code_update_cannot_replace_rc_when_the_admin_copy_does_not_open() {
    for malformed in [None, Some(&[DEK_FORMAT_V3, 0, 0][..])] {
        let mut fs = setup();
        let mut sess = Session::new();
        activate_rc(&mut fs, &mut sess);
        let verifier = record(&mut fs, EF_RC);
        let copy = record(&mut fs, EF_DEK_RC.get());
        let counters = record(&mut fs, EF_PW_PRIV);
        match malformed {
            None => fs.delete_key(EF_DEK_PW3).unwrap(),
            Some(bytes) => fs.put_key(EF_DEK_PW3, Sealed::wrap(bytes)).unwrap(),
        }
        assert_eq!(
            put_reset_code(&dev(), &mut fs, &mut sess, &mut CountRng(7), b"newreset"),
            Sw::EXEC_ERROR
        );
        assert_eq!(record(&mut fs, EF_RC), verifier);
        assert_eq!(record(&mut fs, EF_DEK_RC.get()), copy);
        assert_eq!(record(&mut fs, EF_PW_PRIV), counters);
        assert!(!fs.has_key(EF_DEK_STAGE_RC));
        sess.reset();
        assert_eq!(
            reset_retry(
                &dev(),
                &mut fs,
                &mut sess,
                &mut CountRng(7),
                0,
                PW1_MODE81,
                b"resetme0654321"
            ),
            Sw::OK
        );
    }
}

#[test]
fn a_healthy_dek_load_defers_stage_retirement_when_rescrub_is_refused() {
    let (storage, medium) = RemoveStuck::new();
    let mut fs = Fs::new(storage);
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    let mut sess = Session::new();
    assert_eq!(
        verify_ref(&mut fs, &mut sess, PW1_MODE81, PW1_DEFAULT),
        Sw::OK
    );
    let mut expected = Secret::<[u8; DEK_SIZE]>::zeroed();
    load_dek(&dev(), &mut fs, &sess, &mut expected).unwrap();
    let _staged = stage_dek(
        &dev(),
        &mut fs,
        &mut CountRng(7),
        EF_DEK_PW1,
        PW1_DEFAULT,
        expected.expose(),
    )
    .unwrap();
    let staged = record(&mut fs, EF_DEK_STAGE_PW1.get());
    let committed = record(&mut fs, EF_DEK_PW1.get());
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    medium.refuse(Some(rsk_fs::EF_HARDENED));
    let mut loaded = Secret::<[u8; DEK_SIZE]>::zeroed();
    load_dek(&dev(), &mut fs, &sess, &mut loaded).unwrap();
    assert_eq!(loaded.expose(), expected.expose());
    assert_eq!(record(&mut fs, EF_DEK_STAGE_PW1.get()), staged);
    assert_eq!(record(&mut fs, EF_DEK_PW1.get()), committed);
    assert!(medium.live(rsk_fs::EF_HARDENED));
    medium.refuse(None);
    load_dek(&dev(), &mut fs, &sess, &mut loaded).unwrap();
    assert_eq!(loaded.expose(), expected.expose());
    assert!(!medium.live(EF_DEK_STAGE_PW1.get()));
    assert!(!medium.live(rsk_fs::EF_HARDENED));
    assert_eq!(record(&mut fs, EF_DEK_PW1.get()), committed);
}
