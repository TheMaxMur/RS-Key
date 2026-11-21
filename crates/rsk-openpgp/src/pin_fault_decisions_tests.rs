// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    Write(u16),
    Remove(u16),
}

struct OneRefusal {
    inner: RamStorage,
    fault: Option<Refusal>,
    skip: u32,
    refused: bool,
}

impl OneRefusal {
    fn refuses(&mut self, operation: Refusal) -> bool {
        if self.fault != Some(operation) {
            return false;
        }
        if self.skip != 0 {
            self.skip -= 1;
            return false;
        }
        self.fault = None;
        self.refused = true;
        true
    }
}

impl Storage for OneRefusal {
    fn read(&mut self, fid: u16, out: &mut [u8]) -> Option<usize> {
        self.inner.read(fid, out)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
        if self.refuses(Refusal::Write(fid)) {
            return Err(rsk_sdk::error::Error::MemoryFatal);
        }
        self.inner.write(fid, data)
    }
    fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
        if self.refuses(Refusal::Remove(fid)) {
            return Err(rsk_sdk::error::Error::MemoryFatal);
        }
        self.inner.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.inner.size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(f)
    }
}

fn arm(fs: Fs<RamStorage>, fault: Refusal, skip: u32) -> Fs<OneRefusal> {
    let mut fs = Fs::new(OneRefusal {
        inner: fs.into_storage(),
        fault: Some(fault),
        skip,
        refused: false,
    });
    fs.scan();
    fs
}

#[test]
fn clearing_a_reset_code_refuses_each_independent_persistent_failure() {
    for fault in [
        Refusal::Remove(EF_RC),
        Refusal::Remove(EF_DEK_RC.get()),
        Refusal::Remove(EF_DEK_STAGE_RC.get()),
        Refusal::Write(EF_PW_PRIV),
    ] {
        let mut fs = setup();
        let mut sess = Session::new();
        let mut rng = CountRng(7);
        assert_eq!(
            verify(
                &dev(),
                &mut fs,
                &mut sess,
                &mut rng,
                0,
                PW3_MODE83,
                PW3_DEFAULT
            ),
            Sw::OK
        );
        assert_eq!(
            put_reset_code(&dev(), &mut fs, &mut sess, &mut rng, b"resetme0"),
            Sw::OK
        );
        assert_eq!(
            reset_retry(
                &dev(),
                &mut fs,
                &mut sess,
                &mut rng,
                0,
                PW1_MODE81,
                b"resetme0222222"
            ),
            Sw::OK
        );
        assert!(sess.has_rc);
        assert_eq!(
            verify(
                &dev(),
                &mut fs,
                &mut sess,
                &mut rng,
                0,
                PW3_MODE83,
                PW3_DEFAULT
            ),
            Sw::OK
        );
        let mut expected = Secret::<[u8; DEK_SIZE]>::zeroed();
        load_dek(&dev(), &mut fs, &sess, &mut expected).unwrap();
        let _ = stage_dek(
            &dev(),
            &mut fs,
            &mut rng,
            EF_DEK_RC,
            b"resetme0",
            expected.expose(),
        )
        .unwrap();
        fs.put(0xB000, b"another applet").unwrap();
        let mut before = [0; 8];
        let n = fs.read(EF_PW_PRIV, &mut before).unwrap();
        let mut fs = arm(fs, fault, 0);
        assert_eq!(
            put_reset_code(&dev(), &mut fs, &mut sess, &mut rng, &[]),
            Sw::MEMORY_FAILURE,
            "{fault:?}: an incomplete revocation reported success"
        );
        assert!(!sess.has_rc);
        assert!(sess.has_pw3);
        let mut backend = fs.into_storage();
        assert!(
            backend.refused,
            "{fault:?}: the selected fault was not reached"
        );
        for fid in [EF_RC, EF_DEK_RC.get(), EF_DEK_STAGE_RC.get()] {
            assert_eq!(
                backend.inner.exists(fid),
                fault == Refusal::Remove(fid),
                "{fault:?}: survivor {fid:04X}"
            );
        }
        let mut after = [0; 8];
        assert_eq!(backend.inner.read(EF_PW_PRIV, &mut after), Some(n));
        let mut wanted = before;
        if fault != Refusal::Write(EF_PW_PRIV) {
            wanted[pw_retry_idx(EF_RC)] = 0;
        }
        assert_eq!(after, wanted);
        let mut fs = Fs::new(backend);
        fs.scan();
        assert_eq!(
            put_reset_code(&dev(), &mut fs, &mut sess, &mut rng, &[]),
            Sw::OK
        );
        let mut recovered = Secret::<[u8; DEK_SIZE]>::zeroed();
        load_dek(&dev(), &mut fs, &sess, &mut recovered).unwrap();
        assert_eq!(recovered.expose(), expected.expose());
        sess.reset();
        assert_eq!(
            reset_retry(
                &dev(),
                &mut fs,
                &mut sess,
                &mut rng,
                0,
                PW1_MODE81,
                b"resetme0333333"
            ),
            Sw::REFERENCE_NOT_FOUND
        );
        let mut backend = fs.into_storage();
        for fid in [EF_RC, EF_DEK_RC.get(), EF_DEK_STAGE_RC.get()] {
            assert!(!backend.inner.exists(fid));
        }
        let mut other = [0; 32];
        let len = backend.inner.read(0xB000, &mut other).unwrap();
        assert_eq!(&other[..len], b"another applet");
    }
}

#[test]
fn a_refused_retry_restore_never_grants_either_pw1_mode_or_pw3() {
    for (p2, fid, pin) in [
        (PW1_MODE81, EF_PW1, PW1_DEFAULT),
        (PW1_MODE82, EF_PW1, PW1_DEFAULT),
        (PW3_MODE83, EF_PW3, PW3_DEFAULT),
    ] {
        let fs = setup();
        let mut fs = arm(fs, Refusal::Write(EF_PW_PRIV), 1);
        let mut sess = Session::new();
        assert_eq!(
            verify(&dev(), &mut fs, &mut sess, &mut CountRng(7), 0, p2, pin),
            Sw::MEMORY_FAILURE,
            "{p2:02X}: retry restoration was refused"
        );
        assert!(!sess.has_pw1 && !sess.has_pw2 && !sess.has_pw3 && !sess.has_rc);
        assert_eq!(sess.session_pw1, [0; 32]);
        assert_eq!(sess.session_pw3, [0; 32]);
        let mut backend = fs.into_storage();
        assert!(backend.refused);
        let mut counters = [0; 8];
        backend.inner.read(EF_PW_PRIV, &mut counters).unwrap();
        assert_eq!(counters[pw_retry_idx(fid)], PW_RETRIES_DEFAULT - 1);
        let mut fs = Fs::new(backend);
        fs.scan();
        assert_eq!(
            verify(&dev(), &mut fs, &mut sess, &mut CountRng(7), 0, p2, pin),
            Sw::OK
        );
        assert_eq!(
            (sess.has_pw1, sess.has_pw2, sess.has_pw3),
            (p2 == PW1_MODE81, p2 == PW1_MODE82, p2 == PW3_MODE83)
        );
        let mut dek = Secret::<[u8; DEK_SIZE]>::zeroed();
        load_dek(&dev(), &mut fs, &sess, &mut dek).unwrap();
        fs.read(EF_PW_PRIV, &mut counters).unwrap();
        assert_eq!(counters[pw_retry_idx(fid)], PW_RETRIES_DEFAULT);
    }
}
