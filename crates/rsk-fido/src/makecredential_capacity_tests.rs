// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::consts::{EF_CRED, MAX_RESIDENT_CREDENTIALS};

struct NoCredentialSpace(RamStorage, rsk_sdk::error::Error);
impl Storage for NoCredentialSpace {
    fn read(&mut self, fid: u16, output: &mut [u8]) -> Option<usize> {
        self.0.read(fid, output)
    }
    fn write(&mut self, fid: u16, value: &[u8]) -> rsk_sdk::error::Result<()> {
        if (EF_CRED..EF_CRED + MAX_RESIDENT_CREDENTIALS).contains(&fid) {
            Err(self.1)
        } else {
            self.0.write(fid, value)
        }
    }
    fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
        self.0.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.0.size(fid)
    }
    fn for_each_key(&mut self, visit: &mut dyn FnMut(u16)) -> bool {
        self.0.for_each_key(visit)
    }
}

#[test]
fn a_backend_that_fills_during_resident_publication_reports_key_store_full() {
    assert_publication_error(rsk_sdk::error::Error::NoMemory, CtapError::KeyStoreFull);
}

#[test]
fn a_failed_resident_publication_reports_a_retryable_fault() {
    assert_publication_error(rsk_sdk::error::Error::MemoryFatal, CtapError::Other);
}

fn assert_publication_error(error: rsk_sdk::error::Error, expected: CtapError) {
    let mut fs = Fs::new(NoCredentialSpace(RamStorage::new(), error));
    crate::tests::uv_optional(&mut fs);
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let mut state = crate::FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        presence: &mut presence,
        now_ms: 0,
    };
    let mut output = [0; 4096];
    assert_eq!(
        make_credential(&mut ctx, &build_request(true), &mut output),
        Err(expected)
    );
    assert_eq!(fs.read(EF_CRED, &mut [0; 1]), None);
    assert!(fs.has_key(crate::consts::EF_KEY_DEV));
}
