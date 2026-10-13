// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use std::cell::Cell;
use std::rc::Rc;

struct RefuseMetaDrop {
    inner: RamStorage,
    target: Rc<Cell<Option<u16>>>,
    fired: Rc<Cell<bool>>,
}

fn contains_metadata(mut bytes: &[u8], wanted: u16) -> bool {
    while bytes.len() >= 4 {
        let fid = u16::from_be_bytes([bytes[0], bytes[1]]);
        let len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        assert!(4 + len <= bytes.len());
        if fid == wanted {
            return true;
        }
        bytes = &bytes[4 + len..];
    }
    false
}

impl Storage for RefuseMetaDrop {
    fn read(&mut self, fid: u16, out: &mut [u8]) -> Option<usize> {
        self.inner.read(fid, out)
    }

    fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
        if fid == rsk_fs::EF_META
            && let Some(target) = self.target.get()
        {
            let mut old = [0; 4096];
            let n = self.inner.read(fid, &mut old).unwrap_or(0);
            if contains_metadata(&old[..n], target) && !contains_metadata(data, target) {
                self.target.set(None);
                self.fired.set(true);
                return Err(rsk_sdk::error::Error::MemoryFatal);
            }
        }
        self.inner.write(fid, data)
    }

    fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
        self.inner.remove(fid)
    }

    fn size(&mut self, fid: u16) -> Option<usize> {
        self.inner.size(fid)
    }

    fn for_each_key(&mut self, visit: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(visit)
    }
}

#[test]
fn each_reset_phase_carries_a_single_metadata_fault_to_the_final_answer() {
    for fid in [crate::consts::EF_KEY_DEV.get(), EF_CRED, EF_PIN] {
        let target = Rc::new(Cell::new(None));
        let fired = Rc::new(Cell::new(false));
        let mut fs = Fs::new(RefuseMetaDrop {
            inner: RamStorage::new(),
            target: target.clone(),
            fired: fired.clone(),
        });
        let mut rng = SeqRng(1);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        fs.put(EF_CRED, &[0xc0; 100]).unwrap();
        fs.put(EF_PIN, &[8, 4, 1, 0, 0]).unwrap();
        fs.meta_add(fid, &[1]).unwrap();
        fs.meta_add(0x9a00, &[2]).unwrap();
        target.set(Some(fid));
        let mut state = FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            presence: &mut presence,
            now_ms: 0,
        };
        assert_eq!(
            reset(&mut ctx),
            Err(CtapError::Other),
            "phase containing {fid:#06x}"
        );
        assert!(fired.get());
        assert!(!fs.has_data(EF_CRED));
        assert!(!fs.has_data(EF_PIN));
        assert!(load_keydev(&dev(), &mut fs).is_some());
    }
}
