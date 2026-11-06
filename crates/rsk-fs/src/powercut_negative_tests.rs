// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::powercut::{Device, Op, PowerCutModel};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

const FID: u16 = 0xB000;

#[derive(Default)]
struct State {
    values: BTreeMap<u16, std::vec::Vec<u8>>,
    dead: bool,
    cut_mutation: bool,
    resolving_read: Option<u16>,
    armed_read: Option<u16>,
    cuts: usize,
    error: bool,
    third_meta: Option<std::vec::Vec<u8>>,
    omit: Option<u16>,
    extra: bool,
    walks_to_skip: usize,
}

#[derive(Clone, Default)]
struct Media(Rc<RefCell<State>>);

impl Media {
    fn readable(&self, fid: u16) -> bool {
        let mut state = self.0.borrow_mut();
        if !state.dead && state.armed_read == Some(fid) {
            state.armed_read = None;
            state.dead = true;
            state.cuts += 1;
        }
        state.error = state.dead;
        !state.dead
    }

    fn mutation(&self) -> Result<()> {
        let mut state = self.0.borrow_mut();
        if state.dead {
            return Err(Error::MemoryFatal);
        }
        if state.cut_mutation {
            state.cut_mutation = false;
            state.dead = true;
            state.cuts += 1;
            state.armed_read = state.resolving_read.take();
            if let Some(third) = state.third_meta.take() {
                state.values.insert(EF_META, third);
            }
            return Err(Error::MemoryFatal);
        }
        Ok(())
    }
}

impl Storage for Media {
    fn read(&mut self, fid: u16, out: &mut [u8]) -> Option<usize> {
        if !self.readable(fid) {
            return None;
        }
        let state = self.0.borrow();
        let value = state.values.get(&fid)?;
        let copied = value.len().min(out.len());
        out[..copied].copy_from_slice(&value[..copied]);
        Some(value.len())
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        if !self.readable(fid) {
            return None;
        }
        self.0.borrow().values.get(&fid).map(std::vec::Vec::len)
    }
    fn write(&mut self, fid: u16, value: &[u8]) -> Result<()> {
        self.mutation()?;
        self.0.borrow_mut().values.insert(fid, value.to_vec());
        Ok(())
    }
    fn remove(&mut self, fid: u16) -> Result<()> {
        self.mutation()?;
        self.0.borrow_mut().values.remove(&fid);
        Ok(())
    }
    fn last_error(&self) -> bool {
        self.0.borrow().error
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        let mut state = self.0.borrow_mut();
        if state.dead {
            return false;
        }
        let faulted = state.walks_to_skip == 0;
        state.walks_to_skip = state.walks_to_skip.saturating_sub(1);
        for &fid in state.values.keys() {
            if !(faulted && state.omit == Some(fid)) {
                f(fid);
            }
        }
        if faulted && state.extra {
            f(FID + 1);
        }
        true
    }
}

impl Device for Media {
    type Storage = Self;
    fn boot(&mut self) -> Fs<Self> {
        Fs::new(self.clone())
    }
    fn dead(&self) -> bool {
        self.0.borrow().dead
    }
    fn revive(&mut self) {
        self.0.borrow_mut().dead = false;
    }
}

fn fixture() -> (Media, Fs<Media>, PowerCutModel) {
    let mut device = Media::default();
    let fs = Device::boot(&mut device);
    (device, fs, PowerCutModel::new(&[FID], 1024))
}

#[test]
#[should_panic(expected = "got.is_none()")]
fn a_read_of_an_unmodelled_value_is_an_oracle_failure() {
    let (mut device, mut fs, mut model) = fixture();
    fs.put(FID, b"unmodelled").unwrap();
    model.step(&mut device, &mut fs, Op::Read(FID, 32));
}

#[test]
#[should_panic(expected = "got.is_none()")]
fn a_read_of_unmodelled_metadata_is_an_oracle_failure() {
    let (mut device, mut fs, mut model) = fixture();
    fs.meta_add(FID, b"unmodelled").unwrap();
    model.step(&mut device, &mut fs, Op::MetaFind(FID));
}

#[test]
#[should_panic(expected = "an oversized meta_add must be refused")]
fn a_model_with_the_wrong_metadata_capacity_cannot_approve_a_run() {
    let (mut device, mut fs, _) = fixture();
    let mut model = PowerCutModel::new(&[FID], 0);
    model.step(
        &mut device,
        &mut fs,
        Op::MetaAdd(FID, b"accepted by Fs".to_vec()),
    );
}

#[test]
fn interrupted_deletes_and_metadata_changes_survive_a_second_cut_in_resolution() {
    for operation in [
        Op::Delete(FID),
        Op::MetaAdd(FID, b"new".to_vec()),
        Op::MetaDelete(FID),
    ] {
        let (mut device, mut fs, mut model) = fixture();
        model.step(&mut device, &mut fs, Op::Put(FID, b"owner".to_vec()));
        model.step(&mut device, &mut fs, Op::MetaAdd(FID, b"old".to_vec()));
        {
            let mut state = device.0.borrow_mut();
            state.cut_mutation = true;
            state.resolving_read = Some(if matches!(operation, Op::Delete(_)) {
                FID
            } else {
                EF_META
            });
        }
        model.step(&mut device, &mut fs, operation);
        assert_eq!(device.0.borrow().cuts, 2);
        assert!(!device.dead());
        assert_eq!(fs.try_read(FID, &mut [0; 5]), Ok(Some(5)));
        let mut out = [0; 3];
        assert_eq!(fs.try_meta_find(FID, &mut out), Ok(Some(3)));
        assert_eq!(&out, b"old");
        model.reboot(&mut device, &mut fs);
    }
}

fn corrupt_meta(operation: Op) {
    let (mut device, mut fs, mut model) = fixture();
    model.step(&mut device, &mut fs, Op::MetaAdd(FID, b"old".to_vec()));
    let mut third = std::vec::Vec::from(FID.to_be_bytes());
    third.extend_from_slice(&5u16.to_be_bytes());
    third.extend_from_slice(b"third");
    {
        let mut state = device.0.borrow_mut();
        state.cut_mutation = true;
        state.third_meta = Some(third);
    }
    model.step(&mut device, &mut fs, operation);
}

#[test]
#[should_panic(expected = "torn meta_add: neither the old record nor the new one")]
fn interrupted_metadata_add_cannot_return_a_valid_third_record() {
    corrupt_meta(Op::MetaAdd(FID, b"new".to_vec()));
}

#[test]
#[should_panic(expected = "torn meta_delete: garbage")]
fn interrupted_metadata_delete_cannot_return_a_valid_third_record() {
    corrupt_meta(Op::MetaDelete(FID));
}

fn bad_walk(omit: Option<u16>, extra: bool) {
    let (mut device, mut fs, mut model) = fixture();
    model.step(&mut device, &mut fs, Op::Put(FID, b"owner".to_vec()));
    model.step(&mut device, &mut fs, Op::MetaAdd(FID, b"policy".to_vec()));
    {
        let mut state = device.0.borrow_mut();
        state.omit = omit;
        state.extra = extra;
        state.walks_to_skip = 1;
    }
    model.reboot(&mut device, &mut fs);
}

#[test]
#[should_panic(expected = "committed key missing after the cut")]
fn enumeration_cannot_omit_a_readable_committed_value() {
    bad_walk(Some(FID), false);
}

#[test]
#[should_panic(expected = "unexpected key after the cut")]
fn enumeration_cannot_invent_an_unmodelled_value() {
    bad_walk(None, true);
}

#[test]
#[should_panic(expected = "metadata with no EF_META to hold it")]
fn enumeration_cannot_omit_the_readable_metadata_container() {
    bad_walk(Some(EF_META), false);
}
