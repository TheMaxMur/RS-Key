// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The read half of [`crate::cut::sweep`]: a command run once per flash read it
//! makes, with that one read failed. Its own file for the reason `cut.rs` is.

use crate::Fs;
use crate::storage::Storage;
use rsk_sdk::error::Result;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::rc::Rc;

type Records = BTreeMap<u16, Vec<u8>>;
/// Every mutation in the order served, `None` for a remove.
type Wrote = Vec<(u16, Option<Vec<u8>>)>;

/// Which reads a [`Traced`] medium fails.
#[derive(Clone, Copy)]
enum Fault {
    Healthy,
    /// The read of `fid` after `skip` more of it were served; healthy after it.
    Once {
        fid: u16,
        skip: u32,
    },
    /// Every read of `fid`.
    Every(u16),
}

impl core::fmt::Debug for Fault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Fault::Healthy => write!(f, "no fault"),
            Fault::Once { fid, skip } => write!(f, "a fault on read {} of {fid:#06x}", skip + 1),
            Fault::Every(fid) => write!(f, "a fault on every read of {fid:#06x}"),
        }
    }
}

/// A RAM medium that logs every `read`/`size` and every mutation it serves, and
/// fails the read [`sweep`] aims at, reporting it through [`Storage::last_error`]
/// as the device's `SeqStorage` does. Ordered, so two runs walk their keys alike.
pub struct Traced {
    map: Rc<RefCell<Records>>,
    reads: Rc<RefCell<Vec<u16>>>,
    wrote: Rc<RefCell<Wrote>>,
    fault: Rc<Cell<Fault>>,
    err: bool,
}

impl Traced {
    /// Whether this read of `fid` is the one that fails, logging it either way.
    fn faults(&mut self, fid: u16) -> bool {
        self.reads.borrow_mut().push(fid);
        self.err = match self.fault.get() {
            Fault::Once { fid: f, skip } if f == fid => {
                self.fault.set(match skip {
                    0 => Fault::Healthy,
                    _ => Fault::Once {
                        fid,
                        skip: skip - 1,
                    },
                });
                skip == 0
            }
            Fault::Every(f) => f == fid,
            _ => false,
        };
        self.err
    }
}

impl Storage for Traced {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        if self.faults(fid) {
            return None;
        }
        let map = self.map.borrow();
        let v = map.get(&fid)?;
        let n = v.len().min(buf.len());
        buf[..n].copy_from_slice(&v[..n]);
        Some(v.len())
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
        self.wrote.borrow_mut().push((fid, Some(data.to_vec())));
        self.map.borrow_mut().insert(fid, data.to_vec());
        Ok(())
    }
    fn remove(&mut self, fid: u16) -> Result<()> {
        self.wrote.borrow_mut().push((fid, None));
        self.map.borrow_mut().remove(&fid);
        Ok(())
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        if self.faults(fid) {
            return None;
        }
        self.map.borrow().get(&fid).map(Vec::len)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        for &k in self.map.borrow().keys() {
            f(k);
        }
        true
    }
    fn last_error(&self) -> bool {
        self.err
    }
}

/// One run of the command: what it answered, and the medium around it.
struct Run {
    /// The answer of a command that succeeded, `None` for a refusal.
    answer: Option<Vec<u8>>,
    before: Records,
    after: Records,
    reads: Vec<u16>,
    /// Every value the run gave each fid, `None` for a remove.
    wrote: BTreeMap<u16, BTreeSet<Option<Vec<u8>>>>,
}

/// One read a sweep lets break the rule: its fid, which read of that fid it is
/// (the first is 1), and why a fault there is not a defect.
pub type Excuse = (u16, u32, &'static str);

/// Run a command clean, then once per flash read it made with that read failed,
/// then once per fid it read with every read of it failed, and hold each faulted
/// run to the rule [`Fs::try_read`] states: a fault may only fail the command.
/// It never succeeds where the clean run refused; it leaves no record holding a
/// value the clean run never gave it — what it held before, or any value the clean
/// run wrote there on the way, since failing part-way is failing; and a run that
/// succeeds answers what the clean run answered and leaves the store it left,
/// since a different answer or a mix of old and new is not failing.
///
/// `provision` builds the starting state on a healthy medium and returns what the
/// command needs beside the store (an rng, a session); both must be deterministic,
/// since a faulted run is judged against the clean one. `command` answers `Some`
/// with the command's response when it succeeded, and may be a sequence, which is
/// how a latched flag's harm in a LATER command is reached. `excused` names the
/// one-shot faults that deliberately break the rule, each with its reason; what an
/// excuse lets through is printed, and an excuse no fault needs is stale.
///
/// Answers the clean run's answer, so a row whose success half is the point can
/// check it had one. Blind by construction: each record is judged alone, so two
/// related records left one old and one new pass, and no refusal code is compared.
pub fn sweep<C>(
    provision: impl Fn(&mut Fs<Traced>) -> C,
    command: impl Fn(&mut Fs<Traced>, &mut C) -> Option<Vec<u8>>,
    excused: &[Excuse],
) -> Option<Vec<u8>> {
    let clean = run(&provision, &command, Fault::Healthy);
    assert!(!clean.reads.is_empty(), "vacuous: the command read nothing");
    let mut faults = Vec::new();
    let mut served = BTreeMap::<u16, u32>::new();
    for &fid in &clean.reads {
        let skip = served.entry(fid).or_default();
        faults.push(Fault::Once { fid, skip: *skip });
        *skip += 1;
    }
    faults.extend(served.keys().map(|&fid| Fault::Every(fid)));
    let mut needed = vec![false; excused.len()];
    let mut broken = Vec::new();
    for fault in faults {
        let faulted = run(&provision, &command, fault);
        assert_eq!(
            faulted.before, clean.before,
            "provision is not deterministic"
        );
        // Up to the read that failed, the run must be the clean one, or the fault
        // landed somewhere the clean run never went.
        let at = landing(&clean.reads, fault);
        assert_eq!(
            faulted.reads.get(..=at),
            clean.reads.get(..=at),
            "{fault:?}: the command read differently before the fault landed — it is not deterministic"
        );
        let Some(broke) = judge(&clean, &faulted) else {
            continue;
        };
        let excuse = excused.iter().position(|&(fid, nth, _)| {
            matches!(fault, Fault::Once { fid: f, skip } if f == fid && skip + 1 == nth)
        });
        match excuse {
            Some(i) => {
                needed[i] = true;
                eprintln!("excused: {fault:?} {broke} — {}", excused[i].2);
            }
            None => broken.push(format!("{fault:?} {broke}")),
        }
    }
    assert!(broken.is_empty(), "{}", broken.join("\n"));
    for (&(fid, nth, why), needed) in excused.iter().zip(needed) {
        assert!(
            needed,
            "the excuse for read {nth} of {fid:#06x} is stale, its fault broke nothing: {why}"
        );
    }
    clean.answer
}

fn run<C>(
    provision: &impl Fn(&mut Fs<Traced>) -> C,
    command: &impl Fn(&mut Fs<Traced>, &mut C) -> Option<Vec<u8>>,
    fault: Fault,
) -> Run {
    let map = Rc::new(RefCell::new(Records::new()));
    let reads = Rc::new(RefCell::new(Vec::new()));
    let wrote = Rc::new(RefCell::new(Vec::new()));
    let armed = Rc::new(Cell::new(Fault::Healthy));
    let mut fs = Fs::new(Traced {
        map: map.clone(),
        reads: reads.clone(),
        wrote: wrote.clone(),
        fault: armed.clone(),
        err: false,
    });
    let mut cx = provision(&mut fs);
    let before = map.borrow().clone();
    reads.borrow_mut().clear();
    wrote.borrow_mut().clear();
    armed.set(fault);
    let answer = catch_unwind(AssertUnwindSafe(|| command(&mut fs, &mut cx))).unwrap_or_else(|e| {
        eprintln!("{fault:?}: the command panicked");
        resume_unwind(e)
    });
    let mut values = BTreeMap::<u16, BTreeSet<Option<Vec<u8>>>>::new();
    for (fid, v) in wrote.take() {
        values.entry(fid).or_default().insert(v);
    }
    Run {
        answer,
        before,
        after: map.take(),
        reads: reads.take(),
        wrote: values,
    }
}

/// Where in the clean run's reads `fault` lands.
fn landing(reads: &[u16], fault: Fault) -> usize {
    let (fid, nth) = match fault {
        Fault::Once { fid, skip } => (fid, skip as usize),
        Fault::Every(fid) => (fid, 0),
        Fault::Healthy => unreachable!(),
    };
    reads
        .iter()
        .enumerate()
        .filter(|&(_, &f)| f == fid)
        .nth(nth)
        .map(|(i, _)| i)
        .expect("a fault is only aimed at a read the clean run made")
}

/// How a faulted run broke the rule, if it did: the records it left holding a
/// value the clean run never gave them; then, for a run that succeeded, a clean
/// run that refused, another answer, or another store.
fn judge(clean: &Run, faulted: &Run) -> Option<String> {
    let third: Vec<String> = faulted
        .before
        .keys()
        .chain(faulted.after.keys())
        .copied()
        .collect::<BTreeSet<u16>>()
        .into_iter()
        .filter_map(|fid| {
            let got = faulted.after.get(&fid);
            let clean_gave = clean
                .wrote
                .get(&fid)
                .is_some_and(|vs| vs.contains(&got.cloned()));
            (got != faulted.before.get(&fid) && !clean_gave).then(|| {
                let got = got.map_or("nothing".into(), |v| format!("{} bytes", v.len()));
                format!("{fid:#06x} holding {got}")
            })
        })
        .collect();
    if !third.is_empty() {
        return Some(format!(
            "left {}, a value the clean run never gave it",
            third.join(", ")
        ));
    }
    let answer = faulted.answer.as_ref()?;
    let Some(clean_answer) = clean.answer.as_ref() else {
        return Some("succeeded where the clean run refused".into());
    };
    if answer != clean_answer {
        return Some(format!(
            "succeeded with another answer: {} bytes where the clean run gave {}",
            answer.len(),
            clean_answer.len()
        ));
    }
    let apart: Vec<String> = faulted
        .after
        .keys()
        .chain(clean.after.keys())
        .copied()
        .collect::<BTreeSet<u16>>()
        .into_iter()
        .filter(|fid| faulted.after.get(fid) != clean.after.get(fid))
        .map(|fid| format!("{fid:#06x}"))
        .collect();
    (!apart.is_empty()).then(|| {
        format!(
            "succeeded, leaving {} other than the clean run did",
            apart.join(", ")
        )
    })
}

#[cfg(test)]
#[path = "probe_tests.rs"]
mod tests;
