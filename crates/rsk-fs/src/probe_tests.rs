// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn traced(fault: Fault) -> Traced {
    Traced {
        map: Rc::new(RefCell::new(BTreeMap::from([
            (RECORD, b"abc".to_vec()),
            (RECORD + 2, b"neighbor".to_vec()),
        ]))),
        reads: Rc::new(RefCell::new(Vec::new())),
        wrote: Rc::new(RefCell::new(Vec::new())),
        fault: Rc::new(Cell::new(fault)),
        err: false,
    }
}

#[test]
fn traced_healthy_probes_and_removals_preserve_lengths_and_the_operation_log() {
    let mut backend = traced(Fault::Healthy);
    let mut out = [0; 2];
    assert_eq!(backend.size(RECORD), Some(3));
    assert!(!backend.last_error());
    assert_eq!(backend.size(RECORD + 1), None);
    assert!(!backend.last_error());
    assert_eq!(backend.read(RECORD, &mut out), Some(3));
    assert_eq!(&out, b"ab");
    assert_eq!(*backend.reads.borrow(), [RECORD, RECORD + 1, RECORD]);
    assert_eq!(backend.remove(RECORD), Ok(()));
    assert_eq!(*backend.wrote.borrow(), [(RECORD, None)]);
    assert_eq!(backend.read(RECORD, &mut out), None);
    assert!(!backend.last_error());
    assert_eq!(backend.size(RECORD + 2), Some(8));
}

#[test]
fn traced_faults_bind_to_the_target_and_count_only_its_probes() {
    let mut backend = traced(Fault::Once {
        fid: RECORD,
        skip: 2,
    });
    assert_eq!(backend.size(RECORD + 2), Some(8));
    assert_eq!(backend.size(RECORD), Some(3));
    assert_eq!(backend.read(RECORD, &mut [0; 2]), Some(3));
    assert_eq!(backend.size(RECORD), None);
    assert!(backend.last_error());
    assert_eq!(backend.size(RECORD), Some(3));
    assert!(!backend.last_error());
    backend.fault.set(Fault::Every(RECORD));
    for _ in 0..2 {
        assert_eq!(backend.size(RECORD + 2), Some(8));
        assert!(!backend.last_error());
        assert_eq!(backend.read(RECORD, &mut [0; 2]), None);
        assert!(backend.last_error());
    }
}

#[test]
fn fault_diagnostics_identify_the_kind_target_and_read_number() {
    assert_eq!(format!("{:?}", Fault::Healthy), "no fault");
    assert_eq!(
        format!(
            "{:?}",
            Fault::Once {
                fid: RECORD,
                skip: 2
            }
        ),
        "a fault on read 3 of 0xb000"
    );
    assert_eq!(
        format!("{:?}", Fault::Every(RECORD)),
        "a fault on every read of 0xb000"
    );
}

fn judgment_run(answer: Option<Vec<u8>>, value: u8) -> Run {
    Run {
        answer,
        before: BTreeMap::from([(RECORD, vec![10])]),
        after: BTreeMap::from([(RECORD, vec![value])]),
        reads: vec![RECORD],
        wrote: BTreeMap::from([(RECORD, BTreeSet::from([Some(vec![15]), Some(vec![20])]))]),
    }
}

#[test]
fn fault_judgment_distinguishes_refused_intermediates_from_successful_mixed_stores() {
    let clean = judgment_run(Some(b"answer".to_vec()), 20);
    assert_eq!(judge(&clean, &judgment_run(None, 15)), None);
    assert!(judge(&clean, &judgment_run(None, 99)).is_some());
    assert_eq!(
        judge(&clean, &judgment_run(Some(b"answer".to_vec()), 20)),
        None
    );
    assert!(judge(&clean, &judgment_run(Some(b"answer".to_vec()), 10)).is_some());
}

const RECORD: u16 = 0xB000;

#[test]
#[should_panic(expected = "succeeded where the clean run refused")]
fn the_read_fault_sweep_rejects_a_failure_that_opens_a_closed_gate() {
    sweep(
        |fs| fs.put(RECORD, b"closed").unwrap(),
        |fs, ()| {
            fs.read(RECORD, &mut [0; 6])
                .is_none()
                .then(|| b"allowed".to_vec())
        },
        &[],
    );
}

#[test]
#[should_panic(expected = "succeeded with another answer")]
fn the_read_fault_sweep_rejects_a_successful_fallback_answer() {
    sweep(
        |fs| fs.put(RECORD, b"original").unwrap(),
        |fs, ()| {
            let mut value = [0; 8];
            Some(match fs.read(RECORD, &mut value) {
                Some(_) => value.to_vec(),
                None => b"fallback".to_vec(),
            })
        },
        &[],
    );
}

#[test]
#[should_panic(expected = "command deliberately failed")]
fn the_read_fault_sweep_rethrows_a_command_panic() {
    sweep(
        |fs| fs.put(RECORD, b"value").unwrap(),
        |fs, ()| {
            let _ = fs.read(RECORD, &mut [0; 5]);
            panic!("command deliberately failed");
        },
        &[],
    );
}

#[test]
fn read_fault_exceptions_bind_to_both_the_fid_and_the_read_number() {
    let other = RECORD + 1;
    let answer = sweep(
        |fs| {
            fs.put(RECORD, &[1]).unwrap();
            fs.put(other, &[2]).unwrap();
        },
        |fs, ()| {
            let mut value = [0; 1];
            let first = (fs.read(RECORD, &mut value), fs.read(RECORD, &mut value));
            let second = (fs.read(other, &mut value), fs.read(other, &mut value));
            if (first.0.is_none() && first.1.is_none())
                || (second.0.is_none() && second.1.is_none())
            {
                None
            } else if first.0.is_none()
                || first.1.is_none()
                || second.0.is_none()
                || second.1.is_none()
            {
                Some(b"one-shot control".to_vec())
            } else {
                Some(b"clean".to_vec())
            }
        },
        &[
            (RECORD, 1, "first sample one-shot control"),
            (RECORD, 2, "second sample one-shot control"),
            (other, 1, "other fid first sample control"),
            (other, 2, "other fid second sample control"),
        ],
    );
    assert_eq!(answer, Some(b"clean".to_vec()));
}

#[test]
fn a_provisioned_traced_inventory_can_be_rescanned_without_losing_records() {
    let answer = sweep(
        |fs| {
            fs.put(RECORD, b"owner").unwrap();
            fs.put(RECORD + 1, b"neighbor").unwrap();
            fs.scan();
        },
        |fs, _| {
            let mut keys = Vec::new();
            assert!(fs.for_each_key(&mut |fid| keys.push(fid)));
            assert_eq!(keys, [RECORD, RECORD + 1]);
            let mut value = [0; 5];
            let n = fs.try_read(RECORD, &mut value).ok()??;
            assert_eq!(n, 5);
            Some(value.to_vec())
        },
        &[],
    );
    assert_eq!(answer, Some(b"owner".to_vec()));
}

#[test]
#[should_panic(expected = "internal error: entered unreachable code")]
fn a_healthy_run_cannot_be_assigned_a_fault_landing() {
    let _ = landing(&[], Fault::Healthy);
}
