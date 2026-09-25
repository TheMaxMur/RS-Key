// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The sweep's delete budget — the one thing in this file whose failure mode is a
//! wipe that never ends, so it cannot be reached from the applet's own tests.

use super::*;
use rsk_fs::storage::faults::{RemoveStuck, Undead};

/// `RESET_MAX_DELETES` is the sweep's progress guard, and the applet test that
/// looks like it drives it does not: `reset_reports_failure_when_the_sweep_cannot_converge`
/// re-yields ONE file, and 1 divides everything, so `>` → `==` merely trips the
/// valve one delete early there and the test passes the mutation by construction.
/// FIDO's runaway had the same batch and the same blindness.
///
/// `deleted` rises a whole batch at a time, so `==` lets it step PAST the budget
/// without ever equalling it and the valve stops guarding. Five undead records
/// instead — 5 divides none of the four applets' budgets (1024 · 257 · 512 · 1039).
/// The fixture's ceiling is what makes that failure READABLE: without it the
/// mutation hangs the suite rather than failing it.
#[test]
fn a_sweep_that_never_converges_stops_inside_its_delete_budget() {
    const UNDEAD: u8 = 5;
    // The premise, made checkable rather than argued: `deleted` rises a whole
    // UNDEAD per pass, so a batch that DIVIDES the budget lets `==` fire on the
    // nose and this test stops seeing the valve — silently, suite still green.
    const _: () = assert!(
        !RESET_MAX_DELETES.is_multiple_of(UNDEAD as u32),
        "the batch divides the delete budget, so this test cannot falsify the valve"
    );
    let (backend, count) = Undead::new(2 * RESET_MAX_DELETES);
    let mut fs = Fs::new(backend);
    fs.scan();
    for low in 0..UNDEAD {
        fs.put(data_object_fid(low).unwrap(), &[0x41]).unwrap();
    }
    assert_eq!(
        sweep(&mut fs, is_piv_secret_fid),
        Err(Sw::MEMORY_FAILURE),
        "a sweep the medium never lets converge must fail, not run on"
    );
    assert!(
        count.removals() <= RESET_MAX_DELETES,
        "the valve let the sweep spend {} deletions on a budget of {RESET_MAX_DELETES}",
        count.removals()
    );
}

/// The `?` under the valve — a refused backend removal must STOP the sweep, because
/// `for_each_key` re-yields the fid the medium kept. Nothing in any of the four
/// applets could see it: swallow the `?` and the loop spins on that fid straight
/// into the VALVE, which answers the SAME error, so `let _ = gone.value;` left
/// 140 / 615 / 118 / 197 passing. The removal COUNT is the observation that
/// separates them — one batch against a whole budget.
#[test]
fn a_refused_removal_stops_the_sweep_instead_of_spinning_into_the_valve() {
    const LIVE: u8 = 5;
    let (backend, medium) = RemoveStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    for low in 0..LIVE {
        fs.put(data_object_fid(low).unwrap(), &[0x41]).unwrap();
    }
    // Which of the batch is reached first is a fresh HashMap order per run, so the
    // stop lands anywhere in 1..=LIVE — the bound is what has to hold, not a count.
    medium.refuse(Some(data_object_fid(0).unwrap()));
    assert_eq!(
        sweep(&mut fs, is_piv_secret_fid),
        Err(Sw::MEMORY_FAILURE),
        "a removal the medium refused must fail the sweep"
    );
    assert!(
        medium.attempts() <= LIVE as u32,
        "the sweep asked for {} removals over {LIVE} files: it carried on past the \
         refusal and the delete budget, not the `?`, is what stopped it",
        medium.attempts()
    );
}
