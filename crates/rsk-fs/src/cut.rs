// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The power-cut sweep an applet suite runs over one command, beside the fault media
//! it drives ([`crate::storage::faults`]). Its own file, because the bcd gate excuses
//! a cfg-gated file and not a cfg-gated region of a shipped one.

use crate::Fs;
use crate::storage::faults::{Cut, CutMedium};

/// Run a command once per cut point: the medium serves k mutations and refuses
/// the rest, the store is remounted over what survived, and `oracle` reads it.
/// SQLite's anomaly loop at the command level, for the applet suites.
///
/// `provision` builds the starting state on a fresh medium, uncut. `command` runs
/// the command and answers whether it completed — an applet that swallows a write
/// failure (the audit journal does) can answer `true` over a lost write, so a
/// sweep of one of those needs its own notion. `oracle` sees the remounted store,
/// the budget, whether it completed, and the medium, whose `ops()` is the order
/// that landed. k grows until the command completes, since no larger budget can
/// change what it does.
pub fn sweep(
    provision: impl Fn() -> (Fs<Cut>, CutMedium),
    command: impl Fn(&mut Fs<Cut>) -> bool,
    mut oracle: impl FnMut(&mut Fs<Cut>, u32, bool, &CutMedium),
) {
    let mut torn = false;
    for budget in 0..SWEEP_MAX {
        let (mut fs, medium) = provision();
        // The fixture's own writes are not the command's; the log starts here.
        medium.clear_ops();
        medium.arm(budget);
        let completed = command(&mut fs);
        torn |= !completed;
        // Power back on: the same medium, a healthy budget, no cache carried over.
        medium.arm(u32::MAX);
        let mut fs = Fs::new(fs.into_storage());
        fs.scan();
        oracle(&mut fs, budget, completed, &medium);
        if completed {
            assert!(
                torn,
                "vacuous: budget {budget} completed and none before it was cut"
            );
            return;
        }
    }
    panic!("no budget under {SWEEP_MAX} let the command finish");
}

/// The ceiling [`sweep`] stops at. A command that writes more than this many
/// records is doing something the sweep's per-budget replay cannot afford anyway.
const SWEEP_MAX: u32 = 64;
