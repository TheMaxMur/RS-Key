// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// The use counter only ever climbs, and never past the ceiling: for a stored
/// counter inside the ceiling and *any* session value, both writers land in
/// `stored..=USE_COUNTER_MAX`, and each reports a write exactly when it made
/// one. This is the replay defence — a validation server orders OTPs by
/// `(use, session)`, so a counter that moves backwards, or that stalls while the
/// session keeps restarting at 0, hands out a pair it has already accepted.
///
/// The hypothesis `stored <= USE_COUNTER_MAX` is the invariant itself, so this
/// is its induction step and only that: `cmd_configure` writes a whole zeroed
/// record, which is the base case, and Kani never sees it.
///
/// Only [`SlotRecord`](crate::SlotRecord)'s methods write those two bytes: a press
/// (`press_yubico`) and a boot's first press step them through these rules, CONFIGURE zeroes
/// them (the base case above), and UPDATE, a swap or the re-seal carry them.
///
/// Not proved here: `press_yubico`'s 0 -> 1 promotion (it moves forward), the HOTP
/// factor (`TKTFLAG_UPDATE_MASK` cannot turn a slot HOTP), and that a carried tail is
/// the newest — a stale record put back is the store's question, not this solver's.
#[kani::proof]
fn use_counter_climbs_and_stops_at_the_ceiling() {
    let stored: u16 = kani::any();
    let session: u8 = kani::any();
    kani::assume(stored <= USE_COUNTER_MAX);

    let (pressed, _, persist) = next_use_counter(stored, session);
    assert!(stored <= pressed && pressed <= USE_COUNTER_MAX);
    // A `persist` that disagrees with the value is a silent flash write or,
    // worse, a counter advanced only in RAM — a repeat across the next reboot.
    assert_eq!(persist, pressed != stored);

    if let Some(cycled) = cycle_use_counter(stored) {
        assert!(stored < cycled && cycled <= USE_COUNTER_MAX);
    }

    // Vacuity guard: the assumed region must still reach a write on both paths,
    // or the bounds above hold for the empty reason. Kani exits 0 on a cover
    // nothing satisfies — `scripts/kani.sh`'s cover row is what fails the tier.
    kani::cover!(persist);
    kani::cover!(cycle_use_counter(stored).is_some());
}

/// One rule, two owners of it — not two writers of the counter, which is a
/// larger set (see above). On the press whose session wraps, the per-press
/// writer must take exactly the step a boot's first press takes from the same
/// stored value, and stop exactly where it stops; on every other press the counter
/// must not move at all. The two disagreed: `ticket::build` guarded the counter it
/// had and then incremented (storing 0x8000, the reserved high bit), while the boot
/// step guards the counter it is about to store. A stored 0x8000 froze the boot
/// step permanently, leaving the session to restart at 0 every power-up and the
/// `(use, session)` pair to repeat every 256 presses.
#[kani::proof]
fn the_two_stepped_writers_agree() {
    let stored: u16 = kani::any();
    let session: u8 = kani::any();
    kani::assume(stored <= USE_COUNTER_MAX);

    let (pressed, next_session, persist) = next_use_counter(stored, session);
    let cycled = cycle_use_counter(stored);
    if next_session == 0 {
        assert_eq!(persist, cycled.is_some());
        assert_eq!(pressed, cycled.unwrap_or(stored));
        // Both sides of the wrapping press have to be reachable, or the
        // agreement above is asserted over an empty region.
        kani::cover!(persist);
        kani::cover!(!persist);
    } else {
        assert!(!persist && pressed == stored);
    }
}
