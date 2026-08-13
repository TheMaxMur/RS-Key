// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! A scripted finger for the trusted display's touch pad: a queue of contacts a
//! script or a test pushes, read back through the same [`rsk_display::TouchPad`]
//! the CST328 implements.
//!
//! Level, not edges, like the real controller — so a [`Tap`] is a *duration* of
//! contact rather than a click, and the pad reports it held for as long as the
//! flow keeps polling within it. Every tap is preceded by at least one lifted
//! sample, because every flow here debounces the contact that opened it and would
//! otherwise read one press as two.

use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

/// How long a finger stays off the panel between contacts, by default.
///
/// Sized for the **modal** poll cadence (16 ms), where one lifted sample is not
/// enough: a gesture boundary there can be two nested release waits deep — a menu
/// debounces the row tap, then the pad that row opened debounces again — and each
/// returns on the *first* lifted sample it reads, so a single one lets the second
/// wait swallow the contact after it. The ambient loop's 100 ms tick needs no
/// margin at all: the poll that takes a tap from the queue is itself the lifted
/// sample, so it arms however long this is.
const LIFT_MS: u64 = 80;

/// One scripted contact: lifted for `gap`, then held at `at` for `hold`.
///
/// Both are wall-clock, not sample counts: the flows poll anywhere between 16 ms
/// (a modal) and 100 ms (the ambient loop), so a gesture counted in samples would
/// be a different gesture depending on which screen read it.
#[derive(Clone, Copy)]
pub struct Tap {
    pub at: rsk_ui::Point,
    pub hold: Duration,
    pub gap: Duration,
}

impl Tap {
    /// A tap: one poll of contact, which is all a hit test needs, behind the
    /// standard lift. A deliberate hold — the Approve button's 800 ms fill — is
    /// `Tap { hold: …, ..Tap::at(x, y) }`.
    pub fn at(x: u16, y: u16) -> Self {
        Self {
            at: rsk_ui::Point::new(x, y),
            hold: Duration::ZERO,
            gap: Duration::from_millis(LIFT_MS),
        }
    }
}

/// Which half of a tap the pad is playing back.
#[derive(Clone, Copy)]
enum Phase {
    /// The lifted samples before the contact.
    Gap(Instant),
    /// The contact itself.
    Hold(Instant),
}

/// The queue of scripted contacts, as a touch controller.
pub struct TapPad {
    script: Receiver<Tap>,
    current: Option<(Tap, Phase)>,
}

impl TapPad {
    pub fn new(script: Receiver<Tap>) -> Self {
        Self {
            script,
            current: None,
        }
    }
}

impl rsk_display::TouchPad for TapPad {
    fn read(&mut self) -> Option<rsk_ui::Point> {
        // A contact that has run its course ends here, so the same poll can open
        // the next tap's lift rather than reporting one stale sample first.
        if let Some((tap, Phase::Hold(since))) = self.current
            && since.elapsed() >= tap.hold
        {
            self.current = None;
        }
        match self.current {
            Some((tap, Phase::Hold(_))) => Some(tap.at),
            Some((tap, Phase::Gap(since))) if since.elapsed() >= tap.gap => {
                self.current = Some((tap, Phase::Hold(Instant::now())));
                Some(tap.at)
            }
            Some(_) => None,
            None => {
                // A tap taken from the queue opens *lifted*, which is the sample
                // every debounce in the flow is waiting for.
                if let Ok(tap) = self.script.try_recv() {
                    self.current = Some((tap, Phase::Gap(Instant::now())));
                }
                None
            }
        }
    }
}

/// Parse a tap script: one contact per line, `x,y[,hold_ms[,gap_ms]]`, with `#`
/// comments and blank lines ignored. Coordinates are panel pixels (240×320), the
/// same space `rsk_ui`'s hit tests take.
pub fn parse_script(text: &str) -> Result<Vec<Tap>, String> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        // Naming the field: "needs at least x,y" for a line that has an empty
        // *third* one sends the reader looking in the wrong place.
        const FIELD: [&str; 4] = ["x", "y", "hold_ms", "gap_ms"];
        let at = |i: usize| -> Result<u64, String> {
            let field = line.split(',').nth(i).map(str::trim).unwrap_or("");
            if field.is_empty() {
                return Err(format!("line {}: {line:?} has no {}", n + 1, FIELD[i]));
            }
            field
                .parse()
                .map_err(|_| format!("line {}: {line:?} has a non-numeric {}", n + 1, FIELD[i]))
        };
        let fields = line.split(',').count();
        if fields > 4 {
            return Err(format!(
                "line {}: {line:?} has more than x,y,hold,gap",
                n + 1
            ));
        }
        // A contact off the glass hits nothing and would read as a silently
        // ignored line, so it is a parse error rather than a no-op tap.
        let coord = |i: usize, limit: u16| -> Result<u16, String> {
            match u16::try_from(at(i)?) {
                Ok(v) if v < limit => Ok(v),
                _ => Err(format!(
                    "line {}: {line:?} is off the {}×{} panel",
                    n + 1,
                    rsk_ui::PANEL_W,
                    rsk_ui::PANEL_H
                )),
            }
        };
        // An absent field keeps the default rather than zeroing it — a two-field
        // line is the common case and must still carry a usable lift.
        let mut tap = Tap::at(coord(0, rsk_ui::PANEL_W)?, coord(1, rsk_ui::PANEL_H)?);
        if fields > 2 {
            tap.hold = Duration::from_millis(at(2)?);
        }
        if fields > 3 {
            tap.gap = Duration::from_millis(at(3)?);
        }
        out.push(tap);
    }
    Ok(out)
}

#[cfg(test)]
#[path = "taps_tests.rs"]
mod tests;
