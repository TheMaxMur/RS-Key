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

/// A panel point that hits NOTHING: the lifted sample a settle is made of.
///
/// Searched rather than written down, because a literal would go stale the first
/// time a control grows. The pad layout it checks is the identity one — with
/// scrambling on, a scrambled key could sit here, which is why a settle is a
/// synchronisation device and not a promise that nothing was pressed.
pub fn nowhere() -> rsk_ui::Point {
    let miss = |p| {
        rsk_ui::hit_nav(p).is_none()
            && rsk_ui::hit_pin(p, &rsk_ui::PinLayout::identity()).is_none()
            && rsk_ui::hit_settings_root(p).is_none()
            && rsk_ui::hit_security(p).is_none()
            && rsk_ui::hit_onboard(p).is_none()
            && !rsk_ui::hit_title_back(p)
            && !rsk_ui::ALLOW_RECT.contains(p)
            && !rsk_ui::DENY_RECT.contains(p)
    };
    (0..rsk_ui::PANEL_H)
        .flat_map(|y| (0..rsk_ui::PANEL_W).map(move |x| rsk_ui::Point::new(x, y)))
        .find(|&p| miss(p))
        .expect("every pixel of the panel is a control")
}

/// Resolve a control's NAME to the point that hits it, so a suite speaks the
/// vocabulary the UI owns rather than pixel coordinates that go stale the first
/// time a control moves. Searched with the panel's own hit test, which is what
/// makes the two agree by construction.
///
/// The pad resolves against the IDENTITY layout. With `Scramble PIN pad` on
/// (Settings → Security, off by default) the digits are laid out afresh for every
/// entry and nothing outside the panel can know where they went — that is the
/// setting doing its job, not a gap here, and a suite that turns it on must drive
/// the pad by coordinate or not at all.
pub fn resolve(name: &str) -> Option<rsk_ui::Point> {
    let find = |hit: &dyn Fn(rsk_ui::Point) -> bool| {
        (0..rsk_ui::PANEL_H)
            .flat_map(|y| (0..rsk_ui::PANEL_W).map(move |x| rsk_ui::Point::new(x, y)))
            .find(|&p| hit(p))
    };
    let key = |want: rsk_ui::PinKey| {
        find(&move |p| rsk_ui::hit_pin(p, &rsk_ui::PinLayout::identity()) == Some(want))
    };
    match name {
        "onboard skip" => find(&|p| rsk_ui::hit_onboard(p) == Some(rsk_ui::OnboardChoice::Skip)),
        "allow" => find(&|p| rsk_ui::ALLOW_RECT.contains(p)),
        "deny" => find(&|p| rsk_ui::DENY_RECT.contains(p)),
        "back" => find(&|p| rsk_ui::hit_title_back(p)),
        "nav home" => find(&|p| rsk_ui::hit_nav(p) == Some(rsk_ui::NavTab::Home)),
        "key ok" => key(rsk_ui::PinKey::Ok),
        "key cancel" => key(rsk_ui::PinKey::Cancel),
        "nowhere" => Some(nowhere()),
        _ => match name.strip_prefix("key ")?.parse::<u8>() {
            Ok(d) if d < 10 => key(rsk_ui::PinKey::Digit(d)),
            _ => None,
        },
    }
}

/// One socket line: `x,y[,hold_ms[,gap_ms]]` as a file carries it, or a name from
/// [`resolve`] with the same optional tail (`allow,800` is the consent hold).
pub fn parse_line(line: &str) -> Result<Vec<Tap>, String> {
    let (head, tail) = match line.find(',') {
        Some(i) => (&line[..i], &line[i..]),
        None => (line, ""),
    };
    let head = head.trim();
    if head.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return parse_script(line);
    }
    let at = resolve(head).ok_or_else(|| format!("{head:?} is not a control this panel has"))?;
    parse_script(&format!("{},{}{tail}", at.x, at.y))
}

/// Drive the pad from a socket: one contact per line, the `--taps` grammar or a
/// control's name, plus `settle` for the two lifted samples a boundary needs.
///
/// This exists because the recording apparatus had no finger. `tests/*.py` reach
/// the device over CTAPHID and nothing else, so a flow that asks the panel for a
/// PIN could not be driven from a suite — and the one recording the formal replay
/// is held to therefore had `builtin_uv` false in every event. `--taps` cannot
/// close that: a script is queued blind and consumed whenever the flow next
/// polls, so it races the host commands it is supposed to answer.
///
/// **The channel is what synchronises, exactly as it does in the crate's own
/// display tests: a bound of one.** `send` returns when the pad has room, which
/// after the first contact means it has TAKEN the previous one, and the `ok`
/// answering a line is written only then. A suite that reads `ok` before sending
/// its next command knows where the finger is.
pub fn serve(listener: std::net::TcpListener, tx: std::sync::mpsc::SyncSender<Tap>) {
    for stream in listener.incoming().flatten() {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let Ok(reading) = stream.try_clone() else {
                return;
            };
            let mut out = stream;
            for line in std::io::BufRead::lines(std::io::BufReader::new(reading)) {
                let Ok(line) = line else { return };
                let queued = match line.trim() {
                    // Two, not one: a gesture boundary can be two nested release
                    // waits deep, and each returns on the FIRST lifted sample.
                    "settle" => {
                        let p = nowhere();
                        Ok(vec![Tap::at(p.x, p.y), Tap::at(p.x, p.y)])
                    }
                    rest => parse_line(rest),
                };
                let answer = match queued {
                    Ok(taps) => {
                        for tap in taps {
                            if tx.send(tap).is_err() {
                                return;
                            }
                        }
                        "ok\n".to_string()
                    }
                    // Answered rather than fatal: a suite that mistypes a line
                    // should see which one, on the connection that sent it.
                    Err(why) => format!("err {why}\n"),
                };
                if std::io::Write::write_all(&mut out, answer.as_bytes()).is_err() {
                    return;
                }
            }
        });
    }
}

#[cfg(test)]
#[path = "taps_tests.rs"]
mod tests;
