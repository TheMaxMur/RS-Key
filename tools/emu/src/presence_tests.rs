// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use rsk_sdk::Confirm;

use super::{EmuPresence, PresenceMode, Verdict};
use crate::signals::{SCOPE_FIDO, Signals};

#[test]
fn instant_presence_confirms_without_pending_signal() {
    let signals = Arc::new(Signals::default());
    signals.set_wait_scope(SCOPE_FIDO);
    let mut presence = EmuPresence::new(PresenceMode::Instant, None, signals.clone());

    assert_eq!(presence.ask(Confirm::titled("Test?")), Verdict::Confirmed);
    assert!(!signals.up_pending_for(SCOPE_FIDO));
    assert!(!rsk_fido::UserPresence::shows_confirm(&presence));
}

#[test]
fn terminal_presence_accepts_and_declines_lines() {
    for (line, want) in [("", Verdict::Confirmed), ("d", Verdict::Declined)] {
        let (tx, rx) = mpsc::channel();
        tx.send(line.to_owned()).unwrap();
        let mut presence = EmuPresence::new(
            PresenceMode::Terminal,
            Some(rx),
            Arc::new(Signals::default()),
        );

        assert_eq!(presence.ask(Confirm::titled("Test?")), want);
        assert!(rsk_fido::UserPresence::shows_confirm(&presence));
    }
}

#[test]
fn delayed_presence_marks_pending_and_auto_confirms() {
    let signals = Arc::new(Signals::default());
    signals.set_wait_scope(SCOPE_FIDO);
    signals.begin(0x0102_0304);
    let delay = Duration::from_millis(25);
    let mut presence = EmuPresence::new(PresenceMode::Delayed(delay), None, signals.clone());

    let started = Instant::now();
    assert_eq!(presence.ask(Confirm::titled("Test?")), Verdict::Confirmed);
    assert!(started.elapsed() >= delay);
    assert!(!signals.up_pending_for(SCOPE_FIDO));
    // A timer answered the prompt, so no one confirmed anything: this stays the
    // auto-confirming kind of authenticator, which CTAP 2.1 §6.6 does NOT exempt
    // from the reset window. Claiming otherwise let a reset through 13 s after
    // power-on — see `EmuPresence::shows_confirm`.
    assert!(!rsk_fido::UserPresence::shows_confirm(&presence));
}

#[test]
fn delayed_presence_honours_scoped_cancel_before_confirmation() {
    let signals = Arc::new(Signals::default());
    signals.set_wait_scope(SCOPE_FIDO);
    signals.begin(0x0102_0304);
    let mut presence = EmuPresence::new(
        PresenceMode::Delayed(Duration::from_millis(500)),
        None,
        signals.clone(),
    );
    let (result_tx, result_rx) = mpsc::channel();
    std::thread::spawn(move || {
        result_tx
            .send(presence.ask(Confirm::titled("Test?")))
            .unwrap();
    });

    for _ in 0..100 {
        if signals.up_pending_for(SCOPE_FIDO) {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(signals.up_pending_for(SCOPE_FIDO));

    signals.request_cancel(0x0506_0708);
    assert!(result_rx.recv_timeout(Duration::from_millis(75)).is_err());
    signals.request_cancel(0x0102_0304);
    assert_eq!(
        result_rx.recv_timeout(Duration::from_millis(100)).unwrap(),
        Verdict::Cancelled
    );
    assert!(!signals.up_pending_for(SCOPE_FIDO));
}
