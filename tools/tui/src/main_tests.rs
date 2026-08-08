// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

// The `--once` path prints device-controlled getInfo/identity text raw (no
// ratatui cell grid to neutralise it), so `sanitize` is the one boundary
// between a counterfeit device and the operator's terminal.

#[test]
fn sanitize_strips_ansi_osc_escapes() {
    // ESC (0x1b) + BEL (0x07): OSC window-title, CSI clear, OSC-52 clipboard.
    let out = sanitize("\u{1b}]0;pwn\u{07}\u{1b}[2Jok\u{1b}]52;c;AAAA\u{07}");
    assert!(!out.contains('\u{1b}') && !out.contains('\u{07}'));
    assert!(out.ends_with("ok\u{fffd}]52;c;AAAA\u{fffd}"));
}

#[test]
fn sanitize_strips_bidi_override() {
    // U+202E RIGHT-TO-LEFT OVERRIDE and the isolates are Cf, not Cc, so
    // `char::is_control()` alone would let this Trojan-Source reorder pass.
    for c in ['\u{202E}', '\u{202A}', '\u{2066}', '\u{2069}', '\u{200F}'] {
        assert_eq!(sanitize(&c.to_string()), "\u{fffd}");
    }
}

#[test]
fn sanitize_preserves_benign_text() {
    assert_eq!(sanitize("FIDO_2_0, U2F_V2"), "FIDO_2_0, U2F_V2");
}

// `--selftest` takes its PIN as a bare positional and talks to real hardware, so
// every misreading of that argument is charged to the operator's own key.

fn argv(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| (*s).to_string()).collect()
}

fn at_selftest(a: &[String]) -> Result<Option<&str>, &'static str> {
    let i = a.iter().position(|x| x == "--selftest").unwrap();
    selftest_pin(a, i)
}

#[test]
fn selftest_reads_the_pin_positional_and_tolerates_its_absence() {
    assert_eq!(
        at_selftest(&argv(&["rsk-tui", "--selftest", "1234"])),
        Ok(Some("1234"))
    );
    assert_eq!(at_selftest(&argv(&["rsk-tui", "--selftest"])), Ok(None));
}

#[test]
fn selftest_refuses_to_send_a_flag_as_a_pin() {
    // The device decrements the retry counter before comparing, so each of these
    // cost a real attempt; three consecutive reach PIN_AUTH_BLOCKED, which only a
    // physical power cycle clears (audit run-37).
    for tail in ["--json", "--once", "-h"] {
        let a = argv(&["rsk-tui", "--selftest", tail]);
        assert!(at_selftest(&a).is_err(), "{tail} would be sent as a PIN");
    }
}

#[test]
fn selftest_refuses_the_demo_combination_in_either_order() {
    // `--demo --selftest` used to return before `demo` was read at all, so no
    // MockProvider was built and a real master-seed export/restore ran.
    for a in [
        argv(&["rsk-tui", "--demo", "--selftest"]),
        argv(&["rsk-tui", "--selftest", "--demo"]),
        argv(&["rsk-tui", "--mock", "--selftest", "1234"]),
    ] {
        assert!(at_selftest(&a).is_err(), "{a:?} reached hardware");
    }
}
