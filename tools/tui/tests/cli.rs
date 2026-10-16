// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The `rsk-tui` one-shot argument contract, observed at the process boundary.
//!
//! Phase 6 asks a host tool's invalid arguments and its machine-readable output
//! to be measured where an operator meets them. `main` reads `std::env::args`
//! and calls `std::process::exit`, so these are run as the built binary: the
//! `--selftest` refusals are already unit-tested, but not their exit code or
//! stderr. Every case below refuses or prints before a terminal is opened, so
//! nothing needs a device and nothing runs interactively.

use std::process::Command;

const TUI: &str = env!("CARGO_BIN_EXE_rsk-tui");

/// Run the cockpit with `args`; the process must finish on its own.
fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(TUI)
        .args(args)
        .output()
        .expect("spawn rsk-tui");
    (
        out.status.code().expect("rsk-tui exited normally"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn help_exits_zero_with_the_usage_on_stdout() {
    for flag in ["-h", "--help"] {
        let (code, out, err) = run(&[flag]);
        assert_eq!(code, 0, "{flag}: stderr {err}");
        assert!(out.contains("USAGE:"), "{flag}: {out}");
        assert!(out.contains("--json"), "{flag}: {out}");
    }
}

#[test]
fn selftest_refuses_a_flag_as_a_pin_at_the_process_boundary() {
    // The device decrements its retry counter before comparing, so a flag sent
    // as a PIN costs a real attempt; the refusal must reach the operator, not
    // just the parse helper.
    let (code, out, err) = run(&["--selftest", "--json"]);
    assert_eq!(code, 2, "stderr: {err}");
    assert!(out.is_empty(), "stdout: {out}");
    assert!(err.starts_with("rsk-tui: "), "{err}");
    assert!(err.contains("that is a flag, not a PIN"), "{err}");
    assert!(err.contains("--help"), "{err}");
    assert!(!err.contains("panicked"), "{err}");
}

#[test]
fn selftest_refuses_the_demo_combination_at_the_process_boundary() {
    for args in [
        vec!["--demo", "--selftest"],
        vec!["--selftest", "--demo"],
        vec!["--selftest", "--mock", "1234"],
    ] {
        let (code, _, err) = run(&args);
        assert_eq!(code, 2, "args {args:?}: stderr {err}");
        assert!(err.contains("cannot simulate it"), "args {args:?}: {err}");
        assert!(!err.contains("panicked"), "args {args:?}: {err}");
    }
}

#[test]
fn json_is_one_object_and_nothing_else() {
    // The documented machine-readable surface: a single JSON object on stdout.
    // A `[DEMO …]` marker or any other prose would break a script that pipes it
    // into a JSON reader, so the whole stream must parse.
    let (code, out, err) = run(&["--demo", "--json"]);
    assert_eq!(code, 0, "stderr: {err}");
    assert_eq!(out.lines().count(), 1, "stdout: {out}");
    let v: serde_json::Value = serde_json::from_str(&out).expect("--json stdout is JSON");
    assert_eq!(v["demo"], serde_json::Value::Bool(true));
    for key in [
        "transport",
        "identity",
        "fido",
        "backup",
        "lock",
        "secure_boot",
        "rollback",
        "attestation",
        "flash",
        "applets",
        "led",
        "pgp",
        "piv_meta",
        "errors",
    ] {
        assert!(v.get(key).is_some(), "--json is missing the {key:?} field");
    }
}

#[test]
fn once_is_the_human_path_and_marks_a_simulated_device() {
    // The control for the case above: the same snapshot on `--once` carries the
    // demo banner the JSON stream must not.
    let (code, out, err) = run(&["--demo", "--once"]);
    assert_eq!(code, 0, "stderr: {err}");
    assert!(out.starts_with("[DEMO"), "stdout: {out}");
}
