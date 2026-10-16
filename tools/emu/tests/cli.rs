// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The `rsk-emu` argument contract, observed at the process boundary.
//!
//! Phase 6 asks a host tool's invalid arguments and transport failures to be
//! measured where an operator meets them: a non-zero exit and a named error on
//! stderr, never a panic. `die` exits the process, so the refusals cannot be
//! driven in-process — every case below runs the built binary. Each one is
//! refused during parsing or the first bind, before a socket is served, so no
//! case hangs or needs a device.

use std::net::TcpListener;
use std::process::Command;

const EMU: &str = env!("CARGO_BIN_EXE_rsk-emu");

/// Run the emulator with `args`; the process must finish on its own.
fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(EMU)
        .args(args)
        .output()
        .expect("spawn rsk-emu");
    (
        out.status.code().expect("rsk-emu exited normally"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A refusal: exit 2, a `rsk-emu:` line naming the problem, no panic.
fn refuses(args: &[&str], needle: &str) {
    let (code, _, err) = run(args);
    assert_eq!(code, 2, "args {args:?} exit {code}; stderr: {err}");
    assert!(err.starts_with("rsk-emu: "), "args {args:?} stderr: {err}");
    assert!(err.contains(needle), "args {args:?} stderr: {err}");
    assert!(!err.contains("panicked"), "args {args:?} stderr: {err}");
}

#[test]
fn help_exits_zero_with_the_usage_on_stdout() {
    for flag in ["-h", "--help"] {
        let (code, out, err) = run(&[flag]);
        assert_eq!(code, 0, "{flag}: stderr {err}");
        assert!(out.contains("usage: rsk-emu [options]"), "{flag}: {out}");
    }
}

#[test]
fn an_unknown_argument_is_refused_with_the_usage() {
    let (code, _, err) = run(&["--frobnicate"]);
    assert_eq!(code, 2);
    assert!(err.contains("unknown argument \"--frobnicate\""), "{err}");
    assert!(err.contains("usage: rsk-emu [options]"), "{err}");
}

#[test]
fn a_value_that_is_not_a_port_is_refused() {
    for (flag, value) in [
        ("--fido-port", "nope"),
        ("--ccid-port", "nope"),
        ("--inspect-port", "nope"),
    ] {
        refuses(&[flag, value], &format!("not a port: \"{value}\""));
    }
    // Out of the u16 range, not merely non-numeric.
    refuses(&["--fido-port", "99999"], "not a port: \"99999\"");
}

#[test]
fn a_seed_that_is_not_hex_is_refused() {
    refuses(&["--seed", "zz"], "not hex: \"zz\"");
    refuses(&["--seed", "abc"], "not hex: \"abc\""); // odd length
}

#[test]
fn a_serial_of_the_wrong_length_is_refused() {
    refuses(&["--serial", "1122"], "expected 8 bytes of hex, got 2");
}

#[test]
fn a_byte_count_that_is_not_a_number_is_refused() {
    refuses(&["--power-cut", "lots"], "not a byte count: \"lots\"");
}

#[test]
fn a_zero_auto_touch_delay_is_refused() {
    refuses(
        &["--auto-touch-ms", "0"],
        "auto-touch delay must be positive",
    );
}

#[test]
fn disabling_both_transports_serves_nothing() {
    refuses(
        &["--fido-port", "0", "--ccid-port", "0"],
        "nothing to serve",
    );
}

#[test]
fn flags_that_only_an_image_understands_need_one() {
    refuses(&["--rom", "bootrom.bin"], "add --image");
    refuses(&["--inspect-port", "7801"], "add --image");
}

#[test]
fn the_pad_flags_need_the_display() {
    refuses(&["--taps-port", "7802"], "add --display");
}

#[test]
fn an_unreadable_tap_script_is_refused() {
    refuses(
        &["--taps", "/nonexistent/rsk-emu-taps.txt"],
        "cannot read the tap script",
    );
}

#[test]
fn a_port_already_in_use_is_a_named_bind_failure() {
    // Hold the loopback port so the emulator's own bind cannot have it: the
    // failure is deterministic and needs no second process.
    let held = TcpListener::bind(("127.0.0.1", 0)).expect("bind a loopback port");
    let port = held.local_addr().unwrap().port().to_string();
    refuses(
        &["--fido-port", port.as_str(), "--ccid-port", "0"],
        "cannot bind the fido port",
    );
}
