// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// `firmware/src/main.rs`, re-read off disk at test time and parsed with the
/// standard library instead of with [`parse`].
///
/// Two readings of one file, by two implementations: a `BCD_DEVICE` that is a
/// literal again — however plausible the number — disagrees with this one the
/// moment the firmware moves, which is what the hand-copied mirror could not do.
fn firmware_counter() -> u16 {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../firmware/src/main.rs"
    ))
    .expect("the firmware source this workspace sits beside");
    let hex = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .find_map(|l| l.split_once("let device_release: u16 = 0x"))
        .expect("firmware/src/main.rs binds the counter")
        .1;
    let digits: String = hex.chars().take_while(char::is_ascii_hexdigit).collect();
    u16::from_str_radix(&digits, 16).expect("a bcdDevice-sized value")
}

#[test]
fn the_counter_is_the_firmwares_own() {
    assert_eq!(
        BCD_DEVICE,
        firmware_counter(),
        "the emulator is serving a bcdDevice the firmware in this checkout does \
         not carry — the descriptor it answers first is a lie about which build \
         it is running"
    );
}

/// A number nobody had to remember is worth nothing if the parser can be fooled
/// by prose. `bcd_gate.py` drops comment lines for exactly this, and a decoy
/// ahead of the binding is the shape it was bitten by.
#[test]
fn a_commented_binding_is_not_the_counter() {
    let src = "\
// next release: `let device_release: u16 = 0xFFFF`
    let device_release: u16 = 0x0925;
";
    assert_eq!(parse(src), 0x0925);
    // …and the decoy really is one: on its own it parses, so the test above is
    // not passing because the line is unreadable.
    assert_eq!(parse("let device_release: u16 = 0xFFFF"), 0xFFFF);
}

/// The counter is bound indented inside `fn main`, and it is the value on the
/// *first* binding either reader takes.
#[test]
fn the_first_binding_wins_wherever_it_is_indented() {
    let src = "\
fn main() {
    let device_release: u16 = 0x0925;
    let device_release: u16 = 0x0001;
}
";
    assert_eq!(parse(src), 0x0925);
}

#[test]
#[should_panic(expected = "no longer binds")]
fn a_firmware_that_stopped_binding_it_fails_the_build() {
    parse("fn main() {\n    let rel: u16 = 0x0925;\n}\n");
}

#[test]
#[should_panic(expected = "carries no digits")]
fn an_empty_value_is_not_zero() {
    parse("let device_release: u16 = 0x;\n");
}

#[test]
#[should_panic(expected = "does not fit a bcdDevice")]
fn a_value_wider_than_the_field_is_refused() {
    parse("let device_release: u16 = 0x10925;\n");
}
