// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#[path = "../fuzz_targets/cross_applet.rs"]
mod cross_applet;

#[test]
fn removing_code_keeps_public_oath_commands_available() {
    let mut input = vec![0x03, 0x08, 0x07, 0x00, 0x03, 0x00, 0x00, 0x02, 0x73, 0x00];
    input.extend_from_slice(&[
        0x08, 0x23, 0x00, 0x01, 0x00, 0x00, 0x1e, 0x71, 0x04, b's', b'e', b'e', b'd', 0x73, 0x16,
        0x11, 0x06,
    ]);
    input.extend_from_slice(&[0xaa; 20]);
    cross_applet::exercise(&input);
}
