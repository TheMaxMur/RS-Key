// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn panel_input_is_bounded_to_physical_pixels_and_a_finite_image_time_hold() {
    assert_eq!(parse("panel"), Ok(Command::Panel));
    assert_eq!(parse("panel-read"), Ok(Command::PanelRead));
    assert_eq!(parse("panel-release"), Ok(Command::PanelRelease));
    assert_eq!(parse("panel-wake down"), Ok(Command::PanelWake(true)));
    assert_eq!(parse("panel-wake up"), Ok(Command::PanelWake(false)));
    assert_eq!(
        parse("panel-touch 239 319 60000"),
        Ok(Command::PanelTouch {
            x: 239,
            y: 319,
            hold_ms: 60_000
        })
    );
    for bad in [
        "panel extra",
        "panel-read extra",
        "panel-release extra",
        "panel-wake",
        "panel-wake toggle",
        "panel-touch 240 0 1",
        "panel-touch 0 320 1",
        "panel-touch -1 0 1",
        "panel-touch 0 0 0",
        "panel-touch 0 0 60001",
        "panel-touch 65536 0 1",
    ] {
        assert!(parse(bad).is_err(), "{bad}");
    }
}

#[test]
fn usb_events_require_an_exact_command_and_an_eight_byte_setup_packet() {
    assert_eq!(parse("usb-reset"), Ok(Command::UsbReset));
    assert_eq!(parse("usb-disconnect"), Ok(Command::UsbDisconnect));
    assert_eq!(parse("usb-connect"), Ok(Command::UsbConnect));
    assert_eq!(parse("where"), Ok(Command::Where));
    assert_eq!(
        parse("usb-control 210100a602000000"),
        Ok(Command::UsbControl([0x21, 1, 0, 0xa6, 2, 0, 0, 0]))
    );
    for bad in [
        "usb-reset extra",
        "usb-disconnect extra",
        "usb-connect extra",
        "usb-control",
        "usb-control 2101",
        "usb-control 210100a60200000000",
        "usb-control 210100a6020000zz",
    ] {
        assert!(parse(bad).is_err(), "{bad}");
    }
}

#[test]
fn inspection_refuses_empty_patterns_and_non_sram_writes() {
    for bad in [
        "scan",
        "scan 0",
        "scan zz",
        "plant 10000000 ab",
        "plant 20081fff abcd",
        "cut-cycles -1",
        "begin extra",
        "transport-begin extra",
    ] {
        assert!(parse(bad).is_err(), "{bad}");
    }
    assert_eq!(parse("scan 00ff"), Ok(Command::Scan(vec![0, 255])));
    assert_eq!(parse("cut-cycles 0"), Ok(Command::CutCycles(0)));
    assert_eq!(parse("transport-begin"), Ok(Command::TransportBegin));
    assert_eq!(parse("transport-end"), Ok(Command::TransportEnd));
    assert!(parse("plant 20081fff ab").is_ok());
}

#[test]
fn sram_reads_include_both_edges_and_refuse_overflow_or_other_memory() {
    assert_eq!(
        parse("read 20000000 532480"),
        Ok(Command::Read {
            address: SRAM_BASE,
            length: SRAM_LEN,
        })
    );
    assert_eq!(
        parse("read 20081fff 1"),
        Ok(Command::Read {
            address: SRAM_BASE + SRAM_LEN - 1,
            length: 1,
        })
    );
    for bad in [
        "read 1fffffff 1",
        "read 20082000 1",
        "read 20081fff 2",
        "read 20000000 0",
        "read 20000000 -1",
        "read ffffffff 4294967295",
        "read 20000000 18446744073709551615",
    ] {
        assert!(parse(bad).is_err(), "{bad}");
    }
}

#[test]
fn stack_sample_remembers_a_reserved_frame_after_return() {
    let mut stack = Stack {
        low: SRAM_BASE,
        top: SRAM_BASE + 4096,
        initial_sp: SRAM_BASE + 4000,
        min_sp: SRAM_BASE + 4000,
    };
    stack.sample(SRAM_BASE + 512);
    stack.sample(SRAM_BASE + 4000);
    assert_eq!(stack.top - stack.min_sp, 3584);
    stack.sample(SRAM_BASE - 16);
    assert!(stack.min_sp < stack.low);
}
