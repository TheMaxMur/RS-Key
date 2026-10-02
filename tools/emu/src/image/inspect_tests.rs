// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

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
    ] {
        assert!(parse(bad).is_err(), "{bad}");
    }
    assert_eq!(parse("scan 00ff"), Ok(Command::Scan(vec![0, 255])));
    assert_eq!(parse("cut-cycles 0"), Ok(Command::CutCycles(0)));
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
