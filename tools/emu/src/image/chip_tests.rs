// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::image::elf::Symbol;

const PANIC_START: u32 = 0x1000_0100;
const CALLER_START: u32 = 0x1000_0400;

fn chip(size: u32) -> Chip {
    let elf = Arc::new(Elf {
        segments: Vec::new(),
        symbols: vec![
            Symbol {
                name: "rust_begin_unwind".into(),
                value: PANIC_START | 1,
                size,
            },
            Symbol {
                name: "panic_caller".into(),
                value: CALLER_START | 1,
                size: 8,
            },
            Symbol {
                name: "next_function".into(),
                value: (CALLER_START + 8) | 1,
                size: 8,
            },
        ],
    });
    let (flash, _) = Flash::open(None, &elf).unwrap();
    let mut rom = vec![0; 256];
    rom[..4].copy_from_slice(&0x2008_0000u32.to_le_bytes());
    rom[4..8].copy_from_slice(&0x101u32.to_le_bytes());
    Chip::power_up(
        &rom,
        elf,
        &[0x55; 32],
        &flash,
        otp::factory_rows([1; 8]),
        None,
    )
    .unwrap()
}

#[test]
fn a_quantum_inside_either_cores_panic_handler_is_dead() {
    for core in 0..2 {
        for (size, pc, dead) in [
            (12, PANIC_START - 2, false),
            (12, PANIC_START, true),
            (12, PANIC_START + 2, true),
            (12, PANIC_START + 10, true),
            (12, PANIC_START + 12, false),
            (0, PANIC_START, true),
            (0, PANIC_START + 2, false),
        ] {
            let mut chip = chip(size);
            chip.emu.core_mut(core).regs.set_pc(pc);
            let stopped = chip.check();
            if dead {
                assert!(
                    matches!(stopped, Some(Stop::Dead(ref why))
                        if why.starts_with(&format!("core {core} panicked"))),
                    "core {core}, size {size}, pc {pc:#x}: {stopped:?}"
                );
            } else {
                assert_eq!(stopped, None, "core {core}, size {size}, pc {pc:#x}");
            }
        }
    }
}

#[test]
fn panic_caller_uses_the_instruction_before_the_return_address() {
    let mut chip = chip(12);
    chip.emu.core_mut(0).regs.set_pc(PANIC_START + 2);
    chip.emu.core_mut(0).regs.r[14] = (CALLER_START + 8) | 1;
    let stopped = chip.check();
    assert!(
        matches!(stopped, Some(Stop::Dead(ref why))
            if why.ends_with(" panic_caller")),
        "{stopped:?}"
    );
}

#[test]
fn a_secure_fault_policy_runs_cleanup_before_the_terminal_range() {
    const TERMINAL: u32 = 0x1000_0800;
    for core in 0..2 {
        let mut chip = chip(12);
        chip.fault_stop = Some((TERMINAL, 8));
        chip.hardfault = Some(CALLER_START);
        chip.fault_wait = Some((0x1000_0900, 4));
        chip.emu.core_mut(core).regs.set_pc(CALLER_START);
        assert_eq!(chip.check(), None, "HardFault entry must run its cleanup");
        chip.emu.core_mut(core).regs.set_pc(PANIC_START + 2);
        assert_eq!(chip.check(), None, "panic entry must run its cleanup");
        for pc in [TERMINAL, TERMINAL + 2, TERMINAL + 6] {
            chip.emu.core_mut(core).regs.set_pc(pc);
            assert!(
                matches!(chip.check(), Some(Stop::Dead(_))),
                "terminal PC {pc:#x}"
            );
        }
        chip.emu.core_mut(core).regs.set_pc(0x1000_0902);
        chip.emu.core_mut(core).regs.r[14] = (TERMINAL + 6) | 1;
        assert!(
            matches!(chip.check(), Some(Stop::Dead(_))),
            "terminal WFI helper is fenced"
        );
        chip.emu.core_mut(core).regs.r[14] = (CALLER_START + 2) | 1;
        assert_eq!(chip.check(), None, "an unrelated WFI is still live");
        chip.emu.core_mut(core).regs.set_pc(TERMINAL + 8);
        assert_eq!(
            chip.check(),
            None,
            "next symbol is outside the terminal range"
        );
    }
}
