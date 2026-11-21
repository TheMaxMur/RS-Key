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
fn display_board_releases_wake_and_observes_pwm_instead_of_an_invented_brightness() {
    let mut chip = chip(12);
    chip.enable_panel(super::super::touch::SharedTouch::default())
        .unwrap();
    chip.step(1).unwrap();
    assert_ne!(chip.emu.gpio_read_all() & u64::from(WAKE_BUTTON), 0);
    chip.press_wake(true);
    chip.step(1).unwrap();
    assert_eq!(chip.emu.gpio_read_all() & u64::from(WAKE_BUTTON), 0);
    chip.press_wake(false);
    chip.step(1).unwrap();
    assert_ne!(chip.emu.gpio_read_all() & u64::from(WAKE_BUTTON), 0);
    chip.emu.bus.write32(BACKLIGHT_TOP, 255, 0);
    chip.emu.bus.write32(BACKLIGHT_CC, 128, 0);
    chip.emu.bus.write32(BACKLIGHT_CSR, 1, 0);
    assert_eq!(chip.backlight(), (128, 255));
    chip.emu.bus.write32(BACKLIGHT_CSR, 0, 0);
    assert_eq!(chip.backlight(), (0, 255));
}

fn stack_chip(nonsecure: bool) -> Chip {
    const NS_VECTOR: u32 = 0x1000_1000;
    let mut chip = chip(12);
    let elf = Arc::get_mut(&mut chip.elf).unwrap();
    for (name, value, size) in [
        ("_stack_end", 0x2000_0000, 0),
        ("_stack_start", 0x2000_1000, 0),
        ("core1::CORE1_STACK", 0x2000_2000, 4096),
    ] {
        elf.symbols.push(Symbol {
            name: name.into(),
            value,
            size,
        });
    }
    let mut vectors = 0x2007_8000u32.to_le_bytes().to_vec();
    vectors.extend_from_slice(&(NS_VECTOR + 9).to_le_bytes());
    vectors.extend_from_slice(&[0, 0xbf, 0, 0xbf, 0, 0xbf]);
    elf.segments.push(crate::image::elf::Segment {
        paddr: NS_VECTOR,
        data: vectors.clone(),
    });
    chip.emu
        .bus
        .memory
        .xip_write(NS_VECTOR - 0x1000_0000, &vectors);
    for index in 0..2 {
        let core = chip.emu.core_mut(index);
        core.regs.msplim = 0x2000_0000 + index as u32 * 0x2000;
        core.regs.msp = core.regs.msplim + 0xf00;
        core.regs.set_sp(core.regs.msp);
    }
    let core = chip.emu.core_mut(0);
    core.ppb.ns.vtor = NS_VECTOR;
    core.ppb.sau_ctrl = 1;
    core.ppb.sau_regions[0] = (NS_VECTOR, NS_VECTOR + 0xfe1);
    core.ppb.sau_regions[1] = (0x2007_0000, 0x2007_ffe1);
    core.ppb.sau_regions[2] = (0x1000_2000, 0x1000_2003);
    core.regs.msp_ns = 0x2007_7f00;
    core.regs.msplim_ns = 0x2007_0000;
    core.regs.set_pc(NS_VECTOR + 8);
    if nonsecure {
        core.regs.r[0] = NS_VECTOR + 8;
        core.regs.set_pc(0x1000_0080);
        chip.emu.bus.memory.xip_write(0x80, &[4, 0x47]);
        chip.step(1).unwrap();
    }
    chip
}

#[test]
fn measurement_can_start_while_core0_runs_nonsecure() {
    let mut chip = stack_chip(true);
    assert!(
        chip.begin_measurement().is_ok(),
        "a valid NS stack must not be compared to S bounds"
    );
}

fn measurement_value(report: &str, name: &str) -> u32 {
    report
        .split_whitespace()
        .find_map(|word| word.strip_prefix(&format!("{name}=")))
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
fn painting_keeps_the_live_frames_of_both_security_banks() {
    for nonsecure in [false, true] {
        let mut chip = stack_chip(nonsecure);
        for address in [0x2000_0f00, 0x2007_7f00] {
            chip.plant_sram(address, &[0x5a; 32]);
        }
        chip.begin_measurement().unwrap();
        for address in [0x2000_0f00, 0x2007_7f00] {
            assert_eq!(chip.read_sram(address, 32), "5a".repeat(32));
        }
        let report = chip.end_measurement().unwrap();
        assert_eq!(measurement_value(&report, "core0_min"), 0x2000_0f00);
        assert_eq!(measurement_value(&report, "ns0_min"), 0x2007_7f00);
        assert_eq!(measurement_value(&report, "core1_min"), 0x2000_2f00);
    }
}

#[test]
fn instruction_sampling_keeps_secure_and_nonsecure_peaks_separate() {
    let mut chip = stack_chip(true);
    assert!(!chip.emu.core(0).is_secure());
    chip.begin_measurement().unwrap();
    chip.emu.core_mut(0).regs.set_sp(0x2007_0100);
    chip.step(1).unwrap();
    chip.emu
        .bus
        .memory
        .xip_write(0x2000, &[0x7f, 0xe9, 0x7f, 0xe9, 0, 0xbf]);
    chip.emu.core_mut(0).regs.set_pc(0x1000_2000);
    for _ in 0..16 {
        chip.step(1).unwrap();
        if chip.emu.core(0).is_secure() {
            break;
        }
    }
    assert!(chip.emu.core(0).is_secure());
    chip.emu.core_mut(0).regs.set_sp(0x2000_0080);
    chip.step(1).unwrap();
    chip.emu.core_mut(0).regs.r[0] = 0x1000_1008;
    chip.emu.core_mut(0).regs.set_pc(0x1000_0080);
    for _ in 0..16 {
        chip.step(1).unwrap();
        if !chip.emu.core(0).is_secure() {
            break;
        }
    }
    assert!(!chip.emu.core(0).is_secure());
    chip.emu.core_mut(0).regs.set_sp(0x2007_7f00);
    chip.step(1).unwrap();
    let report = chip.end_measurement().unwrap();
    assert_eq!(measurement_value(&report, "core0_min"), 0x2000_0080);
    assert_eq!(measurement_value(&report, "ns0_min"), 0x2007_0100);
}

#[test]
fn an_ns_underflow_cannot_hide_behind_a_healthy_secure_stack() {
    let mut chip = stack_chip(true);
    chip.begin_measurement().unwrap();
    chip.emu.core_mut(0).regs.set_sp(0x2006_fffc);
    chip.step(1).unwrap();
    let report = chip.end_measurement().unwrap();
    assert!(measurement_value(&report, "ns0_min") < measurement_value(&report, "ns0_low"));
    assert!(measurement_value(&report, "core0_min") >= measurement_value(&report, "core0_low"));
}

#[test]
fn invalid_ns_limits_and_process_stacks_are_refused_before_painting() {
    for nonsecure in [false, true] {
        for process_stack in [false, true] {
            let mut chip = stack_chip(nonsecure);
            chip.plant_sram(0x2000_0000, &[0x5a; 32]);
            let core = chip.emu.core_mut(0);
            if nonsecure {
                if process_stack {
                    core.regs.control = 2;
                } else {
                    core.regs.msplim = 0x2006_ffe0;
                }
            } else if process_stack {
                core.regs.control_ns = 2;
            } else {
                core.regs.msplim_ns = 0x2006_ffe0;
            }
            let error = chip.begin_measurement().unwrap_err();
            assert!(
                error.contains(if process_stack {
                    "process-stack"
                } else {
                    "ns0 is outside"
                }),
                "{error}"
            );
            assert_eq!(chip.read_sram(0x2000_0000, 32), "5a".repeat(32));
        }
    }
}

#[test]
fn ns_stack_budget_uses_the_elf_vector_instead_of_live_flash() {
    let mut chip = stack_chip(true);
    chip.emu
        .bus
        .memory
        .xip_write(0x1000, &0x2007_fff8u32.to_le_bytes());
    chip.begin_measurement().unwrap();
    let report = chip.end_measurement().unwrap();
    assert_eq!(measurement_value(&report, "ns0_top"), 0x2007_8000);
}

#[test]
fn overlapping_stack_ranges_are_refused_before_painting() {
    let mut chip = stack_chip(true);
    chip.plant_sram(0x2000_0f00, &[0x5a; 32]);
    let core = chip.emu.core_mut(0);
    core.ppb.sau_regions[1] = (0x2000_0000, 0x2007_ffe1);
    core.regs.msplim = 0x2000_0000;
    assert!(chip.begin_measurement().unwrap_err().contains("overlap"));
    assert_eq!(chip.read_sram(0x2000_0f00, 32), "5a".repeat(32));
}

#[test]
fn ambiguous_ns_attribution_is_refused_before_painting() {
    for region in [
        (0x1000_1000, 0x1000_1fe1),
        (0x2007_0000, 0x2007_0023),
        (0x2007_0000, 0x2007_0021),
    ] {
        let mut chip = stack_chip(true);
        chip.plant_sram(0x2000_0000, &[0x5a; 32]);
        chip.emu.core_mut(0).ppb.sau_regions[3] = region;
        assert!(chip.begin_measurement().unwrap_err().contains("SAU"));
        assert_eq!(chip.read_sram(0x2000_0000, 32), "5a".repeat(32));
    }
}

#[test]
fn an_ordinary_image_keeps_its_two_stack_report() {
    let mut chip = stack_chip(false);
    chip.emu.core_mut(0).ppb.ns.vtor = 0;
    chip.begin_measurement().unwrap();
    assert!(!chip.end_measurement().unwrap().contains("ns0_"));
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
        chip.emu.core_mut(core).ppb.sfsr = 0x48;
        chip.emu.core_mut(core).ppb.sfar = 0x2008_0100;
        chip.emu.core_mut(core).regs.set_pc(CALLER_START);
        assert_eq!(chip.check(), None, "HardFault entry must run its cleanup");
        chip.emu.core_mut(core).regs.set_pc(PANIC_START + 2);
        assert_eq!(chip.check(), None, "panic entry must run its cleanup");
        for pc in [TERMINAL, TERMINAL + 2, TERMINAL + 6] {
            chip.emu.core_mut(core).regs.set_pc(pc);
            let Some(Stop::Dead(cause)) = chip.check() else {
                panic!("terminal PC {pc:#x}");
            };
            assert!(cause.contains("SFSR 0x00000048, SFAR 0x20080100"));
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
