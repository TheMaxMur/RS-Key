// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

const PHOFF: usize = 52;
const DATA: usize = PHOFF + 32;
const SYMTAB: usize = DATA + 8;
const STRTAB: usize = SYMTAB + 32;
const SHOFF: usize = 136;

fn put(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// An ELF32 with one 8-byte PT_LOAD at 0x1000_0000 and one 4-byte function.
fn tiny() -> Vec<u8> {
    let mut b = vec![0u8; SHOFF + 2 * 40];
    b[..6].copy_from_slice(&[0x7F, b'E', b'L', b'F', 1, 1]);
    put(&mut b, 0x1C, PHOFF as u32);
    put(&mut b, 0x20, SHOFF as u32);
    b[0x2A] = 32; // e_phentsize
    b[0x2C] = 1; // e_phnum
    b[0x2E] = 40; // e_shentsize
    b[0x30] = 2; // e_shnum
    put(&mut b, PHOFF, 1); // PT_LOAD
    put(&mut b, PHOFF + 4, DATA as u32);
    put(&mut b, PHOFF + 12, 0x1000_0000);
    put(&mut b, PHOFF + 16, 8);
    b[DATA..DATA + 8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    put(&mut b, SYMTAB + 16, 1); // symbol 1: its name at strtab + 1
    put(&mut b, SYMTAB + 20, 0x1000_0101);
    put(&mut b, SYMTAB + 24, 4);
    b[STRTAB..STRTAB + 9].copy_from_slice(b"\0main_fn\0");
    put(&mut b, SHOFF + 4, 2); // SHT_SYMTAB
    put(&mut b, SHOFF + 16, SYMTAB as u32);
    put(&mut b, SHOFF + 20, 32);
    put(&mut b, SHOFF + 24, 1); // its strings are section 1
    put(&mut b, SHOFF + 40 + 4, 3); // SHT_STRTAB
    put(&mut b, SHOFF + 40 + 16, STRTAB as u32);
    b
}

#[test]
fn load_segments_and_function_symbols_are_read() {
    let elf = Elf::parse(&tiny()).unwrap();
    assert_eq!(elf.segments.len(), 1);
    assert_eq!(elf.segments[0].paddr, 0x1000_0000);
    assert_eq!(elf.segments[0].data, [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(elf.symbol(&["main"]).map(|s| s.value), Some(0x1000_0101));
    let at = |a| elf.function_at(a).map(|s| s.name.as_str());
    assert_eq!(at(0x1000_0103), Some("main_fn"), "the Thumb bit is ignored");
    assert_eq!(at(0x1000_0104), None);
}

#[test]
fn what_is_not_a_little_endian_elf32_is_refused() {
    let mut b = tiny();
    b[4] = 2; // ELFCLASS64
    assert!(Elf::parse(&b).is_err());
    assert!(Elf::parse(b"MZ").is_err());
}

#[test]
fn a_truncated_or_lying_file_is_an_error_not_a_panic() {
    let b = tiny();
    for n in [40, PHOFF + 20, DATA + 4, SHOFF + 50] {
        assert!(Elf::parse(&b[..n]).is_err(), "cut at {n}");
    }
    let mut b = tiny();
    put(&mut b, SYMTAB + 16, 0xFFFF); // a name past the end of the file
    assert!(Elf::parse(&b).is_err());
}
