// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::image::elf::{Segment, Symbol};

const KV: usize = 0x28_0000;

fn image(fill: u8, len: usize) -> Elf {
    Elf {
        segments: vec![
            Segment {
                paddr: XIP_BASE,
                data: vec![fill; len],
            },
            // RAM-only: nothing to program.
            Segment {
                paddr: 0x2000_0000,
                data: vec![0xEE; 16],
            },
        ],
        symbols: Vec::new(),
    }
}

fn scratch(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("rsk-emu-flash-{name}-{}.bin", std::process::id()))
}

#[test]
fn a_blank_chip_takes_the_image_and_nothing_else() {
    let (f, fresh) = Flash::open(None, &image(0xA5, SECTOR + 10)).unwrap();
    assert!(fresh);
    assert!(f.bytes()[..SECTOR + 10].iter().all(|&b| b == 0xA5));
    assert!(f.bytes()[SECTOR + 10..].iter().all(|&b| b == 0xFF));
    assert_eq!(f.bytes().len(), FLASH_SIZE);
}

#[test]
fn a_new_image_rewrites_its_own_sectors_and_keeps_the_kv_store() {
    let path = scratch("reimage");
    let _ = std::fs::remove_file(&path);
    let (mut f, fresh) = Flash::open(Some(&path), &image(0x11, 2 * SECTOR)).unwrap();
    assert!(fresh);
    let mut chip = f.bytes().to_vec();
    chip[KV..KV + 4].copy_from_slice(b"KV!!");
    assert_eq!(f.sync_from(&chip).unwrap(), 1, "one sector changed");

    let (f, fresh) = Flash::open(Some(&path), &image(0x22, 10)).unwrap();
    assert!(!fresh);
    assert_eq!(&f.bytes()[KV..KV + 4], b"KV!!");
    assert!(f.bytes()[..10].iter().all(|&b| b == 0x22));
    assert!(
        f.bytes()[10..SECTOR].iter().all(|&b| b == 0xFF),
        "the rest of the sector it covers is erased"
    );
    assert!(
        f.bytes()[SECTOR..2 * SECTOR].iter().all(|&b| b == 0x11),
        "a sector the new image does not cover is left alone"
    );
    let on_disk = std::fs::read(&path).unwrap();
    assert_eq!(on_disk, f.bytes());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_store_that_is_not_a_whole_chip_is_refused() {
    let path = scratch("short");
    std::fs::write(&path, [0u8; 1024]).unwrap();
    let err = Flash::open(Some(&path), &image(0, 4)).err().unwrap();
    assert!(err.contains("whole"), "{err}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn an_image_that_leaves_the_flash_is_refused() {
    let mut elf = image(0, 4);
    elf.segments[0].paddr = XIP_BASE + FLASH_SIZE as u32 - 2;
    assert!(Flash::open(None, &elf).is_err());
}

#[test]
fn the_linker_store_boundary_selects_the_whole_flash_capacity() {
    for (end, size) in [
        (2 * 1024 * 1024, 2 * 1024 * 1024),
        (4 * 1024 * 1024, 4 * 1024 * 1024),
        (8 * 1024 * 1024, 8 * 1024 * 1024),
        (16 * 1024 * 1024 - SECTOR, 16 * 1024 * 1024),
    ] {
        let mut elf = image(0xa5, 16);
        elf.symbols.push(Symbol {
            name: "__kvcnt_end".into(),
            value: end as u32,
            size: 0,
        });
        let (mut flash, _) = Flash::open(None, &elf).unwrap();
        assert_eq!(flash.bytes().len(), size);
        let mut chip = flash.bytes().to_vec();
        chip[end - 1] = 0x42;
        assert_eq!(flash.sync_from(&chip).unwrap(), 1);
        assert_eq!(flash.bytes()[end - 1], 0x42);
        assert!(flash.sync_from(&chip[..size - SECTOR]).is_err());
        elf.symbols[0].value = (size + SECTOR) as u32;
        assert!(Flash::open(None, &elf).is_err());
    }
}

#[test]
fn a_large_chip_reload_preserves_the_upper_store_and_its_file_length() {
    let path = scratch("eight-mib");
    let _ = std::fs::remove_file(&path);
    let mut elf = image(0x11, SECTOR);
    elf.symbols.push(Symbol {
        name: "__kvcnt_end".into(),
        value: 8 * 1024 * 1024,
        size: 0,
    });
    let (mut flash, _) = Flash::open(Some(&path), &elf).unwrap();
    assert_eq!(flash.bytes().len(), 8 * 1024 * 1024);
    let mut chip = flash.bytes().to_vec();
    chip[6 * 1024 * 1024..][..4].copy_from_slice(b"KV!!");
    assert_eq!(flash.sync_from(&chip).unwrap(), 1);
    drop(flash);
    elf.segments[0].data.fill(0x22);
    let (flash, fresh) = Flash::open(Some(&path), &elf).unwrap();
    assert!(!fresh);
    assert_eq!(&flash.bytes()[6 * 1024 * 1024..][..4], b"KV!!");
    assert_eq!(std::fs::read(&path).unwrap(), flash.bytes());
    let _ = std::fs::remove_file(&path);
}
