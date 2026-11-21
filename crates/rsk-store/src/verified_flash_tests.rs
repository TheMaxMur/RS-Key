// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use core::convert::Infallible;

struct WindowFlash {
    bytes: [u8; 512],
    next_offset: u32,
    read_bytes: usize,
    count: usize,
}

impl ErrorType for WindowFlash {
    type Error = Infallible;
}

impl ReadNorFlash for WindowFlash {
    const READ_SIZE: usize = 4;
    async fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), Self::Error> {
        assert!(
            !out.is_empty(),
            "readback must advance through a nonempty window"
        );
        assert_eq!(
            offset, self.next_offset,
            "readback must advance without gaps"
        );
        assert_eq!(offset as usize % Self::READ_SIZE, 0);
        assert_eq!(out.len() % Self::READ_SIZE, 0);
        assert!(out.len() <= 260 - self.read_bytes);
        self.count += 1;
        let start = offset as usize;
        out.copy_from_slice(&self.bytes[start..start + out.len()]);
        self.read_bytes += out.len();
        self.next_offset += out.len() as u32;
        Ok(())
    }
    fn capacity(&self) -> usize {
        self.bytes.len()
    }
}

impl NorFlash for WindowFlash {
    const WRITE_SIZE: usize = 4;
    const ERASE_SIZE: usize = 4;
    async fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        let start = offset as usize;
        self.bytes[start..start + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
    async fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        self.bytes[from as usize..to as usize].fill(0xff);
        Ok(())
    }
}

fn flash() -> VerifiedFlash<WindowFlash> {
    VerifiedFlash::new(WindowFlash {
        bytes: [0xff; 512],
        next_offset: 4,
        read_bytes: 0,
        count: 0,
    })
}

#[test]
fn a_program_is_verified_with_nonempty_readback_windows() {
    let mut flash = flash();
    embassy_futures::block_on(flash.write(4, &[0x5a; 260])).unwrap();
    assert_eq!(flash.0.read_bytes, 260);
    assert_eq!(flash.0.next_offset, 264);
}

#[test]
fn an_empty_program_requires_no_readback() {
    let mut flash = flash();
    embassy_futures::block_on(flash.write(4, &[])).unwrap();
    assert_eq!(flash.0.count, 0);
    assert_eq!(flash.0.read_bytes, 0);
}
