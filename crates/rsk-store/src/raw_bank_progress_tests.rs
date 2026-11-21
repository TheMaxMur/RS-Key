// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

struct NonemptyIo(FaultFlash);

impl ErrorType for NonemptyIo {
    type Error = FlashFault;
}

impl ReadNorFlash for NonemptyIo {
    const READ_SIZE: usize = FaultFlash::READ_SIZE;

    async fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result2<()> {
        if bytes.is_empty() {
            return Err(FlashFault);
        }
        self.0.read(offset, bytes).await
    }

    fn capacity(&self) -> usize {
        self.0.capacity()
    }
}

impl NorFlash for NonemptyIo {
    const WRITE_SIZE: usize = FaultFlash::WRITE_SIZE;
    const ERASE_SIZE: usize = FaultFlash::ERASE_SIZE;

    async fn write(&mut self, offset: u32, bytes: &[u8]) -> Result2<()> {
        if bytes.is_empty() {
            return Err(FlashFault);
        }
        self.0.write(offset, bytes).await
    }

    async fn erase(&mut self, from: u32, to: u32) -> Result2<()> {
        self.0.erase(from, to).await
    }
}

impl MultiwriteNorFlash for NonemptyIo {}

#[test]
fn a_completed_bank_read_needs_no_empty_backend_transfer() {
    let flash = FaultFlash::new();
    let mut bank = RawBank::new(NonemptyIo(flash.clone()), MAIN).unwrap();
    let mut out = [0; 32];
    assert_eq!(bank.read(0, &mut out), Ok(()));
    assert_eq!(out, [0xFF; 32]);
    assert_eq!(bank.read(bank.capacity(), &mut []), Ok(()));
}

#[test]
fn a_completed_bank_program_needs_no_empty_backend_transfer() {
    let flash = FaultFlash::new();
    let mut bank = RawBank::new(NonemptyIo(flash.clone()), MAIN).unwrap();
    assert_eq!(bank.program(0, &[0x5A; 32]), Ok(()));
    assert_eq!(bank.program(bank.capacity(), &[]), Ok(()));
    assert_eq!(flash.inner.snapshot(0..32), [0x5A; 32]);
}
