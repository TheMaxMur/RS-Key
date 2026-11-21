// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::authenticated::{KeySource, RootRead};
use embedded_storage_async::nor_flash::{ErrorType, MultiwriteNorFlash, NorFlash, ReadNorFlash};

#[derive(Clone)]
struct WideRead(FaultFlash);
impl ErrorType for WideRead {
    type Error = crate::tests::FlashFault;
}
impl ReadNorFlash for WideRead {
    const READ_SIZE: usize = 32;
    async fn read(&mut self, at: u32, out: &mut [u8]) -> core::result::Result<(), Self::Error> {
        assert!(at.is_multiple_of(32));
        assert!(out.len().is_multiple_of(32));
        self.0.read(at, out).await
    }
    fn capacity(&self) -> usize {
        self.0.capacity()
    }
}
impl NorFlash for WideRead {
    const WRITE_SIZE: usize = 4;
    const ERASE_SIZE: usize = 4096;
    async fn write(&mut self, at: u32, bytes: &[u8]) -> core::result::Result<(), Self::Error> {
        self.0.write(at, bytes).await
    }
    async fn erase(&mut self, from: u32, to: u32) -> core::result::Result<(), Self::Error> {
        self.0.erase(from, to).await
    }
}
impl MultiwriteNorFlash for WideRead {}

#[test]
fn a_proven_read_refuses_a_payload_whose_aligned_window_exceeds_its_scratch() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let mut main = main_on(WideRead(flash.clone()));
    let source = KeySource::new([0x43; 32], |_| RootRead::Blank, false);
    let key = source.key(RootArm::PreOtp).unwrap();
    let small = 0xB000;
    let large = 0xB001;
    block_on(
        main.map
            .store_item(main.buffer.expose_mut(), &small, &&b"owner"[..]),
    )
    .unwrap();
    let mut directory = Directory::<MAX_MAIN_ENTRIES>::new();
    for (fid, data) in [
        (small, &b"owner"[..]),
        (large, &[7; rsk_fs::MAX_VALUE_BYTES][..]),
    ] {
        directory
            .apply(Entry::live(main.identity, key.expose(), fid, 1, data).unwrap())
            .unwrap();
    }
    let checkpoint = Checkpoint {
        identity: main.identity,
        arm: RootArm::PreOtp,
        sequence: 1,
        entries: 2,
        digest: directory.digest(main.identity, key.expose(), 1).unwrap(),
    };
    for journal in &mut main.journals {
        journal
            .write_snapshot(checkpoint, key.expose(), &directory)
            .unwrap();
    }
    let mut owner = [0; 5];
    assert_eq!(main.read(key.expose(), small, &mut owner), Ok(Some(5)));
    assert_eq!(&owner, b"owner");
    assert!(main.read_cache.is_some());
    let before = flash.image();
    flash.arm(&[]);
    let mut out = [0xa5; 16];
    assert_eq!(
        main.read_with_source(source, RootArm::PreOtp, large, &mut out),
        Err(Error::MemoryFatal)
    );
    assert_eq!(out, [0xa5; 16]);
    assert_eq!(flash.image(), before);
    assert!(flash.events().is_empty());
}
