// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use core::cell::Cell;
use embedded_storage_async::nor_flash::{ErrorType, NorFlash, ReadNorFlash};
use std::rc::Rc;

#[derive(Clone)]
struct TransientRead {
    flash: FaultFlash,
    fault: Rc<Cell<Option<ReadFault>>>,
    hits: Rc<Cell<usize>>,
}

#[derive(Clone, Copy)]
enum ReadFault {
    OwnerPrefix(u32),
    PageMarker { skip: usize },
}

impl ErrorType for TransientRead {
    type Error = crate::tests::FlashFault;
}

impl ReadNorFlash for TransientRead {
    const READ_SIZE: usize = 1;

    #[expect(
        clippy::indexing_slicing,
        reason = "The injected read fault changes a checked, fixed-width fixture window."
    )]
    async fn read(
        &mut self,
        offset: u32,
        bytes: &mut [u8],
    ) -> core::result::Result<(), Self::Error> {
        self.flash.read(offset, bytes).await?;
        match self.fault.get() {
            Some(ReadFault::OwnerPrefix(at)) if offset == at && bytes.len() == 4 => {
                assert_eq!(&bytes[..2], &0xB001u16.to_le_bytes());
                bytes[..2].copy_from_slice(&0xB000u16.to_le_bytes());
                self.hits.set(self.hits.get() + 1);
                self.fault.set(None);
            }
            Some(ReadFault::PageMarker { skip }) if offset == 2 * 4096 - 1 && bytes.len() == 2 => {
                if skip > 0 {
                    self.fault
                        .set(Some(ReadFault::PageMarker { skip: skip - 1 }));
                } else {
                    assert_eq!(bytes, [0xFF; 2]);
                    bytes[0] = 0;
                    self.hits.set(self.hits.get() + 1);
                    self.fault.set(None);
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn capacity(&self) -> usize {
        self.flash.capacity()
    }
}

impl NorFlash for TransientRead {
    const WRITE_SIZE: usize = 4;
    const ERASE_SIZE: usize = 4096;

    async fn write(&mut self, offset: u32, bytes: &[u8]) -> core::result::Result<(), Self::Error> {
        self.flash.write(offset, bytes).await
    }

    async fn erase(&mut self, from: u32, to: u32) -> core::result::Result<(), Self::Error> {
        self.flash.erase(from, to).await
    }
}

impl MultiwriteNorFlash for TransientRead {}

#[test]
#[expect(
    clippy::indexing_slicing,
    reason = "The fixture locates and compares the complete published record in a retained flash image."
)]
fn an_unverified_prefix_cannot_retire_the_verified_published_owner() {
    let flash = crate::tests::fault_flash_for_authenticated_tests();
    let fault = Rc::new(Cell::new(None));
    let hits = Rc::new(Cell::new(0));
    let mut main = main_on(TransientRead {
        flash: flash.clone(),
        fault: fault.clone(),
        hits: hits.clone(),
    });
    main.initialize(&KEY, 0, &Directory::new()).unwrap();
    main.write(&KEY, 0xB001, Some(b"owner")).unwrap();
    let before = flash.image();
    let positions = before[..32768]
        .windows(7)
        .enumerate()
        .filter_map(|(at, bytes)| (bytes == [1, 0xB0, b'o', b'w', b'n', b'e', b'r']).then_some(at))
        .collect::<Vec<_>>();
    assert_eq!(positions.len(), 1);
    let payload = positions[0];
    let header = payload - 8..payload;
    let record = header.start..payload + 8;
    flash.arm(&[]);
    fault.set(Some(ReadFault::OwnerPrefix(
        u32::try_from(payload).unwrap(),
    )));

    let result = main.write(&KEY, 0xB002, Some(b"new"));
    let events = flash.events();
    let after = flash.image();
    assert_eq!(hits.get(), 1);
    assert!(fault.get().is_none());
    assert_eq!(&after[record.clone()], &before[record]);
    assert!(events.iter().all(|event| event.0 != Io::Erase));
    assert!(
        events
            .iter()
            .filter(|event| event.0 == Io::Program)
            .all(|event| {
                let start = usize::try_from(event.1).unwrap();
                start + event.2 <= header.start || start >= header.end
            })
    );
    assert_eq!(result, Ok(()));
    let mut owner = [0xA5; 5];
    assert_eq!(main.read(&KEY, 0xB001, &mut owner), Ok(Some(5)));
    assert_eq!(&owner, b"owner");
    let mut added = [0xA5; 3];
    assert_eq!(main.read(&KEY, 0xB002, &mut added), Ok(Some(3)));
    assert_eq!(&added, b"new");
}

#[test]
fn a_transient_page_marker_uses_resolution_before_and_after_publication() {
    for (skip, value) in [(0, Some(&b"new"[..])), (1, Some(&b"new"[..])), (1, None)] {
        let flash = crate::tests::fault_flash_for_authenticated_tests();
        let fault = Rc::new(Cell::new(None));
        let hits = Rc::new(Cell::new(0));
        let mut main = main_on(TransientRead {
            flash: flash.clone(),
            fault: fault.clone(),
            hits: hits.clone(),
        });
        main.initialize(&KEY, 0, &Directory::new()).unwrap();
        main.write(&KEY, 0xB001, Some(b"owner")).unwrap();
        main.write(&KEY, 0xB002, Some(b"prior")).unwrap();
        flash.arm(&[]);
        fault.set(Some(ReadFault::PageMarker { skip }));

        assert_eq!(main.write(&KEY, 0xB002, value), Ok(()));
        let events = flash.events();
        assert_eq!(hits.get(), 1);
        assert!(fault.get().is_none());
        assert!(events.iter().all(|event| event.0 != Io::Erase));
        let mut owner = [0xA5; 5];
        assert_eq!(main.read(&KEY, 0xB001, &mut owner), Ok(Some(5)));
        assert_eq!(&owner, b"owner");
        let mut changed = [0xA5; 3];
        assert_eq!(
            main.read(&KEY, 0xB002, &mut changed),
            Ok(value.map(<[u8]>::len))
        );
        match value {
            Some(bytes) => assert_eq!(changed, bytes),
            None => assert_eq!(changed, [0xA5; 3]),
        }
    }
}
