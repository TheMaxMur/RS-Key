// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn a_cached_published_owner_does_not_read_an_unrelated_faulted_body() {
    const NEIGHBOR: u16 = 0xB000;
    const NEIGHBOR_VALUE: &[u8] = b"unread neighbor";
    let flash = FaultFlash::new();
    let mut store = mount_authenticated(&flash);
    store.initialize_blank().unwrap();
    store.write(NEIGHBOR, NEIGHBOR_VALUE).unwrap();
    store.write(CRED, b"owner").unwrap();
    let mut out = [0; 32];
    assert_eq!(store.read(CRED, &mut out), Some(b"owner".len()));
    assert_eq!(&out[..b"owner".len()], b"owner");
    assert!(!store.last_error());
    let offset = flash
        .inner
        .bytes
        .borrow()
        .windows(NEIGHBOR_VALUE.len())
        .position(|bytes| bytes == NEIGHBOR_VALUE)
        .unwrap();
    *flash.inner.fail_reads_in.borrow_mut() =
        Some(u32::try_from(offset).unwrap()..u32::try_from(offset + NEIGHBOR_VALUE.len()).unwrap());
    let before = flash.image();
    flash.arm(&[]);
    assert_eq!(store.read(CRED, &mut out), Some(b"owner".len()));
    assert_eq!(&out[..b"owner".len()], b"owner");
    assert!(!store.last_error());
    assert_eq!(flash.inner.refused_at(), None);
    assert_eq!(flash.image(), before);
    assert!(flash.events().iter().all(|event| event.0 == Io::Read));
    assert_eq!(store.read(NEIGHBOR, &mut out), None);
    assert!(store.last_error());
    assert!(flash.inner.refused_at().is_some());
    *flash.inner.fail_reads_in.borrow_mut() = None;
    assert_eq!(store.read(NEIGHBOR, &mut out), Some(NEIGHBOR_VALUE.len()));
    assert_eq!(&out[..NEIGHBOR_VALUE.len()], NEIGHBOR_VALUE);
    assert!(!store.last_error());
    assert_eq!(store.read(CRED, &mut out), Some(b"owner".len()));
    assert_eq!(&out[..b"owner".len()], b"owner");
    assert!(!store.last_error());
}
