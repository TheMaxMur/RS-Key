// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn cached_store() -> (FaultFlash, AuthStore) {
    let flash = FaultFlash::new();
    let mut store = mount_authenticated(&flash);
    store.initialize_blank().unwrap();
    for _ in 0..20 {
        store.write(CRED, b"owner").unwrap();
    }
    assert_eq!(
        authenticated_value(&mut store, CRED).unwrap().as_deref(),
        Some(&b"owner"[..])
    );
    (flash, store)
}

#[test]
fn mounted_authority_survives_read_errors_without_accepting_older_snapshots() {
    let flash = FaultFlash::new();
    let mut store = mount_authenticated(&flash);
    store.initialize_blank().unwrap();
    store.write(CRED, b"old").unwrap();
    let old = flash.image();
    store.write(CRED, b"current").unwrap();
    assert_eq!(
        authenticated_value(&mut store, CRED).unwrap().as_deref(),
        Some(&b"current"[..])
    );
    *flash.inner.bytes.borrow_mut() = old.clone();
    flash.arm(&[]);
    for _ in 0..2 {
        assert_eq!(
            authenticated_value(&mut store, CRED),
            Err(Error::MemoryFatal)
        );
        assert_eq!(flash.image(), old);
        assert!(flash.events().iter().all(|event| event.0 == Io::Read));
    }
}

#[test]
fn warm_reads_do_not_rescan_journals_or_write_flash() {
    let (flash, mut store) = cached_store();
    let layout = crate::authenticated::Layout::new(MAIN.end..MAIN.end + 128 * 1024).unwrap();
    flash.arm(&[]);
    assert_eq!(
        authenticated_value(&mut store, CRED).unwrap().as_deref(),
        Some(&b"owner"[..])
    );
    assert_eq!(authenticated_value(&mut store, CRED + 1), Ok(None));
    assert!(
        flash.events().iter().all(|event| event.0 == Io::Read
            && !layout.main.iter().any(|range| range.contains(&event.1)))
    );
}

#[test]
fn cached_reads_refuse_every_failed_read_without_writing_or_returning_absence() {
    let (flash, mut store) = cached_store();
    flash.arm(&[]);
    assert!(authenticated_value(&mut store, CRED).unwrap().is_some());
    let reads = flash
        .events()
        .iter()
        .filter(|event| event.0 == Io::Read)
        .count();
    let original = flash.image();
    for skip in 0..reads {
        flash.arm(&[Rule {
            io: Io::Read,
            skip,
            effect: Effect::Refuse,
            latched: false,
        }]);
        assert_eq!(
            authenticated_value(&mut store, CRED),
            Err(Error::MemoryFatal),
            "read {skip}"
        );
        assert!(flash.hits()[0] > 0);
        assert_eq!(flash.image(), original);
        assert!(flash.events().iter().all(|event| event.0 == Io::Read));
        flash.clear();
        assert!(authenticated_value(&mut store, CRED).unwrap().is_some());
    }
}

#[test]
fn mounted_values_stay_exact_and_mutations_refuse_damaged_journals() {
    let (flash, mut store) = cached_store();
    let layout = crate::authenticated::Layout::new(MAIN.end..MAIN.end + 128 * 1024).unwrap();
    let original = flash.image();
    for range in layout.main {
        for offset in [
            range.start,
            range.start + 95,
            range.start + 96,
            range.end - 1,
        ] {
            for fid in [CRED, CRED + 1] {
                *flash.inner.bytes.borrow_mut() = original.clone();
                assert!(authenticated_value(&mut store, CRED).unwrap().is_some());
                flash.inner.bytes.borrow_mut()[offset as usize] ^= 1;
                let damaged = flash.image();
                flash.arm(&[]);
                let expected = (fid == CRED).then(|| b"owner".to_vec());
                assert_eq!(authenticated_value(&mut store, fid), Ok(expected));
                assert_eq!(flash.image(), damaged);
                assert!(flash.events().iter().all(|event| event.0 == Io::Read));
                flash.arm(&[]);
                assert_eq!(store.write(CRED, b"new"), Err(Error::MemoryFatal));
                assert_eq!(flash.image(), damaged);
                assert!(flash.events().iter().all(|event| event.0 == Io::Read));
            }
        }
    }
}

#[test]
fn cached_authority_refuses_selected_damage_during_the_other_bank_check() {
    use crate::authenticated::{
        Checkpoint, Directory, Journal, Layout, Partition, RawBank, RootArm,
    };
    let (flash, mut store) = cached_store();
    let layout = Layout::new(MAIN.end..MAIN.end + 128 * 1024).unwrap();
    let original = flash.image();
    flash.arm(&[]);
    assert!(authenticated_value(&mut store, CRED).unwrap().is_some());
    flash.arm(&[]);
    assert!(store.for_each_key(&mut |_| {}));
    let skip = flash
        .events()
        .iter()
        .filter(|event| event.0 == Io::Read)
        .position(|event| event.1 == layout.main[1].start && event.2 == 256)
        .unwrap();
    let mut key = crate::authenticated::KeySource::new([0x43; 32], auth_blank, false)
        .key(RootArm::PreOtp)
        .unwrap();
    let mut directory = Directory::<{ crate::authenticated::MAX_MAIN_ENTRIES }>::new();
    let mut journal = Journal::new(
        RawBank::new(flash.clone(), layout.main[0].clone()).unwrap(),
        Partition::Main,
    );
    let scan = journal.scan(key.expose(), &mut directory).unwrap();
    let sequence = scan.state.unwrap().sequence();
    let header = scan.checkpoint.unwrap();
    journal
        .write_snapshot(
            Checkpoint {
                sequence,
                entries: u32::try_from(directory.entries().len()).unwrap(),
                digest: directory
                    .digest(header.identity, key.expose(), sequence)
                    .unwrap(),
                ..header
            },
            key.expose(),
            &directory,
        )
        .unwrap();
    let changed = flash.image();
    assert_ne!(original, changed);
    *flash.inner.bytes.borrow_mut() = original;
    assert!(authenticated_value(&mut store, CRED).unwrap().is_some());
    flash.arm(&[]);
    flash.replace_image_before_read(skip, changed.clone());
    assert_eq!(store.write(CRED, b"new"), Err(Error::MemoryFatal));
    assert_eq!(flash.image(), changed);
    assert!(flash.events().iter().all(|event| event.0 == Io::Read));
    key.wipe();
}

#[test]
fn mounted_absence_needs_no_payload_metadata_repair() {
    let (flash, mut store) = cached_store();
    let damaged = usize::try_from(MAIN.end).unwrap() - 1;
    flash.inner.bytes.borrow_mut()[damaged] = 0;
    flash.arm(&[]);
    assert_eq!(authenticated_value(&mut store, CRED + 1), Ok(None));
    assert_eq!(flash.image()[damaged], 0);
    assert!(flash.events().is_empty());
    assert!(store.for_each_key(&mut |_| {}));
    assert_eq!(flash.image()[damaged], 0xFF);
    assert!(flash.events().iter().any(|event| event.0 == Io::Erase));
    assert_eq!(
        authenticated_value(&mut store, CRED).unwrap().as_deref(),
        Some(&b"owner"[..])
    );
}

#[test]
fn mounted_absence_is_complete_but_mutations_require_readable_payload_metadata() {
    let (flash, mut store) = cached_store();
    *flash.inner.fail_reads_in.borrow_mut() = Some(MAIN.end - 1..MAIN.end);
    flash.arm(&[]);
    assert_eq!(authenticated_value(&mut store, CRED + 1), Ok(None));
    assert!(flash.events().is_empty());
    let before = flash.image();
    assert_eq!(store.write(CRED, b"new"), Err(Error::MemoryFatal));
    assert_eq!(flash.image(), before);
    assert!(flash.inner.refused_at().is_some());
    assert!(flash.events().iter().all(|event| event.0 == Io::Read));
}

#[test]
fn cached_reads_still_authenticate_the_published_payload() {
    let (flash, mut store) = cached_store();
    let offsets: Vec<_> = flash.image()[..usize::try_from(MAIN.end).unwrap()]
        .windows(b"owner".len())
        .enumerate()
        .filter_map(|(offset, bytes)| (bytes == b"owner").then_some(offset))
        .collect();
    assert!(!offsets.is_empty());
    for offset in offsets {
        flash.inner.bytes.borrow_mut()[offset] ^= 1;
    }
    let damaged = flash.image();
    flash.arm(&[]);
    assert_eq!(
        authenticated_value(&mut store, CRED),
        Err(Error::MemoryFatal)
    );
    assert_eq!(flash.image(), damaged);
    assert!(flash.events().iter().all(|event| event.0 == Io::Read));
}

#[test]
fn cached_fingerprints_describe_verified_scan_bytes_not_a_later_media_image() {
    let (flash, _) = cached_store();
    let mut store = mount_authenticated(&flash);
    let layout = crate::authenticated::Layout::new(MAIN.end..MAIN.end + 128 * 1024).unwrap();
    flash.arm(&[]);
    assert!(authenticated_value(&mut store, CRED).unwrap().is_some());
    let trace = flash.events();
    let last_journal = trace
        .iter()
        .rposition(|event| {
            event.0 == Io::Read && layout.main.iter().any(|range| range.contains(&event.1))
        })
        .unwrap();
    let skip = trace[..=last_journal]
        .iter()
        .filter(|event| event.0 == Io::Read)
        .count();
    let mut changed = flash.image();
    changed[usize::try_from(layout.main[0].start).unwrap()] ^= 1;
    let mut fresh = mount_authenticated(&flash);
    flash.arm(&[]);
    flash.replace_image_before_read(skip, changed.clone());
    assert!(authenticated_value(&mut fresh, CRED).unwrap().is_some());
    assert_eq!(flash.image(), changed);
    assert_eq!(authenticated_value(&mut fresh, CRED + 1), Ok(None));
    flash.arm(&[]);
    assert_eq!(fresh.write(CRED, b"new"), Err(Error::MemoryFatal));
    assert_eq!(flash.image(), changed);
    assert!(flash.events().iter().all(|event| event.0 == Io::Read));
}

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

std::thread_local! {
    static ROOT_BYTE: Cell<u8> = const { Cell::new(0x62) };
}

fn changing_fused_root(out: &mut [u8; 32]) -> crate::authenticated::RootRead {
    ROOT_BYTE.with(|byte| out.fill(byte.get()));
    crate::authenticated::RootRead::Fused
}

#[test]
fn warm_absence_refuses_a_changed_but_readable_fused_root() {
    use crate::authenticated::{Authenticated, KeySource, RootArm};
    ROOT_BYTE.with(|byte| byte.set(0x62));
    let flash = FaultFlash::new();
    let end = MAIN.end + 128 * 1024;
    flash.inner.bytes.borrow_mut().resize(end as usize, 0xFF);
    let mut store = Authenticated::new(
        flash.clone(),
        MAIN,
        MAIN.end..end,
        MainCache::new(
            ArrayPageStates::new(),
            ArrayPagePointers::new(),
            ArrayKeyPointers::new(),
        ),
        KeySource::new([0x43; 32], changing_fused_root, true),
        [0x4B; 16],
        RootArm::Otp,
    )
    .unwrap();
    store.initialize_blank().unwrap();
    store.write(CRED, b"owner").unwrap();
    assert_eq!(authenticated_value(&mut store, CRED + 1), Ok(None));
    let before = flash.image();
    ROOT_BYTE.with(|byte| byte.set(0x63));
    flash.arm(&[]);
    assert_eq!(
        authenticated_value(&mut store, CRED + 1),
        Err(Error::MemoryFatal)
    );
    assert_eq!(flash.image(), before);
    assert!(flash.events().is_empty());
    ROOT_BYTE.with(|byte| byte.set(0x62));
    assert_eq!(authenticated_value(&mut store, CRED + 1), Ok(None));
}

#[test]
fn a_valid_warm_value_needs_only_one_payload_read() {
    let flash = FaultFlash::new();
    let mut store = mount_authenticated(&flash);
    store.initialize_blank().unwrap();
    let value = [0x5a; 16];
    store.write(CRED, &value).unwrap();
    let mut out = [0; 16];
    assert_eq!(store.read(CRED, &mut out), Some(value.len()));
    flash.arm(&[]);
    assert_eq!(store.read(CRED, &mut out), Some(value.len()));
    assert!(!store.last_error());
    assert_eq!(out, value);
    // Two FID bytes and this value occupy one aligned 20-byte payload window.
    assert_eq!(
        flash
            .events()
            .iter()
            .filter(|event| event.0 == Io::Read && event.2 == 20)
            .count(),
        1
    );
}
