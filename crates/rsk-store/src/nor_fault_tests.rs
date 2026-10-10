// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[path = "nor_fault_flash.rs"]
pub(super) mod flash;
use flash::{Effect, FaultFlash, Io, Rule};

type FaultStore = SeqStorage<FaultFlash, MainCache, CounterCache>;

#[test]
fn verified_driver_preserves_capacity_and_makes_bounded_readback_progress() {
    use crate::verified_flash::VerifiedFlash;
    let flash = FaultFlash::new();
    let mut verified = VerifiedFlash::new(flash.clone());
    assert_eq!(verified.capacity(), flash.inner.capacity());
    flash.arm(&[Rule {
        io: Io::Read,
        skip: 10,
        effect: Effect::Refuse,
        latched: true,
    }]);
    block_on(verified.write(4, &[0xA5; 516])).unwrap();
    assert_eq!(flash.hits(), [0]);
    assert!(
        flash
            .events()
            .iter()
            .filter(|event| event.0 == Io::Read)
            .all(|event| event.2 > 0)
    );
}

#[path = "nor_damage_capacity_tests.rs"]
mod damage_capacity;

#[path = "raw_bank_tests.rs"]
mod raw_bank;

#[test]
fn a_committed_insert_with_failed_readback_is_not_cached_as_absent_by_fs() {
    const FID: u16 = 0xB000;
    let provision = || {
        let flash = FaultFlash::new();
        let mut fs = rsk_fs::Fs::new(mount_fault(&flash));
        fs.scan();
        assert_eq!(fs.try_has_data(FID), Ok(false));
        flash.arm(&[]);
        (flash, fs)
    };
    let (trace, mut healthy) = provision();
    healthy.put(FID, b"committed data").unwrap();
    let last_read = trace
        .events()
        .iter()
        .filter(|event| event.0 == Io::Read)
        .count()
        - 1;
    let (flash, mut fs) = provision();
    flash.arm(&[Rule {
        io: Io::Read,
        skip: last_read,
        effect: Effect::Refuse,
        latched: false,
    }]);
    assert_eq!(fs.put(FID, b"committed data"), Err(Error::MemoryFatal));
    assert_eq!(flash.hits(), [1]);
    flash.clear();
    assert_eq!(
        value(&mut mount_fault(&flash), FID).as_deref(),
        Some(&b"committed data"[..])
    );
    assert_eq!(
        fs.try_has_data(FID),
        Ok(true),
        "failed readback cannot retain a decided pre-write absence"
    );
    let mut data = [0; 32];
    assert_eq!(fs.try_read(FID, &mut data), Ok(Some(14)));
    assert_eq!(&data[..14], b"committed data");
}

#[test]
fn a_committed_metadata_insert_with_failed_readback_keeps_its_head_visible() {
    let provision = || {
        let flash = FaultFlash::new();
        let mut fs = rsk_fs::Fs::new(mount_fault(&flash));
        fs.scan();
        assert_eq!(fs.meta_find(CRED, &mut [0; 8]), None);
        flash.arm(&[]);
        (flash, fs)
    };
    let (trace, mut healthy) = provision();
    healthy.meta_add(CRED, b"head").unwrap();
    let last_read = trace
        .events()
        .iter()
        .filter(|event| event.0 == Io::Read)
        .count()
        - 1;
    let (flash, mut fs) = provision();
    flash.arm(&[Rule {
        io: Io::Read,
        skip: last_read,
        effect: Effect::Refuse,
        latched: false,
    }]);
    assert_eq!(fs.meta_add(CRED, b"head"), Err(Error::MemoryFatal));
    assert_eq!(flash.hits(), [1]);
    flash.clear();
    let mut reboot = rsk_fs::Fs::new(mount_fault(&flash));
    reboot.scan();
    assert_eq!(reboot.meta_find(CRED, &mut [0; 8]), Some(4));
    let mut head = [0; 8];
    assert_eq!(
        fs.meta_find(CRED, &mut head),
        Some(4),
        "a failed readback cannot hide committed metadata"
    );
    assert_eq!(&head[..4], b"head");
    fs.meta_add(0xB000, b"neighbor").unwrap();
    assert_eq!(fs.meta_find(CRED, &mut head), Some(4));
    assert_eq!(&head[..4], b"head");
}

#[test]
fn an_uncertain_committed_write_invalidates_derived_cache_generations() {
    let provision = || {
        let flash = FaultFlash::new();
        let mut fs = rsk_fs::Fs::new(mount_fault(&flash));
        fs.scan();
        fs.put(CRED, b"old prefix").unwrap();
        flash.arm(&[]);
        (flash, fs)
    };
    let (trace, mut healthy) = provision();
    healthy.put(CRED, b"new prefix").unwrap();
    let last_read = trace
        .events()
        .iter()
        .filter(|event| event.0 == Io::Read)
        .count()
        - 1;
    let (flash, mut fs) = provision();
    let generation = fs.write_gen();
    flash.arm(&[Rule {
        io: Io::Read,
        skip: last_read,
        effect: Effect::Refuse,
        latched: false,
    }]);
    assert_eq!(fs.put(CRED, b"new prefix"), Err(Error::MemoryFatal));
    assert_eq!(flash.hits(), [1]);
    flash.clear();
    assert_eq!(
        value(&mut mount_fault(&flash), CRED).as_deref(),
        Some(&b"new prefix"[..])
    );
    assert_ne!(
        fs.write_gen(),
        generation,
        "derived views cannot reuse a pre-write generation after ambiguous completion"
    );
}

#[test]
fn a_second_scan_fault_cannot_advertise_space_or_admit_a_file_past_the_dynamic_cap() {
    let last_fid = 0x8000 + u16::try_from(rsk_fs::MAX_DYNAMIC_FILES - 1).unwrap();
    let provision = || {
        let flash = FaultFlash::new();
        let mut fs = rsk_fs::Fs::new(mount_fault(&flash));
        fs.scan();
        for fid in 0x8000..last_fid {
            fs.put(fid, b"x").unwrap();
        }
        assert_eq!(fs.free_dynamic(), 1);
        flash.arm(&[]);
        (flash, fs)
    };
    let (trace, mut healthy) = provision();
    healthy.put(last_fid, b"x").unwrap();
    let last_read = trace
        .events()
        .iter()
        .filter(|event| event.0 == Io::Read)
        .count()
        - 1;
    let (flash, mut fs) = provision();
    flash.arm(&[
        Rule {
            io: Io::Read,
            skip: last_read,
            effect: Effect::Refuse,
            latched: false,
        },
        Rule {
            io: Io::Read,
            skip: last_read + 1,
            effect: Effect::Refuse,
            latched: true,
        },
    ]);
    assert_eq!(fs.put(last_fid, b"x"), Err(Error::MemoryFatal));
    assert!(flash.hits().iter().all(|&hits| hits > 0));
    assert_eq!(
        fs.free_dynamic(),
        0,
        "an incomplete scan cannot grant capacity that remains consumed"
    );
    assert_eq!(fs.put(last_fid + 1, b"overflow"), Err(Error::MemoryFatal));
    flash.clear();
    assert_eq!(fs.put(last_fid + 1, b"overflow"), Err(Error::NoMemory));
    let mut reboot = rsk_fs::Fs::new(mount_fault(&flash));
    reboot.scan();
    assert_eq!(reboot.free_dynamic(), 0);
    assert!(!reboot.has_data(last_fid + 1));
    let mut data = [0; 1];
    for fid in 0x8000..=last_fid {
        assert_eq!(reboot.read(fid, &mut data), Some(1));
        assert_eq!(data, *b"x");
    }
}
fn mount_fault(flash: &FaultFlash) -> FaultStore {
    SeqStorage::new(
        flash.clone(),
        MAIN,
        COUNTER,
        MainCache::new(
            ArrayPageStates::new(),
            ArrayPagePointers::new(),
            ArrayKeyPointers::new(),
        ),
        CounterCache::new(
            ArrayPageStates::new(),
            ArrayPagePointers::new(),
            ArrayKeyPointers::new(),
        ),
    )
}
fn value(store: &mut impl Storage, fid: u16) -> Option<Vec<u8>> {
    let mut buf = [0; rsk_fs::MAX_VALUE_BYTES];
    store.read(fid, &mut buf).map(|n| buf[..n].to_vec())
}

#[test]
fn a_program_that_reports_success_without_applying_bytes_cannot_acknowledge_a_record() {
    let flash = FaultFlash::new();
    let mut store = mount_fault(&flash);
    store.write(CRED, b"preceding credential").unwrap();
    store.write(CTR, b"preceding counter").unwrap();
    for fid in [CRED, CTR] {
        flash.arm(&[Rule {
            io: Io::Program,
            skip: 0,
            effect: Effect::Drop,
            latched: true,
        }]);
        assert_eq!(
            store.write(fid, b"replacement"),
            Err(Error::MemoryFatal),
            "a successful program status is not committed data"
        );
        assert!(flash.hits()[0] > 0);
        flash.clear();
        let mut reboot = mount_fault(&flash);
        assert_eq!(
            value(&mut reboot, fid).as_deref(),
            Some(if fid == CRED {
                &b"preceding credential"[..]
            } else {
                &b"preceding counter"[..]
            })
        );
        store = reboot;
    }
}

#[test]
fn each_program_and_its_readback_can_fail_without_replacing_an_unrelated_record() {
    for fid in [CRED, CTR] {
        let provision = || {
            let flash = FaultFlash::new();
            let mut store = mount_fault(&flash);
            store.write(CRED, b"preceding").unwrap();
            store.write(CTR, b"preceding").unwrap();
            store.write(0xB000, b"neighbor").unwrap();
            flash.arm(&[]);
            (flash, store)
        };
        let (trace, mut healthy) = provision();
        healthy.write(fid, b"replacement").unwrap();
        let events = trace.events();
        for io in [Io::Read, Io::Program] {
            let count = events.iter().filter(|event| event.0 == io).count();
            assert!(count > 0);
            for skip in 0..count {
                for (effect, latched) in [
                    (Effect::Refuse, false),
                    (Effect::Refuse, true),
                    (Effect::Drop, false),
                    (Effect::Drop, true),
                    (Effect::KeepTail, false),
                ] {
                    if io == Io::Read && effect != Effect::Refuse {
                        continue;
                    }
                    let (flash, mut store) = provision();
                    flash.arm(&[Rule {
                        io,
                        skip,
                        effect,
                        latched,
                    }]);
                    let answer = store.write(fid, b"replacement");
                    assert!(flash.hits()[0] > 0);
                    flash.clear();
                    let same_instance = value(&mut store, fid).unwrap();
                    assert!([&b"preceding"[..], &b"replacement"[..]].contains(&&same_instance[..]));
                    let mut reboot = mount_fault(&flash);
                    let actual = value(&mut reboot, fid).unwrap();
                    assert_eq!(actual, same_instance);
                    assert!(
                        [&b"preceding"[..], &b"replacement"[..]].contains(&&actual[..]),
                        "{io:?} {skip} {effect:?} {latched}"
                    );
                    if answer.is_ok() {
                        assert_eq!(actual, b"replacement");
                    }
                    assert_eq!(
                        value(&mut reboot, 0xB000).as_deref(),
                        Some(&b"neighbor"[..])
                    );
                    assert_eq!(
                        value(&mut reboot, if fid == CRED { CTR } else { CRED }).as_deref(),
                        Some(&b"preceding"[..])
                    );
                    reboot.write(fid, b"replacement").unwrap();
                    assert_eq!(
                        value(&mut mount_fault(&flash), fid).as_deref(),
                        Some(&b"replacement"[..])
                    );
                }
            }
        }
    }
}

#[test]
fn verification_checks_later_program_chunks_and_the_last_word_of_an_erase() {
    use crate::verified_flash::VerifiedFlash;
    for len in [WORD, 260, 516, 1028] {
        let flash = FaultFlash::new();
        let mut verified = VerifiedFlash::new(flash.clone());
        let mut data = vec![0xFF; len];
        data[len - 1] = 0;
        flash.arm(&[Rule {
            io: Io::Program,
            skip: 0,
            effect: Effect::KeepTail,
            latched: false,
        }]);
        assert!(block_on(verified.write(0, &data)).is_err());
        assert_eq!(flash.hits(), [1]);
        flash.clear();
        block_on(verified.write(0, &data)).unwrap();
        let mut actual = vec![0; len];
        block_on(verified.read(0, &mut actual)).unwrap();
        assert_eq!(actual, data);
    }
    for at in [WORD, 256, 260, SECTOR - WORD] {
        let flash = FaultFlash::new();
        let mut verified = VerifiedFlash::new(flash.clone());
        block_on(verified.write(at as u32, &[0; WORD])).unwrap();
        flash.arm(&[Rule {
            io: Io::Erase,
            skip: 0,
            effect: Effect::Drop,
            latched: false,
        }]);
        assert!(block_on(verified.erase(0, SECTOR as u32)).is_err());
        assert_eq!(flash.hits(), [1]);
        flash.clear();
        block_on(verified.erase(0, SECTOR as u32)).unwrap();
        assert!(
            flash
                .inner
                .snapshot(0..SECTOR as u32)
                .iter()
                .all(|&b| b == 0xFF)
        );
    }
    let flash = FaultFlash::new();
    let mut verified = VerifiedFlash::new(flash.clone());
    block_on(verified.write((SECTOR - WORD) as u32, &[0; WORD])).unwrap();
    flash.arm(&[Rule {
        io: Io::Erase,
        skip: 0,
        effect: Effect::KeepTail,
        latched: false,
    }]);
    assert!(block_on(verified.erase(0, SECTOR as u32)).is_err());
    assert_eq!(flash.hits(), [1]);
    assert!(flash.inner.snapshot(0..256).iter().all(|&b| b == 0xFF));
    assert_eq!(
        flash.inner.snapshot((SECTOR - WORD) as u32..SECTOR as u32),
        [0; WORD]
    );
}

#[derive(Clone)]
struct WideRead(FaultFlash);
impl ErrorType for WideRead {
    type Error = FlashFault;
}
impl ReadNorFlash for WideRead {
    const READ_SIZE: usize = 16;
    async fn read(&mut self, address: u32, bytes: &mut [u8]) -> Result2<()> {
        assert_eq!(address % 16, 0);
        assert!(bytes.len().is_multiple_of(16));
        self.0.read(address, bytes).await
    }
    fn capacity(&self) -> usize {
        self.0.capacity()
    }
}
impl NorFlash for WideRead {
    const WRITE_SIZE: usize = WORD;
    const ERASE_SIZE: usize = SECTOR;
    async fn write(&mut self, address: u32, bytes: &[u8]) -> Result2<()> {
        self.0.write(address, bytes).await
    }
    async fn erase(&mut self, from: u32, to: u32) -> Result2<()> {
        self.0.erase(from, to).await
    }
}

#[test]
fn readback_handles_wider_read_geometry_and_unaligned_program_edges() {
    use crate::verified_flash::VerifiedFlash;
    for address in [4, 12, 252, 260] {
        for len in [4, 20, 260, 516] {
            let flash = FaultFlash::new();
            let mut verified = VerifiedFlash::new(WideRead(flash.clone()));
            block_on(verified.write(address, &vec![0xA5; len])).unwrap();
            assert_eq!(
                flash.inner.snapshot(address..address + len as u32),
                vec![0xA5; len]
            );
            flash.arm(&[Rule {
                io: Io::Program,
                skip: 0,
                effect: Effect::KeepTail,
                latched: false,
            }]);
            assert!(block_on(verified.write(address, &vec![0; len])).is_err());
            assert_eq!(flash.hits(), [1]);
        }
    }
}

#[test]
fn successful_but_dropped_tombstone_programs_cannot_acknowledge_a_removal() {
    for fid in [CRED, CTR] {
        let flash = FaultFlash::new();
        let mut store = mount_fault(&flash);
        store.write(fid, b"surviving record").unwrap();
        store.write(0xB000, b"neighbor").unwrap();
        flash.arm(&[Rule {
            io: Io::Program,
            skip: 0,
            effect: Effect::Drop,
            latched: true,
        }]);
        assert_eq!(store.remove(fid), Err(Error::MemoryFatal));
        assert!(flash.hits()[0] > 0);
        flash.clear();
        let mut reboot = mount_fault(&flash);
        assert_eq!(
            value(&mut reboot, fid).as_deref(),
            Some(&b"surviving record"[..])
        );
        reboot.remove(fid).unwrap();
        let mut second = mount_fault(&flash);
        assert_eq!(value(&mut second, fid), None);
        assert_eq!(
            value(&mut second, 0xB000).as_deref(),
            Some(&b"neighbor"[..])
        );
    }
}

#[test]
fn every_scrub_erase_and_every_erase_readback_preserve_live_data_and_allow_retry() {
    let provision = || {
        let flash = FaultFlash::new();
        let mut store = mount_fault(&flash);
        store.write(CRED, b"superseded secret material").unwrap();
        store.write(CRED, b"live credential").unwrap();
        store.write(CTR, b"counter").unwrap();
        flash.arm(&[]);
        (flash, store)
    };
    let (trace, mut healthy) = provision();
    healthy.compact().unwrap();
    let events = trace.events();
    let erases = events.iter().filter(|event| event.0 == Io::Erase).count();
    assert!(erases > 0);
    let mut reads = 0;
    let mut readback_positions = Vec::new();
    for pair in events.windows(2) {
        if pair[0].0 == Io::Read {
            reads += 1;
        }
        if pair[0].0 == Io::Erase && pair[1].0 == Io::Read {
            readback_positions.push(reads);
        }
    }
    assert_eq!(readback_positions.len(), erases);
    let rules: Vec<_> = (0..erases)
        .flat_map(|skip| {
            [Effect::Refuse, Effect::Drop].map(|effect| Rule {
                io: Io::Erase,
                skip,
                effect,
                latched: true,
            })
        })
        .chain(readback_positions.into_iter().map(|skip| Rule {
            io: Io::Read,
            skip,
            effect: Effect::Refuse,
            latched: true,
        }))
        .collect();
    for rule in rules {
        let (flash, mut store) = provision();
        let counter = flash.inner.snapshot(COUNTER);
        flash.arm(&[rule]);
        assert_eq!(store.compact(), Err(Error::MemoryFatal), "{rule:?}");
        assert!(flash.hits()[0] > 0);
        flash.clear();
        let mut reboot = mount_fault(&flash);
        assert_eq!(
            value(&mut reboot, CRED).as_deref(),
            Some(&b"live credential"[..])
        );
        assert_eq!(flash.inner.snapshot(COUNTER), counter);
        reboot.compact().unwrap();
        let mut second = mount_fault(&flash);
        assert_eq!(
            value(&mut second, CRED).as_deref(),
            Some(&b"live credential"[..])
        );
        assert_eq!(value(&mut second, CTR).as_deref(), Some(&b"counter"[..]));
        assert_eq!(value(&mut second, SCRUB_FILLER_FID), None);
        assert!(!flash.inner.contains(MAIN, b"superseded secret material"));
        assert_eq!(flash.inner.snapshot(COUNTER), counter);
    }
}

#[test]
fn a_failed_erase_cannot_latch_the_at_rest_scrub_marker() {
    for effect in [Effect::Refuse, Effect::Drop] {
        let flash = FaultFlash::new();
        let mut fs = rsk_fs::Fs::new(mount_fault(&flash));
        fs.scan();
        fs.put(0xB000, b"old plaintext remnant").unwrap();
        fs.put(0xB000, b"live data").unwrap();
        flash.arm(&[Rule {
            io: Io::Erase,
            skip: 0,
            effect,
            latched: true,
        }]);
        rsk_fs::run_at_rest_lap(&mut fs);
        assert!(flash.hits()[0] > 0);
        flash.clear();
        let mut reboot = rsk_fs::Fs::new(mount_fault(&flash));
        reboot.scan();
        assert!(!reboot.has_data(rsk_fs::EF_HARDENED));
        rsk_fs::run_at_rest_lap(&mut reboot);
        assert!(reboot.has_data(rsk_fs::EF_HARDENED));
        assert!(!flash.inner.contains(MAIN, b"old plaintext remnant"));
    }
}
