// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[path = "authenticated_fault_tests.rs"]
mod authenticated_faults;

#[path = "managed_tests.rs"]
mod managed;

fn auth_blank(_: &mut [u8; 32]) -> crate::authenticated::RootRead {
    crate::authenticated::RootRead::Blank
}

type AuthStore = crate::authenticated::Authenticated<FaultFlash, MainCache>;

fn mount_authenticated(flash: &FaultFlash) -> AuthStore {
    let end = MAIN.end + 128 * 1024;
    flash.inner.bytes.borrow_mut().resize(end as usize, 0xFF);
    crate::authenticated::Authenticated::new(
        flash.clone(),
        MAIN,
        MAIN.end..end,
        MainCache::new(
            ArrayPageStates::new(),
            ArrayPagePointers::new(),
            ArrayKeyPointers::new(),
        ),
        crate::authenticated::KeySource::new([0x43; 32], auth_blank, false),
        [0x4B; 16],
        crate::authenticated::RootArm::PreOtp,
    )
    .unwrap()
}

#[test]
fn committed_payload_damage_is_not_absence_or_an_older_authorized_value() {
    const OLD: &[u8] = b"previous owner security state";
    const NEW: &[u8] = b"acknowledged owner security state";
    for fid in [CRED, CTR] {
        for older in [false, true] {
            let flash = FaultFlash::new();
            let mut store = mount_authenticated(&flash);
            store.initialize_blank().unwrap();
            if older {
                store.write(fid, OLD).unwrap();
            }
            store.write(fid, NEW).unwrap();
            let offsets: Vec<_> = flash
                .inner
                .bytes
                .borrow()
                .windows(NEW.len())
                .enumerate()
                .filter_map(|(offset, bytes)| (bytes == NEW).then_some(offset))
                .collect();
            assert!(!offsets.is_empty());
            for offset in offsets {
                flash.inner.bytes.borrow_mut()[offset] ^= 0x80;
            }
            let mut fs = rsk_fs::Fs::new(mount_authenticated(&flash));
            assert_eq!(
                fs.try_read(fid, &mut [0; 64]),
                Err(Error::MemoryFatal),
                "an acknowledged security record must not become absent or revert"
            );
        }
    }
}

#[test]
fn filling_each_real_partition_refuses_without_evicting_any_acknowledged_owner() {
    for counter in [false, true] {
        let flash = FaultFlash::new();
        let mut store = mount_fault(&flash);
        store.write(CRED, b"credential owner").unwrap();
        store.write(CTR, b"counter owner").unwrap();
        let untouched = flash.inner.snapshot(if counter { MAIN } else { COUNTER });
        let candidates: Vec<_> = if counter {
            rsk_fs::counter::COUNTER_FIDS
                .iter()
                .map(|fid| fid.get())
                .filter(|&fid| fid != CTR)
                .collect()
        } else {
            (0xB000..0xB040).collect()
        };
        let mut committed = Vec::new();
        let mut refused = None;
        for (i, &fid) in candidates.iter().enumerate() {
            let payload = vec![u8::try_from(i + 1).unwrap(); rsk_fs::MAX_VALUE_BYTES];
            match store.write(fid, &payload) {
                Ok(()) => committed.push((fid, payload)),
                Err(error) => {
                    assert_eq!(error, Error::MemoryFatal);
                    refused = Some(fid);
                    break;
                }
            }
        }
        assert!(!committed.is_empty());
        assert!(refused.is_some(), "the test must reach actual FullStorage");
        assert_eq!(
            flash.inner.snapshot(if counter { MAIN } else { COUNTER }),
            untouched
        );
        let mut reboot = mount_fault(&flash);
        assert_eq!(
            value(&mut reboot, CRED).as_deref(),
            Some(&b"credential owner"[..])
        );
        assert_eq!(
            value(&mut reboot, CTR).as_deref(),
            Some(&b"counter owner"[..])
        );
        for (fid, payload) in &committed {
            assert_eq!(value(&mut reboot, *fid).as_ref(), Some(payload));
        }
        assert_eq!(value(&mut reboot, refused.unwrap()), None);
        let (fid, _) = committed.remove(0);
        reboot.remove(fid).unwrap();
        reboot
            .write(refused.unwrap(), b"recovered capacity")
            .unwrap();
        assert_eq!(
            value(&mut mount_fault(&flash), refused.unwrap()).as_deref(),
            Some(&b"recovered capacity"[..])
        );
        for (fid, payload) in &committed {
            assert_eq!(value(&mut reboot, *fid).as_ref(), Some(payload));
        }
    }
}

#[test]
fn corrupt_nor_payloads_never_escape_as_unchecked_bytes_or_replace_a_neighbor() {
    const OLD: &[u8] = b"older CRC protected value";
    const NEW: &[u8] = b"current CRC protected value";
    for fid in [CRED, CTR] {
        for older in [false, true] {
            for index in 0..NEW.len() {
                let flash = FaultFlash::new();
                let mut store = mount_fault(&flash);
                if older {
                    store.write(fid, OLD).unwrap();
                }
                store.write(fid, NEW).unwrap();
                store.write(0xB000, b"neighbor").unwrap();
                let offset = flash
                    .inner
                    .bytes
                    .borrow()
                    .windows(NEW.len())
                    .position(|bytes| bytes == NEW)
                    .unwrap();
                flash.inner.bytes.borrow_mut()[offset + index] ^= 0x80;
                let mut reboot = mount_fault(&flash);
                let result = value(&mut reboot, fid);
                assert!(
                    result.is_none() || (older && result.as_deref() == Some(OLD)),
                    "damaged bytes must not pass a value CRC"
                );
                assert_eq!(
                    value(&mut reboot, 0xB000).as_deref(),
                    Some(&b"neighbor"[..])
                );
                // CRC framing cannot distinguish an uncommitted torn append from
                // later damage. Its old/absent answer is not an integrity oracle.
                reboot.write(fid, b"owner replacement").unwrap();
                assert_eq!(
                    value(&mut mount_fault(&flash), fid).as_deref(),
                    Some(&b"owner replacement"[..])
                );
            }
        }
    }
}

#[test]
fn read_failure_then_failed_repair_cannot_convert_an_unread_owner_into_an_absence() {
    for fid in [CRED, CTR] {
        let flash = FaultFlash::new();
        let mut store = mount_fault(&flash);
        store.write(fid, b"retained owner").unwrap();
        store.write(0xB000, b"neighbor").unwrap();
        flash.arm(&[
            Rule {
                io: Io::Read,
                skip: 0,
                effect: Effect::Refuse,
                latched: false,
            },
            Rule {
                io: Io::Program,
                skip: 0,
                effect: Effect::Refuse,
                latched: true,
            },
        ]);
        assert_eq!(store.read(fid, &mut [0; 64]), None);
        assert!(store.last_error());
        assert!(flash.hits()[0] > 0);
        assert_eq!(store.write(fid, b"replacement"), Err(Error::MemoryFatal));
        assert!(flash.hits().iter().all(|&hits| hits > 0));
        flash.clear();
        let mut reboot = mount_fault(&flash);
        assert_eq!(
            value(&mut reboot, fid).as_deref(),
            Some(&b"retained owner"[..])
        );
        assert_eq!(
            value(&mut reboot, 0xB000).as_deref(),
            Some(&b"neighbor"[..])
        );
        reboot.write(fid, b"replacement").unwrap();
        assert_eq!(
            value(&mut mount_fault(&flash), fid).as_deref(),
            Some(&b"replacement"[..])
        );
    }
}
