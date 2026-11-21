// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::authenticated::{CHECKPOINT_BYTES, CounterBank, Directory, ENTRY_BYTES, RawBank};

const OWNER: u16 = rsk_fs::counter::OATH_FIRST;

fn update(mounted: &mut Store, hotp: bool, value: u8) -> Result<()> {
    if hotp {
        mounted
            .write_bound_counter(OWNER, &[value; VALUE_BYTES])
            .map(|written| assert!(written))
    } else {
        mounted.write(PIV_RETRIES, &[3, value, 3, 3])
    }
}

fn check(mounted: &mut Store, hotp: bool, acknowledged: bool) {
    let mut value = [0; VALUE_BYTES];
    let observed = if hotp {
        assert_eq!(
            mounted.read_bound_counter(OWNER, &mut value),
            Ok(Some(VALUE_BYTES))
        );
        assert!(value.iter().all(|byte| *byte == value[0]));
        value[0]
    } else {
        assert_eq!(mounted.read(PIV_RETRIES, &mut value), Some(4));
        assert_eq!([value[0], value[2], value[3]], [3; 3]);
        value[1]
    };
    assert!(observed == 1 || !acknowledged && observed == 2);
    assert_eq!(mounted.read(OWNER, &mut value), Some(b"sealed owner".len()));
    assert_eq!(&value[..b"sealed owner".len()], b"sealed owner");
    assert_eq!(mounted.read(OPENPGP_RETRIES, &mut value), Some(7));
    assert_eq!(&value[..7], &[1, 127, 127, 127, 3, 2, 1]);
}

#[test]
fn routed_pin_and_hotp_rollovers_survive_program_and_erase_cuts() {
    for hotp in [false, true] {
        let (seed, mut mounted) = seeded(PIV_RETRIES, &[3; 4]);
        mounted.write(OWNER, b"sealed owner").unwrap();
        mounted
            .write(OPENPGP_RETRIES, &[1, 127, 127, 127, 3, 2, 1])
            .unwrap();
        update(&mut mounted, hotp, 2).unwrap();
        let layout = Layout::new(MAIN_END..END).unwrap();
        let mut raw =
            CounterBank::new(RawBank::new(seed.clone(), layout.counter[0].clone()).unwrap());
        let frame = ENTRY_BYTES
            + if hotp {
                Slot::oath(OWNER).unwrap().bytes()
            } else {
                16
            };
        let key = source().key(RootArm::PreOtp).unwrap();
        for _ in 0..raw.capacity() as usize / frame {
            let scan = raw.scan(key.expose(), &mut Directory::new()).unwrap();
            assert!(scan.next >= u32::try_from(CHECKPOINT_BYTES).unwrap());
            if raw.capacity() - scan.next < u32::try_from(frame).unwrap() {
                break;
            }
            update(&mut mounted, hotp, 2).unwrap();
        }
        let before = seed.image();
        seed.arm(&[]);
        update(&mut mounted, hotp, 1).unwrap();
        let events = seed.events();
        assert_eq!(events.iter().filter(|e| e.0 == Io::Erase).count(), 2);
        let programmed: usize = events
            .iter()
            .filter(|e| e.0 == Io::Program)
            .map(|e| e.2)
            .sum();
        let erased: usize = events
            .iter()
            .filter(|e| e.0 == Io::Erase)
            .map(|e| e.2)
            .sum();
        let mut faults: Vec<_> = (0..=programmed).map(|cut| (Io::Program, cut)).collect();
        for boundary in (0..=erased).step_by(crate::SECTOR) {
            faults.push((Io::Erase, boundary));
            if boundary > 0 {
                faults.push((Io::Erase, boundary - 1));
            }
            if boundary < erased {
                faults.push((Io::Erase, boundary + 1));
            }
        }
        for (io, cut) in faults {
            let flash = crate::tests::fault_flash_for_authenticated_tests();
            flash.replace_image_before_read(0, before.clone());
            let mut mounted = store(&flash);
            check(&mut mounted, hotp, false);
            flash.arm(&[Rule {
                io,
                skip: 0,
                effect: Effect::Shutoff(cut),
                latched: true,
            }]);
            let acknowledged = update(&mut mounted, hotp, 1).is_ok();
            assert!(flash.hits()[0] > 0, "hotp={hotp}, io={io:?}, cut={cut}");
            flash.clear();
            check(&mut store(&flash), hotp, acknowledged);
        }
    }
}
