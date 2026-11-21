// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn relocating_the_main_window_preserves_the_compaction_io_trace() {
    let reference_flash = FaultFlash::new();
    let _reference_store = mount_authenticated(&reference_flash);
    let authority_bytes = u32::try_from(reference_flash.capacity()).unwrap() - MAIN.end;
    let mut reference = None;
    for start in [MAIN.start, MAIN.end] {
        let flash = FaultFlash::new();
        let main = start..start + MAIN.end - MAIN.start;
        let counter = main.end..main.end + authority_bytes;
        flash
            .inner
            .bytes
            .borrow_mut()
            .resize(counter.end as usize, 0xFF);
        let mut store = Authenticated::new(
            flash.clone(),
            main,
            counter,
            MainCache::new(
                ArrayPageStates::new(),
                ArrayPagePointers::new(),
                ArrayKeyPointers::new(),
            ),
            KeySource::new([0x43; 32], auth_blank, false),
            [0x4B; 16],
            RootArm::PreOtp,
        )
        .unwrap();
        store.initialize_blank().unwrap();
        store.write(CRED, b"retired owner").unwrap();
        store.write(CRED, b"current owner").unwrap();
        store.write(CRED + 1, b"neighbor").unwrap();
        store.write(CTR, b"counter").unwrap();
        flash.arm(&[]);
        store.compact().unwrap();
        let trace: Vec<_> = flash
            .events()
            .into_iter()
            .map(|(io, address, length)| (io, address.checked_sub(start).unwrap(), length))
            .collect();
        if let Some(expected) = &reference {
            assert_eq!(
                &trace, expected,
                "moving the partition must not add compaction IO"
            );
        } else {
            reference = Some(trace);
        }
        for (fid, value) in [
            (CRED, &b"current owner"[..]),
            (CRED + 1, &b"neighbor"[..]),
            (CTR, &b"counter"[..]),
        ] {
            let mut out = [0; 128];
            assert_eq!(store.read(fid, &mut out), Some(value.len()));
            assert_eq!(out.get(..value.len()), Some(value));
            assert!(!store.last_error());
        }
    }
}
