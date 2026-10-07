// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::faults::{Cut, CutMedium, Op};
use rsk_secret::Secret;

struct NoEntropy;

impl Rng for NoEntropy {
    fn fill(&mut self, _: &mut [u8]) {
        panic!("repair must preserve the provisioned DEK");
    }
}

fn stored<S: Storage>(fs: &mut Fs<S>, fid: u16) -> Option<Vec<u8>> {
    let mut bytes = [0; rsk_fs::MAX_VALUE_BYTES];
    fs.read(fid, &mut bytes)
        .map(|n| bytes[..n.min(bytes.len())].to_vec())
}

fn setup() -> (Fs<Cut>, CutMedium) {
    let (backend, medium) = Cut::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    fs.put(0xb000, b"neighbor").unwrap();
    (fs, medium)
}

fn remount(fs: Fs<Cut>) -> Fs<Cut> {
    let mut fs = Fs::new(fs.into_storage());
    fs.scan();
    fs
}

fn key(fs: &mut Fs<Cut>) -> Secret<[u8; DEK_SIZE]> {
    let mut session = crate::pin::Session::new();
    assert_eq!(
        crate::pin::verify(
            &dev(),
            fs,
            &mut session,
            &mut NoEntropy,
            0,
            PW3_MODE83,
            PW3_DEFAULT
        ),
        Sw::OK
    );
    let mut out = Secret::<[u8; DEK_SIZE]>::zeroed();
    crate::pin::load_dek(&dev(), fs, &session, &mut out).unwrap();
    out
}

#[test]
fn incomplete_or_zero_length_reset_references_are_not_identified_as_the_factory_code() {
    for reference in [vec![], vec![8], vec![8, 1], vec![8; 33], vec![0; 34]] {
        let (mut fs, medium) = setup();
        let expected = key(&mut fs);
        fs.put(EF_RC, &reference).unwrap();
        fs.put_key(EF_DEK_RC, Sealed::wrap(b"unidentified copy"))
            .unwrap();
        let before = medium.value(EF_DEK_RC.get());
        let generation = fs.write_gen();
        scan_files(&dev(), &mut fs, &mut NoEntropy).unwrap();
        assert_eq!(stored(&mut fs, EF_RC), Some(reference));
        assert_eq!(medium.value(EF_DEK_RC.get()), before);
        assert_eq!(fs.write_gen(), generation);
        assert_eq!(key(&mut fs).expose(), expected.expose());
        assert_eq!(
            medium.value(0xb000).as_deref(),
            Some(b"neighbor".as_slice())
        );
    }
}

#[test]
fn short_status_records_repair_only_the_available_maxima_and_never_grow_a_retry_budget() {
    for length in 1..=pw_retry_idx(EF_RC) {
        let (mut fs, medium) = setup();
        let expected = key(&mut fs);
        let before = vec![0x5a; length];
        fs.put(EF_PW_PRIV, &before).unwrap();
        let mut wanted = before;
        let maxima_end = PW1_RETRY_IDX.min(length);
        wanted[1..maxima_end].copy_from_slice(&PW_STATUS_DEFAULT[1..maxima_end]);
        scan_files(&dev(), &mut fs, &mut NoEntropy).unwrap();
        assert_eq!(stored(&mut fs, EF_PW_PRIV), Some(wanted));
        let generation = fs.write_gen();
        scan_files(&dev(), &mut fs, &mut NoEntropy).unwrap();
        assert_eq!(fs.write_gen(), generation);
        assert_eq!(
            medium.value(0xb000).as_deref(),
            Some(b"neighbor".as_slice())
        );
        assert_eq!(medium.value(EF_RC), None);
        let mut session = crate::pin::Session::new();
        assert_eq!(
            crate::pin::verify(
                &dev(),
                &mut fs,
                &mut session,
                &mut NoEntropy,
                0,
                PW3_MODE83,
                PW3_DEFAULT
            ),
            Sw::MEMORY_FAILURE,
            "a missing retry slot cannot authorize the admin PIN",
        );
        assert!(!session.has_pw3);
        let mut repaired = PW_STATUS_DEFAULT.to_vec();
        repaired[pw_retry_idx(EF_RC)] = 0;
        fs.put(EF_PW_PRIV, &repaired).unwrap();
        assert_eq!(key(&mut fs).expose(), expected.expose());
    }
}

#[test]
fn each_status_repair_reports_a_refused_write_and_keeps_the_original_record() {
    for maxima in [false, true] {
        let (mut fs, medium) = setup();
        let expected = key(&mut fs);
        let mut legacy = PW_STATUS_DEFAULT.to_vec();
        if maxima {
            legacy[1..PW1_RETRY_IDX].fill(6);
            legacy[pw_retry_idx(EF_RC)] = 0;
        } else {
            legacy[pw_retry_idx(EF_RC)] = PW_RETRIES_DEFAULT;
        }
        fs.put(EF_PW_PRIV, &legacy).unwrap();
        medium.clear_ops();
        medium.arm(0);
        assert_eq!(
            scan_files(&dev(), &mut fs, &mut NoEntropy),
            Err(Error::Storage)
        );
        assert_eq!(medium.value(EF_PW_PRIV), Some(legacy));
        assert!(medium.ops().is_empty());
        medium.arm(u32::MAX);
        fs = remount(fs);
        scan_files(&dev(), &mut fs, &mut NoEntropy).unwrap();
        let mut wanted = PW_STATUS_DEFAULT.to_vec();
        wanted[pw_retry_idx(EF_RC)] = 0;
        assert_eq!(medium.ops(), vec![Op::Write(EF_PW_PRIV, wanted.clone())]);
        assert_eq!(stored(&mut fs, EF_PW_PRIV), Some(wanted));
        assert_eq!(key(&mut fs).expose(), expected.expose());
    }
}

fn legacy_status() -> (Fs<Cut>, CutMedium, Secret<[u8; DEK_SIZE]>) {
    let (mut fs, medium) = setup();
    let expected = key(&mut fs);
    let mut legacy = PW_STATUS_DEFAULT.to_vec();
    legacy[1..PW1_RETRY_IDX].fill(6);
    legacy[pw_retry_idx(EF_RC)] = PW_RETRIES_DEFAULT;
    fs.put(EF_PW_PRIV, &legacy).unwrap();
    fs.put(EF_SEX, b"0").unwrap();
    medium.clear_ops();
    (fs, medium, expected)
}

#[test]
fn legacy_boot_repairs_survive_every_pair_of_record_cut_boundaries() {
    let (mut clean, medium, _) = legacy_status();
    scan_files(&dev(), &mut clean, &mut NoEntropy).unwrap();
    let cost = u32::try_from(medium.ops().len()).unwrap();
    assert_eq!(cost, 3);
    let mut reached = [false; 4];
    for first in 0..=cost {
        let (mut probe, medium, _) = legacy_status();
        medium.arm(first);
        let result = scan_files(&dev(), &mut probe, &mut NoEntropy);
        assert_eq!(
            result,
            if first < cost {
                Err(Error::Storage)
            } else {
                Ok(())
            }
        );
        medium.arm(u32::MAX);
        probe = remount(probe);
        medium.clear_ops();
        scan_files(&dev(), &mut probe, &mut NoEntropy).unwrap();
        let recovery_cost = u32::try_from(medium.ops().len()).unwrap();
        for second in 0..=recovery_cost {
            let (mut fs, medium, expected) = legacy_status();
            let protected = [EF_PW1, EF_PW3, EF_DEK_PW1.get(), EF_DEK_PW3.get()]
                .map(|fid| (fid, medium.value(fid)));
            medium.arm(first);
            let result = scan_files(&dev(), &mut fs, &mut NoEntropy);
            reached[0] |= result.is_err();
            reached[1] |= result.is_ok();
            medium.arm(u32::MAX);
            fs = remount(fs);
            medium.arm(second);
            let recovery = scan_files(&dev(), &mut fs, &mut NoEntropy);
            assert_eq!(
                recovery,
                if second < recovery_cost {
                    Err(Error::Storage)
                } else {
                    Ok(())
                }
            );
            reached[2] |= recovery.is_err();
            reached[3] |= recovery.is_ok();
            medium.arm(u32::MAX);
            fs = remount(fs);
            scan_files(&dev(), &mut fs, &mut NoEntropy).unwrap();
            let mut wanted = PW_STATUS_DEFAULT.to_vec();
            wanted[pw_retry_idx(EF_RC)] = 0;
            assert_eq!(stored(&mut fs, EF_PW_PRIV), Some(wanted));
            assert_eq!(stored(&mut fs, EF_SEX), Some(SEX_DEFAULT.to_vec()));
            for (fid, before) in protected {
                assert_eq!(medium.value(fid), before);
            }
            assert_eq!(
                medium.value(0xb000).as_deref(),
                Some(b"neighbor".as_slice())
            );
            assert_eq!(key(&mut fs).expose(), expected.expose());
            let generation = fs.write_gen();
            scan_files(&dev(), &mut fs, &mut NoEntropy).unwrap();
            assert_eq!(fs.write_gen(), generation);
        }
    }
    assert_eq!(reached, [true; 4]);
}
