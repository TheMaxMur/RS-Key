// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::cut::sweep_restarts;
use rsk_fs::storage::faults::Cut;

#[test]
fn a_device_wipe_and_its_owner_retry_defer_every_live_applets_gates() {
    let seeds = [
        rsk_fido::consts::EF_KEY_DEV.get(),
        rsk_fido::consts::EF_KEY_DEV_ENC.get(),
    ];
    let secrets = [
        rsk_fido::consts::EF_CRED,
        rsk_piv::files::key_fid(rsk_piv::files::SLOT_AUTHENTICATION).get(),
        rsk_oath::EF_OATH_CRED,
        rsk_openpgp::consts::EF_PK_SIG.get(),
    ];
    let gates: std::vec::Vec<u16> = (0..=u16::MAX)
        .filter(|&fid| gates_wiped_last(fid))
        .collect();
    let inspect = |fs: &mut Fs<Cut>| {
        if secrets.iter().any(|&fid| fs.has_data(fid)) {
            for &gate in &gates {
                assert!(
                    fs.has_data(gate),
                    "a surviving secret lost gate {gate:#06x}"
                );
            }
        }
        if secrets.iter().any(|&fid| fs.has_data(fid)) && seeds.iter().any(|&fid| fs.has_data(fid))
        {
            assert!(fs.has_data(rsk_fido::consts::EF_BACKUP_SEALED));
        }
    };
    let wipe = |fs: &mut Fs<Cut>| {
        fs.factory_wipe(
            rsk_fido::reset::survives_factory_reset,
            rsk_fido::reset::is_fido_seed_fid,
            gates_wiped_last,
        )
    };
    assert!(sweep_restarts(
        || {
            let (storage, medium) = Cut::new();
            let mut fs = Fs::new(storage);
            fs.scan();
            for fid in seeds
                .into_iter()
                .chain(secrets)
                .chain(gates.iter().copied())
                .chain([rsk_fido::consts::EF_BACKUP_SEALED])
            {
                if let Some(&counter) = rsk_fs::counter::COUNTER_FIDS
                    .iter()
                    .find(|counter| counter.get() == fid)
                {
                    fs.put_counter(counter, b"owned record").unwrap();
                } else {
                    fs.put(fid, b"owned record").unwrap();
                }
            }
            fs.put(
                rsk_fido::consts::EF_ATT_CHAIN,
                b"preserved organization identity",
            )
            .unwrap();
            (fs, medium)
        },
        |fs| wipe(fs).is_ok(),
        |fs| {
            inspect(fs);
            let _ = wipe(fs);
        },
        |fs, _, _, _, medium| {
            for fid in seeds
                .into_iter()
                .chain(secrets)
                .chain(gates.iter().copied())
            {
                assert!(!fs.has_data(fid));
            }
            assert_eq!(
                medium.value(rsk_fido::consts::EF_ATT_CHAIN).as_deref(),
                Some(&b"preserved organization identity"[..])
            );
        }
    ));
}
