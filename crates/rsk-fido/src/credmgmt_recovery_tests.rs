// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::cut::{Snap, sweep_recovery};

/// Every RP record names exactly as many credentials as hold its rpIdHash, and
/// every credential's RP has a record.
fn agrees<S: rsk_fs::Storage>(fs: &mut Fs<S>) -> bool {
    let mut buf = [0u8; RP_REC_MAX];
    let mut named = std::collections::BTreeMap::<[u8; 32], u8>::new();
    for i in cred_slots(fs) {
        if let Some(n) = fs.read(EF_CRED + i, &mut buf)
            && n >= 32
        {
            *named.entry(buf[..32].try_into().unwrap()).or_default() += 1;
        }
    }
    let mut recorded = std::collections::BTreeMap::new();
    for j in 0..MAX_RESIDENT_CREDENTIALS {
        if let Some(n) = fs.read(EF_RP + j, &mut buf)
            && n >= RP_PREFIX
        {
            let hash: [u8; 32] = buf[1..RP_PREFIX].try_into().unwrap();
            recorded.insert(hash, buf[0]);
        }
    }
    named == recorded
}

/// A passkey delete cut at every write, then the boot's settle pass cut at every
/// write of its own, then a healthy boot: the RP records agree with the credentials
/// that remain, the last credential's RP included.
#[test]
fn a_delete_torn_and_its_settle_torn_still_settle_to_the_credentials() {
    for user in [&[1u8, 1][..], &[3, 3][..]] {
        sweep_recovery(
            |fs| {
                let mut rng = SeqRng(1);
                ensure_seed(&dev(), fs, &mut rng).unwrap();
                let (a, ..) = register(fs, &mut rng, "example.com", &[1, 1], "alice");
                register(fs, &mut rng, "example.com", &[2, 2], "bob");
                let (c, ..) = register(fs, &mut rng, "other.com", &[3, 3], "carol");
                if user == [1, 1] { a } else { c }
            },
            |fs, id| {
                let mut out = [0u8; 256];
                let req = cm_request(0x06, Some(&subpara_cred(id)), &TOKEN);
                let _ = run(fs, &mut armed(PERM_CM), &req, &mut out);
            },
            |fs| {
                let _ = settle_rp_records(fs);
            },
            |fs: &mut Fs<Snap>, first, second| {
                assert!(
                    agrees(fs),
                    "user {user:?}, cuts {first}/{second}: the RP records disagree with the credentials: {:?}",
                    rp_counts(fs)
                );
            },
        );
    }
}

#[test]
fn combined_delete_and_recovery_cuts_preserve_untargeted_records() {
    let originals = std::cell::RefCell::new(std::vec::Vec::<(u16, std::vec::Vec<u8>)>::new());
    for target in [0usize, 2] {
        sweep_recovery(
            |fs| {
                let mut rng = SeqRng(1);
                ensure_seed(&dev(), fs, &mut rng).unwrap();
                let (alice, ..) = register(fs, &mut rng, "example.com", &[1], "alice");
                register(fs, &mut rng, "example.com", &[2], "bob");
                let (carol, ..) = register(fs, &mut rng, "other.com", &[3], "carol");
                let mut records = originals.borrow_mut();
                records.clear();
                for slot in cred_slots(fs) {
                    let mut buf = [0u8; CRED_REC_MAX];
                    let n = fs.read(EF_CRED + slot, &mut buf).unwrap();
                    records.push((EF_CRED + slot, buf[..n].to_vec()));
                }
                assert_eq!(records.len(), 3);
                if target == 0 { alice } else { carol }
            },
            |fs, id| {
                let req = cm_request(0x06, Some(&subpara_cred(id)), &TOKEN);
                let _ = run(fs, &mut armed(PERM_CM), &req, &mut [0u8; 256]);
            },
            |fs| {
                let _ = settle_rp_records(fs);
            },
            |fs: &mut Fs<Snap>, first, second| {
                for (index, (fid, original)) in originals.borrow().iter().enumerate() {
                    let mut buf = [0u8; CRED_REC_MAX];
                    let current = fs.read(*fid, &mut buf).map(|n| &buf[..n]);
                    if index == target {
                        assert!(
                            current.is_none() || current == Some(&original[..]),
                            "cuts {first}/{second}: torn target record"
                        );
                    } else {
                        assert_eq!(
                            current,
                            Some(&original[..]),
                            "cuts {first}/{second}: unrelated record {fid:#06x}"
                        );
                    }
                }
                assert!(
                    agrees(fs),
                    "cuts {first}/{second}: RP counts changed behind the credentials"
                );
            },
        );
    }
}

#[test]
fn a_legacy_rp_migration_and_its_retry_can_both_be_interrupted() {
    let mut device = dev();
    device.otp_key = Some(&[0x5A; 32]);
    let domains = ["example.com", "other.com"];
    sweep_recovery(
        |fs| {
            ensure_seed(&device, fs, &mut SeqRng(1)).unwrap();
            fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
            for (slot, domain) in domains.iter().enumerate() {
                let mut record = std::vec![1];
                record.extend_from_slice(&sha256(domain.as_bytes()));
                record.extend_from_slice(domain.as_bytes());
                fs.put(EF_RP + u16::try_from(slot).unwrap(), &record)
                    .unwrap();
            }
        },
        |fs, ()| {
            crate::credential::migrate_rp_seal(&device, fs);
        },
        |fs| {
            crate::credential::migrate_rp_seal(&device, fs);
        },
        |fs: &mut Fs<Snap>, first, second| {
            let mut seed = crate::seed::load_keydev(&device, fs).unwrap();
            for (slot, domain) in domains.iter().enumerate() {
                let hash = sha256(domain.as_bytes());
                let mut record = [0u8; RP_REC_MAX];
                let n = fs
                    .read(EF_RP + u16::try_from(slot).unwrap(), &mut record)
                    .unwrap();
                assert_eq!(record[0], 1);
                assert_eq!(&record[1..RP_PREFIX], &hash);
                let mut scratch = [0u8; RP_REC_MAX];
                assert_eq!(
                    crate::credential::unseal_rp_id(
                        seed.expose(),
                        &hash,
                        &record[RP_PREFIX..n],
                        &mut scratch
                    ),
                    Some((*domain, true)),
                    "cuts {first}/{second}: migration did not converge"
                );
            }
            seed.wipe();
            assert!(
                !fs.has_data(rsk_fs::EF_HARDENED),
                "cuts {first}/{second}: superseded cleartext did not re-arm the scrub"
            );
            let generation = fs.write_gen();
            crate::credential::migrate_rp_seal(&device, fs);
            assert_eq!(
                fs.write_gen(),
                generation,
                "sealed records must not be rewritten on another boot"
            );
        },
    );
}
