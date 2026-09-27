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
