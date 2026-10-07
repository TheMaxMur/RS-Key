// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::faults::ProbeStuck;

fn stored<S: Storage>(fs: &mut Fs<S>, fid: u16) -> std::vec::Vec<u8> {
    let mut out = [0; CRED_REC_MAX];
    let n = fs.read(fid, &mut out).unwrap();
    out[..n].to_vec()
}

#[test]
fn a_faulted_resident_walk_skips_only_the_unreadable_slot_and_never_writes() {
    let (backend, medium) = ProbeStuck::new();
    let mut fs = Fs::new(backend);
    ensure_seed(&dev(), &mut fs, &mut SeqRng(1)).unwrap();
    let seed = load_keydev(&dev(), &mut fs).unwrap();
    add(
        &mut fs,
        seed.expose(),
        1,
        "a.example",
        b"a",
        "alice",
        "Alice",
        0,
    );
    add(
        &mut fs,
        seed.expose(),
        2,
        "b.example",
        b"b",
        "bob",
        "Bob",
        0,
    );
    let generation = fs.write_gen();
    medium.stick_once(EF_RP);
    let mut domains = std::vec::Vec::new();
    assert_eq!(
        for_each_rp(&dev(), &mut fs, |rp| domains.push(rp.rp_id.to_string())),
        1
    );
    assert_eq!(domains, ["b.example"]);
    medium.stick_once(EF_CRED);
    assert_eq!(
        for_each_cred(&dev(), &mut fs, &sha256(b"a.example"), |_| panic!(
            "unreadable credential"
        )),
        0
    );
    assert_eq!(
        for_each_cred(&dev(), &mut fs, &sha256(b"b.example"), |a| assert_eq!(
            a.user_name,
            "bob"
        )),
        1
    );
    assert_eq!(for_each_rp(&dev(), &mut fs, |_| {}), 2);
    assert_eq!(
        for_each_cred(&dev(), &mut fs, &sha256(b"a.example"), |a| assert_eq!(
            a.user_name,
            "alice"
        )),
        1
    );
    assert_eq!(fs.write_gen(), generation);
}

#[test]
fn resident_views_omit_unopenable_boxes_and_preserve_a_healthy_neighbor() {
    let (mut fs, seed) = provisioned();
    add(&mut fs, &seed, 1, "a.example", b"a", "alice", "Alice", 0);
    add(&mut fs, &seed, 2, "b.example", b"b", "bob", "Bob", 0);
    let rp = stored(&mut fs, EF_RP);
    let cred = stored(&mut fs, EF_CRED);
    let mut bad_rp = rp[..RP_PREFIX].to_vec();
    bad_rp.push(0xFF);
    fs.put(EF_RP, &bad_rp).unwrap();
    let mut bad_cred = cred.clone();
    let ciphertext = bad_cred.len() - cred_record_box(&bad_cred).len() + 12;
    bad_cred[ciphertext] ^= 1;
    fs.put(EF_CRED, &bad_cred).unwrap();
    let generation = fs.write_gen();
    let mut domains = std::vec::Vec::new();
    assert_eq!(
        for_each_rp(&dev(), &mut fs, |rp| domains.push(rp.rp_id.to_string())),
        1
    );
    assert_eq!(domains, ["b.example"]);
    assert_eq!(
        for_each_cred(&dev(), &mut fs, &sha256(b"a.example"), |_| panic!(
            "corrupt credential"
        )),
        0
    );
    assert_eq!(
        for_each_cred(&dev(), &mut fs, &sha256(b"b.example"), |a| assert_eq!(
            a.user_id,
            b"b"
        )),
        1
    );
    assert_eq!(stored(&mut fs, EF_RP), bad_rp);
    assert_eq!(stored(&mut fs, EF_CRED), bad_cred);
    assert_eq!(fs.write_gen(), generation);
    fs.put(EF_RP, &rp).unwrap();
    fs.put(EF_CRED, &cred).unwrap();
    assert_eq!(for_each_rp(&dev(), &mut fs, |_| {}), 2);
    assert_eq!(
        for_each_cred(&dev(), &mut fs, &sha256(b"a.example"), |a| assert_eq!(
            a.user_name,
            "alice"
        )),
        1
    );
}

#[test]
fn a_short_credential_cannot_be_displayed_or_deleted_as_a_complete_record() {
    let (mut fs, seed) = provisioned();
    add(&mut fs, &seed, 1, "a.example", b"a", "alice", "Alice", 0);
    let original = stored(&mut fs, EF_CRED);
    fs.put(EF_CRED, &original[..RECORD_PREFIX - 1]).unwrap();
    let generation = fs.write_gen();
    assert_eq!(
        for_each_cred(&dev(), &mut fs, &sha256(b"a.example"), |_| panic!(
            "short credential"
        )),
        0
    );
    assert!(!delete_cred(&mut fs, &mut SeqRng(7), EF_CRED));
    assert_eq!(stored(&mut fs, EF_CRED), original[..RECORD_PREFIX - 1]);
    assert_eq!(fs.write_gen(), generation);
    fs.put(EF_CRED, &original).unwrap();
    assert!(delete_cred(&mut fs, &mut SeqRng(7), EF_CRED));
    assert_eq!(for_each_rp(&dev(), &mut fs, |_| {}), 0);
}

#[test]
fn nickname_writes_refuse_missing_short_or_unreadable_resident_records() {
    let (backend, medium) = ProbeStuck::new();
    let mut fs = Fs::new(backend);
    ensure_seed(&dev(), &mut fs, &mut SeqRng(1)).unwrap();
    let seed = load_keydev(&dev(), &mut fs).unwrap();
    let hash = sha256(b"a.example");
    add(
        &mut fs,
        seed.expose(),
        1,
        "a.example",
        b"a",
        "alice",
        "Alice",
        0,
    );
    let rp = stored(&mut fs, EF_RP);
    medium.stick_once(EF_RP);
    let generation = fs.write_gen();
    assert!(!set_rp_nickname(&dev(), &mut fs, &hash, "Work"));
    assert_eq!(fs.write_gen(), generation);
    fs.put(EF_RP, &rp[..RP_PREFIX - 1]).unwrap();
    let generation = fs.write_gen();
    assert!(!set_rp_nickname(&dev(), &mut fs, &hash, "Work"));
    assert_eq!(fs.write_gen(), generation);
    fs.put(EF_RP, &rp).unwrap();
    medium.stick_once(crate::consts::EF_KEY_DEV.get());
    let generation = fs.write_gen();
    assert!(!set_rp_nickname(&dev(), &mut fs, &hash, "Work"));
    assert_eq!(fs.write_gen(), generation);
    assert!(set_rp_nickname(&dev(), &mut fs, &hash, "Work"));
    assert_eq!(
        for_each_rp(&dev(), &mut fs, |rp| assert_eq!(rp.nickname, Some("Work"))),
        1
    );
}
