// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn sealed_key<S: Storage>(fs: &mut Fs<S>, slot: u8) -> Vec<u8> {
    let mut out = [0; 128];
    let n = fs.read_key(key_fid(slot), &mut out).unwrap();
    out[..n].to_vec()
}

#[test]
fn a_headless_move_cannot_inherit_the_destination_policy_or_cache() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    let (from, to) = (SLOT_AUTHENTICATION, SLOT_RETIRED_FIRST);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            INS_ASYM_KEYGEN,
            0,
            from,
            &gen_template(ALGO_ECCP256)
        )
        .0,
        Sw::OK
    );
    let before = sealed_key(&mut fs, from);
    fs.meta_delete(key_fid(from).get()).unwrap();
    fs.delete(pubkey_fid(from)).unwrap();
    fs.meta_add(
        key_fid(to).get(),
        &[
            ALGO_ECCP256,
            PINPOLICY_NEVER,
            TOUCHPOLICY_NEVER,
            ORIGIN_GENERATED,
        ],
    )
    .unwrap();
    fs.put(pubkey_fid(to), b"orphan point").unwrap();
    fs.put(cert_fid_for_slot(from).unwrap(), b"source certificate")
        .unwrap();
    fs.put(cert_fid_for_slot(to).unwrap(), b"destination certificate")
        .unwrap();
    assert_eq!(
        run(&mut app, &mut fs, INS_MOVE_KEY, to, from, &[]),
        (Sw::OK, vec![])
    );
    assert_eq!(sealed_key(&mut fs, to), before);
    assert!(!fs.has_key(key_fid(from)));
    assert_eq!(fs.meta_find(key_fid(to).get(), &mut [0; 4]), None);
    assert_eq!(fs.read(pubkey_fid(to), &mut [0; MAX_EC_POINT]), None);
    assert_eq!(
        run(&mut app, &mut fs, INS_GET_METADATA, 0, to, &[]),
        (Sw::REFERENCE_NOT_FOUND, vec![])
    );
    verify_pin(&mut app, &mut fs);
    assert_eq!(sign_p256(&mut app, &mut fs, to), Sw::REFERENCE_NOT_FOUND);
    for (slot, wanted) in [
        (from, b"source certificate".as_slice()),
        (to, b"destination certificate".as_slice()),
    ] {
        let mut bytes = [0; 32];
        let n = fs
            .read(cert_fid_for_slot(slot).unwrap(), &mut bytes)
            .unwrap();
        assert_eq!(&bytes[..n], wanted);
    }
}

#[test]
fn an_oversized_source_refuses_the_move_without_truncation_or_mutation() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    let (from, to) = (SLOT_AUTHENTICATION, 0x82);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            INS_ASYM_KEYGEN,
            0,
            from,
            &gen_template(ALGO_ECCP256)
        )
        .0,
        Sw::OK
    );
    let original = sealed_key(&mut fs, from);
    let mut before_head = [0; 4 + MAX_EC_POINT];
    let head_length = fs.meta_find(key_fid(from).get(), &mut before_head).unwrap();
    assert!(!fs.has_key(key_fid(to)));
    assert_eq!(fs.meta_find(key_fid(to).get(), &mut [0; 4]), None);
    let oversized = vec![0x5a; seal::MAX_BLOB + 1];
    fs.put_key(key_fid(from), Sealed::wrap(&oversized)).unwrap();
    let generation = fs.write_gen();
    assert_eq!(
        run(&mut app, &mut fs, INS_MOVE_KEY, to, from, &[]),
        (Sw::MEMORY_FAILURE, vec![])
    );
    let mut after = vec![0; oversized.len()];
    assert_eq!(
        fs.read_key(key_fid(from), &mut after),
        Some(oversized.len())
    );
    assert_eq!(after, oversized);
    let mut after_head = [0; 4 + MAX_EC_POINT];
    assert_eq!(
        fs.meta_find(key_fid(from).get(), &mut after_head),
        Some(head_length)
    );
    assert_eq!(after_head, before_head);
    assert!(!fs.has_key(key_fid(to)));
    assert_eq!(fs.meta_find(key_fid(to).get(), &mut [0; 4]), None);
    assert_eq!(fs.write_gen(), generation);

    fs.put_key(key_fid(from), Sealed::wrap(&original)).unwrap();
    verify_pin(&mut app, &mut fs);
    assert_eq!(sign_p256(&mut app, &mut fs, from), Sw::OK);
    assert_eq!(
        run(&mut app, &mut fs, INS_MOVE_KEY, to, from, &[]),
        (Sw::OK, vec![])
    );
    assert!(!fs.has_key(key_fid(from)));
    assert_eq!(sealed_key(&mut fs, to), original);
    assert_eq!(
        fs.meta_find(key_fid(to).get(), &mut after_head),
        Some(head_length)
    );
    assert_eq!(after_head, before_head);
    verify_pin(&mut app, &mut fs);
    assert_eq!(sign_p256(&mut app, &mut fs, to), Sw::OK);
}

#[test]
fn a_refused_destination_head_drop_preserves_the_source_and_orphan_policy() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let refuse = Rc::new(Cell::new(None));
    let mut fs = Fs::new(RefuseWrite {
        inner: RamStorage::new(),
        refuse: refuse.clone(),
        refuse_remove: Rc::new(Cell::new(None)),
    });
    fs.scan();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    let slots = [SLOT_AUTHENTICATION, 0x82];
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            INS_ASYM_KEYGEN,
            0,
            slots[0],
            &gen_template(ALGO_ECCP256)
        )
        .0,
        Sw::OK
    );
    fs.meta_add(
        key_fid(slots[1]).get(),
        &[
            ALGO_ECCP256,
            PINPOLICY_NEVER,
            TOUCHPOLICY_NEVER,
            ORIGIN_GENERATED,
        ],
    )
    .unwrap();
    let before = sealed_key(&mut fs, slots[0]);
    let mut heads = [[0; 4 + MAX_EC_POINT]; 2];
    let lengths = slots.map(|slot| {
        let i = usize::from(slot != slots[0]);
        fs.meta_find(key_fid(slot).get(), &mut heads[i]).unwrap()
    });
    refuse.set(Some(rsk_fs::EF_META));
    assert_eq!(
        run(&mut app, &mut fs, INS_MOVE_KEY, slots[1], slots[0], &[]),
        (Sw::MEMORY_FAILURE, vec![])
    );
    refuse.set(None);
    for (i, slot) in slots.into_iter().enumerate() {
        let mut head = [0; 4 + MAX_EC_POINT];
        assert_eq!(
            fs.meta_find(key_fid(slot).get(), &mut head),
            Some(lengths[i])
        );
        assert_eq!(head, heads[i]);
    }
    assert_eq!(sealed_key(&mut fs, slots[0]), before);
    assert!(!fs.has_key(key_fid(slots[1])));
    verify_pin(&mut app, &mut fs);
    assert_eq!(sign_p256(&mut app, &mut fs, slots[0]), Sw::OK);
    assert!(app.sess.has_mgm);
    assert_eq!(
        run(&mut app, &mut fs, INS_MOVE_KEY, slots[1], slots[0], &[]),
        (Sw::OK, vec![])
    );
    assert!(!fs.has_key(key_fid(slots[0])));
    assert_eq!(sealed_key(&mut fs, slots[1]), before);
}
