// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn orphan_p384_metadata_reports_only_the_bounded_cached_point() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    let (sw, generated) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0,
        SLOT_AUTHENTICATION,
        &gen_template(ALGO_ECCP384),
    );
    assert_eq!(sw, Sw::OK);
    let point = ec_point_of(&generated);
    assert_eq!(point.len(), 97);
    let fid = key_fid(SLOT_AUTHENTICATION);
    let mut metadata = [0; 102];
    assert_eq!(fs.meta_find(fid.get(), &mut metadata), Some(101));
    assert_eq!(&metadata[4..101], point.as_slice());
    metadata[101] = 0xA5;
    fs.delete_key(fid).unwrap();
    fs.delete(pubkey_fid(SLOT_AUTHENTICATION)).unwrap();
    fs.meta_add(fid.get(), &metadata).unwrap();
    assert!(!fs.has_key(fid));
    assert!(!fs.has_data(pubkey_fid(SLOT_AUTHENTICATION)));
    let generation = fs.write_gen();

    let (sw, response) = run(
        &mut app,
        &mut fs,
        INS_GET_METADATA,
        0,
        SLOT_AUTHENTICATION,
        &[],
    );
    assert_eq!(sw, Sw::OK, "the bounded orphan cache remains readable");
    assert_eq!(find_tag(&response, 0x01), Some(&metadata[..1]));
    assert_eq!(find_tag(&response, 0x02), Some(&metadata[1..3]));
    assert_eq!(find_tag(&response, 0x03), Some(&metadata[3..4]));
    assert_eq!(
        find_tag(find_tag(&response, 0x04).unwrap(), 0x86),
        Some(point.as_slice())
    );
    assert_eq!(fs.write_gen(), generation);
    let mut back = [0; 102];
    assert_eq!(fs.meta_find(fid.get(), &mut back), Some(102));
    assert_eq!(back, metadata);
    assert!(!fs.has_key(fid));
    assert!(!fs.has_data(pubkey_fid(SLOT_AUTHENTICATION)));
}

#[test]
fn a_p384_move_bounds_oversized_metadata_and_keeps_the_sealed_key() {
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    let (sw, generated) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0,
        SLOT_AUTHENTICATION,
        &gen_template(ALGO_ECCP384),
    );
    assert_eq!(sw, Sw::OK);
    let point = ec_point_of(&generated);
    assert_eq!(point.len(), 97);
    let source = key_fid(SLOT_AUTHENTICATION);
    let destination = key_fid(SLOT_RETIRED_FIRST);
    let mut metadata = [0; 102];
    assert_eq!(fs.meta_find(source.get(), &mut metadata), Some(101));
    assert_eq!(&metadata[4..101], point.as_slice());
    metadata[101] = 0xA5;
    fs.meta_add(source.get(), &metadata).unwrap();
    assert!(!fs.has_key(destination));
    // Prove that retaining all 102 bytes would not fall back to a bare head.
    fs.meta_add_reserve(destination.get(), &metadata, keygen::META_POINT_RESERVE)
        .unwrap();
    fs.meta_delete(destination.get()).unwrap();
    let mut original = Secret::<[u8; seal::MAX_BLOB]>::zeroed();
    let sealed_len = fs.read_key(source, original.expose_mut()).unwrap();
    assert!(sealed_len > 0);

    let (sw, response) = run(
        &mut app,
        &mut fs,
        INS_MOVE_KEY,
        SLOT_RETIRED_FIRST,
        SLOT_AUTHENTICATION,
        &[],
    );
    assert_eq!(sw, Sw::OK);
    assert!(response.is_empty());
    let mut moved = Secret::<[u8; seal::MAX_BLOB]>::zeroed();
    assert_eq!(
        fs.read_key(destination, moved.expose_mut()),
        Some(sealed_len)
    );
    assert!(moved.expose()[..sealed_len] == original.expose()[..sealed_len]);
    assert!(!fs.has_key(source));
    let mut source_metadata = [0; 102];
    assert_eq!(fs.meta_find(source.get(), &mut source_metadata), None);
    assert!(!fs.has_data(pubkey_fid(SLOT_AUTHENTICATION)));
    let mut moved_metadata = [0; 102];
    assert_eq!(
        fs.meta_find(destination.get(), &mut moved_metadata),
        Some(101)
    );
    assert_eq!(&moved_metadata[..101], &metadata[..101]);
    let mut moved_point = [0; 97];
    assert_eq!(
        fs.read(pubkey_fid(SLOT_RETIRED_FIRST), &mut moved_point),
        Some(97)
    );
    assert_eq!(moved_point.as_slice(), point.as_slice());
}

#[test]
fn an_authenticated_overlong_management_record_keeps_the_length_refusal() {
    for plain_len in [34, 35] {
        let rng = RefCell::new(TestRng(7));
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
        let device = Device {
            serial_hash: &HASH,
            serial_id: &SERIAL,
            otp_key: None,
            latched: false,
        };
        let mut plain = Secret::<[u8; 35]>::zeroed();
        plain.expose_mut().fill(0x5A);
        plain.expose_mut()[..2].copy_from_slice(&[ALGO_AES256, TOUCHPOLICY_NEVER]);
        let fid = key_fid(SLOT_CARDMGM);
        seal::seal_put(
            &device,
            &mut fs,
            &mut *rng.borrow_mut(),
            fid,
            &plain.expose()[..plain_len],
        )
        .unwrap();
        let mut back = Secret::<[u8; 35]>::zeroed();
        assert_eq!(
            seal::seal_read(&device, &mut fs, fid, &mut back),
            Ok(plain_len)
        );
        assert!(back.expose()[..plain_len] == plain.expose()[..plain_len]);
        let generation = fs.write_gen();

        let (sw, response) = run(&mut app, &mut fs, INS_GET_METADATA, 0, SLOT_CARDMGM, &[]);
        assert_eq!(
            sw,
            if plain_len == 34 {
                Sw::OK
            } else {
                Sw::WRONG_LENGTH
            },
            "authenticated management record length {plain_len}"
        );
        if plain_len == 34 {
            assert_eq!(find_tag(&response, 0x01), Some([ALGO_AES256].as_slice()));
        } else {
            assert!(response.is_empty());
        }
        assert_eq!(fs.write_gen(), generation);
    }
}

#[test]
fn a_raw_oversized_pool_object_reports_only_the_bounded_body() {
    const STORED_BYTES: usize = 3100;
    const VISIBLE_BYTES: usize = 3063;
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    let id = [0x5F, 0xFF, 0x10];
    let body: Vec<u8> = (0..STORED_BYTES).map(|i| (i % 251) as u8).collect();
    let mut record = id[1..].to_vec();
    record.extend_from_slice(&body);
    let fid = *objects::POOL.start();
    fs.put(fid, &record).unwrap();
    let generation = fs.write_gen();
    let data = [TAG_DATA_PATH, 3, id[0], id[1], id[2]];
    let raw = apdu_bytes(INS_GET_DATA, 0x3F, 0xFF, &data);
    let apdu = Apdu::parse(&raw).unwrap();
    // Both possible bodies fit, so response capacity cannot mask the copy bound.
    let mut out = [0; 4096];
    let mut response = ResBuf::new(&mut out);
    assert_eq!(
        Applet::process(&mut app, &apdu, &mut fs, &mut response),
        Sw::OK
    );
    let object = find_tag(response.as_slice(), u16::from(TAG_DATA_OBJECT)).unwrap();
    assert_eq!(object.len(), VISIBLE_BYTES);
    assert_eq!(object, &body[..VISIBLE_BYTES]);
    assert_eq!(response.len(), VISIBLE_BYTES + 4);
    assert_eq!(fs.write_gen(), generation);
    let mut back = vec![0; record.len()];
    assert_eq!(fs.read(fid, &mut back), Some(record.len()));
    assert_eq!(back, record);
}
