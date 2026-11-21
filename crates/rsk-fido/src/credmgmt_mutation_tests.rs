// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn short_hash_prefixes_do_not_select_a_second_credential_read() {
    for length in 0..=4 {
        let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
        let mut fs = Fs::new(backend);
        let mut rng = SeqRng(1);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        register(&mut fs, &mut rng, "example.com", &[1], "owner");
        let hash = sha256(b"example.com");
        let prefix = u32::from_le_bytes(hash[..4].try_into().unwrap());
        assert_ne!(prefix, 0);
        fs.put(EF_CRED + 1, &hash[..length]).unwrap();
        let mut wanted = hash;
        wanted[31] ^= 1;
        let request = cm_request(0x04, Some(&subpara_rpidhash(&wanted)), &TOKEN);
        let generation = fs.write_gen();
        medium.stick_after(EF_CRED + 1, 1);
        let mut state = armed(PERM_CM);
        assert_eq!(
            run(&mut fs, &mut state, &request, &mut [0; 256]),
            Err(if length == 4 {
                CtapError::Other
            } else {
                CtapError::NoCredentials
            }),
            "prefix length {length}"
        );
        assert_eq!(state.cm.rp_index[0], prefix);
        assert_eq!(state.cm.rp_index[1], if length == 4 { prefix } else { 0 });
        assert_eq!(fs.write_gen(), generation);
        medium.stick(None);
        assert_eq!(
            run(&mut fs, &mut armed(PERM_CM), &request, &mut [0; 256]),
            Err(CtapError::NoCredentials)
        );
        assert_eq!(fs.write_gen(), generation);
    }
}

#[test]
fn get_info_counts_the_live_resident_store() {
    let (mut fs, mut rng) = setup();
    let remaining = |fs: &mut Fs<_>, rng: &mut SeqRng| {
        let mut state = FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs,
            rng,
            state: &mut state,
            now_ms: 10,
        };
        let mut out = [0; 2048];
        let n = crate::process_cbor(&mut ctx, &[crate::consts::CTAP_GET_INFO], &mut out);
        assert_eq!(out[0], 0);
        let mut decoder = Decoder::new(&out[1..n]);
        let count = decoder.map().unwrap().unwrap();
        for _ in 0..count {
            if decoder.u8().unwrap() == 0x14 {
                return decoder.u16().unwrap();
            }
            decoder.skip().unwrap();
        }
        panic!("getInfo omitted remainingDiscoverableCredentials");
    };
    assert_eq!(remaining(&mut fs, &mut rng), 256);
    register(&mut fs, &mut rng, "example.com", &[1], "alice");
    assert_eq!(remaining(&mut fs, &mut rng), 255);
}

#[test]
fn update_user_information_preserves_the_complete_stored_user() {
    let (mut fs, mut rng) = setup();
    register(&mut fs, &mut rng, "other.example", &[3], "carol");
    let mut neighbor = [0; CRED_REC_MAX];
    let neighbor_len = fs.read(EF_CRED, &mut neighbor).unwrap();
    let (id, ..) = register(&mut fs, &mut rng, "example.com", &[1, 1], "alice");
    let mut out = [0; 512];
    run(
        &mut fs,
        &mut armed(PERM_CM),
        &cm_request(
            0x07,
            Some(&subpara_update(&id, &[1, 1], "alice2", "Alice Two")),
            &TOKEN,
        ),
        &mut out,
    )
    .unwrap();
    let seed = crate::seed::load_keydev(&dev(), &mut fs).unwrap();
    let mut record = [0; CRED_REC_MAX];
    let slot = cred_slots(&mut fs)[1];
    let n = fs.read(EF_CRED + slot, &mut record).unwrap();
    let mut scratch = [0; CRED_REC_MAX];
    let loaded = credential_load(
        seed.expose(),
        cred_record_box(&record[..n]),
        &sha256(b"example.com"),
        &mut scratch,
    )
    .unwrap();
    assert_eq!(loaded.user_id, &[1, 1]);
    assert_eq!(loaded.user_name, "alice2");
    assert_eq!(loaded.user_display_name, "Alice Two");
    let mut retained = [0; CRED_REC_MAX];
    assert_eq!(fs.read(EF_CRED, &mut retained), Some(neighbor_len));
    assert_eq!(&retained[..neighbor_len], &neighbor[..neighbor_len]);
}

#[test]
fn enumeration_derives_the_public_key_when_the_cache_length_disagrees() {
    let (mut fs, mut rng) = setup();
    let (_, x, y) = register(&mut fs, &mut rng, "example.com", &[1], "alice");
    let slot = cred_slots(&mut fs)[0];
    let mut record = [0; CRED_REC_MAX];
    let n = fs.read(EF_CRED + slot, &mut record).unwrap();
    assert_eq!(record[RECORD_PREFIX], 65);
    record[RECORD_PREFIX] = 64;
    record.copy_within(RECORD_PREFIX + 65..n, RECORD_PREFIX + 64);
    fs.put(EF_CRED + slot, &record[..n - 1]).unwrap();
    let mut out = [0; 512];
    let n = run(
        &mut fs,
        &mut armed(PERM_CM),
        &cm_request(
            0x04,
            Some(&subpara_rpidhash(&sha256(b"example.com"))),
            &TOKEN,
        ),
        &mut out,
    )
    .unwrap();
    let (user, derived_x, derived_y, count) = parse_cred(&out[..n], true);
    assert_eq!(user, &[1]);
    assert_eq!((derived_x, derived_y), (x, y));
    assert_eq!(count, Some(1));
}

#[test]
fn settling_a_ghost_in_slot_one_removes_its_nickname_and_preserves_its_neighbor() {
    let (mut fs, mut rng) = setup();
    register(&mut fs, &mut rng, "example.com", &[1], "alice");
    register(&mut fs, &mut rng, "other.example", &[2], "bob");
    let seed = crate::seed::load_keydev(&dev(), &mut fs).unwrap();
    let mut neighbor = [0; crate::credential::NICK_BOX_MAX];
    let n = crate::credential::seal_nick(
        seed.expose(),
        &sha256(b"example.com"),
        "neighbor",
        &mut neighbor,
    )
    .unwrap();
    fs.put(crate::consts::EF_RPNICK, &neighbor[..n]).unwrap();
    let mut ghost = [0; crate::credential::NICK_BOX_MAX];
    let m = crate::credential::seal_nick(
        seed.expose(),
        &sha256(b"other.example"),
        "ghost",
        &mut ghost,
    )
    .unwrap();
    fs.put(crate::consts::EF_RPNICK + 1, &ghost[..m]).unwrap();
    let slot = cred_slots(&mut fs)[1];
    fs.delete(EF_CRED + slot).unwrap();
    settle_rp_records(&mut fs).unwrap();
    assert_eq!(rp_counts(&mut fs), [1]);
    assert!(!fs.has_data(EF_RP + 1));
    assert!(!fs.has_data(crate::consts::EF_RPNICK + 1));
    let mut retained = [0; crate::credential::NICK_BOX_MAX];
    assert_eq!(fs.read(crate::consts::EF_RPNICK, &mut retained), Some(n));
    assert_eq!(&retained[..n], &neighbor[..n]);
}

#[test]
fn settling_an_overcount_in_slot_one_repairs_its_own_rp() {
    let (mut fs, mut rng) = setup();
    register(&mut fs, &mut rng, "example.com", &[1], "alice");
    register(&mut fs, &mut rng, "other.example", &[2], "bob");
    register(&mut fs, &mut rng, "other.example", &[3], "carol");
    assert_eq!(rp_counts(&mut fs), [1, 2]);
    let mut neighbor = [0; RP_REC_MAX];
    let n = fs.read(EF_RP, &mut neighbor).unwrap();
    let slot = cred_slots(&mut fs)[2];
    fs.delete(EF_CRED + slot).unwrap();
    settle_rp_records(&mut fs).unwrap();
    assert_eq!(rp_counts(&mut fs), [1, 1]);
    let mut retained = [0; RP_REC_MAX];
    assert_eq!(fs.read(EF_RP, &mut retained), Some(n));
    assert_eq!(&retained[..n], &neighbor[..n]);
}
