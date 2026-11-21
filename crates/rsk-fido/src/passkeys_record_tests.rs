// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn a_header_only_legacy_rp_preserves_its_empty_domain_and_count() {
    let (mut fs, _) = provisioned();
    let hash = sha256(b"");
    let mut record = std::vec![1];
    record.extend_from_slice(&hash);
    fs.put(EF_RP, &record).unwrap();
    let generation = fs.write_gen();
    let mut seen = std::vec::Vec::new();
    assert_eq!(
        for_each_rp(&dev(), &mut fs, |rp| {
            seen.push((
                rp.rp_id.to_string(),
                rp.rp_id_hash,
                rp.count,
                rp.nickname.map(str::to_string),
            ));
        }),
        1
    );
    assert_eq!(seen, [("".to_string(), hash, 1, None)]);
    assert_eq!(fs.write_gen(), generation);
}

#[test]
fn a_nickname_reader_keeps_the_sealed_prefix_when_the_record_has_a_suffix() {
    let (mut fs, seed) = provisioned();
    add(&mut fs, &seed, 1, "example.com", b"owner", "", "", 0);
    let hash = sha256(b"example.com");
    let nickname = "n".repeat(RP_NICK_MAX_LEN);
    assert!(set_rp_nickname(&dev(), &mut fs, &hash, &nickname));
    assert_eq!(
        nick_of(&mut fs, "example.com").as_deref(),
        Some(nickname.as_str())
    );
    let mut buffer = [0; RP_REC_MAX];
    let len = fs.read(EF_RPNICK, &mut buffer).unwrap();
    let mut record = buffer[..len].to_vec();
    record.push(0x7F);
    fs.put(EF_RPNICK, &record).unwrap();
    let generation = fs.write_gen();
    assert_eq!(
        nick_of(&mut fs, "example.com").as_deref(),
        Some(nickname.as_str())
    );
    assert_eq!(fs.write_gen(), generation);
}

#[test]
fn deleting_a_header_only_credential_retires_its_blob_rp_nickname_and_store_tag() {
    let (mut fs, seed) = provisioned();
    add(&mut fs, &seed, 1, "example.com", b"owner", "", "", 0);
    let hash = sha256(b"example.com");
    assert!(set_rp_nickname(&dev(), &mut fs, &hash, "owner"));
    let mut record = [0; CRED_REC_MAX];
    let len = fs.read(EF_CRED, &mut record).unwrap();
    assert!(len > RECORD_PREFIX);
    let id: [u8; crate::credential::CRED_RESIDENT_LEN] =
        record[32..RECORD_PREFIX].try_into().unwrap();
    let mut state = crate::FidoState::new();
    let mut rng = SeqRng(9);
    let mut presence = crate::AlwaysConfirm;
    {
        let mut ctx = crate::Ctx {
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            presence: &mut presence,
            now_ms: 0,
        };
        assert!(crate::largeblobext::write(
            &mut ctx, &seed, &id, 0, b"blob", 4
        ));
    }
    fs.put(EF_CRED, &record[..RECORD_PREFIX]).unwrap();
    let before = crate::credential::cred_store_state(&mut fs).unwrap();
    assert!(delete_cred(&mut fs, &mut rng, EF_CRED));
    assert!(!fs.has_data(EF_CRED));
    assert!(!fs.has_data(crate::consts::EF_CRED_BLOB));
    assert_eq!(crate::credential::rp_count(&mut fs, &hash), Ok(0));
    assert!(!fs.has_data(EF_RPNICK));
    assert_ne!(
        crate::credential::cred_store_state(&mut fs).unwrap(),
        before
    );
}
