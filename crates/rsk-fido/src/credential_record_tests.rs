// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn a_header_only_record_keeps_its_count_in_an_undercounted_faulted_store() {
    let hash = sha256(b"example.com");
    let store = |fs: &mut Fs<_>, user: u8| {
        let mut request = input();
        let id = [user];
        request.user_id = &id;
        let mut boxed = [0; 512];
        let len = credential_create(
            &SEED,
            &dev(),
            &request,
            &hash,
            &[user; IV.len()],
            &mut boxed,
        )
        .unwrap();
        credential_store(
            &SEED,
            &dev(),
            fs,
            &mut SeqRng(7),
            &boxed[..len],
            &hash,
            "example.com",
            &id,
            &[],
        )
    };
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    store(&mut fs, 1).unwrap();
    store(&mut fs, 2).unwrap();
    assert_eq!(rp_count(&mut fs, &hash), Ok(2));
    let header = medium.value(EF_CRED).unwrap()[..RECORD_PREFIX].to_vec();
    fs.put(EF_CRED, &header).unwrap();
    let neighbor = medium.value(EF_CRED + 1).unwrap();
    let mut rp = medium.value(EF_RP).unwrap();
    rp[0] = 1;
    fs.put(EF_RP, &rp).unwrap();
    assert_eq!(rp_count(&mut fs, &hash), Ok(1));
    medium.stick(Some(EF_CRED + 1));
    assert_eq!(store(&mut fs, 3), Ok(()));
    medium.stick(None);
    assert_eq!(medium.value(EF_CRED), Some(header));
    assert_eq!(medium.value(EF_CRED + 1), Some(neighbor));
    assert_eq!(rp_count(&mut fs, &hash), Ok(2));
    let stored = medium.value(EF_CRED + 2).unwrap();
    let mut scratch = [0; CRED_REC_MAX];
    let loaded = credential_load(&SEED, cred_record_box(&stored), &hash, &mut scratch).unwrap();
    assert_eq!(loaded.user_id, &[3]);
    assert_eq!(loaded.rp_id, "example.com");
}
