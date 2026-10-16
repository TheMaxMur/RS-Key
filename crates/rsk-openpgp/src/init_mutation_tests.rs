// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn boot_retains_a_reset_code_record_with_a_zero_length_marker() {
    let mut fs = fresh();
    let d = dev();
    scan_files(&d, &mut fs, &mut CountRng(0)).unwrap();
    let mut wrapper = rsk_secret::Secret::<[u8; DEK_FILE_SIZE]>::zeroed();
    assert_eq!(
        fs.read_key(EF_DEK_PW3, wrapper.expose_mut()),
        Some(DEK_FILE_SIZE)
    );
    fs.put_key(EF_DEK_RC, Sealed::wrap(wrapper.expose()))
        .unwrap();
    let mut record = rsk_secret::Secret::<[u8; 34]>::zeroed();
    record.expose_mut()[1] = PIN_FORMAT_V1;
    record.expose_mut()[2..].copy_from_slice(d.pin_derive_verifier(PW3_DEFAULT).expose());
    fs.put(EF_RC, record.expose()).unwrap();
    let generation = fs.write_gen();

    scan_files(&d, &mut fs, &mut CountRng(200)).unwrap();

    let mut retained = rsk_secret::Secret::<[u8; 34]>::zeroed();
    assert_eq!(fs.read(EF_RC, retained.expose_mut()), Some(34));
    assert_eq!(retained.expose(), record.expose());
    let mut retained_wrapper = rsk_secret::Secret::<[u8; DEK_FILE_SIZE]>::zeroed();
    assert_eq!(
        fs.read_key(EF_DEK_RC, retained_wrapper.expose_mut()),
        Some(DEK_FILE_SIZE)
    );
    assert_eq!(retained_wrapper.expose(), wrapper.expose());
    assert_eq!(fs.write_gen(), generation);
}
