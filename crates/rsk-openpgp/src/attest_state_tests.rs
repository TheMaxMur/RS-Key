// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn a_complete_device_minted_attestation_root_is_recognized_without_writes() {
    for missing in [EF_PK_ATT.get(), EF_PB_ATT, EF_ATT_CERT] {
        let mut fs = provisioned_fs(RamStorage::new());
        let mut private = Secret::<[u8; rsk_fs::MAX_VALUE_BYTES]>::zeroed();
        let private_len = fs.read_key(EF_PK_ATT, private.expose_mut()).unwrap();
        let mut public = [0; MAX_EC_PUBDO];
        let public_len = fs.read(EF_PB_ATT, &mut public).unwrap();
        let mut certificate = [0; MAX_CERT];
        let certificate_len = fs.read(EF_ATT_CERT, &mut certificate).unwrap();
        let generation = fs.write_gen();

        assert_eq!(provisioned(&mut fs), Ok(true));
        assert_eq!(fs.write_gen(), generation);
        let mut retained = Secret::<[u8; rsk_fs::MAX_VALUE_BYTES]>::zeroed();
        assert_eq!(
            fs.read_key(EF_PK_ATT, retained.expose_mut()),
            Some(private_len)
        );
        assert_eq!(retained.expose(), private.expose());
        let mut retained_public = [0; MAX_EC_PUBDO];
        assert_eq!(fs.read(EF_PB_ATT, &mut retained_public), Some(public_len));
        assert_eq!(retained_public, public);
        let mut retained_certificate = [0; MAX_CERT];
        assert_eq!(
            fs.read(EF_ATT_CERT, &mut retained_certificate),
            Some(certificate_len)
        );
        assert_eq!(retained_certificate, certificate);

        fs.force_delete(missing).unwrap();
        let generation = fs.write_gen();
        assert_eq!(provisioned(&mut fs), Ok(false));
        assert_eq!(fs.write_gen(), generation);
    }
}
