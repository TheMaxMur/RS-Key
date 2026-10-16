// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn every_defined_internal_file_has_an_internal_catalog_source() {
    for fid in [
        EF_PK_SIG.get(),
        EF_PK_DEC.get(),
        EF_PK_AUT.get(),
        EF_PK_ATT.get(),
        EF_DEK_PW1.get(),
        EF_DEK_RC.get(),
        EF_DEK_PW3.get(),
        EF_DEK_STAGE_PW1.get(),
        EF_DEK_STAGE_RC.get(),
        EF_DEK_STAGE_PW3.get(),
        EF_AES_KEY.get(),
        EF_RESET_CODE,
        EF_FP_ATT,
        EF_FP_CA4,
        EF_TS_ATT,
        EF_PW1,
        EF_RC,
        EF_PW3,
        EF_ALGO_PRIV1,
        EF_ALGO_PRIV2,
        EF_ALGO_PRIV3,
        EF_PW_PRIV,
        EF_PW_RETRIES,
        EF_PB_SIG,
        EF_PB_DEC,
        EF_PB_AUT,
        EF_PB_ATT,
        EF_KEY_ORIGIN,
        EF_DEK,
        EF_DEK_PWPIV,
        EF_CH_1,
        EF_CH_2,
        EF_CH_3,
    ] {
        assert!(matches!(source(fid), DoSource::Internal), "FID {fid:#06x}");
    }
    assert!(matches!(source(0xFFFF), DoSource::None));
    assert!(matches!(source(EF_CH_NAME), DoSource::Flash));
}

#[test]
fn the_cardholder_certificate_has_its_own_catalog_function() {
    assert!(matches!(source(EF_CH_CERT), DoSource::Func(FuncDo::ChCert)));
}
