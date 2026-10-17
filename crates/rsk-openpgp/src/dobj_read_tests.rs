// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::test_tlv::{child, children};
use rsk_fs::storage::faults::ProbeStuck;
use rsk_sdk::Sw;
use rsk_sdk::error::Error;

fn check_single_read(tag: u16, fid: u16, value_len: usize, body_len: usize) {
    let (backend, medium) = ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.put(EF_PW_PRIV, crate::files::PW_STATUS_DEFAULT).unwrap();
    let value = vec![0x42; value_len];
    fs.put(fid, &value).unwrap();
    fs.scan();
    let generation = fs.write_gen();
    medium.stick_after(fid, 1);
    let aid = full_aid(&[1, 2, 3, 4], OPGP_MFR_UNMANAGED);
    let mut out = [0xa5; 1024];
    let request = if tag == EF_PW_STATUS {
        tag
    } else {
        EF_APP_DATA
    };
    let (len, sw) =
        crate::getdata::get_data(request, false, false, &mut fs, &aid, &mut None, &mut out);
    assert_eq!(sw, Sw::OK);
    let body = if tag == EF_PW_STATUS {
        out[..len].to_vec()
    } else {
        let app = children(&child(&children(&out[..len]), EF_APP_DATA));
        let discrete = children(&child(&app, EF_DISCRETE_DO));
        child(&discrete, tag)
    };
    assert_eq!(body.len(), body_len);
    assert_eq!(&body[..value.len()], value);
    assert!(body[value.len()..].iter().all(|byte| *byte == 0));
    assert_eq!(fs.write_gen(), generation);
    assert_eq!(fs.try_read(fid, &mut [0; 32]), Err(Error::MemoryFatal));
    assert_eq!(fs.try_read(fid, &mut out), Ok(Some(value.len())));
    assert_eq!(&out[..value.len()], value);
}

#[test]
fn password_status_reads_the_value_once_without_a_length_probe() {
    check_single_read(EF_PW_STATUS, EF_PW_PRIV, 7, 7);
}

#[test]
fn fixed_lists_read_each_present_value_once_without_a_length_probe() {
    for (tag, fid, value_len, body_len) in [
        (EF_FP, EF_FP_SIG, FP_LEN, usize::from(FP_LIST_LEN)),
        (EF_CA_FP, EF_FP_CA1, FP_LEN, usize::from(CA_FP_LIST_LEN)),
        (EF_TS_ALL, EF_TS_SIG, TS_LEN, usize::from(TS_LIST_LEN)),
    ] {
        check_single_read(tag, fid, value_len, body_len);
    }
}
