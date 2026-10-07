// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::state::PERM_MC;
use minicbor::Decoder;
use minicbor::encode::Write;

fn exclude_request(base: &[u8], id: &[u8], token: Option<&[u8; 32]>) -> Vec<u8> {
    let mut d = Decoder::new(base);
    let count = d.map().unwrap().unwrap();
    let mut e = Encoder::new(Cursor::new([0; 1024]));
    e.map(count + 1 + 2 * u64::from(token.is_some())).unwrap();
    for _ in 0..count {
        let key = d.u8().unwrap();
        if key == 6 {
            e.u8(5).unwrap().array(1).unwrap().map(2).unwrap();
            e.str("id").unwrap().bytes(id).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
        }
        e.u8(key).unwrap();
        let start = d.position();
        d.skip().unwrap();
        e.writer_mut()
            .write_all(&base[start..d.position()])
            .unwrap();
    }
    if let Some(token) = token {
        e.u8(8).unwrap().bytes(&pin_auth(token, &CDH)).unwrap();
        e.u8(9).unwrap().u8(2).unwrap();
    }
    let n = e.writer().position();
    e.into_writer().into_inner()[..n].to_vec()
}

#[test]
fn exclude_visibility_depends_independently_on_credprotect_and_uv() {
    for resident in [false, true] {
        for (level, uv, excluded) in [
            (CRED_PROT_UV_OPTIONAL, false, true),
            (CRED_PROT_UV_REQUIRED, false, false),
            (CRED_PROT_UV_REQUIRED, true, true),
            (CRED_PROT_UV_OPTIONAL, true, true),
        ] {
            let mut a = Authr::fresh();
            let initial = a.send(CTAP_MAKE_CREDENTIAL, &mc_credprotect(level, resident));
            assert_ok(&initial);
            let ad = field_at(&initial.body, 2).unwrap().bytes().unwrap();
            let len = usize::from(u16::from_be_bytes([ad[53], ad[54]]));
            let id = ad[55..55 + len].to_vec();
            let token = uv.then(|| a.arm_token(PERM_MC));
            let request = exclude_request(&mc_credprotect(level, resident), &id, token.as_ref());
            let generation = a.fs.write_gen();
            let answer = a.send(CTAP_MAKE_CREDENTIAL, &request);
            if excluded {
                assert_eq!(
                    answer.status,
                    CtapError::CredentialExcluded.as_u8(),
                    "resident={resident}, level={level}, uv={uv}"
                );
                assert!(answer.body.is_empty());
                assert_eq!(a.fs.write_gen(), generation);
            } else {
                assert_ok(&answer);
                let new = field_at(&answer.body, 2).unwrap().bytes().unwrap();
                let len = usize::from(u16::from_be_bytes([new[53], new[54]]));
                assert_ne!(&new[55..55 + len], id);
            }
        }
    }
}
