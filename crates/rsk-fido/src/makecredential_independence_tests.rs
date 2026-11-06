// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn the_registration_component_keeps_blob_outputs_bound_to_resident_requests() {
    for rk in [false, true] {
        for key in [None, Some(false), Some(true)] {
            for support in [McInput::Absent, McInput::Preferred, McInput::Required] {
                let data = build_request(rk);
                let mut request = parse(&data).unwrap();
                request.ext_large_blob_key = key;
                request.ext_large_blob = support;
                request.att_fmt_pref = AttFmtPref::NoneOnly;
                let mut fs = Fs::new(RamStorage::new());
                crate::tests::uv_optional(&mut fs);
                let before = fs.write_gen();
                let mut rng = SeqRng(1);
                let mut state = crate::FidoState::new();
                let mut presence = crate::AlwaysConfirm;
                let mut ctx = Ctx {
                    presence: &mut presence,
                    dev: dev(),
                    fs: &mut fs,
                    rng: &mut rng,
                    state: &mut state,
                    now_ms: 1000,
                };
                let seed = Secret::new([7; 32]);
                let mut out = [0xa5; 1024];
                let result = make_credential_inner(
                    &mut ctx,
                    &request,
                    &sha256(request.rp_id.as_bytes()),
                    seed.expose(),
                    UvOutcome::NONE,
                    #[cfg(feature = "preview-sign")]
                    None,
                    &mut out,
                );
                if !rk && support == McInput::Required {
                    assert_eq!(result, Err(CtapError::LargeBlobStorageFull));
                    assert_eq!(fs.write_gen(), before);
                    assert_eq!(out, [0xa5; 1024]);
                    continue;
                }
                let len = result.unwrap();
                let mut decoder = Decoder::new(&out[..len]);
                let count = decoder.map().unwrap().unwrap();
                let mut returned_key = false;
                let mut returned_support = false;
                for _ in 0..count {
                    match decoder.u8().unwrap() {
                        5 => {
                            assert_eq!(decoder.bytes().unwrap().len(), 32);
                            returned_key = true;
                        }
                        6 => {
                            assert_eq!(decoder.map().unwrap(), Some(1));
                            assert_eq!(decoder.str().unwrap(), "largeBlob");
                            assert_eq!(decoder.map().unwrap(), Some(1));
                            assert_eq!(decoder.str().unwrap(), "supported");
                            assert!(decoder.bool().unwrap());
                            returned_support = true;
                        }
                        _ => decoder.skip().unwrap(),
                    }
                }
                assert_eq!(returned_key, rk && key == Some(true));
                assert_eq!(returned_support, rk && support != McInput::Absent);
                assert_eq!(decoder.position(), len);
                assert_eq!(fs.write_gen() > before, rk);
            }
        }
    }
}
