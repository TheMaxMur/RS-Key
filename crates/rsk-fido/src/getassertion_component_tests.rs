// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::credential::{CredExt, CredInput, credential_create, credential_store, derive_resident};

#[test]
fn the_assertion_component_requires_both_blob_key_opt_ins() {
    for stored in [false, true] {
        for requested in [None, Some(false), Some(true)] {
            let (mut fs, mut rng) = setup();
            let seed = crate::seed::load_keydev(&dev(), &mut fs).unwrap();
            let rp = sha256(b"example.com");
            let input = CredInput {
                rp_id: "example.com",
                user_id: b"user",
                user_name: "bob",
                user_display_name: "Bob",
                use_sign_count: false,
                rk: true,
                created_ms: 1,
                alg: ALG_ES256,
                curve: i64::from(CURVE_P256),
                ext: CredExt {
                    large_blob_key: stored,
                    ..CredExt::default()
                },
            };
            let mut id = [0; crate::credential::CRED_BOX_MAX];
            let n =
                credential_create(seed.expose(), &dev(), &input, &rp, &[1; 12], &mut id).unwrap();
            let id = &id[..n];
            let resident = derive_resident(id, &dev());
            let mut raw = fido_load_key(seed.expose(), &resident).unwrap();
            let key = CredKey::from_raw(i64::from(CURVE_P256), raw.expose()).unwrap();
            raw.wipe();
            let mut public = [0; 65];
            assert_eq!(key.public_point(&mut public), Some(65));
            credential_store(
                seed.expose(),
                &dev(),
                &mut fs,
                &mut rng,
                id,
                &rp,
                input.rp_id,
                input.user_id,
                &public,
            )
            .unwrap();
            let data = ga_request(Some(&resident));
            let mut request = parse(&data).unwrap();
            request.ext_large_blob_key = requested;
            let mut state = crate::FidoState::new();
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 10,
            };
            let mut out = [0; 1024];
            let n = get_assertion_inner(
                &mut ctx,
                &request,
                &rp,
                seed.expose(),
                UvOutcome::NONE,
                &mut out,
            )
            .unwrap();
            let x: &[u8; 32] = public[1..33].try_into().unwrap();
            let y: &[u8; 32] = public[33..].try_into().unwrap();
            verify_assertion(&out[..n], x, y);
            let mut decoder = Decoder::new(&out[..n]);
            let fields = decoder.map().unwrap().unwrap();
            let mut returned = None;
            for _ in 0..fields {
                if decoder.u8().unwrap() == 7 {
                    returned = Some(decoder.bytes().unwrap());
                } else {
                    decoder.skip().unwrap();
                }
            }
            let expected = (stored && requested == Some(true))
                .then(|| derive_large_blob_key(seed.expose(), &resident));
            assert_eq!(returned, expected.as_ref().map(|bytes| &bytes[..]));
            assert_eq!(decoder.position(), n);
        }
    }
}
