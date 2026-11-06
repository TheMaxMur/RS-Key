// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::consts::{ALG_ES256, FLAG_UP, FLAG_UV, PUBLIC_KEY_TYPE};
use rsk_secret::Secret;

const RP: &str = "token.example";
const OTHER_RP: &str = "other.example";
const CDH: [u8; 32] = [0xCD; 32];

#[derive(Clone, Copy, Debug)]
enum Case {
    Unbound,
    Bound,
    WrongRp,
    MissingPermission,
    BadMac,
    Spent,
}

#[derive(Default)]
struct Touches(usize);

impl crate::UserPresence for Touches {
    fn request(&mut self, _: crate::Confirm<'_>) -> crate::Presence {
        self.0 += 1;
        crate::Presence::Confirmed
    }
}

fn fixture() -> (Fs<RamStorage>, SeqRng, FidoState, Platform) {
    let (mut fs, mut rng) = setup();
    crate::tests::uv_optional(&mut fs);
    let mut state = FidoState::new();
    let mut request = Encoder::new(Cursor::new([0u8; 512]));
    request.map(5).unwrap();
    request.u8(1).unwrap().bytes(&CDH).unwrap();
    request.u8(2).unwrap().map(1).unwrap();
    request.str("id").unwrap().str(RP).unwrap();
    request.u8(3).unwrap().map(1).unwrap();
    request.str("id").unwrap().bytes(&[7]).unwrap();
    request.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
    request.str("alg").unwrap().i64(ALG_ES256).unwrap();
    request.str("type").unwrap().str(PUBLIC_KEY_TYPE).unwrap();
    request.u8(7).unwrap().map(1).unwrap();
    request.str("rk").unwrap().bool(true).unwrap();
    let length = request.writer().position();
    let request = request.into_writer().into_inner();
    crate::makecredential::make_credential(
        &mut Ctx {
            presence: &mut crate::AlwaysConfirm,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        },
        &request[..length],
        &mut [0u8; 2048],
    )
    .unwrap();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.set_pin_req(PIN),
        &mut [0u8; 256],
    )
    .unwrap();
    (fs, rng, state, plat)
}

fn request(param: &[u8]) -> std::vec::Vec<u8> {
    let mut e = Encoder::new(Cursor::new([0u8; 256]));
    e.map(4).unwrap();
    e.u8(1).unwrap().str(RP).unwrap();
    e.u8(2).unwrap().bytes(&CDH).unwrap();
    e.u8(6).unwrap().bytes(param).unwrap();
    e.u8(7).unwrap().u8(2).unwrap();
    let length = e.writer().position();
    e.into_writer().into_inner()[..length].to_vec()
}

#[test]
fn issued_tokens_exercise_each_getassertion_condition() {
    for case in [
        Case::Unbound,
        Case::Bound,
        Case::WrongRp,
        Case::MissingPermission,
        Case::BadMac,
        Case::Spent,
    ] {
        let (mut fs, mut rng, mut state, plat) = fixture();
        let permissions = if matches!(case, Case::MissingPermission) {
            PERM_MC
        } else {
            PERM_GA
        };
        let binding = match case {
            Case::Bound | Case::BadMac | Case::Spent => Some(RP),
            Case::WrongRp => Some(OTHER_RP),
            Case::Unbound | Case::MissingPermission => None,
        };
        let pin_hash_enc = plat.enc(&sha256(PIN)[..16]);
        let mut fields = vec![
            (1, V::U(plat.wire)),
            (2, V::U(CP_GET_PIN_UV_TOKEN_USING_PIN)),
            (3, V::Cose(&plat.x, &plat.y)),
            (6, V::B(&pin_hash_enc)),
            (9, V::U(u64::from(permissions))),
        ];
        let mut rp = Encoder::new(Cursor::new([0u8; 64]));
        if let Some(binding) = binding {
            rp.str(binding).unwrap();
        }
        let length = rp.writer().position();
        let rp = rp.into_writer().into_inner();
        if binding.is_some() {
            fields.push((10, V::Raw(&rp[..length])));
        }
        let mut response = [0u8; 256];
        let n = run(
            &mut fs,
            &mut rng,
            &mut state,
            &build(&fields),
            &mut response,
        )
        .unwrap();
        let token = Secret::new(plat.decrypt_token(&response[..n]));
        assert!(state.user_verified());
        assert_eq!(state.paut.permissions, permissions);
        assert_eq!(state.paut.has_rp_id, binding.is_some());
        if let Some(binding) = binding {
            assert_eq!(state.paut.rp_id_hash, sha256(binding.as_bytes()));
        }
        let mut mac = [0u8; 32];
        let n = pinproto::authenticate(PinProto::Two, token.expose(), &CDH, &mut mac).unwrap();
        if matches!(case, Case::BadMac) {
            mac[0] ^= 1;
        }
        let request = request(&mac[..n]);
        let mut touches = Touches::default();
        let mut ctx = Ctx {
            presence: &mut touches,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 1,
        };
        if matches!(case, Case::Spent) {
            crate::getassertion::get_assertion(&mut ctx, &request, &mut [0u8; 2048]).unwrap();
            assert!(!ctx.state.user_verified());
            assert_eq!(ctx.state.paut.permissions, 0);
        }
        let generation = ctx.fs.write_gen();
        let last_used = ctx.state.paut.last_used_ms;
        let rp_hash = ctx.state.paut.rp_id_hash;
        let bound = ctx.state.paut.has_rp_id;
        let mut out = [0xA5; 2048];
        let result = crate::getassertion::get_assertion(&mut ctx, &request, &mut out);
        if matches!(case, Case::Unbound | Case::Bound) {
            let n = result.unwrap();
            let mut d = Decoder::new(&out[..n]);
            d.map().unwrap();
            assert_eq!(d.u8().unwrap(), 1);
            d.skip().unwrap();
            assert_eq!(d.u8().unwrap(), 2);
            let auth_data = d.bytes().unwrap();
            assert_eq!(&auth_data[..32], &sha256(RP.as_bytes()));
            assert_eq!(auth_data[32] & (FLAG_UP | FLAG_UV), FLAG_UP | FLAG_UV);
            assert!(u32::from_be_bytes(auth_data[33..37].try_into().unwrap()) > 0);
            assert!(ctx.fs.write_gen() > generation);
            assert!(ctx.state.paut.has_rp_id);
            assert_eq!(ctx.state.paut.rp_id_hash, sha256(RP.as_bytes()));
            assert!(!ctx.state.user_verified());
            assert_eq!(ctx.state.paut.permissions, 0);
        } else {
            assert_eq!(result, Err(CtapError::PinAuthInvalid), "{case:?}");
            assert_eq!(out, [0xA5; 2048], "{case:?}: refusal wrote response bytes");
            assert_eq!(
                ctx.fs.write_gen(),
                generation,
                "{case:?}: refusal wrote flash"
            );
            assert_eq!(ctx.state.paut.last_used_ms, last_used);
            assert_eq!(ctx.state.paut.rp_id_hash, rp_hash);
            assert_eq!(ctx.state.paut.has_rp_id, bound);
            assert_eq!(ctx.state.user_verified(), !matches!(case, Case::Spent));
            assert_eq!(
                ctx.state.paut.permissions,
                if matches!(case, Case::Spent) {
                    0
                } else {
                    permissions
                }
            );
        }
        assert_eq!(&ctx.state.paut.token, token.expose());
        assert!(!ctx.state.gna.active);
        assert_eq!(
            touches.0,
            usize::from(matches!(case, Case::Unbound | Case::Bound | Case::Spent))
        );
    }
}
