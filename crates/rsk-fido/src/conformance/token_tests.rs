// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::consts::{
    ALG_ES256, CTAP_GET_ASSERTION, CTAP_MAKE_CREDENTIAL, FLAG_UP, FLAG_UV, PUBLIC_KEY_TYPE,
};
use crate::state::{PERM_GA, PERM_LBW, PERM_MC, PinUvAuthToken};
use minicbor::Encoder;
use minicbor::encode::write::Cursor;
use rsk_crypto::{pinproto, sha256};
use rsk_secret::Secret;

const RP: &str = "token.example";
const CDH: [u8; 32] = [0xCD; 32];

#[derive(Clone, Copy, Debug)]
enum Ceremony {
    Create,
    Assert,
}

impl Ceremony {
    fn command(self) -> u8 {
        match self {
            Self::Create => CTAP_MAKE_CREDENTIAL,
            Self::Assert => CTAP_GET_ASSERTION,
        }
    }

    fn permission(self) -> u8 {
        match self {
            Self::Create => PERM_MC,
            Self::Assert => PERM_GA,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Case {
    Valid,
    BadMac,
    MissingPermission,
    WrongRp,
    Unverified,
    Inactive,
}

fn request(ceremony: Ceremony, auth: Option<(PinProto, &[u8])>) -> Vec<u8> {
    let mut e = Encoder::new(Cursor::new([0u8; 512]));
    let create = matches!(ceremony, Ceremony::Create);
    e.map(if create { 5 } else { 2 } + 2 * u64::from(auth.is_some()))
        .unwrap();
    if create {
        e.u8(1).unwrap().bytes(&CDH).unwrap();
        e.u8(2).unwrap().map(1).unwrap();
        e.str("id").unwrap().str(RP).unwrap();
        e.u8(3).unwrap().map(1).unwrap();
        e.str("id").unwrap().bytes(&[7]).unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str(PUBLIC_KEY_TYPE).unwrap();
        e.u8(7).unwrap().map(1).unwrap();
        e.str("rk").unwrap().bool(true).unwrap();
    } else {
        e.u8(1).unwrap().str(RP).unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
    }
    if let Some((proto, param)) = auth {
        e.u8(if create { 8 } else { 6 })
            .unwrap()
            .bytes(param)
            .unwrap();
        e.u8(if create { 9 } else { 7 })
            .unwrap()
            .u8(match proto {
                PinProto::One => 1,
                PinProto::Two => 2,
            })
            .unwrap();
    }
    let n = e.writer().position();
    e.into_writer().into_inner()[..n].to_vec()
}

#[derive(Debug, PartialEq, Eq)]
struct TokenSnapshot {
    in_use: bool,
    permissions: u8,
    rp_id_hash: [u8; 32],
    has_rp_id: bool,
    user_present: bool,
    user_verified: bool,
    uv_method: crate::uvm::Method,
    issued_at_ms: u64,
    last_used_ms: u64,
}

fn token_snapshot(p: &PinUvAuthToken) -> TokenSnapshot {
    TokenSnapshot {
        in_use: p.in_use,
        permissions: p.permissions,
        rp_id_hash: p.rp_id_hash,
        has_rp_id: p.has_rp_id,
        user_present: p.user_present,
        user_verified: p.user_verified,
        uv_method: p.uv_method,
        issued_at_ms: p.issued_at_ms,
        last_used_ms: p.last_used_ms,
    }
}

fn stored_records(fs: &mut Fs<RamStorage>) -> Vec<(u16, Vec<u8>)> {
    let mut keys = Vec::new();
    assert!(fs.for_each_key(&mut |fid| keys.push(fid)));
    keys.sort_unstable();
    keys.into_iter()
        .map(|fid| {
            let mut bytes = vec![0; rsk_fs::MAX_VALUE_BYTES];
            let n = fs.try_read(fid, &mut bytes).unwrap().unwrap();
            assert!(n <= bytes.len());
            bytes.truncate(n);
            (fid, bytes)
        })
        .collect()
}

#[derive(Default)]
struct CountPresence(usize);

impl UserPresence for CountPresence {
    fn request(&mut self, _: Confirm<'_>) -> Presence {
        self.0 += 1;
        Presence::Confirmed
    }
}

fn send(a: &mut Authr, ceremony: Ceremony, params: &[u8], presence: &mut CountPresence) -> Resp {
    let mut data = vec![ceremony.command()];
    data.extend_from_slice(params);
    a.clock += 1000;
    let mut out = [0xA5; 2048];
    let n = process_cbor(
        &mut Ctx {
            dev: dev(),
            fs: &mut a.fs,
            rng: &mut a.rng,
            state: &mut a.state,
            now_ms: a.clock,
            presence,
        },
        &data,
        &mut out,
    );
    assert!((1..=out.len()).contains(&n));
    if out[0] != CTAP2_OK {
        assert_eq!(n, 1);
        assert!(out[1..].iter().all(|&b| b == 0xA5));
    }
    Resp {
        status: out[0],
        body: out[1..n].to_vec(),
    }
}

fn token_conditions(ceremony: Ceremony) {
    for proto in [PinProto::One, PinProto::Two] {
        for (case, bound) in [
            (Case::Valid, false),
            (Case::Valid, true),
            (Case::BadMac, false),
            (Case::BadMac, true),
            (Case::MissingPermission, false),
            (Case::MissingPermission, true),
            (Case::WrongRp, true),
            (Case::Unverified, false),
            (Case::Unverified, true),
            (Case::Inactive, false),
            (Case::Inactive, true),
        ] {
            let mut a = Authr::fresh();
            if matches!(ceremony, Ceremony::Assert) {
                assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &request(Ceremony::Create, None)));
            }
            let permissions = PERM_MC | PERM_GA | PERM_LBW;
            let token = Secret::new(a.arm_token(permissions));
            let mut param = [0u8; 48];
            let n = pinproto::authenticate(proto, token.expose(), &CDH, &mut param).unwrap();
            // Each refusal changes one condition while its peers still authorize.
            a.state.paut.has_rp_id = bound;
            a.state.paut.rp_id_hash = sha256(if bound {
                RP.as_bytes()
            } else {
                b"other.example"
            });
            match case {
                Case::Valid => {}
                Case::BadMac => param[0] ^= 1,
                Case::MissingPermission => a.state.paut.permissions &= !ceremony.permission(),
                Case::WrongRp => a.state.paut.rp_id_hash = sha256(b"other.example"),
                Case::Unverified => a.state.paut.user_verified = false,
                Case::Inactive => a.state.paut.in_use = false,
            }
            let before = token_snapshot(&a.state.paut);
            let medium = stored_records(&mut a.fs);
            let write_gen = a.fs.write_gen();
            let mut presence = CountPresence::default();
            let r = send(
                &mut a,
                ceremony,
                &request(ceremony, Some((proto, &param[..n]))),
                &mut presence,
            );
            if !matches!(case, Case::Valid) {
                assert_eq!(
                    r.status,
                    CtapError::PinAuthInvalid.as_u8(),
                    "{ceremony:?}, {proto:?}, {case:?}, bound={bound}"
                );
                assert_eq!(presence.0, 0, "authorization must precede user presence");
                assert_eq!(
                    token_snapshot(&a.state.paut),
                    before,
                    "refusal must not refresh or bind the token"
                );
                assert_eq!(&a.state.paut.token, token.expose());
                assert_eq!(a.fs.write_gen(), write_gen);
                assert_eq!(stored_records(&mut a.fs), medium);
                assert!(!a.state.gna.active);
                // Repair only the rejected input/state; the same token can retry.
                match case {
                    Case::BadMac => param[0] ^= 1,
                    Case::MissingPermission => a.state.paut.permissions |= ceremony.permission(),
                    Case::WrongRp => a.state.paut.rp_id_hash = sha256(RP.as_bytes()),
                    Case::Unverified => a.state.paut.user_verified = true,
                    Case::Inactive => a.state.paut.in_use = true,
                    Case::Valid => unreachable!(),
                }
            } else {
                assert_ok(&r);
            }
            let r = if r.status == CTAP2_OK {
                r
            } else {
                send(
                    &mut a,
                    ceremony,
                    &request(ceremony, Some((proto, &param[..n]))),
                    &mut presence,
                )
            };
            assert_ok(&r);
            let mut ad = field_at(&r.body, 2).unwrap();
            assert_eq!(
                ad.bytes().unwrap()[32] & (FLAG_UP | FLAG_UV),
                FLAG_UP | FLAG_UV
            );
            assert_eq!(presence.0, 1);
            assert!(a.state.paut.has_rp_id);
            assert_eq!(a.state.paut.rp_id_hash, sha256(RP.as_bytes()));
            assert_eq!(a.state.paut.last_used_ms, a.clock);
            assert_eq!(a.state.paut.issued_at_ms, before.issued_at_ms);
            assert_eq!(a.state.paut.permissions, PERM_LBW);
            assert!(!a.state.user_verified());
            assert!(!a.state.user_present());
        }
    }
}

#[test]
fn makecredential_token_conditions_are_independent() {
    token_conditions(Ceremony::Create);
}

#[test]
fn getassertion_token_conditions_are_independent() {
    token_conditions(Ceremony::Assert);
}
