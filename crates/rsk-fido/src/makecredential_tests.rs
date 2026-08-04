// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::consts::EF_ALWAYS_UV;
use crate::seed::ensure_seed;
use minicbor::Decoder;
use p256::Sec1Point;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use rsk_crypto::Device;
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;

struct SeqRng(u64);
impl Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

// Every makeCredential ships packed basic attestation with the device x5c.
const ATT_FMT: &str = "packed";

fn build_request(rk: bool) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(if rk { 5 } else { 4 }).unwrap();
        e.u8(1).unwrap().bytes(&[0xCDu8; 32]).unwrap(); // clientDataHash
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str("example.com")
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
        e.str("name").unwrap().str("alice").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        if rk {
            e.u8(7)
                .unwrap()
                .map(1)
                .unwrap()
                .str("rk")
                .unwrap()
                .bool(true)
                .unwrap();
        }
        e.writer().position()
    };
    buf[..n].to_vec()
}

fn run(req: &[u8]) -> (std::vec::Vec<u8>, Fs<RamStorage>) {
    let mut fs = Fs::new(RamStorage::new());
    let dev = Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    };
    let mut rng = SeqRng(1);
    ensure_seed(&dev, &mut fs, &mut rng).unwrap();
    let mut out = [0u8; 1024];
    let len = {
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev,
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 1000,
        };
        make_credential(&mut ctx, req, &mut out).unwrap()
    };
    (out[..len].to_vec(), fs)
}

fn run_err(req: &[u8]) -> CtapError {
    let mut fs = Fs::new(RamStorage::new());
    let dev = Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    };
    let mut rng = SeqRng(1);
    ensure_seed(&dev, &mut fs, &mut rng).unwrap();
    let mut out = [0u8; 1024];
    let mut state = crate::FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev,
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 1000,
    };
    make_credential(&mut ctx, req, &mut out).unwrap_err()
}

// A presence that never confirms — a button left untouched.
struct Decline;
impl crate::UserPresence for Decline {
    fn request(&mut self, _confirm: crate::Confirm<'_>) -> crate::Presence {
        crate::Presence::Timeout
    }
}

// `run_err` with a declining button, to prove an operation is touch-gated.
fn run_err_no_touch(req: &[u8]) -> CtapError {
    let mut fs = Fs::new(RamStorage::new());
    let dev = Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    };
    let mut rng = SeqRng(1);
    ensure_seed(&dev, &mut fs, &mut rng).unwrap();
    let mut out = [0u8; 1024];
    let mut state = crate::FidoState::new();
    let mut presence = Decline;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev,
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 1000,
    };
    make_credential(&mut ctx, req, &mut out).unwrap_err()
}

// Build a makeCredential request, writing keys 1–3 then invoking `tail` for the
// pubKeyCredParams (4) and any excludeList (5). `nkeys` is the total map size.
fn mc_build(nkeys: u64, tail: impl Fn(&mut Encoder<Cursor<&mut [u8]>>)) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(nkeys).unwrap();
        e.u8(1).unwrap().bytes(&[0xCDu8; 32]).unwrap();
        e.u8(2).unwrap().map(1).unwrap();
        e.str("id").unwrap().str("example.com").unwrap();
        e.u8(3).unwrap().map(1).unwrap();
        e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
        tail(&mut e);
        e.writer().position()
    };
    buf[..n].to_vec()
}

// A valid pubKeyCredParams entry ({4: [{alg: ES256, type: public-key}]}).
fn good_params(e: &mut Encoder<Cursor<&mut [u8]>>) {
    e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
    e.str("alg").unwrap().i64(ALG_ES256).unwrap();
    e.str("type").unwrap().str("public-key").unwrap();
}

#[test]
fn makecred_requires_touch() {
    // A bare no-PIN makeCredential must obtain user presence — `up` is
    // implicitly true. A confirming button succeeds; a declining one fails
    // with OperationDenied (guards the no-PIN SSH `ed25519-sk` enrollment path).
    let req = mc_build(4, good_params);
    let _ = run(&req); // AlwaysConfirm → succeeds
    assert_eq!(run_err_no_touch(&req), CtapError::OperationDenied);
}

#[test]
fn malformed_param_error_codes() {
    // pubKeyCredParams entry missing "type" → INVALID_CBOR.
    let req = mc_build(4, |e| {
        e.u8(4).unwrap().array(1).unwrap().map(1).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
    });
    assert_eq!(run_err(&req), CtapError::InvalidCbor);

    // pubKeyCredParams "alg" as a text string → CBOR_UNEXPECTED_TYPE.
    let req = mc_build(4, |e| {
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().str("7").unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
    });
    assert_eq!(run_err(&req), CtapError::CborUnexpectedType);

    // excludeList entry missing "type" → MISSING_PARAMETER.
    let req = mc_build(5, |e| {
        good_params(e);
        e.u8(5).unwrap().array(1).unwrap().map(1).unwrap();
        e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
    });
    assert_eq!(run_err(&req), CtapError::MissingParameter);

    // excludeList entry missing "id" → MISSING_PARAMETER.
    let req = mc_build(5, |e| {
        good_params(e);
        e.u8(5).unwrap().array(1).unwrap().map(1).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
    });
    assert_eq!(run_err(&req), CtapError::MissingParameter);

    // excludeList "type" as a byte string → CBOR_UNEXPECTED_TYPE.
    let req = mc_build(5, |e| {
        good_params(e);
        e.u8(5).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("type").unwrap().bytes(b"public-key").unwrap();
        e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
    });
    assert_eq!(run_err(&req), CtapError::CborUnexpectedType);

    // pubKeyCredParams entry missing "alg" → INVALID_CBOR (Req-4 F-4).
    let req = mc_build(4, |e| {
        e.u8(4).unwrap().array(1).unwrap().map(1).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
    });
    assert_eq!(run_err(&req), CtapError::InvalidCbor);
}

#[test]
fn rp_name_must_be_text() {
    // rp.name as a non-text value → CBOR_UNEXPECTED_TYPE (Req-2 F-2). Built
    // inline because mc_build emits rp = {id} only.
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(4).unwrap();
        e.u8(1).unwrap().bytes(&[0xCDu8; 32]).unwrap();
        e.u8(2).unwrap().map(2).unwrap();
        e.str("id").unwrap().str("example.com").unwrap();
        e.str("name").unwrap().u8(7).unwrap(); // name as an integer
        e.u8(3).unwrap().map(1).unwrap();
        e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
        good_params(&mut e);
        e.writer().position()
    };
    assert_eq!(run_err(&buf[..n]), CtapError::CborUnexpectedType);
}

#[test]
fn makecred_up_option() {
    // up=true is accepted (the default); up=false is rejected with
    // INVALID_OPTION (conformance MakeCredential Req-6 P-3 / F-1).
    let up_true = mc_build(5, |e| {
        good_params(e);
        e.u8(7).unwrap().map(1).unwrap();
        e.str("up").unwrap().bool(true).unwrap();
    });
    let (resp, _) = run(&up_true);
    assert!(!resp.is_empty());

    let up_false = mc_build(5, |e| {
        good_params(e);
        e.u8(7).unwrap().map(1).unwrap();
        e.str("up").unwrap().bool(false).unwrap();
    });
    assert_eq!(run_err(&up_false), CtapError::InvalidOption);
}

#[test]
fn makecred_cancel_maps_keepalive_cancel() {
    // A CTAPHID_CANCEL during the user-presence wait makes makeCredential
    // answer CTAP2_ERR_KEEPALIVE_CANCEL (conformance HID-1 P-10).
    struct Cancel;
    impl crate::UserPresence for Cancel {
        fn request(&mut self, _confirm: crate::Confirm<'_>) -> crate::Presence {
            crate::Presence::Cancelled
        }
    }
    let req = mc_build(4, good_params);
    let mut fs = Fs::new(RamStorage::new());
    let dev = Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    };
    let mut rng = SeqRng(1);
    ensure_seed(&dev, &mut fs, &mut rng).unwrap();
    let mut out = [0u8; 1024];
    let mut state = crate::FidoState::new();
    let mut presence = Cancel;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev,
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 1000,
    };
    assert_eq!(
        make_credential(&mut ctx, &req, &mut out),
        Err(CtapError::KeepAliveCancel)
    );
}

// Parse the response and pull out authData. Under `fido-conformance` the
// attStmt is the packed self-attestation `{alg, sig}`, whose signature is
// checked against the credential public key embedded in authData; by default
// the attStmt is empty (fmt "none"), so only that shape is asserted (guarding
// the issue #26 regression — no fragile EdDSA self-attestation).
fn verify_response(resp: &[u8], client_data_hash: &[u8; 32]) -> std::vec::Vec<u8> {
    let mut d = Decoder::new(resp);
    // 3 base fields ({1,2,3}); a largeBlobKey credential adds field 0x05.
    assert!(d.map().unwrap().unwrap() >= 3);
    assert_eq!(d.u8().unwrap(), 1);
    assert_eq!(d.str().unwrap(), ATT_FMT);
    assert_eq!(d.u8().unwrap(), 2);
    let auth_data = d.bytes().unwrap().to_vec();
    assert_eq!(d.u8().unwrap(), 3);

    // authData layout: rpIdHash(32) flags(1) ctr(4) aaguid(16) credLen(2) credId COSEkey
    assert_eq!(&auth_data[..32], &sha256(b"example.com")[..]);
    // AT + UP always set; UV may also be set when a pinUvAuthParam was verified.
    assert_eq!(auth_data[32] & (FLAG_AT | FLAG_UP), FLAG_AT | FLAG_UP);

    // Basic attestation: {alg, sig, x5c}, ES256 by the device key.
    assert_eq!(d.map().unwrap().unwrap(), 3);
    assert_eq!(d.str().unwrap(), "alg");
    assert_eq!(d.i64().unwrap(), ALG_ES256);
    assert_eq!(d.str().unwrap(), "sig");
    let sig = d.bytes().unwrap().to_vec();
    assert_eq!(d.str().unwrap(), "x5c");
    assert_eq!(d.array().unwrap().unwrap(), 1);
    let leaf = d.bytes().unwrap().to_vec();

    let cred_len = u16::from_be_bytes([auth_data[37 + 16], auth_data[38 + 16]]) as usize;
    let cose_off = 39 + 16 + cred_len;

    // Parse the COSE EC2 key (1:2, 3:-7, -1:1, -2:x, -3:y).
    let mut cd = Decoder::new(&auth_data[cose_off..]);
    assert_eq!(cd.map().unwrap().unwrap(), 5);
    assert_eq!(cd.u8().unwrap(), 1);
    assert_eq!(cd.u8().unwrap(), 2);
    assert_eq!(cd.u8().unwrap(), 3);
    assert_eq!(cd.i64().unwrap(), ALG_ES256);
    assert_eq!(cd.i8().unwrap(), -1);
    assert_eq!(cd.u8().unwrap(), 1);
    assert_eq!(cd.i8().unwrap(), -2);
    assert_eq!(cd.bytes().unwrap().len(), 32, "credential x coordinate");
    assert_eq!(cd.i8().unwrap(), -3);
    assert_eq!(cd.bytes().unwrap().len(), 32, "credential y coordinate");

    // That COSE key is the *credential* key; basic attestation is signed by the
    // device key, so it verifies under the x5c leaf instead.
    let (ax, ay) = crate::conformance::att_leaf_pubkey(&leaf);
    let pt = Sec1Point::from_bytes(&crate::ec::sec1_uncompressed(ax, ay)).unwrap();
    let vk = VerifyingKey::from_sec1_point(&pt).unwrap();
    let mut signed = auth_data.clone();
    signed.extend_from_slice(client_data_hash);
    let s = Signature::from_der(&sig).unwrap();
    vk.verify(&signed, &s)
        .expect("attestation signature verifies");

    auth_data
}

#[test]
fn non_resident_make_credential_self_attestation() {
    let req = build_request(false);
    let (resp, _fs) = run(&req);
    let auth_data = verify_response(&resp, &[0xCD; 32]);
    // Non-resident: credId in authData is the full (prefix-free) box — no cleartext
    // f1d00202 marker, so it can't be fingerprinted as an RS-Key credential.
    let cred_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    assert!(cred_len > 42);
    assert_ne!(&auth_data[55..59], b"\xf1\xd0\x02\x02");
}

#[test]
fn resident_make_credential_stores_and_returns_resident_id() {
    let req = build_request(true);
    let (resp, mut fs) = run(&req);
    let auth_data = verify_response(&resp, &[0xCD; 32]);
    // Resident: credId in authData is the 42-byte (prefix-free v4) resident id —
    // no cleartext f1d00203 marker, so passkeys look random like a YubiKey's.
    let cred_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    assert_eq!(cred_len, 42);
    assert_ne!(&auth_data[59..63], b"\xf1\xd0\x02\x03");
    // The credential was persisted.
    assert!(fs.has_data(crate::consts::EF_CRED));
    assert!(fs.has_data(crate::consts::EF_RP));
    // A fresh credential registers with signCount 0 (per-credential counters); the
    // global EF_COUNTER stays untouched and the credential's own counter is seeded
    // to 1 so its first assertion reports 1.
    assert_eq!(u32::from_be_bytes(auth_data[33..37].try_into().unwrap()), 0);
    assert_eq!(crate::seed::get_sign_counter(&mut fs), 0);
    assert_eq!(crate::seed::cred_sign_counter(&mut fs, 0), Some(1));
}

#[test]
fn unsupported_alg_rejected() {
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(4).unwrap();
        e.u8(1).unwrap().bytes(&[0xCDu8; 32]).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str("example.com")
            .unwrap();
        e.u8(3)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .bytes(&[1, 2])
            .unwrap();
        // Only RS256 (-257) offered → unsupported.
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(-257).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.writer().position()
    };
    let mut fs = Fs::new(RamStorage::new());
    let dev = Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    };
    let mut rng = SeqRng(1);
    ensure_seed(&dev, &mut fs, &mut rng).unwrap();
    let mut out = [0u8; 512];
    let mut state = crate::FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev,
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
    };
    assert_eq!(
        make_credential(&mut ctx, &buf[..n], &mut out),
        Err(CtapError::UnsupportedAlgorithm)
    );
}

#[test]
fn enterprise_attestation_uses_org_chain_when_provisioned() {
    use p256::Sec1Point;
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

    let mut fs = Fs::new(RamStorage::new());
    let dev = Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    };
    let mut rng = SeqRng(1);
    ensure_seed(&dev, &mut fs, &mut rng).unwrap();

    // Org provisioning: sealed key, packed 2-cert chain, EA enabled.
    let org_scalar = [0x21u8; 32];
    crate::seed::store_att_key(&dev, &mut fs, &org_scalar).unwrap();
    let c1 = [0x30u8, 0x03, 1, 2, 3];
    let c2 = [0x30u8, 0x02, 7, 7];
    let mut chain = std::vec::Vec::new();
    chain.extend_from_slice(&c1);
    chain.extend_from_slice(&c2);
    let mut packed = [0u8; 64];
    let plen = crate::cert::att_chain_pack(&chain, &mut packed).unwrap();
    fs.put(EF_ATT_CHAIN, &packed[..plen]).unwrap();
    fs.put(EF_EA_ENABLED, &[1]).unwrap();

    // makeCredential with enterpriseAttestation (0x0A) = 2.
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(5).unwrap();
        e.u8(1).unwrap().bytes(&[0xCDu8; 32]).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str("example.com")
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
        e.str("name").unwrap().str("alice").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(10).unwrap().u8(2).unwrap();
        e.writer().position()
    };
    let mut out = [0u8; 1024];
    let mut state = crate::FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev,
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
    };
    let rlen = make_credential(&mut ctx, &buf[..n], &mut out).unwrap();

    // {1: "packed", 2: authData, 3: {alg, sig, x5c: [c1, c2]}, 4: ep true}.
    let mut d = Decoder::new(&out[..rlen]);
    assert_eq!(d.map().unwrap().unwrap(), 4);
    assert_eq!(d.u8().unwrap(), 1);
    assert_eq!(d.str().unwrap(), "packed");
    assert_eq!(d.u8().unwrap(), 2);
    let auth_data = d.bytes().unwrap().to_vec();
    assert_eq!(d.u8().unwrap(), 3);
    assert_eq!(d.map().unwrap().unwrap(), 3);
    assert_eq!(d.str().unwrap(), "alg");
    assert_eq!(d.i64().unwrap(), ALG_ES256);
    assert_eq!(d.str().unwrap(), "sig");
    let sig = d.bytes().unwrap().to_vec();
    assert_eq!(d.str().unwrap(), "x5c");
    assert_eq!(d.array().unwrap().unwrap(), 2);
    assert_eq!(d.bytes().unwrap(), &c1);
    assert_eq!(d.bytes().unwrap(), &c2);
    assert_eq!(d.u8().unwrap(), 4);
    assert!(d.bool().unwrap());

    // The signature is the org key's, over authData ‖ clientDataHash.
    let (x, y) = P256Key::from_scalar(&org_scalar).unwrap().public_xy();
    let pt = Sec1Point::from_bytes(&crate::ec::sec1_uncompressed(x, y)).unwrap();
    let vk = VerifyingKey::from_sec1_point(&pt).unwrap();
    let mut msg = auth_data;
    msg.extend_from_slice(&[0xCD; 32]);
    vk.verify(&msg, &Signature::from_der(&sig).unwrap())
        .unwrap();
}

#[cfg(feature = "fips-profile")]
#[test]
fn fips_es256k_not_negotiable() {
    // The profile drops secp256k1 from negotiation; the approved set stays.
    assert_eq!(alg_to_curve(ALG_ES256K), None);
    assert!(alg_to_curve(ALG_ES256).is_some());
    assert!(alg_to_curve(ALG_EDDSA).is_some());
    assert!(alg_to_curve(ALG_MLDSA44).is_some());
}

#[test]
fn missing_mandatory_param_rejected() {
    // Map starting at key 2 (clientDataHash missing) → MissingParameter.
    let mut buf = [0u8; 64];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(1).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str("x")
            .unwrap();
        e.writer().position()
    };
    let mut fs = Fs::new(RamStorage::new());
    let dev = Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    };
    let mut rng = SeqRng(1);
    let mut out = [0u8; 64];
    let mut state = crate::FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev,
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
    };
    assert_eq!(
        make_credential(&mut ctx, &buf[..n], &mut out),
        Err(CtapError::MissingParameter)
    );
}

#[test]
fn out_of_order_optional_keys_rejected() {
    // Canonical CBOR requires ascending map keys. Key 6 after key 7 (both
    // optional) descends → INVALID_CBOR (the `key < expected` guard), never a
    // silent second pass over an already-seen field.
    let req = mc_build(6, |e| {
        good_params(e);
        e.u8(7).unwrap().map(1).unwrap();
        e.str("rk").unwrap().bool(true).unwrap();
        e.u8(6).unwrap().map(1).unwrap();
        e.str("credProtect").unwrap().u64(1).unwrap();
    });
    assert_eq!(run_err(&req), CtapError::InvalidCbor);
}

#[test]
fn unknown_top_level_key_ignored() {
    // An unrecognized top-level key (0x0B) is skipped, not an error — the map
    // still parses and the credential is created.
    let req = mc_build(5, |e| {
        good_params(e);
        e.u8(11).unwrap().u8(0).unwrap();
    });
    assert!(!run(&req).0.is_empty());
}

#[test]
fn unknown_option_key_ignored() {
    // An unrecognized option sub-key is skipped; the recognized `rk` still applies.
    let req = mc_build(5, |e| {
        good_params(e);
        e.u8(7).unwrap().map(2).unwrap();
        e.str("rk").unwrap().bool(true).unwrap();
        e.str("bogus").unwrap().bool(true).unwrap();
    });
    let (resp, mut fs) = run(&req);
    assert!(!resp.is_empty());
    assert!(fs.has_data(crate::consts::EF_CRED));
}

#[test]
fn third_party_payment_extension_accepted() {
    // thirdPartyPayment is parsed and sealed into the box (no authData echo); a
    // request carrying it registers successfully.
    let req = mc_build(6, |e| {
        good_params(e);
        e.u8(6).unwrap().map(1).unwrap();
        e.str("thirdPartyPayment").unwrap().bool(true).unwrap();
        e.u8(7).unwrap().map(1).unwrap();
        e.str("rk").unwrap().bool(true).unwrap();
    });
    assert!(!run(&req).0.is_empty());
}

fn dev() -> Device<'static> {
    Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    }
}

/// Configure fs + state as clientPIN leaves them after setPIN + getPinToken:
/// EF_PIN present (the seed stays plain — PIN ops never wrap it), a live
/// token with MC|GA permissions. Returns the token so the test can compute
/// a valid pinUvAuthParam.
fn arm_pin(fs: &mut Fs<RamStorage>, state: &mut crate::FidoState) -> [u8; 32] {
    let mut pin_file = [0u8; 35];
    pin_file[0] = 8; // retries
    pin_file[1] = 4; // length
    pin_file[2] = 1; // format
    fs.put(EF_PIN, &pin_file).unwrap();
    let token = [0x99u8; 32];
    state.paut.token = token;
    state.paut.permissions = PERM_MC | crate::state::PERM_GA;
    state.begin_using_token(false, 0);
    token
}

fn build_request_pin(param: &[u8], proto: u64) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(6).unwrap();
        e.u8(1).unwrap().bytes(&[0xCDu8; 32]).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str("example.com")
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
        e.str("name").unwrap().str("alice").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(8).unwrap().bytes(param).unwrap();
        e.u8(9).unwrap().u64(proto).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

// A resident makeCredential request carrying credBlob + credProtect.
fn mc_request_ext() -> std::vec::Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(6).unwrap();
        e.u8(1).unwrap().bytes(&[0xCDu8; 32]).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str("example.com")
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
        e.str("name").unwrap().str("alice").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(6).unwrap().map(2).unwrap();
        e.str("credBlob")
            .unwrap()
            .bytes(&[0xAA, 0xBB, 0xCC])
            .unwrap();
        e.str("credProtect").unwrap().u64(2).unwrap();
        e.u8(7)
            .unwrap()
            .map(1)
            .unwrap()
            .str("rk")
            .unwrap()
            .bool(true)
            .unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

// The CBOR bytes of the authData extension map (after the COSE public key).
fn auth_data_ext(ad: &[u8]) -> std::vec::Vec<u8> {
    let cred_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    let cose_off = 55 + cred_len;
    let mut d = Decoder::new(&ad[cose_off..]);
    let nk = d.map().unwrap().unwrap();
    for _ in 0..nk {
        d.skip().unwrap(); // key
        d.skip().unwrap(); // value
    }
    ad[cose_off + d.position()..].to_vec()
}

#[test]
fn make_credential_extensions_stored_and_emitted() {
    let req = mc_request_ext();
    let (resp, mut fs) = run(&req);
    let ad = verify_response(&resp, &[0xCD; 32]);
    assert_eq!(ad[32] & FLAG_ED, FLAG_ED, "ED flag set");

    // authData extension map: credBlob bool (sealed ok) + credProtect 2.
    let ext = auth_data_ext(&ad);
    let mut d = Decoder::new(&ext);
    assert_eq!(d.map().unwrap().unwrap(), 2);
    assert_eq!(d.str().unwrap(), "credBlob");
    assert!(d.bool().unwrap());
    assert_eq!(d.str().unwrap(), "credProtect");
    assert_eq!(d.u64().unwrap(), 2);

    // The stored box carries the extensions.
    let mut rec = [0u8; 1024];
    let n = fs.read(crate::consts::EF_CRED, &mut rec).unwrap();
    let seed = crate::seed::load_keydev(&dev(), &mut fs).unwrap();
    let mut scratch = [0u8; 1024];
    let c = crate::credential::credential_load(
        &seed,
        crate::credential::cred_record_box(&rec[..n]),
        &sha256(b"example.com"),
        &mut scratch,
    )
    .unwrap();
    assert_eq!(c.ext.cred_protect, 2);
    assert_eq!(c.ext.cred_blob, &[0xAA, 0xBB, 0xCC]);
}

// A resident makeCredential whose only extension is credProtect = `level`.
fn mc_request_credprotect(level: u64) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(6).unwrap();
        e.u8(1).unwrap().bytes(&[0xCDu8; 32]).unwrap();
        e.u8(2).unwrap().map(1).unwrap();
        e.str("id").unwrap().str("example.com").unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
        e.str("name").unwrap().str("alice").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(6).unwrap().map(1).unwrap();
        e.str("credProtect").unwrap().u64(level).unwrap();
        e.u8(7).unwrap().map(1).unwrap();
        e.str("rk").unwrap().bool(true).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

#[test]
fn credprotect_out_of_range_rejected() {
    // Only levels 1/2/3 are defined (§12.1). A level of 4 must be rejected
    // with INVALID_OPTION, not silently degraded to no-protection.
    assert_eq!(
        run_err(&mc_request_credprotect(4)),
        CtapError::InvalidOption
    );
    // A valid level still registers.
    assert!(!run(&mc_request_credprotect(3)).0.is_empty());
}

#[test]
fn hmac_secret_mc_empty_salt_rejected() {
    // hmac-secret-mc present (with the required hmac-secret flag) but carrying
    // no salt must be rejected up front (MissingParameter), matching the
    // getAssertion hmac-secret empty-salt guard.
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(6).unwrap();
        e.u8(1).unwrap().bytes(&[0xCDu8; 32]).unwrap();
        e.u8(2).unwrap().map(1).unwrap();
        e.str("id").unwrap().str("example.com").unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
        e.str("name").unwrap().str("alice").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(6).unwrap().map(2).unwrap();
        e.str("hmac-secret").unwrap().bool(true).unwrap();
        e.str("hmac-secret-mc").unwrap().map(0).unwrap(); // no salt fields
        e.u8(7).unwrap().map(1).unwrap();
        e.str("rk").unwrap().bool(true).unwrap();
        e.writer().position()
    };
    assert_eq!(run_err(&buf[..n]), CtapError::MissingParameter);
}

#[test]
fn min_pin_length_extension_for_listed_rp() {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    // EF_MINPINLEN = [minLen=6, force=0, sha256("example.com")].
    let mut mp = [0u8; 2 + 32];
    mp[0] = 6;
    mp[2..].copy_from_slice(&sha256(b"example.com"));
    fs.put(EF_MINPINLEN, &mp).unwrap();

    // makeCredential with the minPinLength extension flag.
    let mut buf = [0u8; 512];
    let req = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(5).unwrap();
        e.u8(1).unwrap().bytes(&[0xCDu8; 32]).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str("example.com")
            .unwrap();
        e.u8(3)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .bytes(&[1, 2, 3, 4])
            .unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(6)
            .unwrap()
            .map(1)
            .unwrap()
            .str("minPinLength")
            .unwrap()
            .bool(true)
            .unwrap();
        let n = e.writer().position();
        buf[..n].to_vec()
    };
    let mut out = [0u8; 1024];
    let len = {
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
        make_credential(&mut ctx, &req, &mut out).unwrap()
    };
    let ad = verify_response(&out[..len], &[0xCD; 32]);
    assert_eq!(ad[32] & FLAG_ED, FLAG_ED);
    let ext = auth_data_ext(&ad);
    let mut d = Decoder::new(&ext);
    assert_eq!(d.map().unwrap().unwrap(), 1);
    assert_eq!(d.str().unwrap(), "minPinLength");
    assert_eq!(d.u8().unwrap(), 6);
}

#[test]
fn large_blob_key_in_make_credential() {
    // A resident request opting into largeBlobKey returns the derived key (0x05).
    let mut buf = [0u8; 512];
    let req = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(6).unwrap();
        e.u8(1).unwrap().bytes(&[0xCDu8; 32]).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str("example.com")
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
        e.str("name").unwrap().str("alice").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(6)
            .unwrap()
            .map(1)
            .unwrap()
            .str("largeBlobKey")
            .unwrap()
            .bool(true)
            .unwrap();
        e.u8(7)
            .unwrap()
            .map(1)
            .unwrap()
            .str("rk")
            .unwrap()
            .bool(true)
            .unwrap();
        let n = e.writer().position();
        buf[..n].to_vec()
    };
    let (resp, mut fs) = run(&req);
    verify_response(&resp, &[0xCD; 32]);

    // Field 0x05 is the 32-byte largeBlobKey for the stored credential.
    let mut d = Decoder::new(&resp);
    let fields = d.map().unwrap().unwrap();
    let mut lbk = None;
    for _ in 0..fields {
        if d.u8().unwrap() == 5 {
            lbk = Some(d.bytes().unwrap().to_vec());
        } else {
            d.skip().unwrap();
        }
    }
    let mut rec = [0u8; 1024];
    let _n = fs.read(crate::consts::EF_CRED, &mut rec).unwrap();
    let seed = crate::seed::load_keydev(&dev(), &mut fs).unwrap();
    // v2 resident: largeBlobKey keys off the stable resident id (rec[32..74]),
    // not the box.
    let resident_id = &rec[32..crate::credential::RECORD_PREFIX];
    let expected = crate::credential::derive_large_blob_key(&seed, resident_id);
    assert_eq!(lbk.as_deref(), Some(&expected[..]));
}

#[test]
fn make_credential_with_pin_sets_uv_flag() {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let mut state = crate::FidoState::new();
    let token = arm_pin(&mut fs, &mut state);
    // Platform MACs the clientDataHash with the token (protocol two).
    let cdh = [0xCDu8; 32];
    let mut param = [0u8; 32];
    let plen = rsk_crypto::pinproto::authenticate(PinProto::Two, &token, &cdh, &mut param).unwrap();
    let req = build_request_pin(&param[..plen], 2);
    let mut out = [0u8; 1024];
    let len = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 1000,
        };
        make_credential(&mut ctx, &req, &mut out).unwrap()
    };
    let auth_data = verify_response(&out[..len], &cdh);
    assert_eq!(auth_data[32] & FLAG_UV, FLAG_UV, "UV flag must be set");
}

// An authenticatorConfig/toggleAlwaysUv request MAC'd under `token` (protocol two,
// no subCommandParams): `{1: subCommand, 3: proto, 4: pinUvAuthParam}`.
fn config_toggle_always_uv_req(token: &[u8; 32]) -> std::vec::Vec<u8> {
    let sub = crate::consts::CONFIG_TOGGLE_ALWAYS_UV as u8;
    let mut vp = std::vec![0xffu8; 32];
    vp.push(crate::consts::CTAP_CONFIG);
    vp.push(sub);
    let mut mac = [0u8; 32];
    let mlen = rsk_crypto::pinproto::authenticate(PinProto::Two, token, &vp, &mut mac).unwrap();
    let mut req = std::vec::Vec::new();
    req.push(0xA3); // map(3)
    req.extend_from_slice(&[0x01, sub]); // 1: subCommand
    req.extend_from_slice(&[0x03, 0x02]); // 3: pinUvAuthProtocol = 2
    req.push(0x04); // 4: pinUvAuthParam
    req.push(0x58);
    req.push(mlen as u8);
    req.extend_from_slice(&mac[..mlen]);
    req
}

// GHSA-wqjm-653g-hgw3: a UP-gated makeCredential must run
// clearPinUvAuthTokenPermissionsExceptLbw (CTAP 2.1 §6.5.5.7). A token armed with
// mc|acfg|lbw keeps only lbw after the touch, so the acfg permission can't ride the
// registration into a no-touch authenticatorConfig.
#[test]
fn make_credential_spends_token_permissions_except_lbw() {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let mut state = crate::FidoState::new();
    let token = arm_pin(&mut fs, &mut state);
    state.paut.permissions = PERM_MC | crate::state::PERM_ACFG | crate::state::PERM_LBW;

    let cdh = [0xCDu8; 32];
    let mut param = [0u8; 32];
    let plen = rsk_crypto::pinproto::authenticate(PinProto::Two, &token, &cdh, &mut param).unwrap();
    let req = build_request_pin(&param[..plen], 2);
    let mut out = [0u8; 1024];
    {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 1000,
        };
        make_credential(&mut ctx, &req, &mut out).unwrap();
    }
    assert_eq!(
        state.paut.permissions,
        crate::state::PERM_LBW,
        "only largeBlobWrite survives a UP-gated makeCredential"
    );
    assert!(
        !state.user_verified(),
        "the §6.5.5.7 triad also clears the token's user-verified flag"
    );

    // The behavioural consequence: authenticatorConfig over the same token is now
    // rejected — the touch spent the acfg permission (the PoC's step 4).
    let cfg = config_toggle_always_uv_req(&token);
    let mut cfg_out = [0u8; 64];
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 1000,
    };
    assert_eq!(
        crate::config::authenticator_config(&mut ctx, &cfg, &mut cfg_out),
        Err(CtapError::PinAuthInvalid),
        "acfg must not ride the makeCredential touch (GHSA-wqjm-653g-hgw3)"
    );
}

// Register a non-resident credential and return its credential id (from authData:
// rpIdHash(32) flags(1) ctr(4) aaguid(16) credLen(2) credId …).
fn register_and_get_cred_id(
    fs: &mut Fs<RamStorage>,
    rng: &mut SeqRng,
    state: &mut crate::FidoState,
) -> std::vec::Vec<u8> {
    let mut out = [0u8; 1024];
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs,
        rng,
        state,
        now_ms: 1000,
    };
    let n = make_credential(&mut ctx, &build_request(false), &mut out).unwrap();
    let ad = verify_response(&out[..n], &[0xCD; 32]);
    let clen = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    ad[55..55 + clen].to_vec()
}

// §6.1.2: an excludeList hit must poll user presence BEFORE disclosing
// CTAP2_ERR_CREDENTIAL_EXCLUDED, so the device isn't a silent credential-existence
// oracle. A declining button therefore fails the touch (OperationDenied) instead of
// instantly confirming the credential exists.
#[test]
fn excluded_makecredential_requires_touch_before_disclosing() {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let mut state = crate::FidoState::new();
    let cred_id = register_and_get_cred_id(&mut fs, &mut rng, &mut state);
    let req = mc_build(5, |e| {
        good_params(e);
        e.u8(5).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&cred_id).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
    });
    let mut out = [0u8; 1024];
    let mut presence = Decline;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 1000,
    };
    assert_eq!(
        make_credential(&mut ctx, &req, &mut out),
        Err(CtapError::OperationDenied),
        "excluded makeCredential must poll presence before disclosing the match"
    );
}

// The confirmed path still returns CREDENTIAL_EXCLUDED, and the touch spends the
// pinUvAuthToken so a mc|acfg token can't ride an excluded registration into config.
#[test]
fn excluded_makecredential_confirms_then_spends_token() {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let mut state = crate::FidoState::new();
    let cred_id = register_and_get_cred_id(&mut fs, &mut rng, &mut state);
    let token = arm_pin(&mut fs, &mut state);
    state.paut.permissions = PERM_MC | crate::state::PERM_ACFG | crate::state::PERM_LBW;
    let cdh = [0xCDu8; 32];
    let mut param = [0u8; 32];
    let plen = rsk_crypto::pinproto::authenticate(PinProto::Two, &token, &cdh, &mut param).unwrap();
    let req = mc_build(7, |e| {
        good_params(e);
        e.u8(5).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&cred_id).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(8).unwrap().bytes(&param[..plen]).unwrap();
        e.u8(9).unwrap().u64(2).unwrap();
    });
    let mut out = [0u8; 1024];
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 1000,
    };
    assert_eq!(
        make_credential(&mut ctx, &req, &mut out),
        Err(CtapError::CredentialExcluded)
    );
    assert_eq!(
        state.paut.permissions,
        crate::state::PERM_LBW,
        "the excluded-registration touch spends the token too"
    );
}

#[test]
fn make_credential_requires_pin_for_a_discoverable_credential() {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let mut state = crate::FidoState::new();
    arm_pin(&mut fs, &mut state);
    // A PIN is set and `rk` is true, but the request carries no pinUvAuthParam →
    // PUAT_REQUIRED. makeCredUvNotRqd (§6.1.2 step 7) does NOT cover a
    // discoverable credential.
    let mut out = [0u8; 256];
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
    };
    assert_eq!(
        make_credential(&mut ctx, &build_request(true), &mut out),
        Err(CtapError::PuatRequired)
    );
}

#[test]
fn make_cred_uv_not_rqd_creates_non_discoverable_on_presence_alone() {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let mut state = crate::FidoState::new();
    arm_pin(&mut fs, &mut state);
    // §6.1.2 step 10 (issue #51): a PIN is set, the credential is
    // non-discoverable and no pinUvAuthParam is supplied → the credential is
    // created on user presence alone, with `uv` clear.
    let cdh = [0xCDu8; 32];
    let mut out = [0u8; 1024];
    let len = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        make_credential(&mut ctx, &build_request(false), &mut out).unwrap()
    };
    let auth_data = verify_response(&out[..len], &cdh);
    assert_eq!(auth_data[32] & FLAG_UV, 0, "UV flag must stay clear");
}

#[test]
fn always_uv_overrides_make_cred_uv_not_rqd() {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let mut state = crate::FidoState::new();
    arm_pin(&mut fs, &mut state);
    // §6.1.2 step 6: alwaysUv makes makeCredUvNotRqd false, so even the
    // non-discoverable request above is refused without a token.
    fs.put(EF_ALWAYS_UV, &[1]).unwrap();
    let mut out = [0u8; 256];
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
    };
    assert_eq!(
        make_credential(&mut ctx, &build_request(false), &mut out),
        Err(CtapError::PuatRequired)
    );
}

/// A built-in-UV presence backend (the trusted-display pad): reports `options.uv`
/// available, "types" a fixed PIN, and counts the separate presence gestures the
/// ceremony asks for on top of that.
struct UvPad {
    digits: &'static [u8],
    /// Overrides the entry, to exercise the Deny branch.
    outcome: Option<crate::PinEntry>,
    touches: usize,
}
impl UvPad {
    fn typing() -> Self {
        Self {
            digits: b"1234",
            outcome: None,
            touches: 0,
        }
    }
    fn ending(outcome: crate::PinEntry) -> Self {
        Self {
            digits: &[],
            outcome: Some(outcome),
            touches: 0,
        }
    }
}
impl crate::UserPresence for UvPad {
    fn request(&mut self, _c: crate::Confirm<'_>) -> crate::Presence {
        self.touches += 1;
        crate::Presence::Confirmed
    }
    fn uv_available(&self) -> bool {
        true
    }
    fn collect_pin(&mut self, _min: usize, out: &mut [u8]) -> crate::PinEntry {
        if let Some(o) = self.outcome {
            return o;
        }
        out[..self.digits.len()].copy_from_slice(self.digits);
        crate::PinEntry::Entered(self.digits.len())
    }
}

/// A makeCredential request carrying `options: {uv: true}` (plus `rk` when asked),
/// optionally with a pinUvAuthParam.
fn build_request_uv(rk: bool, param: Option<(&[u8], u64)>) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(if param.is_some() { 7 } else { 5 }).unwrap();
        e.u8(1).unwrap().bytes(&[0xCDu8; 32]).unwrap();
        e.u8(2).unwrap().map(1).unwrap();
        e.str("id").unwrap().str("example.com").unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
        e.str("name").unwrap().str("alice").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(7).unwrap().map(1 + u64::from(rk)).unwrap();
        if rk {
            e.str("rk").unwrap().bool(true).unwrap();
        }
        e.str("uv").unwrap().bool(true).unwrap();
        if let Some((p, proto)) = param {
            e.u8(8).unwrap().bytes(p).unwrap();
            e.u8(9).unwrap().u64(proto).unwrap();
        }
        e.writer().position()
    };
    buf[..n].to_vec()
}

#[test]
fn uv_option_with_pin_uv_auth_param_is_not_an_error() {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let mut state = crate::FidoState::new();
    let token = arm_pin(&mut fs, &mut state);
    // §6.1.2 step 5: pinUvAuthParam takes precedence and the "uv" option is treated
    // as false — the pair is NOT CTAP2_ERR_INVALID_OPTION. python-fido2 sends it.
    let cdh = [0xCDu8; 32];
    let mut param = [0u8; 32];
    let plen = rsk_crypto::pinproto::authenticate(PinProto::Two, &token, &cdh, &mut param).unwrap();
    let req = build_request_uv(false, Some((&param[..plen], 2)));
    let mut out = [0u8; 1024];
    let len = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 1000,
        };
        make_credential(&mut ctx, &req, &mut out).unwrap()
    };
    let auth_data = verify_response(&out[..len], &cdh);
    assert_eq!(auth_data[32] & FLAG_UV, FLAG_UV, "the token still sets UV");
}

#[test]
fn uv_option_without_builtin_uv_is_invalid_option() {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let mut state = crate::FidoState::new();
    arm_pin(&mut fs, &mut state);
    // §6.1.2 step 5: a screenless build has no built-in user verification method,
    // so a token-less uv:true IS CTAP2_ERR_INVALID_OPTION.
    let mut out = [0u8; 256];
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
    };
    assert_eq!(
        make_credential(&mut ctx, &build_request_uv(false, None), &mut out),
        Err(CtapError::InvalidOption)
    );
}

#[test]
fn uv_option_runs_builtin_uv_and_supplies_user_presence() {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    crate::clientpin::store_local_pin(&dev(), &mut fs, b"1234").unwrap();
    let mut state = crate::FidoState::new();
    // §6.1.2 step 11.2: with the pad configured, uv:true is honored — the PIN is
    // typed on the device and never crosses the host. Step 13: that ceremony IS the
    // evidence of user interaction, so no second touch is requested.
    let cdh = [0xCDu8; 32];
    let mut out = [0u8; 1024];
    let mut pad = UvPad::typing();
    let len = {
        let mut ctx = Ctx {
            presence: &mut pad,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        make_credential(&mut ctx, &build_request_uv(true, None), &mut out).unwrap()
    };
    let auth_data = verify_response(&out[..len], &cdh);
    assert_eq!(auth_data[32] & FLAG_UV, FLAG_UV, "built-in UV sets UV");
    assert_eq!(
        pad.touches, 0,
        "built-in UV must not ask for a second touch"
    );
}

#[test]
fn builtin_uv_decline_is_operation_denied() {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    crate::clientpin::store_local_pin(&dev(), &mut fs, b"1234").unwrap();
    let mut state = crate::FidoState::new();
    // The one deliberate divergence from §6.1.2 step 11.2's error ladder: a Deny on
    // the pad stays OPERATION_DENIED. PUAT_REQUIRED would send the platform off to
    // collect the same PIN over USB, undoing the refusal the user just made.
    let mut out = [0u8; 256];
    let mut pad = UvPad::ending(crate::PinEntry::Declined);
    let mut ctx = Ctx {
        presence: &mut pad,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
    };
    assert_eq!(
        make_credential(&mut ctx, &build_request_uv(false, None), &mut out),
        Err(CtapError::OperationDenied)
    );
}

#[test]
fn always_uv_upgrades_a_tokenless_request_to_builtin_uv() {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    crate::clientpin::store_local_pin(&dev(), &mut fs, b"1234").unwrap();
    fs.put(EF_ALWAYS_UV, &[1]).unwrap();
    let mut state = crate::FidoState::new();
    // §6.1.2 step 6.3: alwaysUv treats the "uv" option as true when the pad is
    // configured, so the request is verified rather than refused with 0x36.
    let cdh = [0xCDu8; 32];
    let mut out = [0u8; 1024];
    let mut pad = UvPad::typing();
    let len = {
        let mut ctx = Ctx {
            presence: &mut pad,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        make_credential(&mut ctx, &build_request(false), &mut out).unwrap()
    };
    let auth_data = verify_response(&out[..len], &cdh);
    assert_eq!(auth_data[32] & FLAG_UV, FLAG_UV);
}

#[test]
fn always_uv_requires_user_verification_without_pin() {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let mut state = crate::FidoState::new();
    // No PIN, but alwaysUv is on → makeCredential still demands UV (a verified
    // pinUvAuthToken) and rejects an up-only request. Without the EF_ALWAYS_UV
    // guard this same request succeeds, so the assert is mutation-proof.
    fs.put(EF_ALWAYS_UV, &[1]).unwrap();
    let mut out = [0u8; 256];
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
    };
    assert_eq!(
        make_credential(&mut ctx, &build_request(false), &mut out),
        Err(CtapError::PuatRequired)
    );
}

#[test]
fn make_credential_bad_pin_auth_rejected() {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let mut state = crate::FidoState::new();
    arm_pin(&mut fs, &mut state);
    // A wrong (all-zero) pinUvAuthParam fails the token check.
    let req = build_request_pin(&[0u8; 32], 2);
    let mut out = [0u8; 256];
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
    };
    assert_eq!(
        make_credential(&mut ctx, &req, &mut out),
        Err(CtapError::PinAuthInvalid)
    );
}

// ---- PQC algorithm selection ----

// makeCredential with a multi-entry pubKeyCredParams; returns the alg of the
// credential key selected (COSE label 3 in authData — present in both profiles,
// unlike the attStmt alg which the default "none" fmt omits).
fn selected_alg(algs: &[i64]) -> Result<i64, CtapError> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(4).unwrap();
        e.u8(1).unwrap().bytes(&[0xCDu8; 32]).unwrap();
        e.u8(2).unwrap().map(1).unwrap();
        e.str("id").unwrap().str("example.com").unwrap();
        e.u8(3).unwrap().map(1).unwrap();
        e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
        e.u8(4).unwrap().array(algs.len() as u64).unwrap();
        for &alg in algs {
            e.map(2).unwrap();
            e.str("alg").unwrap().i64(alg).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
        }
        e.writer().position()
    };

    let mut fs = Fs::new(RamStorage::new());
    let dev = Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    };
    let mut rng = SeqRng(1);
    ensure_seed(&dev, &mut fs, &mut rng).unwrap();
    let mut out = [0u8; 8192];
    let mut state = crate::FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev,
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 1000,
    };
    let len = make_credential(&mut ctx, &buf[..n], &mut out)?;

    // Pull authData (field 2), then read the COSE key alg (label 3) from it.
    let mut d = Decoder::new(&out[..len]);
    let fields = d.map().unwrap().unwrap();
    let mut ad = None;
    for _ in 0..fields {
        if d.u8().unwrap() == 2 {
            ad = Some(d.bytes().unwrap().to_vec());
        } else {
            d.skip().unwrap();
        }
    }
    let ad = ad.expect("authData present");
    let cred_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    let mut cd = Decoder::new(&ad[55 + cred_len..]);
    let entries = cd.map().unwrap().unwrap();
    for _ in 0..entries {
        if cd.i64().unwrap() == 3 {
            return Ok(cd.i64().unwrap());
        }
        cd.skip().unwrap();
    }
    panic!("COSE key alg (label 3) missing");
}

#[test]
fn first_supported_alg_wins() {
    use crate::consts::{ALG_MLDSA44, ALG_MLDSA65, ALG_MLDSA87};
    // §6.1.2 step 4: the chosen algorithm is the FIRST supported element of
    // pubKeyCredParams — the platform's order is its preference order, so an
    // ML-DSA entry listed after a classic one does NOT override it.
    assert_eq!(selected_alg(&[ALG_ES256, ALG_MLDSA44]), Ok(ALG_ES256));
    assert_eq!(selected_alg(&[ALG_MLDSA44, ALG_ES256]), Ok(ALG_MLDSA44));
    assert_eq!(selected_alg(&[ALG_ES256, ALG_MLDSA65]), Ok(ALG_ES256));
    // …including between the two ML-DSA sets.
    assert_eq!(selected_alg(&[ALG_MLDSA44, ALG_MLDSA65]), Ok(ALG_MLDSA44));
    assert_eq!(selected_alg(&[ALG_MLDSA65, ALG_MLDSA44]), Ok(ALG_MLDSA65));
    assert_eq!(selected_alg(&[ALG_ES256]), Ok(ALG_ES256));
    assert_eq!(
        selected_alg(&[crate::consts::ALG_ES384, ALG_ES256]),
        Ok(crate::consts::ALG_ES384)
    );
    // -50 (ML-DSA-87) is a recognized id without a backend: alone it is
    // unsupported; alongside a classic alg the classic one is selected.
    assert_eq!(
        selected_alg(&[ALG_MLDSA87]),
        Err(CtapError::UnsupportedAlgorithm)
    );
    assert_eq!(selected_alg(&[ALG_MLDSA87, ALG_ES256]), Ok(ALG_ES256));
}

// ---- Enterprise attestation ----

// makeCredential request carrying enterpriseAttestation (field 0x0A).
fn build_request_ea(ea: u64) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(5).unwrap();
        e.u8(1).unwrap().bytes(&[0xCDu8; 32]).unwrap();
        e.u8(2).unwrap().map(1).unwrap();
        e.str("id").unwrap().str("example.com").unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
        e.str("name").unwrap().str("alice").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(10).unwrap().u64(ea).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

// Run makeCredential with enterprise attestation enabled/disabled (the
// enable persists in flash — EF_EA_ENABLED — per CTAP 2.1).
fn run_ea(req: &[u8], enable: bool) -> Result<(std::vec::Vec<u8>, Fs<RamStorage>), CtapError> {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let mut out = [0u8; 1024];
    let mut state = crate::FidoState::new();
    if enable {
        fs.put(EF_EA_ENABLED, &[1]).unwrap();
    }
    let len = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 1000,
        };
        make_credential(&mut ctx, req, &mut out)?
    };
    Ok((out[..len].to_vec(), fs))
}

#[test]
fn enterprise_attestation_level2_full_attestation() {
    let req = build_request_ea(2);
    let (resp, mut fs) = run_ea(&req, true).unwrap();
    let seed = crate::seed::load_keydev(&dev(), &mut fs).unwrap();

    let mut d = Decoder::new(&resp);
    // { 1: "packed", 2: authData, 3: attStmt, 4: ep } — 4 fields, no largeBlobKey.
    assert_eq!(d.map().unwrap().unwrap(), 4);
    assert_eq!(d.u8().unwrap(), 1);
    assert_eq!(d.str().unwrap(), "packed");
    assert_eq!(d.u8().unwrap(), 2);
    let ad = d.bytes().unwrap().to_vec();
    assert_eq!(d.u8().unwrap(), 3);
    // attStmt = { alg: -7, sig, x5c: [cert] } — full attestation.
    assert_eq!(d.map().unwrap().unwrap(), 3);
    assert_eq!(d.str().unwrap(), "alg");
    assert_eq!(d.i64().unwrap(), ALG_ES256);
    assert_eq!(d.str().unwrap(), "sig");
    let sig = d.bytes().unwrap().to_vec();
    assert_eq!(d.str().unwrap(), "x5c");
    assert_eq!(d.array().unwrap().unwrap(), 1);
    let cert = d.bytes().unwrap().to_vec();
    assert!(!cert.is_empty(), "x5c carries the device EE cert");
    // 4: ep = true.
    assert_eq!(d.u8().unwrap(), 4);
    assert!(d.bool().unwrap());

    // The attestation signature verifies under the DEVICE key (the seed
    // scalar), not the credential key.
    let device_key = P256Key::from_scalar(&seed).unwrap();
    let (x, y) = device_key.public_xy();
    let pt = Sec1Point::from_bytes(&crate::ec::sec1_uncompressed(x, y)).unwrap();
    let vk = VerifyingKey::from_sec1_point(&pt).unwrap();
    let mut signed = ad.clone();
    signed.extend_from_slice(&[0xCD; 32]);
    let s = Signature::from_der(&sig).unwrap();
    vk.verify(&signed, &s)
        .expect("enterprise attestation verifies under the device key");
}

#[test]
fn enterprise_attestation_requires_enable() {
    // EA requested but not enabled via authenticatorConfig → INVALID_PARAMETER.
    assert_eq!(
        run_ea(&build_request_ea(2), false).map(|_| ()).unwrap_err(),
        CtapError::InvalidParameter
    );
}

#[test]
fn enterprise_attestation_bad_level_rejected() {
    // Enabled, but an out-of-range level (3) → INVALID_OPTION.
    assert_eq!(
        run_ea(&build_request_ea(3), true).map(|_| ()).unwrap_err(),
        CtapError::InvalidOption
    );
}

#[test]
fn enterprise_type1_non_listed_rp_is_basic_full_no_ep() {
    // A vendor-facilitated (type-1) request for an RP NOT on the enterprise list
    // returns a NORMAL, non-enterprise attestation: basic_full (x5c present) with
    // NO `ep` flag (CTAP2.1 §6.1.3, conformance Enterprise-Attestation F-6, which
    // asserts attStmt.x5c is an array). No org key here → the device's own cert.
    let (resp, _fs) = run_ea(&build_request_ea(1), true).unwrap();
    let mut d = Decoder::new(&resp);
    assert_eq!(
        d.map().unwrap().unwrap(),
        3,
        "no `ep` field for a non-enterprise attestation"
    );
    assert_eq!(d.u8().unwrap(), 1);
    assert_eq!(d.str().unwrap(), "packed");
    assert_eq!(d.u8().unwrap(), 2);
    d.bytes().unwrap(); // authData
    assert_eq!(d.u8().unwrap(), 3);
    // attStmt = { alg, sig, x5c } — basic_full (self would be 2 entries, no x5c).
    assert_eq!(
        d.map().unwrap().unwrap(),
        3,
        "basic_full attStmt carries x5c, not self"
    );
    assert_eq!(d.str().unwrap(), "alg");
    d.i64().unwrap();
    assert_eq!(d.str().unwrap(), "sig");
    d.bytes().unwrap();
    assert_eq!(d.str().unwrap(), "x5c");
    assert_eq!(d.array().unwrap().unwrap(), 1, "one cert");
    assert!(
        !d.bytes().unwrap().is_empty(),
        "x5c carries the device cert"
    );
}

#[test]
fn enterprise_type1_non_eligible_ignores_org_key() {
    // Regression for conformance Enterprise-Attestation F-6: even with an org/EP
    // attestation key provisioned and EA enabled, a vendor-facilitated (type 1)
    // request for an RP NOT on the enterprise list must NOT use the org/EP cert.
    // It returns a normal basic_full attestation with the DEVICE's own cert and
    // no `ep` — never the enterprise batch cert.
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    crate::seed::store_att_key(&dev(), &mut fs, &[0x21u8; 32]).unwrap();
    let c1 = [0x30u8, 0x03, 1, 2, 3];
    let mut packed = [0u8; 64];
    let plen = crate::cert::att_chain_pack(&c1, &mut packed).unwrap();
    fs.put(EF_ATT_CHAIN, &packed[..plen]).unwrap();
    fs.put(EF_EA_ENABLED, &[1]).unwrap();

    let req = build_request_ea(1); // rp_id "example.com" — not enterprise-eligible
    let mut out = [0u8; 1024];
    let mut state = crate::FidoState::new();
    let resp = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 1000,
        };
        let len = make_credential(&mut ctx, &req, &mut out).unwrap();
        out[..len].to_vec()
    };
    let mut d = Decoder::new(&resp);
    // No `ep` (3 top-level fields), basic_full attStmt (x5c), and the x5c is NOT
    // the provisioned org/EP cert (`c1`) — the device's own cert instead.
    assert_eq!(
        d.map().unwrap().unwrap(),
        3,
        "type-1 non-eligible must not add ep"
    );
    assert_eq!(d.u8().unwrap(), 1);
    assert_eq!(d.str().unwrap(), "packed");
    assert_eq!(d.u8().unwrap(), 2);
    d.bytes().unwrap();
    assert_eq!(d.u8().unwrap(), 3);
    assert_eq!(
        d.map().unwrap().unwrap(),
        3,
        "basic_full attStmt (x5c), not self"
    );
    assert_eq!(d.str().unwrap(), "alg");
    d.i64().unwrap();
    assert_eq!(d.str().unwrap(), "sig");
    d.bytes().unwrap();
    assert_eq!(d.str().unwrap(), "x5c");
    assert_eq!(d.array().unwrap().unwrap(), 1);
    assert_ne!(
        d.bytes().unwrap(),
        &c1,
        "non-eligible type-1 must NOT present the org/EP cert"
    );
}

#[test]
fn vendor_ea_eligibility() {
    // No RP qualifies for vendor-facilitated EA by default; the FIDO conformance
    // test RPID qualifies only under the `ea-conformance-rpid` feature.
    assert!(!rp_eligible_for_vendor_ea("example.com"));
    assert_eq!(
        rp_eligible_for_vendor_ea("enterprisetest.certinfra.fidoalliance.org"),
        cfg!(feature = "ea-conformance-rpid")
    );
}

/// A trusted-display backend: it collects a PIN on its own pad **and** paints the
/// ceremony, recording what each `Confirm` named.
struct DisplayPad {
    touches: usize,
    last_title: &'static str,
    last_primary: std::vec::Vec<u8>,
    last_secondary: std::vec::Vec<u8>,
}
impl DisplayPad {
    fn new() -> Self {
        Self {
            touches: 0,
            last_title: "",
            last_primary: std::vec::Vec::new(),
            last_secondary: std::vec::Vec::new(),
        }
    }
}
impl crate::UserPresence for DisplayPad {
    fn request(&mut self, c: crate::Confirm<'_>) -> crate::Presence {
        self.touches += 1;
        self.last_title = c.title;
        self.last_primary = c.primary.to_vec();
        self.last_secondary = c.secondary.to_vec();
        crate::Presence::Confirmed
    }
    fn shows_confirm(&self) -> bool {
        true
    }
    fn uv_available(&self) -> bool {
        true
    }
    fn collect_pin(&mut self, _min: usize, out: &mut [u8]) -> crate::PinEntry {
        out[..4].copy_from_slice(b"1234");
        crate::PinEntry::Entered(4)
    }
}

#[test]
fn builtin_uv_still_names_the_registration_on_a_display() {
    // Audit run-28 F1, the makeCredential half. §6.1.2 step 13 excuses the second
    // *gesture*, not the disclosure: the "Save new passkey?" card is the only screen
    // that names the rp and account being enrolled, and the PIN pad structurally
    // cannot (`collect_pin` takes no `Confirm`). Without it a host could trade one
    // context-free PIN entry for a credential at an rp of its choosing.
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    crate::clientpin::store_local_pin(&dev(), &mut fs, b"1234").unwrap();
    let mut state = crate::FidoState::new();
    let cdh = [0xCDu8; 32];
    let mut out = [0u8; 1024];
    let mut pad = DisplayPad::new();
    let len = {
        let mut ctx = Ctx {
            presence: &mut pad,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        make_credential(&mut ctx, &build_request_uv(true, None), &mut out).unwrap()
    };
    let auth_data = verify_response(&out[..len], &cdh);
    assert_eq!(auth_data[32] & FLAG_UV, FLAG_UV);
    assert_eq!(pad.touches, 1, "the naming card is painted exactly once");
    assert_eq!(pad.last_title, "Register key?");
    assert_eq!(
        pad.last_primary, b"example.com",
        "the card carries the rp being registered"
    );
}
