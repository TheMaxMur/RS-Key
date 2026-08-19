// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::consts::{ALG_ED25519, ALG_ESP256, ALG_ESP384, ALG_ESP512, EF_ALWAYS_UV};
use crate::seed::ensure_seed;
use minicbor::Decoder;
use p256::Sec1Point;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use rsk_crypto::Device;
use rsk_crypto::pinproto::PinProto;
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

// The COSE `alg` (key 3) of the credential public key a response attests.
fn attested_alg(resp: &[u8]) -> i64 {
    let mut d = Decoder::new(resp);
    assert!(d.map().unwrap().unwrap() >= 3);
    assert_eq!(d.u8().unwrap(), 1);
    assert_eq!(d.str().unwrap(), ATT_FMT);
    assert_eq!(d.u8().unwrap(), 2);
    let auth_data = d.bytes().unwrap();
    let cred_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    let mut cd = Decoder::new(&auth_data[55 + cred_len..]);
    let entries = cd.map().unwrap().unwrap();
    for _ in 0..entries {
        if cd.i64().unwrap() == 3 {
            return cd.i64().unwrap();
        }
        cd.skip().unwrap();
    }
    panic!("attested COSE key carries no alg");
}

// One-element pubKeyCredParams offering `alg`.
fn only_alg(e: &mut Encoder<Cursor<&mut [u8]>>, alg: i64) {
    e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
    e.str("alg").unwrap().i64(alg).unwrap();
    e.str("type").unwrap().str("public-key").unwrap();
}

#[test]
fn a_fully_specified_alg_is_attested_as_itself() {
    // WebAuthn L3 §7.1 has the relying party match the attested key's alg against
    // the list it sent, so a request offering only the curve-explicit spelling must
    // get that spelling back. Folding it onto the legacy id failed the RP's own
    // registration — and with rk set it had already spent a discoverable slot.
    for alg in [ALG_ESP256, ALG_ESP384, ALG_ESP512, ALG_ED25519] {
        let (resp, _fs) = run(&mc_build(4, |e| only_alg(e, alg)));
        assert_eq!(
            attested_alg(&resp),
            alg,
            "curve-explicit alg {alg} must be attested as itself"
        );
    }
    // The legacy spellings are unaffected and each still attests what it offered.
    for alg in [ALG_ES256, ALG_EDDSA] {
        let (resp, _fs) = run(&mc_build(4, |e| only_alg(e, alg)));
        assert_eq!(attested_alg(&resp), alg);
    }
    // With both spellings offered the first supported element wins (§6.1.2 step 3
    // scans in the platform's preference order), so the id chosen is the id
    // attested — the same rule, not a special case for the alias.
    for pair in [[ALG_ESP256, ALG_ES256], [ALG_ES256, ALG_ESP256]] {
        let req = mc_build(4, |e| {
            e.u8(4).unwrap().array(2).unwrap();
            for a in pair {
                e.map(2).unwrap();
                e.str("alg").unwrap().i64(a).unwrap();
                e.str("type").unwrap().str("public-key").unwrap();
            }
        });
        let (resp, _fs) = run(&req);
        assert_eq!(attested_alg(&resp), pair[0]);
    }
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
    // An unrecognized top-level key is skipped, not an error — the map still parses
    // and the credential is created. This used to send 0x0B, which CTAP 2.2 defines
    // as `attestationFormatsPreference`; 0x0C is the first key still unassigned, and
    // the type check that now guards 0x0B is pinned separately below.
    let req = mc_build(5, |e| {
        good_params(e);
        e.u8(12).unwrap().u8(0).unwrap();
    });
    assert!(!run(&req).0.is_empty());
}

/// `attestationFormatsPreference` is typed — "Array of String" — so a request that
/// puts something else there is malformed, and is refused the same way every other
/// mistyped field in this parser is. It is not treated as an ignorable hint: the
/// key stopped being unassigned the moment CTAP 2.2 gave it a meaning, and a client
/// sending an integer has a bug worth surfacing rather than silently absorbing.
///
/// The status is `CTAP2_ERR_CBOR_UNEXPECTED_TYPE`, which is what a wrong major type
/// earns; `INVALID_CBOR` is what an indefinite-length array would earn instead.
#[test]
fn attestation_formats_preference_must_be_an_array() {
    for tail in [
        (|e: &mut Encoder<Cursor<&mut [u8]>>| {
            e.u8(11).unwrap().u8(0).unwrap();
        }) as fn(&mut Encoder<Cursor<&mut [u8]>>),
        |e| {
            e.u8(11).unwrap().str("none").unwrap();
        },
        |e| {
            e.u8(11).unwrap().map(0).unwrap();
        },
    ] {
        let req = mc_build(5, |e| {
            good_params(e);
            tail(e);
        });
        assert_eq!(run_err(&req), CtapError::CborUnexpectedType);
    }

    // A non-string INSIDE the array is the same mistake one level down.
    let req = mc_build(5, |e| {
        good_params(e);
        e.u8(11).unwrap().array(1).unwrap().u8(0).unwrap();
    });
    assert_eq!(run_err(&req), CtapError::CborUnexpectedType);
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

/// §12.1 defines levels 1/2/3 and names no error for anything else, so the oracle
/// decides: a YubiKey 5.7.4 answers CTAP1_ERR_INVALID_PARAMETER to 0, 4 and 255
/// alike. `0` used to register a credential with no protection and no extension
/// output at all — the request said something and the card silently did another.
#[test]
fn credprotect_out_of_range_rejected() {
    for level in [0, 4, 255] {
        assert_eq!(
            run_err(&mc_request_credprotect(level)),
            CtapError::InvalidParameter,
            "credProtect {level}"
        );
    }
    // Every defined level still registers.
    for level in [1, 2, 3] {
        assert!(!run(&mc_request_credprotect(level)).0.is_empty());
    }
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

// The CTAP 2.1 large-blob design, which a `largeblob-ext` build withdraws
// wholesale (§12.4: "Authenticators MUST NOT support both extensions").
#[cfg(not(feature = "largeblob-ext"))]
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
    // No RP qualifies for vendor-facilitated EA on a device with no stored list —
    // an absent EF_EA_RPIDS is the empty list, which is what an already-provisioned
    // device upgraded to this firmware reads. The FIDO conformance test RPID
    // qualifies only under the `ea-conformance-rpid` feature.
    let mut fs = Fs::new(RamStorage::new());
    assert!(!rp_eligible_for_vendor_ea(&mut fs, &sha256(b"example.com")));
    assert_eq!(
        rp_eligible_for_vendor_ea(
            &mut fs,
            &sha256(b"enterprisetest.certinfra.fidoalliance.org")
        ),
        cfg!(feature = "ea-conformance-rpid")
    );

    // A stored list admits exactly its own entries, at any position.
    let mut list = [0u8; 64];
    list[..32].copy_from_slice(&sha256(b"first.example"));
    list[32..].copy_from_slice(&sha256(b"corp.example.com"));
    fs.put(EF_EA_RPIDS, &list).unwrap();
    assert!(rp_eligible_for_vendor_ea(
        &mut fs,
        &sha256(b"first.example")
    ));
    assert!(rp_eligible_for_vendor_ea(
        &mut fs,
        &sha256(b"corp.example.com")
    ));
    assert!(!rp_eligible_for_vendor_ea(&mut fs, &sha256(b"example.com")));
}

#[test]
fn enterprise_type1_listed_rp_uses_org_key() {
    // The twin of `enterprise_type1_non_eligible_ignores_org_key`: the SAME request
    // and the same org key, differing only in that the RP is on the stored list.
    // It must now come back with `ep` and the org/EP cert — otherwise the storage
    // is wired to nothing and the negative test above passes for the wrong reason.
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    crate::seed::store_att_key(&dev(), &mut fs, &[0x21u8; 32]).unwrap();
    let c1 = [0x30u8, 0x03, 1, 2, 3];
    let mut packed = [0u8; 64];
    let plen = crate::cert::att_chain_pack(&c1, &mut packed).unwrap();
    fs.put(EF_ATT_CHAIN, &packed[..plen]).unwrap();
    fs.put(EF_EA_ENABLED, &[1]).unwrap();
    fs.put(EF_EA_RPIDS, &sha256(b"example.com")).unwrap();

    let req = build_request_ea(1); // rp_id "example.com" — now listed
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
    assert_eq!(
        d.map().unwrap().unwrap(),
        4,
        "a listed type-1 RP gets the `ep` field"
    );
    assert_eq!(d.u8().unwrap(), 1);
    assert_eq!(d.str().unwrap(), "packed");
    assert_eq!(d.u8().unwrap(), 2);
    d.bytes().unwrap();
    assert_eq!(d.u8().unwrap(), 3);
    assert_eq!(d.map().unwrap().unwrap(), 3);
    assert_eq!(d.str().unwrap(), "alg");
    d.i64().unwrap();
    assert_eq!(d.str().unwrap(), "sig");
    d.bytes().unwrap();
    assert_eq!(d.str().unwrap(), "x5c");
    assert_eq!(d.array().unwrap().unwrap(), 1);
    assert_eq!(
        d.bytes().unwrap(),
        &c1,
        "a listed type-1 RP gets the org/EP cert"
    );
    assert_eq!(d.u8().unwrap(), 4);
    assert!(d.bool().unwrap(), "ep = true");
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

/// Audit run-36: `font::width` measures glyph INK, so trailing whitespace paints
/// nothing — "bank.com " renders pixel-identically to "bank.com" on the trusted
/// display's sign-in, passkey-list and delete screens while hashing to a wholly
/// different relying party. An all-whitespace id is worse: it passes every
/// length-based emptiness check, so the ceremony paints a blank relying-party line
/// with the attacker's `user.name` as the only text under the globe. No browser can
/// send either (WebAuthn requires a valid domain string, and U+0020 is a forbidden
/// host code point), so refuse it here rather than paint it.
#[test]
fn an_rp_id_carrying_whitespace_is_refused() {
    for id in [
        "bank.com ",
        " bank.com",
        "bank .com",
        "        ",
        "bank.com\t",
    ] {
        let mut buf = [0u8; 256];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(4).unwrap();
            e.u8(1).unwrap().bytes(&[0xCDu8; 32]).unwrap();
            e.u8(2).unwrap().map(1).unwrap();
            e.str("id").unwrap().str(id).unwrap();
            e.u8(3).unwrap().map(1).unwrap();
            e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
            good_params(&mut e);
            e.writer().position()
        };
        assert_eq!(
            run_err(&buf[..n]),
            CtapError::InvalidParameter,
            "rp.id {id:?} was accepted"
        );
    }
    // An ordinary domain is untouched.
    let (resp, _) = run(&mc_build(4, good_params));
    assert!(!resp.is_empty(), "a plain rpId must still register");
}

/// A makeCredential whose excludeList is `entries`, each a `(type, id)` descriptor.
fn mc_build_exclude(entries: &[(&str, &[u8])]) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 8192];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(5).unwrap();
        e.u8(1).unwrap().bytes(&[0xCDu8; 32]).unwrap();
        e.u8(2).unwrap().map(1).unwrap();
        e.str("id").unwrap().str("example.com").unwrap();
        e.u8(3).unwrap().map(1).unwrap();
        e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
        good_params(&mut e);
        e.u8(5).unwrap().array(entries.len() as u64).unwrap();
        for (ty, id) in entries {
            e.map(2).unwrap();
            e.str("id").unwrap().bytes(id).unwrap();
            e.str("type").unwrap().str(ty).unwrap();
        }
        e.writer().position()
    };
    buf[..n].to_vec()
}

// The excludeList is the re-registration guard, so truncating it is worse than
// refusing it: padding the list past maxCredentialCountInList would hide the
// already-registered credential and mint a duplicate. The declining button proves
// the refusal happens at parse time, before any touch is spent.
#[test]
fn exclude_list_over_max_is_limit_exceeded() {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let mut state = crate::FidoState::new();
    let cred_id = register_and_get_cred_id(&mut fs, &mut rng, &mut state);
    let filler = [0xEEu8; 32];

    let mut entries = [("public-key", &filler[..]); MAX_EXCLUDE + 1];
    entries[MAX_EXCLUDE] = ("public-key", &cred_id[..]);

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
        make_credential(&mut ctx, &mc_build_exclude(&entries), &mut out),
        Err(CtapError::LimitExceeded),
        "an oversized excludeList is refused; truncating it would create a duplicate"
    );
}

// The boundary still excludes, so the ceiling is `>` and not `>=` — and a
// foreign-typed descriptor is ignored rather than matched, which is what lets the
// registration through.
#[test]
fn exclude_list_at_max_excludes_and_foreign_types_do_not() {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let mut state = crate::FidoState::new();
    let cred_id = register_and_get_cred_id(&mut fs, &mut rng, &mut state);
    let filler = [0xEEu8; 32];

    let mut entries = [("public-key", &filler[..]); MAX_EXCLUDE];
    entries[MAX_EXCLUDE - 1] = ("public-key", &cred_id[..]);
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
        assert_eq!(
            make_credential(&mut ctx, &mc_build_exclude(&entries), &mut out),
            Err(CtapError::CredentialExcluded),
            "exactly maxCredentialCountInList entries must still exclude"
        );
    }

    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 1000,
    };
    assert!(
        make_credential(
            &mut ctx,
            &mc_build_exclude(&[("not-a-key", &cred_id[..])]),
            &mut out
        )
        .is_ok(),
        "a foreign-typed descriptor names no credential this device can assert"
    );
}

// makeCredential with `pinUvAuthParam` (key 8) and `pinUvAuthProtocol` (key 9)
// each independently present or absent, so §6.1.2 step 2's matrix can be driven
// from the wire instead of from the parsed struct.
fn mc_request_pin_opt(param: Option<&[u8]>, proto: Option<u64>) -> std::vec::Vec<u8> {
    let n = 4 + u64::from(param.is_some()) + u64::from(proto.is_some());
    mc_build(n, |e| {
        good_params(e);
        if let Some(p) = param {
            e.u8(8).unwrap().bytes(p).unwrap();
        }
        if let Some(v) = proto {
            e.u8(9).unwrap().u64(v).unwrap();
        }
    })
}

/// §6.1.2 step 2.1 is about a protocol the platform *sent* and this build does not
/// support; 2.2's MISSING_PARAMETER is about one it did not send. A numeric `0`
/// used to take the second branch, so a platform that sent `pinUvAuthProtocol: 0`
/// was told to add the parameter it had already added — a loop it cannot leave.
/// Measured on a YubiKey 5.7.4: `0` is INVALID_PARAMETER with a param, without a
/// param, and even ahead of step 1's zero-length selection gesture.
#[test]
fn pin_uv_auth_protocol_zero_is_a_value_not_an_absence() {
    let garbage = [0xEEu8; 32];
    for param in [Some(&garbage[..]), None, Some(&[][..])] {
        assert_eq!(
            run_err(&mc_request_pin_opt(param, Some(0))),
            CtapError::InvalidParameter,
            "protocol 0, param {:?}",
            param.map(<[u8]>::len)
        );
        // An unsupported non-zero protocol has always answered this; `0` now joins it.
        assert_eq!(
            run_err(&mc_request_pin_opt(param, Some(3))),
            CtapError::InvalidParameter
        );
    }
    // The absent protocol keeps its own code, and a supported one still reaches
    // the token check — so the gate above discriminates rather than blanket-refusing.
    assert_eq!(
        run_err(&mc_request_pin_opt(Some(&garbage), None)),
        CtapError::MissingParameter
    );
    for proto in [1, 2] {
        assert_eq!(
            run_err(&mc_request_pin_opt(Some(&garbage), Some(proto))),
            CtapError::PinAuthInvalid
        );
    }
    // With a supported protocol the zero-length probe still runs its gesture and
    // reports the PIN state (§6.1.2 step 1) — the gate must not swallow it.
    assert_eq!(
        run_err(&mc_request_pin_opt(Some(&[]), Some(2))),
        CtapError::PinNotSet
    );
}

// Writes request keys into a half-built map.
type Keys<'a> = &'a dyn Fn(&mut Encoder<Cursor<&mut [u8]>>);
// One check-order row: label, the keys it writes, how many, and the code that
// fault alone would get.
type OrderRow<'a> = (&'a str, Keys<'a>, u64, CtapError);

// A makeCredential carrying `pinUvAuthParam` (8) and a `pinUvAuthProtocol` (9)
// of `proto`, over whatever request keys `head` writes. `nkeys` counts only
// those; the two PIN keys are added here.
fn mc_with_proto(nkeys: u64, proto: u64, head: Keys) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(nkeys + 2).unwrap();
        head(&mut e);
        e.u8(8).unwrap().bytes(&[0xEEu8; 32]).unwrap();
        e.u8(9).unwrap().u64(proto).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

fn mc_cdh(e: &mut Encoder<Cursor<&mut [u8]>>) {
    e.u8(1).unwrap().bytes(&[0xCDu8; 32]).unwrap();
}

fn mc_rp(e: &mut Encoder<Cursor<&mut [u8]>>) {
    e.u8(2).unwrap().map(1).unwrap();
    e.str("id").unwrap().str("example.com").unwrap();
}

fn mc_user(e: &mut Encoder<Cursor<&mut [u8]>>) {
    e.u8(3).unwrap().map(1).unwrap();
    e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
}

/// §6.1.2 step 2 outranks the checks below it, not just step 1's selection
/// gesture: a YubiKey 5.7.4 answers CTAP1_ERR_INVALID_PARAMETER to a
/// present-but-unsupported `pinUvAuthProtocol` when the algorithm is also
/// unsupported or `pubKeyCredParams` is empty — measured across both, four
/// readings each. Ours judged it inside `enforce_pin`, i.e. after all of them, so
/// a request that got two things wrong was told about the wrong one. Same class
/// as `a4cbf54`.
///
/// Bounded at both ends, each end measured rather than assumed. Above: a request
/// missing one of the mandatory keys 1..=4 is refused by `parse` before key 9 is
/// ever read, so it keeps answering MISSING_PARAMETER where that card answers
/// INVALID_PARAMETER (`missing_mandatory_param_rejected` pins it), and a
/// malformed `pubKeyCredParams` entry outranks the protocol on that card too.
/// Below: the option-value errors of step 4 — see
/// `option_value_errors_outrank_the_protocol`, which is the other half of this
/// rule and the reason `up:false` is not a row here.
#[test]
fn unsupported_protocol_outranks_every_later_check() {
    let rows: [OrderRow; 2] = [
        (
            "unsupported alg",
            &|e| {
                mc_cdh(e);
                mc_rp(e);
                mc_user(e);
                // An unassigned COSE id, not a real-but-unbacked one: the point of
                // the row is the ordering, so it must not start passing the day an
                // algorithm is added.
                only_alg(e, -1000);
            },
            4,
            CtapError::UnsupportedAlgorithm,
        ),
        (
            // The control code here is OURS, and it is a measured divergence in
            // its own right: that card answers UNSUPPORTED_ALGORITHM to an empty
            // list (and to an absent key 4), three readings, since §6.1.2 step 3's
            // loop simply chooses nothing. Recorded, not silently blessed.
            "empty pubKeyCredParams",
            &|e| {
                mc_cdh(e);
                mc_rp(e);
                mc_user(e);
                e.u8(4).unwrap().array(0).unwrap();
            },
            4,
            CtapError::MissingParameter,
        ),
    ];
    for (label, head, nkeys, alone) in rows {
        assert_eq!(
            run_err(&mc_with_proto(nkeys, 3, head)),
            CtapError::InvalidParameter,
            "unsupported protocol must outrank: {label}"
        );
        // The control: with a SUPPORTED protocol the same request keeps reporting
        // its own fault, so the gate discriminates instead of blanket-refusing.
        assert_eq!(
            run_err(&mc_with_proto(nkeys, 1, head)),
            alone,
            "supported protocol must not mask: {label}"
        );
    }
}

// A makeCredential over `head` with NO pinUvAuthParam and a `pinUvAuthProtocol`
// of `proto` — the shape a bare `uv:true` needs, since a param present would make
// §6.1.2 step 5 treat the option as false.
fn mc_proto_no_param(nkeys: u64, proto: u64, head: Keys) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(nkeys + 1).unwrap();
        head(&mut e);
        e.u8(9).unwrap().u64(proto).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// The other end of the check order, and the one §6.1.2's numbering gets wrong:
/// step 4's option-value errors are judged BEFORE step 2's protocol, not after.
/// Measured on a YubiKey 5.7.4, eight readings per row and across every
/// confounder (`pinUvAuthParam` present, absent or empty; protocol 0, 3 and 9):
/// `up:false` and a bare `uv:true` are CTAP2_ERR_INVALID_OPTION whatever the
/// protocol says, and they outrank a bad algorithm and an empty
/// `pubKeyCredParams` there too. Only the request map's own shape beats them.
///
/// This is a guard against re-hoisting: judging the protocol first — which the
/// spec's step numbers invite — silently converts all of these to
/// INVALID_PARAMETER.
#[test]
fn option_value_errors_outrank_the_protocol() {
    let up_false: Keys = &|e| {
        mc_cdh(e);
        mc_rp(e);
        mc_user(e);
        good_params(e);
        e.u8(7).unwrap().map(1).unwrap();
        e.str("up").unwrap().bool(false).unwrap();
    };
    // Compounded with an algorithm the card also refuses: it answers the option
    // there too, so this pins which of the two wins.
    let up_false_bad_alg: Keys = &|e| {
        mc_cdh(e);
        mc_rp(e);
        mc_user(e);
        only_alg(e, ALG_ESP256);
        e.u8(7).unwrap().map(1).unwrap();
        e.str("up").unwrap().bool(false).unwrap();
    };
    for (label, head) in [
        ("up:false", up_false),
        ("up:false + bad alg", up_false_bad_alg),
    ] {
        for proto in [0u64, 3, 9] {
            assert_eq!(
                run_err(&mc_with_proto(5, proto, head)),
                CtapError::InvalidOption,
                "{label} must outrank protocol {proto}"
            );
        }
        // The control: it is the option being reported, not a blanket refusal —
        // a supported protocol gives the same code.
        assert_eq!(
            run_err(&mc_with_proto(5, 1, head)),
            CtapError::InvalidOption
        );
    }

    // A bare uv:true on a build with no built-in user verification. It carries no
    // pinUvAuthParam: one present would make step 5 clear the option first.
    let uv_true: Keys = &|e| {
        mc_cdh(e);
        mc_rp(e);
        mc_user(e);
        good_params(e);
        e.u8(7).unwrap().map(1).unwrap();
        e.str("uv").unwrap().bool(true).unwrap();
    };
    for proto in [0u64, 3, 9] {
        assert_eq!(
            run_err(&mc_proto_no_param(5, proto, uv_true)),
            CtapError::InvalidOption,
            "bare uv:true must outrank protocol {proto}"
        );
    }
}

/// §6.1.2 step 9 keys on `enterpriseAttestation` being PRESENT, not on it being
/// non-zero: with EA disabled — the shipping default — every present value is
/// refused, `0` included. It used to register an ordinary credential, so a
/// platform asking for enterprise attestation and getting none could not tell.
#[test]
fn enterprise_attestation_zero_is_a_value_not_an_absence() {
    assert_eq!(
        run_ea(&build_request_ea(0), false).map(|_| ()).unwrap_err(),
        CtapError::InvalidParameter
    );
    // Enabled, `0` is still not one of the two defined levels (§6.1.2 step 9's
    // else-branch). No YubiKey reading exists — this key advertises no `ep`.
    assert_eq!(
        run_ea(&build_request_ea(0), true).map(|_| ()).unwrap_err(),
        CtapError::InvalidOption
    );
    // Omitting the field entirely still registers, with EA off or on.
    for enable in [false, true] {
        assert!(
            !run_ea(&mc_build(4, good_params), enable)
                .unwrap()
                .0
                .is_empty()
        );
    }
}

// ---- attestationFormatsPreference (request 0x0B, CTAP 2.2) ----

/// A response's `fmt` (1) and the SIZE of its attStmt (3), for a request whose
/// `attestationFormatsPreference` is `formats` — absent when `None`.
fn att_shape_for(formats: Option<&[&str]>) -> (std::string::String, u64) {
    let req = mc_build(4 + u64::from(formats.is_some()), |e| {
        good_params(e);
        if let Some(list) = formats {
            e.u8(11).unwrap().array(list.len() as u64).unwrap();
            for f in list {
                e.str(f).unwrap();
            }
        }
    });
    let (resp, _) = run(&req);
    let mut d = Decoder::new(&resp);
    d.map().unwrap();
    assert_eq!(d.u8().unwrap(), 1);
    let fmt = d.str().unwrap().to_string();
    assert_eq!(d.u8().unwrap(), 2);
    d.bytes().unwrap();
    assert_eq!(d.u8().unwrap(), 3);
    (fmt, d.map().unwrap().unwrap())
}

/// CTAP 2.2 `attestationFormatsPreference`: for an authenticator that emits exactly
/// one format, a list of exactly `["none"]` is the ONLY shape that changes anything.
/// The lowest-index-supported rule needs two formats to choose between, so a longer
/// list — even one containing "none" — leaves the packed statement untouched. That
/// containment is the safety property: `fmt:"none"` broke OpenSSH < 10.0 when this
/// device emitted it unasked, and it is now reachable only on explicit request.
#[test]
fn attestation_formats_preference_omits_only_for_none_alone() {
    for formats in [
        None,
        Some(&[] as &[&str]),
        Some(&["packed"][..]),
        Some(&["none", "packed"][..]),
        Some(&["packed", "none"][..]),
        Some(&["tpm"][..]),
        Some(&["none", "none"][..]),
    ] {
        let (fmt, stmt) = att_shape_for(formats);
        assert_eq!(fmt, "packed", "{formats:?} must not change the format");
        assert_eq!(stmt, 3, "{formats:?} must keep the full {{alg, sig, x5c}}");
    }

    let (fmt, stmt) = att_shape_for(Some(&["none"]));
    assert_eq!(fmt, "none");
    // Present and empty, not absent: field 3 is required, and a reader that finds no
    // attStmt sees an incomplete attestation object rather than a none-format one.
    assert_eq!(
        stmt, 0,
        "the none statement is an EMPTY map, and it is written"
    );
}

/// An enterprise attestation that was actually performed outranks the preference.
/// It is explicitly enabled in flash and requested per credential, and it is the
/// stronger claim; honouring `["none"]` over it would silently discard what an
/// administrator turned on.
#[test]
fn enterprise_attestation_outranks_a_none_preference() {
    let mut buf = [0u8; 512];
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
        e.u8(10).unwrap().u64(2).unwrap();
        e.u8(11).unwrap().array(1).unwrap().str("none").unwrap();
        e.writer().position()
    };
    let (resp, _) = run_ea(&buf[..n], true).unwrap();
    let mut d = Decoder::new(&resp);
    d.map().unwrap();
    assert_eq!(d.u8().unwrap(), 1);
    assert_eq!(d.str().unwrap(), "packed", "EA must still be attested");
    assert_eq!(d.u8().unwrap(), 2);
    d.bytes().unwrap();
    assert_eq!(d.u8().unwrap(), 3);
    assert_eq!(d.map().unwrap().unwrap(), 3, "the full statement survives");
}
