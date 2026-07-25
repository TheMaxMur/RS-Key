// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::FidoState;
use crate::consts::ALG_ES256;
use crate::makecredential::make_credential;
use crate::seed::ensure_seed;
use minicbor::Encoder;
use minicbor::encode::write::Cursor;
use rsk_crypto::{Device, pinproto, sha256};
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

const CDH: [u8; 32] = [0xCD; 32];
const TOKEN: [u8; 32] = [0x99; 32];

fn dev() -> Device<'static> {
    Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    }
}

fn armed(perms: u8) -> FidoState {
    let mut s = FidoState::new();
    s.paut.token = TOKEN;
    s.paut.permissions = perms;
    s.begin_using_token(false, 0);
    s
}

// A resident makeCredential request for (rp_id, user_id, name).
fn mc_request(rp_id: &str, uid: &[u8], name: &str) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(5).unwrap();
        e.u8(1).unwrap().bytes(&CDH).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str(rp_id)
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(uid).unwrap();
        e.str("name").unwrap().str(name).unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
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

// Register a resident credential, returning its (resident_id, pubkey x, y).
fn register(
    fs: &mut Fs<RamStorage>,
    rng: &mut SeqRng,
    rp_id: &str,
    uid: &[u8],
    name: &str,
) -> (std::vec::Vec<u8>, [u8; 32], [u8; 32]) {
    let mut out = [0u8; 1024];
    let mut state = FidoState::new();
    let n = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs,
            rng,
            state: &mut state,
            now_ms: 10,
        };
        make_credential(&mut ctx, &mc_request(rp_id, uid, name), &mut out).unwrap()
    };
    parse_mc(&out[..n])
}

// Pull (resident credId, pubkey x, y) out of a makeCredential response.
fn parse_mc(resp: &[u8]) -> (std::vec::Vec<u8>, [u8; 32], [u8; 32]) {
    let mut d = Decoder::new(resp);
    d.map().unwrap();
    d.u8().unwrap();
    d.str().unwrap(); // 1: "packed"
    d.u8().unwrap(); // 2
    let ad = d.bytes().unwrap();
    let cred_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    let cred_id = ad[55..55 + cred_len].to_vec();
    let mut cd = Decoder::new(&ad[55 + cred_len..]);
    cd.map().unwrap();
    cd.u8().unwrap();
    cd.u8().unwrap();
    cd.u8().unwrap();
    cd.i64().unwrap();
    cd.i8().unwrap();
    cd.u8().unwrap();
    cd.i8().unwrap();
    let mut x = [0u8; 32];
    x.copy_from_slice(cd.bytes().unwrap());
    cd.i8().unwrap();
    let mut y = [0u8; 32];
    y.copy_from_slice(cd.bytes().unwrap());
    (cred_id, x, y)
}

fn setup() -> (Fs<RamStorage>, SeqRng) {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    (fs, rng)
}

// Encode a subCommandParams map, returning its raw CBOR bytes.
fn subpara_rpidhash(rp_hash: &[u8; 32]) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 64];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(1).unwrap().u8(1).unwrap().bytes(rp_hash).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

fn subpara_cred(cred_id: &[u8]) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 128];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(1).unwrap().u8(2).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(cred_id).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

fn subpara_update(cred_id: &[u8], uid: &[u8], name: &str, dname: &str) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(2).unwrap();
        e.u8(2).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(cred_id).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(3).unwrap().map(3).unwrap();
        e.str("id").unwrap().bytes(uid).unwrap();
        e.str("name").unwrap().str(name).unwrap();
        e.str("displayName").unwrap().str(dname).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

// Build a credMgmt request, MACing over `subcommand ‖ subpara` under `token`.
fn cm_request(subcmd: u8, subpara: Option<&[u8]>, token: &[u8; 32]) -> std::vec::Vec<u8> {
    let mut payload = std::vec![subcmd];
    if let Some(sp) = subpara {
        payload.extend_from_slice(sp);
    }
    let mut mac = [0u8; 32];
    let mlen = pinproto::authenticate(PinProto::Two, token, &payload, &mut mac).unwrap();

    let mut req = std::vec::Vec::new();
    let fields = if subpara.is_some() { 4u8 } else { 3 };
    req.push(0xA0 | fields);
    req.extend_from_slice(&[0x01, subcmd]); // 1: subCommand
    if let Some(sp) = subpara {
        req.push(0x02); // 2: subCommandParams (raw)
        req.extend_from_slice(sp);
    }
    req.extend_from_slice(&[0x03, 0x02]); // 3: pinUvAuthProtocol = 2
    req.push(0x04); // 4: pinUvAuthParam
    req.push(0x58);
    req.push(mlen as u8);
    req.extend_from_slice(&mac[..mlen]);
    req
}

// A bare {1: subcommand} request for the Next walkers.
fn cm_next(subcmd: u8) -> std::vec::Vec<u8> {
    std::vec![0xA1, 0x01, subcmd]
}

fn run(fs: &mut Fs<RamStorage>, state: &mut FidoState, req: &[u8], out: &mut [u8]) -> CtapResult {
    let mut rng = SeqRng(7);
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs,
        rng: &mut rng,
        state,
        now_ms: 100,
    };
    cred_mgmt(&mut ctx, req, out)
}

#[test]
fn metadata_counts_residents() {
    let (mut fs, mut rng) = setup();
    register(&mut fs, &mut rng, "example.com", &[1, 1], "a");
    register(&mut fs, &mut rng, "other.com", &[2, 2], "b");
    let mut state = armed(PERM_CM);
    let mut out = [0u8; 256];
    let n = run(
        &mut fs,
        &mut state,
        &cm_request(0x01, None, &TOKEN),
        &mut out,
    )
    .unwrap();
    let mut d = Decoder::new(&out[..n]);
    assert_eq!(d.map().unwrap().unwrap(), 2);
    assert_eq!(d.u8().unwrap(), 1);
    assert_eq!(d.u16().unwrap(), 2); // existing
    assert_eq!(d.u8().unwrap(), 2);
    assert_eq!(d.u16().unwrap(), MAX_RESIDENT_CREDENTIALS - 2); // remaining
}

#[test]
fn enumerate_rps_walks_then_not_allowed() {
    let (mut fs, mut rng) = setup();
    register(&mut fs, &mut rng, "example.com", &[1, 1], "a");
    register(&mut fs, &mut rng, "other.com", &[2, 2], "b");
    let mut state = armed(PERM_CM);

    // Begin → first RP + total = 2.
    let mut out = [0u8; 256];
    let n = run(
        &mut fs,
        &mut state,
        &cm_request(0x02, None, &TOKEN),
        &mut out,
    )
    .unwrap();
    let (id1, hash1, total) = parse_rp(&out[..n], true);
    assert_eq!(total, Some(2));

    // getNextRP → second RP (no total field).
    let n = run(&mut fs, &mut state, &cm_next(0x03), &mut out).unwrap();
    let (id2, hash2, total2) = parse_rp(&out[..n], false);
    assert_eq!(total2, None);
    assert_ne!(id1, id2);
    assert_eq!(hash1, sha256(id1.as_bytes()));
    assert_eq!(hash2, sha256(id2.as_bytes()));

    // Exhausted → NotAllowed.
    assert_eq!(
        run(&mut fs, &mut state, &cm_next(0x03), &mut out),
        Err(CtapError::NotAllowed)
    );
}

#[test]
fn dropping_the_token_strands_a_walk_in_progress() {
    // The Next walkers carry no pinUvAuthParam of their own (CTAP 2.1 §6.8) — they
    // inherit the Begin's authorization, so retiring that token must end the walk
    // rather than let it keep enumerating the store.
    let (mut fs, mut rng) = setup();
    register(&mut fs, &mut rng, "example.com", &[1, 1], "a");
    register(&mut fs, &mut rng, "other.com", &[2, 2], "b");
    let mut out = [0u8; 256];

    for drop_token in [0, 1] {
        let mut state = armed(PERM_CM);
        run(
            &mut fs,
            &mut state,
            &cm_request(0x02, None, &TOKEN),
            &mut out,
        )
        .unwrap();
        if drop_token == 0 {
            state.stop_using_token();
        } else {
            state.reset_pin_uv_auth_token(&mut SeqRng(9));
        }
        assert_eq!(
            run(&mut fs, &mut state, &cm_next(0x03), &mut out),
            Err(CtapError::NotAllowed)
        );
    }
}

fn parse_rp(resp: &[u8], begin: bool) -> (std::string::String, [u8; 32], Option<u8>) {
    let mut d = Decoder::new(resp);
    let fields = d.map().unwrap().unwrap();
    assert_eq!(fields, if begin { 3 } else { 2 });
    assert_eq!(d.u8().unwrap(), 3);
    assert_eq!(d.map().unwrap().unwrap(), 1);
    assert_eq!(d.str().unwrap(), "id");
    let id = d.str().unwrap().to_string();
    assert_eq!(d.u8().unwrap(), 4);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(d.bytes().unwrap());
    let total = if begin {
        assert_eq!(d.u8().unwrap(), 5);
        Some(d.u8().unwrap())
    } else {
        None
    };
    (id, hash, total)
}

#[test]
fn enumerate_credentials_returns_matching_pubkey() {
    let (mut fs, mut rng) = setup();
    // Two creds for the same rp (distinct users), one for another rp.
    let (_id_a, xa, ya) = register(&mut fs, &mut rng, "example.com", &[1, 1], "alice");
    let (_id_b, xb, yb) = register(&mut fs, &mut rng, "example.com", &[2, 2], "bob");
    register(&mut fs, &mut rng, "other.com", &[3, 3], "carol");
    let rp_hash = sha256(b"example.com");
    let mut state = armed(PERM_CM);

    // Begin → first of two, total = 2, COSE key matches one of the registered keys.
    let mut out = [0u8; 512];
    let n = run(
        &mut fs,
        &mut state,
        &cm_request(0x04, Some(&subpara_rpidhash(&rp_hash)), &TOKEN),
        &mut out,
    )
    .unwrap();
    let (uid1, x1, y1, total) = parse_cred(&out[..n], true);
    assert_eq!(total, Some(2));

    // getNextCredential → the other one.
    let n = run(&mut fs, &mut state, &cm_next(0x05), &mut out).unwrap();
    let (uid2, x2, y2, total2) = parse_cred(&out[..n], false);
    assert_eq!(total2, None);
    assert_ne!(uid1, uid2);

    // The two returned keys are exactly the two registered keys (in some order).
    let got = [(x1, y1), (x2, y2)];
    assert!(got.contains(&(xa, ya)));
    assert!(got.contains(&(xb, yb)));

    // Exhausted → NotAllowed.
    assert_eq!(
        run(&mut fs, &mut state, &cm_next(0x05), &mut out),
        Err(CtapError::NotAllowed)
    );
}

#[test]
fn rp_and_credential_cursors_are_independent_when_interleaved() {
    // The slot cursors for the RP and credential walks are separate, so
    // interleaving getNextRP and getNextCredential must advance each walk without
    // corrupting the other (a regression guard for the cursor optimization).
    let (mut fs, mut rng) = setup();
    register(&mut fs, &mut rng, "example.com", &[1, 1], "alice");
    register(&mut fs, &mut rng, "example.com", &[2, 2], "bob");
    register(&mut fs, &mut rng, "other.com", &[3, 3], "carol");
    let rp_hash = sha256(b"example.com");
    let mut state = armed(PERM_CM);
    let mut out = [0u8; 512];

    // Begin both walks (2 RPs; 2 creds for example.com).
    let n = run(
        &mut fs,
        &mut state,
        &cm_request(0x02, None, &TOKEN),
        &mut out,
    )
    .unwrap();
    let (rp1, _, rp_total) = parse_rp(&out[..n], true);
    assert_eq!(rp_total, Some(2));
    let n = run(
        &mut fs,
        &mut state,
        &cm_request(0x04, Some(&subpara_rpidhash(&rp_hash)), &TOKEN),
        &mut out,
    )
    .unwrap();
    let (cu1, _, _, cred_total) = parse_cred(&out[..n], true);
    assert_eq!(cred_total, Some(2));

    // Interleave the Next calls: RP walk and credential walk advance independently.
    let n = run(&mut fs, &mut state, &cm_next(0x03), &mut out).unwrap();
    let (rp2, _, _) = parse_rp(&out[..n], false);
    let n = run(&mut fs, &mut state, &cm_next(0x05), &mut out).unwrap();
    let (cu2, _, _, _) = parse_cred(&out[..n], false);

    // Each walk returned two distinct entries — no cursor skipped or repeated.
    assert_ne!(rp1, rp2);
    assert_ne!(cu1, cu2);
    // Both are exhausted.
    assert_eq!(
        run(&mut fs, &mut state, &cm_next(0x03), &mut out),
        Err(CtapError::NotAllowed)
    );
    assert_eq!(
        run(&mut fs, &mut state, &cm_next(0x05), &mut out),
        Err(CtapError::NotAllowed)
    );
}

fn parse_cred(resp: &[u8], begin: bool) -> (std::vec::Vec<u8>, [u8; 32], [u8; 32], Option<u8>) {
    let mut d = Decoder::new(resp);
    let fields = d.map().unwrap().unwrap();
    // 6/7/8 [+9 on Begin] + 0x0A credProtect + 0x0C thirdPartyPayment (both
    // always emitted; 0x0A defaults to level 1 when the credential has none).
    assert_eq!(fields, if begin { 6 } else { 5 });
    // 0x06 user
    assert_eq!(d.u8().unwrap(), 6);
    let um = d.map().unwrap().unwrap();
    let mut uid = std::vec::Vec::new();
    for _ in 0..um {
        match d.str().unwrap() {
            "id" => uid = d.bytes().unwrap().to_vec(),
            _ => {
                d.skip().unwrap();
            }
        }
    }
    // 0x07 credentialId
    assert_eq!(d.u8().unwrap(), 7);
    d.skip().unwrap();
    // 0x08 publicKey (COSE EC2)
    assert_eq!(d.u8().unwrap(), 8);
    assert_eq!(d.map().unwrap().unwrap(), 5);
    d.u8().unwrap();
    d.u8().unwrap();
    d.u8().unwrap();
    d.i64().unwrap();
    d.i8().unwrap();
    d.u8().unwrap();
    d.i8().unwrap();
    let mut x = [0u8; 32];
    x.copy_from_slice(d.bytes().unwrap());
    d.i8().unwrap();
    let mut y = [0u8; 32];
    y.copy_from_slice(d.bytes().unwrap());
    let total = if begin {
        assert_eq!(d.u8().unwrap(), 9);
        Some(d.u8().unwrap())
    } else {
        None
    };
    (uid, x, y, total)
}

#[test]
fn enumerate_emits_extension_fields() {
    let (mut fs, mut rng) = setup();
    let rp_hash = sha256(b"example.com");

    // Register a resident credential with credProtect=3 + largeBlobKey.
    let mut buf = [0u8; 512];
    let req = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(6).unwrap();
        e.u8(1).unwrap().bytes(&CDH).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str("example.com")
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&[7, 7, 7, 7]).unwrap();
        e.str("name").unwrap().str("a").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(6).unwrap().map(2).unwrap();
        e.str("credProtect").unwrap().u64(3).unwrap();
        e.str("largeBlobKey").unwrap().bool(true).unwrap();
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
    let mut out = [0u8; 1024];
    {
        let mut state = FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 10,
        };
        make_credential(&mut ctx, &buf[..req], &mut out).unwrap();
    }

    // enumerateCredentialsBegin → response carries 0x0A/0x0B/0x0C.
    let mut state = armed(PERM_CM);
    let n = run(
        &mut fs,
        &mut state,
        &cm_request(0x04, Some(&subpara_rpidhash(&rp_hash)), &TOKEN),
        &mut out,
    )
    .unwrap();
    let mut d = Decoder::new(&out[..n]);
    let fields = d.map().unwrap().unwrap();
    let (mut cp, mut lbk, mut tpp) = (None, None, None);
    for _ in 0..fields {
        match d.u8().unwrap() {
            0x0A => cp = Some(d.u64().unwrap()),
            0x0B => lbk = Some(d.bytes().unwrap().to_vec()),
            0x0C => tpp = Some(d.bool().unwrap()),
            _ => {
                d.skip().unwrap();
            }
        }
    }
    assert_eq!(cp, Some(3), "credProtect");
    assert_eq!(tpp, Some(false), "thirdPartyPayment always emitted");
    // 0x0B is the derived largeBlobKey of the stored credential. A v2 resident
    // credential keys it off the stable resident id (rec[32..RECORD_PREFIX]), not
    // the box, so that prefix is the expected derivation input.
    let mut rec = [0u8; 1024];
    let _m = fs.read(EF_CRED, &mut rec).unwrap();
    let seed = crate::seed::load_keydev(&dev(), &mut fs).unwrap();
    let expected = derive_large_blob_key(&seed, &rec[32..RECORD_PREFIX]);
    assert_eq!(lbk.as_deref(), Some(&expected[..]));
}

#[test]
fn enumerate_defaults_cred_protect_to_level_one() {
    // A credential created without a credProtect extension still reports
    // credProtect = 1 (userVerificationOptional) — the field is always
    // present (conformance CredMgmt-EnumerateCredentials P-1).
    let (mut fs, mut rng) = setup();
    register(&mut fs, &mut rng, "example.com", &[5, 5], "dave");
    let rp_hash = sha256(b"example.com");
    let mut state = armed(PERM_CM);
    let mut out = [0u8; 512];
    let n = run(
        &mut fs,
        &mut state,
        &cm_request(0x04, Some(&subpara_rpidhash(&rp_hash)), &TOKEN),
        &mut out,
    )
    .unwrap();
    let mut d = Decoder::new(&out[..n]);
    let fields = d.map().unwrap().unwrap();
    let mut cp = None;
    for _ in 0..fields {
        match d.u8().unwrap() {
            0x0A => cp = Some(d.u64().unwrap()),
            _ => {
                d.skip().unwrap();
            }
        }
    }
    assert_eq!(cp, Some(1), "default credProtect is level 1");
}

#[test]
fn enumerate_credentials_requires_rpidhash() {
    let (mut fs, mut rng) = setup();
    register(&mut fs, &mut rng, "example.com", &[1, 1], "a");
    let mut state = armed(PERM_CM);
    let mut out = [0u8; 256];
    // 0x04 with no subCommandParams → MissingParameter.
    assert_eq!(
        run(
            &mut fs,
            &mut state,
            &cm_request(0x04, None, &TOKEN),
            &mut out
        ),
        Err(CtapError::MissingParameter)
    );
}

#[test]
fn delete_credential_drops_count_and_rp() {
    let (mut fs, mut rng) = setup();
    let (id_a, ..) = register(&mut fs, &mut rng, "example.com", &[1, 1], "alice");
    register(&mut fs, &mut rng, "example.com", &[2, 2], "bob");
    register(&mut fs, &mut rng, "other.com", &[3, 3], "carol");
    let mut state = armed(PERM_CM);
    let mut out = [0u8; 256];

    // Delete alice → metadata count 3 → 2, example.com RP still present (bob remains).
    let n = run(
        &mut fs,
        &mut state,
        &cm_request(0x06, Some(&subpara_cred(&id_a)), &TOKEN),
        &mut out,
    )
    .unwrap();
    assert_eq!(n, 0);
    assert_eq!(metadata_count(&mut fs, &mut state), 2);
    assert!(rp_present(&mut fs, &mut state, &sha256(b"example.com")));

    // Delete carol (sole cred for other.com) → its RP record disappears. Look
    // her up by enumerating other.com (we did not capture her id at register).
    let other = sha256(b"other.com");
    let n = run(
        &mut fs,
        &mut state,
        &cm_request(0x04, Some(&subpara_rpidhash(&other)), &TOKEN),
        &mut out,
    )
    .unwrap();
    let mut d = Decoder::new(&out[..n]);
    d.map().unwrap();
    d.u8().unwrap();
    d.skip().unwrap(); // user
    d.u8().unwrap(); // 7
    d.map().unwrap();
    assert_eq!(d.str().unwrap(), "id");
    let carol_id = d.bytes().unwrap().to_vec();
    run(
        &mut fs,
        &mut state,
        &cm_request(0x06, Some(&subpara_cred(&carol_id)), &TOKEN),
        &mut out,
    )
    .unwrap();
    assert!(!rp_present(&mut fs, &mut state, &other));
}

#[test]
fn delete_unknown_credential_is_no_credentials() {
    let (mut fs, mut rng) = setup();
    register(&mut fs, &mut rng, "example.com", &[1, 1], "a");
    let mut state = armed(PERM_CM);
    let mut out = [0u8; 256];
    let bogus = [0u8; CRED_RESIDENT_LEN];
    assert_eq!(
        run(
            &mut fs,
            &mut state,
            &cm_request(0x06, Some(&subpara_cred(&bogus)), &TOKEN),
            &mut out
        ),
        Err(CtapError::NoCredentials)
    );
}

#[test]
fn update_user_changes_name() {
    let (mut fs, mut rng) = setup();
    let (id_a, ..) = register(&mut fs, &mut rng, "example.com", &[1, 1], "alice");
    let mut state = armed(PERM_CM);
    let mut out = [0u8; 512];

    // Update alice's name (same user id).
    let n = run(
        &mut fs,
        &mut state,
        &cm_request(
            0x07,
            Some(&subpara_update(&id_a, &[1, 1], "alice2", "Alice Two")),
            &TOKEN,
        ),
        &mut out,
    )
    .unwrap();
    assert_eq!(n, 0);

    // Re-enumerate: still one cred for the rp, with the new name.
    let rp_hash = sha256(b"example.com");
    let n = run(
        &mut fs,
        &mut state,
        &cm_request(0x04, Some(&subpara_rpidhash(&rp_hash)), &TOKEN),
        &mut out,
    )
    .unwrap();
    let name = cred_user_name(&out[..n]);
    assert_eq!(name, "alice2");
}

#[test]
fn update_user_id_mismatch_rejected() {
    let (mut fs, mut rng) = setup();
    let (id_a, ..) = register(&mut fs, &mut rng, "example.com", &[1, 1], "alice");
    let mut state = armed(PERM_CM);
    let mut out = [0u8; 256];
    // A wrong user id → InvalidParameter. The credential's id is [1, 1], so
    // this also pins that a PREFIX ([1]) and the EMPTY id no longer match
    // (they did under the old min-length compare).
    for wrong in [&[9, 9][..], &[1][..], &[][..]] {
        assert_eq!(
            run(
                &mut fs,
                &mut state,
                &cm_request(0x07, Some(&subpara_update(&id_a, wrong, "x", "y")), &TOKEN),
                &mut out
            ),
            Err(CtapError::InvalidParameter),
            "user id {wrong:?} must be rejected"
        );
    }
}

#[test]
fn update_preserves_credential_id_then_deletes() {
    // CTAP2.1 §6.8.5: updateUserInformation must NOT change the credentialId.
    // Regression for conformance CredMgmt-UpdateAndDelete P-2 — the reseal used
    // to rotate the stored resident id, so a later deleteCredential with the
    // platform's (original) id returned NO_CREDENTIALS.
    let (mut fs, mut rng) = setup();
    let (id, ..) = register(&mut fs, &mut rng, "example.com", &[1, 1], "alice");
    let mut state = armed(PERM_CM);
    let mut out = [0u8; 512];
    let rp_hash = sha256(b"example.com");

    // Update the user info (same user id, new name + displayName).
    run(
        &mut fs,
        &mut state,
        &cm_request(
            0x07,
            Some(&subpara_update(&id, &[1, 1], "alice2", "Alice Two")),
            &TOKEN,
        ),
        &mut out,
    )
    .unwrap();

    // enumerateCredentials still reports the SAME credentialId (and new name).
    let n = run(
        &mut fs,
        &mut state,
        &cm_request(0x04, Some(&subpara_rpidhash(&rp_hash)), &TOKEN),
        &mut out,
    )
    .unwrap();
    assert_eq!(
        enumerated_cred_id(&out[..n]),
        id,
        "credentialId must be stable across update"
    );
    assert_eq!(cred_user_name(&out[..n]), "alice2");

    // deleteCredential with the ORIGINAL id now succeeds (was NO_CREDENTIALS).
    let n = run(
        &mut fs,
        &mut state,
        &cm_request(0x06, Some(&subpara_cred(&id)), &TOKEN),
        &mut out,
    )
    .unwrap();
    assert_eq!(n, 0);
    assert_eq!(metadata_count(&mut fs, &mut state), 0);
}

// The credentialId (response field 0x07 "id") from an enumerateCredentials
// response, read order-independently.
fn enumerated_cred_id(resp: &[u8]) -> std::vec::Vec<u8> {
    let mut d = Decoder::new(resp);
    let fields = d.map().unwrap().unwrap();
    let mut id = std::vec::Vec::new();
    for _ in 0..fields {
        if d.u8().unwrap() == 7 {
            let m = d.map().unwrap().unwrap();
            for _ in 0..m {
                match d.str().unwrap() {
                    "id" => id = d.bytes().unwrap().to_vec(),
                    _ => {
                        d.skip().unwrap();
                    }
                }
            }
        } else {
            d.skip().unwrap();
        }
    }
    id
}

fn cred_user_name(resp: &[u8]) -> std::string::String {
    let mut d = Decoder::new(resp);
    d.map().unwrap();
    assert_eq!(d.u8().unwrap(), 6);
    let um = d.map().unwrap().unwrap();
    let mut name = std::string::String::new();
    for _ in 0..um {
        match d.str().unwrap() {
            "name" => name = d.str().unwrap().to_string(),
            "id" => {
                d.bytes().unwrap();
            }
            _ => {
                d.skip().unwrap();
            }
        }
    }
    name
}

fn metadata_count(fs: &mut Fs<RamStorage>, state: &mut FidoState) -> u16 {
    let mut out = [0u8; 64];
    let n = run(fs, state, &cm_request(0x01, None, &TOKEN), &mut out).unwrap();
    let mut d = Decoder::new(&out[..n]);
    d.map().unwrap();
    d.u8().unwrap();
    d.u16().unwrap()
}

fn rp_present(fs: &mut Fs<RamStorage>, state: &mut FidoState, rp_hash: &[u8; 32]) -> bool {
    let mut out = [0u8; 256];
    run(
        fs,
        state,
        &cm_request(0x04, Some(&subpara_rpidhash(rp_hash)), &TOKEN),
        &mut out,
    )
    .is_ok()
}

#[test]
fn missing_param_is_puat_required() {
    let mut fs = Fs::new(RamStorage::new());
    let mut state = armed(PERM_CM);
    let mut out = [0u8; 64];
    // {1: 1} — getCredsMetadata with no pinUvAuthParam.
    assert_eq!(
        run(&mut fs, &mut state, &[0xA1, 0x01, 0x01], &mut out),
        Err(CtapError::PuatRequired)
    );
}

#[test]
fn bad_mac_rejected() {
    let (mut fs, mut rng) = setup();
    register(&mut fs, &mut rng, "example.com", &[1, 1], "a");
    let mut state = armed(PERM_CM);
    let mut out = [0u8; 64];
    // MAC under the wrong token → PinAuthInvalid.
    assert_eq!(
        run(
            &mut fs,
            &mut state,
            &cm_request(0x01, None, &[0x11; 32]),
            &mut out
        ),
        Err(CtapError::PinAuthInvalid)
    );
}

#[test]
fn without_cm_permission_rejected() {
    let (mut fs, mut rng) = setup();
    register(&mut fs, &mut rng, "example.com", &[1, 1], "a");
    // A token without the cm permission.
    let mut state = armed(crate::state::PERM_MC);
    let mut out = [0u8; 64];
    assert_eq!(
        run(
            &mut fs,
            &mut state,
            &cm_request(0x01, None, &TOKEN),
            &mut out
        ),
        Err(CtapError::PinAuthInvalid)
    );
}

#[test]
fn enumerate_rps_empty_is_no_credentials() {
    let (mut fs, _rng) = setup();
    let mut state = armed(PERM_CM);
    let mut out = [0u8; 64];
    assert_eq!(
        run(
            &mut fs,
            &mut state,
            &cm_request(0x02, None, &TOKEN),
            &mut out
        ),
        Err(CtapError::NoCredentials)
    );
}

#[test]
fn get_next_without_begin_is_not_allowed() {
    let (mut fs, mut rng) = setup();
    register(&mut fs, &mut rng, "example.com", &[1, 1], "a");
    let mut state = armed(PERM_CM);
    let mut out = [0u8; 64];
    // getNextRP / getNextCredential with no prior Begin → NotAllowed.
    assert_eq!(
        run(&mut fs, &mut state, &cm_next(0x03), &mut out),
        Err(CtapError::NotAllowed)
    );
    assert_eq!(
        run(&mut fs, &mut state, &cm_next(0x05), &mut out),
        Err(CtapError::NotAllowed)
    );
}

// Does any live EF_RP record contain `needle` in its raw at-rest bytes?
fn rp_flash_has(fs: &mut Fs<RamStorage>, needle: &[u8]) -> bool {
    let mut occupied = [false; MAX_RESIDENT_CREDENTIALS as usize];
    slot_map(fs, EF_RP, &mut occupied);
    let mut buf = [0u8; 256];
    for i in 0..MAX_RESIDENT_CREDENTIALS {
        if !occupied[i as usize] {
            continue;
        }
        if let Some(n) = fs.read(EF_RP + i, &mut buf) {
            let n = n.min(buf.len());
            if buf[..n].windows(needle.len()).any(|w| w == needle) {
                return true;
            }
        }
    }
    false
}

#[test]
fn rp_domain_sealed_on_flash() {
    let (mut fs, mut rng) = setup();
    register(&mut fs, &mut rng, "example.com", &[1, 1], "alice");
    // The rpId domain must not survive in cleartext in the EF_RP record...
    assert!(
        !rp_flash_has(&mut fs, b"example.com"),
        "rpId domain leaked in cleartext on flash"
    );
    // ...but enumerateRPs still round-trips it to the host.
    let mut state = armed(PERM_CM);
    let mut out = [0u8; 256];
    let n = run(
        &mut fs,
        &mut state,
        &cm_request(0x02, None, &TOKEN),
        &mut out,
    )
    .unwrap();
    let (id, hash, _) = parse_rp(&out[..n], true);
    assert_eq!(id, "example.com");
    assert_eq!(hash, sha256(b"example.com"));
}

#[test]
fn legacy_plaintext_rp_migrates_and_stays_usable() {
    let (mut fs, _rng) = setup();
    // A pre-migration EF_RP record: count(1) ‖ rpIdHash(32) ‖ cleartext domain.
    let hash = sha256(b"example.com");
    let mut rec = std::vec::Vec::new();
    rec.push(1u8);
    rec.extend_from_slice(&hash);
    rec.extend_from_slice(b"example.com");
    fs.put(EF_RP, &rec).unwrap();
    assert!(rp_flash_has(&mut fs, b"example.com"));

    // Boot migration boxes the cleartext domain in place.
    crate::credential::migrate_rp_seal(&dev(), &mut fs);
    assert!(
        !rp_flash_has(&mut fs, b"example.com"),
        "migration left the rpId domain in cleartext"
    );
    // The count byte survives the re-box.
    let mut buf = [0u8; 256];
    let n = fs.read(EF_RP, &mut buf).unwrap();
    assert_eq!(buf[0], 1);
    assert_eq!(buf[1..RP_PREFIX], hash[..]);

    // enumerateRPs still recovers the original domain.
    let mut state = armed(PERM_CM);
    let mut out = [0u8; 256];
    let n2 = run(
        &mut fs,
        &mut state,
        &cm_request(0x02, None, &TOKEN),
        &mut out,
    )
    .unwrap();
    let (id, h, _) = parse_rp(&out[..n2], true);
    assert_eq!(id, "example.com");
    assert_eq!(h, hash);

    // Idempotent: a second pass is a no-op and the record stays usable.
    let before = buf[..n.min(buf.len())].to_vec();
    crate::credential::migrate_rp_seal(&dev(), &mut fs);
    let m = fs.read(EF_RP, &mut buf).unwrap();
    assert_eq!(
        &buf[..m.min(buf.len())],
        &before[..],
        "migration not idempotent"
    );
}

// updateUserInformation must reseal a ceiling-sized box. The registered box
// (195-byte rpId, 64-byte uid, max credBlob — sized so the UPDATED box stays
// inside CRED_BOX_MAX) plus 64-byte updated names crosses the OLD 512-byte
// reseal buffer — updates on such credentials used to fail NotAllowed while
// smaller ones worked.
#[test]
fn update_user_reseals_near_ceiling_box() {
    let (mut fs, mut rng) = setup();
    let rp = "a".repeat(191) + ".com";
    let uid = [0x42u8; 64];

    // Resident makeCredential with a credBlob (register() has no ext support).
    let mut buf = [0u8; 1024];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(6).unwrap();
        e.u8(1).unwrap().bytes(&CDH).unwrap();
        e.u8(2).unwrap().map(1).unwrap();
        e.str("id").unwrap().str(&rp).unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&uid).unwrap();
        e.str("name").unwrap().str("a").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(6).unwrap().map(1).unwrap();
        e.str("credBlob").unwrap().bytes(&[0x5A; 127]).unwrap();
        e.u8(7).unwrap().map(1).unwrap();
        e.str("rk").unwrap().bool(true).unwrap();
        e.writer().position()
    };
    let mut out = [0u8; 2048];
    let mut state = FidoState::new();
    let id_a = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 10,
        };
        let n = make_credential(&mut ctx, &buf[..n], &mut out).unwrap();
        parse_mc(&out[..n]).0
    };

    // A MAXIMAL legal update — 64-byte name/displayName alongside the 64-byte
    // uid and 42-byte credId: the resealed box exceeds 512 AND the raw
    // subCommandParams exceed the old 256-byte MAX_RAW_SUBPARA (which rejected
    // exactly this request with RequestTooLarge).
    let new_name = "u".repeat(64);
    let mut sp = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut sp[..]));
        e.map(2).unwrap();
        e.u8(2).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&id_a).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(3).unwrap().map(3).unwrap();
        e.str("id").unwrap().bytes(&uid).unwrap();
        e.str("name").unwrap().str(&new_name).unwrap();
        e.str("displayName").unwrap().str(&new_name).unwrap();
        e.writer().position()
    };
    let subpara = sp[..n].to_vec();
    assert!(
        subpara.len() > 256 && subpara.len() <= MAX_RAW_SUBPARA,
        "subpara must cross the old cap (len {})",
        subpara.len()
    );

    let mut state = armed(PERM_CM);
    let mut out = [0u8; 1024];
    let n = run(
        &mut fs,
        &mut state,
        &cm_request(0x07, Some(&subpara), &TOKEN),
        &mut out,
    )
    .unwrap();
    assert_eq!(n, 0);

    // Re-enumerate: the credential carries the updated name.
    let rp_hash = sha256(rp.as_bytes());
    let n = run(
        &mut fs,
        &mut state,
        &cm_request(0x04, Some(&subpara_rpidhash(&rp_hash)), &TOKEN),
        &mut out,
    )
    .unwrap();
    assert_eq!(cred_user_name(&out[..n]), new_name);
}

// A resident credential at the DNS rpId ceiling (253 bytes). Its EF_RP
// bookkeeping record is RP_PREFIX + iv + rpId + tag = 314 bytes — the old
// RP_REC_MAX = 256 failed this create with KeyStoreFull while the same rpId
// registered fine non-resident. enumerateRPs proves the record (and its boxed
// rpId) round-trips.
#[test]
fn resident_rp_id_at_dns_max_registers() {
    let (mut fs, mut rng) = setup();
    let rp = "a".repeat(249) + ".com";
    register(&mut fs, &mut rng, &rp, &[7, 7], "ceil");

    let mut state = armed(PERM_CM);
    let mut out = [0u8; 512];
    let n = run(
        &mut fs,
        &mut state,
        &cm_request(0x02, None, &TOKEN),
        &mut out,
    )
    .unwrap();
    let (id, hash, total) = parse_rp(&out[..n], true);
    assert_eq!(id, rp);
    assert_eq!(hash, sha256(rp.as_bytes()));
    assert_eq!(total, Some(1));
}

// updateUserInformation on the MAXIMAL box: a resident cred at DNS-max rpId
// with a 127-byte credBlob and EMPTY names creates small, then a 64+64-byte
// name update reseals it to ~670-748 bytes. This is the case the old 640
// reseal buffer rejected (NotAllowed) even though create succeeded.
#[test]
fn update_user_reseals_maximal_box() {
    let (mut fs, mut rng) = setup();
    let rp = "a".repeat(249) + ".com"; // 253, DNS max
    let uid = [0x42u8; 64];

    let mut buf = [0u8; 1024];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(6).unwrap();
        e.u8(1).unwrap().bytes(&CDH).unwrap();
        e.u8(2).unwrap().map(1).unwrap();
        e.str("id").unwrap().str(&rp).unwrap();
        e.u8(3).unwrap().map(1).unwrap();
        e.str("id").unwrap().bytes(&uid).unwrap(); // no name → small create box
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(6).unwrap().map(1).unwrap();
        e.str("credBlob").unwrap().bytes(&[0x5A; 127]).unwrap();
        e.u8(7).unwrap().map(1).unwrap();
        e.str("rk").unwrap().bool(true).unwrap();
        e.writer().position()
    };
    let mut out = [0u8; 2048];
    let mut state = FidoState::new();
    let id_a = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 10,
        };
        let n = make_credential(&mut ctx, &buf[..n], &mut out).unwrap();
        parse_mc(&out[..n]).0
    };

    let new_name = "u".repeat(64);
    let mut sp = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut sp[..]));
        e.map(2).unwrap();
        e.u8(2).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&id_a).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(3).unwrap().map(3).unwrap();
        e.str("id").unwrap().bytes(&uid).unwrap();
        e.str("name").unwrap().str(&new_name).unwrap();
        e.str("displayName").unwrap().str(&new_name).unwrap();
        e.writer().position()
    };
    let subpara = sp[..n].to_vec();

    let mut state = armed(PERM_CM);
    let mut out = [0u8; 1024];
    let n = run(
        &mut fs,
        &mut state,
        &cm_request(0x07, Some(&subpara), &TOKEN),
        &mut out,
    )
    .unwrap();
    assert_eq!(n, 0);

    let rp_hash = sha256(rp.as_bytes());
    let n = run(
        &mut fs,
        &mut state,
        &cm_request(0x04, Some(&subpara_rpidhash(&rp_hash)), &TOKEN),
        &mut out,
    )
    .unwrap();
    assert_eq!(cred_user_name(&out[..n]), new_name);
}

// A getAssertion over allowList=[id] must sign authData‖clientDataHash under the
// ECDSA public key (x, y). Proves the signing key is the one makeCredential
// issued — used before AND after an updateUserInformation reseal.
fn assert_ga_signs_under(fs: &mut Fs<RamStorage>, id: &[u8], x: &[u8; 32], y: &[u8; 32]) {
    use p256::Sec1Point;
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    let mut buf = [0u8; 256];
    let req = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(3).unwrap();
        e.u8(1).unwrap().str("example.com").unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(3).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.str("id").unwrap().bytes(id).unwrap();
        e.writer().position()
    };
    let mut out = [0u8; 1024];
    let mut st = FidoState::new();
    let mut rng = SeqRng(7);
    let n = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs,
            rng: &mut rng,
            state: &mut st,
            now_ms: 20,
        };
        crate::getassertion::get_assertion(&mut ctx, &buf[..req], &mut out).unwrap()
    };
    let mut d = Decoder::new(&out[..n]);
    d.map().unwrap();
    assert_eq!(d.u8().unwrap(), 1);
    d.skip().unwrap(); // {id, type}
    assert_eq!(d.u8().unwrap(), 2);
    let ad = d.bytes().unwrap().to_vec();
    assert_eq!(d.u8().unwrap(), 3);
    let sig = d.bytes().unwrap().to_vec();
    let pt = Sec1Point::from_bytes(&crate::ec::sec1_uncompressed(x, y)).unwrap();
    let vk = VerifyingKey::from_sec1_point(&pt).unwrap();
    let mut signed = ad;
    signed.extend_from_slice(&CDH);
    vk.verify(&signed, &Signature::from_der(&sig).unwrap())
        .expect("assertion verifies under the original credential key");
}

// The largeBlobKey (enumerate field 0x0B) of an enumerateCredentials response.
fn enum_largeblobkey(resp: &[u8]) -> Option<std::vec::Vec<u8>> {
    let mut d = Decoder::new(resp);
    let fields = d.map().unwrap().unwrap();
    let mut lbk = None;
    for _ in 0..fields {
        if d.u8().unwrap() == 0x0B {
            lbk = Some(d.bytes().unwrap().to_vec());
        } else {
            d.skip().unwrap();
        }
    }
    lbk
}

// #3 end to end: updateUserInformation used to reseal the box and rotate its
// box-derived signing key, so the RP's stored pubkey stopped verifying. v2
// credentials key off the stable resident id — makeCredential's pubkey,
// enumerateCredentials' pubkey and getAssertion's signing key all stay put across
// the reseal.
#[test]
fn update_preserves_signing_key_end_to_end() {
    let (mut fs, mut rng) = setup();
    let (id, x, y) = register(&mut fs, &mut rng, "example.com", &[1, 1], "alice");
    assert_ne!(
        &id[4..8],
        b"\xf1\xd0\x02\x03",
        "new resident id is prefix-free v4"
    );
    let rp_hash = sha256(b"example.com");

    // Before the update, getAssertion already signs under the registered key.
    assert_ga_signs_under(&mut fs, &id, &x, &y);

    // updateUserInformation reseals the box (fresh IV → new box).
    let mut state = armed(PERM_CM);
    let mut out = [0u8; 512];
    run(
        &mut fs,
        &mut state,
        &cm_request(
            0x07,
            Some(&subpara_update(&id, &[1, 1], "alice2", "Alice Two")),
            &TOKEN,
        ),
        &mut out,
    )
    .unwrap();

    // enumerateCredentials reports the SAME pubkey after the reseal.
    let n = run(
        &mut fs,
        &mut state,
        &cm_request(0x04, Some(&subpara_rpidhash(&rp_hash)), &TOKEN),
        &mut out,
    )
    .unwrap();
    let (_uid, x2, y2, _t) = parse_cred(&out[..n], true);
    assert_eq!((x2, y2), (x, y), "enumerate pubkey stable across update");

    // And getAssertion STILL signs under the original key (the actual fix).
    assert_ga_signs_under(&mut fs, &id, &x, &y);
}

// The largeBlobKey likewise survives the reseal (v2 keys off the stable id).
#[test]
fn update_preserves_largeblobkey() {
    let (mut fs, mut rng) = setup();
    let rp_hash = sha256(b"example.com");
    // register() offers no extensions, so build a resident cred with largeBlobKey.
    let mut buf = [0u8; 512];
    let req = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(6).unwrap();
        e.u8(1).unwrap().bytes(&CDH).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str("example.com")
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&[8, 8]).unwrap();
        e.str("name").unwrap().str("a").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(6).unwrap().map(1).unwrap();
        e.str("largeBlobKey").unwrap().bool(true).unwrap();
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
    let mut out = [0u8; 1024];
    {
        let mut state = FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 10,
        };
        make_credential(&mut ctx, &buf[..req], &mut out).unwrap();
    }
    let mut state = armed(PERM_CM);

    // enumerate → capture id + largeBlobKey (0x0B).
    let n = run(
        &mut fs,
        &mut state,
        &cm_request(0x04, Some(&subpara_rpidhash(&rp_hash)), &TOKEN),
        &mut out,
    )
    .unwrap();
    let id = enumerated_cred_id(&out[..n]);
    let lbk0 = enum_largeblobkey(&out[..n]);
    assert!(lbk0.is_some(), "largeBlobKey present");

    // updateUserInformation, then re-enumerate: same largeBlobKey.
    run(
        &mut fs,
        &mut state,
        &cm_request(
            0x07,
            Some(&subpara_update(&id, &[8, 8], "a2", "A Two")),
            &TOKEN,
        ),
        &mut out,
    )
    .unwrap();
    let n = run(
        &mut fs,
        &mut state,
        &cm_request(0x04, Some(&subpara_rpidhash(&rp_hash)), &TOKEN),
        &mut out,
    )
    .unwrap();
    let lbk1 = enum_largeblobkey(&out[..n]);
    assert_eq!(
        lbk0, lbk1,
        "largeBlobKey stable across updateUserInformation"
    );
}

// ---- enumerateCredentials RP index (slot→rpId-hash-prefix fast path) ----

/// A `Storage` that counts `read` calls, so a test can assert the enumeration
/// reads the store O(creds) times, not O(rps·creds).
struct CountingStorage {
    inner: RamStorage,
    reads: std::rc::Rc<std::cell::Cell<usize>>,
}
impl Storage for CountingStorage {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.reads.set(self.reads.get() + 1);
        self.inner.read(fid, buf)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
        self.inner.write(fid, data)
    }
    fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
        self.inner.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.inner.size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(f)
    }
}

fn register_into<S: Storage>(fs: &mut Fs<S>, rng: &mut SeqRng, rp: &str, uid: &[u8], name: &str) {
    let mut out = [0u8; 1024];
    let mut state = FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs,
        rng,
        state: &mut state,
        now_ms: 10,
    };
    make_credential(&mut ctx, &mc_request(rp, uid, name), &mut out).unwrap();
}

fn run_into<S: Storage>(
    fs: &mut Fs<S>,
    state: &mut FidoState,
    req: &[u8],
    out: &mut [u8],
) -> CtapResult {
    let mut rng = SeqRng(7);
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs,
        rng: &mut rng,
        state,
        now_ms: 100,
    };
    cred_mgmt(&mut ctx, req, out)
}

#[test]
fn enumerate_credentials_many_distinct_rps_each_returns_its_own() {
    // The worst case for the index: N distinct rps, one credential each. Every
    // credential must still be found exactly once under its own rp.
    let (mut fs, mut rng) = setup();
    const N: usize = 40;
    let mut hashes = std::vec::Vec::new();
    for i in 0..N {
        let rp = std::format!("rp{i:04}.example");
        register(&mut fs, &mut rng, &rp, &[i as u8, 0], "u");
        hashes.push(sha256(rp.as_bytes()));
    }
    let mut state = armed(PERM_CM);
    let mut out = [0u8; 512];
    for h in &hashes {
        let n = run(
            &mut fs,
            &mut state,
            &cm_request(0x04, Some(&subpara_rpidhash(h)), &TOKEN),
            &mut out,
        )
        .unwrap();
        assert_eq!(parse_cred(&out[..n], true).3, Some(1));
        // Exactly one credential for this rp — no next.
        assert_eq!(
            run(&mut fs, &mut state, &cm_next(0x05), &mut out),
            Err(CtapError::NotAllowed)
        );
    }
}

#[test]
fn enumerate_credentials_index_refreshes_after_a_write() {
    // A credential added AFTER the index was built (in a prior enumerate) must be
    // found — `Fs::write_gen` has to invalidate the cached index.
    let (mut fs, mut rng) = setup();
    register(&mut fs, &mut rng, "aaa.example", &[1], "a");
    register(&mut fs, &mut rng, "bbb.example", &[2], "b");
    let mut state = armed(PERM_CM);
    let mut out = [0u8; 512];
    let h_aaa = sha256(b"aaa.example");
    // Build the index by enumerating aaa.
    let n = run(
        &mut fs,
        &mut state,
        &cm_request(0x04, Some(&subpara_rpidhash(&h_aaa)), &TOKEN),
        &mut out,
    )
    .unwrap();
    assert_eq!(parse_cred(&out[..n], true).3, Some(1));

    // New rp added after the index was built → must be visible.
    register(&mut fs, &mut rng, "ccc.example", &[3], "c");
    let h_ccc = sha256(b"ccc.example");
    let n = run(
        &mut fs,
        &mut state,
        &cm_request(0x04, Some(&subpara_rpidhash(&h_ccc)), &TOKEN),
        &mut out,
    )
    .unwrap();
    assert_eq!(
        parse_cred(&out[..n], true).3,
        Some(1),
        "credential added after the index was built must be found"
    );

    // A second credential under an existing rp bumps that rp's count.
    register(&mut fs, &mut rng, "aaa.example", &[9], "a2");
    let n = run(
        &mut fs,
        &mut state,
        &cm_request(0x04, Some(&subpara_rpidhash(&h_aaa)), &TOKEN),
        &mut out,
    )
    .unwrap();
    assert_eq!(parse_cred(&out[..n], true).3, Some(2));
}

#[test]
fn enumerate_credentials_reads_are_linear_not_quadratic() {
    // N distinct rps × 1 credential. With the index the store is read ~O(N) times
    // (one build pass + one confirmed read per rp); the pre-index code re-read all
    // N slots on each of the N per-rp Begins, i.e. ~N² reads.
    let reads = std::rc::Rc::new(std::cell::Cell::new(0usize));
    let mut fs = Fs::new(CountingStorage {
        inner: RamStorage::new(),
        reads: reads.clone(),
    });
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    const N: usize = 32;
    let mut hashes = std::vec::Vec::new();
    for i in 0..N {
        let rp = std::format!("rp{i:04}.example");
        register_into(&mut fs, &mut rng, &rp, &[i as u8, 0], "u");
        hashes.push(sha256(rp.as_bytes()));
    }
    let mut state = armed(PERM_CM);
    let mut out = [0u8; 512];
    reads.set(0);
    for h in &hashes {
        run_into(
            &mut fs,
            &mut state,
            &cm_request(0x04, Some(&subpara_rpidhash(h)), &TOKEN),
            &mut out,
        )
        .unwrap();
    }
    let total = reads.get();
    assert!(
        total <= 8 * N,
        "enumerateCredentials read the store {total} times for N={N} rps; \
         expected ~O(N), quadratic (pre-index) would be ~{}",
        N * N
    );
}
