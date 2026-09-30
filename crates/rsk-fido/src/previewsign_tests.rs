// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::consts::{
    ALG_EDDSA, ALG_MLDSA44, ALG_MLDSA65, ALG_MLDSA87, EF_PIN, FLAG_AT, FLAG_ED, MAX_MSG_SIZE,
};
use crate::getassertion::get_assertion;
use crate::makecredential::make_credential;
use crate::seed::{ensure_seed, load_keydev};
use crate::state::PERM_GA;
use crate::tests::unhex;
use crate::{AlwaysConfirm, Confirm, Ctx, FidoState, Presence, UserPresence};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use rsk_crypto::Device;
use rsk_crypto::pinproto::PinProto;
use rsk_crypto::sha256;
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;
use std::string::{String, ToString};
use std::vec::Vec;

struct SeqRng(u64);
impl Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

/// Counts what it is asked and the titles it is shown, and answers each ask the
/// same way.
struct Button {
    asked: u32,
    titles: Vec<&'static str>,
    answer: Presence,
}

impl Button {
    fn touching() -> Self {
        Self {
            asked: 0,
            titles: Vec::new(),
            answer: Presence::Confirmed,
        }
    }
    fn untouched() -> Self {
        Self {
            asked: 0,
            titles: Vec::new(),
            answer: Presence::Timeout,
        }
    }
}

impl UserPresence for Button {
    fn request(&mut self, confirm: Confirm<'_>) -> Presence {
        self.asked += 1;
        self.titles.push(confirm.title);
        self.answer
    }
}

const CDH: [u8; 32] = [0xCD; 32];
const RP: &str = "example.com";
/// What python-fido2's device tests offer: every algorithm the draft's prototypes
/// named, ESP256-split-ARKG among them.
const ALL_ALGORITHMS: [i64; 5] = [-9, -7, -300, -70009, ALG_ESP256_SPLIT_ARKG];
/// python-fido2 2.2.1's ctx in its v4 device test.
const RT_CTX: &[u8] = b"python-fido2.test_sign_extension_v4";
const MESSAGE: &[u8] = b"test message";

// The seed this fixed device mints first, and what python-fido2 2.2.1's
// `derive_public_key` makes of it for `RT_CTX` (scratch `gen_vectors.py`): the ARKG
// handle, the derived key, and the client's COSE_Sign_Args, byte for byte.
const RT_PK_BL: &str = "0449bb35a31c33f62de9527d6aa842b8f7877116b90c31470ba765baad8cf643464fab1f40cd166528e694e92f23d0fd8910cb1d891a0383888c0df9ad02a906bb";
const RT_PK_KEM: &str = "048096b2a6e706f714e50ad58735307d7182f486165eecf87f88077331c5a54e79b14a63674c32c81e7794e2805122a3a0e8494a3ac6eb47fcb7190bcd73f42bb9";
const RT_ARKG_KH: &str = "745807f40acb58beedb662e2054c51a70401cf15be2b7a19eab0fce157a7dd98362ab887d453e80d415f24c9f20ad9428c76672277be93cebc3503d892ce46e5e756e1b227a4c2be36ce8c030592f4c0a1";
const RT_PK_PRIME: &str = "04e877a3c7fceec18ebe241617c2a1a3a1fb82684b65b1d3d854d475b7d4810e0c8705ae96afc9dedcb090760d7f58f088f4ddcb6de247fc7f1a7c76b05bd5bd42";
const RT_ARGS: &str = "a3033a00010002205851745807f40acb58beedb662e2054c51a70401cf15be2b7a19eab0fce157a7dd98362ab887d453e80d415f24c9f20ad9428c76672277be93cebc3503d892ce46e5e756e1b227a4c2be36ce8c030592f4c0a1215823707974686f6e2d6669646f322e746573745f7369676e5f657874656e73696f6e5f7634";
/// python-fido2's own CBOR of that seed as an `ARKG_P256_PLACEHOLDER` key — the
/// shape its tests build, with every COSE id the draft placeholders.
const RT_SEED_COSE: &str = "a5013a00010000033a000100a320a501020326200121582049bb35a31c33f62de9527d6aa842b8f7877116b90c31470ba765baad8cf643462258204fab1f40cd166528e694e92f23d0fd8910cb1d891a0383888c0df9ad02a906bb21a5010203381820012158208096b2a6e706f714e50ad58735307d7182f486165eecf87f88077331c5a54e79225820b14a63674c32c81e7794e2805122a3a0e8494a3ac6eb47fcb7190bcd73f42bb92228";

fn dev() -> Device<'static> {
    Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
        latched: false,
    }
}

type Enc<'b> = Encoder<Cursor<&'b mut [u8]>>;

/// Whatever `f` encodes.
fn enc(f: impl FnOnce(&mut Enc<'_>)) -> Vec<u8> {
    let mut buf = std::vec![0u8; 4096];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        f(&mut e);
        e.writer().position()
    };
    buf.truncate(n);
    buf
}

/// A device with a seed, kept across its commands.
struct Board {
    fs: Fs<RamStorage>,
    rng: SeqRng,
    state: FidoState,
    now_ms: u64,
}

impl Board {
    fn new() -> Self {
        let mut fs = Fs::new(RamStorage::new());
        crate::tests::uv_optional(&mut fs);
        let mut rng = SeqRng(1);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        Self {
            fs,
            rng,
            state: FidoState::new(),
            now_ms: 1000,
        }
    }

    fn run(
        &mut self,
        mc: bool,
        req: &[u8],
        presence: &mut dyn UserPresence,
    ) -> Result<Vec<u8>, CtapError> {
        let mut out = std::vec![0u8; MAX_MSG_SIZE as usize];
        self.now_ms += 10;
        let mut ctx = Ctx {
            dev: dev(),
            fs: &mut self.fs,
            rng: &mut self.rng,
            state: &mut self.state,
            now_ms: self.now_ms,
            presence,
        };
        let n = if mc {
            make_credential(&mut ctx, req, &mut out)?
        } else {
            get_assertion(&mut ctx, req, &mut out)?
        };
        out.truncate(n);
        Ok(out)
    }

    fn mc(&mut self, req: &[u8]) -> Result<Vec<u8>, CtapError> {
        self.run(true, req, &mut AlwaysConfirm)
    }

    fn ga(&mut self, req: &[u8]) -> Result<Vec<u8>, CtapError> {
        self.run(false, req, &mut AlwaysConfirm)
    }

    /// A PIN, and a live token with the getAssertion permission; returns the token.
    fn arm_pin(&mut self) -> [u8; 32] {
        let mut pin_file = [0u8; 35];
        pin_file[..3].copy_from_slice(&[8, 4, 1]);
        self.fs.put(EF_PIN, &pin_file).unwrap();
        let token = [0x99u8; 32];
        self.state.paut.token = token;
        self.state.paut.permissions = PERM_GA;
        self.state.begin_using_token(false, self.now_ms);
        token
    }

    /// The device's attestation public key: the seed's own P-256 point.
    fn attestation_key(&mut self) -> VerifyingKey {
        let seed = load_keydev(&dev(), &mut self.fs).unwrap();
        let (x, y) = P256Key::from_scalar(seed.expose()).unwrap().public_xy();
        let point = p256::Sec1Point::from_bytes(crate::ec::sec1_uncompressed(x, y)).unwrap();
        VerifyingKey::from_sec1_point(&point).unwrap()
    }
}

/// The registration input `{alg: algs, ?flags}`.
fn generate_key(algs: &[i64], flags: Option<u64>) -> Vec<u8> {
    enc(|e| {
        e.map(1 + u64::from(flags.is_some())).unwrap();
        e.i64(KEY_ALG).unwrap().array(algs.len() as u64).unwrap();
        for &alg in algs {
            e.i64(alg).unwrap();
        }
        if let Some(flags) = flags {
            e.i64(KEY_FLAGS).unwrap().u64(flags).unwrap();
        }
    })
}

/// A makeCredential for [`RP`] with `alg`, carrying `preview` (the extension's
/// value, raw).
fn mc_req(alg: i64, preview: Option<&[u8]>, rk: bool, none_att: bool) -> Vec<u8> {
    mc_req_with(alg, preview, rk, none_att, 0, |_| {})
}

/// [`mc_req`], with `more` other extensions that `extra` writes.
fn mc_req_with(
    alg: i64,
    preview: Option<&[u8]>,
    rk: bool,
    none_att: bool,
    more: u64,
    extra: impl FnOnce(&mut Enc<'_>),
) -> Vec<u8> {
    let has_ext = preview.is_some() || more > 0;
    enc(|e| {
        e.map(4 + u64::from(has_ext) + u64::from(rk) + u64::from(none_att))
            .unwrap();
        e.u8(1).unwrap().bytes(&CDH).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str(RP)
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
        e.str("name").unwrap().str("alice").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(alg).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        if has_ext {
            e.u8(6)
                .unwrap()
                .map(u64::from(preview.is_some()) + more)
                .unwrap();
            extra(e);
            if let Some(value) = preview {
                e.str(NAME).unwrap();
                e.writer_mut().write_all(value).unwrap();
            }
        }
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
        if none_att {
            e.u8(11).unwrap().array(1).unwrap().str("none").unwrap();
        }
    })
}

/// The signing input `{?kh, ?tbs, ?args}`.
fn sign_input(kh: Option<&[u8]>, tbs: Option<&[u8]>, args: Option<&[u8]>) -> Vec<u8> {
    let entries = [(KEY_KH, kh), (KEY_TBS, tbs), (KEY_ARGS, args)];
    enc(|e| {
        e.map(entries.iter().filter(|(_, v)| v.is_some()).count() as u64)
            .unwrap();
        for (key, value) in entries {
            if let Some(value) = value {
                e.i64(key).unwrap().bytes(value).unwrap();
            }
        }
    })
}

/// COSE_Sign_Args with whichever of `alg`, the ARKG handle and ctx are given, and
/// optionally one label nobody defined.
fn sign_args(alg: Option<i64>, kh: Option<&[u8]>, ctx: Option<&[u8]>, unknown: bool) -> Vec<u8> {
    let n = u64::from(alg.is_some())
        + u64::from(kh.is_some())
        + u64::from(ctx.is_some())
        + u64::from(unknown);
    enc(|e| {
        e.map(n).unwrap();
        if let Some(alg) = alg {
            e.i64(ARGS_ALG).unwrap().i64(alg).unwrap();
        }
        if let Some(kh) = kh {
            e.i64(ARGS_ARKG_KH).unwrap().bytes(kh).unwrap();
        }
        if let Some(ctx) = ctx {
            e.i64(ARGS_ARKG_CTX).unwrap().bytes(ctx).unwrap();
        }
        if unknown {
            e.u8(42).unwrap().u16(1337).unwrap();
        }
    })
}

/// A getAssertion's allowList (key 3).
#[derive(Clone, Copy)]
enum Allow<'a> {
    Absent,
    Empty,
    Of(&'a [u8]),
}

/// A getAssertion for [`RP`]: the allowList, the previewSign value raw, the `up`
/// option when given, and a pinUvAuthParam.
fn ga_req(
    allow: Allow<'_>,
    preview: Option<&[u8]>,
    up: Option<bool>,
    pin_param: Option<&[u8]>,
) -> Vec<u8> {
    enc(|e| {
        let n = 2
            + u64::from(!matches!(allow, Allow::Absent))
            + u64::from(preview.is_some())
            + u64::from(up.is_some())
            + 2 * u64::from(pin_param.is_some());
        e.map(n).unwrap();
        e.u8(1).unwrap().str(RP).unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        match allow {
            Allow::Absent => {}
            Allow::Empty => {
                e.u8(3).unwrap().array(0).unwrap();
            }
            Allow::Of(id) => {
                e.u8(3).unwrap().array(1).unwrap().map(2).unwrap();
                e.str("id").unwrap().bytes(id).unwrap();
                e.str("type").unwrap().str("public-key").unwrap();
            }
        }
        if let Some(value) = preview {
            e.u8(4).unwrap().map(1).unwrap().str(NAME).unwrap();
            e.writer_mut().write_all(value).unwrap();
        }
        if let Some(up) = up {
            e.u8(5)
                .unwrap()
                .map(1)
                .unwrap()
                .str("up")
                .unwrap()
                .bool(up)
                .unwrap();
        }
        if let Some(param) = pin_param {
            e.u8(6).unwrap().bytes(param).unwrap();
            e.u8(7).unwrap().u8(2).unwrap();
        }
    })
}

/// What a registration response says, with previewSign's parts pulled out.
#[derive(Default)]
struct Registered {
    fields: Vec<u64>,
    fmt: String,
    auth_data: Vec<u8>,
    att_stmt: Vec<u8>,
    cred_id: Vec<u8>,
    ext_names: Vec<String>,
    preview_alg: Option<i64>,
    unsigned_names: Vec<String>,
    att_obj: Option<Vec<u8>>,
}

fn registered(resp: &[u8]) -> Registered {
    let mut r = Registered::default();
    let mut d = Decoder::new(resp);
    for _ in 0..d.map().unwrap().unwrap() {
        let key = d.u64().unwrap();
        r.fields.push(key);
        match key {
            1 => r.fmt = d.str().unwrap().to_string(),
            2 => r.auth_data = d.bytes().unwrap().to_vec(),
            3 => {
                let start = d.position();
                d.skip().unwrap();
                r.att_stmt = resp[start..d.position()].to_vec();
            }
            6 => {
                for _ in 0..d.map().unwrap().unwrap() {
                    let name = d.str().unwrap();
                    r.unsigned_names.push(name.to_string());
                    if name == NAME {
                        assert_eq!(d.map().unwrap(), Some(1));
                        assert_eq!(d.i64().unwrap(), KEY_ATT_OBJ);
                        r.att_obj = Some(d.bytes().unwrap().to_vec());
                    } else {
                        d.skip().unwrap();
                    }
                }
            }
            _ => d.skip().unwrap(),
        }
    }
    assert_eq!(d.position(), resp.len(), "one map, nothing after it");
    let ad = &r.auth_data;
    let id_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    r.cred_id = ad[55..55 + id_len].to_vec();
    let mut e = Decoder::new(&ad[55 + id_len..]);
    e.skip().unwrap(); // the credential's COSE key
    if ad[32] & FLAG_ED != 0 {
        for _ in 0..e.map().unwrap().unwrap() {
            let name = e.str().unwrap();
            r.ext_names.push(name.to_string());
            if name == NAME {
                assert_eq!(e.map().unwrap(), Some(1));
                assert_eq!(e.i64().unwrap(), KEY_ALG);
                r.preview_alg = Some(e.i64().unwrap());
            } else {
                e.skip().unwrap();
            }
        }
    }
    assert_eq!(
        e.position(),
        ad.len() - 55 - id_len,
        "authData ends at its extensions"
    );
    r
}

/// The signing key's attestation object, taken apart.
struct AttestedKey {
    fmt: String,
    auth_data: Vec<u8>,
    att_stmt: Vec<u8>,
    handle: Vec<u8>,
    /// The ARKG-pub COSE key's own bytes.
    cose: Vec<u8>,
    bl: [u8; POINT_LEN],
    kem: [u8; POINT_LEN],
    flags: u64,
}

/// One EC2 key of the ARKG-pub, which must name `alg`.
fn ec2(d: &mut Decoder<'_>, alg: i64) -> [u8; POINT_LEN] {
    assert_eq!(d.map().unwrap(), Some(5));
    assert_eq!((d.u8().unwrap(), d.u8().unwrap()), (1, 2));
    assert_eq!((d.u8().unwrap(), d.i64().unwrap()), (3, alg));
    assert_eq!((d.i8().unwrap(), d.u8().unwrap()), (-1, 1));
    assert_eq!(d.i8().unwrap(), -2);
    let x = d.bytes().unwrap().to_vec();
    assert_eq!(d.i8().unwrap(), -3);
    let y = d.bytes().unwrap().to_vec();
    let mut point = [0u8; POINT_LEN];
    point[0] = 0x04;
    point[1..33].copy_from_slice(&x);
    point[33..].copy_from_slice(&y);
    point
}

fn attested_key(att_obj: &[u8]) -> AttestedKey {
    let mut d = Decoder::new(att_obj);
    assert_eq!(d.map().unwrap(), Some(3));
    assert_eq!(d.u8().unwrap(), 1);
    let fmt = d.str().unwrap().to_string();
    assert_eq!(d.u8().unwrap(), 2);
    let ad = d.bytes().unwrap().to_vec();
    assert_eq!(d.u8().unwrap(), 3);
    let start = d.position();
    d.skip().unwrap();
    let att_stmt = att_obj[start..d.position()].to_vec();
    assert_eq!(d.position(), att_obj.len(), "one map, nothing after it");

    let id_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    let handle = ad[55..55 + id_len].to_vec();
    let mut k = Decoder::new(&ad[55 + id_len..]);
    assert_eq!(k.map().unwrap(), Some(5));
    assert_eq!((k.u8().unwrap(), k.i64().unwrap()), (1, KTY_ARKG_PUB));
    assert_eq!((k.u8().unwrap(), k.i64().unwrap()), (3, ALG_ARKG_P256));
    assert_eq!(k.i8().unwrap(), PUB_BL);
    let bl = ec2(&mut k, ALG_ES256);
    assert_eq!(k.i8().unwrap(), PUB_KEM);
    let kem = ec2(&mut k, ALG_ECDH_ES_HKDF_256);
    assert_eq!((k.i8().unwrap(), k.i64().unwrap()), (PUB_DKALG, ALG_ESP256));
    let cose = ad[55 + id_len..55 + id_len + k.position()].to_vec();
    assert_eq!(k.map().unwrap(), Some(1));
    assert_eq!(k.str().unwrap(), NAME);
    assert_eq!(k.map().unwrap(), Some(1));
    assert_eq!(k.i64().unwrap(), KEY_FLAGS);
    let flags = k.u64().unwrap();
    assert_eq!(
        k.position(),
        ad.len() - 55 - id_len,
        "authData ends at its extensions"
    );
    AttestedKey {
        fmt,
        auth_data: ad,
        att_stmt,
        handle,
        cose,
        bl,
        kem,
        flags,
    }
}

/// A packed statement's `(sig, x5c)`.
fn packed(att_stmt: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut d = Decoder::new(att_stmt);
    assert_eq!(d.map().unwrap(), Some(3));
    assert_eq!(d.str().unwrap(), "alg");
    assert_eq!(d.i64().unwrap(), ALG_ES256);
    assert_eq!(d.str().unwrap(), "sig");
    let sig = d.bytes().unwrap().to_vec();
    assert_eq!(d.str().unwrap(), "x5c");
    let n = d.array().unwrap().unwrap();
    let certs = (0..n).map(|_| d.bytes().unwrap().to_vec()).collect();
    (sig, certs)
}

/// An assertion's authData and its previewSign signature, if it carries one.
fn asserted(resp: &[u8]) -> (Vec<u8>, Option<Vec<u8>>, Vec<String>) {
    let mut d = Decoder::new(resp);
    let mut ad = Vec::new();
    for _ in 0..d.map().unwrap().unwrap() {
        match d.u64().unwrap() {
            2 => ad = d.bytes().unwrap().to_vec(),
            _ => d.skip().unwrap(),
        }
    }
    let mut sig = None;
    let mut names = Vec::new();
    if ad[32] & FLAG_ED != 0 {
        let mut e = Decoder::new(&ad[37..]);
        for _ in 0..e.map().unwrap().unwrap() {
            let name = e.str().unwrap();
            names.push(name.to_string());
            if name == NAME {
                assert_eq!(e.map().unwrap(), Some(1));
                assert_eq!(e.i64().unwrap(), KEY_SIG);
                sig = Some(e.bytes().unwrap().to_vec());
            } else {
                e.skip().unwrap();
            }
        }
        assert_eq!(
            e.position(),
            ad.len() - 37,
            "authData ends at its extensions"
        );
    }
    (ad, sig, names)
}

/// Register a credential with previewSign `[ESP256-split-ARKG]` at `flags`; the
/// credential id and its signing key.
fn register(board: &mut Board, flags: Option<u64>, rk: bool) -> (Vec<u8>, AttestedKey) {
    let input = generate_key(&[ALG_ESP256_SPLIT_ARKG], flags);
    let reg = registered(
        &board
            .mc(&mc_req(ALG_ES256, Some(&input), rk, false))
            .unwrap(),
    );
    let key = attested_key(reg.att_obj.as_deref().unwrap());
    (reg.cred_id, key)
}

/// Play the relying party for `key`: derive a public key from its seed for
/// [`RT_CTX`], and the COSE_Sign_Args naming it. `(pk', args)`.
fn relying_party(key: &AttestedKey, ikm: &[u8]) -> ([u8; POINT_LEN], Vec<u8>) {
    let (pk, kh) = crate::arkg::tests::derive_public_key(&key.bl, &key.kem, ikm, RT_CTX);
    let args = sign_args(Some(ALG_ESP256_SPLIT_ARKG), Some(&kh), Some(RT_CTX), false);
    (pk, args)
}

/// A complete signing request for `cred`, over [`MESSAGE`]'s digest.
fn signing_request(cred: &[u8], key: &AttestedKey, args: &[u8], up: Option<bool>) -> Vec<u8> {
    let tbs = sha256(MESSAGE);
    let input = sign_input(Some(&key.handle), Some(&tbs), Some(args));
    ga_req(Allow::Of(cred), Some(&input), up, None)
}

fn verify_signature(pk: &[u8], sig: &[u8]) {
    let vk = VerifyingKey::from_sec1_bytes(pk).unwrap();
    let sig = Signature::from_der(sig).unwrap();
    vk.verify_prehash(&sha256(MESSAGE), &sig)
        .expect("the signature verifies under the key the relying party derived");
}

/// The end-to-end check against the reference: python-fido2 2.2.1 derived
/// `RT_PK_PRIME` and `RT_ARGS` from this device's seed; the device signs, and the
/// signature verifies under that key — ESP256 over the message, split.
#[test]
fn a_signature_verifies_under_the_key_python_fido2_derived() {
    let mut board = Board::new();
    let (cred, key) = register(&mut board, Some(1), false);
    assert_eq!(
        (hex(&key.bl), hex(&key.kem)),
        (RT_PK_BL.to_string(), RT_PK_KEM.to_string())
    );
    assert_eq!(
        hex(&key.cose),
        RT_SEED_COSE,
        "the ARKG-pub key, byte for byte"
    );
    // The client's args are exactly `{alg, -1: its ARKG handle, -2: ctx}`.
    let args = sign_args(
        Some(ALG_ESP256_SPLIT_ARKG),
        Some(&unhex(RT_ARKG_KH)),
        Some(RT_CTX),
        false,
    );
    assert_eq!(args, unhex(RT_ARGS));

    let mut button = Button::touching();
    let resp = board
        .run(
            false,
            &signing_request(&cred, &key, &args, None),
            &mut button,
        )
        .unwrap();
    assert_eq!(button.asked, 1, "one touch");
    let (ad, sig, names) = asserted(&resp);
    assert_eq!(ad[32] & FLAG_UP, FLAG_UP);
    assert_eq!(names, [NAME]);
    let sig = sig.unwrap();
    verify_signature(&unhex(RT_PK_PRIME), &sig);
    // The key that signed is the derived one, not either half of the seed.
    let sig = Signature::from_der(&sig).unwrap();
    for half in [RT_PK_BL, RT_PK_KEM] {
        let vk = VerifyingKey::from_sec1_bytes(&unhex(half)).unwrap();
        assert!(vk.verify_prehash(&sha256(MESSAGE), &sig).is_err());
    }
    // The in-crate relying party agrees with the reference on this seed too.
    let (pk, _) = crate::arkg::tests::derive_public_key(
        &key.bl,
        &key.kem,
        &sha256(b"rsk-fido previewSign round trip"),
        RT_CTX,
    );
    assert_eq!(hex(&pk), RT_PK_PRIME);
}

/// Refusals a registration can earn, in the order a YubiKey 5.8.0 answers them —
/// `flags`, then the elements' type, then support — each before the touch.
#[test]
fn registration_refusals_come_in_the_reference_order() {
    use CtapError::{CborUnexpectedType, InvalidOption, MissingParameter, UnsupportedAlgorithm};
    let mut board = Board::new();
    let cases: [(&[i64], Option<u64>, CtapError); 10] = [
        (&[ALG_ESP256_SPLIT_ARKG], Some(0b010), InvalidOption),
        (&[ALG_ESP256_SPLIT_ARKG], Some(0b100), InvalidOption),
        (&[1], Some(0b010), InvalidOption),
        (&[1], Some(0b001), CborUnexpectedType),
        (&[ALG_ESP256_SPLIT_ARKG, 7], Some(0b001), CborUnexpectedType),
        (&[0], None, CborUnexpectedType),
        (&[-18], Some(0b001), UnsupportedAlgorithm),
        (&[-9, -7, -300, -70009], Some(0b001), UnsupportedAlgorithm),
        (&[-18, 3], Some(0b001), CborUnexpectedType),
        (&[], Some(0b001), UnsupportedAlgorithm),
    ];
    for (algs, flags, want) in cases {
        let mut button = Button::touching();
        let req = mc_req(ALG_ES256, Some(&generate_key(algs, flags)), false, false);
        assert_eq!(
            board.run(true, &req, &mut button),
            Err(want),
            "{algs:?} {flags:?}"
        );
        assert_eq!(
            button.asked, 0,
            "{algs:?} {flags:?}: refused before the touch"
        );
    }
    // An element of another type, no `alg`, and a value that is not a map.
    let text = enc(|e| {
        e.map(1).unwrap();
        e.i64(KEY_ALG)
            .unwrap()
            .array(1)
            .unwrap()
            .str("ESP256")
            .unwrap();
    });
    let no_alg = enc(|e| {
        e.map(1).unwrap().i64(KEY_FLAGS).unwrap().u8(1).unwrap();
    });
    let flags_text = enc(|e| {
        e.map(1).unwrap().i64(KEY_FLAGS).unwrap().str("1").unwrap();
    });
    let not_a_map = enc(|e| {
        e.bool(true).unwrap();
    });
    for (value, want) in [
        (text, CborUnexpectedType),
        (no_alg, MissingParameter),
        (flags_text, CborUnexpectedType),
        (not_a_map, CborUnexpectedType),
    ] {
        let mut button = Button::touching();
        let req = mc_req(ALG_ES256, Some(&value), false, false);
        assert_eq!(board.run(true, &req, &mut button), Err(want));
        assert_eq!(button.asked, 0);
    }
}

/// python-fido2's `test_register_invalid_flags`: all 256 values, three accepted.
#[test]
fn every_flags_value_but_the_drafts_three_is_refused() {
    let mut board = Board::new();
    for flags in 0..=255u64 {
        let req = mc_req(
            ALG_ES256,
            Some(&generate_key(&ALL_ALGORITHMS, Some(flags))),
            false,
            false,
        );
        match board.mc(&req) {
            Ok(resp) if matches!(flags, 0b000 | 0b001 | 0b101) => {
                let reg = registered(&resp);
                assert_eq!(
                    reg.preview_alg,
                    Some(ALG_ESP256_SPLIT_ARKG),
                    "the one it has"
                );
            }
            got => assert_eq!(got, Err(CtapError::InvalidOption), "flags {flags:#010b}"),
        }
    }
}

/// The one deviation: an ML-DSA credential refuses the extension as the draft refuses
/// an algorithm it cannot serve, before the touch — and only the combination.
#[test]
fn an_ml_dsa_credential_refuses_the_extension() {
    let mut board = Board::new();
    let input = generate_key(&[ALG_ESP256_SPLIT_ARKG], Some(1));
    for alg in [ALG_MLDSA44, ALG_MLDSA65, ALG_MLDSA87] {
        let mut button = Button::touching();
        let req = mc_req(alg, Some(&input), false, false);
        assert_eq!(
            board.run(true, &req, &mut button),
            Err(CtapError::UnsupportedAlgorithm)
        );
        assert_eq!(button.asked, 0, "ML-DSA {alg}: refused before the touch");
    }
    let reg = registered(&board.mc(&mc_req(ALG_MLDSA44, None, false, false)).unwrap());
    assert_eq!(reg.preview_alg, None, "the credential alone is still made");
    // Every classic curve takes it — P-521's key being the largest the response
    // bound (`COSE_EC2_MAX`) allows for.
    for alg in [
        ALG_ES256,
        ALG_EDDSA,
        crate::consts::ALG_ES384,
        crate::consts::ALG_ES512,
    ] {
        let reg = registered(&board.mc(&mc_req(alg, Some(&input), false, false)).unwrap());
        assert_eq!(reg.preview_alg, Some(ALG_ESP256_SPLIT_ARKG), "alg {alg}");
    }
}

/// YubiKey 5.8.0, measured 2026-09-30: a key asked for `unattended` is made and
/// attested so, and signs with no touch — UP clear, authData flags `0x80` — or with
/// one (`0x81`); a `require-up` key answers `up:false` with UP_REQUIRED (`0x3B`).
#[test]
fn an_unattended_key_signs_without_a_touch() {
    let mut board = Board::new();
    let (cred, key) = register(&mut board, Some(0b000), false);
    assert_eq!(key.flags, 0b000, "attested as unattended");
    assert_eq!(key.auth_data[32], FLAG_UP | FLAG_AT | FLAG_ED, "0xC1");
    assert_eq!(key.auth_data[33..37], [0; 4], "signCount 0");
    let (pk, args) = relying_party(&key, b"unattended");

    // `up:false`, the draft's unattended signature: served, and nobody asked.
    let mut button = Button::touching();
    let req = signing_request(&cred, &key, &args, Some(false));
    let resp = board.run(false, &req, &mut button);
    assert_eq!(button.asked, 0);
    let (ad, sig, _) = asserted(&resp.unwrap());
    assert_eq!(ad[32], FLAG_ED, "UP clear");
    verify_signature(&pk, &sig.unwrap());
    // With `up`, the touch is asked for: withheld, nothing is signed…
    let mut button = Button::untouched();
    let req = signing_request(&cred, &key, &args, Some(true));
    assert_eq!(
        board.run(false, &req, &mut button),
        Err(CtapError::OperationDenied)
    );
    assert_eq!(button.asked, 1);
    // …given, the signature comes back.
    let mut button = Button::touching();
    let resp = board.run(false, &req, &mut button).unwrap();
    assert_eq!(button.asked, 1);
    let (ad, sig, _) = asserted(&resp);
    assert_eq!(ad[32], FLAG_ED | FLAG_UP);
    verify_signature(&pk, &sig.unwrap());

    // A `require-up` key: no signature without the touch, one with it.
    let (cred, key) = register(&mut board, Some(0b001), false);
    let (pk, args) = relying_party(&key, b"require-up");
    let mut button = Button::touching();
    let req = signing_request(&cred, &key, &args, Some(false));
    assert_eq!(
        board.run(false, &req, &mut button),
        Err(CtapError::UpRequired)
    );
    assert_eq!(button.asked, 0);
    let req = signing_request(&cred, &key, &args, Some(true));
    let (ad, sig, _) = asserted(&board.run(false, &req, &mut button).unwrap());
    assert_eq!(ad[32], FLAG_ED | FLAG_UP);
    verify_signature(&pk, &sig.unwrap());
}

/// The touch that releases a previewSign signature signs bytes the host chose, so a
/// trusted screen asks to sign data; an assertion without the extension still asks
/// to sign in.
#[test]
fn a_signing_assertion_asks_to_sign_data() {
    let mut board = Board::new();
    let (cred, key) = register(&mut board, Some(1), false);
    let (_, args) = relying_party(&key, b"title");
    let mut button = Button::touching();
    let req = signing_request(&cred, &key, &args, Some(true));
    board.run(false, &req, &mut button).unwrap();
    assert_eq!(button.titles, ["Sign data?"]);
    let mut button = Button::touching();
    let req = ga_req(Allow::Of(&cred), None, Some(true), None);
    board.run(false, &req, &mut button).unwrap();
    assert_eq!(button.titles, ["Sign in?"]);
}

/// `require-uv`: no verified user, no signature — `PUAT_REQUIRED`; with a PIN
/// token the assertion carries UV and signs.
#[test]
fn a_require_uv_key_needs_a_verified_assertion() {
    let mut board = Board::new();
    let (cred, key) = register(&mut board, Some(0b101), false);
    assert_eq!(key.flags, 0b101);
    let (pk, args) = relying_party(&key, b"uv");
    let tbs = sha256(MESSAGE);
    let input = sign_input(Some(&key.handle), Some(&tbs), Some(&args));
    let req = ga_req(Allow::Of(&cred), Some(&input), None, None);
    assert_eq!(board.ga(&req), Err(CtapError::PuatRequired));

    let token = board.arm_pin();
    let mut param = [0u8; 32];
    let n = rsk_crypto::pinproto::authenticate(PinProto::Two, &token, &CDH, &mut param).unwrap();
    let req = ga_req(Allow::Of(&cred), Some(&input), None, Some(&param[..n]));
    let (ad, sig, _) = asserted(&board.ga(&req).unwrap());
    assert_eq!(ad[32] & (FLAG_UP | FLAG_UV), FLAG_UP | FLAG_UV);
    verify_signature(&pk, &sig.unwrap());
}

/// Refusals a signing request can earn, in the draft's order (v4 authentication
/// steps 1–10), every one before the touch.
#[test]
fn assertion_refusals_come_in_the_draft_order() {
    use CtapError::{
        CborUnexpectedType, InvalidCbor, InvalidCredential, InvalidLength, InvalidOption,
        MissingParameter, UpRequired,
    };
    let mut board = Board::new();
    let (cred, key) = register(&mut board, Some(1), false);
    let (_, other) = register(&mut board, Some(1), false);
    let (pk, args) = relying_party(&key, b"order");
    let (_, kh) = crate::arkg::tests::derive_public_key(&key.bl, &key.kem, b"order", RT_CTX);
    let tbs = sha256(MESSAGE).to_vec();
    let handle = key.handle.clone();
    let alt =
        |alg: Option<i64>, kh: Option<&[u8]>, ctx: Option<&[u8]>| sign_args(alg, kh, ctx, false);
    let arg_alg = Some(ALG_ESP256_SPLIT_ARKG);
    let flipped = |b: &[u8], i: usize| {
        let mut b = b.to_vec();
        b[i] ^= 0x01;
        b
    };
    let long_ctx = [0x61u8; 65];

    // (what, allowList present, kh, tbs, args, up, want)
    type Case<'a> = (
        &'a str,
        bool,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<bool>,
        CtapError,
    );
    let cases: Vec<Case<'_>> = std::vec![
        (
            "no allowList",
            false,
            Some(handle.clone()),
            Some(tbs.clone()),
            Some(args.clone()),
            None,
            InvalidOption
        ),
        (
            "no kh",
            true,
            None,
            Some(tbs.clone()),
            Some(args.clone()),
            None,
            InvalidOption
        ),
        (
            "no tbs",
            true,
            Some(handle.clone()),
            None,
            Some(args.clone()),
            None,
            InvalidOption
        ),
        (
            "another credential's handle",
            true,
            Some(other.handle.clone()),
            Some(tbs.clone()),
            Some(args.clone()),
            None,
            InvalidCredential
        ),
        (
            "a handle a byte short",
            true,
            Some(handle[..HANDLE_LEN - 1].to_vec()),
            Some(tbs.clone()),
            Some(args.clone()),
            None,
            InvalidCredential
        ),
        (
            "a handle with bytes past its end",
            true,
            Some([&handle[..], &[0u8; 16]].concat()),
            Some(tbs.clone()),
            Some(args.clone()),
            None,
            InvalidCredential
        ),
        (
            "a flipped MAC byte",
            true,
            Some(flipped(&handle, 0)),
            Some(tbs.clone()),
            Some(args.clone()),
            None,
            InvalidCredential
        ),
        (
            "a flipped params byte",
            true,
            Some(flipped(&handle, MAC_LEN + 6)),
            Some(tbs.clone()),
            Some(args.clone()),
            None,
            InvalidCredential
        ),
        (
            "a bad handle beats missing args",
            true,
            Some(flipped(&handle, 1)),
            Some(tbs.clone()),
            None,
            None,
            InvalidCredential
        ),
        (
            "no args",
            true,
            Some(handle.clone()),
            Some(tbs.clone()),
            None,
            None,
            MissingParameter
        ),
        (
            "args without alg",
            true,
            Some(handle.clone()),
            Some(tbs.clone()),
            Some(alt(None, Some(&kh), Some(RT_CTX))),
            None,
            InvalidCredential
        ),
        (
            "args naming another alg",
            true,
            Some(handle.clone()),
            Some(tbs.clone()),
            Some(alt(
                Some(ALG_ESP256_SPLIT_ARKG + 1),
                Some(&kh),
                Some(RT_CTX)
            )),
            None,
            InvalidCredential
        ),
        (
            "the args' alg beats up:false",
            true,
            Some(handle.clone()),
            Some(tbs.clone()),
            Some(alt(None, Some(&kh), Some(RT_CTX))),
            Some(false),
            InvalidCredential
        ),
        (
            "args without the ARKG handle",
            true,
            Some(handle.clone()),
            Some(tbs.clone()),
            Some(alt(arg_alg, None, Some(RT_CTX))),
            None,
            MissingParameter
        ),
        (
            "args without ctx",
            true,
            Some(handle.clone()),
            Some(tbs.clone()),
            Some(alt(arg_alg, Some(&kh), None)),
            None,
            MissingParameter
        ),
        (
            "args that are not a map",
            true,
            Some(handle.clone()),
            Some(tbs.clone()),
            Some(enc(|e| {
                e.u8(3).unwrap();
            })),
            None,
            CborUnexpectedType
        ),
        (
            "args with a byte after the map",
            true,
            Some(handle.clone()),
            Some(tbs.clone()),
            Some([args.as_slice(), &[0]].concat()),
            None,
            InvalidCbor
        ),
        (
            "a 31-byte tbs",
            true,
            Some(handle.clone()),
            Some(tbs[..31].to_vec()),
            Some(args.clone()),
            None,
            InvalidLength
        ),
        (
            "a 33-byte tbs",
            true,
            Some(handle.clone()),
            Some([tbs.as_slice(), &[0]].concat()),
            Some(args.clone()),
            None,
            InvalidLength
        ),
        (
            "up:false",
            true,
            Some(handle.clone()),
            Some(tbs.clone()),
            Some(args.clone()),
            Some(false),
            UpRequired
        ),
        (
            "up:false beats a bad ARKG handle",
            true,
            Some(handle.clone()),
            Some(tbs.clone()),
            Some(alt(arg_alg, Some(&flipped(&kh, 0)), Some(RT_CTX))),
            Some(false),
            UpRequired
        ),
        (
            "a flipped ARKG tag byte",
            true,
            Some(handle.clone()),
            Some(tbs.clone()),
            Some(alt(arg_alg, Some(&flipped(&kh, 0)), Some(RT_CTX))),
            None,
            InvalidCredential
        ),
        (
            "a ctx the ARKG handle is not for",
            true,
            Some(handle.clone()),
            Some(tbs.clone()),
            Some(alt(arg_alg, Some(&kh), Some(b"other"))),
            None,
            InvalidCredential
        ),
        (
            "a 65-byte ctx",
            true,
            Some(handle.clone()),
            Some(tbs.clone()),
            Some(alt(arg_alg, Some(&kh), Some(&long_ctx))),
            None,
            InvalidCredential
        ),
    ];
    for (what, allow, kh, tbs, args, up, want) in cases {
        let input = sign_input(kh.as_deref(), tbs.as_deref(), args.as_deref());
        let allow = if allow {
            Allow::Of(&cred)
        } else {
            Allow::Absent
        };
        let req = ga_req(allow, Some(&input), up, None);
        let mut button = Button::touching();
        assert_eq!(board.run(false, &req, &mut button), Err(want), "{what}");
        assert_eq!(button.asked, 0, "{what}: refused before the touch");
    }
    // An empty allowList is no allowList.
    let input = sign_input(Some(&handle), Some(&tbs), Some(&args));
    assert_eq!(
        board.ga(&ga_req(Allow::Empty, Some(&input), None, None)),
        Err(InvalidOption)
    );
    // A kh of the wrong CBOR type is the parser's.
    let text_kh = enc(|e| {
        e.map(1).unwrap().i64(KEY_KH).unwrap().str("kh").unwrap();
    });
    assert_eq!(
        board.ga(&ga_req(Allow::Of(&cred), Some(&text_kh), None, None)),
        Err(CborUnexpectedType)
    );

    // And the request all of those broke, whole — with a label COSE_Sign_Args
    // does not define, which is ignored (python-fido2's `test_assert_unknown_args`).
    for args in [
        args.clone(),
        sign_args(arg_alg, Some(&kh), Some(RT_CTX), true),
    ] {
        let (_, sig, _) = asserted(
            &board
                .ga(&signing_request(&cred, &key, &args, None))
                .unwrap(),
        );
        verify_signature(&pk, &sig.unwrap());
    }
}

/// A resident credential signs by its stable resident id, and discovery — no
/// allowList — refuses the extension while serving the credential without it.
#[test]
fn a_resident_credential_signs_by_its_id_but_never_through_discovery() {
    let mut board = Board::new();
    let (cred, key) = register(&mut board, Some(1), true);
    assert_eq!(cred.len(), crate::credential::CRED_RESIDENT_LEN);
    let (pk, args) = relying_party(&key, b"resident");
    let (_, sig, _) = asserted(
        &board
            .ga(&signing_request(&cred, &key, &args, None))
            .unwrap(),
    );
    verify_signature(&pk, &sig.unwrap());

    let tbs = sha256(MESSAGE);
    let input = sign_input(Some(&key.handle), Some(&tbs), Some(&args));
    let discovery = ga_req(Allow::Absent, Some(&input), None, None);
    assert_eq!(board.ga(&discovery), Err(CtapError::InvalidOption));
    let (_, sig, _) = asserted(&board.ga(&ga_req(Allow::Absent, None, None, None)).unwrap());
    assert!(
        sig.is_none(),
        "the credential itself is still there to discover"
    );
}

/// A handle opens for its own credential and relying party only.
#[test]
fn a_handle_is_bound_to_its_credential_and_rp() {
    let mut board = Board::new();
    let (cred, key) = register(&mut board, Some(1), false);
    let seed = load_keydev(&dev(), &mut board.fs).unwrap();
    let secret = credential_secret(seed.expose(), &cred);
    let rp = sha256(RP.as_bytes());
    let opened = open_handle(&secret, &key.handle, &rp).map(|p| (p.alg, p.flags));
    assert_eq!(opened.ok(), Some((ALG_ESP256_SPLIT_ARKG, 1)));
    let other_rp = sha256(b"example.org");
    assert_eq!(
        open_handle(&secret, &key.handle, &other_rp).err(),
        Some(CtapError::InvalidCredential)
    );
    let mut other_cred = cred.clone();
    other_cred[20] ^= 0x01;
    let other_secret = credential_secret(seed.expose(), &other_cred);
    assert_eq!(
        open_handle(&other_secret, &key.handle, &rp).err(),
        Some(CtapError::InvalidCredential)
    );
}

/// `kh` and `tbs` are judged before any credential is looked for: a request that
/// lacks one is refused as such, untouched, even when nothing would match.
#[test]
fn a_missing_kh_or_tbs_is_refused_before_the_credential_lookup() {
    let mut board = Board::new();
    let stranger = [0x5Au8; 64];
    let tbs = sha256(MESSAGE);
    let handle = [1u8; HANDLE_LEN];
    for input in [
        sign_input(None, Some(&tbs), None),
        sign_input(Some(&handle), None, None),
    ] {
        let mut button = Button::touching();
        let req = ga_req(Allow::Of(&stranger), Some(&input), None, None);
        assert_eq!(
            board.run(false, &req, &mut button),
            Err(CtapError::InvalidOption)
        );
        assert_eq!(button.asked, 0);
    }
    // Without previewSign the stranger is the ordinary no-match, after a touch.
    let mut button = Button::touching();
    let req = ga_req(Allow::Of(&stranger), None, None, None);
    assert_eq!(
        board.run(false, &req, &mut button),
        Err(CtapError::NoCredentials)
    );
    assert_eq!(button.asked, 1);
}

/// The MAC vouches for who wrote a handle, not for its layout: a MAC-valid handle
/// of another shape — another algorithm, a short auxIkm padded back to length by a
/// longer flags encoding — is still refused.
#[test]
fn a_mac_valid_handle_of_another_shape_is_refused() {
    let mut board = Board::new();
    let (cred, _) = register(&mut board, Some(1), false);
    let seed = load_keydev(&dev(), &mut board.fs).unwrap();
    let secret = credential_secret(seed.expose(), &cred);
    let rp = sha256(RP.as_bytes());
    let forge = |alg: i64, flags: u8, aux: &[u8]| {
        let params = enc(|e| {
            e.array(3).unwrap().i64(alg).unwrap().u8(flags).unwrap();
            e.bytes(aux).unwrap();
        });
        let mut handle = handle_mac(&secret, &params, &rp).unwrap().to_vec();
        handle.extend_from_slice(&params);
        handle
    };
    let minted = forge(ALG_ESP256_SPLIT_ARKG, 1, &[7; AUX_IKM_LEN]);
    assert!(
        open_handle(&secret, &minted, &rp).is_ok(),
        "the shape it mints opens"
    );
    for handle in [
        forge(ALG_ESP256_SPLIT_ARKG + 1, 1, &[7; AUX_IKM_LEN]),
        forge(ALG_ESP256_SPLIT_ARKG, 24, &[7; AUX_IKM_LEN - 1]),
    ] {
        assert_eq!(handle.len(), HANDLE_LEN);
        assert_eq!(
            open_handle(&secret, &handle, &rp).err(),
            Some(CtapError::InvalidCredential)
        );
    }
}

/// The `none` format reaches the signing key's attestation too: `fmt: "none"`,
/// an empty statement, nothing signed.
#[test]
fn a_none_attestation_is_none_for_the_signing_key_too() {
    let mut board = Board::new();
    let input = generate_key(&[ALG_ESP256_SPLIT_ARKG], None);
    let reg = registered(
        &board
            .mc(&mc_req(ALG_ES256, Some(&input), false, true))
            .unwrap(),
    );
    assert_eq!(reg.fmt, "none");
    let key = attested_key(reg.att_obj.as_deref().unwrap());
    assert_eq!(key.fmt, "none");
    assert_eq!(key.att_stmt, [0xA0], "an empty map");
    assert_eq!(key.flags, 1, "no flags asked is require-up");
}

/// Beside the other extensions each output lands in CTAP canonical order.
#[test]
fn the_outputs_sort_among_the_other_extensions() {
    let mut board = Board::new();
    let input = generate_key(&[ALG_ESP256_SPLIT_ARKG], Some(1));
    let req = mc_req_with(ALG_ES256, Some(&input), false, false, 3, |e| {
        e.str("credBlob").unwrap().bytes(b"blob").unwrap();
        e.str("hmac-secret").unwrap().bool(true).unwrap();
        e.str("credProtect").unwrap().u8(1).unwrap();
    });
    let reg = registered(&board.mc(&req).unwrap());
    assert_eq!(
        reg.ext_names,
        ["credBlob", "credProtect", "hmac-secret", NAME]
    );
    let key = attested_key(reg.att_obj.as_deref().unwrap());

    let (pk, args) = relying_party(&key, b"beside");
    let tbs = sha256(MESSAGE);
    let value = sign_input(Some(&key.handle), Some(&tbs), Some(&args));
    let req = enc(|e| {
        e.map(4).unwrap();
        e.u8(1).unwrap().str(RP).unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(3).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&reg.cred_id).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(4).unwrap().map(3).unwrap();
        e.str("thirdPartyPayment").unwrap().bool(true).unwrap();
        e.str(NAME).unwrap();
        e.writer_mut().write_all(&value).unwrap();
        e.str("credBlob").unwrap().bool(true).unwrap();
    });
    let (_, sig, names) = asserted(&board.ga(&req).unwrap());
    assert_eq!(names, ["credBlob", NAME, "thirdPartyPayment"]);
    verify_signature(&pk, &sig.unwrap());
}

/// Every assertion output at its largest at once — a full credBlob, both
/// hmac-secret salts, previewSign's signature, thirdPartyPayment — past the 320
/// bytes the others alone needed, and it still fits (`GA_EXT_MAX`).
#[test]
fn the_largest_extension_outputs_fit_one_assertion() {
    use rsk_crypto::pinproto::{authenticate, ecdh, encrypt, public_xy};
    let mut board = Board::new();
    board.state.regenerate(&mut board.rng);
    let (ax, ay) = board.state.ephemeral_public().unwrap();
    let blob = [0xB1u8; crate::consts::MAX_CREDBLOB_LENGTH];
    let input = generate_key(&[ALG_ESP256_SPLIT_ARKG], Some(1));
    let req = mc_req_with(ALG_ES256, Some(&input), false, false, 2, |e| {
        e.str("credBlob").unwrap().bytes(&blob).unwrap();
        e.str("hmac-secret").unwrap().bool(true).unwrap();
    });
    let reg = registered(&board.mc(&req).unwrap());
    let key = attested_key(reg.att_obj.as_deref().unwrap());
    let (pk, args) = relying_party(&key, b"largest");

    // The platform's half of hmac-secret, protocol two, two salts.
    let plat = [0x22u8; 32];
    let (px, py) = public_xy(&plat).unwrap();
    let mut shared = [0u8; 64];
    let n = ecdh(PinProto::Two, &plat, &ax, &ay, &mut shared).unwrap();
    let mut salt_enc = [0u8; 80];
    let ne = encrypt(
        PinProto::Two,
        &shared[..n],
        &[0x01; 16],
        &[0x77; 64],
        &mut salt_enc,
    )
    .unwrap();
    let mut salt_auth = [0u8; 32];
    let na = authenticate(PinProto::Two, &shared[..n], &salt_enc[..ne], &mut salt_auth).unwrap();

    let tbs = sha256(MESSAGE);
    let value = sign_input(Some(&key.handle), Some(&tbs), Some(&args));
    let req = enc(|e| {
        e.map(4).unwrap();
        e.u8(1).unwrap().str(RP).unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(3).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&reg.cred_id).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(4).unwrap().map(4).unwrap();
        e.str("credBlob").unwrap().bool(true).unwrap();
        e.str("hmac-secret").unwrap().map(4).unwrap();
        e.u8(1).unwrap().map(5).unwrap();
        e.u8(1).unwrap().u8(2).unwrap();
        e.u8(3).unwrap().i64(ALG_ECDH_ES_HKDF_256).unwrap();
        e.i8(-1).unwrap().u8(1).unwrap();
        e.i8(-2).unwrap().bytes(&px).unwrap();
        e.i8(-3).unwrap().bytes(&py).unwrap();
        e.u8(2).unwrap().bytes(&salt_enc[..ne]).unwrap();
        e.u8(3).unwrap().bytes(&salt_auth[..na]).unwrap();
        e.u8(4).unwrap().u8(2).unwrap();
        e.str(NAME).unwrap();
        e.writer_mut().write_all(&value).unwrap();
        e.str("thirdPartyPayment").unwrap().bool(true).unwrap();
    });
    let (ad, sig, names) = asserted(&board.ga(&req).unwrap());
    assert_eq!(
        names,
        ["credBlob", "hmac-secret", NAME, "thirdPartyPayment"]
    );
    assert!(ad.len() > 37 + 320, "{} bytes of authData", ad.len());
    verify_signature(&pk, &sig.unwrap());
}

/// Field 6 carries both unsigned outputs when both extensions are served —
/// largeBlob's first, the shorter key.
#[cfg(feature = "largeblob-ext")]
#[test]
fn large_blob_and_preview_sign_share_the_unsigned_outputs() {
    let mut board = Board::new();
    let input = generate_key(&[ALG_ESP256_SPLIT_ARKG], Some(1));
    let req = mc_req_with(ALG_ES256, Some(&input), true, false, 1, |e| {
        e.str("largeBlob").unwrap().map(1).unwrap();
        e.str("support").unwrap().str("preferred").unwrap();
    });
    let reg = registered(&board.mc(&req).unwrap());
    assert_eq!(reg.unsigned_names, ["largeBlob", NAME]);
    assert!(reg.att_obj.is_some());
}

/// YubiKey 5.8.0, measured 2026-09-30: beside a credential attested as ever, the
/// signing key's attestation object is `fmt: "none"` with an empty statement.
#[test]
fn registration_returns_an_arkg_seed_beside_the_credential() {
    let mut board = Board::new();
    let input = generate_key(&[ALG_ESP256_SPLIT_ARKG], Some(1));
    let resp = board
        .mc(&mc_req(ALG_ES256, Some(&input), false, false))
        .unwrap();
    let reg = registered(&resp);
    assert_eq!(
        reg.fields,
        [1, 2, 3, 6],
        "fmt, authData, attStmt, unsigned outputs"
    );
    assert_eq!(reg.preview_alg, Some(ALG_ESP256_SPLIT_ARKG));
    assert_eq!(reg.ext_names, [NAME]);
    assert_eq!(reg.unsigned_names, [NAME]);

    let key = attested_key(reg.att_obj.as_deref().unwrap());
    let ad = &key.auth_data;
    assert_eq!(ad[..32], sha256(RP.as_bytes()), "the credential's rpIdHash");
    assert_eq!(ad[32], reg.auth_data[32], "the credential's flags");
    assert_eq!(ad[32] & (FLAG_AT | FLAG_ED), FLAG_AT | FLAG_ED);
    assert_eq!(ad[33..37], [0; 4], "signCount 0");
    assert_eq!(ad[37..53], AAGUID, "the credential's AAGUID");
    assert_eq!(ad[37..53], reg.auth_data[37..53]);
    assert_eq!(key.handle.len(), HANDLE_LEN);
    assert_ne!(
        key.handle, reg.cred_id,
        "the handle is not the credential id"
    );
    assert_eq!(key.flags, 1, "require-up");
    assert_eq!(ad.len(), 316, "fits AUTH_DATA_MAX with room");
    assert!(ad.len() <= AUTH_DATA_MAX);

    // The credential is attested by the device key; its signing key by nothing.
    assert_eq!((reg.fmt.as_str(), key.fmt.as_str()), ("packed", "none"));
    assert_eq!(key.att_stmt, [0xA0], "an empty map");
    let (outer_sig, _) = packed(&reg.att_stmt);
    let mut outer = reg.auth_data.clone();
    outer.extend_from_slice(&CDH);
    board
        .attestation_key()
        .verify(&outer, &Signature::from_der(&outer_sig).unwrap())
        .expect("the device key attests the credential");

    // Pins the seed this fixed device mints; the reference vectors are for it.
    assert_eq!(
        (hex(&key.bl), hex(&key.kem)),
        (RT_PK_BL.to_string(), RT_PK_KEM.to_string()),
        "the fixed device's ARKG public seed"
    );
}

/// A board with an organisation key and a two-certificate chain installed and
/// enterprise attestation enabled: the org key's scalar and the chain.
fn enterprise_board() -> (Board, [u8; 32], Vec<Vec<u8>>) {
    use crate::consts::{EF_ATT_CHAIN, EF_EA_ENABLED};
    let mut board = Board::new();
    let org = [0x21u8; 32];
    crate::seed::store_att_key(&dev(), &mut board.fs, &org).unwrap();
    let (c1, c2) = ([0x30u8, 0x03, 1, 2, 3], [0x30u8, 0x02, 7, 7]);
    let mut chain = [0u8; 64];
    let n = crate::cert::att_chain_pack(&[&c1[..], &c2[..]].concat(), &mut chain).unwrap();
    board.fs.put(EF_ATT_CHAIN, &chain[..n]).unwrap();
    board.fs.put(EF_EA_ENABLED, &[1]).unwrap();
    (board, org, std::vec![c1.to_vec(), c2.to_vec()])
}

/// Whether `sig` over `auth_data ‖ CDH` verifies under `key`.
fn attests(key: &VerifyingKey, auth_data: &[u8], sig: &[u8]) -> bool {
    let mut signed = auth_data.to_vec();
    signed.extend_from_slice(&CDH);
    key.verify(&signed, &Signature::from_der(sig).unwrap())
        .is_ok()
}

fn org_key(scalar: &[u8; 32]) -> VerifyingKey {
    let (x, y) = P256Key::from_scalar(scalar).unwrap().public_xy();
    let point = p256::Sec1Point::from_bytes(crate::ec::sec1_uncompressed(x, y)).unwrap();
    VerifyingKey::from_sec1_point(&point).unwrap()
}

/// A registration asking for previewSign with `input` and for enterprise
/// attestation 2, the platform-managed kind.
fn enterprise_mc_req(input: &[u8]) -> Vec<u8> {
    enc(|e| {
        e.map(6).unwrap();
        e.u8(1).unwrap().bytes(&CDH).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str(RP)
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&[1, 2, 3, 4]).unwrap();
        e.str("name").unwrap().str("alice").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(6).unwrap().map(1).unwrap().str(NAME).unwrap();
        e.writer_mut().write_all(input).unwrap();
        e.u8(0x0A).unwrap().u8(2).unwrap();
    })
}

/// Under enterprise attestation the signing key is attested as the credential is:
/// by the organisation's key, with its chain, both signed off the one choice.
#[test]
fn an_enterprise_registration_attests_the_signing_key_with_the_org_key() {
    let (mut board, org, chain) = enterprise_board();
    let input = generate_key(&[ALG_ESP256_SPLIT_ARKG], Some(1));
    let reg = registered(&board.mc(&enterprise_mc_req(&input)).unwrap());
    assert!(reg.fields.contains(&4), "epAtt: {:?}", reg.fields);
    let key = attested_key(reg.att_obj.as_deref().unwrap());
    let (sig, x5c) = packed(&key.att_stmt);
    assert_eq!(x5c, packed(&reg.att_stmt).1, "the credential's chain");
    assert_eq!(x5c, chain);
    assert!(
        attests(&org_key(&org), &key.auth_data, &sig),
        "the org key attests the signing key"
    );
}

/// Over an org chain that reads back cut, what a build before ab8bcfc3 could store,
/// no enterprise attestation is performed: the credential takes the device's own,
/// and its signing key the `none` object a registration without EA gets.
#[test]
fn an_enterprise_request_over_a_cut_chain_attests_no_signing_key() {
    let (mut board, _, _) = enterprise_board();
    let mut cut = std::vec![2u8];
    for _ in 0..2 {
        cut.extend_from_slice(&1500u16.to_le_bytes());
        cut.extend_from_slice(&[0x30; 1500]);
    }
    assert!(cut.len() > crate::cert::ATT_CHAIN_REC_MAX);
    board.fs.put(crate::consts::EF_ATT_CHAIN, &cut).unwrap();
    let input = generate_key(&[ALG_ESP256_SPLIT_ARKG], Some(1));
    let reg = registered(&board.mc(&enterprise_mc_req(&input)).unwrap());
    assert!(!reg.fields.contains(&4), "epAtt: {:?}", reg.fields);
    let mut ee = [0u8; 1024];
    let n = board.fs.read(crate::consts::EF_EE_DEV, &mut ee).unwrap();
    let (_, x5c) = packed(&reg.att_stmt);
    assert_eq!(x5c, [ee[..n].to_vec()], "the device's own certificate");
    let key = attested_key(reg.att_obj.as_deref().unwrap());
    assert_eq!(key.fmt, "none");
    assert_eq!(key.att_stmt, [0xA0], "an empty map");
}

/// The other half: with the org key installed but enterprise attestation not asked
/// for, the org key vouches for nothing, since a signature under it names the
/// organisation to the site: the device's key attests the credential, none its key.
#[test]
fn a_registration_without_enterprise_attestation_keeps_the_org_key_out() {
    let (mut board, org, chain) = enterprise_board();
    let input = generate_key(&[ALG_ESP256_SPLIT_ARKG], Some(1));
    let reg = registered(
        &board
            .mc(&mc_req(ALG_ES256, Some(&input), false, false))
            .unwrap(),
    );
    assert!(!reg.fields.contains(&4), "epAtt: {:?}", reg.fields);
    let (sig, x5c) = packed(&reg.att_stmt);
    assert_ne!(x5c, chain, "the org chain rode a registration without EA");
    assert!(!attests(&org_key(&org), &reg.auth_data, &sig));
    assert!(attests(&board.attestation_key(), &reg.auth_data, &sig));
    let key = attested_key(reg.att_obj.as_deref().unwrap());
    assert_eq!(key.fmt, "none");
    assert_eq!(key.att_stmt, [0xA0], "an empty map");
}

/// Enterprise attestation performed with no org key installed is the device's own,
/// with `ep`; the signing key is attested as the credential is, by the device key.
#[test]
fn an_enterprise_registration_without_an_org_key_attests_the_signing_key_with_the_device_key() {
    let mut board = Board::new();
    board.fs.put(crate::consts::EF_EA_ENABLED, &[1]).unwrap();
    let input = generate_key(&[ALG_ESP256_SPLIT_ARKG], Some(1));
    let reg = registered(&board.mc(&enterprise_mc_req(&input)).unwrap());
    assert!(reg.fields.contains(&4), "epAtt: {:?}", reg.fields);
    let key = attested_key(reg.att_obj.as_deref().unwrap());
    assert_eq!(key.fmt, "packed");
    let (sig, x5c) = packed(&key.att_stmt);
    assert_eq!(x5c, packed(&reg.att_stmt).1, "the credential's chain");
    assert!(
        attests(&board.attestation_key(), &key.auth_data, &sig),
        "the device key attests the signing key"
    );
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| std::format!("{x:02x}")).collect()
}
