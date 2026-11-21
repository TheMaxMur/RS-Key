// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! OATH observations after the real CCID dispatcher has answered.
//!
//! The access code is a challenge-response gate, so a status word is not the
//! contract: SET CODE and VALIDATE are checked against an HMAC computed here,
//! independently of `rsk_crypto` (which the applet itself calls). The applet's
//! challenge is read out of the SELECT response, never guessed, so a stale
//! challenge is a refusal the oracle can predict.

use super::{APPLETS, Apdu, INS_GET_RESPONSE, Sw, status};
use sha2::{Digest, Sha256, Sha512};

const PUT: u8 = 0x01;
const DELETE: u8 = 0x02;
const SET_CODE: u8 = 0x03;
const RESET: u8 = 0x04;
const RENAME: u8 = 0x05;
const CALCULATE: u8 = 0xA2;
const VALIDATE: u8 = 0xA3;
const OATH_INDEX: usize = 3;
const NAME: u8 = 0x71;
const KEY: u8 = 0x73;
const PROPERTY: u8 = 0x78;
const CHALLENGE: u8 = 0x74;
const RESPONSE: u8 = 0x75;
const ALGO: u8 = 0x7B;

const ALG_HMAC_SHA1: u8 = 0x01;
const CHALLENGE_LEN: usize = 8;
const SECRET_MIN: usize = 14;
const SECRET_MAX: usize = 64;

type Header = (u8, u8, u8, u8);

#[derive(Default)]
pub(super) struct OathOracle {
    selected: Option<usize>,
    code_set: bool,
    validated: bool,
    /// The access code a successful SET CODE installed: algorithm byte and
    /// secret, exactly as the wire carried them.
    code: Option<(u8, Vec<u8>)>,
    /// The applet's current challenge, parsed from the last SELECT response.
    /// `None` until a SELECT reveals one and after SET CODE regenerates it.
    challenge: Option<[u8; CHALLENGE_LEN]>,
    live: Vec<Vec<u8>>,
    chain: Option<(Header, Vec<u8>)>,
}

impl OathOracle {
    pub(super) fn reset_card(&mut self) {
        self.selected = None;
        self.validated = false;
        self.challenge = None;
        self.clear_chaining();
    }

    pub(super) fn clear_chaining(&mut self) {
        self.chain = None;
    }

    pub(super) fn factory_wipe(&mut self) {
        self.code_set = false;
        self.code = None;
        self.challenge = None;
        self.live.clear();
        // This target wipes Fs directly while the applets remain live: neither
        // the dispatcher's selection nor its buffered command was reset.
    }

    /// Whether an access code is installed, so the scripted route knows whether
    /// it may drive SET CODE (and whether a SELECT must carry a challenge).
    pub(super) fn code_set(&self) -> bool {
        self.code_set
    }

    pub(super) fn observe(&mut self, raw: &[u8], res: &[u8], enabled: [bool; 8]) {
        let Ok(p) = Apdu::parse(raw) else { return };
        if res.is_empty() {
            return;
        }
        let sw = status(res);
        let select = p.ins == 0xA4 && p.p1 == 4 && matches!(p.p2, 0 | 4);
        let header = (p.cla & !0x10, p.ins, p.p1, p.p2);
        // A held response and the no-chain GET RESPONSE acknowledgement do
        // not execute an applet command or open a new command chain.
        if p.ins == INS_GET_RESPONSE && self.chain.is_none() {
            return;
        }
        if !p.is_chaining() && p.is_secure_messaging() && !select && sw == Sw::CLA_NOT_SUPPORTED {
            return;
        }
        if p.is_chaining() {
            if sw != Sw::OK {
                self.clear_chaining();
                return;
            }
            let (_, body) = self.chain.get_or_insert_with(|| (header, Vec::new()));
            body.extend_from_slice(p.data);
            return;
        }
        if select {
            self.clear_chaining();
            let found = APPLETS.iter().enumerate().position(|(i, (aid, _))| {
                enabled[i] && !p.data.is_empty() && aid.starts_with(p.data)
            });
            if let Some(i) = found {
                if i == OATH_INDEX {
                    self.select_response(res, sw);
                } else {
                    self.challenge = None;
                }
                let reselect = self.selected == Some(i);
                self.validated =
                    i == OATH_INDEX && (!self.code_set || (reselect && self.validated));
                self.selected = Some(i);
            }
            return;
        }
        let data = if let Some((opener, mut body)) = self.chain.take() {
            if header != opener || body.len() + p.nc > rsk_sdk::applet::CHAIN_BUF_SIZE {
                return;
            }
            body.extend_from_slice(p.data);
            body
        } else {
            p.data.to_vec()
        };
        if self.selected != Some(OATH_INDEX) || !enabled[OATH_INDEX] {
            return;
        }
        self.command(p.ins, &data, res, sw);
    }

    /// The SELECT body is the applet's word on where the challenge starts: the
    /// challenge and its algorithm are present exactly when a code is set.
    fn select_response(&mut self, res: &[u8], sw: Sw) {
        assert_eq!(sw, Sw::OK, "OATH SELECT answered {sw:?}");
        let body = &res[..res.len() - 2];
        let challenge = rsk_sdk::tlv::find_tag(body, u16::from(CHALLENGE));
        let algo = rsk_sdk::tlv::find_tag(body, u16::from(ALGO));
        if self.code_set {
            let challenge = challenge.expect("SELECT with a code set carried no TAG_CHALLENGE");
            assert_eq!(
                challenge.len(),
                CHALLENGE_LEN,
                "SELECT challenge width is not {CHALLENGE_LEN}"
            );
            assert_eq!(
                algo,
                Some([ALG_HMAC_SHA1].as_slice()),
                "SELECT algorithm is not HMAC-SHA1"
            );
            self.challenge = Some(challenge.try_into().expect("width checked above"));
        } else {
            assert!(
                challenge.is_none(),
                "a code-less SELECT carried a challenge"
            );
            assert!(algo.is_none(), "a code-less SELECT carried an algorithm");
            self.challenge = None;
        }
    }

    fn command(&mut self, ins: u8, data: &[u8], res: &[u8], sw: Sw) {
        let success = sw == Sw::OK || sw.to_bytes()[0] == 0x61;
        if self.code_set
            && !self.validated
            && matches!(ins, PUT | DELETE | SET_CODE | RENAME | CALCULATE)
        {
            assert!(
                !success,
                "OATH {ins:#04x} was served without a validated code"
            );
        }
        match ins {
            SET_CODE if success => self.accept_set_code(data),
            VALIDATE if success => self.accept_validate(data, res),
            VALIDATE if sw == Sw::DATA_INVALID && self.code_set => self.validated = false,
            RESET if success => {
                self.factory_wipe();
                self.validated = true;
            }
            _ => {}
        }
        if !success {
            return;
        }
        let mut names = fields(data).filter_map(|(tag, value)| (tag == NAME).then_some(value));
        // DELETE uses the SDK's BER walker, without PUT/RENAME's bare PROPERTY.
        let name = if ins == DELETE {
            rsk_sdk::tlv::find_tag(data, u16::from(NAME))
        } else {
            names.next()
        };
        let Some(name) = name else { return };
        match ins {
            PUT => {
                if !self.live.iter().any(|held| held == name) {
                    self.live.push(name.to_vec());
                }
            }
            DELETE => self.live.retain(|held| held != name),
            RENAME => {
                let new_name = names.next().expect("successful RENAME has two names");
                let held = self
                    .live
                    .iter_mut()
                    .find(|held| held.as_slice() == name)
                    .expect("OATH RENAME served a credential no acknowledged PUT left live");
                *held = new_name.to_vec();
            }
            CALCULATE => assert!(
                self.live.iter().any(|held| held == name),
                "OATH CALCULATE served a credential no acknowledged PUT left live"
            ),
            _ => {}
        }
    }

    /// Assert the successful SET CODE really was `HMAC(alg, secret, challenge)`,
    /// then remember the secret it installed. `73 00` is the removal.
    fn accept_set_code(&mut self, data: &[u8]) {
        assert!(
            self.validated,
            "SET CODE succeeded while the applet was locked"
        );
        let mut fields = fields(data);
        let Some((tag, key)) = fields.next() else {
            panic!("SET CODE succeeded without a KEY field");
        };
        assert_eq!(tag, KEY, "SET CODE succeeded without a KEY first field");
        if key.is_empty() {
            assert!(
                fields.next().is_none(),
                "SET CODE removal accepted trailing fields"
            );
            self.code = None;
            self.code_set = false;
            self.validated = true;
            self.challenge = None;
            return;
        }
        let Some((tag, challenge)) = fields.next() else {
            panic!("SET CODE succeeded without a CHALLENGE field");
        };
        assert_eq!(
            tag, CHALLENGE,
            "SET CODE succeeded without a CHALLENGE second field"
        );
        let Some((tag, response)) = fields.next() else {
            panic!("SET CODE succeeded without a RESPONSE field");
        };
        assert_eq!(
            tag, RESPONSE,
            "SET CODE succeeded without a RESPONSE third field"
        );
        assert!(
            fields.next().is_none(),
            "SET CODE accepted a field after RESPONSE"
        );
        assert_eq!(
            challenge.len(),
            CHALLENGE_LEN,
            "SET CODE accepted a challenge that is not {CHALLENGE_LEN} bytes"
        );
        let (alg, secret) = key.split_first().expect("non-empty KEY has an algorithm");
        assert!(
            (SECRET_MIN..=SECRET_MAX).contains(&secret.len()),
            "SET CODE accepted a {}-byte secret",
            secret.len()
        );
        let expected =
            hmac(*alg, secret, challenge).expect("SET CODE installed an algorithm with no HMAC");
        assert_eq!(
            response,
            expected.as_slice(),
            "SET CODE accepted a response that is not HMAC(alg, secret, challenge)"
        );
        self.code = Some((*alg, secret.to_vec()));
        self.code_set = true;
        self.validated = false;
        // The applet regenerated its own challenge; only a SELECT can reveal it.
        self.challenge = None;
    }

    /// Assert the proof answers the challenge SELECT handed out, and that the
    /// mutual answer is the same key over the host's challenge.
    fn accept_validate(&mut self, data: &[u8], res: &[u8]) {
        let (alg, secret) = self
            .code
            .clone()
            .expect("VALIDATE succeeded without a host-known code");
        let current = self
            .challenge
            .expect("VALIDATE succeeded before a SELECT revealed a challenge");
        let mut fields = fields(data);
        let Some((tag, response)) = fields.next() else {
            panic!("VALIDATE succeeded without a RESPONSE field");
        };
        assert_eq!(
            tag, RESPONSE,
            "VALIDATE succeeded without a RESPONSE first field"
        );
        let Some((tag, host_challenge)) = fields.next() else {
            panic!("VALIDATE succeeded without a CHALLENGE field");
        };
        assert_eq!(
            tag, CHALLENGE,
            "VALIDATE succeeded without a CHALLENGE second field"
        );
        assert!(
            fields.next().is_none(),
            "VALIDATE accepted a field after CHALLENGE"
        );
        let expected =
            hmac(alg, &secret, &current).expect("the stored access code's algorithm has no HMAC");
        assert_eq!(
            response,
            expected.as_slice(),
            "VALIDATE accepted a response that is not HMAC(stored secret, applet challenge)"
        );
        let answer = hmac(alg, &secret, host_challenge)
            .expect("the stored access code's algorithm has no HMAC");
        let body = &res[..res.len() - 2];
        let answered = rsk_sdk::tlv::find_tag(body, u16::from(RESPONSE))
            .expect("a successful VALIDATE carried no TAG_RESPONSE");
        assert_eq!(
            answered,
            answer.as_slice(),
            "VALIDATE answer is not HMAC(stored secret, host challenge)"
        );
        self.validated = true;
    }
}

// OATH accepts BER lengths and a bare PROPERTY byte in PUT/RENAME; the SDK's
// general TLV walker treats that byte as a length. Only observed fields matter.
fn fields(mut data: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    std::iter::from_fn(move || {
        let tag = *data.first()?;
        let (start, len) = if tag == PROPERTY {
            (1, 1)
        } else {
            match *data.get(1)? {
                0x81 => (3, *data.get(2)? as usize),
                0x82 => (
                    4,
                    u16::from_be_bytes([*data.get(2)?, *data.get(3)?]) as usize,
                ),
                len => (2, len as usize),
            }
        };
        let end = start + len;
        let value = data.get(start..end)?;
        data = data.get(end..)?;
        Some((tag, value))
    })
}

/// HMAC under a YKOATH algorithm byte (1 = SHA-1, 2 = SHA-256, 3 = SHA-512),
/// or `None` for a nibble the applet would have refused. Independent of
/// `rsk_crypto` on purpose: the point is a second computation.
pub(super) fn hmac(alg: u8, key: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    match alg & 0x0F {
        ALG_HMAC_SHA1 => Some(hmac_sha1(key, msg).to_vec()),
        2 => Some(hmac_sha256(key, msg).to_vec()),
        3 => Some(hmac_sha512(key, msg).to_vec()),
        _ => None,
    }
}

fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    hmac_block::<64, 20, _>(key, msg, sha1)
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    hmac_block::<64, 32, _>(key, msg, sha256)
}

fn hmac_sha512(key: &[u8], msg: &[u8]) -> [u8; 64] {
    hmac_block::<128, 64, _>(key, msg, sha512)
}

/// The RFC 2104 construction: hash the (possibly hashed) key into a block,
/// then `H((k ^ opad) || H((k ^ ipad) || msg))`.
fn hmac_block<const BLOCK: usize, const OUT: usize, F>(key: &[u8], msg: &[u8], hash: F) -> [u8; OUT]
where
    F: Fn(&[u8]) -> [u8; OUT],
{
    let mut block = [0u8; BLOCK];
    if key.len() > BLOCK {
        block[..OUT].copy_from_slice(&hash(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(BLOCK + msg.len());
    let mut outer = Vec::with_capacity(BLOCK + OUT);
    inner.extend(block.iter().map(|b| b ^ 0x36));
    outer.extend(block.iter().map(|b| b ^ 0x5c));
    inner.extend_from_slice(msg);
    outer.extend_from_slice(&hash(&inner));
    hash(&outer)
}

fn sha256(msg: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(msg));
    out
}

fn sha512(msg: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out.copy_from_slice(&Sha512::digest(msg));
    out
}

/// A local SHA-1 (FIPS 180-4), deliberately not `rsk_crypto::sha1`.
fn sha1(msg: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let bit_len = (msg.len() as u64).wrapping_mul(8);
    let mut padded = msg.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for block in padded.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for (i, word) in block.as_chunks::<4>().0.iter().take(16).enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, &word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (dst, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(h) {
        *dst = word.to_be_bytes();
    }
    out
}

#[cfg(test)]
#[path = "cross_applet_oath_tests.rs"]
mod tests;
