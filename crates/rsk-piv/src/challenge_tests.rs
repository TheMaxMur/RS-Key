// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! How long an outstanding GENERAL AUTHENTICATE challenge/witness at 9B stays
//! answerable. SP 800-73-4 Part 2 §3.2.4 does not say, so the table is a YubiKey
//! 5.7.4 measurement (3/3, ten slots): only another `0x87` and a GET METADATA of
//! 9B itself leave one standing. Driven through the real dispatcher, because the
//! SELECT rows are the dispatcher's to answer.

use super::*;
use rsk_fs::storage::ram::RamStorage;
use rsk_sdk::Dispatcher;

const SERIAL: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const HASH: [u8; 32] = [0x22; 32];
const DEFAULT_PIN: [u8; 8] = [b'1', b'2', b'3', b'4', b'5', b'6', 0xFF, 0xFF];
const DEFAULT_MGM: [u8; 24] = [
    1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
];

struct TestRng(u64);
impl Rng for TestRng {
    fn fill(&mut self, b: &mut [u8]) {
        for x in b.iter_mut() {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *x = (self.0 >> 33) as u8;
        }
    }
}

/// Which handshake the fixture arms, and how its step 2 is built.
#[derive(Clone, Copy)]
enum Flow {
    /// t81: the card hands out a plaintext challenge; the host encrypts it.
    SingleChallenge,
    /// t80: the card hands out an encrypted witness; the host decrypts it.
    MutualWitness,
}

/// Arm a handshake at 9B, run `between`, then answer the ORIGINAL step 1.
/// Returns the status word of that answer: `9000` = the challenge survived.
fn answer_after(flow: Flow, between: &[&[u8]]) -> Sw {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    let rng = RefCell::new(TestRng(11));
    let pres = RefCell::new(AlwaysConfirm);
    let mut piv = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut applets: [&mut dyn Applet<Fs<RamStorage>>; 1] = [&mut piv];
    let mut disp = Dispatcher::default();
    let mut out = [0u8; 2048];

    let mut go = |applets: &mut [&mut dyn Applet<Fs<RamStorage>>], raw: &[u8]| {
        let mut res = ResBuf::new(&mut out);
        let sw = disp.process(raw, applets, &mut fs, &mut res);
        (sw, res.as_slice().to_vec())
    };

    let mut sel = vec![0x00u8, 0xA4, 0x04, 0x00, PIV_AID.len() as u8];
    sel.extend_from_slice(PIV_AID);
    assert_eq!(go(&mut applets, &sel).0, Sw::OK);

    let tag = match flow {
        Flow::SingleChallenge => 0x81,
        Flow::MutualWitness => 0x80,
    };
    let (sw, step1) = go(
        &mut applets,
        &[
            0x00,
            0x87,
            ALGO_AES192,
            0x9B,
            0x04,
            0x7C,
            0x02,
            tag,
            0x00,
            0x00,
        ],
    );
    assert_eq!(sw, Sw::OK, "step 1");
    let mut block: [u8; 16] = step1[4..20].try_into().unwrap();
    let mut step2 = match flow {
        Flow::SingleChallenge => {
            // The card's plaintext challenge, encrypted back.
            rsk_crypto::aes_ecb_encrypt_block(&DEFAULT_MGM, &mut block).unwrap();
            let mut v = vec![
                0x00u8,
                0x87,
                ALGO_AES192,
                0x9B,
                0x14,
                0x7C,
                0x12,
                0x82,
                0x10,
            ];
            v.extend_from_slice(&block);
            v
        }
        Flow::MutualWitness => {
            // The card's encrypted witness, decrypted, plus a host challenge.
            rsk_crypto::aes_ecb_decrypt_block(&DEFAULT_MGM, &mut block).unwrap();
            let mut v = vec![
                0x00u8,
                0x87,
                ALGO_AES192,
                0x9B,
                0x26,
                0x7C,
                0x24,
                0x80,
                0x10,
            ];
            v.extend_from_slice(&block);
            v.extend_from_slice(&[0x81, 0x10]);
            v.extend_from_slice(&[0xA5; 16]);
            v
        }
    };
    step2.push(0x00);

    for raw in between {
        go(&mut applets, raw);
    }
    go(&mut applets, &step2).0
}

/// The intervening commands, and whether the oracle leaves the challenge standing.
fn rows() -> Vec<(&'static str, Vec<u8>, bool)> {
    let mut sel_piv = vec![0x00u8, 0xA4, 0x04, 0x00, PIV_AID.len() as u8];
    sel_piv.extend_from_slice(PIV_AID);
    vec![
        ("re-SELECT the PIV AID", sel_piv, true),
        // A GENERAL AUTHENTICATE that fails at another slot still shields it.
        (
            "GA at an empty slot 9A",
            vec![
                0x00, 0x87, 0x11, 0x9A, 0x08, 0x7C, 0x06, 0x82, 0x00, 0x81, 0x02, 0xAA, 0xBB, 0x00,
            ],
            true,
        ),
        ("GET METADATA 9B", vec![0x00, 0xF7, 0x00, 0x9B, 0x00], true),
        ("GET METADATA 9A", vec![0x00, 0xF7, 0x00, 0x9A, 0x00], false),
        (
            "GET DATA (CHUID)",
            vec![
                0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x02, 0x00,
            ],
            false,
        ),
        (
            "PUT DATA (fails)",
            vec![0x00, 0xDB, 0x3F, 0xFF, 0x03, 0x5C, 0x01, 0x99],
            false,
        ),
        (
            "VERIFY (correct PIN)",
            {
                let mut v = vec![0x00u8, 0x20, 0x00, 0x80, 0x08];
                v.extend_from_slice(&DEFAULT_PIN);
                v
            },
            false,
        ),
        (
            "VERIFY (wrong PIN)",
            vec![
                0x00, 0x20, 0x00, 0x80, 0x08, b'9', b'9', b'9', b'9', b'9', b'9', 0xFF, 0xFF,
            ],
            false,
        ),
        ("VERIFY status query", vec![0x00, 0x20, 0x00, 0x80], false),
        ("GET VERSION", vec![0x00, 0xFD, 0x00, 0x00, 0x00], false),
        ("GET SERIAL", vec![0x00, 0xF8, 0x00, 0x00, 0x00], false),
        (
            "an unimplemented INS",
            vec![0x00, 0xEE, 0x00, 0x00, 0x00],
            false,
        ),
    ]
}

#[test]
fn an_outstanding_challenge_survives_only_two_commands() {
    for flow in [Flow::SingleChallenge, Flow::MutualWitness] {
        assert_eq!(
            answer_after(flow, &[]),
            Sw::OK,
            "control: nothing intervened"
        );
        for (name, raw, survives) in rows() {
            let want = if survives {
                Sw::OK
            } else {
                Sw::INCORRECT_PARAMS
            };
            assert_eq!(answer_after(flow, &[&raw]), want, "after {name}");
        }
    }
}

/// The neighbouring cells the same handshake answers, all measured: a challenge is
/// single-use, and "no challenge outstanding" is a different status word from
/// "wrong answer" — a fix for the lifetime must not collapse the two.
#[test]
fn a_challenge_is_single_use() {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    let rng = RefCell::new(TestRng(3));
    let pres = RefCell::new(AlwaysConfirm);
    let mut piv = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut applets: [&mut dyn Applet<Fs<RamStorage>>; 1] = [&mut piv];
    let mut disp = Dispatcher::default();
    let mut out = [0u8; 2048];
    let mut go = |applets: &mut [&mut dyn Applet<Fs<RamStorage>>], raw: &[u8]| {
        let mut res = ResBuf::new(&mut out);
        let sw = disp.process(raw, applets, &mut fs, &mut res);
        (sw, res.as_slice().to_vec())
    };
    let mut sel = vec![0x00u8, 0xA4, 0x04, 0x00, PIV_AID.len() as u8];
    sel.extend_from_slice(PIV_AID);
    assert_eq!(go(&mut applets, &sel).0, Sw::OK);

    let (sw, step1) = go(
        &mut applets,
        &[
            0x00,
            0x87,
            ALGO_AES192,
            0x9B,
            0x04,
            0x7C,
            0x02,
            0x81,
            0x00,
            0x00,
        ],
    );
    assert_eq!(sw, Sw::OK);
    let mut block: [u8; 16] = step1[4..20].try_into().unwrap();
    rsk_crypto::aes_ecb_encrypt_block(&DEFAULT_MGM, &mut block).unwrap();
    let mut step2 = vec![
        0x00u8,
        0x87,
        ALGO_AES192,
        0x9B,
        0x14,
        0x7C,
        0x12,
        0x82,
        0x10,
    ];
    step2.extend_from_slice(&block);
    step2.push(0x00);

    assert_eq!(go(&mut applets, &step2).0, Sw::OK);
    assert_eq!(
        go(&mut applets, &step2).0,
        Sw::INCORRECT_PARAMS,
        "the same challenge answered twice"
    );
}
