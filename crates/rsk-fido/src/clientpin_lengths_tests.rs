// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The encrypted PIN inputs' lengths, cell by cell as a YubiKey 5.8.0 answered them
//! (measured 2026-09-30 with python-fido2 2.2.1). A row is a status byte per length,
//! `0x00` for success, in the order of the length list above it.

use super::*;

const PROTOCOLS: [(PinProto, u64); 2] = [(PinProto::Two, 2), (PinProto::One, 1)];

/// `len` bytes built the way the probe built them: `pt` zero-padded and encrypted
/// where `len` is the protocol's IV and whole blocks, filler bytes where it is not.
fn blob(plat: &Platform, len: usize, pt: &[u8]) -> std::vec::Vec<u8> {
    let iv = plat.proto.iv_overhead();
    if len < iv || !(len - iv).is_multiple_of(16) {
        return std::vec![0xA5; len];
    }
    let mut padded = std::vec![0u8; len - iv];
    let n = pt.len().min(padded.len());
    padded[..n].copy_from_slice(&pt[..n]);
    let mut out = [0u8; 16 + 256];
    let n = pinproto::encrypt(plat.proto, plat.secret(), &[0x55; 16], &padded, &mut out).unwrap();
    out[..n].to_vec()
}

/// `plat`'s MAC over `data`, or its complement.
fn mac(plat: &Platform, data: &[u8], good: bool) -> std::vec::Vec<u8> {
    let mut m = plat.mac(data);
    if !good {
        m.iter_mut().for_each(|b| *b ^= 0xFF);
    }
    m
}

fn status(answer: CtapResult) -> u8 {
    answer.map_or_else(|e| e.as_u8(), |_| 0)
}

/// setPIN on a fresh device with a newPinEnc of `len` bytes. Where the length holds a
/// padded PIN it is 64 non-zero bytes (a policy violation), elsewhere `1234`, which a
/// device that decrypted a short block count would take for a PIN.
fn set_pin_cell(proto: PinProto, wire: u64, len: usize, good: bool) -> (u8, bool) {
    let (mut fs, mut rng) = setup();
    let mut state = FidoState::new();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, proto, wire);
    let exact = len == PADDED_PIN_LEN + proto.iv_overhead();
    let pin: &[u8] = if exact {
        &[b'A'; PADDED_PIN_LEN]
    } else {
        b"1234"
    };
    let npe = blob(&plat, len, pin);
    let puap = mac(&plat, &npe, good);
    let req = build(&[
        (1, V::U(wire)),
        (2, V::U(3)),
        (3, V::Cose(&plat.x, &plat.y)),
        (4, V::B(&puap)),
        (5, V::B(&npe)),
    ]);
    let mut out = [0u8; 64];
    let answer = status(run(&mut fs, &mut rng, &mut state, &req, &mut out));
    (answer, fs.has_data(EF_PIN))
}

/// The lengths `yk/setpin_sweep.py` sent.
const SET_LENS: [usize; 34] = [
    0, 1, 15, 16, 17, 32, 48, 50, 63, 64, 65, 66, 70, 72, 79, 80, 81, 88, 90, 95, 96, 97, 100, 112,
    113, 127, 128, 129, 144, 145, 160, 200, 255, 256,
];
/// Both protocols, a bad MAC.
const SET_BAD_MAC: [u8; 34] = [
    0x37, 0x37, 0x37, 0x33, 0x37, 0x33, 0x33, 0x37, 0x37, 0x33, 0x37, 0x37, 0x37, 0x37, 0x37, 0x33,
    0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37,
    0x37, 0x37,
];
/// Protocol two, a good MAC. At 16 bytes, an IV and no ciphertext, the YubiKey
/// re-enumerated (three times of three); the row holds its neighbours' answer there.
const SET_TWO_GOOD_MAC: [u8; 34] = [
    0x37, 0x37, 0x37, 0x02, 0x37, 0x02, 0x02, 0x37, 0x37, 0x02, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37,
    0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37,
    0x37, 0x37,
];
/// Protocol one, a good MAC.
const SET_ONE_GOOD_MAC: [u8; 34] = [
    0x37, 0x37, 0x37, 0x02, 0x37, 0x02, 0x02, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x02,
    0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37, 0x37,
    0x37, 0x37,
];

/// setPIN with no PIN set: one length gate for both protocols ahead of the MAC (`37`),
/// then the MAC (`33`), then the padded PIN's exact length (`02`), then the PIN policy.
/// No cell stores a PIN.
#[test]
fn set_pin_judges_the_new_pin_length_as_a_yubikey_does() {
    let mut wrong = std::vec::Vec::new();
    for (proto, wire) in PROTOCOLS {
        for good in [false, true] {
            let row = match (proto, good) {
                (_, false) => &SET_BAD_MAC,
                (PinProto::Two, true) => &SET_TWO_GOOD_MAC,
                (PinProto::One, true) => &SET_ONE_GOOD_MAC,
            };
            for (&len, &want) in SET_LENS.iter().zip(row) {
                let (got, stored) = set_pin_cell(proto, wire, len, good);
                if got != want || stored {
                    wrong.push(format!(
                        "p{wire} {good} {len}: {got:#04x} {want:#04x} {stored}"
                    ));
                }
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "protocol, good MAC, newPinEnc bytes: answered, a YubiKey 5.8.0's, PIN stored: {wrong:#?}"
    );
}

/// changePIN over [`PIN`] with a newPinEnc of `len` bytes that pads [`PIN`] itself where
/// it can, so a cell that succeeds re-sets the same PIN, and a pinHashEnc of `hash_len`
/// bytes over `current`. Answers the status and the retries left after it.
fn change_pin_cell(
    proto: PinProto,
    wire: u64,
    len: usize,
    hash_len: usize,
    current: &[u8],
    good: bool,
) -> (u8, u8) {
    let (mut fs, mut rng, mut state, _) = setup_with_pin(PIN);
    let plat = key_agreement(&mut fs, &mut rng, &mut state, proto, wire);
    let npe = blob(&plat, len, PIN);
    let phe = blob(&plat, hash_len, &sha256(current)[..16]);
    let mut macd = npe.clone();
    macd.extend_from_slice(&phe);
    let puap = mac(&plat, &macd, good);
    let req = build(&[
        (1, V::U(wire)),
        (2, V::U(4)),
        (3, V::Cose(&plat.x, &plat.y)),
        (4, V::B(&puap)),
        (5, V::B(&npe)),
        (6, V::B(&phe)),
    ]);
    let mut out = [0u8; 64];
    let answer = status(run(&mut fs, &mut rng, &mut state, &req, &mut out));
    (answer, ef_pin_retries(&mut fs))
}

/// The lengths `yk/changepin_sweep.py` sent.
const CHANGE_LENS: [usize; 22] = [
    0, 1, 15, 16, 17, 32, 48, 50, 63, 64, 65, 70, 79, 80, 81, 95, 96, 97, 112, 128, 144, 256,
];
/// Both protocols, a bad MAC.
const CHANGE_BAD_MAC: [u8; 22] = [
    0x37, 0x37, 0x37, 0x33, 0x37, 0x33, 0x33, 0x37, 0x37, 0x33, 0x37, 0x37, 0x37, 0x33, 0x37, 0x37,
    0x37, 0x37, 0x37, 0x37, 0x37, 0x37,
];
/// Protocol two, a good MAC; at 16 bytes the YubiKey re-enumerated, as for setPIN.
const CHANGE_TWO_GOOD_MAC: [u8; 22] = [
    0x37, 0x37, 0x37, 0x02, 0x37, 0x02, 0x02, 0x37, 0x37, 0x02, 0x37, 0x37, 0x37, 0x00, 0x37, 0x37,
    0x37, 0x37, 0x37, 0x37, 0x37, 0x37,
];
/// Protocol one, a good MAC.
const CHANGE_ONE_GOOD_MAC: [u8; 22] = [
    0x37, 0x37, 0x37, 0x02, 0x37, 0x02, 0x02, 0x37, 0x37, 0x00, 0x37, 0x37, 0x37, 0x02, 0x37, 0x37,
    0x37, 0x37, 0x37, 0x37, 0x37, 0x37,
];

/// changePIN's newPinEnc, the right current PIN: `set_pin`'s gate first, then the MAC,
/// then the padded PIN's exact length only after the current PIN has been checked — so
/// no cell spends a retry, and every retry count stays at the full budget.
#[test]
fn change_pin_judges_the_new_pin_length_as_a_yubikey_does() {
    let mut wrong = std::vec::Vec::new();
    for (proto, wire) in PROTOCOLS {
        let hash = 16 + proto.iv_overhead();
        for good in [false, true] {
            let row = match (proto, good) {
                (_, false) => &CHANGE_BAD_MAC,
                (PinProto::Two, true) => &CHANGE_TWO_GOOD_MAC,
                (PinProto::One, true) => &CHANGE_ONE_GOOD_MAC,
            };
            for (&len, &want) in CHANGE_LENS.iter().zip(row) {
                let (got, retries) = change_pin_cell(proto, wire, len, hash, PIN, good);
                if got != want || retries != MAX_PIN_RETRIES {
                    wrong.push(format!(
                        "p{wire} {good} {len}: {got:#04x} {want:#04x} {retries}"
                    ));
                }
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "protocol, good MAC, newPinEnc bytes: answered, a YubiKey 5.8.0's, retries: {wrong:#?}"
    );
}

/// The order around the current PIN, measured the same session: the gate outranks a
/// wrong PIN and a pinHashEnc of the wrong length, and costs no retry; the exact length
/// does not outrank a wrong PIN, which spends one as it would anyway.
#[test]
fn change_pin_judges_the_new_pin_length_before_and_after_the_pin_as_a_yubikey_does() {
    for (proto, wire) in PROTOCOLS {
        let hash = 16 + proto.iv_overhead();
        for (len, hash_len, current, want) in [
            (96, hash, WRONG_PIN, (0x37, MAX_PIN_RETRIES)),
            (48, hash, WRONG_PIN, (0x31, MAX_PIN_RETRIES - 1)),
            (48, hash, PIN, (0x02, MAX_PIN_RETRIES)),
            (96, 48, PIN, (0x37, MAX_PIN_RETRIES)),
            (50, 48, PIN, (0x37, MAX_PIN_RETRIES)),
            (48, 48, PIN, (0x02, MAX_PIN_RETRIES)),
        ] {
            assert_eq!(
                change_pin_cell(proto, wire, len, hash_len, current, true),
                want,
                "protocol {wire}: newPinEnc {len}, pinHashEnc {hash_len}, the right PIN: {}",
                current == PIN
            );
        }
    }
}

/// The lengths `yk/changepin_sweep.py` sent for pinHashEnc.
const CHANGE_HASH_LENS: [usize; 13] = [0, 1, 15, 16, 17, 31, 32, 33, 47, 48, 64, 80, 96];
/// Both protocols, a bad MAC: one block, bare or behind protocol two's IV, reaches it.
const CHANGE_HASH_BAD_MAC: [u8; 13] = [
    0x02, 0x02, 0x02, 0x33, 0x02, 0x02, 0x33, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
];
/// Protocol two, a good MAC.
const CHANGE_HASH_TWO_GOOD_MAC: [u8; 13] = [
    0x02, 0x02, 0x02, 0x33, 0x02, 0x02, 0x00, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
];
/// Protocol one, a good MAC.
const CHANGE_HASH_ONE_GOOD_MAC: [u8; 13] = [
    0x02, 0x02, 0x02, 0x00, 0x02, 0x02, 0x33, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
];

/// changePIN's pinHashEnc, the padded new PIN [`PIN`] again: neither protocol's length is
/// `02` before the MAC, the other protocol's is `33` after it, and no cell spends a retry.
#[test]
fn change_pin_judges_the_pin_hash_length_as_a_yubikey_does() {
    let mut wrong = std::vec::Vec::new();
    for (proto, wire) in PROTOCOLS {
        let new = PADDED_PIN_LEN + proto.iv_overhead();
        for good in [false, true] {
            let row = match (proto, good) {
                (_, false) => &CHANGE_HASH_BAD_MAC,
                (PinProto::Two, true) => &CHANGE_HASH_TWO_GOOD_MAC,
                (PinProto::One, true) => &CHANGE_HASH_ONE_GOOD_MAC,
            };
            for (&len, &want) in CHANGE_HASH_LENS.iter().zip(row) {
                let (got, retries) = change_pin_cell(proto, wire, new, len, PIN, good);
                if got != want || retries != MAX_PIN_RETRIES {
                    wrong.push(format!(
                        "p{wire} {good} {len}: {got:#04x} {want:#04x} {retries}"
                    ));
                }
            }
        }
        // Ahead of the PIN check: a wrong PIN behind a pinHashEnc of 48 bytes costs nothing.
        let (got, retries) = change_pin_cell(proto, wire, new, 48, WRONG_PIN, true);
        if (got, retries) != (0x02, MAX_PIN_RETRIES) {
            wrong.push(format!("p{wire} wrong PIN 48: {got:#04x} {retries}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "protocol, good MAC, pinHashEnc bytes: answered, a YubiKey 5.8.0's, retries: {wrong:#?}"
    );
}

/// `rpId` example.com, CBOR-encoded, for 0x09's `ga`.
const EXAMPLE_COM: &[u8] = b"\x6bexample.com";

/// getPinToken (0x05), or getPinUvAuthTokenUsingPinWithPermissions (0x09) for `ga` at
/// example.com, over [`PIN`] with a pinHashEnc of `len` bytes over `current`. Answers
/// the status and the retries left after it.
fn get_token_cell(proto: PinProto, wire: u64, sub: u64, len: usize, current: &[u8]) -> (u8, u8) {
    let (mut fs, mut rng, mut state, _) = setup_with_pin(PIN);
    let plat = key_agreement(&mut fs, &mut rng, &mut state, proto, wire);
    let phe = blob(&plat, len, &sha256(current)[..16]);
    let mut fields = std::vec![
        (1, V::U(wire)),
        (2, V::U(sub)),
        (3, V::Cose(&plat.x, &plat.y)),
        (6, V::B(&phe)),
    ];
    if sub == CP_GET_PIN_UV_TOKEN_USING_PIN {
        fields.push((9, V::U(u64::from(PERM_GA))));
        fields.push((10, V::Raw(EXAMPLE_COM)));
    }
    let mut out = [0u8; 128];
    let answer = status(run(
        &mut fs,
        &mut rng,
        &mut state,
        &build(&fields),
        &mut out,
    ));
    (answer, ef_pin_retries(&mut fs))
}

/// The lengths `yk/order_probe.py` sent.
const TOKEN_HASH_LENS: [usize; 9] = [0, 15, 16, 17, 31, 32, 33, 48, 64];
/// Protocol two. At 16 bytes, an IV and no ciphertext, the hash compared is empty: a
/// wrong PIN, and a retry spent.
const TOKEN_TWO: [(u8, u8); 9] = [
    (0x02, MAX_PIN_RETRIES),
    (0x02, MAX_PIN_RETRIES),
    (0x31, MAX_PIN_RETRIES - 1),
    (0x02, MAX_PIN_RETRIES),
    (0x02, MAX_PIN_RETRIES),
    (0x00, MAX_PIN_RETRIES),
    (0x02, MAX_PIN_RETRIES),
    (0x02, MAX_PIN_RETRIES),
    (0x02, MAX_PIN_RETRIES),
];
/// Protocol one. At 32 bytes two blocks decrypt, and the first is the hash compared.
const TOKEN_ONE: [(u8, u8); 9] = [
    (0x02, MAX_PIN_RETRIES),
    (0x02, MAX_PIN_RETRIES),
    (0x00, MAX_PIN_RETRIES),
    (0x02, MAX_PIN_RETRIES),
    (0x02, MAX_PIN_RETRIES),
    (0x00, MAX_PIN_RETRIES),
    (0x02, MAX_PIN_RETRIES),
    (0x02, MAX_PIN_RETRIES),
    (0x02, MAX_PIN_RETRIES),
];

/// On a display the gate comes before the consent screen: a display whose user refuses
/// every consent answers `02` to a 48-byte pinHashEnc, and its refusal (`27`) to 32 bytes.
#[test]
fn a_malformed_pin_hash_asks_the_display_nothing() {
    for sub in [CP_GET_PIN_TOKEN, CP_GET_PIN_UV_TOKEN_USING_PIN] {
        for (len, want) in [
            (48, CtapError::InvalidParameter),
            (32, CtapError::OperationDenied),
        ] {
            let (mut fs, mut rng, mut state, _) = setup_with_pin(PIN);
            let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
            let phe = blob(&plat, len, &sha256(PIN)[..16]);
            let mut fields = std::vec![
                (1, V::U(2)),
                (2, V::U(sub)),
                (3, V::Cose(&plat.x, &plat.y)),
                (6, V::B(&phe)),
            ];
            if sub == CP_GET_PIN_UV_TOKEN_USING_PIN {
                fields.push((9, V::U(u64::from(PERM_GA))));
            }
            let mut out = [0u8; 128];
            let req = build(&fields);
            let answer = run_with(
                &mut DenyConsent,
                &mut fs,
                &mut rng,
                &mut state,
                &req,
                &mut out,
            );
            assert_eq!(
                answer,
                Err(want),
                "subcommand {sub:#04x}, pinHashEnc {len} bytes"
            );
            assert_eq!(ef_pin_retries(&mut fs), MAX_PIN_RETRIES);
        }
    }
}

/// getPinToken and 0x09 alike: a pinHashEnc of neither protocol's length is `02` before
/// the PIN is tried, so it costs no retry even behind a wrong PIN.
#[test]
fn get_pin_token_judges_the_pin_hash_length_as_a_yubikey_does() {
    let mut wrong = std::vec::Vec::new();
    for sub in [CP_GET_PIN_TOKEN, CP_GET_PIN_UV_TOKEN_USING_PIN] {
        for (proto, wire) in PROTOCOLS {
            let row = match proto {
                PinProto::Two => &TOKEN_TWO,
                PinProto::One => &TOKEN_ONE,
            };
            for (&len, &want) in TOKEN_HASH_LENS.iter().zip(row) {
                let got = get_token_cell(proto, wire, sub, len, PIN);
                if got != want {
                    wrong.push(format!("{sub:#04x} p{wire} {len}: {got:x?} {want:x?}"));
                }
            }
            let got = get_token_cell(proto, wire, sub, 48, WRONG_PIN);
            if got != (0x02, MAX_PIN_RETRIES) {
                wrong.push(format!("{sub:#04x} p{wire} wrong PIN 48: {got:x?}"));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "subcommand, protocol, pinHashEnc bytes: (answered, retries), a YubiKey 5.8.0's: {wrong:#?}"
    );
}
