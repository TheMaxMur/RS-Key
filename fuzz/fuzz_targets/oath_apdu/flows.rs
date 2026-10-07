// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_crypto::{hmac_sha1, hmac_sha256, hmac_sha512};
use rsk_fs::Storage;
use rsk_fs::storage::faults::ProbeStuck;
use rsk_oath::{EF_OATH_CRED, OathApplet};
use rsk_sdk::tlv::find_tag;

const NAME: u8 = 0x71;
const KEY: u8 = 0x73;
const CHALLENGE: u8 = 0x74;
const RESPONSE: u8 = 0x75;
const IMF: u8 = 0x7a;
const LOGIN: u8 = 0x83;
const PASSWORD: u8 = 0x84;
const PUT: u8 = 0x01;
const DELETE: u8 = 0x02;
const SET_CODE: u8 = 0x03;
const RENAME: u8 = 0x05;
const GET_CREDENTIAL: u8 = 0xb5;
const LIST: u8 = 0xa1;
const CALCULATE: u8 = 0xa2;
const VALIDATE: u8 = 0xa3;
const VERIFY_CODE: u8 = 0xb1;
const CALCULATE_ALL: u8 = 0xa4;
const PROPERTY: u8 = 0x78;
const ONLY_INCREASING: u8 = 1;
const PERSISTENT_READ: u8 = 0x40;
const MAX_MARK_CREDS: u16 = 3;

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut body = vec![tag, u8::try_from(value.len()).unwrap()];
    body.extend(value);
    body
}

fn command<S: Storage>(
    app: &mut OathApplet,
    fs: &mut Fs<S>,
    ins: u8,
    p2: u8,
    body: &[u8],
) -> (Sw, Vec<u8>) {
    let mut raw = vec![0, ins, 0, p2];
    if !body.is_empty() {
        raw.push(u8::try_from(body.len()).unwrap());
        raw.extend(body);
    }
    let apdu = Apdu::parse(&raw).unwrap();
    let mut bytes = [0; 4096];
    let mut res = ResBuf::new(&mut bytes);
    let sw = app.process(&apdu, fs, &mut res);
    (sw, res.as_slice().to_vec())
}

fn mac(alg: u8, key: &[u8], challenge: &[u8]) -> Vec<u8> {
    match alg {
        1 => hmac_sha1(key, challenge).to_vec(),
        2 => hmac_sha256(key, challenge).to_vec(),
        3 => hmac_sha512(key, challenge).to_vec(),
        _ => unreachable!(),
    }
}

fn code(mac: &[u8], digits: u8) -> [u8; 4] {
    let offset = usize::from(mac.last().unwrap() & 0xf);
    let word = u32::from_be_bytes(mac[offset..offset + 4].try_into().unwrap());
    ((word & 0x7fff_ffff) % 10u32.pow(u32::from(digits))).to_be_bytes()
}

pub(super) fn check(data: &[u8]) {
    check_marks(data);
    let selector = data.first().copied().unwrap_or(0);
    let alg = selector % 3 + 1;
    let digits = selector / 3 % 3 + 6;
    let hotp = selector & 0x20 != 0;
    let mut secret = vec![selector; 14];
    secret.extend(data.iter().take(50));
    let challenge = &data[..data.len().min(64)];
    let mut counter = [0; 4];
    for (dst, src) in counter.iter_mut().zip(data) {
        *dst = *src;
    }
    let initial = u64::from(u32::from_be_bytes(counter));
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    let rng = RefCell::new(CountRng(0));
    let touch = RefCell::new(rsk_oath::AlwaysConfirm);
    let mut app = OathApplet::new([1, 2, 3, 4, 5, 6, 7, 8], [0x22; 32], None, &rng, &touch);
    let mut key = vec![if hotp { 0x10 | alg } else { 0x20 | alg }, digits];
    key.extend(&secret);
    let mut put = tlv(NAME, b"credential");
    put.extend(tlv(KEY, &key));
    put.extend(tlv(LOGIN, b"login"));
    put.extend(tlv(PASSWORD, b"password"));
    if hotp {
        put.extend(tlv(IMF, &counter));
    }
    assert_eq!(command(&mut app, &mut fs, PUT, 0, &put), (Sw::OK, vec![]));
    let body = [tlv(NAME, b"credential"), tlv(CHALLENGE, challenge)].concat();
    let p2 = selector & 1;
    let moving = initial.to_be_bytes();
    let digest = mac(alg, &secret, if hotp { &moving } else { challenge });
    let mut answer = vec![digits];
    if p2 == 0 {
        answer.extend(&digest);
    } else {
        answer.extend(code(&digest, digits));
    }
    assert_eq!(
        command(&mut app, &mut fs, CALCULATE, p2, &body),
        (Sw::OK, tlv(RESPONSE + p2, &answer))
    );
    if hotp {
        let digest = mac(alg, &secret, &(initial + 1).to_be_bytes());
        let verify = [tlv(NAME, b"ignored"), tlv(RESPONSE, &code(&digest, digits))].concat();
        assert_eq!(
            command(&mut app, &mut fs, VERIFY_CODE, 0, &verify),
            (Sw::OK, vec![])
        );
    }
    let rename = [tlv(NAME, b"credential"), tlv(NAME, b"renamed")].concat();
    assert_eq!(
        command(&mut app, &mut fs, RENAME, 0, &rename),
        (Sw::OK, vec![])
    );
    let expected = [
        tlv(NAME, b"renamed"),
        tlv(LOGIN, b"login"),
        tlv(PASSWORD, b"password"),
    ]
    .concat();
    assert_eq!(
        command(&mut app, &mut fs, GET_CREDENTIAL, 0, &tlv(NAME, b"renamed")),
        (Sw::OK, expected)
    );
    assert_eq!(
        command(&mut app, &mut fs, DELETE, 0, &tlv(NAME, b"renamed")),
        (Sw::OK, vec![])
    );
    assert_eq!(command(&mut app, &mut fs, LIST, 0, &[]), (Sw::OK, vec![]));

    let mut access = vec![alg];
    access.extend(&secret);
    let mut auth_challenge = [0; 8];
    for (dst, src) in auth_challenge.iter_mut().zip(data) {
        *dst = *src;
    }
    let set = [
        tlv(KEY, &access),
        tlv(CHALLENGE, &auth_challenge),
        tlv(RESPONSE, &mac(alg, &secret, &auth_challenge)),
    ]
    .concat();
    assert_eq!(
        command(&mut app, &mut fs, SET_CODE, 0, &set),
        (Sw::OK, vec![])
    );
    let mut bytes = [0; 256];
    let mut res = ResBuf::new(&mut bytes);
    assert_eq!(Applet::select(&mut app, false, &mut fs, &mut res), Sw::OK);
    let card_challenge = find_tag(res.as_slice(), CHALLENGE.into()).unwrap();
    let proof = mac(alg, &secret, card_challenge);
    let mut wrong = proof.clone();
    wrong[0] ^= 1;
    let body = [tlv(RESPONSE, &wrong), tlv(CHALLENGE, &auth_challenge)].concat();
    assert_eq!(
        command(&mut app, &mut fs, VALIDATE, 0, &body),
        (Sw::WRONG_DATA, vec![]),
        "VALIDATE accepted a wrong access-code proof"
    );
    assert_eq!(
        command(&mut app, &mut fs, LIST, 0, &[]),
        (Sw::SECURITY_STATUS_NOT_SATISFIED, vec![])
    );
    let body = [tlv(RESPONSE, &proof), tlv(CHALLENGE, &auth_challenge)].concat();
    assert_eq!(
        command(&mut app, &mut fs, VALIDATE, 0, &body),
        (Sw::OK, tlv(RESPONSE, &mac(alg, &secret, &auth_challenge)))
    );
    assert_eq!(command(&mut app, &mut fs, LIST, 0, &[]), (Sw::OK, vec![]));
}

pub(super) fn mark_position(selector: u8, position: u8) -> (u16, u16) {
    let count = u16::from((selector & !PERSISTENT_READ) / 4) % MAX_MARK_CREDS + 1;
    let failed = u16::from(position) % count;
    (count, failed)
}

fn check_marks(data: &[u8]) {
    let raw_selector = data.first().copied().unwrap_or(0);
    let selector = raw_selector & !PERSISTENT_READ;
    let (count, failed) = mark_position(raw_selector, data.get(1).copied().unwrap_or(0));
    let alg = selector % 3 + 1;
    let digits = selector / 3 % 3 + 6;
    let p2 = selector & 1;
    let mut secret = vec![selector; 14];
    secret.extend(data.iter().skip(2).take(50));
    let (backend, medium) = ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    let rng = RefCell::new(CountRng(0));
    let touch = RefCell::new(rsk_oath::AlwaysConfirm);
    let mut app = OathApplet::new([1, 2, 3, 4, 5, 6, 7, 8], [0x22; 32], None, &rng, &touch);
    let mut key = vec![0x20 | alg, digits];
    key.extend(&secret);
    for i in 0..count {
        let name = [u8::try_from(i).unwrap()];
        let put = [
            tlv(NAME, &name),
            tlv(KEY, &key),
            vec![PROPERTY, ONLY_INCREASING],
        ]
        .concat();
        assert_eq!(command(&mut app, &mut fs, PUT, 0, &put), (Sw::OK, vec![]));
    }
    let before: Vec<_> = (0..count).map(|i| medium.value(EF_OATH_CRED + i)).collect();
    if raw_selector & PERSISTENT_READ == 0 {
        medium.stick_once(EF_OATH_CRED + failed);
    } else {
        medium.stick(Some(EF_OATH_CRED + failed));
    }
    let challenge = u64::from(selector) + 1;
    let body = tlv(CHALLENGE, &challenge.to_be_bytes());
    assert_eq!(
        command(&mut app, &mut fs, CALCULATE_ALL, p2, &body),
        (Sw::MEMORY_FAILURE, vec![]),
        "bulk code escaped a failed mark preflight"
    );
    for i in failed..count {
        assert_eq!(medium.value(EF_OATH_CRED + i), before[usize::from(i)]);
    }
    for i in 0..failed {
        let request = [tlv(NAME, &[u8::try_from(i).unwrap()]), body.clone()].concat();
        assert_eq!(
            command(&mut app, &mut fs, CALCULATE, p2, &request),
            (Sw::WRONG_DATA, vec![]),
            "the committed prefix must refuse its persisted challenge"
        );
    }
    medium.stick(None);
    let digest = mac(alg, &secret, &challenge.to_be_bytes());
    let mut answer = vec![digits];
    if p2 == 0 {
        answer.extend(&digest);
    } else {
        answer.extend(code(&digest, digits));
    }
    for i in failed..count {
        let request = [tlv(NAME, &[u8::try_from(i).unwrap()]), body.clone()].concat();
        assert_eq!(
            command(&mut app, &mut fs, CALCULATE, p2, &request),
            (Sw::OK, tlv(RESPONSE + p2, &answer)),
            "the unread suffix must still accept the unmarked challenge"
        );
    }
    let challenge = (challenge + 1).to_be_bytes();
    let digest = mac(alg, &secret, &challenge);
    let mut answer = vec![digits];
    if p2 == 0 {
        answer.extend(&digest);
    } else {
        answer.extend(code(&digest, digits));
    }
    let mut expected = Vec::new();
    for i in 0..count {
        expected.extend(tlv(NAME, &[u8::try_from(i).unwrap()]));
        expected.extend(tlv(RESPONSE + p2, &answer));
    }
    let body = tlv(CHALLENGE, &challenge);
    assert_eq!(
        command(&mut app, &mut fs, CALCULATE_ALL, p2, &body),
        (Sw::OK, expected)
    );
    assert_eq!(
        command(&mut app, &mut fs, CALCULATE_ALL, p2, &body),
        (Sw::WRONG_DATA, vec![])
    );
}
