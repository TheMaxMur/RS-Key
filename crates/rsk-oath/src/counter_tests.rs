// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! HOTP's moving factor on a medium that refuses to advance it. The response buffer
//! reaches the wire whatever the status word says, so a code built ahead of a refused
//! counter write is issued a second time by the next CALCULATE.

use super::*;
use std::rc::Rc;

#[derive(Default)]
struct BoundValue {
    sealed: Option<Vec<u8>>,
    refuse_read: bool,
    refuse_write: bool,
}

struct BoundStorage {
    inner: RamStorage,
    value: Rc<RefCell<BoundValue>>,
}

impl Storage for BoundStorage {
    fn read(&mut self, fid: u16, out: &mut [u8]) -> Option<usize> {
        self.inner.read(fid, out)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
        if fid == EF_OATH_CRED {
            self.value.borrow_mut().sealed = None;
        }
        self.inner.write(fid, data)
    }
    fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
        if fid == EF_OATH_CRED {
            self.value.borrow_mut().sealed = None;
        }
        self.inner.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.inner.size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(f)
    }
    fn read_bound_counter(
        &mut self,
        fid: u16,
        out: &mut [u8],
    ) -> rsk_sdk::error::Result<Option<usize>> {
        assert_eq!(fid, EF_OATH_CRED);
        let state = self.value.borrow();
        if state.refuse_read {
            return Err(rsk_sdk::error::Error::MemoryFatal);
        }
        Ok(state.sealed.as_ref().map(|value| {
            let count = value.len().min(out.len());
            out[..count].copy_from_slice(&value[..count]);
            value.len()
        }))
    }
    fn write_bound_counter(&mut self, fid: u16, sealed: &[u8]) -> rsk_sdk::error::Result<bool> {
        assert_eq!(fid, EF_OATH_CRED);
        let mut state = self.value.borrow_mut();
        if state.refuse_write {
            return Err(rsk_sdk::error::Error::MemoryFatal);
        }
        state.sealed = Some(sealed.to_vec());
        Ok(true)
    }
}

fn bound_fs() -> (Fs<BoundStorage>, Rc<RefCell<BoundValue>>) {
    let value = Rc::new(RefCell::new(BoundValue::default()));
    let mut fs = Fs::new(BoundStorage {
        inner: RamStorage::new(),
        value: value.clone(),
    });
    fs.scan();
    (fs, value)
}

#[test]
fn access_code_bytes_that_resemble_hotp_tlvs_never_read_a_bound_counter() {
    let (mut fs, _) = bound_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let mut key = [0; 17];
    key[..5].copy_from_slice(&[ALG_HMAC_SHA1, 0, TAG_KEY, 1, OATH_TYPE_HOTP]);
    let challenge = [9; CHALLENGE_LEN];
    let body = [
        tlv(TAG_KEY, &key),
        tlv(TAG_CHALLENGE, &challenge),
        tlv(TAG_RESPONSE, &hmac_sha1(&key[1..], &challenge)),
    ]
    .concat();
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_SET_CODE, 0, 0, &body)).0,
        Sw::OK
    );
    let body = [
        tlv(TAG_RESPONSE, &hmac_sha1(&key[1..], &app.challenge)),
        tlv(TAG_CHALLENGE, &challenge),
    ]
    .concat();
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_VALIDATE, 0, 0, &body)),
        (Sw::OK, tlv(TAG_RESPONSE, &hmac_sha1(&key[1..], &challenge)))
    );
}

/// What a healthy CALCULATE of the RFC 4226 credential answers at `counter`, in
/// either response form: the truncated code (`P2=01`) or the full HMAC (`P2=00`).
fn hotp_response(p2: u8, counter: u64) -> Vec<u8> {
    if p2 == 0x01 {
        let code: u32 = [755224, 287082][counter as usize];
        let mut v = vec![TAG_RESPONSE + 1, 5, 6];
        v.extend(code.to_be_bytes());
        return v;
    }
    let mut v = vec![TAG_RESPONSE, 21, 6];
    v.extend(hmac_sha1(SECRET_SHA1, &counter.to_be_bytes()));
    v
}

#[test]
fn a_refused_counter_advance_puts_no_hotp_code_on_the_wire() {
    for p2 in [0x00, 0x01] {
        let (mut fs, medium) = new_cut_fs();
        let rng = RefCell::new(CountRng(7));
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        let cred = put_data(b"h", 0x11, 6, SECRET_SHA1, false, None);
        assert_eq!(put(&mut app, &mut fs, &cred), Sw::OK);
        let mut body = tlv(TAG_NAME, b"h");
        body.extend(tlv(TAG_CHALLENGE, &0u64.to_be_bytes()));
        let calc = apdu(INS_CALCULATE, 0, p2, &body);

        medium.arm(0);
        let refused = run(&mut app, &mut fs, &calc);
        medium.arm(u32::MAX);
        let second = run(&mut app, &mut fs, &calc);
        let third = run(&mut app, &mut fs, &calc);

        assert_eq!(
            [refused, second, third],
            [
                (Sw::MEMORY_FAILURE, vec![]),
                (Sw::OK, hotp_response(p2, 0)),
                (Sw::OK, hotp_response(p2, 1)),
            ],
            "P2={p2:02X}: a refused advance must send no code and burn no counter"
        );
    }
}

#[test]
fn bound_hotp_failures_never_release_a_code_or_fall_back_to_the_main_record() {
    for p2 in [0, 1] {
        let (mut fs, medium) = bound_fs();
        let rng = RefCell::new(CountRng(7));
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        let cred = put_data(b"h", 0x11, 6, SECRET_SHA1, false, None);
        assert_eq!(put(&mut app, &mut fs, &cred), Sw::OK);
        let fid = KeyFid::new(EF_OATH_CRED);
        let mut before = [0; seal::MAX_BLOB];
        let length = fs.read_key(fid, &mut before).unwrap();
        let body = [tlv(TAG_NAME, b"h"), tlv(TAG_CHALLENGE, &[])].concat();
        let calc = apdu(INS_CALCULATE, 0, p2, &body);
        medium.borrow_mut().refuse_write = true;
        assert_eq!(run(&mut app, &mut fs, &calc), (Sw::MEMORY_FAILURE, vec![]));
        medium.borrow_mut().refuse_write = false;
        assert_eq!(
            run(&mut app, &mut fs, &calc),
            (Sw::OK, hotp_response(p2, 0))
        );
        medium.borrow_mut().refuse_read = true;
        assert_eq!(run(&mut app, &mut fs, &calc), (Sw::MEMORY_FAILURE, vec![]));
        medium.borrow_mut().refuse_read = false;
        let sealed = medium.borrow().sealed.clone().unwrap();
        for damaged in [vec![0; 35], vec![0; 36], vec![0; 37]] {
            medium.borrow_mut().sealed = Some(damaged);
            assert_eq!(run(&mut app, &mut fs, &calc), (Sw::MEMORY_FAILURE, vec![]));
        }
        medium.borrow_mut().sealed = Some(sealed);
        assert_eq!(
            run(&mut app, &mut fs, &calc),
            (Sw::OK, hotp_response(p2, 1))
        );
        let mut after = [0; seal::MAX_BLOB];
        assert_eq!(fs.read_key(fid, &mut after), Some(length));
        assert_eq!(before, after);
    }
}

#[test]
fn root_migration_materializes_the_bound_hotp_counter_before_resealing_its_owner() {
    let (mut fs, medium) = bound_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let cred = put_data(b"h", 0x11, 6, SECRET_SHA1, false, None);
    assert_eq!(put(&mut app, &mut fs, &cred), Sw::OK);
    let body = [tlv(TAG_NAME, b"h"), tlv(TAG_CHALLENGE, &[])].concat();
    let calc = apdu(INS_CALCULATE, 0, 1, &body);
    assert_eq!(run(&mut app, &mut fs, &calc), (Sw::OK, hotp_response(1, 0)));
    let dev = Device {
        serial_hash: &[0x22; 32],
        serial_id: &SERIAL,
        otp_key: Some(&TEST_MKEK),
        latched: false,
    };
    let mut before = [0; seal::MAX_BLOB];
    let length = fs.read_key(KeyFid::new(EF_OATH_CRED), &mut before).unwrap();
    let detached = medium.borrow().sealed.clone();
    let generation = fs.write_gen();
    medium.borrow_mut().refuse_read = true;
    assert!(migrate_seal(&dev, &mut fs, &mut *rng.borrow_mut()));
    assert_eq!(fs.write_gen(), generation);
    let mut after = [0; seal::MAX_BLOB];
    assert_eq!(
        fs.read_key(KeyFid::new(EF_OATH_CRED), &mut after),
        Some(length)
    );
    assert_eq!(after, before);
    assert_eq!(medium.borrow().sealed, detached);
    medium.borrow_mut().refuse_read = false;
    assert!(!migrate_seal(&dev, &mut fs, &mut *rng.borrow_mut()));
    assert!(medium.borrow().sealed.is_none());
    let mut otp = OathApplet::new(
        SERIAL,
        [0x22; 32],
        Some(rsk_crypto::FusedKey::open(test_mkek)),
        &rng,
        &touch,
    );
    assert_eq!(run(&mut otp, &mut fs, &calc), (Sw::OK, hotp_response(1, 1)));
}
