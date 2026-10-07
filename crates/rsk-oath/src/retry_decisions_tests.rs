// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use std::cell::Cell;
use std::rc::Rc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RetryFault {
    None,
    RefuseWrite,
    RefuseFinalWrite,
    DropWrite,
    ShortReadback,
    WrongCounter,
}

struct RetryStorage {
    inner: RamStorage,
    fault: Rc<Cell<RetryFault>>,
    pending: bool,
    hits: Rc<Cell<usize>>,
}

impl Storage for RetryStorage {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        let n = self.inner.read(fid, buf)?;
        if fid == EF_OTP_PIN && self.pending {
            self.pending = false;
            self.hits.set(self.hits.get() + 1);
            match self.fault.get() {
                RetryFault::ShortReadback => return Some(n - 1),
                RetryFault::WrongCounter => buf[0] = buf[0].saturating_add(1),
                _ => unreachable!(),
            }
        }
        Some(n)
    }

    fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
        if fid == EF_OTP_PIN {
            match self.fault.get() {
                RetryFault::RefuseWrite => {
                    self.hits.set(self.hits.get() + 1);
                    return Err(rsk_sdk::error::Error::MemoryFatal);
                }
                RetryFault::DropWrite => {
                    self.hits.set(self.hits.get() + 1);
                    return Ok(());
                }
                RetryFault::RefuseFinalWrite => {
                    self.hits.set(self.hits.get() + 1);
                    if self.hits.get() == 2 {
                        return Err(rsk_sdk::error::Error::MemoryFatal);
                    }
                }
                RetryFault::ShortReadback | RetryFault::WrongCounter => self.pending = true,
                RetryFault::None => {}
            }
        }
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

#[test]
fn a_refused_final_pin_change_keeps_the_old_verifier_and_spent_retry() {
    let control = Rc::new(Cell::new(RetryFault::None));
    let hits = Rc::new(Cell::new(0));
    let mut fs = Fs::new(RetryStorage {
        inner: RamStorage::new(),
        fault: control.clone(),
        pending: false,
        hits: hits.clone(),
    });
    fs.scan();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let mut credential = put_data(b"bank", 0x21, 6, SECRET_SHA1, false, None);
    credential.extend(tlv(TAG_PWS_PASSWORD, b"s3cr3t"));
    assert_eq!(put(&mut app, &mut fs, &credential), Sw::OK);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))
        ),
        (Sw::OK, vec![])
    );
    assert_eq!(pin_command(&mut app, &mut fs, INS_VERIFY_PIN), Sw::OK);
    let mut before = [0; OTP_PIN_REC_V1];
    assert_eq!(fs.read(EF_OTP_PIN, &mut before), Some(before.len()));
    control.set(RetryFault::RefuseFinalWrite);
    let change = [tlv(TAG_PASSWORD, b"1234"), tlv(TAG_NEW_PASSWORD, b"5678")].concat();
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_CHANGE_PIN, 0, 0, &change)),
        (Sw::MEMORY_FAILURE, vec![])
    );
    assert_eq!(
        hits.get(),
        2,
        "the decrement succeeds and the replacement write refuses"
    );
    assert!(!app.validated && !app.otp_pin_verified);
    let mut after = [0; OTP_PIN_REC_V1];
    assert_eq!(fs.read(EF_OTP_PIN, &mut after), Some(after.len()));
    assert_eq!(after[0], before[0] - 1);
    assert_eq!(&after[1..], &before[1..]);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &apdu(INS_GET_CREDENTIAL, 0, 0, &tlv(TAG_NAME, b"bank"))
        ),
        (Sw::SECURITY_STATUS_NOT_SATISFIED, vec![])
    );
    control.set(RetryFault::None);
    let mut fs = Fs::new(fs.into_storage());
    fs.scan();
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, b"5678"))
        ),
        (Sw::SECURITY_STATUS_NOT_SATISFIED, vec![])
    );
    assert_eq!(pin_command(&mut app, &mut fs, INS_VERIFY_PIN), Sw::OK);
    let (sw, body) = run(
        &mut app,
        &mut fs,
        &apdu(INS_GET_CREDENTIAL, 0, 0, &tlv(TAG_NAME, b"bank")),
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(
        find_tag(&body, TAG_PWS_PASSWORD.into()),
        Some(b"s3cr3t".as_slice())
    );
}

fn pin_command<S: Storage>(app: &mut OathApplet, fs: &mut Fs<S>, ins: u8) -> Sw {
    let mut body = tlv(TAG_PASSWORD, b"1234");
    if ins == INS_CHANGE_PIN {
        body.extend(tlv(TAG_NEW_PASSWORD, b"5678"));
    }
    run(app, fs, &apdu(ins, 0, 0, &body)).0
}

#[test]
fn retry_persistence_faults_refuse_both_commands_and_close_the_safe() {
    for fault in [
        RetryFault::RefuseWrite,
        RetryFault::DropWrite,
        RetryFault::ShortReadback,
        RetryFault::WrongCounter,
    ] {
        for ins in [INS_VERIFY_PIN, INS_CHANGE_PIN] {
            let control = Rc::new(Cell::new(RetryFault::None));
            let hits = Rc::new(Cell::new(0));
            let mut fs = Fs::new(RetryStorage {
                inner: RamStorage::new(),
                fault: control.clone(),
                pending: false,
                hits: hits.clone(),
            });
            fs.scan();
            let rng = RefCell::new(CountRng(7));
            let touch = RefCell::new(AlwaysConfirm);
            let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
            let mut cred = put_data(b"bank", 0x21, 6, SECRET_SHA1, false, None);
            cred.extend(tlv(TAG_PWS_PASSWORD, b"s3cr3t"));
            assert_eq!(put(&mut app, &mut fs, &cred), Sw::OK);
            assert_eq!(
                run(
                    &mut app,
                    &mut fs,
                    &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))
                )
                .0,
                Sw::OK
            );
            assert_eq!(pin_command(&mut app, &mut fs, INS_VERIFY_PIN), Sw::OK);
            let mut before = [0; OTP_PIN_REC_V1];
            assert_eq!(fs.read(EF_OTP_PIN, &mut before), Some(before.len()));
            control.set(fault);
            assert_eq!(
                pin_command(&mut app, &mut fs, ins),
                Sw::SECURITY_STATUS_NOT_SATISFIED,
                "{fault:?}, INS {ins:02x}: an unconfirmed retry must not authorize the correct PIN"
            );
            assert_eq!(
                hits.get(),
                1,
                "the selected fault must reach the retry write/read-back"
            );
            assert!(!app.validated && !app.otp_pin_verified);
            control.set(RetryFault::None);
            let mut after = [0; OTP_PIN_REC_V1];
            assert_eq!(fs.read(EF_OTP_PIN, &mut after), Some(after.len()));
            assert_eq!(
                &after[1..],
                &before[1..],
                "a refused CHANGE must retain the verifier"
            );
            let spent = matches!(fault, RetryFault::ShortReadback | RetryFault::WrongCounter);
            assert_eq!(after[0], before[0] - u8::from(spent));
            assert_eq!(
                run(
                    &mut app,
                    &mut fs,
                    &apdu(INS_GET_CREDENTIAL, 0, 0, &tlv(TAG_NAME, b"bank"))
                )
                .0,
                Sw::SECURITY_STATUS_NOT_SATISFIED
            );
            assert_eq!(pin_command(&mut app, &mut fs, INS_VERIFY_PIN), Sw::OK);
            assert!(app.validated && app.otp_pin_verified);
            let (sw, response) = run(
                &mut app,
                &mut fs,
                &apdu(INS_GET_CREDENTIAL, 0, 0, &tlv(TAG_NAME, b"bank")),
            );
            assert_eq!(sw, Sw::OK);
            assert_eq!(
                find_tag(&response, TAG_PWS_PASSWORD as u16),
                Some(b"s3cr3t".as_slice())
            );
        }
    }
}

#[test]
fn malformed_stored_pin_lengths_are_not_authentication_attempts() {
    for len in [0, 1, 2, OTP_PIN_REC_LEGACY - 1, OTP_PIN_REC_V1 + 1, 65] {
        for ins in [INS_VERIFY_PIN, INS_CHANGE_PIN] {
            let mut fs = new_fs();
            let rng = RefCell::new(CountRng(7));
            let touch = RefCell::new(AlwaysConfirm);
            let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
            let dev = Device {
                serial_hash: &[0x22; 32],
                serial_id: &SERIAL,
                otp_key: None,
                latched: false,
            };
            let mut record = OathApplet::otp_pin_record_v1(&dev, b"1234").to_vec();
            record.resize(len, 0);
            fs.put(EF_OTP_PIN, &record).unwrap();
            assert_eq!(
                pin_command(&mut app, &mut fs, ins),
                Sw::CONDITIONS_NOT_SATISFIED,
                "stored length {len}, INS {ins:02x}"
            );
            assert!(!app.otp_pin_verified);
            let mut after = [0; 65];
            assert_eq!(fs.read(EF_OTP_PIN, &mut after), Some(len));
            assert_eq!(&after[..len], record);
        }
    }
}

#[test]
fn refused_verify_rescrub_keeps_the_old_verifier_and_the_spent_retry() {
    let (storage, medium) = RemoveStuck::new();
    let mut fs = Fs::new(storage);
    fs.scan();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let nootp = Device {
        serial_hash: &[0x22; 32],
        serial_id: &SERIAL,
        otp_key: None,
        latched: false,
    };
    let old = OathApplet::otp_pin_record_v1(&nootp, b"1234");
    fs.put(EF_OTP_PIN, &old).unwrap();
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    medium.refuse(Some(rsk_fs::EF_HARDENED));
    let mut app = OathApplet::new(
        SERIAL,
        [0x22; 32],
        Some(rsk_crypto::FusedKey::open(test_mkek)),
        &rng,
        &touch,
    );
    assert_eq!(pin_command(&mut app, &mut fs, INS_VERIFY_PIN), Sw::OK);
    assert!(app.validated && app.otp_pin_verified);
    let mut record = [0; OTP_PIN_REC_V1];
    assert_eq!(fs.read(EF_OTP_PIN, &mut record), Some(record.len()));
    assert_eq!(record[0], MAX_OTP_COUNTER - 1);
    assert_eq!(&record[1..], &old[1..]);
    assert!(medium.live(rsk_fs::EF_HARDENED));
    medium.refuse(None);
    assert_eq!(pin_command(&mut app, &mut fs, INS_VERIFY_PIN), Sw::OK);
    assert_eq!(fs.read(EF_OTP_PIN, &mut record), Some(record.len()));
    let otp = Device {
        otp_key: Some(&TEST_MKEK),
        ..nootp
    };
    assert_eq!(record, OathApplet::otp_pin_record_v1(&otp, b"1234"));
    assert!(!medium.live(rsk_fs::EF_HARDENED));
}
