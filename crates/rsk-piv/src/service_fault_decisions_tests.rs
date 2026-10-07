// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

const OTP: [u8; 32] = [0x55; 32];
const ADMIN_DATA_ID: u32 = 0x5f_ff_00;

std::thread_local! {
    static READS: Cell<usize> = const { Cell::new(0) };
    static FAIL_AT: Cell<Option<usize>> = const { Cell::new(None) };
}

fn arm_key_read(fail: Option<usize>) {
    READS.with(|reads| reads.set(0));
    FAIL_AT.with(|fault| fault.set(fail));
}

fn key_source(out: &mut [u8; 32]) -> bool {
    let at = READS.with(|reads| {
        let next = reads.get() + 1;
        reads.set(next);
        next
    });
    *out = OTP;
    !FAIL_AT.with(|fault| fault.get() == Some(at))
}

fn identity(otp: bool) -> Device<'static> {
    Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: otp.then_some(&OTP),
        latched: otp,
    }
}

fn stored<S: Storage>(fs: &mut Fs<S>, fid: u16) -> Option<Vec<u8>> {
    let mut bytes = [0; rsk_fs::MAX_VALUE_BYTES];
    fs.read(fid, &mut bytes)
        .map(|n| bytes[..n.min(bytes.len())].to_vec())
}

#[test]
fn empty_fixed_objects_refuse_or_synthesize_the_declared_default_without_writing() {
    for id in [CHUID_ID, PRINTED_ID, ADMIN_DATA_ID] {
        let rng = RefCell::new(TestRng(7));
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        verify_pin(&mut app, &mut fs);
        let fid = object_fid(id).unwrap();
        fs.put(fid, &[]).unwrap();
        assert_eq!(fs.read(fid, &mut [0; 1]), Some(0));
        let path = [
            TAG_DATA_PATH,
            3,
            u8::try_from(id >> 16).unwrap(),
            u8::try_from((id >> 8) & 0xff).unwrap(),
            u8::try_from(id & 0xff).unwrap(),
        ];
        let generation = fs.write_gen();
        let response = run(&mut app, &mut fs, INS_GET_DATA, 0x3f, 0xff, &path);
        if id == CHUID_ID {
            let body = crate::chuid::default_chuid(&HASH);
            let mut expected = vec![TAG_DATA_OBJECT, u8::try_from(body.len()).unwrap()];
            expected.extend_from_slice(&body);
            assert_eq!(response, (Sw::OK, expected));
        } else {
            assert_eq!(response, (Sw::FILE_NOT_FOUND, vec![]));
        }
        assert_eq!(fs.write_gen(), generation);
        assert_eq!(stored(&mut fs, fid), Some(vec![]));
        fs.put(fid, b"healthy").unwrap();
        let mut expected = vec![TAG_DATA_OBJECT, 7];
        expected.extend_from_slice(b"healthy");
        assert_eq!(
            run(&mut app, &mut fs, INS_GET_DATA, 0x3f, 0xff, &path),
            (Sw::OK, expected)
        );
    }
}

#[test]
fn management_metadata_requires_its_head_without_replacing_the_sealed_key() {
    for head in [
        None,
        Some(&[][..]),
        Some(&[ALGO_AES192][..]),
        Some(&[ALGO_AES192, 0][..]),
    ] {
        let rng = RefCell::new(TestRng(7));
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        verify_pin(&mut app, &mut fs);
        let expected = run(&mut app, &mut fs, INS_GET_METADATA, 0, SLOT_CARDMGM, &[]);
        assert_eq!(expected.0, Sw::OK);
        let sealed = stored(&mut fs, key_fid(SLOT_CARDMGM).get());
        let mut metadata = [0; 8];
        let n = fs
            .meta_find(key_fid(SLOT_CARDMGM).get(), &mut metadata)
            .unwrap();
        fs.meta_delete(key_fid(SLOT_CARDMGM).get()).unwrap();
        if let Some(head) = head {
            fs.meta_add(key_fid(SLOT_CARDMGM).get(), head).unwrap();
        }
        let generation = fs.write_gen();
        assert_eq!(
            run(&mut app, &mut fs, INS_GET_METADATA, 0, SLOT_CARDMGM, &[]),
            (Sw::REFERENCE_NOT_FOUND, vec![])
        );
        assert_eq!(fs.write_gen(), generation);
        assert_eq!(stored(&mut fs, key_fid(SLOT_CARDMGM).get()), sealed);
        assert!(app.sess.has_pin);
        fs.meta_add(key_fid(SLOT_CARDMGM).get(), &metadata[..n])
            .unwrap();
        assert_eq!(
            run(&mut app, &mut fs, INS_GET_METADATA, 0, SLOT_CARDMGM, &[]),
            expected
        );
    }
}

#[test]
fn a_latched_key_read_fault_at_either_protected_read_returns_no_management_key() {
    for fail in [1, 2] {
        arm_key_read(None);
        let rng = RefCell::new(TestRng(7));
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(
            SERIAL,
            HASH,
            Some(FusedKey::latched(key_source)),
            &rng,
            &presence,
        );
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        verify_pin(&mut app, &mut fs);
        assert_eq!(
            protect_mgm_key(&identity(true), &mut fs, &mut TestRng(17)),
            Sw::OK
        );
        let path = [TAG_DATA_PATH, 3, 0x5f, 0xc1, 9];
        let expected = run(&mut app, &mut fs, INS_GET_DATA, 0x3f, 0xff, &path);
        assert_eq!(expected.0, Sw::OK);
        let before = stored(&mut fs, key_fid(SLOT_CARDMGM).get());
        let generation = fs.write_gen();
        arm_key_read(Some(fail));
        let wire = apdu_bytes(INS_GET_DATA, 0x3f, 0xff, &path);
        let request = Apdu::parse(&wire).unwrap();
        let mut output = [0xa5; 64];
        let mut response = ResBuf::new(&mut output);
        assert_eq!(
            app.process(&request, &mut fs, &mut response),
            Sw::FUSED_KEY_UNREAD
        );
        assert!(response.as_slice().is_empty());
        assert_eq!(output, [0xa5; 64]);
        READS.with(|reads| assert_eq!(reads.get(), fail));
        assert_eq!(fs.write_gen(), generation);
        assert_eq!(stored(&mut fs, key_fid(SLOT_CARDMGM).get()), before);
        assert!(app.sess.has_pin);
        arm_key_read(None);
        assert_eq!(
            run(&mut app, &mut fs, INS_GET_DATA, 0x3f, 0xff, &path),
            expected
        );
    }
}

#[test]
fn rsa_completion_with_an_unread_latched_key_preserves_the_slot_and_output() {
    let key = rsk_rsa::generate_rsa(&mut RsaRng(&mut TestRng(99)), RSA_FIXTURE_BYTES * 8).unwrap();
    arm_key_read(None);
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(
        SERIAL,
        HASH,
        Some(FusedKey::latched(key_source)),
        &rng,
        &presence,
    );
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    fs.put(0xb000, b"neighbor").unwrap();
    let generation = fs.write_gen();
    arm_key_read(Some(1));
    let mut output = [0xa5; 1024];
    let policy = [PINPOLICY_ONCE, TOUCHPOLICY_NEVER];
    assert_eq!(
        app.rsa_generate_finish(
            &mut fs,
            &mut TestRng(17),
            SLOT_AUTHENTICATION,
            policy,
            &key,
            &mut output
        ),
        (0, Sw::FUSED_KEY_UNREAD)
    );
    assert_eq!(output, [0xa5; 1024]);
    assert_eq!(fs.write_gen(), generation);
    assert!(!fs.has_key(key_fid(SLOT_AUTHENTICATION)));
    assert_eq!(
        stored(&mut fs, 0xb000).as_deref(),
        Some(b"neighbor".as_slice())
    );
    arm_key_read(None);
    let (n, sw) = app.rsa_generate_finish(
        &mut fs,
        &mut TestRng(17),
        SLOT_AUTHENTICATION,
        policy,
        &key,
        &mut output,
    );
    assert_eq!(sw, Sw::OK);
    assert!(n > 0);
    assert!(fs.has_key(key_fid(SLOT_AUTHENTICATION)));
}

#[test]
fn a_refused_unblock_rearm_preserves_the_pin_and_requires_a_healthy_retry() {
    let remove = Rc::new(Cell::new(None));
    let mut fs = Fs::new(RefuseWrite {
        inner: RamStorage::new(),
        refuse: Rc::new(Cell::new(None)),
        refuse_remove: remove.clone(),
    });
    fs.scan();
    let rng = RefCell::new(TestRng(7));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
    select(&mut app, &mut fs);
    set_retries_left(&mut fs, RETRY_PIN, 0).unwrap();
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    fs.put(0xb000, b"neighbor").unwrap();
    let pin = stored(&mut fs, EF_PIN);
    let retries = stored(&mut fs, EF_RETRIES);
    let mut input = DEFAULT_PUK.to_vec();
    let new = [b'9', b'8', b'2', b'7', b'3', b'6', 0xff, 0xff];
    input.extend_from_slice(&new);
    remove.set(Some(rsk_fs::EF_HARDENED));
    assert_eq!(
        run(&mut app, &mut fs, INS_RESET_RETRY, 0, REF_PIN, &input),
        (Sw::MEMORY_FAILURE, vec![])
    );
    assert_eq!(stored(&mut fs, EF_PIN), pin);
    assert_eq!(stored(&mut fs, EF_RETRIES), retries);
    assert_eq!(stored(&mut fs, rsk_fs::EF_HARDENED), Some(vec![1]));
    assert!(fs.rescrub_refused());
    assert!(!app.sess.has_pin);
    remove.set(None);
    let mut fs = Fs::new(fs.into_storage());
    fs.scan();
    assert_eq!(
        run(&mut app, &mut fs, INS_RESET_RETRY, 0, REF_PIN, &input),
        (Sw::OK, vec![])
    );
    assert!(!app.sess.has_pin);
    assert_eq!(retries_left(&mut fs, RETRY_PIN), Ok(DEFAULT_RETRIES));
    assert_eq!(
        run(&mut app, &mut fs, INS_VERIFY, 0, REF_PIN, &new),
        (Sw::OK, vec![])
    );
    assert_eq!(
        stored(&mut fs, 0xb000).as_deref(),
        Some(b"neighbor".as_slice())
    );
    assert_eq!(stored(&mut fs, rsk_fs::EF_HARDENED), None);
}
