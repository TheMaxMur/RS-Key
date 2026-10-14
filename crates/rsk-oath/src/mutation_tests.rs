// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use std::cell::Cell;
use std::rc::Rc;

fn device() -> Device<'static> {
    Device {
        serial_hash: &[0x22; 32],
        serial_id: &SERIAL,
        otp_key: None,
        latched: false,
    }
}

fn frame<S: Storage>(
    app: &mut OathApplet,
    fs: &mut Fs<S>,
    ins: u8,
    out: &mut [u8],
) -> (Sw, Vec<u8>) {
    let raw = apdu(ins, 0, 0, &[]);
    let mut res = ResBuf::new(out);
    let sw = Applet::process(app, &Apdu::parse(&raw).unwrap(), fs, &mut res);
    (sw, res.as_slice().to_vec())
}

#[test]
fn verifying_an_unflagged_hotp_never_requests_presence() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(StubPresence(Presence::Declined, 0));
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(
        put(
            &mut app,
            &mut fs,
            &put_data(b"h", 0x11, 6, SECRET_SHA1, false, None)
        ),
        Sw::OK
    );
    let mut body = tlv(TAG_NAME, b"h");
    body.extend(tlv(TAG_RESPONSE, &755224u32.to_be_bytes()));
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_VERIFY_CODE, 0, 0, &body)),
        (Sw::OK, Vec::new())
    );
    assert_eq!(touch.borrow().1, 0);
}

#[test]
fn a_shortened_entry_cannot_supply_a_pending_list_tail() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(
        put(
            &mut app,
            &mut fs,
            &put_data(b"ab", 0x21, 6, SECRET_SHA1, false, None)
        ),
        Sw::OK
    );
    assert_eq!(
        frame(&mut app, &mut fs, INS_LIST, &mut [0; 4]),
        (Sw(0x6101), vec![0x72, 3, 0x21, b'a'])
    );
    let mut blob = tlv(TAG_NAME, b"a");
    blob.extend(tlv(
        TAG_KEY,
        &[vec![0x21, 6], SECRET_SHA1.to_vec()].concat(),
    ));
    assert!(seal::seal_put(
        &device(),
        &mut fs,
        &mut CountRng(1),
        KeyFid::new(EF_OATH_CRED),
        &blob
    ));
    assert_eq!(
        frame(&mut app, &mut fs, INS_SEND_REMAINING, &mut [0; 16]),
        (Sw::MEMORY_FAILURE, Vec::new())
    );
}

#[test]
fn losing_a_list_tail_stops_before_reading_the_next_credential() {
    let (backend, control) = rsk_fs::read_change::ChangingRead::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    for name in [b"ab", b"cd"] {
        assert_eq!(
            put(
                &mut app,
                &mut fs,
                &put_data(name, 0x21, 6, SECRET_SHA1, false, None)
            ),
            Sw::OK
        );
    }
    assert_eq!(
        frame(&mut app, &mut fs, INS_LIST, &mut [0; 4]).0,
        Sw(0x6106)
    );
    fs.put_key(
        KeyFid::new(EF_OATH_CRED),
        rsk_fs::Sealed::wrap(b"broken seal"),
    )
    .unwrap();
    control.replace_on_read(EF_OATH_CRED + 1, 0, None);
    assert_eq!(
        frame(&mut app, &mut fs, INS_SEND_REMAINING, &mut [0; 16]),
        (Sw::MEMORY_FAILURE, Vec::new())
    );
    assert!(
        !control.served(),
        "a lost tail cannot probe another credential"
    );
}

#[test]
fn list_counts_past_255_remaining_bytes_before_saturating_sw2() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    for suffix in b'a'..=b'e' {
        let mut name = [b'x'; 61];
        name[60] = suffix;
        assert_eq!(
            put(
                &mut app,
                &mut fs,
                &put_data(&name, 0x21, 6, SECRET_SHA1, false, None)
            ),
            Sw::OK
        );
    }
    assert_eq!(
        frame(&mut app, &mut fs, INS_LIST, &mut [0; 1]),
        (Sw(0x6100), vec![TAG_NAME_LIST])
    );
}

#[test]
fn a_prefixed_response_spends_only_its_remaining_capacity() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(
        put(
            &mut app,
            &mut fs,
            &put_data(b"abc", 0x21, 6, SECRET_SHA1, false, None)
        ),
        Sw::OK
    );
    let mut out = [0; 4];
    let mut res = ResBuf::new(&mut out);
    res.push(0xA5);
    let raw = apdu(INS_LIST, 0, 0, &[]);
    assert_eq!(
        Applet::process(&mut app, &Apdu::parse(&raw).unwrap(), &mut fs, &mut res),
        Sw(0x6103)
    );
    assert_eq!(res.as_slice(), [0xA5, TAG_NAME_LIST, 4, 0x21]);
    assert_eq!(
        frame(&mut app, &mut fs, INS_SEND_REMAINING, &mut [0; 4]),
        (Sw::OK, b"abc".to_vec())
    );
}

#[test]
fn an_oversized_legacy_rename_is_refused_without_losing_the_name() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let mut blob = tlv(
        TAG_KEY,
        &[vec![0x21, 6], SECRET_SHA1[..14].to_vec()].concat(),
    );
    blob.extend([0x86, 0x82, 0x03, 0xE7]);
    blob.extend([0xA5; 999]);
    blob.extend(tlv(TAG_NAME, b"a"));
    assert_eq!(blob.len(), 1024);
    let fid = KeyFid::new(EF_OATH_CRED);
    assert!(seal::seal_put(
        &device(),
        &mut fs,
        &mut CountRng(1),
        fid,
        &blob
    ));
    let mut body = tlv(TAG_NAME, b"a");
    body.extend(tlv(TAG_NAME, &[b'b'; 64]));
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_RENAME, 0, 0, &body)),
        (Sw::FILE_FULL, Vec::new())
    );
    let mut after = Secret::<[u8; CRED_MAX]>::zeroed();
    assert_eq!(
        seal::seal_read(&device(), &mut fs, fid, &mut after),
        Some(blob.len())
    );
    assert_eq!(&after.expose()[..blob.len()], blob);
}

#[test]
fn a_legacy_mark_of_another_width_is_refused_unchanged() {
    let mut blob = [0; CRED_MAX];
    let body = tlv(TAG_LAST_CHAL, &[0; 8]);
    blob[..body.len()].copy_from_slice(&body);
    let before = blob;
    let mut n = body.len();
    assert!(!raise_mark(&mut blob, &mut n, &[1]));
    assert_eq!(n, body.len());
    assert_eq!(blob, before);
}

#[test]
fn calculating_an_increasing_credential_refuses_a_legacy_short_mark() {
    let mut fs = new_fs();
    let fid = KeyFid::new(EF_OATH_CRED);
    let mut blob = tlv(TAG_NAME, b"totp");
    blob.extend(tlv(
        TAG_KEY,
        &[vec![0x21, 6], SECRET_SHA1.to_vec()].concat(),
    ));
    blob.extend(tlv(TAG_PROPERTY, &[PROP_INCREASING]));
    blob.extend(tlv(TAG_LAST_CHAL, &[0; 8]));
    assert!(seal::seal_put(
        &device(),
        &mut fs,
        &mut CountRng(1),
        fid,
        &blob
    ));
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let mut body = tlv(TAG_NAME, b"totp");
    body.extend(tlv(TAG_CHALLENGE, &[1]));
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_CALCULATE, 0, 1, &body)),
        (Sw::WRONG_DATA, Vec::new())
    );
    let mut after = Secret::<[u8; CRED_MAX]>::zeroed();
    assert_eq!(
        seal::seal_read(&device(), &mut fs, fid, &mut after),
        Some(blob.len())
    );
    assert_eq!(&after.expose()[..blob.len()], blob);
}

#[test]
fn ordinary_bulk_codes_ignore_an_unused_legacy_mark() {
    let mut fs = new_fs();
    let mut blob = tlv(TAG_NAME, b"totp");
    blob.extend(tlv(
        TAG_KEY,
        &[vec![0x21, 6], SECRET_SHA1.to_vec()].concat(),
    ));
    blob.extend(tlv(TAG_LAST_CHAL, &[0; 8]));
    assert!(seal::seal_put(
        &device(),
        &mut fs,
        &mut CountRng(1),
        KeyFid::new(EF_OATH_CRED),
        &blob
    ));
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let body = tlv(TAG_CHALLENGE, &1u64.to_be_bytes());
    let mut expected = tlv(TAG_NAME, b"totp");
    expected.extend([0x76, 5, 6]);
    expected.extend(287082u32.to_be_bytes());
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_CALC_ALL, 0, 1, &body)),
        (Sw::OK, expected)
    );
}

#[test]
fn a_full_legacy_name_and_sha512_response_exactly_fill_the_entry_workspace() {
    let mut fs = new_fs();
    let name = [b'x'; 255];
    let key = [vec![0x23, 8], SECRET_SHA512.to_vec()].concat();
    let mut blob = vec![TAG_NAME, 0x81, 255];
    blob.extend(name);
    blob.extend(tlv(TAG_KEY, &key));
    assert!(seal::seal_put(
        &device(),
        &mut fs,
        &mut CountRng(1),
        KeyFid::new(EF_OATH_CRED),
        &blob
    ));
    let mut challenge = [0; CHALLENGE_MAX];
    challenge[..8].copy_from_slice(&1u64.to_be_bytes());
    let chain = Chain::CalcAll {
        p2: 0,
        chal: challenge,
        chal_len: 8,
    };
    let mut scratch = Secret::zeroed();
    let mut out = [0; PAGE_ENTRY_MAX];
    let mut expected = vec![TAG_NAME, 255];
    expected.extend(name);
    expected.extend([TAG_RESPONSE, 65, 8]);
    expected.extend(hmac_sha512(SECRET_SHA512, &1u64.to_be_bytes()));
    assert_eq!(
        page_entry(
            &chain,
            &device(),
            &mut fs,
            EF_OATH_CRED,
            &mut scratch,
            &mut out
        ),
        Some(expected.len())
    );
    assert_eq!(out.as_slice(), expected);
}

#[test]
fn legacy_list_names_stop_at_the_one_byte_entry_length_boundary() {
    for (len, sw, expected_len) in [(253, Sw(0x61FF), 1), (254, Sw::OK, 0)] {
        let mut fs = new_fs();
        let mut blob = vec![TAG_NAME, 0x81, len];
        blob.extend(vec![b'x'; usize::from(len)]);
        blob.extend(tlv(
            TAG_KEY,
            &[vec![0x21, 6], SECRET_SHA1.to_vec()].concat(),
        ));
        assert!(seal::seal_put(
            &device(),
            &mut fs,
            &mut CountRng(1),
            KeyFid::new(EF_OATH_CRED),
            &blob
        ));
        let rng = RefCell::new(CountRng(7));
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        let (actual_sw, body) = frame(&mut app, &mut fs, INS_LIST, &mut [0; 1]);
        assert_eq!(actual_sw, sw, "name length {len}");
        assert_eq!(body.len(), expected_len, "name length {len}");
    }
}

#[test]
fn a_single_undead_credential_spends_the_complete_reset_budget() {
    let (backend, count) = Undead::new(2 * RESET_MAX_DELETES);
    let mut fs = Fs::new(backend);
    fs.scan();
    fs.put_key(KeyFid::new(EF_OATH_CRED), rsk_fs::Sealed::wrap(b"undead"))
        .unwrap();
    assert_eq!(sweep(&mut fs, is_oath_cred_fid), Err(Sw::MEMORY_FAILURE));
    assert_eq!(count.removals(), RESET_MAX_DELETES);
}

#[test]
fn a_leading_slash_is_part_of_the_name_without_a_period_prefix() {
    let name = b"/Example:bob";
    assert_eq!(split_period(name), (None, name.as_slice()));
}

#[test]
fn long_form_tlv_lengths_preserve_the_value_boundary_at_any_offset() {
    let mut two = vec![TAG_NAME, 1, b'x', 0x86, 0x82, 1, 0];
    two.extend([0xA5; 256]);
    assert_eq!(tlv_at(&two, 3), Some((0x86, 7..263)));
    let mut one = vec![0x86, 0x81, 128];
    one.extend([0xA5; 128]);
    assert_eq!(tlv_at(&one, 0), Some((0x86, 3..131)));
}

#[test]
fn a_maximal_plaintext_legacy_credential_can_still_be_migrated() {
    let mut blob = tlv(TAG_NAME, b"a");
    blob.extend(tlv(
        TAG_KEY,
        &[vec![0x21, 6], SECRET_SHA1.to_vec()].concat(),
    ));
    blob.extend([0x86, 0x82, 0x03, 0xE1]);
    blob.extend([0xA5; 993]);
    assert_eq!(blob.len(), 1024);
    let fid = KeyFid::new(EF_OATH_CRED);
    assert!(is_legacy_plaintext(fid, &blob));
    blob.push(0);
    assert!(!is_legacy_plaintext(fid, &blob));
}

#[test]
fn a_password_safe_login_does_not_change_the_order_of_oath_fields() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let mut body = tlv(TAG_NAME, b"bank");
    body.extend(tlv(TAG_PWS_LOGIN, b"alice"));
    body.extend(tlv(
        TAG_KEY,
        &[vec![0x21, 6], SECRET_SHA1.to_vec()].concat(),
    ));
    assert_eq!(put(&mut app, &mut fs, &body), Sw::OK);
}

struct ReadOnce {
    inner: RamStorage,
    armed: Rc<Cell<bool>>,
    reads: Rc<Cell<usize>>,
}

impl Storage for ReadOnce {
    fn read(&mut self, fid: u16, out: &mut [u8]) -> Option<usize> {
        if self.armed.get() && fid == EF_OATH_CRED {
            self.reads.set(self.reads.get() + 1);
            assert_eq!(
                self.reads.get(),
                1,
                "LIST must advance past a malformed credential"
            );
        }
        self.inner.read(fid, out)
    }
    fn write(&mut self, fid: u16, bytes: &[u8]) -> rsk_sdk::error::Result<()> {
        self.inner.write(fid, bytes)
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
fn list_reads_each_malformed_credential_once_before_advancing() {
    let armed = Rc::new(Cell::new(false));
    let reads = Rc::new(Cell::new(0));
    let mut fs = Fs::new(ReadOnce {
        inner: RamStorage::new(),
        armed: armed.clone(),
        reads: reads.clone(),
    });
    fs.scan();
    assert!(seal::seal_put(
        &device(),
        &mut fs,
        &mut CountRng(1),
        KeyFid::new(EF_OATH_CRED),
        &tlv(TAG_NAME, b"no-key")
    ));
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    armed.set(true);
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[])),
        (Sw::OK, Vec::new())
    );
    assert_eq!(reads.get(), 1);
}
