// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::ram::RamStorage;

struct CountRng(u8);
impl Rng for CountRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

fn dev() -> Device<'static> {
    Device {
        serial_hash: &[0x22; 32],
        serial_id: &SERIAL_ID,
        otp_key: None,
    }
}

const SERIAL_ID: [u8; 8] = [0xAA, 0xBB, 0xCC, 0xDD, 5, 6, 7, 8];
const SERIAL_HASH: [u8; 32] = [0x22; 32];

/// A provisioned MKEK for the tests. The applet holds a way to READ the fuses, not
/// the key, so a test source has to be a plain `fn`.
fn test_mkek() -> Option<[u8; 32]> {
    Some([0x66; 32])
}

fn make_fs() -> Fs<RamStorage> {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    fs
}

fn run(app: &mut OpenpgpApplet, fs: &mut Fs<RamStorage>, raw: &[u8]) -> (Vec<u8>, Sw) {
    let apdu = Apdu::parse(raw).unwrap();
    let mut buf = [0u8; SCRATCH];
    let mut res = ResBuf::new(&mut buf);
    let sw = app.process(&apdu, fs, &mut res);
    (res.as_slice().to_vec(), sw)
}

/// [`run`] with a response buffer that can hold `MAX_DO_BYTES` — `SCRATCH` is
/// 1024 and is deliberately not the GET DATA ceiling, so reading a DO back at
/// its announced size needs the transport's buffer rather than the applet's.
fn run_big(app: &mut OpenpgpApplet, fs: &mut Fs<RamStorage>, raw: &[u8]) -> (Vec<u8>, Sw) {
    let apdu = Apdu::parse(raw).unwrap();
    let mut buf = [0u8; crate::files::MAX_APDU_BYTES];
    let mut res = ResBuf::new(&mut buf);
    let sw = app.process(&apdu, fs, &mut res);
    (res.as_slice().to_vec(), sw)
}

#[test]
fn select_emits_fci() {
    let rng = RefCell::new(CountRng(0));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    let mut buf = [0u8; 64];
    let mut res = ResBuf::new(&mut buf);
    let sw = app.select(false, &mut fs, &mut res);
    assert_eq!(sw, Sw::OK);
    assert_eq!(res.as_slice()[0], 0x6F);
}

#[test]
fn get_data_pw_status_via_process() {
    let rng = RefCell::new(CountRng(0));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    let (body, sw) = run(&mut app, &mut fs, &[0x00, consts::INS_GET_DATA, 0x00, 0xC4]);
    assert_eq!(sw, Sw::OK);
    // RC retry counter (index 5) ships deactivated at 0.
    assert_eq!(&body, &[0x01, 127, 127, 127, 3, 0, 3]);
}

#[test]
fn put_data_pw_status_routes_to_handler() {
    // PUT DATA 0xC4 (PW status) must route to put_pw_status, which needs PW3 →
    // SECURITY_STATUS_NOT_SATISFIED without it. The generic DO path rejects 0xC4
    // with CONDITIONS_NOT_SATISFIED, so this error code pins the dispatch route.
    let rng = RefCell::new(CountRng(0));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    let (_b, sw) = run(
        &mut app,
        &mut fs,
        &[0x00, consts::INS_PUT_DATA, 0x00, 0xC4, 0x01, 0xFF],
    );
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
}

// §4.4.2: C4's max-length bytes "should not be changed". `put_pw_status` copied
// the flag *and* all three, so `PUT C4 = 01 06 06 06` answered 9000 and the card
// went on announcing max 6 while VERIFY still compared a 40-byte password — an
// announcement about itself that it did not enforce.
#[test]
fn put_data_c4_cannot_move_the_announced_pw_maxima() {
    let rng = RefCell::new(CountRng(0));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    let read_c4 = |app: &mut OpenpgpApplet, fs: &mut Fs<RamStorage>| {
        run(app, fs, &[0x00, consts::INS_GET_DATA, 0x00, 0xC4]).0
    };

    assert_eq!(
        put(&mut app, &mut fs, 0x00, 0xC4, &[0x01, 0x06, 0x06, 0x06]),
        Sw::WRONG_DATA
    );
    assert_eq!(read_c4(&mut app, &mut fs), [0x01, 127, 127, 127, 3, 0, 3]);
    // The flag itself still moves, and only to a value the DO defines.
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xC4, &[0x00]), Sw::OK);
    assert_eq!(read_c4(&mut app, &mut fs), [0x00, 127, 127, 127, 3, 0, 3]);
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xC4, &[0x02]), Sw::WRONG_DATA);
    assert_eq!(read_c4(&mut app, &mut fs), [0x00, 127, 127, 127, 3, 0, 3]);
}

#[test]
fn put_data_reset_code_routes_to_handler() {
    // PUT DATA 0xD3 (resetting code) must route to put_reset_code, which needs
    // PW3 → SECURITY_STATUS_NOT_SATISFIED without it (not the generic path's
    // CONDITIONS_NOT_SATISFIED), pinning the dispatch route.
    let rng = RefCell::new(CountRng(0));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    let (_b, sw) = run(
        &mut app,
        &mut fs,
        &[0x00, consts::INS_PUT_DATA, 0x00, 0xD3, 0x02, 0xAB, 0xCD],
    );
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
}

#[test]
fn an_out_of_range_reset_code_is_wrong_data() {
    // Same judgement as CHANGE REFERENCE DATA's new value, different command and
    // different word: this value arrives in PUT DATA's data field. Measured on a
    // YubiKey 5.7.4, 3/3, at 1, 5, 6, 7 and 128 — `6A80` where CHANGE is `6985`.
    let rng = RefCell::new(CountRng(0));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    for n in [1usize, 5, 6, 7, consts::PIN_MAX_LEN + 1, 200] {
        assert_eq!(
            put(&mut app, &mut fs, 0x00, 0xD3, &vec![b'R'; n]),
            Sw::WRONG_DATA,
            "a {n}-byte resetting code"
        );
    }
    // The shortest one the policy allows lands, and clearing the DO still works —
    // an empty PUT deletes the reset code, which is not a length refusal.
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xD3, b"resetme0"), Sw::OK);
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xD3, &[]), Sw::OK);
}

#[test]
fn get_challenge_returns_ne_random_bytes() {
    let rng = RefCell::new(CountRng(0));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    // Case-2 APDU, Le = 8 → 8 random bytes (CountRng yields 0,1,…,7).
    let (body, sw) = run(
        &mut app,
        &mut fs,
        &[0x00, consts::INS_CHALLENGE, 0x00, 0x00, 0x08],
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(body, (0u8..8).collect::<Vec<_>>());
}

// DO C0 bytes 3-4 are the card's own statement of how much randomness it will
// hand over. It said 128 while the command served anything up to the 1024-byte
// scratch, so the number a host read off the card described nothing. The two are
// one constant now, and §7.2.15's P1 = P2 = 00 is enforced (a YubiKey 5.7.4
// refuses only when both are non-zero — this is the strictly stricter side).
#[test]
fn get_challenge_serves_exactly_what_do_c0_announces() {
    let rng = RefCell::new(CountRng(0));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);

    let (c0, sw) = run(&mut app, &mut fs, &[0x00, consts::INS_GET_DATA, 0x00, 0xC0]);
    assert_eq!(sw, Sw::OK);
    let announced = ((c0[2] as usize) << 8) | c0[3] as usize;
    assert_eq!(announced, files::MAX_CHALLENGE_BYTES);

    let ext = |ne: usize| {
        [
            0x00,
            consts::INS_CHALLENGE,
            0x00,
            0x00,
            0x00,
            (ne >> 8) as u8,
            ne as u8,
        ]
    };
    // Everything up to the announcement is served in full…
    for ne in [1, 8, 255, 256, 257, announced - 1, announced] {
        let (body, sw) = run(&mut app, &mut fs, &ext(ne));
        assert_eq!(sw, Sw::OK, "Le {ne}");
        assert_eq!(body.len(), ne, "Le {ne}");
    }
    // …and one byte past it is refused, not truncated under 9000.
    for ne in [announced + 1, 2048, 4096] {
        let (body, sw) = run(&mut app, &mut fs, &ext(ne));
        assert_eq!(sw, Sw::WRONG_LENGTH, "Le {ne}");
        assert!(body.is_empty(), "Le {ne}");
    }

    for (p1, p2) in [(0x01, 0x00), (0x00, 0x01), (0x01, 0x01), (0xFF, 0xFF)] {
        let (body, sw) = run(
            &mut app,
            &mut fs,
            &[0x00, consts::INS_CHALLENGE, p1, p2, 0x08],
        );
        assert_eq!(sw, Sw::WRONG_P1P2, "P1P2 {p1:02X}{p2:02X}");
        assert!(body.is_empty());
    }

    // Command data with a valid Le is accepted and ignored, as on a YubiKey.
    let (body, sw) = run(
        &mut app,
        &mut fs,
        &[0x00, consts::INS_CHALLENGE, 0x00, 0x00, 0x01, 0xAA, 0x08],
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(body.len(), 8);

    // Command data and no Le at all: zero random bytes under 9000 would read as
    // a served challenge. 6A80 is that card's answer, measured; 6700 was ours.
    let (body, sw) = run(
        &mut app,
        &mut fs,
        &[0x00, consts::INS_CHALLENGE, 0x00, 0x00, 0x01, 0xAA],
    );
    assert_eq!(sw, Sw::WRONG_DATA);
    assert!(body.is_empty());
}

#[test]
fn activate_file_is_ok() {
    let rng = RefCell::new(CountRng(0));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    let (body, sw) = run(
        &mut app,
        &mut fs,
        &[0x00, consts::INS_ACTIVATE_FILE, 0x00, 0x00],
    );
    assert_eq!(sw, Sw::OK);
    assert!(body.is_empty());
}

#[test]
fn terminate_via_process_wipes_only_after_pw3() {
    let rng = RefCell::new(CountRng(0));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    fs.put(consts::EF_PK_SIG.get(), &[0xAB; 40]).unwrap();
    // Without PW3 (and PW3 unblocked) the terminate is refused — nothing wiped.
    let (_b, sw) = run(
        &mut app,
        &mut fs,
        &[0x00, consts::INS_TERMINATE_DF, 0x00, 0x00],
    );
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    assert!(fs.has_data(consts::EF_PK_SIG.get()));
    // VERIFY PW3, then terminate wipes the imported key and re-seeds defaults.
    let mut v = vec![0x00, consts::INS_VERIFY, 0x00, consts::PW3_MODE83];
    v.push(consts::PW3_DEFAULT.len() as u8);
    v.extend_from_slice(consts::PW3_DEFAULT);
    assert_eq!(run(&mut app, &mut fs, &v).1, Sw::OK);
    let (_b, sw) = run(
        &mut app,
        &mut fs,
        &[0x00, consts::INS_TERMINATE_DF, 0x00, 0x00],
    );
    assert_eq!(sw, Sw::OK);
    assert!(!fs.has_data(consts::EF_PK_SIG.get()));
    assert!(fs.has_data(consts::EF_DEK_PW1.get()));
}

#[test]
fn verify_change_pin_end_to_end_via_process() {
    let rng = RefCell::new(CountRng(50));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);

    // VERIFY PW3 (admin) with the default PIN.
    let mut v = vec![0x00, consts::INS_VERIFY, 0x00, consts::PW3_MODE83];
    v.push(consts::PW3_DEFAULT.len() as u8);
    v.extend_from_slice(consts::PW3_DEFAULT);
    let (_, sw) = run(&mut app, &mut fs, &v);
    assert_eq!(sw, Sw::OK);

    // PUT DATA login (needs PW3) now succeeds.
    let mut p = vec![0x00, consts::INS_PUT_DATA, 0x00, 0x5E, 0x05];
    p.extend_from_slice(b"alice");
    let (_, sw) = run(&mut app, &mut fs, &p);
    assert_eq!(sw, Sw::OK);
    assert_eq!(
        run(&mut app, &mut fs, &[0x00, consts::INS_GET_DATA, 0x00, 0x5E]).0,
        b"alice"
    );

    // CHANGE PIN PW1: "123456" -> "654321".
    let mut c = vec![0x00, consts::INS_CHANGE_PIN, 0x00, consts::PW1_MODE81];
    let body = [consts::PW1_DEFAULT, b"654321"].concat();
    c.push(body.len() as u8);
    c.extend_from_slice(&body);
    let (_, sw) = run(&mut app, &mut fs, &c);
    assert_eq!(sw, Sw::OK);

    // New PW1 verifies; old one fails.
    let mut v1 = vec![0x00, consts::INS_VERIFY, 0x00, consts::PW1_MODE81, 0x06];
    v1.extend_from_slice(b"654321");
    assert_eq!(run(&mut app, &mut fs, &v1).1, Sw::OK);
}

#[test]
fn change_pin_rejects_an_empty_new_pw3() {
    // With Lc == |PW3| the whole body is the old PIN and the new one is empty. The
    // zero-length verifier that used to store could be neither verified nor
    // decremented to blocked, wedging the applet and its TERMINATE DF way out.
    let rng = RefCell::new(CountRng(0));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    let mut c = vec![0x00, consts::INS_CHANGE_PIN, 0x00, consts::PW3_MODE83];
    c.push(consts::PW3_DEFAULT.len() as u8);
    c.extend_from_slice(consts::PW3_DEFAULT);
    assert_eq!(run(&mut app, &mut fs, &c).1, Sw::CONDITIONS_NOT_SATISFIED);

    // A fresh session: PW3 still gates TERMINATE DF, still verifies, and the
    // factory reset still runs.
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    let term = [0x00, consts::INS_TERMINATE_DF, 0x00, 0x00];
    assert_eq!(
        run(&mut app, &mut fs, &term).1,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    assert_eq!(run(&mut app, &mut fs, &term).1, Sw::OK);
}

#[test]
fn change_pin_enforces_the_reference_length_limits() {
    // OpenPGP 3.4 §4.2: PW1 at least 6 bytes, capped by the maximum DO C4 advertises.
    let rng = RefCell::new(CountRng(0));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    // `6985`, not `6700`: the APDU is well formed, the value in it is the problem.
    // A YubiKey 5.7.4 answers `6985` at every out-of-range length, 3/3, for both
    // references and without spending a retry.
    for new in [b"12345".as_slice(), &[0x39u8; consts::PIN_MAX_LEN + 1]] {
        let body = [consts::PW1_DEFAULT, new].concat();
        let mut c = vec![0x00, consts::INS_CHANGE_PIN, 0x00, consts::PW1_MODE81];
        c.push(body.len() as u8);
        c.extend_from_slice(&body);
        assert_eq!(run(&mut app, &mut fs, &c).1, Sw::CONDITIONS_NOT_SATISFIED);
    }
    // Nothing was written: the old PW1 still verifies.
    verify_pin(&mut app, &mut fs, consts::PW1_MODE81, consts::PW1_DEFAULT);
}

#[test]
fn a_blocked_pw3_neither_migrates_nor_writes() {
    // `make_fs` seeds the verifiers on the pre-OTP arm, so an applet holding the
    // MKEK takes check_pin's kbase-migration fallback. On a blocked reference it
    // must do nothing at all — the migration's flash writes are a PIN oracle.
    let rng = RefCell::new(CountRng(0));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(
        SERIAL_ID,
        SERIAL_HASH,
        Some(test_mkek as FusedKey),
        &rng,
        &presence,
    );
    let mut wrong = vec![0x00, consts::INS_VERIFY, 0x00, consts::PW3_MODE83, 0x08];
    wrong.extend_from_slice(b"99999999");
    for _ in 0..3 {
        run(&mut app, &mut fs, &wrong);
    }
    let mut before = [0u8; 64];
    let n = fs.read(consts::EF_PW3, &mut before).expect("PW3 verifier");

    let mut v = vec![0x00, consts::INS_VERIFY, 0x00, consts::PW3_MODE83];
    v.push(consts::PW3_DEFAULT.len() as u8);
    v.extend_from_slice(consts::PW3_DEFAULT);
    assert_eq!(run(&mut app, &mut fs, &v).1, Sw::PIN_BLOCKED);
    let mut after = [0u8; 64];
    assert_eq!(fs.read(consts::EF_PW3, &mut after), Some(n));
    assert_eq!(before[..n], after[..n], "blocked PW3 migrated its verifier");
}

#[test]
fn an_unblocked_legacy_verifier_still_migrates() {
    // The block floor must not disable the lazy kbase migration: with retries left,
    // the correct PIN on the pre-OTP arm verifies and is re-stored under the OTP
    // generation, which is what the next session checks against.
    let rng = RefCell::new(CountRng(0));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(
        SERIAL_ID,
        SERIAL_HASH,
        Some(test_mkek as FusedKey),
        &rng,
        &presence,
    );
    let mut before = [0u8; 64];
    let n = fs.read(consts::EF_PW3, &mut before).expect("PW3 verifier");
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    let mut after = [0u8; 64];
    assert_eq!(fs.read(consts::EF_PW3, &mut after), Some(n));
    assert_ne!(
        before[..n],
        after[..n],
        "verifier stayed on the pre-OTP arm"
    );
    let mut app2 = OpenpgpApplet::new(
        SERIAL_ID,
        SERIAL_HASH,
        Some(test_mkek as FusedKey),
        &rng,
        &presence,
    );
    verify_pin(&mut app2, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
}

#[test]
fn put_data_denied_without_auth() {
    let rng = RefCell::new(CountRng(0));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    let mut p = vec![0x00, consts::INS_PUT_DATA, 0x00, 0x5E, 0x03];
    p.extend_from_slice(b"bob");
    assert_eq!(
        run(&mut app, &mut fs, &p).1,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
}

#[test]
fn select_resets_session() {
    let rng = RefCell::new(CountRng(0));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    // Authenticate, then SELECT — the auth must clear.
    let mut v = vec![0x00, consts::INS_VERIFY, 0x00, consts::PW3_MODE83];
    v.push(consts::PW3_DEFAULT.len() as u8);
    v.extend_from_slice(consts::PW3_DEFAULT);
    run(&mut app, &mut fs, &v);
    assert!(app.sess.has_pw3);
    let mut buf = [0u8; 64];
    let mut res = ResBuf::new(&mut buf);
    app.select(false, &mut fs, &mut res);
    assert!(!app.sess.has_pw3);
}

// ---- IMPORT + PSO + INTERNAL AUTHENTICATE (EC) ---------------------------

// Algorithm-attribute values (the stored form: algo-id ‖ OID). A NIST curve
// is tagged ECDSA (0x13) on a signing key but ECDH (0x12) on the decipher key
// — the same OID, so both must resolve to the same curve.
const ATTR_P256: &[u8] = &[0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const ATTR_P256_ECDH: &[u8] = &[0x12, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const ATTR_ED25519: &[u8] = &[0x16, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01];

fn verify_pin(app: &mut OpenpgpApplet, fs: &mut Fs<RamStorage>, mode: u8, pin: &[u8]) {
    let mut a = vec![0x00, consts::INS_VERIFY, 0x00, mode, pin.len() as u8];
    a.extend_from_slice(pin);
    assert_eq!(run(app, fs, &a).1, Sw::OK, "VERIFY mode {mode:#x}");
}

fn put(app: &mut OpenpgpApplet, fs: &mut Fs<RamStorage>, p1: u8, p2: u8, data: &[u8]) -> Sw {
    let mut a = vec![0x00, consts::INS_PUT_DATA, p1, p2, data.len() as u8];
    a.extend_from_slice(data);
    run(app, fs, &a).1
}

/// PUT DATA in the extended-length form, so a body past 255 bytes is expressible.
fn put_long(app: &mut OpenpgpApplet, fs: &mut Fs<RamStorage>, p1: u8, p2: u8, data: &[u8]) -> Sw {
    let mut a = vec![0x00, consts::INS_PUT_DATA, p1, p2, 0x00];
    a.push((data.len() >> 8) as u8);
    a.push(data.len() as u8);
    a.extend_from_slice(data);
    run(app, fs, &a).1
}

// Build the IMPORT (0xDB) extended-header-list APDU for an EC key. The 7F48
// template lists only the tag-length pair (0x92 = the private scalar); the
// scalar bytes themselves go in 5F48. All lengths short-form.
fn ec_import(crt: u8, scalar: &[u8]) -> Vec<u8> {
    let tmpl = [0x92u8, scalar.len() as u8];
    let f7f48 = [&[0x7F, 0x48, tmpl.len() as u8], tmpl.as_slice()].concat();
    let f5f48 = [&[0x5F, 0x48, scalar.len() as u8], scalar].concat();
    let body = [&[crt, 0x00], f7f48.as_slice(), f5f48.as_slice()].concat();
    let header = [&[0x4D, body.len() as u8], body.as_slice()].concat();
    let mut a = vec![
        0x00,
        consts::INS_PUT_DATA_ODD,
        0x3F,
        0xFF,
        header.len() as u8,
    ];
    a.extend_from_slice(&header);
    a
}

fn p256_vk(scalar: &[u8; 32]) -> p256::ecdsa::VerifyingKey {
    let sk = p256::ecdsa::SigningKey::from_bytes(&p256::FieldBytes::from(*scalar)).unwrap();
    *sk.verifying_key()
}

#[test]
fn import_p256_then_pso_sign_verifies() {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    let rng = RefCell::new(CountRng(7));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);

    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xC1, ATTR_P256), Sw::OK);

    let scalar = [0x11u8; 32];
    let (_, sw) = run(&mut app, &mut fs, &ec_import(0xB6, &scalar));
    assert_eq!(sw, Sw::OK);

    // PSO:CDS over a 32-byte digest, authorised by PW1.
    verify_pin(&mut app, &mut fs, consts::PW1_MODE81, consts::PW1_DEFAULT);
    let digest = [0x42u8; 32];
    let mut a = vec![0x00, consts::INS_PSO, 0x9E, 0x9A, digest.len() as u8];
    a.extend_from_slice(&digest);
    let (sig, sw) = run(&mut app, &mut fs, &a);
    assert_eq!(sw, Sw::OK);
    assert_eq!(sig.len(), 64, "raw r‖s");

    let s = p256::ecdsa::Signature::from_slice(&sig).unwrap();
    p256_vk(&scalar).verify_prehash(&digest, &s).unwrap();

    // The signature counter advanced from 0 to 1.
    let mut c = [0u8; 3];
    let n = fs.read(consts::EF_SIG_COUNT, &mut c).unwrap();
    assert_eq!(&c[..n], &[0, 0, 1]);
}

// Audit run-33. OpenPGP 3.4's DO access table makes the DS-Counter WRITE = *Never*:
// it is the card's only evidence that the key was used while its owner was away, so
// the admin PIN must not roll it back. Deleting it was also a post-crypto DoS —
// `inc_sig_count` runs after PSO:CDS has already signed, so every later signature
// burned the private-key op and returned 6A88 until the next boot.
#[test]
fn put_data_refuses_to_write_the_signature_counter() {
    let rng = RefCell::new(CountRng(7));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    put(&mut app, &mut fs, 0x00, 0xC1, ATTR_P256);

    // Sign once so the counter is non-zero and provably not merely absent.
    let scalar = [0x11u8; 32];
    assert_eq!(run(&mut app, &mut fs, &ec_import(0xB6, &scalar)).1, Sw::OK);
    verify_pin(&mut app, &mut fs, consts::PW1_MODE81, consts::PW1_DEFAULT);
    let digest = [0x42u8; 32];
    let mut a = vec![0x00, consts::INS_PSO, 0x9E, 0x9A, digest.len() as u8];
    a.extend_from_slice(&digest);
    assert_eq!(run(&mut app, &mut fs, &a).1, Sw::OK);

    // Neither a rewrite nor a delete is allowed, even with PW3.
    for data in [&[0u8, 0, 0][..], &[]] {
        assert_eq!(
            put(&mut app, &mut fs, 0x00, 0x93, data),
            Sw::CONDITIONS_NOT_SATISFIED
        );
    }
    let mut c = [0u8; 3];
    let n = fs.read(consts::EF_SIG_COUNT, &mut c).unwrap();
    assert_eq!(
        &c[..n],
        &[0, 0, 1],
        "counter must survive the write attempt"
    );
}

// Audit run-33. `nbits` went straight from the wire into `RsaKeygen`, which took any
// 32-byte multiple — so PW3 could set rsa512 and the key the *owner* generated
// afterwards was factorable, while GET DATA C1 reported whatever was written. Only
// what DO 0xFA advertises may be stored.
#[test]
fn put_data_refuses_an_unadvertised_algorithm_attribute() {
    let rng = RefCell::new(CountRng(7));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);

    for attr in [
        &[0x01u8, 0x02, 0x00, 0x00, 0x20, 0x00][..], // RSA-512: factorable
        &[0x01, 0x06, 0x00, 0x00, 0x20, 0x00],       // RSA-1536: never advertised
        &[0x01, 0x10, 0x0F, 0x00, 0x20, 0x00],       // 4111 bits → really RSA-4096
        &[0x13, 0x2B, 0x81, 0x04, 0x00, 0x21],       // an OID we do not implement
        // Ed448 and X448 were advertised while GENERATE and IMPORT refused them,
        // so the write landed and the slot stayed dead until a good attribute was
        // written back — `gpg --card-status` reporting Ed448 for a slot where
        // nothing works. A YubiKey 5.7.4 answers 6A80 to every attribute it does
        // not advertise and leaves the DO unchanged (measured, 3/3).
        &[0x16, 0x2B, 0x65, 0x71], // Ed448
        &[0x12, 0x2B, 0x65, 0x6F], // X448
    ] {
        assert_eq!(
            put(&mut app, &mut fs, 0x00, 0xC1, attr),
            Sw::WRONG_DATA,
            "accepted {attr:02x?}"
        );
        assert!(
            !fs.has_data(consts::EF_ALGO_PRIV1),
            "stored {attr:02x?} anyway"
        );
    }

    // Every advertised attribute still writes, and clearing back to the default works.
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xC1, ATTR_P256), Sw::OK);
    assert_eq!(
        put(
            &mut app,
            &mut fs,
            0x00,
            0xC1,
            &[0x01, 0x08, 0x00, 0x00, 0x20, 0x00]
        ),
        Sw::OK,
        "rsa2k is advertised"
    );
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xC1, &[]), Sw::OK);
    // ECDH/ECDSA over one OID name the same curve, and MSE can repoint DECIPHER at
    // the AUT slot, so the operation byte must not narrow what a slot accepts.
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xC3, ATTR_P256_ECDH), Sw::OK);
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xC2, ATTR_P256), Sw::OK);
}

struct Fixed(crate::Presence);
impl crate::UserPresence for Fixed {
    fn request(&mut self, _confirm: crate::Confirm<'_>) -> crate::Presence {
        self.0
    }
}

// Import a P-256 SIG key + verify PW1, then enable the SIG UIF (touch) DO.
fn setup_uif_sig(app: &mut OpenpgpApplet, fs: &mut Fs<RamStorage>) {
    verify_pin(app, fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    assert_eq!(put(app, fs, 0x00, 0xC1, ATTR_P256), Sw::OK);
    assert_eq!(run(app, fs, &ec_import(0xB6, &[0x11u8; 32])).1, Sw::OK);
    verify_pin(app, fs, consts::PW1_MODE81, consts::PW1_DEFAULT);
    fs.put(consts::EF_UIF_SIG, &[0x01, 0x20]).unwrap(); // UIF on
}

fn pso_cds(app: &mut OpenpgpApplet, fs: &mut Fs<RamStorage>) -> (Vec<u8>, Sw) {
    let mut a = vec![0x00, consts::INS_PSO, 0x9E, 0x9A, 0x20];
    a.extend_from_slice(&[0x42u8; 32]);
    run(app, fs, &a)
}

#[test]
fn uif_blocks_pso_sign_without_touch() {
    let rng = RefCell::new(CountRng(7));
    let mut fs = make_fs();
    let presence = RefCell::new(Fixed(crate::Presence::Timeout));
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    setup_uif_sig(&mut app, &mut fs);

    // A missed touch → SECURE_MESSAGE_EXEC_ERROR (0x6600), before any signing.
    assert_eq!(pso_cds(&mut app, &mut fs).1, Sw::SECURE_MESSAGE_EXEC_ERROR);
    let mut c = [0u8; 3];
    let n = fs.read(consts::EF_SIG_COUNT, &mut c).unwrap();
    assert_eq!(&c[..n], &[0, 0, 0], "counter must not advance when blocked");
}

/// UIF `02` is "permanently enabled" (OpenPGP 3.4 §4.4.3.6): PUT DATA may not lower
/// it, so a caller holding PW3 alone — which already satisfies the PSO:CDS ACL —
/// cannot turn a signature into a touchless one. Only a factory reset clears it.
#[test]
fn permanent_uif_cannot_be_revoked_with_pw3() {
    let rng = RefCell::new(CountRng(7));
    let mut fs = make_fs();
    let presence = RefCell::new(Fixed(crate::Presence::Timeout));
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);

    // Arm the permanent policy through the ordinary PUT DATA path.
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xD6, &[0x02, 0x20]), Sw::OK);

    // Lowering it is refused, and the stored value is untouched.
    assert_eq!(
        put(&mut app, &mut fs, 0x00, 0xD6, &[0x00, 0x20]),
        Sw::CONDITIONS_NOT_SATISFIED
    );
    assert_eq!(
        put(&mut app, &mut fs, 0x00, 0xD6, &[0x01, 0x20]),
        Sw::CONDITIONS_NOT_SATISFIED
    );
    assert_eq!(
        put(&mut app, &mut fs, 0x00, 0xD6, &[]),
        Sw::CONDITIONS_NOT_SATISFIED
    );
    let mut cur = [0u8; 2];
    let n = fs.read(consts::EF_UIF_SIG, &mut cur).unwrap();
    assert_eq!(&cur[..n], &[0x02, 0x20]);

    // Re-writing the same permanent value stays idempotent, and undefined flag
    // values are rejected rather than stored and echoed back as meaningful.
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xD6, &[0x02, 0x20]), Sw::OK);
    assert_eq!(
        put(&mut app, &mut fs, 0x00, 0xD7, &[0x03, 0x20]),
        Sw::WRONG_DATA
    );
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xD7, &[0x01]), Sw::WRONG_DATA);

    // A non-permanent policy is still freely revocable (the documented on/off flow).
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xD8, &[0x01, 0x20]), Sw::OK);
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xD8, &[0x00, 0x20]), Sw::OK);
}

#[test]
fn uif_on_with_touch_signs() {
    let rng = RefCell::new(CountRng(7));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    setup_uif_sig(&mut app, &mut fs);

    // UIF on but the touch is confirmed → the signature is produced as normal.
    let (sig, sw) = pso_cds(&mut app, &mut fs);
    assert_eq!(sw, Sw::OK);
    assert_eq!(sig.len(), 64);
}

#[test]
fn sign_without_pin_is_denied() {
    let rng = RefCell::new(CountRng(7));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    put(&mut app, &mut fs, 0x00, 0xC1, ATTR_P256);
    run(&mut app, &mut fs, &ec_import(0xB6, &[0x11u8; 32]));
    // Fresh SELECT clears the session → PSO must be refused.
    let mut buf = [0u8; 8];
    let mut res = ResBuf::new(&mut buf);
    app.select(false, &mut fs, &mut res);
    let mut a = vec![0x00, consts::INS_PSO, 0x9E, 0x9A, 0x20];
    a.extend_from_slice(&[0x42u8; 32]);
    assert_eq!(
        run(&mut app, &mut fs, &a).1,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
}

#[test]
fn import_p256_dec_then_pso_decipher_ecdh() {
    let rng = RefCell::new(CountRng(7));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);

    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    put(&mut app, &mut fs, 0x00, 0xC2, ATTR_P256_ECDH); // DEC algo attr (ECDH)
    let dec_scalar = [0x22u8; 32];
    let (_, sw) = run(&mut app, &mut fs, &ec_import(0xB8, &dec_scalar));
    assert_eq!(sw, Sw::OK);

    verify_pin(&mut app, &mut fs, consts::PW1_MODE82, consts::PW1_DEFAULT);

    // An ephemeral peer key; the card must return the shared x-coordinate.
    let eph = [0x33u8; 32];
    let eph_pub = p256_vk(&eph).to_sec1_point(false);
    let f86 = [&[0x86, eph_pub.as_bytes().len() as u8], eph_pub.as_bytes()].concat();
    let f7f49 = [&[0x7F, 0x49, f86.len() as u8], f86.as_slice()].concat();
    let a6 = [&[0xA6, f7f49.len() as u8], f7f49.as_slice()].concat();
    let mut a = vec![0x00, consts::INS_PSO, 0x80, 0x86, a6.len() as u8];
    a.extend_from_slice(&a6);
    let (z, sw) = run(&mut app, &mut fs, &a);
    assert_eq!(sw, Sw::OK);

    // Expected = ECDH(dec_scalar, eph_pub).x.
    let sk = p256::SecretKey::from_bytes(&p256::FieldBytes::from(dec_scalar)).unwrap();
    let peer = p256::PublicKey::from_sec1_bytes(eph_pub.as_bytes()).unwrap();
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    assert_eq!(&z, shared.raw_secret_bytes().as_slice());
}

#[test]
fn mse_redirects_decipher_to_aut_slot() {
    let rng = RefCell::new(CountRng(7));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);

    // DEC slot and AUT slot each hold a *different* P-256 ECDH key.
    put(&mut app, &mut fs, 0x00, 0xC2, ATTR_P256_ECDH); // DEC algo attr
    put(&mut app, &mut fs, 0x00, 0xC3, ATTR_P256_ECDH); // AUT algo attr (ECDH for the test)
    let dec_scalar = [0x22u8; 32];
    let aut_scalar = [0x44u8; 32];
    assert_eq!(
        run(&mut app, &mut fs, &ec_import(0xB8, &dec_scalar)).1,
        Sw::OK
    );
    assert_eq!(
        run(&mut app, &mut fs, &ec_import(0xA4, &aut_scalar)).1,
        Sw::OK
    );

    verify_pin(&mut app, &mut fs, consts::PW1_MODE82, consts::PW1_DEFAULT);

    // One peer ephemeral key, reused across both deciphers.
    let eph = [0x33u8; 32];
    let eph_pub = p256_vk(&eph).to_sec1_point(false);
    let f86 = [&[0x86, eph_pub.as_bytes().len() as u8], eph_pub.as_bytes()].concat();
    let f7f49 = [&[0x7F, 0x49, f86.len() as u8], f86.as_slice()].concat();
    let a6 = [&[0xA6, f7f49.len() as u8], f7f49.as_slice()].concat();
    let mut dec_cmd = vec![0x00, consts::INS_PSO, 0x80, 0x86, a6.len() as u8];
    dec_cmd.extend_from_slice(&a6);

    // Default slots: DECIPHER uses the DEC key.
    let (z_dec, sw) = run(&mut app, &mut fs, &dec_cmd);
    assert_eq!(sw, Sw::OK);

    // MSE: point the confidentiality template (P2=0xB8 = PSO:DECIPHER) at key
    // ref 3 → the AUT slot.
    let mse = [0x00, consts::INS_MSE, 0x41, 0xB8, 0x03, 0x83, 0x01, 0x03];
    assert_eq!(run(&mut app, &mut fs, &mse).1, Sw::OK);

    // Now DECIPHER uses the AUT key → a different shared secret, matching host ECDH.
    let (z_aut, sw) = run(&mut app, &mut fs, &dec_cmd);
    assert_eq!(sw, Sw::OK);
    assert_ne!(z_dec, z_aut, "MSE did not redirect the decipher slot");
    let sk = p256::SecretKey::from_bytes(&p256::FieldBytes::from(aut_scalar)).unwrap();
    let peer = p256::PublicKey::from_sec1_bytes(eph_pub.as_bytes()).unwrap();
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    assert_eq!(&z_aut, shared.raw_secret_bytes().as_slice());
}

// OpenPGP 3.4 §7.2.18's own worked example is `00 22 41 A4 03 83 01 02` — an
// ISO 7816-8 Authentication Template, so it configures INTERNAL AUTHENTICATE.
// It is also the only form a conformant host sends, and it used to answer 9000
// while changing nothing. Driven through `process`, not `mse`, because the
// defect was invisible to a helper-level test: both arms wrote a session field.
#[test]
fn mse_at_template_redirects_internal_authenticate() {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    let rng = RefCell::new(CountRng(7));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);

    // A different ECDSA P-256 key in the DEC and AUT slots, so the verifying key
    // that accepts the signature names the slot the card actually used.
    put(&mut app, &mut fs, 0x00, 0xC2, ATTR_P256);
    put(&mut app, &mut fs, 0x00, 0xC3, ATTR_P256);
    let dec_scalar = [0x22u8; 32];
    let aut_scalar = [0x44u8; 32];
    assert_eq!(
        run(&mut app, &mut fs, &ec_import(consts::CRT_DEC, &dec_scalar)).1,
        Sw::OK
    );
    assert_eq!(
        run(&mut app, &mut fs, &ec_import(consts::CRT_AUT, &aut_scalar)).1,
        Sw::OK
    );
    verify_pin(&mut app, &mut fs, consts::PW1_MODE82, consts::PW1_DEFAULT);

    let digest = [0x42u8; 32];
    let mut int_aut = vec![0x00, consts::INS_INTERNAL_AUT, 0x00, 0x00, 32];
    int_aut.extend_from_slice(&digest);

    let (sig, sw) = run(&mut app, &mut fs, &int_aut);
    assert_eq!(sw, Sw::OK);
    let s = p256::ecdsa::Signature::from_slice(&sig).unwrap();
    p256_vk(&aut_scalar).verify_prehash(&digest, &s).unwrap();

    let mse = [0x00, consts::INS_MSE, 0x41, 0xA4, 0x03, 0x83, 0x01, 0x02];
    assert_eq!(run(&mut app, &mut fs, &mse).1, Sw::OK);

    let (sig, sw) = run(&mut app, &mut fs, &int_aut);
    assert_eq!(sw, Sw::OK);
    let s = p256::ecdsa::Signature::from_slice(&sig).unwrap();
    p256_vk(&dec_scalar)
        .verify_prehash(&digest, &s)
        .expect("MSE 41 A4 {83 01 02} did not repoint INTERNAL AUTHENTICATE");
    assert!(p256_vk(&aut_scalar).verify_prehash(&digest, &s).is_err());
}

#[test]
fn import_ed25519_aut_then_internal_authenticate() {
    use ed25519_dalek::Verifier;
    let rng = RefCell::new(CountRng(7));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);

    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    put(&mut app, &mut fs, 0x00, 0xC3, ATTR_ED25519); // AUT algo attr
    let seed = [0x44u8; 32];
    let (_, sw) = run(&mut app, &mut fs, &ec_import(0xA4, &seed));
    assert_eq!(sw, Sw::OK);

    verify_pin(&mut app, &mut fs, consts::PW1_MODE82, consts::PW1_DEFAULT);

    // INTERNAL AUTHENTICATE signs the message directly (PureEdDSA).
    let msg = b"challenge-to-sign-with-the-auth-key";
    let mut a = vec![0x00, consts::INS_INTERNAL_AUT, 0x00, 0x00, msg.len() as u8];
    a.extend_from_slice(msg);
    let (sig, sw) = run(&mut app, &mut fs, &a);
    assert_eq!(sw, Sw::OK);
    assert_eq!(sig.len(), 64);

    let vk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
    let s = ed25519_dalek::Signature::from_slice(&sig).unwrap();
    vk.verify(msg, &s).unwrap();
}

// ---- RSA IMPORT + PSO + INTERNAL AUTHENTICATE ----------------------------

// The same fixed RSA-2048 key as keys::rsa_tests (primes sans the sign byte).
const RSA_P: &str = "f05c23060effc422e4310c13b5aecda74744925c97c17d202aa9ed306941fa1e942e61c8d9c80961cf90459af36b9e7d529610f5165d60836de5aef2aeb47ea500c5a61bb96fd3bb4aca36d45464cce24ff0b67bb3ba382d9bdd95b7133eab86125800f10b0627fe1bd7689802d767dd9911eefb60d76e2ec860163f3077a5bd";
const RSA_Q: &str = "c6a96b4a9b7bdd654152f3302dd23bd7b18e62f999cf0d44d01c6ce18cfdfb1c29e523edebe5e6df8967f49afe38d6a9345bc6f4f966e0de2902bddc7caf5a4a1761d18b070cd4cda287388cbdf523c39e246c220af3292fee181b4bb1c3f533b74de89c586e6f9d47ae4bb7f8735d3f0b377a76a7ca6c81324833c2b78b737d";
// SHA-256 DigestInfo prefix (what gpg sends ahead of the 32-byte hash).
const DI_SHA256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

fn hx(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn ber_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else if n < 0x100 {
        vec![0x81, n as u8]
    } else {
        vec![0x82, (n >> 8) as u8, n as u8]
    }
}

// Build the RSA IMPORT (0xDB) extended-header-list APDU: 7F48 lists the
// tag-length pairs for 0x91 (E), 0x92 (P), 0x93 (Q); 5F48 carries E‖P‖Q. The
// body exceeds 255 bytes, so it goes in an extended-length APDU.
fn rsa_import(crt: u8, e: &[u8], p: &[u8], q: &[u8]) -> Vec<u8> {
    let mut tmpl = Vec::new();
    for (tag, v) in [(0x91u8, e), (0x92, p), (0x93, q)] {
        tmpl.push(tag);
        tmpl.extend_from_slice(&ber_len(v.len()));
    }
    let mut f7f48 = vec![0x7F, 0x48];
    f7f48.extend_from_slice(&ber_len(tmpl.len()));
    f7f48.extend_from_slice(&tmpl);

    let kd = [e, p, q].concat();
    let mut f5f48 = vec![0x5F, 0x48];
    f5f48.extend_from_slice(&ber_len(kd.len()));
    f5f48.extend_from_slice(&kd);

    let mut body = vec![crt, 0x00];
    body.extend_from_slice(&f7f48);
    body.extend_from_slice(&f5f48);
    let mut header = vec![0x4D];
    header.extend_from_slice(&ber_len(body.len()));
    header.extend_from_slice(&body);

    let mut a = vec![0x00, consts::INS_PUT_DATA_ODD, 0x3F, 0xFF, 0x00];
    a.push((header.len() >> 8) as u8);
    a.push(header.len() as u8);
    a.extend_from_slice(&header);
    a
}

fn rsa_pubkey() -> rsa::RsaPublicKey {
    let key = keys::rsa_from_pqe(&[0x01, 0x00, 0x01], &hx(RSA_P), &hx(RSA_Q)).unwrap();
    rsa::RsaPublicKey::from(&key)
}

#[test]
fn import_rsa_sig_then_pso_sign_verifies() {
    let rng = RefCell::new(CountRng(7));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);

    // No algo attribute set → the slot defaults to RSA-2048 (gpg's default).
    let (_, sw) = run(
        &mut app,
        &mut fs,
        &rsa_import(0xB6, &[0x01, 0x00, 0x01], &hx(RSA_P), &hx(RSA_Q)),
    );
    assert_eq!(sw, Sw::OK);

    // PSO:CDS over a SHA-256 DigestInfo, authorised by PW1.
    verify_pin(&mut app, &mut fs, consts::PW1_MODE81, consts::PW1_DEFAULT);
    let mut di = DI_SHA256.to_vec();
    di.extend_from_slice(&[0x42u8; 32]);
    let mut a = vec![0x00, consts::INS_PSO, 0x9E, 0x9A, di.len() as u8];
    a.extend_from_slice(&di);
    let (sig, sw) = run(&mut app, &mut fs, &a);
    assert_eq!(sw, Sw::OK);
    assert_eq!(sig.len(), 256);
    rsa_pubkey()
        .verify(rsa::Pkcs1v15Sign::new_unprefixed(), &di, &sig)
        .unwrap();

    // The signature counter advanced 0 → 1.
    let mut c = [0u8; 3];
    let n = fs.read(consts::EF_SIG_COUNT, &mut c).unwrap();
    assert_eq!(&c[..n], &[0, 0, 1]);
}

#[test]
fn import_rsa_holds_the_key_to_the_algorithm_attribute() {
    // §4.4.3.12: "The length of the key data shall match the values given in the
    // DO 'Algorithm attributes' (C1 - C3)." Without it the card gives two answers
    // about one key — C1 says one size, the public-key DO publishes another, and
    // `gpg --card-status` prints the attribute. Measured on a YubiKey 5.7.4: every
    // mismatch is `6A80` and nothing is stored.
    let rng = RefCell::new(CountRng(7));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);

    // The slot announces RSA-4096; the key on offer is the 2048-bit fixture.
    let attr4096 = [0x01u8, 0x10, 0x00, 0x00, 0x20, 0x00];
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xC1, &attr4096), Sw::OK);
    let (_, sw) = run(
        &mut app,
        &mut fs,
        &rsa_import(0xB6, &[0x01, 0x00, 0x01], &hx(RSA_P), &hx(RSA_Q)),
    );
    assert_eq!(sw, Sw::WRONG_DATA);
    assert!(
        !fs.has_data(consts::EF_PK_SIG.get()),
        "nothing may be stored"
    );

    // The same key against the attribute that describes it.
    let attr2048 = [0x01u8, 0x08, 0x00, 0x00, 0x20, 0x00];
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xC1, &attr2048), Sw::OK);
    let (_, sw) = run(
        &mut app,
        &mut fs,
        &rsa_import(0xB6, &[0x01, 0x00, 0x01], &hx(RSA_P), &hx(RSA_Q)),
    );
    assert_eq!(sw, Sw::OK);
}

#[test]
fn import_refuses_an_unadvertised_stored_algorithm_attribute() {
    // GENERATE's own gate, on the other door into the same slot. A build predating
    // the PUT DATA gate stored any attribute under PW3 and `EF_ALGO_PRIV*` has no
    // default and no migration, so the value survives the upgrade — and an import
    // against it lands a key this build will not honour.
    let rng = RefCell::new(CountRng(7));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);

    // rsa2048 with a non-standard 17-bit exponent field: not in DO 0xFA.
    fs.put(consts::EF_ALGO_PRIV1, &[0x01, 0x08, 0x00, 0x00, 0x11, 0x00])
        .unwrap();
    let (_, sw) = run(
        &mut app,
        &mut fs,
        &rsa_import(0xB6, &[0x01, 0x00, 0x01], &hx(RSA_P), &hx(RSA_Q)),
    );
    assert_eq!(sw, Sw::WRONG_DATA);
    assert!(!fs.has_data(consts::EF_PK_SIG.get()));
}

#[test]
fn import_rsa_rejects_non_65537_exponent() {
    let rng = RefCell::new(CountRng(7));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);

    // The CRT signer / DECIPHER hardcode e = 65537, so a key with e = 3 would be
    // silently unusable; import must reject it, not store a dead key.
    let (_, sw) = run(
        &mut app,
        &mut fs,
        &rsa_import(0xB6, &[0x03], &hx(RSA_P), &hx(RSA_Q)),
    );
    assert_eq!(sw, Sw::WRONG_DATA);
    assert!(!fs.has_data(consts::EF_PK_SIG.get()));

    // A leading-zero-padded 65537 MPI is still accepted (padding tolerated).
    let (_, sw) = run(
        &mut app,
        &mut fs,
        &rsa_import(0xB6, &[0x00, 0x01, 0x00, 0x01], &hx(RSA_P), &hx(RSA_Q)),
    );
    assert_eq!(sw, Sw::OK);
}

#[test]
fn import_rsa_dec_then_pso_decipher() {
    let rng = RefCell::new(CountRng(7));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    let (_, sw) = run(
        &mut app,
        &mut fs,
        &rsa_import(0xB8, &[0x01, 0x00, 0x01], &hx(RSA_P), &hx(RSA_Q)),
    );
    assert_eq!(sw, Sw::OK);

    verify_pin(&mut app, &mut fs, consts::PW1_MODE82, consts::PW1_DEFAULT);

    // Encrypt a "session key" to the imported public key; the card recovers it.
    let msg = b"a-32-byte-openpgp-session-key!!!";
    let ct = rsa_pubkey()
        .encrypt(
            &mut keys::RngAdapter(&mut CountRng(3)),
            rsa::Pkcs1v15Encrypt,
            msg,
        )
        .unwrap();
    let mut data = vec![0x00u8]; // OpenPGP padding-indicator byte
    data.extend_from_slice(&ct);
    let mut a = vec![0x00, consts::INS_PSO, 0x80, 0x86, 0x00];
    a.push((data.len() >> 8) as u8);
    a.push(data.len() as u8);
    a.extend_from_slice(&data);
    let (pt, sw) = run(&mut app, &mut fs, &a);
    assert_eq!(sw, Sw::OK);
    assert_eq!(&pt, msg);
}

#[test]
fn import_rsa_aut_then_internal_authenticate() {
    let rng = RefCell::new(CountRng(7));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    let (_, sw) = run(
        &mut app,
        &mut fs,
        &rsa_import(0xA4, &[0x01, 0x00, 0x01], &hx(RSA_P), &hx(RSA_Q)),
    );
    assert_eq!(sw, Sw::OK);

    // INTERNAL AUTHENTICATE over a SHA-256 DigestInfo, authorised by PW2.
    verify_pin(&mut app, &mut fs, consts::PW1_MODE82, consts::PW1_DEFAULT);
    let mut di = DI_SHA256.to_vec();
    di.extend_from_slice(&[0x55u8; 32]);
    let mut a = vec![0x00, consts::INS_INTERNAL_AUT, 0x00, 0x00, di.len() as u8];
    a.extend_from_slice(&di);
    let (sig, sw) = run(&mut app, &mut fs, &a);
    assert_eq!(sw, Sw::OK);
    assert_eq!(sig.len(), 256);
    rsa_pubkey()
        .verify(rsa::Pkcs1v15Sign::new_unprefixed(), &di, &sig)
        .unwrap();
}

// ---- Cv25519 (X25519) ECDH -----------------------------------------------

// cv25519 algorithm attribute (stored form = algo-id ‖ OID): ECDH (0x12).
const ATTR_CV25519: &[u8] = &[
    0x12, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01,
];

#[test]
fn import_cv25519_dec_then_pso_decipher() {
    // RFC 7748 §6.1: import Alice (her LE scalar reversed into the big-endian
    // OpenPGP MPI), decipher Bob's 0x40-prefixed ephemeral key → shared K.
    let alice_le = hx("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let bob_pub = hx("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let k = hx("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    let rng = RefCell::new(CountRng(7));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xC2, ATTR_CV25519), Sw::OK);

    let mut alice_be = alice_le.clone();
    alice_be.reverse();
    let (_, sw) = run(&mut app, &mut fs, &ec_import(0xB8, &alice_be));
    assert_eq!(sw, Sw::OK);

    verify_pin(&mut app, &mut fs, consts::PW1_MODE82, consts::PW1_DEFAULT);

    // PSO:DECIPHER with the 0x40-prefixed peer point.
    let mut point = vec![0x40u8];
    point.extend_from_slice(&bob_pub);
    let f86 = [&[0x86, point.len() as u8], point.as_slice()].concat();
    let f7f49 = [&[0x7F, 0x49, f86.len() as u8], f86.as_slice()].concat();
    let a6 = [&[0xA6, f7f49.len() as u8], f7f49.as_slice()].concat();
    let mut a = vec![0x00, consts::INS_PSO, 0x80, 0x86, a6.len() as u8];
    a.extend_from_slice(&a6);
    let (z, sw) = run(&mut app, &mut fs, &a);
    assert_eq!(sw, Sw::OK);
    assert_eq!(
        z, k,
        "cv25519 DECIPHER must equal the RFC 7748 shared secret"
    );
}

// ---- GENERATE ASYMMETRIC KEY PAIR (0x47) ---------------------------------

// A linear-congruential RNG, better distributed than CountRng for the RSA
// prime search (which would labour over highly structured input).
struct LcgRng(u64);
impl Rng for LcgRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (self.0 >> 33) as u8;
        }
    }
}

// GENERATE (0x47): P1 = 0x80 generate / 0x81 read-public; data = CRT ‖ 0x00.
fn keygen(app: &mut OpenpgpApplet, fs: &mut Fs<RamStorage>, p1: u8, crt: u8) -> (Vec<u8>, Sw) {
    run(
        app,
        fs,
        &[0x00, consts::INS_KEYPAIR_GEN, p1, 0x00, 0x02, crt, 0x00],
    )
}

// Extract the 0x86 EC point from a 7F49 public-key DO (short-form lengths).
fn ec_point(do_: &[u8]) -> &[u8] {
    assert_eq!(&do_[..2], &[0x7F, 0x49]);
    assert!(do_[2] < 0x80, "short-form outer length");
    assert_eq!(do_[3], 0x86);
    let plen = do_[4] as usize;
    &do_[5..5 + plen]
}

// Extract (N, E) from a 7F49 82 LL { 81 82 <N> · 82 <E> } RSA public-key DO.
fn rsa_n_e(d: &[u8]) -> (Vec<u8>, Vec<u8>) {
    assert_eq!(&d[..3], &[0x7F, 0x49, 0x82]);
    let mut i = 5; // skip 7F49 + the 2-byte outer length
    assert_eq!(d[i], 0x81);
    assert_eq!(d[i + 1], 0x82);
    let nlen = ((d[i + 2] as usize) << 8) | d[i + 3] as usize;
    i += 4;
    let n = d[i..i + nlen].to_vec();
    i += nlen;
    assert_eq!(d[i], 0x82);
    let elen = d[i + 1] as usize;
    let e = d[i + 2..i + 2 + elen].to_vec();
    (n, e)
}

#[test]
fn generate_p256_sig_sign_verifies_and_reads_back() {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    let rng = RefCell::new(LcgRng(1));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);

    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xC1, ATTR_P256), Sw::OK);

    let (do_, sw) = keygen(&mut app, &mut fs, 0x80, 0xB6);
    assert_eq!(sw, Sw::OK);
    let point = ec_point(&do_).to_vec();
    assert_eq!(point.len(), 65); // uncompressed P-256

    // Read-public (P1 = 0x81) returns the identical DO.
    let (do2, sw) = keygen(&mut app, &mut fs, 0x81, 0xB6);
    assert_eq!(sw, Sw::OK);
    assert_eq!(do2, do_);

    // The card signs with the generated key; the signature must verify against
    // the returned public point — keygen/store/load/sign all agree.
    verify_pin(&mut app, &mut fs, consts::PW1_MODE81, consts::PW1_DEFAULT);
    let digest = [0x42u8; 32];
    let mut a = vec![0x00, consts::INS_PSO, 0x9E, 0x9A, digest.len() as u8];
    a.extend_from_slice(&digest);
    let (sig, sw) = run(&mut app, &mut fs, &a);
    assert_eq!(sw, Sw::OK);
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).unwrap();
    let s = p256::ecdsa::Signature::from_slice(&sig).unwrap();
    vk.verify_prehash(&digest, &s).unwrap();

    // SIG keygen reset the signature counter; PSO then advanced it 0 → 1.
    let mut c = [0u8; 3];
    let n = fs.read(consts::EF_SIG_COUNT, &mut c).unwrap();
    assert_eq!(&c[..n], &[0, 0, 1]);
}

#[test]
fn generate_requires_pw3() {
    let rng = RefCell::new(LcgRng(1));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    // Generate without admin auth is refused; reading an absent key is not found.
    assert_eq!(
        keygen(&mut app, &mut fs, 0x80, 0xB6).1,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(
        keygen(&mut app, &mut fs, 0x81, 0xB6).1,
        Sw::REFERENCE_NOT_FOUND
    );
}

#[test]
fn generate_dec_ecdh_mints_aes_key() {
    let rng = RefCell::new(LcgRng(2));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xC2, ATTR_P256_ECDH), Sw::OK);
    assert!(!fs.has_data(consts::EF_AES_KEY.get()));

    let (do_, sw) = keygen(&mut app, &mut fs, 0x80, 0xB8);
    assert_eq!(sw, Sw::OK);
    let point = ec_point(&do_).to_vec();
    // Generating the DEC key also seeds the card's AES key, `D5` being empty here.
    assert!(fs.has_data(consts::EF_AES_KEY.get()));

    // The card computes ECDH with the generated key; ECDH is symmetric, so
    // ECDH(dec_priv, eph_pub).x == ECDH(eph_priv, dec_pub).x.
    verify_pin(&mut app, &mut fs, consts::PW1_MODE82, consts::PW1_DEFAULT);
    let eph = [0x33u8; 32];
    let eph_pub = p256_vk(&eph).to_sec1_point(false);
    let f86 = [&[0x86, eph_pub.as_bytes().len() as u8], eph_pub.as_bytes()].concat();
    let f7f49 = [&[0x7F, 0x49, f86.len() as u8], f86.as_slice()].concat();
    let a6 = [&[0xA6, f7f49.len() as u8], f7f49.as_slice()].concat();
    let mut a = vec![0x00, consts::INS_PSO, 0x80, 0x86, a6.len() as u8];
    a.extend_from_slice(&a6);
    let (z, sw) = run(&mut app, &mut fs, &a);
    assert_eq!(sw, Sw::OK);
    let sk = p256::SecretKey::from_bytes(&p256::FieldBytes::from(eph)).unwrap();
    let peer = p256::PublicKey::from_sec1_bytes(&point).unwrap();
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    assert_eq!(&z, shared.raw_secret_bytes().as_slice());
}

#[test]
fn aes_pso_encipher_decipher_roundtrip() {
    // OpenPGP-card AES symmetric PSO: ENCIPHER (86 80) plaintext -> 0x02 ||
    // cryptogram; DECIPHER (80 86) 0x02 || cryptogram -> plaintext, using the
    // AES key the DEC keygen seeded. The key is DEK-sealed (unknown host-side),
    // so correctness is shown by round-trip.
    let rng = RefCell::new(LcgRng(7));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xC2, ATTR_P256_ECDH), Sw::OK);
    let (_do, sw) = keygen(&mut app, &mut fs, 0x80, 0xB8); // mints EF_AES_KEY
    assert_eq!(sw, Sw::OK);
    assert!(fs.has_data(consts::EF_AES_KEY.get()));

    verify_pin(&mut app, &mut fs, consts::PW1_MODE82, consts::PW1_DEFAULT); // PW2
    let pt = [0xABu8; 32]; // two AES blocks

    let mut a = vec![0x00, consts::INS_PSO, 0x86, 0x80, pt.len() as u8];
    a.extend_from_slice(&pt);
    let (cg, sw) = run(&mut app, &mut fs, &a);
    assert_eq!(sw, Sw::OK);
    assert_eq!(cg[0], 0x02); // padding indicator
    assert_eq!(cg.len(), pt.len() + 1);
    assert_ne!(&cg[1..], &pt[..]); // actually enciphered

    let mut a = vec![0x00, consts::INS_PSO, 0x80, 0x86, cg.len() as u8];
    a.extend_from_slice(&cg);
    let (back, sw) = run(&mut app, &mut fs, &a);
    assert_eq!(sw, Sw::OK);
    assert_eq!(&back, &pt[..]);

    // Raw CBC, no padding: a non-block-aligned plaintext is rejected.
    let mut a = vec![0x00, consts::INS_PSO, 0x86, 0x80, 15];
    a.extend_from_slice(&[0u8; 15]);
    assert_eq!(run(&mut app, &mut fs, &a).1, Sw::WRONG_LENGTH);
}

#[test]
fn aes_pso_refused_without_dec_password() {
    // The AES PSO needs PW2 (or PW3); with no password the gate rejects it
    // before touching the key.
    let rng = RefCell::new(LcgRng(8));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    let mut a = vec![0x00, consts::INS_PSO, 0x86, 0x80, 16];
    a.extend_from_slice(&[0u8; 16]);
    assert_eq!(
        run(&mut app, &mut fs, &a).1,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
}

// SELECT DATA command selecting cardholder-cert occurrence `occ` (tag 7F21).
fn select_cert(occ: u8) -> Vec<u8> {
    vec![
        0x00,
        consts::INS_SELECT_DATA,
        occ,
        0x04,
        0x06,
        0x60,
        0x04,
        0x5C,
        0x02,
        0x7F,
        0x21,
    ]
}

#[test]
fn cardholder_cert_write_read_per_occurrence() {
    let rng = RefCell::new(LcgRng(11));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);

    // Occurrence 0 is the default (no SELECT DATA needed): write + read back.
    let cert0 = [0x30u8, 0x03, 0xAA, 0xBB, 0xCC];
    let mut p = vec![0x00, consts::INS_PUT_DATA, 0x7F, 0x21, cert0.len() as u8];
    p.extend_from_slice(&cert0);
    assert_eq!(run(&mut app, &mut fs, &p).1, Sw::OK);
    let (g, sw) = run(&mut app, &mut fs, &[0x00, consts::INS_GET_DATA, 0x7F, 0x21]);
    assert_eq!(sw, Sw::OK);
    assert_eq!(g, cert0);

    // Select occurrence 1 and store a different cert there.
    assert_eq!(run(&mut app, &mut fs, &select_cert(1)).1, Sw::OK);
    let cert1 = [0x31u8, 0x02, 0x99, 0x88];
    let mut p = vec![0x00, consts::INS_PUT_DATA, 0x7F, 0x21, cert1.len() as u8];
    p.extend_from_slice(&cert1);
    assert_eq!(run(&mut app, &mut fs, &p).1, Sw::OK);
    assert_eq!(
        run(&mut app, &mut fs, &[0x00, consts::INS_GET_DATA, 0x7F, 0x21]).0,
        cert1
    );

    // Back to occurrence 0 → still the original cert (instances are independent).
    assert_eq!(run(&mut app, &mut fs, &select_cert(0)).1, Sw::OK);
    assert_eq!(
        run(&mut app, &mut fs, &[0x00, consts::INS_GET_DATA, 0x7F, 0x21]).0,
        cert0
    );

    // Empty PUT deletes the selected occurrence.
    assert_eq!(
        run(&mut app, &mut fs, &[0x00, consts::INS_PUT_DATA, 0x7F, 0x21]).1,
        Sw::OK
    );
    assert!(
        run(&mut app, &mut fs, &[0x00, consts::INS_GET_DATA, 0x7F, 0x21])
            .0
            .is_empty()
    );
}

#[test]
fn cardholder_cert_write_needs_pw3_and_select_validates() {
    let rng = RefCell::new(LcgRng(12));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);

    // Write without PW3 is refused.
    let p = vec![0x00, consts::INS_PUT_DATA, 0x7F, 0x21, 0x02, 0xDE, 0xAD];
    assert_eq!(
        run(&mut app, &mut fs, &p).1,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );

    // SELECT DATA validation: unknown tag / out-of-range occurrence / bad P2.
    let mut bad_tag = select_cert(0);
    (bad_tag[9], bad_tag[10]) = (0x00, 0x65); // tag 0x0065 (cardholder data)
    assert_eq!(run(&mut app, &mut fs, &bad_tag).1, Sw::REFERENCE_NOT_FOUND);
    // An occurrence past the last one is a wrong P1 — a YubiKey answers `6B00` to
    // 3 and 4 where 0-2 are `9000`; the unknown TAG above stays `6A88` because it
    // is named in the data field, not in P1P2.
    assert_eq!(run(&mut app, &mut fs, &select_cert(3)).1, Sw::WRONG_P1P2);
    let mut bad_p2 = select_cert(0);
    bad_p2[3] = 0x00;
    assert_eq!(run(&mut app, &mut fs, &bad_p2).1, Sw::INCORRECT_P1P2);
}

// SELECT DATA is the walk's other starting gun — measured on a YubiKey 5.7.4,
// which walks from the selected occurrence with no GET DATA in between — and
// neither command refuses a body: GET DATA ignores one, GET NEXT DATA answers
// 6A80 rather than 6700.
#[test]
fn select_data_arms_the_walk_and_a_body_is_not_a_length_error() {
    let rng = RefCell::new(LcgRng(29));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);

    let certs: [&[u8]; 3] = [&[0xB0; 8], &[0xB1; 9], &[0xB2; 10]];
    for (occ, cert) in certs.iter().enumerate() {
        assert_eq!(run(&mut app, &mut fs, &select_cert(occ as u8)).1, Sw::OK);
        let mut p = vec![0x00, consts::INS_PUT_DATA, 0x7F, 0x21, cert.len() as u8];
        p.extend_from_slice(cert);
        assert_eq!(run(&mut app, &mut fs, &p).1, Sw::OK);
    }

    let get = [0x00, consts::INS_GET_DATA, 0x7F, 0x21];
    let next = [0x00, consts::INS_GET_NEXT_DATA, 0x7F, 0x21];

    // Control: the applet SELECT clears the anchor, so the walk really is armed
    // by what follows and not left over from the writes above.
    app.deselect(&mut fs);
    assert_eq!(run(&mut app, &mut fs, &next).1, Sw::WRONG_DATA);

    // SELECT DATA alone arms it, from the occurrence it selected.
    assert_eq!(run(&mut app, &mut fs, &select_cert(0)).1, Sw::OK);
    assert_eq!(run(&mut app, &mut fs, &next), (certs[1].to_vec(), Sw::OK));
    assert_eq!(run(&mut app, &mut fs, &next), (certs[2].to_vec(), Sw::OK));
    assert_eq!(run(&mut app, &mut fs, &next).1, Sw::WRONG_DATA);

    app.deselect(&mut fs);
    assert_eq!(run(&mut app, &mut fs, &select_cert(1)).1, Sw::OK);
    // The occurrence SELECT DATA chose is the one GET DATA reads and the one the
    // walk starts from — the same pointer, not two.
    assert_eq!(run(&mut app, &mut fs, &get), (certs[1].to_vec(), Sw::OK));
    assert_eq!(run(&mut app, &mut fs, &next), (certs[2].to_vec(), Sw::OK));

    // A body is ignored on GET DATA — of the cert and of an ordinary DO — and is
    // wrong data, not a wrong length, on GET NEXT.
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &[0x00, consts::INS_GET_DATA, 0x7F, 0x21, 0x01, 0xAA]
        ),
        (certs[2].to_vec(), Sw::OK)
    );
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &[0x00, consts::INS_GET_DATA, 0x00, 0x5E, 0x01, 0xAA]
        )
        .1,
        Sw::OK
    );
    assert_eq!(run(&mut app, &mut fs, &select_cert(0)).1, Sw::OK);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &[0x00, consts::INS_GET_NEXT_DATA, 0x7F, 0x21, 0x01, 0xAA]
        )
        .1,
        Sw::WRONG_DATA
    );
    // …and refusing it moved nothing: the walk still starts where it was armed.
    assert_eq!(run(&mut app, &mut fs, &next), (certs[1].to_vec(), Sw::OK));
}

// OpenPGP 3.4 §4.4.3.8 gives DO 0xDE three status values per slot: 00 absent,
// 01 generated on card, 02 imported. Ours collapsed them to a boolean, so an
// imported key claimed on-card generation — the one direction that misleads a
// host about whether the key could have been backed up. The transition table
// below is the one measured on a YubiKey 5.7.4.
#[test]
fn key_info_reports_generated_and_imported_apart() {
    let rng = RefCell::new(LcgRng(17));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);

    fn key_info(app: &mut OpenpgpApplet, fs: &mut Fs<RamStorage>) -> Vec<u8> {
        let (b, sw) = run(app, fs, &[0x00, consts::INS_GET_DATA, 0x00, 0xDE]);
        assert_eq!(sw, Sw::OK);
        b
    }
    fn generate(app: &mut OpenpgpApplet, fs: &mut Fs<RamStorage>, crt: u8) {
        let a = [0x00, consts::INS_KEYPAIR_GEN, 0x80, 0x00, 0x02, crt, 0x00];
        assert_eq!(run(app, fs, &a).1, Sw::OK);
    }

    for tag in [0xC1u8, 0xC2, 0xC3] {
        assert_eq!(put(&mut app, &mut fs, 0x00, tag, ATTR_P256), Sw::OK);
    }
    // No keys at all.
    assert_eq!(key_info(&mut app, &mut fs), [1, 0, 2, 0, 3, 0]);

    generate(&mut app, &mut fs, consts::CRT_AUT);
    assert_eq!(key_info(&mut app, &mut fs), [1, 0, 2, 0, 3, 1]);

    // IMPORT over the same slot: generated → imported.
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &ec_import(consts::CRT_AUT, &[0x44u8; 32])
        )
        .1,
        Sw::OK
    );
    assert_eq!(key_info(&mut app, &mut fs), [1, 0, 2, 0, 3, 2]);

    // A power cycle must not lose it — the origin is persisted, not session state.
    app.deselect(&mut fs);
    assert_eq!(key_info(&mut app, &mut fs), [1, 0, 2, 0, 3, 2]);

    // IMPORT into a slot that was empty, and GENERATE back over the imported one.
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &ec_import(consts::CRT_DEC, &[0x55u8; 32])
        )
        .1,
        Sw::OK
    );
    assert_eq!(key_info(&mut app, &mut fs), [1, 0, 2, 2, 3, 2]);
    generate(&mut app, &mut fs, consts::CRT_AUT);
    assert_eq!(key_info(&mut app, &mut fs), [1, 0, 2, 2, 3, 1]);
    generate(&mut app, &mut fs, consts::CRT_SIG);
    assert_eq!(key_info(&mut app, &mut fs), [1, 1, 2, 2, 3, 1]);

    // A key predating the origin record must not be claimed as on-card: drop the
    // record with all three keys in place and every slot reads back imported.
    fs.delete(consts::EF_KEY_ORIGIN).unwrap();
    assert_eq!(key_info(&mut app, &mut fs), [1, 2, 2, 2, 3, 2]);

    // TERMINATE DF takes the record with everything else.
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &[0x00, consts::INS_TERMINATE_DF, 0x00, 0x00]
        )
        .1,
        Sw::OK
    );
    assert!(!fs.has_data(consts::EF_KEY_ORIGIN));
    assert_eq!(key_info(&mut app, &mut fs), [1, 0, 2, 0, 3, 0]);
}

// OpenPGP 3.4 §4.4.2 fixes the fingerprint DOs at 20 bytes and the timestamps
// at 4 — §4.4.1 lists only the C5/C6/CD aggregates that republish them as
// fixed-width slices. A write of any other
// length used to be stored, so the same DO read back as two different values —
// itself standalone, and a truncation inside the aggregate. A YubiKey 5.7.4
// answers 6A80 at every other length and leaves the DO alone.
/// §4.4.1 caps the cardholder name at 39 bytes and the language preference at 8,
/// and §4.4.3.4 gives the sex DO a value list rather than a length. A YubiKey
/// 5.7.4 refuses a byte over either cap with `6A80` and leaves the DO alone
/// (measured at the maximum, +1, 254 and 255), and its list is narrower than ISO
/// 5218: `'A'` and `'0'` alike are `6A80`.
#[test]
fn put_data_caps_the_cardholder_dos() {
    let rng = RefCell::new(CountRng(7));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);

    for (p1, p2, max) in [
        (0x00u8, 0x5Bu8, consts::NAME_MAX),
        (0x5F, 0x2D, consts::LANG_MAX),
    ] {
        let good = vec![b'x'; max];
        assert_eq!(put(&mut app, &mut fs, p1, p2, &good), Sw::OK);
        for n in [max + 1, max + 2, 254, 255] {
            assert_eq!(
                put(&mut app, &mut fs, p1, p2, &vec![b'y'; n]),
                Sw::WRONG_DATA,
                "PUT {p1:02X}{p2:02X} len {n}"
            );
            let (body, sw) = run(
                &mut app,
                &mut fs,
                &[0x00, consts::INS_GET_DATA, p1, p2, 0x00],
            );
            assert_eq!(sw, Sw::OK);
            assert_eq!(body, good, "PUT {p1:02X}{p2:02X} len {n} altered the DO");
        }
        // Clearing the DO is still allowed — this is a cap, not a fixed width.
        assert_eq!(put(&mut app, &mut fs, p1, p2, &[]), Sw::OK);
    }

    // Sex: the codes the card takes, and nothing else. `'0'` (ISO 5218 "not
    // known") is in the standard and NOT in the set: a YubiKey 5.7.4 answers
    // `6A80` to it, 3/3, and holds `'9'` itself.
    for v in consts::SEX_VALUES {
        assert_eq!(put(&mut app, &mut fs, 0x5F, 0x35, &[*v]), Sw::OK);
    }
    for v in [b'0', b'A', b'3', b'm', 0x00] {
        assert_eq!(
            put(&mut app, &mut fs, 0x5F, 0x35, &[v]),
            Sw::WRONG_DATA,
            "sex {v:#04X}"
        );
    }
    assert_eq!(put(&mut app, &mut fs, 0x5F, 0x35, b"11"), Sw::WRONG_DATA);
}

#[test]
fn put_data_polices_the_fixed_length_dos() {
    let rng = RefCell::new(LcgRng(19));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);

    // Each of the nine, at its own length and at every length around it.
    let fps = [0xC7u8, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC];
    let tss = [0xCEu8, 0xCF, 0xD0];
    for (tags, want) in [(&fps[..], consts::FP_LEN), (&tss[..], consts::TS_LEN)] {
        for &tag in tags {
            let good = vec![0xB0u8; want];
            assert_eq!(put(&mut app, &mut fs, 0x00, tag, &good), Sw::OK);
            for n in [0, 1, want - 1, want + 1, want * 2, 60] {
                assert_eq!(
                    put(&mut app, &mut fs, 0x00, tag, &vec![0xEE; n]),
                    Sw::WRONG_DATA,
                    "PUT {tag:#04X} len {n}"
                );
                // …and the refusal changed nothing.
                let (body, sw) = run(&mut app, &mut fs, &[0x00, consts::INS_GET_DATA, 0x00, tag]);
                assert_eq!(sw, Sw::OK);
                assert_eq!(body, good, "PUT {tag:#04X} len {n} altered the DO");
            }
        }
    }

    // The aggregates stay read-only, at every length, and say so the way a
    // YubiKey does: `6B00`, the tag being this command's P1P2.
    for tag in [0xC5u8, 0xC6, 0xCD] {
        for n in [0, 4, 12, 20, 60, 61] {
            assert_eq!(
                put(&mut app, &mut fs, 0x00, tag, &vec![0xEE; n]),
                Sw::WRONG_P1P2
            );
        }
    }

    // What was written lands in the right slice of each aggregate.
    let (c5, _) = run(&mut app, &mut fs, &[0x00, consts::INS_GET_DATA, 0x00, 0xC5]);
    assert_eq!(c5, vec![0xB0u8; consts::KEY_SLOTS * consts::FP_LEN]);
    let (c6, _) = run(&mut app, &mut fs, &[0x00, consts::INS_GET_DATA, 0x00, 0xC6]);
    assert_eq!(c6, vec![0xB0u8; consts::KEY_SLOTS * consts::FP_LEN]);
    let (cd, _) = run(&mut app, &mut fs, &[0x00, consts::INS_GET_DATA, 0x00, 0xCD]);
    assert_eq!(cd, vec![0xB0u8; consts::KEY_SLOTS * consts::TS_LEN]);
}

// OpenPGP 3.4 §7.2.7 gives GET NEXT DATA exactly one job — walk the three 7F21
// occurrences — and §5 makes that read *Always*. Measured on a YubiKey 5.7.4:
// GET DATA anchors the walk, GET NEXT advances then reads, and the step past the
// last occurrence is 6A80 with the pointer left where it was.
#[test]
fn get_next_data_walks_the_cardholder_cert_occurrences() {
    let rng = RefCell::new(LcgRng(13));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);

    let certs: [&[u8]; 3] = [&[0xA0; 8], &[0xA1; 9], &[0xA2; 10]];
    for (occ, cert) in certs.iter().enumerate() {
        assert_eq!(run(&mut app, &mut fs, &select_cert(occ as u8)).1, Sw::OK);
        let mut p = vec![0x00, consts::INS_PUT_DATA, 0x7F, 0x21, cert.len() as u8];
        p.extend_from_slice(cert);
        assert_eq!(run(&mut app, &mut fs, &p).1, Sw::OK);
    }

    let get = [0x00, consts::INS_GET_DATA, 0x7F, 0x21];
    let next = [0x00, consts::INS_GET_NEXT_DATA, 0x7F, 0x21];

    // No anchor yet: a cold GET NEXT is wrong data, not a walk from occurrence 0.
    app.deselect(&mut fs);
    assert_eq!(run(&mut app, &mut fs, &next).1, Sw::WRONG_DATA);

    // The whole walk with NOTHING verified — 7F21 READ is Always.
    assert_eq!(run(&mut app, &mut fs, &select_cert(0)).1, Sw::OK);
    assert_eq!(run(&mut app, &mut fs, &get), (certs[0].to_vec(), Sw::OK));
    assert_eq!(run(&mut app, &mut fs, &next), (certs[1].to_vec(), Sw::OK));
    assert_eq!(run(&mut app, &mut fs, &next), (certs[2].to_vec(), Sw::OK));
    assert_eq!(run(&mut app, &mut fs, &next).1, Sw::WRONG_DATA);
    assert_eq!(run(&mut app, &mut fs, &next).1, Sw::WRONG_DATA);
    // The exhausted step does not move the pointer on.
    assert_eq!(run(&mut app, &mut fs, &get), (certs[2].to_vec(), Sw::OK));

    // An intervening GET DATA of another DO re-anchors the walk elsewhere.
    assert_eq!(run(&mut app, &mut fs, &select_cert(0)).1, Sw::OK);
    assert_eq!(run(&mut app, &mut fs, &get).1, Sw::OK);
    assert_eq!(
        run(&mut app, &mut fs, &[0x00, consts::INS_GET_DATA, 0x00, 0x5E]).1,
        Sw::OK
    );
    assert_eq!(run(&mut app, &mut fs, &next).1, Sw::WRONG_DATA);

    // A GET NEXT of some other tag is refused and leaves the anchor alone.
    assert_eq!(run(&mut app, &mut fs, &get).1, Sw::OK);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &[0x00, consts::INS_GET_NEXT_DATA, 0x01, 0x01]
        )
        .1,
        Sw::WRONG_DATA
    );
    assert_eq!(run(&mut app, &mut fs, &next), (certs[1].to_vec(), Sw::OK));

    // GET NEXT after a GET DATA of a DO that has no occurrences: still 6A80.
    for tag in [[0x01u8, 0x01], [0x00, 0x5E], [0x00, 0x6E]] {
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                &[0x00, consts::INS_GET_DATA, tag[0], tag[1]]
            )
            .1,
            Sw::OK
        );
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                &[0x00, consts::INS_GET_NEXT_DATA, tag[0], tag[1]]
            )
            .1,
            Sw::WRONG_DATA
        );
    }
}

#[test]
fn generate_ed25519_aut_internal_authenticate_verifies() {
    use ed25519_dalek::Verifier;
    let rng = RefCell::new(LcgRng(3));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xC3, ATTR_ED25519), Sw::OK);

    let (do_, sw) = keygen(&mut app, &mut fs, 0x80, 0xA4);
    assert_eq!(sw, Sw::OK);
    let point = ec_point(&do_).to_vec();
    assert_eq!(point.len(), 32);

    verify_pin(&mut app, &mut fs, consts::PW1_MODE82, consts::PW1_DEFAULT);

    let msg = b"challenge-to-sign-with-the-auth-key";
    let mut a = vec![0x00, consts::INS_INTERNAL_AUT, 0x00, 0x00, msg.len() as u8];
    a.extend_from_slice(msg);
    let (sig, sw) = run(&mut app, &mut fs, &a);
    assert_eq!(sw, Sw::OK);
    let mut pb = [0u8; 32];
    pb.copy_from_slice(&point);
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pb).unwrap();
    vk.verify(msg, &ed25519_dalek::Signature::from_slice(&sig).unwrap())
        .unwrap();
}

#[test]
fn generate_rsa_sig_sign_verifies() {
    let rng = RefCell::new(LcgRng(0xDEAD_BEEF));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    // RSA-1024, the smallest size the card advertises in DO 0xFA. (Audit run-33:
    // C1/C2/C3 now only accept an advertised attribute, so the old RSA-512 this
    // used for speed is refused — which is the point of that gate.)
    let attr = [0x01u8, 0x04, 0x00, 0x00, 0x20, 0x00];
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xC1, &attr), Sw::OK);

    let (do_, sw) = keygen(&mut app, &mut fs, 0x80, 0xB6);
    assert_eq!(sw, Sw::OK);
    let (n, e) = rsa_n_e(&do_);
    assert_eq!(n.len(), 128); // RSA-1024 modulus
    let pk = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&n),
        rsa::BigUint::from_bytes_be(&e),
    )
    .unwrap();

    verify_pin(&mut app, &mut fs, consts::PW1_MODE81, consts::PW1_DEFAULT);
    let mut di = DI_SHA256.to_vec();
    di.extend_from_slice(&[0x42u8; 32]);
    let mut a = vec![0x00, consts::INS_PSO, 0x9E, 0x9A, di.len() as u8];
    a.extend_from_slice(&di);
    let (sig, sw) = run(&mut app, &mut fs, &a);
    assert_eq!(sw, Sw::OK);
    assert_eq!(sig.len(), 128);
    pk.verify(rsa::Pkcs1v15Sign::new_unprefixed(), &di, &sig)
        .unwrap();
}

#[test]
fn rsa_keepalive_generate_path_produces_signable_key() {
    // Drive the CCID keepalive path exactly as the firmware's `poll_long`:
    // rsa_generate_params -> RsaKeygen::step* -> rsa_generate_finish, then check
    // the stored key signs through the normal dispatch.
    let rng = RefCell::new(LcgRng(0xCAFE_F00D));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    let attr = [0x01u8, 0x04, 0x00, 0x00, 0x20, 0x00]; // RSA-1024 (smallest advertised)
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xC1, &attr), Sw::OK);

    let gen_apdu = [0x00, consts::INS_KEYPAIR_GEN, 0x80, 0x00, 0x02, 0xB6, 0x00];
    let p = Apdu::parse(&gen_apdu).unwrap();
    let (fid, nbits) = app
        .rsa_generate_params(&mut fs, p.p1, p.p2, p.data)
        .unwrap()
        .expect("RSA generate params");
    assert_eq!(fid, consts::EF_PK_SIG);

    let mut kg = keys::RsaKeygen::new(nbits);
    let mut sieve = rsk_rsa::IncrementalSieve::new();
    let key = loop {
        match kg.step(&mut sieve, &mut *rng.borrow_mut()) {
            keys::RsaStep::Done(k) => break k,
            keys::RsaStep::Failed => panic!("keygen failed"),
            keys::RsaStep::More => {}
        }
    };
    let mut out = [0u8; 600];
    let (n, sw) = app.rsa_generate_finish(&mut fs, &mut *rng.borrow_mut(), fid, &key, &mut out);
    assert_eq!(sw, Sw::OK);
    let (modn, e) = rsa_n_e(&out[..n]);
    assert_eq!(modn.len(), 128); // RSA-1024 modulus
    let pk = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&modn),
        rsa::BigUint::from_bytes_be(&e),
    )
    .unwrap();

    verify_pin(&mut app, &mut fs, consts::PW1_MODE81, consts::PW1_DEFAULT);
    let mut di = DI_SHA256.to_vec();
    di.extend_from_slice(&[0x42u8; 32]);
    let mut a = vec![0x00, consts::INS_PSO, 0x9E, 0x9A, di.len() as u8];
    a.extend_from_slice(&di);
    let (sig, sw) = run(&mut app, &mut fs, &a);
    assert_eq!(sw, Sw::OK);
    pk.verify(rsa::Pkcs1v15Sign::new_unprefixed(), &di, &sig)
        .unwrap();
}

#[test]
fn rsa_generate_params_accepts_rsa4096() {
    // There is no 2048-only gate: a 4096-bit algorithm attribute flows straight
    // through `rsa_generate_params` to `RsaKeygen::new(4096)` (which is
    // size-generic, asm modexp MAX_MOD = 256 B = an RSA-4096 prime). The full
    // keygen+sign is the `#[ignore]`d test below (on-device keygen runs for
    // minutes, so it is not a default test).
    let rng = RefCell::new(LcgRng(0xCAFE_F00D));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    // RSA-4096 algo attribute: 0x1000 = 4096 modulus bits.
    let attr = [0x01u8, 0x10, 0x00, 0x00, 0x20, 0x00];
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xC1, &attr), Sw::OK);

    let gen_apdu = [0x00, consts::INS_KEYPAIR_GEN, 0x80, 0x00, 0x02, 0xB6, 0x00];
    let p = Apdu::parse(&gen_apdu).unwrap();
    let (fid, nbits) = app
        .rsa_generate_params(&mut fs, p.p1, p.p2, p.data)
        .unwrap()
        .expect("RSA generate params");
    assert_eq!(fid, consts::EF_PK_SIG);
    assert_eq!(nbits, 4096);
}

#[test]
fn rsa_generate_params_accepts_rsa3072() {
    // RSA-3072 (0x0C00) flows through the same size-generic path as 2048/4096:
    // a 1536-bit prime is 192 B (multiple of 32, <= asm MAX_MOD 256).
    let rng = RefCell::new(LcgRng(0xCAFE_F00D));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    let attr = [0x01u8, 0x0C, 0x00, 0x00, 0x20, 0x00]; // RSA-3072
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xC1, &attr), Sw::OK);
    let gen_apdu = [0x00, consts::INS_KEYPAIR_GEN, 0x80, 0x00, 0x02, 0xB6, 0x00];
    let p = Apdu::parse(&gen_apdu).unwrap();
    let (fid, nbits) = app
        .rsa_generate_params(&mut fs, p.p1, p.p2, p.data)
        .unwrap()
        .expect("RSA generate params");
    assert_eq!(fid, consts::EF_PK_SIG);
    assert_eq!(nbits, 3072);
}

#[test]
#[ignore = "full on-host RSA-4096 keygen — slow (num-bigint, no asm); run with --ignored"]
fn rsa4096_generate_path_produces_signable_key() {
    // End-to-end proof the 4096 path is correct: generate a real RSA-4096 key
    // through the keepalive path, then sign + verify with the rsa crate.
    let rng = RefCell::new(LcgRng(0xCAFE_F00D));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    let attr = [0x01u8, 0x10, 0x00, 0x00, 0x20, 0x00]; // RSA-4096
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xC1, &attr), Sw::OK);

    let gen_apdu = [0x00, consts::INS_KEYPAIR_GEN, 0x80, 0x00, 0x02, 0xB6, 0x00];
    let p = Apdu::parse(&gen_apdu).unwrap();
    let (fid, nbits) = app
        .rsa_generate_params(&mut fs, p.p1, p.p2, p.data)
        .unwrap()
        .expect("RSA generate params");
    assert_eq!(nbits, 4096);

    let mut kg = keys::RsaKeygen::new(nbits);
    let mut sieve = rsk_rsa::IncrementalSieve::new();
    let key = loop {
        match kg.step(&mut sieve, &mut *rng.borrow_mut()) {
            keys::RsaStep::Done(k) => break k,
            keys::RsaStep::Failed => panic!("keygen failed"),
            keys::RsaStep::More => {}
        }
    };
    let mut out = [0u8; 600]; // >= MAX_RSA_PUBDO (531 for RSA-4096)
    let (n, sw) = app.rsa_generate_finish(&mut fs, &mut *rng.borrow_mut(), fid, &key, &mut out);
    assert_eq!(sw, Sw::OK);
    let (modn, e) = rsa_n_e(&out[..n]);
    assert_eq!(modn.len(), 512); // RSA-4096 modulus
    let pk = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&modn),
        rsa::BigUint::from_bytes_be(&e),
    )
    .unwrap();

    verify_pin(&mut app, &mut fs, consts::PW1_MODE81, consts::PW1_DEFAULT);
    let mut di = DI_SHA256.to_vec();
    di.extend_from_slice(&[0x42u8; 32]);
    let mut a = std::vec![0x00, consts::INS_PSO, 0x9E, 0x9A, di.len() as u8];
    a.extend_from_slice(&di);
    let (sig, sw) = run(&mut app, &mut fs, &a);
    assert_eq!(sw, Sw::OK);
    pk.verify(rsa::Pkcs1v15Sign::new_unprefixed(), &di, &sig)
        .unwrap();
}

// E40. §7.2.10/§7.2.11/§7.2.13 give PSO:CDS the access condition PW1 no. 81 and
// PSO:DECIPHER / INTERNAL AUTHENTICATE PW1 no. 82, and name no other reference.
// The applet let PW3 stand in for all three; a YubiKey 5.7.4 answers 6982 to PW3
// alone, three runs of this whole matrix, cell for cell. This is a NARROWING —
// unlocking signing with the admin PIN used to work and now does not.
#[test]
fn pw3_alone_opens_no_key_operation() {
    let rng = RefCell::new(LcgRng(23));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    put(&mut app, &mut fs, 0x00, 0xC1, ATTR_P256);
    put(&mut app, &mut fs, 0x00, 0xC2, ATTR_P256_ECDH);
    put(&mut app, &mut fs, 0x00, 0xC3, ATTR_P256);
    for crt in [consts::CRT_SIG, consts::CRT_DEC, consts::CRT_AUT] {
        assert_eq!(keygen(&mut app, &mut fs, 0x80, crt).1, Sw::OK);
    }

    let eph_pub = p256_vk(&[0x33u8; 32]).to_sec1_point(false);
    let f86 = [&[0x86, eph_pub.as_bytes().len() as u8], eph_pub.as_bytes()].concat();
    let f7f49 = [&[0x7F, 0x49, f86.len() as u8], f86.as_slice()].concat();
    let a6 = [&[0xA6, f7f49.len() as u8], f7f49.as_slice()].concat();
    let mut dec = vec![0x00, consts::INS_PSO, 0x80, 0x86, a6.len() as u8];
    dec.extend_from_slice(&a6);
    let mut cds = vec![0x00, consts::INS_PSO, 0x9E, 0x9A, 32];
    cds.extend_from_slice(&[0x42u8; 32]);
    let mut aut = vec![0x00, consts::INS_INTERNAL_AUT, 0x00, 0x00, 32];
    aut.extend_from_slice(&[0x42u8; 32]);
    // AES ENCIPHER over the card key the DEC keygen seeded.
    let mut aes = vec![0x00, consts::INS_PSO, 0x86, 0x80, 16];
    aes.extend_from_slice(&[0x11u8; 16]);

    // Every combination of the three latches; the columns are CDS, DEC, AUT, AES.
    let denied = Sw::SECURITY_STATUS_NOT_SATISFIED;
    for (latches, want) in [
        (&[][..], [denied; 4]),
        (&[consts::PW1_MODE81], [Sw::OK, denied, denied, denied]),
        (&[consts::PW1_MODE82], [denied, Sw::OK, Sw::OK, Sw::OK]),
        (&[consts::PW3_MODE83], [denied; 4]),
        (
            &[consts::PW1_MODE81, consts::PW3_MODE83],
            [Sw::OK, denied, denied, denied],
        ),
        (
            &[consts::PW1_MODE82, consts::PW3_MODE83],
            [denied, Sw::OK, Sw::OK, Sw::OK],
        ),
        (
            &[consts::PW1_MODE81, consts::PW1_MODE82],
            [Sw::OK, Sw::OK, Sw::OK, Sw::OK],
        ),
    ] {
        app.deselect(&mut fs);
        for &mode in latches {
            let pw = if mode == consts::PW3_MODE83 {
                consts::PW3_DEFAULT
            } else {
                consts::PW1_DEFAULT
            };
            verify_pin(&mut app, &mut fs, mode, pw);
        }
        for (cmd, expect, name) in [
            (&cds, want[0], "PSO:CDS"),
            (&dec, want[1], "PSO:DECIPHER"),
            (&aut, want[2], "INTERNAL AUTHENTICATE"),
            (&aes, want[3], "PSO:ENCIPHER (AES)"),
        ] {
            assert_eq!(
                run(&mut app, &mut fs, cmd).1,
                expect,
                "{name} with latches {latches:02X?}"
            );
        }
    }
}

/// OpenPGP 3.4.1 §5 splits the private-use DOs between two owners: `0101`
/// and `0103` are the cardholder's (PW1 no. 82), `0102` and `0104` the admin's
/// (PW3), and there is no admin override on the cardholder's pair. Measured on a
/// YubiKey 5.7.4, 3/3, in all four auth states: with only PW3 verified both
/// `00CA010300` and `00DA0103…` answer `6982`, and so does `00DA0101…`.
#[test]
fn the_private_use_dos_answer_to_the_password_that_owns_them() {
    let rng = RefCell::new(LcgRng(23));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);

    let denied = Sw::SECURITY_STATUS_NOT_SATISFIED;
    // (mode latched, [0101, 0102, 0103, 0104]) for GET, then for PUT.
    let none: &[u8] = &[];
    let pw1: &[u8] = &[consts::PW1_MODE81];
    let pw2: &[u8] = &[consts::PW1_MODE82];
    let pw3: &[u8] = &[consts::PW3_MODE83];
    let reads = [
        (none, [Sw::OK, Sw::OK, denied, denied]),
        (pw1, [Sw::OK, Sw::OK, denied, denied]),
        (pw2, [Sw::OK, Sw::OK, Sw::OK, denied]),
        (pw3, [Sw::OK, Sw::OK, denied, Sw::OK]),
    ];
    let writes = [
        (none, [denied; 4]),
        (pw1, [denied; 4]),
        (pw2, [Sw::OK, denied, Sw::OK, denied]),
        (pw3, [denied, Sw::OK, denied, Sw::OK]),
    ];

    let latch = |app: &mut OpenpgpApplet, fs: &mut Fs<RamStorage>, modes: &[u8]| {
        app.deselect(fs);
        for &mode in modes {
            let pw = if mode == consts::PW3_MODE83 {
                consts::PW3_DEFAULT
            } else {
                consts::PW1_DEFAULT
            };
            verify_pin(app, fs, mode, pw);
        }
    };
    // Every DO carries a baseline written from a fully-authenticated session, so
    // a later refusal means "this state may not" and not "this DO is unwritable".
    latch(&mut app, &mut fs, &[consts::PW1_MODE82, consts::PW3_MODE83]);
    for lo in 1..=4u8 {
        assert_eq!(put(&mut app, &mut fs, 0x01, lo, b"BASE"), Sw::OK);
    }

    for (modes, want) in reads {
        latch(&mut app, &mut fs, modes);
        for (i, expect) in want.iter().enumerate() {
            let lo = i as u8 + 1;
            let sw = run(
                &mut app,
                &mut fs,
                &[0x00, consts::INS_GET_DATA, 0x01, lo, 0x00],
            )
            .1;
            assert_eq!(sw, *expect, "GET DATA 01{lo:02X} with {modes:02X?}");
        }
    }

    for (modes, want) in writes {
        latch(&mut app, &mut fs, modes);
        for (i, expect) in want.iter().enumerate() {
            let lo = i as u8 + 1;
            let marker = [0x57, modes.first().copied().unwrap_or(0), lo];
            assert_eq!(
                put(&mut app, &mut fs, 0x01, lo, &marker),
                *expect,
                "PUT DATA 01{lo:02X} with {modes:02X?}"
            );
            // The SW is not the evidence — what is in the DO is. Read it back
            // from a session that may read every one of the four.
            latch(&mut app, &mut fs, &[consts::PW1_MODE82, consts::PW3_MODE83]);
            let (body, sw) = run(
                &mut app,
                &mut fs,
                &[0x00, consts::INS_GET_DATA, 0x01, lo, 0x00],
            );
            assert_eq!(sw, Sw::OK);
            if expect.is_ok() {
                assert_eq!(body, marker, "PUT DATA 01{lo:02X} with {modes:02X?}");
                assert_eq!(put(&mut app, &mut fs, 0x01, lo, b"BASE"), Sw::OK);
            } else {
                // A refusal that *deletes* the DO would pass a "the marker is not
                // there" assertion, and losing the value is the worse half.
                assert_eq!(
                    body, b"BASE",
                    "a refused PUT DATA 01{lo:02X} with {modes:02X?} changed the DO"
                );
            }
            latch(&mut app, &mut fs, modes);
        }
    }
}

/// E81: PUT DATA carries its target in P1P2, and the card judges the PASSWORD
/// before it says anything about the tag. Measured on a YubiKey 5.7.4 over
/// **7 tags × 3 auth states** (unverified, PW2, PW3) × 3 runs: every tag is a flat
/// `6982` until PW3, and only then does it tell `6B00` (not a writable target)
/// from `9000`. Ours resolved the tag first, so an unauthenticated caller could
/// enumerate the writable set by the `6B00`-vs-`6982` split.
///
/// Two things below are ours, not the card's, and are marked as such: the PW1
/// (P2 `81`) column, which the measurement did not visit, and the `93` row, which
/// it did not include — its `6985` under PW3 is this applet's own answer, reasoned
/// at `putdata::put_data`, and only its pre-PW3 cells are parity.
#[test]
fn put_data_judges_the_password_before_the_tag() {
    let rng = RefCell::new(LcgRng(29));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);

    let denied = Sw::SECURITY_STATUS_NOT_SATISFIED;
    // (tag, what PW3 gets). Everything before PW3 is `denied`, on every row.
    // Rows 1-6 and 8 are the card's; row 7 (`93`) is ours — see the note above.
    let tags: [(u8, Sw); 8] = [
        // `D5` is a DELIBERATE divergence in the PW3 column: a YubiKey answers
        // `6B00` there because it has no AES DO at all, and we implement §7.2.11's
        // — so a one-byte body is a wrong length. Only the pre-PW3 cells are parity
        // (`put_data_d5_installs_the_key_the_aes_pso_uses` owns the rest).
        (0xD5, Sw::WRONG_DATA),               // AES key
        (0xC5, Sw::WRONG_P1P2),               // fingerprints, read-only
        (0xCD, Sw::WRONG_P1P2),               // timestamps, read-only
        (0x7A, Sw::WRONG_P1P2),               // security support, read-only
        (0x42, Sw::WRONG_P1P2),               // wholly unknown
        (0xFF, Sw::WRONG_P1P2),               // wholly unknown
        (0x93, Sw::CONDITIONS_NOT_SATISFIED), // DS counter: write = never
        (0x5E, Sw::OK),                       // login data, PW3-writable
    ];
    let none: &[u8] = &[];
    for modes in [none, &[consts::PW1_MODE81], &[consts::PW1_MODE82]] {
        app.deselect(&mut fs);
        for &mode in modes {
            verify_pin(&mut app, &mut fs, mode, consts::PW1_DEFAULT);
        }
        for (tag, _) in tags {
            assert_eq!(
                put(&mut app, &mut fs, 0x00, tag, &[0xAA]),
                denied,
                "PUT DATA {tag:02X} with {modes:02X?}"
            );
        }
    }
    // Only with PW3 does the card start distinguishing the tags at all.
    app.deselect(&mut fs);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    for (tag, want) in tags {
        assert_eq!(
            put(&mut app, &mut fs, 0x00, tag, &[0xAA]),
            want,
            "PUT DATA {tag:02X} with PW3"
        );
    }
}

/// E96: the password outranks the body's LENGTH too. `MAX_DO_BYTES` — the cap
/// `C0` announces — was checked above every ACL, so a body one byte past it came
/// back `6A80` where every other unauthenticated PUT DATA answers `6982`. A
/// YubiKey 5.7.4 answers `6982` at 10, 2036, 2037 and 3000 bytes, on `5E`, `7A`,
/// `D5`, `D3`, `C4`, `7F21`, `C1`, `0101`, `0103` and an unknown tag alike —
/// 3 runs, byte-identical.
///
/// The PW3 column is a **deliberate divergence and is not parity**: measured, the
/// card answers `9000` to an over-long chained write and silently keeps only
/// `n mod 256` bytes (`n = 256` stores nothing at all; 300 → 44; 2036 → 244;
/// 3000 → 184; identical at two chunk sizes). Adopting that would lose user data,
/// which is the one carve-out — so an over-long authorised write stays `6A80`
/// with the DO untouched.
#[test]
fn put_data_judges_the_password_before_the_body_length() {
    let rng = RefCell::new(LcgRng(29));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);

    let over = vec![0x41u8; crate::files::MAX_DO_BYTES + 1];
    let at_cap = vec![0x41u8; crate::files::MAX_DO_BYTES];
    // Every routed tag plus the generic and the two PW2 DOs — the length gate sat
    // above all of them, so the flatness has to be shown across the whole split.
    let tags: [(u8, u8); 10] = [
        (0x00, 0x5E),
        (0x00, 0x7A),
        (0x00, 0xD5),
        (0x00, 0xD3),
        (0x00, 0xC4),
        (0x7F, 0x21),
        (0x00, 0xC1),
        (0x01, 0x01),
        (0x01, 0x03),
        (0xFF, 0xFF),
    ];
    let none: &[u8] = &[];
    for modes in [none, &[consts::PW1_MODE81], &[consts::PW1_MODE82]] {
        app.deselect(&mut fs);
        for &mode in modes {
            verify_pin(&mut app, &mut fs, mode, consts::PW1_DEFAULT);
        }
        for (p1, p2) in tags {
            // PW1 no. 82 is the cardholder's, so it authorises `0101`/`0103` and
            // only those: they are past the ACL and meet the length gate instead.
            let want = if modes == [consts::PW1_MODE82] && p1 == 0x01 && (p2 == 0x01 || p2 == 0x03)
            {
                Sw::WRONG_DATA
            } else {
                Sw::SECURITY_STATUS_NOT_SATISFIED
            };
            assert_eq!(
                put_long(&mut app, &mut fs, p1, p2, &over),
                want,
                "over-long PUT DATA {p1:02X}{p2:02X} with {modes:02X?}"
            );
            // The same tags at the cap: `6982` before this fix and after it, so a
            // reader can see the ACL answer is what moved and not the boundary.
            // (The assertion that a moved boundary fails is the `at_cap` write
            // under PW3 at the end — this pair is the flatness, not the edge.)
            if want == Sw::SECURITY_STATUS_NOT_SATISFIED {
                assert_eq!(
                    put_long(&mut app, &mut fs, p1, p2, &at_cap),
                    Sw::SECURITY_STATUS_NOT_SATISFIED,
                    "at-cap PUT DATA {p1:02X}{p2:02X} with {modes:02X?}"
                );
            }
        }
    }
    // With PW3 the refusal is ours and not the card's — see the note above. The
    // two cardholder DOs stay `6982` even here, because PW3 is not their password:
    // which password a caller holds, not which one is "higher", is what decides
    // whether the length gate is reached at all. And a tag no arm can write never
    // reaches it either (E188) — that half IS parity, and it has its own test.
    app.deselect(&mut fs);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    for (p1, p2) in tags {
        let want = if p1 == 0x01 {
            Sw::SECURITY_STATUS_NOT_SATISFIED
        } else if !crate::putdata::writable(((p1 as u16) << 8) | p2 as u16) {
            Sw::WRONG_P1P2
        } else {
            Sw::WRONG_DATA
        };
        assert_eq!(
            put_long(&mut app, &mut fs, p1, p2, &over),
            want,
            "over-long PUT DATA {p1:02X}{p2:02X} with PW3"
        );
    }
    // …and the cap itself is still writable, so the refusal is protecting the
    // buffer rather than moving the boundary in by one.
    assert_eq!(put_long(&mut app, &mut fs, 0x00, 0x5E, &at_cap), Sw::OK);

    // The status word is not the evidence — what is in the DO is. Adopting the
    // card's own answer here means answering and keeping `n mod 256` bytes, so a
    // refusal that stores a truncation would satisfy every assertion above. It
    // does not satisfy this one: the cap-length value written a moment ago is
    // still there, whole, after the refusal.
    assert_eq!(
        put_long(&mut app, &mut fs, 0x00, 0x5E, &over),
        Sw::WRONG_DATA
    );
    let (back, sw) = run_big(
        &mut app,
        &mut fs,
        &[0x00, consts::INS_GET_DATA, 0x00, 0x5E, 0x00, 0x08, 0x00],
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(back, at_cap, "the refused write left the DO whole");
}

/// E23(c): DO `D5` is the spec's way for a host to supply the AES key PSO:ENC and
/// PSO:DECIPHER use, and Extended Capabilities b2 announces we have them. We
/// announced the capability with no writer, so the only key those operations could
/// ever use was the one GENERATE mints internally — a capability no conforming
/// host could complete. A YubiKey has nothing to copy here: it answers `6B00` to
/// `PUT DATA D5` in every state and leaves b2 clear, so §4.4.3.7 and §7.2.11 are
/// the reference and the widths are theirs — 16 or 32 bytes, nothing else.
#[test]
fn put_data_d5_installs_the_key_the_aes_pso_uses() {
    let rng = RefCell::new(LcgRng(31));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);

    let d5 = |app: &mut OpenpgpApplet, fs: &mut Fs<RamStorage>, key: &[u8]| {
        put(app, fs, 0x00, 0xD5, key)
    };
    let encipher = |app: &mut OpenpgpApplet, fs: &mut Fs<RamStorage>, pt: &[u8]| {
        let mut a = vec![0x00, consts::INS_PSO, 0x86, 0x80, pt.len() as u8];
        a.extend_from_slice(pt);
        run(app, fs, &a)
    };

    // §5 gives `D5` WRITE to PW3, and the judgement comes before the length.
    assert_eq!(
        d5(&mut app, &mut fs, &[0x11; 32]),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    verify_pin(&mut app, &mut fs, consts::PW1_MODE82, consts::PW1_DEFAULT);
    assert_eq!(
        d5(&mut app, &mut fs, &[0x11; 32]),
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "the DEC password is not the admin one"
    );
    assert!(!fs.has_data(consts::EF_AES_KEY.get()));

    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    // AES-128 and AES-256, and nothing between or outside.
    for len in [16usize, 32] {
        assert_eq!(d5(&mut app, &mut fs, &vec![0x11; len]), Sw::OK, "len {len}");
    }
    let pt = [0xABu8; 16];
    let standing = encipher(&mut app, &mut fs, &pt);
    assert_eq!(standing.1, Sw::OK);
    for len in [0usize, 1, 15, 17, 24, 31, 33, 64] {
        assert_eq!(
            d5(&mut app, &mut fs, &vec![0x22; len]),
            Sw::WRONG_DATA,
            "len {len}"
        );
        // A refused write must leave the standing key doing the work.
        assert_eq!(encipher(&mut app, &mut fs, &pt), standing, "len {len}");
    }

    // The key the host writes is the key the operation uses: two different keys
    // must give two different cryptograms, and re-installing the first must bring
    // its cryptogram back. The key is DEK-sealed, so this is how it is shown.
    assert_eq!(d5(&mut app, &mut fs, &[0x33; 32]), Sw::OK);
    let other = encipher(&mut app, &mut fs, &pt);
    assert_eq!(other.1, Sw::OK);
    assert_ne!(other.0, standing.0, "a new D5 key did not reach the PSO");
    assert_eq!(d5(&mut app, &mut fs, &[0x11; 32]), Sw::OK);
    assert_eq!(encipher(&mut app, &mut fs, &pt), standing);

    // …and the WHOLE key is the key, not a prefix of it. Two keys differing only
    // past byte 16 would still give two cryptograms, so the argument above cannot
    // see an AES-256 → AES-128 truncation. FIPS-197 §C.1/C.3 can: a zero-IV CBC of
    // one block is that block under ECB, so these are the published vectors.
    let fips = [
        (
            &[
                0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                0x0D, 0x0E, 0x0F,
            ][..],
            [
                0x69u8, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30, 0xD8, 0xCD, 0xB7, 0x80, 0x70,
                0xB4, 0xC5, 0x5A,
            ],
        ),
        (
            &[
                0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
                0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
            ][..],
            [
                0x8Eu8, 0xA2, 0xB7, 0xCA, 0x51, 0x67, 0x45, 0xBF, 0xEA, 0xFC, 0x49, 0x90, 0x4B,
                0x49, 0x60, 0x89,
            ],
        ),
    ];
    let block = [
        0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    for (key, want) in fips {
        assert_eq!(d5(&mut app, &mut fs, key), Sw::OK);
        // The write is the admin's and the use is the cardholder's, so prove the
        // two are separate sessions: drop everything and come back with PW2 only.
        app.deselect(&mut fs);
        verify_pin(&mut app, &mut fs, consts::PW1_MODE82, consts::PW1_DEFAULT);
        let (cg, sw) = encipher(&mut app, &mut fs, &block);
        assert_eq!(sw, Sw::OK);
        assert_eq!(cg[0], 0x02);
        assert_eq!(&cg[1..], &want, "FIPS-197 vector, {}-byte key", key.len());
        // …and it round-trips back through DECIPHER.
        let mut a = vec![0x00, consts::INS_PSO, 0x80, 0x86, cg.len() as u8];
        a.extend_from_slice(&cg);
        let (back, sw) = run(&mut app, &mut fs, &a);
        assert_eq!(sw, Sw::OK);
        assert_eq!(&back, &block[..], "round-trip, {}-byte key", key.len());
        verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    }

    // READ = *Never* (§5), and there is no cell to copy: a YubiKey 5.7.4 does
    // not implement `D5` at all — `PUT DATA D5` is `6B00` under PW3 there and so
    // is PSO:ENCIPHER — so this DO is ours and the spec decides. `6B00` is what
    // that card answers for every DO it does not serve, which is what a DO that
    // can never be read looks like on the wire.
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &[0x00, consts::INS_GET_DATA, 0x00, 0xD5, 0x00]
        )
        .1,
        Sw::WRONG_P1P2
    );
}

/// E98: `D5` is card-level, so no keygen may destroy it. §7.2.12 gives PSO:ENCIPHER
/// no key reference at all — `D5` is its whole key material, on a command that never
/// touches the DEC slot — and §7.2.14 lets GENERATE reset the DS counter and "other
/// related DO (e. g. certificates)"; the card's one `D5` is related to none of its
/// three key pairs. GENERATE still mints into an EMPTY `D5`, because Extended
/// Capabilities b2 promises AES and a fresh card has no other way to get a key there.
#[test]
fn a_keygen_mints_the_aes_key_only_when_d5_is_empty() {
    let rng = RefCell::new(LcgRng(41));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    verify_pin(&mut app, &mut fs, consts::PW1_MODE82, consts::PW1_DEFAULT);
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xC1, ATTR_P256), Sw::OK);
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xC2, ATTR_P256_ECDH), Sw::OK);
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xC3, ATTR_P256), Sw::OK);

    let encipher = |app: &mut OpenpgpApplet, fs: &mut Fs<RamStorage>| {
        let mut a = vec![0x00, consts::INS_PSO, 0x86, 0x80, 16];
        a.extend_from_slice(&[0xABu8; 16]);
        run(app, fs, &a)
    };
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xD5, &[0x11u8; 32]), Sw::OK);
    let installed = encipher(&mut app, &mut fs);
    assert_eq!(installed.1, Sw::OK);

    // IMPORT into the DEC slot leaves it alone…
    let scalar = [0x22u8; 32];
    assert_eq!(run(&mut app, &mut fs, &ec_import(0xB8, &scalar)).1, Sw::OK);
    assert_eq!(
        encipher(&mut app, &mut fs),
        installed,
        "IMPORT must not touch the AES key"
    );

    // …and so does GENERATE, on every slot — the DEC one twice, because a second
    // regeneration is the rotation the old precedence was defended as.
    for crt in [0xB6u8, 0xB8, 0xA4, 0xB8] {
        assert_eq!(
            keygen(&mut app, &mut fs, 0x80, crt).1,
            Sw::OK,
            "crt {crt:#04X}"
        );
        assert_eq!(
            encipher(&mut app, &mut fs),
            installed,
            "GENERATE {crt:#04X} destroyed the host's D5 key"
        );
    }

    // On a card whose `D5` is empty, the DEC keygen still mints one: the capability
    // b2 announces has to work before any host has written the DO.
    let mut fresh = make_fs();
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(
        &mut app,
        &mut fresh,
        consts::PW3_MODE83,
        consts::PW3_DEFAULT,
    );
    assert_eq!(
        put(&mut app, &mut fresh, 0x00, 0xC2, ATTR_P256_ECDH),
        Sw::OK
    );
    assert!(!fresh.has_key(consts::EF_AES_KEY));
    assert_eq!(keygen(&mut app, &mut fresh, 0x80, 0xB8).1, Sw::OK);
    assert!(fresh.has_key(consts::EF_AES_KEY));
}

/// The E81 rule at the other door. IMPORT (`0xDB`) carries its target — the
/// control-reference template naming the key slot — inside the body, and
/// `parse_ehl_head` resolved it before the PW3 check: an unauthenticated caller
/// got `6A80` for a CRT the card does not know and `6982` for one it does, which
/// enumerates the accepted slot set exactly as the `6B00`/`6982` split enumerated
/// the writable DOs. Unmeasured on a YubiKey — the reference was measured on
/// `0xDA` — so this cell follows by class, not by measurement.
#[test]
fn import_judges_the_password_before_the_key_slot() {
    let rng = RefCell::new(LcgRng(37));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);

    // `B6`/`B8`/`A4` are the slots the card knows; `99` is not one.
    let ehl = |crt: u8| {
        let body = [crt, 0x00, 0x7F, 0x48, 0x00, 0x5F, 0x48, 0x00];
        let header = [&[0x4D, body.len() as u8], body.as_slice()].concat();
        let mut a = vec![
            0x00,
            consts::INS_PUT_DATA_ODD,
            0x3F,
            0xFF,
            header.len() as u8,
        ];
        a.extend_from_slice(&header);
        a
    };
    for crt in [0xB6u8, 0xB8, 0xA4, 0x99, 0x00, 0xFF] {
        assert_eq!(
            run(&mut app, &mut fs, &ehl(crt)).1,
            Sw::SECURITY_STATUS_NOT_SATISFIED,
            "IMPORT CRT {crt:02X} unauthenticated"
        );
    }
    // …and a well-formed import is refused the same way, so the flatness is the
    // ACL and not the body being unparseable.
    let scalar = [0x11u8; 32];
    assert_eq!(
        run(&mut app, &mut fs, &ec_import(0xB6, &scalar)).1,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );

    // The controls: with PW3 the card tells the slots apart again, and the same
    // well-formed import lands.
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    assert_eq!(run(&mut app, &mut fs, &ehl(0x99)).1, Sw::WRONG_DATA);
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xC1, ATTR_P256), Sw::OK);
    assert_eq!(run(&mut app, &mut fs, &ec_import(0xB6, &scalar)).1, Sw::OK);
}

/// E188: under PW3, a tag PUT DATA cannot write has no body length to be wrong
/// about. `MAX_DO_BYTES` is deliberately one owner sitting ABOVE the routing
/// split — the cardholder-certificate arm writes flash without passing through
/// `putdata::put_data`, so a check living only there would guard every DO except
/// the one `C0`'s bytes 5-6 are about — but that put it above the tag as well, so
/// an unwritable tag answered `6B00` up to the cap and `6A80` past it. A YubiKey
/// 5.7.4 answers `6B00` at 10, 2036, 2037, 2038 and 3000 bytes on `7A`, `FFFF`
/// and `0042` alike with PW3 verified, 3 runs byte-identical.
///
/// The order is now password → tag → length, and the length gate still sits above
/// the split. Nothing about the unauthorised column moves: it is a flat `6982` at
/// every tag and every length, which is `0x0922`'s property and its own test's.
#[test]
fn put_data_judges_the_tag_before_the_body_length() {
    let rng = RefCell::new(LcgRng(37));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);

    let cap = crate::files::MAX_DO_BYTES;
    // Unwritable and unknown tags: one answer at every length, including past the
    // cap. `7A` is WRITE = *Never* in §5, `C5`/`CD` are computed aggregates read
    // out of `6E`/`73`, and the last two are not DOs at all.
    for (p1, p2) in [
        (0x00u8, 0x7Au8),
        (0x00, 0xC5),
        (0x00, 0xCD),
        (0xFF, 0xFF),
        (0x00, 0x42),
    ] {
        for len in [0usize, 10, cap - 1, cap, cap + 1, cap + 2, cap + 512] {
            assert_eq!(
                put_long(&mut app, &mut fs, p1, p2, &vec![0x41u8; len]),
                Sw::WRONG_P1P2,
                "PUT DATA {p1:02X}{p2:02X} with {len} bytes under PW3"
            );
        }
    }
    // A tag it CAN write still meets the length gate past the cap, and still
    // takes the cap itself — the carve-out `0x0922` recorded, since the reference
    // answers `9000` there and keeps only `n mod 256` bytes.
    assert_eq!(
        put_long(&mut app, &mut fs, 0x00, 0x5E, &vec![0x41u8; cap]),
        Sw::OK
    );
    assert_eq!(
        put_long(&mut app, &mut fs, 0x00, 0x5E, &vec![0x41u8; cap + 1]),
        Sw::WRONG_DATA
    );
    // …and the routed arms, which the length gate exists to cover, answer for
    // their own contents rather than for the tag.
    assert_eq!(
        put_long(&mut app, &mut fs, 0x7F, 0x21, &vec![0x41u8; cap + 1]),
        Sw::WRONG_DATA
    );
    assert_eq!(
        put_long(&mut app, &mut fs, 0x00, 0xD5, &vec![0x41u8; cap + 1]),
        Sw::WRONG_DATA
    );

    // One owner: `writable` must answer for the whole 16-bit space exactly as the
    // command does. Without this the predicate above the length gate and the
    // writer's own `_ => WRONG_P1P2` arm are two tables that can drift.
    //
    // The set, not just the agreement. Wherever `writable` is false the cell
    // reduces to `false == false` and asserts nothing, so the loop alone catches
    // a WIDENED predicate and not a narrowed one — dropping `EF_RESET_CODE`,
    // `EF_PW_STATUS` or `EF_ALGO_SIG` from it passes the loop untouched. Naming
    // the set makes a removed arm change an observable list.
    let mut writable = std::vec::Vec::new();
    for fid in 0..=0xFFFFu16 {
        let sw = put(&mut app, &mut fs, (fid >> 8) as u8, fid as u8, &[]);
        assert_eq!(
            crate::putdata::writable(fid),
            sw != Sw::WRONG_P1P2,
            "PUT DATA {fid:04X} answered {:04X}",
            sw.0
        );
        if crate::putdata::writable(fid) {
            writable.push(fid);
        }
    }
    assert_eq!(
        writable,
        std::vec![
            0x0101, 0x0102, 0x0103, 0x0104, 0x005B, 0x005E, 0x0093, 0x00C1, 0x00C2, 0x00C3, 0x00C4,
            0x00C7, 0x00C8, 0x00C9, 0x00CA, 0x00CB, 0x00CC, 0x00CE, 0x00CF, 0x00D0, 0x00D3, 0x00D5,
            0x00D6, 0x00D7, 0x00D8, 0x00F9, 0x5F2D, 0x5F35, 0x5F50, 0x7F21,
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<std::vec::Vec<_>>(),
        "the writable set, in full"
    );
}

// Derived by co-refutation (`scripts/comutate.py`): re-injecting the model's
// `BugSigPinNotSpent` left every host test green. The one-shot rule was carried
// by `RSKeyAppletSeams` and by nothing under it.
#[test]
fn the_one_shot_pw_status_spends_pw1_at_the_signature() {
    // OpenPGP 3.4 §7.2.10: with DO C4's first byte at 0x00, "PW1 valid for one
    // PSO:CDS" — the second signature must ask again. `inc_sig_count` is where
    // that is enforced, *after* the signature, and the flag's only writer is a
    // PW3 PUT DATA C4 (which is why the two live or die together).
    let rng = RefCell::new(CountRng(7));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xC1, ATTR_P256), Sw::OK);
    assert_eq!(
        run(&mut app, &mut fs, &ec_import(0xB6, &[0x11u8; 32])).1,
        Sw::OK
    );

    let digest = [0x42u8; 32];
    let mut sign = vec![0x00, consts::INS_PSO, 0x9E, 0x9A, digest.len() as u8];
    sign.extend_from_slice(&digest);

    // Default (0x01) is "valid for several": both signatures pass on one VERIFY.
    verify_pin(&mut app, &mut fs, consts::PW1_MODE81, consts::PW1_DEFAULT);
    assert_eq!(run(&mut app, &mut fs, &sign).1, Sw::OK);
    assert_eq!(
        run(&mut app, &mut fs, &sign).1,
        Sw::OK,
        "0x01 is not one-shot"
    );

    // One-shot (0x00): the first passes, the second is 6982 until PW1 is
    // presented again — and then it is one-shot once more.
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xC4, &[0x00]), Sw::OK);
    verify_pin(&mut app, &mut fs, consts::PW1_MODE81, consts::PW1_DEFAULT);
    assert_eq!(run(&mut app, &mut fs, &sign).1, Sw::OK);
    assert_eq!(
        run(&mut app, &mut fs, &sign).1,
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "the one-shot PW status did not spend PW1",
    );
    verify_pin(&mut app, &mut fs, consts::PW1_MODE81, consts::PW1_DEFAULT);
    assert_eq!(run(&mut app, &mut fs, &sign).1, Sw::OK);
    assert_eq!(
        run(&mut app, &mut fs, &sign).1,
        Sw::SECURITY_STATUS_NOT_SATISFIED,
    );
}

// The wire half of `the_pw_status_byte_refuses_a_user_status`. PUT DATA is gated
// twice — `write_authorized` at the dispatch and `put_pw_status`'s own
// restatement — and co-refutation showed why both need asserting: widening only
// the inner one still answered 6982 at the command, so the kill measured a
// defence in depth rather than the modelled defect.
#[test]
fn put_data_c4_refuses_a_user_status() {
    let rng = RefCell::new(CountRng(7));
    let mut fs = make_fs();
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    verify_pin(&mut app, &mut fs, consts::PW1_MODE81, consts::PW1_DEFAULT);
    verify_pin(&mut app, &mut fs, consts::PW1_MODE82, consts::PW1_DEFAULT);
    assert_eq!(
        put(&mut app, &mut fs, 0x00, 0xC4, &[0x00]),
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "a user status wrote the one-shot flag",
    );
    verify_pin(&mut app, &mut fs, consts::PW3_MODE83, consts::PW3_DEFAULT);
    assert_eq!(put(&mut app, &mut fs, 0x00, 0xC4, &[0x00]), Sw::OK);
}
