// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::ram::RamStorage;

/// PUT's body grammar — a rule per field, a measured card cell per rule. Hung
/// off this module rather than the crate root so it inherits the helpers below.
#[path = "put_tests.rs"]
mod put_tests;

/// The `only increasing` property's high-water mark, on both read paths.
#[path = "increasing_tests.rs"]
mod increasing_tests;

/// The challenge itself: how wide it may be, and that both read paths HMAC all
/// of it.
#[path = "challenge_tests.rs"]
mod challenge_tests;

/// What a failed OTP-PIN attempt does to the standing authentication.
#[path = "otp_pin_tests.rs"]
mod otp_pin_tests;

/// What SET CODE accepts as an access code, and what a refusal leaves behind.
#[path = "set_code_tests.rs"]
mod set_code_tests;

/// The four bytes a truncated CALCULATE / CALCULATE ALL response carries.
#[path = "code_tests.rs"]
mod code_tests;

/// RFC 6238 reference secrets.
const SECRET_SHA1: &[u8] = b"12345678901234567890";
const SECRET_SHA256: &[u8] = b"12345678901234567890123456789012";
const SECRET_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

struct CountRng(u8);
impl Rng for CountRng {
    fn fill(&mut self, b: &mut [u8]) {
        for x in b.iter_mut() {
            *x = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

/// Answers every touch request with a fixed outcome and counts the asks.
struct StubPresence(Presence, u32);
impl UserPresence for StubPresence {
    fn request(&mut self, _confirm: Confirm<'_>) -> Presence {
        self.1 += 1;
        self.0
    }
}

const SERIAL: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0];

/// A provisioned MKEK for the tests. The applet holds a way to READ the fuses, not
/// the key, so a test source has to be a plain `fn` — a closure over a local could
/// not coerce to one.
const TEST_MKEK: [u8; 32] = [0x55; 32];
fn test_mkek() -> Option<[u8; 32]> {
    Some(TEST_MKEK)
}

fn new_fs() -> Fs<RamStorage> {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    fs
}

fn select(app: &mut OathApplet, fs: &mut Fs<RamStorage>) -> (Sw, Vec<u8>) {
    let mut out = [0u8; 256];
    let mut res = ResBuf::new(&mut out);
    let sw = Applet::select(app, false, fs, &mut res);
    (sw, res.as_slice().to_vec())
}

fn run(app: &mut OathApplet, fs: &mut Fs<RamStorage>, raw: &[u8]) -> (Sw, Vec<u8>) {
    let mut out = [0u8; 2048];
    let mut res = ResBuf::new(&mut out);
    let apdu = Apdu::parse(raw).unwrap();
    let sw = Applet::process(app, &apdu, fs, &mut res);
    (sw, res.as_slice().to_vec())
}

fn apdu(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    assert!(data.len() < 256);
    let mut v = vec![0x00, ins, p1, p2];
    if !data.is_empty() {
        v.push(data.len() as u8);
        v.extend_from_slice(data);
    }
    v
}

fn tlv(tag: u8, val: &[u8]) -> Vec<u8> {
    assert!(val.len() < 128);
    let mut v = vec![tag, val.len() as u8];
    v.extend_from_slice(val);
    v
}

/// PUT data the way ykman builds it: NAME and KEY TLVs, the property as a
/// bare byte pair, the IMF as a 4-byte TLV.
fn put_data(
    name: &[u8],
    ty_alg: u8,
    digits: u8,
    secret: &[u8],
    touch: bool,
    imf: Option<u32>,
) -> Vec<u8> {
    let mut d = tlv(TAG_NAME, name);
    let mut key = vec![ty_alg, digits];
    key.extend_from_slice(secret);
    d.extend(tlv(TAG_KEY, &key));
    if touch {
        d.extend([TAG_PROPERTY, PROP_TOUCH]);
    }
    if let Some(c) = imf {
        d.extend(tlv(TAG_IMF, &c.to_be_bytes()));
    }
    d
}

fn put(app: &mut OathApplet, fs: &mut Fs<RamStorage>, data: &[u8]) -> Sw {
    run(app, fs, &apdu(INS_PUT, 0, 0, data)).0
}

/// CALCULATE and decode the truncated decimal code.
fn calc_code(
    app: &mut OathApplet,
    fs: &mut Fs<RamStorage>,
    name: &[u8],
    challenge: u64,
    digits: u32,
) -> u32 {
    let mut d = tlv(TAG_CHALLENGE, &challenge.to_be_bytes());
    d.extend(tlv(TAG_NAME, name));
    let (sw, body) = run(app, fs, &apdu(INS_CALCULATE, 0, 0x01, &d));
    assert_eq!(sw, Sw::OK);
    // [tag=0x76][len=5][digits][4-byte code]
    assert_eq!(body[0], TAG_RESPONSE + 1);
    assert_eq!(body[1], 5);
    let v = u32::from_be_bytes([body[3], body[4], body[5], body[6]]);
    v % 10u32.pow(digits)
}

#[test]
fn for_each_cred_lists_public_metadata() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    // TOTP/SHA1, 6 digits, no touch; HOTP/SHA256, 8 digits, touch-gated.
    assert_eq!(
        put(
            &mut app,
            &mut fs,
            &put_data(b"GitHub:alex", 0x21, 6, &[0xAA; 20], false, None)
        ),
        Sw::OK
    );
    assert_eq!(
        put(
            &mut app,
            &mut fs,
            &put_data(b"AWS", 0x12, 8, &[0xBB; 32], true, Some(0))
        ),
        Sw::OK
    );

    let dev = Device {
        serial_hash: &[0x22; 32],
        serial_id: &SERIAL,
        otp_key: None,
    };
    let mut seen: Vec<(Vec<u8>, bool, u8, u8, u16, bool)> = Vec::new();
    let n = for_each_cred(&dev, &mut fs, |c| {
        seen.push((c.name.to_vec(), c.hotp, c.algo, c.digits, c.period, c.touch))
    });
    assert_eq!(n, 2);
    let gh = seen.iter().find(|c| c.0 == b"GitHub:alex").unwrap();
    // No period prefix → default 30 s for a TOTP credential.
    assert_eq!(
        (gh.1, gh.2, gh.3, gh.4, gh.5),
        (false, ALG_HMAC_SHA1, 6, 30, false)
    );
    assert_eq!(algo_name(gh.2), "SHA1");
    let aws = seen.iter().find(|c| c.0 == b"AWS").unwrap();
    // HOTP is counter-based → period 0 (not shown as a step).
    assert_eq!(
        (aws.1, aws.2, aws.3, aws.4, aws.5),
        (true, ALG_HMAC_SHA256, 8, 0, true)
    );
}

#[test]
fn period_prefix_is_split_off_the_name() {
    assert_eq!(
        split_period(b"60/Example:bob"),
        (Some(60), &b"Example:bob"[..])
    );
    assert_eq!(split_period(b"15/x"), (Some(15), &b"x"[..]));
    // No prefix, a slash that is not a period, and an over-long digit run all pass through.
    assert_eq!(split_period(b"GitHub:alex"), (None, &b"GitHub:alex"[..]));
    assert_eq!(split_period(b"a/b"), (None, &b"a/b"[..]));
    assert_eq!(split_period(b"12345/x"), (None, &b"12345/x"[..]));
}

/// Host stand-in for the `split_period` Kani proof: LCG-mutated names (biased
/// toward digits and `/`) must always leave the label a genuine suffix, cap a
/// parsed period at 9999, and never overflow — regardless of the input.
#[test]
fn split_period_property_fuzz() {
    fn check(name: &[u8]) {
        let (period, label) = split_period(name);
        assert!(label.len() <= name.len());
        // the label is exactly the tail of the input
        assert_eq!(label, &name[name.len() - label.len()..]);
        match period {
            Some(p) => {
                assert!(p <= 9999);
                assert!(label.len() < name.len());
            }
            None => assert_eq!(label.len(), name.len()),
        }
    }
    for n in [
        &b""[..],
        b"/",
        b"3",
        b"30/",
        b"9999/",
        b"12345/x",
        b"/abc",
        b"0/x",
        b"00/y",
        b"issuer:acct",
    ] {
        check(n);
    }
    let mut lcg: u64 = 0x2545_F491_4F6C_DD1D;
    let mut next = || -> u8 {
        lcg = lcg
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (lcg >> 33) as u8
    };
    for _ in 0..50000 {
        let len = (next() % 24) as usize;
        let mut v = Vec::with_capacity(len);
        for _ in 0..len {
            let r = next();
            // Bias toward digits and the '/' separator so the prefix path is hit.
            v.push(match r & 3 {
                0 => b'0' + (r % 10),
                1 => b'/',
                _ => r,
            });
        }
        check(&v);
    }
}

#[test]
fn totp_with_period_prefix_reports_period_and_strips_prefix() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(
        put(
            &mut app,
            &mut fs,
            &put_data(b"60/Example:bob", 0x21, 8, &[0xAA; 20], false, None)
        ),
        Sw::OK
    );
    let dev = Device {
        serial_hash: &[0x22; 32],
        serial_id: &SERIAL,
        otp_key: None,
    };
    let mut got = None;
    for_each_cred(&dev, &mut fs, |c| {
        got = Some((c.name.to_vec(), c.period, c.digits));
    });
    assert_eq!(got, Some((b"Example:bob".to_vec(), 60, 8)));
}

#[test]
fn select_reports_version_and_serial() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let (sw, body) = select(&mut app, &mut fs);
    assert_eq!(sw, Sw::OK);
    assert_eq!(&body[..5], &[TAG_T_VERSION, 3, 5, 7, 4]);
    assert_eq!(body[5], TAG_NAME);
    assert_eq!(body[6], 8);
    // The device id is an opaque one-way hash of serial_hash, NOT the raw serial
    // hex — so it is not predictable from the semi-public device serial.
    assert_ne!(
        &body[7..15],
        b"12345678",
        "must not leak the raw serial hex"
    );
    // No access code: no challenge TLV, applet usable straight away.
    assert_eq!(body.len(), 15);
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[]));
    assert_eq!(sw, Sw::OK);

    // Stable across re-SELECT, and bound to serial_hash (a different hash differs).
    let (_, body2) = select(&mut app, &mut fs);
    assert_eq!(
        &body2[7..15],
        &body[7..15],
        "device id must be stable across boots"
    );
    let mut other = OathApplet::new(SERIAL, [0x33; 32], None, &rng, &touch);
    let (_, body3) = select(&mut other, &mut fs);
    assert_ne!(
        &body3[7..15],
        &body[7..15],
        "device id must depend on serial_hash"
    );
}

#[test]
fn totp_rfc6238_vectors() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    // RFC 6238 appendix B, time 59 s → T = 1, 8 digits.
    for (name, alg, secret, code) in [
        (b"sha1".as_slice(), ALG_HMAC_SHA1, SECRET_SHA1, 94287082u32),
        (b"sha256", ALG_HMAC_SHA256, SECRET_SHA256, 46119246),
        (b"sha512", ALG_HMAC_SHA512, SECRET_SHA512, 90693936),
    ] {
        assert_eq!(
            put(
                &mut app,
                &mut fs,
                &put_data(name, 0x20 | alg, 8, secret, false, None)
            ),
            Sw::OK
        );
        assert_eq!(calc_code(&mut app, &mut fs, name, 1, 8), code);
    }
}

#[test]
fn totp_full_response() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    put(
        &mut app,
        &mut fs,
        &put_data(b"t", 0x21, 6, SECRET_SHA1, false, None),
    );
    let mut d = tlv(TAG_CHALLENGE, &1u64.to_be_bytes());
    d.extend(tlv(TAG_NAME, b"t"));
    let (sw, body) = run(&mut app, &mut fs, &apdu(INS_CALCULATE, 0, 0x00, &d));
    assert_eq!(sw, Sw::OK);
    assert_eq!(body[0], TAG_RESPONSE);
    assert_eq!(body[1], 21); // digits byte + full SHA-1 HMAC
    assert_eq!(body[2], 6);
    assert_eq!(&body[3..23], &hmac_sha1(SECRET_SHA1, &1u64.to_be_bytes()));
}

#[test]
fn hotp_rfc4226_sequence_and_counter_persistence() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    // No IMF sent → counter starts at 0 (RFC 4226 appendix D, 6 digits).
    put(
        &mut app,
        &mut fs,
        &put_data(b"h", 0x11, 6, SECRET_SHA1, false, None),
    );
    for code in [755224u32, 287082, 359152] {
        // The host challenge is ignored for HOTP.
        assert_eq!(calc_code(&mut app, &mut fs, b"h", 0xDEAD, 6), code);
    }
    // A fresh applet over the same storage continues the sequence.
    let mut app2 = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(calc_code(&mut app2, &mut fs, b"h", 0, 6), 969429);
}

#[test]
fn hotp_imf_padded_and_honoured() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    // ykman sends the initial counter as 4 bytes; stored padded to 8.
    put(
        &mut app,
        &mut fs,
        &put_data(b"h", 0x11, 6, SECRET_SHA1, false, Some(5)),
    );
    assert_eq!(calc_code(&mut app, &mut fs, b"h", 0, 6), 254676); // count 5
    assert_eq!(calc_code(&mut app, &mut fs, b"h", 0, 6), 287922); // count 6
}

#[test]
fn calculate_touch_cred_requires_press() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    // HOTP: a denied attempt must also leave the counter unburnt.
    let deny = RefCell::new(StubPresence(Presence::Timeout, 0));
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &deny);
    put(
        &mut app,
        &mut fs,
        &put_data(b"h", 0x11, 6, SECRET_SHA1, true, None),
    );
    let mut d = tlv(TAG_CHALLENGE, &0u64.to_be_bytes());
    d.extend(tlv(TAG_NAME, b"h"));
    let (sw, body) = run(&mut app, &mut fs, &apdu(INS_CALCULATE, 0, 0x01, &d));
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    assert!(body.is_empty());
    assert_eq!(deny.borrow().1, 1);
    // Confirmed press → the counter-0 code: the denied try burned nothing.
    let confirm = RefCell::new(StubPresence(Presence::Confirmed, 0));
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &confirm);
    assert_eq!(calc_code(&mut app, &mut fs, b"h", 0, 6), 755224);
    assert_eq!(confirm.borrow().1, 1);
}

#[test]
fn calculate_plain_cred_never_asks_for_touch() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let deny = RefCell::new(StubPresence(Presence::Declined, 0));
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &deny);
    put(
        &mut app,
        &mut fs,
        &put_data(b"t", 0x21, 8, SECRET_SHA1, false, None),
    );
    assert_eq!(calc_code(&mut app, &mut fs, b"t", 1, 8), 94287082);
    assert_eq!(deny.borrow().1, 0);
}

#[test]
fn cred_secret_is_sealed_on_flash() {
    // The whole point of the seal: an enrolled credential's HMAC secret must
    // not sit in the clear on flash, and the seal must still round-trip.
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(StubPresence(Presence::Confirmed, 0));
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(
        put(
            &mut app,
            &mut fs,
            &put_data(b"acct", 0x21, 8, SECRET_SHA1, false, None)
        ),
        Sw::OK
    );

    let mut fids = [0u16; MAX_OATH_CRED as usize];
    assert_eq!(present_creds(&mut fs, &mut fids), 1);
    let mut raw = [0u8; CRED_MAX];
    let len = fs.read(fids[0], &mut raw).unwrap();
    assert!(
        !raw[..len]
            .windows(SECRET_SHA1.len())
            .any(|w| w == SECRET_SHA1),
        "OATH HMAC secret stored in plaintext on flash",
    );
    // The seal round-trips — the RFC 6238 SHA-1 vector still computes.
    assert_eq!(calc_code(&mut app, &mut fs, b"acct", 1, 8), 94287082);
}

/// `present_creds` (now the in-RAM `present_slots` bitmap) must return exactly the
/// same ascending FID set a fresh `for_each_key` scan of the OATH range yields —
/// including across a deletion gap — so LIST / CALCULATE ALL stay byte-identical.
#[test]
fn present_creds_matches_for_each_key_occupancy() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);

    for name in [b"aa".as_slice(), b"bb", b"cc", b"dd"] {
        assert_eq!(
            put(
                &mut app,
                &mut fs,
                &put_data(name, 0x21, 6, SECRET_SHA1, false, None)
            ),
            Sw::OK
        );
    }
    // Delete the second credential so the live set has an interior gap.
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &apdu(INS_DELETE, 0, 0, &tlv(TAG_NAME, b"bb"))
        )
        .0,
        Sw::OK
    );

    let mut fids = [0u16; MAX_OATH_CRED as usize];
    let n = present_creds(&mut fs, &mut fids);

    // Independent occupancy oracle: a fresh whole-partition scan of the range.
    let mut want = Vec::new();
    fs.for_each_key(&mut |fid| {
        if (EF_OATH_CRED..EF_OATH_CRED + MAX_OATH_CRED).contains(&fid) {
            want.push(fid);
        }
    });
    want.sort_unstable();

    assert_eq!(
        &fids[..n],
        want.as_slice(),
        "present_creds != for_each_key occupancy"
    );
    assert!(
        fids[..n].windows(2).all(|w| w[0] < w[1]),
        "present_creds not strictly ascending"
    );
    // free_slot must land on the freed interior slot, not append past the tail.
    assert_eq!(free_slot(&mut fs), Some(EF_OATH_CRED + 1));
}

#[test]
fn legacy_plaintext_cred_migrates_and_stays_usable() {
    // A credential enrolled before sealing existed is stored as a bare TLV
    // with the secret in the clear. The boot pass must seal it in place
    // without losing it.
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(StubPresence(Presence::Confirmed, 0));
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);

    // Pre-seal layout: NAME ‖ KEY(type|alg, digits, secret), written raw.
    let mut blob = tlv(TAG_NAME, b"acct");
    let mut key = vec![0x21u8, 8];
    key.extend_from_slice(SECRET_SHA1);
    blob.extend(tlv(TAG_KEY, &key));
    fs.put(EF_OATH_CRED, &blob).unwrap();
    let mut raw = [0u8; CRED_MAX];
    let len = fs.read(EF_OATH_CRED, &mut raw).unwrap();
    assert!(
        raw[..len]
            .windows(SECRET_SHA1.len())
            .any(|w| w == SECRET_SHA1),
        "fixture should start as plaintext",
    );

    // Boot migration seals it (device must match the applet's identity).
    let dev = Device {
        serial_hash: &[0x22; 32],
        serial_id: &SERIAL,
        otp_key: None,
    };
    let mut mrng = CountRng(1);
    migrate_seal(&dev, &mut fs, &mut mrng);

    let len = fs.read(EF_OATH_CRED, &mut raw).unwrap();
    assert!(
        !raw[..len]
            .windows(SECRET_SHA1.len())
            .any(|w| w == SECRET_SHA1),
        "migration left the OATH secret in plaintext",
    );
    // The credential is still usable: CALCULATE unseals and computes.
    assert_eq!(calc_code(&mut app, &mut fs, b"acct", 1, 8), 94287082);
    // Idempotent: a second pass is a no-op (it already authenticates).
    migrate_seal(&dev, &mut fs, &mut mrng);
    assert_eq!(calc_code(&mut app, &mut fs, b"acct", 1, 8), 94287082);
}

#[test]
fn calculate_all_reports_touch_without_press() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let deny = RefCell::new(StubPresence(Presence::Timeout, 0));
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &deny);
    put(
        &mut app,
        &mut fs,
        &put_data(b"t", 0x21, 6, SECRET_SHA1, true, None),
    );
    let d = tlv(TAG_CHALLENGE, &1u64.to_be_bytes());
    let (sw, body) = run(&mut app, &mut fs, &apdu(INS_CALC_ALL, 0, 0x01, &d));
    assert_eq!(sw, Sw::OK);
    // Touch creds are reported (0x7C), never computed, no button involved.
    let expect = [tlv(TAG_NAME, b"t"), vec![TAG_TOUCH_RESPONSE, 1, 6]].concat();
    assert_eq!(body, expect);
    assert_eq!(deny.borrow().1, 0);
}

#[test]
fn put_validates_key_and_name() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    // Missing key.
    assert_eq!(
        put(&mut app, &mut fs, &tlv(TAG_NAME, b"x")),
        Sw::INCORRECT_PARAMS
    );
    // Missing name.
    assert_eq!(
        put(&mut app, &mut fs, &tlv(TAG_KEY, &[0x21, 6, 1, 2])),
        Sw::INCORRECT_PARAMS
    );
    // Key shorter than [type, digits] is rejected.
    let mut d = tlv(TAG_NAME, b"x");
    d.extend(tlv(TAG_KEY, &[0x21]));
    assert_eq!(put(&mut app, &mut fs, &d), Sw::INCORRECT_PARAMS);
}

#[test]
fn put_overwrites_same_name() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    put(
        &mut app,
        &mut fs,
        &put_data(b"a", 0x21, 6, b"oldkey-0123456789", false, None),
    );
    put(
        &mut app,
        &mut fs,
        &put_data(b"a", 0x21, 8, SECRET_SHA1, false, None),
    );
    let (sw, body) = run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[]));
    assert_eq!(sw, Sw::OK);
    // One entry only, and CALCULATE uses the new key/digits.
    assert_eq!(body, [vec![TAG_NAME_LIST, 2, 0x21], b"a".to_vec()].concat());
    assert_eq!(calc_code(&mut app, &mut fs, b"a", 1, 8), 94287082);
}

#[test]
fn list_plain_and_extended() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    put(
        &mut app,
        &mut fs,
        &put_data(b"plain", 0x21, 6, SECRET_SHA1, false, None),
    );
    put(
        &mut app,
        &mut fs,
        &put_data(b"touchy", 0x22, 6, SECRET_SHA256, true, None),
    );
    let mut with_pws = put_data(b"pws", 0x21, 6, SECRET_SHA1, false, None);
    with_pws.extend(tlv(TAG_PWS_LOGIN, b"user"));
    put(&mut app, &mut fs, &with_pws);

    let (sw, body) = run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[]));
    assert_eq!(sw, Sw::OK);
    let expect = [
        vec![TAG_NAME_LIST, 6, 0x21],
        b"plain".to_vec(),
        vec![TAG_NAME_LIST, 7, 0x22],
        b"touchy".to_vec(),
        vec![TAG_NAME_LIST, 4, 0x21],
        b"pws".to_vec(),
    ]
    .concat();
    assert_eq!(body, expect);

    // Extended form appends a properties byte: touch = 0x1, PWS data = 0x4.
    let (sw, body) = run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[0x01]));
    assert_eq!(sw, Sw::OK);
    let expect = [
        vec![TAG_NAME_LIST, 7, 0x21],
        b"plain".to_vec(),
        vec![0x0],
        vec![TAG_NAME_LIST, 8, 0x22],
        b"touchy".to_vec(),
        vec![0x1],
        vec![TAG_NAME_LIST, 5, 0x21],
        b"pws".to_vec(),
        vec![0x4],
    ]
    .concat();
    assert_eq!(body, expect);
}

#[test]
fn delete_removes_credential() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    put(
        &mut app,
        &mut fs,
        &put_data(b"gone", 0x21, 6, SECRET_SHA1, false, None),
    );
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(INS_DELETE, 0, 0, &tlv(TAG_NAME, b"gone")),
    );
    assert_eq!(sw, Sw::OK);
    let (_, body) = run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[]));
    assert!(body.is_empty());
    // Deleting it again: unknown name.
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(INS_DELETE, 0, 0, &tlv(TAG_NAME, b"gone")),
    );
    assert_eq!(sw, Sw::DATA_INVALID);
}

#[test]
fn rename_replaces_name_in_place() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    put(
        &mut app,
        &mut fs,
        &put_data(b"old", 0x21, 8, SECRET_SHA1, false, None),
    );
    let mut d = tlv(TAG_NAME, b"old");
    d.extend(tlv(TAG_NAME, b"newname"));
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_RENAME, 0, 0, &d));
    assert_eq!(sw, Sw::OK);
    // Old gone, new resolves and still calculates correctly.
    assert_eq!(calc_code(&mut app, &mut fs, b"newname", 1, 8), 94287082);
    let mut d = tlv(TAG_CHALLENGE, &1u64.to_be_bytes());
    d.extend(tlv(TAG_NAME, b"old"));
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_CALCULATE, 0, 1, &d));
    assert_eq!(sw, Sw::DATA_INVALID);

    // Same old/new name is the taken-target case; unknown name is DATA_INVALID.
    let mut d = tlv(TAG_NAME, b"newname");
    d.extend(tlv(TAG_NAME, b"newname"));
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_RENAME, 0, 0, &d));
    assert_eq!(sw, Sw::DATA_INVALID);
    let mut d = tlv(TAG_NAME, b"missing");
    d.extend(tlv(TAG_NAME, b"other"));
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_RENAME, 0, 0, &d));
    assert_eq!(sw, Sw::DATA_INVALID);
}

/// One credential per name is the store's rule — PUT keeps it by overwriting
/// (`put_overwrites_same_name`), so RENAME keeps it by refusing. A YubiKey 5.7.4
/// answers `6984` to a taken target, and nothing on the card moves.
#[test]
fn rename_onto_an_existing_name_is_refused() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    put(
        &mut app,
        &mut fs,
        &put_data(b"alpha", 0x21, 8, SECRET_SHA1, false, None),
    );
    put(
        &mut app,
        &mut fs,
        &put_data(b"beta", 0x21, 8, b"beta-secret-01234567", false, None),
    );
    let alpha_code = calc_code(&mut app, &mut fs, b"alpha", 1, 8);
    let beta_code = calc_code(&mut app, &mut fs, b"beta", 1, 8);
    assert_ne!(alpha_code, beta_code);

    let mut d = tlv(TAG_NAME, b"alpha");
    d.extend(tlv(TAG_NAME, b"beta"));
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_RENAME, 0, 0, &d));
    assert_eq!(sw, Sw::DATA_INVALID);
    // Refused means untouched: two rows, each still answering with its own secret.
    // A second `beta` would shadow the first, and deleting it would silently change
    // which code the surviving row produces.
    let (_, body) = run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[]));
    assert_eq!(
        body,
        [
            vec![TAG_NAME_LIST, 6, 0x21],
            b"alpha".to_vec(),
            vec![TAG_NAME_LIST, 5, 0x21],
            b"beta".to_vec(),
        ]
        .concat()
    );
    assert_eq!(calc_code(&mut app, &mut fs, b"alpha", 1, 8), alpha_code);
    assert_eq!(calc_code(&mut app, &mut fs, b"beta", 1, 8), beta_code);

    // Renaming onto itself is that same taken target, not a syntax error.
    let mut d = tlv(TAG_NAME, b"beta");
    d.extend(tlv(TAG_NAME, b"beta"));
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_RENAME, 0, 0, &d));
    assert_eq!(sw, Sw::DATA_INVALID);
    // A taken target is judged first, so these two pin that the missing-source
    // answer survives it: both refusals must stay the one status word, or the
    // card's `6984` for a source it does not have turns into the target's.
    for (from, to) in [(&b"nosuch"[..], &b"nosuch"[..]), (b"nosuch", b"beta")] {
        let mut d = tlv(TAG_NAME, from);
        d.extend(tlv(TAG_NAME, to));
        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_RENAME, 0, 0, &d));
        assert_eq!(sw, Sw::DATA_INVALID);
    }

    // The collision predicate is the byte-exact one the source lookup already
    // uses: a target differing only in case is free, and the rename carries the
    // secret across.
    let mut d = tlv(TAG_NAME, b"alpha");
    d.extend(tlv(TAG_NAME, b"Beta"));
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_RENAME, 0, 0, &d));
    assert_eq!(sw, Sw::OK);
    assert_eq!(calc_code(&mut app, &mut fs, b"Beta", 1, 8), alpha_code);
    assert_eq!(calc_code(&mut app, &mut fs, b"beta", 1, 8), beta_code);
}

/// Drive the full access-code lifecycle the way ykman does.
#[test]
fn set_code_and_validate_flow() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    put(
        &mut app,
        &mut fs,
        &put_data(b"c", 0x21, 8, SECRET_SHA1, false, None),
    );
    let code_key = {
        let mut k = vec![ALG_HMAC_SHA1];
        k.extend_from_slice(&[0xAB; 16]);
        k
    };

    // SET CODE with a response that doesn't prove key knowledge.
    let mut d = tlv(TAG_KEY, &code_key);
    d.extend(tlv(TAG_CHALLENGE, &[1, 2, 3, 4, 5, 6, 7, 8]));
    d.extend(tlv(TAG_RESPONSE, &[0u8; 20]));
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_SET_CODE, 0, 0, &d));
    assert_eq!(sw, Sw::DATA_INVALID);

    // Correct proof: response = HMAC(key, challenge).
    let chal = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let proof = hmac_sha1(&[0xAB; 16], &chal);
    let mut d = tlv(TAG_KEY, &code_key);
    d.extend(tlv(TAG_CHALLENGE, &chal));
    d.extend(tlv(TAG_RESPONSE, &proof));
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_SET_CODE, 0, 0, &d));
    assert_eq!(sw, Sw::OK);

    // The session is immediately unvalidated, and so is a fresh SELECT.
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[]));
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    let (sw, body) = select(&mut app, &mut fs);
    assert_eq!(sw, Sw::OK);
    // Challenge + algorithm TLVs are now present.
    let card_chal = find_tag(&body, TAG_CHALLENGE as u16).unwrap().to_vec();
    assert_eq!(card_chal.len(), 8);
    assert_eq!(find_tag(&body, TAG_ALGO as u16), Some(&[ALG_HMAC_SHA1][..]));
    for ins in [
        INS_PUT,
        INS_DELETE,
        INS_LIST,
        INS_CALCULATE,
        INS_CALC_ALL,
        INS_RENAME,
        INS_VERIFY_CODE,
    ] {
        let (sw, _) = run(&mut app, &mut fs, &apdu(ins, 0, 0, &[]));
        assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED, "ins {ins:#x}");
    }

    // VALIDATE with a wrong response stays locked…
    let host_chal = [9u8, 9, 9, 9, 8, 8, 8, 8];
    let mut d = tlv(TAG_CHALLENGE, &host_chal);
    d.extend(tlv(TAG_RESPONSE, &[0u8; 20]));
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_VALIDATE, 0, 0, &d));
    assert_eq!(sw, Sw::INCORRECT_PARAMS);
    // …and a truncated (1-byte) response must not brute-force its way in.
    let full = hmac_sha1(&[0xAB; 16], &card_chal);
    let mut d = tlv(TAG_CHALLENGE, &host_chal);
    d.extend(tlv(TAG_RESPONSE, &full[..1]));
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_VALIDATE, 0, 0, &d));
    assert_eq!(sw, Sw::INCORRECT_PARAMS);

    // Correct response unlocks and returns the mutual proof.
    let mut d = tlv(TAG_CHALLENGE, &host_chal);
    d.extend(tlv(TAG_RESPONSE, &full));
    let (sw, body) = run(&mut app, &mut fs, &apdu(INS_VALIDATE, 0, 0, &d));
    assert_eq!(sw, Sw::OK);
    assert_eq!(
        find_tag(&body, TAG_RESPONSE as u16),
        Some(&hmac_sha1(&[0xAB; 16], &host_chal)[..])
    );
    assert_eq!(calc_code(&mut app, &mut fs, b"c", 1, 8), 94287082);

    // SET CODE with an empty key removes the code again.
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(INS_SET_CODE, 0, 0, &tlv(TAG_KEY, &[])),
    );
    assert_eq!(sw, Sw::OK);
    let (_, body) = select(&mut app, &mut fs);
    assert_eq!(find_tag(&body, TAG_CHALLENGE as u16), None);
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[]));
    assert_eq!(sw, Sw::OK);
}

#[test]
fn validate_without_code_reports_invalid() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let mut d = tlv(TAG_CHALLENGE, &[0; 8]);
    d.extend(tlv(TAG_RESPONSE, &[0; 20]));
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_VALIDATE, 0, 0, &d));
    assert_eq!(sw, Sw::DATA_INVALID);
    // But the applet stays usable — no access code is set.
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[]));
    assert_eq!(sw, Sw::OK);
}

#[test]
fn reset_clears_creds_code_and_pin() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    put(
        &mut app,
        &mut fs,
        &put_data(b"a", 0x21, 6, SECRET_SHA1, false, None),
    );
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234")),
    );
    assert_eq!(sw, Sw::OK);

    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_RESET, 0, 0, &[]));
    assert_eq!(sw, Sw::INCORRECT_P1P2);
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_RESET, 0xDE, 0xAD, &[]));
    assert_eq!(sw, Sw::OK);

    let (_, body) = run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[]));
    assert!(body.is_empty());
    // The OTP PIN file is gone — SET PIN works again.
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"5678")),
    );
    assert_eq!(sw, Sw::OK);
}

#[test]
fn cred_sealed_before_otp_burn_survives_the_burn() {
    // #3 regression: a credential sealed while the OTP MKEK is unburned is
    // under the NO-OTP kbase. After the burn migrate_seal must recover it via
    // the pre-OTP arm and re-seal under the OTP arm — NOT re-wrap the
    // ciphertext as plaintext (which would double-encrypt and destroy it).
    let mut fs = new_fs();
    let mut rng = CountRng(7);
    let nootp = Device {
        serial_hash: &[0x22; 32],
        serial_id: &SERIAL,
        otp_key: None,
    };
    let otp = Device {
        otp_key: Some(&TEST_MKEK),
        ..nootp
    };
    // Seal a credential blob under the pre-OTP arm (content is opaque to the
    // migration — it re-seals bytes, so a fixed payload suffices).
    let secret = b"a-totp-cred-tlv-blob\x00\x01\x02";
    let fid = KeyFid::new(EF_OATH_CRED);
    assert!(seal::seal_put(&nootp, &mut fs, &mut rng, fid, secret));

    // The OTP-armed device cannot read it yet…
    let mut buf = [0u8; CRED_MAX];
    assert!(seal::seal_read(&otp, &mut fs, fid, &mut buf).is_none());

    // …migrate_seal recovers and re-seals it under the OTP arm, byte-identical.
    migrate_seal(&otp, &mut fs, &mut rng);
    let n = seal::seal_read(&otp, &mut fs, fid, &mut buf).expect("cred survives the burn");
    assert_eq!(&buf[..n], secret);

    // Idempotent, and it is no longer readable under the pre-OTP arm.
    migrate_seal(&otp, &mut fs, &mut rng);
    assert!(seal::seal_read(&otp, &mut fs, fid, &mut buf).is_some());
    assert!(seal::seal_read(&nootp, &mut fs, fid, &mut buf).is_none());
}

/// A device whose records were sealed on other silicon: `serial_hash` is the GCM
/// AAD, so nothing it holds opens under either arm here.
fn foreign_sealed(fs: &mut Fs<RamStorage>, fid: KeyFid, plain: &[u8]) -> Device<'static> {
    let dev = Device {
        serial_hash: &[0x22; 32],
        serial_id: &SERIAL,
        otp_key: None,
    };
    let foreign = Device {
        serial_hash: &[0x77; 32],
        ..dev
    };
    assert!(seal::seal_put(&foreign, fs, &mut CountRng(7), fid, plain));
    let mut buf = [0u8; seal::MAX_BLOB];
    assert!(seal::seal_read(&dev, fs, fid, &mut buf).is_none());
    dev
}

#[test]
fn cred_that_opens_under_no_arm_survives_the_boot_lap() {
    // run-37 #1: a record that authenticates under neither arm is not legacy
    // plaintext. Re-sealing it double-wraps the ciphertext and destroys the
    // credential, so the lap must leave it byte-identical — as its PIV / OTP /
    // keydev siblings do.
    let mut fs = new_fs();
    let fid = KeyFid::new(EF_OATH_CRED);
    let mut plain = tlv(TAG_NAME, b"acct");
    plain.extend(tlv(TAG_KEY, &[0x21, 8]));
    let dev = foreign_sealed(&mut fs, fid, &plain);

    let mut before = [0u8; seal::MAX_BLOB];
    let n = fs.read_key(fid, &mut before).unwrap();
    migrate_seal(&dev, &mut fs, &mut CountRng(1));

    let mut after = [0u8; seal::MAX_BLOB];
    let m = fs.read_key(fid, &mut after).unwrap();
    assert_eq!(
        (m, &after[..m]),
        (n, &before[..n]),
        "the lap re-sealed a record it could not open",
    );
}

#[test]
fn oversized_sealed_cred_is_not_truncated_by_the_boot_lap() {
    // A maximal credential seals to CRED_MAX + 28 bytes. Read through a CRED_MAX
    // scratch it came back short of its GCM tag, and the lap re-sealed the
    // truncated ciphertext — an information-theoretic loss.
    let mut fs = new_fs();
    let fid = KeyFid::new(EF_OATH_CRED);
    let dev = foreign_sealed(&mut fs, fid, &[0xA5; CRED_MAX]);

    let mut before = [0u8; seal::MAX_BLOB];
    assert_eq!(fs.read_key(fid, &mut before), Some(seal::MAX_BLOB));
    migrate_seal(&dev, &mut fs, &mut CountRng(1));

    let mut after = [0u8; seal::MAX_BLOB];
    assert_eq!(
        fs.read_key(fid, &mut after),
        Some(seal::MAX_BLOB),
        "the lap truncated a maximal sealed blob",
    );
    assert_eq!(
        after, before,
        "the lap re-sealed a record it could not open"
    );
}

#[test]
fn otp_pin_set_before_burn_still_verifies_after_burn() {
    // #4 regression: v1 is OTP-rooted, so a PIN set before the OTP burn is
    // stored under the NO-OTP kbase. After the burn otp_pin_matches must fall
    // back to the pre-OTP arm (and the success re-stores under the OTP arm),
    // so the PIN is not permanently locked out. The legacy double_hash_pin
    // survived a burn; v1 must not regress that.
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);

    // Pre-burn: set the OTP-PIN (v1 under the NO-OTP kbase).
    {
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234")),
        );
        assert_eq!(sw, Sw::OK);
    }

    // Post-burn: the same PIN must still verify, via the without_otp fallback.
    let mut app = OathApplet::new(SERIAL, [0x22; 32], Some(test_mkek), &rng, &touch);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234")),
    );
    assert_eq!(sw, Sw::OK);

    // The success re-stored the verifier under the OTP arm (self-heal).
    let otp_dev = Device {
        serial_hash: &[0x22; 32],
        serial_id: &SERIAL,
        otp_key: Some(&TEST_MKEK),
    };
    let mut rec = [0u8; 34];
    assert_eq!(fs.read(EF_OTP_PIN, &mut rec), Some(34));
    assert_eq!(rec[1], OTP_PIN_FMT_V1);
    assert_eq!(
        &rec[2..],
        &otp_dev.pin_derive_verifier(b"1234")[..],
        "verifier re-stored under the OTP arm"
    );

    // A wrong PIN post-burn still fails.
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, b"nope")),
    );
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
}

/// Lock the applet behind an access code, so a fresh SELECT starts unvalidated.
fn lock_with_code(app: &mut OathApplet, fs: &mut Fs<RamStorage>) {
    let mut code_key = vec![ALG_HMAC_SHA1];
    code_key.extend_from_slice(&[0xAB; 16]);
    let chal = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let proof = hmac_sha1(&[0xAB; 16], &chal);
    let mut d = tlv(TAG_KEY, &code_key);
    d.extend(tlv(TAG_CHALLENGE, &chal));
    d.extend(tlv(TAG_RESPONSE, &proof));
    assert_eq!(run(app, fs, &apdu(INS_SET_CODE, 0, 0, &d)).0, Sw::OK);
    select(app, fs);
}

#[test]
fn set_pin_rejected_while_access_code_locked() {
    // run-2 F4: minting the OTP-PIN on an access-code-locked applet must require
    // validation, else an unauthenticated host creates the secret that unlocks
    // the store. (A no-code applet starts validated=true, so first-set still works.)
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    lock_with_code(&mut app, &mut fs);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234")),
    );
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    assert!(!fs.has_data(EF_OTP_PIN), "no OTP-PIN minted while locked");
}

/// run-26: the sibling of the case above — planting the PIN *before* any access
/// code exists. `select()` sets validated = !code_set, so on a factory-state applet
/// `validated` is vacuously true and SET PIN was otherwise unauthenticated. The PIN
/// then survived the owner setting an access code and unlocked the store through
/// VERIFY PIN, invisibly. Two halves: the plant needs the operator, and installing
/// a new access code drops any PIN minted without it.
#[test]
fn otp_pin_cannot_be_planted_before_an_access_code_exists() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));

    // A code-less applet: minting the unlock secret now requires a touch.
    let decline = RefCell::new(StubPresence(Presence::Timeout, 0));
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &decline);
    select(&mut app, &mut fs);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"0000")),
    );
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    assert!(!fs.has_data(EF_OTP_PIN), "declined touch mints nothing");

    // With the operator present it is allowed (the nitropy first-set flow).
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    select(&mut app, &mut fs);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"0000")),
    );
    assert_eq!(sw, Sw::OK);
    assert!(fs.has_data(EF_OTP_PIN));

    // The owner now protects the applet: the pre-existing PIN must not remain as a
    // second unlock path for the store this code is being set to guard.
    lock_with_code(&mut app, &mut fs);
    assert!(
        !fs.has_data(EF_OTP_PIN),
        "installing an access code drops an OTP-PIN minted without it"
    );

    // And the applet really is closed: a fresh SELECT needs VALIDATE, and the old
    // PIN no longer opens it.
    select(&mut app, &mut fs);
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[]));
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, b"0000")),
    );
    assert_ne!(sw, Sw::OK, "the dropped PIN must not unlock the store");
}

#[test]
fn change_pin_locks_out_at_floor_and_recovers_only_via_reset() {
    // run-3 #2 + run-6: CHANGE PIN decrements the retry counter on a wrong old-PIN,
    // AND — unlike the earlier design — refuses once the counter floors at 0, for
    // BOTH a wrong and a correct old-PIN. The floor "recovery" via a correct old
    // CHANGE was an unlimited online guessing oracle (spend_otp_retry saturates
    // 0->0, so the compare kept running). Recovery after lock-out is now RESET.
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))
        )
        .0,
        Sw::OK
    );
    for _ in 0..MAX_OTP_COUNTER {
        let mut d = tlv(TAG_PASSWORD, b"9999");
        d.extend(tlv(TAG_NEW_PASSWORD, b"0000"));
        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_CHANGE_PIN, 0, 0, &d));
        assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    }
    // Counter exhausted: the correct PIN is now refused via BOTH VERIFY and CHANGE
    // (the floor no longer runs the compare — no unlimited oracle).
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))
        )
        .0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    let mut d = tlv(TAG_PASSWORD, b"1234");
    d.extend(tlv(TAG_NEW_PASSWORD, b"5678"));
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_CHANGE_PIN, 0, 0, &d)).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "correct old-PIN must NOT recover at the floor (that was the oracle)"
    );
    // Recovery is RESET: it wipes the OTP-PIN, after which a fresh PIN can be set.
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_RESET, 0xDE, 0xAD, &[])).0,
        Sw::OK
    );
    assert!(!fs.has_data(EF_OTP_PIN), "RESET wipes the OTP-PIN");
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"5678"))
        )
        .0,
        Sw::OK
    );
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, b"5678"))
        )
        .0,
        Sw::OK
    );
}

#[test]
fn put_rejects_two_byte_tag_form() {
    // run-3 #6: a stored credential must not carry a (tag&0x1f)==0x1f byte, which
    // the 1-byte PutIter and the 2-byte SDK Tlv walker would read differently.
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let mut d = put_data(b"c", 0x21, 6, SECRET_SHA1, false, None);
    d.extend(tlv(0x7F, &[0xAA])); // low 5 bits == 0x1f
    assert_eq!(put(&mut app, &mut fs, &d), Sw::INCORRECT_PARAMS);
}

#[test]
fn legacy_otp_pin_verifies_and_upgrades_to_otp_rooted() {
    // A device provisioned before #35 stored [counter, double_hash_pin(pin)]
    // (serial-only, fast). It must still verify, and the first success
    // upgrades it to the OTP-rooted v1 verifier so a flash dump can no longer
    // offline-crack it.
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let dev = Device {
        serial_hash: &[0x22; 32],
        serial_id: &SERIAL,
        otp_key: None,
    };
    // Legacy record straight to flash (what old firmware wrote).
    let mut legacy = [0u8; 33];
    legacy[0] = MAX_OTP_COUNTER;
    legacy[1..].copy_from_slice(&dev.double_hash_pin(b"1234"));
    fs.put(EF_OTP_PIN, &legacy).unwrap();

    // The legacy PIN still verifies…
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234")),
    );
    assert_eq!(sw, Sw::OK);

    // …and the record is upgraded to the OTP-rooted v1 verifier.
    let mut rec = [0u8; 34];
    assert_eq!(fs.read(EF_OTP_PIN, &mut rec), Some(34));
    assert_eq!(rec[1], OTP_PIN_FMT_V1);
    assert_eq!(&rec[2..], &dev.pin_derive_verifier(b"1234")[..]);
    assert_ne!(
        &rec[2..],
        &dev.double_hash_pin(b"1234")[..],
        "must not store the legacy hash after upgrade"
    );

    // A wrong legacy PIN fails cleanly: no upgrade, counter decrements.
    let mut fs2 = new_fs();
    fs2.put(EF_OTP_PIN, &legacy).unwrap();
    let (sw, _) = run(
        &mut app,
        &mut fs2,
        &apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, b"nope")),
    );
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    let mut rec2 = [0u8; 34];
    assert_eq!(
        fs2.read(EF_OTP_PIN, &mut rec2),
        Some(33),
        "failure preserves the legacy format"
    );
    assert_eq!(rec2[0], MAX_OTP_COUNTER - 1, "counter decremented");
}

#[test]
fn otp_pin_set_change_verify_and_lockout() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    // VERIFY/CHANGE before a PIN exists.
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, b"x")),
    );
    assert_eq!(sw, Sw::CONDITIONS_NOT_SATISFIED);

    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234")),
    );
    assert_eq!(sw, Sw::OK);
    // SET PIN refuses to overwrite.
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"x")),
    );
    assert_eq!(sw, Sw::CONDITIONS_NOT_SATISFIED);

    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234")),
    );
    assert_eq!(sw, Sw::OK);

    // CHANGE PIN with wrong then right old PIN.
    let mut d = tlv(TAG_PASSWORD, b"wrong");
    d.extend(tlv(TAG_NEW_PASSWORD, b"0000"));
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_CHANGE_PIN, 0, 0, &d));
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    let mut d = tlv(TAG_PASSWORD, b"1234");
    d.extend(tlv(TAG_NEW_PASSWORD, b"abcd"));
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_CHANGE_PIN, 0, 0, &d));
    assert_eq!(sw, Sw::OK);

    // Three failures exhaust the retry counter; then the right PIN fails via
    // BOTH VERIFY and CHANGE (the floor no longer runs the compare — run-6).
    for _ in 0..3 {
        let (sw, _) = run(
            &mut app,
            &mut fs,
            &apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, b"nope")),
        );
        assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    }
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, b"abcd")),
    );
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    let mut d = tlv(TAG_PASSWORD, b"abcd");
    d.extend(tlv(TAG_NEW_PASSWORD, b"1234"));
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_CHANGE_PIN, 0, 0, &d));
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    // Recovery is RESET (wipes the PIN); then a fresh PIN can be set + verified.
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_RESET, 0xDE, 0xAD, &[])).0,
        Sw::OK
    );
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234")),
    );
    assert_eq!(sw, Sw::OK);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234")),
    );
    assert_eq!(sw, Sw::OK);
}

#[test]
fn verify_code_checks_hotp_slot0() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    // Slot 0 = HOTP credential at counter 0 → code 755224.
    put(
        &mut app,
        &mut fs,
        &put_data(b"h", 0x11, 6, SECRET_SHA1, false, None),
    );

    let mut d = tlv(TAG_NAME, b"h");
    d.extend(tlv(TAG_RESPONSE, &755224u32.to_be_bytes()));
    let (sw, body) = run(&mut app, &mut fs, &apdu(INS_VERIFY_CODE, 0, 0, &d));
    assert_eq!(sw, Sw::OK);
    assert!(body.is_empty());
    // VERIFY CODE does not advance the counter.
    let mut d = tlv(TAG_NAME, b"h");
    d.extend(tlv(TAG_RESPONSE, &755224u32.to_be_bytes()));
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_VERIFY_CODE, 0, 0, &d));
    assert_eq!(sw, Sw::OK);

    let mut d = tlv(TAG_NAME, b"h");
    d.extend(tlv(TAG_RESPONSE, &111111u32.to_be_bytes()));
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_VERIFY_CODE, 0, 0, &d));
    assert_eq!(sw, SW_WRONG_DATA);
}

#[test]
fn verify_code_touch_cred_requires_press() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    // Slot 0 = touch-flagged HOTP credential; a denied press must block VERIFY CODE
    // so it can't be a presence-free guessing oracle on the current OTP.
    let deny = RefCell::new(StubPresence(Presence::Timeout, 0));
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &deny);
    put(
        &mut app,
        &mut fs,
        &put_data(b"h", 0x11, 6, SECRET_SHA1, true, None),
    );
    let mut d = tlv(TAG_NAME, b"h");
    d.extend(tlv(TAG_RESPONSE, &755224u32.to_be_bytes()));
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_VERIFY_CODE, 0, 0, &d));
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    assert_eq!(deny.borrow().1, 1);
    // A confirmed press lets the correct code verify.
    let confirm = RefCell::new(StubPresence(Presence::Confirmed, 0));
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &confirm);
    let mut d = tlv(TAG_NAME, b"h");
    d.extend(tlv(TAG_RESPONSE, &755224u32.to_be_bytes()));
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_VERIFY_CODE, 0, 0, &d));
    assert_eq!(sw, Sw::OK);
    assert_eq!(confirm.borrow().1, 1);
}

#[test]
fn validate_fails_closed_on_unreadable_code() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    // Plant a present-but-oversized (unreadable) access code directly, bypassing the
    // SET CODE bound, and lock the applet as a fresh SELECT would with a code present.
    let dev = Device {
        serial_hash: &[0x22; 32],
        serial_id: &SERIAL,
        otp_key: None,
    };
    let big = [0x21u8; OATH_CODE_MAX + 8];
    assert!(seal::seal_put(
        &dev,
        &mut fs,
        &mut CountRng(1),
        EF_OATH_CODE,
        &big
    ));
    app.validated = false;
    // VALIDATE must NOT unlock: the code cannot be read, so fail closed.
    let mut d = tlv(TAG_CHALLENGE, &[0u8; 8]);
    d.extend(tlv(TAG_RESPONSE, &[0u8; 20]));
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_VALIDATE, 0, 0, &d));
    assert_eq!(sw, Sw::DATA_INVALID);
    assert!(!app.validated);
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[]));
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
}

#[test]
fn get_credential_returns_pws_fields() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let mut d = put_data(b"site", 0x21, 6, SECRET_SHA1, true, None);
    d.extend(tlv(TAG_PWS_LOGIN, b"user"));
    d.extend(tlv(TAG_PWS_PASSWORD, b"hunter2"));
    d.extend(tlv(TAG_PWS_METADATA, b"meta"));
    assert_eq!(put(&mut app, &mut fs, &d), Sw::OK);

    let (sw, body) = run(
        &mut app,
        &mut fs,
        &apdu(INS_GET_CREDENTIAL, 0, 0, &tlv(TAG_NAME, b"site")),
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(find_tag(&body, TAG_NAME as u16), Some(&b"site"[..]));
    assert_eq!(find_tag(&body, TAG_PWS_LOGIN as u16), Some(&b"user"[..]));
    assert_eq!(
        find_tag(&body, TAG_PWS_PASSWORD as u16),
        Some(&b"hunter2"[..])
    );
    assert_eq!(find_tag(&body, TAG_PWS_METADATA as u16), Some(&b"meta"[..]));
    assert_eq!(
        find_tag(&body, TAG_PROPERTY as u16),
        Some(&[PROP_TOUCH][..])
    );

    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(INS_GET_CREDENTIAL, 0, 0, &tlv(TAG_NAME, b"nope")),
    );
    assert_eq!(sw, Sw::DATA_INVALID);
}

#[test]
fn calculate_all_mixes_response_kinds() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    put(
        &mut app,
        &mut fs,
        &put_data(b"totp", 0x21, 8, SECRET_SHA1, false, None),
    );
    put(
        &mut app,
        &mut fs,
        &put_data(b"hotp", 0x11, 6, SECRET_SHA1, false, None),
    );
    put(
        &mut app,
        &mut fs,
        &put_data(b"tuch", 0x21, 7, SECRET_SHA1, true, None),
    );

    let chal = tlv(TAG_CHALLENGE, &1u64.to_be_bytes());
    let (sw, body) = run(&mut app, &mut fs, &apdu(INS_CALC_ALL, 0, 0x01, &chal));
    assert_eq!(sw, Sw::OK);

    // Entry 1: full truncated TOTP response (RFC 6238 SHA-1 @ T=1), the eight
    // digits the credential was stored with.
    let mut expect = tlv(TAG_NAME, b"totp");
    expect.extend([TAG_RESPONSE + 1, 5, 8]);
    expect.extend(&94_287_082u32.to_be_bytes());
    // Entry 2: HOTP is not calculated in bulk.
    expect.extend(tlv(TAG_NAME, b"hotp"));
    expect.extend([TAG_NO_RESPONSE, 1, 6]);
    // Entry 3: touch-gated TOTP defers to individual CALCULATE.
    expect.extend(tlv(TAG_NAME, b"tuch"));
    expect.extend([TAG_TOUCH_RESPONSE, 1, 7]);
    assert_eq!(body, expect);

    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_CALC_ALL, 0, 0x02, &chal));
    assert_eq!(sw, Sw::INCORRECT_P1P2);
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_CALC_ALL, 0, 0x01, &[]));
    assert_eq!(sw, Sw::INCORRECT_PARAMS);
}

#[test]
fn calculate_rejects_unknowns() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    // Unknown credential name.
    let mut d = tlv(TAG_CHALLENGE, &1u64.to_be_bytes());
    d.extend(tlv(TAG_NAME, b"ghost"));
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_CALCULATE, 0, 1, &d));
    assert_eq!(sw, Sw::DATA_INVALID);
    // Missing challenge.
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &apdu(INS_CALCULATE, 0, 1, &tlv(TAG_NAME, b"x")),
    );
    assert_eq!(sw, Sw::INCORRECT_PARAMS);
    // Unknown algorithm nibble in a stored key fails cleanly. PUT refuses one
    // now (E34), so the fixture is planted the way a build before it stored one
    // — otherwise this asserts over an empty slot and proves nothing.
    assert_eq!(
        put(
            &mut app,
            &mut fs,
            &put_data(b"bad", 0x29, 6, SECRET_SHA1, false, None)
        ),
        Sw::INCORRECT_PARAMS,
    );
    let dev = Device {
        serial_hash: &[0x22; 32],
        serial_id: &SERIAL,
        otp_key: None,
    };
    let mut blob = tlv(TAG_NAME, b"bad");
    let mut key = vec![0x29u8, 6];
    key.extend_from_slice(SECRET_SHA1);
    blob.extend(tlv(TAG_KEY, &key));
    assert!(seal::seal_put(
        &dev,
        &mut fs,
        &mut CountRng(3),
        KeyFid::new(EF_OATH_CRED),
        &blob
    ));
    let mut d = tlv(TAG_CHALLENGE, &1u64.to_be_bytes());
    d.extend(tlv(TAG_NAME, b"bad"));
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_CALCULATE, 0, 1, &d));
    assert_eq!(sw, Sw::EXEC_ERROR);
    // Bad CLA and unknown INS.
    let (sw, _) = run(&mut app, &mut fs, &[0x80, INS_LIST, 0, 0]);
    assert_eq!(sw, Sw::CLA_NOT_SUPPORTED);
    let (sw, _) = run(&mut app, &mut fs, &[0x00, 0xEE, 0, 0]);
    assert_eq!(sw, Sw::INS_NOT_SUPPORTED);
}

#[test]
fn slots_fill_and_report_full() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    for i in 0..MAX_OATH_CRED {
        let name = [b'n', (i >> 8) as u8, i as u8];
        assert_eq!(
            put(
                &mut app,
                &mut fs,
                &put_data(&name, 0x21, 6, b"k0123456789abcdef", false, None)
            ),
            Sw::OK,
            "slot {i}"
        );
    }
    assert_eq!(
        put(
            &mut app,
            &mut fs,
            &put_data(b"overflow", 0x21, 6, SECRET_SHA1, false, None)
        ),
        Sw::FILE_FULL
    );
}

/// The firmware hands OATH a `RESP_CAP - 2 = 2036`-byte response slice
/// (firmware/src/ccid_handler.rs); the generic `run()` above uses 2048, which
/// truncates at a slightly different count. Reproduce the exact on-device
/// capacity so the enumeration cap matches the hardware.
const FW_RESP_CAP: usize = 2036;

fn run_fw(app: &mut OathApplet, fs: &mut Fs<RamStorage>, raw: &[u8]) -> (Sw, Vec<u8>) {
    let mut out = [0u8; FW_RESP_CAP];
    let mut res = ResBuf::new(&mut out);
    let apdu = Apdu::parse(raw).unwrap();
    let sw = Applet::process(app, &apdu, fs, &mut res);
    (sw, res.as_slice().to_vec())
}

/// Count short-form TLVs with `tag` in a response body.
fn count_tag(body: &[u8], tag: u8) -> usize {
    let (mut i, mut n) = (0usize, 0usize);
    while i + 2 <= body.len() {
        let len = body[i + 1] as usize;
        if body[i] == tag {
            n += 1;
        }
        i += 2 + len;
    }
    n
}

/// A distinct 12-byte account name `b"acct000000NNN"` (ykman-length), no alloc-fmt.
fn acct_name(i: u16) -> Vec<u8> {
    let mut n = b"acct00000000".to_vec();
    let mut v = i as u32;
    for p in (4..12).rev() {
        n[p] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    n
}

/// Drive a LIST / CALCULATE ALL across YKOATH SEND REMAINING (0xA5) pages,
/// concatenating each `61xx` frame's body until the final page returns OK.
fn enumerate_all(app: &mut OathApplet, fs: &mut Fs<RamStorage>, first: &[u8]) -> (usize, Vec<u8>) {
    let (mut sw, mut body) = run_fw(app, fs, first);
    let mut pages = 1;
    while sw == Sw::BYTES_REMAINING_00 {
        let (s, b) = run_fw(app, fs, &apdu(INS_SEND_REMAINING, 0, 0, &[]));
        sw = s;
        body.extend(b);
        pages += 1;
    }
    assert_eq!(sw, Sw::OK);
    (pages, body)
}

/// Regression for the OATH enumeration cap (HW-found 2026-07-15): a full store
/// (255 credentials) exceeds the single 2036-byte response frame, so LIST and
/// CALCULATE ALL used to silently `break` and return `Sw::OK` — a host saw only
/// ~135 / ~94 of them. With YKOATH `61xx` + SEND REMAINING pagination every
/// credential now surfaces across pages, the way ykman / Yubico Authenticator
/// already read a real YubiKey.
#[test]
fn list_and_calc_all_paginate_the_full_store() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    for i in 0..MAX_OATH_CRED {
        assert_eq!(
            put(
                &mut app,
                &mut fs,
                &put_data(&acct_name(i), 0x21, 6, SECRET_SHA1, false, None)
            ),
            Sw::OK,
            "slot {i}"
        );
    }

    // LIST spans multiple frames and enumerates all 255 — including the late
    // account the pre-fix single frame truncated out.
    let (pages, body) = enumerate_all(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[]));
    assert!(pages >= 2, "255 names cannot fit one 2036-byte frame");
    assert_eq!(count_tag(&body, TAG_NAME_LIST), MAX_OATH_CRED as usize);
    let late = acct_name(MAX_OATH_CRED - 1);
    assert!(
        body.windows(late.len()).any(|w| w == &late[..]),
        "the last account is now enumerated"
    );

    // CALCULATE ALL likewise pages through all 255.
    let chal = tlv(TAG_CHALLENGE, &1u64.to_be_bytes());
    let (pages, body) = enumerate_all(&mut app, &mut fs, &apdu(INS_CALC_ALL, 0, 0x01, &chal));
    assert!(pages >= 2);
    assert_eq!(count_tag(&body, TAG_NAME), MAX_OATH_CRED as usize);

    // Any command other than SEND REMAINING abandons a half-read page: after a
    // LIST returns 61xx, an unrelated CALCULATE clears the cursor, so the next
    // SEND REMAINING is an empty OK, not a stale resumed frame.
    let (sw, _) = run_fw(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[]));
    assert_eq!(sw, Sw::BYTES_REMAINING_00);
    let mut d = tlv(TAG_CHALLENGE, &1u64.to_be_bytes());
    d.extend(tlv(TAG_NAME, &acct_name(0)));
    let (sw, _) = run_fw(&mut app, &mut fs, &apdu(INS_CALCULATE, 0, 0x01, &d));
    assert_eq!(sw, Sw::OK);
    let (sw, body) = run_fw(&mut app, &mut fs, &apdu(INS_SEND_REMAINING, 0, 0, &[]));
    assert_eq!(sw, Sw::OK);
    assert!(body.is_empty(), "abandoned page must not resume");
}

/// A backend that stops accepting removals after `budget` of them, and yields keys
/// newest-first — standing in for the flash ring's write order, which is what
/// `for_each_key` really gives (not FID order).
struct TornStorage {
    inner: RamStorage,
    budget: usize,
    order: Vec<u16>,
}

impl TornStorage {
    fn new(budget: usize) -> Self {
        Self {
            inner: RamStorage::new(),
            budget,
            order: Vec::new(),
        }
    }
}

impl Storage for TornStorage {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.inner.read(fid, buf)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
        if !self.order.contains(&fid) {
            self.order.push(fid);
        }
        self.inner.write(fid, data)
    }
    fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
        if self.budget == 0 {
            return Err(rsk_sdk::error::Error::MemoryFatal);
        }
        self.budget -= 1;
        self.order.retain(|&f| f != fid);
        self.inner.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.inner.size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        // Write order, oldest first — the access code was set before the
        // credentials here, so a single-phase sweep would reach it first.
        for fid in self.order.clone() {
            f(fid);
        }
        true
    }
}

fn torn_fs(budget: usize) -> Fs<TornStorage> {
    let mut fs = Fs::new(TornStorage::new(budget));
    fs.scan();
    fs
}

/// The access code must outlive every credential it protects. `for_each_key`
/// yields in write order, so a one-phase sweep deletes whatever the ring reaches
/// first; a power cut there would leave the store readable with no code at all,
/// since `select` derives `validated` from `!code_set`.
#[test]
fn a_torn_reset_never_strips_the_access_code_first() {
    // Access code written first, so it sits earliest in the ring.
    let mut fs = torn_fs(2);
    fs.put(EF_OATH_CODE.get(), &[0xAB; 20]).unwrap();
    for i in 0..5u16 {
        fs.put(EF_OATH_CRED + i, &[0x11; 24]).unwrap();
    }

    // The sweep runs out of removals partway through the credentials.
    assert_eq!(wipe_oath(&mut fs), Err(Sw::MEMORY_FAILURE));

    // It must have spent them on credentials, never on the code.
    assert!(
        fs.has_data(EF_OATH_CODE.get()),
        "a partial wipe left the credentials unprotected"
    );
    let left = (0..5u16).filter(|i| fs.has_data(EF_OATH_CRED + i)).count();
    assert_eq!(left, 3, "the two removals went to credentials");
}

/// Audit run-36: `wipe_oath` carries the two-phase rule, but the device-wide
/// `Fs::factory_wipe` bypasses it entirely and takes its phase-2 set from the
/// firmware's union — which could not name this predicate while it was private, so
/// OATH was left out of it and a torn device reset served every surviving
/// credential with no access code at all. The predicate is `pub` for that caller;
/// assert it actually buys the ordering property on that path, for every prefix.
#[test]
fn the_exported_lock_predicate_protects_the_device_wide_wipe() {
    for budget in 0..8usize {
        // Access code first, so it sits earliest in the ring — the order a
        // single-phase sweep would delete it in.
        let mut fs = torn_fs(budget);
        fs.put(EF_OATH_CODE.get(), &[0xAB; 20]).unwrap();
        fs.put(EF_OTP_PIN, &[0x01; 34]).unwrap();
        for i in 0..5u16 {
            fs.put(EF_OATH_CRED + i, &[0x11; 24]).unwrap();
        }

        let _ = fs.factory_wipe(|_| false, is_oath_lock_fid);

        if (0..5u16).any(|i| fs.has_data(EF_OATH_CRED + i)) {
            assert!(
                fs.has_data(EF_OATH_CODE.get()),
                "budget {budget}: credentials outlived the access code, so the next \
                 SELECT would derive `validated` from its absence and serve them"
            );
        }
    }
}

#[test]
fn a_completed_reset_clears_credentials_and_the_code() {
    let mut fs = torn_fs(usize::MAX);
    fs.put(EF_OATH_CODE.get(), &[0xAB; 20]).unwrap();
    fs.put(EF_OTP_PIN, &[0x01; 34]).unwrap();
    for i in 0..5u16 {
        fs.put(EF_OATH_CRED + i, &[0x11; 24]).unwrap();
    }
    assert_eq!(wipe_oath(&mut fs), Ok(()));
    assert!(!fs.has_data(EF_OATH_CODE.get()));
    assert!(!fs.has_data(EF_OTP_PIN));
    assert!((0..5u16).all(|i| !fs.has_data(EF_OATH_CRED + i)));
}

/// An OTP PIN the owner set must be required before the password-safe secrets
/// are served, on the code-less applet that is the shipping default.
///
/// `validated` was the only gate, and `select()` sets it unconditionally when no
/// access code is configured — so the PIN gated nothing: a fresh session that
/// presented no credential at all got the stored password back. `cmd_set_otp_pin`
/// already reasoned about that hole and defended itself with a touch; the two
/// commands that return secrets did not.
#[test]
fn an_otp_pin_is_required_before_the_password_safe_is_served() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(3));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], Some(test_mkek), &rng, &touch);
    select(&mut app, &mut fs);

    let mut cred = put_data(b"bank", 0x21, 6, SECRET_SHA1, false, None);
    cred.extend(tlv(TAG_PWS_PASSWORD, b"hunter2"));
    put(&mut app, &mut fs, &cred);
    let get = apdu(INS_GET_CREDENTIAL, 0, 0, &tlv(TAG_NAME, b"bank"));

    // No PIN and no code: an openly unprotected store, unchanged — YKOATH leaves
    // a code-less applet open and this is the same choice, made visibly.
    let (sw, body) = run(&mut app, &mut fs, &get);
    assert_eq!(sw, Sw::OK);
    assert!(find_tag(&body, TAG_PWS_PASSWORD as u16).is_some());

    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &apdu(INS_SET_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))
        )
        .0,
        Sw::OK
    );

    // A new session: SELECT re-opens the code-less applet, but the PIN now exists
    // and has not been presented.
    let mut app = OathApplet::new(SERIAL, [0x22; 32], Some(test_mkek), &rng, &touch);
    select(&mut app, &mut fs);
    let (sw, body) = run(&mut app, &mut fs, &get);
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    assert!(body.is_empty(), "a refusal carries no secret");

    // VERIFY CODE (0xB1) is the other reader and gets the same gate.
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &apdu(INS_VERIFY_CODE, 0, 0, &tlv(TAG_NAME, b"bank"))
        )
        .0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );

    // Present it, and the same session is served.
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))
        )
        .0,
        Sw::OK
    );
    let (sw, body) = run(&mut app, &mut fs, &get);
    assert_eq!(sw, Sw::OK);
    assert_eq!(
        find_tag(&body, TAG_PWS_PASSWORD as u16),
        Some(&b"hunter2"[..])
    );

    // A wrong PIN revokes the unlock the correct one granted.
    assert_ne!(
        run(
            &mut app,
            &mut fs,
            &apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, b"9999"))
        )
        .0,
        Sw::OK
    );
    assert_eq!(
        run(&mut app, &mut fs, &get).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );

    // And a re-SELECT does not inherit it.
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            &apdu(INS_VERIFY_PIN, 0, 0, &tlv(TAG_PASSWORD, b"1234"))
        )
        .0,
        Sw::OK
    );
    select(&mut app, &mut fs);
    assert_eq!(
        run(&mut app, &mut fs, &get).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
}
