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
    assert_eq!(run(&mut app, &mut fs, &c).1, Sw::WRONG_LENGTH);

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
    for new in [b"12345".as_slice(), &[0x39u8; consts::PIN_MAX_LEN + 1]] {
        let body = [consts::PW1_DEFAULT, new].concat();
        let mut c = vec![0x00, consts::INS_CHANGE_PIN, 0x00, consts::PW1_MODE81];
        c.push(body.len() as u8);
        c.extend_from_slice(&body);
        assert_eq!(run(&mut app, &mut fs, &c).1, Sw::WRONG_LENGTH);
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
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, Some([0x66; 32]), &rng, &presence);
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
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, Some([0x66; 32]), &rng, &presence);
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
    let mut app2 = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, Some([0x66; 32]), &rng, &presence);
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
    ] {
        assert_eq!(
            put(&mut app, &mut fs, 0x00, 0xC1, attr),
            crate::consts::WRONG_DATA,
            "accepted {attr:02x?}"
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
        consts::WRONG_DATA
    );
    assert_eq!(
        put(&mut app, &mut fs, 0x00, 0xD7, &[0x01]),
        consts::WRONG_DATA
    );

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

    // MSE: point the DECIPHER template (P2=0xA4) at key ref 3 → the AUT slot.
    let mse = [0x00, consts::INS_MSE, 0x41, 0xA4, 0x03, 0x83, 0x01, 0x03];
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
    assert_eq!(sw, consts::WRONG_DATA);
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
    // Generating the DEC key also mints a fresh AES key.
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
    // AES key minted on the DEC slot. The key is DEK-sealed (unknown host-side),
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
    assert_eq!(
        run(&mut app, &mut fs, &select_cert(3)).1,
        Sw::REFERENCE_NOT_FOUND
    );
    let mut bad_p2 = select_cert(0);
    bad_p2[3] = 0x00;
    assert_eq!(run(&mut app, &mut fs, &bad_p2).1, Sw::INCORRECT_P1P2);
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

    // PW3 still authorises INTERNAL AUTHENTICATE (it accepts PW2 or PW3).
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
    let mut sieve = rsk_rsa_asm::IncrementalSieve::new();
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
    let mut sieve = rsk_rsa_asm::IncrementalSieve::new();
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
