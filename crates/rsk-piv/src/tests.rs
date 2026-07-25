// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::ram::RamStorage;
use rsk_openpgp::keys::{Curve, PrivKey};

use std::cell::Cell;
use std::collections::HashMap;
use std::rc::Rc;

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use sha2::Digest;

const SERIAL: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const HASH: [u8; 32] = [0x22; 32];

/// Deterministic LCG randomness — good enough for nonces and prime search.
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

fn new_fs() -> Fs<RamStorage> {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    fs
}

fn select<S: Storage>(app: &mut PivApplet, fs: &mut Fs<S>) -> Vec<u8> {
    let mut out = [0u8; 256];
    let mut res = ResBuf::new(&mut out);
    let sw = Applet::select(app, false, fs, &mut res);
    assert_eq!(sw, Sw::OK);
    res.as_slice().to_vec()
}

fn apdu_bytes(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut raw = vec![0x00, ins, p1, p2];
    if data.is_empty() {
    } else if data.len() <= 255 {
        raw.push(data.len() as u8);
        raw.extend_from_slice(data);
    } else {
        raw.push(0);
        raw.extend_from_slice(&(data.len() as u16).to_be_bytes());
        raw.extend_from_slice(data);
    }
    raw
}

fn run<S: Storage>(
    app: &mut PivApplet,
    fs: &mut Fs<S>,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
) -> (Sw, Vec<u8>) {
    let raw = apdu_bytes(ins, p1, p2, data);
    let apdu = Apdu::parse(&raw).unwrap();
    let mut out = [0u8; 2048];
    let mut res = ResBuf::new(&mut out);
    let sw = Applet::process(app, &apdu, fs, &mut res);
    (sw, res.as_slice().to_vec())
}

/// Mutual-auth against the default AES-192 management key.
fn auth_mgm<S: Storage>(app: &mut PivApplet, fs: &mut Fs<S>) {
    let (sw, wit) = run(
        app,
        fs,
        INS_AUTHENTICATE,
        ALGO_AES192,
        0x9B,
        &[0x7C, 0x02, 0x80, 0x00],
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(&wit[..4], &[0x7C, 0x12, 0x80, 0x10]);
    let mut w: [u8; 16] = wit[4..20].try_into().unwrap();
    rsk_crypto::aes_ecb_decrypt_block(&DEFAULT_MGM, &mut w).unwrap();
    let host_chal = [0xA5u8; 16];
    let mut msg = vec![0x7C, 0x24, 0x80, 0x10];
    msg.extend_from_slice(&w);
    msg.push(0x81);
    msg.push(0x10);
    msg.extend_from_slice(&host_chal);
    let (sw, resp) = run(app, fs, INS_AUTHENTICATE, ALGO_AES192, 0x9B, &msg);
    assert_eq!(sw, Sw::OK);
    assert_eq!(&resp[..4], &[0x7C, 0x12, 0x82, 0x10]);
    let mut expect = host_chal;
    rsk_crypto::aes_ecb_encrypt_block(&DEFAULT_MGM, &mut expect).unwrap();
    assert_eq!(&resp[4..20], &expect);
}

fn verify_pin<S: Storage>(app: &mut PivApplet, fs: &mut Fs<S>) {
    let (sw, _) = run(app, fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN);
    assert_eq!(sw, Sw::OK);
}

fn gen_template(algo: u8) -> Vec<u8> {
    vec![0xAC, 0x03, 0x80, 0x01, algo]
}

/// Presence stand-in whose answer the test flips between calls.
struct Scripted {
    confirm: bool,
}
impl UserPresence for Scripted {
    fn request(&mut self, _confirm: rsk_sdk::Confirm<'_>) -> Presence {
        if self.confirm {
            Presence::Confirmed
        } else {
            Presence::Declined
        }
    }
}

/// Extract `point` from the keygen response `7F49 { 86 point }` (P-256 and
/// P-384 bodies use short-form lengths).
fn ec_point_of(resp: &[u8]) -> Vec<u8> {
    assert_eq!(&resp[..2], &[0x7F, 0x49]);
    let body = &resp[3..];
    assert_eq!(body[0], 0x86);
    let plen = body[1] as usize;
    body[2..2 + plen].to_vec()
}

#[test]
fn touch_policy_enforced_on_slot_sign() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(Scripted { confirm: true });
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    // Management auth: default mgm touch is NEVER, so no touch is consulted.
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    // Generate a P-256 key in 9A — default touch policy ALWAYS.
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0,
        0x9A,
        &gen_template(ALGO_ECCP256),
    );
    assert_eq!(sw, Sw::OK);
    let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9A, &[]);
    assert_eq!(sw, Sw::OK);
    assert_eq!(find_tag(&md, 0x02).unwrap()[1], TOUCHPOLICY_ALWAYS);
    let digest = [0x42u8; 32];
    let mut msg = vec![0x7C, 0x24, 0x82, 0x00, 0x81, 0x20];
    msg.extend_from_slice(&digest);
    // Touch declined → the sign is refused.
    pres.borrow_mut().confirm = false;
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_ECCP256,
        0x9A,
        &msg,
    );
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    // Touch confirmed → it proceeds.
    pres.borrow_mut().confirm = true;
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_ECCP256,
        0x9A,
        &msg,
    );
    assert_eq!(sw, Sw::OK);
}

#[test]
fn touch_policy_never_skips_presence() {
    // A slot generated with an explicit touch policy NEVER must not consult
    // presence — a declining button still lets the sign through.
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(Scripted { confirm: false });
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    // AC template with touch policy tag 0xAB = NEVER.
    let tmpl = vec![
        0xAC,
        0x06,
        0x80,
        0x01,
        ALGO_ECCP256,
        0xAB,
        0x01,
        TOUCHPOLICY_NEVER,
    ];
    let (sw, _) = run(&mut app, &mut fs, INS_ASYM_KEYGEN, 0, 0x9E, &tmpl);
    assert_eq!(sw, Sw::OK);
    let digest = [0x42u8; 32];
    let mut msg = vec![0x7C, 0x24, 0x82, 0x00, 0x81, 0x20];
    msg.extend_from_slice(&digest);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_ECCP256,
        0x9E,
        &msg,
    );
    assert_eq!(sw, Sw::OK);
}

#[test]
fn management_auth_preserves_pin_verification() {
    // age-plugin-yubikey first-run order: VERIFY PIN, THEN mutual-auth the 9B
    // management key, THEN use a pin-policy=ONCE slot key. The 9B key's stored
    // pin-policy is ALWAYS, but a mutual auth is not a key-slot operation, so it
    // must NOT clear the session PIN state — only an is_key sign does. Before the
    // fix the mgmt auth cleared has_pin and the slot sign failed with 6982.
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);

    verify_pin(&mut app, &mut fs); // has_pin set first…
    auth_mgm(&mut app, &mut fs); // …then the 9B (pin-policy ALWAYS) mutual auth.

    // Retired-slot key, pin-policy ONCE, touch NEVER (isolates the PIN check).
    let tmpl = vec![
        0xAC,
        0x09,
        0x80,
        0x01,
        ALGO_ECCP256,
        0xAA,
        0x01,
        PINPOLICY_ONCE,
        0xAB,
        0x01,
        TOUCHPOLICY_NEVER,
    ];
    let (sw, _) = run(&mut app, &mut fs, INS_ASYM_KEYGEN, 0, 0x82, &tmpl);
    assert_eq!(sw, Sw::OK);

    // pin-policy ONCE is satisfied by the earlier VERIFY — the sign must pass.
    let mut msg = vec![0x7C, 0x24, 0x82, 0x00, 0x81, 0x20];
    msg.extend_from_slice(&[0x42u8; 32]);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_ECCP256,
        0x82,
        &msg,
    );
    assert_eq!(
        sw,
        Sw::OK,
        "mgmt mutual auth must not clear the session PIN state"
    );
}

#[test]
fn select_returns_apt() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    let apt = select(&mut app, &mut fs);
    assert_eq!(apt[0], 0x61);
    assert_eq!(apt[1] as usize, apt.len() - 2, "APT length backpatched");
    let body = &apt[2..];
    // NIST SP 800-73-4 §3.1.1: outer 4F is the PIV AID/PIX, and 79 (coexistent
    // tag allocation authority) MUST wrap a nested 4F with the NIST RID — OpenSC's
    // piv_match_card rejects the card as PIV without it (falls back to OpenPGP).
    assert_eq!(
        find_tag(body, 0x4F).unwrap(),
        &[0x00, 0x00, 0x10, 0x00, 0x01, 0x00]
    );
    let taa = find_tag(body, 0x79).expect("coexistent tag allocation authority");
    assert_eq!(
        find_tag(taa, 0x4F).expect("nested 4F with NIST RID"),
        &[0xA0, 0x00, 0x00, 0x03, 0x08]
    );
    assert_eq!(find_tag(body, 0x50).unwrap(), b"RS-Key PIV");
    assert!(find_tag(body, 0xAC).is_some());
}

#[test]
fn select_skips_rescan_after_first() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();

    // First SELECT provisions the default files.
    select(&mut app, &mut fs);
    assert!(fs.has_data(EF_PIN), "first SELECT provisions the defaults");

    // Delete a default, then re-SELECT: the fast-path skips scan_files, so the
    // deleted file is NOT recreated (nothing removes it mid-power-cycle without a
    // reboot). On the pre-guard code scan_files would heal it and this fails.
    fs.delete(EF_PIN).unwrap();
    select(&mut app, &mut fs);
    assert!(
        !fs.has_data(EF_PIN),
        "re-SELECT must skip scan_files (deleted default not recreated)"
    );

    // A power cycle (fresh applet over the same fs) re-provisions the defaults.
    let mut app2 = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut app2, &mut fs);
    assert!(
        fs.has_data(EF_PIN),
        "a fresh applet re-provisions the defaults"
    );
}

#[test]
fn version_and_serial() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    let (sw, v) = run(&mut app, &mut fs, INS_VERSION, 0, 0, &[]);
    assert_eq!(sw, Sw::OK);
    assert_eq!(v, vec![5, 7, 4]);
    let (sw, s) = run(&mut app, &mut fs, INS_YK_SERIAL, 0, 0, &[]);
    assert_eq!(sw, Sw::OK);
    assert_eq!(s, rsk_mgmt::serial4(SERIAL).to_vec());
}

#[test]
fn pin_verify_retry_and_unblock() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    // Retry query on a fresh card.
    let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &[]);
    assert_eq!(sw, Sw::new(0x63, 0xC3));
    // Wrong PIN decrements.
    let wrong = [0x39u8; 8];
    let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &wrong);
    assert_eq!(sw, Sw::new(0x63, 0xC2));
    verify_pin(&mut app, &mut fs);
    // Success resets the counter and satisfies the empty-data query.
    let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &[]);
    assert_eq!(sw, Sw::OK);
    // P1=FF drops the security state.
    let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0xFF, 0x80, &[]);
    assert_eq!(sw, Sw::OK);
    let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &[]);
    assert_eq!(sw, Sw::new(0x63, 0xC3));
    // Block the PIN, then unblock with the PUK.
    for left in [2, 1] {
        let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &wrong);
        assert_eq!(sw, Sw::new(0x63, 0xC0 | left));
    }
    let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &wrong);
    assert_eq!(sw, Sw::PIN_BLOCKED);
    let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN);
    assert_eq!(sw, Sw::PIN_BLOCKED);
    let mut unblock = DEFAULT_PUK.to_vec();
    let newpin = *b"654321\xff\xff";
    unblock.extend_from_slice(&newpin);
    let (sw, _) = run(&mut app, &mut fs, INS_RESET_RETRY, 0, 0x80, &unblock);
    assert_eq!(sw, Sw::OK);
    let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &newpin);
    assert_eq!(sw, Sw::OK);
}

#[test]
fn change_pin_and_puk() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    let newpin = *b"00112233";
    let mut msg = DEFAULT_PIN.to_vec();
    msg.extend_from_slice(&newpin);
    let (sw, _) = run(&mut app, &mut fs, INS_CHANGE_PIN, 0, 0x80, &msg);
    assert_eq!(sw, Sw::OK);
    let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &newpin);
    assert_eq!(sw, Sw::OK);
    // Wrong old PIN burns a retry and reports it.
    let mut bad = DEFAULT_PIN.to_vec();
    bad.extend_from_slice(b"99999999");
    let (sw, _) = run(&mut app, &mut fs, INS_CHANGE_PIN, 0, 0x80, &bad);
    assert_eq!(sw, Sw::new(0x63, 0xC2));
    // PUK change.
    let mut msg = DEFAULT_PUK.to_vec();
    msg.extend_from_slice(b"87654321");
    let (sw, _) = run(&mut app, &mut fs, INS_CHANGE_PIN, 0, 0x81, &msg);
    assert_eq!(sw, Sw::OK);
}

/// The on-device (panel) PIN/PUK/unblock path: `pad_pin` + the shared
/// `change_reference` / `unblock_pin_with_puk` library fns must produce a state
/// a host (ykman / yubico-piv-tool, which always pads to 8 with 0xFF) accepts.
#[test]
fn panel_pin_ops_match_host_wire() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
    };

    // pad_pin builds the 8-byte PIV wire form (matches the stored defaults).
    assert_eq!(pad_pin(b"123456"), Some(DEFAULT_PIN));
    assert_eq!(pad_pin(b"12345678"), Some(DEFAULT_PUK));
    assert_eq!(pad_pin(b""), None);
    assert_eq!(pad_pin(b"123456789"), None);

    // Panel change-PIN: "123456" -> "654321", both padded as the panel will.
    let old = pad_pin(b"123456").unwrap();
    let new = pad_pin(b"654321").unwrap();
    assert_eq!(
        change_reference(&dev, &mut fs, PinRef::Pin, &old, &new),
        Sw::OK
    );
    // A host VERIFY (always padded) accepts the panel-set PIN...
    let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &new);
    assert_eq!(sw, Sw::OK);
    // ...and the unpadded 6-byte form does NOT — padding is load-bearing.
    let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, b"654321");
    assert_ne!(sw, Sw::OK);
    let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &new); // reset the burned retry
    assert_eq!(sw, Sw::OK);

    // Wrong old PIN burns a retry and leaves the PIN unchanged.
    let wrong = pad_pin(b"000000").unwrap();
    assert_eq!(
        change_reference(&dev, &mut fs, PinRef::Pin, &wrong, &old),
        Sw::new(0x63, 0xC2)
    );
    assert_eq!(reference_retries_left(&mut fs, PinRef::Pin), Some(2));
    let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &new);
    assert_eq!(sw, Sw::OK);

    // Panel change-PUK.
    let newpuk = pad_pin(b"87654321").unwrap();
    assert_eq!(
        change_reference(&dev, &mut fs, PinRef::Puk, &DEFAULT_PUK, &newpuk),
        Sw::OK
    );

    // Panel unblock: block the PIN, then reset it with the new PUK.
    for _ in 0..3 {
        let _ = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &wrong);
    }
    let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &new);
    assert_eq!(sw, Sw::PIN_BLOCKED);
    let fresh = pad_pin(b"111111").unwrap();
    assert_eq!(unblock_pin_with_puk(&dev, &mut fs, &newpuk, &fresh), Sw::OK);
    let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &fresh);
    assert_eq!(sw, Sw::OK);
    // Wrong PUK on unblock burns a PUK retry.
    let badpuk = pad_pin(b"00000000").unwrap();
    assert_eq!(
        unblock_pin_with_puk(&dev, &mut fs, &badpuk, &fresh),
        Sw::new(0x63, 0xC2)
    );
}

/// The PIN-protected management key (ykman `--protect`): a random AES-256 key
/// sealed in 0x9B, the ADMIN-DATA flag set, the key readable from PRINTED only
/// after a PIN VERIFY — and NOT readable at all until protection is enabled.
#[test]
fn pin_protected_mgm_key_roundtrip() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
    };
    let get = |id: [u8; 3]| [0x5C, 0x03, id[0], id[1], id[2]];
    const PRINTED: [u8; 3] = [0x5F, 0xC1, 0x09];
    const ADMIN: [u8; 3] = [0x5F, 0xFF, 0x00];

    // No leak: before protection PRINTED reads as absent (even though the
    // default mgmt key exists in 0x9B) — protection is opt-in.
    let (sw, _) = run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get(PRINTED));
    assert_eq!(sw, Sw::FILE_NOT_FOUND);

    // Protect: fresh random AES-256 key, sealed + flagged.
    assert_eq!(protect_mgm_key(&dev, &mut fs, &mut TestRng(42)), Sw::OK);

    // ADMIN DATA is readable WITHOUT a PIN, carrying the protected flag.
    let (sw, admin) = run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get(ADMIN));
    assert_eq!(sw, Sw::OK);
    assert_eq!(&admin, &[0x53, 0x05, 0x80, 0x03, 0x81, 0x01, 0x02]);

    // PRINTED is now flagged but PIN-gated.
    let (sw, _) = run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get(PRINTED));
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);

    // After a PIN VERIFY, PRINTED yields the wrapped 32-byte key.
    verify_pin(&mut app, &mut fs);
    let (sw, printed) = run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get(PRINTED));
    assert_eq!(sw, Sw::OK);
    assert_eq!(
        &printed[..6],
        &[0x53, 0x24, PROTECTED_TAG, 0x22, PROTECTED_MGM_TAG, 0x20]
    );
    let host_key: [u8; 32] = printed[6..38].try_into().unwrap();

    // The synthesized key equals the sealed 0x9B auth key (single source).
    let mut sealed = [0u8; 32];
    assert_eq!(
        seal::seal_read(&dev, &mut fs, key_fid(SLOT_CARDMGM), &mut sealed),
        Ok(32)
    );
    assert_eq!(host_key, sealed);

    // And the host-read key authenticates via AES-256 mutual auth.
    let (sw, wit) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_AES256,
        0x9B,
        &[0x7C, 0x02, 0x80, 0x00],
    );
    assert_eq!(sw, Sw::OK);
    let mut w: [u8; 16] = wit[4..20].try_into().unwrap();
    rsk_crypto::aes_ecb_decrypt_block(&host_key, &mut w).unwrap();
    let host_chal = [0xA5u8; 16];
    let mut msg = vec![0x7C, 0x24, 0x80, 0x10];
    msg.extend_from_slice(&w);
    msg.extend_from_slice(&[0x81, 0x10]);
    msg.extend_from_slice(&host_chal);
    let (sw, resp) = run(&mut app, &mut fs, INS_AUTHENTICATE, ALGO_AES256, 0x9B, &msg);
    assert_eq!(sw, Sw::OK);
    let mut expect = host_chal;
    rsk_crypto::aes_ecb_encrypt_block(&host_key, &mut expect).unwrap();
    assert_eq!(&resp[4..20], &expect);
}

/// A real ykman PivmanData carries a 16-byte salt + timestamp (~29 bytes), over the
/// parse buffer; `mgm_is_protected` must read its full stored length (`Storage::read`
/// returns the full length, not the copied count) without panicking and still find the
/// protected flag.
#[test]
fn mgm_is_protected_tolerates_oversized_admin_data() {
    let mut fs = new_fs();
    let mut inner = vec![PIVMAN_FLAGS_TAG, 0x01, PIVMAN_FLAG_MGM_PROTECTED];
    inner.extend_from_slice(&[0x82, 0x10]);
    inner.extend_from_slice(&[0u8; 16]); // salt
    inner.extend_from_slice(&[0x83, 0x04]);
    inner.extend_from_slice(&[0u8; 4]); // timestamp
    let mut admin = vec![PIVMAN_TAG, inner.len() as u8];
    admin.extend_from_slice(&inner);
    assert!(admin.len() > 16);
    fs.put(EF_PIVMAN_DATA, &admin).unwrap();
    assert!(mgm_is_protected(&mut fs));
}

#[test]
fn protect_mgm_preserves_timestamp_and_flags_drops_salt() {
    // Host-written PivmanData: an unrelated flag bit (0x01), a derived-key
    // salt, and a PIN-change timestamp. On-panel protect must keep the
    // timestamp and that flag bit, force MGM_PROTECTED, and drop the now
    // obsolete salt — ykman's `--protect` clears the salt identically.
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
    };
    let mut fs = new_fs();
    let mut inner = vec![PIVMAN_FLAGS_TAG, 0x01, 0x01];
    inner.extend_from_slice(&[0x82, 0x10]); // salt
    inner.extend_from_slice(&[0xAB; 16]);
    inner.extend_from_slice(&[PIVMAN_TS_TAG, 0x04, 0xDE, 0xAD, 0xBE, 0xEF]);
    let mut admin = vec![PIVMAN_TAG, inner.len() as u8];
    admin.extend_from_slice(&inner);
    fs.put(EF_PIVMAN_DATA, &admin).unwrap();

    assert_eq!(protect_mgm_key(&dev, &mut fs, &mut TestRng(42)), Sw::OK);
    assert!(mgm_is_protected(&mut fs));

    let mut out = [0u8; 64];
    let n = fs.read(EF_PIVMAN_DATA, &mut out).unwrap();
    let body = &out[..n];
    assert_eq!(body[0], PIVMAN_TAG);
    let inner = &body[2..2 + body[1] as usize];
    assert_eq!(
        find_tag(inner, PIVMAN_FLAGS_TAG as u16).unwrap(),
        &[0x01 | PIVMAN_FLAG_MGM_PROTECTED]
    );
    assert_eq!(
        find_tag(inner, PIVMAN_TS_TAG as u16).unwrap(),
        &[0xDE, 0xAD, 0xBE, 0xEF]
    );
    assert!(find_tag(inner, 0x82).is_none()); // salt dropped

    // With no prior record at all, protect still emits a minimal protected
    // object (flags only, no stray timestamp).
    let mut fs2 = new_fs();
    assert_eq!(protect_mgm_key(&dev, &mut fs2, &mut TestRng(9)), Sw::OK);
    let n2 = fs2.read(EF_PIVMAN_DATA, &mut out).unwrap();
    let inner2 = &out[2..2 + out[1] as usize];
    assert_eq!(n2, 5);
    assert_eq!(
        find_tag(inner2, PIVMAN_FLAGS_TAG as u16).unwrap(),
        &[PIVMAN_FLAG_MGM_PROTECTED]
    );
    assert!(find_tag(inner2, PIVMAN_TS_TAG as u16).is_none());
}

/// The escrow is an opt-in for ONE key: a host-planted ADMIN-DATA flag must not
/// survive SET MANAGEMENT KEY, so the rotated key is not PIN-readable from
/// PRINTED. The rest of the record (the PIN-change timestamp) survives.
#[test]
fn set_mgmkey_revokes_the_pin_protected_escrow() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    let get = |id: [u8; 3]| [0x5C, 0x03, id[0], id[1], id[2]];
    const PRINTED: [u8; 3] = [0x5F, 0xC1, 0x09];
    const ADMIN: [u8; 3] = [0x5F, 0xFF, 0x00];

    // Plant the flag the way a host does: PUT DATA on the ADMIN DATA object.
    let mut plant = vec![TAG_DATA_PATH, 0x03, 0x5F, 0xFF, 0x00, TAG_DATA_OBJECT, 0x0B];
    plant.extend_from_slice(&[PIVMAN_TAG, 0x09]);
    plant.extend_from_slice(&[PIVMAN_FLAGS_TAG, 0x01, PIVMAN_FLAG_MGM_PROTECTED]);
    plant.extend_from_slice(&[PIVMAN_TS_TAG, 0x04, 0xDE, 0xAD, 0xBE, 0xEF]);
    let (sw, _) = run(&mut app, &mut fs, INS_PUT_DATA, 0x3F, 0xFF, &plant);
    assert_eq!(sw, Sw::OK);
    verify_pin(&mut app, &mut fs);
    let (sw, _) = run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get(PRINTED));
    assert_eq!(
        sw,
        Sw::OK,
        "the planted flag discloses the key it was set for"
    );

    // Rotate the management key (ykman `change-management-key`, no --protect).
    let new_key = [0x5Au8; 24];
    let mut set_key = vec![ALGO_AES192, SLOT_CARDMGM, new_key.len() as u8];
    set_key.extend_from_slice(&new_key);
    let (sw, _) = run(&mut app, &mut fs, INS_SET_MGMKEY, 0xFF, 0xFF, &set_key);
    assert_eq!(sw, Sw::OK);

    // The rotated key is NOT disclosed: the flag went with the key it escrowed.
    assert!(!mgm_is_protected(&mut fs));
    let (sw, printed) = run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get(PRINTED));
    assert_eq!(sw, Sw::FILE_NOT_FOUND);
    assert!(printed.is_empty());
    let (sw, admin) = run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get(ADMIN));
    assert_eq!(sw, Sw::OK);
    let inner = find_tag(
        find_tag(&admin, TAG_DATA_OBJECT as u16).unwrap(),
        PIVMAN_TAG as u16,
    )
    .unwrap();
    assert_eq!(find_tag(inner, PIVMAN_FLAGS_TAG as u16).unwrap(), &[0x00]);
    assert_eq!(
        find_tag(inner, PIVMAN_TS_TAG as u16).unwrap(),
        &[0xDE, 0xAD, 0xBE, 0xEF]
    );

    // Opting back in still works: the host re-sets the flag for the new key.
    let (sw, _) = run(&mut app, &mut fs, INS_PUT_DATA, 0x3F, 0xFF, &plant);
    assert_eq!(sw, Sw::OK);
    let (sw, printed) = run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get(PRINTED));
    assert_eq!(sw, Sw::OK);
    assert_eq!(&printed[6..6 + new_key.len()], &new_key);
}

/// `Storage` that refuses to write one fid — a flash failure landing exactly on
/// SET MANAGEMENT KEY's seal write. The target is shared with the test so it can
/// be armed after the setup writes have landed.
struct RefuseWrite {
    inner: RamStorage,
    refuse: Rc<Cell<Option<u16>>>,
}

impl Storage for RefuseWrite {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.inner.read(fid, buf)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
        if self.refuse.get() == Some(fid) {
            return Err(rsk_sdk::error::Error::MemoryFatal);
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

/// SET MANAGEMENT KEY torn by a failed seal write: the escrow flag must still
/// describe the key that is STILL in 0x9B. Revoking it first would lock an owner
/// who only ever knew the key through PRINTED out of PIV administration, with a
/// status word that says nothing about it.
#[test]
fn failed_set_mgmkey_keeps_the_escrow_for_the_unchanged_key() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let refuse = Rc::new(Cell::new(None));
    let mut fs = Fs::new(RefuseWrite {
        inner: RamStorage::new(),
        refuse: Rc::clone(&refuse),
    });
    fs.scan();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);

    // Escrow the current (default) key the way ykman `--protect` does.
    let mut plant = vec![TAG_DATA_PATH, 0x03, 0x5F, 0xFF, 0x00, TAG_DATA_OBJECT, 0x05];
    plant.extend_from_slice(&[PIVMAN_TAG, 0x03]);
    plant.extend_from_slice(&[PIVMAN_FLAGS_TAG, 0x01, PIVMAN_FLAG_MGM_PROTECTED]);
    let (sw, _) = run(&mut app, &mut fs, INS_PUT_DATA, 0x3F, 0xFF, &plant);
    assert_eq!(sw, Sw::OK);
    let printed_id = [0x5C, 0x03, 0x5F, 0xC1, 0x09];
    let (sw, printed) = run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &printed_id);
    assert_eq!(sw, Sw::OK);
    assert_eq!(&printed[6..6 + DEFAULT_MGM.len()], &DEFAULT_MGM);

    // Rotate the key with the flash write of the sealed key failing.
    refuse.set(Some(key_fid(SLOT_CARDMGM).get()));
    let new_key = [0x5Au8; 24];
    let mut set_key = vec![ALGO_AES192, SLOT_CARDMGM, new_key.len() as u8];
    set_key.extend_from_slice(&new_key);
    let (sw, _) = run(&mut app, &mut fs, INS_SET_MGMKEY, 0xFF, 0xFF, &set_key);
    assert_eq!(sw, Sw::MEMORY_FAILURE);

    // The old key is untouched — and still reachable through the escrow.
    refuse.set(None);
    assert!(mgm_is_protected(&mut fs));
    let (sw, printed) = run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &printed_id);
    assert_eq!(sw, Sw::OK, "a failed rotation must not revoke the escrow");
    assert_eq!(&printed[6..6 + DEFAULT_MGM.len()], &DEFAULT_MGM);
}

/// Host stand-in for the `pivman_set_protected` Kani proof: an LCG-mutated
/// corpus of prior records (biased to start with the real tags) must always
/// yield a well-formed, protected, salt-free object — and a well-formed
/// timestamp must survive verbatim.
#[test]
fn pivman_set_protected_property_fuzz() {
    fn check(prior: &[u8]) {
        let mut out = [0u8; PIVMAN_MAX];
        let n = pivman_set_protected(prior, &mut out);
        assert!((5..=PIVMAN_MAX).contains(&n));
        assert_eq!(out[0], PIVMAN_TAG);
        assert_eq!(out[1] as usize, n - 2);
        let inner = &out[2..n];
        let flags = find_tag(inner, PIVMAN_FLAGS_TAG as u16).unwrap();
        assert_eq!(flags.len(), 1);
        assert!(flags[0] & PIVMAN_FLAG_MGM_PROTECTED != 0);
        assert!(find_tag(inner, 0x82).is_none()); // salt
        if inner.len() > 3 {
            assert_eq!(inner[3], PIVMAN_TS_TAG);
        }
    }

    for body in [
        &[][..],
        &[PIVMAN_TAG][..],
        &[PIVMAN_TAG, 0x00][..],
        &[PIVMAN_TAG, 0xFF][..],
        &[PIVMAN_TAG, 0x03, PIVMAN_FLAGS_TAG, 0x01, 0x00][..],
        &[0x81, 0x01, 0x02][..], // missing outer wrapper → nothing carried
    ] {
        check(body);
    }

    // A well-formed prior with flags + salt + timestamp: salt dropped, ts kept.
    let prior = {
        let mut inner = vec![PIVMAN_FLAGS_TAG, 0x01, 0x01, 0x82, 0x10]; // 0x82 = salt
        inner.extend_from_slice(&[0u8; 16]);
        inner.extend_from_slice(&[PIVMAN_TS_TAG, 0x04, 1, 2, 3, 4]);
        let mut rec = vec![PIVMAN_TAG, inner.len() as u8];
        rec.extend_from_slice(&inner);
        rec
    };
    let mut out = [0u8; PIVMAN_MAX];
    let n = pivman_set_protected(&prior, &mut out);
    let inner = &out[2..n];
    assert_eq!(
        find_tag(inner, PIVMAN_TS_TAG as u16).unwrap(),
        &[1, 2, 3, 4]
    );
    assert!(find_tag(inner, 0x82).is_none()); // salt dropped

    let mut lcg: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || -> u8 {
        lcg = lcg
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (lcg >> 33) as u8
    };
    for _ in 0..20000 {
        let len = (next() % 40) as usize;
        let mut b = Vec::with_capacity(len + 2);
        if next() & 1 != 0 {
            b.push(PIVMAN_TAG);
            b.push(next());
        }
        for _ in 0..len {
            b.push(next());
        }
        check(&b);
    }
}

#[test]
fn mgm_mutual_auth_gates_keygen() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0,
        0x9A,
        &gen_template(ALGO_ECCP256),
    );
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    let (sw, resp) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0,
        0x9A,
        &gen_template(ALGO_ECCP256),
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(&resp[..2], &[0x7F, 0x49]);
}

#[test]
fn mgm_single_auth() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    let (sw, chal) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_AES192,
        0x9B,
        &[0x7C, 0x02, 0x81, 0x00],
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(&chal[..4], &[0x7C, 0x12, 0x81, 0x10]);
    let mut enc: [u8; 16] = chal[4..20].try_into().unwrap();
    rsk_crypto::aes_ecb_encrypt_block(&DEFAULT_MGM, &mut enc).unwrap();
    let mut msg = vec![0x7C, 0x12, 0x82, 0x10];
    msg.extend_from_slice(&enc);
    let (sw, _) = run(&mut app, &mut fs, INS_AUTHENTICATE, ALGO_AES192, 0x9B, &msg);
    assert_eq!(sw, Sw::OK);
    // The gate is open now.
    verify_pin(&mut app, &mut fs);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0,
        0x9D,
        &gen_template(ALGO_ECCP256),
    );
    assert_eq!(sw, Sw::OK);
}

#[test]
fn mgm_single_auth_wrong_response_fails() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_AES192,
        0x9B,
        &[0x7C, 0x02, 0x81, 0x00],
    );
    assert_eq!(sw, Sw::OK);
    let mut msg = vec![0x7C, 0x12, 0x82, 0x10];
    msg.extend_from_slice(&[0u8; 16]);
    let (sw, _) = run(&mut app, &mut fs, INS_AUTHENTICATE, ALGO_AES192, 0x9B, &msg);
    assert_eq!(sw, Sw::DATA_INVALID);
    let (sw, _) = run(&mut app, &mut fs, INS_SET_RETRIES, 5, 5, &[]);
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
}

#[test]
fn single_auth_challenge_cannot_be_replayed_as_mutual_witness() {
    // Regression for the management-key bypass: single-auth step 1 returns the
    // challenge in plaintext; that value must NOT satisfy the mutual-auth step-2
    // witness check (which would set has_mgm with no knowledge of the key).
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    // Step 1: obtain the plaintext single-auth challenge C.
    let (sw, chal) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_AES192,
        0x9B,
        &[0x7C, 0x02, 0x81, 0x00],
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(&chal[..4], &[0x7C, 0x12, 0x81, 0x10]);
    let c: [u8; 16] = chal[4..20].try_into().unwrap();
    // Replay C as the mutual-auth step-2 witness (t80) — must be rejected.
    let mut msg = vec![0x7C, 0x24, 0x80, 0x10];
    msg.extend_from_slice(&c);
    msg.push(0x81);
    msg.push(0x10);
    msg.extend_from_slice(&[0u8; 16]);
    let (sw, _) = run(&mut app, &mut fs, INS_AUTHENTICATE, ALGO_AES192, 0x9B, &msg);
    assert_ne!(
        sw,
        Sw::OK,
        "single-auth challenge accepted as mutual witness"
    );
    // has_mgm must still be closed: a mgmt-gated op is refused.
    let (sw, _) = run(&mut app, &mut fs, INS_SET_RETRIES, 5, 5, &[]);
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
}

#[test]
fn mgm_encrypt_oracle_is_refused_and_cannot_forge_auth() {
    // Class invariant (run-6 CRITICAL + run-1 CRITICAL): NO GENERAL AUTHENTICATE
    // path reachable without prior auth may set has_mgm. The removed symmetric
    // tag-0x81 "internal authenticate" branch was an encrypt oracle: it returned
    // E(mgm, R) for the card's own single-auth challenge R, letting an attacker
    // forge the tag-0x82 response with zero key knowledge. Assert the oracle is
    // gone and has_mgm stays closed against a secret (unknown) key.
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    // Operator rotates 9B to a secret AES-256 key the attacker never learns.
    auth_mgm(&mut app, &mut fs);
    let secret = [0x5Au8; 32];
    let mut setk = vec![ALGO_AES256, 0x9B, 32];
    setk.extend_from_slice(&secret);
    assert_eq!(
        run(&mut app, &mut fs, INS_SET_MGMKEY, 0xFF, 0xFF, &setk).0,
        Sw::OK
    );
    // Fresh session: attacker with ZERO knowledge of `secret`.
    select(&mut app, &mut fs);
    // (1) single-auth step 1 -> plaintext challenge R.
    let (sw, chal) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_AES256,
        0x9B,
        &[0x7C, 0x02, 0x81, 0x00],
    );
    assert_eq!(sw, Sw::OK);
    let r: [u8; 16] = chal[4..20].try_into().unwrap();
    // (2) the former encrypt oracle: tag 0x81 non-empty must now be REFUSED
    // and leak no ciphertext.
    let mut orc = vec![0x7C, 0x12, 0x81, 0x10];
    orc.extend_from_slice(&r);
    let (sw, resp) = run(&mut app, &mut fs, INS_AUTHENTICATE, ALGO_AES256, 0x9B, &orc);
    assert_eq!(sw, Sw::INCORRECT_P1P2, "encrypt oracle must be refused");
    assert!(
        resp.is_empty() || !resp.windows(2).any(|w| w == [0x82, 0x10]),
        "no E(mgm, .) may be returned"
    );
    // (3) any guessed/garbage tag-0x82 response must fail (can't forge without E).
    let mut msg = vec![0x7C, 0x12, 0x82, 0x10];
    msg.extend_from_slice(&[0u8; 16]);
    let (sw, _) = run(&mut app, &mut fs, INS_AUTHENTICATE, ALGO_AES256, 0x9B, &msg);
    assert_ne!(sw, Sw::OK);
    // has_mgm must remain closed: a management-gated op is refused.
    assert_eq!(
        run(&mut app, &mut fs, INS_SET_RETRIES, 5, 5, &[]).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "has_mgm forged without the key"
    );
}

#[test]
fn mgm_challenge_bound_to_issuing_algorithm() {
    // Run-7 H2: a 9B challenge/witness issued under one algorithm must not be
    // answerable under another. AES-192 and 3DES share a 24-byte key, so the
    // length gate alone does not separate them — `chal_algo` binding does.
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    // Single-auth step 1 under AES-192 → plaintext challenge (chal_algo = AES-192).
    let (sw, chal) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_AES192,
        0x9B,
        &[0x7C, 0x02, 0x81, 0x00],
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(&chal[..4], &[0x7C, 0x12, 0x81, 0x10]);
    // Answer step 2 (tag 0x82) under 3DES (8-byte block) — refused before any
    // compare because the issuing algorithm differs.
    let mut d3 = vec![0x7C, 0x0A, 0x82, 0x08];
    d3.extend_from_slice(&[0u8; 8]);
    let (sw, _) = run(&mut app, &mut fs, INS_AUTHENTICATE, ALGO_3DES, 0x9B, &d3);
    assert_eq!(
        sw,
        Sw::INCORRECT_PARAMS,
        "cross-algo step-2 must be refused"
    );
    // has_mgm stays closed.
    let (sw, _) = run(&mut app, &mut fs, INS_SET_RETRIES, 5, 5, &[]);
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
}

#[test]
fn get_data_clamps_oversized_stored_object() {
    // Run-7 H3 (defense-in-depth): a stored object longer than the MAX_OBJECT
    // read buffer must be returned clamped, never panic on the slice. Only a raw
    // flash write can plant such a record (put_data caps at MAX_OBJECT); this
    // guards the reader regardless.
    let rng = RefCell::new(TestRng(1));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    // Plant a 2000-byte value at the 5FC100 object fid (0xD200), bypassing put_data.
    let big = [0xABu8; 2000];
    fs.put(object_fid(0x5F_C1_00).unwrap(), &big).unwrap();
    let (sw, resp) = run(
        &mut app,
        &mut fs,
        INS_GET_DATA,
        0x3F,
        0xFF,
        &[0x5C, 0x03, 0x5F, 0xC1, 0x00],
    );
    assert_eq!(sw, Sw::OK, "oversized object must not panic");
    // 0x53 wrapper (tag + 3-byte long-form length) around exactly MAX_OBJECT
    // bytes, not the planted 2000.
    assert_eq!(resp[0], 0x53);
    assert_eq!(resp.len(), 4 + MAX_OBJECT, "payload clamped to MAX_OBJECT");
}

#[cfg(feature = "fips-profile")]
#[test]
fn fips_refuses_3des_mgm_and_rsa1024() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    // A new 3DES management key is refused (SP 800-131A)…
    let mut msg = vec![ALGO_3DES, 0x9B, 24];
    msg.extend_from_slice(&DEFAULT_MGM);
    let (sw, _) = run(&mut app, &mut fs, INS_SET_MGMKEY, 0xFF, 0xFF, &msg);
    assert_eq!(sw, WRONG_DATA);
    // …and so is RSA-1024 generation.
    let tmpl = [0xAC, 0x03, 0x80, 0x01, ALGO_RSA1024];
    let (sw, _) = run(&mut app, &mut fs, INS_ASYM_KEYGEN, 0x00, 0x9A, &tmpl);
    assert_eq!(sw, WRONG_DATA);
    // AES management keys are unaffected.
    let mut msg = vec![ALGO_AES256, 0x9B, 32];
    msg.extend_from_slice(&[0x11; 32]);
    let (sw, _) = run(&mut app, &mut fs, INS_SET_MGMKEY, 0xFF, 0xFF, &msg);
    assert_eq!(sw, Sw::OK);
}

#[test]
fn mgm_3des_roundtrip() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    // Switch the management key to 3DES (same bytes, new type).
    let mut msg = vec![ALGO_3DES, 0x9B, 24];
    msg.extend_from_slice(&DEFAULT_MGM);
    let (sw, _) = run(&mut app, &mut fs, INS_SET_MGMKEY, 0xFF, 0xFF, &msg);
    assert_eq!(sw, Sw::OK);
    // Metadata reports the new type and no longer claims default…
    let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9B, &[]);
    assert_eq!(sw, Sw::OK);
    assert_eq!(find_tag(&md, 0x01).unwrap(), &[ALGO_3DES]);
    // …well, the bytes ARE the default key, just typed 3DES.
    assert_eq!(find_tag(&md, 0x05).unwrap(), &[1]);
    // Mutual auth over 8-byte 3DES blocks with well-formed TLVs.
    let (sw, wit) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_3DES,
        0x9B,
        &[0x7C, 0x02, 0x80, 0x00],
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(&wit[..4], &[0x7C, 0x0A, 0x80, 0x08]);
    let mut w: [u8; 8] = wit[4..12].try_into().unwrap();
    let key24: [u8; 24] = DEFAULT_MGM;
    rsk_crypto::des3_decrypt_block(&key24, &mut w);
    let host_chal = [0x5Au8; 8];
    let mut msg = vec![0x7C, 0x14, 0x80, 0x08];
    msg.extend_from_slice(&w);
    msg.push(0x81);
    msg.push(0x08);
    msg.extend_from_slice(&host_chal);
    let (sw, resp) = run(&mut app, &mut fs, INS_AUTHENTICATE, ALGO_3DES, 0x9B, &msg);
    assert_eq!(sw, Sw::OK);
    assert_eq!(&resp[..4], &[0x7C, 0x0A, 0x82, 0x08]);
    let mut expect = host_chal;
    rsk_crypto::des3_encrypt_block(&key24, &mut expect);
    assert_eq!(&resp[4..12], &expect);
}

#[test]
fn ec_metadata_point_is_cached_and_derive_fallback_matches() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    let (sw, _resp) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0,
        0x9A,
        &gen_template(ALGO_ECCP256),
    );
    assert_eq!(sw, Sw::OK);

    // The slot's meta record now carries the public point after the 4-byte head.
    let mut meta = [0u8; 4 + MAX_EC_POINT];
    let n = fs.meta_find(key_fid(0x9A).get(), &mut meta).unwrap();
    assert!(
        n > 4,
        "a generated EC slot caches its public point in the meta record"
    );

    // GET METADATA emits exactly that cached point (no d·G).
    let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9A, &[]);
    assert_eq!(sw, Sw::OK);
    let cached = find_tag(find_tag(&md, 0x04).unwrap(), 0x86)
        .unwrap()
        .to_vec();
    assert_eq!(&meta[4..n], &cached[..]);

    // Keygen also writes the per-slot pubkey cache file (read first, O(1) at any
    // slot count).
    assert!(
        fs.has_data(pubkey_fid(0x9A)),
        "keygen caches the point per-slot"
    );

    // Strip BOTH caches to model a key made by pre-cache firmware: GET METADATA
    // derives the point and must return the same bytes.
    fs.delete(pubkey_fid(0x9A)).unwrap();
    fs.meta_add(key_fid(0x9A).get(), &meta[..4]).unwrap();
    let (sw, md2) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9A, &[]);
    assert_eq!(sw, Sw::OK);
    let derived = find_tag(find_tag(&md2, 0x04).unwrap(), 0x86)
        .unwrap()
        .to_vec();
    assert_eq!(cached, derived, "derive fallback matches the cached point");
}

#[test]
fn ec_metadata_cache_is_best_effort_under_meta_pressure() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);

    // Stuff EF_META (META_MAX=1024, reserve=256) so a new EC slot has no room to
    // cache its ~65-byte point but ample room for its 4-byte head. Filler fid is
    // outside the PIV key_fid range (0xD1xx), so GET METADATA never reads it.
    let filler = [0u8; 740]; // record 744; point-budget (768) free = 24 < a P-256 record
    fs.meta_add(0xABCD, &filler).unwrap();

    let (sw, _resp) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0,
        0x9A,
        &gen_template(ALGO_ECCP256),
    );
    assert_eq!(
        sw,
        Sw::OK,
        "key still provisions when its point cannot be cached"
    );

    // Under the reserve the slot stored only its essential 4-byte head, no point.
    let mut meta = [0u8; 4 + MAX_EC_POINT];
    let n = fs.meta_find(key_fid(0x9A).get(), &mut meta).unwrap();
    assert_eq!(n, 4, "best-effort: no point cached under meta pressure");
    assert_eq!(
        meta[0], ALGO_ECCP256,
        "the algo head is intact for the gate"
    );

    // Under EF_META pressure the point is cached in the per-slot file instead, so
    // GET METADATA stays O(1) (no d·G) and still returns the correct public key.
    assert!(
        fs.has_data(pubkey_fid(0x9A)),
        "the per-slot pubkey file caches the point when EF_META is full"
    );
    let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9A, &[]);
    assert_eq!(sw, Sw::OK);
    let point = find_tag(find_tag(&md, 0x04).unwrap(), 0x86).unwrap();
    assert_eq!(point.len(), 65, "uncompressed P-256 point");
    assert_eq!(point[0], 0x04);
}

#[test]
fn keygen_p256_sign_and_verify() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    let (sw, resp) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0,
        0x9A,
        &gen_template(ALGO_ECCP256),
    );
    assert_eq!(sw, Sw::OK);
    let point = ec_point_of(&resp);
    assert_eq!(point.len(), 65);
    // Slot metadata.
    let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9A, &[]);
    assert_eq!(sw, Sw::OK);
    assert_eq!(find_tag(&md, 0x01).unwrap(), &[ALGO_ECCP256]);
    assert_eq!(
        find_tag(&md, 0x02).unwrap(),
        &[PINPOLICY_ONCE, TOUCHPOLICY_ALWAYS]
    );
    assert_eq!(find_tag(&md, 0x03).unwrap(), &[ORIGIN_GENERATED]);
    let pk = find_tag(&md, 0x04).unwrap();
    assert_eq!(find_tag(pk, 0x86).unwrap(), &point[..]);
    // Sign a digest, verify with the returned point.
    let digest: [u8; 32] = sha2::Sha256::digest(b"piv test message").into();
    let mut msg = vec![0x7C, 0x24, 0x82, 0x00, 0x81, 0x20];
    msg.extend_from_slice(&digest);
    let (sw, sig) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_ECCP256,
        0x9A,
        &msg,
    );
    assert_eq!(sw, Sw::OK);
    let dyn_auth = find_tag(&sig, 0x7C).unwrap();
    let der = find_tag(dyn_auth, 0x82).unwrap().to_vec();
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).unwrap();
    let psig = p256::ecdsa::Signature::from_der(&der).unwrap();
    vk.verify_prehash(&digest, &psig).unwrap();
}

#[test]
fn pin_policy_always_on_signature_slot() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0,
        0x9C,
        &gen_template(ALGO_ECCP256),
    );
    assert_eq!(sw, Sw::OK);
    let digest = [0x42u8; 32];
    let mut msg = vec![0x7C, 0x24, 0x82, 0x00, 0x81, 0x20];
    msg.extend_from_slice(&digest);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_ECCP256,
        0x9C,
        &msg,
    );
    assert_eq!(sw, Sw::OK);
    // PIN-always: the second signature needs a fresh VERIFY.
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_ECCP256,
        0x9C,
        &msg,
    );
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    verify_pin(&mut app, &mut fs);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_ECCP256,
        0x9C,
        &msg,
    );
    assert_eq!(sw, Sw::OK);
}

#[test]
fn cert_object_is_wrapped_and_parses() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    let (sw, resp) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0,
        0x9A,
        &gen_template(ALGO_ECCP256),
    );
    assert_eq!(sw, Sw::OK);
    let point = ec_point_of(&resp);
    let (sw, obj) = run(
        &mut app,
        &mut fs,
        INS_GET_DATA,
        0x3F,
        0xFF,
        &[0x5C, 0x03, 0x5F, 0xC1, 0x05],
    );
    assert_eq!(sw, Sw::OK);
    let body = find_tag(&obj, 0x53).unwrap();
    let cert = find_tag(body, 0x70).unwrap();
    assert_eq!(find_tag(body, 0x71).unwrap(), &[0x00]);
    let (_, parsed) = x509_parser::parse_x509_certificate(cert).unwrap();
    assert!(
        parsed
            .subject()
            .to_string()
            .contains("CN=RS-Key PIV Slot 9A")
    );
    // Self-signature verifies against the slot public key.
    let digest: [u8; 32] = sha2::Sha256::digest(parsed.tbs_certificate.as_ref()).into();
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).unwrap();
    let sig = p256::ecdsa::Signature::from_der(&parsed.signature_value.data).unwrap();
    vk.verify_prehash(&digest, &sig).unwrap();
}

#[test]
fn retired_slot_generate_then_cert_roundtrip() {
    // Reproduces the age-plugin-yubikey generate flow into a retired slot (its
    // "Slot 1" = PIV retired R1 = keyref 0x82, cert object 5FC10D). age-plugin
    // detects slot occupancy via Key::list, which reads each retired slot's
    // certificate — so the cert must persist and read back, else the slot shows
    // "(Empty)" and decryption can't find the identity.
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);

    let get_r1 = [0x5C, 0x03, 0x5F, 0xC1, 0x0D];
    // Fresh retired slot reads empty (the pre-generate occupancy check).
    let (sw, _) = run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get_r1);
    assert_eq!(sw, Sw::FILE_NOT_FOUND);

    // GENERATE into R1 (keyref 0x82).
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0,
        0x82,
        &gen_template(ALGO_ECCP256),
    );
    assert_eq!(sw, Sw::OK, "GENERATE into retired R1 must succeed");

    // Our GENERATE auto-writes a self-signed cert → the slot must read occupied.
    let (sw, obj) = run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get_r1);
    assert_eq!(
        sw,
        Sw::OK,
        "retired slot cert must be readable after GENERATE"
    );
    assert!(find_tag(&obj, 0x53).is_some());

    // age-plugin then PUT DATA its own self-signed cert (carrying the age OID).
    // A real P-256 age cert is ~400 bytes, so the 0x70/0x53 lengths are long-form
    // and the command is an extended-length APDU — the path a 10-byte fake misses.
    let cert_payload = vec![0xABu8; 390];
    let mut inner = vec![
        0x70,
        0x82,
        (cert_payload.len() >> 8) as u8,
        cert_payload.len() as u8,
    ];
    inner.extend_from_slice(&cert_payload);
    inner.extend_from_slice(&[0x71, 0x01, 0x00, 0xFE, 0x00]);
    let mut put = vec![
        0x5C,
        0x03,
        0x5F,
        0xC1,
        0x0D,
        0x53,
        0x82,
        (inner.len() >> 8) as u8,
        inner.len() as u8,
    ];
    put.extend_from_slice(&inner);
    let (sw, _) = run(&mut app, &mut fs, INS_PUT_DATA, 0x3F, 0xFF, &put);
    assert_eq!(sw, Sw::OK, "PUT DATA of the age cert must succeed");

    // The slot must still read occupied, now with the age cert.
    let (sw, obj2) = run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get_r1);
    assert_eq!(
        sw,
        Sw::OK,
        "retired slot cert must read back after PUT DATA"
    );
    assert_eq!(
        find_tag(&obj2, 0x53).and_then(|b| find_tag(b, 0x70)),
        Some(&cert_payload[..])
    );
}

#[test]
fn attestation_chains_to_f9() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0,
        0x9A,
        &gen_template(ALGO_ECCP256),
    );
    assert_eq!(sw, Sw::OK);
    let (sw, att) = run(&mut app, &mut fs, INS_ATTESTATION, 0x9A, 0, &[]);
    assert_eq!(sw, Sw::OK);
    let (_, att_cert) = x509_parser::parse_x509_certificate(&att).unwrap();
    assert!(
        att_cert
            .subject()
            .to_string()
            .contains("CN=RS-Key PIV Attestation 9A")
    );
    assert!(
        att_cert
            .issuer()
            .to_string()
            .contains("CN=RS-Key PIV Slot F9")
    );
    // The Yubico statement extensions are present.
    let oids: Vec<String> = att_cert
        .extensions()
        .iter()
        .map(|e| e.oid.to_id_string())
        .collect();
    for oid in [
        "1.3.6.1.4.1.41482.3.3",
        "1.3.6.1.4.1.41482.3.7",
        "1.3.6.1.4.1.41482.3.8",
        "1.3.6.1.4.1.41482.3.9",
    ] {
        assert!(oids.iter().any(|o| o == oid), "{oid} missing");
    }
    // The F9 certificate object verifies the attestation signature.
    let (sw, f9obj) = run(
        &mut app,
        &mut fs,
        INS_GET_DATA,
        0x3F,
        0xFF,
        &[0x5C, 0x03, 0x5F, 0xFF, 0x01],
    );
    assert_eq!(sw, Sw::OK);
    let f9cert = find_tag(find_tag(&f9obj, 0x53).unwrap(), 0x70).unwrap();
    let (_, f9) = x509_parser::parse_x509_certificate(f9cert).unwrap();
    let spk = &f9.tbs_certificate.subject_pki.subject_public_key.data;
    let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(spk).unwrap();
    let digest: [u8; 32] = sha2::Sha256::digest(att_cert.tbs_certificate.as_ref()).into();
    let sig = p384::ecdsa::Signature::from_der(&att_cert.signature_value.data).unwrap();
    use p384::ecdsa::signature::hazmat::PrehashVerifier as _;
    vk.verify_prehash(&digest, &sig).unwrap();
    // An imported key must not attest.
    let scalar = [0x11u8; 32];
    let mut imp = vec![0x06, 32];
    imp.extend_from_slice(&scalar);
    let (sw, _) = run(&mut app, &mut fs, INS_IMPORT_ASYM, ALGO_ECCP256, 0x9D, &imp);
    assert_eq!(sw, Sw::OK);
    let (sw, _) = run(&mut app, &mut fs, INS_ATTESTATION, 0x9D, 0, &[]);
    assert_eq!(sw, Sw::INCORRECT_PARAMS);
}

/// Generate an Ed25519 key, sign through GENERAL AUTHENTICATE and check the
/// self-signed certificate carries the RFC 8410 SPKI and a valid PureEdDSA
/// self-signature over the raw TBS.
#[test]
fn ed25519_generate_sign_and_self_signed_cert() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    let (sw, resp) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0,
        0x9A,
        &gen_template(ALGO_ED25519),
    );
    assert_eq!(sw, Sw::OK);
    let point = ec_point_of(&resp);
    assert_eq!(point.len(), 32);
    let pk: [u8; 32] = point.as_slice().try_into().unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).unwrap();

    // GET METADATA reports algo 0xE0 and the same 32-byte public key (tag 0x86).
    let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9A, &[]);
    assert_eq!(sw, Sw::OK);
    assert_eq!(find_tag(&md, 0x01).unwrap(), &[ALGO_ED25519]);
    let metapk = find_tag(find_tag(&md, 0x04).unwrap(), 0x86).unwrap();
    assert_eq!(metapk, &point[..]);

    // GENERAL AUTHENTICATE signs the raw message; the bare 64-byte sig verifies.
    let message = [0x42u8; 32];
    let mut msg = vec![0x7C, 0x24, 0x82, 0x00, 0x81, 0x20];
    msg.extend_from_slice(&message);
    let (sw, sig) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_ED25519,
        0x9A,
        &msg,
    );
    assert_eq!(sw, Sw::OK);
    let raw = find_tag(find_tag(&sig, 0x7C).unwrap(), 0x82).unwrap();
    assert_eq!(raw.len(), 64);
    let sigbytes: [u8; 64] = raw.try_into().unwrap();
    vk.verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&sigbytes))
        .unwrap();

    // The self-signed cert parses, names the slot and self-verifies.
    let (sw, obj) = run(
        &mut app,
        &mut fs,
        INS_GET_DATA,
        0x3F,
        0xFF,
        &[0x5C, 0x03, 0x5F, 0xC1, 0x05],
    );
    assert_eq!(sw, Sw::OK);
    let cert = find_tag(find_tag(&obj, 0x53).unwrap(), 0x70).unwrap();
    let (_, parsed) = x509_parser::parse_x509_certificate(cert).unwrap();
    assert!(
        parsed
            .subject()
            .to_string()
            .contains("CN=RS-Key PIV Slot 9A")
    );
    let csig: [u8; 64] = parsed.signature_value.data.as_ref().try_into().unwrap();
    vk.verify_strict(
        parsed.tbs_certificate.as_ref(),
        &ed25519_dalek::Signature::from_bytes(&csig),
    )
    .unwrap();
}

/// A key slot whose metadata is shorter than the [algo, pin, touch] header
/// (unreachable via normal writers — a defense-in-depth backstop) is rejected
/// by GENERAL AUTHENTICATE rather than reading policy from the zero-fill, which
/// would silently drop the touch gate.
#[test]
fn general_auth_rejects_short_meta() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0,
        0x9A,
        &gen_template(ALGO_ED25519),
    );
    assert_eq!(sw, Sw::OK);
    // Control: with the normal (4-byte) meta the sign succeeds.
    let message = [0x42u8; 32];
    let mut msg = vec![0x7C, 0x24, 0x82, 0x00, 0x81, 0x20];
    msg.extend_from_slice(&message);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_ED25519,
        0x9A,
        &msg,
    );
    assert_eq!(sw, Sw::OK);
    // Truncate the slot meta below the 3-byte [algo, pin, touch] header and
    // repeat: the guard fires (without it the missing bytes read as the zero-fill
    // and the sign would succeed, silently dropping the touch gate). Both 1- and
    // 2-byte records must be rejected — this pins the threshold at 3, not 2.
    for short in [&[ALGO_ED25519][..], &[ALGO_ED25519, PINPOLICY_ONCE][..]] {
        fs.meta_delete(key_fid(0x9A).get()).unwrap();
        fs.meta_add(key_fid(0x9A).get(), short).unwrap();
        let (sw, _) = run(
            &mut app,
            &mut fs,
            INS_AUTHENTICATE,
            ALGO_ED25519,
            0x9A,
            &msg,
        );
        assert_eq!(
            sw,
            Sw::REFERENCE_NOT_FOUND,
            "meta length {} must be rejected",
            short.len()
        );
    }
    // Exactly the 3-byte header is accepted (threshold is 3, not 4): a minimal
    // [algo, pin, touch] meta signs again.
    fs.meta_delete(key_fid(0x9A).get()).unwrap();
    fs.meta_add(
        key_fid(0x9A).get(),
        &[ALGO_ED25519, PINPOLICY_ONCE, TOUCHPOLICY_NEVER],
    )
    .unwrap();
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_ED25519,
        0x9A,
        &msg,
    );
    assert_eq!(sw, Sw::OK);
}

/// Generate an X25519 key: it gets no self-signed certificate (it can't sign),
/// and GENERAL AUTHENTICATE exponentiation (`ykman calculate-secret`) agrees a
/// shared secret that matches the host side.
#[test]
fn x25519_generate_has_no_cert_and_agrees() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    let (sw, resp) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0,
        0x9D,
        &gen_template(ALGO_X25519),
    );
    assert_eq!(sw, Sw::OK);
    let card_point = ec_point_of(&resp);
    assert_eq!(card_point.len(), 32);

    // No certificate was written for the slot (5FC10B, the 9D cert object).
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_GET_DATA,
        0x3F,
        0xFF,
        &[0x5C, 0x03, 0x5F, 0xC1, 0x0B],
    );
    assert_eq!(sw, Sw::FILE_NOT_FOUND);

    // calculate-secret: host public point in tag 0x85 → 32-byte shared secret.
    let host_scalar = [0x33u8; 32];
    let host_pub = x25519_dalek::x25519(host_scalar, x25519_dalek::X25519_BASEPOINT_BYTES);
    let mut msg = vec![0x7C, 0x22, 0x85, 0x20];
    msg.extend_from_slice(&host_pub);
    let (sw, secret) = run(&mut app, &mut fs, INS_AUTHENTICATE, ALGO_X25519, 0x9D, &msg);
    assert_eq!(sw, Sw::OK);
    let shared = find_tag(find_tag(&secret, 0x7C).unwrap(), 0x82).unwrap();
    let cardpk: [u8; 32] = card_point.as_slice().try_into().unwrap();
    let expected = x25519_dalek::x25519(host_scalar, cardpk);
    assert_eq!(shared, &expected[..]);
}

/// Import an Ed25519 seed (tag 0x07) and an X25519 scalar (tag 0x08) the way
/// `ykman piv keys import` does, then sign / agree with the imported keys.
#[test]
fn import_ed25519_and_x25519() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);

    let seed = [0x07u8; 32];
    let mut imp = vec![0x07, 32];
    imp.extend_from_slice(&seed);
    let (sw, _) = run(&mut app, &mut fs, INS_IMPORT_ASYM, ALGO_ED25519, 0x9A, &imp);
    assert_eq!(sw, Sw::OK);
    let vk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
    let message = [0x11u8; 32];
    let mut msg = vec![0x7C, 0x24, 0x82, 0x00, 0x81, 0x20];
    msg.extend_from_slice(&message);
    let (sw, sig) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_ED25519,
        0x9A,
        &msg,
    );
    assert_eq!(sw, Sw::OK);
    let raw = find_tag(find_tag(&sig, 0x7C).unwrap(), 0x82).unwrap();
    let sigbytes: [u8; 64] = raw.try_into().unwrap();
    vk.verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&sigbytes))
        .unwrap();

    // X25519 import into 9D; agree against the card's own reported public key
    // (GET METADATA) so the test is agnostic to the internal scalar endianness.
    let mut x_scalar = [0u8; 32];
    for (i, b) in x_scalar.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(1);
    }
    let mut imp = vec![0x08, 32];
    imp.extend_from_slice(&x_scalar);
    let (sw, _) = run(&mut app, &mut fs, INS_IMPORT_ASYM, ALGO_X25519, 0x9D, &imp);
    assert_eq!(sw, Sw::OK);
    let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9D, &[]);
    assert_eq!(sw, Sw::OK);
    let card_pub = find_tag(find_tag(&md, 0x04).unwrap(), 0x86)
        .unwrap()
        .to_vec();
    let host_scalar = [0x55u8; 32];
    let host_pub = x25519_dalek::x25519(host_scalar, x25519_dalek::X25519_BASEPOINT_BYTES);
    let mut msg = vec![0x7C, 0x22, 0x85, 0x20];
    msg.extend_from_slice(&host_pub);
    let (sw, secret) = run(&mut app, &mut fs, INS_AUTHENTICATE, ALGO_X25519, 0x9D, &msg);
    assert_eq!(sw, Sw::OK);
    let shared = find_tag(find_tag(&secret, 0x7C).unwrap(), 0x82).unwrap();
    let cardpk: [u8; 32] = card_pub.as_slice().try_into().unwrap();
    assert_eq!(shared, &x25519_dalek::x25519(host_scalar, cardpk)[..]);
}

/// Importing a *pre-existing* X25519 private key must make the slot adopt that
/// key's real public identity. ykman / yubico-piv-tool send the scalar
/// little-endian (RFC 8410); the card's reported public point therefore has to
/// equal the one standard tooling derives from the same bytes — otherwise
/// ciphertext or certs already bound to the public key can never be decrypted by
/// the slot. (The sibling test above is deliberately endianness-agnostic — it
/// agrees against the card's own key — so it cannot catch a flipped import; this
/// pins the byte order.)
#[test]
fn x25519_import_public_key_matches_host_derivation() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);

    // A non-palindromic scalar so a reversed byte order yields a different key.
    let mut d = [0u8; 32];
    for (i, b) in d.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(3);
    }
    let host_pub = x25519_dalek::x25519(d, x25519_dalek::X25519_BASEPOINT_BYTES);

    let mut imp = vec![0x08, 32];
    imp.extend_from_slice(&d);
    let (sw, _) = run(&mut app, &mut fs, INS_IMPORT_ASYM, ALGO_X25519, 0x9D, &imp);
    assert_eq!(sw, Sw::OK);

    let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9D, &[]);
    assert_eq!(sw, Sw::OK);
    let card_pub = find_tag(find_tag(&md, 0x04).unwrap(), 0x86).unwrap();
    assert_eq!(card_pub, &host_pub[..]);
}

/// An Ed25519 slot attests: the cert chains to F9 (P-384 ECDSA over the TBS)
/// and carries the RFC 8410 Ed25519 SPKI.
#[test]
fn ed25519_attestation_chains_to_f9() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0,
        0x9A,
        &gen_template(ALGO_ED25519),
    );
    assert_eq!(sw, Sw::OK);
    let (sw, att) = run(&mut app, &mut fs, INS_ATTESTATION, 0x9A, 0, &[]);
    assert_eq!(sw, Sw::OK);
    let (_, att_cert) = x509_parser::parse_x509_certificate(&att).unwrap();
    assert!(
        att_cert
            .subject()
            .to_string()
            .contains("CN=RS-Key PIV Attestation 9A")
    );
    // The attested SPKI is the 32-byte Ed25519 key.
    assert_eq!(
        att_cert
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .len(),
        32
    );
    // F9 (P-384) signs the attestation TBS.
    let (sw, f9obj) = run(
        &mut app,
        &mut fs,
        INS_GET_DATA,
        0x3F,
        0xFF,
        &[0x5C, 0x03, 0x5F, 0xFF, 0x01],
    );
    assert_eq!(sw, Sw::OK);
    let f9cert = find_tag(find_tag(&f9obj, 0x53).unwrap(), 0x70).unwrap();
    let (_, f9) = x509_parser::parse_x509_certificate(f9cert).unwrap();
    let spk = &f9.tbs_certificate.subject_pki.subject_public_key.data;
    let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(spk).unwrap();
    let digest: [u8; 32] = sha2::Sha256::digest(att_cert.tbs_certificate.as_ref()).into();
    let sig = p384::ecdsa::Signature::from_der(&att_cert.signature_value.data).unwrap();
    use p384::ecdsa::signature::hazmat::PrehashVerifier as _;
    vk.verify_prehash(&digest, &sig).unwrap();
}

/// The on-device RSA store path (the display's `Generate key` → RSA 2048): persist a
/// firmware-generated key into an empty retired slot, with the same add-never-overwrite
/// fence as the EC path. The slow prime search is the firmware's job; here we hand
/// `store_retired_rsa` a ready key.
#[test]
fn on_device_rsa_stores_into_empty_retired_slot() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
    };
    let key = rsk_openpgp::keys::generate_rsa(&mut TestRng(99), 1024).unwrap();
    let slot = info::next_free_retired(&mut fs).unwrap();
    assert!(info::store_retired_rsa(&dev, &mut fs, &mut TestRng(5), slot, &key).is_ok());
    // Reads back like a host-generated RSA slot: key + cert present, RSA meta, generated.
    assert!(fs.has_key(key_fid(slot)));
    assert!(fs.has_data(cert_fid_for_slot(slot).unwrap()));
    let mut meta = [0u8; 8];
    let n = fs.meta_find(key_fid(slot).get(), &mut meta).unwrap();
    assert!(n >= 4);
    assert_eq!(meta[0], ALGO_RSA1024); // a 1024-bit test key
    assert_eq!(meta[3], ORIGIN_GENERATED);
    // Add-never-overwrite: the now-occupied slot, and any non-retired slot, are refused.
    assert!(info::store_retired_rsa(&dev, &mut fs, &mut TestRng(5), slot, &key).is_err());
    assert!(
        info::store_retired_rsa(&dev, &mut fs, &mut TestRng(5), SLOT_AUTHENTICATION, &key).is_err()
    );
}

/// Buffer-sizing proof for the largest key: a real RSA-4096 key seals, gets a self-signed
/// cert that fits `MAX_CERT` and parses, and reads back as RSA-4096. Slow on host
/// (num-bigint, no asm), so `#[ignore]`d — run with `--ignored`.
#[test]
#[ignore = "full on-host RSA-4096 keygen — slow; run with --ignored"]
fn on_device_rsa4096_buffers_round_trip() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
    };
    let key = rsk_openpgp::keys::generate_rsa(&mut TestRng(99), 4096).unwrap();
    let slot = info::next_free_retired(&mut fs).unwrap();
    assert!(info::store_retired_rsa(&dev, &mut fs, &mut TestRng(5), slot, &key).is_ok());
    let mut meta = [0u8; 8];
    fs.meta_find(key_fid(slot).get(), &mut meta).unwrap();
    assert_eq!(meta[0], ALGO_RSA4096);
    // The self-signed cert fits MAX_CERT (the DER writer is bounds-checked) and parses; its
    // SPKI carries the 4096-bit key (≈526-byte RSAPublicKey, far larger than a 2048's ≈270).
    let mut obj = [0u8; 2048];
    let n = fs.read(cert_fid_for_slot(slot).unwrap(), &mut obj).unwrap();
    let cert = find_tag(&obj[..n], 0x70).unwrap();
    let (_, parsed) = x509_parser::parse_x509_certificate(cert).unwrap();
    assert!(parsed.subject().to_string().contains("Slot"));
    assert!(
        parsed
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .len()
            > 400
    );
    // Regression: the firmware fast-path (rsa_generate_finish) must tag a 4096 key as
    // RSA-4096, not silently RSA-2048.
    let mut resp = [0u8; 1024];
    let (_, sw) = app.rsa_generate_finish(
        &mut fs,
        &mut TestRng(5),
        0x83,
        [PINPOLICY_ONCE, TOUCHPOLICY_ALWAYS],
        &key,
        &mut resp,
    );
    assert_eq!(sw, Sw::OK);
    let mut m2 = [0u8; 8];
    fs.meta_find(key_fid(0x83).get(), &mut m2).unwrap();
    assert_eq!(m2[0], ALGO_RSA4096);
    // Regression: MOVE KEY's blob buffer must hold a 4096 sealed record (540 B), not panic
    // at the old 300-byte size. Move the stored 4096 key to another retired slot.
    auth_mgm(&mut app, &mut fs);
    let (sw, _) = run(&mut app, &mut fs, INS_MOVE_KEY, 0x84, slot, &[]);
    assert_eq!(sw, Sw::OK);
    assert!(fs.has_key(key_fid(0x84)));
}

#[test]
fn ecdh_on_key_management_slot() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    let (sw, resp) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0,
        0x9D,
        &gen_template(ALGO_ECCP256),
    );
    assert_eq!(sw, Sw::OK);
    let card_point = ec_point_of(&resp);
    use p256::elliptic_curve::sec1::ToSec1Point;
    let host_sk = p256::SecretKey::from_slice(&[7u8; 32]).unwrap();
    let host_pub_unc = host_sk.public_key().to_sec1_point(false);
    let mut msg = vec![0x7C, 0x45, 0x82, 0x00, 0x85, 0x41];
    msg.extend_from_slice(host_pub_unc.as_bytes());
    let (sw, out) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_ECCP256,
        0x9D,
        &msg,
    );
    assert_eq!(sw, Sw::OK);
    let dyn_auth = find_tag(&out, 0x7C).unwrap();
    let shared = find_tag(dyn_auth, 0x82).unwrap().to_vec();
    // Host-side ECDH against the card's public point.
    let card_pub = p256::PublicKey::from_sec1_bytes(&card_point).unwrap();
    let host_shared = p256::ecdh::diffie_hellman(host_sk.to_nonzero_scalar(), card_pub.as_affine());
    assert_eq!(shared, host_shared.raw_secret_bytes().as_slice());
}

#[test]
fn rsa1024_keygen_sign_verify_and_metadata() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    let (sw, resp) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0,
        0x9A,
        &gen_template(ALGO_RSA1024),
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(&resp[..2], &[0x7F, 0x49]);
    let body = &resp[5..];
    assert_eq!(body[0], 0x81);
    assert_eq!(body[1], 0x82);
    let nlen = u16::from_be_bytes([body[2], body[3]]) as usize;
    let n_bytes = &body[4..4 + nlen];
    assert_eq!(nlen, 128);
    // Build a PKCS#1 v1.5 EM for SHA-256 and have the card run the raw op.
    let digest: [u8; 32] = sha2::Sha256::digest(b"rsa piv").into();
    let mut em = vec![0x00, 0x01];
    let di = [
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    let pad = 128 - 3 - di.len() - digest.len();
    em.extend(core::iter::repeat_n(0xFF, pad));
    em.push(0x00);
    em.extend_from_slice(&di);
    em.extend_from_slice(&digest);
    assert_eq!(em.len(), 128);
    let mut msg = vec![0x7C, 0x81, 0x85, 0x82, 0x00, 0x81, 0x81, 0x80];
    msg.extend_from_slice(&em);
    let (sw, out) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_RSA1024,
        0x9A,
        &msg,
    );
    assert_eq!(sw, Sw::OK);
    let dyn_auth = find_tag(&out, 0x7C).unwrap();
    let sig = find_tag(dyn_auth, 0x82).unwrap().to_vec();
    assert_eq!(sig.len(), 128);
    // Verify the raw op: sig^e mod n must reproduce the EM (the leading
    // 0x00 is dropped by to_bytes_be).
    let n = rsa::BigUint::from_bytes_be(n_bytes);
    let m = rsa::BigUint::from_bytes_be(&sig).modpow(&rsa::BigUint::from(65537u32), &n);
    assert_eq!(m.to_bytes_be(), em[1..]);
    // Metadata exposes the same modulus.
    let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9A, &[]);
    assert_eq!(sw, Sw::OK);
    let pk = find_tag(&md, 0x04).unwrap();
    assert_eq!(find_tag(pk, 0x81).unwrap(), n_bytes);
    // The self-signed RSA certificate parses, names the slot and is signed
    // sha256WithRSAEncryption.
    let (sw, obj) = run(
        &mut app,
        &mut fs,
        INS_GET_DATA,
        0x3F,
        0xFF,
        &[0x5C, 0x03, 0x5F, 0xC1, 0x05],
    );
    assert_eq!(sw, Sw::OK);
    let cert = find_tag(find_tag(&obj, 0x53).unwrap(), 0x70).unwrap();
    let (_, parsed) = x509_parser::parse_x509_certificate(cert).unwrap();
    assert!(
        parsed
            .subject()
            .to_string()
            .contains("CN=RS-Key PIV Slot 9A")
    );
    assert_eq!(
        parsed.signature_algorithm.algorithm.to_id_string(),
        "1.2.840.113549.1.1.11"
    );
    // RSA-slot attestation: the P-384 F9 key signs with ecdsa-with-SHA256.
    let (sw, att) = run(&mut app, &mut fs, INS_ATTESTATION, 0x9A, 0, &[]);
    assert_eq!(sw, Sw::OK);
    let (_, att_cert) = x509_parser::parse_x509_certificate(&att).unwrap();
    assert_eq!(
        att_cert.signature_algorithm.algorithm.to_id_string(),
        "1.2.840.10045.4.3.2"
    );
}

#[test]
fn rsa_import_and_sign() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    let key = {
        let mut krng = TestRng(99);
        rsk_openpgp::keys::generate_rsa(&mut krng, 1024).unwrap()
    };
    use rsa::traits::PrivateKeyParts as _;
    let primes = key.primes();
    let p = primes[0].to_bytes_be();
    let q = primes[1].to_bytes_be();
    let mut imp = vec![0x01, p.len() as u8];
    imp.extend_from_slice(&p);
    imp.push(0x02);
    imp.push(q.len() as u8);
    imp.extend_from_slice(&q);
    let (sw, _) = run(&mut app, &mut fs, INS_IMPORT_ASYM, ALGO_RSA1024, 0x9E, &imp);
    assert_eq!(sw, Sw::OK);
    let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9E, &[]);
    assert_eq!(sw, Sw::OK);
    assert_eq!(find_tag(&md, 0x03).unwrap(), &[ORIGIN_IMPORTED]);
    use rsa::traits::PublicKeyParts as _;
    assert_eq!(
        find_tag(find_tag(&md, 0x04).unwrap(), 0x81).unwrap(),
        key.n().to_bytes_be()
    );
}

#[test]
fn objects_roundtrip_and_discovery() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    // Discovery needs no auth and is served raw.
    let (sw, disc) = run(
        &mut app,
        &mut fs,
        INS_GET_DATA,
        0x3F,
        0xFF,
        &[0x5C, 0x01, 0x7E],
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(disc, DISCOVERY);
    // PUT is management-gated.
    let chuid = [0x30, 0x19, 0xD4, 0xE7, 0x39, 0xDA];
    let mut put = vec![0x5C, 0x03, 0x5F, 0xC1, 0x02, 0x53, chuid.len() as u8];
    put.extend_from_slice(&chuid);
    let (sw, _) = run(&mut app, &mut fs, INS_PUT_DATA, 0x3F, 0xFF, &put);
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    auth_mgm(&mut app, &mut fs);
    let (sw, _) = run(&mut app, &mut fs, INS_PUT_DATA, 0x3F, 0xFF, &put);
    assert_eq!(sw, Sw::OK);
    let (sw, obj) = run(
        &mut app,
        &mut fs,
        INS_GET_DATA,
        0x3F,
        0xFF,
        &[0x5C, 0x03, 0x5F, 0xC1, 0x02],
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(find_tag(&obj, 0x53).unwrap(), &chuid);
    // Empty 53 deletes the host CHUID; the card then falls back to a synthesized
    // default (a valid GUID for the Windows minidriver) rather than answering 6A82.
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_PUT_DATA,
        0x3F,
        0xFF,
        &[0x5C, 0x03, 0x5F, 0xC1, 0x02, 0x53, 0x00],
    );
    assert_eq!(sw, Sw::OK);
    let (sw, obj) = run(
        &mut app,
        &mut fs,
        INS_GET_DATA,
        0x3F,
        0xFF,
        &[0x5C, 0x03, 0x5F, 0xC1, 0x02],
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(
        find_tag(&obj, 0x53).unwrap(),
        &crate::chuid::default_chuid(&HASH)
    );
    // Unknown object id.
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_GET_DATA,
        0x3F,
        0xFF,
        &[0x5C, 0x03, 0x5F, 0x00, 0x01],
    );
    assert_eq!(sw, Sw::FILE_NOT_FOUND);
}

#[test]
fn chuid_synthesized_on_fresh_card() {
    // A freshly flashed card with no host-written CHUID still serves one, so the
    // Windows PIV minidriver has the card GUID it needs to enumerate the slots
    // (issue #44 follow-up: without it, RSA/EC auth stays "pending" under CAPI).
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    let (sw, obj) = run(
        &mut app,
        &mut fs,
        INS_GET_DATA,
        0x3F,
        0xFF,
        &[0x5C, 0x03, 0x5F, 0xC1, 0x02],
    );
    assert_eq!(sw, Sw::OK);
    let body = find_tag(&obj, 0x53).unwrap();
    assert_eq!(body, &crate::chuid::default_chuid(&HASH));
    // The GUID (tag 34) is the serial-hash prefix: stable across reboots and
    // device-unique, so Windows never re-enrols the card.
    assert_eq!(&body[29..45], &HASH[..16]);
}

#[test]
fn pin_metadata_shapes() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x80, &[]);
    assert_eq!(sw, Sw::OK);
    assert_eq!(find_tag(&md, 0x05).unwrap(), &[1]);
    assert_eq!(find_tag(&md, 0x06).unwrap(), &[3, 3]);
    // Change the PIN: no longer default, and a burnt retry shows up.
    let mut msg = DEFAULT_PIN.to_vec();
    msg.extend_from_slice(b"violets8");
    let (sw, _) = run(&mut app, &mut fs, INS_CHANGE_PIN, 0, 0x80, &msg);
    assert_eq!(sw, Sw::OK);
    let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN);
    assert_eq!(sw, Sw::new(0x63, 0xC2));
    let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x80, &[]);
    assert_eq!(sw, Sw::OK);
    assert_eq!(find_tag(&md, 0x05).unwrap(), &[0]);
    assert_eq!(find_tag(&md, 0x06).unwrap(), &[3, 2]);
    // Management-key metadata shape.
    let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9B, &[]);
    assert_eq!(sw, Sw::OK);
    assert_eq!(find_tag(&md, 0x01).unwrap(), &[ALGO_AES192]);
    // Default management key ships touch-OFF (real-YubiKey behaviour).
    assert_eq!(
        find_tag(&md, 0x02).unwrap(),
        &[PINPOLICY_ALWAYS, TOUCHPOLICY_NEVER]
    );
    assert_eq!(find_tag(&md, 0x05).unwrap(), &[1]);
}

#[test]
fn move_and_delete_key() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0,
        0x9A,
        &gen_template(ALGO_ECCP256),
    );
    assert_eq!(sw, Sw::OK);
    // Move 9A → retired 0x82.
    let (sw, _) = run(&mut app, &mut fs, INS_MOVE_KEY, 0x82, 0x9A, &[]);
    assert_eq!(sw, Sw::OK);
    let (sw, _) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9A, &[]);
    assert_eq!(sw, Sw::REFERENCE_NOT_FOUND);
    let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x82, &[]);
    assert_eq!(sw, Sw::OK);
    assert_eq!(find_tag(&md, 0x01).unwrap(), &[ALGO_ECCP256]);
    // The certificate object moved with it.
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_GET_DATA,
        0x3F,
        0xFF,
        &[0x5C, 0x03, 0x5F, 0xC1, 0x05],
    );
    assert_eq!(sw, Sw::FILE_NOT_FOUND);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_GET_DATA,
        0x3F,
        0xFF,
        &[0x5C, 0x03, 0x5F, 0xC1, 0x0D],
    );
    assert_eq!(sw, Sw::OK);
    // Retired → active is rejected; delete works.
    let (sw, _) = run(&mut app, &mut fs, INS_MOVE_KEY, 0x9A, 0x82, &[]);
    assert_eq!(sw, Sw::INCORRECT_P1P2);
    let (sw, _) = run(&mut app, &mut fs, INS_MOVE_KEY, 0xFF, 0x82, &[]);
    assert_eq!(sw, Sw::OK);
    let (sw, _) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x82, &[]);
    assert_eq!(sw, Sw::REFERENCE_NOT_FOUND);
}

#[test]
fn move_key_same_slot_rejected() {
    // MOVE KEY onto its own slot (p1 == p2) must be rejected before any write:
    // the source-delete would otherwise erase the very slot just rewritten,
    // silently destroying the (possibly only) key while returning success.
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0,
        0x9A,
        &gen_template(ALGO_ECCP256),
    );
    assert_eq!(sw, Sw::OK);
    let (sw, _) = run(&mut app, &mut fs, INS_MOVE_KEY, 0x9A, 0x9A, &[]);
    assert_eq!(sw, Sw::INCORRECT_P1P2);
    // The key survives the rejected self-move.
    let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9A, &[]);
    assert_eq!(sw, Sw::OK);
    assert_eq!(find_tag(&md, 0x01).unwrap(), &[ALGO_ECCP256]);
}

#[test]
fn set_retries_and_reset_card() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0,
        0x9A,
        &gen_template(ALGO_ECCP256),
    );
    assert_eq!(sw, Sw::OK);
    let (sw, _) = run(&mut app, &mut fs, INS_SET_RETRIES, 5, 4, &[]);
    assert_eq!(sw, Sw::OK);
    let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x80, &[]);
    assert_eq!(sw, Sw::OK);
    assert_eq!(find_tag(&md, 0x06).unwrap(), &[5, 5]);
    // Reset requires both references blocked.
    let (sw, _) = run(&mut app, &mut fs, INS_RESET, 0, 0, &[]);
    assert_eq!(sw, Sw::INCORRECT_PARAMS);
    let wrong = [0x39u8; 8];
    for _ in 0..5 {
        let _ = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &wrong);
    }
    let mut bad_unblock = wrong.to_vec();
    bad_unblock.extend_from_slice(&wrong);
    for _ in 0..4 {
        let _ = run(&mut app, &mut fs, INS_RESET_RETRY, 0, 0x80, &bad_unblock);
    }
    let (sw, _) = run(&mut app, &mut fs, INS_RESET, 0, 0, &[]);
    assert_eq!(sw, Sw::OK);
    // Factory state: default PIN verifies, the generated key is gone.
    let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN);
    assert_eq!(sw, Sw::OK);
    let (sw, _) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9A, &[]);
    assert_eq!(sw, Sw::REFERENCE_NOT_FOUND);
    let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9B, &[]);
    assert_eq!(sw, Sw::OK);
    assert_eq!(find_tag(&md, 0x05).unwrap(), &[1]);
}

/// Every live PIV fid, in the range [`files::reset_files`] sweeps (de-duped: a
/// backend yields one entry per stored version).
fn piv_fids<S: Storage>(fs: &mut Fs<S>) -> Vec<u16> {
    let mut fids = Vec::new();
    fs.for_each_key(&mut |fid| {
        if files::is_piv_fid(fid) && !fids.contains(&fid) {
            fids.push(fid);
        }
    });
    fids.sort_unstable();
    fids
}

/// A host can stuff far more PIV files than one sweep batch holds (240 data
/// objects are writable through PUT DATA alone). RESET must converge over ALL of
/// them: a capped sweep left key slots live behind the re-seeded default PIN.
#[test]
fn reset_sweeps_more_files_than_one_batch() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);

    // Every host-writable data object: 5FC100..5FC1EF (5FC109 is the virtual
    // PRINTED object, never stored) plus the ADMIN DATA object 5FFF00.
    let put = |id: [u8; 3]| {
        [
            TAG_DATA_PATH,
            3,
            id[0],
            id[1],
            id[2],
            TAG_DATA_OBJECT,
            1,
            0x41,
        ]
    };
    for low in 0x00..=0xEFu8 {
        let (sw, _) = run(
            &mut app,
            &mut fs,
            INS_PUT_DATA,
            0x3F,
            0xFF,
            &put([0x5F, 0xC1, low]),
        );
        assert_eq!(sw, Sw::OK);
    }
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_PUT_DATA,
        0x3F,
        0xFF,
        &put([0x5F, 0xFF, 0x00]),
    );
    assert_eq!(sw, Sw::OK);
    // Plus key slots, each adding its sealed key and its cached public point.
    for slot in [0x9A, 0x9C, 0x9D, 0x9E, 0x82, 0x83, 0x84, 0x85] {
        let (sw, _) = run(
            &mut app,
            &mut fs,
            INS_ASYM_KEYGEN,
            0,
            slot,
            &gen_template(ALGO_ECCP256),
        );
        assert_eq!(sw, Sw::OK);
    }
    assert!(
        piv_fids(&mut fs).len() > 256,
        "the fill must exceed the old 8x32 sweep budget"
    );

    // Block both references, then RESET.
    let wrong = [0x39u8; 8];
    for _ in 0..3 {
        let _ = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &wrong);
    }
    let mut bad_unblock = wrong.to_vec();
    bad_unblock.extend_from_slice(&wrong);
    for _ in 0..3 {
        let _ = run(&mut app, &mut fs, INS_RESET_RETRY, 0, 0x80, &bad_unblock);
    }
    let (sw, _) = run(&mut app, &mut fs, INS_RESET, 0, 0, &[]);
    assert_eq!(sw, Sw::OK);

    // Only the factory files remain — no data object and no key slot but 9B/F9.
    let mut factory = vec![
        EF_PIN,
        EF_PUK,
        EF_RETRIES,
        key_fid(SLOT_CARDMGM).get(),
        key_fid(SLOT_ATTESTATION).get(),
        pubkey_fid(SLOT_ATTESTATION),
        EF_ATTESTATION_CERT,
    ];
    factory.sort_unstable();
    assert_eq!(piv_fids(&mut fs), factory);
    let (sw, _) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9A, &[]);
    assert_eq!(sw, Sw::REFERENCE_NOT_FOUND);
}

/// `Storage` whose `remove` reports success without deleting anything — a backend
/// the sweep can never converge over. RESET must then fail rather than report a
/// factory state it did not reach.
struct StubbornStorage(RamStorage);

impl Storage for StubbornStorage {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.0.read(fid, buf)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
        self.0.write(fid, data)
    }
    fn remove(&mut self, _fid: u16) -> rsk_sdk::error::Result<()> {
        Ok(())
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.0.size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        self.0.for_each_key(f)
    }
}

#[test]
fn reset_reports_failure_when_the_sweep_cannot_converge() {
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
    };
    let mut fs = Fs::new(StubbornStorage(RamStorage::new()));
    fs.scan();
    fs.put(data_object_fid(0x01).unwrap(), &[0x41]).unwrap();
    assert_eq!(
        reset_files(&dev, &mut fs, &mut TestRng(3)),
        Err(Sw::MEMORY_FAILURE)
    );
}

/// A failed sweep must not leave the applet without the files it just deleted:
/// the PIN/PUK/retry files go first, and a card missing them answers 6A88 (no
/// retry counters) to every later RESET instead of the honest 6581.
#[test]
fn failed_reset_reprovisions_instead_of_wedging_the_applet() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = Fs::new(StubbornStorage(RamStorage::new()));
    fs.scan();
    select(&mut app, &mut fs);
    let wrong = [0x39u8; 8];
    for _ in 0..3 {
        let _ = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &wrong);
    }
    let mut bad_unblock = wrong.to_vec();
    bad_unblock.extend_from_slice(&wrong);
    for _ in 0..3 {
        let _ = run(&mut app, &mut fs, INS_RESET_RETRY, 0, 0x80, &bad_unblock);
    }
    let (sw, _) = run(&mut app, &mut fs, INS_RESET, 0, 0, &[]);
    assert_eq!(sw, Sw::MEMORY_FAILURE);

    // Still a working card: the defaults are back, so RESET reports the real
    // precondition (references not blocked) and the default PIN verifies again.
    let (sw, _) = run(&mut app, &mut fs, INS_RESET, 0, 0, &[]);
    assert_eq!(
        sw,
        Sw::INCORRECT_PARAMS,
        "a failed RESET must not wedge on 6A88"
    );
    let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN);
    assert_eq!(sw, Sw::OK);
    assert!(
        !app.files_ensured,
        "SELECT must re-provision after a failed sweep"
    );
}

/// `Storage` modelling the log-structured backend's *versions*: an overwrite
/// supersedes rather than replaces, so `for_each_key` yields a fid once per
/// stored version until reclaim (`sequential-storage`'s `fetch_all_items`).
#[derive(Default)]
struct VersionedStorage {
    inner: RamStorage,
    versions: HashMap<u16, usize>,
}

impl Storage for VersionedStorage {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.inner.read(fid, buf)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
        self.inner.write(fid, data)?;
        *self.versions.entry(fid).or_default() += 1;
        Ok(())
    }
    fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
        self.versions.remove(&fid);
        self.inner.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.inner.size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        for (&fid, &versions) in &self.versions {
            for _ in 0..versions {
                f(fid);
            }
        }
        true
    }
}

/// The sweep's convergence budget must measure DELETED FILES, not passes: a host
/// that rewrites each of the 240 data objects ten times leaves ~2400 enumerated
/// versions over ~250 distinct fids, so a batch of 32 yields can carry a single
/// file. RESET must still reach the factory state instead of failing with keys
/// live and the PIN files already gone.
#[test]
fn reset_converges_over_multi_version_stuffing() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = Fs::new(VersionedStorage::default());
    fs.scan();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);

    let put = |id: [u8; 3]| {
        [
            TAG_DATA_PATH,
            3,
            id[0],
            id[1],
            id[2],
            TAG_DATA_OBJECT,
            1,
            0x41,
        ]
    };
    // 5FC109 is the virtual PRINTED object (acknowledged, never stored), so the
    // 240 objects that do land are 5FC100..5FC1EF minus it, plus ADMIN DATA.
    for _ in 0..10 {
        for low in 0x00..=0xEFu8 {
            let (sw, _) = run(
                &mut app,
                &mut fs,
                INS_PUT_DATA,
                0x3F,
                0xFF,
                &put([0x5F, 0xC1, low]),
            );
            assert_eq!(sw, Sw::OK);
        }
        let (sw, _) = run(
            &mut app,
            &mut fs,
            INS_PUT_DATA,
            0x3F,
            0xFF,
            &put([0x5F, 0xFF, 0x00]),
        );
        assert_eq!(sw, Sw::OK);
    }
    let mut yields = 0usize;
    fs.for_each_key(&mut |fid| {
        if files::is_piv_fid(fid) {
            yields += 1;
        }
    });
    let distinct = piv_fids(&mut fs).len();
    assert!(yields > 2400, "the fill must supersede, not replace");
    assert!(
        yields > distinct * 8,
        "the stuffing must starve an un-de-duped batch"
    );

    // Block both references, then RESET.
    let wrong = [0x39u8; 8];
    for _ in 0..3 {
        let _ = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &wrong);
    }
    let mut bad_unblock = wrong.to_vec();
    bad_unblock.extend_from_slice(&wrong);
    for _ in 0..3 {
        let _ = run(&mut app, &mut fs, INS_RESET_RETRY, 0, 0x80, &bad_unblock);
    }
    let (sw, _) = run(&mut app, &mut fs, INS_RESET, 0, 0, &[]);
    assert_eq!(sw, Sw::OK);

    // Only the factory files remain, and the default PIN is usable again.
    let mut factory = vec![
        EF_PIN,
        EF_PUK,
        EF_RETRIES,
        key_fid(SLOT_CARDMGM).get(),
        key_fid(SLOT_ATTESTATION).get(),
        pubkey_fid(SLOT_ATTESTATION),
        EF_ATTESTATION_CERT,
    ];
    factory.sort_unstable();
    assert_eq!(piv_fids(&mut fs), factory);
    let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN);
    assert_eq!(sw, Sw::OK);
}

/// `Storage` whose enumeration is truncated by a flash read fault: it yields
/// nothing and reports the walk incomplete, while the files are still there.
struct TruncatedWalk(RamStorage);

impl Storage for TruncatedWalk {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.0.read(fid, buf)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
        self.0.write(fid, data)
    }
    fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
        self.0.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.0.size(fid)
    }
    fn for_each_key(&mut self, _f: &mut dyn FnMut(u16)) -> bool {
        false
    }
}

/// An un-yielded fid is not an absent fid: a truncated walk must fail the reset
/// rather than report a factory state it only failed to look at.
#[test]
fn reset_fails_when_the_enumeration_is_truncated() {
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
    };
    let mut fs = Fs::new(TruncatedWalk(RamStorage::new()));
    fs.scan();
    let obj = data_object_fid(0x01).unwrap();
    fs.put(obj, &[0x41]).unwrap();
    assert_eq!(
        reset_files(&dev, &mut fs, &mut TestRng(3)),
        Err(Sw::MEMORY_FAILURE)
    );
    let mut buf = [0u8; 4];
    assert_eq!(fs.read(obj, &mut buf), Some(1), "the file was never swept");
}

#[test]
fn set_retries_requires_pin_not_just_mgmt() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    // Management alone (the public default key) must NOT reset the PIN: INS 0xFA
    // wipes PIN/PUK to defaults, so it also requires the current PIN (YubiKey).
    auth_mgm(&mut app, &mut fs);
    let (sw, _) = run(&mut app, &mut fs, INS_SET_RETRIES, 5, 4, &[]);
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    // With the PIN also verified it proceeds and applies the new totals.
    verify_pin(&mut app, &mut fs);
    let (sw, _) = run(&mut app, &mut fs, INS_SET_RETRIES, 5, 4, &[]);
    assert_eq!(sw, Sw::OK);
    let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x80, &[]);
    assert_eq!(sw, Sw::OK);
    assert_eq!(find_tag(&md, 0x06).unwrap(), &[5, 5]);
}

#[test]
fn management_gates() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    let scalar = [0x11u8; 32];
    let mut imp = vec![0x06, 32];
    imp.extend_from_slice(&scalar);
    let (sw, _) = run(&mut app, &mut fs, INS_IMPORT_ASYM, ALGO_ECCP256, 0x9D, &imp);
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    let mut setkey = vec![ALGO_AES192, 0x9B, 24];
    setkey.extend_from_slice(&DEFAULT_MGM);
    let (sw, _) = run(&mut app, &mut fs, INS_SET_MGMKEY, 0xFF, 0xFF, &setkey);
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    let (sw, _) = run(&mut app, &mut fs, INS_MOVE_KEY, 0x82, 0x9A, &[]);
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    // X25519 generates a key and returns its 32-byte public point (no
    // self-signed cert — it can't sign).
    auth_mgm(&mut app, &mut fs);
    let (sw, resp) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0,
        0x9A,
        &gen_template(ALGO_X25519),
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(ec_point_of(&resp).len(), 32);
    // Unknown INS.
    let (sw, _) = run(&mut app, &mut fs, 0x01, 0, 0, &[]);
    assert_eq!(sw, Sw::INS_NOT_SUPPORTED);
}

#[test]
fn keys_at_rest_are_sealed() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    let scalar = [0x11u8; 32];
    let mut imp = vec![0x06, 32];
    imp.extend_from_slice(&scalar);
    let (sw, _) = run(&mut app, &mut fs, INS_IMPORT_ASYM, ALGO_ECCP256, 0x9D, &imp);
    assert_eq!(sw, Sw::OK);
    // The raw file must not contain the scalar (GCM-sealed).
    let mut blob = [0u8; 300];
    let n = fs.read_key(key_fid(0x9D), &mut blob).unwrap();
    assert!(n > 32);
    assert!(!blob[..n].windows(32).any(|w| w == scalar));
}

/// `Storage` that eats EF_META writes once the budget runs out — a power cut with
/// the sealed key already on flash. The budget is shared with the test so the tear
/// can be armed after the setup writes have landed.
struct TornMeta {
    inner: RamStorage,
    meta_writes_left: Rc<Cell<usize>>,
}

impl Storage for TornMeta {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.inner.read(fid, buf)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
        if fid == rsk_fs::EF_META {
            let left = self.meta_writes_left.get();
            if left == 0 {
                return Err(rsk_sdk::error::Error::MemoryFatal);
            }
            self.meta_writes_left.set(left - 1);
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

/// IMPORT torn by a power cut between the sealed key and its origin record: the
/// slot must be left with NO record, so ATTESTATION (which is neither PIN- nor
/// management-gated) refuses instead of certifying the imported key as generated.
#[test]
fn torn_import_leaves_no_attestable_origin() {
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
    };
    let budget = Rc::new(Cell::new(usize::MAX));
    let mut fs = Fs::new(TornMeta {
        inner: RamStorage::new(),
        meta_writes_left: Rc::clone(&budget),
    });
    fs.scan();
    let mut rng = TestRng(7);
    scan_files(&dev, &mut fs, &mut rng).unwrap();
    let req = keygen::GenReq {
        algo: ALGO_ECCP256,
        pin_policy: None,
        touch_policy: None,
    };
    let mut out = [0u8; 2048];
    let mut res = ResBuf::new(&mut out);
    assert_eq!(
        keygen::generate_ec(&dev, &mut fs, &mut rng, 0x9A, &req, &mut res),
        Sw::OK
    );
    let mut res = ResBuf::new(&mut out);
    assert_eq!(
        keygen::attest(&dev, &mut fs, &mut rng, 0x9A, [0; 4], &mut res),
        Sw::OK,
        "the generated slot attests before the import"
    );

    // One EF_META write left: enough for the origin-record drop that has to
    // precede the key, not for the record that follows it. A build that does not
    // drop first spends the budget on the wrong write and lands elsewhere.
    budget.set(1);
    let scalar = [0x33u8; 32];
    let mut imp = vec![0x06, 32];
    imp.extend_from_slice(&scalar);
    let sess = Session {
        has_mgm: true,
        ..Default::default()
    };
    assert_eq!(
        keygen::import(&sess, &dev, &mut fs, &mut rng, ALGO_ECCP256, 0x9A, &imp),
        Sw::MEMORY_FAILURE
    );

    // The imported key IS live — this is the state the ordering has to survive.
    let live = seal::load_ec_key(&dev, &mut fs, key_fid(0x9A)).unwrap();
    let imported = PrivKey::from_scalar(Curve::P256, &scalar).unwrap();
    let (mut live_pt, mut imported_pt) = ([0u8; MAX_EC_POINT], [0u8; MAX_EC_POINT]);
    let ln = live.public_point(&mut live_pt).unwrap();
    let inl = imported.public_point(&mut imported_pt).unwrap();
    assert_eq!(&live_pt[..ln], &imported_pt[..inl]);

    // No origin record survived, so attestation fails closed.
    let mut meta = [0u8; 8];
    assert!(fs.meta_find(key_fid(0x9A).get(), &mut meta).is_none());
    let mut res = ResBuf::new(&mut out);
    assert_eq!(
        keygen::attest(&dev, &mut fs, &mut rng, 0x9A, [0; 4], &mut res),
        Sw::REFERENCE_NOT_FOUND,
        "an imported key must never inherit the slot's ORIGIN_GENERATED"
    );
}

#[test]
fn kbase_migration_reseals_slots_and_pin_falls_back() {
    const OTP: [u8; 32] = [0x44; 32];
    // Provision under a pre-OTP device: defaults + a generated 9A key.
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    let (sw, resp) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0,
        0x9A,
        &gen_template(ALGO_ECCP256),
    );
    assert_eq!(sw, Sw::OK);
    let point = ec_point_of(&resp);

    // The boot pass re-seals the key slots; a second run is a no-op.
    let dev_new = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: Some(&OTP),
    };
    migrate_kbase(&dev_new, &mut fs, &mut TestRng(9));
    migrate_kbase(&dev_new, &mut fs, &mut TestRng(11));

    // An OTP-build applet on the migrated state: the sealed management key
    // authenticates, the default PIN verifies via the fallback (and once
    // more directly against the re-stored verifier), and slot 9A signs with
    // the SAME key it had before the migration.
    let mut app2 = PivApplet::new(SERIAL, HASH, Some(OTP), &rng, &pres);
    select(&mut app2, &mut fs);
    auth_mgm(&mut app2, &mut fs);
    verify_pin(&mut app2, &mut fs);
    verify_pin(&mut app2, &mut fs);
    let digest: [u8; 32] = sha2::Sha256::digest(b"kbase migration").into();
    let mut msg = vec![0x7C, 0x24, 0x82, 0x00, 0x81, 0x20];
    msg.extend_from_slice(&digest);
    let (sw, sig) = run(
        &mut app2,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_ECCP256,
        0x9A,
        &msg,
    );
    assert_eq!(sw, Sw::OK);
    let dyn_auth = find_tag(&sig, 0x7C).unwrap();
    let der = find_tag(dyn_auth, 0x82).unwrap().to_vec();
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).unwrap();
    let psig = p256::ecdsa::Signature::from_der(&der).unwrap();
    vk.verify_prehash(&digest, &psig).unwrap();

    // A pre-OTP applet no longer accepts the migrated PIN verifier.
    let mut app3 = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut app3, &mut fs);
    let (sw, _) = run(&mut app3, &mut fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN);
    assert_eq!(sw, Sw::new(0x63, 0xC2));
}

/// Targeted property fuzz for the Pivman ADMIN-DATA (`5FFF00`) parse and the
/// PIN-protected PRINTED (`5FC109`) assembly. A management-key-authenticated
/// host can PUT *arbitrary* bytes into the ADMIN-DATA object; `mgm_is_protected`
/// then parses them, and that parse gates whether the (PIN-readable) wrapped
/// management key is disclosed. The contract under any stored bytes:
///   (a) the protected flag is set IFF a well-formed `80{81{..02..}}` says so —
///       a truncated/garbage record fails CLOSED (never spuriously protected);
///   (b) neither the parse nor the PRINTED assembly panics / reads OOB;
///   (c) when protection IS on, GET DATA `5FC109` discloses the key only after a
///       PIN VERIFY, and the wrapped key is exactly the sealed 0x9B mgmt key.
/// A deterministic enumeration (LCG-mutated PivmanData payloads, plus a
/// hand-picked adversarial corpus) stands in for libfuzzer so this runs in the
/// normal host gate. `protect_mgm_key` seeds the sealed 0x9B key once so the
/// PRINTED assembly path is reachable.
#[test]
fn pivman_printed_codec_property_fuzz() {
    const ADMIN: [u8; 3] = [0x5F, 0xFF, 0x00];
    const PRINTED: [u8; 3] = [0x5F, 0xC1, 0x09];

    // Oracle for the ADMIN-DATA protection flag, independent of the parser
    // under test: the record is `80 <l> { ... 81 <m> <flags..> ... }` and is
    // protected iff the FIRST 81 object inside the 80 body has a non-empty
    // value whose first byte has bit 0x02 set. Mirrors a strict ykman reader.
    fn oracle_protected(rec: &[u8]) -> bool {
        if rec.len() < 2 || rec[0] != PIVMAN_TAG {
            return false;
        }
        let inner_len = (rec[1] as usize).min(rec.len() - 2);
        let inner = &rec[2..2 + inner_len];
        let mut p = 0usize;
        while p < inner.len() {
            let tag = inner[p];
            p += 1;
            if p >= inner.len() {
                return false;
            }
            let l = inner[p] as usize;
            p += 1;
            if l > inner.len() - p {
                return false; // overrun → walker ends, tag not found
            }
            if tag == PIVMAN_FLAGS_TAG {
                return l > 0 && inner[p] & PIVMAN_FLAG_MGM_PROTECTED != 0;
            }
            p += l;
        }
        false
    }

    let put_admin = |app: &mut PivApplet, fs: &mut Fs<RamStorage>, body: &[u8]| -> Sw {
        // PUT DATA: 5C 03 5FFF00  53 <len> <body>
        let mut data = vec![0x5C, 0x03, ADMIN[0], ADMIN[1], ADMIN[2]];
        let mut ll = [0u8; 3];
        let n = format_len(body.len() as u16, &mut ll);
        data.push(0x53);
        data.extend_from_slice(&ll[..n]);
        data.extend_from_slice(body);
        run(app, fs, INS_PUT_DATA, 0x3F, 0xFF, &data).0
    };

    // Hand-picked adversarial PivmanData bodies (the value inside the 0x53).
    let corpus: Vec<Vec<u8>> = vec![
        vec![],                                                           // empty → delete
        vec![PIVMAN_TAG],                                                 // bare outer tag, no len
        vec![PIVMAN_TAG, 0x00],                                           // outer len 0, no inner
        vec![PIVMAN_TAG, 0xFF], // outer len overruns buffer
        vec![PIVMAN_TAG, 0x03, PIVMAN_FLAGS_TAG, 0x01, 0x02], // canonical protected
        vec![PIVMAN_TAG, 0x03, PIVMAN_FLAGS_TAG, 0x01, 0x00], // canonical NOT protected
        vec![PIVMAN_TAG, 0x02, PIVMAN_FLAGS_TAG, 0x01], // flag tag, len 1, value MISSING (truncated)
        vec![PIVMAN_TAG, 0x02, PIVMAN_FLAGS_TAG, 0x00], // flag tag, empty value
        vec![PIVMAN_TAG, 0x05, PIVMAN_FLAGS_TAG, 0x03, 0x02, 0x02, 0x02], // multi-byte flags, bit set
        vec![PIVMAN_TAG, 0x03, 0x82, 0x01, 0x02], // wrong inner tag (0x82 not 0x81)
        vec![PIVMAN_TAG, 0xFF, PIVMAN_FLAGS_TAG, 0x01, 0x02], // outer len 255 >> body; clamp must hold
        vec![PIVMAN_TAG, 0x03, PIVMAN_FLAGS_TAG, 0x01, 0xFF], // all flag bits incl 0x02
        vec![PIVMAN_TAG, 0x03, PIVMAN_FLAGS_TAG, 0x01, 0xFD], // every bit EXCEPT 0x02 → not protected
        vec![0x81, 0x01, 0x02],                               // missing outer 0x80 wrapper
        vec![
            PIVMAN_TAG,
            0x06,
            0x83,
            0x01,
            0x00,
            PIVMAN_FLAGS_TAG,
            0x01,
            0x02,
        ], // flag after another tag
        // Real ykman shape: flags + 16B salt + 4B timestamp.
        {
            let mut v = vec![PIVMAN_FLAGS_TAG, 0x01, 0x02, 0x82, 0x10];
            v.extend_from_slice(&[0u8; 16]);
            v.extend_from_slice(&[0x83, 0x04]);
            v.extend_from_slice(&[0u8; 4]);
            let mut rec = vec![PIVMAN_TAG, v.len() as u8];
            rec.extend_from_slice(&v);
            rec
        },
    ];

    // LCG-mutated bodies: random length 0..=80, random bytes, biased to start
    // with the real tags so the parser's deep branches are exercised.
    let mut lcg: u64 = 0x1234_5678_9abc_def1;
    let next = |lcg: &mut u64| -> u8 {
        *lcg = lcg
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (*lcg >> 33) as u8
    };
    let mut inputs = corpus;
    for _ in 0..4000 {
        let len = (next(&mut lcg) % 80) as usize;
        let mut b = Vec::with_capacity(len + 2);
        if next(&mut lcg) & 0x3 != 0 {
            b.push(PIVMAN_TAG);
            b.push(next(&mut lcg));
        }
        for _ in 0..len {
            b.push(next(&mut lcg));
        }
        inputs.push(b);
    }

    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
    };

    for body in inputs {
        if body.len() > MAX_OBJECT {
            continue; // PUT DATA rejects oversize before storage
        }
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        // Hold a management-key session FIRST (default AES-192 key), which is
        // what PUT DATA requires; then `protect_mgm_key` swaps 0x9B for a fresh
        // random key without touching the session, so PRINTED is reachable.
        auth_mgm(&mut app, &mut fs);
        assert_eq!(protect_mgm_key(&dev, &mut fs, &mut TestRng(42)), Sw::OK);

        let _ = put_admin(&mut app, &mut fs, &body);

        // (a) protection flag matches the independent oracle — no spurious flip.
        let stored = {
            let mut o = [0u8; 64];
            fs.read(EF_PIVMAN_DATA, &mut o)
                .map(|n| o[..n.min(o.len())].to_vec())
        };
        let oracle = stored.as_deref().map(oracle_protected).unwrap_or(false);
        let actual = mgm_is_protected(&mut fs);
        assert_eq!(
            actual, oracle,
            "protection flag disagrees with oracle for body {body:02x?}, stored {stored:02x?}",
        );

        // (b)+(c) GET DATA 5FC109 must not panic and must honour the gate.
        let get_printed = [0x5C, 0x03, PRINTED[0], PRINTED[1], PRINTED[2]];

        // Without a PIN: never discloses the key.
        let (sw_nopin, body_nopin) = run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get_printed);
        if actual {
            assert_eq!(sw_nopin, Sw::SECURITY_STATUS_NOT_SATISFIED);
        } else {
            assert_eq!(sw_nopin, Sw::FILE_NOT_FOUND);
        }
        assert!(body_nopin.is_empty() || sw_nopin != Sw::OK);

        // With a PIN verified: discloses ONLY if protection is on, and the
        // disclosed key is exactly the sealed 0x9B mgmt key (32B), TLV-wrapped.
        verify_pin(&mut app, &mut fs);
        let (sw_pin, out) = run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get_printed);
        if actual {
            assert_eq!(sw_pin, Sw::OK);
            assert_eq!(
                &out[..6],
                &[0x53, 0x24, PROTECTED_TAG, 0x22, PROTECTED_MGM_TAG, 0x20]
            );
            let mut sealed = [0u8; 32];
            let klen = seal::seal_read(&dev, &mut fs, key_fid(SLOT_CARDMGM), &mut sealed)
                .expect("sealed mgmt key present");
            assert_eq!(klen, 32);
            assert_eq!(&out[6..38], &sealed[..]);
        } else {
            assert_eq!(sw_pin, Sw::FILE_NOT_FOUND);
        }
    }
}
