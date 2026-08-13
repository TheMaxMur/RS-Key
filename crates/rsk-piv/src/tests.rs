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

/// P-256 GENERAL AUTHENTICATE over a fixed digest at `slot`.
fn sign_p256<S: Storage>(app: &mut PivApplet, fs: &mut Fs<S>, slot: u8) -> Sw {
    let mut msg = vec![0x7C, 0x24, 0x82, 0x00, 0x81, 0x20];
    msg.extend_from_slice(&[0x42u8; 32]);
    run(app, fs, INS_AUTHENTICATE, ALGO_ECCP256, slot, &msg).0
}

/// P-256 ECDH (tag 85) at 0x9D against `point`.
fn ecdh_p256<S: Storage>(app: &mut PivApplet, fs: &mut Fs<S>, point: &[u8]) -> Sw {
    let mut msg = vec![0x7C, 0x45, 0x82, 0x00, 0x85, 0x41];
    msg.extend_from_slice(point);
    run(app, fs, INS_AUTHENTICATE, ALGO_ECCP256, SLOT_KEYMGM, &msg).0
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
    // Generate a P-256 key in 9A asking for touch ALWAYS — the card's own default
    // is NEVER, so the policy under test has to be named.
    let mut tmpl = gen_template(ALGO_ECCP256);
    tmpl.extend_from_slice(&[0xAB, 0x01, TOUCHPOLICY_ALWAYS]);
    tmpl[1] += 3;
    let (sw, _) = run(&mut app, &mut fs, INS_ASYM_KEYGEN, 0, 0x9A, &tmpl);
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

/// SP 800-73-4 lists `6A80` for an undefined key reference and no `6A88` anywhere
/// in the VERIFY response table; a YubiKey 5.7.4 answers `6A80` to every P2 but
/// `80`, measured in both the case-1 and the `Le` form.
#[test]
fn verify_of_an_undefined_reference_is_wrong_data() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    for p2 in [0x00u8, 0x01, 0x04, 0x81, 0x82, 0x9B, 0xFF] {
        assert_eq!(
            run(&mut app, &mut fs, INS_VERIFY, 0, p2, &[]).0,
            Sw::WRONG_DATA,
            "P2 {p2:02X}"
        );
        assert_eq!(
            run(&mut app, &mut fs, INS_VERIFY, 0, p2, &DEFAULT_PIN).0,
            Sw::WRONG_DATA,
            "P2 {p2:02X} with data"
        );
    }
    // The one reference this application does have still answers its own status.
    assert_eq!(
        run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &[]).0,
        Sw::retries(3)
    );
}

/// SP 800-73-4 pt2 §2.4.3 fixes the reference at 8 bytes on the wire, and a body
/// that cannot be one is not a mismatch. Measured on a YubiKey 5.7.4, every
/// length taken in 1-16, 24 and 32 but 8: `6A80`, counter untouched — while the
/// 8-byte all-pad control burns on both cards, so it is a wire-form gate and not
/// a refusal to compare. Three malformed VERIFYs used to block our PIN.
///
/// Also pins the two cells the refusal has to get right beyond the counter: it
/// revokes the standing status, and it is judged ahead of the blocked floor, so a
/// blocked PIN answers `6A80` and not `6983`. Both measured on the oracle, 2 runs.
///
/// `Lc = 1` is the exception on both cards now, for the reason E182 measured: it
/// is refused above the whole applet, so VERIFY never runs and has no status to
/// take. This note used to call that the one divergence and keep the stricter
/// side of it — it was the rule's first sighting, one command wide.
#[test]
fn a_verify_body_that_is_not_the_wire_form_costs_no_retry() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    let body = [0x31u8; 32];
    for n in [1usize, 2, 4, 6, 7, 9, 16, 32] {
        assert_eq!(
            run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &body[..n]).0,
            Sw::WRONG_DATA,
            "{n}-byte body"
        );
        assert_eq!(
            reference_retries_left(&mut fs, PinRef::Pin),
            Some(3),
            "{n}-byte body cost a retry"
        );
    }
    // The control: a well-formed reference that is simply wrong still burns.
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            INS_VERIFY,
            0,
            0x80,
            &[PIN_PAD; PIN_WIRE_LEN]
        )
        .0,
        Sw::retries(2)
    );
    assert_eq!(reference_retries_left(&mut fs, PinRef::Pin), Some(2));
    // …and the standing status goes, as it does on a YubiKey — except at
    // `Lc = 1`, which never reaches this command on either card.
    for n in [6usize, 1] {
        verify_pin(&mut app, &mut fs);
        assert_eq!(run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &[]).0, Sw::OK);
        assert_eq!(
            run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &body[..n]).0,
            Sw::WRONG_DATA
        );
        assert_eq!(
            run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &[]).0,
            if n == 1 { Sw::OK } else { Sw::retries(3) },
            "a refused {n}-byte body and the standing status"
        );
    }
    // A wrong P1 or P2 is refused too and does NOT revoke — measured, and the
    // reason the rule above is about the wire form and not about refusals.
    verify_pin(&mut app, &mut fs);
    for (p1, p2) in [(0x01u8, 0x80u8), (0x00, 0x81)] {
        run(&mut app, &mut fs, INS_VERIFY, p1, p2, &DEFAULT_PIN);
        assert_eq!(
            run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &[]).0,
            Sw::OK,
            "P1 {p1:02X} P2 {p2:02X} revoked the standing status"
        );
    }
    // Blocked: the wire form is judged first, so a malformed body is 6A80 where
    // a well-formed one — right or wrong — is 6983.
    for _ in 0..3 {
        run(
            &mut app,
            &mut fs,
            INS_VERIFY,
            0,
            0x80,
            &[PIN_PAD; PIN_WIRE_LEN],
        );
    }
    assert_eq!(
        run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN).0,
        Sw::PIN_BLOCKED
    );
    assert_eq!(
        run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &body[..6]).0,
        Sw::WRONG_DATA
    );
    assert_eq!(
        run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &[]).0,
        Sw::PIN_BLOCKED
    );
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

/// VERIFY's own framing is one status word on the reference — `6A80` — where
/// ours had two: `6A86` for an undefined P1 and `6700` for `P1 = FF` carrying a
/// body. Measured on a YubiKey 5.7.4 over `01`, `02`, `7F`, `FE` and
/// `FF`-with-body, 3 runs byte-identical, and none of them moves the standing PIN
/// status. Only a malformed *body* at `P1 = 00` drops it — a different rule that
/// stays.
///
/// Both PIN states, deliberately: with the axis walked only on a verified card, a
/// gate reading `p1 != 00 && p1 != FF && has_pin` passed the whole suite while
/// serving the retry counter — and a wrong-P1 VERIFY — to an unverified caller.
#[test]
fn verify_refuses_its_own_framing_with_one_status_word() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    for verified in [false, true] {
        if verified {
            verify_pin(&mut app, &mut fs);
        }
        for p1 in [0x01u8, 0x02, 0x7F, 0xFE] {
            for body in [&[][..], &DEFAULT_PIN[..]] {
                assert_eq!(
                    run(&mut app, &mut fs, INS_VERIFY, p1, 0x80, body).0,
                    Sw::WRONG_DATA,
                    "VERIFY P1={p1:02X} with {} body bytes, verified={verified}",
                    body.len()
                );
            }
        }
        // `P1 = FF` names the reset, so a body makes it a VERIFY the card cannot
        // read — not a length error.
        for body in [&DEFAULT_PIN[..], &[0x41][..]] {
            assert_eq!(
                run(&mut app, &mut fs, INS_VERIFY, 0xFF, 0x80, body).0,
                Sw::WRONG_DATA,
                "VERIFY P1=FF with {} body bytes, verified={verified}",
                body.len()
            );
        }
        // The control the loop turns on: none of the refusals above moved the
        // PIN state in either direction, so the retry query still answers what it
        // did before them — the full counter unverified, `9000` verified.
        let want = if verified {
            Sw::OK
        } else {
            Sw::new(0x63, 0xC3)
        };
        assert_eq!(
            run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &[]).0,
            want,
            "retry query after the refusals, verified={verified}"
        );
    }
    // The two P1 values the command does define still do their own jobs.
    assert_eq!(
        run(&mut app, &mut fs, INS_VERIFY, 0xFF, 0x80, &[]).0,
        Sw::OK
    );
    assert_eq!(
        run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &[]).0,
        Sw::new(0x63, 0xC3)
    );
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

/// CHANGE REFERENCE DATA and RESET RETRY COUNTER answer `6A88` — *reference not
/// found* — to a key reference they do not have, and to a P1 that is not `00`.
/// Not `6A86`: measured on a YubiKey 5.7.4 over P2 `00`/`01`/`04`/`82`/`9B`/`FF`
/// (plus `81` on `2C`) and P1 `01`/`FF`, each with no body, a 16-byte body and a
/// 4-byte one, 3 runs byte-identical.
///
/// The asymmetry is the point, and is why this cell had to be measured rather
/// than derived: on the same card, in the same session, **`VERIFY`'s undefined
/// reference is `6A80` and these two are `6A88`**. Both axes answer alike here —
/// an undefined P1 is a reference that is not found, not a wrong parameter.
#[test]
fn an_undefined_pin_reference_is_not_found() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    let mut pair = DEFAULT_PIN.to_vec();
    pair.extend_from_slice(&DEFAULT_PIN);
    let bodies: [&[u8]; 3] = [&[], &pair, b"ABCD"];

    for verified in [false, true] {
        if verified {
            verify_pin(&mut app, &mut fs);
        }
        for body in bodies {
            for p2 in [0x00u8, 0x01, 0x04, 0x82, 0x9B, 0xFF] {
                assert_eq!(
                    run(&mut app, &mut fs, INS_CHANGE_PIN, 0, p2, body).0,
                    Sw::REFERENCE_NOT_FOUND,
                    "CHANGE P2={p2:02X} body={} verified={verified}",
                    body.len()
                );
            }
            // `2C` unblocks the PIN with the PUK, so `81` names no reference here
            // even though `24` accepts it.
            for p2 in [0x00u8, 0x01, 0x04, 0x81, 0x82, 0x9B, 0xFF] {
                assert_eq!(
                    run(&mut app, &mut fs, INS_RESET_RETRY, 0, p2, body).0,
                    Sw::REFERENCE_NOT_FOUND,
                    "RESET RETRY P2={p2:02X} body={} verified={verified}",
                    body.len()
                );
            }
            for p1 in [0x01u8, 0xFF] {
                for p2 in [0x80u8, 0x55] {
                    assert_eq!(
                        run(&mut app, &mut fs, INS_CHANGE_PIN, p1, p2, body).0,
                        Sw::REFERENCE_NOT_FOUND,
                        "CHANGE P1={p1:02X} P2={p2:02X} verified={verified}"
                    );
                    assert_eq!(
                        run(&mut app, &mut fs, INS_RESET_RETRY, p1, p2, body).0,
                        Sw::REFERENCE_NOT_FOUND,
                        "RESET RETRY P1={p1:02X} P2={p2:02X} verified={verified}"
                    );
                }
            }
            // Both halves of the measurement, after every body: on the oracle the
            // counters stayed at `03 03` and a standing PIN status survived the
            // whole sweep. The second is the one with teeth — `set_pin` also
            // refreshes `pin_fresh`, so a refusal that set it would hand an
            // unauthenticated caller a gate that PINPOLICY_ALWAYS slots, the Table 3
            // objects and SET RETRIES all read.
            for ref_ in [0x80u8, 0x81] {
                let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, ref_, &[]);
                assert_eq!(sw, Sw::OK);
                assert_eq!(
                    find_tag(&md, 0x06).unwrap(),
                    &[3, 3],
                    "retries at {ref_:02X} after body={}",
                    body.len()
                );
            }
            assert_eq!(
                run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &[]).0,
                if verified {
                    Sw::OK
                } else {
                    Sw::new(0x63, 0xC3)
                },
                "standing PIN status after body={} verified={verified}",
                body.len()
            );
        }
        // A *defined* reference under the same malformed bodies is `6A80`, not
        // `6A88` — measured on the oracle, both cells — so the two refusals stay
        // tellable apart and the sweep above is not a blanket answer.
        for (ins, p2) in [
            (INS_CHANGE_PIN, 0x80u8),
            (INS_CHANGE_PIN, 0x81),
            (INS_RESET_RETRY, 0x80),
        ] {
            for body in [&[][..], b"ABCD"] {
                assert_eq!(
                    run(&mut app, &mut fs, ins, 0, p2, body).0,
                    Sw::WRONG_DATA,
                    "INS {ins:02X} P2={p2:02X} body={} verified={verified}",
                    body.len()
                );
            }
        }
    }
    let mut chg = DEFAULT_PIN.to_vec();
    chg.extend_from_slice(b"00112233");
    assert_eq!(
        run(&mut app, &mut fs, INS_CHANGE_PIN, 0, 0x80, &chg).0,
        Sw::OK
    );
    let mut unblock = DEFAULT_PUK.to_vec();
    unblock.extend_from_slice(&DEFAULT_PIN);
    assert_eq!(
        run(&mut app, &mut fs, INS_RESET_RETRY, 0, 0x80, &unblock).0,
        Sw::OK
    );
}

/// A CHANGE REFERENCE DATA / RESET RETRY COUNTER body is two wire forms, and
/// nothing else. Ours split at the *stored* length and handed the whole
/// remainder over as the new value, so `8 ‖ 6` stored a six-byte reference that
/// no conformant host can ever present again — and with the PUK shortened the
/// same way, only a card-destroying RESET got out. A YubiKey 5.7.4 answers
/// `6A80` to every body but 16 bytes, judged *before* the old half, so a wrong
/// old reference in a malformed body costs no retry either (3 runs per cell).
#[test]
fn a_reference_change_takes_two_wire_forms_or_nothing() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    let short = b"654321";
    let full = b"654321\xff\xff";
    for (ins, p2, old) in [
        (INS_CHANGE_PIN, 0x80u8, &DEFAULT_PIN),
        (INS_CHANGE_PIN, 0x81, &DEFAULT_PUK),
        (INS_RESET_RETRY, 0x80, &DEFAULT_PUK),
    ] {
        for new in [&short[..], &short[..4], b"654321\xff\xff\xff"] {
            let mut msg = old.to_vec();
            msg.extend_from_slice(new);
            assert_eq!(
                run(&mut app, &mut fs, ins, 0, p2, &msg).0,
                Sw::WRONG_DATA,
                "INS {ins:02X} P2 {p2:02X} with a {}-byte new value",
                new.len()
            );
        }
        // The old half alone, and a short old half, are the same refusal.
        assert_eq!(run(&mut app, &mut fs, ins, 0, p2, old).0, Sw::WRONG_DATA);
        let mut msg = old[..6].to_vec();
        msg.extend_from_slice(full);
        assert_eq!(run(&mut app, &mut fs, ins, 0, p2, &msg).0, Sw::WRONG_DATA);
        // …and a WRONG old reference inside a malformed body costs no retry —
        // under the wire form and over it, since only the length gate can refuse
        // an over-long body before the comparison runs.
        for tail in [&short[..], b"654321\xff\xff\xff"] {
            let mut msg = [0x39u8; PIN_WIRE_LEN].to_vec();
            msg.extend_from_slice(tail);
            assert_eq!(run(&mut app, &mut fs, ins, 0, p2, &msg).0, Sw::WRONG_DATA);
        }
    }
    assert_eq!(reference_retries_left(&mut fs, PinRef::Pin), Some(3));
    assert_eq!(reference_retries_left(&mut fs, PinRef::Puk), Some(3));
    // The PIN is still the one the card started with, and still addressable.
    assert_eq!(
        run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN).0,
        Sw::OK
    );
    // The panel-facing owner refuses an unpadded value too, so no caller can
    // reintroduce a stored reference the wire form cannot produce.
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
    };
    assert_eq!(
        change_reference(&dev, &mut fs, PinRef::Pin, &DEFAULT_PIN, short),
        Sw::WRONG_DATA
    );
    assert_eq!(
        unblock_pin_with_puk(&dev, &mut fs, &DEFAULT_PUK, short),
        Sw::WRONG_DATA
    );
}

/// A card an OLDER build let a non-conformant host poison — a reference stored
/// unpadded, so the wire form can never present it — must keep every exit it had.
/// The three configurations, each driven through the real APDUs:
///
/// The reason this is a test and not a comment: sizing the length gate off the
/// *stored* length instead of a flat two wire forms looks like it preserves more
/// (a short old half could still be presented), and in fact takes the last exit
/// away — the 16-byte body every host sends would stop burning, the PUK counter
/// could never reach zero, and `INS FB` RESET is gated on both counters at zero.
#[test]
fn a_poisoned_reference_keeps_every_exit_it_had() {
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
    };
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    // Six raw bytes, never 0xFF-padded — and deliberately the PREFIX of the
    // padded default, so a body split at the stored length would match where one
    // split at the wire form must not.
    let short = b"123456";
    let block = |app: &mut PivApplet, fs: &mut Fs<RamStorage>, ins: u8, p2: u8, body: &[u8]| {
        for _ in 0..4 {
            if run(app, fs, ins, 0, p2, body).0 == Sw::PIN_BLOCKED {
                return true;
            }
        }
        false
    };

    // (a) the PIN alone is poisoned: the PUK unblock repairs it, keys intact.
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    put_pin_verifier(&dev, &mut fs, EF_PIN, short).unwrap();
    assert_eq!(
        run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN).0,
        Sw::retries(2),
        "the padded VERIFY no conformant host can avoid"
    );
    // The body splits at the wire form, not at what the card stored: the padded
    // old half must MISS the short verifier rather than match its first six bytes.
    let mut change = DEFAULT_PIN.to_vec();
    change.extend_from_slice(b"87654321");
    assert_eq!(
        run(&mut app, &mut fs, INS_CHANGE_PIN, 0, 0x80, &change).0,
        Sw::retries(1)
    );
    let mut unblock = DEFAULT_PUK.to_vec();
    unblock.extend_from_slice(&DEFAULT_PIN);
    assert_eq!(
        run(&mut app, &mut fs, INS_RESET_RETRY, 0, 0x80, &unblock).0,
        Sw::OK
    );
    assert_eq!(
        run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN).0,
        Sw::OK
    );

    // (b) the PUK alone is poisoned: SET RETRIES rewrites both, keys intact.
    let mut fs = new_fs();
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut app, &mut fs);
    put_pin_verifier(&dev, &mut fs, EF_PUK, short).unwrap();
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    assert_eq!(run(&mut app, &mut fs, INS_SET_RETRIES, 3, 3, &[]).0, Sw::OK);
    let mut change = DEFAULT_PUK.to_vec();
    change.extend_from_slice(b"87654321");
    assert_eq!(
        run(&mut app, &mut fs, INS_CHANGE_PIN, 0, 0x81, &change).0,
        Sw::OK
    );

    // (c) BOTH poisoned: no repair is reachable, so the reset ladder is the last
    // exit and every rung of it has to still work.
    let mut fs = new_fs();
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut app, &mut fs);
    put_pin_verifier(&dev, &mut fs, EF_PIN, short).unwrap();
    put_pin_verifier(&dev, &mut fs, EF_PUK, short).unwrap();
    assert_eq!(
        run(&mut app, &mut fs, INS_RESET, 0, 0, &[]).0,
        Sw::WRONG_DATA,
        "RESET before the counters are spent"
    );
    assert!(
        block(&mut app, &mut fs, INS_VERIFY, 0x80, &DEFAULT_PIN),
        "the padded VERIFY must still spend the PIN counter"
    );
    let mut unblock = DEFAULT_PUK.to_vec();
    unblock.extend_from_slice(&DEFAULT_PIN);
    assert!(
        block(&mut app, &mut fs, INS_RESET_RETRY, 0x80, &unblock),
        "the 16-byte unblock every host sends must still spend the PUK counter"
    );
    assert_eq!(run(&mut app, &mut fs, INS_RESET, 0, 0, &[]).0, Sw::OK);
    assert_eq!(
        run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN).0,
        Sw::OK,
        "the reset restored an addressable card"
    );
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
    // ...and the unpadded 6-byte form does NOT — padding is load-bearing. It is
    // refused on the wire form, so it costs the standing status but no retry.
    let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, b"654321");
    assert_eq!(sw, Sw::WRONG_DATA);
    assert_eq!(reference_retries_left(&mut fs, PinRef::Pin), Some(3));
    let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &new);
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

    // PRINTED carries Table 3's PIN read condition whatever it holds, so an
    // unauthenticated read never gets as far as asking whether it exists.
    let (sw, _) = run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get(PRINTED));
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    // No leak: with the PIN, before protection it still reads as absent (even
    // though the default mgmt key exists in 0x9B) — protection is opt-in.
    verify_pin(&mut app, &mut fs);
    let (sw, _) = run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get(PRINTED));
    assert_eq!(sw, Sw::FILE_NOT_FOUND);
    let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0xFF, 0x80, &[]);
    assert_eq!(sw, Sw::OK); // drop the PIN status again

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

/// SP 800-73-4 pt1 Table 3 gives four data objects a contact read condition of
/// PIN — fingerprints, facial image, printed information, iris images — and a
/// YubiKey 5.7.4 gates exactly those four and no others. Ours served three of
/// them to anyone who could open the reader, so a card provisioned as a real PIV
/// credential handed over its biometrics with no PIN. Measured 3 runs per card:
/// the gate is judged BEFORE the object's existence (an absent one is `6982`
/// unauthenticated and `6A82` with the PIN), and the management key does not
/// stand in for the PIN.
#[test]
fn the_pin_read_condition_objects_are_not_world_readable() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    let get = |id: u32| [0x5C, 0x03, (id >> 16) as u8, (id >> 8) as u8, id as u8];
    let put = |id: u32| {
        let mut v = get(id).to_vec();
        v.extend_from_slice(&[TAG_DATA_OBJECT, 0x03, 0x41, 0x42, 0x43]);
        v
    };
    let gated = [
        CARDHOLDER_FINGERPRINTS_ID,
        CARDHOLDER_FACIAL_IMAGE_ID,
        PRINTED_ID,
        CARDHOLDER_IRIS_IMAGES_ID,
    ];
    // The controls include each gated id's immediate neighbours, so an off-by-one
    // in `read_needs_pin` cannot pass. CHUID is a weak control on its own — it
    // answers OK even when absent (the Windows synthesis) — hence the rest.
    let ungated = [
        CHUID_ID,
        0x5FC101u32,
        0x5FC102,
        0x5FC104,
        0x5FC105,
        0x5FC107,
        0x5FC10A,
        0x5FC10B,
        0x5FC10C,
        0x5FC120,
        0x5FC122,
    ];
    for id in gated.iter().chain(ungated.iter()) {
        assert_eq!(
            run(&mut app, &mut fs, INS_PUT_DATA, 0x3F, 0xFF, &put(*id)).0,
            Sw::OK,
            "PUT {id:06X}"
        );
    }

    // A power cycle: the management key stays up, the PIN does not.
    let mut cold = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut cold, &mut fs);
    for id in gated {
        assert_eq!(
            run(&mut cold, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get(id)).0,
            Sw::SECURITY_STATUS_NOT_SATISFIED,
            "{id:06X} was world-readable"
        );
    }
    for id in ungated {
        assert_eq!(
            run(&mut cold, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get(id)).0,
            Sw::OK,
            "{id:06X} lost its Always read condition"
        );
    }
    // The management key is not the PIN.
    auth_mgm(&mut cold, &mut fs);
    for id in gated {
        assert_eq!(
            run(&mut cold, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get(id)).0,
            Sw::SECURITY_STATUS_NOT_SATISFIED,
            "{id:06X} opened to the management key"
        );
    }
    // …and an ABSENT gated object is still the security status, not 6A82 —
    // the gate comes first, so it cannot be used to probe what a card holds.
    verify_pin(&mut cold, &mut fs);
    for id in gated {
        let (sw, body) = run(&mut cold, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get(id));
        assert_eq!(sw, Sw::OK, "{id:06X}");
        assert_eq!(
            &body,
            &[TAG_DATA_OBJECT, 0x03, 0x41, 0x42, 0x43],
            "{id:06X}"
        );
    }
    let absent = CARDHOLDER_IRIS_IMAGES_ID;
    let mut wipe = get(absent).to_vec();
    wipe.extend_from_slice(&[TAG_DATA_OBJECT, 0x00]);
    assert_eq!(
        run(&mut cold, &mut fs, INS_PUT_DATA, 0x3F, 0xFF, &wipe).0,
        Sw::OK
    );
    assert_eq!(
        run(&mut cold, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get(absent)).0,
        Sw::FILE_NOT_FOUND
    );
    let mut cold2 = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut cold2, &mut fs);
    assert_eq!(
        run(&mut cold2, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get(absent)).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
}

/// PRINTED (`5FC109`) is a data object on a YubiKey — `ykman piv objects
/// import/export` round-trips it, measured — and here it is also where the
/// PIN-protected management key is read back from. Ours answered `9000` to the
/// write and threw the bytes away, so the round trip silently lost whatever a
/// host stored. It stores now, with one exception that stays: a body that IS an
/// escrow record is still acknowledged and not persisted, because the key it
/// carries is already sealed in `0x9B` and writing the host's copy would put a
/// management key in flash in plaintext — the one thing this design exists to
/// avoid. An escrowed card keeps reading back the synthesized key, as before.
#[test]
fn printed_information_round_trips_but_an_escrow_body_is_never_stored() {
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
    let get = [0x5C, 0x03, 0x5F, 0xC1, 0x09];
    let printed = [TAG_DATA_OBJECT, 0x03, 0x41, 0x42, 0x43];
    let mut put = get.to_vec();
    put.extend_from_slice(&printed);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);

    assert_eq!(
        run(&mut app, &mut fs, INS_PUT_DATA, 0x3F, 0xFF, &put).0,
        Sw::OK
    );
    let (sw, body) = run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get);
    assert_eq!(sw, Sw::OK, "PRINTED did not round-trip");
    assert_eq!(&body, &printed);

    // It is real storage: it survives a power cycle, and it is still PIN-gated.
    let mut cold = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut cold, &mut fs);
    assert_eq!(
        run(&mut cold, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    verify_pin(&mut cold, &mut fs);
    let (sw, body) = run(&mut cold, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get);
    assert_eq!(sw, Sw::OK);
    assert_eq!(&body, &printed);

    // An escrow body is acknowledged and NOT persisted. Written while protection
    // is off, so nothing can mask it: the read still finds the earlier printed
    // information, never the key the host offered.
    let host_key = [0x5Au8; 24];
    let mut escrow = vec![PROTECTED_TAG, 2 + host_key.len() as u8];
    escrow.push(PROTECTED_MGM_TAG);
    escrow.push(host_key.len() as u8);
    escrow.extend_from_slice(&host_key);
    let mut put_escrow = get.to_vec();
    put_escrow.extend_from_slice(&[TAG_DATA_OBJECT, escrow.len() as u8]);
    put_escrow.extend_from_slice(&escrow);
    auth_mgm(&mut cold, &mut fs);
    assert_eq!(
        run(&mut cold, &mut fs, INS_PUT_DATA, 0x3F, 0xFF, &put_escrow).0,
        Sw::OK
    );
    let (sw, body) = run(&mut cold, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get);
    assert_eq!(sw, Sw::OK);
    assert_eq!(&body, &printed, "the host's escrow copy was stored");

    // Once protection is on, the synthesized key wins over anything stored.
    assert_eq!(protect_mgm_key(&dev, &mut fs, &mut TestRng(42)), Sw::OK);
    let (sw, body) = run(&mut cold, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get);
    assert_eq!(sw, Sw::OK);
    assert_eq!(
        &body[..6],
        &[
            TAG_DATA_OBJECT,
            0x24,
            PROTECTED_TAG,
            0x22,
            PROTECTED_MGM_TAG,
            0x20
        ]
    );
    let mut sealed = [0u8; 32];
    let n = seal::seal_read(&dev, &mut fs, key_fid(SLOT_CARDMGM), &mut sealed).unwrap();
    assert_eq!(&body[6..6 + n], &sealed[..n]);
    // …so a write of anything else is refused while it is live, rather than
    // acknowledged and hidden under it. (A YubiKey takes the write and loses the
    // escrowed key with it; that is the data loss we do not copy.)
    assert_eq!(
        run(&mut cold, &mut fs, INS_PUT_DATA, 0x3F, 0xFF, &put).0,
        Sw::CONDITIONS_NOT_SATISFIED
    );
    // Revoking is `ykman`'s own sequence and its first step is an EMPTY 53 to
    // PRINTED, so the empty body has to stay accepted while protection is on —
    // and it is the delete form, so the printed information goes with the escrow.
    // Asserted the way a host actually does it, not the way the library call
    // alone would leave it.
    let mut wipe = get.to_vec();
    wipe.extend_from_slice(&[TAG_DATA_OBJECT, 0x00]);
    assert_eq!(
        run(&mut cold, &mut fs, INS_PUT_DATA, 0x3F, 0xFF, &wipe).0,
        Sw::OK
    );
    mgm_clear_protected(&mut fs).unwrap();
    verify_pin(&mut cold, &mut fs);
    assert_eq!(
        run(&mut cold, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get).0,
        Sw::FILE_NOT_FOUND
    );
    // …and with the escrow gone it is ordinary storage again. (The management
    // status from earlier still stands — `protect_mgm_key` rotates the key in
    // flash, not the session — so no second mutual auth here, which would need
    // the random key it just minted.)
    assert_eq!(
        run(&mut cold, &mut fs, INS_PUT_DATA, 0x3F, 0xFF, &put).0,
        Sw::OK
    );
    let (sw, body) = run(&mut cold, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get);
    assert_eq!(sw, Sw::OK);
    assert_eq!(&body, &printed);
}

/// The escrow guard's own table. It is the whole reason a management key does
/// not end up in flash in plaintext, so the shapes either side of it are pinned
/// here rather than left to the one happy-path body the caller test sends.
#[test]
fn the_escrow_guard_matches_that_shape_and_no_other() {
    let key = [0x5Au8; 24];
    let escrow = |k: &[u8]| {
        let mut v = vec![
            PROTECTED_TAG,
            2 + k.len() as u8,
            PROTECTED_MGM_TAG,
            k.len() as u8,
        ];
        v.extend_from_slice(k);
        v
    };
    assert!(is_mgm_escrow(&escrow(&key)));
    assert!(is_mgm_escrow(&escrow(&[0u8; 16])));
    assert!(is_mgm_escrow(&escrow(&[0u8; 32])));
    for (body, why) in [
        (vec![], "empty"),
        (vec![PROTECTED_TAG, 0x00], "88 with no content"),
        (
            vec![PROTECTED_TAG, 0x02, PROTECTED_MGM_TAG, 0x00],
            "empty key",
        ),
        (escrow(&[0u8; 20]), "not a management-key length"),
        (
            vec![PROTECTED_TAG, 0x02, 0x8A, 0x18],
            "the inner tag is not 89",
        ),
        (
            [escrow(&key).as_slice(), &[0x41]].concat(),
            "a trailing byte after the record",
        ),
        (
            [&[0x30u8, 0x1C][..], escrow(&key).as_slice()].concat(),
            "an escrow nested one level down",
        ),
        (
            [&escrow(&key)[..2], &[0x41, 0x42], &escrow(&key)[2..]].concat(),
            "content before the inner tag",
        ),
    ] {
        assert!(!is_mgm_escrow(&body), "{why} was taken for an escrow");
    }
    // Printed information that merely carries the tags is stored, not swallowed.
    assert!(!is_mgm_escrow(&[
        TAG_DATA_OBJECT,
        0x04,
        PROTECTED_TAG,
        0x02,
        PROTECTED_MGM_TAG,
        0x00
    ]));
}

/// `Storage` that refuses to write, or to remove, one fid — a flash failure
/// landing exactly on SET MANAGEMENT KEY's seal write, or on a PUT DATA that
/// deletes. Both targets are shared with the test so they can be armed after the
/// setup writes have landed.
struct RefuseWrite {
    inner: RamStorage,
    refuse: Rc<Cell<Option<u16>>>,
    refuse_remove: Rc<Cell<Option<u16>>>,
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
        if self.refuse_remove.get() == Some(fid) {
            return Err(rsk_sdk::error::Error::MemoryFatal);
        }
        self.inner.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.inner.size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(f)
    }
}

/// A PUT DATA that deletes must not answer `9000` when the delete did not
/// happen. The write half already maps a refusing store to `6581`; the delete
/// half swallowed it, so a host wiping fingerprints off a card got the word that
/// says they are gone while they were still there.
#[test]
fn a_delete_that_did_not_happen_is_not_reported_as_done() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let refuse_remove = Rc::new(Cell::new(None));
    let mut fs = Fs::new(RefuseWrite {
        inner: RamStorage::new(),
        refuse: Rc::new(Cell::new(None)),
        refuse_remove: Rc::clone(&refuse_remove),
    });
    fs.scan();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    let id = CARDHOLDER_FINGERPRINTS_ID;
    let path = [0x5C, 0x03, (id >> 16) as u8, (id >> 8) as u8, id as u8];
    let mut put = path.to_vec();
    put.extend_from_slice(&[TAG_DATA_OBJECT, 0x03, 0x41, 0x42, 0x43]);
    assert_eq!(
        run(&mut app, &mut fs, INS_PUT_DATA, 0x3F, 0xFF, &put).0,
        Sw::OK
    );
    let mut wipe = path.to_vec();
    wipe.extend_from_slice(&[TAG_DATA_OBJECT, 0x00]);
    refuse_remove.set(Some(0xD200 | (id & 0xFF) as u16));
    assert_eq!(
        run(&mut app, &mut fs, INS_PUT_DATA, 0x3F, 0xFF, &wipe).0,
        Sw::MEMORY_FAILURE
    );
    verify_pin(&mut app, &mut fs);
    assert_eq!(
        run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &path).0,
        Sw::OK,
        "the object is still there, which is what the refusal was about"
    );
    // With the flash healthy again the same command succeeds and the object goes.
    refuse_remove.set(None);
    assert_eq!(
        run(&mut app, &mut fs, INS_PUT_DATA, 0x3F, 0xFF, &wipe).0,
        Sw::OK
    );
    assert_eq!(
        run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &path).0,
        Sw::FILE_NOT_FOUND
    );
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
        refuse_remove: Rc::new(Cell::new(None)),
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
    assert_eq!(sw, Sw::WRONG_DATA, "encrypt oracle must be refused");
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
    assert_eq!(sw, Sw::WRONG_DATA, "cross-algo step-2 must be refused");
    // has_mgm stays closed.
    let (sw, _) = run(&mut app, &mut fs, INS_SET_RETRIES, 5, 5, &[]);
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
}

#[test]
fn a_new_mgmt_handshake_revokes_the_standing_9b_status() {
    // E38's class on a third command. Measured on a YubiKey 5.7.4, three runs,
    // each after `ykman piv reset`: a standing 9B status does not survive a new
    // management-key handshake — a failed step 2 revokes it, and so does a bare
    // challenge request that is never answered. Ours kept it, so PUT DATA went on
    // succeeding after a wrong-key attempt.
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    // PUT DATA of PRINTED: management-key gated like every other object.
    let put = |app: &mut PivApplet, fs: &mut Fs<RamStorage>| -> Sw {
        let obj = [0x5C, 0x03, 0x5F, 0xC1, 0x09, 0x53, 0x03, 0x41, 0x42, 0x43];
        run(app, fs, INS_PUT_DATA, 0x3F, 0xFF, &obj).0
    };
    select(&mut app, &mut fs);
    assert_eq!(
        put(&mut app, &mut fs),
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "control: the instrument reads 9B closed"
    );
    auth_mgm(&mut app, &mut fs);
    assert_eq!(put(&mut app, &mut fs), Sw::OK, "control: 9B open");

    // Single auth, wrong response.
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
    assert_eq!(
        put(&mut app, &mut fs),
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "a failed single auth must revoke 9B"
    );

    // Mutual auth, wrong witness.
    auth_mgm(&mut app, &mut fs);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_AES192,
        0x9B,
        &[0x7C, 0x02, 0x80, 0x00],
    );
    assert_eq!(sw, Sw::OK);
    let mut msg = vec![0x7C, 0x24, 0x80, 0x10];
    msg.extend_from_slice(&[0u8; 16]);
    msg.push(0x81);
    msg.push(0x10);
    msg.extend_from_slice(&[0xA5u8; 16]);
    let (sw, _) = run(&mut app, &mut fs, INS_AUTHENTICATE, ALGO_AES192, 0x9B, &msg);
    assert_eq!(sw, Sw::DATA_INVALID);
    assert_eq!(
        put(&mut app, &mut fs),
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "a failed mutual auth must revoke 9B"
    );

    // Either step 1 revokes it on its own, answered or not.
    for step1 in [[0x7C, 0x02, 0x81, 0x00], [0x7C, 0x02, 0x80, 0x00]] {
        auth_mgm(&mut app, &mut fs);
        let (sw, _) = run(
            &mut app,
            &mut fs,
            INS_AUTHENTICATE,
            ALGO_AES192,
            0x9B,
            &step1,
        );
        assert_eq!(sw, Sw::OK);
        assert_eq!(
            put(&mut app, &mut fs),
            Sw::SECURITY_STATUS_NOT_SATISFIED,
            "issuing a challenge must revoke 9B"
        );
    }

    // …and only a step 1 does. Measured on the same YubiKey: every other 9B
    // request leaves the status alone, so revoking on the dispatch as a whole
    // would be a divergence of its own.
    let mut t82_unsolicited = vec![0x7C, 0x12, 0x82, 0x10];
    t82_unsolicited.extend_from_slice(&[0u8; 16]);
    let mut t81_oracle = vec![0x7C, 0x12, 0x81, 0x10];
    t81_oracle.extend_from_slice(&[0u8; 16]);
    for (algo, body) in [
        (ALGO_AES192, t82_unsolicited),
        (ALGO_AES192, t81_oracle),
        (ALGO_AES192, vec![0x7C, 0x03, 0x85, 0x01, 0x00]),
        (0x99, vec![0x7C, 0x02, 0x81, 0x00]),
    ] {
        auth_mgm(&mut app, &mut fs);
        let (sw, _) = run(&mut app, &mut fs, INS_AUTHENTICATE, algo, 0x9B, &body);
        assert_ne!(sw, Sw::OK, "algo {algo:#04x} body {body:02x?}");
        assert_eq!(
            put(&mut app, &mut fs),
            Sw::OK,
            "a 9B request that is not a handshake step must keep the status"
        );
    }

    // Cross-term, measured on the same YubiKey: a wrong PIN leaves 9B alone.
    auth_mgm(&mut app, &mut fs);
    let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &[0x39u8; 8]);
    assert_eq!(sw, Sw::new(0x63, 0xC2));
    assert_eq!(
        put(&mut app, &mut fs),
        Sw::OK,
        "a wrong PIN must not revoke 9B"
    );
}

#[test]
fn a_key_slot_challenge_is_not_a_management_key_challenge() {
    // The revocation above rides on the handshake, and every single-auth
    // challenge used to enter the session whatever slot asked for it — so one
    // taken out at 9A answered 9B, and staging the failure there cost nothing.
    // A YubiKey 5.7.4 issues no challenge outside 9B at all (6A80, two runs).
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    let put = |app: &mut PivApplet, fs: &mut Fs<RamStorage>| -> Sw {
        let obj = [0x5C, 0x03, 0x5F, 0xC1, 0x09, 0x53, 0x03, 0x41, 0x42, 0x43];
        run(app, fs, INS_PUT_DATA, 0x3F, 0xFF, &obj).0
    };
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    // A key slot only reaches the dispatch once it holds a key: an empty one
    // answers 6A88 and would prove nothing.
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0x00,
        0x9A,
        &gen_template(ALGO_ECCP256),
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(put(&mut app, &mut fs), Sw::OK, "control: 9B open");

    // No challenge is issued outside 9B at all any more. Under the slot's own
    // algorithm the empty-81 arm is a private-key operation and answers with a
    // signature; under any other it is refused before the key. Both rows, so the
    // property does not rest on the request dying somewhere earlier.
    let (sw, out) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_ECCP256,
        0x9A,
        &[0x7C, 0x02, 0x81, 0x00],
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(out[2], TAG_AUTH_RESPONSE, "a signature, not a challenge");
    let (sw, out) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_AES192,
        0x9A,
        &[0x7C, 0x02, 0x81, 0x00],
    );
    assert_eq!(
        sw,
        Sw::WRONG_DATA,
        "measured on the oracle, 2 runs, all symmetric algos"
    );
    assert!(out.is_empty());
    assert_eq!(
        put(&mut app, &mut fs),
        Sw::OK,
        "a key-slot request must leave 9B alone"
    );
    // Nothing entered the session either, so there is no challenge at 9B to
    // answer — which is the property this test was written for.
    let mut msg = vec![0x7C, 0x12, 0x82, 0x10];
    msg.extend_from_slice(&[0x42u8; 16]);
    let (sw, _) = run(&mut app, &mut fs, INS_AUTHENTICATE, ALGO_AES192, 0x9B, &msg);
    assert_eq!(
        sw,
        Sw::WRONG_DATA,
        "no challenge was issued, so none can be answered"
    );

    // Control in the same run: asked for at 9B, the identical request revokes.
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_AES192,
        0x9B,
        &[0x7C, 0x02, 0x81, 0x00],
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(put(&mut app, &mut fs), Sw::SECURITY_STATUS_NOT_SATISFIED);
}

#[test]
fn a_key_slot_challenge_does_not_disturb_a_9b_handshake() {
    // The same session field: a key-slot request used to overwrite the
    // outstanding 9B challenge, so a host that interleaved one lost the
    // handshake and its status with it. Measured on a YubiKey 5.7.4, two runs:
    // a GENERAL AUTHENTICATE at another slot leaves the handshake completable.
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    let put = |app: &mut PivApplet, fs: &mut Fs<RamStorage>| -> Sw {
        let obj = [0x5C, 0x03, 0x5F, 0xC1, 0x09, 0x53, 0x03, 0x41, 0x42, 0x43];
        run(app, fs, INS_PUT_DATA, 0x3F, 0xFF, &obj).0
    };
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0x00,
        0x9A,
        &gen_template(ALGO_ECCP256),
    );
    assert_eq!(sw, Sw::OK);

    for interleaved in [false, true] {
        auth_mgm(&mut app, &mut fs);
        let (sw, chal) = run(
            &mut app,
            &mut fs,
            INS_AUTHENTICATE,
            ALGO_AES192,
            0x9B,
            &[0x7C, 0x02, 0x81, 0x00],
        );
        assert_eq!(sw, Sw::OK);
        if interleaved {
            let (sw, _) = run(
                &mut app,
                &mut fs,
                INS_AUTHENTICATE,
                ALGO_ECCP256,
                0x9A,
                &[0x7C, 0x02, 0x81, 0x00],
            );
            assert_eq!(sw, Sw::OK);
        }
        let mut r: [u8; 16] = chal[4..20].try_into().unwrap();
        rsk_crypto::aes_ecb_encrypt_block(&DEFAULT_MGM, &mut r).unwrap();
        let mut msg = vec![0x7C, 0x12, 0x82, 0x10];
        msg.extend_from_slice(&r);
        let (sw, _) = run(&mut app, &mut fs, INS_AUTHENTICATE, ALGO_AES192, 0x9B, &msg);
        assert_eq!(sw, Sw::OK, "interleaved {interleaved}");
        assert_eq!(put(&mut app, &mut fs), Sw::OK, "interleaved {interleaved}");
    }
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
    assert_eq!(sw, Sw::WRONG_DATA);
    // …and so is RSA-1024 generation.
    let tmpl = [0xAC, 0x03, 0x80, 0x01, ALGO_RSA1024];
    let (sw, _) = run(&mut app, &mut fs, INS_ASYM_KEYGEN, 0x00, 0x9A, &tmpl);
    assert_eq!(sw, Sw::WRONG_DATA);
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
        &[PINPOLICY_ONCE, TOUCHPOLICY_NEVER]
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

/// A signature at a pin-policy ALWAYS slot re-locks that policy and nothing else.
/// Measured on a YubiKey 5.7.4: sign at 9C, then 9A/9D/PRINTED/the status query all
/// still answer 9000. Ours cleared the card's only PIN latch, so one S/MIME
/// signature shut every PIN-gated surface until the host verified again.
#[test]
fn a_pin_always_signature_keeps_the_rest_of_the_pin_session() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    // 9C's default pin policy resolves to ALWAYS, 9A's and 9D's to ONCE.
    for slot in [SLOT_SIGNATURE, SLOT_AUTHENTICATION] {
        let tmpl = gen_template(ALGO_ECCP256);
        assert_eq!(
            run(&mut app, &mut fs, INS_ASYM_KEYGEN, 0, slot, &tmpl).0,
            Sw::OK
        );
    }
    let (sw, resp) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0,
        SLOT_KEYMGM,
        &gen_template(ALGO_ECCP256),
    );
    assert_eq!(sw, Sw::OK);
    let point = ec_point_of(&resp);

    // Plant the ADMIN-DATA flag the way a host does, so PRINTED is a real
    // PIN-gated object rather than an absent one.
    let plant = vec![
        TAG_DATA_PATH,
        0x03,
        0x5F,
        0xFF,
        0x00,
        TAG_DATA_OBJECT,
        0x05,
        PIVMAN_TAG,
        0x03,
        PIVMAN_FLAGS_TAG,
        0x01,
        PIVMAN_FLAG_MGM_PROTECTED,
    ];
    assert_eq!(
        run(&mut app, &mut fs, INS_PUT_DATA, 0x3F, 0xFF, &plant).0,
        Sw::OK
    );
    let printed = [TAG_DATA_PATH, 0x03, 0x5F, 0xC1, 0x09];

    // Each instrument below reads the PIN status and nothing else: with the
    // status dropped (`VERIFY P1=FF`) every one of them refuses.
    assert_eq!(
        run(&mut app, &mut fs, INS_VERIFY, 0xFF, 0x80, &[]).0,
        Sw::OK
    );
    assert_eq!(
        run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &printed).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(
        sign_p256(&mut app, &mut fs, SLOT_AUTHENTICATION),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(
        ecdh_p256(&mut app, &mut fs, &point),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );

    verify_pin(&mut app, &mut fs);
    assert_eq!(sign_p256(&mut app, &mut fs, SLOT_SIGNATURE), Sw::OK);
    assert_eq!(
        sign_p256(&mut app, &mut fs, SLOT_AUTHENTICATION),
        Sw::OK,
        "a pin-policy ONCE slot"
    );
    assert_eq!(
        ecdh_p256(&mut app, &mut fs, &point),
        Sw::OK,
        "ECDH at a pin-policy ONCE slot"
    );
    assert_eq!(
        run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &printed).0,
        Sw::OK,
        "the PIN-protected PRINTED object"
    );
    assert_eq!(
        run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &[]).0,
        Sw::OK,
        "the VERIFY status query"
    );
    assert_eq!(
        run(&mut app, &mut fs, INS_PUT_DATA, 0x3F, 0xFF, &plant).0,
        Sw::OK,
        "the standing 9B status"
    );
    // Only the ALWAYS slot itself re-locks.
    assert_eq!(
        sign_p256(&mut app, &mut fs, SLOT_SIGNATURE),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
}

/// The other half of the same rule, also measured on 5.7.4: the freshness an
/// ALWAYS slot reads is spent by a key operation at *any* PIN-gated slot — a ONCE
/// signature or an ECDH closes 9C — while a pin-policy NEVER operation spends
/// nothing. Ours keyed the clear on ALWAYS, so a ONCE operation left 9C open.
#[test]
fn a_key_operation_at_a_once_slot_spends_the_always_freshness() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    for slot in [SLOT_SIGNATURE, SLOT_AUTHENTICATION] {
        let tmpl = gen_template(ALGO_ECCP256);
        assert_eq!(
            run(&mut app, &mut fs, INS_ASYM_KEYGEN, 0, slot, &tmpl).0,
            Sw::OK
        );
    }
    let (sw, resp) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0,
        SLOT_KEYMGM,
        &gen_template(ALGO_ECCP256),
    );
    assert_eq!(sw, Sw::OK);
    let point = ec_point_of(&resp);
    // A retired slot, pin policy NEVER, to check what must NOT spend.
    let tmpl = vec![
        0xAC,
        0x09,
        0x80,
        0x01,
        ALGO_ECCP256,
        0xAA,
        0x01,
        PINPOLICY_NEVER,
        0xAB,
        0x01,
        TOUCHPOLICY_NEVER,
    ];
    assert_eq!(
        run(&mut app, &mut fs, INS_ASYM_KEYGEN, 0, 0x82, &tmpl).0,
        Sw::OK
    );

    verify_pin(&mut app, &mut fs);
    assert_eq!(sign_p256(&mut app, &mut fs, SLOT_AUTHENTICATION), Sw::OK);
    assert_eq!(
        sign_p256(&mut app, &mut fs, SLOT_SIGNATURE),
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "a signature at a ONCE slot spends the ALWAYS freshness"
    );

    verify_pin(&mut app, &mut fs);
    assert_eq!(ecdh_p256(&mut app, &mut fs, &point), Sw::OK);
    assert_eq!(
        sign_p256(&mut app, &mut fs, SLOT_SIGNATURE),
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "an ECDH at a ONCE slot spends it too"
    );

    verify_pin(&mut app, &mut fs);
    assert_eq!(sign_p256(&mut app, &mut fs, 0x82), Sw::OK);
    assert_eq!(
        sign_p256(&mut app, &mut fs, SLOT_SIGNATURE),
        Sw::OK,
        "a pin-policy NEVER operation spends nothing"
    );
}

/// A GENERAL AUTHENTICATE that reaches no key at all is refused and spends
/// nothing. A YubiKey 5.7.4 answers `6A80` to every body carrying no operation
/// tag it recognises — 3 runs each on an unknown tag, a truncated TLV and a lone
/// empty response placeholder — where we used to answer `9000` and do nothing.
#[test]
fn a_general_authenticate_that_uses_no_key_spends_nothing() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            INS_ASYM_KEYGEN,
            0,
            SLOT_SIGNATURE,
            &gen_template(ALGO_ECCP256)
        )
        .0,
        Sw::OK
    );
    verify_pin(&mut app, &mut fs);
    for body in [
        vec![0x7C, 0x02, 0x82, 0x00],       // the response placeholder, alone
        vec![0x7C, 0x03, 0x5F, 0x01, 0x00], // a tag this card does not know
        vec![0x7C, 0x01, 0x82],             // a truncated TLV inside the template
        vec![0x7C, 0x02, 0x80, 0x00],       // mutual auth, which is 9B-only
    ] {
        let (sw, out) = run(
            &mut app,
            &mut fs,
            INS_AUTHENTICATE,
            ALGO_ECCP256,
            SLOT_SIGNATURE,
            &body,
        );
        assert_eq!(sw, Sw::WRONG_DATA, "body {body:02X?}");
        assert!(out.is_empty(), "body {body:02X?}");
    }
    assert_eq!(
        sign_p256(&mut app, &mut fs, SLOT_SIGNATURE),
        Sw::OK,
        "no key was used, so the PIN freshness must still stand"
    );
}

/// GENERAL AUTHENTICATE dispatches on the FIRST operation tag the body carries,
/// and at a key slot an empty `81` is a private-key operation, not a request for
/// a challenge. Measured on a YubiKey 5.7.4, 3 runs each:
///
/// | body at a provisioned key slot | answer |
/// |---|---|
/// | `7C 02 81 00` | a signature (`7C 49 82 47 30 45 …`), and it spends |
/// | `7C .. 82 00 81 00 85 <point>` | a signature — `81` comes first |
/// | `7C .. 82 00 85 <point> 81 00` | the shared secret — `85` comes first |
/// | `7C 02 85 00` | `6A80`, and it spends: the request reached the key |
///
/// Ours minted 16 random bytes under tag `81` for the first two — a host that
/// does not check the tag reads them as a signature — and answered `9000` doing
/// nothing for the last. `find_tag` per tag is order-blind, so the third row was
/// answered with random bytes as well. At `9B` an empty `81` is still the
/// single-auth challenge this arm exists for.
#[test]
fn general_authenticate_takes_the_first_operation_tag_in_the_body() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    for slot in [SLOT_KEYMGM, SLOT_SIGNATURE] {
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                INS_ASYM_KEYGEN,
                0,
                slot,
                &gen_template(ALGO_ECCP256)
            )
            .0,
            Sw::OK
        );
    }
    let point = {
        let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, SLOT_KEYMGM, &[]);
        assert_eq!(sw, Sw::OK);
        let pk = find_tag(&md, 0x04).unwrap();
        pk[2..2 + pk[1] as usize].to_vec()
    };
    let ga = |app: &mut PivApplet, fs: &mut Fs<RamStorage>, slot: u8, body: Vec<u8>| {
        run(app, fs, INS_AUTHENTICATE, ALGO_ECCP256, slot, &body)
    };
    let wrap = |inner: Vec<u8>| {
        let mut v = vec![0x7C, inner.len() as u8];
        v.extend_from_slice(&inner);
        v
    };

    // An empty 81 at a key slot signs, and spends the freshness a 9C read.
    verify_pin(&mut app, &mut fs);
    let (sw, out) = ga(&mut app, &mut fs, SLOT_KEYMGM, vec![0x7C, 0x02, 0x81, 0x00]);
    assert_eq!(sw, Sw::OK);
    assert_eq!(out[0], 0x7C);
    assert_eq!(
        out[2], TAG_AUTH_RESPONSE,
        "tag 82, a signature, not a challenge"
    );
    assert_eq!(out[4], 0x30, "a DER SEQUENCE, not random bytes");
    assert_eq!(
        sign_p256(&mut app, &mut fs, SLOT_SIGNATURE),
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "the empty-81 operation reached the key, so it spends"
    );

    // Tag order decides between a signature and an agreement.
    let mut sig_first = vec![0x82, 0x00, 0x81, 0x00, 0x85, point.len() as u8];
    sig_first.extend_from_slice(&point);
    let mut ecdh_first = vec![0x82, 0x00, 0x85, point.len() as u8];
    ecdh_first.extend_from_slice(&point);
    ecdh_first.extend_from_slice(&[0x81, 0x00]);
    verify_pin(&mut app, &mut fs);
    let (sw, out) = ga(&mut app, &mut fs, SLOT_KEYMGM, wrap(sig_first));
    assert_eq!(sw, Sw::OK);
    assert_eq!(out[2], TAG_AUTH_RESPONSE, "81 first: a signature");
    assert_eq!(
        out[4], 0x30,
        "…in DER, not the first byte of a shared secret"
    );
    verify_pin(&mut app, &mut fs);
    let (sw, out) = ga(&mut app, &mut fs, SLOT_KEYMGM, wrap(ecdh_first));
    assert_eq!(sw, Sw::OK);
    assert_eq!(
        &out[..4],
        &[0x7C, 0x22, 0x82, 0x20],
        "85 first: 32 raw bytes"
    );

    // An 85 the curve cannot use is refused — after reaching the key, so it costs
    // the freshness exactly as a good one does.
    for bad in [vec![0x85, 0x00], vec![0x85, 0x02, 0x04, 0x05]] {
        verify_pin(&mut app, &mut fs);
        assert_eq!(sign_p256(&mut app, &mut fs, SLOT_SIGNATURE), Sw::OK);
        verify_pin(&mut app, &mut fs);
        let (sw, out) = ga(&mut app, &mut fs, SLOT_KEYMGM, wrap(bad.clone()));
        assert_eq!(sw, Sw::WRONG_DATA, "body {bad:02X?}");
        assert!(out.is_empty());
        assert_eq!(
            sign_p256(&mut app, &mut fs, SLOT_SIGNATURE),
            Sw::SECURITY_STATUS_NOT_SATISFIED,
            "body {bad:02X?} reached the key, so it spends"
        );
    }

    // An ECDH asked at 9B is refused with the same word as every other "not for
    // this slot / not this key's algorithm" cell — measured, 2 runs, `6A80`.
    let mut at_9b = vec![0x85, point.len() as u8];
    at_9b.extend_from_slice(&point);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            INS_AUTHENTICATE,
            ALGO_ECCP256,
            SLOT_CARDMGM,
            &wrap(at_9b)
        )
        .0,
        Sw::WRONG_DATA
    );

    // …and 9B keeps the arm this all started from: an empty 81 there is the
    // single-auth challenge, in plaintext under tag 81.
    let (sw, out) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_AES192,
        SLOT_CARDMGM,
        &[0x7C, 0x02, 0x81, 0x00],
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(&out[..4], &[0x7C, 0x12, 0x81, 0x10]);
}

/// The last cell of the same boundary: a *denied touch* stops the operation before
/// the key, so it spends nothing — measured on a YubiKey 5.7.4 (a touch-policy
/// ALWAYS slot left to time out leaves every ALWAYS slot open).
#[test]
fn a_denied_touch_spends_no_pin_freshness() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(Scripted { confirm: true });
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    // 9A is generated touch ALWAYS (the card's default is NEVER); 9C touch NEVER
    // so the instrument itself never asks for one.
    let mut always = gen_template(ALGO_ECCP256);
    always.extend_from_slice(&[0xAB, 0x01, TOUCHPOLICY_ALWAYS]);
    always[1] += 3;
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            INS_ASYM_KEYGEN,
            0,
            SLOT_AUTHENTICATION,
            &always
        )
        .0,
        Sw::OK
    );
    let tmpl = vec![
        0xAC,
        0x09,
        0x80,
        0x01,
        ALGO_ECCP256,
        0xAA,
        0x01,
        PINPOLICY_ALWAYS,
        0xAB,
        0x01,
        TOUCHPOLICY_NEVER,
    ];
    assert_eq!(
        run(&mut app, &mut fs, INS_ASYM_KEYGEN, 0, SLOT_SIGNATURE, &tmpl).0,
        Sw::OK
    );

    verify_pin(&mut app, &mut fs);
    pres.borrow_mut().confirm = false;
    assert_eq!(
        sign_p256(&mut app, &mut fs, SLOT_AUTHENTICATION),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    pres.borrow_mut().confirm = true;
    assert_eq!(
        sign_p256(&mut app, &mut fs, SLOT_SIGNATURE),
        Sw::OK,
        "the declined operation never reached the key"
    );
}

/// Where the spend happens, measured on a YubiKey 5.7.4: a request that *reaches*
/// the slot's key spends the freshness even when it then fails (a garbage ECDH
/// point, an RSA cryptogram of the wrong length), while one that never gets that
/// far — a wrong algorithm, an unprovisioned slot — spends nothing.
#[test]
fn a_key_operation_that_fails_still_spends_the_freshness() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    for (slot, algo) in [
        (SLOT_SIGNATURE, ALGO_ECCP256),
        (SLOT_AUTHENTICATION, ALGO_ECCP256),
        (SLOT_KEYMGM, ALGO_ECCP256),
        (0x82, ALGO_RSA1024),
    ] {
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                INS_ASYM_KEYGEN,
                0,
                slot,
                &gen_template(algo)
            )
            .0,
            Sw::OK
        );
    }

    verify_pin(&mut app, &mut fs);
    let junk = [0x04u8; 65];
    assert_eq!(ecdh_p256(&mut app, &mut fs, &junk), Sw::WRONG_DATA);
    assert_eq!(
        sign_p256(&mut app, &mut fs, SLOT_SIGNATURE),
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "a failed ECDH used the key, so it spent the freshness"
    );

    verify_pin(&mut app, &mut fs);
    let mut short = vec![0x7C, 0x0C, 0x82, 0x00, 0x81, 0x08];
    short.extend_from_slice(&[0x42u8; 8]);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            INS_AUTHENTICATE,
            ALGO_RSA1024,
            0x82,
            &short
        )
        .0,
        Sw::WRONG_DATA
    );
    assert_eq!(
        sign_p256(&mut app, &mut fs, SLOT_SIGNATURE),
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "a wrong-length RSA cryptogram reached the key too"
    );

    // The other side of the boundary.
    verify_pin(&mut app, &mut fs);
    let mut wrong_algo = vec![0x7C, 0x24, 0x82, 0x00, 0x81, 0x20];
    wrong_algo.extend_from_slice(&[0x42u8; 32]);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            INS_AUTHENTICATE,
            ALGO_ECCP384,
            SLOT_AUTHENTICATION,
            &wrong_algo
        )
        .0,
        Sw::WRONG_DATA
    );
    assert_eq!(
        sign_p256(&mut app, &mut fs, SLOT_SIGNATURE),
        Sw::OK,
        "a wrong algorithm never reaches the key"
    );
    // The RSA arm is the one that had no algorithm check at all: it loaded the
    // slot's key and spent before refusing on the cryptogram length, so an
    // RSA-2048 request at any other slot cost the freshness. Same word, same
    // accounting, measured (a P-256 slot addressed as RSA-2048 is 6A80).
    verify_pin(&mut app, &mut fs);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            INS_AUTHENTICATE,
            ALGO_RSA2048,
            SLOT_AUTHENTICATION,
            &wrong_algo
        )
        .0,
        Sw::WRONG_DATA
    );
    assert_eq!(
        sign_p256(&mut app, &mut fs, SLOT_SIGNATURE),
        Sw::OK,
        "the RSA arm's wrong algorithm never reaches the key either"
    );

    verify_pin(&mut app, &mut fs);
    assert_eq!(
        sign_p256(&mut app, &mut fs, 0x8A),
        Sw::REFERENCE_NOT_FOUND,
        "an unprovisioned slot"
    );
    assert_eq!(sign_p256(&mut app, &mut fs, SLOT_SIGNATURE), Sw::OK);
}

/// A slot record carrying the literal `DEFAULT` policy byte — what a pre-run-34
/// build stored — is resolved at use time, and the resolution now picks the spend
/// as well as the gate. 9C means ALWAYS there, every other slot ONCE.
#[test]
fn a_legacy_default_pin_policy_byte_resolves_at_use_time() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    for slot in [SLOT_SIGNATURE, SLOT_AUTHENTICATION] {
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                INS_ASYM_KEYGEN,
                0,
                slot,
                &gen_template(ALGO_ECCP256)
            )
            .0,
            Sw::OK
        );
        // The record is the 4-byte head plus keygen's cached public point.
        let mut meta = [0u8; 96];
        let n = fs.meta_find(key_fid(slot).get(), &mut meta).unwrap();
        meta[1] = PINPOLICY_DEFAULT;
        fs.meta_add(key_fid(slot).get(), &meta[..n]).unwrap();
    }

    select(&mut app, &mut fs);
    assert_eq!(
        sign_p256(&mut app, &mut fs, SLOT_AUTHENTICATION),
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "DEFAULT at 9A is ONCE, not NEVER"
    );
    verify_pin(&mut app, &mut fs);
    assert_eq!(sign_p256(&mut app, &mut fs, SLOT_AUTHENTICATION), Sw::OK);
    assert_eq!(
        sign_p256(&mut app, &mut fs, SLOT_SIGNATURE),
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "the 9A operation spent the freshness DEFAULT-at-9C reads"
    );
    verify_pin(&mut app, &mut fs);
    assert_eq!(sign_p256(&mut app, &mut fs, SLOT_SIGNATURE), Sw::OK);
    assert_eq!(
        sign_p256(&mut app, &mut fs, SLOT_SIGNATURE),
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "DEFAULT at 9C is ALWAYS"
    );
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
    assert_eq!(sw, Sw::WRONG_DATA);
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

/// An imported private scalar is exactly the field length or it is not that
/// key. Ours bounded it from above only, so a one-byte P-256 scalar was stored
/// and signed with (`d = 1`, a key anyone can forge against), and 32 bytes
/// declared as P-384 was silently accepted as a P-384 key. A YubiKey 5.7.4
/// answers `6A80` to every length but the field's — measured 1, 2, 31, 33 on
/// P-256 and 32, 47 on P-384, three runs — and left-padding is the host's job,
/// not the card's, because a host that got the length wrong got the key wrong.
#[test]
fn an_imported_scalar_is_exactly_the_field_length() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    let imp = |tag: u8, n: usize| {
        let mut v = vec![tag, n as u8];
        v.extend(core::iter::repeat_n(0x11u8, n));
        v
    };
    for (algo, field) in [(ALGO_ECCP256, 32usize), (ALGO_ECCP384, 48)] {
        for n in [1usize, 2, field - 1, field + 1] {
            assert_eq!(
                run(
                    &mut app,
                    &mut fs,
                    INS_IMPORT_ASYM,
                    algo,
                    0x9E,
                    &imp(0x06, n)
                )
                .0,
                Sw::WRONG_DATA,
                "algo {algo:02X} with a {n}-byte scalar"
            );
        }
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                INS_IMPORT_ASYM,
                algo,
                0x9E,
                &imp(0x06, field)
            )
            .0,
            Sw::OK,
            "algo {algo:02X} at the field length"
        );
    }
    // The Edwards pair carries its scalar under its own tag and is the same rule.
    for (algo, tag) in [(ALGO_ED25519, 0x07u8), (ALGO_X25519, 0x08)] {
        for n in [1usize, 31, 33] {
            assert_eq!(
                run(&mut app, &mut fs, INS_IMPORT_ASYM, algo, 0x9E, &imp(tag, n)).0,
                Sw::WRONG_DATA,
                "algo {algo:02X} with a {n}-byte scalar"
            );
        }
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                INS_IMPORT_ASYM,
                algo,
                0x9E,
                &imp(tag, 32)
            )
            .0,
            Sw::OK,
            "algo {algo:02X} at 32 bytes"
        );
    }
    // The all-zero scalar was already refused and still is.
    let mut zero = vec![0x06, 32];
    zero.extend_from_slice(&[0u8; 32]);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            INS_IMPORT_ASYM,
            ALGO_ECCP256,
            0x9E,
            &zero
        )
        .0,
        Sw::WRONG_DATA
    );
    // Audit run-36's rule, on the inputs this gate newly refuses: a refused import
    // leaves the slot exactly as it was. Every import arm drops the slot meta and
    // seals the new key first, so a length judged after the write would have
    // destroyed a provisioned slot on each of the rows above.
    let before = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9E, &[]);
    assert_eq!(before.0, Sw::OK);
    for (algo, n) in [
        (ALGO_ECCP256, 1usize),
        (ALGO_ECCP384, 32),
        (ALGO_ED25519, 31),
    ] {
        let tag = if algo == ALGO_ED25519 { 0x07 } else { 0x06 };
        assert_eq!(
            run(&mut app, &mut fs, INS_IMPORT_ASYM, algo, 0x9E, &imp(tag, n)).0,
            Sw::WRONG_DATA
        );
        assert_eq!(
            run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9E, &[]),
            before,
            "a refused {n}-byte {algo:02X} import moved the slot"
        );
    }
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
        &[PINPOLICY_DEFAULT, TOUCHPOLICY_NEVER]
    );
    assert_eq!(find_tag(&md, 0x05).unwrap(), &[1]);
}

/// Slot `9B` is not a key slot — `is_key(0x9B)` is false in both the PIN gate and
/// the freshness spend — so its stored pin-policy byte gates nothing. Two writers
/// filled it in anyway and disagreed: `scan_files` wrote ALWAYS, the panel's
/// protect flow wrote NEVER, and which one a card carried depended on its
/// history. `GET METADATA 9B` shows the byte, so the disagreement was on the
/// wire. A YubiKey 5.7.4 reports `0x00` there in every state — fresh, escrowed,
/// after a host rotation — measured 2 runs, and that is the honest value for a
/// slot with no policy to report.
#[test]
fn the_management_slot_reports_one_pin_policy_in_every_state() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
    };
    select(&mut app, &mut fs);
    let policy = |app: &mut PivApplet, fs: &mut Fs<RamStorage>| -> Vec<u8> {
        let (sw, md) = run(app, fs, INS_GET_METADATA, 0, SLOT_CARDMGM, &[]);
        assert_eq!(sw, Sw::OK);
        find_tag(&md, 0x02).unwrap().to_vec()
    };
    let fresh = policy(&mut app, &mut fs);
    assert_eq!(fresh, [PINPOLICY_DEFAULT, TOUCHPOLICY_NEVER]);

    // The panel's protect flow is the second writer.
    assert_eq!(protect_mgm_key(&dev, &mut fs, &mut TestRng(42)), Sw::OK);
    assert_eq!(policy(&mut app, &mut fs)[0], fresh[0], "protect_mgm_key");

    // …and a host rotation is the third path through the same record.
    let mut fs2 = new_fs();
    let mut app2 = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut app2, &mut fs2);
    auth_mgm(&mut app2, &mut fs2);
    let mut set_key = vec![ALGO_AES256, SLOT_CARDMGM, 32];
    set_key.extend_from_slice(&[0x5Au8; 32]);
    assert_eq!(
        run(&mut app2, &mut fs2, INS_SET_MGMKEY, 0xFF, 0xFF, &set_key).0,
        Sw::OK
    );
    assert_eq!(
        policy(&mut app2, &mut fs2)[0],
        fresh[0],
        "SET MANAGEMENT KEY"
    );

    // The byte gates nothing, in either state — 9B is reached with no PIN at all.
    let mut cold = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut cold, &mut fs);
    let (sw, _) = run(
        &mut cold,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_AES256,
        SLOT_CARDMGM,
        &[0x7C, 0x02, 0x80, 0x00],
    );
    assert_eq!(sw, Sw::OK, "9B is not PIN-gated by its own metadata byte");
}

/// E95: the same sweep on the *touch* axis, which E42 left alone. Three writers said
/// NEVER and the metadata **repair** said ALWAYS, so a card that lost its head came
/// back demanding a touch its owner never asked for — and lowering it needs a
/// management auth that now has to pass that very touch. The repair is a
/// re-provisioning: `scan_files` restores every other missing record at its published
/// default, so the touch byte takes the published default too. A YubiKey cannot be
/// asked which is right — its 9B metadata is a projection of the key record, with no
/// write command, no `DELETE 9B` (`00 F6 FF 9B` → `6A88`) and no observed partial
/// read — so the reference answers the reachable question instead: a fresh card, 3/3.
#[test]
fn the_management_slot_reports_one_touch_policy_in_every_state() {
    let rng = RefCell::new(TestRng(11));
    let pres = RefCell::new(AlwaysConfirm);
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
    };
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    let meta = |app: &mut PivApplet, fs: &mut Fs<RamStorage>| -> Vec<u8> {
        let (sw, md) = run(app, fs, INS_GET_METADATA, 0, SLOT_CARDMGM, &[]);
        assert_eq!(sw, Sw::OK);
        md
    };
    // Byte-for-byte what a YubiKey 5.7.4 answers on a fresh card (3/3, and again
    // after a second `piv reset`): AES-192, pin DEFAULT, touch NEVER, key is default.
    assert_eq!(
        meta(&mut app, &mut fs),
        [
            0x01,
            0x01,
            ALGO_AES192,
            0x02,
            0x02,
            0x00,
            0x01,
            0x05,
            0x01,
            0x01
        ]
    );

    assert_eq!(protect_mgm_key(&dev, &mut fs, &mut TestRng(43)), Sw::OK);
    let touch = |md: &[u8]| find_tag(md, 0x02).unwrap()[1];
    assert_eq!(
        touch(&meta(&mut app, &mut fs)),
        TOUCHPOLICY_NEVER,
        "protect_mgm_key"
    );

    // The repair arm: the head gone, the key alive. A fresh applet so SELECT re-runs
    // `scan_files` rather than trusting its own fast path, and a DECLINING button —
    // the substance of this finding is the gate that gets enforced, not the byte that
    // gets reported, and only a mutual auth that completes can tell them apart.
    let declines = RefCell::new(Scripted { confirm: false });
    let mut fs3 = new_fs();
    let mut healed = PivApplet::new(SERIAL, HASH, None, &rng, &declines);
    select(&mut healed, &mut fs3);
    fs3.meta_delete(files::key_fid(SLOT_CARDMGM).get()).unwrap();
    let mut healed = PivApplet::new(SERIAL, HASH, None, &rng, &declines);
    select(&mut healed, &mut fs3);
    auth_mgm(&mut healed, &mut fs3); // asserts OK — a touch would fail here
    assert_eq!(
        touch(&meta(&mut healed, &mut fs3)),
        TOUCHPOLICY_NEVER,
        "the repair arm disagrees with every other writer"
    );

    // …and a host that DID raise the gate still has it: SET MGM KEY P2 = 0xFE is the
    // one path that may write ALWAYS, exactly as the reference does. Its own card —
    // `protect_mgm_key` above replaced the default key `auth_mgm` presents.
    let mut fs2 = new_fs();
    let mut app2 = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut app2, &mut fs2);
    auth_mgm(&mut app2, &mut fs2);
    let mut set_key = vec![ALGO_AES256, SLOT_CARDMGM, 32];
    set_key.extend_from_slice(&[0x7Bu8; 32]);
    assert_eq!(
        run(&mut app2, &mut fs2, INS_SET_MGMKEY, 0xFF, 0xFE, &set_key).0,
        Sw::OK
    );
    assert_eq!(
        touch(&meta(&mut app2, &mut fs2)),
        TOUCHPOLICY_ALWAYS,
        "SET MANAGEMENT KEY P2=0xFE"
    );
}

/// E142: `protect_mgm_key` is the last writer of the `9B` touch byte that ignores
/// what stood there. The previous fix reconciled the repair arm on the argument
/// that a re-provisioning restores published defaults and that an owner who raised
/// the gate keeps it; the panel's protect action broke the second half — it re-keys
/// the slot, and wrote `NEVER` over an `ALWAYS` the owner had set with
/// `SET MGM KEY P2 = 0xFE`.
///
/// The reference cannot arbitrate: `--protect` there is a `SET MGM KEY` and states
/// its own P2, so the card is only ever told the policy, never asked to keep one.
/// Ours has no P2 to state — a panel hold is its whole input — so the choice is
/// between inventing `NEVER` and carrying the owner's value, and the rule that
/// decides it is the one this repo already applies: a raised gate is a setting, and
/// a command named for something else must not drop it.
#[test]
fn protecting_the_management_key_keeps_a_gate_the_owner_raised() {
    let rng = RefCell::new(TestRng(13));
    let pres = RefCell::new(AlwaysConfirm);
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
    };
    let touch = |md: &[u8]| find_tag(md, 0x02).unwrap()[1];
    let meta = |app: &mut PivApplet, fs: &mut Fs<RamStorage>| -> Vec<u8> {
        let (sw, md) = run(app, fs, INS_GET_METADATA, 0, SLOT_CARDMGM, &[]);
        assert_eq!(sw, Sw::OK);
        md
    };

    for raised in [false, true] {
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
        if raised {
            let mut set_key = vec![ALGO_AES256, SLOT_CARDMGM, 32];
            set_key.extend_from_slice(&[0x7Bu8; 32]);
            assert_eq!(
                run(&mut app, &mut fs, INS_SET_MGMKEY, 0xFF, 0xFE, &set_key).0,
                Sw::OK
            );
        }
        let before = if raised {
            TOUCHPOLICY_ALWAYS
        } else {
            TOUCHPOLICY_NEVER
        };
        assert_eq!(touch(&meta(&mut app, &mut fs)), before, "raised={raised}");

        assert_eq!(protect_mgm_key(&dev, &mut fs, &mut TestRng(44)), Sw::OK);
        assert_eq!(
            touch(&meta(&mut app, &mut fs)),
            before,
            "protect_mgm_key must not move the touch byte, raised={raised}"
        );
        // The rest of the record is the protect action's own: a fresh AES-256 key,
        // and the escrow flag set. Without these the assertion above would also
        // pass on a protect that did nothing at all.
        let md = meta(&mut app, &mut fs);
        assert_eq!(find_tag(&md, 0x01).unwrap(), &[ALGO_AES256]);
        assert_eq!(find_tag(&md, 0x05).unwrap(), &[0], "not the factory key");
        assert!(mgm_is_protected(&mut fs), "the escrow flag is set");
    }

    // Carrying the byte forward must not become "trust whatever is there". A head
    // that is gone, and one carrying a value no writer emits, both resolve to the
    // published default — the same rule the repair arm was given, so a torn or
    // spurious record cannot invent a gate through this path either.
    for planted in [None, Some(0x7Fu8), Some(TOUCHPOLICY_CACHED)] {
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        let fid = files::key_fid(SLOT_CARDMGM).get();
        fs.meta_delete(fid).unwrap();
        if let Some(byte) = planted {
            fs.meta_add(fid, &[ALGO_AES192, MGM_PIN_POLICY, byte])
                .unwrap();
        }
        assert_eq!(protect_mgm_key(&dev, &mut fs, &mut TestRng(45)), Sw::OK);
        assert_eq!(
            touch(&meta(&mut app, &mut fs)),
            TOUCHPOLICY_NEVER,
            "planted={planted:?}"
        );
    }
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
    // Retired → active works too — the trip is not one-way. Measured on a
    // YubiKey 5.7.4: 82 → 9A, 9A → 82 and 82 → 9C all answer 9000, three runs.
    let (sw, _) = run(&mut app, &mut fs, INS_MOVE_KEY, 0x9A, 0x82, &[]);
    assert_eq!(sw, Sw::OK);
    let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x9A, &[]);
    assert_eq!(sw, Sw::OK);
    assert_eq!(find_tag(&md, 0x01).unwrap(), &[ALGO_ECCP256]);
    let (sw, _) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x82, &[]);
    assert_eq!(sw, Sw::REFERENCE_NOT_FOUND, "the source slot is emptied");
    // …and the moved key is the same key: it still signs.
    verify_pin(&mut app, &mut fs);
    assert_eq!(sign_p256(&mut app, &mut fs, 0x9A), Sw::OK);
    // Back out again, then delete.
    let (sw, _) = run(&mut app, &mut fs, INS_MOVE_KEY, 0x82, 0x9A, &[]);
    assert_eq!(sw, Sw::OK);
    let (sw, _) = run(&mut app, &mut fs, INS_MOVE_KEY, 0xFF, 0x82, &[]);
    assert_eq!(sw, Sw::OK);
    let (sw, _) = run(&mut app, &mut fs, INS_GET_METADATA, 0, 0x82, &[]);
    assert_eq!(sw, Sw::REFERENCE_NOT_FOUND);
}

/// The attestation identity is the device's, and no host replaces it. A YubiKey
/// lets one: `IMPORT` into `f9` loads a host key and `PUT DATA 5FFF01` loads the
/// matching certificate, a documented enterprise feature there. Here `f9` is
/// generated at first boot and never leaves, so taking those two commands would
/// let anyone holding the management key swap the device's attestation identity
/// irreversibly over one APDU. Measured cost of the other choice, on the record:
/// one probe pass in this project destroyed a real YubiKey's factory chain with
/// a single `PUT DATA 5FFF01`, and no reset restores it.
///
/// A DELIBERATE divergence. This test exists so a parity sweep cannot quietly
/// adopt it; the reasoning also lives in `docs/limitations.md`.
#[test]
fn the_attestation_identity_is_not_host_replaceable() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    // The key the card minted for itself, before anyone tries to displace it.
    let (sw, before) = run(
        &mut app,
        &mut fs,
        INS_GET_METADATA,
        0,
        SLOT_ATTESTATION,
        &[],
    );
    assert_eq!(sw, Sw::OK);

    let mut scalar = vec![0x06, 48];
    scalar.extend_from_slice(&[0x11u8; 48]);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            INS_IMPORT_ASYM,
            ALGO_ECCP384,
            SLOT_ATTESTATION,
            &scalar
        )
        .0,
        Sw::INCORRECT_P1P2,
        "IMPORT at F9"
    );
    let mut cert = vec![TAG_DATA_PATH, 0x03, 0x5F, 0xFF, 0x01, TAG_DATA_OBJECT, 0x03];
    cert.extend_from_slice(&[0x41, 0x42, 0x43]);
    assert_eq!(
        run(&mut app, &mut fs, INS_PUT_DATA, 0x3F, 0xFF, &cert).0,
        Sw::WRONG_DATA,
        "PUT DATA 5FFF01"
    );
    // Neither refusal moved anything: the key, its metadata and the certificate
    // the card signed for itself are the ones it started with.
    let (sw, after) = run(
        &mut app,
        &mut fs,
        INS_GET_METADATA,
        0,
        SLOT_ATTESTATION,
        &[],
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(after, before);
    let (sw, obj) = run(
        &mut app,
        &mut fs,
        INS_GET_DATA,
        0x3F,
        0xFF,
        &[0x5C, 0x03, 0x5F, 0xFF, 0x01],
    );
    assert_eq!(sw, Sw::OK);
    assert!(find_tag(find_tag(&obj, 0x53).unwrap(), 0x70).is_some());
    // …and attestation still works, which is what the refusals protect.
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            INS_ATTESTATION,
            SLOT_AUTHENTICATION,
            0,
            &[]
        )
        .0,
        Sw::REFERENCE_NOT_FOUND,
        "no key at 9A yet"
    );
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            INS_ASYM_KEYGEN,
            0,
            SLOT_AUTHENTICATION,
            &gen_template(ALGO_ECCP256)
        )
        .0,
        Sw::OK
    );
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            INS_ATTESTATION,
            SLOT_AUTHENTICATION,
            0,
            &[]
        )
        .0,
        Sw::OK
    );
}

/// `GET METADATA F9` answered `6A88` — "referenced data not found" — on a card
/// that mints that key and its self-signed certificate at first boot, which is
/// wrong on its face. The slot simply has no metadata record: `scan_files`
/// stores the key, its cached public point and the certificate, and never a
/// head, because `is_key(0xF9)` is false and nothing else needed one. A YubiKey
/// answers `9000` with algorithm, policies, origin and the public key. Ours
/// synthesizes the head rather than storing one, so a card provisioned by an
/// older build answers the same as a fresh one.
#[test]
fn the_attestation_slot_reports_its_metadata() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    let (sw, md) = run(
        &mut app,
        &mut fs,
        INS_GET_METADATA,
        0,
        SLOT_ATTESTATION,
        &[],
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(find_tag(&md, 0x01).unwrap(), &[ALGO_ECCP384]);
    assert_eq!(find_tag(&md, 0x03).unwrap(), &[ORIGIN_GENERATED]);
    // The public key is the one the F9 certificate carries.
    let pk = find_tag(&md, 0x04).unwrap();
    assert_eq!(pk[0], 0x86);
    let point = &pk[2..2 + pk[1] as usize];
    assert_eq!(point.len(), 97);
    let (sw, obj) = run(
        &mut app,
        &mut fs,
        INS_GET_DATA,
        0x3F,
        0xFF,
        &[0x5C, 0x03, 0x5F, 0xFF, 0x01],
    );
    assert_eq!(sw, Sw::OK);
    let cert = find_tag(find_tag(&obj, 0x53).unwrap(), 0x70).unwrap();
    let (_, parsed) = x509_parser::parse_x509_certificate(cert).unwrap();
    assert_eq!(
        parsed
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .as_ref(),
        point
    );
    // Ungated, like every other GET METADATA and like the oracle's.
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            INS_GET_METADATA,
            0,
            SLOT_ATTESTATION,
            &[]
        )
        .0,
        Sw::OK
    );
    // A card whose F9 key is gone reports it gone, rather than a synthetic head
    // over nothing. Read on the same applet: a SELECT would re-provision it.
    fs.delete_key(key_fid(SLOT_ATTESTATION)).unwrap();
    let _ = fs.delete(pubkey_fid(SLOT_ATTESTATION));
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            INS_GET_METADATA,
            0,
            SLOT_ATTESTATION,
            &[]
        )
        .0,
        Sw::REFERENCE_NOT_FOUND
    );
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

/// `SET RETRIES` with a zero in either parameter is refused, and that is a
/// DELIBERATE divergence — the one place this applet does not follow the oracle.
/// `00 FA 00 00` on a YubiKey 5.7.4 answers `9000` and sets both counters to
/// `0/0`, permanently blocking the card; `ykman piv info` then reads
/// `PIN tries remaining: 0/0` and only a factory reset recovers, taking every
/// key with it. AGENTS.md's one parity carve-out is "never adopt a YubiKey
/// behaviour that loses user data", so the refusal stays. This test exists so a
/// future parity sweep cannot quietly turn it into a brick.
///
/// Measured once, by the review pass that found it; deliberately NOT re-run —
/// blocking the oracle at 0/0 to re-confirm a finding that says "do not change
/// this" is not worth the card.
#[test]
fn a_zero_retry_budget_is_refused_and_that_is_deliberate() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    for (p1, p2) in [(0u8, 0u8), (0, 3), (3, 0)] {
        assert_eq!(
            run(&mut app, &mut fs, INS_SET_RETRIES, p1, p2, &[]).0,
            Sw::WRONG_DATA,
            "P1 {p1} P2 {p2}"
        );
    }
    // Nothing moved: a refused call is not a half-applied one, so the references
    // and their counters are still the ones the card started with.
    assert_eq!(reference_retries_left(&mut fs, PinRef::Pin), Some(3));
    assert_eq!(reference_retries_left(&mut fs, PinRef::Puk), Some(3));
    assert_eq!(
        run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN).0,
        Sw::OK
    );
    // …and the smallest budget that is still a budget goes through.
    assert_eq!(run(&mut app, &mut fs, INS_SET_RETRIES, 1, 1, &[]).0, Sw::OK);
    assert_eq!(reference_retries_left(&mut fs, PinRef::Pin), Some(1));
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
    assert_eq!(sw, Sw::WRONG_DATA);
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

    // Every host-writable data object: 5FC100..5FC1EF plus the ADMIN DATA
    // object 5FFF00.
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

/// The BIT group template `7F61` and the data object `5FC1B6` are two different
/// objects, and used to share one fid: `object_fid(0x5FC1B6)` is `0xD200 | 0xB6`
/// = `0xD2B6`, and `7F61` was mapped to that same `0xD2B6`, so a write to one
/// read back through the other. Measured on both cards: writing `5FC1B6` under
/// the management key is `9000` on a YubiKey 5.7.4 and on ours, and afterwards
/// `GET DATA 7F61` is `6A82` there and was the written value here.
#[test]
fn the_bit_group_template_is_not_an_alias_of_a_data_object() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);

    let bitgt = [TAG_DATA_PATH, 0x02, 0x7F, 0x61];
    let obj = [TAG_DATA_PATH, 0x03, 0x5F, 0xC1, 0xB6];
    assert_eq!(
        run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &bitgt).0,
        Sw::FILE_NOT_FOUND,
        "7F61 on a fresh card"
    );

    let mut write = obj.to_vec();
    write.extend_from_slice(&[TAG_DATA_OBJECT, 0x04, 0x41, 0x42, 0x43, 0x44]);
    assert_eq!(
        run(&mut app, &mut fs, INS_PUT_DATA, 0x3F, 0xFF, &write).0,
        Sw::OK
    );
    let (sw, back) = run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &obj);
    assert_eq!(sw, Sw::OK);
    assert_eq!(&back, &[TAG_DATA_OBJECT, 0x04, 0x41, 0x42, 0x43, 0x44]);
    // The whole finding: this was `9000` with `5FC1B6`'s bytes.
    assert_eq!(
        run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &bitgt).0,
        Sw::FILE_NOT_FOUND,
        "7F61 after writing 5FC1B6"
    );
    // Both cards refuse the `5C`-form write to `7F61` — this pins `put_data`'s
    // own 3-byte-path guard, not the map, and it passes with the alias restored.
    // It is here because it is why the alias was only ever reachable from the
    // other end. (A *bare* `7F 61 …` body is a different encoding and lands on
    // the acknowledged-not-stored arm.)
    let mut bad = bitgt.to_vec();
    bad.extend_from_slice(&[TAG_DATA_OBJECT, 0x02, 0x42, 0x42]);
    assert_eq!(
        run(&mut app, &mut fs, INS_PUT_DATA, 0x3F, 0xFF, &bad).0,
        Sw::WRONG_DATA
    );
    // The wire cells above hold for any fid `7F61` cannot reach, so this last
    // pair is about the map itself: `7F61` owns no file at all, rather than a
    // second one that would have to be kept out of `data_object_fid`'s way.
    assert_eq!(object_fid(0x7F61), None);
    assert_eq!(object_fid(0x5F_C1_B6), Some(0xD2B6));
}

/// An object id is its whole value. `object_fid`'s second arm matched on
/// `id & 0xFFFF`, so every id ending in `FF01` or `FF00` — including the 2-byte
/// `FF01` — resolved to the attestation certificate or the ADMIN-DATA object. A
/// YubiKey 5.7.4 resolves the exact three bytes and nothing else: `5FFF01` is
/// `9000` with 418 bytes, and `FF01`, `00FF01`, `7FFF01`, `ABFF01`, `FF00` and
/// `ABFF00` are all `6A82` (3 runs, byte-identical).
///
/// Also pins `data_object_fid`'s reservation bound, which is what keeps
/// `5FC1F0`/`5FC1F1` from being a second way into those two files — a
/// management-key write to the attestation certificate, which
/// `docs/limitations.md` says cannot happen. Widening the bound leaves the rest
/// of this suite green.
#[test]
fn an_object_id_is_its_whole_value() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);

    // The attestation certificate is minted by `scan_files`, so the 3-byte id
    // answers with it and every masked spelling must not.
    let exact = [TAG_DATA_PATH, 0x03, 0x5F, 0xFF, 0x01];
    let (sw, real) = run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &exact);
    assert_eq!(sw, Sw::OK);
    assert!(
        real.len() > 64,
        "the attestation cert is there to be aliased"
    );
    for masked in [
        &[TAG_DATA_PATH, 0x02, 0xFF, 0x01][..],
        &[TAG_DATA_PATH, 0x03, 0x00, 0xFF, 0x01][..],
        &[TAG_DATA_PATH, 0x03, 0x7F, 0xFF, 0x01][..],
        &[TAG_DATA_PATH, 0x03, 0xAB, 0xFF, 0x01][..],
        &[TAG_DATA_PATH, 0x02, 0xFF, 0x00][..],
        &[TAG_DATA_PATH, 0x03, 0xAB, 0xFF, 0x00][..],
    ] {
        assert_eq!(
            run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, masked).0,
            Sw::FILE_NOT_FOUND,
            "masked id {:02X?}",
            &masked[2..]
        );
    }
    // The ADMIN-DATA object is empty until something writes it, which is exactly
    // how the `7F61` alias hid: write it, then re-check the masked spellings.
    let mut admin = vec![TAG_DATA_PATH, 0x03, 0x5F, 0xFF, 0x00, TAG_DATA_OBJECT, 0x02];
    admin.extend_from_slice(&[PIVMAN_TAG, 0x00]);
    assert_eq!(
        run(&mut app, &mut fs, INS_PUT_DATA, 0x3F, 0xFF, &admin).0,
        Sw::OK
    );
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            INS_GET_DATA,
            0x3F,
            0xFF,
            &[TAG_DATA_PATH, 0x02, 0xFF, 0x00]
        )
        .0,
        Sw::FILE_NOT_FOUND,
        "FF00 once 5FFF00 has data"
    );

    // The `5FC1xx` arm's mask must be exact too, and this is the cell that makes
    // it matter: `read_needs_pin` matches the id EXACTLY, so a masked spelling
    // that still resolved to the file would read a Table 3 object with no PIN.
    let fp = [TAG_DATA_PATH, 0x03, 0x5F, 0xC1, 0x03];
    let mut plant = fp.to_vec();
    plant.extend_from_slice(&[TAG_DATA_OBJECT, 0x03, 0x41, 0x42, 0x43]);
    assert_eq!(
        run(&mut app, &mut fs, INS_PUT_DATA, 0x3F, 0xFF, &plant).0,
        Sw::OK
    );
    assert_eq!(
        run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &fp).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "the fingerprints object is PIN-gated by its exact id"
    );
    for masked in [
        &[TAG_DATA_PATH, 0x03, 0x1F, 0xC1, 0x03][..],
        &[TAG_DATA_PATH, 0x03, 0xAF, 0xC1, 0x03][..],
        &[TAG_DATA_PATH, 0x02, 0xC1, 0x03][..],
    ] {
        assert_eq!(
            run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, masked).0,
            Sw::FILE_NOT_FOUND,
            "masked 5FC103 as {:02X?} must not skip the PIN gate",
            &masked[2..]
        );
    }

    // The reservation that keeps the `5FC1xx` range out of those two files.
    assert_eq!(data_object_fid(0xEF), Some(0xD2EF));
    assert_eq!(data_object_fid(0xF0), None);
    assert_eq!(data_object_fid(0xF1), None);
    let mut over = vec![TAG_DATA_PATH, 0x03, 0x5F, 0xC1, 0xF1, TAG_DATA_OBJECT, 0x03];
    over.extend_from_slice(b"XXX");
    assert_eq!(
        run(&mut app, &mut fs, INS_PUT_DATA, 0x3F, 0xFF, &over).0,
        Sw::WRONG_DATA,
        "5FC1F1 must not be a second door to the attestation certificate"
    );
    let (sw, still) = run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &exact);
    assert_eq!(sw, Sw::OK);
    assert_eq!(still, real, "the attestation certificate is untouched");
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
/// a card missing the retry counters answers 6A88 to every later RESET instead of
/// the honest 6581. (The PIN/PUK/retry files now go *last* — see
/// `a_torn_reset_never_leaves_a_key_behind_the_default_pin`.)
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

    // Not wedged: the retry file is still there, so a second RESET answers the
    // honest 6581 rather than 6A88 (no retry counters to read).
    let (sw, _) = run(&mut app, &mut fs, INS_RESET, 0, 0, &[]);
    assert_eq!(
        sw,
        Sw::MEMORY_FAILURE,
        "a failed RESET must fail honestly, not wedge on 6A88"
    );
    // And the card is left exactly as the failed RESET found it. Deleting the gate
    // records last (audit run-35) means a sweep that never got past phase 1 has not
    // touched them — so the references stay blocked instead of being handed back a
    // fresh 3/3 budget, which is what the old ordering did on every failed RESET.
    let (sw, _) = run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN);
    assert_eq!(
        sw,
        Sw::PIN_BLOCKED,
        "a failed RESET must not refill the retries"
    );
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
    // The 241 objects that land are 5FC100..5FC1EF plus ADMIN DATA.
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
    // The applet holds a way to READ the fuses, not the key, so its test source has
    // to be a plain `fn` — a closure over `OTP` could not coerce to one.
    fn otp_source() -> Option<[u8; 32]> {
        Some(OTP)
    }
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
    let mut app2 = PivApplet::new(SERIAL, HASH, Some(otp_source as FusedKey), &rng, &pres);
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

        // Without a PIN: never discloses the key, and never says whether the
        // object is there — PRINTED's read condition is PIN whatever it holds.
        let (sw_nopin, body_nopin) = run(&mut app, &mut fs, INS_GET_DATA, 0x3F, 0xFF, &get_printed);
        assert_eq!(sw_nopin, Sw::SECURITY_STATUS_NOT_SATISFIED);
        assert!(body_nopin.is_empty());

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

/// RFC 5280 §4.2.1.3: "If the keyCertSign bit is asserted, then the cA bit in the
/// basic constraints extension MUST also be asserted." Every certificate the device
/// emits asserted keyCertSign, leaves included, while their basicConstraints says
/// `cA=FALSE` — a self-contradiction on the object an auditor reads to decide what
/// the key is for (audit run-34 #36). The two must track each other, so assert the
/// pair on every cert this test can reach rather than one of them in isolation.
#[test]
fn key_cert_sign_is_asserted_only_on_a_ca() {
    use x509_parser::extensions::ParsedExtension;

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

    // The attestation leaf (cA=FALSE) and the F9 self-signed CA it chains to.
    let (sw, leaf) = run(&mut app, &mut fs, INS_ATTESTATION, 0x9A, 0, &[]);
    assert_eq!(sw, Sw::OK);
    let (sw, f9) = run(
        &mut app,
        &mut fs,
        INS_GET_DATA,
        0x3F,
        0xFF,
        &[0x5C, 0x03, 0x5F, 0xFF, 0x01],
    );
    assert_eq!(sw, Sw::OK);
    let f9der = find_tag(find_tag(&f9, 0x53).unwrap(), 0x70).expect("F9 cert object");

    for (label, der) in [("attestation leaf", &leaf[..]), ("F9 self-cert", f9der)] {
        let (_, c) = x509_parser::parse_x509_certificate(der).unwrap();
        let is_ca = c.basic_constraints().unwrap().is_some_and(|bc| bc.value.ca);
        let ku = c
            .extensions()
            .iter()
            .find_map(|e| match e.parsed_extension() {
                ParsedExtension::KeyUsage(k) => Some(k),
                _ => None,
            })
            .expect("keyUsage extension");
        assert!(ku.digital_signature(), "{label}: no digitalSignature");
        assert_eq!(
            ku.key_cert_sign(),
            is_ca,
            "{label}: keyCertSign={} but cA={is_ca} — RFC 5280 §4.2.1.3",
            ku.key_cert_sign()
        );
    }
}

/// Policy bytes: `DEFAULT` and undefined values must not reach flash, and both
/// gates must fail closed on whatever is already there. Only the length of the
/// management key was checked at use, so an AES-192 key answered a full 3DES
/// mutual auth (audit run-34 #18/#19).
#[test]
fn policy_bytes_are_resolved_and_undefined_ones_refused() {
    use crate::keygen::resolved_policies;

    // An ABSENT tag is what "default" means…
    assert_eq!(
        resolved_policies(0x9A, None, None).unwrap(),
        [PINPOLICY_ONCE, TOUCHPOLICY_NEVER]
    );
    assert_eq!(
        resolved_policies(SLOT_SIGNATURE, None, None).unwrap()[0],
        PINPOLICY_ALWAYS
    );
    // …and nothing undefined is ever stored — `DEFAULT` on the wire included (E80).
    for bad in [PINPOLICY_DEFAULT, 4u8, 0x42, 0xFF] {
        assert!(
            resolved_policies(0x9A, Some(bad), None).is_err(),
            "pin {bad}"
        );
        assert!(
            resolved_policies(0x9A, None, Some(bad)).is_err(),
            "touch {bad}"
        );
    }
    // Every stored value round-trips.
    for p in [PINPOLICY_NEVER, PINPOLICY_ONCE, PINPOLICY_ALWAYS] {
        for t in [TOUCHPOLICY_NEVER, TOUCHPOLICY_ALWAYS, TOUCHPOLICY_CACHED] {
            assert_eq!(resolved_policies(0x9A, Some(p), Some(t)).unwrap(), [p, t]);
        }
    }
}

/// A GENERATE that names no touch policy takes the card's default, and the card's
/// default is NEVER. Measured on a YubiKey 5.7.4, 3 runs × 4 slots, both through
/// `ykman` and through a raw GENERATE with no `AC` policy tags at all: touch byte
/// `0x01` every time. Ours resolved the same absent tag to ALWAYS, so a plain
/// `ykman piv keys generate 9a` minted a key demanding a physical press on every
/// private-key operation — scripted PIV use (pkcs11, age-plugin, SSH) hung on it
/// with no diagnostic beyond a timeout, and the flag the user needed was the one
/// they had not passed. Asked for explicitly, ALWAYS still means ALWAYS.
#[test]
fn a_generated_key_takes_the_cards_touch_default_which_is_never() {
    use crate::keygen::resolved_policies;
    for slot in [
        SLOT_AUTHENTICATION,
        SLOT_SIGNATURE,
        SLOT_KEYMGM,
        SLOT_CARDAUTH,
        SLOT_RETIRED_FIRST,
    ] {
        assert_eq!(
            resolved_policies(slot, None, None).unwrap()[1],
            TOUCHPOLICY_NEVER,
            "slot {slot:02X}"
        );
        assert_eq!(
            resolved_policies(slot, None, Some(TOUCHPOLICY_ALWAYS)).unwrap()[1],
            TOUCHPOLICY_ALWAYS,
            "slot {slot:02X} asked for ALWAYS"
        );
    }
    // End to end, against a presence that says no: a default-generated key signs
    // anyway, because it never asks. Only the stored byte can make this pass.
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(Scripted { confirm: false });
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0,
        SLOT_AUTHENTICATION,
        &gen_template(ALGO_ECCP256),
    );
    assert_eq!(sw, Sw::OK);
    let (sw, meta) = run(
        &mut app,
        &mut fs,
        INS_GET_METADATA,
        0,
        SLOT_AUTHENTICATION,
        &[],
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(&meta[3..6], &[0x02, 0x02, PINPOLICY_ONCE]);
    assert_eq!(meta[6], TOUCHPOLICY_NEVER);
    verify_pin(&mut app, &mut fs);
    assert_eq!(sign_p256(&mut app, &mut fs, SLOT_AUTHENTICATION), Sw::OK);
    // …and a slot generated with an explicit ALWAYS is refused by that same
    // declining presence, so the assertion above is about the stored policy and
    // not about the presence stub having stopped being asked at all.
    let mut tmpl = gen_template(ALGO_ECCP256);
    tmpl.extend_from_slice(&[0xAB, 0x01, TOUCHPOLICY_ALWAYS]);
    tmpl[1] += 3;
    let (sw, _) = run(&mut app, &mut fs, INS_ASYM_KEYGEN, 0, SLOT_KEYMGM, &tmpl);
    assert_eq!(sw, Sw::OK);
    assert_eq!(
        sign_p256(&mut app, &mut fs, SLOT_KEYMGM),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
}

/// `9E` is the Card Authentication Key — SP 800-73-4 makes it the slot usable
/// *without* a PIN, for physical-access and contactless readers — and a YubiKey
/// 5.7.4 defaults it to PIN `NEVER`. Ours defaulted it to `ONCE`, which made the
/// slot useless for the one thing it is for. Measured 3 runs: a default `9E` key
/// signs with no VERIFY at all, and its signature spends no ALWAYS freshness,
/// while `9A` in the same state answers `6982` and does spend. An explicit
/// `--pin-policy ONCE` is honoured identically on both cards, so nobody loses a
/// gate they asked for.
#[test]
fn the_card_authentication_slot_needs_no_pin_by_default() {
    use crate::keygen::resolved_policies;
    for (slot, want) in [
        (SLOT_AUTHENTICATION, PINPOLICY_ONCE),
        (SLOT_SIGNATURE, PINPOLICY_ALWAYS),
        (SLOT_KEYMGM, PINPOLICY_ONCE),
        (SLOT_CARDAUTH, PINPOLICY_NEVER),
        (SLOT_RETIRED_FIRST, PINPOLICY_ONCE),
    ] {
        assert_eq!(
            resolved_policies(slot, None, None).unwrap()[0],
            want,
            "slot {slot:02X}"
        );
    }
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    for slot in [SLOT_AUTHENTICATION, SLOT_SIGNATURE, SLOT_CARDAUTH] {
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                INS_ASYM_KEYGEN,
                0,
                slot,
                &gen_template(ALGO_ECCP256)
            )
            .0,
            Sw::OK
        );
    }
    // Nothing verified: the card-auth slot signs, the authentication slot does not.
    assert_eq!(sign_p256(&mut app, &mut fs, SLOT_CARDAUTH), Sw::OK);
    assert_eq!(
        sign_p256(&mut app, &mut fs, SLOT_AUTHENTICATION),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    // …and a NEVER-policy operation spends no freshness, where a ONCE one does.
    verify_pin(&mut app, &mut fs);
    assert_eq!(sign_p256(&mut app, &mut fs, SLOT_CARDAUTH), Sw::OK);
    assert_eq!(sign_p256(&mut app, &mut fs, SLOT_SIGNATURE), Sw::OK);
    verify_pin(&mut app, &mut fs);
    assert_eq!(sign_p256(&mut app, &mut fs, SLOT_AUTHENTICATION), Sw::OK);
    assert_eq!(
        sign_p256(&mut app, &mut fs, SLOT_SIGNATURE),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    // An explicit ONCE at 9E is still a gate.
    let mut once = gen_template(ALGO_ECCP256);
    once.extend_from_slice(&[0xAA, 0x01, PINPOLICY_ONCE]);
    once[1] += 3;
    auth_mgm(&mut app, &mut fs);
    assert_eq!(
        run(&mut app, &mut fs, INS_ASYM_KEYGEN, 0, SLOT_CARDAUTH, &once).0,
        Sw::OK
    );
    let mut cold = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut cold, &mut fs);
    assert_eq!(
        sign_p256(&mut cold, &mut fs, SLOT_CARDAUTH),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    verify_pin(&mut cold, &mut fs);
    assert_eq!(sign_p256(&mut cold, &mut fs, SLOT_CARDAUTH), Sw::OK);
}

/// A literal `0` policy byte in slot metadata is what an *older* build could
/// store, and only the use-time path ever sees one. It has to mean the same
/// thing the store-time resolver means, or a legacy record and a new one behave
/// differently at the same slot with nothing to notice it — which is why both
/// now go through `resolved_policies`.
#[test]
fn a_legacy_default_policy_byte_resolves_as_the_card_default() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    for slot in [SLOT_AUTHENTICATION, SLOT_SIGNATURE, SLOT_CARDAUTH] {
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                INS_ASYM_KEYGEN,
                0,
                slot,
                &gen_template(ALGO_ECCP256)
            )
            .0,
            Sw::OK
        );
        // Overwrite the resolved head with the unresolved byte an older build left.
        fs.meta_add(
            key_fid(slot).get(),
            &[ALGO_ECCP256, PINPOLICY_DEFAULT, TOUCHPOLICY_NEVER],
        )
        .unwrap();
    }
    let mut cold = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut cold, &mut fs);
    // 9E resolves to NEVER, so it signs with nothing verified; 9A does not.
    assert_eq!(sign_p256(&mut cold, &mut fs, SLOT_CARDAUTH), Sw::OK);
    assert_eq!(
        sign_p256(&mut cold, &mut fs, SLOT_AUTHENTICATION),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    // 9C resolves to ALWAYS, so one VERIFY buys exactly one signature there.
    verify_pin(&mut cold, &mut fs);
    assert_eq!(sign_p256(&mut cold, &mut fs, SLOT_AUTHENTICATION), Sw::OK);
    assert_eq!(
        sign_p256(&mut cold, &mut fs, SLOT_SIGNATURE),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    // An UNDEFINED byte is not resolvable and must stay fail-closed.
    fs.meta_add(
        key_fid(SLOT_CARDAUTH).get(),
        &[ALGO_ECCP256, 0x42, TOUCHPOLICY_NEVER],
    )
    .unwrap();
    let mut cold2 = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut cold2, &mut fs);
    assert_eq!(
        sign_p256(&mut cold2, &mut fs, SLOT_CARDAUTH),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
}

#[test]
fn generate_refuses_an_undefined_policy_byte() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    // AC { 80 01 <algo> · AB 01 42 } — an undefined touch policy.
    let tmpl = [0xAC, 0x06, 0x80, 0x01, ALGO_ECCP256, 0xAB, 0x01, 0x42];
    let (sw, _) = run(&mut app, &mut fs, INS_ASYM_KEYGEN, 0, 0x9A, &tmpl);
    assert_eq!(
        sw,
        Sw::WRONG_DATA,
        "an undefined touch policy must not be stored"
    );
}

/// E80: "default" is expressed by OMITTING the policy tag. An explicit `AA 01 00`
/// / `AB 01 00` is a value, and a YubiKey 5.7.4 refuses it exactly as it refuses
/// `0xFF` — `6A80`, 3/3, on `9E` and `9A`, with and without the sibling tag. Ours
/// mapped it onto `PINPOLICY_DEFAULT` and resolved it, so it accepted an input the
/// reference rejects. Not to be confused with
/// `a_legacy_default_pin_policy_byte_resolves_at_use_time`: a `0` already **stored**
/// in a slot's metadata by an older build must go on resolving. Wire acceptance and
/// stored resolution are two owners of the same byte, and only the wire one diverged.
#[test]
fn an_explicit_zero_policy_byte_is_refused_like_any_other_undefined_one() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);

    let template = |policies: &[u8]| {
        let mut ac = vec![0x80, 0x01, ALGO_ECCP256];
        ac.extend_from_slice(policies);
        let mut t = vec![0xAC, ac.len() as u8];
        t.extend_from_slice(&ac);
        t
    };
    // The oracle's own row list, in its order: the three `0x00` spellings, then the
    // accepted `0x01`s, then the undefined values that already matched.
    let rows: [(&str, &[u8], Sw); 9] = [
        ("no policy tags", &[], Sw::OK),
        ("AA 01 00", &[0xAA, 0x01, 0x00], Sw::WRONG_DATA),
        ("AB 01 00", &[0xAB, 0x01, 0x00], Sw::WRONG_DATA),
        (
            "AA 01 00 + AB 01 00",
            &[0xAA, 0x01, 0x00, 0xAB, 0x01, 0x00],
            Sw::WRONG_DATA,
        ),
        ("AA 01 01", &[0xAA, 0x01, PINPOLICY_NEVER], Sw::OK),
        ("AB 01 01", &[0xAB, 0x01, TOUCHPOLICY_NEVER], Sw::OK),
        ("AA 01 05", &[0xAA, 0x01, 0x05], Sw::WRONG_DATA),
        ("AA 01 FF", &[0xAA, 0x01, 0xFF], Sw::WRONG_DATA),
        ("AB 01 FF", &[0xAB, 0x01, 0xFF], Sw::WRONG_DATA),
    ];
    // What is in the slot: the sealed key bytes AND the metadata record. Neither
    // alone is enough — `has_key` cannot tell a refusal that *replaced* the key from
    // one that left it alone (run-36 is about the replacement), and the meta record
    // is written last, so a refusal between key and meta leaves GET METADATA
    // answering exactly what it answered before.
    let identity = |app: &mut PivApplet, fs: &mut Fs<RamStorage>, slot: u8| {
        let mut sealed = [0u8; 256];
        let key = fs
            .read_key(key_fid(slot), &mut sealed)
            .map(|n| sealed[..n.min(sealed.len())].to_vec());
        (key, run(app, fs, INS_GET_METADATA, 0, slot, &[]))
    };
    for slot in [SLOT_CARDAUTH, SLOT_AUTHENTICATION] {
        // The first command on an untouched slot is a refusing one, so the guard
        // below runs once against a genuinely empty slot as well as against a
        // provisioned one.
        for (label, policies, want) in rows.iter().rev().chain(rows.iter()) {
            let before = identity(&mut app, &mut fs, slot);
            let sw = run(
                &mut app,
                &mut fs,
                INS_ASYM_KEYGEN,
                0,
                slot,
                &template(policies),
            )
            .0;
            assert_eq!(sw, *want, "GENERATE {slot:02X} with {label}");
            if *want == Sw::WRONG_DATA {
                assert_eq!(
                    identity(&mut app, &mut fs, slot),
                    before,
                    "GENERATE {slot:02X} with {label} touched the slot"
                );
            }
        }
    }
}

/// IMPORT reads the same `AA`/`AB` tags through the same resolver, so it refuses
/// the same byte. **Unmeasured on the reference** — no YubiKey reading exists for
/// an imported `AA 01 00` — so this cell is taken by class, not by measurement:
/// one byte must not mean two different things on two commands of one card.
#[test]
fn import_refuses_an_explicit_zero_policy_byte() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);

    let import = |app: &mut PivApplet, fs: &mut Fs<RamStorage>, scalar: u8, policies: &[u8]| {
        let mut imp = vec![0x06, 0x20];
        imp.extend_from_slice(&[scalar; 32]);
        imp.extend_from_slice(policies);
        run(app, fs, INS_IMPORT_ASYM, ALGO_ECCP256, SLOT_KEYMGM, &imp).0
    };
    let identity = |app: &mut PivApplet, fs: &mut Fs<RamStorage>| {
        let mut sealed = [0u8; 256];
        let key = fs
            .read_key(key_fid(SLOT_KEYMGM), &mut sealed)
            .map(|n| sealed[..n.min(sealed.len())].to_vec());
        (key, run(app, fs, INS_GET_METADATA, 0, SLOT_KEYMGM, &[]))
    };

    // Into an empty slot first, then over a provisioned one with a DIFFERENT key:
    // `import` writes the key and drops the slot meta, so a refusal that came after
    // it left the old key gone and the new one with no metadata to gate it.
    assert_eq!(
        import(&mut app, &mut fs, 0x77, &[0xAA, 0x01, 0x00]),
        Sw::WRONG_DATA
    );
    assert!(
        !fs.has_key(key_fid(SLOT_KEYMGM)),
        "a refusal filled the slot"
    );
    assert_eq!(import(&mut app, &mut fs, 0x77, &[]), Sw::OK);

    let before = identity(&mut app, &mut fs);
    assert_eq!(before.1.0, Sw::OK);
    for policies in [&[0xAA, 0x01, 0x00][..], &[0xAB, 0x01, 0x00][..]] {
        assert_eq!(
            import(&mut app, &mut fs, 0x55, policies),
            Sw::WRONG_DATA,
            "{policies:02X?}"
        );
        assert_eq!(
            identity(&mut app, &mut fs),
            before,
            "a refused IMPORT {policies:02X?} replaced the slot"
        );
    }
    // The control: a defined value still lands, and moves the metadata.
    assert_eq!(
        import(&mut app, &mut fs, 0x55, &[0xAA, 0x01, PINPOLICY_NEVER]),
        Sw::OK
    );
    assert_ne!(identity(&mut app, &mut fs), before);
}

/// The touch twin of `a_legacy_default_pin_policy_byte_resolves_at_use_time`: a
/// stored `0` needs no use-time resolution because `check_touch` fails closed —
/// only `TOUCHPOLICY_NEVER` skips the prompt — so a pre-run-34 record behaves
/// exactly like the ALWAYS an absent tag resolves to.
#[test]
fn a_legacy_default_touch_policy_byte_still_demands_a_touch() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(Scripted { confirm: true });
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            INS_ASYM_KEYGEN,
            0,
            SLOT_AUTHENTICATION,
            &gen_template(ALGO_ECCP256)
        )
        .0,
        Sw::OK
    );
    // Rewrite the stored touch byte to what an older build could have left there.
    let mut meta = [0u8; 96];
    let n = fs
        .meta_find(key_fid(SLOT_AUTHENTICATION).get(), &mut meta)
        .unwrap();
    meta[2] = TOUCHPOLICY_DEFAULT;
    fs.meta_add(key_fid(SLOT_AUTHENTICATION).get(), &meta[..n])
        .unwrap();

    assert_eq!(sign_p256(&mut app, &mut fs, SLOT_AUTHENTICATION), Sw::OK);
    pres.borrow_mut().confirm = false;
    assert_ne!(
        sign_p256(&mut app, &mut fs, SLOT_AUTHENTICATION),
        Sw::OK,
        "a stored DEFAULT touch byte must not mean 'no touch'"
    );
}

#[test]
fn the_management_key_algorithm_is_enforced_at_use() {
    // The factory 9B key is AES-192; 3DES shares its 24-byte length, so only the
    // *declared* algorithm separates them.
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_3DES,
        0x9B,
        &[0x7C, 0x02, 0x81, 0x00],
    );
    assert_eq!(sw, Sw::WRONG_DATA, "3DES against an AES-192 key");
    // …and the real algorithm still works.
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_AUTHENTICATE,
        ALGO_AES192,
        0x9B,
        &[0x7C, 0x02, 0x81, 0x00],
    );
    assert_eq!(sw, Sw::OK);
}

/// `Storage` that enumerates in INSERTION order — the flash ring's oldest-first
/// yield, which `RamStorage`'s `HashMap` does not model — and whose `remove`
/// starts failing after `budget` deletions, standing in for a power cut mid-wipe.
#[derive(Clone)]
struct TearAfter {
    items: Vec<(u16, Vec<u8>)>,
    budget: usize,
}

impl Storage for TearAfter {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        let v = &self.items.iter().find(|(k, _)| *k == fid)?.1;
        let n = v.len().min(buf.len());
        buf[..n].copy_from_slice(&v[..n]);
        Some(v.len())
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
        match self.items.iter_mut().find(|(k, _)| *k == fid) {
            Some(e) => e.1 = data.to_vec(),
            None => self.items.push((fid, data.to_vec())),
        }
        Ok(())
    }
    fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
        if self.budget == 0 {
            return Err(rsk_sdk::error::Error::MemoryFatal);
        }
        self.budget -= 1;
        self.items.retain(|(k, _)| *k != fid);
        Ok(())
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.items
            .iter()
            .find(|(k, _)| *k == fid)
            .map(|(_, v)| v.len())
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        for (k, _) in &self.items {
            f(*k);
        }
        true
    }
}

/// Audit run-35: a PIV RESET interrupted part-way must never leave a slot key
/// live behind the re-provisioned factory PIN.
///
/// `wipe_piv` sweeps in flash-ring order, `scan_files` re-creates any absent
/// credential file at its factory default, and PIV slot keys are sealed
/// device-rooted rather than PIN-bound — so a single combined sweep that reached
/// `EF_PIN` before the keys and then lost power handed the owner's keys to
/// whoever holds the card, behind PIN 123456. The invariant asserted here is the
/// ordering one, not an end state: for EVERY tear point, a surviving key implies a
/// surviving owner PIN.
#[test]
fn a_torn_reset_never_leaves_a_key_behind_the_default_pin() {
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
    };
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);

    // Provision a card the way an owner would: a key in 9A and a PIN of their own.
    let mut fs = Fs::new(TearAfter {
        items: Vec::new(),
        budget: usize::MAX,
    });
    fs.scan();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    let owner_pin = [0x39u8, 0x38, 0x37, 0x36, 0x35, 0x34, 0xFF, 0xFF];
    let mut chg = DEFAULT_PIN.to_vec();
    chg.extend_from_slice(&owner_pin);
    let (sw, _) = run(&mut app, &mut fs, INS_CHANGE_PIN, 0, 0x80, &chg);
    assert_eq!(sw, Sw::OK, "owner sets their own PIN");
    let tmpl = [0xAC, 0x03, 0x80, 0x01, ALGO_ECCP256];
    let (sw, _) = run(&mut app, &mut fs, INS_ASYM_KEYGEN, 0, 0x9A, &tmpl);
    assert_eq!(sw, Sw::OK, "owner generates a key in 9A");

    let mut owner_rec = [0u8; 64];
    let owner_n = fs.read(files::EF_PIN, &mut owner_rec).unwrap();
    let base: TearAfter = fs.into_storage();
    let live = base.items.len();

    let mut saw_survivor = false;
    for budget in 0..live {
        let mut fs = Fs::new(TearAfter {
            budget,
            ..base.clone()
        });
        fs.scan();
        let _ = reset_files(&dev, &mut fs, &mut TestRng(3));

        if !fs.has_key(files::key_fid(SLOT_AUTHENTICATION)) {
            continue;
        }
        saw_survivor = true;
        let mut now = [0u8; 64];
        let n = fs.read(files::EF_PIN, &mut now).unwrap_or(0);
        assert_eq!(
            (&now[..n], n),
            (&owner_rec[..owner_n], owner_n),
            "tear at {budget} left the 9A key live behind a re-provisioned PIN"
        );
    }
    assert!(
        saw_survivor,
        "vacuous: no tear point left a key behind, so nothing was proved"
    );
}

/// Audit run-36: the two-phase split classified only the PIN, PUK and retry
/// counters as gates — but `scan_files` re-provisions the 9B management key at the
/// *published* `DEFAULT_MGM` too, so it gates the applet exactly as they do. A
/// sweep that took it first and then lost power handed PIV administrative
/// authority (IMPORT, GENERATE, PUT DATA, MOVE KEY) to whoever holds the card,
/// over slot keys that are still live. Same invariant as
/// `a_torn_reset_never_leaves_a_key_behind_the_default_pin`, on the other gate:
/// for EVERY tear point, a surviving key implies a surviving owner management key.
#[test]
fn a_torn_reset_never_leaves_a_key_behind_the_default_mgm() {
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
    };
    let rng = RefCell::new(TestRng(11));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);

    // Provision the way `ykman piv` does: rotate the management key away from the
    // published default FIRST, then generate the slot key it protects.
    let mut fs = Fs::new(TearAfter {
        items: Vec::new(),
        budget: usize::MAX,
    });
    fs.scan();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    let owner_key = [0x5Au8; 24];
    let mut set_key = vec![ALGO_AES192, SLOT_CARDMGM, owner_key.len() as u8];
    set_key.extend_from_slice(&owner_key);
    let (sw, _) = run(&mut app, &mut fs, INS_SET_MGMKEY, 0xFF, 0xFF, &set_key);
    assert_eq!(sw, Sw::OK, "owner rotates the management key");
    let tmpl = [0xAC, 0x03, 0x80, 0x01, ALGO_ECCP256];
    let (sw, _) = run(&mut app, &mut fs, INS_ASYM_KEYGEN, 0, 0x9A, &tmpl);
    assert_eq!(sw, Sw::OK, "owner generates a key in 9A");

    // The owner's sealed 9B record. A re-provisioned DEFAULT_MGM is sealed with a
    // fresh nonce, so byte equality is what separates "the owner's key survived"
    // from "the published default was re-seeded over it".
    let mgm_fid = files::key_fid(SLOT_CARDMGM).get();
    let mut owner_rec = [0u8; 128];
    let owner_n = fs.read(mgm_fid, &mut owner_rec).unwrap();
    let base: TearAfter = fs.into_storage();
    let live = base.items.len();

    let mut saw_survivor = false;
    for budget in 0..live {
        let mut fs = Fs::new(TearAfter {
            budget,
            ..base.clone()
        });
        fs.scan();
        let _ = reset_files(&dev, &mut fs, &mut TestRng(3));

        if !fs.has_key(files::key_fid(SLOT_AUTHENTICATION)) {
            continue;
        }
        saw_survivor = true;
        let mut now = [0u8; 128];
        let n = fs.read(mgm_fid, &mut now).unwrap_or(0);
        assert_eq!(
            (&now[..n], n),
            (&owner_rec[..owner_n], owner_n),
            "tear at {budget} left the 9A key live behind a re-provisioned DEFAULT_MGM"
        );
    }
    assert!(
        saw_survivor,
        "vacuous: no tear point left a key behind, so nothing was proved"
    );
}

/// The 9B key and its metadata are provisioned as a pair, but only the *key* is a
/// phase-2 gate — `EF_META` is one record shared by every applet and the
/// device-wide wipe takes it in phase 1. `scan_files` must therefore repair a
/// surviving key's missing metadata, or PIV administration is wedged: `meta_find`
/// failing makes `GENERAL AUTHENTICATE` answer `REFERENCE_NOT_FOUND` forever,
/// and the key-absent guard means nothing ever re-adds it.
#[test]
fn scan_files_repairs_the_mgm_metadata_when_only_it_is_missing() {
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
    };
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    scan_files(&dev, &mut fs, &mut TestRng(5)).unwrap();
    let mgm_fid = files::key_fid(SLOT_CARDMGM).get();
    let mut before = [0u8; 128];
    let before_n = fs.read(mgm_fid, &mut before).unwrap();

    // The state a torn device-wide wipe leaves: the key live, its metadata gone.
    fs.meta_delete(mgm_fid).unwrap();
    let mut meta = [0u8; 8];
    assert!(fs.meta_find(mgm_fid, &mut meta).is_none());

    scan_files(&dev, &mut fs, &mut TestRng(6)).unwrap();

    let n = fs.meta_find(mgm_fid, &mut meta).unwrap_or(0);
    assert!(n >= 3, "the metadata the auth path reads was not repaired");
    assert_eq!(meta[0], ALGO_AES192, "repaired with the wrong algorithm");
    // E95: the repair is a re-provisioning, and `scan_files` re-provisions every
    // other missing record at its published default (PIN, PUK, retries, the key
    // itself). The touch byte is not recoverable, so it takes that same default —
    // the one a YubiKey 5.7.4 reports on a fresh card, measured 3/3.
    assert_eq!(
        meta[2], TOUCHPOLICY_NEVER,
        "the repair invented a touch gate"
    );
    let mut after = [0u8; 128];
    let after_n = fs.read(mgm_fid, &mut after).unwrap();
    assert_eq!(
        (&after[..after_n], after_n),
        (&before[..before_n], before_n),
        "repairing the metadata must not re-seed the key"
    );
}

/// Audit run-36: `generate_ec` wrote the certificate, the sealed key and the pubkey
/// cache and only THEN resolved the requested policies, so a request carrying a
/// policy byte this firmware does not implement — Yubico defines PIN policy 0x04/0x05
/// for Bio match — answered 6A80 with the slot's previous key and certificate already
/// destroyed, and the new key governed by the OLD key's metadata. A refused command
/// must leave the slot exactly as it found it. Its two sibling generate paths
/// (`generate_rsa_blocking`, the firmware RSA fast path) already validate first.
#[test]
fn a_refused_generate_leaves_the_slot_untouched() {
    let rng = RefCell::new(TestRng(21));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);

    // A key with an explicit NEVER/NEVER policy.
    let ok = [
        0xAC,
        0x09,
        0x80,
        0x01,
        ALGO_ECCP256,
        0xAA,
        0x01,
        PINPOLICY_NEVER,
        0xAB,
        0x01,
        TOUCHPOLICY_NEVER,
    ];
    let (sw, _) = run(&mut app, &mut fs, INS_ASYM_KEYGEN, 0, 0x9A, &ok);
    assert_eq!(sw, Sw::OK);
    let mut before = [0u8; 128];
    let before_n = fs
        .read(files::pubkey_fid(SLOT_AUTHENTICATION), &mut before)
        .unwrap();

    // Same slot, a touch-policy byte this firmware does not implement.
    let bad = [
        0xAC,
        0x09,
        0x80,
        0x01,
        ALGO_ECCP256,
        0xAA,
        0x01,
        PINPOLICY_ALWAYS,
        0xAB,
        0x01,
        0x09,
    ];
    let (sw, _) = run(&mut app, &mut fs, INS_ASYM_KEYGEN, 0, 0x9A, &bad);
    assert_ne!(sw, Sw::OK, "an undefined policy byte must be refused");

    let mut after = [0u8; 128];
    let after_n = fs
        .read(files::pubkey_fid(SLOT_AUTHENTICATION), &mut after)
        .unwrap_or(0);
    assert_eq!(
        (&after[..after_n], after_n),
        (&before[..before_n], before_n),
        "the refused GENERATE replaced the slot's key anyway"
    );
}

/// The other tear direction: `Fs::force_delete` swallows a failed `meta_delete`
/// (`let _ =`) and removes the key anyway, so the head can outlive the key it
/// describes. Minting `DEFAULT_MGM` under a stale AES-256 head wedges the slot on
/// `mgm_len != want` in `general_authenticate` — and RESET runs this same path, so
/// nothing would ever clear it. The mint arm must rewrite the head unconditionally.
#[test]
fn scan_files_rewrites_a_stale_mgm_head_when_the_key_is_re_minted() {
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
    };
    let mgm = files::key_fid(SLOT_CARDMGM);
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    scan_files(&dev, &mut fs, &mut TestRng(5)).unwrap();
    // The owner ran SET MGM KEY with an AES-256 key, so the head records AES-256.
    fs.meta_add(
        mgm.get(),
        &[ALGO_AES256, PINPOLICY_ALWAYS, TOUCHPOLICY_ALWAYS],
    )
    .unwrap();

    // The key goes, the head survives.
    let mut st = fs.into_storage();
    st.remove(mgm.get()).unwrap();
    let mut fs = Fs::new(st);
    fs.scan();

    scan_files(&dev, &mut fs, &mut TestRng(6)).unwrap();

    let mut meta = [0u8; 8];
    let n = fs.meta_find(mgm.get(), &mut meta).unwrap_or(0);
    assert!(n >= 3, "no head at all after the re-mint");
    assert_eq!(
        meta[0], ALGO_AES192,
        "a re-minted 24-byte DEFAULT_MGM kept a stale AES-256 head, so every mutual \
         auth refuses on the length compare and RESET cannot clear it"
    );
}

/// The repair must read the surviving key's algorithm rather than assume the
/// fresh-card one: claiming AES-192 over a 16- or 32-byte key makes
/// `general_authenticate` refuse on `meta[0] != algo` (crates/rsk-piv/src/auth.rs),
/// so a "repair" that hardcodes it wedges the very slot it exists to unwedge.
#[test]
fn the_mgm_metadata_repair_reads_the_surviving_keys_algorithm() {
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
    };
    let mgm_fid = files::key_fid(SLOT_CARDMGM);
    for (key, want) in [
        (vec![0x11u8; 16], ALGO_AES128),
        (vec![0x22u8; 32], ALGO_AES256),
    ] {
        let mut fs = Fs::new(RamStorage::new());
        fs.scan();
        scan_files(&dev, &mut fs, &mut TestRng(5)).unwrap();
        // The owner's key, of a width the fresh-card default does not have.
        seal::seal_put(&dev, &mut fs, &mut TestRng(8), mgm_fid, &key).unwrap();
        fs.meta_delete(mgm_fid.get()).unwrap();

        scan_files(&dev, &mut fs, &mut TestRng(9)).unwrap();

        let mut meta = [0u8; 8];
        let n = fs.meta_find(mgm_fid.get(), &mut meta).unwrap_or(0);
        assert!(n >= 3, "metadata not repaired for a {}-byte key", key.len());
        assert_eq!(
            meta[0],
            want,
            "a {}-byte key was repaired as {:#04x}, which refuses every auth",
            key.len(),
            meta[0]
        );
    }
}

/// A new PIN or PUK must be 6-8 bytes before its padding. Without the rule the
/// card took a 3-digit PIN as its own credential — 1000 candidates against a
/// three-try counter, which is precisely the search space the minimum exists to
/// set. SP 800-85A-4 assertion C.2.2.1 wants `6A80` with the retry counter
/// untouched, and a YubiKey 5.7.4 gives exactly that (measured).
///
/// The digits-only half of SP 800-73-4 §2.4.3 is deliberately NOT enforced: the
/// same YubiKey stores a non-digit reference on both the PIN and the PUK, so a
/// host may send one and the card must take it.
#[test]
fn a_new_reference_shorter_than_the_minimum_is_refused() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);

    let pad = |v: &[u8]| {
        let mut o = [0xFFu8; PIN_WIRE_LEN];
        o[..v.len()].copy_from_slice(v);
        o
    };
    let change = |app: &mut PivApplet, fs: &mut Fs<_>, p2: u8, old: &[u8], new: &[u8]| {
        let mut msg = old.to_vec();
        msg.extend_from_slice(new);
        run(app, fs, INS_CHANGE_PIN, 0, p2, &msg).0
    };

    for (new, label) in [
        (&pad(b"777")[..], "3 bytes"),
        (&pad(b"12345")[..], "5 bytes, one short"),
        (&pad(b"")[..], "nothing but padding"),
    ] {
        assert_eq!(
            change(&mut app, &mut fs, 0x80, &DEFAULT_PIN, new),
            Sw::WRONG_DATA,
            "PIN <- {label}"
        );
        // …and the old PIN is untouched by the refusal.
        assert_eq!(
            run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN).0,
            Sw::OK
        );
        assert_eq!(
            change(&mut app, &mut fs, 0x81, &DEFAULT_PUK, new),
            Sw::WRONG_DATA,
            "PUK <- {label}"
        );
    }

    // A value longer than the wire form, ending in padding, would strip to a
    // legal length and then be STORED at its full length — a reference no host
    // can present again. It has to be refused on the raw length.
    let mut over = pad(b"123456").to_vec();
    over.extend_from_slice(&[0xFF; 8]);
    assert_eq!(
        change(&mut app, &mut fs, 0x80, &DEFAULT_PIN, &over),
        Sw::WRONG_DATA,
        "a 16-byte new value must not be stored"
    );
    assert_eq!(
        run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN).0,
        Sw::OK,
        "and the reference is untouched"
    );

    // A correct old PIN with a malformed new one must not COST a try — and in
    // fact it restores the counter, because the old reference verified and
    // §3.2.1.1 resets on any successful verification. Measured on a YubiKey
    // 5.7.4 from a counter already at 2: the refusal takes it back to 3, the
    // same as here. So SP 800-85A-4 C.2.2.1's "remains unchanged" holds a
    // fortiori, and asserting "unchanged" literally would be asserting a
    // divergence.
    let full = reference_retries_left(&mut fs, PinRef::Pin).unwrap();
    let mut wrong = pad(b"999999").to_vec();
    wrong.extend_from_slice(&pad(b"654321"));
    run(&mut app, &mut fs, INS_CHANGE_PIN, 0, 0x80, &wrong);
    assert!(
        reference_retries_left(&mut fs, PinRef::Pin).unwrap() < full,
        "the wrong old PIN spent a try"
    );
    change(&mut app, &mut fs, 0x80, &DEFAULT_PIN, &pad(b"777"));
    assert_eq!(
        reference_retries_left(&mut fs, PinRef::Pin).unwrap(),
        full,
        "a refused format costs nothing; the verified old reference restored it"
    );

    // A WRONG old PIN does spend one, malformed new value or not — a YubiKey
    // judges the old reference first and so does this.
    let mut bad = pad(b"999999").to_vec();
    bad.extend_from_slice(&pad(b"777"));
    let sw = run(&mut app, &mut fs, INS_CHANGE_PIN, 0, 0x80, &bad).0;
    assert_eq!(sw, Sw::new(0x63, 0xC2), "the old reference is judged first");

    // The lengths that ARE allowed, including a non-digit one.
    run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN);
    for (new, label) in [
        (&pad(b"123456")[..], "6 bytes"),
        (&pad(b"1234567")[..], "7 bytes"),
        (&pad(b"12345678")[..], "8 bytes"),
        (&pad(b"ABCDEF")[..], "6 non-digits — a YubiKey takes these"),
    ] {
        assert_eq!(
            change(&mut app, &mut fs, 0x80, &pad(b"123456"), new),
            Sw::OK,
            "PIN <- {label}"
        );
        // put it back for the next case
        assert_eq!(
            change(&mut app, &mut fs, 0x80, new, &pad(b"123456")),
            Sw::OK
        );
    }

    // RESET RETRY COUNTER is the other writer and gets the same rule.
    let mut msg = DEFAULT_PUK.to_vec();
    msg.extend_from_slice(&pad(b"777"));
    assert_eq!(
        run(&mut app, &mut fs, INS_RESET_RETRY, 0, 0x80, &msg).0,
        Sw::WRONG_DATA
    );
}

/// A failed VERIFY must drop a standing one. SP 800-73-4 Part 2 §3.2.1.1 says the
/// security status of the key reference **shall** be set to FALSE on a mismatch,
/// and a YubiKey 5.7.4 does it — measured: sign, one wrong VERIFY, next signature
/// `6982`. Ours kept signing, so entering wrong PINs at a card you think is
/// compromised — the human reflex, and the standard advice — did not stop an
/// attacker holding a session in which the real PIN had already been entered.
#[test]
fn a_failed_verify_revokes_the_standing_one() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    assert_eq!(
        run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN).0,
        Sw::OK
    );
    // Generate a key so there is a PIN-gated operation to hold the status against.
    let (sw, _) = run(
        &mut app,
        &mut fs,
        INS_ASYM_KEYGEN,
        0,
        0x9A,
        &[0xAC, 0x03, 0x80, 0x01, 0x11],
    );
    assert_eq!(sw, Sw::OK);
    let sign = |app: &mut PivApplet, fs: &mut Fs<_>| {
        let inner = [&[0x82u8, 0x00, 0x81, 32][..], &[0u8; 32][..]].concat();
        let body = [&[0x7Cu8, inner.len() as u8][..], &inner[..]].concat();
        run(app, fs, INS_AUTHENTICATE, 0x11, 0x9A, &body).0
    };
    assert_eq!(sign(&mut app, &mut fs), Sw::OK, "the control: it signs");

    // One wrong PIN.
    let mut wrong = *b"99999999";
    wrong[6..].copy_from_slice(&[0xFF, 0xFF]);
    assert_eq!(
        run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &wrong).0,
        Sw::new(0x63, 0xC2)
    );
    assert_eq!(
        sign(&mut app, &mut fs),
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "a failed VERIFY must revoke the standing one"
    );

    // Re-verifying restores it, and blocking the PIN leaves nothing standing.
    assert_eq!(
        run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN).0,
        Sw::OK
    );
    assert_eq!(sign(&mut app, &mut fs), Sw::OK);
    for _ in 0..3 {
        run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &wrong);
    }
    assert_eq!(
        run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &[]).0,
        Sw::PIN_BLOCKED
    );
    assert_eq!(
        sign(&mut app, &mut fs),
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "a blocked PIN must not leave a session signing"
    );
}

/// The other half of that rule, and the reason [`verify_reference`] takes no
/// `Session`: only VERIFY revokes. A wrong old PIN at CHANGE REFERENCE DATA, a
/// wrong PUK at RESET RETRY COUNTER, and the panel's own gate all spend a retry
/// and leave the card's security status exactly where it was — including the
/// attempt that blocks the reference.
///
/// SP 800-73-4 Part 2 §3.2.2 and §3.2.3 say the opposite (set it to FALSE on
/// `63CX`), so this is the parity rule overriding the spec, which is why it needs
/// a test rather than a comment. Measured on a YubiKey 5.7.4, three passes from a
/// factory reset with the VERIFY row above as the control that a revocation is
/// visible at all: sign `9000` after one failed CHANGE, after the CHANGE that
/// blocks the PIN, after a failed RESET RETRY COUNTER, and after the one that
/// blocks the PUK.
#[test]
fn only_a_failed_verify_revokes_the_standing_one() {
    let rng = RefCell::new(TestRng(11));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    let dev = Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
    };
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    verify_pin(&mut app, &mut fs);
    assert_eq!(
        run(
            &mut app,
            &mut fs,
            INS_ASYM_KEYGEN,
            0,
            0x9A,
            &gen_template(ALGO_ECCP256)
        )
        .0,
        Sw::OK
    );
    assert_eq!(
        sign_p256(&mut app, &mut fs, 0x9A),
        Sw::OK,
        "the control: it signs"
    );

    let wrong = pad_pin(b"999999").unwrap();
    let wrong_puk = pad_pin(b"99999999").unwrap();
    let new = pad_pin(b"654321").unwrap();

    // The panel's gate (`rsk-display`'s `gate_piv_ref`) is this call: the old-secret
    // check of a CHANGE, never a VERIFY. It cannot go red — E45's fix has to add a
    // `Session` parameter — so it is a tripwire on that signature, not coverage.
    assert_eq!(
        verify_reference(&dev, &mut fs, PinRef::Pin, &wrong),
        Sw::retries(2)
    );
    assert_eq!(
        sign_p256(&mut app, &mut fs, 0x9A),
        Sw::OK,
        "the panel's PIN gate must not revoke a host's security status"
    );
    assert_eq!(
        verify_reference(&dev, &mut fs, PinRef::Pin, &DEFAULT_PIN),
        Sw::OK
    );

    // RESET RETRY COUNTER spends the PUK's own counter, down to blocking it.
    for left in [2u8, 1] {
        let msg = [&wrong_puk[..], &new[..]].concat();
        assert_eq!(
            run(&mut app, &mut fs, INS_RESET_RETRY, 0, 0x80, &msg).0,
            Sw::retries(left)
        );
        assert_eq!(sign_p256(&mut app, &mut fs, 0x9A), Sw::OK);
    }
    let msg = [&wrong_puk[..], &new[..]].concat();
    assert_eq!(
        run(&mut app, &mut fs, INS_RESET_RETRY, 0, 0x80, &msg).0,
        Sw::PIN_BLOCKED
    );
    assert_eq!(
        sign_p256(&mut app, &mut fs, 0x9A),
        Sw::OK,
        "blocking the PUK must not revoke the PIN's security status"
    );

    // CHANGE REFERENCE DATA spends the PIN's, down to blocking it — and the
    // standing status outlives even that, which is the cell E45 read as a defect.
    for left in [2u8, 1] {
        let msg = [&wrong[..], &new[..]].concat();
        assert_eq!(
            run(&mut app, &mut fs, INS_CHANGE_PIN, 0, 0x80, &msg).0,
            Sw::retries(left)
        );
        assert_eq!(sign_p256(&mut app, &mut fs, 0x9A), Sw::OK);
    }
    let msg = [&wrong[..], &new[..]].concat();
    assert_eq!(
        run(&mut app, &mut fs, INS_CHANGE_PIN, 0, 0x80, &msg).0,
        Sw::PIN_BLOCKED
    );
    assert_eq!(
        sign_p256(&mut app, &mut fs, 0x9A),
        Sw::OK,
        "blocking the PIN through CHANGE must not revoke the standing status"
    );
}

/// `GET METADATA 9B`'s tag `05` answers "is this slot as it left the factory",
/// not "are these the factory key bytes". Measured on a YubiKey 5.7.4, 2 runs
/// byte-identical, `00 F7 00 9B 00` after each write:
///
/// ```text
///   fresh reset                     01 01 0A 02 02 00 01 05 01 01
///   a different AES-192 key, P2=FF  01 01 0A 02 02 00 01 05 01 00
///   the FACTORY key back, P2=FF     01 01 0A 02 02 00 01 05 01 01
///   the FACTORY key, P2=FE          01 01 0A 02 02 00 02 05 01 00   <- touch ALWAYS
/// ```
///
/// Ours read the key bytes alone, so the last row said `01` — the record
/// contradicting itself, since tag `02` in the same response publishes the touch
/// byte that made the slot non-default.
///
/// The touch byte is the whole rule, deliberately. Folding in `meta[1]` reads as
/// the same argument and is the wrong answer: `0x0875` shipped `PINPOLICY_ALWAYS`
/// there, `0x08D7` changed the mint without repairing what was already written,
/// and `set_mgmkey` forwards the byte — so every upgraded card still holding the
/// factory key would report `00`, and `ykman piv info` would stop warning about a
/// management key that really is the published default. The last cell here is
/// that card.
#[test]
fn the_management_slots_default_flag_answers_for_the_slots_touch_policy() {
    let rng = RefCell::new(TestRng(21));
    let pres = RefCell::new(AlwaysConfirm);
    let default_flag = |app: &mut PivApplet, fs: &mut Fs<RamStorage>| -> u8 {
        let (sw, md) = run(app, fs, INS_GET_METADATA, 0, SLOT_CARDMGM, &[]);
        assert_eq!(sw, Sw::OK);
        // The touch byte travels with it, so a flag that moved for the wrong
        // reason cannot pass as the right one.
        let touch = find_tag(&md, 0x02).unwrap()[1];
        let flag = find_tag(&md, 0x05).unwrap()[0];
        assert_eq!(
            find_tag(&md, 0x01).unwrap().len(),
            1,
            "the algorithm tag is still there"
        );
        flag | (touch << 4)
    };
    let factory = |p2: u8| {
        let mut b = vec![ALGO_AES192, SLOT_CARDMGM, 24];
        b.extend_from_slice(&DEFAULT_MGM);
        (b, p2)
    };

    // a. fresh card: the factory key, touch NEVER.
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    assert_eq!(
        default_flag(&mut app, &mut fs),
        1 | (TOUCHPOLICY_NEVER << 4),
        "a fresh card is the factory configuration"
    );

    // b. a different key at P2=FF — the key half, which already worked.
    let mut other = vec![ALGO_AES192, SLOT_CARDMGM, 24];
    other.extend_from_slice(&[0x7Bu8; 24]);
    assert_eq!(
        run(&mut app, &mut fs, INS_SET_MGMKEY, 0xFF, 0xFF, &other).0,
        Sw::OK
    );
    assert_eq!(
        default_flag(&mut app, &mut fs),
        TOUCHPOLICY_NEVER << 4,
        "a rotated key is not the factory configuration"
    );

    // c. the FACTORY key written back at P2=FF — default again.
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    let (body, p2) = factory(0xFF);
    assert_eq!(
        run(&mut app, &mut fs, INS_SET_MGMKEY, 0xFF, p2, &body).0,
        Sw::OK
    );
    assert_eq!(
        default_flag(&mut app, &mut fs),
        1 | (TOUCHPOLICY_NEVER << 4),
        "the factory key written back is the factory configuration"
    );

    // d. the FACTORY key at P2=FE — the cell this fixes.
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    auth_mgm(&mut app, &mut fs);
    let (body, p2) = factory(0xFE);
    assert_eq!(
        run(&mut app, &mut fs, INS_SET_MGMKEY, 0xFF, p2, &body).0,
        Sw::OK
    );
    assert_eq!(
        default_flag(&mut app, &mut fs),
        TOUCHPOLICY_ALWAYS << 4,
        "the factory key behind a raised touch gate is not the factory configuration"
    );

    // e. planted touch bytes. `NEVER` is the rule, not "anything but ALWAYS": a
    // head carrying a value no writer emits is not the factory configuration
    // either, and `!= ALWAYS` would call it one.
    // The last row is the card the rule is scoped for — `0x0875`'s
    // `PINPOLICY_ALWAYS` in `meta[1]`, still on the factory key. It must keep
    // reporting `01`, or an upgrade silently retires a true warning.
    let flag_for = |planted: [u8; 3]| -> u8 {
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut fs = new_fs();
        select(&mut app, &mut fs);
        fs.meta_add(files::key_fid(SLOT_CARDMGM).get(), &planted)
            .unwrap();
        find_tag(
            &run(&mut app, &mut fs, INS_GET_METADATA, 0, SLOT_CARDMGM, &[]).1,
            0x05,
        )
        .unwrap()[0]
    };
    for touch in [TOUCHPOLICY_CACHED, TOUCHPOLICY_DEFAULT, 0x7F] {
        assert_eq!(
            flag_for([ALGO_AES192, MGM_PIN_POLICY, touch]),
            0,
            "touch byte {touch:#04X} is not the factory configuration"
        );
    }
    assert_eq!(
        flag_for([ALGO_AES192, PINPOLICY_ALWAYS, TOUCHPOLICY_NEVER]),
        1,
        "a card provisioned before 0x08D7 still reports its factory key"
    );
}

/// The PIN and PUK metadata records carry the algorithm tag every other slot
/// carries. Ours emitted only `05` and `06`, so the two records the command
/// serves for a *secret* had a different shape from the ones it serves for a key
/// — the only cell left in the whole PIV P1P2 sweep differing from the reference
/// in shape rather than in content. A YubiKey 5.7.4 answers both `00 F7 00 80 00`
/// and `00 F7 00 81 00` with `01 01 FF 05 01 01 06 02 03 03`, measured 3 runs
/// byte-identical on a fresh `ykman piv reset`.
#[test]
fn the_pin_and_puk_metadata_carry_the_algorithm_tag() {
    let rng = RefCell::new(TestRng(9));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);
    for slot in [REF_PIN, REF_PUK] {
        let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, slot, &[]);
        assert_eq!(sw, Sw::OK);
        assert_eq!(
            md,
            // The byte, not the constant that holds it: written as `ALGO_PIN`
            // both sides of this move together and any value but `0x0A` ships
            // green, which is the whole payload of this change.
            std::vec![0x01, 0x01, 0xFF, 0x05, 0x01, 1, 0x06, 0x02, 3, 3],
            "slot {slot:02X}: the whole record, in the reference's order"
        );
    }
    // The tag is fixed, so it must not move when the rest of the record does:
    // change the PIN and spend a retry, and only `05` and `06` follow.
    let mut msg = DEFAULT_PIN.to_vec();
    msg.extend_from_slice(b"violets8");
    assert_eq!(
        run(&mut app, &mut fs, INS_CHANGE_PIN, 0, 0x80, &msg).0,
        Sw::OK
    );
    assert_eq!(
        run(&mut app, &mut fs, INS_VERIFY, 0, 0x80, &DEFAULT_PIN).0,
        Sw::new(0x63, 0xC2)
    );
    let (sw, md) = run(&mut app, &mut fs, INS_GET_METADATA, 0, REF_PIN, &[]);
    assert_eq!(sw, Sw::OK);
    assert_eq!(
        md,
        std::vec![0x01, 0x01, 0xFF, 0x05, 0x01, 0, 0x06, 0x02, 3, 2]
    );
}

/// E182 said the reference judges framing before authorisation "with no single
/// rule". It has one, and the cells that raised the finding are one row of it: a
/// **one-byte body is `6A80` on every PIV command**, and every other length
/// behaves exactly as `Lc = 0`. Measured on a YubiKey 5.7.4, `Lc` walked over
/// 0..40 on eleven instructions and then separated three ways — the answer is the
/// same for data bytes `41`, `00` and `5C`, with and without a trailing `Le`, and
/// in the extended-length encoding. Eleven of the fourteen carry the full length
/// axis; the other three — `FD VERSION`, `F8 SERIAL` and an undefined `EE` — were
/// asked at `Lc` 0, 1 and 2 only, which is enough: they answer `9000`, `9000` and
/// `6D00` at 0 and 2 and `6A80` at 1, so the rule outranks even "this instruction
/// does not exist". So it is a length rule at the top of the applet, before the
/// ACL and before the command exists. A body that short can be no command's, and
/// the answer depends on nothing, so it enumerates nothing.
///
/// Below it, the reference's own order is authorisation first for the commands
/// this leaves `6700` on: `F6` ignores its body entirely (`6982` unauthenticated
/// at every length, `6A88` for the empty slot once authenticated), `47` answers
/// `6982` at every length and every body shape, and `87` — which has no ACL of
/// its own, being the authentication — answers `6A80` and never `6700`.
#[test]
fn a_one_byte_body_is_the_same_refusal_on_every_command() {
    let rng = RefCell::new(TestRng(17));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut fs = new_fs();
    select(&mut app, &mut fs);

    // (INS, P1, P2) — every instruction `process` dispatches, gated and ungated
    // alike, plus its `_ => 6D00` fall-through. `A4` is here at `P2 = 01`, the
    // in-applet re-SELECT: the dispatcher intercepts `P2 = 00`/`04` before the
    // applet, and the reference draws the same line — `00 A4 04 00 01 A0` is
    // `9000` there while `00 A4 04 01 01 A0` is `6A80`. The rule is applet-local
    // on both cards and must not be lifted to the dispatcher (`rsk-oath` takes a
    // legitimate `Lc = 1`).
    let cmds: [(u8, u8, u8); 18] = [
        (INS_VERIFY, 0x00, 0x80),
        (INS_CHANGE_PIN, 0x00, 0x80),
        (INS_RESET_RETRY, 0x00, 0x80),
        (INS_ASYM_KEYGEN, 0x00, 0x9A),
        (INS_AUTHENTICATE, ALGO_AES192, SLOT_CARDMGM),
        (INS_GET_DATA, 0x3F, 0xFF),
        (INS_PUT_DATA, 0x3F, 0xFF),
        (INS_MOVE_KEY, 0x9A, 0x9C),
        (INS_GET_METADATA, 0x00, 0x9A),
        (INS_YK_SERIAL, 0x00, 0x00),
        (INS_ATTESTATION, 0x9A, 0x00),
        (INS_SET_RETRIES, 0x03, 0x03),
        (INS_RESET, 0x00, 0x00),
        (INS_VERSION, 0x00, 0x00),
        (INS_SET_MGMKEY, 0xFF, 0xFF),
        (INS_IMPORT_ASYM, 0x06, 0x9A),
        (INS_SELECT, 0x04, 0x01),
        (0xEE, 0x00, 0x00),
    ];
    for authed in [false, true] {
        if authed {
            select(&mut app, &mut fs);
            auth_mgm(&mut app, &mut fs);
            verify_pin(&mut app, &mut fs);
        }
        for (ins, p1, p2) in cmds {
            for byte in [0x41u8, 0x00, 0x5C] {
                assert_eq!(
                    run(&mut app, &mut fs, ins, p1, p2, &[byte]).0,
                    Sw::WRONG_DATA,
                    "INS {ins:02X} with the one byte {byte:02X}, authed={authed}"
                );
            }
            // The control: two bytes is NOT this refusal on the ungated reads,
            // which serve their answer and ignore the body. Without it a blanket
            // `6A80` for every body would satisfy the loop above.
            if matches!(ins, INS_VERSION | INS_YK_SERIAL) {
                assert_eq!(
                    run(&mut app, &mut fs, ins, p1, p2, &[0x41, 0x42]).0,
                    Sw::OK,
                    "INS {ins:02X} ignores a two-byte body"
                );
                assert_eq!(run(&mut app, &mut fs, ins, p1, p2, &[]).0, Sw::OK);
            }
        }
    }

    // The three commands E182 named, where a `6700` outranked the credential.
    let long = [0x41u8; 8];
    select(&mut app, &mut fs);
    for body in [&[][..], &long[..]] {
        assert_eq!(
            run(&mut app, &mut fs, INS_MOVE_KEY, 0x9A, 0x9C, body).0,
            Sw::SECURITY_STATUS_NOT_SATISFIED,
            "MOVE KEY unauthenticated, {} body bytes",
            body.len()
        );
        assert_eq!(
            run(&mut app, &mut fs, INS_ASYM_KEYGEN, 0x00, 0x9A, body).0,
            Sw::SECURITY_STATUS_NOT_SATISFIED,
            "KEYGEN unauthenticated, {} body bytes",
            body.len()
        );
        // GENERAL AUTHENTICATE has no ACL — it is the authentication — so its
        // framing is all it can answer for, and `6700` was the wrong word.
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                INS_AUTHENTICATE,
                ALGO_AES192,
                SLOT_CARDMGM,
                body
            )
            .0,
            Sw::WRONG_DATA,
            "GENERAL AUTHENTICATE, {} body bytes",
            body.len()
        );
    }
    // The credential outranks P1P2 as well as the body, on the same three
    // commands plus IMPORT — measured on the reference, which answers `6982`
    // unauthenticated to a bad P1, a P2 naming no slot, and a slot IMPORT
    // refuses. Which slots a command takes is not something a caller with no
    // credential learns one refusal at a time.
    for (ins, p1, p2, body) in [
        (
            INS_ASYM_KEYGEN,
            0x00u8,
            0x01u8,
            &[0xAC, 0x03, 0x80, 0x01, 0x11][..],
        ),
        (
            INS_ASYM_KEYGEN,
            0x01,
            0x9A,
            &[0xAC, 0x03, 0x80, 0x01, 0x11][..],
        ),
        (INS_MOVE_KEY, 0x01, 0x9C, &[][..]),
        (INS_IMPORT_ASYM, 0x06, 0x01, &[0x41, 0x42, 0x43, 0x44][..]),
    ] {
        assert_eq!(
            run(&mut app, &mut fs, ins, p1, p2, body).0,
            Sw::SECURITY_STATUS_NOT_SATISFIED,
            "INS {ins:02X} P1P2 {p1:02X}{p2:02X} unauthenticated"
        );
    }
    // GENERAL AUTHENTICATE's template tag must OPEN the body, not merely appear
    // in it. `80 00 7C 02 80 00` carries a real top-level `7C` in second place,
    // which the tag search finds and would otherwise serve; the reference
    // answers `6A80`, and so does `5C 00 7C 02 80 00`. Without the first-byte
    // check ours would run the witness step from a body it never validated.
    for body in [
        &[0x80u8, 0x00, 0x7C, 0x02, 0x80, 0x00][..],
        &[0x5C, 0x00, 0x7C, 0x02, 0x80, 0x00][..],
    ] {
        assert_eq!(
            run(
                &mut app,
                &mut fs,
                INS_AUTHENTICATE,
                ALGO_AES192,
                SLOT_CARDMGM,
                body
            )
            .0,
            Sw::WRONG_DATA,
            "a dynamic-auth template that does not open the body"
        );
    }

    // …and once authorised the same two commands answer for the request again,
    // so the ACL was hoisted rather than the checks deleted.
    auth_mgm(&mut app, &mut fs);
    assert_eq!(
        run(&mut app, &mut fs, INS_MOVE_KEY, 0x9A, 0x9C, &long).0,
        Sw::FILE_NOT_FOUND,
        "MOVE KEY authorised: the empty source slot, not the body"
    );
    assert_eq!(
        run(&mut app, &mut fs, INS_ASYM_KEYGEN, 0x00, 0x9A, &[]).0,
        Sw::WRONG_DATA,
        "KEYGEN authorised: the missing template"
    );
    assert_eq!(
        run(&mut app, &mut fs, INS_ASYM_KEYGEN, 0x00, 0x9A, &long).0,
        Sw::WRONG_DATA,
        "KEYGEN authorised: the wrong template tag"
    );
    // The P1P2 strictness E140 kept is still there, one gate lower.
    let tmpl = [0xACu8, 0x03, 0x80, 0x01, 0x11];
    for (p1, p2) in [(0x01u8, 0x9Au8), (0x00, 0x01)] {
        assert_eq!(
            run(&mut app, &mut fs, INS_ASYM_KEYGEN, p1, p2, &tmpl).0,
            Sw::INCORRECT_P1P2,
            "KEYGEN authorised: P1P2 {p1:02X}{p2:02X}"
        );
    }
    assert_eq!(
        run(&mut app, &mut fs, INS_MOVE_KEY, 0x01, 0x9C, &[]).0,
        Sw::INCORRECT_P1P2,
        "MOVE KEY authorised: a destination naming no slot"
    );
}
