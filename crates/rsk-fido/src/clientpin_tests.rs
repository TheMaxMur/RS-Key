// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::FidoState;
use crate::consts::EF_KEY_DEV;
use crate::seed::{ensure_seed, load_keydev};
use crate::test_pins::{DEVICE_PIN, NEW_PIN, PIN, WRONG_PIN};
use minicbor::encode::Write as _;
use rsk_crypto::Device;
use rsk_crypto::pinproto::public_xy;
use rsk_fs::Fs;
use rsk_fs::storage::faults::{Cut, CutMedium, ProbeStuck};
use rsk_fs::storage::ram::RamStorage;

struct SeqRng(u64);
impl Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

fn dev() -> Device<'static> {
    Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    }
}

fn setup() -> (Fs<RamStorage>, SeqRng) {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    (fs, rng)
}

/// [`setup`] on a medium that logs the order of the appends it serves — the only
/// place the re-arm of the at-rest lap can be seen to land BEFORE the re-key it
/// covers rather than after it.
fn setup_cut() -> (Fs<Cut>, CutMedium, SeqRng) {
    let (cut, medium) = Cut::new();
    let mut fs = Fs::new(cut);
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    (fs, medium, rng)
}

fn run<S: rsk_fs::Storage>(
    fs: &mut Fs<S>,
    rng: &mut SeqRng,
    state: &mut FidoState,
    data: &[u8],
    out: &mut [u8],
) -> CtapResult {
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs,
        rng,
        state,
        now_ms: 0,
    };
    client_pin(&mut ctx, data, out)
}

/// A built-in-UV presence backend for the 0x06/0x07 tests: it reports built-in
/// UV available and "types" a fixed PIN on the (virtual) pad, honoring the same
/// min-length gate the real pad enforces. An explicit `outcome` overrides the
/// entry to exercise the decline / timeout / cancel branches. Every `Confirm`
/// title it is shown is recorded, so a test can assert what the card *named*.
struct UvPad {
    digits: std::vec::Vec<u8>,
    outcome: Option<PinEntry>,
    titles: std::vec::Vec<&'static str>,
}
impl UvPad {
    fn typing(pin: &[u8]) -> Self {
        Self {
            digits: pin.to_vec(),
            outcome: None,
            titles: std::vec::Vec::new(),
        }
    }
    fn ending(outcome: PinEntry) -> Self {
        Self {
            digits: std::vec::Vec::new(),
            outcome: Some(outcome),
            titles: std::vec::Vec::new(),
        }
    }
}
impl crate::UserPresence for UvPad {
    fn request(&mut self, c: crate::Confirm<'_>) -> crate::Presence {
        self.titles.push(c.title);
        crate::Presence::Confirmed
    }
    // A PIN pad implies a screen, so this backend also answers the §6.5.5.7 consent.
    fn shows_confirm(&self) -> bool {
        true
    }
    fn uv_available(&self) -> bool {
        true
    }
    fn collect_pin(&mut self, min_len: usize, out: &mut [u8]) -> PinEntry {
        if let Some(o) = self.outcome {
            return o;
        }
        if self.digits.len() < min_len {
            return PinEntry::Declined;
        }
        let n = self.digits.len().min(out.len());
        out[..n].copy_from_slice(&self.digits[..n]);
        PinEntry::Entered(n)
    }
}

/// A display whose user refuses the §6.5.5.7 consent screen. Its pad panics: the
/// refusal must end the operation before any PIN is collected.
struct DenyConsent;
impl crate::UserPresence for DenyConsent {
    fn request(&mut self, _c: crate::Confirm<'_>) -> crate::Presence {
        crate::Presence::Declined
    }
    fn shows_confirm(&self) -> bool {
        true
    }
    fn uv_available(&self) -> bool {
        true
    }
    fn collect_pin(&mut self, _min: usize, _out: &mut [u8]) -> PinEntry {
        unreachable!("consent is refused before the pad is reached")
    }
}

/// `run` with a caller-supplied presence backend (for the built-in-UV pad).
fn run_with(
    presence: &mut dyn crate::UserPresence,
    fs: &mut Fs<RamStorage>,
    rng: &mut SeqRng,
    state: &mut FidoState,
    data: &[u8],
    out: &mut [u8],
) -> CtapResult {
    let mut ctx = Ctx {
        presence,
        dev: dev(),
        fs,
        rng,
        state,
        now_ms: 0,
    };
    client_pin(&mut ctx, data, out)
}

// A clientPIN request field value.
enum V<'a> {
    U(u64),
    B(&'a [u8]),
    Cose(&'a [u8; 32], &'a [u8; 32]),
    /// A keyAgreement whose coordinates go on the wire verbatim, however long.
    CoseVar(&'a [u8], &'a [u8]),
    /// Pre-encoded CBOR, written as the field's value.
    Raw(&'a [u8]),
}

fn build(fields: &[(u8, V)]) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 1024];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(fields.len() as u64).unwrap();
        for (k, v) in fields {
            e.u8(*k).unwrap();
            match v {
                V::U(x) => {
                    e.u64(*x).unwrap();
                }
                V::B(b) => {
                    e.bytes(b).unwrap();
                }
                V::Cose(x, y) => cose_key_ecdh(&mut e, x, y).unwrap(),
                V::Raw(b) => e.writer_mut().write_all(b).unwrap(),
                V::CoseVar(x, y) => crate::cose::cose_key_ec2_var(
                    &mut e,
                    crate::consts::ALG_ECDH_ES_HKDF_256,
                    crate::consts::CURVE_P256,
                    x,
                    y,
                )
                .unwrap(),
            }
        }
        e.writer().position()
    };
    buf[..n].to_vec()
}

// The platform's ephemeral key + the shared secret with the authenticator.
struct Platform {
    proto: PinProto,
    wire: u64,
    x: [u8; 32],
    y: [u8; 32],
    shared: [u8; 64],
    slen: usize,
}

fn key_agreement<S: rsk_fs::Storage>(
    fs: &mut Fs<S>,
    rng: &mut SeqRng,
    state: &mut FidoState,
    proto: PinProto,
    wire: u64,
) -> Platform {
    let req = build(&[(1, V::U(wire)), (2, V::U(2))]);
    let mut out = [0u8; 256];
    let n = run(fs, rng, state, &req, &mut out).unwrap();
    // { 1: { 1:2, 3:-25, -1:1, -2:x, -3:y } }
    let mut d = Decoder::new(&out[..n]);
    assert_eq!(d.map().unwrap().unwrap(), 1);
    assert_eq!(d.u8().unwrap(), 1);
    assert_eq!(d.map().unwrap().unwrap(), 5);
    assert_eq!(d.u8().unwrap(), 1);
    assert_eq!(d.u8().unwrap(), 2);
    assert_eq!(d.u8().unwrap(), 3);
    assert_eq!(d.i64().unwrap(), crate::consts::ALG_ECDH_ES_HKDF_256);
    assert_eq!(d.i8().unwrap(), -1);
    assert_eq!(d.u8().unwrap(), 1);
    assert_eq!(d.i8().unwrap(), -2);
    let mut ax = [0u8; 32];
    ax.copy_from_slice(d.bytes().unwrap());
    assert_eq!(d.i8().unwrap(), -3);
    let mut ay = [0u8; 32];
    ay.copy_from_slice(d.bytes().unwrap());

    // The authenticator's key must be a valid P-256 point.
    let pscalar = {
        let mut s = [0u8; 32];
        s[31] = 0x42;
        s[0] = 0x13;
        s
    };
    let (x, y) = public_xy(&pscalar).unwrap();
    let mut shared = [0u8; 64];
    let slen = pinproto::ecdh(proto, &pscalar, &ax, &ay, &mut shared).unwrap();
    Platform {
        proto,
        wire,
        x,
        y,
        shared,
        slen,
    }
}

impl Platform {
    fn secret(&self) -> &[u8] {
        &self.shared[..self.slen]
    }

    // Encrypt a value with a fixed IV (deterministic test vectors).
    fn enc(&self, pt: &[u8]) -> std::vec::Vec<u8> {
        let mut out = [0u8; 96];
        let n = pinproto::encrypt(self.proto, self.secret(), &[0x55; 16], pt, &mut out).unwrap();
        out[..n].to_vec()
    }

    fn mac(&self, data: &[u8]) -> std::vec::Vec<u8> {
        let mut out = [0u8; 32];
        let n = pinproto::authenticate(self.proto, self.secret(), data, &mut out).unwrap();
        out[..n].to_vec()
    }

    fn set_pin_req(&self, pin: &[u8]) -> std::vec::Vec<u8> {
        let mut padded = [0u8; 64];
        padded[..pin.len()].copy_from_slice(pin);
        let npe = self.enc(&padded);
        let puap = self.mac(&npe);
        build(&[
            (1, V::U(self.wire)),
            (2, V::U(3)),
            (3, V::Cose(&self.x, &self.y)),
            (4, V::B(&puap)),
            (5, V::B(&npe)),
        ])
    }

    fn get_token_req(&self, pin: &[u8]) -> std::vec::Vec<u8> {
        let h = sha256(pin);
        let phe = self.enc(&h[..16]);
        build(&[
            (1, V::U(self.wire)),
            (2, V::U(5)),
            (3, V::Cose(&self.x, &self.y)),
            (6, V::B(&phe)),
        ])
    }

    // getPinUvAuthTokenUsingPinWithPermissions (subCommand 9) with `perms`.
    fn get_token_perms_req(&self, pin: &[u8], perms: u64) -> std::vec::Vec<u8> {
        self.get_token_perms_req_coords(pin, perms, &self.x, &self.y)
    }

    // The same request with the keyAgreement coordinates written verbatim, so a
    // test can send a coordinate that is not 32 bytes while the ECDH underneath
    // stays correct.
    fn get_token_perms_req_coords(
        &self,
        pin: &[u8],
        perms: u64,
        x: &[u8],
        y: &[u8],
    ) -> std::vec::Vec<u8> {
        let h = sha256(pin);
        let phe = self.enc(&h[..16]);
        build(&[
            (1, V::U(self.wire)),
            (2, V::U(9)),
            (3, V::CoseVar(x, y)),
            (6, V::B(&phe)),
            (9, V::U(perms)),
        ])
    }

    // getPinUvAuthTokenUsingUvWithPermissions (subCommand 6): built-in UV, so no
    // encrypted PIN on the wire — just keyAgreement + the requested permissions.
    fn get_uv_token_req(&self, perms: u64) -> std::vec::Vec<u8> {
        build(&[
            (1, V::U(self.wire)),
            (2, V::U(6)),
            (3, V::Cose(&self.x, &self.y)),
            (9, V::U(perms)),
        ])
    }

    fn change_pin_req(&self, old: &[u8], new: &[u8]) -> std::vec::Vec<u8> {
        let mut padded = [0u8; 64];
        padded[..new.len()].copy_from_slice(new);
        let npe = self.enc(&padded);
        let oh = sha256(old);
        let phe = self.enc(&oh[..16]);
        let mut macd = npe.clone();
        macd.extend_from_slice(&phe);
        let puap = self.mac(&macd);
        build(&[
            (1, V::U(self.wire)),
            (2, V::U(4)),
            (3, V::Cose(&self.x, &self.y)),
            (4, V::B(&puap)),
            (5, V::B(&npe)),
            (6, V::B(&phe)),
        ])
    }

    // Decrypt the pinUvAuthToken from a getPinToken response.
    fn decrypt_token(&self, resp: &[u8]) -> [u8; 32] {
        let mut d = Decoder::new(resp);
        assert_eq!(d.map().unwrap().unwrap(), 1);
        assert_eq!(d.u8().unwrap(), 2);
        let enc = d.bytes().unwrap();
        let mut tok = [0u8; 32];
        let n = pinproto::decrypt(self.proto, self.secret(), enc, &mut tok).unwrap();
        assert_eq!(n, 32);
        tok
    }
}

fn set_and_get_token(proto: PinProto, wire: u64) {
    let (mut fs, mut rng) = setup();
    let mut state = FidoState::new();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, proto, wire);

    // setPIN replies with only the status byte (empty body).
    let mut out = [0u8; 256];
    let n = run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.set_pin_req(PIN),
        &mut out,
    )
    .unwrap();
    assert_eq!(n, 0);
    assert!(fs.has_data(EF_PIN));

    // getPinToken returns the encrypted token; it decrypts to paut.token.
    let n = run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.get_token_req(PIN),
        &mut out,
    )
    .unwrap();
    let token = plat.decrypt_token(&out[..n]);
    assert_eq!(token, state.paut.token);
    assert_eq!(state.paut.permissions, PERM_MC | PERM_GA);
}

#[test]
fn set_pin_then_get_token_protocol_two() {
    set_and_get_token(PinProto::Two, 2);
}

#[test]
fn set_pin_then_get_token_protocol_one() {
    set_and_get_token(PinProto::One, 1);
}

#[test]
fn set_pin_over_max_length_is_policy_violation() {
    // A new PIN longer than 63 bytes (padded > 64) must be a
    // PIN_POLICY_VIOLATION, not INVALID_PARAMETER — conformance
    // ClientPin2-Policy F-2. Protocol 2's 16-byte IV pushed the 96-byte
    // ciphertext past the strict `== 80` guard, wrongly yielding 0x02.
    let (mut fs, mut rng) = setup();
    let mut state = FidoState::new();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    // 80-byte padded block → an over-length PIN; encrypts to 96 bytes (> 80).
    let padded = [0x31u8; 80];
    let npe = plat.enc(&padded);
    let puap = plat.mac(&npe);
    let req = build(&[
        (1, V::U(plat.wire)),
        (2, V::U(3)),
        (3, V::Cose(&plat.x, &plat.y)),
        (4, V::B(&puap)),
        (5, V::B(&npe)),
    ]);
    let mut out = [0u8; 64];
    assert_eq!(
        run(&mut fs, &mut rng, &mut state, &req, &mut out),
        Err(CtapError::PinPolicyViolation)
    );
}

/// §6.5.5.5 measures the PIN against minPINLength in **Unicode code points**
/// (getInfo 0x0D), not UTF-8 bytes — otherwise a 2-character CJK PIN clears a floor
/// of 4 on byte count alone. The stored PINCodePointLength follows the same unit,
/// since `setMinPINLength` compares its new floor against it.
#[test]
fn pin_length_is_measured_in_code_points() {
    let (mut fs, mut rng) = setup();
    let mut state = FidoState::new();
    fs.put(EF_MINPINLEN, &[4, 0]).unwrap();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    let mut out = [0u8; 256];
    // "密码" — 2 code points, 6 bytes.
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.set_pin_req("密码".as_bytes()),
            &mut out
        ),
        Err(CtapError::PinPolicyViolation)
    );
    // "ÄÖÜß" — 4 code points, 8 bytes.
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.set_pin_req("ÄÖÜß".as_bytes()),
        &mut out,
    )
    .unwrap();
    let mut pf = [0u8; PIN_FILE_LEN];
    assert_eq!(fs.read(EF_PIN, &mut pf), Some(PIN_FILE_LEN));
    assert_eq!(pf[1], 4, "PINCodePointLength, not the 8-byte encoding");
}

/// §6.5.5.6: while a forced PIN change is pending, re-entering the same PIN does not
/// satisfy it — the flag survives and the operation is a policy violation.
#[test]
fn force_change_refuses_the_same_pin() {
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
    fs.put(EF_MINPINLEN, &[4, 1]).unwrap(); // forceChangePin set
    let mut out = [0u8; 256];
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.change_pin_req(PIN, PIN),
            &mut out
        ),
        Err(CtapError::PinPolicyViolation)
    );
    let mut mp = [0u8; 2];
    assert_eq!(fs.read(EF_MINPINLEN, &mut mp), Some(2));
    assert_eq!(mp[1], 1, "the forced-change flag must survive");
    // A genuinely different PIN satisfies the policy and clears the flag.
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.change_pin_req(PIN, NEW_PIN),
        &mut out,
    )
    .unwrap();
    assert_eq!(fs.read(EF_MINPINLEN, &mut mp), Some(2));
    assert_eq!(mp[1], 0);
}

/// Set a PIN host-side, returning everything wired for a built-in-UV test.
fn setup_with_pin(pin: &[u8]) -> (Fs<RamStorage>, SeqRng, FidoState, Platform) {
    let (mut fs, mut rng) = setup();
    let mut state = FidoState::new();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    let mut out = [0u8; 256];
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.set_pin_req(pin),
        &mut out,
    )
    .unwrap();
    (fs, rng, state, plat)
}

fn ef_pin_retries(fs: &mut Fs<RamStorage>) -> u8 {
    let mut pf = [0u8; PIN_FILE_LEN];
    assert_eq!(fs.read(EF_PIN, &mut pf), Some(PIN_FILE_LEN));
    pf[0]
}

/// Device-local verify (the display delete gate): a correct PIN verifies and
/// resets the budget, a wrong one is rejected and spends exactly one retry —
/// the same persistent counter the host PIN path uses.
#[test]
fn local_pin_correct_wrong_and_reset() {
    let (mut fs, _rng, _state, _plat) = setup_with_pin(PIN);
    assert!(matches!(
        spend_and_verify_local_pin(&dev(), &mut fs, PIN),
        LocalPin::Ok
    ));
    assert_eq!(ef_pin_retries(&mut fs), MAX_PIN_RETRIES);
    match spend_and_verify_local_pin(&dev(), &mut fs, WRONG_PIN) {
        LocalPin::Wrong { retries_left } => assert_eq!(retries_left, MAX_PIN_RETRIES - 1),
        _ => panic!("expected Wrong"),
    }
    assert_eq!(ef_pin_retries(&mut fs), MAX_PIN_RETRIES - 1);
    // A later correct PIN restores the full budget.
    assert!(matches!(
        spend_and_verify_local_pin(&dev(), &mut fs, PIN),
        LocalPin::Ok
    ));
    assert_eq!(ef_pin_retries(&mut fs), MAX_PIN_RETRIES);
}

/// The persistent gate hard-blocks once the budget is spent, and never
/// underflows past zero — even a correct PIN can't recover after the lock.
#[test]
fn local_pin_blocks_at_zero() {
    let (mut fs, _rng, _state, _plat) = setup_with_pin(PIN);
    for _ in 0..MAX_PIN_RETRIES - 1 {
        assert!(matches!(
            spend_and_verify_local_pin(&dev(), &mut fs, WRONG_PIN),
            LocalPin::Wrong { .. }
        ));
    }
    assert!(matches!(
        spend_and_verify_local_pin(&dev(), &mut fs, WRONG_PIN),
        LocalPin::Blocked
    ));
    assert_eq!(ef_pin_retries(&mut fs), 0);
    assert!(matches!(
        spend_and_verify_local_pin(&dev(), &mut fs, PIN),
        LocalPin::Blocked
    ));
}

/// `pin_is_set` tracks EF_PIN; with no PIN a local verify is Blocked (the
/// caller is expected to gate on `pin_is_set` first).
#[test]
fn local_pin_is_set_and_unset() {
    let (mut fs, _rng, _state, _plat) = setup_with_pin(PIN);
    assert!(pin_is_set(&mut fs));
    let (mut bare, _rng2) = setup();
    assert!(!pin_is_set(&mut bare));
    assert!(matches!(
        spend_and_verify_local_pin(&dev(), &mut bare, PIN),
        LocalPin::Blocked
    ));
}

/// `pin_retries_left` reports the live budget for the unlock pad's "N tries
/// remaining" line — without spending a try — and is `None` when no PIN is set.
#[test]
fn pin_retries_left_reads_the_budget_without_spending_it() {
    let (mut bare, _rng) = setup();
    assert_eq!(pin_retries_left(&mut bare), None);
    let (mut fs, _rng2, _state, _plat) = setup_with_pin(PIN);
    assert_eq!(pin_retries_left(&mut fs), Some(MAX_PIN_RETRIES));
    // A read does not decrement; the counter only moves on a real verify.
    assert_eq!(pin_retries_left(&mut fs), Some(MAX_PIN_RETRIES));
    assert!(matches!(
        spend_and_verify_local_pin(&dev(), &mut fs, WRONG_PIN),
        LocalPin::Wrong { .. }
    ));
    assert_eq!(pin_retries_left(&mut fs), Some(MAX_PIN_RETRIES - 1));
}

/// Device-local set (the on-device Set/Change PIN flow) must write the *same*
/// EF_PIN verifier the host setPIN path stores for the same PIN + device — so a PIN
/// chosen on the screen is honored over USB exactly as if it had been set there.
#[test]
fn store_local_pin_matches_the_host_verifier() {
    let (mut host_fs, _r, _s, _p) = setup_with_pin(b"246810");
    let mut host_pf = [0u8; PIN_FILE_LEN];
    assert_eq!(host_fs.read(EF_PIN, &mut host_pf), Some(PIN_FILE_LEN));

    let (mut fs, _rng) = setup();
    store_local_pin(&dev(), &mut fs, b"246810").unwrap();
    let mut local_pf = [0u8; PIN_FILE_LEN];
    assert_eq!(fs.read(EF_PIN, &mut local_pf), Some(PIN_FILE_LEN));

    assert_eq!(host_pf, local_pf, "local set must match the host verifier");
    assert!(matches!(
        spend_and_verify_local_pin(&dev(), &mut fs, b"246810"),
        LocalPin::Ok
    ));
}

/// The trusted-display **device PIN** is fully independent of the FIDO clientPIN: it has
/// its own record (`EF_DEVICE_PIN`) and counter, setting one never sets the other, and
/// neither PIN's value opens the other.
#[test]
fn device_pin_is_independent_of_fido_pin() {
    let (mut fs, _rng) = setup();
    // No device PIN yet → not set; a verify is Blocked (the caller gates on is_set).
    assert!(!device_pin_is_set(&mut fs));
    assert_eq!(device_pin_retries_left(&mut fs), None);
    assert!(matches!(
        spend_and_verify_device_pin(&dev(), &mut fs, PIN),
        LocalPin::Blocked
    ));
    // Set the device PIN: it is set, the FIDO clientPIN stays unset.
    store_device_pin(&dev(), &mut fs, DEVICE_PIN).unwrap();
    assert!(device_pin_is_set(&mut fs));
    assert!(
        !pin_is_set(&mut fs),
        "device PIN must not set the FIDO clientPIN"
    );
    // Correct device PIN verifies; a wrong one spends only its own counter.
    assert!(matches!(
        spend_and_verify_device_pin(&dev(), &mut fs, DEVICE_PIN),
        LocalPin::Ok
    ));
    assert!(matches!(
        spend_and_verify_device_pin(&dev(), &mut fs, WRONG_PIN),
        LocalPin::Wrong { .. }
    ));
    assert_eq!(device_pin_retries_left(&mut fs), Some(MAX_PIN_RETRIES - 1));
    assert_eq!(pin_retries_left(&mut fs), None, "FIDO counter untouched");
    // Add a different FIDO clientPIN: both coexist, each opened only by its own value.
    store_local_pin(&dev(), &mut fs, b"246810").unwrap();
    assert!(pin_is_set(&mut fs) && device_pin_is_set(&mut fs));
    assert!(matches!(
        spend_and_verify_local_pin(&dev(), &mut fs, b"246810"),
        LocalPin::Ok
    ));
    assert!(matches!(
        spend_and_verify_device_pin(&dev(), &mut fs, DEVICE_PIN),
        LocalPin::Ok
    ));
    assert!(
        matches!(
            spend_and_verify_device_pin(&dev(), &mut fs, b"246810"),
            LocalPin::Wrong { .. }
        ),
        "the FIDO PIN value must not open the device PIN"
    );
}

/// The set flow enforces `minPINLength`: the CTAP-default floor of 4, then a stricter
/// policy floor — and a refused set stores nothing.
#[test]
fn store_local_pin_enforces_min_length() {
    let (mut fs, _rng) = setup();
    match store_local_pin(&dev(), &mut fs, b"12") {
        Err(SetPinError::TooShort { min }) => assert_eq!(min, MIN_PIN_LENGTH),
        _ => panic!("expected TooShort at the default floor"),
    }
    assert!(!pin_is_set(&mut fs));
    // A policy floor of 6 refuses a 4-digit PIN…
    fs.put(EF_MINPINLEN, &[6, 0]).unwrap();
    // Literal on purpose: this case IS the short PIN, so it must not follow `PIN`.
    match store_local_pin(&dev(), &mut fs, b"1234") {
        Err(SetPinError::TooShort { min }) => assert_eq!(min, 6),
        _ => panic!("expected TooShort at the policy floor"),
    }
    assert!(!pin_is_set(&mut fs));
    // …but accepts one that meets it.
    store_local_pin(&dev(), &mut fs, b"123456").unwrap();
    assert!(pin_is_set(&mut fs));
    assert!(matches!(
        spend_and_verify_local_pin(&dev(), &mut fs, b"123456"),
        LocalPin::Ok
    ));
}

/// The set flow caps the new PIN at the host-representable maximum, so a panel-set PIN
/// can never be one the host clientPIN path is unable to verify (a lockout footgun).
#[test]
fn store_local_pin_enforces_max_length() {
    // The 63-byte ceiling is accepted and verifies…
    let (mut fs, _rng) = setup();
    let at_max = [b'1'; MAX_PIN_LENGTH];
    store_local_pin(&dev(), &mut fs, &at_max).unwrap();
    assert!(matches!(
        spend_and_verify_local_pin(&dev(), &mut fs, &at_max),
        LocalPin::Ok
    ));
    // …one byte over is refused and stores nothing.
    let (mut fs2, _rng2) = setup();
    match store_local_pin(&dev(), &mut fs2, &[b'1'; MAX_PIN_LENGTH + 1]) {
        Err(SetPinError::TooLong { max }) => assert_eq!(max as usize, MAX_PIN_LENGTH),
        other => panic!("expected TooLong, got {other:?}"),
    }
    assert!(!pin_is_set(&mut fs2));
}

/// A device-local change installs the new PIN with a fresh retry budget and rotates
/// it: the old PIN stops verifying, the new one verifies.
#[test]
fn store_local_pin_change_resets_budget_and_rotates() {
    let (mut fs, _rng, _state, _plat) = setup_with_pin(PIN);
    assert!(matches!(
        spend_and_verify_local_pin(&dev(), &mut fs, WRONG_PIN),
        LocalPin::Wrong { .. }
    ));
    assert_eq!(ef_pin_retries(&mut fs), MAX_PIN_RETRIES - 1);
    store_local_pin(&dev(), &mut fs, NEW_PIN).unwrap();
    assert_eq!(ef_pin_retries(&mut fs), MAX_PIN_RETRIES);
    assert!(matches!(
        spend_and_verify_local_pin(&dev(), &mut fs, PIN),
        LocalPin::Wrong { .. }
    ));
    assert!(matches!(
        spend_and_verify_local_pin(&dev(), &mut fs, NEW_PIN),
        LocalPin::Ok
    ));
}

/// Built-in UV: with a PIN set host-side, obtain a pinUvAuthToken via the
/// on-device pad (subCommand 6) — the PIN never crosses the wire. The minted
/// token carries the requested permissions and counts as user-verified.
#[test]
fn builtin_uv_token_success() {
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
    let mut out = [0u8; 256];
    let mut pad = UvPad::typing(PIN);
    let n = run_with(
        &mut pad,
        &mut fs,
        &mut rng,
        &mut state,
        &plat.get_uv_token_req(PERM_GA as u64),
        &mut out,
    )
    .unwrap();
    assert_eq!(plat.decrypt_token(&out[..n]), state.paut.token);
    assert_eq!(state.paut.permissions, PERM_GA);
    assert!(state.user_verified());
    // A correct entry restores the full retry budget.
    assert_eq!(ef_pin_retries(&mut fs), MAX_PIN_RETRIES);
}

/// The pad verifies the user; it does not stand in for the touch. §6.5.5.7.3 step
/// 13 would let a built-in UV that "supplied evidence of user interaction" mint a
/// token carrying presence, and §6.1.2 step 14 would then skip the presence
/// request — deleting the one screen that names the rp, which is the whole point
/// of the display. This device takes step 14, and this test keeps it there.
#[test]
fn builtin_uv_token_does_not_carry_user_presence() {
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
    let mut out = [0u8; 256];
    let mut pad = UvPad::typing(PIN);
    run_with(
        &mut pad,
        &mut fs,
        &mut rng,
        &mut state,
        &plat.get_uv_token_req(PERM_GA as u64),
        &mut out,
    )
    .unwrap();
    assert!(state.user_verified(), "the pad did verify the user");
    assert!(
        !state.user_present(),
        "a PIN typed on the pad must not stand in for the per-operation touch"
    );
}

/// A wrong on-screen PIN is reported as UV_INVALID (the built-in-UV dialect of
/// PIN_INVALID) and spends one of the shared retries.
#[test]
fn builtin_uv_wrong_pin_is_uv_invalid_and_burns_a_retry() {
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
    let mut out = [0u8; 256];
    let mut pad = UvPad::typing(WRONG_PIN);
    assert_eq!(
        run_with(
            &mut pad,
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_uv_token_req(PERM_GA as u64),
            &mut out,
        ),
        Err(CtapError::UvInvalid)
    );
    assert_eq!(ef_pin_retries(&mut fs), MAX_PIN_RETRIES - 1);
}

/// §6.5.5.7.3: `acfg` on the built-in-UV path is gated by the **uvAcfg** option ID,
/// which this device does not advertise — even though `authnrCfg` (which gates the
/// same permission on the host-PIN path, 0x09) is true.
#[test]
fn builtin_uv_token_refuses_acfg_permission() {
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
    let mut out = [0u8; 256];
    let mut pad = UvPad::typing(PIN);
    assert_eq!(
        run_with(
            &mut pad,
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_uv_token_req(crate::state::PERM_ACFG as u64),
            &mut out,
        ),
        Err(CtapError::UnauthorizedPermission)
    );
    // The same permission over the host-PIN path (0x09) is allowed.
    let n = run_with(
        &mut pad,
        &mut fs,
        &mut rng,
        &mut state,
        &plat.get_token_perms_req(PIN, crate::state::PERM_ACFG as u64),
        &mut out,
    )
    .unwrap();
    assert!(n > 0);
}

/// §6.5.5.7.3: a supported-but-unconfigured built-in UV method is NOT_ALLOWED, not
/// the host path's PIN_NOT_SET.
#[test]
fn builtin_uv_token_without_a_pin_is_not_allowed() {
    let (mut fs, mut rng) = setup();
    let mut state = FidoState::new();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    let mut out = [0u8; 256];
    let mut pad = UvPad::typing(PIN);
    assert_eq!(
        run_with(
            &mut pad,
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_uv_token_req(PERM_GA as u64),
            &mut out,
        ),
        Err(CtapError::NotAllowed)
    );
}

/// §6.5.5.7: on a device with a display the token is only minted after the user
/// approves the requested permissions on screen — and a refusal costs no retry,
/// since it lands before the PIN is checked at all.
#[test]
fn token_needs_on_screen_consent_on_a_display() {
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
    let mut out = [0u8; 256];
    // Host-supplied PIN (0x09).
    assert_eq!(
        run_with(
            &mut DenyConsent,
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_token_perms_req(PIN, PERM_GA as u64),
            &mut out,
        ),
        Err(CtapError::OperationDenied)
    );
    assert_eq!(ef_pin_retries(&mut fs), MAX_PIN_RETRIES);
    // Built-in UV (0x06) — the pad is never even reached (DenyConsent panics there).
    assert_eq!(
        run_with(
            &mut DenyConsent,
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_uv_token_req(PERM_GA as u64),
            &mut out,
        ),
        Err(CtapError::OperationDenied)
    );
    assert_eq!(ef_pin_retries(&mut fs), MAX_PIN_RETRIES);
    // A screenless build asks nothing and still mints the token.
    assert!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_token_perms_req(PIN, PERM_GA as u64),
            &mut out,
        )
        .is_ok()
    );
}

/// Tapping Cancel on the pad is a deliberate decline (OPERATION_DENIED) and,
/// unlike a wrong PIN, never spends a retry.
#[test]
fn builtin_uv_decline_denies_without_burning_a_retry() {
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
    let mut out = [0u8; 256];
    let mut pad = UvPad::ending(PinEntry::Declined);
    assert_eq!(
        run_with(
            &mut pad,
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_uv_token_req(PERM_GA as u64),
            &mut out,
        ),
        Err(CtapError::OperationDenied)
    );
    assert_eq!(ef_pin_retries(&mut fs), MAX_PIN_RETRIES);
}

/// Without an on-device pad (the default backend), the built-in-UV subcommands
/// are ones this build does not implement, so §8.1's rule applies to them like
/// any undefined value: CTAP2_ERR_INVALID_SUBCOMMAND.
#[test]
fn builtin_uv_subcommands_are_invalid_subcommand_without_a_pad() {
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
    let mut out = [0u8; 256];
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_uv_token_req(PERM_GA as u64),
            &mut out,
        ),
        Err(CtapError::InvalidSubcommand)
    );
    let uv_retries = build(&[(1, V::U(plat.wire)), (2, V::U(7))]);
    assert_eq!(
        run(&mut fs, &mut rng, &mut state, &uv_retries, &mut out),
        Err(CtapError::InvalidSubcommand)
    );
}

/// §8.1: "If the authenticator implements a command code having subcommands, but
/// does not implement an invoked subcommand, it MUST return
/// CTAP2_ERR_INVALID_SUBCOMMAND." 0x00 stays MISSING_PARAMETER — it is the
/// absent-parameter sentinel, not a subcommand value (see the `0x0` arm).
#[test]
fn undefined_clientpin_subcommand_is_invalid_subcommand() {
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
    let mut out = [0u8; 256];
    for sub in [0x08u64, 0x0A, 0x7F, 0xFF] {
        let req = build(&[(1, V::U(plat.wire)), (2, V::U(sub))]);
        assert_eq!(
            run(&mut fs, &mut rng, &mut state, &req, &mut out),
            Err(CtapError::InvalidSubcommand),
            "clientPIN subcommand {sub:#04x}"
        );
    }
}

/// getUVRetries (0x07) reports the shared budget that getPINRetries does, under
/// response key 0x05.
#[test]
fn get_uv_retries_mirrors_pin_retries() {
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
    let mut out = [0u8; 256];
    // Burn one retry with a wrong on-screen PIN.
    let mut pad = UvPad::typing(WRONG_PIN);
    let _ = run_with(
        &mut pad,
        &mut fs,
        &mut rng,
        &mut state,
        &plat.get_uv_token_req(PERM_GA as u64),
        &mut out,
    );
    // getUVRetries → { 5: uvRetries }, equal to the now-decremented PIN budget.
    let mut idle = UvPad::ending(PinEntry::Declined);
    let req = build(&[(1, V::U(plat.wire)), (2, V::U(7))]);
    let n = run_with(&mut idle, &mut fs, &mut rng, &mut state, &req, &mut out).unwrap();
    let mut d = Decoder::new(&out[..n]);
    assert_eq!(d.map().unwrap().unwrap(), 1);
    assert_eq!(d.u8().unwrap(), 5);
    let uv = d.u8().unwrap();
    assert_eq!(uv, MAX_PIN_RETRIES - 1);
    assert_eq!(uv, ef_pin_retries(&mut fs));
}

#[cfg(feature = "fips-profile")]
#[test]
fn fips_min_pin_floor_is_six() {
    let (mut fs, mut rng) = setup();
    let mut state = FidoState::new();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    let mut out = [0u8; 256];
    // Four code points sit under the profile's floor… (literal on purpose: this case
    // IS the short PIN, so it must not follow the suite's compliant `PIN`.)
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.set_pin_req(b"1234"),
            &mut out
        ),
        Err(CtapError::PinPolicyViolation)
    );
    // …a trivial six (an ascending run) is refused like the length floor…
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.set_pin_req(b"123456"),
            &mut out
        ),
        Err(CtapError::PinPolicyViolation)
    );
    // …and a non-trivial six passes.
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.set_pin_req(b"135790"),
        &mut out,
    )
    .unwrap();
    assert!(fs.has_data(EF_PIN));
}

#[cfg(feature = "strong-pin")]
#[test]
fn strong_pin_floor_is_six() {
    let (mut fs, mut rng) = setup();
    let mut state = FidoState::new();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    let mut out = [0u8; 256];
    // Four code points sit under the strong-pin floor.
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.set_pin_req(b"1234"),
            &mut out
        ),
        Err(CtapError::PinPolicyViolation)
    );
    // A non-trivial six-code-point PIN passes.
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.set_pin_req(b"135790"),
        &mut out,
    )
    .unwrap();
    assert!(fs.has_data(EF_PIN));
}

/// One representative per rule, driven through the real setPIN request rather than the
/// helper: a rule the request path never reaches refuses nothing. The families the
/// original check missed are the last four.
#[cfg(feature = "strong-pin")]
#[test]
fn strong_pin_refuses_every_trivial_family() {
    for (weak, why) in [
        (&b"000000"[..], "one repeated code point"),
        (b"123456", "an ascending run"),
        (b"654321", "a descending run"),
        (b"121212", "a two-code-point period"),
        (b"123123", "a three-code-point period"),
        (b"112211", "two distinct code points"),
        (b"159753", "a keypad line, denylisted"),
    ] {
        let (mut fs, mut rng) = setup();
        let mut state = FidoState::new();
        let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
        let mut out = [0u8; 256];
        assert_eq!(
            run(
                &mut fs,
                &mut rng,
                &mut state,
                &plat.set_pin_req(weak),
                &mut out
            ),
            Err(CtapError::PinPolicyViolation),
            "{} should be refused: {why}",
            core::str::from_utf8(weak).unwrap()
        );
        assert!(!fs.has_data(EF_PIN));
    }
}

/// The rule's own boundaries, where the request path cannot reach them: what it must
/// still ACCEPT is half of this, or a check that refuses everything would pass the
/// table above.
#[cfg(feature = "strong-pin")]
#[test]
fn pin_triviality_holds_its_boundaries() {
    // Refused.
    for (weak, why) in [
        (&b"12121"[..], "a period that does not divide the length"),
        (b"abcdef", "a run is not a digits-only rule"),
        (
            "\u{0410}\u{0410}\u{0410}\u{0410}\u{0410}\u{0410}".as_bytes(),
            "one repeated MULTI-BYTE code point",
        ),
        (
            &[0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa],
            "not UTF-8 — refused, not measured",
        ),
    ] {
        assert!(pin_is_trivial(weak), "should be trivial: {why}");
    }
    // Accepted — the other direction, without which the rule could simply be `true`.
    for (ok, why) in [
        (&b"135790"[..], "no period, no run, six distinct"),
        (b"100200", "exactly three distinct code points is enough"),
        (b"481629", "the display suite's own PIN"),
    ] {
        assert!(!pin_is_trivial(ok), "should be allowed: {why}");
    }
}

#[cfg(feature = "strong-pin")]
#[test]
fn strong_pin_rejects_trivial() {
    // A repeated digit, an ascending run, and a descending run are refused at length six.
    for weak in [b"000000", b"123456", b"654321"] {
        let (mut fs, mut rng) = setup();
        let mut state = FidoState::new();
        let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
        let mut out = [0u8; 256];
        assert_eq!(
            run(
                &mut fs,
                &mut rng,
                &mut state,
                &plat.set_pin_req(weak),
                &mut out
            ),
            Err(CtapError::PinPolicyViolation)
        );
        assert!(!fs.has_data(EF_PIN));
    }
}

/// getInfo's `pinComplexityPolicy` (0x1B) claims a PIN rule beyond `minPINLength`,
/// and is worth something only if it tracks what `store_new_pin` actually refuses.
/// So drive the ±1 run the rule is about and require the two to agree. There is no
/// `cfg` in the expectation: a build that advertises a policy it does not enforce,
/// or enforces one it does not advertise, fails this from whichever side broke.
///
/// The name carries `strong_pin` on purpose — `check.sh`'s strong-pin row is a
/// NAME FILTER, and it is the only gate row where this reaches its `true` arm.
#[test]
fn pin_complexity_policy_tracks_the_strong_pin_rule() {
    // Six code points clears BOTH length floors, so only the trivial-PIN rule can
    // reject it — which is what 0x1B is claiming to describe.
    let (mut fs, mut rng) = setup();
    let mut state = FidoState::new();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    let mut out = [0u8; 256];
    let refused = matches!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.set_pin_req(b"123456"),
            &mut out
        ),
        Err(CtapError::PinPolicyViolation)
    );

    let mut info = [0u8; 1024];
    let n = crate::getinfo::get_info(
        false, 4, false, false, false, false, 256, None, None, &mut info,
    )
    .unwrap();
    let mut d = minicbor::Decoder::new(&info[..n]);
    let entries = d.map().unwrap().unwrap();
    let mut advertised = None;
    for _ in 0..entries {
        if d.u32().unwrap() == 0x1B {
            advertised = Some(d.bool().unwrap());
        } else {
            d.skip().unwrap();
        }
    }
    assert_eq!(
        advertised,
        Some(refused),
        "0x1B must say exactly whether a trivial PIN is refused"
    );
}

#[test]
fn forced_pin_change_blocks_tokens_until_change_pin() {
    let (mut fs, mut rng) = setup();
    let mut state = FidoState::new();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    let mut out = [0u8; 256];
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.set_pin_req(PIN),
        &mut out,
    )
    .unwrap();

    // setMinPINLength(forceChangePin) state: [min, force, rpIdHash…].
    let mut mp = [0u8; 2 + 32];
    mp[0] = 4;
    mp[1] = 1;
    mp[2..].copy_from_slice(&sha256(b"example.com"));
    fs.put(EF_MINPINLEN, &mp).unwrap();

    // The *correct* PIN is refused while the flag is up. Via the legacy
    // getPinToken (0x05) the code is PIN_INVALID (the conformance tool's
    // ClientPin2-GetPinToken F-5; 0x09 instead uses POLICY_VIOLATION — see
    // `forced_pin_change_0x09_is_policy_violation`). The verify already
    // succeeded, so this is not a failed verify and the retry counter stays full.
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_token_req(PIN),
            &mut out
        ),
        Err(CtapError::PinInvalid)
    );
    let mut pf = [0u8; PIN_FILE_LEN];
    assert_eq!(fs.read(EF_PIN, &mut pf), Some(PIN_FILE_LEN));
    assert_eq!(pf[0], MAX_PIN_RETRIES);

    // changePIN satisfies the policy: flag drops, min + RP list survive.
    let n = run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.change_pin_req(PIN, NEW_PIN),
        &mut out,
    )
    .unwrap();
    assert_eq!(n, 0);
    let mut after = [0u8; 2 + 32];
    assert_eq!(fs.read(EF_MINPINLEN, &mut after), Some(2 + 32));
    assert_eq!(after[..2], [4, 0]);
    assert_eq!(after[2..], mp[2..]);

    // Tokens flow again with the new PIN.
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.get_token_req(NEW_PIN),
        &mut out,
    )
    .unwrap();
}

#[test]
fn forced_pin_change_0x09_is_policy_violation() {
    // getPinUvAuthTokenUsingPinWithPermissions (0x09) reports a pending forced
    // PIN change as PIN_POLICY_VIOLATION (0x37) — unlike the legacy getPinToken
    // (0x05) above, which reports PIN_INVALID. The FIDO conformance
    // ClientPin2-GetPinUvAuthTokenUsingPinWithPermissions F-1 asserts
    // POLICY_VIOLATION, so a single shared code can satisfy only one of the two.
    let (mut fs, mut rng) = setup();
    let mut state = FidoState::new();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    let mut out = [0u8; 256];
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.set_pin_req(PIN),
        &mut out,
    )
    .unwrap();
    let mut mp = [0u8; 2 + 32];
    mp[0] = 4;
    mp[1] = 1;
    mp[2..].copy_from_slice(&sha256(b"example.com"));
    fs.put(EF_MINPINLEN, &mp).unwrap();
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_token_perms_req(PIN, PERM_MC as u64),
            &mut out
        ),
        Err(CtapError::PinPolicyViolation)
    );
}

#[test]
fn seed_stays_loadable_after_pin_ops_and_legacy_wrap_migrates() {
    let (mut fs, mut rng) = setup();
    let mut state = FidoState::new();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);

    // Before a PIN, the seed loads.
    let seed0 = load_keydev(&dev(), &mut fs).unwrap();

    let mut out = [0u8; 256];
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.set_pin_req(PIN),
        &mut out,
    )
    .unwrap();
    // Setting a PIN leaves the seed loadable with no session, so a
    // power-cycled UP-only assertion keeps working.
    assert_eq!(
        crate::bare(load_keydev(&dev(), &mut fs)),
        Some(crate::bare(&seed0))
    );

    // A legacy PIN-wrapped blob is unreadable (the UP-only failure window)…
    let pin_hash = sha256(PIN);
    crate::seed::wrap_keydev_legacy(&dev(), &mut fs, seed0.expose(), &pin_hash[..16]);
    assert!((load_keydev(&dev(), &mut fs)).is_none());

    // …until the first successful PIN op of any boot migrates it back.
    let mut state2 = FidoState::new();
    let plat2 = key_agreement(&mut fs, &mut rng, &mut state2, PinProto::Two, 2);
    let n = run(
        &mut fs,
        &mut rng,
        &mut state2,
        &plat2.get_token_req(PIN),
        &mut out,
    )
    .unwrap();
    let _ = plat2.decrypt_token(&out[..n]);
    assert_eq!(
        crate::bare(load_keydev(&dev(), &mut fs)),
        Some(crate::bare(&seed0))
    );
}

#[test]
fn wrong_pin_decrements_then_locks_out() {
    let (mut fs, mut rng) = setup();
    let mut state = FidoState::new();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    let mut out = [0u8; 256];
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.set_pin_req(PIN),
        &mut out,
    )
    .unwrap();

    // First two wrong attempts: PinInvalid, retry counter drops.
    for _ in 0..2 {
        assert_eq!(
            run(
                &mut fs,
                &mut rng,
                &mut state,
                &plat.get_token_req(WRONG_PIN),
                &mut out
            ),
            Err(CtapError::PinInvalid)
        );
    }
    // Third consecutive mismatch trips the per-boot lockout.
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_token_req(WRONG_PIN),
            &mut out
        ),
        Err(CtapError::PinAuthBlocked)
    );
    assert!(state.needs_power_cycle);

    // getPINRetries reflects the three decrements (8 -> 5) and powerCycleState.
    let n = run(
        &mut fs,
        &mut rng,
        &mut state,
        &build(&[(1, V::U(2)), (2, V::U(1))]),
        &mut out,
    )
    .unwrap();
    let mut d = Decoder::new(&out[..n]);
    assert_eq!(d.map().unwrap().unwrap(), 2);
    assert_eq!(d.u8().unwrap(), 3);
    assert_eq!(d.u8().unwrap(), MAX_PIN_RETRIES - 3);
}

#[test]
fn the_legacy_get_pin_token_refuses_an_rp_id() {
    // CTAP 2.1 §6.5.5.7: subCommand 5 takes neither permissions nor an rpId —
    // it grants the fixed mc|ga set and no rp binding. The refusal was held by
    // nothing: `clientpin.rs:426` hands `req.rp_id` to `issue_token` whatever the
    // subcommand, so relaxing the guard mints a legacy token BOUND to an rp the
    // caller named. Found by the reverse mutation pass (D2).
    let (mut fs, mut rng) = setup();
    let mut state = FidoState::new();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    let mut out = [0u8; 256];
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.set_pin_req(PIN),
        &mut out,
    )
    .unwrap();

    let h = sha256(PIN);
    let phe = plat.enc(&h[..16]);
    let rp_id = [0x62u8, b'r', b'p']; // CBOR text(2) "rp"
    let req = build(&[
        (1, V::U(plat.wire)),
        (2, V::U(5)),
        (3, V::Cose(&plat.x, &plat.y)),
        (6, V::B(&phe)),
        (10, V::Raw(&rp_id)),
    ]);
    assert_eq!(
        run(&mut fs, &mut rng, &mut state, &req, &mut out),
        Err(CtapError::InvalidParameter),
        "subCommand 5 must refuse an rpId rather than bind the token to it"
    );
    assert!(
        !state.paut.in_use,
        "a refused request must not have minted a token"
    );
}

#[test]
fn change_pin_over_protocol_one() {
    // The whole clientPIN suite ran on PIN protocol TWO except one setPIN case,
    // so every length rule in changePIN was measured at `PADDED_PIN_LEN + 16`
    // and never at `+ 0` — where the same expression written wrong turns the
    // over-long guard into "refuse every changePIN". Found by the reverse
    // mutation pass (D2): protocol 1 is still in CTAP 2.1 and this firmware
    // still speaks it.
    let (mut fs, mut rng) = setup();
    let mut state = FidoState::new();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::One, 1);
    let mut out = [0u8; 256];
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.set_pin_req(PIN),
        &mut out,
    )
    .unwrap();

    let n = run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.change_pin_req(PIN, NEW_PIN),
        &mut out,
    )
    .unwrap();
    assert_eq!(n, 0, "changePIN over protocol 1 must be accepted");

    assert!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_token_req(NEW_PIN),
            &mut out
        )
        .is_ok(),
        "the new PIN must work over protocol 1"
    );
}

#[test]
fn change_pin_then_new_pin_works_and_old_fails() {
    let (mut fs, mut rng) = setup();
    let mut state = FidoState::new();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    let mut out = [0u8; 256];
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.set_pin_req(PIN),
        &mut out,
    )
    .unwrap();

    // changePIN replies with only the status byte.
    let n = run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.change_pin_req(PIN, NEW_PIN),
        &mut out,
    )
    .unwrap();
    assert_eq!(n, 0);

    // The new PIN yields a token; the old PIN is now invalid.
    assert!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_token_req(NEW_PIN),
            &mut out
        )
        .is_ok()
    );
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_token_req(PIN),
            &mut out
        ),
        Err(CtapError::PinInvalid)
    );
}

#[test]
fn set_pin_rejects_short_pin_and_double_set() {
    let (mut fs, mut rng) = setup();
    let mut state = FidoState::new();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    let mut out = [0u8; 256];
    // 3-char PIN < minimum 4.
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.set_pin_req(b"123"),
            &mut out
        ),
        Err(CtapError::PinPolicyViolation)
    );
    // A valid set, then a second set — §6.5.5.5: "If a PIN has already been set,
    // authenticator returns CTAP2_ERR_PIN_AUTH_INVALID error."
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.set_pin_req(PIN),
        &mut out,
    )
    .unwrap();
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.set_pin_req(NEW_PIN),
            &mut out
        ),
        Err(CtapError::PinAuthInvalid)
    );
}

#[test]
fn bad_pin_auth_param_rejected() {
    let (mut fs, mut rng) = setup();
    let mut state = FidoState::new();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    let mut out = [0u8; 256];
    // A setPIN with a wrong (all-zero) pinUvAuthParam fails authentication.
    let mut padded = [0u8; 64];
    padded[..PIN.len()].copy_from_slice(PIN);
    let npe = plat.enc(&padded);
    let bad_mac = [0u8; 32];
    let req = build(&[
        (1, V::U(2)),
        (2, V::U(3)),
        (3, V::Cose(&plat.x, &plat.y)),
        (4, V::B(&bad_mac[..plat.proto.mac_len()])),
        (5, V::B(&npe)),
    ]);
    assert_eq!(
        run(&mut fs, &mut rng, &mut state, &req, &mut out),
        Err(CtapError::PinAuthInvalid)
    );
}

#[test]
fn pin_verifier_and_pinwrapped_seed_migrate_at_verify() {
    const OTP_KEY: [u8; 32] = [0x77; 32];
    fn otp_dev() -> Device<'static> {
        Device {
            otp_key: Some(&OTP_KEY),
            ..dev()
        }
    }

    // Legacy pre-OTP state: seed exists, a PIN is set, and the seed was
    // left PIN-wrapped (0x03).
    let (mut fs, medium, mut rng) = setup_cut();
    let seed0 = load_keydev(&dev(), &mut fs).unwrap();
    let mut padded = [0u8; PADDED_PIN_LEN];
    padded[..PIN.len()].copy_from_slice(PIN);
    let mut state = FidoState::new();
    {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        store_new_pin(&mut ctx, &padded).unwrap();
    }
    let pin_hash = sha256(PIN);
    crate::seed::wrap_keydev_legacy(&dev(), &mut fs, seed0.expose(), &pin_hash[..16]);
    let mut raw = [0u8; 61];
    assert_eq!(fs.read(EF_KEY_DEV.get(), &mut raw), Some(61));
    assert_eq!(raw[0], 0x03);
    // The one-shot at-rest lap has already run on this device: the migration
    // below supersedes a chip-serial-sealed copy AFTER it, so it must re-arm
    // the lap (request_rescrub) or that copy stays readable in a raw flash
    // dump forever — audit run-35 found four of five lazy re-keys skipping it.
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    assert!(
        fs.has_data(rsk_fs::EF_HARDENED),
        "fixture: the lap has latched"
    );

    // The OTP build: first verify migrates the verifier and unwraps the
    // seed straight to a plain 0x12, costing no retry.
    let mut state2 = FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: otp_dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state2,
        now_ms: 0,
    };
    // The verify's own retry spend rewrites EF_PIN with the SAME verifier, so
    // "still weak" is every write that leaves the verifier bytes alone.
    let before = medium
        .value(EF_PIN)
        .expect("fixture: EF_PIN is on the medium");
    medium.clear_ops();
    spend_and_verify_pin_hash(&mut ctx, &pin_hash[..16]).unwrap();
    medium.assert_re_armed_before(
        EF_PIN,
        |v| v.len() == before.len() && v[1..] == before[1..],
        "spend_and_verify_pin_hash's kbase fallback",
    );
    let mut pin_rec = [0u8; PIN_FILE_LEN];
    ctx.fs.read(EF_PIN, &mut pin_rec).unwrap();
    assert_eq!(pin_rec[0], MAX_PIN_RETRIES);
    assert_eq!(ctx.fs.read(EF_KEY_DEV.get(), &mut raw), Some(61));
    assert_eq!(raw[0], 0x12);
    assert_eq!(
        crate::bare(load_keydev(&otp_dev(), ctx.fs)),
        Some(crate::bare(&seed0))
    );
    // What this witnesses is the `request_rescrub` CALL, not a leak: `RamStorage`
    // is a map that overwrites in place, so no superseded copy survives any write
    // here for a test to read. The medium that keeps one is the flash ring.
    assert!(
        !ctx.fs.has_data(rsk_fs::EF_HARDENED),
        "a lazy re-key must re-arm the at-rest lap: the marker is still latched, \
         so no rescrub was requested"
    );

    // Second verify takes the direct path (verifier already re-stored).
    let mut state3 = FidoState::new();
    let mut presence3 = crate::AlwaysConfirm;
    let mut ctx3 = Ctx {
        presence: &mut presence3,
        dev: otp_dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state3,
        now_ms: 0,
    };
    spend_and_verify_pin_hash(&mut ctx3, &pin_hash[..16]).unwrap();
}

/// F6: the `if migrated` guard is narrower than the writes it was placed in front of.
/// `migrate_keydev_pin` re-keys `EF_KEY_DEV` off the pre-OTP arm on the SUCCESS path,
/// whatever `EF_PIN`'s verifier says — and the two records part company the moment a
/// faulted `read_key` makes that migration a no-op for one verify: `EF_PIN` lands
/// OTP-rooted, the seed stays 0x03, and every later verify re-keys it with `migrated`
/// false and no re-arm anywhere. So the re-arm belongs where the knowledge is.
#[test]
fn a_seed_migration_with_an_already_migrated_verifier_re_arms_the_lap() {
    const OTP_KEY: [u8; 32] = [0x79; 32];
    fn otp_dev() -> Device<'static> {
        Device {
            otp_key: Some(&OTP_KEY),
            ..dev()
        }
    }

    let (mut fs, medium, mut rng) = setup_cut();
    let seed0 = load_keydev(&dev(), &mut fs).unwrap();
    let mut padded = [0u8; PADDED_PIN_LEN];
    padded[..PIN.len()].copy_from_slice(PIN);
    let mut state = FidoState::new();
    // EF_PIN is written by the OTP build, so its verifier is ALREADY OTP-rooted and
    // the fallback that sets `migrated` never fires.
    {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: otp_dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        store_new_pin(&mut ctx, &padded).unwrap();
    }
    // The seed is the straggler: a pre-OTP PIN-wrapped 0x03 under the same PIN.
    let pin_hash = sha256(PIN);
    crate::seed::wrap_keydev_legacy(&dev(), &mut fs, seed0.expose(), &pin_hash[..16]);
    let mut raw = [0u8; 61];
    assert_eq!(fs.read(EF_KEY_DEV.get(), &mut raw), Some(61));
    assert_eq!(raw[0], 0x03, "fixture: the seed is pre-OTP PIN-wrapped");
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    assert!(
        fs.has_data(rsk_fs::EF_HARDENED),
        "fixture: the lap has latched"
    );

    medium.clear_ops();
    let mut state2 = FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: otp_dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state2,
        now_ms: 0,
    };
    spend_and_verify_pin_hash(&mut ctx, &pin_hash[..16]).unwrap();
    assert_eq!(ctx.fs.read(EF_KEY_DEV.get(), &mut raw), Some(61));
    assert_eq!(
        raw[0], 0x12,
        "fixture: the verify really did re-key the seed off the pre-OTP arm"
    );
    assert_eq!(
        crate::bare(load_keydev(&otp_dev(), ctx.fs)),
        Some(crate::bare(&seed0))
    );
    assert!(
        !ctx.fs.has_data(rsk_fs::EF_HARDENED),
        "the seed was re-keyed off the chip-serial arm with `migrated` false, so \
         nothing re-armed the lap and that 0x03 copy stays in the ring for good"
    );
    // EF_PIN is rewritten here too (the retry spend and its reset), but it re-keys
    // nothing — the append the order is about is the seed's.
    medium.assert_re_armed_before(EF_KEY_DEV.get(), |_| false, "migrate_keydev_pin");
}

/// How the two records part company on a real card, so F6's state is not a fixture.
/// `migrate_keydev_pin` opens with `fs.read_key(EF_KEY_DEV, …)`, and `read_key`
/// collapses a flash READ FAULT into the same `None` an absent slot gives — so one
/// faulted probe makes the seed migration a silent no-op for that verify, while the
/// SAME verify goes on to persist an OTP-rooted `EF_PIN`. From then on `migrated` is
/// false for a seed still sitting at 0x03.
#[test]
fn a_faulted_seed_probe_leaves_the_verifier_migrated_and_the_seed_behind() {
    const OTP_KEY: [u8; 32] = [0x7A; 32];
    fn otp_dev() -> Device<'static> {
        Device {
            otp_key: Some(&OTP_KEY),
            ..dev()
        }
    }

    let (stuck, medium) = ProbeStuck::new();
    let mut fs = Fs::new(stuck);
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let seed0 = load_keydev(&dev(), &mut fs).unwrap();
    let mut padded = [0u8; PADDED_PIN_LEN];
    padded[..PIN.len()].copy_from_slice(PIN);
    let mut state = FidoState::new();
    {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        store_new_pin(&mut ctx, &padded).unwrap();
    }
    let pin_hash = sha256(PIN);
    crate::seed::wrap_keydev_legacy(&dev(), &mut fs, seed0.expose(), &pin_hash[..16]);
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();

    // Verify #1 on the OTP build: `migrated` is true, so the verifier is re-keyed and
    // the lap re-armed — but the seed probe faults, and the migration answers Ok over
    // a record it never read.
    medium.stick_once(EF_KEY_DEV.get());
    {
        let mut state2 = FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: otp_dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state2,
            now_ms: 0,
        };
        spend_and_verify_pin_hash(&mut ctx, &pin_hash[..16]).unwrap();
    }
    let mut raw = [0u8; 61];
    assert_eq!(fs.read(EF_KEY_DEV.get(), &mut raw), Some(61));
    assert_eq!(raw[0], 0x03, "the faulted probe left the seed pre-OTP");
    let mut pin_rec = [0u8; PIN_FILE_LEN];
    assert_eq!(fs.read(EF_PIN, &mut pin_rec), Some(PIN_FILE_LEN));
    assert_eq!(
        &pin_rec[3..PIN_FILE_LEN],
        &otp_dev().pin_derive_verifier(&pin_hash[..16]).expose()[..PIN_FILE_LEN - 3],
        "…while the same verify persisted an OTP-rooted verifier, so no later \
         verify will set `migrated` again",
    );

    // The next boot laps and latches the marker again.
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    let mut state3 = FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: otp_dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state3,
        now_ms: 0,
    };
    spend_and_verify_pin_hash(&mut ctx, &pin_hash[..16]).unwrap();
    assert_eq!(ctx.fs.read(EF_KEY_DEV.get(), &mut raw), Some(61));
    assert_eq!(
        raw[0], 0x12,
        "verify #2 re-keyed the seed off the chip-serial arm"
    );
    assert!(
        !ctx.fs.has_data(rsk_fs::EF_HARDENED),
        "…with `migrated` false, so on the old guard nothing re-armed the lap and \
         the 0x03 copy stays in the ring for the life of the key"
    );
}

/// The trusted display's PIN verify carries its own copy of the kbase fallback, so
/// nothing `spend_and_verify_pin_hash` does holds it: it re-keys the same pre-OTP
/// verifier and owes the same re-arm, in the same order. No test reached this site
/// at all before — the host path shadowed it in every reachability sweep.
#[test]
fn a_local_pin_verify_re_arms_the_lap_before_it_re_keys() {
    const OTP_KEY: [u8; 32] = [0x78; 32];
    fn otp_dev() -> Device<'static> {
        Device {
            otp_key: Some(&OTP_KEY),
            ..dev()
        }
    }

    // Pre-OTP: the verifier `store_new_pin` lands is rooted in the public chip serial.
    let (mut fs, medium, mut rng) = setup_cut();
    let mut padded = [0u8; PADDED_PIN_LEN];
    padded[..PIN.len()].copy_from_slice(PIN);
    let mut state = FidoState::new();
    {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        store_new_pin(&mut ctx, &padded).unwrap();
    }
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    assert!(
        fs.has_data(rsk_fs::EF_HARDENED),
        "fixture: the lap has latched"
    );

    // The OTP build. The pad's verify takes the fallback and re-stores the verifier
    // under the OTP arm; its own retry spend rewrites EF_PIN without re-keying it,
    // so "still weak" is every write that leaves the verifier bytes alone.
    let before = medium
        .value(EF_PIN)
        .expect("fixture: EF_PIN is on the medium");
    medium.clear_ops();
    assert!(matches!(
        spend_and_verify_local_pin(&otp_dev(), &mut fs, PIN),
        LocalPin::Ok
    ));
    assert_ne!(
        medium.value(EF_PIN).as_deref().map(|v| &v[1..]),
        Some(&before[1..]),
        "fixture: the verify never re-keyed the verifier, so there is no order to hold"
    );
    assert!(
        !fs.has_data(rsk_fs::EF_HARDENED),
        "a lazy re-key must re-arm the at-rest lap: the marker is still latched, \
         so no rescrub was requested"
    );
    medium.assert_re_armed_before(
        EF_PIN,
        |v| v.len() == before.len() && v[1..] == before[1..],
        "spend_and_verify_pin_at's kbase fallback",
    );
}

#[test]
fn pin_verify_fails_closed_when_the_retry_write_does_not_persist() {
    use std::cell::Cell;
    use std::rc::Rc;

    // A backend that, once armed, accepts the EF_PIN write (returns Ok) but
    // silently fails to persist it — modelling a glitch / partial flash
    // program. The decremented retry counter never reaches storage, so a later
    // read sees the stale (higher) count: exactly what spend_and_verify_pin_hash's
    // read-back must catch before trusting the count.
    struct StaleEfPin {
        inner: RamStorage,
        drop_ef_pin_writes: Rc<Cell<bool>>,
    }
    impl Storage for StaleEfPin {
        fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
            self.inner.read(fid, buf)
        }
        fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
            if fid == EF_PIN && self.drop_ef_pin_writes.get() {
                return Ok(()); // reports success, persists nothing
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

    let drop_writes = Rc::new(Cell::new(false));
    let mut fs = Fs::new(StaleEfPin {
        inner: RamStorage::new(),
        drop_ef_pin_writes: drop_writes.clone(),
    });
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();

    // Enroll PIN "1234" with writes persisting normally.
    let mut padded = [0u8; PADDED_PIN_LEN];
    padded[..PIN.len()].copy_from_slice(PIN);
    {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut FidoState::new(),
            now_ms: 0,
        };
        store_new_pin(&mut ctx, &padded).unwrap();
    }

    let pin_hash = sha256(PIN);

    // Control: with the backend healthy, the correct PIN verifies (and resets
    // the counter to full) — so a PinBlocked below can only be the read-back.
    {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut FidoState::new(),
            now_ms: 0,
        };
        spend_and_verify_pin_hash(&mut ctx, &pin_hash[..16]).unwrap();
    }

    // Arm the fault: the decremented counter no longer reaches storage. Even
    // with the CORRECT PIN, the read-back sees the stale count and must fail
    // closed rather than proceed on an unverified (un-decremented) counter.
    drop_writes.set(true);
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut FidoState::new(),
        now_ms: 0,
    };
    assert_eq!(
        spend_and_verify_pin_hash(&mut ctx, &pin_hash[..16]),
        Err(CtapError::PinBlocked),
    );
}

// pinUvAuthToken rolling window (CTAP 2.1 §6.5.5.7): an unused token retires
// once the inactivity window elapses, and not one tick sooner.
#[test]
fn pin_uv_auth_token_expires_after_inactivity_window() {
    use crate::consts::PUAT_INITIAL_USAGE_LIMIT_MS as W;
    let mut state = FidoState::new();
    state.paut.permissions = crate::state::PERM_CM;
    state.begin_using_token(false, 1_000);

    // One millisecond short of the window: still live.
    state.expire_stale_token(1_000 + W - 1);
    assert!(state.paut.in_use);
    assert!(state.user_verified());

    // Window elapsed with no use: retired, flags/permissions cleared closed.
    state.expire_stale_token(1_000 + W);
    assert!(!state.paut.in_use);
    assert_eq!(state.paut.permissions, 0);
    assert!(!state.user_verified());
    assert!(!state.user_present());
}

// Each use rolls the deadline forward; the token then dies one window after its
// last use, not its issuance.
#[test]
fn pin_uv_auth_token_rolls_forward_on_use() {
    use crate::consts::PUAT_INITIAL_USAGE_LIMIT_MS as W;
    let mut state = FidoState::new();
    state.begin_using_token(false, 0);

    // Used near the end of the first window: deadline moves to (W - 5000) + W.
    state.mark_token_used(W - 5_000);
    state.expire_stale_token(W + 1_000); // 6000 since use < W -> alive
    assert!(state.paut.in_use);

    // Used again: deadline moves again, surviving well past 2× the window.
    state.mark_token_used(W + 1_000);
    state.expire_stale_token(2 * W); // 29000 since use < W -> alive
    assert!(state.paut.in_use);

    // Left idle from the last use: dies exactly one window later.
    state.expire_stale_token(W + 1_000 + W);
    assert!(!state.paut.in_use);
}

// The absolute lifetime cap retires the token even when it is still being used
// inside the rolling window.
#[test]
fn pin_uv_auth_token_hard_capped_despite_use() {
    use crate::consts::PUAT_MAX_USAGE_PERIOD_MS as MAX;
    let mut state = FidoState::new();
    state.begin_using_token(false, 0);

    // A fresh use 1 s before the cap — the rolling window alone would keep it
    // alive (since_use == 1000), but the cap from issuance retires it anyway.
    state.mark_token_used(MAX - 1_000);
    state.expire_stale_token(MAX);
    assert!(!state.paut.in_use);
}

// The timer never touches an idle token, never expires early on clock wrap, and
// mark_token_used on a not-in-use token is a no-op.
#[test]
fn pin_uv_auth_token_timer_ignores_idle_and_wrap() {
    let mut state = FidoState::new();
    state.expire_stale_token(u64::MAX);
    assert!(!state.paut.in_use);

    // `now` before issuance (clock wrap): saturating_sub -> 0, so no early expiry.
    state.begin_using_token(false, 10_000);
    state.expire_stale_token(0);
    assert!(state.paut.in_use);

    let mut idle = FidoState::new();
    idle.mark_token_used(12_345);
    assert_eq!(idle.paut.last_used_ms, 0);
}

#[test]
fn ephemeral_public_is_cached_and_matches_a_fresh_derive() {
    let mut rng = SeqRng(42);
    let mut state = FidoState::new();
    // Uninitialized: no ephemeral key-agreement key yet.
    assert!(state.ephemeral_public().is_none());
    // ensure_initialized is what boot (and, before the fix, the first clientPIN)
    // calls; it must leave a cached public key consistent with the scalar.
    state.ensure_initialized(&mut rng);
    let cached = state.ephemeral_public().expect("initialized");
    // The cache equals a fresh d·G of the stored scalar (correctness) and is
    // stable across calls (getKeyAgreement no longer recomputes the multiply).
    assert_eq!(cached, public_xy(state.ephemeral_scalar()).unwrap());
    assert_eq!(state.ephemeral_public().unwrap(), cached);
    // The wrong-PIN regenerate path refreshes both the scalar and the cache.
    state.regenerate(&mut rng);
    let cached2 = state.ephemeral_public().unwrap();
    assert_eq!(cached2, public_xy(state.ephemeral_scalar()).unwrap());
    assert_ne!(cached2, cached);
}

/// CTAP 2.1 §6.5.7 wants a fresh IV on the encrypted token, and protocol two puts
/// it in the clear at the head of the ciphertext. The IV was hard-coded to zero,
/// which the freshly-random token mostly masked — except on the `PERM_PCMR`
/// branch, whose token is filled once per power cycle, so two issuances under one
/// shared secret were byte-identical and linkable (audit run-34 #37).
#[test]
fn each_pin_token_carries_a_fresh_iv() {
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
    let mut ivs = std::vec::Vec::new();
    for _ in 0..4 {
        let mut out = [0u8; 256];
        let n = run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_token_req(PIN),
            &mut out,
        )
        .unwrap();
        // {2: <iv ‖ ct>} — the first 16 bytes of the value are protocol two's IV.
        let mut d = Decoder::new(&out[..n]);
        assert_eq!(d.map().unwrap().unwrap(), 1);
        assert_eq!(d.u8().unwrap(), 2);
        let enc = d.bytes().unwrap();
        assert!(enc.len() >= 16 + 32, "short token ciphertext");
        ivs.push(enc[..16].to_vec());
    }
    assert!(ivs.iter().all(|iv| iv != &[0u8; 16]), "zero IV: {ivs:02x?}");
    for i in 1..ivs.len() {
        assert!(
            !ivs[..i].contains(&ivs[i]),
            "IV repeated across issuances: {ivs:02x?}"
        );
    }
}

/// CTAP 2.2 §6.5.5.7.2 step 14: a `pcmr` request is answered with the *persistent*
/// token and stops there. It is minted at the grant — never the all-zero default a
/// RAM-only token had before any changePIN — and, being flash-backed, the same
/// bytes come back after a power cycle, which is the whole point of `pcmr`: the
/// platform keeps read access to credential metadata across replugs.
#[test]
fn pcmr_issues_a_persistent_token_that_survives_a_power_cycle() {
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
    let mut out = [0u8; 256];
    let n = run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.get_token_perms_req(PIN, PERM_PCMR as u64),
        &mut out,
    )
    .unwrap();
    let ppuat = plat.decrypt_token(&out[..n]);
    assert_ne!(ppuat, [0u8; 32], "the persistent token must be random");
    assert!(
        !state.paut.in_use,
        "the pcmr branch returns before beginUsingPinUvAuthToken"
    );

    // A fresh FidoState is a power cycle: RAM state is gone, the token is not.
    let mut rebooted = FidoState::new();
    let plat2 = key_agreement(&mut fs, &mut rng, &mut rebooted, PinProto::Two, 2);
    let n = run(
        &mut fs,
        &mut rng,
        &mut rebooted,
        &plat2.get_token_perms_req(PIN, PERM_PCMR as u64),
        &mut out,
    )
    .unwrap();
    assert_eq!(plat2.decrypt_token(&out[..n]), ppuat);
}

/// §6.5.5.6 step 15 also resets the *in-RAM* pinUvAuthToken, not just the
/// persistent grant the sibling below covers: a session token issued before a
/// changePIN must be dead after it. Co-refutation surfaced this as a gap — the
/// model's `BugTokenSurvivesPinChange` (`NoTokenAfterInvalidation`) is RED, but
/// dropping `reset_pin_uv_auth_token` from `change_pin` left every unit test
/// green because the persistent-token test exercises `clear_ppuat`, a different
/// door. The RAM session token had no host test at all.
#[test]
fn change_pin_revokes_the_session_token() {
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
    let mut out = [0u8; 256];
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.get_token_perms_req(PIN, (PERM_MC | PERM_GA) as u64),
        &mut out,
    )
    .unwrap();
    assert!(state.paut.in_use, "the token is in use after issuance");
    assert_eq!(state.paut.permissions, PERM_MC | PERM_GA);

    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.change_pin_req(PIN, NEW_PIN),
        &mut out,
    )
    .unwrap();

    assert!(
        !state.paut.in_use && state.paut.permissions == 0,
        "changePIN left the pre-change session token live"
    );
}

/// §6.5.5.6 step 15 calls resetPersistentPinUvAuthToken — "all persistent
/// permissions are cleared on pin change" — so the old holder's grant dies with
/// the old PIN and the next grant mints different bytes.
#[test]
fn change_pin_revokes_the_persistent_token() {
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
    let mut out = [0u8; 256];
    let n = run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.get_token_perms_req(PIN, PERM_PCMR as u64),
        &mut out,
    )
    .unwrap();
    let before = plat.decrypt_token(&out[..n]);

    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.change_pin_req(PIN, NEW_PIN),
        &mut out,
    )
    .unwrap();

    let plat2 = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    let n = run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat2.get_token_perms_req(NEW_PIN, PERM_PCMR as u64),
        &mut out,
    )
    .unwrap();
    assert_ne!(plat2.decrypt_token(&out[..n]), before);
}

/// The on-pad PIN change carries the same step-15 revocation as the host paths. It
/// used to delegate that to a RAM flag the firmware consumed on the next CBOR
/// command, so an APDU-only warm reboot (or a plain replug) dropped the signal and
/// left the pre-change `pcmr` grant reading the credential directory for ever — after
/// the owner had performed the exact remediation the product tells them to perform
/// (audit run-37).
#[test]
fn local_pin_change_revokes_the_persistent_token() {
    let (mut fs, mut rng, _state, _plat) = setup_with_pin(PIN);
    let before = crate::seed::ensure_ppuat(&dev(), &mut fs, &mut rng).unwrap();

    store_local_pin(&dev(), &mut fs, NEW_PIN).unwrap();

    assert!(
        crate::seed::load_ppuat(&dev(), &mut fs).is_none(),
        "a grant minted under the old PIN must not survive the on-pad change"
    );
    assert_ne!(
        crate::bare(crate::seed::ensure_ppuat(&dev(), &mut fs, &mut rng).unwrap()),
        crate::bare(&before)
    );
}

/// The revocation sits in `write_pin_verifier`, the one function every `EF_PIN`
/// verifier write in this crate goes through, so a *future* PIN-establishing path
/// cannot reintroduce run-37's defect by forgetting it. `EF_DEVICE_PIN` is a separate
/// credential that grants no `pcmr`, so it must revoke nothing.
#[test]
fn every_ef_pin_verifier_write_revokes_the_persistent_token() {
    let (mut fs, mut rng) = setup();
    let token = crate::seed::ensure_ppuat(&dev(), &mut fs, &mut rng).unwrap();

    write_pin_verifier(EF_DEVICE_PIN, &dev(), &mut fs, NEW_PIN, 4).unwrap();
    assert_eq!(
        crate::bare(crate::seed::load_ppuat(&dev(), &mut fs)),
        Some(crate::bare(&token)),
        "the device PIN grants nothing, so it revokes nothing"
    );

    write_pin_verifier(EF_PIN, &dev(), &mut fs, PIN, 4).unwrap();
    assert!(crate::seed::load_ppuat(&dev(), &mut fs).is_none());
}

/// The `pcmr` consent card must name what it grants: a flash record that outlives
/// every power cycle until a PIN change or a reset. On the built-in-UV path the host
/// sends no PIN at all, so this screen is the entire disclosure — and it used to be
/// the same "Allow host access?" the ten-minute `mc|ga` token gets (audit run-37).
#[test]
fn pcmr_consent_card_names_the_permission() {
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
    let mut out = [0u8; 256];
    let mut pad = UvPad::typing(PIN);

    run_with(
        &mut pad,
        &mut fs,
        &mut rng,
        &mut state,
        &plat.get_uv_token_req(PERM_GA as u64),
        &mut out,
    )
    .unwrap();
    run_with(
        &mut pad,
        &mut fs,
        &mut rng,
        &mut state,
        &plat.get_uv_token_req(PERM_PCMR as u64),
        &mut out,
    )
    .unwrap();

    assert_eq!(pad.titles.len(), 2);
    assert_ne!(
        pad.titles[0], pad.titles[1],
        "a permanent directory grant must not be approved behind the session card"
    );
    assert_eq!(pad.titles[1], "Always list passkeys?");
    // The same card also covers the host-PIN path (0x09).
    let mut pad2 = UvPad::typing(PIN);
    run_with(
        &mut pad2,
        &mut fs,
        &mut rng,
        &mut state,
        &plat.get_token_perms_req(PIN, PERM_PCMR as u64),
        &mut out,
    )
    .unwrap();
    assert_eq!(pad2.titles, std::vec!["Always list passkeys?"]);
}

/// A platform scalar whose public key's `x` (`which = 0`) or `y` (`which = 1`)
/// starts with a zero byte, with that public key. Stripping a byte off an
/// arbitrary coordinate lands off the curve, so such a request is refused either
/// way and a test built on one cannot tell the length rule from the failed ECDH —
/// only a genuine leading-zero encoding exercises what the old left-pad rescued.
fn scalar_with_leading_zero(which: usize) -> ([u8; 32], [u8; 32], [u8; 32]) {
    for i in 1u32..100_000 {
        let mut s = [0u8; 32];
        s[28..].copy_from_slice(&i.to_be_bytes());
        let (x, y) = public_xy(&s).unwrap();
        if [x, y][which][0] == 0 {
            return (s, x, y);
        }
    }
    panic!("no P-256 scalar with a leading-zero coordinate in the search range");
}

/// Agree with the authenticator's current ephemeral key using `pscalar` instead
/// of [`key_agreement`]'s fixed one.
fn platform_from(state: &FidoState, proto: PinProto, wire: u64, pscalar: &[u8; 32]) -> Platform {
    let (ax, ay) = state.ephemeral_public().unwrap();
    let (x, y) = public_xy(pscalar).unwrap();
    let mut shared = [0u8; 64];
    let slen = pinproto::ecdh(proto, pscalar, &ax, &ay, &mut shared).unwrap();
    Platform {
        proto,
        wire,
        x,
        y,
        shared,
        slen,
    }
}

/// §6.5's keyAgreement is a P-256 COSE key, and a coordinate that is not exactly
/// 32 bytes is not one. A short one used to be left-padded, so a platform whose
/// bignum drops a leading zero still got a token; a YubiKey 5.7.4 answers
/// INVALID_PARAMETER to 31 and to 33 bytes alike.
#[test]
fn key_agreement_coordinate_must_be_exactly_32_bytes() {
    let (mut fs, mut rng) = setup();
    let mut state = FidoState::new();
    let mut out = [0u8; 256];
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.set_pin_req(PIN),
        &mut out,
    )
    .unwrap();

    for which in [0usize, 1] {
        let (pscalar, x, y) = scalar_with_leading_zero(which);
        // Control: this very key at full width mints a token, so each refusal
        // below is the coordinate's length and not the key agreement.
        let plat = platform_from(&state, PinProto::Two, 2, &pscalar);
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_token_perms_req(PIN, PERM_MC as u64),
            &mut out,
        )
        .unwrap();

        let short = [&x[1..], &y[1..]][which];
        let padded = [&[0u8][..], [&x[..], &y[..]][which]].concat();
        for (label, coord) in [("stripped to 31", short), ("padded to 33", &padded[..])] {
            let (cx, cy) = if which == 0 {
                (coord, &y[..])
            } else {
                (&x[..], coord)
            };
            let plat = platform_from(&state, PinProto::Two, 2, &pscalar);
            let req = plat.get_token_perms_req_coords(PIN, PERM_MC as u64, cx, cy);
            assert_eq!(
                run(&mut fs, &mut rng, &mut state, &req, &mut out),
                Err(CtapError::InvalidParameter),
                "coordinate {which} {label}"
            );
        }
    }
}

// A platform keyAgreement whose `alg` is a chosen value, or omitted entirely.
fn cose_with_alg(x: &[u8; 32], y: &[u8; 32], alg: Option<i64>) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 128];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(if alg.is_some() { 5 } else { 4 }).unwrap();
        e.u8(1).unwrap().u8(2).unwrap();
        if let Some(a) = alg {
            e.u8(3).unwrap().i64(a).unwrap();
        }
        e.i8(-1).unwrap().u8(1).unwrap();
        e.i8(-2).unwrap().bytes(x).unwrap();
        e.i8(-3).unwrap().bytes(y).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// `pinHashEnc` arrives unbounded (`clientpin.rs:100`). Widened to `&&`, the length
/// guard (`clientpin.rs:254-256`) lets a short one reach the decrypt and spend a PIN
/// retry; an over-long one meets the checked `macd` copy and the same refusal.
#[test]
fn change_pin_refuses_a_pin_hash_of_the_wrong_length() {
    let mut answers = std::vec::Vec::new();
    // Four times the 16-byte hash it should carry, and none at all.
    for hash in [&[0u8; 64][..], &[]] {
        for (proto, wire) in [(PinProto::One, 1u64), (PinProto::Two, 2u64)] {
            let (mut fs, mut rng) = setup();
            let mut state = FidoState::new();
            let plat = key_agreement(&mut fs, &mut rng, &mut state, proto, wire);
            let mut out = [0u8; 256];
            run(
                &mut fs,
                &mut rng,
                &mut state,
                &plat.set_pin_req(PIN),
                &mut out,
            )
            .unwrap();

            let mut padded = [0u8; 64];
            padded[..NEW_PIN.len()].copy_from_slice(NEW_PIN);
            let npe = plat.enc(&padded);
            let phe = plat.enc(hash);
            let mut macd = npe.clone();
            macd.extend_from_slice(&phe);
            let puap = plat.mac(&macd);
            let req = build(&[
                (1, V::U(wire)),
                (2, V::U(4)),
                (3, V::Cose(&plat.x, &plat.y)),
                (4, V::B(&puap)),
                (5, V::B(&npe)),
                (6, V::B(&phe)),
            ]);
            let answer = run(&mut fs, &mut rng, &mut state, &req, &mut out);
            answers.push((wire, hash.len(), answer, ef_pin_retries(&mut fs)));
        }
    }
    // One verdict over all four, so a widened guard shows what each protocol does.
    assert!(
        answers.iter().all(|(_, _, answer, retries)| {
            *answer == Err(CtapError::InvalidParameter) && *retries == MAX_PIN_RETRIES
        }),
        "(protocol, hash bytes, answer, retries left): {answers:?}"
    );
}

/// clientPIN's own copies of the "numeric 0 means absent" sentinel. A
/// `pinUvAuthProtocol` of 0 answered MISSING_PARAMETER on every subcommand, and a
/// keyAgreement whose `alg` was 0 — or simply omitted — was refused the same way.
/// Measured on a YubiKey 5.7.4: protocol 0 is INVALID_PARAMETER, and `alg` is
/// never read (kty, crv and alg may say anything, including nothing).
#[test]
fn clientpin_protocol_zero_is_invalid_and_alg_is_not_read() {
    let (mut fs, mut rng) = setup();
    let mut state = FidoState::new();
    let mut out = [0u8; 256];

    // Every subcommand, defined or not, and the `0` sentinel with them: the
    // protocol is judged before the dispatch, as on a YubiKey 5.7.4 — measured on
    // getPINRetries, which is the one subcommand every host calls unauthenticated
    // and which used to answer SUCCESS with a protocol it does not support.
    for sub in [0u64, 1, 2, 3, 4, 5, 6, 7, 9, 0x99] {
        for proto in [0u64, 3, 255] {
            assert_eq!(
                run(
                    &mut fs,
                    &mut rng,
                    &mut state,
                    &build(&[(1, V::U(proto)), (2, V::U(sub))]),
                    &mut out
                ),
                Err(CtapError::InvalidParameter),
                "subcommand {sub} with protocol {proto}"
            );
        }
    }
    // Control: with a supported protocol those same subcommands keep their own
    // answers, so the rule above is the protocol's.
    assert!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &build(&[(1, V::U(1)), (2, V::U(1))]),
            &mut out
        )
        .is_ok(),
        "getPINRetries under a supported protocol"
    );
    for (sub, want) in [
        (0u64, CtapError::MissingParameter),
        (0x99, CtapError::InvalidSubcommand),
    ] {
        assert_eq!(
            run(
                &mut fs,
                &mut rng,
                &mut state,
                &build(&[(1, V::U(1)), (2, V::U(sub))]),
                &mut out
            ),
            Err(want),
            "subcommand {sub} under a supported protocol"
        );
    }

    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.set_pin_req(PIN),
        &mut out,
    )
    .unwrap();
    // Every `alg` the platform can put in the COSE key — including the sentinel
    // value and no key at all — still mints a token, because the ECDH is correct.
    for alg in [
        None,
        Some(0),
        Some(-7),
        Some(crate::consts::ALG_ECDH_ES_HKDF_256),
    ] {
        let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
        let h = sha256(PIN);
        let phe = plat.enc(&h[..16]);
        let cose = cose_with_alg(&plat.x, &plat.y, alg);
        let req = build(&[
            (1, V::U(2)),
            (2, V::U(9)),
            (3, V::Raw(&cose)),
            (6, V::B(&phe)),
            (9, V::U(PERM_MC as u64)),
        ]);
        run(&mut fs, &mut rng, &mut state, &req, &mut out)
            .unwrap_or_else(|e| panic!("alg {alg:?} refused with {e:?}"));
    }
}

/// What a failed PIN check does to a pinUvAuthToken already in a platform's
/// hands. Hung off this module so it inherits the Platform harness above.
#[path = "pin_token_tests.rs"]
mod pin_token_tests;

/// §6.5.5.6 step 15's implementation is the record's deletion: `EF_PAUTHTOKEN`'s
/// presence IS the grant, so after a successful changePIN the record itself must
/// be gone — not merely re-minted on the next request. Co-refutation measured
/// this as a gap: dropping `clear_ppuat` from `change_pin` broke no test, because
/// the sibling asserts the NEXT grant differs, a property the re-seal satisfies
/// through a different door. This one asserts the deletion itself.
#[test]
fn change_pin_deletes_the_persistent_grant_record() {
    use crate::consts::EF_PAUTHTOKEN;
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
    let mut out = [0u8; 256];
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.get_token_perms_req(PIN, PERM_PCMR as u64),
        &mut out,
    )
    .unwrap();
    assert!(
        fs.has_data(EF_PAUTHTOKEN.get()),
        "the pcmr issuance mints the flash grant"
    );

    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.change_pin_req(PIN, NEW_PIN),
        &mut out,
    )
    .unwrap();
    assert!(
        !fs.has_data(EF_PAUTHTOKEN.get()),
        "changePIN left the persistent grant record on flash"
    );
}

/// `Storage` whose mutating ops — `write` and `remove` both — start failing after
/// `budget` successes and never recover: a power cut inside changePIN's two-record
/// sequence. Per-file double by the tree's convention (`reset_tests::TearAfter`,
/// `credential_tests::FailWriteAfter`, `credmgmt_tests::TearMutatingAfter`).
struct TearPinFlowAfter {
    inner: RamStorage,
    budget: usize,
}

impl TearPinFlowAfter {
    fn spend(&mut self) -> rsk_sdk::error::Result<()> {
        if self.budget == 0 {
            return Err(rsk_sdk::error::Error::NoMemory);
        }
        self.budget -= 1;
        Ok(())
    }
}

impl rsk_fs::Storage for TearPinFlowAfter {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.inner.read(fid, buf)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
        self.spend()?;
        self.inner.write(fid, data)
    }
    fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
        self.spend()?;
        self.inner.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.inner.size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(f)
    }
}

/// The order inside changePIN is the property: the grant is revoked BEFORE the
/// new verifier lands, so no tear point leaves both a changed `EF_PIN` and a live
/// `EF_PAUTHTOKEN` — a grant minted under a PIN its holder no longer knows.
/// Co-refutation measured the reorder as a gap: the end state of a completed
/// changePIN is identical either way, so only a torn sequence distinguishes them,
/// and no harness tore this flow.
#[test]
fn a_torn_change_pin_never_leaves_the_grant_under_the_new_pin() {
    use crate::consts::EF_PAUTHTOKEN;
    let mut pin_before = [0u8; PIN_FILE_LEN];
    let base = {
        let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
        let mut out = [0u8; 256];
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_token_perms_req(PIN, PERM_PCMR as u64),
            &mut out,
        )
        .unwrap();
        assert!(fs.has_data(EF_PAUTHTOKEN.get()));
        assert_eq!(fs.read(EF_PIN, &mut pin_before), Some(PIN_FILE_LEN));
        fs.into_storage()
    };

    let (mut saw_torn, mut saw_landed) = (false, false);
    for budget in 0..12 {
        let mut fs = Fs::new(TearPinFlowAfter {
            inner: base.clone(),
            budget,
        });
        fs.scan();
        let mut rng = SeqRng(5);
        let mut state = FidoState::new();
        // The DH handshake writes nothing, so the platform double survives any budget.
        let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
        let mut out = [0u8; 256];
        let r = run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.change_pin_req(PIN, NEW_PIN),
            &mut out,
        );
        if r.is_err() {
            saw_torn = true;
        }
        // Power back on: same medium, fresh caches, no more failures.
        let mut medium = fs.into_storage();
        medium.budget = usize::MAX;
        let mut fs = Fs::new(medium);
        fs.scan();
        let mut pin_now = [0u8; PIN_FILE_LEN];
        // Byte 0 is the retry budget, and the old-PIN verify spends and restores
        // it — a write that lands BEFORE either record this property is about.
        // The verifier region is the rest; only store_new_pin changes it.
        let changed =
            fs.read(EF_PIN, &mut pin_now) != Some(PIN_FILE_LEN) || pin_now[1..] != pin_before[1..];
        if changed {
            saw_landed = true;
            assert!(
                !fs.has_data(EF_PAUTHTOKEN.get()),
                "budget {budget}: the new verifier landed with the old holder's \
                 grant still live"
            );
        }
    }
    assert!(saw_torn, "vacuous: no budget tore the change");
    assert!(saw_landed, "vacuous: no budget landed the new verifier");
}

/// setPIN's only guard is `has_data(EF_PIN)`, so a probe the flash could not serve
/// let an unauthenticated host install its own PIN over the owner's — the case
/// `Storage::last_error` was added for (audit run-36) and the half of it the
/// present-cache alone never closed: nothing is memoised, and the single call
/// still answers "no PIN set".
#[test]
fn a_faulted_probe_does_not_let_setpin_replace_the_owners_pin() {
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let mut state = FidoState::new();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    let mut out = [0u8; 256];
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.set_pin_req(PIN),
        &mut out,
    )
    .unwrap();
    let owner = medium
        .value(EF_PIN)
        .expect("the owner's PIN record is on the medium");

    medium.stick(Some(EF_PIN));
    let plat2 = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat2.set_pin_req(NEW_PIN),
            &mut out
        ),
        Err(CtapError::Other),
        "setPIN over a PIN it could not read must fail, not install a new one"
    );
    assert_eq!(
        medium.value(EF_PIN).as_deref(),
        Some(&owner[..]),
        "a faulted EF_PIN probe let setPIN replace the owner's PIN"
    );
}

/// `local_pin_gate` returns `true` outright when no PIN of the scope is set — the
/// hold gesture then stands alone — so a faulted probe reading as "no PIN" waived
/// every destructive on-device action. Both scopes resolve to SET now.
#[test]
fn a_faulted_pin_probe_reads_as_pin_set_for_the_local_gates() {
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    assert!(
        !pin_is_set(&mut fs),
        "control: a fresh card has no clientPIN"
    );
    assert!(!device_pin_is_set(&mut fs), "nor a device PIN");
    fs.put(EF_PIN, &[8, 4, 1]).unwrap();
    fs.put(EF_DEVICE_PIN, &[8, 4, 1]).unwrap();

    medium.stick(Some(EF_PIN));
    assert!(
        pin_is_set(&mut fs),
        "a faulted EF_PIN probe waived the display's clientPIN gate"
    );
    medium.stick(Some(EF_DEVICE_PIN));
    assert!(
        device_pin_is_set(&mut fs),
        "a faulted EF_DEVICE_PIN probe waived the display's device-PIN gate"
    );
}

/// `min_pin_length` is the floor every set-PIN path enforces against, and it read
/// `EF_MINPINLEN` with `Fs::read` — the same `None` for "no policy set" and for a
/// record the flash could not serve, collapsing to the build's `MIN_PIN_LENGTH`. One
/// faulted probe therefore stored a PIN the owner's policy forbids, and the stored
/// verifier is what every later authentication uses. Both writers are driven: the
/// panel's `store_local_pin` and the host setPIN, which reach the floor by different
/// doors.
#[test]
fn a_faulted_min_pin_probe_does_not_store_a_pin_under_the_floor() {
    // The panel's set-PIN. `PIN` is six code points — above every profile's
    // `MIN_PIN_LENGTH`, so the collapsed floor is what admits it, not the length.
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    fs.put(EF_MINPINLEN, &[16, 0]).unwrap();
    assert!(
        matches!(
            store_local_pin(&dev(), &mut fs, PIN),
            Err(SetPinError::TooShort { min: 16 })
        ),
        "control: the panel enforces the policy floor"
    );
    medium.stick_once(EF_MINPINLEN);
    let r = store_local_pin(&dev(), &mut fs, PIN);
    medium.stick(None);
    assert!(
        !pin_is_set(&mut fs),
        "a faulted floor probe stored a panel PIN of {} code points under a floor of 16",
        PIN.len()
    );
    // `Storage`, not `TooShort`: the floor is exactly what could not be read, so
    // naming a number the pad would then show would be an invention.
    assert!(
        matches!(r, Err(SetPinError::Storage)),
        "a set that could not read the floor it must enforce has to refuse, got {r:?}"
    );

    // The host setPIN reaches the same floor through `store_new_pin`.
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    fs.put(EF_MINPINLEN, &[16, 0]).unwrap();
    let mut state = FidoState::new();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    let mut out = [0u8; 256];
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.set_pin_req(PIN),
            &mut out
        ),
        Err(CtapError::PinPolicyViolation),
        "control: the host setPIN enforces the policy floor"
    );
    medium.stick_once(EF_MINPINLEN);
    let r = run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.set_pin_req(PIN),
        &mut out,
    );
    medium.stick(None);
    assert!(
        !fs.has_data(EF_PIN),
        "a faulted floor probe stored a host PIN of {} code points under a floor of 16",
        PIN.len()
    );
    assert!(r.is_err(), "the host setPIN under the floor has to refuse");
}

/// While `EF_MINPINLEN[1]` is set, a correct PIN still does not buy a
/// pinUvAuthToken — changePIN has to lift the flag first (CTAP 2.1 §6.5.5.7.1,
/// ClientPin2-GetPinToken F-5). `force_change_pending` read the flag with `Fs::read`,
/// and every caller spends its `false` to let something THROUGH, so a faulted probe
/// waived the gate and handed out the token the flag exists to withhold.
#[test]
fn a_faulted_force_change_probe_does_not_waive_the_pending_change() {
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let mut state = FidoState::new();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    let mut out = [0u8; 256];
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.set_pin_req(PIN),
        &mut out,
    )
    .unwrap();
    fs.put(EF_MINPINLEN, &[4, 1]).unwrap(); // forceChangePin pending

    // Control: the correct PIN is refused while the flag stands, and no token is
    // minted for the host.
    state.paut.permissions = 0;
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_token_req(PIN),
            &mut out
        ),
        Err(CtapError::PinInvalid),
        "control: a pending forced change withholds the token"
    );

    state.paut.permissions = 0;
    medium.stick_once(EF_MINPINLEN);
    let r = run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.get_token_req(PIN),
        &mut out,
    );
    medium.stick(None);
    assert_eq!(
        state.paut.permissions, 0,
        "a faulted probe issued a pinUvAuthToken while a forced PIN change was pending"
    );
    assert_eq!(
        r,
        Err(CtapError::PinInvalid),
        "a flag the medium could not read must not be taken for no pending change"
    );
}

/// The collapse `clear_force_change` keeps, measured rather than assumed: a faulted
/// probe there leaves `EF_MINPINLEN` exactly as it was — flag still standing, floor
/// and RP-id list untouched — and the whole cost is one more changePIN, onto a
/// THIRD value, since §6.5.5.6 refuses the current one. It is the
/// third EF_MINPINLEN read of the command (`force_change_pending`, then
/// `store_new_pin`'s floor, then this one), so `stick_after(.., 2)` is what reaches it.
///
/// The bound in both directions is the point. Nothing opens: the surviving flag is
/// the RESTRICTIVE answer, so the token stays withheld. And propagating the `Err`
/// instead would report a FAILED changePIN over a new PIN that is already stored —
/// the one outcome here that costs the owner more than a repeat.
#[test]
fn a_faulted_force_change_clear_costs_one_more_pin_change_and_nothing_else() {
    // A third distinct PIN, from the vetted vocabulary: the repeat change must land
    // on a value the pending-change rule accepts (§6.5.5.6 refuses the current one).
    const THIRD_PIN: &[u8] = DEVICE_PIN;
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let mut state = FidoState::new();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    let mut out = [0u8; 256];
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.set_pin_req(PIN),
        &mut out,
    )
    .unwrap();
    // [min, force, one RP-id hash]: the policy the absent arm would have to rebuild.
    let mut policy = [0xC7u8; 2 + 32];
    policy[0] = 4;
    policy[1] = 1;
    fs.put(EF_MINPINLEN, &policy).unwrap();
    let pin_before = medium.value(EF_PIN).expect("the verifier is on the medium");

    state.paut.permissions = 0;
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_token_req(PIN),
            &mut out
        ),
        Err(CtapError::PinInvalid),
        "control: a pending forced change withholds the token"
    );

    medium.stick_after(EF_MINPINLEN, 2);
    let r = run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.change_pin_req(PIN, NEW_PIN),
        &mut out,
    );
    medium.stick(None);
    assert_eq!(
        medium.value(EF_MINPINLEN).as_deref(),
        Some(&policy[..]),
        "a faulted probe rewrote the minPINLength policy it could not read"
    );
    assert!(
        r.is_ok(),
        "the new PIN is stored by then, so the change must not report failure"
    );
    assert_ne!(
        medium.value(EF_PIN),
        Some(pin_before),
        "and the new verifier really landed"
    );

    // Nothing opened: the flag survived, so the token is still withheld.
    state.paut.permissions = 0;
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_token_req(NEW_PIN),
            &mut out
        ),
        Err(CtapError::PinInvalid),
        "a surviving forced-change flag must still withhold the token"
    );

    // And the whole cost: ONE more changePIN clears it.
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.change_pin_req(NEW_PIN, THIRD_PIN),
        &mut out,
    )
    .unwrap();
    state.paut.permissions = 0;
    assert!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_token_req(THIRD_PIN),
            &mut out
        )
        .is_ok(),
        "one repeat change clears the flag — the cost is bounded there"
    );
    let mut after = [0u8; 2 + 32];
    let n = fs.read(EF_MINPINLEN, &mut after).unwrap();
    assert_eq!(
        (after[0], after[1], &after[2..n]),
        (4, 0, &policy[2..]),
        "and it drops the flag alone, keeping the floor and the RP-id list"
    );
}

/// `Fs::read` answers the record's FULL length, and `EF_MINPINLEN` is
/// `[min, force, hash*]` under a cap that has moved: a record written by a build
/// with a wider `MAX_MIN_PIN_RPIDS` reads back longer than this build's buffer.
/// `&buf[..n]` then panicked — on the changePIN path, AFTER `store_new_pin` has
/// committed the new PIN, so the host never sees a status word at all.
///
/// The answer asserted here is about the DATA: the stored record is untouched,
/// every RP id still in it. Clamping instead would have written it back shortened.
#[test]
fn a_min_pin_record_wider_than_this_build_is_left_whole_rather_than_truncated() {
    let mut fs = Fs::new(RamStorage::new());
    let mut oversized = [0xABu8; 2 + 32 * (MAX_MIN_PIN_RPIDS + 1)];
    oversized[0] = 6;
    oversized[1] = 1; // forceChangePin set, so the clear has work to do
    fs.put(EF_MINPINLEN, &oversized).unwrap();

    assert!(clear_force_change(&mut fs).is_ok());

    let mut back = [0u8; 2 + 32 * (MAX_MIN_PIN_RPIDS + 2)];
    let n = fs.read(EF_MINPINLEN, &mut back).unwrap();
    assert_eq!(n, oversized.len(), "the record kept every RP id it had");
    assert_eq!(&back[..n], &oversized[..], "and kept them unchanged");
}

/// A `pcmr` request whose read of the grant faults must fail rather than mint: the
/// read's `None` used to reach `ensure_ppuat` as "never minted", and the platform
/// asking was handed a new token that revoked every other platform's grant.
#[test]
fn a_faulted_grant_read_does_not_hand_out_a_new_pcmr_token() {
    let (backend, medium) = ProbeStuck::new();
    let mut fs = Fs::new(backend);
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let mut state = FidoState::new();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    let mut out = [0u8; 256];
    let pcmr = plat.get_token_perms_req(PIN, PERM_PCMR as u64);
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.set_pin_req(PIN),
        &mut out,
    )
    .unwrap();
    let n = run(&mut fs, &mut rng, &mut state, &pcmr, &mut out).unwrap();
    let ppuat = plat.decrypt_token(&out[..n]);
    let stored = medium.value(crate::consts::EF_PAUTHTOKEN.get()).unwrap();

    medium.stick_once(crate::consts::EF_PAUTHTOKEN.get());
    let r = run(&mut fs, &mut rng, &mut state, &pcmr, &mut out);
    assert_eq!(
        medium.value(crate::consts::EF_PAUTHTOKEN.get()).as_deref(),
        Some(&stored[..]),
        "a faulted read minted a new persistent token over the live one"
    );
    assert!(
        r.is_err(),
        "a grant that could not be read was answered as issued"
    );

    let n = run(&mut fs, &mut rng, &mut state, &pcmr, &mut out).unwrap();
    assert_eq!(plat.decrypt_token(&out[..n]), ppuat);
}

// The permission-domain sweep lives in its own file: it is a source obligation
// of the formal programme (PLAT-MODEL-001), not another clientPIN case, and it
// needs this module's fixture.
#[path = "clientpin_perms_tests.rs"]
mod perms;

/// setPIN, cut at every write it makes. The grant provisioning minted is revoked
/// before the new verifier lands, so no cut point leaves a PIN standing over a token
/// its holder did not set; the record that lands is whole, at a full retry budget,
/// and verifies. Two sites hold that order — `set_pin`'s own `clear_ppuat` and
/// `write_pin_verifier`'s — so this goes red only when both are reversed.
#[test]
fn a_torn_set_pin_leaves_no_pin_or_a_usable_one() {
    use crate::consts::{EF_PAUTHTOKEN, MAX_PIN_RETRIES};

    rsk_fs::cut::sweep(
        || {
            let (fs, medium, _) = setup_cut();
            (fs, medium)
        },
        |fs| {
            let mut rng = SeqRng(5);
            let mut state = FidoState::new();
            let plat = key_agreement(fs, &mut rng, &mut state, PinProto::Two, 2);
            let mut out = [0u8; 256];
            run(fs, &mut rng, &mut state, &plat.set_pin_req(PIN), &mut out).is_ok()
        },
        |fs, budget, completed, medium| {
            let mut stored = [0u8; PIN_FILE_LEN];
            let Some(len) = fs.read(EF_PIN, &mut stored) else {
                assert!(
                    !completed,
                    "budget {budget}: setPIN reported success and no PIN survived"
                );
                return;
            };
            assert_eq!(
                len,
                PIN_FILE_LEN,
                "budget {budget}: the record that landed is not a PIN record — {:?}",
                medium.ops()
            );
            assert_eq!(
                stored[0], MAX_PIN_RETRIES,
                "budget {budget}: the PIN landed with a spent retry budget"
            );
            assert!(
                !fs.has_data(EF_PAUTHTOKEN.get()),
                "budget {budget}: the new PIN landed over the grant provisioning minted — {:?}",
                medium.ops()
            );
            // Usable, not merely present: the PIN that landed is the one set.
            let mut rng = SeqRng(9);
            let mut state = FidoState::new();
            let plat = key_agreement(fs, &mut rng, &mut state, PinProto::Two, 2);
            let mut out = [0u8; 256];
            assert!(
                run(fs, &mut rng, &mut state, &plat.get_token_req(PIN), &mut out).is_ok(),
                "budget {budget}: the PIN that survived does not verify"
            );
        },
    );
}

/// A PIN record cut short cannot be verified against and must not be spent from:
/// getPinToken answers ERR_OTHER before the decrement and leaves the record as it
/// was. An empty one reads as no PIN at all, with the full budget on offer.
#[test]
fn a_pin_record_of_the_wrong_length_is_neither_verified_nor_spent() {
    let (mut fs, mut rng) = setup();
    let mut state = FidoState::new();
    let mut out = [0u8; 256];
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.set_pin_req(PIN),
        &mut out,
    )
    .unwrap();
    let mut rec = [0u8; PIN_FILE_LEN];
    assert_eq!(fs.read(EF_PIN, &mut rec), Some(PIN_FILE_LEN));

    fs.put(EF_PIN, &rec[..PIN_FILE_LEN - 1]).unwrap();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_token_req(PIN),
            &mut out
        ),
        Err(CtapError::Other)
    );
    let mut after = [0u8; PIN_FILE_LEN];
    assert_eq!(
        fs.read(EF_PIN, &mut after),
        Some(PIN_FILE_LEN - 1),
        "the short record was rewritten"
    );
    assert_eq!(after[..PIN_FILE_LEN - 1], rec[..PIN_FILE_LEN - 1]);

    fs.put(EF_PIN, &[]).unwrap();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_token_req(PIN),
            &mut out
        ),
        Err(CtapError::PinNotSet)
    );
    let n = run(
        &mut fs,
        &mut rng,
        &mut state,
        &build(&[(1, V::U(2)), (2, V::U(1))]),
        &mut out,
    )
    .unwrap();
    let mut d = Decoder::new(&out[..n]);
    d.map().unwrap();
    assert_eq!(d.u8().unwrap(), 3);
    assert_eq!(
        d.u8().unwrap(),
        MAX_PIN_RETRIES,
        "an empty record read as a spent budget"
    );
}

/// The whole retry budget, spent by wrong PINs across the replugs the mismatch
/// limit forces: the eighth answers PIN_BLOCKED, and from then on so does the right
/// PIN. Every other test stopped at a third mismatch, so this lockout never ran.
#[test]
fn the_last_wrong_pin_locks_the_pin_for_good() {
    let (mut fs, mut rng) = setup();
    let mut state = FidoState::new();
    let mut out = [0u8; 256];
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.set_pin_req(PIN),
        &mut out,
    )
    .unwrap();
    for n in 1..=MAX_PIN_RETRIES {
        let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
        let got = run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_token_req(WRONG_PIN),
            &mut out,
        );
        let want = if n == MAX_PIN_RETRIES {
            CtapError::PinBlocked
        } else if n % PIN_MISMATCH_LIMIT == 0 {
            CtapError::PinAuthBlocked
        } else {
            CtapError::PinInvalid
        };
        assert_eq!(got, Err(want), "wrong PIN {n} of {MAX_PIN_RETRIES}");
        if state.needs_power_cycle {
            // A replug: the RAM state goes, the flash counter stays.
            state = FidoState::new();
        }
    }
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_token_req(PIN),
            &mut out
        ),
        Err(CtapError::PinBlocked),
        "the right PIN got through a spent budget"
    );
}

/// A present-but-empty `EF_MINPINLEN` sets no policy, so setPIN measures the new PIN
/// against the build's `MIN_PIN_LENGTH` — not against the zero an unread byte of the
/// buffer holds, under which a PIN of any length is stored.
#[test]
fn an_empty_min_pin_record_leaves_the_build_floor_in_force() {
    let (mut fs, mut rng) = setup();
    fs.put(EF_MINPINLEN, &[]).unwrap();
    let mut state = FidoState::new();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    let mut out = [0u8; 256];
    let short = &PIN[..usize::from(MIN_PIN_LENGTH) - 1];
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.set_pin_req(short),
            &mut out
        ),
        Err(CtapError::PinPolicyViolation),
        "a PIN under the build floor was stored over an empty policy record"
    );
    assert!(!fs.has_data(EF_PIN));
}

/// `spend_and_verify_pin_hash` refuses a spent budget itself instead of trusting the
/// gate in front of it, which every command path runs first — so it is driven
/// directly. Past it, the decrement wraps the counter to 255 in a release build.
#[test]
fn a_spent_budget_is_refused_before_the_decrement() {
    let (mut fs, mut rng, mut state, _plat) = setup_with_pin(PIN);
    let mut rec = [0u8; PIN_FILE_LEN];
    assert_eq!(fs.read(EF_PIN, &mut rec), Some(PIN_FILE_LEN));
    rec[0] = 0;
    fs.put(EF_PIN, &rec).unwrap();
    let pin_hash = sha256(PIN);
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
    };
    assert_eq!(
        spend_and_verify_pin_hash(&mut ctx, &pin_hash[..16]),
        Err(CtapError::PinBlocked)
    );
    assert_eq!(ef_pin_retries(&mut fs), 0, "a spent counter was rewritten");
}

/// The pad's verify reads the same record, and a record of the wrong length is as
/// unusable there: Blocked, with nothing spent and nothing rewritten.
#[test]
fn a_local_verify_over_a_short_pin_record_is_blocked_and_spends_nothing() {
    let (mut fs, _rng, _state, _plat) = setup_with_pin(PIN);
    let mut rec = [0u8; PIN_FILE_LEN];
    assert_eq!(fs.read(EF_PIN, &mut rec), Some(PIN_FILE_LEN));
    fs.put(EF_PIN, &rec[..PIN_FILE_LEN - 1]).unwrap();
    assert!(matches!(
        spend_and_verify_local_pin(&dev(), &mut fs, PIN),
        LocalPin::Blocked
    ));
    let mut after = [0u8; PIN_FILE_LEN];
    assert_eq!(
        fs.read(EF_PIN, &mut after),
        Some(PIN_FILE_LEN - 1),
        "the short record was rewritten"
    );
    assert_eq!(after[..PIN_FILE_LEN - 1], rec[..PIN_FILE_LEN - 1]);
}

/// On an OTP-keyed device — every fused card — a wrong PIN also meets the pre-OTP
/// fallback, and the fallback must fail it too. No test sent one before, so a
/// fallback that matched anything was green on both paths.
#[test]
fn a_wrong_pin_on_an_otp_keyed_device_is_wrong_on_both_paths() {
    const OTP_KEY: [u8; 32] = [0x7B; 32];
    fn otp_dev() -> Device<'static> {
        Device {
            otp_key: Some(&OTP_KEY),
            ..dev()
        }
    }

    // The verifier is the pre-OTP one, so the fallback really compares.
    let (mut fs, mut rng, mut state, _plat) = setup_with_pin(PIN);
    let mut before = [0u8; PIN_FILE_LEN];
    assert_eq!(fs.read(EF_PIN, &mut before), Some(PIN_FILE_LEN));
    let wrong = sha256(WRONG_PIN);
    {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: otp_dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        assert_eq!(
            spend_and_verify_pin_hash(&mut ctx, &wrong[..16]),
            Err(CtapError::PinInvalid),
            "the host path let a wrong PIN through the pre-OTP fallback"
        );
    }
    match spend_and_verify_local_pin(&otp_dev(), &mut fs, WRONG_PIN) {
        LocalPin::Wrong { retries_left } => assert_eq!(retries_left, MAX_PIN_RETRIES - 2),
        _ => panic!("the pad let a wrong PIN through the pre-OTP fallback"),
    }
    let mut after = [0u8; PIN_FILE_LEN];
    assert_eq!(fs.read(EF_PIN, &mut after), Some(PIN_FILE_LEN));
    assert_eq!(after[1..], before[1..], "a wrong PIN re-keyed the verifier");
}

/// A verify that re-keys a pre-OTP verifier re-arms the at-rest lap first, and a
/// medium that will not drop the marker turns the verify away on both paths: the
/// chip-serial verifier stays the record in force, not superseded under a latch.
#[test]
fn a_refused_re_arm_turns_a_migrating_verify_away() {
    use rsk_fs::storage::faults::RemoveStuck;
    const OTP_KEY: [u8; 32] = [0x7C; 32];
    fn otp_dev() -> Device<'static> {
        Device {
            otp_key: Some(&OTP_KEY),
            ..dev()
        }
    }

    let (backend, medium) = RemoveStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let mut padded = [0u8; PADDED_PIN_LEN];
    padded[..PIN.len()].copy_from_slice(PIN);
    let mut state = FidoState::new();
    {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        store_new_pin(&mut ctx, &padded).unwrap();
    }
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    medium.refuse(Some(rsk_fs::EF_HARDENED));
    let mut before = [0u8; PIN_FILE_LEN];
    assert_eq!(fs.read(EF_PIN, &mut before), Some(PIN_FILE_LEN));

    let pin_hash = sha256(PIN);
    {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: otp_dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        assert_eq!(
            spend_and_verify_pin_hash(&mut ctx, &pin_hash[..16]),
            Err(CtapError::Other)
        );
    }
    assert!(matches!(
        spend_and_verify_local_pin(&otp_dev(), &mut fs, PIN),
        LocalPin::Blocked
    ));
    let mut after = [0u8; PIN_FILE_LEN];
    assert_eq!(fs.read(EF_PIN, &mut after), Some(PIN_FILE_LEN));
    assert_eq!(
        after[1..],
        before[1..],
        "the verifier was re-keyed with the at-rest lap still latched"
    );
}

/// A PIN that fills the whole 64-byte block leaves no terminating zero, so it is past
/// maxPINLength's 63 and refused as policy (CTAP 2.1 §6.5.5.5), with nothing stored.
#[test]
fn a_pin_filling_the_padded_block_is_policy_violation() {
    let (mut fs, mut rng) = setup();
    let mut state = FidoState::new();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    let mut out = [0u8; 256];
    let whole = [b'7'; PADDED_PIN_LEN];
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.set_pin_req(&whole),
            &mut out
        ),
        Err(CtapError::PinPolicyViolation)
    );
    assert!(!fs.has_data(EF_PIN));
}

/// The device PIN's bounds are the build's own — `MIN_PIN_LENGTH` and the
/// host-representable `MAX_PIN_LENGTH`, no host policy — and a PIN outside them is
/// refused with nothing stored.
#[test]
fn store_device_pin_enforces_its_length_bounds() {
    let (mut fs, _rng) = setup();
    match store_device_pin(&dev(), &mut fs, &PIN[..usize::from(MIN_PIN_LENGTH) - 1]) {
        Err(SetPinError::TooShort { min }) => assert_eq!(min, MIN_PIN_LENGTH),
        other => panic!("expected TooShort, got {other:?}"),
    }
    match store_device_pin(&dev(), &mut fs, &[b'5'; MAX_PIN_LENGTH + 1]) {
        Err(SetPinError::TooLong { max }) => assert_eq!(max as usize, MAX_PIN_LENGTH),
        other => panic!("expected TooLong, got {other:?}"),
    }
    assert!(!fs.has_data(EF_DEVICE_PIN));
}

/// The pad's verify reads its decrement back before trusting it, as the host's does
/// (`pin_verify_fails_closed_when_the_retry_write_does_not_persist`): a counter write
/// the medium reports and does not keep turns even the right PIN away.
#[test]
fn a_local_verify_fails_closed_when_the_retry_write_does_not_persist() {
    use std::cell::Cell;
    use std::rc::Rc;

    struct StaleEfPin {
        inner: RamStorage,
        drop_ef_pin_writes: Rc<Cell<bool>>,
    }
    impl Storage for StaleEfPin {
        fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
            self.inner.read(fid, buf)
        }
        fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
            if fid == EF_PIN && self.drop_ef_pin_writes.get() {
                return Ok(()); // reports success, persists nothing
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

    let drop_writes = Rc::new(Cell::new(false));
    let mut fs = Fs::new(StaleEfPin {
        inner: RamStorage::new(),
        drop_ef_pin_writes: drop_writes.clone(),
    });
    ensure_seed(&dev(), &mut fs, &mut SeqRng(1)).unwrap();
    store_local_pin(&dev(), &mut fs, PIN).unwrap();
    assert!(
        matches!(
            spend_and_verify_local_pin(&dev(), &mut fs, PIN),
            LocalPin::Ok
        ),
        "control: the right PIN verifies on a medium that keeps its writes"
    );
    drop_writes.set(true);
    assert!(
        matches!(
            spend_and_verify_local_pin(&dev(), &mut fs, PIN),
            LocalPin::Blocked
        ),
        "the pad trusted a retry counter it could not read back"
    );
}

/// Built-in UV shares clientPIN's budget and its per-boot mismatch lockout, and
/// refuses while either stands (UV_BLOCKED, §6.5.5.7.3) before a consent card or a
/// PIN entry: past the lockout the pad would take guesses a boot no longer allows.
#[test]
fn builtin_uv_is_blocked_by_the_power_cycle_lockout_or_a_spent_budget() {
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
    state.needs_power_cycle = true; // what three wrong PINs in one boot leave
    let mut out = [0u8; 256];
    let mut pad = UvPad::typing(PIN);
    assert_eq!(
        run_with(
            &mut pad,
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_uv_token_req(PERM_GA as u64),
            &mut out,
        ),
        Err(CtapError::UvBlocked),
        "the pad took the PIN past the per-boot lockout"
    );
    assert!(
        pad.titles.is_empty(),
        "a locked-out UV painted a consent card"
    );

    let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
    let mut rec = [0u8; PIN_FILE_LEN];
    assert_eq!(fs.read(EF_PIN, &mut rec), Some(PIN_FILE_LEN));
    rec[0] = 0;
    fs.put(EF_PIN, &rec).unwrap();
    let mut pad = UvPad::typing(PIN);
    assert_eq!(
        run_with(
            &mut pad,
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_uv_token_req(PERM_GA as u64),
            &mut out,
        ),
        Err(CtapError::UvBlocked)
    );
    assert!(pad.titles.is_empty(), "a blocked UV painted a consent card");
}

/// A pending forced PIN change holds the built-in-UV token back as it holds the
/// host-PIN one: the pad verifies, and no token is issued until changePIN.
#[test]
fn builtin_uv_token_waits_for_a_forced_pin_change() {
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
    fs.put(EF_MINPINLEN, &[MIN_PIN_LENGTH, 1]).unwrap();
    let before = state.paut.token;
    let mut out = [0u8; 256];
    let mut pad = UvPad::typing(PIN);
    assert_eq!(
        run_with(
            &mut pad,
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_uv_token_req(PERM_GA as u64),
            &mut out,
        ),
        Err(CtapError::PinPolicyViolation),
        "a UV token was issued over a pending forced change"
    );
    assert_eq!(
        state.paut.token, before,
        "the refused request minted a token"
    );
}

/// Three wrong PINs in a boot lock clientPIN until a power cycle, and the lock is
/// read before the PIN is: even the right one is turned away, with no retry spent,
/// on getPinToken and changePIN alike. The lockout test stops at the third wrong
/// PIN, so neither check had been reached; without them the budget goes in one boot.
#[test]
fn the_power_cycle_lockout_turns_the_right_pin_away() {
    let (mut fs, mut rng, mut state, _plat) = setup_with_pin(PIN);
    state.needs_power_cycle = true; // what three wrong PINs in one boot leave
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    let mut out = [0u8; 256];
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_token_req(PIN),
            &mut out
        ),
        Err(CtapError::PinAuthBlocked),
        "getPinToken took a PIN past the per-boot lockout"
    );
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.change_pin_req(PIN, NEW_PIN),
            &mut out
        ),
        Err(CtapError::PinAuthBlocked),
        "changePIN took a PIN past the per-boot lockout"
    );
    assert_eq!(
        ef_pin_retries(&mut fs),
        MAX_PIN_RETRIES,
        "a locked-out attempt spent a retry"
    );
}

/// changePIN's pinUvAuthParam covers `newPinEnc ‖ pinHashEnc` (CTAP 2.1 §6.5.5.6), and
/// a MAC that does not verify is refused before the old PIN is tried: no retry is
/// spent and the PIN stands. setPIN's twin had a test; this one had none.
#[test]
fn change_pin_with_a_bad_pin_auth_param_changes_nothing() {
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(PIN);
    let mut before = [0u8; PIN_FILE_LEN];
    assert_eq!(fs.read(EF_PIN, &mut before), Some(PIN_FILE_LEN));
    let mut padded = [0u8; PADDED_PIN_LEN];
    padded[..NEW_PIN.len()].copy_from_slice(NEW_PIN);
    let npe = plat.enc(&padded);
    let old = sha256(PIN);
    let phe = plat.enc(&old[..16]);
    let bad_mac = [0u8; 32];
    let req = build(&[
        (1, V::U(plat.wire)),
        (2, V::U(4)),
        (3, V::Cose(&plat.x, &plat.y)),
        (4, V::B(&bad_mac[..plat.proto.mac_len()])),
        (5, V::B(&npe)),
        (6, V::B(&phe)),
    ]);
    let mut out = [0u8; 256];
    assert_eq!(
        run(&mut fs, &mut rng, &mut state, &req, &mut out),
        Err(CtapError::PinAuthInvalid),
        "a changePIN whose MAC does not verify was acted on"
    );
    let mut after = [0u8; PIN_FILE_LEN];
    assert_eq!(fs.read(EF_PIN, &mut after), Some(PIN_FILE_LEN));
    assert_eq!(after, before, "a refused changePIN touched the PIN record");
}

// The read-fault sweep lives in its own file; it needs this module's fixtures.
#[path = "clientpin_reads_tests.rs"]
mod reads;
