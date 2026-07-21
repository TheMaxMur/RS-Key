// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::FidoState;
use crate::consts::EF_KEY_DEV;
use crate::seed::{ensure_seed, load_keydev};
use rsk_crypto::Device;
use rsk_crypto::pinproto::public_xy;
use rsk_fs::Fs;
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

fn run(
    fs: &mut Fs<RamStorage>,
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
/// entry to exercise the decline / timeout / cancel branches.
struct UvPad {
    digits: std::vec::Vec<u8>,
    outcome: Option<PinEntry>,
}
impl UvPad {
    fn typing(pin: &[u8]) -> Self {
        Self {
            digits: pin.to_vec(),
            outcome: None,
        }
    }
    fn ending(outcome: PinEntry) -> Self {
        Self {
            digits: std::vec::Vec::new(),
            outcome: Some(outcome),
        }
    }
}
impl crate::UserPresence for UvPad {
    fn request(&mut self, _c: crate::Confirm<'_>) -> crate::Presence {
        crate::Presence::Confirmed
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

fn key_agreement(
    fs: &mut Fs<RamStorage>,
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
        let h = sha256(pin);
        let phe = self.enc(&h[..16]);
        build(&[
            (1, V::U(self.wire)),
            (2, V::U(9)),
            (3, V::Cose(&self.x, &self.y)),
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
        &plat.set_pin_req(b"1234"),
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
        &plat.get_token_req(b"1234"),
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
    let (mut fs, _rng, _state, _plat) = setup_with_pin(b"1234");
    assert!(matches!(
        spend_and_verify_local_pin(&dev(), &mut fs, b"1234"),
        LocalPin::Ok
    ));
    assert_eq!(ef_pin_retries(&mut fs), MAX_PIN_RETRIES);
    match spend_and_verify_local_pin(&dev(), &mut fs, b"9999") {
        LocalPin::Wrong { retries_left } => assert_eq!(retries_left, MAX_PIN_RETRIES - 1),
        _ => panic!("expected Wrong"),
    }
    assert_eq!(ef_pin_retries(&mut fs), MAX_PIN_RETRIES - 1);
    // A later correct PIN restores the full budget.
    assert!(matches!(
        spend_and_verify_local_pin(&dev(), &mut fs, b"1234"),
        LocalPin::Ok
    ));
    assert_eq!(ef_pin_retries(&mut fs), MAX_PIN_RETRIES);
}

/// The persistent gate hard-blocks once the budget is spent, and never
/// underflows past zero — even a correct PIN can't recover after the lock.
#[test]
fn local_pin_blocks_at_zero() {
    let (mut fs, _rng, _state, _plat) = setup_with_pin(b"1234");
    for _ in 0..MAX_PIN_RETRIES - 1 {
        assert!(matches!(
            spend_and_verify_local_pin(&dev(), &mut fs, b"0000"),
            LocalPin::Wrong { .. }
        ));
    }
    assert!(matches!(
        spend_and_verify_local_pin(&dev(), &mut fs, b"0000"),
        LocalPin::Blocked
    ));
    assert_eq!(ef_pin_retries(&mut fs), 0);
    assert!(matches!(
        spend_and_verify_local_pin(&dev(), &mut fs, b"1234"),
        LocalPin::Blocked
    ));
}

/// `pin_is_set` tracks EF_PIN; with no PIN a local verify is Blocked (the
/// caller is expected to gate on `pin_is_set` first).
#[test]
fn local_pin_is_set_and_unset() {
    let (mut fs, _rng, _state, _plat) = setup_with_pin(b"1234");
    assert!(pin_is_set(&mut fs));
    let (mut bare, _rng2) = setup();
    assert!(!pin_is_set(&mut bare));
    assert!(matches!(
        spend_and_verify_local_pin(&dev(), &mut bare, b"1234"),
        LocalPin::Blocked
    ));
}

/// `pin_retries_left` reports the live budget for the unlock pad's "N tries
/// remaining" line — without spending a try — and is `None` when no PIN is set.
#[test]
fn pin_retries_left_reads_the_budget_without_spending_it() {
    let (mut bare, _rng) = setup();
    assert_eq!(pin_retries_left(&mut bare), None);
    let (mut fs, _rng2, _state, _plat) = setup_with_pin(b"1234");
    assert_eq!(pin_retries_left(&mut fs), Some(MAX_PIN_RETRIES));
    // A read does not decrement; the counter only moves on a real verify.
    assert_eq!(pin_retries_left(&mut fs), Some(MAX_PIN_RETRIES));
    assert!(matches!(
        spend_and_verify_local_pin(&dev(), &mut fs, b"9999"),
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
        spend_and_verify_device_pin(&dev(), &mut fs, b"1234"),
        LocalPin::Blocked
    ));
    // Set the device PIN: it is set, the FIDO clientPIN stays unset.
    store_device_pin(&dev(), &mut fs, b"4321").unwrap();
    assert!(device_pin_is_set(&mut fs));
    assert!(
        !pin_is_set(&mut fs),
        "device PIN must not set the FIDO clientPIN"
    );
    // Correct device PIN verifies; a wrong one spends only its own counter.
    assert!(matches!(
        spend_and_verify_device_pin(&dev(), &mut fs, b"4321"),
        LocalPin::Ok
    ));
    assert!(matches!(
        spend_and_verify_device_pin(&dev(), &mut fs, b"0000"),
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
        spend_and_verify_device_pin(&dev(), &mut fs, b"4321"),
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
    let (mut fs, _rng, _state, _plat) = setup_with_pin(b"1234");
    assert!(matches!(
        spend_and_verify_local_pin(&dev(), &mut fs, b"9999"),
        LocalPin::Wrong { .. }
    ));
    assert_eq!(ef_pin_retries(&mut fs), MAX_PIN_RETRIES - 1);
    store_local_pin(&dev(), &mut fs, b"4711").unwrap();
    assert_eq!(ef_pin_retries(&mut fs), MAX_PIN_RETRIES);
    assert!(matches!(
        spend_and_verify_local_pin(&dev(), &mut fs, b"1234"),
        LocalPin::Wrong { .. }
    ));
    assert!(matches!(
        spend_and_verify_local_pin(&dev(), &mut fs, b"4711"),
        LocalPin::Ok
    ));
}

/// Built-in UV: with a PIN set host-side, obtain a pinUvAuthToken via the
/// on-device pad (subCommand 6) — the PIN never crosses the wire. The minted
/// token carries the requested permissions and counts as user-verified.
#[test]
fn builtin_uv_token_success() {
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(b"1234");
    let mut out = [0u8; 256];
    let mut pad = UvPad::typing(b"1234");
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

/// A wrong on-screen PIN is reported as UV_INVALID (the built-in-UV dialect of
/// PIN_INVALID) and spends one of the shared retries.
#[test]
fn builtin_uv_wrong_pin_is_uv_invalid_and_burns_a_retry() {
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(b"1234");
    let mut out = [0u8; 256];
    let mut pad = UvPad::typing(b"9999");
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

/// Tapping Cancel on the pad is a deliberate decline (OPERATION_DENIED) and,
/// unlike a wrong PIN, never spends a retry.
#[test]
fn builtin_uv_decline_denies_without_burning_a_retry() {
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(b"1234");
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
/// answer UnsupportedOption — exactly as a standard key does.
#[test]
fn builtin_uv_subcommands_unsupported_without_a_pad() {
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(b"1234");
    let mut out = [0u8; 256];
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_uv_token_req(PERM_GA as u64),
            &mut out,
        ),
        Err(CtapError::UnsupportedOption)
    );
    let uv_retries = build(&[(1, V::U(plat.wire)), (2, V::U(7))]);
    assert_eq!(
        run(&mut fs, &mut rng, &mut state, &uv_retries, &mut out),
        Err(CtapError::UnsupportedOption)
    );
}

/// getUVRetries (0x07) reports the shared budget that getPINRetries does, under
/// response key 0x05.
#[test]
fn get_uv_retries_mirrors_pin_retries() {
    let (mut fs, mut rng, mut state, plat) = setup_with_pin(b"1234");
    let mut out = [0u8; 256];
    // Burn one retry with a wrong on-screen PIN.
    let mut pad = UvPad::typing(b"0000");
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
    // Four code points sit under the profile's floor…
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
        &plat.set_pin_req(b"1234"),
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
            &plat.get_token_req(b"1234"),
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
        &plat.change_pin_req(b"1234", b"123456"),
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
        &plat.get_token_req(b"123456"),
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
        &plat.set_pin_req(b"1234"),
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
            &plat.get_token_perms_req(b"1234", PERM_MC as u64),
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
        &plat.set_pin_req(b"1234"),
        &mut out,
    )
    .unwrap();
    // Setting a PIN leaves the seed loadable with no session, so a
    // power-cycled UP-only assertion keeps working.
    assert_eq!(load_keydev(&dev(), &mut fs), Some(seed0));

    // A legacy PIN-wrapped blob is unreadable (the UP-only failure window)…
    let pin_hash = sha256(b"1234");
    crate::seed::wrap_keydev_legacy(&dev(), &mut fs, &seed0, &pin_hash[..16]);
    assert_eq!(load_keydev(&dev(), &mut fs), None);

    // …until the first successful PIN op of any boot migrates it back.
    let mut state2 = FidoState::new();
    let plat2 = key_agreement(&mut fs, &mut rng, &mut state2, PinProto::Two, 2);
    let n = run(
        &mut fs,
        &mut rng,
        &mut state2,
        &plat2.get_token_req(b"1234"),
        &mut out,
    )
    .unwrap();
    let _ = plat2.decrypt_token(&out[..n]);
    assert_eq!(load_keydev(&dev(), &mut fs), Some(seed0));
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
        &plat.set_pin_req(b"1234"),
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
                &plat.get_token_req(b"9999"),
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
            &plat.get_token_req(b"9999"),
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
fn change_pin_then_new_pin_works_and_old_fails() {
    let (mut fs, mut rng) = setup();
    let mut state = FidoState::new();
    let plat = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
    let mut out = [0u8; 256];
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.set_pin_req(b"1234"),
        &mut out,
    )
    .unwrap();

    // changePIN replies with only the status byte.
    let n = run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.change_pin_req(b"1234", b"5678"),
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
            &plat.get_token_req(b"5678"),
            &mut out
        )
        .is_ok()
    );
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.get_token_req(b"1234"),
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
    // A valid set, then a second set is NotAllowed.
    run(
        &mut fs,
        &mut rng,
        &mut state,
        &plat.set_pin_req(b"1234"),
        &mut out,
    )
    .unwrap();
    assert_eq!(
        run(
            &mut fs,
            &mut rng,
            &mut state,
            &plat.set_pin_req(b"4321"),
            &mut out
        ),
        Err(CtapError::NotAllowed)
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
    padded[..4].copy_from_slice(b"1234");
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
    let (mut fs, mut rng) = setup();
    let seed0 = load_keydev(&dev(), &mut fs).unwrap();
    let mut padded = [0u8; PADDED_PIN_LEN];
    padded[..4].copy_from_slice(b"9246");
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
    let pin_hash = sha256(b"9246");
    crate::seed::wrap_keydev_legacy(&dev(), &mut fs, &seed0, &pin_hash[..16]);
    let mut raw = [0u8; 61];
    assert_eq!(fs.read(EF_KEY_DEV.get(), &mut raw), Some(61));
    assert_eq!(raw[0], 0x03);

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
    spend_and_verify_pin_hash(&mut ctx, &pin_hash[..16]).unwrap();
    let mut pin_rec = [0u8; PIN_FILE_LEN];
    ctx.fs.read(EF_PIN, &mut pin_rec).unwrap();
    assert_eq!(pin_rec[0], MAX_PIN_RETRIES);
    assert_eq!(ctx.fs.read(EF_KEY_DEV.get(), &mut raw), Some(61));
    assert_eq!(raw[0], 0x12);
    assert_eq!(load_keydev(&otp_dev(), ctx.fs), Some(seed0));

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
    padded[..4].copy_from_slice(b"1234");
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

    let pin_hash = sha256(b"1234");

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
