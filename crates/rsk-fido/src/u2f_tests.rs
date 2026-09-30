// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::consts::EF_ALWAYS_UV;
use crate::seed::ensure_seed;
use crate::test_pins::{PIN, WRONG_PIN};
use p256::Sec1Point;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use rsk_crypto::Device;
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
        latched: false,
    }
}

const APP: [u8; 32] = [0x5A; 32];
const CHAL: [u8; 32] = [0xC4; 32];

fn ext_apdu(ins: u8, p1: u8, data: &[u8]) -> std::vec::Vec<u8> {
    let mut v = std::vec![
        0x00,
        ins,
        p1,
        0x00,
        0x00,
        (data.len() >> 8) as u8,
        data.len() as u8
    ];
    v.extend_from_slice(data);
    v.extend_from_slice(&[0x00, 0x00]); // extended Le
    v
}

fn vkey(x: &[u8], y: &[u8]) -> VerifyingKey {
    let pt = Sec1Point::from_bytes(&crate::ec::sec1_uncompressed(x, y)).unwrap();
    VerifyingKey::from_sec1_point(&pt).unwrap()
}

struct Fixed(crate::Presence);
impl crate::UserPresence for Fixed {
    fn request(&mut self, _confirm: crate::Confirm<'_>) -> crate::Presence {
        self.0
    }
}

/// Presence mock that counts how many times a touch was requested — lets a
/// test prove a path returns *without* prompting the user.
struct CountingPresence {
    verdict: crate::Presence,
    calls: usize,
}
impl crate::UserPresence for CountingPresence {
    fn request(&mut self, _confirm: crate::Confirm<'_>) -> crate::Presence {
        self.calls += 1;
        self.verdict
    }
}

#[test]
fn register_without_touch_is_refused() {
    let mut fs = Fs::new(RamStorage::new());
    crate::tests::uv_optional(&mut fs);
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let mut data = std::vec::Vec::new();
    data.extend_from_slice(&CHAL);
    data.extend_from_slice(&APP);
    let reg_bytes = ext_apdu(CTAP_REGISTER, 0, &data);
    let reg_apdu = Apdu::parse(&reg_bytes).unwrap();
    let mut out = [0u8; 1024];
    let (sw, n) = {
        let mut state = crate::FidoState::new();
        let mut presence = Fixed(crate::Presence::Timeout);
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        process_u2f(&mut ctx, &reg_apdu, &mut out)
    };
    assert_eq!(sw, Sw::CONDITIONS_NOT_SATISFIED);
    assert_eq!(n, 0);
}

#[test]
fn u2f_disabled_when_always_uv() {
    // CTAP 2.1 §7.2.4: with alwaysUv on, the CTAP1/U2F interface is disabled —
    // register and authenticate are refused even with a willing touch
    // (AlwaysConfirm), so U2F cannot bypass the always-require-UV guarantee the
    // CTAP2 side enforces.
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    fs.put(EF_ALWAYS_UV, &[1]).unwrap();

    let mut reg_data = std::vec::Vec::new();
    reg_data.extend_from_slice(&CHAL);
    reg_data.extend_from_slice(&APP);
    let reg_bytes = ext_apdu(CTAP_REGISTER, 0, &reg_data);
    let reg = Apdu::parse(&reg_bytes).unwrap();

    let mut auth_data = std::vec::Vec::new();
    auth_data.extend_from_slice(&CHAL);
    auth_data.extend_from_slice(&APP);
    auth_data.push(64);
    auth_data.extend_from_slice(&[0u8; 64]);
    let auth_bytes = ext_apdu(CTAP_AUTHENTICATE, U2F_AUTH_ENFORCE, &auth_data);
    let auth = Apdu::parse(&auth_bytes).unwrap();

    let mut state = crate::FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
    };
    let mut out = [0u8; 1024];
    // §7.2.4 names the code: "MUST immediately fail and return
    // SW_COMMAND_NOT_ALLOWED". SW_CONDITIONS_NOT_SATISFIED would read as
    // "touch me again" and leave the client retrying a disabled interface.
    assert_eq!(
        process_u2f(&mut ctx, &reg, &mut out).0,
        Sw::COMMAND_NOT_ALLOWED,
        "U2F register must be refused under alwaysUv"
    );
    assert_eq!(
        process_u2f(&mut ctx, &auth, &mut out).0,
        Sw::COMMAND_NOT_ALLOWED,
        "U2F authenticate must be refused under alwaysUv"
    );
}

/// A trusted-display backend: it has a screen, a configured PIN pad, and types
/// `digits` on it. Counts the touches asked for on top of the PIN entry.
struct UvPad {
    digits: &'static [u8],
    touches: usize,
}
impl crate::UserPresence for UvPad {
    fn request(&mut self, _c: crate::Confirm<'_>) -> crate::Presence {
        self.touches += 1;
        crate::Presence::Confirmed
    }
    fn shows_confirm(&self) -> bool {
        true
    }
    fn uv_available(&self) -> bool {
        true
    }
    fn collect_pin(&mut self, _min: usize, out: &mut [u8]) -> crate::PinEntry {
        out[..self.digits.len()].copy_from_slice(self.digits);
        crate::PinEntry::Entered(self.digits.len())
    }
}

/// §7.2.4 disables CTAP1/U2F under alwaysUv "unless the CTAP1/U2F authenticator is
/// protected by a built-in user verification method". With a configured PIN pad that
/// exception applies: register and authenticate keep working, but every one of them
/// runs the pad — the PIN, not a bare touch, is what authorizes them. A wrong PIN
/// refuses the operation. The pad replaces the *touch*, not the *screen*: a backend
/// that paints `Confirm` still names the operation first, so "Register key?" and
/// "Sign in?" stay distinguishable instead of collapsing into one unlabelled PIN
/// prompt (audit run-28).
#[test]
fn u2f_survives_always_uv_behind_builtin_uv() {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    crate::clientpin::store_local_pin(&dev(), &mut fs, PIN).unwrap();
    fs.put(EF_ALWAYS_UV, &[1]).unwrap();

    let mut reg_data = std::vec::Vec::new();
    reg_data.extend_from_slice(&CHAL);
    reg_data.extend_from_slice(&APP);
    let reg_bytes = ext_apdu(CTAP_REGISTER, 0, &reg_data);
    let reg = Apdu::parse(&reg_bytes).unwrap();

    let mut out = [0u8; 1024];
    let mut pad = UvPad {
        digits: PIN,
        touches: 0,
    };
    let (sw, n) = {
        let mut state = crate::FidoState::new();
        let mut ctx = Ctx {
            presence: &mut pad,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        process_u2f(&mut ctx, &reg, &mut out)
    };
    assert_eq!(sw, Sw::OK, "U2F stays alive behind a configured PIN pad");
    assert!(n > 64);
    assert_eq!(
        pad.touches, 1,
        "one naming card, then the pad — not a second bare touch"
    );

    // The registered handle then authenticates through the same pad…
    let key_handle = out[67..67 + KEY_HANDLE_LEN].to_vec();
    let mut auth_data = std::vec::Vec::new();
    auth_data.extend_from_slice(&CHAL);
    auth_data.extend_from_slice(&APP);
    auth_data.push(KEY_HANDLE_LEN as u8);
    auth_data.extend_from_slice(&key_handle);
    let auth_bytes = ext_apdu(CTAP_AUTHENTICATE, U2F_AUTH_ENFORCE, &auth_data);
    let auth = Apdu::parse(&auth_bytes).unwrap();
    let sw = {
        let mut state = crate::FidoState::new();
        let mut ctx = Ctx {
            presence: &mut pad,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        process_u2f(&mut ctx, &auth, &mut out).0
    };
    assert_eq!(sw, Sw::OK);
    assert_eq!(pad.touches, 2, "authenticate names its operation too");

    // …and a wrong PIN refuses it.
    let mut wrong = UvPad {
        digits: WRONG_PIN,
        touches: 0,
    };
    let sw = {
        let mut state = crate::FidoState::new();
        let mut ctx = Ctx {
            presence: &mut wrong,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        process_u2f(&mut ctx, &auth, &mut out).0
    };
    assert_eq!(sw, Sw::CONDITIONS_NOT_SATISFIED);
}

/// The exception is about a *configured* method, not a capability: a display build
/// with no PIN yet has nothing to verify against, so U2F is disabled as anywhere else.
#[test]
fn u2f_disabled_under_always_uv_when_the_pad_has_no_pin() {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    fs.put(EF_ALWAYS_UV, &[1]).unwrap();

    let mut reg_data = std::vec::Vec::new();
    reg_data.extend_from_slice(&CHAL);
    reg_data.extend_from_slice(&APP);
    let reg_bytes = ext_apdu(CTAP_REGISTER, 0, &reg_data);
    let reg = Apdu::parse(&reg_bytes).unwrap();
    let mut out = [0u8; 1024];
    let mut pad = UvPad {
        digits: PIN,
        touches: 0,
    };
    let mut state = crate::FidoState::new();
    let mut ctx = Ctx {
        presence: &mut pad,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
    };
    assert_eq!(
        process_u2f(&mut ctx, &reg, &mut out).0,
        Sw::COMMAND_NOT_ALLOWED
    );
}

/// Don't-enforce-user-presence (P1 = 0x08) may skip the touch, but not the built-in
/// UV that keeps the interface reachable under alwaysUv — otherwise it would hand
/// back exactly the un-verified signature §7.2.4 exists to prevent. A `strict-up`
/// build has no don't-enforce to begin with, so it refuses the control byte.
#[test]
fn u2f_dont_enforce_still_runs_builtin_uv() {
    let mut fs = Fs::new(RamStorage::new());
    crate::tests::uv_optional(&mut fs);
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    crate::clientpin::store_local_pin(&dev(), &mut fs, PIN).unwrap();

    // Register first (alwaysUv still off, so this is a plain touch).
    let mut reg_data = std::vec::Vec::new();
    reg_data.extend_from_slice(&CHAL);
    reg_data.extend_from_slice(&APP);
    let reg_bytes = ext_apdu(CTAP_REGISTER, 0, &reg_data);
    let reg = Apdu::parse(&reg_bytes).unwrap();
    let mut out = [0u8; 1024];
    let n = {
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        let (sw, n) = process_u2f(&mut ctx, &reg, &mut out);
        assert_eq!(sw, Sw::OK);
        n
    };
    assert!(n > 64);
    let key_handle = out[67..67 + KEY_HANDLE_LEN].to_vec();

    fs.put(EF_ALWAYS_UV, &[1]).unwrap();
    let mut auth_data = std::vec::Vec::new();
    auth_data.extend_from_slice(&CHAL);
    auth_data.extend_from_slice(&APP);
    auth_data.push(KEY_HANDLE_LEN as u8);
    auth_data.extend_from_slice(&key_handle);
    let auth_bytes = ext_apdu(CTAP_AUTHENTICATE, U2F_AUTH_NO_ENFORCE, &auth_data);
    let auth = Apdu::parse(&auth_bytes).unwrap();
    let mut wrong = UvPad {
        digits: WRONG_PIN,
        touches: 0,
    };
    let mut state = crate::FidoState::new();
    let mut ctx = Ctx {
        presence: &mut wrong,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
    };
    // `strict-up` does not accept don't-enforce at all (see `authenticate_p1_matrix`),
    // so it refuses the control byte before any UV runs. Either way the request
    // cannot reach a signature without verification.
    let want = if cfg!(feature = "strict-up") {
        Sw::INCORRECT_P1P2
    } else {
        Sw::CONDITIONS_NOT_SATISFIED
    };
    assert_eq!(
        process_u2f(&mut ctx, &auth, &mut out).0,
        want,
        "don't-enforce cannot opt out of the built-in UV"
    );
}

#[test]
fn register_then_authenticate() {
    let mut fs = Fs::new(RamStorage::new());
    crate::tests::uv_optional(&mut fs);
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();

    // --- register ---
    let mut data = std::vec::Vec::new();
    data.extend_from_slice(&CHAL); // U2F register request: challenge then application
    data.extend_from_slice(&APP);
    let reg_bytes = ext_apdu(CTAP_REGISTER, 0, &data);
    let reg_apdu = Apdu::parse(&reg_bytes).unwrap();
    let mut out = [0u8; 1024];
    let (sw, n) = {
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        process_u2f(&mut ctx, &reg_apdu, &mut out)
    };
    assert_eq!(sw, Sw::OK);
    let resp = &out[..n];
    assert_eq!(resp[0], U2F_REGISTER_ID);
    assert_eq!(resp[1], 0x04);
    let pub_x = &resp[2..34];
    let pub_y = &resp[34..66];
    assert_eq!(resp[66] as usize, KEY_HANDLE_LEN);
    let key_handle = resp[67..67 + KEY_HANDLE_LEN].to_vec();
    let cert_and_sig = &resp[67 + KEY_HANDLE_LEN..];
    // The cert is a SEQUENCE; the registration signature follows it.
    assert_eq!(cert_and_sig[0], 0x30);
    let cert_len = 4 + (((cert_and_sig[2] as usize) << 8) | cert_and_sig[3] as usize);
    let reg_sig = &cert_and_sig[cert_len..];

    // Verify the registration signature under the device (attestation) key.
    let mut seed = crate::seed::load_keydev(&dev(), &mut fs).unwrap();
    let device_key = P256Key::from_scalar(seed.expose()).unwrap();
    seed.wipe();
    let (dx, dy) = device_key.public_xy();
    let mut base = std::vec![0x00u8];
    base.extend_from_slice(&APP);
    base.extend_from_slice(&CHAL);
    base.extend_from_slice(&key_handle);
    base.push(0x04);
    base.extend_from_slice(pub_x);
    base.extend_from_slice(pub_y);
    vkey(&dx, &dy)
        .verify(&base, &Signature::from_der(reg_sig).unwrap())
        .expect("registration signature verifies under the attestation key");

    // --- authenticate ---
    let mut ad = std::vec::Vec::new();
    ad.extend_from_slice(&CHAL);
    ad.extend_from_slice(&APP);
    ad.push(KEY_HANDLE_LEN as u8);
    ad.extend_from_slice(&key_handle);
    let auth_bytes = ext_apdu(CTAP_AUTHENTICATE, U2F_AUTH_ENFORCE, &ad);
    let auth_apdu = Apdu::parse(&auth_bytes).unwrap();
    let mut out2 = [0u8; 256];
    let (sw, n) = {
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        process_u2f(&mut ctx, &auth_apdu, &mut out2)
    };
    assert_eq!(sw, Sw::OK);
    let a = &out2[..n];
    assert_eq!(a[0] & U2F_AUTH_FLAG_TUP, U2F_AUTH_FLAG_TUP);
    let ctr = u32::from_be_bytes([a[1], a[2], a[3], a[4]]);
    let auth_sig = &a[5..];

    // The assertion signs appId ‖ flags ‖ counter ‖ chal under the credential key.
    let mut sbase = std::vec::Vec::new();
    sbase.extend_from_slice(&APP);
    sbase.push(a[0]);
    sbase.extend_from_slice(&ctr.to_be_bytes());
    sbase.extend_from_slice(&CHAL);
    vkey(pub_x, pub_y)
        .verify(&sbase, &Signature::from_der(auth_sig).unwrap())
        .expect("authentication signature verifies under the credential key");
}

#[test]
fn check_only_and_bad_handle() {
    let mut fs = Fs::new(RamStorage::new());
    crate::tests::uv_optional(&mut fs);
    let mut rng = SeqRng(2);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();

    // Register to get a valid handle.
    let mut data = std::vec::Vec::new();
    data.extend_from_slice(&CHAL); // U2F register request: challenge then application
    data.extend_from_slice(&APP);
    let mut out = [0u8; 1024];
    let reg_bytes = ext_apdu(CTAP_REGISTER, 0, &data);
    let kh = {
        let reg = Apdu::parse(&reg_bytes).unwrap();
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        let (_, _n) = process_u2f(&mut ctx, &reg, &mut out);
        out[67..67 + KEY_HANDLE_LEN].to_vec()
    };

    // check-only on a valid handle → CONDITIONS_NOT_SATISFIED.
    let mut ad = std::vec::Vec::new();
    ad.extend_from_slice(&CHAL);
    ad.extend_from_slice(&APP);
    ad.push(KEY_HANDLE_LEN as u8);
    ad.extend_from_slice(&kh);
    let mut o = [0u8; 256];
    let chk_bytes = ext_apdu(CTAP_AUTHENTICATE, U2F_AUTH_CHECK_ONLY, &ad);
    let chk = Apdu::parse(&chk_bytes).unwrap();
    let mut state = crate::FidoState::new();
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
        process_u2f(&mut ctx, &chk, &mut o).0,
        Sw::CONDITIONS_NOT_SATISFIED
    );

    // A bogus handle (wrong tag) → WRONG_DATA.
    let mut bad = ad.clone();
    let l = bad.len();
    bad[l - 1] ^= 0xFF; // corrupt the handle's HMAC tag
    let bad_bytes = ext_apdu(CTAP_AUTHENTICATE, U2F_AUTH_ENFORCE, &bad);
    let badc = Apdu::parse(&bad_bytes).unwrap();
    assert_eq!(process_u2f(&mut ctx, &badc, &mut o).0, Sw::WRONG_DATA);
}

#[test]
fn enforce_auth_rejects_unknown_handle_without_touch() {
    // U2F conformance (U2F-Authenticate F-2): an unknown handle MUST be
    // rejected with WRONG_DATA (0x6A80) *before* any user-presence prompt.
    // With a presence that never confirms, the old order (touch first) returned
    // CONDITIONS_NOT_SATISFIED (0x6985) after a timed-out touch and streamed
    // keepalives that desynced the host. The handle check must win, and the
    // touch must not even be requested.
    let mut fs = Fs::new(RamStorage::new());
    crate::tests::uv_optional(&mut fs);
    let mut rng = SeqRng(7);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();

    let mut ad = std::vec::Vec::new();
    ad.extend_from_slice(&CHAL);
    ad.extend_from_slice(&APP);
    ad.push(KEY_HANDLE_LEN as u8);
    ad.extend_from_slice(&[0xEE; KEY_HANDLE_LEN]); // garbage handle — not ours
    let bytes = ext_apdu(CTAP_AUTHENTICATE, U2F_AUTH_ENFORCE, &ad);
    let apdu = Apdu::parse(&bytes).unwrap();
    let mut o = [0u8; 256];

    let mut state = crate::FidoState::new();
    let mut presence = CountingPresence {
        verdict: crate::Presence::Timeout,
        calls: 0,
    };
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
    };
    let (sw, n) = process_u2f(&mut ctx, &apdu, &mut o);
    assert_eq!(sw, Sw::WRONG_DATA); // 0x6A80, not 0x6985
    assert_eq!(n, 0);
    assert_eq!(
        presence.calls, 0,
        "an unknown handle must be rejected without requesting a touch"
    );
}

#[test]
fn authenticate_p1_matrix() {
    // U2F Raw Message Formats §7.2 assigns 0x03 / 0x07 / 0x08 and nothing else. A
    // reserved control byte used to skip the touch, clear the TUP flag and sign
    // anyway — a silent signing oracle; it must be INCORRECT_P1P2 instead.
    let mut fs = Fs::new(RamStorage::new());
    crate::tests::uv_optional(&mut fs);
    let mut rng = SeqRng(11);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();

    let mut data = std::vec::Vec::new();
    data.extend_from_slice(&CHAL);
    data.extend_from_slice(&APP);
    let reg_bytes = ext_apdu(CTAP_REGISTER, 0, &data);
    let mut out = [0u8; 1024];
    let kh = {
        let reg = Apdu::parse(&reg_bytes).unwrap();
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        assert_eq!(process_u2f(&mut ctx, &reg, &mut out).0, Sw::OK);
        out[67..67 + KEY_HANDLE_LEN].to_vec()
    };
    let mut ad = std::vec::Vec::new();
    ad.extend_from_slice(&CHAL);
    ad.extend_from_slice(&APP);
    ad.push(KEY_HANDLE_LEN as u8);
    ad.extend_from_slice(&kh);

    // `strict-up` promises a touch on every assertion, so don't-enforce is not an
    // accepted control byte there — `want_up` (getassertion.rs) only covers CTAP2.
    let no_enforce = if cfg!(feature = "strict-up") {
        (U2F_AUTH_NO_ENFORCE, Sw::INCORRECT_P1P2, false, false)
    } else {
        (U2F_AUTH_NO_ENFORCE, Sw::OK, true, false)
    };
    // (P1, status word, produces a signature, demands a touch)
    let cases = [
        (0x00, Sw::INCORRECT_P1P2, false, false),
        (0x01, Sw::INCORRECT_P1P2, false, false),
        (0x02, Sw::INCORRECT_P1P2, false, false),
        (U2F_AUTH_ENFORCE, Sw::OK, true, true),
        (0x04, Sw::INCORRECT_P1P2, false, false),
        (
            U2F_AUTH_CHECK_ONLY,
            Sw::CONDITIONS_NOT_SATISFIED,
            false,
            false,
        ),
        no_enforce,
        (0x42, Sw::INCORRECT_P1P2, false, false),
        (0xFF, Sw::INCORRECT_P1P2, false, false),
    ];

    for (p1, want_sw, signs, touches) in cases {
        let bytes = ext_apdu(CTAP_AUTHENTICATE, p1, &ad);
        let apdu = Apdu::parse(&bytes).unwrap();
        let mut o = [0u8; 256];
        let mut state = crate::FidoState::new();
        let mut presence = CountingPresence {
            verdict: crate::Presence::Confirmed,
            calls: 0,
        };
        let (sw, n) = {
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 0,
            };
            process_u2f(&mut ctx, &apdu, &mut o)
        };
        assert_eq!(sw, want_sw, "P1 {p1:#04x} status word");
        assert_eq!(n > 0, signs, "P1 {p1:#04x} signature");
        assert_eq!(presence.calls, usize::from(touches), "P1 {p1:#04x} touch");
        if signs {
            // The TUP flag must report the touch that actually happened.
            assert_eq!(
                o[0] & U2F_AUTH_FLAG_TUP != 0,
                touches,
                "P1 {p1:#04x} TUP flag"
            );
        }
    }
}

#[test]
fn version() {
    let mut fs = Fs::new(RamStorage::new());
    crate::tests::uv_optional(&mut fs);
    let mut rng = SeqRng(3);
    let ver = Apdu::parse(&[0x00, CTAP_VERSION, 0x00, 0x00]).unwrap();
    let mut o = [0u8; 16];
    let mut state = crate::FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
    };
    let (sw, n) = process_u2f(&mut ctx, &ver, &mut o);
    assert_eq!(sw, Sw::OK);
    assert_eq!(&o[..n], b"U2F_V2");
}

#[test]
fn bad_cla_and_ins() {
    let mut fs = Fs::new(RamStorage::new());
    crate::tests::uv_optional(&mut fs);
    let mut rng = SeqRng(9);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let mut state = crate::FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
    };
    let mut o = [0u8; 64];
    // Non-zero CLA → 0x6E00 CLA_NOT_SUPPORTED.
    let bad_cla = Apdu::parse(&[0x01, CTAP_VERSION, 0x00, 0x00]).unwrap();
    assert_eq!(
        process_u2f(&mut ctx, &bad_cla, &mut o).0,
        Sw::CLA_NOT_SUPPORTED
    );
    // Unknown INS (CLA 0) → 0x6D00 INS_NOT_SUPPORTED.
    let bad_ins = Apdu::parse(&[0x00, 0x00, 0x00, 0x00]).unwrap();
    assert_eq!(
        process_u2f(&mut ctx, &bad_ins, &mut o).0,
        Sw::INS_NOT_SUPPORTED
    );
}

/// Don't-enforce AUTHENTICATE signs with no gesture at all on the default build, so an
/// unbudgeted journal entry per call let a host holding one key handle evict the whole
/// 128-slot audit window (audit run-37). A run of them now costs one entry; an enforced
/// authenticate still earns its own.
#[cfg(not(feature = "strict-up"))]
#[test]
fn no_enforce_authenticate_cannot_flush_the_audit_journal() {
    let mut fs = Fs::new(RamStorage::new());
    crate::tests::uv_optional(&mut fs);
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let mut out = [0u8; 1024];
    let mut state = crate::FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
    };

    let mut reg_data = std::vec::Vec::new();
    reg_data.extend_from_slice(&CHAL);
    reg_data.extend_from_slice(&APP);
    let reg_bytes = ext_apdu(CTAP_REGISTER, 0, &reg_data);
    let reg = Apdu::parse(&reg_bytes).unwrap();
    let (sw, n) = process_u2f(&mut ctx, &reg, &mut out);
    assert_eq!(sw, Sw::OK);
    assert!(n > 64);
    let key_handle = out[67..67 + KEY_HANDLE_LEN].to_vec();

    let mut auth_data = std::vec::Vec::new();
    auth_data.extend_from_slice(&CHAL);
    auth_data.extend_from_slice(&APP);
    auth_data.push(KEY_HANDLE_LEN as u8);
    auth_data.extend_from_slice(&key_handle);
    let silent_bytes = ext_apdu(CTAP_AUTHENTICATE, U2F_AUTH_NO_ENFORCE, &auth_data);
    let silent = Apdu::parse(&silent_bytes).unwrap();
    let touched_bytes = ext_apdu(CTAP_AUTHENTICATE, U2F_AUTH_ENFORCE, &auth_data);
    let touched = Apdu::parse(&touched_bytes).unwrap();

    // Journalling starts after the registration, so the window is exactly the flood.
    crate::journal::set_enabled(ctx.fs, true).unwrap();
    crate::journal::append(&mut ctx, crate::journal::EV_PIN_LOCKOUT, 0, &[]);
    for _ in 0..crate::consts::AUDIT_RING_SLOTS + 2 {
        assert_eq!(process_u2f(&mut ctx, &silent, &mut out).0, Sw::OK);
    }
    assert_eq!(process_u2f(&mut ctx, &touched, &mut out).0, Sw::OK);

    let (_, m) = crate::journal::chain_head(&dev(), &mut fs).unwrap();
    assert_eq!(m.start, 0, "nothing evicted from the window");
    // BOOT, PIN_LOCKOUT, the coalesced silent run, the touched authenticate.
    assert_eq!(m.seq_next, 4);
}

/// U2F AUTHENTICATE signs the GLOBAL counter, so the same collapse the CTAP2
/// per-credential counters carry lands here as a signed one: a probe the flash
/// could not serve read as counter 0, and the bump then wrote 1 over the live
/// value. The RP is told this key has never been used.
#[test]
fn a_faulted_counter_probe_does_not_sign_a_fabricated_u2f_counter() {
    use crate::consts::EF_COUNTER;
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    crate::tests::uv_optional(&mut fs);
    fs.scan();
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();

    let mut data = std::vec::Vec::new();
    data.extend_from_slice(&CHAL);
    data.extend_from_slice(&APP);
    let reg_bytes = ext_apdu(CTAP_REGISTER, 0, &data);
    let reg_apdu = Apdu::parse(&reg_bytes).unwrap();
    let mut out = [0u8; 1024];
    let authenticate = |fs: &mut Fs<rsk_fs::storage::faults::ProbeStuck>,
                        rng: &mut SeqRng,
                        apdu: &Apdu,
                        out: &mut [u8]| {
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs,
            rng,
            state: &mut state,
            now_ms: 0,
        };
        process_u2f(&mut ctx, apdu, out)
    };
    let (sw, _) = authenticate(&mut fs, &mut rng, &reg_apdu, &mut out);
    assert_eq!(sw, Sw::OK);
    let key_handle = out[67..67 + KEY_HANDLE_LEN].to_vec();

    // Off a first boot's zero, so a roll-back shows in the reported counter too.
    fs.put_counter(EF_COUNTER, &500u32.to_le_bytes()).unwrap();
    let before = medium.value(EF_COUNTER.get()).expect("on the medium");

    let mut ad = std::vec::Vec::new();
    ad.extend_from_slice(&CHAL);
    ad.extend_from_slice(&APP);
    ad.push(KEY_HANDLE_LEN as u8);
    ad.extend_from_slice(&key_handle);
    let auth_bytes = ext_apdu(CTAP_AUTHENTICATE, U2F_AUTH_ENFORCE, &ad);
    let auth_apdu = Apdu::parse(&auth_bytes).unwrap();
    let mut out2 = [0u8; 256];
    medium.stick(Some(EF_COUNTER.get()));
    let (sw, n) = authenticate(&mut fs, &mut rng, &auth_apdu, &mut out2);
    medium.stick(None);
    assert_eq!(
        medium.value(EF_COUNTER.get()).as_deref(),
        Some(&before[..]),
        "a faulted probe rolled the U2F signature counter back"
    );
    assert_eq!(n, 0, "and returned a body built on a counter it never read");
    assert_eq!(
        sw,
        Sw::MEMORY_FAILURE,
        "an AUTHENTICATE that could not read its counter must refuse"
    );

    // The recovered device keeps counting from the live value.
    let (sw, _) = authenticate(&mut fs, &mut rng, &auth_apdu, &mut out2);
    assert_eq!(sw, Sw::OK);
    assert_eq!(
        u32::from_be_bytes([out2[1], out2[2], out2[3], out2[4]]),
        500
    );
}

/// The write half of the same counter. A bump the flash refuses must stop the
/// signature: otherwise the next AUTHENTICATE signs the same counter again, and a
/// counter that does not increase is what a cloned key looks like to the RP.
#[test]
fn a_refused_counter_advance_signs_nothing() {
    use crate::consts::EF_COUNTER;
    let (backend, medium) = rsk_fs::storage::faults::Cut::new();
    let mut fs = Fs::new(backend);
    crate::tests::uv_optional(&mut fs);
    fs.scan();
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();

    let authenticate = |fs: &mut Fs<rsk_fs::storage::faults::Cut>,
                        rng: &mut SeqRng,
                        apdu: &Apdu,
                        out: &mut [u8]| {
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs,
            rng,
            state: &mut state,
            now_ms: 0,
        };
        process_u2f(&mut ctx, apdu, out)
    };
    let mut data = std::vec::Vec::new();
    data.extend_from_slice(&CHAL);
    data.extend_from_slice(&APP);
    let reg_apdu_bytes = ext_apdu(CTAP_REGISTER, 0, &data);
    let mut out = [0u8; 1024];
    let (sw, _) = authenticate(
        &mut fs,
        &mut rng,
        &Apdu::parse(&reg_apdu_bytes).unwrap(),
        &mut out,
    );
    assert_eq!(sw, Sw::OK);
    let mut ad = std::vec::Vec::new();
    ad.extend_from_slice(&CHAL);
    ad.extend_from_slice(&APP);
    ad.push(KEY_HANDLE_LEN as u8);
    ad.extend_from_slice(&out[67..67 + KEY_HANDLE_LEN]);
    let auth_bytes = ext_apdu(CTAP_AUTHENTICATE, U2F_AUTH_ENFORCE, &ad);
    let auth_apdu = Apdu::parse(&auth_bytes).unwrap();
    fs.put_counter(EF_COUNTER, &500u32.to_le_bytes()).unwrap();

    // Each answer as the RP sees it: the status, and the counter a body carried.
    let mut signed = |fs: &mut Fs<rsk_fs::storage::faults::Cut>| {
        let mut out = [0u8; 256];
        let (sw, n) = authenticate(fs, &mut rng, &auth_apdu, &mut out);
        (
            sw,
            (n > 0).then(|| u32::from_be_bytes([out[1], out[2], out[3], out[4]])),
        )
    };
    medium.arm(0);
    let refused = signed(&mut fs);
    medium.arm(u32::MAX);
    let answers = [refused, signed(&mut fs), signed(&mut fs)];

    assert_eq!(
        answers,
        [
            (Sw::MEMORY_FAILURE, None),
            (Sw::OK, Some(500)),
            (Sw::OK, Some(501))
        ],
        "a refused advance must sign nothing, and the counter must not repeat"
    );
}

// A U2F REGISTER's touch is not the CTAP2 user-presence test CTAP 2.1 §6.5.5.7
// spends a pinUvAuthToken on: a live one survives it.
#[test]
fn a_u2f_register_touch_leaves_a_live_token_unspent() {
    let mut fs = Fs::new(RamStorage::new());
    crate::tests::uv_optional(&mut fs);
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let mut data = std::vec::Vec::new();
    data.extend_from_slice(&CHAL);
    data.extend_from_slice(&APP);
    let reg_bytes = ext_apdu(CTAP_REGISTER, 0, &data);
    let reg_apdu = Apdu::parse(&reg_bytes).unwrap();
    let mut out = [0u8; 1024];
    let mut state = crate::FidoState::new();
    let armed = crate::state::PERM_MC | crate::state::PERM_GA | crate::state::PERM_ACFG;
    state.paut.permissions = armed;
    state.begin_using_token(false, 0);
    let (sw, _) = {
        let mut presence = Fixed(crate::Presence::Confirmed);
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        process_u2f(&mut ctx, &reg_apdu, &mut out)
    };
    assert_eq!(sw, Sw::OK);
    assert_eq!(state.paut.permissions, armed);
    assert!(state.user_verified());
}

/// U2F HID frames every request in extended-length encoding, and a YubiKey 5.8.0
/// holds CTAPHID_MSG to it: these are the cells measured there, with what it answered.
#[test]
fn a_hid_request_takes_the_extended_encoding_alone() {
    let reads = |raw: &[u8]| hid_apdu(raw).map(|a| (a.ins, a.data.to_vec()));
    // A bare header, and `00 Lc Lc` with that many data bytes; what follows is ignored.
    assert_eq!(reads(&[0x00, 0x03, 0x00, 0x00]), Ok((0x03, vec![])));
    assert_eq!(
        reads(&[0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00]),
        Ok((0x03, vec![]))
    );
    let data = [0x00, 0x02, 0x07, 0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB];
    for tail in [&[][..], &[0x00, 0x00], &[0x01], &[0x00, 0x00, 0x00]] {
        let raw = [&data[..], tail].concat();
        assert_eq!(
            reads(&raw),
            Ok((0x02, vec![0xAA, 0xBB])),
            "tail {tail:02X?}"
        );
    }
    // Every short form is a wrong length, and so is an extended one with its data cut.
    for raw in [
        &[0x00, 0x03, 0x00, 0x00, 0x00][..],
        &[0x00, 0x03, 0x00, 0x00, 0x06],
        &[0x00, 0x03, 0x00, 0x00, 0x01, 0x00],
        &[0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x06],
        &[0x00, 0x03, 0x00, 0x00, 0x00, 0x01],
        &[0x00, 0x02, 0x07, 0x00, 0x00, 0x00, 0x03, 0xAA, 0xBB],
        &[0x00, 0x03, 0x00],
    ] {
        assert_eq!(reads(raw), Err(Sw::WRONG_LENGTH), "{raw:02X?}");
    }
    // The class is judged before the lengths.
    assert_eq!(
        reads(&[0x80, 0x03, 0x00, 0x00, 0x00]),
        Err(Sw::CLA_NOT_SUPPORTED)
    );
}

/// U2F Raw Message Formats §6.1: VERSION "takes no data as input". A YubiKey 5.8.0
/// refuses one that carries some `6700` over CTAPHID and CCID alike, and ignores P1.
#[test]
fn a_version_with_data_is_a_wrong_length() {
    let mut fs = Fs::new(RamStorage::new());
    crate::tests::uv_optional(&mut fs);
    let mut rng = SeqRng(3);
    let mut state = crate::FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
    };
    let mut o = [0u8; 16];
    for raw in [
        &[0x00, CTAP_VERSION, 0x00, 0x00, 0x01, 0x00][..],
        &ext_apdu(CTAP_VERSION, 0x00, &[0x00]),
    ] {
        let apdu = Apdu::parse(raw).unwrap();
        assert_eq!(
            process_u2f(&mut ctx, &apdu, &mut o),
            (Sw::WRONG_LENGTH, 0),
            "{raw:02X?}"
        );
    }
    let flagged = Apdu::parse(&[0x00, CTAP_VERSION, 0x01, 0x00]).unwrap();
    let (sw, n) = process_u2f(&mut ctx, &flagged, &mut o);
    assert_eq!(
        (sw, &o[..n]),
        (Sw::OK, &b"U2F_V2"[..]),
        "a P1 is not judged"
    );
}

/// getInfo's `versions` (0x01), read over the real dispatch.
fn get_info_versions(ctx: &mut Ctx<RamStorage, SeqRng>) -> std::vec::Vec<std::string::String> {
    let mut out = [0u8; 1024];
    let n = crate::process_cbor(ctx, &[crate::consts::CTAP_GET_INFO], &mut out);
    assert_eq!(out[0], 0, "getInfo refused");
    let mut d = minicbor::Decoder::new(&out[1..n]);
    d.map().unwrap();
    assert_eq!(d.u8().unwrap(), 0x01, "versions leads the map");
    let count = d.array().unwrap().unwrap();
    (0..count).map(|_| d.str().unwrap().into()).collect()
}

/// Every door that says whether U2F is served — VERSION, the SELECT body, getInfo's
/// `U2F_V2` — in §7.2.4's states: off under alwaysUv, `6986` and `FIDO_2_0` as on a YubiKey
/// 5.8.0 (measured 2026-09-30), unless a pad with a PIN keeps it on; all three agree.
#[test]
fn every_u2f_door_answers_from_one_gate() {
    let version = Apdu::parse(&[0x00, CTAP_VERSION, 0x00, 0x00]).unwrap();
    for (what, always_uv, pad, pin, served) in [
        ("alwaysUv off", false, false, false, true),
        ("alwaysUv on, no pad", true, false, false, false),
        ("alwaysUv on, a pad with no PIN", true, true, false, false),
        ("alwaysUv on, a pad with a PIN", true, true, true, true),
        ("alwaysUv off, a pad with a PIN", false, true, true, true),
    ] {
        let mut fs = Fs::new(RamStorage::new());
        crate::tests::uv_optional(&mut fs);
        let mut rng = SeqRng(1);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        if pin {
            crate::clientpin::store_local_pin(&dev(), &mut fs, PIN).unwrap();
        }
        fs.put(EF_ALWAYS_UV, &[u8::from(always_uv)]).unwrap();
        let mut plain = crate::AlwaysConfirm;
        let mut uv_pad = UvPad {
            digits: PIN,
            touches: 0,
        };
        let presence: &mut dyn crate::UserPresence = if pad { &mut uv_pad } else { &mut plain };
        let selected = select_version(&mut fs, presence);
        let mut state = crate::FidoState::new();
        let mut ctx = Ctx {
            presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        let mut out = [0u8; 16];
        let (sw, n) = process_u2f(&mut ctx, &version, &mut out);
        let listed = get_info_versions(&mut ctx).iter().any(|v| v == "U2F_V2");
        let text = |b: &[u8]| std::string::String::from_utf8_lossy(b).into_owned();
        let want = if served {
            (Sw::OK, "U2F_V2".into(), "U2F_V2".into(), true)
        } else {
            (Sw::COMMAND_NOT_ALLOWED, "".into(), "FIDO_2_0".into(), false)
        };
        assert_eq!(
            (sw, text(&out[..n]), text(selected), listed),
            want,
            "{what}: (VERSION, its body, the SELECT body, U2F_V2 in getInfo)"
        );
    }
}

/// The certificate a REGISTER response carries after the key handle: one DER
/// SEQUENCE, however long its length field.
fn registered_cert(resp: &[u8]) -> std::vec::Vec<u8> {
    let cert = &resp[1 + 65 + 1 + KEY_HANDLE_LEN..];
    let (head, body) = match cert[1] {
        0x81 => (3, usize::from(cert[2])),
        0x82 => (4, usize::from(u16::from_be_bytes([cert[2], cert[3]]))),
        n => (2, usize::from(n)),
    };
    cert[..head + body].to_vec()
}

/// An org attestation key the flash could not read is not an absent one: REGISTER
/// answers the `MEMORY_FAILURE` a counter fault answers, which the host retries,
/// rather than swap the org batch attestation for the device's own for good. One
/// stored but not openable here, and none at all, still take the device's.
#[test]
fn an_org_key_the_flash_would_not_read_fails_the_registration() {
    use crate::consts::EF_ATT_KEY;
    let mut leaf = [0u8; 64];
    let n = crate::cert::att_chain_pack(&[0x30u8, 0x03, 1, 2, 3], &mut leaf).unwrap();
    let elsewhere = Device {
        serial_hash: &[0xBA; 32],
        ..dev()
    };
    let register = |sealed_by: Option<&Device>, fault: bool| {
        let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
        let mut fs = Fs::new(backend);
        crate::tests::uv_optional(&mut fs);
        fs.scan();
        let mut rng = SeqRng(1);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        if let Some(by) = sealed_by {
            crate::seed::store_att_key(by, &mut fs, &[0x21u8; 32]).unwrap();
            fs.put(EF_ATT_CHAIN, &leaf[..n]).unwrap();
        }
        let mut ee = [0u8; 1024];
        let ee_len = fs.read(EF_EE_DEV, &mut ee).unwrap();
        medium.stick(fault.then_some(EF_ATT_KEY.get()));
        let reg_bytes = ext_apdu(CTAP_REGISTER, 0, &[CHAL, APP].concat());
        let mut out = [0u8; 1024];
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        let (sw, len) = process_u2f(&mut ctx, &Apdu::parse(&reg_bytes).unwrap(), &mut out);
        let cert = (sw == Sw::OK).then(|| registered_cert(&out[..len]));
        (sw, len, cert, ee[..ee_len].to_vec())
    };
    let (sw, _, cert, _) = register(Some(&dev()), false);
    assert_eq!(
        (sw, cert),
        (Sw::OK, Some(leaf[3..n].to_vec())),
        "control: the org chain's leaf"
    );
    let (sw, len, _, _) = register(Some(&dev()), true);
    assert_eq!((sw, len), (Sw::MEMORY_FAILURE, 0), "a faulted org key read");
    for (what, sealed_by) in [("sealed elsewhere", Some(&elsewhere)), ("absent", None)] {
        let (sw, _, cert, device) = register(sealed_by, false);
        assert_eq!(
            (sw, cert),
            (Sw::OK, Some(device)),
            "{what}: the device's cert"
        );
    }
}
