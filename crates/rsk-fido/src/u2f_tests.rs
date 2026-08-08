// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::consts::EF_ALWAYS_UV;
use crate::seed::ensure_seed;
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
    crate::clientpin::store_local_pin(&dev(), &mut fs, b"1234").unwrap();
    fs.put(EF_ALWAYS_UV, &[1]).unwrap();

    let mut reg_data = std::vec::Vec::new();
    reg_data.extend_from_slice(&CHAL);
    reg_data.extend_from_slice(&APP);
    let reg_bytes = ext_apdu(CTAP_REGISTER, 0, &reg_data);
    let reg = Apdu::parse(&reg_bytes).unwrap();

    let mut out = [0u8; 1024];
    let mut pad = UvPad {
        digits: b"1234",
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
        digits: b"9999",
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
        digits: b"1234",
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
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    crate::clientpin::store_local_pin(&dev(), &mut fs, b"1234").unwrap();

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
        digits: b"9999",
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
    let device_key = P256Key::from_scalar(&seed).unwrap();
    seed.zeroize();
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

    // A bogus handle (wrong tag) → INCORRECT_PARAMS.
    let mut bad = ad.clone();
    let l = bad.len();
    bad[l - 1] ^= 0xFF; // corrupt the handle's HMAC tag
    let bad_bytes = ext_apdu(CTAP_AUTHENTICATE, U2F_AUTH_ENFORCE, &bad);
    let badc = Apdu::parse(&bad_bytes).unwrap();
    assert_eq!(process_u2f(&mut ctx, &badc, &mut o).0, Sw::INCORRECT_PARAMS);
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
    assert_eq!(sw, Sw::INCORRECT_PARAMS); // 0x6A80 WRONG_DATA, not 0x6985
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

    let (_, m) = crate::journal::chain_head(&dev(), &mut fs);
    assert_eq!(m.start, 0, "nothing evicted from the window");
    // BOOT, PIN_LOCKOUT, the coalesced silent run, the touched authenticate.
    assert_eq!(m.seq_next, 4);
}
