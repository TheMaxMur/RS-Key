// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::consts::{ALG_ES256, EF_ALWAYS_UV};
use crate::makecredential::make_credential;
use crate::seed::ensure_seed;
use minicbor::Decoder;
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

const CDH: [u8; 32] = [0xCD; 32];

// Every makeCredential ships packed basic attestation with the device x5c.
const ATT_FMT: &str = "packed";

fn dev() -> Device<'static> {
    Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    }
}

fn mc_request(rk: bool) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(if rk { 5 } else { 4 }).unwrap();
        e.u8(1).unwrap().bytes(&CDH).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str("example.com")
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&[9, 8, 7, 6]).unwrap();
        e.str("name").unwrap().str("bob").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        if rk {
            e.u8(7)
                .unwrap()
                .map(1)
                .unwrap()
                .str("rk")
                .unwrap()
                .bool(true)
                .unwrap();
        }
        e.writer().position()
    };
    buf[..n].to_vec()
}

// Pull (credId, pubkey x, y) out of a makeCredential response's authData.
fn parse_mc(resp: &[u8]) -> (std::vec::Vec<u8>, [u8; 32], [u8; 32]) {
    let mut d = Decoder::new(resp);
    // 3 base fields; a largeBlobKey credential adds field 0x05 (read 1 & 2 only).
    assert!(d.map().unwrap().unwrap() >= 3);
    assert_eq!(d.u8().unwrap(), 1);
    assert_eq!(d.str().unwrap(), ATT_FMT);
    assert_eq!(d.u8().unwrap(), 2);
    let ad = d.bytes().unwrap();
    let cred_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    let cred_id = ad[55..55 + cred_len].to_vec();
    let mut cd = Decoder::new(&ad[55 + cred_len..]);
    assert_eq!(cd.map().unwrap().unwrap(), 5);
    cd.u8().unwrap(); // 1
    cd.u8().unwrap(); // kty 2
    cd.u8().unwrap(); // 3
    cd.i64().unwrap(); // alg
    cd.i8().unwrap(); // -1
    cd.u8().unwrap(); // crv 1
    cd.i8().unwrap(); // -2
    let mut x = [0u8; 32];
    x.copy_from_slice(cd.bytes().unwrap());
    cd.i8().unwrap(); // -3
    let mut y = [0u8; 32];
    y.copy_from_slice(cd.bytes().unwrap());
    (cred_id, x, y)
}

fn verify_assertion(resp: &[u8], x: &[u8; 32], y: &[u8; 32]) -> usize {
    let mut d = Decoder::new(resp);
    let fields = d.map().unwrap().unwrap() as usize;
    assert_eq!(d.u8().unwrap(), 1);
    assert_eq!(d.map().unwrap().unwrap(), 2);
    assert_eq!(d.str().unwrap(), "id");
    let _cred_id = d.bytes().unwrap().to_vec();
    assert_eq!(d.str().unwrap(), "type");
    assert_eq!(d.str().unwrap(), "public-key");
    assert_eq!(d.u8().unwrap(), 2);
    let auth_data = d.bytes().unwrap().to_vec();
    assert_eq!(d.u8().unwrap(), 3);
    let sig = d.bytes().unwrap().to_vec();

    // Assertion authData has UP set and NO attested-credential-data (AT) bit
    // (it is 37 bytes plus any extension output).
    assert!(auth_data.len() >= 37);
    assert_eq!(auth_data[32] & 0x01, 0x01); // UP
    assert_eq!(auth_data[32] & 0x40, 0x00); // no AT

    let pt = Sec1Point::from_bytes(&crate::ec::sec1_uncompressed(x, y)).unwrap();
    let vk = VerifyingKey::from_sec1_point(&pt).unwrap();
    let mut signed = auth_data;
    signed.extend_from_slice(&CDH);
    let s = Signature::from_der(&sig).unwrap();
    vk.verify(&signed, &s)
        .expect("assertion signature verifies under the credential key");
    fields
}

/// Arm a PIN + live token (GA permission) over an already-seeded device.
/// The seed stays plain — PIN ops never wrap it.
fn arm_pin(fs: &mut Fs<RamStorage>, state: &mut crate::FidoState) -> [u8; 32] {
    let mut pin_file = [0u8; 35];
    pin_file[0] = 8;
    pin_file[1] = 4;
    pin_file[2] = 1;
    fs.put(EF_PIN, &pin_file).unwrap();
    let token = [0x99u8; 32];
    state.paut.token = token;
    state.paut.permissions = PERM_GA;
    state.begin_using_token(false, 0);
    token
}

fn ga_request_pin(allow: &[u8], param: &[u8], proto: u64) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(5).unwrap();
        e.u8(1).unwrap().str("example.com").unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(3).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.str("id").unwrap().bytes(allow).unwrap();
        e.u8(6).unwrap().bytes(param).unwrap();
        e.u8(7).unwrap().u64(proto).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

#[test]
fn assertion_with_pin_sets_uv_flag() {
    let (mut fs, mut rng) = setup();
    let mut state = crate::FidoState::new();
    let mut out = [0u8; 1024];
    // Register without a PIN.
    let mc = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 10,
        };
        let n = make_credential(&mut ctx, &mc_request(false), &mut out).unwrap();
        out[..n].to_vec()
    };
    let (cred_id, x, y) = parse_mc(&mc);

    // Arm a PIN + token, then log in with a valid pinUvAuthParam.
    let token = arm_pin(&mut fs, &mut state);
    let mut param = [0u8; 32];
    let plen = rsk_crypto::pinproto::authenticate(PinProto::Two, &token, &CDH, &mut param).unwrap();
    let req = ga_request_pin(&cred_id, &param[..plen], 2);
    let mut out2 = [0u8; 1024];
    let n = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 20,
        };
        get_assertion(&mut ctx, &req, &mut out2).unwrap()
    };
    verify_assertion(&out2[..n], &x, &y);
    // authData must carry the UV flag now.
    let mut d = Decoder::new(&out2[..n]);
    d.map().unwrap();
    d.u8().unwrap();
    d.skip().unwrap(); // 1: credential
    d.u8().unwrap(); // 2
    let ad = d.bytes().unwrap();
    assert_eq!(ad[32] & FLAG_UV, FLAG_UV, "UV flag must be set");
}

// GHSA-wqjm-653g-hgw3: a getAssertion that asserts user presence must run
// clearPinUvAuthTokenPermissionsExceptLbw (CTAP 2.1 §6.2.2 / §6.5.5.7). A token
// armed with ga|acfg|lbw keeps only lbw after the touch, so acfg can't ride the
// assertion into a no-touch authenticatorConfig.
#[test]
fn assertion_up_true_spends_token_permissions_except_lbw() {
    let (mut fs, mut rng) = setup();
    let mut state = crate::FidoState::new();
    let mut out = [0u8; 1024];
    let cred_id = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 10,
        };
        let n = make_credential(&mut ctx, &mc_request(false), &mut out).unwrap();
        parse_mc(&out[..n]).0
    };
    let token = arm_pin(&mut fs, &mut state);
    state.paut.permissions = PERM_GA | crate::state::PERM_ACFG | crate::state::PERM_LBW;
    let mut param = [0u8; 32];
    let plen = rsk_crypto::pinproto::authenticate(PinProto::Two, &token, &CDH, &mut param).unwrap();
    let req = ga_request_pin(&cred_id, &param[..plen], 2); // `up` defaults to true
    let mut o = [0u8; 1024];
    {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 20,
        };
        get_assertion(&mut ctx, &req, &mut o).unwrap();
    }
    assert_eq!(
        state.paut.permissions,
        crate::state::PERM_LBW,
        "only largeBlobWrite survives a UP-gated getAssertion"
    );
    assert!(
        !state.user_verified(),
        "the §6.5.5.7 triad also clears the token's user-verified flag"
    );
}

// The nuance the fix must preserve: an up:false pre-flight (silent credential
// discovery) tests no presence, so it must NOT spend the token — else the real
// up:true assertion that follows on the same token loses its permission. Keyed on
// the raw `up`, so an unconditional clear would fail here even on the default build.
#[test]
fn assertion_up_false_preflight_keeps_token_permissions() {
    let (mut fs, mut rng) = setup();
    let mut state = crate::FidoState::new();
    let mut out = [0u8; 1024];
    let cred_id = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 10,
        };
        let n = make_credential(&mut ctx, &mc_request(false), &mut out).unwrap();
        parse_mc(&out[..n]).0
    };
    let _token = arm_pin(&mut fs, &mut state);
    state.paut.permissions = PERM_GA | crate::state::PERM_ACFG;
    let req = ga_request_up(&cred_id, false); // up:false, no pinUvAuthParam
    let mut o = [0u8; 1024];
    {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 20,
        };
        get_assertion(&mut ctx, &req, &mut o).unwrap();
    }
    assert_eq!(
        state.paut.permissions,
        PERM_GA | crate::state::PERM_ACFG,
        "an up:false pre-flight must not spend the token"
    );
}

// GHSA-wqjm follow-up: the getAssertion NO_CREDENTIALS branch also takes a real
// "Sign in?" anti-oracle touch, so it must spend the token like the success path —
// a no-match ceremony must not leave an acfg token usable without a fresh touch.
#[test]
fn assertion_no_match_spends_token_permissions_except_lbw() {
    let (mut fs, mut rng) = setup();
    let mut state = crate::FidoState::new();
    let token = arm_pin(&mut fs, &mut state);
    state.paut.permissions = PERM_GA | crate::state::PERM_ACFG | crate::state::PERM_LBW;
    let mut param = [0u8; 32];
    let plen = rsk_crypto::pinproto::authenticate(PinProto::Two, &token, &CDH, &mut param).unwrap();
    // up:true (default) with an allowList entry that resolves to no credential → the
    // no-match branch polls presence, then returns NoCredentials.
    let bogus = [0x77u8; 42];
    let req = ga_request_pin(&bogus, &param[..plen], 2);
    let mut o = [0u8; 1024];
    let err = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 20,
        };
        get_assertion(&mut ctx, &req, &mut o).unwrap_err()
    };
    assert_eq!(err, CtapError::NoCredentials);
    assert_eq!(
        state.paut.permissions,
        crate::state::PERM_LBW,
        "the no-match branch spends the token too"
    );
    assert!(
        !state.user_verified(),
        "no-match branch also clears the UV flag"
    );
}

#[test]
fn unscoped_pin_token_binds_rpid_on_first_getassertion() {
    // A GA-capable token minted without an rpId (legacy getPinToken) must bind
    // to the request's rpId on first use (CTAP 2.1 §6.2.2), so it can't be
    // replayed across RPs for its whole lifetime.
    let (mut fs, mut rng) = setup();
    let mut state = crate::FidoState::new();
    let mut out = [0u8; 1024];
    let cred_id = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 10,
        };
        let n = make_credential(&mut ctx, &mc_request(true), &mut out).unwrap();
        parse_mc(&out[..n]).0
    };
    let token = arm_pin(&mut fs, &mut state);
    assert!(!state.paut.has_rp_id, "token starts unscoped");
    let mut param = [0u8; 32];
    let plen = rsk_crypto::pinproto::authenticate(PinProto::Two, &token, &CDH, &mut param).unwrap();
    {
        let req = ga_request_pin(&cred_id, &param[..plen], 2);
        let mut o = [0u8; 1024];
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 20,
        };
        get_assertion(&mut ctx, &req, &mut o).unwrap();
    }
    assert!(
        state.paut.has_rp_id,
        "unscoped token must bind on first use"
    );
    // A second GA for a DIFFERENT rpId is rejected before credential lookup.
    let mut buf = [0u8; 512];
    let m = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(4).unwrap();
        e.u8(1).unwrap().str("other.example").unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(6).unwrap().bytes(&param[..plen]).unwrap();
        e.u8(7).unwrap().u64(2).unwrap();
        e.writer().position()
    };
    let mut o = [0u8; 1024];
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 30,
    };
    assert_eq!(
        get_assertion(&mut ctx, &buf[..m], &mut o).unwrap_err(),
        CtapError::PinAuthInvalid,
        "a token bound to example.com must reject other.example"
    );
}

#[test]
fn numberofcredentials_clamped_to_queue_capacity() {
    // With more resident creds for one rp than the getNextAssertion queue holds
    // (MAX_ASSERTION_CREDS), numberOfCredentials must be clamped to what is
    // servable, not over-report and strand the excess behind a NOT_ALLOWED.
    let (mut fs, mut rng) = setup();
    let mut state = crate::FidoState::new();
    let mut out = [0u8; 1024];
    for i in 0..(crate::state::MAX_ASSERTION_CREDS + 1) {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 10,
        };
        make_credential(&mut ctx, &mc_request_user(&[i as u8; 16]), &mut out).unwrap();
    }
    let req = ga_request(None); // discovery, no allowList
    let mut o = [0u8; 1024];
    let n = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 20,
        };
        get_assertion(&mut ctx, &req, &mut o).unwrap()
    };
    let (_user, count) = user_and_count(&o[..n]);
    assert_eq!(
        count,
        Some(crate::state::MAX_ASSERTION_CREDS as u32),
        "count clamped to what the queue can serve"
    );
}

fn ga_request(allow: Option<&[u8]>) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(if allow.is_some() { 3 } else { 2 }).unwrap();
        e.u8(1).unwrap().str("example.com").unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        if let Some(id) = allow {
            e.u8(3).unwrap().array(1).unwrap().map(2).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
            e.str("id").unwrap().bytes(id).unwrap();
        }
        e.writer().position()
    };
    buf[..n].to_vec()
}

fn setup() -> (Fs<RamStorage>, SeqRng) {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    (fs, rng)
}

/// A presence source that always declines — `require_presence` then returns
/// `OperationDenied`, so it proves whether a touch was actually polled.
struct Decline;
impl crate::UserPresence for Decline {
    fn request(&mut self, _confirm: crate::Confirm<'_>) -> crate::Presence {
        crate::Presence::Declined
    }
}

/// A getAssertion for `allow` carrying the options map `{ "up": up }`.
fn ga_request_up(allow: &[u8], up: bool) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(4).unwrap();
        e.u8(1).unwrap().str("example.com").unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(3).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.str("id").unwrap().bytes(allow).unwrap();
        e.u8(5)
            .unwrap()
            .map(1)
            .unwrap()
            .str("up")
            .unwrap()
            .bool(up)
            .unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

fn register_non_resident(fs: &mut Fs<RamStorage>, rng: &mut SeqRng) -> std::vec::Vec<u8> {
    let mut out = [0u8; 1024];
    let mut state = crate::FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs,
        rng,
        state: &mut state,
        now_ms: 10,
    };
    let n = make_credential(&mut ctx, &mc_request(false), &mut out).unwrap();
    let (cred_id, _x, _y) = parse_mc(&out[..n]);
    cred_id
}

// Default build: the platform's silent pre-flight (up:false) must return an
// assertion WITHOUT polling the button and with the UP flag clear — that is
// what keeps a WebAuthn login to a single touch. Mutation-proof: a Decline
// presence would deny the operation if the touch were polled, and the same
// credential with up:true IS denied.
#[cfg(not(feature = "strict-up"))]
#[test]
fn up_false_preflight_is_silent_and_clears_up_flag() {
    let (mut fs, mut rng) = setup();
    let cred_id = register_non_resident(&mut fs, &mut rng);

    let mut out = [0u8; 1024];
    let n = {
        let mut state = crate::FidoState::new();
        let mut presence = Decline;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 20,
        };
        get_assertion(&mut ctx, &ga_request_up(&cred_id, false), &mut out)
            .expect("up:false returns an assertion without a touch")
    };
    let ad = assertion_auth_data(&out[..n]);
    assert_eq!(ad[32] & 0x01, 0x00, "up:false → UP flag clear");

    // up:true with the same declined button IS refused — the touch is normally
    // required, so this guards against the gate becoming a no-op.
    let mut out2 = [0u8; 1024];
    let mut state = crate::FidoState::new();
    let mut presence = Decline;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 30,
    };
    assert_eq!(
        get_assertion(&mut ctx, &ga_request_up(&cred_id, true), &mut out2),
        Err(CtapError::OperationDenied),
        "up:true with a declined touch must be denied",
    );
}

/// The silent pre-flight is ungated, so an unbudgeted entry per call let a host holding
/// any credential evict the whole 128-slot audit window — and with it the record of
/// whatever it had just done (audit run-37). A run of them now costs one entry; an
/// assertion that collected a gesture still earns its own.
#[cfg(not(feature = "strict-up"))]
#[test]
fn silent_assertions_cannot_flush_the_audit_journal() {
    let (mut fs, mut rng) = setup();
    let cred_id = register_non_resident(&mut fs, &mut rng);
    crate::journal::set_enabled(&mut fs, true).unwrap();
    let silent = ga_request_up(&cred_id, false);
    let gestured = ga_request_up(&cred_id, true);

    let mut out = [0u8; 1024];
    {
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 20,
        };
        // The evidence the flood is meant to displace.
        crate::journal::append(&mut ctx, crate::journal::EV_BACKUP_EXPORT, 0, &[]);
        for _ in 0..crate::consts::AUDIT_RING_SLOTS + 2 {
            get_assertion(&mut ctx, &silent, &mut out).unwrap();
        }
        get_assertion(&mut ctx, &gestured, &mut out).unwrap();
    }

    let (_, m) = crate::journal::chain_head(&dev(), &mut fs);
    assert_eq!(m.start, 0, "nothing evicted from the window");
    // BOOT, BACKUP_EXPORT, the coalesced silent run, the gestured assertion.
    assert_eq!(m.seq_next, 4);
    let mut seen = std::vec::Vec::new();
    crate::journal::for_each_event(&dev(), &mut fs, |e| {
        seen.push(e.event);
        true
    });
    assert!(seen.contains(&crate::journal::EV_BACKUP_EXPORT));
}

// strict-up build: even up:false polls the button, so a declined touch denies
// the assertion (the opt-in two-touch behavior).
#[cfg(feature = "strict-up")]
#[test]
fn strict_up_polls_button_even_on_up_false() {
    let (mut fs, mut rng) = setup();
    let cred_id = register_non_resident(&mut fs, &mut rng);
    let mut out = [0u8; 1024];
    let mut state = crate::FidoState::new();
    let mut presence = Decline;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 20,
    };
    assert_eq!(
        get_assertion(&mut ctx, &ga_request_up(&cred_id, false), &mut out),
        Err(CtapError::OperationDenied),
        "strict-up: up:false still requires a touch",
    );
}

#[test]
fn register_then_login_non_resident() {
    let (mut fs, mut rng) = setup();
    let mut out = [0u8; 1024];

    let mc = {
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 10,
        };
        let n = make_credential(&mut ctx, &mc_request(false), &mut out).unwrap();
        out[..n].to_vec()
    };
    let (cred_id, x, y) = parse_mc(&mc);
    assert!(cred_id.len() > 42, "non-resident returns the full box");

    let mut out2 = [0u8; 1024];
    let ga = {
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 20,
        };
        let n = get_assertion(&mut ctx, &ga_request(Some(&cred_id)), &mut out2).unwrap();
        out2[..n].to_vec()
    };
    // No user field for a non-resident credential.
    assert_eq!(verify_assertion(&ga, &x, &y), 3);
}

/// A built-in-UV presence backend (the trusted-display pad): reports `options.uv`
/// available, "types" a fixed PIN, and counts the separate presence gestures the
/// ceremony asks for on top of that.
struct UvPad {
    /// Overrides the entry, to exercise the Deny branch.
    outcome: Option<crate::PinEntry>,
    touches: usize,
}
impl UvPad {
    fn typing() -> Self {
        Self {
            outcome: None,
            touches: 0,
        }
    }
    fn ending(outcome: crate::PinEntry) -> Self {
        Self {
            outcome: Some(outcome),
            touches: 0,
        }
    }
}
impl crate::UserPresence for UvPad {
    fn request(&mut self, _c: crate::Confirm<'_>) -> crate::Presence {
        self.touches += 1;
        crate::Presence::Confirmed
    }
    fn uv_available(&self) -> bool {
        true
    }
    fn collect_pin(&mut self, _min: usize, out: &mut [u8]) -> crate::PinEntry {
        if let Some(o) = self.outcome {
            return o;
        }
        out[..4].copy_from_slice(b"1234");
        crate::PinEntry::Entered(4)
    }
}

/// A getAssertion for `allow` carrying `options: {uv: true}`, optionally with a
/// pinUvAuthParam.
fn ga_request_uv(allow: &[u8], param: Option<(&[u8], u64)>) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(if param.is_some() { 6 } else { 4 }).unwrap();
        e.u8(1).unwrap().str("example.com").unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(3).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.str("id").unwrap().bytes(allow).unwrap();
        e.u8(5).unwrap().map(1).unwrap();
        e.str("uv").unwrap().bool(true).unwrap();
        if let Some((p, proto)) = param {
            e.u8(6).unwrap().bytes(p).unwrap();
            e.u8(7).unwrap().u64(proto).unwrap();
        }
        e.writer().position()
    };
    buf[..n].to_vec()
}

#[test]
fn uv_option_with_pin_uv_auth_param_is_not_an_error() {
    let (mut fs, mut rng) = setup();
    let cred_id = register_non_resident(&mut fs, &mut rng);
    let mut state = crate::FidoState::new();
    let token = arm_pin(&mut fs, &mut state);
    // §6.2.2 step 4: pinUvAuthParam takes precedence and the "uv" option is treated
    // as false — the pair is NOT CTAP2_ERR_INVALID_OPTION.
    let mut param = [0u8; 32];
    let plen = rsk_crypto::pinproto::authenticate(PinProto::Two, &token, &CDH, &mut param).unwrap();
    let mut out = [0u8; 1024];
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
    };
    let req = ga_request_uv(&cred_id, Some((&param[..plen], 2)));
    let n = get_assertion(&mut ctx, &req, &mut out).unwrap();
    let ad = assertion_auth_data(&out[..n]);
    assert_eq!(ad[32] & FLAG_UV, FLAG_UV, "the token still sets UV");
}

#[test]
fn uv_option_without_builtin_uv_is_invalid_option() {
    let (mut fs, mut rng) = setup();
    let cred_id = register_non_resident(&mut fs, &mut rng);
    let mut state = crate::FidoState::new();
    arm_pin(&mut fs, &mut state);
    // §6.2.2 step 4: a screenless build has no built-in user verification method,
    // so a token-less uv:true IS CTAP2_ERR_INVALID_OPTION.
    let mut out = [0u8; 1024];
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
        get_assertion(&mut ctx, &ga_request_uv(&cred_id, None), &mut out),
        Err(CtapError::InvalidOption)
    );
}

#[test]
fn uv_option_runs_builtin_uv_and_supplies_user_presence() {
    let (mut fs, mut rng) = setup();
    let cred_id = register_non_resident(&mut fs, &mut rng);
    crate::clientpin::store_local_pin(&dev(), &mut fs, b"1234").unwrap();
    let mut state = crate::FidoState::new();
    // §6.2.2 step 6.2: with the pad configured, uv:true is honored — the PIN is
    // typed on the device. Step 8: that ceremony IS the evidence of user
    // interaction, so UP is set without asking for a second touch.
    let mut out = [0u8; 1024];
    let mut pad = UvPad::typing();
    let n = {
        let mut ctx = Ctx {
            presence: &mut pad,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        get_assertion(&mut ctx, &ga_request_uv(&cred_id, None), &mut out).unwrap()
    };
    let ad = assertion_auth_data(&out[..n]);
    assert_eq!(ad[32] & FLAG_UV, FLAG_UV, "built-in UV sets UV");
    assert_eq!(ad[32] & FLAG_UP, FLAG_UP, "…and asserts presence");
    assert_eq!(
        pad.touches, 0,
        "built-in UV must not ask for a second touch"
    );
}

#[test]
fn builtin_uv_decline_is_operation_denied() {
    let (mut fs, mut rng) = setup();
    let cred_id = register_non_resident(&mut fs, &mut rng);
    crate::clientpin::store_local_pin(&dev(), &mut fs, b"1234").unwrap();
    let mut state = crate::FidoState::new();
    // The one deliberate divergence from §6.2.2 step 6.2's error ladder: a Deny on
    // the pad stays OPERATION_DENIED. PUAT_REQUIRED would send the platform off to
    // collect the same PIN over USB, undoing the refusal the user just made.
    let mut out = [0u8; 1024];
    let mut pad = UvPad::ending(crate::PinEntry::Declined);
    let mut ctx = Ctx {
        presence: &mut pad,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
    };
    assert_eq!(
        get_assertion(&mut ctx, &ga_request_uv(&cred_id, None), &mut out),
        Err(CtapError::OperationDenied)
    );
}

#[test]
fn always_uv_upgrades_a_tokenless_request_to_builtin_uv() {
    let (mut fs, mut rng) = setup();
    let cred_id = register_non_resident(&mut fs, &mut rng);
    crate::clientpin::store_local_pin(&dev(), &mut fs, b"1234").unwrap();
    fs.put(EF_ALWAYS_UV, &[1]).unwrap();
    let mut state = crate::FidoState::new();
    // §6.2.2 step 5.4: alwaysUv treats the "uv" option as true when the pad is
    // configured, so the request is verified rather than refused with 0x36.
    let mut out = [0u8; 1024];
    let mut pad = UvPad::typing();
    let n = {
        let mut ctx = Ctx {
            presence: &mut pad,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        get_assertion(&mut ctx, &ga_request(Some(&cred_id)), &mut out).unwrap()
    };
    let ad = assertion_auth_data(&out[..n]);
    assert_eq!(ad[32] & FLAG_UV, FLAG_UV);
}

#[test]
fn always_uv_requires_user_verification() {
    let (mut fs, mut rng) = setup();
    // alwaysUv on → getAssertion demands UV; an up-only request is refused with
    // PUAT_REQUIRED before any credential lookup. Without the EF_ALWAYS_UV guard
    // the same request proceeds and returns NO_CREDENTIALS, so this is
    // mutation-proof for the guard.
    fs.put(EF_ALWAYS_UV, &[1]).unwrap();
    let mut out = [0u8; 256];
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
        get_assertion(&mut ctx, &ga_request(None), &mut out),
        Err(CtapError::PuatRequired)
    );
}

// alwaysUv on: the platform's silent up:false pre-flight (credential discovery)
// must still succeed WITHOUT user verification — that is what lets ssh-sk / a
// WebAuthn platform locate the credential before prompting for UV (CTAP 2.1
// §6.2.2 step 5 guards the PUAT_REQUIRED path on up=true). The returned assertion
// is silent (UP+UV flags clear); an interactive up:true request with no
// pinUvAuthParam is still refused with PUAT_REQUIRED. Not run under strict-up:
// the exemption still applies there, but strict-up polls the button on the probe,
// so a Decline denies (OPERATION_DENIED) instead of returning the silent
// assertion this test asserts — that path is covered by
// `always_uv_strict_up_preflight_polls_button_not_puat`.
#[cfg(not(feature = "strict-up"))]
#[test]
fn always_uv_allows_silent_up_false_preflight() {
    let (mut fs, mut rng) = setup();
    let cred_id = register_non_resident(&mut fs, &mut rng);
    fs.put(EF_ALWAYS_UV, &[1]).unwrap();

    // up:false pre-flight → a silent assertion with NO touch polled (a Decline
    // presence would deny if the button were read), UP and UV flags clear.
    let mut out = [0u8; 1024];
    let n = {
        let mut state = crate::FidoState::new();
        let mut presence = Decline;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 20,
        };
        get_assertion(&mut ctx, &ga_request_up(&cred_id, false), &mut out)
            .expect("alwaysUv still answers the silent up:false discovery probe")
    };
    let ad = assertion_auth_data(&out[..n]);
    assert_eq!(
        ad[32] & FLAG_UP,
        0,
        "up:false under alwaysUv → UP flag clear"
    );
    assert_eq!(ad[32] & FLAG_UV, 0, "silent probe carries no UV");

    // up:true with no pinUvAuthParam is still refused before any credential work.
    let mut out2 = [0u8; 256];
    let mut state = crate::FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 30,
    };
    assert_eq!(
        get_assertion(&mut ctx, &ga_request_up(&cred_id, true), &mut out2),
        Err(CtapError::PuatRequired),
        "an interactive up:true request under alwaysUv still demands UV",
    );
}

// alwaysUv + strict-up: the silent up:false pre-flight must NOT be refused with
// PUAT_REQUIRED in enforce_pin — that re-broke ssh-sk ("device not found") when
// the two features combined (issue #34 follow-up). strict-up still polls the
// button on the probe (its kept two-touch behavior), so a Decline denies with
// OPERATION_DENIED and a confirmed touch returns an assertion — either way, never
// PUAT_REQUIRED. Crucially the returned assertion stays INERT (UP=0): emitting UP=1
// here would let an up:false probe defeat alwaysUv (a usable no-UV assertion on a
// stolen key), so the emitted UP flag keys on the raw `up`, not the button poll.
#[cfg(feature = "strict-up")]
#[test]
fn always_uv_strict_up_preflight_polls_button_not_puat() {
    let (mut fs, mut rng) = setup();
    let cred_id = register_non_resident(&mut fs, &mut rng);
    fs.put(EF_ALWAYS_UV, &[1]).unwrap();

    // Declined touch → OPERATION_DENIED (reached the button poll), NOT
    // PUAT_REQUIRED (enforce_pin rejected the probe outright before the fix).
    let mut out = [0u8; 1024];
    {
        let mut state = crate::FidoState::new();
        let mut presence = Decline;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 20,
        };
        assert_eq!(
            get_assertion(&mut ctx, &ga_request_up(&cred_id, false), &mut out),
            Err(CtapError::OperationDenied),
            "always-uv+strict-up up:false probe polls the button, not PUAT_REQUIRED",
        );
    }

    // A confirmed touch returns an assertion so ssh-sk's pre-flight proceeds instead
    // of failing "device not found" — but the probe stays inert (UP flag clear even
    // though the button was polled), so it can't be relayed as a real login.
    let mut out2 = [0u8; 1024];
    let n = {
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 30,
        };
        get_assertion(&mut ctx, &ga_request_up(&cred_id, false), &mut out2)
            .expect("always-uv+strict-up answers a confirmed up:false probe")
    };
    let ad = assertion_auth_data(&out2[..n]);
    assert_eq!(
        ad[32] & FLAG_UP,
        0,
        "strict-up up:false → UP flag CLEAR: the polled probe stays inert so it can't defeat alwaysUv"
    );
    assert_eq!(ad[32] & FLAG_UV, 0, "silent probe carries no UV");
}

#[test]
fn u2f_handle_usable_via_ctap2_allowlist() {
    use crate::keyderiv::derive_new;
    use rsk_crypto::pinproto::public_xy;
    // A U2F/CTAP1 key handle bound to this rp must be usable in a CTAP2
    // getAssertion allowList.
    let (mut fs, mut rng) = setup();
    let rp_id_hash = sha256(b"example.com");
    let seed = crate::seed::load_keydev(&dev(), &mut fs).unwrap();
    // cmd_register would derive this handle + scalar from the device seed.
    let (kh, scalar) = derive_new(&seed, &rp_id_hash, &mut rng);
    let (x, y) = public_xy(&scalar).unwrap();

    let mut out = [0u8; 1024];
    let mut state = crate::FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 20,
    };
    let n = get_assertion(&mut ctx, &ga_request(Some(&kh)), &mut out).unwrap();
    let ga = out[..n].to_vec();
    // The handle round-trips as the credential id and the assertion signature
    // verifies under the U2F-registered public key.
    assert_eq!(cred_id_of(&ga), kh.to_vec());
    assert_eq!(verify_assertion(&ga, &x, &y), 3);
}

#[test]
fn register_then_login_resident_discovery() {
    let (mut fs, mut rng) = setup();
    let mut out = [0u8; 1024];

    let mc = {
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 10,
        };
        let n = make_credential(&mut ctx, &mc_request(true), &mut out).unwrap();
        out[..n].to_vec()
    };
    let (_resident_id, x, y) = parse_mc(&mc);

    // No allowList → the device discovers the resident credential.
    let mut out2 = [0u8; 1024];
    let ga = {
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 20,
        };
        let n = get_assertion(&mut ctx, &ga_request(None), &mut out2).unwrap();
        out2[..n].to_vec()
    };
    // Resident: includes the user field (id 9,8,7,6).
    assert_eq!(verify_assertion(&ga, &x, &y), 4);
    let mut d = Decoder::new(&ga);
    d.map().unwrap();
    for _ in 0..3 {
        // skip credential, authData, sig (keys 1,2,3)
        d.u8().unwrap();
        d.skip().unwrap();
    }
    assert_eq!(d.u8().unwrap(), 4);
    assert_eq!(d.map().unwrap().unwrap(), 1);
    assert_eq!(d.str().unwrap(), "id");
    assert_eq!(d.bytes().unwrap(), &[9, 8, 7, 6]);
}

#[test]
fn discovery_returns_stored_resident_id() {
    // get_assertion (resident discovery) must echo the credential's STORED
    // 42-byte resident id — not one re-derived from the box — so the id stays
    // stable after an updateUserInformation reseal (CTAP2.1 §6.8.5). Proven by
    // overwriting the stored prefix: a re-derived id would not equal it.
    let (mut fs, mut rng) = setup();
    let mut out = [0u8; 1024];
    {
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 10,
        };
        make_credential(&mut ctx, &mc_request(true), &mut out).unwrap();
    }

    // Overwrite the stored resident-id prefix with a sentinel; the box is left
    // intact, so a re-derived id would differ from this.
    let mut rec = [0u8; 1024];
    let n = fs.read(EF_CRED, &mut rec).unwrap();
    let mut sentinel = [0u8; CRED_RESIDENT_LEN];
    for (i, b) in sentinel.iter_mut().enumerate() {
        *b = 0xC0 ^ i as u8;
    }
    sentinel[8] = 2; // keep the v3 marker so the record's pubkey trailer still parses
    rec[32..RECORD_PREFIX].copy_from_slice(&sentinel);
    fs.put(EF_CRED, &rec[..n]).unwrap();

    // Discovery (no allowList) returns the stored sentinel as the credentialId.
    let mut out2 = [0u8; 1024];
    let ga = {
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 20,
        };
        let m = get_assertion(&mut ctx, &ga_request(None), &mut out2).unwrap();
        out2[..m].to_vec()
    };
    assert_eq!(cred_id_of(&ga), sentinel.to_vec());
}

/// authData signCount (big-endian) from a getAssertion / getNextAssertion response.
fn assertion_sign_count(resp: &[u8]) -> u32 {
    let mut d = Decoder::new(resp);
    d.map().unwrap();
    assert_eq!(d.u8().unwrap(), 1);
    d.skip().unwrap(); // 1: { id, type }
    assert_eq!(d.u8().unwrap(), 2);
    let ad = d.bytes().unwrap();
    u32::from_be_bytes(ad[33..37].try_into().unwrap())
}

/// A resident makeCredential request for `example.com` with the given user id (so
/// two calls yield two DISTINCT discoverable credentials).
fn mc_request_rk_uid(uid: &[u8]) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(5).unwrap();
        e.u8(1).unwrap().bytes(&CDH).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str("example.com")
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(uid).unwrap();
        e.str("name").unwrap().str("bob").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(7)
            .unwrap()
            .map(1)
            .unwrap()
            .str("rk")
            .unwrap()
            .bool(true)
            .unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// Drive one makeCredential over `fs`, returning the response bytes.
fn run_make(fs: &mut Fs<RamStorage>, rng: &mut SeqRng, req: &[u8]) -> std::vec::Vec<u8> {
    let mut out = [0u8; 1024];
    let mut state = crate::FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs,
        rng,
        state: &mut state,
        now_ms: 10,
    };
    let n = make_credential(&mut ctx, req, &mut out).unwrap();
    out[..n].to_vec()
}

/// Drive one getAssertion over `fs`, returning the response bytes.
fn run_assert(fs: &mut Fs<RamStorage>, rng: &mut SeqRng, req: &[u8]) -> std::vec::Vec<u8> {
    let mut out = [0u8; 1024];
    let mut state = crate::FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs,
        rng,
        state: &mut state,
        now_ms: 30,
    };
    let n = get_assertion(&mut ctx, req, &mut out).unwrap();
    out[..n].to_vec()
}

#[test]
fn sign_count_is_per_credential() {
    // The privacy fix (differential-harness finding #4): each resident credential
    // keeps its OWN signature counter, so asserting one never advances another's —
    // colluding RPs can't reconstruct this key's cross-site usage from a shared
    // global counter. Registration reports 0; each assertion climbs the
    // credential's own counter.
    let (mut fs, mut rng) = setup();
    let a = parse_mc(&run_make(
        &mut fs,
        &mut rng,
        &mc_request_rk_uid(&[1, 1, 1, 1]),
    ))
    .0;
    let b = parse_mc(&run_make(
        &mut fs,
        &mut rng,
        &mc_request_rk_uid(&[2, 2, 2, 2]),
    ))
    .0;
    assert_ne!(a, b, "distinct users get distinct resident ids");

    // Credential A climbs 1, 2 on its own assertions.
    let a1 = run_assert(&mut fs, &mut rng, &ga_request(Some(&a)));
    let a2 = run_assert(&mut fs, &mut rng, &ga_request(Some(&a)));
    assert_eq!(assertion_sign_count(&a1), 1);
    assert_eq!(assertion_sign_count(&a2), 2);

    // Credential B's FIRST assertion reports 1 — its OWN counter, not the shared
    // global value (which under the old scheme would already read 3 here).
    let b1 = run_assert(&mut fs, &mut rng, &ga_request(Some(&b)));
    assert_eq!(assertion_sign_count(&b1), 1);

    // A resumes its own sequence, unperturbed by B.
    let a3 = run_assert(&mut fs, &mut rng, &ga_request(Some(&a)));
    assert_eq!(assertion_sign_count(&a3), 3);
}

#[test]
fn non_resident_sign_count_is_zero() {
    // A non-resident credential keeps no on-device state, so it reports signCount 0
    // on every assertion (nothing to correlate) and never touches EF_COUNTER.
    let (mut fs, mut rng) = setup();
    let cred_id = parse_mc(&run_make(&mut fs, &mut rng, &mc_request(false))).0;
    let g0 = crate::seed::get_sign_counter(&mut fs);
    for _ in 0..3 {
        let resp = run_assert(&mut fs, &mut rng, &ga_request(Some(&cred_id)));
        assert_eq!(assertion_sign_count(&resp), 0);
    }
    assert_eq!(
        crate::seed::get_sign_counter(&mut fs),
        g0,
        "global counter untouched by CTAP2 assertions"
    );
}

#[test]
fn legacy_resident_credential_seeds_from_global_counter() {
    // A resident credential from before EF_CRED_CTR existed has no counter entry.
    // Its first assertion must SEED from the frozen global counter so the signCount
    // never DEcreases across the upgrade, then climb per-credential from there.
    let (mut fs, mut rng) = setup();
    let cred_id = parse_mc(&run_make(
        &mut fs,
        &mut rng,
        &mc_request_rk_uid(&[3, 3, 3, 3]),
    ))
    .0;
    // Recreate a pre-upgrade device: a non-trivial global counter and no per-cred entry.
    fs.put(crate::consts::EF_COUNTER, &100u32.to_le_bytes())
        .unwrap();
    fs.delete(crate::consts::EF_CRED_CTR).unwrap();

    let r1 = run_assert(&mut fs, &mut rng, &ga_request(Some(&cred_id)));
    assert_eq!(
        assertion_sign_count(&r1),
        100,
        "seeds from the frozen global"
    );
    let r2 = run_assert(&mut fs, &mut rng, &ga_request(Some(&cred_id)));
    assert_eq!(assertion_sign_count(&r2), 101, "then climbs per-credential");
}

#[test]
fn legacy_credential_survives_gap_zerofill() {
    // Regression (adversarial review): writing a HIGHER slot zero-extends the packed
    // EF_CRED_CTR file across lower legacy slots. Such a zero-filled slot must still
    // read as unmaterialized (seed from the frozen global), NOT as a real signCount 0
    // — otherwise a pre-upgrade credential regresses to 0 and trips an RP's clone
    // alarm. Two resident creds: L lands in slot 0, H in slot 1.
    let (mut fs, mut rng) = setup();
    let l = parse_mc(&run_make(
        &mut fs,
        &mut rng,
        &mc_request_rk_uid(&[4, 4, 4, 4]),
    ))
    .0;
    let h = parse_mc(&run_make(
        &mut fs,
        &mut rng,
        &mc_request_rk_uid(&[5, 5, 5, 5]),
    ))
    .0;
    // Recreate a pre-upgrade device: a live global and NO per-credential file at all.
    fs.put(crate::consts::EF_COUNTER, &50u32.to_le_bytes())
        .unwrap();
    fs.delete(crate::consts::EF_CRED_CTR).unwrap();

    // Assert H (slot 1) first: this materializes slot 1 and zero-extends the packed
    // file over slot 0.
    let _ = run_assert(&mut fs, &mut rng, &ga_request(Some(&h)));

    // L (slot 0) is now a zero-filled gap entry. It must seed from the global (50),
    // never report 0.
    let r = run_assert(&mut fs, &mut rng, &ga_request(Some(&l)));
    assert_eq!(
        assertion_sign_count(&r),
        50,
        "a zero-filled legacy slot seeds from the global, not signCount 0"
    );
    // And then climbs on its own from the seed.
    let r2 = run_assert(&mut fs, &mut rng, &ga_request(Some(&l)));
    assert_eq!(assertion_sign_count(&r2), 51);
}

#[test]
fn no_matching_credentials() {
    let (mut fs, mut rng) = setup();
    let mut out = [0u8; 256];
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
    // No credentials registered → NoCredentials (a touch is polled first now; the
    // AlwaysConfirm presence auto-confirms, so the disclosed result is unchanged).
    assert_eq!(
        get_assertion(&mut ctx, &ga_request(None), &mut out),
        Err(CtapError::NoCredentials)
    );
}

// A up:true getAssertion that matches no credential polls the button BEFORE
// returning NoCredentials, so a plugged-in device is not a silent
// credential-existence oracle (matches a genuine YubiKey). A declined touch
// surfaces as OperationDenied — proving the poll ran — for both a discoverable
// walk and an allowList miss; the silent up:false pre-flight stays touch-free and
// still fast-fails NoCredentials (ssh-sk credential discovery).
#[cfg(not(feature = "strict-up"))]
#[test]
fn no_match_polls_presence_before_disclosing() {
    let (mut fs, mut rng) = setup();
    let fake = [0x5Au8; CRED_RESIDENT_LEN]; // a resident-length id that matches nothing
    let mut out = [0u8; 256];

    // (A) discoverable (no allowList), up:true default → button polled → declined.
    {
        let mut state = crate::FidoState::new();
        let mut presence = Decline;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 10,
        };
        assert_eq!(
            get_assertion(&mut ctx, &ga_request(None), &mut out),
            Err(CtapError::OperationDenied),
            "discoverable no-match must poll the button before NoCredentials",
        );
    }
    // (B) allowList carrying an unknown id, up:true default → same.
    {
        let mut state = crate::FidoState::new();
        let mut presence = Decline;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 20,
        };
        assert_eq!(
            get_assertion(&mut ctx, &ga_request(Some(&fake)), &mut out),
            Err(CtapError::OperationDenied),
            "allowList miss must poll the button before NoCredentials",
        );
    }
    // up:false silent pre-flight: no touch polled (Decline never fires) and the
    // fast NoCredentials is preserved.
    {
        let mut state = crate::FidoState::new();
        let mut presence = Decline;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 30,
        };
        assert_eq!(
            get_assertion(&mut ctx, &ga_request_up(&fake, false), &mut out),
            Err(CtapError::NoCredentials),
            "up:false pre-flight must stay silent and fast-fail",
        );
    }
}

// strict-up build: even an up:false no-match polls the button (its opt-in
// touch-on-every-assertion), so a declined touch denies before NoCredentials.
#[cfg(feature = "strict-up")]
#[test]
fn strict_up_no_match_polls_presence_even_on_up_false() {
    let (mut fs, mut rng) = setup();
    let fake = [0x5Au8; CRED_RESIDENT_LEN];
    let mut out = [0u8; 256];
    let mut state = crate::FidoState::new();
    let mut presence = Decline;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 10,
    };
    assert_eq!(
        get_assertion(&mut ctx, &ga_request_up(&fake, false), &mut out),
        Err(CtapError::OperationDenied),
        "strict-up: even an up:false no-match polls the button",
    );
}

#[test]
fn out_of_order_optional_keys_rejected() {
    // Canonical CBOR requires ascending map keys; key 6 after key 7 descends →
    // INVALID_CBOR (the `key < expected` guard), before any credential lookup.
    let (mut fs, mut rng) = setup();
    let mut buf = [0u8; 128];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(4).unwrap();
        e.u8(1).unwrap().str("example.com").unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(7).unwrap().u64(1).unwrap(); // pinUvAuthProtocol
        e.u8(6).unwrap().bytes(&[0u8; 16]).unwrap(); // pinUvAuthParam — descends
        e.writer().position()
    };
    assert_eq!(
        run_ga(&mut fs, &mut rng, &buf[..n]),
        Err(CtapError::InvalidCbor)
    );
}

#[test]
fn unknown_top_level_key_ignored() {
    // An unrecognized top-level key (0x08) is skipped, not an error: parse
    // succeeds and the empty lookup then reports NO_CREDENTIALS.
    let (mut fs, mut rng) = setup();
    let mut buf = [0u8; 128];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(3).unwrap();
        e.u8(1).unwrap().str("example.com").unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(8).unwrap().u8(0).unwrap(); // unknown → skip
        e.writer().position()
    };
    assert_eq!(
        run_ga(&mut fs, &mut rng, &buf[..n]),
        Err(CtapError::NoCredentials)
    );
}

#[test]
fn unknown_option_key_ignored() {
    // An unrecognized option sub-key is skipped; the known `up` still parses.
    // No credential registered → NO_CREDENTIALS (parse got past the option map).
    let (mut fs, mut rng) = setup();
    let mut buf = [0u8; 128];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(3).unwrap();
        e.u8(1).unwrap().str("example.com").unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(5).unwrap().map(2).unwrap();
        e.str("up").unwrap().bool(true).unwrap();
        e.str("bogus").unwrap().bool(true).unwrap();
        e.writer().position()
    };
    assert_eq!(
        run_ga(&mut fs, &mut rng, &buf[..n]),
        Err(CtapError::NoCredentials)
    );
}

// A resident makeCredential request with a custom user id.
fn mc_request_user(uid: &[u8]) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(5).unwrap();
        e.u8(1).unwrap().bytes(&CDH).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str("example.com")
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(uid).unwrap();
        e.str("name").unwrap().str("user").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(7)
            .unwrap()
            .map(1)
            .unwrap()
            .str("rk")
            .unwrap()
            .bool(true)
            .unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

// Pull (user id, numberOfCredentials) out of an assertion response.
fn user_and_count(resp: &[u8]) -> (std::vec::Vec<u8>, Option<u32>) {
    let mut d = Decoder::new(resp);
    let fields = d.map().unwrap().unwrap();
    let mut user = std::vec::Vec::new();
    let mut count = None;
    for _ in 0..fields {
        match d.u8().unwrap() {
            4 => {
                // The user map is {id [, name, displayName]} on a multi-credential
                // discovery; read every entry, keeping the id.
                let entries = d.map().unwrap().unwrap();
                for _ in 0..entries {
                    match d.str().unwrap() {
                        "id" => user = d.bytes().unwrap().to_vec(),
                        _ => {
                            d.skip().unwrap();
                        }
                    }
                }
            }
            5 => count = Some(d.u32().unwrap()),
            _ => {
                d.skip().unwrap();
            }
        }
    }
    (user, count)
}

// The credential id from response key 1 ({id, type}).
fn cred_id_of(resp: &[u8]) -> std::vec::Vec<u8> {
    let mut d = Decoder::new(resp);
    let fields = d.map().unwrap().unwrap();
    let mut id = std::vec::Vec::new();
    for _ in 0..fields {
        match d.u8().unwrap() {
            1 => {
                let m = d.map().unwrap().unwrap();
                for _ in 0..m {
                    match d.str().unwrap() {
                        "id" => id = d.bytes().unwrap().to_vec(),
                        _ => {
                            d.skip().unwrap();
                        }
                    }
                }
            }
            _ => {
                d.skip().unwrap();
            }
        }
    }
    id
}

// The user "name" (empty if absent) from an assertion response's user map.
fn user_name_of(resp: &[u8]) -> std::string::String {
    let mut d = Decoder::new(resp);
    let fields = d.map().unwrap().unwrap();
    let mut name = std::string::String::new();
    for _ in 0..fields {
        match d.u8().unwrap() {
            4 => {
                let m = d.map().unwrap().unwrap();
                for _ in 0..m {
                    match d.str().unwrap() {
                        "name" => name = d.str().unwrap().into(),
                        _ => {
                            d.skip().unwrap();
                        }
                    }
                }
            }
            _ => {
                d.skip().unwrap();
            }
        }
    }
    name
}

// A getAssertion request with a two-item allowList.
fn ga_request_allow2(id1: &[u8], id2: &[u8]) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(3).unwrap();
        e.u8(1).unwrap().str("example.com").unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(3).unwrap().array(2).unwrap();
        for id in [id1, id2] {
            e.map(2).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
            e.str("id").unwrap().bytes(id).unwrap();
        }
        e.writer().position()
    };
    buf[..n].to_vec()
}

#[test]
fn allowlist_returns_single_assertion_without_count() {
    let (mut fs, mut rng) = setup();
    let mut state = crate::FidoState::new();

    // Two resident credentials for the same rp.
    for (uid, t) in [(&[9u8, 8, 7, 6][..], 10u64), (&[1u8, 1, 1, 1][..], 20u64)] {
        let mut out = [0u8; 1024];
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: t,
        };
        make_credential(&mut ctx, &mc_request_user(uid), &mut out).unwrap();
    }

    // Discover both ids via a no-allowList walk.
    let (id_a, id_b) = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 30,
        };
        let mut o1 = [0u8; 1024];
        let n1 = get_assertion(&mut ctx, &ga_request(None), &mut o1).unwrap();
        let a = cred_id_of(&o1[..n1]);
        let mut o2 = [0u8; 1024];
        let n2 = get_next_assertion(&mut ctx, &mut o2).unwrap();
        (a, cred_id_of(&o2[..n2]))
    };

    // With an allowList of BOTH, CTAP2.1 returns one assertion, no count, and
    // getNextAssertion is not armed.
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 40,
    };
    let mut o = [0u8; 1024];
    let n = get_assertion(&mut ctx, &ga_request_allow2(&id_a, &id_b), &mut o).unwrap();
    let (_user, count) = user_and_count(&o[..n]);
    assert_eq!(count, None);
    let mut o3 = [0u8; 256];
    assert_eq!(
        get_next_assertion(&mut ctx, &mut o3),
        Err(CtapError::NotAllowed)
    );
}

#[test]
fn get_next_assertion_walks_resident_credentials() {
    let (mut fs, mut rng) = setup();
    let mut state = crate::FidoState::new();

    // Register two resident credentials for the same rp (distinct users/times).
    for (uid, t) in [(&[9u8, 8, 7, 6][..], 10u64), (&[1u8, 1, 1, 1][..], 20u64)] {
        let mut out = [0u8; 1024];
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: t,
        };
        make_credential(&mut ctx, &mc_request_user(uid), &mut out).unwrap();
    }

    // getAssertion (no allowList) → newest credential + numberOfCredentials = 2.
    let mut o1 = [0u8; 1024];
    let n1 = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 30,
        };
        get_assertion(&mut ctx, &ga_request(None), &mut o1).unwrap()
    };
    let (u1, count1) = user_and_count(&o1[..n1]);
    assert_eq!(count1, Some(2));
    assert_eq!(u1, &[1, 1, 1, 1]); // newest (created 20)
    // Without user verification the user map is id-only — name/displayName are
    // user-identifiable info, withheld unless uv (§6.2.2 privacy rule).
    assert_eq!(user_name_of(&o1[..n1]), "");

    // getNextAssertion → the older credential, no numberOfCredentials field.
    let mut o2 = [0u8; 1024];
    let n2 = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 31,
        };
        get_next_assertion(&mut ctx, &mut o2).unwrap()
    };
    let (u2, count2) = user_and_count(&o2[..n2]);
    assert_eq!(count2, None);
    assert_eq!(u2, &[9, 8, 7, 6]); // older (created 10)
    // getNextAssertion likewise withholds name/displayName without uv.
    assert_eq!(user_name_of(&o2[..n2]), "");

    // The list is exhausted → NOT_ALLOWED, and stays that way.
    let mut o3 = [0u8; 256];
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 32,
    };
    assert_eq!(
        get_next_assertion(&mut ctx, &mut o3),
        Err(CtapError::NotAllowed)
    );
}

/// §6.3 "Reset the timer": the 30-second budget covers the gap between consecutive
/// calls, not the whole walk. A platform drawing an account picker over three
/// credentials must not run out of it partway through.
#[test]
fn get_next_assertion_timer_is_per_leg() {
    let (mut fs, mut rng) = setup();
    let mut state = crate::FidoState::new();
    for (uid, t) in [
        (&[1u8, 1, 1, 1][..], 10u64),
        (&[2u8, 2, 2, 2][..], 20),
        (&[3u8, 3, 3, 3][..], 30),
    ] {
        let mut out = [0u8; 1024];
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: t,
        };
        make_credential(&mut ctx, &mc_request_user(uid), &mut out).unwrap();
    }

    let mut leg = |now_ms: u64, first: bool| {
        let mut out = [0u8; 1024];
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms,
        };
        if first {
            get_assertion(&mut ctx, &ga_request(None), &mut out).map(|_| ())
        } else {
            get_next_assertion(&mut ctx, &mut out).map(|_| ())
        }
    };
    assert_eq!(leg(100, true), Ok(()));
    // 25 s later: inside the window measured from the getAssertion.
    assert_eq!(leg(25_100, false), Ok(()));
    // Another 25 s: 50 s since the getAssertion, but only 25 s since the last leg.
    assert_eq!(leg(50_100, false), Ok(()));
}

/// …and a genuine gap still expires the walk.
#[test]
fn get_next_assertion_expires_after_a_quiet_thirty_seconds() {
    let (mut fs, mut rng) = setup();
    let mut state = crate::FidoState::new();
    for (uid, t) in [(&[1u8, 1, 1, 1][..], 10u64), (&[2u8, 2, 2, 2][..], 20)] {
        let mut out = [0u8; 1024];
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: t,
        };
        make_credential(&mut ctx, &mc_request_user(uid), &mut out).unwrap();
    }
    let mut out = [0u8; 1024];
    {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 100,
        };
        get_assertion(&mut ctx, &ga_request(None), &mut out).unwrap();
    }
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 30_101,
    };
    assert_eq!(
        get_next_assertion(&mut ctx, &mut out),
        Err(CtapError::NotAllowed)
    );
}

/// A `getNextAssertion` belongs to the channel whose `getAssertion` opened the
/// walk. A second process on its own CTAPHID channel asking for it gets
/// `CTAP2_ERR_NOT_ALLOWED` — otherwise it collects an assertion signed over the
/// FIRST channel's clientDataHash, under the first request's presence decision,
/// having neither supplied the one nor satisfied the other.
///
/// Ported from OpenSK's `test_channel_interleaving`; the same scoping this state
/// struct's neighbour `mse_cid` already applies, and the unscoped version of it
/// is what audit run-31 filed as HIGH.
#[test]
fn get_next_assertion_refuses_a_second_channel() {
    const CHANNEL_A: u32 = 0x0100_0000;
    const CHANNEL_B: u32 = 0x0200_0000;

    let (mut fs, mut rng) = setup();
    let mut state = crate::FidoState::new();
    for (uid, t) in [(&[9u8, 8, 7, 6][..], 10u64), (&[1u8, 1, 1, 1][..], 20u64)] {
        let mut out = [0u8; 1024];
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: t,
        };
        make_credential(&mut ctx, &mc_request_user(uid), &mut out).unwrap();
    }

    state.channel = CHANNEL_A;
    let mut o1 = [0u8; 1024];
    let n1 = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 30,
        };
        get_assertion(&mut ctx, &ga_request(None), &mut o1).unwrap()
    };
    assert_eq!(user_and_count(&o1[..n1]).1, Some(2), "a walk is open");

    state.channel = CHANNEL_B;
    let mut o2 = [0u8; 1024];
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 31,
    };
    assert_eq!(
        get_next_assertion(&mut ctx, &mut o2),
        Err(CtapError::NotAllowed),
        "another channel may not walk this one's assertions"
    );
}

#[test]
fn get_next_assertion_uses_per_credential_counter() {
    // The getNextAssertion path must advance the walked credential's OWN counter
    // (keyed by its EF_CRED slot), not a shared one: two credentials returned by a
    // single discovery both report signCount 1 on their first use, and each climbs
    // independently on the next discovery.
    let (mut fs, mut rng) = setup();
    let mut state = crate::FidoState::new();
    for (uid, t) in [(&[9u8, 8, 7, 6][..], 10u64), (&[1u8, 1, 1, 1][..], 20u64)] {
        let mut out = [0u8; 1024];
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: t,
        };
        make_credential(&mut ctx, &mc_request_user(uid), &mut out).unwrap();
    }

    let discover =
        |fs: &mut Fs<RamStorage>, rng: &mut SeqRng, state: &mut crate::FidoState, t: u64| {
            let mut o1 = [0u8; 1024];
            let mut o2 = [0u8; 1024];
            let (n1, n2) = {
                let mut presence = crate::AlwaysConfirm;
                let mut ctx = Ctx {
                    presence: &mut presence,
                    dev: dev(),
                    fs,
                    rng,
                    state,
                    now_ms: t,
                };
                let n1 = get_assertion(&mut ctx, &ga_request(None), &mut o1).unwrap();
                let n2 = get_next_assertion(&mut ctx, &mut o2).unwrap();
                (n1, n2)
            };
            (
                assertion_sign_count(&o1[..n1]),
                assertion_sign_count(&o2[..n2]),
            )
        };

    // First use of each credential → both report their own counter's 1.
    assert_eq!(discover(&mut fs, &mut rng, &mut state, 30), (1, 1));
    // Next discovery → each climbs independently to 2.
    assert_eq!(discover(&mut fs, &mut rng, &mut state, 40), (2, 2));
}

#[test]
fn declined_get_assertion_disarms_get_next_assertion() {
    // run-4 (HIGH): getNextAssertion performs no presence check of its own, so a
    // getAssertion whose touch was declined/ignored must leave nothing armed —
    // else the next getNextAssertion emits a UP=1 assertion the user never
    // approved (a user-presence bypass for resident credentials #2..N).
    let (mut fs, mut rng) = setup();
    let mut state = crate::FidoState::new();
    for (uid, t) in [(&[9u8, 8, 7, 6][..], 10u64), (&[1u8, 1, 1, 1][..], 20u64)] {
        let mut out = [0u8; 1024];
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: t,
        };
        make_credential(&mut ctx, &mc_request_user(uid), &mut out).unwrap();
    }

    // getAssertion (no allowList) with the touch DECLINED → OPERATION_DENIED,
    // and the multi-credential queue must be torn down, not left armed.
    let mut o1 = [0u8; 1024];
    {
        let mut presence = Decline;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 30,
        };
        assert_eq!(
            get_assertion(&mut ctx, &ga_request(None), &mut o1),
            Err(CtapError::OperationDenied)
        );
    }

    // getNextAssertion must refuse — no touchless assertion for the older cred.
    let mut o2 = [0u8; 1024];
    let mut presence = Decline;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 31,
    };
    assert_eq!(
        get_next_assertion(&mut ctx, &mut o2),
        Err(CtapError::NotAllowed)
    );
}

#[test]
fn multi_cred_user_identity_returned_with_uv() {
    // The uv side of the §6.2.2 privacy rule: with user verification a
    // multi-credential discovery returns the full user identity (id + name).
    let (mut fs, mut rng) = setup();
    let mut state = crate::FidoState::new();
    for (uid, t) in [(&[9u8, 8, 7, 6][..], 10u64), (&[1u8, 1, 1, 1][..], 20u64)] {
        let mut out = [0u8; 1024];
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: t,
        };
        make_credential(&mut ctx, &mc_request_user(uid), &mut out).unwrap();
    }

    // Arm a PIN + token and present a valid pinUvAuthParam, no allowList
    // (so the discovery returns multiple credentials) → uv is set.
    let token = arm_pin(&mut fs, &mut state);
    let mut param = [0u8; 32];
    let plen = rsk_crypto::pinproto::authenticate(PinProto::Two, &token, &CDH, &mut param).unwrap();
    let req = {
        let mut buf = [0u8; 256];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(4).unwrap();
            e.u8(1).unwrap().str("example.com").unwrap();
            e.u8(2).unwrap().bytes(&CDH).unwrap();
            e.u8(6).unwrap().bytes(&param[..plen]).unwrap();
            e.u8(7).unwrap().u64(2).unwrap();
            e.writer().position()
        };
        buf[..n].to_vec()
    };
    let mut o = [0u8; 1024];
    let n = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 30,
        };
        get_assertion(&mut ctx, &req, &mut o).unwrap()
    };
    let (_u, count) = user_and_count(&o[..n]);
    assert_eq!(count, Some(2));
    assert_eq!(user_name_of(&o[..n]), "user");
}

// A resident makeCredential request carrying a credProtect level.
fn mc_request_credprotect(level: u64) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(6).unwrap();
        e.u8(1).unwrap().bytes(&CDH).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str("example.com")
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&[9, 8, 7, 6]).unwrap();
        e.str("name").unwrap().str("bob").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(6)
            .unwrap()
            .map(1)
            .unwrap()
            .str("credProtect")
            .unwrap()
            .u64(level)
            .unwrap();
        e.u8(7)
            .unwrap()
            .map(1)
            .unwrap()
            .str("rk")
            .unwrap()
            .bool(true)
            .unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

fn run_mc(fs: &mut Fs<RamStorage>, rng: &mut SeqRng, req: &[u8]) -> std::vec::Vec<u8> {
    let mut out = [0u8; 1024];
    let mut state = crate::FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs,
        rng,
        state: &mut state,
        now_ms: 10,
    };
    let n = make_credential(&mut ctx, req, &mut out).unwrap();
    out[..n].to_vec()
}

fn run_ga(fs: &mut Fs<RamStorage>, rng: &mut SeqRng, req: &[u8]) -> CtapResult {
    let mut out = [0u8; 1024];
    let mut state = crate::FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs,
        rng,
        state: &mut state,
        now_ms: 20,
    };
    get_assertion(&mut ctx, req, &mut out).map(|n| out[..n].to_vec().len())
}

#[test]
fn credprotect_optional_with_list_hidden_in_discovery() {
    let (mut fs, mut rng) = setup();
    // Register a UV-optional-with-list (level 2) resident credential.
    let mc = run_mc(&mut fs, &mut rng, &mc_request_credprotect(2));
    let (resident_id, x, y) = parse_mc(&mc);

    // Resident discovery (no allowList) without UV → hidden → NoCredentials.
    assert_eq!(
        run_ga(&mut fs, &mut rng, &ga_request(None)),
        Err(CtapError::NoCredentials)
    );

    // The same credential via an allowList is visible.
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
            now_ms: 20,
        };
        get_assertion(&mut ctx, &ga_request(Some(&resident_id)), &mut out).unwrap()
    };
    verify_assertion(&out[..n], &x, &y);
}

#[test]
fn credprotect_uv_required_hidden_even_with_allow_list() {
    let (mut fs, mut rng) = setup();
    // Register a UV-required (level 3) resident credential.
    let mc = run_mc(&mut fs, &mut rng, &mc_request_credprotect(3));
    let (resident_id, _x, _y) = parse_mc(&mc);

    // Hidden in discovery and via the allowList without UV.
    assert_eq!(
        run_ga(&mut fs, &mut rng, &ga_request(None)),
        Err(CtapError::NoCredentials)
    );
    assert_eq!(
        run_ga(&mut fs, &mut rng, &ga_request(Some(&resident_id))),
        Err(CtapError::NoCredentials)
    );
}

// A resident makeCredential request carrying a credBlob.
fn mc_request_credblob(blob: &[u8]) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(6).unwrap();
        e.u8(1).unwrap().bytes(&CDH).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str("example.com")
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&[9, 8, 7, 6]).unwrap();
        e.str("name").unwrap().str("bob").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(6)
            .unwrap()
            .map(1)
            .unwrap()
            .str("credBlob")
            .unwrap()
            .bytes(blob)
            .unwrap();
        e.u8(7)
            .unwrap()
            .map(1)
            .unwrap()
            .str("rk")
            .unwrap()
            .bool(true)
            .unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

fn ga_request_credblob(allow: &[u8]) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(4).unwrap();
        e.u8(1).unwrap().str("example.com").unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(3).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.str("id").unwrap().bytes(allow).unwrap();
        e.u8(4)
            .unwrap()
            .map(1)
            .unwrap()
            .str("credBlob")
            .unwrap()
            .bool(true)
            .unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

fn assertion_auth_data(resp: &[u8]) -> std::vec::Vec<u8> {
    let mut d = Decoder::new(resp);
    let fields = d.map().unwrap().unwrap();
    let mut ad = std::vec::Vec::new();
    for _ in 0..fields {
        if d.u8().unwrap() == 2 {
            ad = d.bytes().unwrap().to_vec();
        } else {
            d.skip().unwrap();
        }
    }
    ad
}

#[test]
fn credblob_echoed_in_assertion() {
    let (mut fs, mut rng) = setup();
    let mc = run_mc(&mut fs, &mut rng, &mc_request_credblob(&[0x11, 0x22, 0x33]));
    let (resident_id, x, y) = parse_mc(&mc);

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
            now_ms: 20,
        };
        get_assertion(&mut ctx, &ga_request_credblob(&resident_id), &mut out).unwrap()
    };
    verify_assertion(&out[..n], &x, &y);
    let ad = assertion_auth_data(&out[..n]);
    assert_eq!(ad[32] & FLAG_ED, FLAG_ED, "ED flag set");
    // authData extension map: credBlob bytes echoed from the stored credential.
    let mut d = Decoder::new(&ad[37..]);
    assert_eq!(d.map().unwrap().unwrap(), 1);
    assert_eq!(d.str().unwrap(), "credBlob");
    assert_eq!(d.bytes().unwrap(), &[0x11, 0x22, 0x33]);
}

/// getInfo advertises `maxCredBlobLength`, and §12.2 has the platform send anything
/// up to and including it — so exactly that many bytes must round-trip. One byte more
/// is refused, and makeCredential says so with `credBlob: false`.
#[test]
fn credblob_at_the_advertised_maximum_round_trips() {
    let (mut fs, mut rng) = setup();
    let blob = [0x7Eu8; crate::consts::MAX_CREDBLOB_LENGTH];
    let mc = run_mc(&mut fs, &mut rng, &mc_request_credblob(&blob));
    let (resident_id, x, y) = parse_mc(&mc);

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
            now_ms: 20,
        };
        get_assertion(&mut ctx, &ga_request_credblob(&resident_id), &mut out).unwrap()
    };
    verify_assertion(&out[..n], &x, &y);
    let ad = assertion_auth_data(&out[..n]);
    let mut d = Decoder::new(&ad[37..]);
    assert_eq!(d.map().unwrap().unwrap(), 1);
    assert_eq!(d.str().unwrap(), "credBlob");
    assert_eq!(d.bytes().unwrap(), &blob[..]);

    // One byte over the advertised maximum: not stored, and reported as such.
    let over = [0x7Eu8; crate::consts::MAX_CREDBLOB_LENGTH + 1];
    let mc = run_mc(&mut fs, &mut rng, &mc_request_credblob(&over));
    let (resident_id, ..) = parse_mc(&mc);
    let n = {
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 30,
        };
        get_assertion(&mut ctx, &ga_request_credblob(&resident_id), &mut out).unwrap()
    };
    let ad = assertion_auth_data(&out[..n]);
    let mut d = Decoder::new(&ad[37..]);
    d.map().unwrap();
    assert_eq!(d.str().unwrap(), "credBlob");
    assert!(
        d.bytes().unwrap().is_empty(),
        "an over-long blob is not kept"
    );
}

// A resident makeCredential request that opts into largeBlobKey (+ hmac-secret).
fn mc_request_lbk_hmac() -> std::vec::Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(6).unwrap();
        e.u8(1).unwrap().bytes(&CDH).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str("example.com")
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(&[9, 8, 7, 6]).unwrap();
        e.str("name").unwrap().str("bob").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(6).unwrap().map(2).unwrap();
        e.str("hmac-secret").unwrap().bool(true).unwrap();
        e.str("largeBlobKey").unwrap().bool(true).unwrap();
        e.u8(7)
            .unwrap()
            .map(1)
            .unwrap()
            .str("rk")
            .unwrap()
            .bool(true)
            .unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

// The stored credential box for EF_CRED slot 0, and the device seed.
fn stored_box_and_seed(fs: &mut Fs<RamStorage>) -> (std::vec::Vec<u8>, [u8; 32]) {
    let mut rec = [0u8; 1024];
    let n = fs.read(EF_CRED, &mut rec).unwrap();
    let seed = crate::seed::load_keydev(&dev(), fs).unwrap();
    (cred_record_box(&rec[..n]).to_vec(), seed)
}

fn cose_xy(e: &mut Encoder<Cursor<&mut [u8]>>, x: &[u8; 32], y: &[u8; 32]) {
    e.map(5).unwrap();
    e.u8(1).unwrap().u8(2).unwrap(); // kty EC2
    e.u8(3).unwrap().i64(-25).unwrap(); // alg ECDH
    e.i8(-1).unwrap().u8(1).unwrap(); // crv P-256
    e.i8(-2).unwrap().bytes(x).unwrap();
    e.i8(-3).unwrap().bytes(y).unwrap();
}

fn ga_request_hmac(
    allow: &[u8],
    px: &[u8; 32],
    py: &[u8; 32],
    se: &[u8],
    sa: &[u8],
) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(4).unwrap();
        e.u8(1).unwrap().str("example.com").unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(3).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.str("id").unwrap().bytes(allow).unwrap();
        e.u8(4).unwrap().map(1).unwrap();
        e.str("hmac-secret").unwrap().map(4).unwrap();
        e.u8(1).unwrap();
        cose_xy(&mut e, px, py);
        e.u8(2).unwrap().bytes(se).unwrap();
        e.u8(3).unwrap().bytes(sa).unwrap();
        e.u8(4).unwrap().u8(2).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

#[test]
fn hmac_secret_assertion_end_to_end() {
    use rsk_crypto::pinproto::{authenticate, ecdh, encrypt, public_xy};
    let (mut fs, mut rng) = setup();
    let mut state = crate::FidoState::new();
    state.regenerate(&mut rng); // the clientPIN getKeyAgreement ephemeral key
    let (ax, ay) = state.ephemeral_public().unwrap();

    let mc = run_mc_state(&mut fs, &mut rng, &mut state, &mc_request_lbk_hmac());
    let (resident_id, _x, _y) = parse_mc(&mc);

    // Platform half (protocol two): ECDH, encrypt the salt, MAC it.
    let plat = {
        let mut s = [0u8; 32];
        s[0] = 0x22;
        s[31] = 0x22;
        s
    };
    let (px, py) = public_xy(&plat).unwrap();
    let mut shared = [0u8; 64];
    let slen = ecdh(PinProto::Two, &plat, &ax, &ay, &mut shared).unwrap();
    let salt = [0x77u8; 32];
    let iv = [0x01u8; 16];
    let mut se = [0u8; 48];
    let ne = encrypt(PinProto::Two, &shared[..slen], &iv, &salt, &mut se).unwrap();
    let mut sa = [0u8; 32];
    let na = authenticate(PinProto::Two, &shared[..slen], &se[..ne], &mut sa).unwrap();

    let req = ga_request_hmac(&resident_id, &px, &py, &se[..ne], &sa[..na]);
    let mut out = [0u8; 1024];
    let n = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 20,
        };
        get_assertion(&mut ctx, &req, &mut out).unwrap()
    };
    let ad = assertion_auth_data(&out[..n]);
    assert_eq!(ad[32] & FLAG_ED, FLAG_ED);

    // Pull the hmac-secret output from the authData extensions and decrypt it.
    let mut d = Decoder::new(&ad[37..]);
    assert_eq!(d.map().unwrap().unwrap(), 1);
    assert_eq!(d.str().unwrap(), "hmac-secret");
    let hmac_out = d.bytes().unwrap();
    assert_eq!(hmac_out.len(), 48); // v2: 16 IV + 32
    let mut dec = [0u8; 32];
    rsk_crypto::pinproto::decrypt(PinProto::Two, &shared[..slen], hmac_out, &mut dec).unwrap();

    // It must equal HMAC(CredRandomWithoutUV, salt) for the stored credential.
    // A v2 resident credential keys hmac-secret off the stable resident id, not
    // the box, so the reseal-stable id is the expected derivation input.
    let (_cred_box, seed) = stored_box_and_seed(&mut fs);
    let cr = crate::credential::derive_hmac_key(&seed, &resident_id[..]);
    assert_eq!(&dec[..], &rsk_crypto::hmac_sha256(&cr[..32], &salt)[..]);
}

fn run_mc_state(
    fs: &mut Fs<RamStorage>,
    rng: &mut SeqRng,
    state: &mut crate::FidoState,
    req: &[u8],
) -> std::vec::Vec<u8> {
    let mut out = [0u8; 1024];
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs,
        rng,
        state,
        now_ms: 10,
    };
    let n = make_credential(&mut ctx, req, &mut out).unwrap();
    out[..n].to_vec()
}

// An updateUserInformation (credMgmt 0x07) request that reseals `cred_id`'s box
// with a new name (same user id), MAC'd under `token` (protocol 2). The
// subCommandParams are encoded once and embedded verbatim — the device re-MACs
// exactly those bytes, so the request must carry the identical encoding.
fn cm_update_request(
    cred_id: &[u8],
    uid: &[u8],
    name: &str,
    token: &[u8; 32],
) -> std::vec::Vec<u8> {
    use rsk_crypto::pinproto::authenticate;
    let mut sp = [0u8; 256];
    let spn = {
        let mut e = Encoder::new(Cursor::new(&mut sp[..]));
        e.map(2).unwrap();
        e.u8(2).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(cred_id).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(3).unwrap().map(3).unwrap();
        e.str("id").unwrap().bytes(uid).unwrap();
        e.str("name").unwrap().str(name).unwrap();
        e.str("displayName").unwrap().str(name).unwrap();
        e.writer().position()
    };
    let subpara = &sp[..spn];

    let mut payload = std::vec![0x07u8];
    payload.extend_from_slice(subpara);
    let mut mac = [0u8; 32];
    let mlen = authenticate(PinProto::Two, token, &payload, &mut mac).unwrap();

    let mut req = std::vec::Vec::new();
    req.push(0xA4); // map(4)
    req.extend_from_slice(&[0x01, 0x07]); // 1: subCommand = updateUserInformation
    req.push(0x02); // 2: subCommandParams (raw, re-MAC'd verbatim)
    req.extend_from_slice(subpara);
    req.extend_from_slice(&[0x03, 0x02]); // 3: pinUvAuthProtocol = 2
    req.push(0x04); // 4: pinUvAuthParam
    req.push(0x58); // byte string, 1-byte length prefix
    req.push(mlen as u8);
    req.extend_from_slice(&mac[..mlen]);
    req
}

// Drive updateUserInformation to reseal `cred_id` (fresh IV → new box), under a
// freshly-armed credentialManagement token.
fn reseal_credential(
    fs: &mut Fs<RamStorage>,
    rng: &mut SeqRng,
    cred_id: &[u8],
    uid: &[u8],
    name: &str,
) {
    let token = [0x99u8; 32];
    let mut state = crate::FidoState::new();
    state.paut.token = token;
    state.paut.permissions = crate::state::PERM_CM;
    state.begin_using_token(false, 0);
    let req = cm_update_request(cred_id, uid, name, &token);
    let mut out = [0u8; 512];
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs,
        rng,
        state: &mut state,
        now_ms: 50,
    };
    let n = crate::credmgmt::cred_mgmt(&mut ctx, &req, &mut out).unwrap();
    assert_eq!(
        n, 0,
        "updateUserInformation replies with only the status byte"
    );
}

// The decrypted (IV-stripped) hmac-secret extension output carried in an
// assertion's authData, under the platform's shared secret.
fn hmac_secret_plaintext(resp: &[u8], shared: &[u8]) -> std::vec::Vec<u8> {
    let ad = assertion_auth_data(resp);
    assert_eq!(ad[32] & FLAG_ED, FLAG_ED, "extension output present");
    let mut d = Decoder::new(&ad[37..]);
    assert_eq!(d.map().unwrap().unwrap(), 1);
    assert_eq!(d.str().unwrap(), "hmac-secret");
    let ct = d.bytes().unwrap();
    let mut dec = [0u8; 32];
    let n = rsk_crypto::pinproto::decrypt(PinProto::Two, shared, ct, &mut dec).unwrap();
    dec[..n].to_vec()
}

// #3 hmac-secret, end to end across a REAL updateUserInformation reseal. Register
// a resident credential with hmac-secret, evaluate hmac-secret through
// getAssertion (the full ECDH + hmacsecret::eval path), run updateUserInformation
// — which reseals the box with a fresh IV — then evaluate hmac-secret AGAIN. The
// decrypted secret must be identical: a v2 credential keys cred_random off the
// STABLE resident id, not the (rotated) box, so the platform's stored secret
// survives the update. Neuter the marker (v2→v1) and this fails — the box changes
// and dec2 diverges from dec1. This complements the derivation-level unit test
// [`credential::resident_key_input`] with the full command path.
#[test]
fn hmac_secret_survives_updateuserinfo_reseal_end_to_end() {
    use rsk_crypto::pinproto::{authenticate, ecdh, encrypt, public_xy};
    let (mut fs, mut rng) = setup();
    let mut state = crate::FidoState::new();
    state.regenerate(&mut rng); // the clientPIN getKeyAgreement ephemeral key
    let (ax, ay) = state.ephemeral_public().unwrap();

    let mc = run_mc_state(&mut fs, &mut rng, &mut state, &mc_request_lbk_hmac());
    let (resident_id, ..) = parse_mc(&mc);
    assert_ne!(
        &resident_id[4..8],
        b"\xf1\xd0\x02\x03",
        "new resident id is prefix-free v4"
    );

    // Platform half (protocol two): ECDH against the authenticator ephemeral,
    // encrypt the salt, MAC it. Fixed across both evaluations.
    let plat = {
        let mut s = [0u8; 32];
        s[0] = 0x22;
        s[31] = 0x22;
        s
    };
    let (px, py) = public_xy(&plat).unwrap();
    let mut shared = [0u8; 64];
    let slen = ecdh(PinProto::Two, &plat, &ax, &ay, &mut shared).unwrap();
    let salt = [0x77u8; 32];
    let iv = [0x01u8; 16];
    let mut se = [0u8; 48];
    let ne = encrypt(PinProto::Two, &shared[..slen], &iv, &salt, &mut se).unwrap();
    let mut sa = [0u8; 32];
    let na = authenticate(PinProto::Two, &shared[..slen], &se[..ne], &mut sa).unwrap();
    let req = ga_request_hmac(&resident_id, &px, &py, &se[..ne], &sa[..na]);

    // First evaluation (before the reseal).
    let dec1 = {
        let mut out = [0u8; 1024];
        let n = {
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 20,
            };
            get_assertion(&mut ctx, &req, &mut out).unwrap()
        };
        hmac_secret_plaintext(&out[..n], &shared[..slen])
    };

    // updateUserInformation reseals the box with a fresh IV — the stored box MUST
    // change, else box-derived keys could pass this test spuriously.
    let box_before = stored_box_and_seed(&mut fs).0;
    reseal_credential(&mut fs, &mut rng, &resident_id, &[9, 8, 7, 6], "bob2");
    let box_after = stored_box_and_seed(&mut fs).0;
    assert_ne!(
        box_before, box_after,
        "reseal must rotate the box (fresh IV)"
    );

    // Second evaluation (after the reseal). A fresh per-call IV makes the
    // ciphertext differ, but the decrypted secret must be identical.
    let dec2 = {
        let mut out = [0u8; 1024];
        let n = {
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 30,
            };
            get_assertion(&mut ctx, &req, &mut out).unwrap()
        };
        hmac_secret_plaintext(&out[..n], &shared[..slen])
    };

    // The property this test adds: the hmac-secret secret survives the reseal.
    assert_eq!(
        dec1, dec2,
        "hmac-secret output must survive an updateUserInformation reseal"
    );
    // And it is the correct HMAC(CredRandomWithoutUV, salt), keyed off the STABLE
    // resident id rather than the rotated box.
    let seed = crate::seed::load_keydev(&dev(), &mut fs).unwrap();
    let cr = crate::credential::derive_hmac_key(&seed, &resident_id[..]);
    assert_eq!(dec1, rsk_crypto::hmac_sha256(&cr[..32], &salt).to_vec());
}

// The CTAP 2.1 large-blob design, which a `largeblob-ext` build withdraws
// wholesale (§12.4: "Authenticators MUST NOT support both extensions").
#[cfg(not(feature = "largeblob-ext"))]
#[test]
fn large_blob_key_in_assertion() {
    let (mut fs, mut rng) = setup();
    let mut state = crate::FidoState::new();
    let mc = run_mc_state(&mut fs, &mut rng, &mut state, &mc_request_lbk_hmac());
    let (resident_id, _x, _y) = parse_mc(&mc);

    // getAssertion requesting largeBlobKey → response field 0x07 with the key.
    let mut buf = [0u8; 512];
    let req = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(4).unwrap();
        e.u8(1).unwrap().str("example.com").unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(3).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.str("id").unwrap().bytes(&resident_id).unwrap();
        e.u8(4)
            .unwrap()
            .map(1)
            .unwrap()
            .str("largeBlobKey")
            .unwrap()
            .bool(true)
            .unwrap();
        let n = e.writer().position();
        buf[..n].to_vec()
    };
    let mut out = [0u8; 1024];
    let n = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 20,
        };
        get_assertion(&mut ctx, &req, &mut out).unwrap()
    };
    // Field 0x07 is the 32-byte largeBlobKey for this credential.
    let mut d = Decoder::new(&out[..n]);
    let fields = d.map().unwrap().unwrap();
    let mut lbk = None;
    for _ in 0..fields {
        if d.u8().unwrap() == 7 {
            lbk = Some(d.bytes().unwrap().to_vec());
        } else {
            d.skip().unwrap();
        }
    }
    // v2 resident: largeBlobKey keys off the stable resident id, not the box.
    let (_cred_box, seed) = stored_box_and_seed(&mut fs);
    let expected = crate::credential::derive_large_blob_key(&seed, &resident_id[..]);
    assert_eq!(lbk.as_deref(), Some(&expected[..]));
}

// makeCredential request offering a single non-default algorithm.
fn mc_request_alg(alg: i64) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(4).unwrap();
        e.u8(1).unwrap().bytes(&CDH).unwrap();
        e.u8(2).unwrap().map(1).unwrap();
        e.str("id").unwrap().str("example.com").unwrap();
        e.u8(3).unwrap().map(1).unwrap();
        e.str("id").unwrap().bytes(&[7, 7, 7, 7]).unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(alg).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

// makeCredential authData → (credId, cose x, cose y) for any EC2 curve.
fn parse_mc_ec2(resp: &[u8]) -> (std::vec::Vec<u8>, std::vec::Vec<u8>, std::vec::Vec<u8>) {
    let mut d = Decoder::new(resp);
    assert!(d.map().unwrap().unwrap() >= 3);
    assert_eq!(d.u8().unwrap(), 1);
    assert_eq!(d.str().unwrap(), ATT_FMT);
    assert_eq!(d.u8().unwrap(), 2);
    let ad = d.bytes().unwrap();
    let cred_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    let cred_id = ad[55..55 + cred_len].to_vec();
    let mut cd = Decoder::new(&ad[55 + cred_len..]);
    assert_eq!(cd.map().unwrap().unwrap(), 5);
    cd.u8().unwrap();
    cd.u8().unwrap(); // 1: kty 2
    cd.u8().unwrap();
    cd.i64().unwrap(); // 3: alg
    cd.i8().unwrap();
    cd.u8().unwrap(); // -1: crv
    cd.i8().unwrap();
    let x = cd.bytes().unwrap().to_vec(); // -2
    cd.i8().unwrap();
    let y = cd.bytes().unwrap().to_vec(); // -3
    (cred_id, x, y)
}

fn assertion_sig(resp: &[u8]) -> std::vec::Vec<u8> {
    let mut d = Decoder::new(resp);
    let fields = d.map().unwrap().unwrap();
    let mut sig = std::vec::Vec::new();
    for _ in 0..fields {
        if d.u8().unwrap() == 3 {
            sig = d.bytes().unwrap().to_vec();
        } else {
            d.skip().unwrap();
        }
    }
    sig
}

#[test]
fn es384_register_then_login_verifies() {
    use crate::consts::ALG_ES384;
    use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    let (mut fs, mut rng) = setup();

    // Register a P-384 (ES384) credential and pull its COSE public key.
    let mut o1 = [0u8; 1024];
    let mc = {
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 10,
        };
        let n = make_credential(&mut ctx, &mc_request_alg(ALG_ES384), &mut o1).unwrap();
        o1[..n].to_vec()
    };
    let (cred_id, x, y) = parse_mc_ec2(&mc);
    assert_eq!(x.len(), 48, "P-384 coordinates are 48 bytes");

    // Log in with the credential and verify the assertion under the P-384 key.
    let mut o2 = [0u8; 1024];
    let ga = {
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 20,
        };
        let n = get_assertion(&mut ctx, &ga_request(Some(&cred_id)), &mut o2).unwrap();
        o2[..n].to_vec()
    };
    let ad = assertion_auth_data(&ga);
    let sig = assertion_sig(&ga);
    let pt = p384::Sec1Point::from_bytes(&crate::ec::sec1_uncompressed(x, y)).unwrap();
    let vk = VerifyingKey::from_sec1_point(&pt).unwrap();
    let mut signed = ad;
    signed.extend_from_slice(&CDH);
    vk.verify(&signed, &Signature::from_der(&sig).unwrap())
        .expect("ES384 assertion verifies under the credential key");
}

// makeCredential authData → (credId, OKP pubkey) for Ed25519.
fn parse_mc_okp(resp: &[u8]) -> (std::vec::Vec<u8>, [u8; 32]) {
    let mut d = Decoder::new(resp);
    assert!(d.map().unwrap().unwrap() >= 3);
    assert_eq!(d.u8().unwrap(), 1);
    assert_eq!(d.str().unwrap(), ATT_FMT);
    assert_eq!(d.u8().unwrap(), 2);
    let ad = d.bytes().unwrap();
    let cred_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    let cred_id = ad[55..55 + cred_len].to_vec();
    let mut cd = Decoder::new(&ad[55 + cred_len..]);
    assert_eq!(cd.map().unwrap().unwrap(), 4);
    cd.u8().unwrap();
    assert_eq!(cd.u8().unwrap(), 1); // kty OKP
    cd.u8().unwrap();
    cd.i64().unwrap(); // alg
    cd.i8().unwrap();
    cd.u8().unwrap(); // crv
    cd.i8().unwrap();
    let pk: [u8; 32] = cd.bytes().unwrap().try_into().unwrap();
    (cred_id, pk)
}

#[test]
fn ed25519_register_then_login_verifies() {
    use crate::consts::ALG_EDDSA;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let (mut fs, mut rng) = setup();

    let mut o1 = [0u8; 1024];
    let mc = {
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 10,
        };
        let n = make_credential(&mut ctx, &mc_request_alg(ALG_EDDSA), &mut o1).unwrap();
        o1[..n].to_vec()
    };
    let (cred_id, pk) = parse_mc_okp(&mc);

    let mut o2 = [0u8; 1024];
    let ga = {
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 20,
        };
        let n = get_assertion(&mut ctx, &ga_request(Some(&cred_id)), &mut o2).unwrap();
        o2[..n].to_vec()
    };
    let ad = assertion_auth_data(&ga);
    let sig = assertion_sig(&ga);
    let vk = VerifyingKey::from_bytes(&pk).unwrap();
    let mut signed = ad;
    signed.extend_from_slice(&CDH);
    vk.verify(&signed, &Signature::from_slice(&sig).unwrap())
        .expect("Ed25519 assertion verifies under the credential key");
}

#[test]
fn get_next_assertion_without_state_is_not_allowed() {
    let (mut fs, mut rng) = setup();
    let mut state = crate::FidoState::new();
    let mut out = [0u8; 64];
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
        get_next_assertion(&mut ctx, &mut out),
        Err(CtapError::NotAllowed)
    );
}

// ---- ML-DSA-44 (PQC) end-to-end ----

// Run one CTAP call against `fs` with a PQC-sized response buffer.
fn call(
    fs: &mut Fs<RamStorage>,
    rng: &mut SeqRng,
    now_ms: u64,
    f: impl FnOnce(&mut Ctx<RamStorage, SeqRng>, &mut [u8]) -> crate::error::CtapResult,
) -> Result<std::vec::Vec<u8>, CtapError> {
    let mut out = [0u8; 8192];
    let mut state = crate::FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs,
        rng,
        state: &mut state,
        now_ms,
    };
    let n = f(&mut ctx, &mut out)?;
    Ok(out[..n].to_vec())
}

// makeCredential authData → (credId, AKP alg, AKP pubkey) for ML-DSA.
fn parse_mc_akp(resp: &[u8]) -> (std::vec::Vec<u8>, i64, std::vec::Vec<u8>) {
    let mut d = Decoder::new(resp);
    assert!(d.map().unwrap().unwrap() >= 3);
    assert_eq!(d.u8().unwrap(), 1);
    assert_eq!(d.str().unwrap(), ATT_FMT);
    assert_eq!(d.u8().unwrap(), 2);
    let ad = d.bytes().unwrap();
    let cred_len = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    let cred_id = ad[55..55 + cred_len].to_vec();
    let mut cd = Decoder::new(&ad[55 + cred_len..]);
    assert_eq!(
        cd.map().unwrap().unwrap(),
        3,
        "AKP COSE key is a 3-entry map"
    );
    cd.u8().unwrap();
    assert_eq!(cd.u8().unwrap(), crate::consts::KTY_AKP); // 1: kty
    cd.u8().unwrap();
    let alg = cd.i64().unwrap(); // 3: alg
    cd.i8().unwrap(); // -1: pub
    let pk = cd.bytes().unwrap().to_vec();
    (cred_id, alg, pk)
}

// Assert the makeCredential attestation shape: fmt "packed" (field 1) with a
// three-entry `{alg, sig, x5c}` statement (field 3), whatever the credential
// algorithm is.
fn assert_basic_att_stmt(resp: &[u8]) {
    let mut d = Decoder::new(resp);
    let fields = d.map().unwrap().unwrap();
    let mut saw_fmt = false;
    let mut saw_stmt = false;
    for _ in 0..fields {
        match d.u8().unwrap() {
            1 => {
                assert_eq!(d.str().unwrap(), ATT_FMT);
                saw_fmt = true;
            }
            3 => {
                assert_eq!(
                    d.map().unwrap().unwrap(),
                    3,
                    "attStmt carries alg, sig and x5c"
                );
                d.skip().unwrap();
                assert_eq!(d.i64().unwrap(), ALG_ES256, "attestation alg is ES256");
                saw_stmt = true;
                break;
            }
            _ => d.skip().unwrap(),
        }
    }
    assert!(saw_fmt && saw_stmt);
}

fn mldsa_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let pk: [u8; rsk_crypto::MLDSA44_PK_LEN] = pk.try_into().expect("AKP pk length");
    let sig: [u8; rsk_crypto::MLDSA44_SIG_LEN] = sig.try_into().expect("ML-DSA sig length");
    rsk_crypto::mldsa44_verify(&pk, msg, &sig)
}

#[test]
fn mldsa44_register_then_login_verifies() {
    use crate::consts::ALG_MLDSA44;
    let (mut fs, mut rng) = setup();

    // Register: the self-attestation must verify under the AKP COSE key.
    let mc = call(&mut fs, &mut rng, 10, |ctx, out| {
        make_credential(ctx, &mc_request_alg(ALG_MLDSA44), out)
    })
    .unwrap();
    let (cred_id, alg, pk) = parse_mc_akp(&mc);
    assert_eq!(alg, ALG_MLDSA44);
    assert_eq!(pk.len(), rsk_crypto::MLDSA44_PK_LEN);
    // The attestation is ES256 by the device key whatever the credential algorithm
    // is, so a post-quantum credential changes nothing about the statement.
    assert_basic_att_stmt(&mc);

    // Login with the returned credential id; the assertion signature must
    // verify under the same key.
    let ga = call(&mut fs, &mut rng, 20, |ctx, out| {
        get_assertion(ctx, &ga_request(Some(&cred_id)), out)
    })
    .unwrap();
    let ad = assertion_auth_data(&ga);
    let sig = assertion_sig(&ga);
    assert_eq!(sig.len(), rsk_crypto::MLDSA44_SIG_LEN);
    let mut signed = ad;
    signed.extend_from_slice(&CDH);
    assert!(
        mldsa_verify(&pk, &signed, &sig),
        "ML-DSA-44 assertion verifies under the credential key"
    );
}

fn mldsa65_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let pk: [u8; rsk_crypto::MLDSA65_PK_LEN] = pk.try_into().expect("AKP pk length");
    let sig: [u8; rsk_crypto::MLDSA65_SIG_LEN] = sig.try_into().expect("ML-DSA sig length");
    rsk_crypto::mldsa65_verify(&pk, msg, &sig)
}

#[test]
fn mldsa65_register_then_login_verifies() {
    use crate::consts::ALG_MLDSA65;
    let (mut fs, mut rng) = setup();

    // Register: the self-attestation must verify under the AKP COSE key.
    let mc = call(&mut fs, &mut rng, 10, |ctx, out| {
        make_credential(ctx, &mc_request_alg(ALG_MLDSA65), out)
    })
    .unwrap();
    let (cred_id, alg, pk) = parse_mc_akp(&mc);
    assert_eq!(alg, ALG_MLDSA65);
    assert_eq!(pk.len(), rsk_crypto::MLDSA65_PK_LEN);
    // The attestation is ES256 by the device key whatever the credential algorithm
    // is, so a post-quantum credential changes nothing about the statement.
    assert_basic_att_stmt(&mc);

    // Login with the returned credential id; the assertion signature must
    // verify under the same key.
    let ga = call(&mut fs, &mut rng, 20, |ctx, out| {
        get_assertion(ctx, &ga_request(Some(&cred_id)), out)
    })
    .unwrap();
    let ad = assertion_auth_data(&ga);
    let sig = assertion_sig(&ga);
    assert_eq!(sig.len(), rsk_crypto::MLDSA65_SIG_LEN);
    let mut signed = ad;
    signed.extend_from_slice(&CDH);
    assert!(
        mldsa65_verify(&pk, &signed, &sig),
        "ML-DSA-65 assertion verifies under the credential key"
    );
}

// rk makeCredential with an explicit algorithm and user id (the upgrade flow).
fn mc_request_alg_rk(alg: i64, uid: &[u8]) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(5).unwrap();
        e.u8(1).unwrap().bytes(&CDH).unwrap();
        e.u8(2).unwrap().map(1).unwrap();
        e.str("id").unwrap().str("example.com").unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(uid).unwrap();
        e.str("name").unwrap().str("user").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(alg).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(7).unwrap().map(1).unwrap();
        e.str("rk").unwrap().bool(true).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// The classic→PQC upgrade: re-registering the same rp/user with ML-DSA-44
/// overwrites the resident slot (one credential, now PQC) while an old
/// *non-resident* ES256 credential id keeps asserting — the box is
/// self-contained, so downstream state survives the upgrade.
#[test]
fn classic_to_pqc_upgrade() {
    use crate::consts::{ALG_ES256, ALG_MLDSA44};
    use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
    let (mut fs, mut rng) = setup();
    let uid = [9u8, 9, 9];

    // An old non-resident ES256 credential (the box IS the credential id).
    let mc_old = call(&mut fs, &mut rng, 10, |ctx, out| {
        make_credential(ctx, &mc_request_alg(ALG_ES256), out)
    })
    .unwrap();
    let (old_id, x, y) = parse_mc_ec2(&mc_old);

    // A resident ES256 credential, then the PQC re-registration of the SAME
    // rp/user — the slot is overwritten, not duplicated.
    call(&mut fs, &mut rng, 20, |ctx, out| {
        make_credential(ctx, &mc_request_alg_rk(ALG_ES256, &uid), out)
    })
    .unwrap();
    let mc_pqc = call(&mut fs, &mut rng, 30, |ctx, out| {
        make_credential(ctx, &mc_request_alg_rk(ALG_MLDSA44, &uid), out)
    })
    .unwrap();
    let (_, alg, pqc_pk) = parse_mc_akp(&mc_pqc);
    assert_eq!(alg, ALG_MLDSA44);

    // Resident discovery: exactly one credential survives, and it signs
    // with ML-DSA-44.
    let ga = call(&mut fs, &mut rng, 40, |ctx, out| {
        get_assertion(ctx, &ga_request(None), out)
    })
    .unwrap();
    let (_, n_creds) = user_and_count(&ga);
    assert_eq!(n_creds, None, "a single credential omits the count");
    let sig = assertion_sig(&ga);
    assert_eq!(sig.len(), rsk_crypto::MLDSA44_SIG_LEN);
    let mut signed = assertion_auth_data(&ga);
    signed.extend_from_slice(&CDH);
    assert!(mldsa_verify(&pqc_pk, &signed, &sig));

    // The old non-resident ES256 id still works via allowList.
    let ga_old = call(&mut fs, &mut rng, 50, |ctx, out| {
        get_assertion(ctx, &ga_request(Some(&old_id)), out)
    })
    .unwrap();
    let sig = assertion_sig(&ga_old);
    let mut signed = assertion_auth_data(&ga_old);
    signed.extend_from_slice(&CDH);
    let pt = p256::Sec1Point::from_bytes(&crate::ec::sec1_uncompressed(x, y)).unwrap();
    let vk = VerifyingKey::from_sec1_point(&pt).unwrap();
    vk.verify(&signed, &Signature::from_der(&sig).unwrap())
        .expect("pre-upgrade ES256 credential still asserts");
}

// A ceiling-sized credential must round-trip. A 253-byte rpId (the DNS
// ceiling) plus overlong user strings (truncated to 64, CTAP 2.1 §6.1.2) and a
// credBlob pushes the box past the OLD 512-byte assert cap — the create/assert
// divergence stranded exactly these: create succeeded, then Best::consider
// silently skipped the id and every assertion ended NO_CREDENTIALS.
#[test]
fn near_ceiling_credential_roundtrips() {
    let (mut fs, mut rng) = setup();
    let rp = "a".repeat(249) + ".com";
    let uid = [0x42u8; 64];
    let long_name = "n".repeat(100);

    let mut buf = [0u8; 1024];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(5).unwrap();
        e.u8(1).unwrap().bytes(&CDH).unwrap();
        e.u8(2).unwrap().map(1).unwrap();
        e.str("id").unwrap().str(&rp).unwrap();
        e.u8(3).unwrap().map(3).unwrap();
        e.str("id").unwrap().bytes(&uid).unwrap();
        e.str("name").unwrap().str(&long_name).unwrap();
        e.str("displayName").unwrap().str(&long_name).unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(6).unwrap().map(1).unwrap();
        e.str("credBlob").unwrap().bytes(&[0x5A; 32]).unwrap();
        e.writer().position()
    };
    let mc_req = buf[..n].to_vec();

    let mut out = [0u8; 2048];
    let mc = {
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 10,
        };
        let n = make_credential(&mut ctx, &mc_req, &mut out).unwrap();
        out[..n].to_vec()
    };
    let (cred_id, x, y) = parse_mc(&mc);
    assert!(
        cred_id.len() > 512,
        "box must cross the old assert cap (len {})",
        cred_id.len()
    );
    assert!(cred_id.len() <= crate::credential::CRED_BOX_MAX);

    let mut gbuf = [0u8; 1024];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut gbuf[..]));
        e.map(3).unwrap();
        e.u8(1).unwrap().str(&rp).unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(3).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.str("id").unwrap().bytes(&cred_id).unwrap();
        e.writer().position()
    };
    let ga_req = gbuf[..n].to_vec();

    let mut out2 = [0u8; 2048];
    let ga = {
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 20,
        };
        let n = get_assertion(&mut ctx, &ga_req, &mut out2).unwrap();
        out2[..n].to_vec()
    };
    verify_assertion(&ga, &x, &y);
}

// The TRUE maximal box — 253-byte rpId + 64-byte user.id + 64-byte names + a
// 127-byte credBlob + hmac-secret — must create and assert. This box is
// ~670-748 bytes, well over the old 640 ceiling that CRED_BOX_MAX=640 (a
// literal that omitted credBlob + extensions) silently rejected as Other.
#[test]
fn maximal_box_creates_and_asserts() {
    let (mut fs, mut rng) = setup();
    let rp = "a".repeat(249) + ".com"; // 253 bytes, DNS max
    let uid = [0x42u8; 64];
    let long = "n".repeat(100); // truncated to 64 at seal

    let mut buf = [0u8; 2048];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(5).unwrap();
        e.u8(1).unwrap().bytes(&CDH).unwrap();
        e.u8(2).unwrap().map(1).unwrap();
        e.str("id").unwrap().str(&rp).unwrap();
        e.u8(3).unwrap().map(3).unwrap();
        e.str("id").unwrap().bytes(&uid).unwrap();
        e.str("name").unwrap().str(&long).unwrap();
        e.str("displayName").unwrap().str(&long).unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(6).unwrap().map(2).unwrap();
        e.str("credBlob").unwrap().bytes(&[0x5A; 127]).unwrap();
        e.str("hmac-secret").unwrap().bool(true).unwrap();
        e.writer().position()
    };
    let mc_req = buf[..n].to_vec();

    let mut out = [0u8; 2048];
    let mc = {
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: u64::MAX, // largest createdMs → widest box
        };
        let n = make_credential(&mut ctx, &mc_req, &mut out).unwrap();
        out[..n].to_vec()
    };
    let (cred_id, x, y) = parse_mc(&mc);
    assert!(
        cred_id.len() > 640,
        "box must cross the old 640 cap (len {})",
        cred_id.len()
    );
    assert!(cred_id.len() <= crate::credential::CRED_BOX_MAX);

    let mut gbuf = [0u8; 1024];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut gbuf[..]));
        e.map(3).unwrap();
        e.u8(1).unwrap().str(&rp).unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(3).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.str("id").unwrap().bytes(&cred_id).unwrap();
        e.writer().position()
    };
    let mut out2 = [0u8; 2048];
    let ga = {
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 20,
        };
        let n = get_assertion(&mut ctx, &gbuf[..n], &mut out2).unwrap();
        out2[..n].to_vec()
    };
    verify_assertion(&ga, &x, &y);
}

// An rpId or user.id past its ceiling is rejected explicitly (InvalidLength),
// not by a downstream box overflow that would surface as a vague Other.
#[test]
fn overlong_rpid_or_userid_rejected() {
    let (mut fs, mut rng) = setup();
    let over_rp = "a".repeat(251) + ".com"; // 255 > RP_ID_MAX(253)
    let mk = |rp: &str, uid: &[u8]| {
        let mut buf = [0u8; 512];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(4).unwrap();
            e.u8(1).unwrap().bytes(&CDH).unwrap();
            e.u8(2).unwrap().map(1).unwrap();
            e.str("id").unwrap().str(rp).unwrap();
            e.u8(3).unwrap().map(1).unwrap();
            e.str("id").unwrap().bytes(uid).unwrap();
            e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
            e.str("alg").unwrap().i64(ALG_ES256).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
            e.writer().position()
        };
        buf[..n].to_vec()
    };
    for req in [mk(&over_rp, &[1, 2, 3, 4]), mk("ok.com", &[0u8; 65])] {
        let mut out = [0u8; 512];
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 10,
        };
        assert_eq!(
            make_credential(&mut ctx, &req, &mut out),
            Err(CtapError::InvalidLength)
        );
    }
}

// Resident discovery + getNextAssertion must each sign with the credential's OWN
// key. For v2 credentials that key derives from the stable resident id, so this
// pins that BOTH signing sites (get_assertion and get_next_assertion) use it and
// agree with makeCredential's pubkey — get_next_assertion had no such
// signature-verify coverage before.
#[test]
fn discovery_and_getnext_sign_with_credential_keys() {
    let (mut fs, mut rng) = setup();
    let mut state = crate::FidoState::new();

    // Register two resident creds for the same rp; capture each (uid, pubkey).
    let mut keys: std::vec::Vec<([u8; 4], [u8; 32], [u8; 32])> = std::vec::Vec::new();
    for (uid, t) in [(&[9u8, 8, 7, 6][..], 10u64), (&[1u8, 1, 1, 1][..], 20u64)] {
        let mut out = [0u8; 1024];
        let n = {
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: t,
            };
            make_credential(&mut ctx, &mc_request_user(uid), &mut out).unwrap()
        };
        let (_id, x, y) = parse_mc(&out[..n]);
        let mut u = [0u8; 4];
        u.copy_from_slice(uid);
        keys.push((u, x, y));
    }
    let pick = |uid: &[u8]| -> ([u8; 32], [u8; 32]) {
        for (u, x, y) in &keys {
            if &u[..] == uid {
                return (*x, *y);
            }
        }
        panic!("uid not registered");
    };

    // Discovery getAssertion → newest credential; verify under its key.
    let mut o1 = [0u8; 1024];
    let n1 = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 30,
        };
        get_assertion(&mut ctx, &ga_request(None), &mut o1).unwrap()
    };
    let (u1, _c1) = user_and_count(&o1[..n1]);
    let (x1, y1) = pick(&u1);
    verify_assertion(&o1[..n1], &x1, &y1);

    // getNextAssertion → the older credential; verify under ITS key.
    let mut o2 = [0u8; 1024];
    let n2 = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 31,
        };
        get_next_assertion(&mut ctx, &mut o2).unwrap()
    };
    let (u2, _c2) = user_and_count(&o2[..n2]);
    assert_ne!(u1, u2, "two different credentials");
    let (x2, y2) = pick(&u2);
    verify_assertion(&o2[..n2], &x2, &y2);
}

// A resident makeCredential request (custom user id) that opts into hmac-secret.
fn mc_request_hmac_user(uid: &[u8]) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(6).unwrap();
        e.u8(1).unwrap().bytes(&CDH).unwrap();
        e.u8(2)
            .unwrap()
            .map(1)
            .unwrap()
            .str("id")
            .unwrap()
            .str("example.com")
            .unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(uid).unwrap();
        e.str("name").unwrap().str("user").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(6)
            .unwrap()
            .map(1)
            .unwrap()
            .str("hmac-secret")
            .unwrap()
            .bool(true)
            .unwrap();
        e.u8(7)
            .unwrap()
            .map(1)
            .unwrap()
            .str("rk")
            .unwrap()
            .bool(true)
            .unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

// A discovery (no allowList) getAssertion carrying an hmac-secret extension.
fn ga_request_hmac_discovery(
    px: &[u8; 32],
    py: &[u8; 32],
    se: &[u8],
    sa: &[u8],
) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(3).unwrap();
        e.u8(1).unwrap().str("example.com").unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(4).unwrap().map(1).unwrap();
        e.str("hmac-secret").unwrap().map(4).unwrap();
        e.u8(1).unwrap();
        cose_xy(&mut e, px, py);
        e.u8(2).unwrap().bytes(se).unwrap();
        e.u8(3).unwrap().bytes(sa).unwrap();
        e.u8(4).unwrap().u8(2).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

// #3 getNextAssertion path: the hmac-secret cred_random for the SECOND and later
// credentials in a resident discovery walk is evaluated in next_assertion_response
// — a site the single-entry-allowList hmac tests (which resolve inside
// get_assertion_inner) never reach. A v2 credential keys it off its stable resident
// id, so this pins that getNextAssertion, not just the first getAssertion, uses the
// credential's own resident-id-derived secret. Revert that site to the box and dec2
// stops matching the resident-id derivation.
#[test]
fn getnextassertion_hmac_secret_keys_off_resident_id() {
    use rsk_crypto::pinproto::{authenticate, ecdh, encrypt, public_xy};
    let (mut fs, mut rng) = setup();
    let mut state = crate::FidoState::new();
    state.regenerate(&mut rng); // the clientPIN getKeyAgreement ephemeral key
    let (ax, ay) = state.ephemeral_public().unwrap();

    // Two resident creds for one RP with hmac-secret (distinct users + times, so
    // discovery yields the newest and getNextAssertion the older).
    for (uid, t) in [(&[9u8, 8, 7, 6][..], 10u64), (&[1u8, 1, 1, 1][..], 20u64)] {
        let mut out = [0u8; 1024];
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: t,
        };
        make_credential(&mut ctx, &mc_request_hmac_user(uid), &mut out).unwrap();
    }

    // Platform half (protocol two), shared across both evaluations.
    let plat = {
        let mut s = [0u8; 32];
        s[0] = 0x22;
        s[31] = 0x22;
        s
    };
    let (px, py) = public_xy(&plat).unwrap();
    let mut shared = [0u8; 64];
    let slen = ecdh(PinProto::Two, &plat, &ax, &ay, &mut shared).unwrap();
    let salt = [0x77u8; 32];
    let iv = [0x01u8; 16];
    let mut se = [0u8; 48];
    let ne = encrypt(PinProto::Two, &shared[..slen], &iv, &salt, &mut se).unwrap();
    let mut sa = [0u8; 32];
    let na = authenticate(PinProto::Two, &shared[..slen], &se[..ne], &mut sa).unwrap();
    let req = ga_request_hmac_discovery(&px, &py, &se[..ne], &sa[..na]);

    let seed = crate::seed::load_keydev(&dev(), &mut fs).unwrap();
    let expected = |cred_id: &[u8]| {
        let cr = crate::credential::derive_hmac_key(&seed, cred_id);
        rsk_crypto::hmac_sha256(&cr[..32], &salt).to_vec()
    };

    // Discovery getAssertion → newest credential; its hmac output keys off its id.
    let mut o1 = [0u8; 1024];
    let n1 = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 30,
        };
        get_assertion(&mut ctx, &req, &mut o1).unwrap()
    };
    let id1 = cred_id_of(&o1[..n1]);
    let dec1 = hmac_secret_plaintext(&o1[..n1], &shared[..slen]);
    assert_eq!(
        dec1,
        expected(&id1),
        "first assertion keys hmac off its resident id"
    );

    // getNextAssertion → the older credential — the next_assertion_response site.
    let mut o2 = [0u8; 1024];
    let n2 = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 31,
        };
        get_next_assertion(&mut ctx, &mut o2).unwrap()
    };
    let id2 = cred_id_of(&o2[..n2]);
    let dec2 = hmac_secret_plaintext(&o2[..n2], &shared[..slen]);
    assert_ne!(id1, id2, "two distinct credentials");
    assert_eq!(
        dec2,
        expected(&id2),
        "getNextAssertion must key hmac-secret off the credential's stable resident id"
    );
    assert_ne!(
        dec1, dec2,
        "distinct credentials → distinct hmac-secret outputs"
    );
}

/// A trusted-display backend: it collects a PIN on its own pad **and** paints the
/// ceremony, recording what each `Confirm` named.
struct DisplayPad {
    touches: usize,
    last_title: &'static str,
    last_primary: std::vec::Vec<u8>,
}
impl DisplayPad {
    fn new() -> Self {
        Self {
            touches: 0,
            last_title: "",
            last_primary: std::vec::Vec::new(),
        }
    }
}
impl crate::UserPresence for DisplayPad {
    fn request(&mut self, c: crate::Confirm<'_>) -> crate::Presence {
        self.touches += 1;
        self.last_title = c.title;
        self.last_primary = c.primary.to_vec();
        crate::Presence::Confirmed
    }
    fn shows_confirm(&self) -> bool {
        true
    }
    fn uv_available(&self) -> bool {
        true
    }
    fn collect_pin(&mut self, _min: usize, out: &mut [u8]) -> crate::PinEntry {
        out[..4].copy_from_slice(b"1234");
        crate::PinEntry::Entered(4)
    }
}

#[test]
fn builtin_uv_still_names_the_rp_on_a_display() {
    // Audit run-28 F1. §6.2.2 step 8 lets the pad entry stand in for the *gesture*,
    // and the build used it to skip the whole ceremony — but `collect_pin` carries no
    // `Confirm` and `PinPad.title` is trusted `&'static str` by construction, so the
    // pad can never name a relying party. Skipping the card therefore traded one
    // context-free PIN entry for an assertion over an rp the user never saw. On a
    // backend that paints ceremonies the card must survive; the flags are unchanged.
    let (mut fs, mut rng) = setup();
    let cred_id = register_non_resident(&mut fs, &mut rng);
    crate::clientpin::store_local_pin(&dev(), &mut fs, b"1234").unwrap();
    let mut state = crate::FidoState::new();
    let mut out = [0u8; 1024];
    let mut pad = DisplayPad::new();
    let n = {
        let mut ctx = Ctx {
            presence: &mut pad,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        get_assertion(&mut ctx, &ga_request_uv(&cred_id, None), &mut out).unwrap()
    };
    let ad = assertion_auth_data(&out[..n]);
    assert_eq!(ad[32] & (FLAG_UP | FLAG_UV), FLAG_UP | FLAG_UV);
    assert_eq!(pad.touches, 1, "the naming card is painted exactly once");
    assert_eq!(pad.last_title, "Sign in?");
    assert_eq!(
        pad.last_primary, b"example.com",
        "the card carries the rp the assertion is for"
    );
}

/// A getAssertion whose allowList is `entries`, each a `(type, id)` descriptor.
fn ga_request_list(entries: &[(&str, &[u8])]) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 8192];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(3).unwrap();
        e.u8(1).unwrap().str("example.com").unwrap();
        e.u8(2).unwrap().bytes(&CDH).unwrap();
        e.u8(3).unwrap().array(entries.len() as u64).unwrap();
        for (ty, id) in entries {
            e.map(2).unwrap();
            e.str("type").unwrap().str(ty).unwrap();
            e.str("id").unwrap().bytes(id).unwrap();
        }
        e.writer().position()
    };
    buf[..n].to_vec()
}

// getInfo 0x07 advertises maxCredentialCountInList; an allowList longer than that
// is CTAP2_ERR_LIMIT_EXCEEDED so the platform knows to split it. Truncating instead
// answers "no such credential" for a credential this device holds — and the failure
// is invisible whenever the match happens to land in the retained head, which is
// why both orderings are asserted here.
#[test]
fn allow_list_over_max_is_limit_exceeded() {
    let (mut fs, mut rng) = setup();
    let cred_id = register_non_resident(&mut fs, &mut rng);
    let filler = [0xEEu8; 32];

    let mut entries = [("public-key", &filler[..]); MAX_ALLOW + 1];
    entries[MAX_ALLOW] = ("public-key", &cred_id[..]);
    assert_eq!(
        run_ga(&mut fs, &mut rng, &ga_request_list(&entries)),
        Err(CtapError::LimitExceeded),
        "an oversized allowList is refused, not silently truncated"
    );

    // Same list, target first: a truncating parser would answer this one and hide
    // the bug behind the ordering.
    entries[MAX_ALLOW] = ("public-key", &filler[..]);
    entries[0] = ("public-key", &cred_id[..]);
    assert_eq!(
        run_ga(&mut fs, &mut rng, &ga_request_list(&entries)),
        Err(CtapError::LimitExceeded),
        "the ceiling is on the list, not on where the match sits"
    );

    // The boundary itself still works, so the check is `>` and not `>=`.
    let mut ok = [("public-key", &filler[..]); MAX_ALLOW];
    ok[MAX_ALLOW - 1] = ("public-key", &cred_id[..]);
    assert!(
        run_ga(&mut fs, &mut rng, &ga_request_list(&ok)).is_ok(),
        "exactly maxCredentialCountInList entries must still assert"
    );
}

// A descriptor whose type is not "public-key" names a credential kind this device
// cannot assert, so it must not be matched on its id — and a list left with no
// usable descriptor still scopes the request: it fails, rather than falling
// through to resident discovery and answering with some other credential.
#[test]
fn foreign_type_in_allow_list_neither_matches_nor_falls_through() {
    let (mut fs, mut rng) = setup();
    let cred_id = register_non_resident(&mut fs, &mut rng);

    // A resident credential for the same rp exists, so a fall-through to discovery
    // would have something to answer with.
    {
        let mut out = [0u8; 1024];
        let mut state = crate::FidoState::new();
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 10,
        };
        make_credential(&mut ctx, &mc_request(true), &mut out).unwrap();
    }
    assert!(
        run_ga(&mut fs, &mut rng, &ga_request(None)).is_ok(),
        "control: with no allowList, discovery does answer"
    );

    assert_eq!(
        run_ga(
            &mut fs,
            &mut rng,
            &ga_request_list(&[("not-a-key", &cred_id)])
        ),
        Err(CtapError::NoCredentials),
        "a foreign-typed descriptor must not match on its id"
    );
}
