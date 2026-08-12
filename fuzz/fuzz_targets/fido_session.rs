// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Stateful CTAP2 session fuzzing, structure-aware. The single-command FIDO
//! targets (fido_cbor, fido_largeblobs, fido_credmgmt, …) each drive ONE command
//! from a fresh state; this one replays an attacker-chosen *sequence* of
//! CTAPHID_CBOR messages against a single `FidoState` + flash `Fs`, the way a
//! real host session does. PIN/token state, the credential store, the large-blob
//! array and the journal persist across commands — the bugs of this class
//! (largeBlobs offset accumulation, the mgmt write→read length mismatch) are
//! multi-step by nature, invisible to a fresh-state target.
//!
//! **Why the generator.** A raw byte mutator solves the 1-byte command dispatch
//! (99.8%) and then stops dead at the CBOR parameter map: the accumulated
//! makeCredential corpus has a *median input of 4 bytes* against a ~86-byte
//! minimum valid request, and a dictionary of the tag bytes was measured to move
//! `clientpin.rs` 4.3 → 16.3% while moving `makecredential.rs` 5.9 → **5.4%**.
//! Nothing under a generator reaches the code past `parse`. So byte 0 selects an
//! arm: `% 5 == 0` replays raw length-prefixed messages exactly as this target
//! always has (the accumulated corpus keeps working as raw material), and 1..=4
//! open a *generated* session — well-formed CBOR built with
//! `libfuzzer_sys::arbitrary::Unstructured` (re-exported, so no new dependency)
//! and the `minicbor` encoder already in the manifest — whose first command is
//! makeCredential / getAssertion / clientPIN / credentialManagement respectively
//! and whose later commands are drawn from [`MIX`].
//!
//! Four things make the generated arms reach state, not just parsers:
//!
//!  * **A fixed identity pool.** `rp.id` and `user.id` come from four constants
//!    ([`RP_IDS`] / [`USER_IDS`]), never from fuzzer bytes. Random 32-byte
//!    rpIdHashes never collide, so under any byte-level target a later
//!    getAssertion or credentialManagement can never find what an earlier
//!    makeCredential stored. Index 0 of each pool is the identity
//!    [`provisioned`] already holds.
//!  * **credentialId feedback.** A credentialId is an AEAD box; a mutator cannot
//!    invent one. [`CredPool`] harvests them out of makeCredential's own authData
//!    so allowList / excludeList / deleteCredential get ids that actually match.
//!  * **A genuine pinUvAuthParam.** The harness arms the token itself, so it can
//!    HMAC with it ([`Auth::Token`]) instead of only ever feeding the reject path.
//!    §6.5.5.7 spends the token on the first ceremony, so [`MIX`] can re-arm it —
//!    that stands in for the clientPIN handshake the fuzzer cannot run.
//!  * **The large-blob accumulator.** A commit wants the whole
//!    `body ‖ left16(SHA-256(body))` array over fragments whose offsets chain, so
//!    [`lb_write`] reads the device's own `lba` to continue the array it armed.
//!
//! The oracle is [`check_reply`]: nothing may panic, and every reply is either a
//! bare CTAP error byte or `0x00` followed by exactly one definite-length CBOR
//! map with no trailing bytes — a malformed *response* is a finding, not merely a
//! non-panic. getInfo must additionally succeed whatever the sequence left
//! behind, and [`Sess::display_walk`] then reads the store back through the
//! trusted-display Passkeys view (`passkeys.rs`, which no CTAP command reaches —
//! the display task calls it directly), where a listed relying party with no
//! credential behind it is a dangling index entry.
//!
//! The provisioned flash image is built once and cloned per exec (the
//! `RamStorage` doc invites exactly this snapshot).

use std::sync::OnceLock;

use libfuzzer_sys::arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use minicbor::encode::write::{Cursor, EndOfSlice};
use minicbor::encode::{Error as EncError, Write};
use minicbor::{Decoder, Encoder};
use rsk_crypto::pinproto::{self, PinProto};
use rsk_crypto::{Device, sha256};
use rsk_fido::consts::{self, CP_GET_PIN_UV_TOKEN_USING_PIN};
use rsk_fido::credential::{
    CRED_RESIDENT_LEN, CredExt, CredInput, credential_create, credential_store, derive_resident,
};
use rsk_fido::passkeys::{for_each_cred, for_each_rp};
use rsk_fido::seed::{ensure_seed, load_keydev};
use rsk_fido::state::{LargeBlobState, PERM_ACFG, PERM_CM, PERM_GA, PERM_LBW, PERM_MC, PERM_PCMR};
use rsk_fido::{Ctx, FidoState, Rng, process_cbor};
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;

type Enc<'a> = Encoder<Cursor<&'a mut [u8]>>;
type EncRes = Result<(), EncError<EndOfSlice>>;

/// The token [`Sess::new`] arms `FidoState` with. The harness owns it, so it can
/// mint the MAC a mutator never could — until [`Sess::pin_handshake`] replaces it
/// with one the device really issued.
const TOKEN: [u8; 32] = [0x99; 32];
const ALL_PERMS: u8 = PERM_MC | PERM_GA | PERM_CM | PERM_LBW | PERM_ACFG | PERM_PCMR;
/// What a token request may ask for. `pcmr` is excluded because §6.5.5.7.2 refuses
/// it in company, and it answers with the persistent token rather than a session one.
const HANDSHAKE_PERMS: u64 = (ALL_PERMS & !PERM_PCMR) as u64;

/// The two clientPIN subcommands the handshake needs that `rsk-fido` does not name
/// itself: getKeyAgreement and setPIN.
const CP_GET_KEY_AGREEMENT: u64 = 0x02;
const CP_SET_PIN: u64 = 0x03;
/// The host's ECDH scalar — fixed, so a session costs one scalar multiply instead
/// of a keygen and an input keeps its meaning across runs. In `[1, n)` for P-256.
const HOST_SCALAR: [u8; 32] = [0x42; 32];
/// The PIN the handshake sets. Eight bytes clears `MIN_PIN_LENGTH` on both the
/// default build (4) and `strong-pin` (6).
const PIN: &[u8] = b"12345678";

/// Relying parties a request may name. Index 0 is what [`provisioned`] stores, so
/// a getAssertion can hit a resident credential from the very first command; the
/// trailing-space entry is the display-spoof rpId `make_credential` rejects.
const RP_IDS: [&str; 4] = ["a.co", "example.com", "sub.login.example.org", "bank.com "];
/// `user.id` pool; index 0 matches [`provisioned`], index 3 sits on `USER_ID_MAX`.
const USER_IDS: [&[u8]; 4] = [&[1, 2], &[0xA5; 16], &[0x5A; 32], &[0xC3; 64]];
/// `user.name` / `displayName` pool. The last is 70 bytes of two-byte characters,
/// so `truncate_utf8` has to cut it on a character boundary, not at byte 64.
const USER_NAMES: [&str; 4] = [
    "u",
    "alex@example.com",
    "",
    "ααααααααααααααααααααααααααααααααααα",
];
/// COSE algorithms for `pubKeyCredParams` — the curve-explicit aliases and the
/// K1 policy gate included, plus RS256 (`-257`), which no build supports.
/// ML-DSA is deliberately absent: its reply cannot fit [`OUT_MAX`], so every such
/// request would pay a lattice keygen to end in `CTAP2_ERR_OTHER`. The
/// `fido_cred_pqc` target owns that surface.
const ALGS: [i64; 8] = [
    consts::ALG_ES256,
    consts::ALG_EDDSA,
    consts::ALG_ESP256,
    consts::ALG_ES384,
    consts::ALG_ES512,
    consts::ALG_ES256K,
    consts::ALG_ED25519,
    -257,
];
/// `PublicKeyCredentialType` values — the one WebAuthn defines, and one that must
/// be dropped rather than matched on its id.
const CRED_TYPES: [&str; 4] = [
    consts::PUBLIC_KEY_TYPE,
    consts::PUBLIC_KEY_TYPE,
    consts::PUBLIC_KEY_TYPE,
    "payment-credential",
];
/// `pinUvAuthProtocol` values: both defined ones, plus the two error legs
/// (`0` = missing, `3` = unsupported).
const PROTOS: [u64; 6] = [1, 2, 1, 2, 0, 3];
/// clientPIN subcommands, including the two built-in-UV ones this build answers
/// `CTAP2_ERR_INVALID_SUBCOMMAND` to and two undefined values.
const CP_SUBS: [u64; 12] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09, 0x0A, 0x0B, 0xFF,
];
/// credentialManagement subcommands, plus one undefined value.
const CM_SUBS: [u64; 8] = [
    consts::CM_GET_CREDS_METADATA,
    consts::CM_ENUMERATE_RPS_BEGIN,
    consts::CM_ENUMERATE_RPS_NEXT,
    consts::CM_ENUMERATE_CREDS_BEGIN,
    consts::CM_ENUMERATE_CREDS_NEXT,
    consts::CM_DELETE_CREDENTIAL,
    consts::CM_UPDATE_USER_INFO,
    0x08,
];
/// `pinUvAuthToken` permission masks a clientPIN request may ask for.
const PERM_SETS: [u64; 5] = [0x00, 0x01, 0x03, 0x7F, 0xFF];
/// authenticatorConfig subcommands: the three CTAP 2.1 ones, the vendor arm, the
/// absent-parameter sentinel (`0`) and one this build refuses.
const CFG_SUBS: [u64; 6] = [
    consts::CONFIG_ENABLE_EA,
    consts::CONFIG_TOGGLE_ALWAYS_UV,
    consts::CONFIG_SET_MIN_PIN,
    consts::CONFIG_VENDOR,
    0x00,
    0x04,
];
/// `vendorCommandId` for the 0xFF arm: the soft-lock pair, the four PicoForge
/// physical-config ids, and one that must land on `CTAP2_ERR_INVALID_SUBCOMMAND`.
const CFG_VENDOR_IDS: [u64; 7] = [
    consts::CONFIG_AUT_ENABLE,
    consts::CONFIG_AUT_DISABLE,
    consts::CONFIG_PHY_VIDPID,
    consts::CONFIG_PHY_LED_GPIO,
    consts::CONFIG_PHY_LED_BRIGHTNESS,
    consts::CONFIG_PHY_OPTIONS,
    0,
];
/// rpIds a `setMinPINLength` list draws from. The long one is here so that a list
/// over `MAX_MIN_PIN_RPIDS` also overshoots `MAX_RAW_SUBPARA`, which is refused
/// earlier and by a different rule (`CTAP2_ERR_REQUEST_TOO_LARGE`).
const MIN_PIN_RP_IDS: [&str; 4] = [
    RP_IDS[0],
    RP_IDS[1],
    RP_IDS[2],
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example",
];
/// `minPINLength` values: `0` keeps the current floor, `63` is `MAX_PIN_LENGTH`
/// and the two above it are the ceiling refusal that a bare `as u8` used to wrap.
const MIN_PINS: [u64; 7] = [0, 1, 4, 8, 63, 64, 256];
/// Large-blob array body sizes. `0` puts the array under `LARGEBLOB_MIN`; the rest
/// are well inside `MAX_FRAGMENT_LENGTH`, so a split is the harness's choice
/// rather than a transport limit.
const LB_BODIES: [usize; 5] = [0, 1, 24, 100, 300];
/// Scratch for one generated large-blob array — the largest [`LB_BODIES`] entry
/// plus its 16-byte integrity tag.
const LB_MAX: usize = LB_BODIES[LB_BODIES.len() - 1] + 16;

const K_MC: u8 = 1;
const K_GA: u8 = 2;
const K_CP: u8 = 3;
const K_CM: u8 = 4;
const K_INFO: u8 = 5;
const K_NEXT: u8 = 6;
const K_RESET: u8 = 7;
/// Not a command: re-arm the pinUvAuthToken (see [`Sess::rearm`]).
const K_REARM: u8 = 8;
const K_CFG: u8 = 9;
const K_LB: u8 = 10;
/// Arms 0..=4 of byte 0; arm 0 is the raw replay.
const ARMS: u8 = 5;

/// The command mix after the opening one; repeated entries weight the draw.
/// Reset is rare on purpose — it wipes the store, and a session that resets early
/// spends the rest of its budget against an empty one.
///
/// **Sixteen entries, and only two of them changed meaning.** `pick` draws this by
/// `% MIX.len()`, so a 17th re-phases every sequence the accumulated corpus encodes
/// — an 18-entry version cost `getassertion.rs` 9.3 pp and `ec.rs` 8.8 pp, measured
/// over that corpus. The two slots come from clientPIN and credentialManagement,
/// which paid 0.1 and 0.4 pp for them.
const MIX: [u8; 16] = [
    K_MC, K_MC, K_MC, K_MC, K_GA, K_GA, K_GA, K_GA, K_CP, K_LB, K_CM, K_CFG, K_INFO, K_NEXT,
    K_REARM, K_RESET,
];

/// Commands per generated session. Long enough for create → assert → enumerate →
/// delete, short enough that one exec stays under a millisecond of EC keygen.
const MAX_STEPS: usize = 12;
/// Scratch for one generated request. Three pooled credentialIds
/// (`MAX_CRED_ID_LENGTH` each) plus the descriptors around them is the worst case.
const MSG_MAX: usize = 3072;
/// Response buffer, unchanged from before the generator so arm 0 sees exactly the
/// device buffer it always did.
const OUT_MAX: usize = 2048;
/// Padding a descriptor id past the third takes, so an over-long list still fits
/// [`MSG_MAX`].
const SHORT_ID: &[u8] = &[0xEE; 8];

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

/// The snapshot every exec starts from: a flash image with the seed ensured and
/// one resident credential for `RP_IDS[0]` / `USER_IDS[0]`, plus that
/// credential's resident id — the one credentialId a session can use before it
/// has minted any of its own.
struct Provisioned {
    img: RamStorage,
    resident_id: [u8; CRED_RESIDENT_LEN],
}

fn provisioned() -> &'static Provisioned {
    static IMG: OnceLock<Provisioned> = OnceLock::new();
    IMG.get_or_init(|| {
        let d = dev();
        let mut fs = Fs::new(RamStorage::new());
        let mut rng = SeqRng(1);
        let _ = ensure_seed(&d, &mut fs, &mut rng);
        let rp_hash = sha256(RP_IDS[0].as_bytes());
        let mut resident_id = [0u8; CRED_RESIDENT_LEN];
        if let Some(seed) = load_keydev(&d, &mut fs) {
            let input = CredInput {
                rp_id: RP_IDS[0],
                user_id: USER_IDS[0],
                user_name: "u",
                user_display_name: "",
                use_sign_count: true,
                rk: true,
                created_ms: 1,
                alg: -7,  // ES256
                curve: 1, // P-256
                ext: CredExt {
                    cred_protect: 0,
                    cred_blob: &[],
                    hmac_secret: false,
                    large_blob_key: false,
                    third_party_payment: false,
                },
            };
            let mut cred_box = [0u8; 512];
            if let Ok(len) =
                credential_create(&seed, &d, &input, &rp_hash, &[0x11; 12], &mut cred_box)
            {
                resident_id = derive_resident(&cred_box[..len], &d);
                let _ = credential_store(
                    &seed,
                    &d,
                    &mut fs,
                    &cred_box[..len],
                    &rp_hash,
                    RP_IDS[0],
                    USER_IDS[0],
                    &[],
                );
            }
        }
        Provisioned {
            img: fs.into_storage(),
            resident_id,
        }
    })
}

// ---------------------------------------------------------------- credentialIds

const CRED_ID_MAX: usize = consts::MAX_CRED_ID_LENGTH as usize;
const POOL: usize = 4;

/// credentialIds this session has seen. A credentialId is an AEAD box, so an
/// allowList entry a mutator invents can never match — without this feedback
/// getAssertion's whole non-resident leg and every `deleteCredential` are
/// unreachable no matter how long the fuzzer runs.
struct CredPool {
    ids: [[u8; CRED_ID_MAX]; POOL],
    lens: [usize; POOL],
    n: usize,
    next: usize,
}

impl CredPool {
    fn new() -> Self {
        Self {
            ids: [[0; CRED_ID_MAX]; POOL],
            lens: [0; POOL],
            n: 0,
            next: 0,
        }
    }

    fn add(&mut self, id: &[u8]) {
        if id.is_empty() || id.len() > CRED_ID_MAX {
            return;
        }
        let i = self.next;
        self.ids[i][..id.len()].copy_from_slice(id);
        self.lens[i] = id.len();
        self.next = (i + 1) % POOL;
        self.n = (self.n + 1).min(POOL);
    }

    /// An id for a credential descriptor: usually one this session really has,
    /// occasionally filler so the no-match leg stays exercised too.
    fn pick_id(&self, u: &mut Unstructured<'_>) -> &[u8] {
        if self.n == 0 || u.ratio(1u8, 8).unwrap_or(false) {
            return SHORT_ID;
        }
        let i = u.int_in_range(0..=self.n - 1).unwrap_or(0);
        &self.ids[i][..self.lens[i]]
    }

    /// Learn the credentialId out of a makeCredential reply's authData
    /// (`rpIdHash ‖ flags ‖ signCount ‖ aaguid ‖ credIdLen ‖ credId`).
    fn harvest(&mut self, reply: &[u8]) {
        const OFF: usize = 32 + 1 + 4 + 16;
        let Some(auth) = map_bytes(reply, 2) else {
            return;
        };
        if auth.len() < OFF + 2 || auth[32] & consts::FLAG_AT == 0 {
            return;
        }
        let len = u16::from_be_bytes([auth[OFF], auth[OFF + 1]]) as usize;
        if let Some(id) = auth.get(OFF + 2..OFF + 2 + len) {
            self.add(id);
        }
    }
}

/// The byte string a reply map carries under `key` — makeCredential's `authData`
/// and clientPIN's encrypted `pinUvAuthToken` are both response key 2.
fn map_bytes(reply: &[u8], key: u32) -> Option<&[u8]> {
    let mut d = Decoder::new(reply);
    let n = d.map().ok()??;
    let mut found = None;
    for _ in 0..n {
        match d.u32() {
            Ok(k) if k == key => found = Some(d.bytes().ok()?),
            Ok(_) => d.skip().ok()?,
            Err(_) => return None,
        }
    }
    found
}

// ------------------------------------------------------------------- generators

/// Draw an element of `pool`; an exhausted `Unstructured` yields the first.
fn pick<T: Copy>(u: &mut Unstructured<'_>, pool: &[T]) -> T {
    *u.choose(pool).unwrap_or(&pool[0])
}

/// Fill `buf[..n]` with a deterministic pattern and return it. Payload *content*
/// steers no parser here — length and shape do — so it spends no fuzzer bytes.
fn filler(buf: &mut [u8], tag: u8, n: usize) -> &[u8] {
    let n = n.min(buf.len());
    for (i, b) in buf[..n].iter_mut().enumerate() {
        *b = tag.wrapping_add(i as u8);
    }
    &buf[..n]
}

/// Emit a byte string of `n` filler bytes under `tag`.
fn enc_filler(enc: &mut Enc<'_>, tag: u8, n: usize) -> EncRes {
    let mut buf = [0u8; 160];
    enc.bytes(filler(&mut buf, tag, n))?;
    Ok(())
}

/// clientDataHash length: 32 (the only accepted one) unless the fuzzer asks for
/// the `CTAP2_ERR_MISSING_PARAMETER` leg.
fn cdh_len(u: &mut Unstructured<'_>) -> usize {
    if u.ratio(1u8, 8).unwrap_or(false) {
        u.int_in_range(0..=48).unwrap_or(0)
    } else {
        32
    }
}

/// An optional descriptor-list length that sometimes overshoots
/// `MAX_CREDENTIAL_COUNT_IN_LIST`, so the `CTAP2_ERR_LIMIT_EXCEEDED` leg is reachable.
fn opt_count(u: &mut Unstructured<'_>, num: u8, den: u8) -> Option<u64> {
    if !u.ratio(num, den).unwrap_or(false) {
        return None;
    }
    Some(
        u.int_in_range(0..=consts::MAX_CREDENTIAL_COUNT_IN_LIST + 1)
            .unwrap_or(0),
    )
}

/// A present-or-absent boolean map entry.
fn tri(u: &mut Unstructured<'_>) -> Option<bool> {
    match u.int_in_range(0u8..=3).unwrap_or(0) {
        0 => None,
        1 => Some(false),
        _ => Some(true),
    }
}

/// `pinUvAuthParam` / `pinUvAuthProtocol` for one request.
enum Auth {
    /// Neither key present.
    Absent,
    /// Zero-length param — CTAP 2.1 §6.1.2 step 1's selection-gesture probe.
    Probe(u64),
    /// The real HMAC under the session's live token. Everything past
    /// `verify_token` — the uv flag, the permission and rpId-binding checks, the
    /// §6.5.5.7 spend — is unreachable without this.
    Token(u64, [u8; 32]),
    /// Fuzzer-shaped bytes of a chosen length: the reject leg.
    Garbage(u64, usize),
}

impl Auth {
    fn draw(u: &mut Unstructured<'_>, token: &[u8; 32]) -> Self {
        let proto = pick(u, &PROTOS);
        match u.int_in_range(0u8..=7).unwrap_or(0) {
            0..=2 => Auth::Absent,
            3 => Auth::Probe(proto),
            4..=6 => Auth::Token(proto, *token),
            _ => Auth::Garbage(proto, pick(u, &[15usize, 16, 17, 32, 33])),
        }
    }

    fn present(&self) -> bool {
        !matches!(self, Auth::Absent)
    }

    fn proto(&self) -> u64 {
        match *self {
            Auth::Absent => 0,
            Auth::Probe(p) | Auth::Token(p, _) | Auth::Garbage(p, _) => p,
        }
    }

    /// The param bytes covering `msg`, written into `buf`.
    fn param<'b>(&self, msg: &[u8], buf: &'b mut [u8; 32]) -> &'b [u8] {
        match *self {
            Auth::Absent | Auth::Probe(_) => &[],
            Auth::Token(p, token) => {
                // An undefined protocol is rejected before the MAC is ever
                // checked, so any concrete one will do for the bytes.
                let proto = PinProto::from_u64(p).unwrap_or(PinProto::Two);
                let n = pinproto::authenticate(proto, &token, msg, buf).unwrap_or(0);
                &buf[..n]
            }
            Auth::Garbage(_, n) => {
                let k = n.min(32);
                buf.fill(0x5A);
                &buf[..k]
            }
        }
    }
}

/// The `options` map (rk / up / uv), each key present or absent.
struct Opts {
    rk: Option<bool>,
    up: Option<bool>,
    uv: Option<bool>,
}

impl Opts {
    fn draw(u: &mut Unstructured<'_>) -> Self {
        Self {
            rk: tri(u),
            up: tri(u),
            uv: tri(u),
        }
    }

    fn any(&self) -> bool {
        self.rk.is_some() || self.up.is_some() || self.uv.is_some()
    }

    fn encode(&self, enc: &mut Enc<'_>) -> EncRes {
        let n = u64::from(self.rk.is_some())
            + u64::from(self.up.is_some())
            + u64::from(self.uv.is_some());
        enc.map(n)?;
        for (k, v) in [("rk", self.rk), ("up", self.up), ("uv", self.uv)] {
            if let Some(b) = v {
                enc.str(k)?.bool(b)?;
            }
        }
        Ok(())
    }
}

/// A COSE_Key of the shape clientPIN key agreement and hmac-secret expect: EC2
/// P-256 with ECDH-ES+HKDF-256.
fn cose_key(enc: &mut Enc<'_>, x: &[u8], y: &[u8]) -> EncRes {
    enc.map(5)?
        .u8(1)?
        .u8(2)?
        .u8(3)?
        .i64(consts::ALG_ECDH_ES_HKDF_256)?
        .i8(-1)?
        .u8(consts::CURVE_P256)?
        .i8(-2)?
        .bytes(x)?
        .i8(-3)?
        .bytes(y)?;
    Ok(())
}

/// The same key with filler coordinates, so the point is off-curve and the ECDH
/// must refuse rather than compute.
fn cose_p256(u: &mut Unstructured<'_>, enc: &mut Enc<'_>) -> EncRes {
    let len = pick(u, &[32usize, 32, 32, 31, 33, 0]);
    let mut xb = [0u8; 48];
    let mut yb = [0u8; 48];
    cose_key(enc, filler(&mut xb, 0x33, len), filler(&mut yb, 0x44, len))
}

/// The `hmac-secret` extension map: `{1: COSE key, 2: saltEnc, 3: saltAuth, 4: proto}`.
/// The salt lengths straddle `salt_plaintext_len`'s two accepted sizes and their
/// v2 IV overhead.
fn hmac_secret(u: &mut Unstructured<'_>, enc: &mut Enc<'_>) -> EncRes {
    let salt = pick(u, &[32usize, 48, 64, 80, 33]);
    let auth = pick(u, &[16usize, 32]);
    enc.map(4)?.u8(1)?;
    cose_p256(u, enc)?;
    enc.u8(2)?;
    enc_filler(enc, 0x55, salt)?;
    enc.u8(3)?;
    enc_filler(enc, 0x66, auth)?;
    enc.u8(4)?.u64(pick(u, &PROTOS))?;
    Ok(())
}

/// makeCredential's `extensions` map (request key 6).
struct McExt {
    cred_protect: Option<u64>,
    cred_blob: Option<usize>,
    min_pin_length: Option<bool>,
    third_party: Option<bool>,
    hmac_secret: Option<bool>,
    large_blob_key: Option<bool>,
    hmac_secret_mc: bool,
}

impl McExt {
    fn draw(u: &mut Unstructured<'_>) -> Self {
        Self {
            cred_protect: u
                .ratio(1u8, 3)
                .unwrap_or(false)
                .then(|| pick(u, &[0u64, 1, 2, 3, 4])),
            // 128 is MAX_CREDBLOB_LENGTH; 129 is the first over-long one.
            cred_blob: u
                .ratio(1u8, 3)
                .unwrap_or(false)
                .then(|| pick(u, &[0usize, 32, 128, 129])),
            min_pin_length: tri(u),
            third_party: tri(u),
            hmac_secret: tri(u),
            large_blob_key: tri(u),
            hmac_secret_mc: u.ratio(1u8, 6).unwrap_or(false),
        }
    }

    fn count(&self) -> u64 {
        u64::from(self.cred_protect.is_some())
            + u64::from(self.cred_blob.is_some())
            + u64::from(self.min_pin_length.is_some())
            + u64::from(self.third_party.is_some())
            + u64::from(self.hmac_secret.is_some())
            + u64::from(self.large_blob_key.is_some())
            + u64::from(self.hmac_secret_mc)
    }

    fn encode(&self, u: &mut Unstructured<'_>, enc: &mut Enc<'_>) -> EncRes {
        enc.map(self.count())?;
        if let Some(v) = self.cred_protect {
            enc.str("credProtect")?.u64(v)?;
        }
        if let Some(n) = self.cred_blob {
            enc.str("credBlob")?;
            enc_filler(enc, 0x77, n)?;
        }
        for (k, v) in [
            ("minPinLength", self.min_pin_length),
            ("thirdPartyPayment", self.third_party),
            ("hmac-secret", self.hmac_secret),
            ("largeBlobKey", self.large_blob_key),
        ] {
            if let Some(b) = v {
                enc.str(k)?.bool(b)?;
            }
        }
        if self.hmac_secret_mc {
            enc.str("hmac-secret-mc")?;
            hmac_secret(u, enc)?;
        }
        Ok(())
    }
}

/// getAssertion's `extensions` map (request key 4).
struct GaExt {
    cred_blob: Option<bool>,
    third_party: Option<bool>,
    large_blob_key: Option<bool>,
    hmac_secret: bool,
}

impl GaExt {
    fn draw(u: &mut Unstructured<'_>) -> Self {
        Self {
            cred_blob: tri(u),
            third_party: tri(u),
            large_blob_key: tri(u),
            hmac_secret: u.ratio(1u8, 3).unwrap_or(false),
        }
    }

    fn count(&self) -> u64 {
        u64::from(self.cred_blob.is_some())
            + u64::from(self.third_party.is_some())
            + u64::from(self.large_blob_key.is_some())
            + u64::from(self.hmac_secret)
    }

    fn encode(&self, u: &mut Unstructured<'_>, enc: &mut Enc<'_>) -> EncRes {
        enc.map(self.count())?;
        for (k, v) in [
            ("credBlob", self.cred_blob),
            ("thirdPartyPayment", self.third_party),
            ("largeBlobKey", self.large_blob_key),
        ] {
            if let Some(b) = v {
                enc.str(k)?.bool(b)?;
            }
        }
        if self.hmac_secret {
            enc.str("hmac-secret")?;
            hmac_secret(u, enc)?;
        }
        Ok(())
    }
}

/// A `PublicKeyCredentialDescriptor` array — getAssertion's allowList or
/// makeCredential's excludeList.
fn descriptors(u: &mut Unstructured<'_>, pool: &CredPool, k: u64, enc: &mut Enc<'_>) -> EncRes {
    enc.array(k)?;
    for i in 0..k {
        let id = if i < 3 { pool.pick_id(u) } else { SHORT_ID };
        let ty = pick(u, &CRED_TYPES);
        enc.map(2)?.str("id")?.bytes(id)?.str("type")?.str(ty)?;
    }
    Ok(())
}

/// `authenticatorMakeCredential` (0x01). Keys 1..=4 are mandatory and ordered
/// first; 5..=10 are optional and ascending, which `parse` enforces.
fn mc(u: &mut Unstructured<'_>, pool: &CredPool, token: &[u8; 32], enc: &mut Enc<'_>) -> EncRes {
    let rp = pick(u, &RP_IDS);
    let uid = pick(u, &USER_IDS);
    let uname = pick(u, &USER_NAMES);
    let udisp = pick(u, &USER_NAMES);
    let mut cdh_buf = [0u8; 48];
    let cdh = filler(&mut cdh_buf, 0x11, cdh_len(u));
    let algs = u.int_in_range(1u64..=3).unwrap_or(1);
    let excl = opt_count(u, 1, 3);
    let ext = McExt::draw(u);
    let opts = Opts::draw(u);
    let auth = Auth::draw(u, token);
    let ea = u
        .ratio(1u8, 8)
        .unwrap_or(false)
        .then(|| pick(u, &[0u64, 1, 2, 7]));

    let fields = 4
        + u64::from(excl.is_some())
        + u64::from(ext.count() > 0)
        + u64::from(opts.any())
        + 2 * u64::from(auth.present())
        + u64::from(ea.is_some());
    enc.map(fields)?;

    enc.u8(1)?.bytes(cdh)?;
    enc.u8(2)?
        .map(2)?
        .str("id")?
        .str(rp)?
        .str("name")?
        .str("Example RP")?;
    enc.u8(3)?
        .map(3)?
        .str("id")?
        .bytes(uid)?
        .str("name")?
        .str(uname)?
        .str("displayName")?
        .str(udisp)?;
    enc.u8(4)?.array(algs)?;
    for _ in 0..algs {
        let alg = pick(u, &ALGS);
        let ty = pick(u, &CRED_TYPES);
        enc.map(2)?.str("alg")?.i64(alg)?.str("type")?.str(ty)?;
    }
    if let Some(k) = excl {
        enc.u8(5)?;
        descriptors(u, pool, k, enc)?;
    }
    if ext.count() > 0 {
        enc.u8(6)?;
        ext.encode(u, enc)?;
    }
    if opts.any() {
        enc.u8(7)?;
        opts.encode(enc)?;
    }
    if auth.present() {
        let mut mac = [0u8; 32];
        enc.u8(8)?.bytes(auth.param(cdh, &mut mac))?;
        enc.u8(9)?.u64(auth.proto())?;
    }
    if let Some(v) = ea {
        enc.u8(10)?.u64(v)?;
    }
    Ok(())
}

/// `authenticatorGetAssertion` (0x02). Keys 1..=2 mandatory and first.
fn ga(u: &mut Unstructured<'_>, pool: &CredPool, token: &[u8; 32], enc: &mut Enc<'_>) -> EncRes {
    let rp = pick(u, &RP_IDS);
    let mut cdh_buf = [0u8; 48];
    let cdh = filler(&mut cdh_buf, 0x22, cdh_len(u));
    let allow = opt_count(u, 1, 2);
    let ext = GaExt::draw(u);
    let opts = Opts::draw(u);
    let auth = Auth::draw(u, token);

    let fields = 2
        + u64::from(allow.is_some())
        + u64::from(ext.count() > 0)
        + u64::from(opts.any())
        + 2 * u64::from(auth.present());
    enc.map(fields)?;

    enc.u8(1)?.str(rp)?;
    enc.u8(2)?.bytes(cdh)?;
    if let Some(k) = allow {
        enc.u8(3)?;
        descriptors(u, pool, k, enc)?;
    }
    if ext.count() > 0 {
        enc.u8(4)?;
        ext.encode(u, enc)?;
    }
    if opts.any() {
        enc.u8(5)?;
        opts.encode(enc)?;
    }
    if auth.present() {
        let mut mac = [0u8; 32];
        enc.u8(6)?.bytes(auth.param(cdh, &mut mac))?;
        enc.u8(7)?.u64(auth.proto())?;
    }
    Ok(())
}

/// `authenticatorClientPIN` (0x06). Keys 1..=2 mandatory and first; the rest
/// ascend 3, 4, 5, 6, 9, 10.
fn cp(u: &mut Unstructured<'_>, enc: &mut Enc<'_>) -> EncRes {
    let proto = pick(u, &PROTOS);
    let sub = pick(u, &CP_SUBS);
    let ka = u.ratio(1u8, 2).unwrap_or(false);
    let param = u.ratio(1u8, 2).unwrap_or(false);
    // 64 is a v1 padded PIN block, 80 the same under v2's IV prefix.
    let new_pin = u
        .ratio(1u8, 2)
        .unwrap_or(false)
        .then(|| pick(u, &[64usize, 80, 63, 32]));
    let pin_hash = u
        .ratio(1u8, 2)
        .unwrap_or(false)
        .then(|| pick(u, &[16usize, 32, 15]));
    let perms = u
        .ratio(1u8, 3)
        .unwrap_or(false)
        .then(|| pick(u, &PERM_SETS));
    let rp_id = u.ratio(1u8, 4).unwrap_or(false).then(|| pick(u, &RP_IDS));

    let fields = 2
        + u64::from(ka)
        + u64::from(param)
        + u64::from(new_pin.is_some())
        + u64::from(pin_hash.is_some())
        + u64::from(perms.is_some())
        + u64::from(rp_id.is_some());
    enc.map(fields)?;

    enc.u8(1)?.u64(proto)?;
    enc.u8(2)?.u64(sub)?;
    if ka {
        enc.u8(3)?;
        cose_p256(u, enc)?;
    }
    if param {
        enc.u8(4)?;
        enc_filler(enc, 0x88, pick(u, &[16usize, 32]))?;
    }
    if let Some(n) = new_pin {
        enc.u8(5)?;
        enc_filler(enc, 0x99, n)?;
    }
    if let Some(n) = pin_hash {
        enc.u8(6)?;
        enc_filler(enc, 0xAA, n)?;
    }
    if let Some(v) = perms {
        enc.u8(9)?.u64(v)?;
    }
    if let Some(v) = rp_id {
        enc.u8(10)?.str(v)?;
    }
    Ok(())
}

// -------------------------------------------------------------- clientPIN ECDH

/// The host's ECDH public point, derived once: it is a fixed scalar, and a
/// scalar multiply per execution would be pure overhead.
fn host_key() -> &'static ([u8; 32], [u8; 32]) {
    static K: OnceLock<([u8; 32], [u8; 32])> = OnceLock::new();
    K.get_or_init(|| pinproto::public_xy(&HOST_SCALAR).expect("a fixed in-range scalar"))
}

/// The optional halves of a clientPIN request, in the ascending key order `parse`
/// enforces: keyAgreement (3), pinUvAuthParam (4), newPinEnc (5), pinHashEnc (6)
/// and permissions (9). An empty slice or a zero means the key is absent.
#[derive(Default)]
struct CpReq<'a> {
    key_agreement: bool,
    param: &'a [u8],
    new_pin_enc: &'a [u8],
    pin_hash_enc: &'a [u8],
    permissions: u64,
}

fn cp_body(enc: &mut Enc<'_>, proto: u64, sub: u64, r: &CpReq<'_>) -> EncRes {
    let fields = 2
        + u64::from(r.key_agreement)
        + u64::from(!r.param.is_empty())
        + u64::from(!r.new_pin_enc.is_empty())
        + u64::from(!r.pin_hash_enc.is_empty())
        + u64::from(r.permissions != 0);
    enc.map(fields)?;
    enc.u8(1)?.u64(proto)?.u8(2)?.u64(sub)?;
    if r.key_agreement {
        let (x, y) = host_key();
        enc.u8(3)?;
        cose_key(enc, x, y)?;
    }
    if !r.param.is_empty() {
        enc.u8(4)?.bytes(r.param)?;
    }
    if !r.new_pin_enc.is_empty() {
        enc.u8(5)?.bytes(r.new_pin_enc)?;
    }
    if !r.pin_hash_enc.is_empty() {
        enc.u8(6)?.bytes(r.pin_hash_enc)?;
    }
    if r.permissions != 0 {
        enc.u8(9)?.u64(r.permissions)?;
    }
    Ok(())
}

/// One well-formed clientPIN message into `buf`; 0 if it did not fit.
fn cp_msg(buf: &mut [u8], proto: u64, sub: u64, r: &CpReq<'_>) -> usize {
    buf[0] = consts::CTAP_CLIENT_PIN;
    let mut enc = Encoder::new(Cursor::new(&mut buf[1..]));
    if cp_body(&mut enc, proto, sub, r).is_err() {
        return 0;
    }
    1 + enc.writer().position()
}

/// The `(x, y)` of the COSE key a getKeyAgreement reply carries under key 1.
fn key_agreement_xy(body: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let mut d = Decoder::new(body);
    let n = d.map().ok()??;
    let (mut x, mut y) = (None, None);
    for _ in 0..n {
        if d.u32().ok()? != 1 {
            d.skip().ok()?;
            continue;
        }
        let m = d.map().ok()??;
        for _ in 0..m {
            match d.i32().ok()? {
                -2 => x = d.bytes().ok()?.try_into().ok(),
                -3 => y = d.bytes().ok()?.try_into().ok(),
                _ => d.skip().ok()?,
            }
        }
    }
    Some((x?, y?))
}

/// `subCommandParams` (credentialManagement key 2), built standalone because the
/// pinUvAuthParam MAC covers its raw bytes.
fn cm_subpara(
    u: &mut Unstructured<'_>,
    pool: &CredPool,
    buf: &mut [u8],
) -> Result<usize, EncError<EndOfSlice>> {
    let rp_hash = u.ratio(2u8, 3).unwrap_or(true);
    let cred = u.ratio(1u8, 2).unwrap_or(false);
    let user = u.ratio(1u8, 3).unwrap_or(false);
    if !(rp_hash || cred || user) {
        return Ok(0);
    }
    let hash = sha256(pick(u, &RP_IDS).as_bytes());
    // A short hash is the MissingParameter leg of enumerateCredentials.
    let hash_len = if u.ratio(1u8, 8).unwrap_or(false) {
        31
    } else {
        32
    };
    let id = pool.pick_id(u);
    let uid = pick(u, &USER_IDS);
    let uname = pick(u, &USER_NAMES);

    let mut enc = Encoder::new(Cursor::new(buf));
    enc.map(u64::from(rp_hash) + u64::from(cred) + u64::from(user))?;
    if rp_hash {
        enc.u8(1)?.bytes(&hash[..hash_len])?;
    }
    if cred {
        enc.u8(2)?
            .map(2)?
            .str("id")?
            .bytes(id)?
            .str("type")?
            .str(consts::PUBLIC_KEY_TYPE)?;
    }
    if user {
        enc.u8(3)?
            .map(3)?
            .str("id")?
            .bytes(uid)?
            .str("name")?
            .str(uname)?
            .str("displayName")?
            .str(uname)?;
    }
    Ok(enc.writer().position())
}

/// `authenticatorCredentialManagement` (0x0A). Key 1 mandatory and first; 2, 3, 4
/// ascend after it.
fn cm(u: &mut Unstructured<'_>, pool: &CredPool, token: &[u8; 32], enc: &mut Enc<'_>) -> EncRes {
    const SUB_MAX: usize = 1024;
    let sub = pick(u, &CM_SUBS);
    let mut sub_buf = [0u8; SUB_MAX];
    let sub_len = if u.ratio(3u8, 4).unwrap_or(true) {
        cm_subpara(u, pool, &mut sub_buf).unwrap_or(0)
    } else {
        0
    };
    let auth = Auth::draw(u, token);

    let fields = 1 + u64::from(sub_len > 0) + 2 * u64::from(auth.present());
    enc.map(fields)?;
    enc.u8(1)?.u64(sub)?;
    if sub_len > 0 {
        enc.u8(2)?;
        enc.writer_mut()
            .write_all(&sub_buf[..sub_len])
            .map_err(EncError::write)?;
    }
    if auth.present() {
        // CTAP 2.1 §6.8: the MAC covers subCommand ‖ subCommandParams.
        let mut msg = [0u8; 1 + SUB_MAX];
        msg[0] = sub as u8;
        msg[1..1 + sub_len].copy_from_slice(&sub_buf[..sub_len]);
        let mut mac = [0u8; 32];
        enc.u8(3)?.u64(auth.proto())?;
        enc.u8(4)?
            .bytes(auth.param(&msg[..1 + sub_len], &mut mac))?;
    }
    Ok(())
}

/// Scratch for one authenticatorConfig `subCommandParams` map. Sized past
/// `MAX_RAW_SUBPARA` so the over-long list [`MIN_PIN_RP_IDS`] can build still
/// reaches the device, instead of dying in the encoder before its refusal runs.
const CFG_SUB_MAX: usize = consts::MAX_RAW_SUBPARA + 256;

/// `subCommandParams` (authenticatorConfig key 2), built standalone because the
/// pinUvAuth MAC covers its raw bytes.
fn cfg_subpara(
    u: &mut Unstructured<'_>,
    sub: u64,
    buf: &mut [u8],
) -> Result<usize, EncError<EndOfSlice>> {
    let mut enc = Encoder::new(Cursor::new(buf));
    if sub == consts::CONFIG_SET_MIN_PIN {
        let rps = u
            .int_in_range(0u64..=consts::MAX_MIN_PIN_RPIDS as u64 + 1)
            .unwrap_or(0);
        enc.map(3)?
            .u8(1)?
            .u64(pick(u, &MIN_PINS))?
            .u8(2)?
            .array(rps)?;
        for _ in 0..rps {
            enc.str(pick(u, &MIN_PIN_RP_IDS))?;
        }
        enc.u8(3)?.bool(u.ratio(1u8, 2).unwrap_or(false))?;
    } else if sub == consts::CONFIG_VENDOR {
        enc.map(3)?.u8(1)?.u64(pick(u, &CFG_VENDOR_IDS))?.u8(2)?;
        // The soft-lock ids read this as an MSE-wrapped 32-byte lock key.
        enc_filler(&mut enc, 0xBB, pick(u, &[0usize, 32, 60, 92]))?;
        enc.u8(3)?.u64(pick(u, &[0u64, 0x1050_0407, 0xFFFF_FFFF]))?;
    } else {
        // A subcommand that defines no params still carries a map, and `parse`
        // has to skip it without reading it as one of the two it does know.
        enc.map(1)?.u8(1)?.u64(pick(u, &[0u64, 1]))?;
    }
    Ok(enc.writer().position())
}

/// `authenticatorConfig` (0x0D). Key 1 (subCommand) is mandatory and first; 3 and
/// 4 ascend after it. No dedicated target reaches this command — only
/// `process_cbor` callers do — and everything past `verify_token` needs the
/// `acfg` token this harness owns.
fn cfg(u: &mut Unstructured<'_>, token: &[u8; 32], enc: &mut Enc<'_>) -> EncRes {
    let sub = pick(u, &CFG_SUBS);
    let mut sub_buf = [0u8; CFG_SUB_MAX];
    let sub_len = if u.ratio(7u8, 8).unwrap_or(true) {
        cfg_subpara(u, sub, &mut sub_buf).unwrap_or(0)
    } else {
        0
    };
    let auth = Auth::draw(u, token);

    let fields = 1 + u64::from(sub_len > 0) + 2 * u64::from(auth.present());
    enc.map(fields)?;
    enc.u8(1)?.u64(sub)?;
    if sub_len > 0 {
        enc.u8(2)?;
        enc.writer_mut()
            .write_all(&sub_buf[..sub_len])
            .map_err(EncError::write)?;
    }
    if auth.present() {
        // CTAP 2.1 §6.11: the MAC covers 0xff×32 ‖ 0x0d ‖ subCommand ‖ subCommandParams.
        let mut msg = [0u8; 34 + CFG_SUB_MAX];
        msg[..32].fill(0xff);
        msg[32] = consts::CTAP_CONFIG;
        msg[33] = sub as u8;
        msg[34..34 + sub_len].copy_from_slice(&sub_buf[..sub_len]);
        let mut mac = [0u8; 32];
        enc.u8(3)?.u64(auth.proto())?;
        enc.u8(4)?
            .bytes(auth.param(&msg[..34 + sub_len], &mut mac))?;
    }
    Ok(())
}

/// A valid large-blob array — `body ‖ left16(SHA-256(body))`, the shape §6.10.2's
/// commit verifies. A mutator never assembles one, so the commit, its integrity
/// check and the flash write are unreachable without this.
fn lb_array(buf: &mut [u8; LB_MAX], body: usize) -> usize {
    let n = filler(buf, 0xCC, body.min(LB_MAX - 16)).len();
    let tag = sha256(&buf[..n]);
    buf[n..n + 16].copy_from_slice(&tag[..16]);
    n + 16
}

/// `authenticatorLargeBlobs` (0x0C) read: `{1: get, 3: offset}`. §6.10.2 forbids
/// `length` and the auth pair here, so `extra` supplies one to exercise that.
fn lb_read(u: &mut Unstructured<'_>, enc: &mut Enc<'_>) -> EncRes {
    let get = pick(u, &[0u64, 1, 32, consts::MAX_FRAGMENT_LENGTH as u64 + 1]);
    // The last two are past any stored array, and past `usize` on the device.
    let off = pick(u, &[0u64, 8, 4096, u64::from(u32::MAX) + 5]);
    let extra = u.ratio(1u8, 8).unwrap_or(false);
    enc.map(2 + u64::from(extra))?
        .u8(1)?
        .u64(get)?
        .u8(3)?
        .u64(off)?;
    if extra {
        enc.u8(4)?.u64(consts::LARGEBLOB_MIN as u64)?;
    }
    Ok(())
}

/// `authenticatorLargeBlobs` (0x0C) write: `{2: fragment, 3: offset, 4: length?}`
/// plus the auth pair. `lba` is the device's own accumulator, so a split write's
/// second fragment continues the *same* array — without that the commit only ever
/// reaches its integrity refusal, and the cross-command offset accumulation this
/// target exists for is never exercised.
fn lb_write(
    u: &mut Unstructured<'_>,
    lba: &LargeBlobState,
    token: &[u8; 32],
    enc: &mut Enc<'_>,
) -> EncRes {
    let mut buf = [0u8; LB_MAX];
    let next = lba.expected_next_offset;
    // Drawn even when the accumulator decides it, so one input costs the same
    // bytes whatever state it lands in and keeps its meaning across execs.
    let fresh = pick(u, &LB_BODIES) + 16;
    let total = if next > 0 && (consts::LARGEBLOB_MIN..=LB_MAX).contains(&lba.expected_length) {
        lba.expected_length
    } else {
        fresh
    };
    let n = lb_array(&mut buf, total - 16);

    let off = if u.ratio(7u8, 8).unwrap_or(true) {
        next
    } else {
        pick(u, &[0usize, 1, 4096])
    };
    let lo = off.min(n);
    // Half of what is left, so a second fragment has somewhere to land.
    let hi = if u.ratio(1u8, 2).unwrap_or(false) {
        lo + (n - lo).div_ceil(2)
    } else {
        n
    };
    let frag = &buf[lo..hi];
    // `length` belongs on the arming fragment only; sending it on a continuation
    // (or omitting it at offset 0) is the `CTAP1_ERR_INVALID_PARAMETER` leg.
    let length = (off == 0) != u.ratio(1u8, 8).unwrap_or(false);
    let auth = Auth::draw(u, token);

    enc.map(2 + u64::from(length) + 2 * u64::from(auth.present()))?;
    enc.u8(2)?.bytes(frag)?.u8(3)?.u64(off as u64)?;
    if length {
        enc.u8(4)?.u64(n as u64)?;
    }
    if auth.present() {
        // §6.10.2: the MAC covers 0xff×32 ‖ 0x0c ‖ 0x00 ‖ offset_le(4) ‖ sha256(fragment).
        let mut msg = [0u8; 70];
        msg[..32].fill(0xff);
        msg[32] = consts::CTAP_LARGE_BLOBS;
        msg[34..38].copy_from_slice(&(off as u32).to_le_bytes());
        msg[38..70].copy_from_slice(&sha256(frag));
        let mut mac = [0u8; 32];
        enc.u8(5)?.bytes(auth.param(&msg, &mut mac))?;
        enc.u8(6)?.u64(auth.proto())?;
    }
    Ok(())
}

/// Build one CTAPHID_CBOR message of `kind` into `buf`; 0 means the encoder ran
/// out of room and the step is skipped.
fn build(
    kind: u8,
    u: &mut Unstructured<'_>,
    pool: &CredPool,
    lba: &LargeBlobState,
    token: &[u8; 32],
    buf: &mut [u8],
) -> usize {
    buf[0] = match kind {
        K_MC => consts::CTAP_MAKE_CREDENTIAL,
        K_GA => consts::CTAP_GET_ASSERTION,
        K_CP => consts::CTAP_CLIENT_PIN,
        K_CM => consts::CTAP_CREDENTIAL_MGMT,
        K_CFG => consts::CTAP_CONFIG,
        K_LB => consts::CTAP_LARGE_BLOBS,
        K_INFO => consts::CTAP_GET_INFO,
        K_NEXT => consts::CTAP_GET_NEXT_ASSERTION,
        _ => consts::CTAP_RESET,
    };
    if matches!(kind, K_INFO | K_NEXT | K_RESET) {
        return 1;
    }
    let mut enc = Encoder::new(Cursor::new(&mut buf[1..]));
    let built = match kind {
        K_MC => mc(u, pool, token, &mut enc),
        K_GA => ga(u, pool, token, &mut enc),
        K_CP => cp(u, &mut enc),
        K_CFG => cfg(u, token, &mut enc),
        K_LB if u.ratio(1u8, 3).unwrap_or(false) => lb_read(u, &mut enc),
        K_LB => lb_write(u, lba, token, &mut enc),
        _ => cm(u, pool, token, &mut enc),
    };
    if built.is_err() {
        return 0;
    }
    1 + enc.writer().position()
}

// ----------------------------------------------------------------------- oracle

/// The reply contract `process_cbor` owes on every input: a status byte; an error
/// carries nothing else; a success payload is exactly one definite-length CBOR
/// map with no trailing bytes. A malformed *response* is a finding here, not
/// merely a non-panic.
fn check_reply(out: &[u8], w: usize) {
    assert!(w >= 1 && w <= out.len(), "reply length {w} out of range");
    if out[0] != rsk_fido::CTAP2_OK {
        assert_eq!(w, 1, "a CTAP error reply carries only its status byte");
        return;
    }
    if w == 1 {
        return;
    }
    let body = &out[1..w];
    let mut d = Decoder::new(body);
    assert_eq!(
        d.datatype().ok(),
        Some(minicbor::data::Type::Map),
        "a CTAP2 success payload is a definite-length map"
    );
    d.skip()
        .expect("a success payload must be well-formed CBOR");
    assert_eq!(
        d.position(),
        body.len(),
        "trailing bytes after the reply map"
    );
}

// ---------------------------------------------------------------------- session

/// How many relying parties the display walk keeps hashes for.
const DISPLAY_ROWS: usize = 8;

struct Sess {
    dev: Device<'static>,
    fs: Fs<RamStorage>,
    state: FidoState,
    rng: SeqRng,
    presence: rsk_fido::AlwaysConfirm,
    now_ms: u64,
    pool: CredPool,
    /// The token the generated requests MAC with — [`TOKEN`] until a handshake
    /// mints a real one, and back to it on every [`Sess::rearm`].
    token: [u8; 32],
    out: [u8; OUT_MAX],
}

impl Sess {
    fn new(p: &'static Provisioned) -> Self {
        let mut fs = Fs::new(p.img.clone());
        fs.scan();
        let mut pool = CredPool::new();
        pool.add(&p.resident_id);
        let mut s = Self {
            dev: dev(),
            fs,
            state: FidoState::new(),
            rng: SeqRng(2),
            presence: rsk_fido::AlwaysConfirm,
            now_ms: 2,
            pool,
            token: TOKEN,
            out: [0; OUT_MAX],
        };
        s.rearm();
        s
    }

    /// Plant a token with every permission. A real platform gets a fresh one from
    /// clientPIN after each ceremony spends it (§6.5.5.7 clears UV and all but
    /// largeBlobWrite); this is the cheap stand-in, so a session that never runs
    /// [`Sess::pin_handshake`] still gets more than one token-authorized command
    /// before the rest bounce off `PIN_AUTH_INVALID`.
    fn rearm(&mut self) {
        self.token = TOKEN;
        self.state.paut.token = TOKEN;
        self.state.paut.permissions = ALL_PERMS;
        self.state.paut.has_rp_id = false;
        self.state.begin_using_token(false, self.now_ms);
    }

    /// The clientPIN handshake a platform really runs: getKeyAgreement, ECDH
    /// against a fixed host scalar, setPIN, then a permissions token, which the
    /// generated requests then MAC with. It sets `EF_PIN` — the branch every
    /// PIN-set leg of makeCredential and getAssertion hangs off, and one no
    /// mutator can reach, since setPIN wants a MAC over an ECDH nobody can guess.
    fn pin_handshake(&mut self, proto: PinProto) {
        let p = match proto {
            PinProto::One => 1,
            PinProto::Two => 2,
        };
        let mut msg = [0u8; 256];

        let n = cp_msg(&mut msg, p, CP_GET_KEY_AGREEMENT, &CpReq::default());
        let w = self.step(&msg[..n]);
        if self.out[0] != rsk_fido::CTAP2_OK {
            return;
        }
        let Some((dx, dy)) = key_agreement_xy(&self.out[1..w]) else {
            return;
        };
        let mut shared = [0u8; 64];
        let Ok(slen) = pinproto::ecdh(proto, &HOST_SCALAR, &dx, &dy, &mut shared) else {
            return;
        };
        let secret = &shared[..slen];
        let iv = [0x5Cu8; pinproto::IV_SIZE];

        // setPIN: the padded PIN encrypted under the shared secret, MAC'd with it.
        let mut padded = [0u8; 64];
        padded[..PIN.len()].copy_from_slice(PIN);
        let mut new_pin_enc = [0u8; 64 + pinproto::IV_SIZE];
        let Ok(enc_len) = pinproto::encrypt(proto, secret, &iv, &padded, &mut new_pin_enc) else {
            return;
        };
        let mut mac = [0u8; 32];
        let Ok(mac_len) = pinproto::authenticate(proto, secret, &new_pin_enc[..enc_len], &mut mac)
        else {
            return;
        };
        let n = cp_msg(
            &mut msg,
            p,
            CP_SET_PIN,
            &CpReq {
                key_agreement: true,
                param: &mac[..mac_len],
                new_pin_enc: &new_pin_enc[..enc_len],
                ..CpReq::default()
            },
        );
        self.step(&msg[..n]);

        // …then a token: left16(SHA-256(PIN)) under the same secret.
        let mut pin_hash_enc = [0u8; 16 + pinproto::IV_SIZE];
        let Ok(hash_len) =
            pinproto::encrypt(proto, secret, &iv, &sha256(PIN)[..16], &mut pin_hash_enc)
        else {
            return;
        };
        let n = cp_msg(
            &mut msg,
            p,
            CP_GET_PIN_UV_TOKEN_USING_PIN,
            &CpReq {
                key_agreement: true,
                pin_hash_enc: &pin_hash_enc[..hash_len],
                permissions: HANDSHAKE_PERMS,
                ..CpReq::default()
            },
        );
        let w = self.step(&msg[..n]);
        if self.out[0] != rsk_fido::CTAP2_OK {
            return;
        }
        let Some(sealed) = map_bytes(&self.out[1..w], 2) else {
            return;
        };
        let mut token = [0u8; 32];
        let Ok(len) = pinproto::decrypt(proto, secret, sealed, &mut token) else {
            return;
        };
        assert_eq!(len, TOKEN.len(), "an issued pinUvAuthToken is 32 bytes");
        // §6.5.5.7 mints a fresh token per issuance (`reset_pin_uv_auth_token`);
        // handing back the one the session already held is the linkability the
        // random IV on the ciphertext exists to prevent, one layer down.
        assert_ne!(
            token, self.token,
            "getPinToken re-issued the standing token"
        );
        self.token = token;
    }

    /// Drive one CTAPHID_CBOR message; returns the reply length in `self.out`.
    fn step(&mut self, msg: &[u8]) -> usize {
        let mut ctx = Ctx {
            presence: &mut self.presence,
            dev: self.dev,
            fs: &mut self.fs,
            rng: &mut self.rng,
            state: &mut self.state,
            now_ms: self.now_ms,
        };
        let w = process_cbor(&mut ctx, msg, &mut self.out);
        check_reply(&self.out, w);
        match msg.first().copied() {
            // getInfo is stateless by spec: it must succeed whatever the
            // sequence did before it.
            Some(consts::CTAP_GET_INFO) => assert_eq!(self.out[0], rsk_fido::CTAP2_OK),
            Some(consts::CTAP_MAKE_CREDENTIAL) if self.out[0] == rsk_fido::CTAP2_OK => {
                self.pool.harvest(&self.out[1..w]);
            }
            _ => {}
        }
        // Advance past the token-timeout edges.
        self.now_ms += 997;
        w
    }

    /// The trusted-display Passkeys view over whatever the session left in flash.
    /// `process_cbor` cannot reach `passkeys.rs` — the display task calls it
    /// directly — so without this the store the CTAP walkers wrote is only ever
    /// read back by the CTAP walkers themselves.
    fn display_walk(&mut self) {
        let dev = self.dev;
        let mut hashes = [[0u8; 32]; DISPLAY_ROWS];
        let mut rows = 0usize;
        let total = for_each_rp(&dev, &mut self.fs, |rp| {
            if rows < DISPLAY_ROWS {
                hashes[rows] = rp.rp_id_hash;
                rows += 1;
            }
        });
        assert!(total >= rows, "the RP walk under-counted what it yielded");
        for h in &hashes[..rows] {
            // for_each_rp yields only RPs whose record says >=1 credential AND
            // whose domain unsealed under the live seed, so the credentials must
            // unseal too. A row with none behind it is a dangling index entry —
            // an empty relying party painted on the Passkeys screen.
            assert!(
                for_each_cred(&dev, &mut self.fs, h, |_| {}) > 0,
                "a listed relying party with no credential behind it"
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&arm, rest)) = data.split_first() else {
        return;
    };
    let mut s = Sess::new(provisioned());

    // Byte 0 carries two more bits above the arm selector: whether to run the
    // clientPIN handshake first, and under which protocol. They come out of `arm`
    // rather than from `u`, because a drawn bit re-phases every generated sequence
    // the accumulated corpus encodes while `arm / ARMS` costs nothing.
    let q = arm / ARMS;
    if q & 1 == 1 {
        s.pin_handshake(if q & 2 == 0 {
            PinProto::Two
        } else {
            PinProto::One
        });
    }

    if arm % ARMS == 0 {
        // Arm 0 — raw replay: BE16-length-prefixed CBOR messages, the shape the
        // accumulated corpus is in. Large-blob fragments need more than one byte
        // of length.
        let mut i = 0;
        while i + 2 <= rest.len() {
            let n = u16::from_be_bytes([rest[i], rest[i + 1]]) as usize;
            i += 2;
            let end = (i + n).min(rest.len());
            s.step(&rest[i..end]);
            i = end;
        }
    } else {
        let mut u = Unstructured::new(rest);
        let mut kind = arm % ARMS; // 1..=4 — the opening command
        let mut msg = [0u8; MSG_MAX];
        for _ in 0..MAX_STEPS {
            if kind == K_REARM {
                s.rearm();
            } else {
                let n = build(kind, &mut u, &s.pool, &s.state.lba, &s.token, &mut msg);
                if n > 0 {
                    s.step(&msg[..n]);
                }
            }
            if u.is_empty() {
                break;
            }
            kind = pick(&mut u, &MIX);
        }
    }

    s.display_walk();
});
