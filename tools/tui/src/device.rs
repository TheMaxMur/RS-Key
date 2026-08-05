// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Native device I/O for rsk-tui — FIDO CTAPHID over hidapi and the CCID applets
//! over PC/SC. No external processes: the TUI talks to the key directly.
//!
//! The dashboard reads (getInfo, vendor/rescue status, applet presence) are
//! unauthenticated. The seed backup (export/restore) implements the full MSE
//! channel (P-256 ECDH -> HKDF -> ChaCha20-Poly1305) and, when a PIN is set, the
//! clientPIN protocol-two pinUvAuthToken (ECDH -> HKDF -> AES-CBC + HMAC) +
//! BIP-39 — all in Rust, no `rsk` shell-out. SLIP-39 and the picotool/BOOTSEL
//! fuse rituals stay in the CLI.
//!
//! Everything device-facing is funneled through the [`DeviceProvider`] trait so
//! the UI can be driven by a [`MockProvider`] with no hardware (`--demo`).

use aes::Aes256;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use ciborium::value::{Integer, Value};
use cipher::block_padding::NoPadding;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey, SecretKey};
use pcsc::{Context, Protocols, Scope, ShareMode};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::model::*;

const REPORT_LEN: usize = 64;
const CTAPHID_INIT: u8 = 0x86;
const CTAPHID_CBOR: u8 = 0x90;
const CTAPHID_KEEPALIVE: u8 = 0xBB; // device-still-processing status frame
/// Ceiling on the keepalive wait: a hostile device can stream keepalives forever (each read
/// returns before the per-frame timeout, so that timeout never fires), which would freeze the
/// synchronous TUI. Bail past any legitimate ceremony (30s presence window + slack) instead.
const KEEPALIVE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(120);
const FIDO_USAGE_PAGE: u16 = 0xF1D0;
const CTAP_VENDOR: u8 = 0x41;
const CTAP2_ERR_PIN_REQUIRED: u8 = 0x36;
const MSG_PIN_REQUIRED: &str = "device requires a PIN (set one and retry)";
const PERM_ACFG: i64 = 0x20;
const PERM_CREDMGMT: i64 = 0x04;
/// authenticatorCredentialManagement (0x0A) getCredsMetadata (0x01) — the
/// PIN-gated resident-credential count. Response: {1: existing, 2: remaining}.
const CTAP_CREDENTIAL_MGMT: u8 = 0x0A;
const CM_GET_CREDS_METADATA: u8 = 0x01;

const VENDOR_AID: &[u8] = &[0xF0, 0x00, 0x00, 0x00, 0x01];
const RESCUE_AID: &[u8] = &[0xA0, 0x58, 0x3F, 0xC1, 0x9B, 0x7E, 0x4F, 0x21];
const OPENPGP_AID: &[u8] = &[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];
const PIV_AID: &[u8] = &[
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
];
const OATH_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];
const OTP_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01];

const INS_LED_GET: u8 = 0x11;
const SW_OK: (u8, u8) = (0x90, 0x00);

// Vendor subcommands (CTAP_VENDOR).
const VENDOR_MSE: u8 = 1;
const VENDOR_BACKUP_EXPORT: u8 = 2;
const VENDOR_BACKUP_LOAD: u8 = 3;
const VENDOR_BACKUP_FINALIZE: u8 = 4;
const VENDOR_STATE: u8 = 5;
const VENDOR_ATT_STATE: u8 = 11;
const VENDOR_AUDIT_READ: u8 = 7;
const VENDOR_AUDIT_CHECKPOINT: u8 = 8;

const AUDIT_ENTRY_LEN: usize = 20;
const CKPT_TAG: &[u8] = b"RSK-AUDIT-CKPT-v1";

// Per-frame HID read budgets (ms): quick probe, CBOR exchange, touch-gated op.
const READ_TIMEOUT_MS: i32 = 2000;
const EXCHANGE_TIMEOUT_MS: i32 = 5000;
const TOUCH_TIMEOUT_MS: i32 = 20_000;

pub const COLORS: [&str; 8] = [
    "off", "red", "green", "blue", "yellow", "magenta", "cyan", "white",
];

/// Next idle color: wrap through the non-"off" colours.
fn next_idle_color(current: usize) -> usize {
    (current % (COLORS.len() - 1)) + 1
}

const AUDIT_EVENTS: &[(u8, &str)] = &[
    (0x01, "BOOT"),
    (0x02, "MAKE_CREDENTIAL"),
    (0x03, "GET_ASSERTION"),
    (0x04, "RESET"),
    (0x05, "PIN_SET"),
    (0x06, "PIN_CHANGE"),
    (0x07, "PIN_LOCKOUT"),
    (0x08, "CFG_MIN_PIN"),
    (0x09, "CFG_ENTERPRISE_ATT"),
    (0x0A, "LOCK_ENGAGE"),
    (0x0B, "LOCK_RELEASE"),
    (0x0C, "BACKUP_EXPORT"),
    (0x0D, "BACKUP_LOAD"),
    (0x0E, "BACKUP_FINALIZE"),
    (0x0F, "U2F_REGISTER"),
    (0x10, "U2F_AUTH"),
    (0x11, "CHECKPOINT"),
    (0x12, "ATT_IMPORT"),
    (0x13, "ATT_CLEAR"),
    (0x14, "CFG_ALWAYS_UV"),
    (0x15, "CONFIG_WRITE"),
];

fn event_name(t: u8) -> String {
    AUDIT_EVENTS
        .iter()
        .find(|(k, _)| *k == t)
        .map(|(_, n)| (*n).to_string())
        .unwrap_or_else(|| format!("0x{t:02x}"))
}

// ===========================================================================
// Provider abstraction — the only surface the app talks to.
// ===========================================================================

/// Everything the cockpit can ask of a device. Implemented by
/// [`HardwareProvider`] (real I/O) and [`MockProvider`] (`--demo`).
pub trait DeviceProvider {
    fn snapshot(&mut self) -> DeviceSnapshot;
    /// Run a (non-Refresh) action. The caller has already collected any inputs.
    fn run(&mut self, action: Action, input: &ActionInput) -> ActionResult;
}

/// Talks to a real key over hidapi + PC/SC.
#[derive(Default)]
pub struct HardwareProvider;

impl DeviceProvider for HardwareProvider {
    fn snapshot(&mut self) -> DeviceSnapshot {
        snapshot()
    }

    fn run(&mut self, action: Action, input: &ActionInput) -> ActionResult {
        let pin = input.pin.as_deref().map(String::as_str);
        match action {
            // Refresh is handled by the caller (it just re-snapshots).
            Action::Refresh => ActionResult::Ok("status refreshed".into()),
            Action::CredCount => match cred_count(pin) {
                Ok((existing, remaining)) => ActionResult::Ok(format!(
                    "{existing} resident passkey{} · ~{remaining} slot{} free",
                    if existing == 1 { "" } else { "s" },
                    if remaining == 1 { "" } else { "s" },
                )),
                Err(e) => ActionResult::Failed(format!("credMgmt failed: {e}")),
            },
            Action::LedGet => match led_get() {
                Ok(s) => ActionResult::Report {
                    title: "LED state".into(),
                    body: s,
                },
                Err(e) => ActionResult::Failed(format!("LED read failed: {e}")),
            },
            Action::LedCycle => match led_cycle_idle() {
                Ok(s) => ActionResult::Ok(s),
                Err(e) => ActionResult::Failed(format!("LED set failed: {e}")),
            },
            Action::RebootApp => match reboot(false) {
                Ok(s) => ActionResult::Ok(s),
                Err(e) => ActionResult::Failed(format!("reboot failed: {e}")),
            },
            Action::RebootBootsel => match reboot(true) {
                Ok(s) => ActionResult::Ok(s),
                Err(e) => ActionResult::Failed(format!("reboot failed: {e}")),
            },
            Action::BackupExport => match backup_export(pin) {
                Ok(words) => ActionResult::Reveal {
                    title: "seed · BIP-39 (24 words)".into(),
                    body: Zeroizing::new(words),
                },
                Err(e) => ActionResult::Failed(format!("export failed: {e}")),
            },
            Action::BackupExportSlip39 => match backup_export_slip39(pin) {
                Ok(body) => ActionResult::Reveal {
                    title: "seed · SLIP-39 (2-of-3 shares)".into(),
                    body: Zeroizing::new(body),
                },
                Err(e) => ActionResult::Failed(format!("export failed: {e}")),
            },
            Action::BackupRestore => {
                let phrase = input.phrase.as_deref().map(String::as_str).unwrap_or("");
                match backup_restore(phrase, pin) {
                    Ok(s) => ActionResult::Ok(s),
                    Err(e) => ActionResult::Failed(format!("restore failed: {e}")),
                }
            }
            Action::BackupFinalize => match backup_finalize() {
                Ok(s) => ActionResult::Ok(s),
                Err(e) => ActionResult::Failed(format!("finalize failed: {e}")),
            },
            Action::AuditRead => match audit_read(pin) {
                Ok((title, body)) => ActionResult::Report { title, body },
                Err(e) => ActionResult::Failed(format!("audit read failed: {e}")),
            },
            Action::Verify => match verify_identity(pin) {
                Ok((title, body)) => ActionResult::Report { title, body },
                Err(e) => ActionResult::Failed(format!("verify failed: {e}")),
            },
        }
    }
}

// ===========================================================================
// FIDO CTAPHID (hidapi)
// ===========================================================================

/// How many FIDO HID devices are attached. More than one means this dashboard cannot
/// know that the device it acts on is the one whose CCID serial it shows.
fn hid_device_count() -> usize {
    match hidapi::HidApi::new() {
        Ok(api) => api
            .device_list()
            .filter(|d| d.usage_page() == FIDO_USAGE_PAGE)
            .count(),
        Err(_) => 0,
    }
}

/// Open the FIDO HID device, also returning its bcdDevice + product string.
fn hid_open_info() -> Option<(hidapi::HidDevice, u16, Option<String>)> {
    let api = hidapi::HidApi::new().ok()?;
    let info = api
        .device_list()
        .find(|d| d.usage_page() == FIDO_USAGE_PAGE)?;
    let bcd = info.release_number();
    let product = info.product_string().map(str::to_string);
    let dev = info.open_device(&api).ok()?;
    Some((dev, bcd, product))
}

fn hid_open() -> Option<hidapi::HidDevice> {
    hid_open_info().map(|(d, _, _)| d)
}

/// Open the FIDO HID device for an **action**, refusing to guess when more than one
/// authenticator is attached.
///
/// `hid_open_info` takes the first match and `rs_key_reader` independently takes the
/// first matching reader, so with two keys plugged in one dashboard could drive two
/// different devices — `BackupExport` labelling another key's seed as this one's,
/// `BackupFinalize` irreversibly sealing whichever answered. The snapshot may still
/// present a best-effort view (it flags `hid_ambiguous`), but an irreversible write
/// must not proceed on a guess: `tools/rsk` already refuses these outright via
/// `connect_fido(exclusive=True)`, and touch-gating binds the ceremony, not the
/// device it lands on (audit run-33).
fn hid_open_exclusive() -> Result<hidapi::HidDevice, String> {
    refuse_ambiguous(hid_device_count())?;
    hid_open().ok_or_else(|| "no FIDO device".into())
}

/// The refusal itself, split from the open so it is testable without a device —
/// all it depends on is a count.
fn refuse_ambiguous(n: usize) -> Result<(), String> {
    if n > 1 {
        return Err(format!(
            "{n} FIDO devices attached — unplug all but the intended one; \
             this action is irreversible and must not guess"
        ));
    }
    Ok(())
}

fn hid_write(dev: &hidapi::HidDevice, frame: &[u8]) {
    let mut buf = [0u8; REPORT_LEN + 1];
    let n = frame.len().min(REPORT_LEN);
    buf[1..1 + n].copy_from_slice(&frame[..n]);
    let _ = dev.write(&buf);
}

fn hid_read(dev: &hidapi::HidDevice, ms: i32) -> Vec<u8> {
    let mut buf = [0u8; REPORT_LEN];
    match dev.read_timeout(&mut buf, ms) {
        Ok(n) => buf[..n].to_vec(),
        Err(_) => Vec::new(),
    }
}

fn ctaphid_init(dev: &hidapi::HidDevice) -> Option<[u8; 4]> {
    let mut f = vec![0xff, 0xff, 0xff, 0xff, CTAPHID_INIT, 0, 8];
    f.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    hid_write(dev, &f);
    let r = hid_read(dev, READ_TIMEOUT_MS);
    if r.len() < 19 || r[4] != CTAPHID_INIT {
        return None;
    }
    Some([r[15], r[16], r[17], r[18]])
}

/// Send a CTAP2 CBOR command and return the raw response (status byte + payload).
/// `ms` is the per-frame read timeout — long for touch-gated ops.
fn send_cbor(dev: &hidapi::HidDevice, cid: [u8; 4], payload: &[u8], ms: i32) -> Vec<u8> {
    let n = payload.len();
    let mut f = cid.to_vec();
    f.extend_from_slice(&[CTAPHID_CBOR, (n >> 8) as u8, (n & 0xff) as u8]);
    f.extend_from_slice(&payload[..n.min(57)]);
    hid_write(dev, &f);
    let (mut off, mut seq) = (57usize, 0u8);
    while off < n {
        let mut c = cid.to_vec();
        c.push(seq);
        let end = (off + 59).min(n);
        c.extend_from_slice(&payload[off..end]);
        hid_write(dev, &c);
        off = end;
        seq = seq.wrapping_add(1);
    }
    let mut r = hid_read(dev, ms);
    let deadline = std::time::Instant::now() + KEEPALIVE_DEADLINE;
    while r.len() >= 5 && r[4] == CTAPHID_KEEPALIVE {
        // UP wait — but a hostile device can stream keepalives forever; give up rather
        // than freeze the synchronous TUI event loop.
        if std::time::Instant::now() > deadline {
            return Vec::new();
        }
        r = hid_read(dev, ms);
    }
    if r.len() < 7 {
        return Vec::new();
    }
    let bcnt = ((r[5] as usize) << 8) | r[6] as usize;
    let mut data = r[7..(7 + bcnt).min(r.len())].to_vec();
    while data.len() < bcnt {
        // Bound the wall clock as well as the byte budget: a device trickling one
        // 6-byte frame per HID timeout makes progress every iteration, so the guard
        // below never fires — it would otherwise freeze the synchronous TUI event loop
        // for hours (audit run-30). An empty result is how the keepalive path signals
        // failure to callers.
        if std::time::Instant::now() > deadline {
            return Vec::new();
        }
        let c = hid_read(dev, ms);
        if c.len() < 6 {
            break;
        }
        let take = (bcnt - data.len()).min(59).min(c.len() - 5);
        data.extend_from_slice(&c[5..5 + take]);
    }
    data.truncate(bcnt);
    data
}

/// Encode + send a vendor (0x41) command and decode the CBOR response map.
/// Returns `(status, value)`.
fn vendor(dev: &hidapi::HidDevice, cid: [u8; 4], req: Value, ms: i32) -> (u8, Option<Value>) {
    let mut payload = vec![CTAP_VENDOR];
    payload.extend_from_slice(&cbor(&req));
    let r = send_cbor(dev, cid, &payload, ms);
    match r.first() {
        Some(0) => (0, ciborium::de::from_reader(&r[1..]).ok()),
        Some(s) => (*s, None),
        None => (0xFF, None),
    }
}

// ===========================================================================
// CBOR helpers
// ===========================================================================

fn iv(n: i64) -> Value {
    Value::Integer(Integer::from(n))
}

fn cbor(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(v, &mut out).expect("cbor encode");
    out
}

fn cose_key(x: &[u8], y: &[u8]) -> Value {
    Value::Map(vec![
        (iv(1), iv(2)),
        (iv(3), iv(-25)),
        (iv(-1), iv(1)),
        (iv(-2), Value::Bytes(x.to_vec())),
        (iv(-3), Value::Bytes(y.to_vec())),
    ])
}

fn map_get(v: &Value, key: i128) -> Option<&Value> {
    if let Value::Map(m) = v {
        for (k, val) in m {
            if let Value::Integer(i) = k
                && i128::from(*i) == key
            {
                return Some(val);
            }
        }
    }
    None
}

fn as_u32(v: &Value) -> Option<u32> {
    if let Value::Integer(i) = v {
        u32::try_from(i128::from(*i)).ok()
    } else {
        None
    }
}

// ===========================================================================
// crypto primitives (HW-verified — do not alter the algorithm)
// ===========================================================================

fn ecdh_pub() -> (SecretKey, [u8; 32], [u8; 32]) {
    let sk = SecretKey::random(&mut OsRng);
    let ep = sk.public_key().to_encoded_point(false);
    let (mut x, mut y) = ([0u8; 32], [0u8; 32]);
    x.copy_from_slice(ep.x().unwrap());
    y.copy_from_slice(ep.y().unwrap());
    (sk, x, y)
}

fn ecdh_raw(sk: &SecretKey, px: &[u8; 32], py: &[u8; 32]) -> Option<[u8; 32]> {
    let ep = EncodedPoint::from_affine_coordinates(px.into(), py.into(), false);
    let peer = Option::<PublicKey>::from(PublicKey::from_encoded_point(&ep))?;
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    let mut z = [0u8; 32];
    z.copy_from_slice(shared.raw_secret_bytes());
    Some(z)
}

fn hkdf32(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut okm)
        .expect("hkdf");
    okm
}

fn hmac256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}

fn aes_cbc_encrypt(key: &[u8; 32], pt: &[u8]) -> Vec<u8> {
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);
    let mut buf = pt.to_vec();
    let n = buf.len();
    cbc::Encryptor::<Aes256>::new_from_slices(key, &iv)
        .unwrap()
        .encrypt_padded_mut::<NoPadding>(&mut buf, n)
        .unwrap();
    let mut out = iv.to_vec();
    out.extend_from_slice(&buf);
    out
}

fn aes_cbc_decrypt(key: &[u8; 32], data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 32 {
        return None;
    }
    let (iv, ct) = data.split_at(16);
    let mut buf = ct.to_vec();
    let pt = cbc::Decryptor::<Aes256>::new_from_slices(key, iv)
        .ok()?
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .ok()?;
    Some(pt.to_vec())
}

fn chacha_decrypt(key: &[u8; 32], nonce: &[u8], aad: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    ChaCha20Poly1305::new_from_slice(key)
        .ok()?
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .ok()
}

fn chacha_encrypt(key: &[u8; 32], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Vec<u8> {
    ChaCha20Poly1305::new_from_slice(key)
        .unwrap()
        .encrypt(Nonce::from_slice(nonce), Payload { msg: pt, aad })
        .unwrap()
}

// ===========================================================================
// snapshot — the unauthenticated reads that fill the dashboard
// ===========================================================================

/// Gather the full device snapshot over both transports. Every channel is
/// probed softly: an absent or erroring channel is recorded, never fatal.
pub fn snapshot() -> DeviceSnapshot {
    let mut snap = DeviceSnapshot::default();
    read_fido(&mut snap);
    read_ccid(&mut snap);
    snap
}

fn read_fido(snap: &mut DeviceSnapshot) {
    let Some((dev, bcd, product)) = hid_open_info() else {
        snap.transport.hid = Link::Absent;
        return;
    };
    snap.transport.hid = Link::Present;
    snap.fido.present = true;
    snap.identity.bcd_device = Some(bcd);
    snap.identity.product = product;
    // The header merges HID-sourced and CCID-sourced identity into one line, and every
    // action re-opens the HID device independently. With more than one authenticator
    // attached that line would vouch for a device the action may not be talking to —
    // during a seed export, that is the difference between a real recovery phrase and
    // a forged one. Flag it rather than presenting a confident identity.
    snap.identity.hid_ambiguous = hid_device_count() > 1;

    let Some(cid) = ctaphid_init(&dev) else {
        snap.transport.hid = Link::Error;
        snap.errors.push("CTAPHID init failed".into());
        return;
    };

    let gi = send_cbor(&dev, cid, &[0x04], READ_TIMEOUT_MS);
    if gi.first() == Some(&0)
        && let Ok(v) = ciborium::de::from_reader::<Value, _>(&gi[1..])
    {
        if let Some(Value::Array(a)) = map_get(&v, 1) {
            snap.fido.versions = a
                .iter()
                .filter_map(|x| x.as_text().map(String::from))
                .collect();
        }
        if let Some(Value::Integer(i)) = map_get(&v, 14) {
            let n = i128::from(*i) as u32;
            snap.identity.firmware = Some(format!(
                "{}.{}.{}",
                (n >> 16) & 0xff,
                (n >> 8) & 0xff,
                n & 0xff
            ));
        }
        if let Some(Value::Bytes(b)) = map_get(&v, 3) {
            snap.identity.aaguid = Some(hex(b));
        }
        if let Some(Value::Map(opts)) = map_get(&v, 4) {
            for (k, val) in opts {
                if let Some(name) = k.as_text() {
                    if name == "clientPin" {
                        snap.fido.client_pin = val.as_bool();
                    }
                    if val.as_bool() == Some(true) {
                        snap.fido.options.push(name.to_string());
                    }
                }
            }
            snap.fido.options.sort();
        }
    }

    // Vendor STATE — backup + soft-lock.
    if let (0, Some(v)) = vendor(
        &dev,
        cid,
        Value::Map(vec![(iv(1), iv(VENDOR_STATE as i64))]),
        READ_TIMEOUT_MS,
    ) {
        snap.backup = Some(BackupState {
            sealed: map_get(&v, 1).and_then(Value::as_bool).unwrap_or(false),
            has_seed: map_get(&v, 2).and_then(Value::as_bool).unwrap_or(false),
        });
        if let (Some(locked), Some(unlocked)) = (
            map_get(&v, 3).and_then(Value::as_bool),
            map_get(&v, 4).and_then(Value::as_bool),
        ) {
            snap.lock = Some(LockState { locked, unlocked });
        }
    }

    // Vendor ATT_STATE — org attestation.
    if let (0, Some(v)) = vendor(
        &dev,
        cid,
        Value::Map(vec![(iv(1), iv(VENDOR_ATT_STATE as i64))]),
        READ_TIMEOUT_MS,
    ) {
        let installed = map_get(&v, 1).and_then(Value::as_bool).unwrap_or(false);
        let chain = match map_get(&v, 2) {
            Some(Value::Bytes(b)) if installed => Some(hex(b)),
            _ => None,
        };
        snap.attestation = Some(AttestationState {
            installed,
            chain_sha256: chain,
        });
    }
}

fn read_ccid(snap: &mut DeviceSnapshot) {
    let ctx = match Context::establish(Scope::User) {
        Ok(c) => c,
        Err(_) => {
            snap.transport.pcsc = Link::Absent;
            return;
        }
    };
    let mut names = [0u8; 2048];
    let readers: Vec<&std::ffi::CStr> = match ctx.list_readers(&mut names) {
        Ok(r) => r.collect(),
        Err(_) => {
            snap.transport.pcsc = Link::Error;
            return;
        }
    };
    if readers.is_empty() {
        snap.transport.pcsc = Link::Absent;
        return;
    }
    snap.transport.pcsc = Link::Present;
    let target = match rs_key_reader(&readers) {
        Ok(t) => t,
        Err(e) => {
            snap.transport.ccid = Link::Absent;
            snap.transport.note = Some(e);
            return;
        }
    };
    let card = match ctx.connect(target, ShareMode::Shared, Protocols::ANY) {
        Ok(c) => c,
        Err(e) => {
            snap.transport.ccid = Link::Busy;
            snap.transport.note = Some(format!("CCID reader busy? ({e})"));
            return;
        }
    };
    let mut ccid = Ccid {
        card,
        buf: [0u8; 1024],
    };

    // Rescue applet: identity + secure boot + rollback + flash.
    if ccid.select(RESCUE_AID).is_ok() {
        snap.transport.ccid = Link::Present;
        if let Ok((d, s1, s2)) = ccid.apdu_select(RESCUE_AID)
            && (s1, s2) == SW_OK
            && d.len() >= 12
        {
            snap.identity.serial = Some(hex(&d[4..12]));
            snap.identity.sdk = Some(format!("{}.{}", d[2], d[3]));
        }
        if let Ok((d, s1, s2)) = ccid.apdu(&[0x80, 0x1E, 0x03, 0x00, 0x00])
            && (s1, s2) == SW_OK
            && d.len() >= 3
        {
            snap.secure_boot = Some(SecureBootState {
                enabled: d[0] != 0,
                locked: d[1] != 0,
                bootkey: d[2],
            });
        }
        if let Ok((d, s1, s2)) = ccid.apdu(&[0x80, 0x1E, 0x06, 0x00, 0x00])
            && (s1, s2) == SW_OK
            && d.len() >= 3
        {
            snap.rollback = Some(RollbackState {
                required: d[0] != 0,
                version: d[1],
                capacity: d[2],
            });
        }
        if let Ok((d, s1, s2)) = ccid.apdu(&[0x80, 0x1E, 0x02, 0x00, 0x00])
            && (s1, s2) == SW_OK
            && d.len() >= 20
        {
            snap.flash = Some(FlashState {
                free: u32::from_be_bytes([d[0], d[1], d[2], d[3]]),
                used: u32::from_be_bytes([d[4], d[5], d[6], d[7]]),
                kv_total: u32::from_be_bytes([d[8], d[9], d[10], d[11]]),
                files: u32::from_be_bytes([d[12], d[13], d[14], d[15]]),
                chip: u32::from_be_bytes([d[16], d[17], d[18], d[19]]),
            });
        }
    } else {
        snap.transport.ccid = Link::Error;
    }

    // Applet presence — a plain SELECT is a read with no state change. Where the
    // applet answers, pull the cheap unauthenticated metadata while it is still
    // the selected applet (OpenPGP `6E`, PIV PIN GET METADATA).
    let openpgp = ccid.select(OPENPGP_AID).is_ok();
    snap.applets.openpgp = Some(openpgp);
    if openpgp {
        snap.pgp = read_pgp_info(&mut ccid);
    }
    let piv = ccid.select(PIV_AID).is_ok();
    snap.applets.piv = Some(piv);
    if piv {
        snap.piv_meta = read_piv_meta(&mut ccid);
    }
    snap.applets.oath = Some(ccid.select(OATH_AID).is_ok());
    snap.applets.otp = Some(ccid.select(OTP_AID).is_ok());

    // LED colours (VENDOR_AID) — last, since selecting it deselects the applets
    // probed above.
    if ccid.select(VENDOR_AID).is_ok()
        && let Ok((d, stride)) = led_read_config(&mut ccid)
    {
        snap.led = parse_led(&d, stride);
    }
}

/// Find the value of the first top-level BER-TLV with `tag` (1- or 2-byte tag,
/// short / `0x81` / `0x82` length). Enough for the OpenPGP `6E` template and the
/// PIV metadata TLVs; a malformed length just ends the walk (returns `None`).
fn ber_find(mut d: &[u8], tag: u16) -> Option<&[u8]> {
    while !d.is_empty() {
        let (t, rest) = if d[0] & 0x1F == 0x1F {
            if d.len() < 2 {
                return None;
            }
            ((u16::from(d[0]) << 8) | u16::from(d[1]), &d[2..])
        } else {
            (u16::from(d[0]), &d[1..])
        };
        let (len, val) = match rest.split_first() {
            Some((&n, r)) if n < 0x80 => (n as usize, r),
            Some((&0x81, r)) => (*r.first()? as usize, &r[1..]),
            Some((&0x82, r)) => (((*r.first()? as usize) << 8) | *r.get(1)? as usize, &r[2..]),
            _ => return None,
        };
        if val.len() < len {
            return None;
        }
        if t == tag {
            return Some(&val[..len]);
        }
        d = &val[len..];
    }
    None
}

/// OpenPGP application-related data from the `6E` GET DATA template: card serial,
/// the three PIN retry counters (`C4`), and how many key slots are populated
/// (`C5`). Every field is optional — a card that omits one just leaves it unset.
fn read_pgp_info(c: &mut Ccid) -> Option<PgpInfo> {
    let d = c.get_data_full(0x00, 0x6E).ok()?;
    let inner = ber_find(&d, 0x6E).unwrap_or(&d);
    let mut info = PgpInfo::default();
    // 4F AID: D276 0001 2401 vvvv mmmm ssssssss 0000 — serial is bytes 10..14.
    if let Some(aid) = ber_find(inner, 0x4F)
        && aid.len() >= 14
    {
        info.serial = Some(hex(&aid[10..14]));
    }
    // C4 PW status: [validity, pw1max, rcmax, pw3max, pw1tries, rctries, pw3tries].
    if let Some(c4) = ber_find(inner, 0xC4)
        && c4.len() >= 7
    {
        info.pin_retries = Some([c4[4], c4[5], c4[6]]);
    }
    // C5 fingerprints: 3 x 20 bytes (sig/dec/auth); an all-zero block = no key.
    if let Some(c5) = ber_find(inner, 0xC5)
        && c5.len() >= 60
    {
        info.keys_present = (0..3)
            .filter(|k| c5[k * 20..k * 20 + 20].iter().any(|&b| b != 0))
            .count() as u8;
    }
    Some(info)
}

/// PIV PIN metadata (GET METADATA, INS 0xF7 / P2 0x80): retry counters + whether
/// the PIN is still the factory default. Unauthenticated.
fn read_piv_meta(c: &mut Ccid) -> Option<PivInfo> {
    let (d, s1, s2) = c.apdu(&[0x00, 0xF7, 0x00, 0x80, 0x00]).ok()?;
    if (s1, s2) != SW_OK {
        return None;
    }
    let mut info = PivInfo::default();
    if let Some(def) = ber_find(&d, 0x05)
        && !def.is_empty()
    {
        info.pin_default = def[0] != 0;
    }
    if let Some(r) = ber_find(&d, 0x06)
        && r.len() >= 2
    {
        info.pin_total = r[0];
        info.pin_left = r[1];
    }
    Some(info)
}

// ===========================================================================
// CCID applets (PC/SC)
// ===========================================================================

// Default build's product carries "RS-Key"; the opt-in Yubico interop
// flavor carries "RSK". Neither is in a genuine YubiKey's reader name.
const READER_TOKEN_DEFAULT: &str = "RS-Key";
const READER_TOKEN_INTEROP: &str = "RSK";

fn rs_key_reader<'a>(readers: &[&'a std::ffi::CStr]) -> Result<&'a std::ffi::CStr, String> {
    // No first-reader fallback: with the RS-Key's CCID interface absent (unplugged, or
    // `ykman config usb --disable CCID`) any other card in a reader would be selected —
    // and this dashboard SELECTs five applets on it every refresh and then renders its
    // PIN retry counters as the RS-Key's. `tools/rsk/ccid.py` dropped the same fallback.
    // …and no first-of-several either: two attached keys present two matching
    // readers, so `reboot`'s BOOTSEL drop could land on the other one while the HID
    // side of the same screen talks to this one. The CLI refuses the same way
    // (`ccid.connect(exclusive=True)`) — audit run-33.
    let matching: Vec<&std::ffi::CStr> = readers
        .iter()
        .filter(|r| {
            let n = r.to_string_lossy();
            n.contains(READER_TOKEN_DEFAULT) || n.contains(READER_TOKEN_INTEROP)
        })
        .copied()
        .collect();
    match matching.as_slice() {
        [one] => Ok(one),
        [] => {
            let names: Vec<String> = readers.iter().map(|r| r.to_string_lossy().into()).collect();
            Err(format!(
                "no RS-Key reader found (readers: {})",
                names.join(", ")
            ))
        }
        many => Err(format!(
            "{} RS-Key readers found — unplug all but the intended device",
            many.len()
        )),
    }
}

struct Ccid {
    card: pcsc::Card,
    buf: [u8; 1024],
}

impl Ccid {
    fn open() -> Result<Self, String> {
        let ctx = Context::establish(Scope::User).map_err(|e| format!("pcsc: {e}"))?;
        let mut names = [0u8; 2048];
        let readers: Vec<&std::ffi::CStr> = ctx
            .list_readers(&mut names)
            .map_err(|e| format!("readers: {e}"))?
            .collect();
        if readers.is_empty() {
            return Err("no PC/SC readers".into());
        }
        let target = rs_key_reader(&readers)?;
        let card = ctx
            .connect(target, ShareMode::Shared, Protocols::ANY)
            .map_err(|e| format!("connect (reader busy?): {e}"))?;
        Ok(Ccid {
            card,
            buf: [0u8; 1024],
        })
    }

    fn apdu(&mut self, data: &[u8]) -> Result<(Vec<u8>, u8, u8), String> {
        let r = self
            .card
            .transmit(data, &mut self.buf)
            .map_err(|e| format!("transmit: {e}"))?;
        if r.len() < 2 {
            return Err("short response".into());
        }
        Ok((r[..r.len() - 2].to_vec(), r[r.len() - 2], r[r.len() - 1]))
    }

    /// SELECT an applet, returning the full response (data + status).
    fn apdu_select(&mut self, aid: &[u8]) -> Result<(Vec<u8>, u8, u8), String> {
        let mut a = vec![0x00, 0xA4, 0x04, 0x00, aid.len() as u8];
        a.extend_from_slice(aid);
        a.push(0x00);
        self.apdu(&a)
    }

    fn select(&mut self, aid: &[u8]) -> Result<(), String> {
        let (_, s1, s2) = self.apdu_select(aid)?;
        if (s1, s2) != SW_OK {
            return Err(format!("SELECT failed {s1:02X}{s2:02X}"));
        }
        Ok(())
    }

    /// GET DATA (00 CA P1 P2) with 61xx GET RESPONSE chaining, so a DO larger than
    /// one APDU (the OpenPGP `6E` template) comes back whole.
    fn get_data_full(&mut self, p1: u8, p2: u8) -> Result<Vec<u8>, String> {
        chain_get_response(|apdu| self.apdu(apdu), p1, p2)
    }
}

/// Drive `00 CA` GET DATA plus its `61xx` GET RESPONSE chaining over `send`, BOUNDED
/// so a hostile/counterfeit device that streams `61xx` forever can neither hang the
/// synchronous TUI event loop (a bare `61 00` adds no bytes, so a size cap alone never
/// fires — the round cap is what stops the spin) nor grow `out` without limit.
fn chain_get_response(
    mut send: impl FnMut(&[u8]) -> Result<(Vec<u8>, u8, u8), String>,
    p1: u8,
    p2: u8,
) -> Result<Vec<u8>, String> {
    const MAX_CHAIN: usize = 64; // no legitimate DO needs this many GET RESPONSE rounds
    const MAX_DO_LEN: usize = 8 * 1024; // nor this many bytes
    let (mut out, mut s1, mut s2) = send(&[0x00, 0xCA, p1, p2, 0x00])?;
    let mut rounds = 0usize;
    while s1 == 0x61 {
        rounds += 1;
        if rounds > MAX_CHAIN {
            return Err("GET RESPONSE chain too long (hostile device?)".into());
        }
        let (more, ns1, ns2) = send(&[0x00, 0xC0, 0x00, 0x00, s2])?;
        out.extend_from_slice(&more);
        if out.len() > MAX_DO_LEN {
            return Err("data object too large (hostile device?)".into());
        }
        (s1, s2) = (ns1, ns2);
    }
    if (s1, s2) != SW_OK {
        return Err(format!("GET DATA {s1:02X}{s2:02X}"));
    }
    Ok(out)
}

// ===========================================================================
// LED / reboot (native, unauthenticated)
// ===========================================================================

/// Extract the four status colours (indices into [`COLORS`]) from a raw
/// EF_LED_CONF record + its per-status stride, mirroring the offsets in
/// [`led_get`]: `d[0]` is the steady flag, then four `stride`-byte blocks whose
/// colour byte is at `+1` for stride ≥ 3 (effect-prefixed) or `+0` otherwise.
fn parse_led(d: &[u8], stride: usize) -> Option<LedState> {
    if d.len() < 1 + 4 * stride {
        return None;
    }
    let color = |i: usize| {
        let off = 1 + i * stride;
        if stride >= 3 { d[off + 1] } else { d[off] }
    };
    Some(LedState {
        steady: d[0] != 0,
        idle: color(0),
        processing: color(1),
        touch: color(2),
        boot: color(3),
    })
}

/// Send GET LED and return the raw EF_LED_CONF record plus its per-status stride.
fn led_read_config(c: &mut Ccid) -> Result<(Vec<u8>, usize), String> {
    let (d, s1, s2) = c.apdu(&[0x00, INS_LED_GET, 0x00, 0x00, 0x00])?;
    if (s1, s2) != SW_OK || d.len() < 9 {
        return Err(format!("GET LED {s1:02X}{s2:02X}"));
    }
    let stride = if d.len() >= 17 {
        4
    } else if d.len() >= 13 {
        3
    } else {
        2
    };
    Ok((d, stride))
}

pub fn led_get() -> Result<String, String> {
    let mut c = Ccid::open()?;
    c.select(VENDOR_AID)?;
    let (d, stride) = led_read_config(&mut c)?;
    let names = ["idle", "processing", "touch", "boot"];
    let effect_names = ["legacy", "vapor", "bounce", "flow", "sparkle"];
    let mut out = format!("mode = {}\n", if d[0] != 0 { "steady" } else { "blink" });
    for (i, name) in names.iter().enumerate() {
        let off = 1 + i * stride;
        // stride=2: [color, brightness]; stride>=3: [effect, color, brightness, …]
        let (color, brightness) = if stride >= 3 {
            (d[off + 1], d[off + 2])
        } else {
            (d[off], d[off + 1])
        };
        let effect = if stride >= 3 {
            format!(
                " effect={}",
                effect_names.get(d[off] as usize).copied().unwrap_or("?")
            )
        } else {
            String::new()
        };
        out += &format!(
            "{name:<11} {}  (brightness {}){}\n",
            COLORS.get(color as usize).copied().unwrap_or("?"),
            brightness,
            effect,
        );
    }
    Ok(out)
}

pub fn led_cycle_idle() -> Result<String, String> {
    let mut c = Ccid::open()?;
    c.select(VENDOR_AID)?;
    let (d, stride) = led_read_config(&mut c)?;
    // idle status: color/brightness offset depends on stride.
    let (idle_color, idle_brightness) = if stride >= 3 {
        (d[2], d[3]) // [steady, (effect, color, brightness, …), …]
    } else {
        (d[1], d[2]) // [steady, (color, brightness), …]
    };
    let next = next_idle_color(idle_color as usize);
    let brightness = if idle_brightness == 0 {
        16
    } else {
        idle_brightness
    };
    let p2 = (next as u8 & 0x7) | if d[0] != 0 { 0x08 } else { 0 };
    let (_, s1, s2) = c.apdu(&[0x00, 0x10, brightness, p2])?;
    if (s1, s2) != SW_OK {
        return Err(format!("SET LED {s1:02X}{s2:02X}"));
    }
    Ok(format!("idle color → {}", COLORS[next]))
}

pub fn reboot(bootsel: bool) -> Result<String, String> {
    let mut c = Ccid::open()?;
    c.select(VENDOR_AID)?;
    // The device gates reboot-to-BOOTSEL behind an on-screen confirm and answers 6985
    // when it is declined or times out. Discarding the status word reported a refused
    // security gate as a green success (`tools/rsk/reboot.py` gets this right).
    let (_, s1, s2) = c.apdu(&[0x00, 0x1F, if bootsel { 0x01 } else { 0x00 }, 0x00, 0x00])?;
    if (s1, s2) == (0x69, 0x85) {
        return Err("reboot declined on the device".into());
    }
    if (s1, s2) != (0x90, 0x00) {
        return Err(format!("reboot refused ({s1:02x}{s2:02x})"));
    }
    Ok(format!(
        "reboot → {} sent",
        if bootsel { "BOOTSEL" } else { "app" }
    ))
}

// ===========================================================================
// audit journal (read) + identity verify (signed checkpoint)
// ===========================================================================

/// Read the tamper-evident journal (vendor AUDIT_READ). Read-only; the device
/// asks for a PIN if one is set, or a touch if not. Returns `(title, pretty body)`.
pub fn audit_read(pin: Option<&str>) -> Result<(String, String), String> {
    let dev = hid_open().ok_or("no FIDO device")?;
    let cid = ctaphid_init(&dev).ok_or("CTAPHID init failed")?;
    let token = pin.map(|p| acfg_token(&dev, cid, p)).transpose()?;

    let mut req = vec![(iv(1), iv(VENDOR_AUDIT_READ as i64))];
    if let Some((_, v)) = gate_param(token.as_ref(), VENDOR_AUDIT_READ, &[]) {
        req.push((iv(3), iv(2)));
        req.push((iv(4), v));
    }
    let (st, v) = vendor(&dev, cid, Value::Map(req), EXCHANGE_TIMEOUT_MS);
    match st {
        0 => {}
        CTAP2_ERR_PIN_REQUIRED => return Err(MSG_PIN_REQUIRED.into()),
        // No PIN set → the read is touch-gated instead (firmware ≥ 0x0808).
        0x27 => {
            return Err(
                "no touch within the timeout — press the button when the LED blinks".into(),
            );
        }
        s => return Err(format!("status {s:#x}")),
    }
    let v = v.ok_or("decode failed")?;
    let start = map_get(&v, 1).and_then(as_u32).ok_or("no start")?;
    let seq_next = map_get(&v, 2).and_then(as_u32).ok_or("no seq")?;
    let epoch = match map_get(&v, 3) {
        Some(Value::Bytes(b)) => b.clone(),
        _ => return Err("no epoch".into()),
    };
    let entries = match map_get(&v, 4) {
        Some(Value::Bytes(b)) => b.clone(),
        _ => return Err("no entries".into()),
    };
    // Treat the device as untrusted: a length that is not a whole number of entries
    // would make the fixed-stride display slice run past the end and panic — and a
    // *short* export would let a device present 1 of N events as a complete window
    // while the tamper surface reports nothing. Both checks, matching audit.py.
    if seq_next < start {
        return Err("malformed audit journal (window runs backwards)".into());
    }
    let want = (seq_next - start) as usize * AUDIT_ENTRY_LEN;
    if entries.len() % AUDIT_ENTRY_LEN != 0 || entries.len() != want {
        return Err("export length does not match the window — corrupt journal?".into());
    }

    let head = fold(&epoch, &entries);
    let count = entries.len() / AUDIT_ENTRY_LEN;
    let mut body = format!(
        "window [{start}, {seq_next})  —  {count} entries, {start} folded into the epoch\n\
         epoch : {}\n\
         head  : {}  (chain over the window)\n\n",
        hex(&epoch),
        hex(&head),
    );
    // Show the most recent entries that comfortably fit a modal.
    let show = 14usize;
    let skip = count.saturating_sub(show);
    if skip > 0 {
        body += &format!("(showing last {show} of {count})\n");
    }
    body += &format!(
        "{:>6}  {:>9}  {:<16} {:>3}  detail\n",
        "seq", "uptime", "event", "aux"
    );
    for off in (skip * AUDIT_ENTRY_LEN..entries.len()).step_by(AUDIT_ENTRY_LEN) {
        let e = &entries[off..off + AUDIT_ENTRY_LEN];
        let seq = u32::from_le_bytes([e[0], e[1], e[2], e[3]]);
        let t_ms = u32::from_le_bytes([e[4], e[5], e[6], e[7]]);
        body += &format!(
            "{seq:>6}  {:>8.1}s  {:<16} {:>3}  {}\n",
            t_ms as f64 / 1000.0,
            event_name(e[8]),
            e[9],
            hex(&e[10..18]),
        );
    }
    Ok(("audit journal".into(), body))
}

fn fold(epoch: &[u8], entries: &[u8]) -> Vec<u8> {
    let mut h = epoch.to_vec();
    for off in (0..entries.len()).step_by(AUDIT_ENTRY_LEN) {
        let end = (off + AUDIT_ENTRY_LEN).min(entries.len());
        let mut hasher = Sha256::new();
        hasher.update(&h);
        hasher.update(&entries[off..end]);
        h = hasher.finalize().to_vec();
    }
    h
}

/// Challenge-response signature check (vendor AUDIT_CHECKPOINT): the device signs a
/// fresh challenge with its DEVK-derived P-256 attestation key. The verifying key
/// arrives in the same response, so a valid signature proves only that the responder
/// holds the key it advertises — NOT which device it is. The verdict withholds any
/// identity claim and points at the pinning CLI, matching inventory.py / audit.py; a
/// self-signed counterfeit must not read as "verified" (audit run-30). Touch-gated;
/// PIN if one is set.
pub fn verify_identity(pin: Option<&str>) -> Result<(String, String), String> {
    let dev = hid_open_exclusive()?;
    let cid = ctaphid_init(&dev).ok_or("CTAPHID init failed")?;
    let token = pin.map(|p| acfg_token(&dev, cid, p)).transpose()?;

    let mut challenge = [0u8; 16];
    OsRng.fill_bytes(&mut challenge);
    let subpara = Value::Map(vec![(iv(1), Value::Bytes(challenge.to_vec()))]);
    let raw_subpara = cbor(&subpara);
    let mut req = vec![
        (iv(1), iv(VENDOR_AUDIT_CHECKPOINT as i64)),
        (iv(2), subpara),
    ];
    if let Some((_, v)) = gate_param(token.as_ref(), VENDOR_AUDIT_CHECKPOINT, &raw_subpara) {
        req.push((iv(3), iv(2)));
        req.push((iv(4), v));
    }
    let (st, v) = vendor(&dev, cid, Value::Map(req), 30000);
    match st {
        0 => {}
        CTAP2_ERR_PIN_REQUIRED => return Err(MSG_PIN_REQUIRED.into()),
        0x30 => {
            return Err(
                "no OTP DEVK provisioned — attestation unavailable (docs/production.md)".into(),
            );
        }
        0x27 => {
            return Err(
                "no touch within the timeout — press the button when the LED blinks".into(),
            );
        }
        s => return Err(format!("checkpoint failed: {s:#x}")),
    }
    let v = v.ok_or("decode failed")?;
    let head = match map_get(&v, 1) {
        Some(Value::Bytes(b)) => b.clone(),
        _ => return Err("no head".into()),
    };
    let seq = map_get(&v, 2).and_then(as_u32).ok_or("no seq")?;
    let sig = match map_get(&v, 3) {
        Some(Value::Bytes(b)) => b.clone(),
        _ => return Err("no signature".into()),
    };
    let pubkey = match map_get(&v, 4) {
        Some(Value::Bytes(b)) => b.clone(),
        _ => return Err("no pubkey".into()),
    };

    let vk = VerifyingKey::from_sec1_bytes(&pubkey).map_err(|_| "bad attestation pubkey")?;
    let signature = Signature::from_der(&sig).map_err(|_| "bad signature DER")?;
    let mut msg = Vec::with_capacity(CKPT_TAG.len() + head.len() + 4 + challenge.len());
    msg.extend_from_slice(CKPT_TAG);
    msg.extend_from_slice(&head);
    msg.extend_from_slice(&seq.to_le_bytes());
    msg.extend_from_slice(&challenge);
    if vk.verify(&msg, &signature).is_err() {
        return Err("SIGNATURE INVALID — this device cannot prove its identity".into());
    }

    let fp: String = Sha256::digest(&pubkey)
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect();
    let body = format!(
        "signature OK — the device signed a fresh challenge with the key it advertises.\n\
         the key is NOT pinned, so this does not prove which device signed it.\n\n\
         fingerprint : {fp}\n\
         att key     : {}\n\
         chain head  : {}\n\
         seq         : {seq}\n\n\
         Pin this fingerprint with `rsk inventory verify --expect-key {fp}` so a swapped\n\
         or counterfeit board fails the check instead of quietly verifying.",
        hex(&pubkey),
        hex(&head),
    );
    Ok(("device identity".into(), body))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ===========================================================================
// seed backup (native: MSE + clientPIN proto-2 + BIP-39)
// ===========================================================================

fn client_pin(dev: &hidapi::HidDevice, cid: [u8; 4], fields: Value) -> Option<Value> {
    let mut p = vec![0x06];
    p.extend_from_slice(&cbor(&fields));
    let r = send_cbor(dev, cid, &p, EXCHANGE_TIMEOUT_MS);
    if r.first() != Some(&0) {
        return None;
    }
    ciborium::de::from_reader(&r[1..]).ok()
}

/// clientPIN protocol-two pinUvAuthToken with the acfg permission.
fn acfg_token(dev: &hidapi::HidDevice, cid: [u8; 4], pin: &str) -> Result<[u8; 32], String> {
    pin_uv_token(dev, cid, pin, PERM_ACFG)
}

/// clientPIN protocol-two pinUvAuthToken bound to `perm` (a `PERM_*` mask). The
/// audit/verify flows request `PERM_ACFG`; the credMgmt count requests
/// `PERM_CREDMGMT`. The crypto (ECDH → HKDF → AES-CBC) is HW-verified — do not
/// alter the algorithm.
fn pin_uv_token(
    dev: &hidapi::HidDevice,
    cid: [u8; 4],
    pin: &str,
    perm: i64,
) -> Result<[u8; 32], String> {
    let ka = client_pin(dev, cid, Value::Map(vec![(iv(1), iv(2)), (iv(2), iv(2))]))
        .ok_or("getKeyAgreement failed")?;
    let auth = map_get(&ka, 1).ok_or("no keyAgreement")?;
    let (ax, ay) = (coord(auth, -2)?, coord(auth, -3)?);
    let (sk, px, py) = ecdh_pub();
    let z = ecdh_raw(&sk, &ax, &ay).ok_or("ECDH failed")?;
    let aes = hkdf32(&[0u8; 32], &z, b"CTAP2 AES key");
    let mut ph = Sha256::digest(pin.as_bytes())[..16].to_vec();
    let enc = aes_cbc_encrypt(&aes, &ph);
    ph.zeroize();
    let req = Value::Map(vec![
        (iv(1), iv(2)),
        (iv(2), iv(9)),
        (iv(3), cose_key(&px, &py)),
        (iv(6), Value::Bytes(enc)),
        (iv(9), iv(perm)),
    ]);
    let resp = client_pin(dev, cid, req).ok_or("getPinUvAuthToken failed (wrong PIN?)")?;
    let enc_tok = match map_get(&resp, 2) {
        Some(Value::Bytes(b)) => b.clone(),
        _ => return Err("no token in response".into()),
    };
    let tok = aes_cbc_decrypt(&aes, &enc_tok).ok_or("token decrypt failed")?;
    tok.as_slice()
        .try_into()
        .map_err(|_| "bad token length".into())
}

fn coord(cose: &Value, key: i128) -> Result<[u8; 32], String> {
    match map_get(cose, key) {
        Some(Value::Bytes(b)) if b.len() <= 32 => {
            let mut out = [0u8; 32];
            out[32 - b.len()..].copy_from_slice(b);
            Ok(out)
        }
        _ => Err("missing COSE coordinate".into()),
    }
}

/// MSE key agreement; returns (channel key, AAD = device pubkey).
fn mse(dev: &hidapi::HidDevice, cid: [u8; 4]) -> Result<([u8; 32], [u8; 65]), String> {
    let (sk, px, py) = ecdh_pub();
    let req = Value::Map(vec![
        (iv(1), iv(VENDOR_MSE as i64)),
        (iv(2), Value::Map(vec![(iv(1), cose_key(&px, &py))])),
    ]);
    let (st, v) = vendor(dev, cid, req, EXCHANGE_TIMEOUT_MS);
    if st != 0 {
        return Err(format!("MSE failed: {st:#x}"));
    }
    let v = v.ok_or("MSE decode")?;
    let dk = map_get(&v, 1).ok_or("no device key")?;
    let (dx, dy) = (coord(dk, -2)?, coord(dk, -3)?);
    let z = ecdh_raw(&sk, &dx, &dy).ok_or("ECDH failed")?;
    let mut aad = [0u8; 65];
    aad[0] = 0x04;
    aad[1..33].copy_from_slice(&dx);
    aad[33..].copy_from_slice(&dy);
    Ok((hkdf32(b"", &z, &aad), aad))
}

fn gate_param(token: Option<&[u8; 32]>, subcmd: u8, raw_subpara: &[u8]) -> Option<(Value, Value)> {
    let token = token?;
    let mut msg = vec![0xffu8; 32];
    msg.extend_from_slice(&[CTAP_VENDOR, subcmd]);
    msg.extend_from_slice(raw_subpara);
    Some((iv(2), Value::Bytes(hmac256(token, &msg))))
}

/// credMgmt getCredsMetadata — the resident-passkey count. Always PIN-gated
/// (credMgmt has no touch fallback), so `pin` is required. Returns
/// `(existing, remaining)`. The pinUvAuthParam over the standard command is
/// `authenticate(token, [subCommand])` — no `0xff` prefix, unlike the vendor
/// gating in [`gate_param`].
pub fn cred_count(pin: Option<&str>) -> Result<(u16, u16), String> {
    let pin = pin.ok_or("a FIDO PIN is required to count resident passkeys")?;
    let dev = hid_open().ok_or("no FIDO device")?;
    let cid = ctaphid_init(&dev).ok_or("CTAPHID init failed")?;
    let token = pin_uv_token(&dev, cid, pin, PERM_CREDMGMT)?;
    let auth = hmac256(&token, &[CM_GET_CREDS_METADATA]);
    let req = Value::Map(vec![
        (iv(1), iv(CM_GET_CREDS_METADATA as i64)),
        (iv(3), iv(2)),
        (iv(4), Value::Bytes(auth)),
    ]);
    let mut payload = vec![CTAP_CREDENTIAL_MGMT];
    payload.extend_from_slice(&cbor(&req));
    let r = send_cbor(&dev, cid, &payload, EXCHANGE_TIMEOUT_MS);
    match r.first() {
        Some(0) => {}
        Some(&CTAP2_ERR_PIN_REQUIRED) => return Err(MSG_PIN_REQUIRED.into()),
        Some(0x33) | Some(0x31) => return Err("PIN authentication failed (wrong PIN?)".into()),
        Some(s) => return Err(format!("credMgmt status {s:#x}")),
        None => return Err("no response".into()),
    }
    let v: Value = ciborium::de::from_reader(&r[1..]).map_err(|_| "decode failed")?;
    let existing = map_get(&v, 1)
        .and_then(as_u32)
        .ok_or("no count in response")? as u16;
    let remaining = map_get(&v, 2).and_then(as_u32).unwrap_or(0) as u16;
    Ok((existing, remaining))
}

/// Export the 32-byte seed and return it as a 24-word BIP-39 phrase.
/// Run the MSE channel + vendor BACKUP_EXPORT and decrypt the blob to the raw
/// 32-byte seed. Shared by the BIP-39 and SLIP-39 export paths; the returned
/// buffer zeroizes on drop.
fn fetch_backup_seed(pin: Option<&str>) -> Result<Zeroizing<Vec<u8>>, String> {
    let dev = hid_open_exclusive()?;
    let cid = ctaphid_init(&dev).ok_or("CTAPHID init failed")?;
    let token = pin.map(|p| acfg_token(&dev, cid, p)).transpose()?;
    let (key, aad) = mse(&dev, cid)?;

    let mut req = vec![(iv(1), iv(VENDOR_BACKUP_EXPORT as i64))];
    if let Some((_, v)) = gate_param(token.as_ref(), VENDOR_BACKUP_EXPORT, &[]) {
        req.push((iv(3), iv(2)));
        req.push((iv(4), v));
    }
    let mut payload = vec![CTAP_VENDOR];
    payload.extend_from_slice(&cbor(&Value::Map(req)));
    let r = send_cbor(&dev, cid, &payload, TOUCH_TIMEOUT_MS);
    match r.first() {
        Some(&0) => {}
        Some(&CTAP2_ERR_PIN_REQUIRED) => return Err(MSG_PIN_REQUIRED.into()),
        Some(&0x30) => return Err("export refused — already sealed".into()),
        Some(s) => return Err(format!("export failed: {s:#x}")),
        None => return Err("no response (timeout / no touch)".into()),
    }
    let v: Value = ciborium::de::from_reader(&r[1..]).map_err(|_| "decode")?;
    let blob = match map_get(&v, 1) {
        Some(Value::Bytes(b)) if b.len() == 60 => b.clone(),
        _ => return Err("bad export blob".into()),
    };
    let seed = chacha_decrypt(&key, &blob[..12], &aad, &blob[12..]).ok_or("AEAD decrypt failed")?;
    Ok(Zeroizing::new(seed))
}

pub fn backup_export(pin: Option<&str>) -> Result<String, String> {
    let seed = fetch_backup_seed(pin)?;
    Ok(bip39::Mnemonic::from_entropy(&seed)
        .map_err(|e| e.to_string())?
        .to_string())
}

/// Export the seed as a printable SLIP-39 share set (2-of-3, the host CLI's
/// default). Generate-only via the in-tree `rsk-slip39` crate; recombining the
/// shares to restore stays in the CLI.
pub fn backup_export_slip39(pin: Option<&str>) -> Result<String, String> {
    let seed = fetch_backup_seed(pin)?;
    let mut secret = <[u8; 32]>::try_from(&seed[..]).map_err(|_| "seed not 32 bytes")?;
    let body = slip39_body(&secret, 2, 3);
    secret.zeroize();
    body
}

/// Split a 32-byte secret into a printable `threshold`-of-`count` SLIP-39 share
/// block, bit-compatible with `rsk backup restore --scheme slip39`. The returned
/// string is secret — the caller wraps it in `Zeroizing`.
fn slip39_body(secret: &[u8; 32], threshold: u8, count: u8) -> Result<String, String> {
    let mut out = [[0u16; rsk_slip39::WORDS_PER_SHARE]; rsk_slip39::MAX_SHARES];
    let mut fill = |b: &mut [u8]| OsRng.fill_bytes(b);
    rsk_slip39::generate(secret, threshold, count, &mut fill, &mut out)
        .map_err(|e| format!("slip39 encode failed: {e:?}"))?;
    let mut body = format!(
        "Any {threshold} of these {count} SLIP-39 shares reconstruct the seed.\n\
         Write each on its own card; keep them apart.\n"
    );
    for (s, share) in out.iter().take(count as usize).enumerate() {
        body.push_str(&format!("\nshare {} of {count}\n", s + 1));
        for (j, &idx) in share.iter().enumerate() {
            body.push_str(rsk_slip39::word(idx));
            let last = j + 1 == share.len();
            body.push(if last || (j + 1) % 7 == 0 { '\n' } else { ' ' });
        }
    }
    out.zeroize();
    Ok(body)
}

/// Seal the one-time backup export window (vendor BACKUP_FINALIZE, subcmd 4).
/// Touch-gated, no PIN; a factory reset reopens it. Irreversible otherwise.
pub fn backup_finalize() -> Result<String, String> {
    let dev = hid_open_exclusive()?;
    let cid = ctaphid_init(&dev).ok_or("CTAPHID init failed")?;
    let (st, _) = vendor(
        &dev,
        cid,
        Value::Map(vec![(iv(1), iv(VENDOR_BACKUP_FINALIZE as i64))]),
        TOUCH_TIMEOUT_MS,
    );
    match st {
        0 => Ok("backup window sealed — a factory reset reopens it".into()),
        0x27 => Err("finalize cancelled — no touch".into()),
        s => Err(format!("finalize failed: {s:#x}")),
    }
}

fn seed_fp(words: &str) -> Result<String, String> {
    let m = bip39::Mnemonic::parse(words).map_err(|e| e.to_string())?;
    let (mut ent, len) = m.to_entropy_array();
    let fp = Sha256::digest(&ent[..len])
        .iter()
        .take(4)
        .map(|b| format!("{b:02x}"))
        .collect();
    ent.zeroize();
    Ok(fp)
}

/// Verify the native MSE / clientPIN / BIP-39 paths end-to-end without leaking the
/// seed: export, restore the SAME phrase back (identity-preserving), re-export,
/// and confirm the fingerprint is stable. Needs the no-touch build.
pub fn export_selftest(pin: Option<&str>) -> Result<String, String> {
    let words = backup_export(pin)?;
    let fp1 = seed_fp(&words)?;
    backup_restore(&words, pin)?;
    let fp2 = seed_fp(&backup_export(pin)?)?;
    if fp1 != fp2 {
        return Err(format!("round-trip fp mismatch {fp1} != {fp2}"));
    }
    Ok(format!("export+restore round-trip clean  seed_fp={fp1}"))
}

/// Restore the seed from a 24-word BIP-39 phrase.
pub fn backup_restore(phrase: &str, pin: Option<&str>) -> Result<String, String> {
    let m = bip39::Mnemonic::parse(phrase.trim()).map_err(|e| format!("invalid phrase: {e}"))?;
    let (mut entropy, len) = m.to_entropy_array();
    if len != 32 {
        entropy.zeroize();
        return Err("phrase must encode 32 bytes (24 words)".into());
    }
    // Wipe on drop, not on the success path: each of the four device-side steps
    // below returns early, and every one of them used to leave the plaintext master
    // seed in freed heap memory. `to_entropy_array` hands back a plain [u8; 33],
    // so that copy needs clearing too (audit run-35).
    let seed = Zeroizing::new(entropy[..32].to_vec());
    entropy.zeroize();

    let dev = hid_open_exclusive()?;
    let cid = ctaphid_init(&dev).ok_or("CTAPHID init failed")?;
    let token = pin.map(|p| acfg_token(&dev, cid, p)).transpose()?;
    let (key, aad) = mse(&dev, cid)?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&chacha_encrypt(&key, &nonce, &aad, &seed));

    let subpara = Value::Map(vec![(iv(1), Value::Bytes(blob))]);
    let raw_subpara = cbor(&subpara);
    let mut req = vec![(iv(1), iv(VENDOR_BACKUP_LOAD as i64)), (iv(2), subpara)];
    if let Some((_, v)) = gate_param(token.as_ref(), VENDOR_BACKUP_LOAD, &raw_subpara) {
        req.push((iv(3), iv(2)));
        req.push((iv(4), v));
    }
    let (st, _) = vendor(&dev, cid, Value::Map(req), TOUCH_TIMEOUT_MS);
    match st {
        0 => Ok("seed restored — FIDO identity matches the backup".into()),
        CTAP2_ERR_PIN_REQUIRED => Err(MSG_PIN_REQUIRED.into()),
        s => Err(format!("restore failed: {s:#x}")),
    }
}

// ===========================================================================
// Mock provider — drives the whole UI with no hardware (`--demo`).
// ===========================================================================

/// A simulated RS-Key for `--demo`. Actions visibly mutate the fake state but
/// never pretend to touch hardware: every result is prefixed `[demo]`.
pub struct MockProvider {
    idle_color: usize,
    sealed: bool,
}

impl MockProvider {
    pub fn new() -> Self {
        MockProvider {
            idle_color: 6, // cyan
            sealed: false,
        }
    }
}

impl Default for MockProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceProvider for MockProvider {
    fn snapshot(&mut self) -> DeviceSnapshot {
        DeviceSnapshot {
            transport: TransportStatus {
                hid: Link::Present,
                pcsc: Link::Present,
                ccid: Link::Present,
                note: None,
            },
            identity: Identity {
                serial: Some("37bebfdca282523b".into()),
                sdk: Some("3.4".into()),
                firmware: Some("5.7.4".into()),
                bcd_device: Some(0x0759),
                aaguid: Some("9c5e0fd2c2c34c2fa1d6e3b7a0c41122".into()),
                product: Some("RS-Key Security Key (demo)".into()),
                hid_ambiguous: false,
            },
            fido: FidoState {
                present: true,
                versions: vec!["U2F_V2".into(), "FIDO_2_0".into(), "FIDO_2_1".into()],
                client_pin: Some(true),
                options: vec![
                    "clientPin".into(),
                    "credMgmt".into(),
                    "pinUvAuthToken".into(),
                    "rk".into(),
                    "up".into(),
                ],
            },
            backup: Some(BackupState {
                sealed: self.sealed,
                has_seed: true,
            }),
            lock: Some(LockState {
                locked: false,
                unlocked: false,
            }),
            secure_boot: Some(SecureBootState {
                enabled: true,
                locked: false,
                bootkey: 1,
            }),
            rollback: Some(RollbackState {
                required: false,
                version: 0,
                capacity: 48,
            }),
            attestation: Some(AttestationState {
                installed: false,
                chain_sha256: None,
            }),
            flash: Some(FlashState {
                free: 1_048_576,
                used: 4_096,
                kv_total: 65_536,
                files: 7,
                chip: 8_388_608,
            }),
            applets: Applets {
                openpgp: Some(true),
                piv: Some(true),
                oath: Some(true),
                otp: Some(true),
            },
            led: Some(LedState {
                steady: true,
                idle: self.idle_color as u8,
                processing: 3, // blue
                touch: 2,      // green
                boot: 7,       // white
            }),
            pgp: Some(PgpInfo {
                serial: Some("2a1b3c4d".into()),
                pin_retries: Some([3, 0, 3]),
                keys_present: 2,
            }),
            piv_meta: Some(PivInfo {
                pin_left: 3,
                pin_total: 3,
                pin_default: true,
            }),
            errors: Vec::new(),
            demo: true,
        }
    }

    fn run(&mut self, action: Action, _input: &ActionInput) -> ActionResult {
        match action {
            Action::Refresh => ActionResult::Ok("status refreshed".into()),
            Action::CredCount => {
                ActionResult::Ok("[demo] 12 resident passkeys · ~120 slots free".into())
            }
            Action::LedGet => ActionResult::Report {
                title: "LED state".into(),
                body: format!(
                    "mode = steady\nidle        {}  (brightness 16) effect=vapor\nprocessing  blue  (brightness 32) effect=flow\ntouch       green  (brightness 64) effect=bounce\nboot        white  (brightness  8) effect=sparkle\n",
                    COLORS[self.idle_color]
                ),
            },
            Action::LedCycle => {
                self.idle_color = next_idle_color(self.idle_color);
                ActionResult::Ok(format!("[demo] idle color → {}", COLORS[self.idle_color]))
            }
            Action::RebootApp => ActionResult::Ok("[demo] reboot → app (no device touched)".into()),
            Action::RebootBootsel => {
                ActionResult::Ok("[demo] reboot → BOOTSEL (no device touched)".into())
            }
            Action::BackupExport => {
                // A canonical, obviously-fake mnemonic (entropy = 32 zero bytes).
                let words = bip39::Mnemonic::from_entropy(&[0u8; 32])
                    .map(|m| m.to_string())
                    .unwrap_or_default();
                ActionResult::Reveal {
                    title: "seed · BIP-39 (DEMO — not a real key)".into(),
                    body: Zeroizing::new(words),
                }
            }
            Action::BackupExportSlip39 => {
                // Obviously-fake shares from an all-zero secret.
                let body = slip39_body(&[0u8; 32], 2, 3).unwrap_or_default();
                ActionResult::Reveal {
                    title: "seed · SLIP-39 2-of-3 (DEMO — not a real key)".into(),
                    body: Zeroizing::new(body),
                }
            }
            Action::BackupRestore => ActionResult::Ok("[demo] seed restored".into()),
            Action::BackupFinalize => {
                self.sealed = true;
                ActionResult::Ok("[demo] backup window sealed".into())
            }
            Action::AuditRead => ActionResult::Report {
                title: "audit journal".into(),
                body: "window [0, 4)  —  4 entries, 0 folded into the epoch\n\
                       epoch : 00000000…  head : 7f3a91c4…  (chain over the window)\n\n\
                          seq     uptime  event            aux  detail\n\
                           0       0.4s  BOOT                0  0000000000000000\n\
                           1       2.1s  PIN_SET             0  0000000000000000\n\
                           2      14.8s  MAKE_CREDENTIAL     1  a1b2c3d4e5f60718\n\
                           3      31.0s  GET_ASSERTION       1  a1b2c3d4e5f60718\n"
                    .into(),
            },
            Action::Verify => ActionResult::Report {
                title: "device identity".into(),
                body: "identity verified ✓  (demo — no real signature)\n\n\
                       fingerprint : demo0000demo0000\n\
                       att key     : 04demo…\n\
                       seq         : 4\n"
                    .into(),
            },
        }
    }
}

#[cfg(test)]
#[path = "device_tests.rs"]
mod tests;
