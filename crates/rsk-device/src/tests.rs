// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The wiring, off the board: the real applet set over a host `Fs`, with the four
//! things only a device can supply — the board hooks, the presence source, the
//! rescue platform and the vendor platform — as recording doubles.
//!
//! The applets themselves are their own crates' business and are tested there.
//! What is under test here is what this crate decides: which applet a message
//! reaches, what makes one invisible, and which of the board's verbs a dispatch
//! is supposed to call.

extern crate std;

use core::cell::RefCell;
use std::vec::Vec;

use rsk_fs::storage::ram::RamStorage;
use rsk_fs::{Fs, Storage};

use super::*;

pub const SERIAL_ID: [u8; 8] = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18];
pub const SERIAL_HASH: [u8; 32] = [0x5A; 32];
const KV_TOTAL: u32 = 64 * 1024;
const FLASH_SIZE: u32 = 4 * 1024 * 1024;
const OPENPGP_MFR: u16 = 0x1234;

/// The board verbs, as a record of what a dispatch asked for.
#[derive(Default)]
pub struct Board {
    pub config_written: usize,
    pub reboots: usize,
    /// Every soft lock handed over for persisting, newest last.
    pub pin_locks: Vec<PinLock>,
    /// What this boot inherited — a warm reset's canary, or nothing.
    pub boot: BootState,
    /// The panel re-keyed the clientPIN; consumed on the next read, like the real
    /// one-shot flag.
    pub local_pin_change: bool,
    pub boot_state_reads: usize,
    /// Off by default, as a host build is; set, [`Hooks::rsa_search`] answers as
    /// an accelerator that ran, finding `search_key` — which is what lets a test
    /// see whether a keygen fast path fired at all.
    pub accelerator: bool,
    /// What the accelerator finds, once: `None` is the search that found nothing.
    pub search_key: Option<Box<rsk_rsa::RsaKey>>,
}

impl<S: Storage> Hooks<S> for Board {
    fn config_written(&mut self, _fs: &mut Fs<S>) {
        self.config_written += 1;
    }
    fn request_reboot(&mut self) {
        self.reboots += 1;
    }
    fn store_pin_lock(&mut self, lock: PinLock) {
        self.pin_locks.push(lock);
    }
    fn boot_state(&mut self) -> BootState {
        self.boot_state_reads += 1;
        self.boot
    }
    fn local_pin_changed(&mut self) -> bool {
        core::mem::take(&mut self.local_pin_change)
    }
    // `None` — no accelerator — is what a host build is, and the fall-through it
    // causes is itself under test in `ccid_tests`; `accelerator` opts into the
    // other two answers, a failed search and a found key.
    fn rsa_search(&mut self, _nbits: usize, _rng: &mut dyn rsk_sdk::Rng) -> SearchResult {
        if self.accelerator {
            Some(self.search_key.take())
        } else {
            None
        }
    }
}

/// Physical presence — one button, as on the device. Confirms by default; a
/// test that needs a refusal flips `answer`, and one that needs the trusted
/// display's on-screen PIN pad flips `pad`.
pub struct Finger {
    pub answer: bool,
    pub requests: usize,
    /// What `uv_available()` answers. FALSE is the button-only device; only the
    /// display backend overrides it in the firmware (`rsk-display`'s presence),
    /// and it is an INPUT to §6.1.2's token-less gate that the phase-4 recording
    /// carries per boundary.
    pub pad: bool,
}

impl Default for Finger {
    fn default() -> Self {
        Self {
            answer: true,
            requests: 0,
            pad: false,
        }
    }
}

impl rsk_sdk::UserPresence for Finger {
    fn uv_available(&self) -> bool {
        self.pad
    }

    fn request(&mut self, _confirm: rsk_sdk::Confirm<'_>) -> rsk_sdk::Presence {
        self.requests += 1;
        if self.answer {
            rsk_sdk::Presence::Confirmed
        } else {
            rsk_sdk::Presence::Declined
        }
    }
}

/// A deterministic stand-in for the device TRNG (xorshift64*).
pub struct TestRng(u64);

impl TestRng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

impl rsk_sdk::Rng for TestRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let n = self.next().to_le_bytes();
            let len = chunk.len();
            chunk.copy_from_slice(&n[..len]);
        }
    }
}

/// The rescue applet's board: no secure boot, no OTP, a session clock.
#[derive(Default)]
pub struct RescueBoard {
    time: Option<u32>,
    pub reboots: Vec<bool>,
}

impl rsk_rescue::Platform for RescueBoard {
    fn secure_boot_status(&self) -> rsk_rescue::SecureBootStatus {
        rsk_rescue::SecureBootStatus {
            enabled: false,
            locked: false,
            bootkey: 0xFF,
        }
    }
    fn now(&self) -> Option<u32> {
        self.time
    }
    fn set_time(&mut self, epoch: u32) {
        self.time = Some(epoch);
    }
    fn request_reboot(&mut self, bootsel: bool) {
        self.reboots.push(bootsel);
    }
    fn read_page58_lock_raw(&self) -> Option<u32> {
        Some(0)
    }
    fn pre_otp_left(&self) -> Option<u16> {
        Some(0)
    }
    fn lock_page58(&mut self) -> bool {
        false // never burn a fuse from a test
    }
    fn read_rollback_raw(&self) -> Option<rsk_rescue::rollback::RollbackRaw> {
        Some(rsk_rescue::rollback::RollbackRaw {
            flags0: [0; 3],
            version0: [0; 3],
            version1: [0; 3],
        })
    }
    fn set_rollback_required(&mut self) -> bool {
        false
    }
}

/// The vendor applet's board: every method defaults to "this build has none of
/// that hardware", which is exactly what a host build is.
pub struct VendorBoard;

impl rsk_vendor::Platform for VendorBoard {}

/// A backend that refuses every `write` and serves every read. `RamStorage` cannot
/// fail, so a wrapper that folds a store error into a bool — `ctap_mgmt`'s WRITE
/// CONFIG ack — is unobservable over it, and `.is_ok()` → `true` there leaves all
/// 77 tests green while a refused `persist_dev_conf` is acked to ykman as a written
/// config.
///
/// Local rather than in `rsk_fs::storage::faults`, unlike the two fault mediums the
/// applet sweeps share: one crate needs this shape, and that module's cost is a bcd
/// digit, because the counter's row reads FILES and `storage.rs` is a plain module
/// even where its contents are gated. It carries WRITE CONFIG's gate, a DEFAULT-build
/// arm.
#[cfg(not(feature = "strict-config"))]
#[derive(Default)]
pub struct WriteStuck(RamStorage);

#[cfg(not(feature = "strict-config"))]
impl WriteStuck {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(not(feature = "strict-config"))]
impl Storage for WriteStuck {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.0.read(fid, buf)
    }
    fn write(&mut self, _fid: u16, _data: &[u8]) -> rsk_sdk::error::Result<()> {
        Err(rsk_sdk::error::Error::MemoryFatal)
    }
    fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
        self.0.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.0.size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        self.0.for_each_key(f)
    }
}

/// Everything a handler borrows, owned for the test's lifetime. Generic over the
/// backend because [`RamStorage`] cannot fail: a wrapper that folds a store error
/// into a `bool` is only observable over one that can (`rsk_fs::storage::faults`,
/// or the local [`WriteStuck`]).
pub struct Env<S: Storage = RamStorage> {
    pub fs: RefCell<Fs<S>>,
    pub rng: RefCell<TestRng>,
    pub board: RefCell<Board>,
    pub finger: RefCell<Finger>,
    pub rescue: RefCell<RescueBoard>,
    /// The device's one FIDO session state, as the worker holds it: both
    /// transports that reach the applet borrow this same cell.
    pub fido_state: RefCell<rsk_fido::FidoState>,
}

impl Default for Env<RamStorage> {
    fn default() -> Self {
        Self::new()
    }
}

impl Env<RamStorage> {
    pub fn new() -> Self {
        Self::with_storage(RamStorage::new())
    }
}

impl<S: Storage> Env<S> {
    /// The same wiring over a chosen backend.
    pub fn with_storage(storage: S) -> Self {
        Self {
            fs: RefCell::new(Fs::new(storage)),
            rng: RefCell::new(TestRng(0x0DDB_A11C_0FFE_E1E5)),
            board: RefCell::new(Board::default()),
            finger: RefCell::new(Finger::default()),
            fido_state: RefCell::new(rsk_fido::FidoState::new()),
            rescue: RefCell::new(RescueBoard::default()),
        }
    }

    /// The CCID side: the full eight-applet set behind the dispatcher.
    pub fn ccid(&self) -> CcidApplets<'_, S, TestRng, VendorBoard> {
        CcidApplets::new(
            &self.fs,
            &self.rng,
            &self.board,
            &self.finger,
            &self.fido_state,
            &self.rescue,
            VendorBoard,
            SERIAL_ID,
            SERIAL_HASH,
            None,
            None,
            KV_TOTAL,
            FLASH_SIZE,
            OPENPGP_MFR,
        )
    }

    /// The CTAPHID side: FIDO/U2F plus the vendor AID.
    pub fn ctap(&self) -> AppletHandler<'_, S, TestRng, VendorBoard> {
        AppletHandler::new(
            &self.fs,
            &self.rng,
            &self.board,
            &self.finger,
            &self.fido_state,
            VendorBoard,
            SERIAL_ID,
            SERIAL_HASH,
            None,
            None,
        )
    }
}

/// The device key-derivation inputs the handlers are built with, so a test can seal
/// or verify a record the same way a dispatch would. No secret of its own.
pub fn dev() -> rsk_crypto::Device<'static> {
    rsk_crypto::Device {
        serial_hash: &SERIAL_HASH,
        serial_id: &SERIAL_ID,
        otp_key: None,
    }
}

/// A short-form APDU. `Lc` is omitted for an empty body, so a SELECT and a
/// case-1 command are both spelled here rather than at every call site.
pub fn apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut a = std::vec![cla, ins, p1, p2];
    if !data.is_empty() {
        a.push(data.len() as u8);
        a.extend_from_slice(data);
    }
    a
}

/// SELECT (by DF name) for `aid`.
pub fn select(aid: &[u8]) -> Vec<u8> {
    apdu(0x00, 0xA4, 0x04, 0x00, aid)
}

/// The trailing status word of a response APDU.
pub fn sw(res: &[u8]) -> rsk_sdk::Sw {
    let n = res.len();
    assert!(n >= 2, "a response APDU always carries its status word");
    rsk_sdk::Sw::new(res[n - 2], res[n - 1])
}

/// The `EF_DEV_CONF` blob that enables exactly `caps`, in the ykman WRITE CONFIG
/// wire form: a leading length byte, then TLV `0x03 len usb_enabled_be`.
pub fn dev_conf(caps: u16) -> Vec<u8> {
    let be = caps.to_be_bytes();
    let tlv = std::vec![rsk_devconf::raw::TAG_USB_ENABLED, 2, be[0], be[1]];
    let mut blob = std::vec![tlv.len() as u8];
    blob.extend_from_slice(&tlv);
    blob
}

/// `credentialManagement { getCredsMetadata, pinUvAuthProtocol: 2, pinUvAuthParam }`,
/// the parameter MACed under `token` over the subcommand byte (CTAP 2.1 §6.8.2).
pub fn get_creds_metadata(token: &[u8; 32]) -> Vec<u8> {
    let subcommand = rsk_fido::consts::CM_GET_CREDS_METADATA as u8;
    let mut param = [0u8; 32];
    let n = rsk_crypto::pinproto::authenticate(
        rsk_crypto::pinproto::PinProto::Two,
        token,
        &[subcommand],
        &mut param,
    )
    .expect("a 32-byte MAC fits");
    let mut body = std::vec![rsk_fido::consts::CTAP_CREDENTIAL_MGMT, 0xA3];
    body.extend_from_slice(&[0x01, subcommand, 0x03, 0x02, 0x04, 0x58, n as u8]);
    body.extend_from_slice(&param[..n]);
    body
}

/// The P-256 base point (SEC 2 §2.4.2), whose private half is 1.
const P256_G: ([u8; 32], [u8; 32]) = (
    [
        0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40,
        0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98,
        0xC2, 0x96,
    ],
    [
        0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E,
        0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF,
        0x51, 0xF5,
    ],
);

/// `clientPIN { pinUvAuthProtocol: 2, getPinToken, keyAgreement: G, pinHashEnc }` whose PIN
/// hash is wrong for any PIN: a valid platform key is all the key agreement checks, and 32
/// zero bytes decrypt to a hash no PIN has.
pub fn wrong_pin_token_request() -> Vec<u8> {
    let mut body = std::vec![rsk_fido::consts::CTAP_CLIENT_PIN, 0xA4, 0x01, 0x02, 0x02];
    body.push(rsk_fido::consts::CP_GET_PIN_TOKEN as u8);
    // keyAgreement: COSE_Key { kty: EC2, alg: ECDH-ES+HKDF-256, crv: P-256, x, y }.
    body.extend_from_slice(&[0x03, 0xA5, 0x01, 0x02, 0x03, 0x38, 0x18, 0x20, 0x01]);
    body.extend_from_slice(&[0x21, 0x58, 0x20]);
    body.extend_from_slice(&P256_G.0);
    body.extend_from_slice(&[0x22, 0x58, 0x20]);
    body.extend_from_slice(&P256_G.1);
    body.extend_from_slice(&[0x06, 0x58, 0x20]);
    body.extend_from_slice(&[0; 32]);
    body
}

/// A vendor `CONFIG_WRITE` (0x41) CBOR command `{1: subcmd, 2: {1: target, 2: blob}}`,
/// unauthenticated — the same request `rsk-fido`'s `config_write_req` builds.
pub fn vendor_config_write(target: u64, blob: &[u8]) -> Vec<u8> {
    use minicbor::Encoder;
    use minicbor::encode::write::Cursor;
    let mut buf = std::vec![0u8; 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(2).unwrap();
        e.u8(1)
            .unwrap()
            .u64(rsk_fido::consts::VENDOR_CONFIG_WRITE)
            .unwrap();
        e.u8(2).unwrap().map(2).unwrap();
        e.u8(1).unwrap().u64(target).unwrap();
        e.u8(2).unwrap().bytes(blob).unwrap();
        e.writer().position()
    };
    let mut body = std::vec![rsk_fido::consts::CTAP_VENDOR];
    body.extend_from_slice(&buf[..n]);
    body
}
