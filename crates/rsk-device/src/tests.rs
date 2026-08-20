// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The wiring, off the board: the real applet set over a RAM `Fs`, with the four
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

use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;

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
    /// Off by default, as a host build is; set it and [`Hooks::rsa_search`] says
    /// "the accelerator ran and found nothing", which is what lets a test see
    /// whether a keygen fast path fired at all.
    pub accelerator: bool,
}

impl Hooks<RamStorage> for Board {
    fn config_written(&mut self, _fs: &mut Fs<RamStorage>) {
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
    // other answer so a test can tell a fast path that fired from one that did not.
    fn rsa_search(&mut self, _nbits: usize, _rng: &mut dyn rsk_sdk::Rng) -> SearchResult {
        if self.accelerator { Some(None) } else { None }
    }
}

/// Physical presence — one button, as on the device. Confirms by default; a
/// test that needs a refusal flips `answer`.
pub struct Finger {
    pub answer: bool,
    pub requests: usize,
}

impl Default for Finger {
    fn default() -> Self {
        Self {
            answer: true,
            requests: 0,
        }
    }
}

impl rsk_sdk::UserPresence for Finger {
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

/// Everything a handler borrows, owned for the test's lifetime.
pub struct Env {
    pub fs: RefCell<Fs<RamStorage>>,
    pub rng: RefCell<TestRng>,
    pub board: RefCell<Board>,
    pub finger: RefCell<Finger>,
    pub rescue: RefCell<RescueBoard>,
    /// The device's one FIDO session state, as the worker holds it: both
    /// transports that reach the applet borrow this same cell.
    pub fido_state: RefCell<rsk_fido::FidoState>,
}

impl Default for Env {
    fn default() -> Self {
        Self::new()
    }
}

impl Env {
    pub fn new() -> Self {
        Self {
            fs: RefCell::new(Fs::new(RamStorage::new())),
            rng: RefCell::new(TestRng(0x0DDB_A11C_0FFE_E1E5)),
            board: RefCell::new(Board::default()),
            finger: RefCell::new(Finger::default()),
            fido_state: RefCell::new(rsk_fido::FidoState::new()),
            rescue: RefCell::new(RescueBoard::default()),
        }
    }

    /// The CCID side: the full eight-applet set behind the dispatcher.
    pub fn ccid(&self) -> CcidApplets<'_, RamStorage, TestRng, VendorBoard> {
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
    pub fn ctap(&self) -> AppletHandler<'_, RamStorage, TestRng, VendorBoard> {
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
    let tlv = std::vec![0x03u8, 2, be[0], be[1]];
    let mut blob = std::vec![tlv.len() as u8];
    blob.extend_from_slice(&tlv);
    blob
}
