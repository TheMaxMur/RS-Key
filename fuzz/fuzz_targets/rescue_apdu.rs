// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the rescue applet dispatch (`RescueApplet::process`) — phy write/read,
//! flash info, secure-boot status, time set/get, reboot, the keydev paths and
//! the one-way OTP writes (rollback-required arm; the fake platform reports
//! secure boot enabled so its full guard chain is reachable) are all reachable
//! from a length-prefixed APDU replay. The keydev sign/pubkey commands run real
//! secp256k1 ops over the fuzzer-driven flash state; none may panic.

use core::cell::RefCell;

use libfuzzer_sys::fuzz_target;
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;
use rsk_rescue::rollback::{ROLLBACK_REQUIRED_BIT, RollbackRaw};
use rsk_rescue::{Confirm, Platform, Presence, RescueApplet, Rng, SecureBootStatus, UserPresence};
use rsk_sdk::{Apdu, Applet, ResBuf};

mod apdu_frame;
use apdu_frame::next_frame;

const SERIAL_ID: [u8; 8] = [0xAA, 0xBB, 0xCC, 0xDD, 5, 6, 7, 8];
const SERIAL_HASH: [u8; 32] = [0x22; 32];

struct CountRng(u8);
impl Rng for CountRng {
    fn fill(&mut self, b: &mut [u8]) {
        for x in b.iter_mut() {
            *x = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

// Always confirm so the presence-gated commands (attestation sign / cert / phy
// write / BOOTSEL) stay reachable for the fuzzer.
struct AlwaysConfirm;
impl UserPresence for AlwaysConfirm {
    fn request(&mut self, _c: Confirm<'_>) -> Presence {
        Presence::Confirmed
    }
}

struct FakePlatform {
    time: Option<u32>,
    flags0: [u32; 3],
}
impl Platform for FakePlatform {
    fn secure_boot_status(&self) -> SecureBootStatus {
        // enabled: true keeps the rollback-require arm's deepest path fuzzable.
        SecureBootStatus {
            enabled: true,
            locked: false,
            bootkey: 0,
        }
    }
    fn now(&self) -> Option<u32> {
        self.time
    }
    fn set_time(&mut self, epoch: u32) {
        self.time = Some(epoch);
    }
    fn request_reboot(&mut self, _bootsel: bool) {}
    fn read_page58_lock_raw(&self) -> Option<u32> {
        Some(0)
    }
    fn lock_page58(&mut self) -> bool {
        true
    }
    fn read_rollback_raw(&self) -> Option<RollbackRaw> {
        Some(RollbackRaw {
            flags0: self.flags0,
            version0: [0b111; 3],
            version1: [0; 3],
        })
    }
    fn set_rollback_required(&mut self) -> bool {
        for row in self.flags0.iter_mut() {
            *row |= ROLLBACK_REQUIRED_BIT;
        }
        true
    }
}

fuzz_target!(|data: &[u8]| {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    let rng = RefCell::new(CountRng(0));
    let platform = RefCell::new(FakePlatform {
        time: None,
        flags0: [0; 3],
    });
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = RescueApplet::new(
        SERIAL_ID,
        SERIAL_HASH,
        None,
        None,
        &rng,
        &platform,
        &presence,
        64 * 1024,
        4 * 1024 * 1024,
    );

    // `[len][apdu bytes…]*`; 0xFF is the extended-Lc escape (see `apdu_frame`).
    let mut rest = data;
    while let Some((frame, tail)) = next_frame(rest) {
        rest = tail;
        if let Ok(apdu) = Apdu::parse(frame.as_slice()) {
            let mut buf = [0u8; 2048];
            let mut res = ResBuf::new(&mut buf);
            let _ = app.process(&apdu, &mut fs, &mut res);
        }
    }
});
