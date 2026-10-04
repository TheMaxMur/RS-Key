// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Replay rescue APDUs against plain and fused boots, including unreadable keys,
//! refused burns, silent write loss and denied presence. A successful OTP command
//! must agree with the fake registers; a denied burn must never reach the platform.

use core::cell::RefCell;

use libfuzzer_sys::fuzz_target;
use rsk_crypto::FusedKey;
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;
use rsk_rescue::otp_lock::PAGE58_LATCH_VALUE;
use rsk_rescue::rollback::{ROLLBACK_REQUIRED_BIT, RollbackRaw};
use rsk_rescue::{Platform, RescueApplet, Rng, SecureBootStatus};
use rsk_sdk::{Apdu, Applet, Confirm, Presence, ResBuf, Sw, UserPresence};

mod apdu_frame;
use apdu_frame::next_frame;

const SERIAL_ID: [u8; 8] = [0xAA, 0xBB, 0xCC, 0xDD, 5, 6, 7, 8];
const SERIAL_HASH: [u8; 32] = [0x22; 32];
const RESCUE_CLA: u8 = 0x80;
const INS_OTP_LOCK: u8 = 0x1b;
const P1_LOCK_PAGE58: u8 = 0x58;
const P1_REQUIRE_ROLLBACK: u8 = 0x48;
const MKEK_MODE_MASK: u8 = 3;
const DEVK_PRESENT: u8 = 1 << 2;
const READ_FAULT: u8 = 1 << 3;
const REFUSE_BURN: u8 = 1 << 4;
const IGNORE_BURN: u8 = 1 << 5;
const DENY_PRESENCE: u8 = 1 << 6;
const SECURE_BOOT_DISABLED: u8 = 1 << 7;

const OTP_COMMANDS: &[u8] = &[
    12,
    RESCUE_CLA,
    INS_OTP_LOCK,
    P1_LOCK_PAGE58,
    0,
    6,
    b'L',
    b'O',
    b'C',
    b'K',
    b'5',
    b'8',
    0,
    12,
    RESCUE_CLA,
    INS_OTP_LOCK,
    P1_REQUIRE_ROLLBACK,
    0,
    6,
    b'R',
    b'O',
    b'L',
    b'L',
    b'B',
    b'K',
    0,
];

struct CountRng(u8);
impl Rng for CountRng {
    fn fill(&mut self, b: &mut [u8]) {
        for x in b.iter_mut() {
            *x = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

struct FakePlatform {
    time: Option<u32>,
    flags0: [u32; 3],
    lock: u32,
    readable: bool,
    secure_boot: bool,
    burn: Burn,
    writes: u32,
}

#[derive(Clone, Copy)]
enum Burn {
    Commit,
    Refuse,
    Ignore,
}

impl Platform for FakePlatform {
    fn secure_boot_status(&self) -> SecureBootStatus {
        SecureBootStatus {
            enabled: self.secure_boot,
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
        self.readable.then_some(self.lock)
    }
    fn pre_otp_left(&self) -> Option<u16> {
        Some(0)
    }
    fn lock_page58(&mut self) -> bool {
        self.writes += 1;
        match self.burn {
            Burn::Commit => {
                self.lock |= PAGE58_LATCH_VALUE;
                true
            }
            Burn::Refuse => false,
            Burn::Ignore => true,
        }
    }
    fn read_rollback_raw(&self) -> Option<RollbackRaw> {
        self.readable.then_some(RollbackRaw {
            flags0: self.flags0,
            version0: [0b111; 3],
            version1: [0; 3],
        })
    }
    fn set_rollback_required(&mut self) -> bool {
        self.writes += 1;
        match self.burn {
            Burn::Commit => {
                for row in self.flags0.iter_mut() {
                    *row |= ROLLBACK_REQUIRED_BIT;
                }
                true
            }
            Burn::Refuse => false,
            Burn::Ignore => true,
        }
    }
}

struct FuzzPresence(bool);
impl UserPresence for FuzzPresence {
    fn request(&mut self, _: Confirm<'_>) -> Presence {
        if self.0 {
            Presence::Confirmed
        } else {
            Presence::Declined
        }
    }
}

fn fused_key(out: &mut [u8; 32]) -> bool {
    *out = [0x11; 32];
    true
}

fn unreadable_key(_: &mut [u8; 32]) -> bool {
    false
}

fn replay(data: &[u8], mode: u8) {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    let rng = RefCell::new(CountRng(0));
    let platform = RefCell::new(FakePlatform {
        time: None,
        flags0: [0; 3],
        lock: 0,
        readable: mode & READ_FAULT == 0,
        secure_boot: mode & SECURE_BOOT_DISABLED == 0,
        burn: if mode & REFUSE_BURN != 0 {
            Burn::Refuse
        } else if mode & IGNORE_BURN != 0 {
            Burn::Ignore
        } else {
            Burn::Commit
        },
        writes: 0,
    });
    let confirmed = mode & DENY_PRESENCE == 0;
    let presence = RefCell::new(FuzzPresence(confirmed));
    let mkek = match mode & MKEK_MODE_MASK {
        0 => None,
        1 => Some(FusedKey::open(fused_key)),
        2 => Some(FusedKey::open(unreadable_key)),
        _ => Some(FusedKey::latched(fused_key)),
    };
    let mut app = RescueApplet::new(
        SERIAL_ID,
        SERIAL_HASH,
        mkek,
        (mode & DEVK_PRESENT != 0).then_some(FusedKey::open(fused_key)),
        &rng,
        &platform,
        &presence,
        64 * 1024,
        4 * 1024 * 1024,
    );

    // `[len][apdu bytes…]*`; 0xFF is the extended-Lc escape (see `apdu_frame`).
    // Raw mutation rarely finds the magic payloads; drive both on the selected boot.
    let driven = if mode == 0 { &[][..] } else { OTP_COMMANDS };
    for input in [data, driven] {
        let mut rest = input;
        while let Some((frame, tail)) = next_frame(rest) {
            rest = tail;
            if let Ok(apdu) = Apdu::parse(frame.as_slice()) {
                let mut buf = [0u8; 2048];
                let mut res = ResBuf::new(&mut buf);
                let before = platform.borrow().writes;
                let sw = app.process(&apdu, &mut fs, &mut res);
                let after = platform.borrow();
                if !confirmed {
                    assert_eq!(after.writes, before, "a denied burn reached the platform");
                }
                if sw == Sw::OK && apdu.cla == RESCUE_CLA && apdu.ins == INS_OTP_LOCK {
                    match apdu.p1 {
                        P1_LOCK_PAGE58 => assert_eq!(
                            after.lock, PAGE58_LATCH_VALUE,
                            "LOCK58 reported success without the complete latch"
                        ),
                        P1_REQUIRE_ROLLBACK => assert!(
                            rsk_rescue::rollback::required(rsk_rescue::rollback::majority(
                                after.flags0
                            )),
                            "ROLLBK reported success without the majority fuse"
                        ),
                        _ => panic!("an unsupported OTP selector reported success"),
                    }
                }
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    replay(data, 0);
    // Keep the original corpus's replay; a suffix also selects a faulted or fused boot.
    let mode = data.last().copied().unwrap_or(0);
    if mode != 0 {
        replay(data, mode);
    }
});
