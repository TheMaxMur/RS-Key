// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the OATH OTP-PIN record format parsing (`rsk_oath`): seed `EF_OTP_PIN`
//! with arbitrary stored bytes and drive VERIFY / CHANGE with an arbitrary
//! password, under both device generations. This exercises `otp_pin_matches`'s
//! v1(34)/legacy(33) length dispatch and its pre-OTP `without_otp()` fallback,
//! plus the lazy upgrade-on-success path. The record and password are attacker-
//! controlled; none of the shapes may panic.

use core::cell::RefCell;

use libfuzzer_sys::fuzz_target;
use rsk_crypto::FusedKey;
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;
use rsk_oath::{OathApplet, Rng};
use rsk_sdk::{Apdu, Applet, ResBuf};

// crate-private constants, mirrored (must match crates/rsk-oath/src/lib.rs).
const EF_OTP_PIN: u16 = 0x10A0;
const INS_VERIFY_PIN: u8 = 0xB2;
const INS_CHANGE_PIN: u8 = 0xB3;
const TAG_PASSWORD: u8 = 0x80;
const TAG_NEW_PASSWORD: u8 = 0x81;

/// The OTP-fused MKEK, as the applet takes it: a reader, not the key. Matches how
/// the firmware supplies one — the fuse is read on demand, never held in RAM.
fn fused_mkek() -> Option<[u8; 32]> {
    Some([0x5A; 32])
}

struct CountRng(u8);
impl Rng for CountRng {
    fn fill(&mut self, b: &mut [u8]) {
        for x in b.iter_mut() {
            *x = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

fn tlv(tag: u8, val: &[u8]) -> Vec<u8> {
    let mut v = vec![tag, val.len() as u8];
    v.extend_from_slice(val);
    v
}

fn apdu(ins: u8, data: &[u8]) -> Vec<u8> {
    let mut v = vec![0x00, ins, 0x00, 0x00, data.len() as u8];
    v.extend_from_slice(data);
    v
}

fn drive(app: &mut OathApplet, fs: &mut Fs<RamStorage>, raw: &[u8]) {
    if let Ok(a) = Apdu::parse(raw) {
        let mut buf = [0u8; 512];
        let mut res = ResBuf::new(&mut buf);
        let _ = app.process(&a, fs, &mut res);
    }
}

fuzz_target!(|data: &[u8]| {
    // Split the input into a stored OTP-PIN record and a presented password.
    let Some((&rlen, rest)) = data.split_first() else {
        return;
    };
    let rlen = (rlen as usize).min(rest.len()).min(40); // TLV len byte caps at 127
    let (rec, pw) = rest.split_at(rlen);
    let pw = &pw[..pw.len().min(64)];

    // Both generations: None exercises the legacy/serial arm, Some exercises the
    // v1 OTP-rooted verifier and its without_otp() fallback.
    let generations: [Option<FusedKey>; 2] = [None, Some(fused_mkek)];
    for otp in generations {
        let mut fs = Fs::new(RamStorage::new());
        fs.scan();
        // Seed the fuzzer's raw record (EF_OTP_PIN is a plaintext verifier slot).
        if fs.put(EF_OTP_PIN, rec).is_err() {
            continue;
        }
        let rng = RefCell::new(CountRng(0));
        let touch = RefCell::new(rsk_oath::AlwaysConfirm);
        let mut app = OathApplet::new([1, 2, 3, 4, 5, 6, 7, 8], [0x22; 32], otp, &rng, &touch);

        drive(
            &mut app,
            &mut fs,
            &apdu(INS_VERIFY_PIN, &tlv(TAG_PASSWORD, pw)),
        );
        let mut chg = tlv(TAG_PASSWORD, pw);
        chg.extend_from_slice(&tlv(TAG_NEW_PASSWORD, pw));
        drive(&mut app, &mut fs, &apdu(INS_CHANGE_PIN, &chg));
    }
});
