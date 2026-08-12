// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the whole YKOATH applet dispatch (`OathApplet::process`) — the OATH
//! analogue of `openpgp_apdu`/`mgmt_apdu`. The applet is seeded with one TOTP
//! and one HOTP credential (so CALCULATE / LIST / RENAME / VERIFY CODE reach
//! real stored blobs), then a sequence of length-prefixed attacker APDUs is
//! replayed against the live applet + RAM flash, with a SELECT between
//! sequences. None may panic.

use core::cell::RefCell;

use libfuzzer_sys::fuzz_target;
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;
use rsk_oath::{OathApplet, Rng};
use rsk_sdk::{Apdu, Applet, ResBuf, Sw};

mod apdu_frame;
use apdu_frame::{Frame, next_frame};

struct CountRng(u8);
impl Rng for CountRng {
    fn fill(&mut self, b: &mut [u8]) {
        for x in b.iter_mut() {
            *x = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

fn run(app: &mut OathApplet, fs: &mut Fs<RamStorage>, raw: &[u8]) -> Sw {
    if let Ok(apdu) = Apdu::parse(raw) {
        let mut buf = [0u8; 4096];
        let mut res = ResBuf::new(&mut buf);
        return app.process(&apdu, fs, &mut res);
    }
    // The status the dispatcher answers for an unparseable command.
    Sw::WRONG_LENGTH
}

fuzz_target!(|data: &[u8]| {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    let rng = RefCell::new(CountRng(0));
    let touch = RefCell::new(rsk_oath::AlwaysConfirm);
    let mut app = OathApplet::new([1, 2, 3, 4, 5, 6, 7, 8], [0x22; 32], None, &rng, &touch);

    // Seed one TOTP and one HOTP credential through the real PUT path. The
    // seeding takes no fuzzer input, so asserting it worked cannot flake — and
    // a seed that silently stops storing is invisible otherwise.
    for put in [
        &[
            0x00, 0x01, 0, 0, 0x1E, // PUT, Lc = 30
            0x71, 0x04, b't', b'o', b't', b'p', // NAME
            0x73, 0x16, 0x21, 6, // KEY: TOTP|SHA1, 6 digits
            b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'1', b'2', b'3', b'4',
            b'5', b'6', b'7', b'8', b'9', b'0',
        ][..],
        &[
            0x00, 0x01, 0, 0, 0x16, // PUT, Lc = 22
            0x71, 0x04, b'h', b'o', b't', b'p', // NAME
            0x73, 0x08, 0x11, 6, b'k', b'e', b'y', b'k', b'e', b'y', // KEY: HOTP|SHA1
            0x78, 0x02, // bare property pair (touch)
            0x7A, 0x02, 0x00, 0x05, // IMF, short (padded by PUT)
        ][..],
    ] {
        assert_eq!(run(&mut app, &mut fs, put), Sw::OK, "seed PUT must succeed");
    }

    // Replay attacker APDUs: [len][apdu bytes…]*, with a SELECT between them
    // and 0xFF as the extended-Lc escape (see `apdu_frame`).
    let mut rest = data;
    while let Some((frame, tail)) = next_frame(rest) {
        rest = tail;
        match frame {
            // Re-SELECT: regenerates the challenge / re-locks if a code is set.
            Frame::Select => {
                let mut buf = [0u8; 256];
                let mut res = ResBuf::new(&mut buf);
                let _ = Applet::select(&mut app, false, &mut fs, &mut res);
            }
            f => {
                run(&mut app, &mut fs, f.as_slice());
            }
        }
    }
});
