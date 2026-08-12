// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the whole OpenPGP applet dispatch (`OpenpgpApplet::process`) — the
//! analogue of `fido_cbor` for the CCID side. A freshly-initialised applet is
//! PIN-authenticated (PW3 admin + PW1/PW2) so the parsers behind the PIN gates
//! are reachable, then a sequence of length-prefixed attacker APDUs is replayed
//! against the live applet + flash. This exercises every command parser at once:
//! GET / PUT DATA, VERIFY / CHANGE PIN / RESET RETRY, IMPORT, PSO (incl. the ECDH
//! `parse_ecdh_point` wrapper), INTERNAL AUTHENTICATE and SELECT. None may panic.

use core::cell::RefCell;

use libfuzzer_sys::fuzz_target;
use rsk_crypto::Device;
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;
use rsk_openpgp::consts::{
    EF_CH_CERT, EF_LOGIN_DATA, EF_PRIV_DO_1, EF_PRIV_DO_2, EF_PRIV_DO_3, EF_PRIV_DO_4, EF_URI_URL,
    INS_GET_DATA, INS_PUT_DATA, INS_VERIFY, PW1_DEFAULT, PW1_MODE81, PW1_MODE82, PW3_DEFAULT,
    PW3_MODE83,
};
use rsk_openpgp::files::MAX_DO_BYTES;
use rsk_openpgp::{OpenpgpApplet, Rng, scan_files};
use rsk_sdk::{Apdu, Applet, ResBuf, Sw};

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

fn dev() -> Device<'static> {
    Device {
        serial_hash: &SERIAL_HASH,
        serial_id: &SERIAL_ID,
        otp_key: None,
    }
}

fn run(app: &mut OpenpgpApplet, fs: &mut Fs<RamStorage>, raw: &[u8]) -> Sw {
    if let Ok(apdu) = Apdu::parse(raw) {
        let mut buf = [0u8; 2048];
        let mut res = ResBuf::new(&mut buf);
        return app.process(&apdu, fs, &mut res);
    }
    // The status the dispatcher answers for an unparseable command.
    Sw::WRONG_LENGTH
}

/// The DOs PUT DATA stores verbatim and GET DATA hands back unwrapped. The
/// cardholder certificate is finding E25's own object; login data, the URL and
/// the private-use DOs shared its cliff.
const RAW_DOS: [u16; 7] = [
    EF_CH_CERT,
    EF_LOGIN_DATA,
    EF_URI_URL,
    EF_PRIV_DO_1,
    EF_PRIV_DO_2,
    EF_PRIV_DO_3,
    EF_PRIV_DO_4,
];

/// DO lengths the driven round trip straddles: the old 1024-byte scratch cliff
/// finding E25 lived on, the short-Lc boundary, and the announced ceiling.
const DO_LENS: [usize; 8] = [0, 1, 255, 256, 1023, 1024, 1025, MAX_DO_BYTES];

/// PUT DATA `fid` with `n` filler bytes through the live applet.
fn put_data(app: &mut OpenpgpApplet, fs: &mut Fs<RamStorage>, fid: u16, n: usize) -> Sw {
    let mut raw = std::vec![0x00, INS_PUT_DATA, (fid >> 8) as u8, fid as u8, 0x00];
    raw.extend_from_slice(&[(n >> 8) as u8, n as u8]);
    raw.extend((0..n).map(|i| 0x41 + (i % 26) as u8));
    run(app, fs, &raw)
}

/// GET DATA `fid` through the live applet: the status and the body length served.
fn get_data_len(app: &mut OpenpgpApplet, fs: &mut Fs<RamStorage>, fid: u16) -> (Sw, usize) {
    let raw = [0x00, INS_GET_DATA, (fid >> 8) as u8, fid as u8, 0x00];
    let apdu = Apdu::parse(&raw).expect("a case-2 GET DATA is well formed");
    let mut buf = [0u8; 2048];
    let mut res = ResBuf::new(&mut buf);
    let sw = app.process(&apdu, fs, &mut res);
    (sw, res.len())
}

fuzz_target!(|data: &[u8]| {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    if scan_files(&dev(), &mut fs, &mut CountRng(0)).is_err() {
        return;
    }
    let rng = RefCell::new(CountRng(0));
    let presence = RefCell::new(rsk_openpgp::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);

    // Authenticate so the IMPORT / PSO / INTERNAL-AUT parsers are reachable.
    // The seeding takes no fuzzer input, so asserting it worked cannot flake —
    // and a seed that silently stops authenticating is invisible otherwise.
    for (mode, pin) in [
        (PW3_MODE83, PW3_DEFAULT),
        (PW1_MODE81, PW1_DEFAULT),
        (PW1_MODE82, PW1_DEFAULT),
    ] {
        let mut v = vec![0x00, INS_VERIFY, 0x00, mode, pin.len() as u8];
        v.extend_from_slice(pin);
        assert_eq!(
            run(&mut app, &mut fs, &v),
            Sw::OK,
            "seed VERIFY of mode {mode:#04X} must succeed"
        );
    }

    // Replay a sequence of length-prefixed APDUs (so the fuzzer can chain e.g.
    // PUT DATA then GET DATA, or IMPORT then PSO) against the live applet. The
    // 0xFF prefix is the extended-Lc escape — see `apdu_frame`; PUT DATA up to
    // MAX_DO_BYTES (2036) is only reachable through it.
    let mut rest = data;
    while let Some((frame, tail)) = next_frame(rest) {
        rest = tail;
        let raw = frame.as_slice();
        // Skip on-device GENERATE (INS 0x47, P1 0x80): key generation is not an
        // input parser, and an RSA keygen would dominate the fuzzer's time budget.
        // The generate dispatch is covered by host tests; read-public (P1 0x81) is
        // still fuzzed here.
        let is_generate = raw.len() >= 3 && raw[1] == 0x47 && raw[2] == 0x80;
        if is_generate {
            continue;
        }
        let sw = run(&mut app, &mut fs, raw);
        // E25's shape, and the only thing the extended-Lc escape's reach is worth
        // without it: a DO written whole and served short under `9000`. The
        // read-back is a command in the sequence like any other.
        if sw == Sw::OK
            && let Ok(apdu) = Apdu::parse(raw)
            && apdu.ins == INS_PUT_DATA
        {
            let fid = ((apdu.p1 as u16) << 8) | apdu.p2 as u16;
            let wrote = apdu.data.len();
            if RAW_DOS.contains(&fid) {
                let (sw, served) = get_data_len(&mut app, &mut fs, fid);
                assert!(
                    sw != Sw::OK || served == wrote,
                    "DO {fid:#06x}: PUT stored {wrote} bytes, GET DATA served {served} under 9000"
                );
            }
        }
    }

    // Driven, because watching is not enough: of the 355 commands past 255 bytes
    // that 8413 accumulated inputs have produced, not one is an `INS DA`, so the
    // band the extended-Lc escape opened is written here or nowhere.
    let fid = RAW_DOS[data.first().copied().unwrap_or(0) as usize % RAW_DOS.len()];
    let n = DO_LENS[data.last().copied().unwrap_or(0) as usize % DO_LENS.len()];
    if put_data(&mut app, &mut fs, fid, n) == Sw::OK {
        let (sw, served) = get_data_len(&mut app, &mut fs, fid);
        assert!(
            sw != Sw::OK || served == n,
            "DO {fid:#06x}: PUT stored {n} bytes, GET DATA served {served} under 9000"
        );
    }
});
