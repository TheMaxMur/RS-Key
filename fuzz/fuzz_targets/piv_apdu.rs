// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz the whole PIV applet dispatch (`PivApplet::process`) — the PIV analogue
//! of `openpgp_apdu`/`oath_apdu`/`mgmt_apdu`. The applet is SELECTed (creating
//! the default PINs, management key and F9 attestation cert), authenticated to
//! the default management key and PIN-verified, and seeded with a generated
//! P-256 key in slot 9A so AUTHENTICATE / ATTEST / GET DATA reach real stored
//! blobs. Then a sequence of length-prefixed attacker APDUs is replayed against
//! the live applet + RAM flash, with a SELECT between sequences. None may
//! panic. RSA generate is skipped, in the seed and in the replay: keygen is not
//! an input parser, and the prime search would dominate the time budget.

use core::cell::RefCell;

use libfuzzer_sys::fuzz_target;
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;
use rsk_piv::files::{ALGO_RSA1024, ALGO_RSA2048, ALGO_RSA3072, ALGO_RSA4096, TAG_GEN_TEMPLATE};
use rsk_piv::{AlwaysConfirm, INS_ASYM_KEYGEN, PivApplet, Rng};
use rsk_sdk::tlv::find_tag;
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

const DEFAULT_PIN: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF];
const DEFAULT_MGM: [u8; 24] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];

fn run(app: &mut PivApplet, fs: &mut Fs<RamStorage>, raw: &[u8]) -> (Sw, Vec<u8>) {
    if let Ok(apdu) = Apdu::parse(raw) {
        let mut buf = [0u8; 4096];
        let mut res = ResBuf::new(&mut buf);
        let sw = app.process(&apdu, fs, &mut res);
        return (sw, res.as_slice().to_vec());
    }
    // The status the dispatcher answers for an unparseable command.
    (Sw::WRONG_LENGTH, Vec::new())
}

/// The algorithm tag inside the `AC` generate template (`keygen::parse_gen_template`).
const TAG_GEN_ALGO: u16 = 0x80;

/// True for a GENERATE asking for an RSA key. `keygen` gates on `has_mgm`, so
/// while the seed above failed to authenticate this was unreachable; with it
/// fixed one RSA-2048 request costs ~800 ms against a 5 ms whole iteration.
fn is_rsa_keygen(raw: &[u8]) -> bool {
    let Ok(apdu) = Apdu::parse(raw) else {
        return false;
    };
    if apdu.ins != INS_ASYM_KEYGEN {
        return false;
    }
    find_tag(apdu.data, TAG_GEN_TEMPLATE as u16)
        .and_then(|ac| find_tag(ac, TAG_GEN_ALGO))
        .and_then(|a| a.first())
        .is_some_and(|a| {
            matches!(
                *a,
                ALGO_RSA1024 | ALGO_RSA2048 | ALGO_RSA3072 | ALGO_RSA4096
            )
        })
}

/// Authenticate to the default AES-192 management key (two-step mutual auth).
/// Returns step 2's status word — the caller asserts on it.
fn auth_mgm(app: &mut PivApplet, fs: &mut Fs<RamStorage>) -> Sw {
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{BlockDecrypt, KeyInit};
    let (sw, wit) = run(
        app,
        fs,
        &[0x00, 0x87, 0x0A, 0x9B, 0x04, 0x7C, 0x02, 0x80, 0x00],
    );
    assert_eq!(sw, Sw::OK, "mutual auth step 1 (witness) must succeed");
    assert!(wit.len() >= 20, "witness response too short: {wit:02X?}");
    let cipher = aes::Aes192::new(GenericArray::from_slice(&DEFAULT_MGM));
    let mut w = [0u8; 16];
    w.copy_from_slice(&wit[4..20]);
    let mut blk = GenericArray::clone_from_slice(&w);
    cipher.decrypt_block(&mut blk);
    // Lc counts the whole 7C wrapper (2 + 36) and the 7C length both inner
    // objects (80 10 + 16, 81 10 + 16). Undercounting the 81 header by 2 made
    // `Tlv::next` drop the host challenge, so step 2 answered 6A80 forever.
    let mut msg = vec![0x00, 0x87, 0x0A, 0x9B, 0x26, 0x7C, 0x24, 0x80, 0x10];
    msg.extend_from_slice(&blk);
    msg.push(0x81);
    msg.push(0x10);
    msg.extend_from_slice(&[0xA5; 16]);
    run(app, fs, &msg).0
}

fuzz_target!(|data: &[u8]| {
    let rng = RefCell::new(CountRng(0));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new([1, 2, 3, 4, 5, 6, 7, 8], [0x22; 32], None, &rng, &pres);
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();

    // SELECT to initialize the default files.
    {
        let mut buf = [0u8; 256];
        let mut res = ResBuf::new(&mut buf);
        let _ = Applet::select(&mut app, false, &mut fs, &mut res);
    }
    // The seeding below takes no fuzzer input, so these assertions are
    // deterministic: they can only fire when the seed itself stops working,
    // which is invisible in a coverage-less green CI row.
    assert_eq!(
        auth_mgm(&mut app, &mut fs),
        Sw::OK,
        "mutual auth step 2 must succeed"
    );
    // VERIFY default PIN.
    let mut verify = vec![0x00, 0x20, 0x00, 0x80, 0x08];
    verify.extend_from_slice(&DEFAULT_PIN);
    assert_eq!(
        run(&mut app, &mut fs, &verify).0,
        Sw::OK,
        "VERIFY of the default PIN must succeed"
    );
    // GENERATE P-256 in slot 9A. It is management-key gated, so an OK here is
    // the proof that `has_mgm` actually flipped in mutual auth step 2.
    let (gen_sw, gen_body) = run(
        &mut app,
        &mut fs,
        &[0x00, 0x47, 0x00, 0x9A, 0x05, 0xAC, 0x03, 0x80, 0x01, 0x11],
    );
    assert_eq!(gen_sw, Sw::OK, "GENERATE in slot 9A must succeed");
    assert!(!gen_body.is_empty(), "GENERATE must return a public key");

    // Replay attacker APDUs: [len][apdu bytes…]*, with a SELECT between them
    // and 0xFF as the extended-Lc escape (see `apdu_frame`) — a PIV certificate
    // import does not fit a short Lc.
    let mut rest = data;
    while let Some((frame, tail)) = next_frame(rest) {
        rest = tail;
        match frame {
            Frame::Select => {
                let mut buf = [0u8; 256];
                let mut res = ResBuf::new(&mut buf);
                let _ = Applet::select(&mut app, false, &mut fs, &mut res);
            }
            f if !is_rsa_keygen(f.as_slice()) => {
                run(&mut app, &mut fs, f.as_slice());
            }
            _ => {}
        }
    }
});
