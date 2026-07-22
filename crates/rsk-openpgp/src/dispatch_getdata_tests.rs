// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Does the on-device dispatch path handle a no-command-data (ISO-7816 Case-1 /
//! Case-2) GET DATA, or does it drop it to `6D00`?
//!
//! On real hardware (Waveshare RP2350-Zero, macOS PC/SC) `GET DATA` returned
//! `6D 00` (INS not supported) while data-bearing commands (VERIFY, PSO, PIV
//! GET DATA) reached the applet. `6D00` is only reachable via the applet's
//! `_ => INS_NOT_SUPPORTED` fall-through, i.e. `apdu.ins != 0xCA` — impossible if
//! the byte on the wire is `CA`. This test drives the exact bytes through the
//! REAL [`Dispatcher`] (the same dispatch the CCID transport calls via
//! `handle_apdu`), not the direct `applet.process()` the other tests use, to pin
//! whether the firmware code path itself mangles a Case-1/2 APDU. If these pass,
//! the firmware dispatch is correct and the on-device `6D00` is a host-side
//! (macOS CCID) artifact, not a firmware bug.

use super::*;
use rsk_fs::storage::ram::RamStorage;
use rsk_sdk::Dispatcher;

struct CountRng(u8);
impl Rng for CountRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

const SERIAL_ID: [u8; 8] = [0xAA, 0xBB, 0xCC, 0xDD, 5, 6, 7, 8];
const SERIAL_HASH: [u8; 32] = [0x22; 32];

fn setup() -> Fs<RamStorage> {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    let dev = Device {
        serial_hash: &SERIAL_HASH,
        serial_id: &SERIAL_ID,
        otp_key: None,
    };
    scan_files(&dev, &mut fs, &mut CountRng(0)).unwrap();
    fs
}

/// Drive one raw APDU through the real dispatcher (the exact call the CCID
/// transport's `handle_apdu` makes on-device) and return `(body, sw)`.
fn dispatch(
    disp: &mut Dispatcher,
    applets: &mut [&mut dyn rsk_sdk::Applet<Fs<RamStorage>>],
    fs: &mut Fs<RamStorage>,
    raw: &[u8],
) -> (Vec<u8>, Sw) {
    let mut buf = [0u8; 2048];
    let mut res = ResBuf::new(&mut buf);
    let sw = disp.process(raw, applets, fs, &mut res);
    (res.as_slice().to_vec(), sw)
}

// The OpenPGP SELECT-by-AID APDU (Case-4: has data).
const SELECT_OPENPGP: &[u8] = &[
    0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
];

#[test]
fn getdata_aid_case2_via_dispatcher_returns_aid_not_6d00() {
    let mut fs = setup();
    let rng = RefCell::new(CountRng(0));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    let mut disp = Dispatcher::default();
    let mut applets: [&mut dyn rsk_sdk::Applet<Fs<RamStorage>>; 1] = [&mut app];

    assert_eq!(
        dispatch(&mut disp, &mut applets, &mut fs, SELECT_OPENPGP).1,
        Sw::OK
    );

    // Case-2 GET DATA 0x4F (Le=0 → 256) — the exact byte string that gave 6D00
    // on hardware.
    let (aid, sw) = dispatch(
        &mut disp,
        &mut applets,
        &mut fs,
        &[0x00, 0xCA, 0x00, 0x4F, 0x00],
    );
    assert_eq!(sw, Sw::OK, "Case-2 GET DATA 0x4F must return OK, not 6D00");
    assert_eq!(aid.len(), 16, "the AID DO is 16 bytes");
    assert_eq!(
        &aid[..6],
        &[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01],
        "OpenPGP AID prefix"
    );
    assert_eq!(
        &aid[10..14],
        &crate::files::serial_bcd(&rsk_mgmt::serial4(SERIAL_ID)),
        "BCD device serial spliced at offset 10 (YubiKey convention)"
    );

    // Case-1 GET DATA 0x4F (no Le) — the 4-byte form, also 6D00 on hardware.
    let (aid1, sw1) = dispatch(&mut disp, &mut applets, &mut fs, &[0x00, 0xCA, 0x00, 0x4F]);
    assert_eq!(sw1, Sw::OK, "Case-1 GET DATA 0x4F must return OK, not 6D00");
    assert_eq!(aid1, aid, "Case-1 and Case-2 return the same AID");
}

#[test]
fn getdata_pw_status_case2_via_dispatcher_returns_ok() {
    // GET DATA 0xC4 (PW status) — another Case-2 command gpg issues on connect.
    let mut fs = setup();
    let rng = RefCell::new(CountRng(0));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    let mut disp = Dispatcher::default();
    let mut applets: [&mut dyn rsk_sdk::Applet<Fs<RamStorage>>; 1] = [&mut app];

    assert_eq!(
        dispatch(&mut disp, &mut applets, &mut fs, SELECT_OPENPGP).1,
        Sw::OK
    );
    let (body, sw) = dispatch(
        &mut disp,
        &mut applets,
        &mut fs,
        &[0x00, 0xCA, 0x00, 0xC4, 0x00],
    );
    assert_eq!(sw, Sw::OK, "Case-2 GET DATA 0xC4 must return OK, not 6D00");
    assert_eq!(&body, &[0x01, 127, 127, 127, 3, 0, 3], "PW status DO");
}

#[test]
fn verify_default_pw1_via_dispatcher_is_ok() {
    // The on-device path for VERIFY (Case-3), to confirm SELECT sets the active
    // applet and a provisioned EF_PW1 verifies through the dispatcher — the
    // hardware returned 6A88 here (EF_PW1 not found), so on host (provisioned)
    // it must return OK, isolating the hardware result as a provisioning/host
    // question rather than a dispatch bug.
    let mut fs = setup();
    let rng = RefCell::new(CountRng(0));
    let presence = RefCell::new(crate::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
    let mut disp = Dispatcher::default();
    let mut applets: [&mut dyn rsk_sdk::Applet<Fs<RamStorage>>; 1] = [&mut app];

    assert_eq!(
        dispatch(&mut disp, &mut applets, &mut fs, SELECT_OPENPGP).1,
        Sw::OK
    );
    // VERIFY PW1 (mode 0x81) with the default "123456".
    let verify = [
        0x00, 0x20, 0x00, 0x81, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
    ];
    assert_eq!(
        dispatch(&mut disp, &mut applets, &mut fs, &verify).1,
        Sw::OK,
        "default PW1 must verify through the dispatcher on a provisioned FS"
    );
}
