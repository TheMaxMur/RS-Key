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

/// A cardholder certificate the size DO C0 announces must survive the round trip
/// whole, and one byte past it must be refused at the write instead of coming
/// back short with `9000`. Driven through the dispatcher because the truncation
/// lived in the applet's own scratch, not in `put_data` or `get_data`: a 1500-byte
/// certificate — an ordinary X.509 size, and §9.7's named use — used to write OK,
/// read back 1024 bytes and report success, losing 476 with nothing to tell the
/// host. A YubiKey 5.7.4 announces the same 2048 and holds to it exactly.
#[test]
fn a_do_the_card_announces_room_for_reads_back_whole() {
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
    let mut verify = std::vec![
        0x00u8,
        0x20,
        0x00,
        0x83,
        crate::consts::PW3_DEFAULT.len() as u8
    ];
    verify.extend_from_slice(crate::consts::PW3_DEFAULT);
    assert_eq!(
        dispatch(&mut disp, &mut applets, &mut fs, &verify).1,
        Sw::OK
    );

    // C0 bytes 5-6 (certificate) and 7-8 (special DOs) are the announcement.
    let (c0, sw) = dispatch(
        &mut disp,
        &mut applets,
        &mut fs,
        &[0x00, 0xCA, 0x00, 0xC0, 0x00],
    );
    assert_eq!(sw, Sw::OK);
    let announced = u16::from_be_bytes([c0[4], c0[5]]) as usize;
    assert_eq!(announced, crate::files::MAX_DO_BYTES);
    assert_eq!(u16::from_be_bytes([c0[6], c0[7]]) as usize, announced);

    // Chained PUT DATA 7F21 — 255-byte segments, the shape a host uses.
    let value: Vec<u8> = (0..announced).map(|i| (i * 7 + 11) as u8).collect();
    let write = |disp: &mut Dispatcher,
                 applets: &mut [&mut dyn rsk_sdk::Applet<Fs<RamStorage>>],
                 fs: &mut Fs<RamStorage>,
                 v: &[u8]| {
        let mut rest = v;
        while rest.len() > 255 {
            let mut a = std::vec![0x10u8, 0xDA, 0x7F, 0x21, 255];
            a.extend_from_slice(&rest[..255]);
            let sw = dispatch(disp, applets, fs, &a).1;
            if sw != Sw::OK {
                return sw;
            }
            rest = &rest[255..];
        }
        let mut a = std::vec![0x00u8, 0xDA, 0x7F, 0x21, rest.len() as u8];
        a.extend_from_slice(rest);
        dispatch(disp, applets, fs, &a).1
    };
    assert_eq!(
        write(&mut disp, &mut applets, &mut fs, &value),
        Sw::OK,
        "a certificate of exactly the announced length must be accepted"
    );

    // A 2048-byte DO exceeds one short-Le response, so the read walks the `61xx`
    // GET RESPONSE chain the way gpg and opensc do.
    let read_cert = |disp: &mut Dispatcher,
                     applets: &mut [&mut dyn rsk_sdk::Applet<Fs<RamStorage>>],
                     fs: &mut Fs<RamStorage>| {
        let (mut body, mut sw) = dispatch(disp, applets, fs, &[0x00, 0xCA, 0x7F, 0x21, 0x00]);
        while sw.0 & 0xFF00 == 0x6100 {
            let (more, next) = dispatch(disp, applets, fs, &[0x00, 0xC0, 0x00, 0x00, sw.0 as u8]);
            body.extend_from_slice(&more);
            sw = next;
        }
        (body, sw)
    };
    let (back, sw) = read_cert(&mut disp, &mut applets, &mut fs);
    assert_eq!(sw, Sw::OK);
    assert_eq!(
        back.len(),
        announced,
        "read back short — the 9000 would be a lie"
    );
    assert_eq!(back, value, "read back different bytes");

    // One byte past the announcement: refused at the write, and the stored value
    // is left alone rather than half-replaced.
    let mut too_long = value.clone();
    too_long.push(0xFF);
    assert_eq!(
        write(&mut disp, &mut applets, &mut fs, &too_long),
        crate::consts::WRONG_DATA,
        "one byte over the announced maximum must be refused, not truncated"
    );
    let (still, _) = read_cert(&mut disp, &mut applets, &mut fs);
    assert_eq!(
        still, value,
        "a refused write must not disturb the stored DO"
    );

    // Far past it the dispatcher's chain buffer ends the conversation before the
    // applet sees a thing. Which status that is belongs to the E9/E28 CLA sweep
    // (it is `CLA_NOT_SUPPORTED` or `WRONG_LENGTH` depending on which segment
    // overflows); what must hold either way is that it is not a success and the
    // stored certificate is untouched.
    let way_over = std::vec![0x5Au8; announced + 512];
    assert_ne!(write(&mut disp, &mut applets, &mut fs, &way_over), Sw::OK);
    let (survived, _) = read_cert(&mut disp, &mut applets, &mut fs);
    assert_eq!(survived, value);
}

/// DO 7F66 is a promise a host is entitled to act on (§7.7), so the number on the
/// wire must be the one the transport carries — not the encoder's own idea of it.
/// The tie from [`crate::files::MAX_APDU_BYTES`] to the CCID frame is a
/// compile-time assertion in `rsk-device`, the only crate that sees both; this is
/// the other half, that GET DATA really emits that constant.
#[test]
fn exlen_info_announces_the_apdu_the_transport_carries() {
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
        &[0x00, 0xCA, 0x7F, 0x66, 0x00],
    );
    assert_eq!(sw, Sw::OK);
    let max = crate::files::MAX_APDU_BYTES as u16;
    assert_eq!(
        body,
        std::vec![
            0x02,
            0x02,
            (max >> 8) as u8,
            max as u8,
            0x02,
            0x02,
            (max >> 8) as u8,
            max as u8,
        ],
        "7F66 must announce {max} in both directions"
    );
    // The same DO inside the application-related data `6E`, which is where a
    // YubiKey serves it and where `gpg` reads it. Extended `Le`, so the template
    // arrives whole instead of through `61xx`.
    let (tpl, sw) = dispatch(
        &mut disp,
        &mut applets,
        &mut fs,
        &[0x00, 0xCA, 0x00, 0x6E, 0x00, 0x00, 0x00],
    );
    assert_eq!(sw, Sw::OK);
    let at = tpl
        .windows(2)
        .position(|w| w == [0x7F, 0x66])
        .expect("7F66 inside 6E");
    assert_eq!(
        &tpl[at + 3..at + 11],
        &body[..],
        "6E carries the same bytes"
    );
}

/// The P1P2 values GET DATA serves. Everything else in the 16-bit space answers
/// one status word — including the internal storage FIDs, which are addressable
/// through P1P2 and used to answer `6982` where an absent tag answered `6A88`.
const SERVED: &[u16] = &[
    0x004F, 0x005B, 0x005E, 0x0065, 0x006E, 0x0073, 0x007A, 0x0093, 0x00C0, 0x00C1, 0x00C2, 0x00C3,
    0x00C4, 0x00C5, 0x00C6, 0x00C7, 0x00C8, 0x00C9, 0x00CA, 0x00CB, 0x00CC, 0x00CD, 0x00CE, 0x00CF,
    0x00D0, 0x00D6, 0x00D7, 0x00D8, 0x00DE, 0x00F9, 0x00FA, 0x0101, 0x0102, 0x0103, 0x0104, 0x5F2D,
    0x5F35, 0x5F50, 0x5F52, 0x7F21, 0x7F66, 0x7F74,
];

/// The pages the sweep walks end to end: every page carrying a served DO, plus
/// the `0x10xx`/`0x1fxx` region where the internal EFs live.
const SWEPT_PAGES: &[u8] = &[0x00, 0x01, 0x10, 0x1F, 0x5F, 0x7F];

/// GET DATA speaks ONE status word for every P1P2 it does not serve, and the
/// `6982` it keeps means "this DO exists and you are not authorised for it" —
/// nothing else. Measured on a YubiKey 5.7.4 over the whole 16-bit space,
/// unauthenticated: 65513 of 65536 cells are `6B00`, the 21 it serves are `9000`
/// or `61xx`, and its only two `6982`s are `0103`/`0104`, the private DOs it
/// does serve. Ours split that answer three ways — `6A88` for an absent tag,
/// `6982` for one of the 28 internal storage FIDs, `9000` for the write-only
/// reset-code DO — so the split enumerated the file system through a command
/// that needs no credential.
///
/// In-application SELECT is swept in the same loop because it resolves the fid
/// from the same table and the dispatcher does not intercept it: it had the same
/// split, and a fix in one command alone would leave the map readable from the
/// other.
#[test]
fn get_data_answers_one_status_word_for_every_do_it_does_not_serve() {
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

    for verified in [false, true] {
        if verified {
            for (mode, pin) in [
                (0x81u8, consts::PW1_DEFAULT),
                (0x82, consts::PW1_DEFAULT),
                (0x83, consts::PW3_DEFAULT),
            ] {
                let mut a = std::vec![0x00, consts::INS_VERIFY, 0x00, mode, pin.len() as u8];
                a.extend_from_slice(pin);
                assert_eq!(dispatch(&mut disp, &mut applets, &mut fs, &a).1, Sw::OK);
            }
        }
        let mut cells = 0usize;
        let check = |disp: &mut Dispatcher,
                     applets: &mut [&mut dyn rsk_sdk::Applet<Fs<RamStorage>>],
                     fs: &mut Fs<RamStorage>,
                     tag: u16| {
            let raw = [0x00, 0xCA, (tag >> 8) as u8, tag as u8, 0x00];
            let sw = dispatch(disp, applets, fs, &raw).1;
            // §5 gives `0103` READ = PW1-82 and `0104` READ = PW3, and the
            // reference implements exactly that — measured 3/3 from a genuine
            // deselect: unauthenticated both are `6982`, PW1-82 alone opens
            // `0103` and not `0104`, PW3 alone the reverse.
            let private = matches!(tag, 0x0103 | 0x0104) && !verified;
            if private {
                assert_eq!(
                    sw,
                    Sw::SECURITY_STATUS_NOT_SATISFIED,
                    "GET DATA {tag:04X} unauthenticated"
                );
            } else if SERVED.contains(&tag) {
                // A template past 256 bytes leaves through the dispatcher's
                // response chaining, so `61xx` is this command's other success.
                assert!(
                    sw.is_ok() || sw.sw1() == 0x61,
                    "GET DATA {tag:04X} verified={verified}: {:04X} is not a served DO",
                    sw.0
                );
            } else {
                assert_eq!(sw, Sw::WRONG_P1P2, "GET DATA {tag:04X} verified={verified}");
            }
            // The same question through in-application SELECT, which the
            // dispatcher does NOT intercept for `P1 <= 0x02` and which resolves
            // the fid from the same table: an internal EF must be
            // indistinguishable from an absent one here too. `0103`/`0104` are
            // ungated for SELECT on both sides — it selects, it does not read.
            let sel = [0x00, 0xA4, 0x00, 0x00, 0x02, (tag >> 8) as u8, tag as u8];
            let sw = dispatch(disp, applets, fs, &sel).1;
            let want = if SERVED.contains(&tag) {
                Sw::OK
            } else {
                Sw::REFERENCE_NOT_FOUND
            };
            assert_eq!(sw, want, "SELECT fid {tag:04X} verified={verified}");
        };
        for &p1 in SWEPT_PAGES {
            for p2 in 0..=0xFFu8 {
                check(
                    &mut disp,
                    &mut applets,
                    &mut fs,
                    ((p1 as u16) << 8) | p2 as u16,
                );
                cells += 1;
            }
        }
        for p1 in 0..=0xFFu8 {
            if SWEPT_PAGES.contains(&p1) {
                continue;
            }
            for p2 in [0x00u8, 0x42] {
                check(
                    &mut disp,
                    &mut applets,
                    &mut fs,
                    ((p1 as u16) << 8) | p2 as u16,
                );
                cells += 1;
            }
        }
        assert_eq!(cells, 2036, "the swept surface must not shrink silently");
    }
}
