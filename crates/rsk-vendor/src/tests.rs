// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::ram::RamStorage;

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

/// A [`Platform`] with every capability present, so the arms that a real board
/// serves can be driven here. `led` is the live block SET LED rewrites.
#[derive(Default)]
struct FullPlatform {
    led: [u8; CONF_LEN],
    reboots: Vec<(bool,)>,
}

impl Platform for FullPlatform {
    fn led_block(&self) -> Option<[u8; CONF_LEN]> {
        Some(self.led)
    }

    fn set_led(
        &mut self,
        status: u8,
        color: u8,
        brightness: u8,
        steady: bool,
        effect: Option<u8>,
        speed: Option<u8>,
    ) -> Option<[u8; CONF_LEN]> {
        self.led[0] = u8::from(steady);
        let at = 1 + status as usize * 4;
        self.led[at] = effect.unwrap_or(self.led[at]);
        self.led[at + 1] = color;
        self.led[at + 2] = brightness;
        self.led[at + 3] = speed.unwrap_or(self.led[at + 3]);
        Some(self.led)
    }

    fn core1_stats(&self) -> Option<[u8; 32]> {
        Some([7u8; 32])
    }

    fn request_reboot(&mut self, bootsel: bool) -> bool {
        self.reboots.push((bootsel,));
        true
    }
}

/// The default platform: a build with none of the hardware. Every gated arm has
/// to answer `INS_NOT_SUPPORTED` rather than a plausible-looking success.
struct BarePlatform;
impl Platform for BarePlatform {}

struct Declining;
impl UserPresence for Declining {
    fn request(&mut self, _confirm: Confirm<'_>) -> Presence {
        Presence::Declined
    }
}

fn apdu(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut v = vec![0x00, ins, p1, p2];
    if !data.is_empty() {
        v.push(data.len() as u8);
        v.extend_from_slice(data);
    }
    v
}

fn run<P: Platform>(
    app: &mut VendorApplet<P>,
    fs: &mut Fs<RamStorage>,
    raw: &[u8],
) -> (Sw, Vec<u8>) {
    let mut out = [0u8; 256];
    let mut res = ResBuf::new(&mut out);
    let parsed = Apdu::parse(raw).unwrap();
    let sw = Applet::process(app, &parsed, fs, &mut res);
    (sw, res.as_slice().to_vec())
}

#[test]
fn counter_starts_at_zero_and_increments() {
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = VendorApplet::new(BarePlatform, &pres);
    let mut fs = Fs::new(RamStorage::default());

    let (sw, body) = run(&mut app, &mut fs, &apdu(INS_GET, 0, 0, &[]));
    assert_eq!((sw, body), (Sw::OK, vec![0, 0, 0, 0]));

    for want in 1u32..=3 {
        let (sw, body) = run(&mut app, &mut fs, &apdu(INS_INCREMENT, 0, 0, &[]));
        assert_eq!(sw, Sw::OK);
        assert_eq!(body, want.to_be_bytes(), "INCREMENT returns the new value");
    }
    let (_, body) = run(&mut app, &mut fs, &apdu(INS_GET, 0, 0, &[]));
    assert_eq!(body, 3u32.to_be_bytes(), "GET reads what INCREMENT stored");
}

#[test]
fn the_counter_is_the_persisted_file() {
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = VendorApplet::new(BarePlatform, &pres);
    let mut fs = Fs::new(RamStorage::default());
    run(&mut app, &mut fs, &apdu(INS_INCREMENT, 0, 0, &[]));

    // Rebuild the file system over the same backend — a reboot, as far as the
    // applet can tell. `01_flash_persistence.py` asserts exactly this on a board.
    let mut rebooted = Fs::new(fs.into_storage());
    let (_, body) = run(&mut app, &mut rebooted, &apdu(INS_GET, 0, 0, &[]));
    assert_eq!(body, 1u32.to_be_bytes(), "the counter survived the rebuild");
}

#[test]
fn a_build_without_the_hardware_says_so() {
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = VendorApplet::new(BarePlatform, &pres);
    let mut fs = Fs::new(RamStorage::default());

    // Not "OK with an empty body": a host tool reads a status word, and a silent
    // success would report an LED that was never set.
    for ins in [
        INS_SET_LED,
        INS_GET_LED,
        INS_CORE1_STATS,
        INS_KEYGEN_BENCH,
        INS_BENCH,
    ] {
        let (sw, body) = run(&mut app, &mut fs, &apdu(ins, 0, 0, &[]));
        assert_eq!(sw, Sw::INS_NOT_SUPPORTED, "ins {ins:#04x}");
        assert!(body.is_empty(), "ins {ins:#04x} answered with a body");
    }
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_REBOOT, 0, 0, &[]));
    assert_eq!(sw, Sw::INS_NOT_SUPPORTED, "no reset to run");
    assert!(
        !fs.has_data(EF_LED_CONF),
        "a refused SET LED persisted nothing"
    );
}

#[test]
fn set_led_applies_and_persists_the_block() {
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = VendorApplet::new(FullPlatform::default(), &pres);
    let mut fs = Fs::new(RamStorage::default());

    // status 1 (P2 bits 5:4), colour 3, steady, brightness 200, effect 5, speed 9.
    let raw = apdu(INS_SET_LED, 200, 0x10 | 0x08 | 0x03, &[5, 9]);
    assert_eq!(run(&mut app, &mut fs, &raw).0, Sw::OK);

    let (sw, block) = run(&mut app, &mut fs, &apdu(INS_GET_LED, 0, 0, &[]));
    assert_eq!(sw, Sw::OK);
    assert_eq!(block.len(), CONF_LEN);
    assert_eq!(block[0], 1, "steady");
    assert_eq!(
        &block[5..9],
        &[5, 3, 200, 9],
        "status 1 = effect, colour, br, speed"
    );

    let mut stored = [0u8; CONF_LEN];
    let n = fs
        .read(EF_LED_CONF, &mut stored)
        .expect("EF_LED_CONF written");
    assert_eq!(
        (n, &stored[..]),
        (CONF_LEN, &block[..]),
        "persisted == live"
    );
}

#[test]
fn an_effect_only_update_keeps_the_speed() {
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = VendorApplet::new(FullPlatform::default(), &pres);
    let mut fs = Fs::new(RamStorage::default());

    run(&mut app, &mut fs, &apdu(INS_SET_LED, 10, 0x00, &[1, 42]));
    run(&mut app, &mut fs, &apdu(INS_SET_LED, 10, 0x00, &[2]));
    let (_, block) = run(&mut app, &mut fs, &apdu(INS_GET_LED, 0, 0, &[]));
    assert_eq!(block[1], 2, "effect updated");
    assert_eq!(block[4], 42, "speed left alone by a one-byte update");
}

#[test]
fn reboot_to_bootsel_needs_the_operator() {
    let pres = RefCell::new(Declining);
    let mut app = VendorApplet::new(FullPlatform::default(), &pres);
    let mut fs = Fs::new(RamStorage::default());

    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_REBOOT, 0x01, 0, &[]));
    assert_eq!(sw, Sw::CONDITIONS_NOT_SATISFIED);
    assert!(
        app.platform.reboots.is_empty(),
        "a declined touch queued a reboot anyway — the cross-AID bypass this gate exists to close"
    );

    // The warm restart is deliberately ungated: it drops no secrets to a host.
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_REBOOT, 0x00, 0, &[]));
    assert_eq!(sw, Sw::OK);
    assert_eq!(app.platform.reboots, vec![(false,)]);
}

#[test]
fn reboot_rejects_a_bad_p1_and_a_body() {
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = VendorApplet::new(FullPlatform::default(), &pres);
    let mut fs = Fs::new(RamStorage::default());

    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_REBOOT, 0x02, 0, &[])).0,
        Sw::INCORRECT_P1P2
    );
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_REBOOT, 0x00, 0, &[0xAA])).0,
        Sw::WRONG_LENGTH
    );
    assert!(app.platform.reboots.is_empty());
}

#[test]
fn an_unknown_instruction_is_refused() {
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = VendorApplet::new(FullPlatform::default(), &pres);
    let mut fs = Fs::new(RamStorage::default());
    assert_eq!(
        run(&mut app, &mut fs, &apdu(0xEE, 0, 0, &[])).0,
        Sw::INS_NOT_SUPPORTED
    );
}

#[test]
fn select_is_the_aid_and_answers_ok() {
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = VendorApplet::new(BarePlatform, &pres);
    let mut fs = Fs::new(RamStorage::default());
    let mut out = [0u8; 16];
    let mut res = ResBuf::new(&mut out);
    assert_eq!(Applet::select(&mut app, false, &mut fs, &mut res), Sw::OK);
    assert!(res.as_slice().is_empty());
    assert_eq!(
        <VendorApplet<BarePlatform> as Applet<Fs<RamStorage>>>::aid(&app),
        &[0xF0, 0x00, 0x00, 0x00, 0x01]
    );
}
