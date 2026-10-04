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
        INS_STACK_RESIDUE,
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

/// Measured over the device's own store (`rsk_store::SeqStorage` on the board's
/// 352-page main ring), driving byte-identical APDUs: every replayed SET LED cost
/// 28.1 B of the *credential* partition, and 117.0 / 203.8 B on a 74.8% / 85.2%
/// live ring, where reclaim had to migrate credential records past it.
#[test]
fn a_replayed_set_led_does_not_reach_flash() {
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = VendorApplet::new(FullPlatform::default(), &pres);
    let mut fs = Fs::new(RamStorage::default());

    let raw = apdu(INS_SET_LED, 200, 0x10 | 0x08 | 0x03, &[5, 9]);
    assert_eq!(run(&mut app, &mut fs, &raw).0, Sw::OK);
    let after_first = fs.write_gen();

    for _ in 0..8 {
        assert_eq!(
            run(&mut app, &mut fs, &raw).0,
            Sw::OK,
            "a replay still answers OK"
        );
    }
    assert_eq!(
        fs.write_gen(),
        after_first,
        "a replayed SET LED wrote flash; the FIDO twin returns early here"
    );

    // The guard must not swallow a real change with it.
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_SET_LED, 201, 0x10, &[])).0,
        Sw::OK
    );
    assert_eq!(
        fs.write_gen(),
        after_first + 1,
        "a changed block must persist"
    );
}

/// The guard reads flash, not a memory of what this applet last wrote: the record
/// is also written by the FIDO twin and by the boot default, so a block that
/// arrived by either of those must not be rewritten either.
#[test]
fn a_block_already_on_flash_is_not_rewritten() {
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = VendorApplet::new(FullPlatform::default(), &pres);
    let mut fs = Fs::new(RamStorage::default());

    // What the APDU below produces from a zeroed platform — seeded straight into
    // flash, so the record is already what the write would store while the live
    // block is not.
    let want = [1u8, 0, 0, 0, 0, 5, 3, 200, 9, 0, 0, 0, 0, 0, 0, 0, 0];
    fs.put(EF_LED_CONF, &want).unwrap();
    let seeded = fs.write_gen();

    let raw = apdu(INS_SET_LED, 200, 0x10 | 0x08 | 0x03, &[5, 9]);
    assert_eq!(run(&mut app, &mut fs, &raw).0, Sw::OK);
    assert_eq!(fs.write_gen(), seeded, "the record already held this block");
}

/// GET LED answers from the live block, so it cannot be used to check what the
/// guard skipped writing — and nothing pinned that until the review of the guard
/// showed a `GET LED` rewired to read flash left every test green.
#[test]
fn get_led_reads_the_live_block_not_flash() {
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = VendorApplet::new(FullPlatform::default(), &pres);
    let mut fs = Fs::new(RamStorage::default());

    app.platform.led = [7u8; CONF_LEN];
    fs.put(EF_LED_CONF, &[9u8; CONF_LEN]).unwrap();

    let (sw, block) = run(&mut app, &mut fs, &apdu(INS_GET_LED, 0, 0, &[]));
    assert_eq!(sw, Sw::OK);
    assert_eq!(block, [7u8; CONF_LEN], "GET LED answered from flash");
}

/// A key provisioned by an older firmware carries a shorter `EF_LED_CONF` (the
/// codec still decodes 13/9/3/2-byte layouts). The guard must compare only a
/// full-length record, or that key never migrates to the current block.
#[test]
fn a_legacy_record_is_still_upgraded() {
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = VendorApplet::new(FullPlatform::default(), &pres);
    let mut fs = Fs::new(RamStorage::default());

    // Deliberately a *prefix* of the 17-byte block the write below produces: a
    // guard that compared only as far as the stored record goes would call this
    // unchanged and leave the key on the old layout for ever.
    fs.put(EF_LED_CONF, &[1u8, 0, 0, 0, 0, 5, 3, 200, 9, 0, 0, 0, 0])
        .unwrap();
    let seeded = fs.write_gen();

    let raw = apdu(INS_SET_LED, 200, 0x10 | 0x08 | 0x03, &[5, 9]);
    assert_eq!(run(&mut app, &mut fs, &raw).0, Sw::OK);
    assert_eq!(
        fs.write_gen(),
        seeded + 1,
        "a short record was left on flash"
    );
    assert_eq!(fs.size(EF_LED_CONF), Some(CONF_LEN));
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

/// Measured on `tools/emu` before this gate existed: 391 increments/s sustained
/// over the CCID socket and 411/s over CTAPHID_MSG, no PIN and no touch, each one
/// appending 16 bytes to the counter partition — a page erase every ~255 of them
/// once the 128 KiB partition has filled. Whoever can open either interface could
/// cycle the flash that also holds the FIDO signature counters. This applet's own
/// reason for gating the BOOTSEL reboot applies verbatim: it answers on both
/// transports, so an ungated write here is one nothing else on the device gates.
#[test]
fn incrementing_the_counter_needs_the_operator() {
    let pres = RefCell::new(Declining);
    let mut app = VendorApplet::new(BarePlatform, &pres);
    let mut fs = Fs::new(RamStorage::default());

    let (sw, body) = run(&mut app, &mut fs, &apdu(INS_INCREMENT, 0, 0, &[]));
    assert_eq!(sw, Sw::CONDITIONS_NOT_SATISFIED);
    assert!(body.is_empty(), "a refused increment answered with a value");
    assert!(
        !fs.has_counter(COUNTER_FID),
        "a declined touch wrote flash anyway — the wear this gate exists to close"
    );

    // Reading it back is not a write and stays ungated, so a host tool can still
    // see the counter it is not allowed to move.
    let (sw, body) = run(&mut app, &mut fs, &apdu(INS_GET, 0, 0, &[]));
    assert_eq!((sw, body), (Sw::OK, vec![0, 0, 0, 0]));
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
fn core1_statistics_and_confirmed_bootsel_reach_the_platform_hooks() {
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = VendorApplet::new(FullPlatform::default(), &pres);
    let mut fs = Fs::new(RamStorage::default());
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_CORE1_STATS, 0, 0, &[])),
        (Sw::OK, vec![7; 32])
    );
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_REBOOT, 1, 0, &[])),
        (Sw::OK, vec![])
    );
    assert_eq!(app.platform.reboots, vec![(true,)]);
}

#[test]
fn refused_counter_and_led_writes_report_the_storage_failure() {
    for raw in [
        apdu(INS_INCREMENT, 0, 0, &[]),
        apdu(INS_SET_LED, 200, 0, &[1, 2]),
    ] {
        let (storage, medium) = rsk_fs::storage::faults::Cut::new();
        let mut fs = Fs::new(storage);
        fs.scan();
        let pres = RefCell::new(AlwaysConfirm);
        let mut app = VendorApplet::new(FullPlatform::default(), &pres);
        medium.arm(0);
        let parsed = Apdu::parse(&raw).unwrap();
        let mut bytes = [0; 64];
        let mut response = ResBuf::new(&mut bytes);
        assert_eq!(
            Applet::process(&mut app, &parsed, &mut fs, &mut response),
            Sw::MEMORY_FAILURE
        );
        assert!(response.is_empty());
        assert!(!fs.has_data(COUNTER_FID.get()));
        assert!(!fs.has_data(EF_LED_CONF));
    }
}

#[test]
fn a_later_led_record_is_clamped_to_the_current_format() {
    let mut fs = Fs::new(RamStorage::default());
    let record: Vec<_> = (0..u8::try_from(CONF_LEN + 5).unwrap()).collect();
    fs.put(EF_LED_CONF, &record).unwrap();
    let mut conf = [0; CONF_LEN];
    assert_eq!(
        load_or_seed_led_config(&mut fs, &[0; CONF_LEN], &mut conf),
        Ok(CONF_LEN)
    );
    assert_eq!(&conf, &record[..CONF_LEN]);
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

/// The boot-time LED load has two arms and a fault can reach only one of them.
///
/// A device that never customised its LEDs has no record, and the block is seeded
/// once so a host `CONFIG_READ` has a full block to read-modify-write. A complete
/// boot scan decides the whole FID space, so that absence is answered from RAM and
/// no read fault can reach it — armed persistently here to prove it.
#[test]
fn a_first_boot_absence_still_seeds_the_live_led_block() {
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    let live = [7u8; CONF_LEN];
    let mut buf = [0u8; CONF_LEN];

    medium.stick(Some(EF_LED_CONF));
    let n = load_or_seed_led_config(&mut fs, &live, &mut buf).expect("a decided absence");
    medium.stick(None);
    assert_eq!((n, &buf[..]), (CONF_LEN, &live[..]));
    assert_eq!(
        medium.value(EF_LED_CONF).as_deref(),
        Some(&live[..]),
        "a first boot must still persist the block a host reads back"
    );
}

/// The other arm: a boot walk one read fault cut short leaves every FID undecided,
/// so the probe reaches the backend and a fault reads as that same absence — which
/// overwrites the owner's LED configuration with the build defaults, at boot,
/// unauthenticated.
#[test]
fn a_faulted_led_probe_does_not_overwrite_the_owners_block() {
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    let owner = [3u8; CONF_LEN];
    fs.put(EF_LED_CONF, &owner).unwrap();

    // The state the fault is live in: nothing decided, so every probe reaches the
    // backend whether its record is present or absent.
    let mut fs = Fs::new(fs.into_storage());
    medium.truncate_walk(true);
    fs.scan();
    medium.truncate_walk(false);

    let live = [7u8; CONF_LEN];
    let mut buf = [0u8; CONF_LEN];
    medium.stick_once(EF_LED_CONF);
    let r = load_or_seed_led_config(&mut fs, &live, &mut buf);
    assert_eq!(
        medium.value(EF_LED_CONF).as_deref(),
        Some(&owner[..]),
        "a faulted probe overwrote the owner's LED block with the build defaults"
    );
    assert!(
        r.is_err(),
        "a boot that could not read the LED block must apply nothing, not the defaults"
    );
}

/// The configuration lock covers the LED record, and no code opens it here: while
/// one is set, SET LED answers `6986` and neither the live block nor flash moves.
/// Cleared, the same write lands.
#[test]
fn a_locked_configuration_refuses_set_led() {
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = VendorApplet::new(FullPlatform::default(), &pres);
    let mut fs = Fs::new(RamStorage::default());
    let mut code = vec![0x0A, 16];
    code.extend_from_slice(&[0xA5; 16]);
    rsk_devconf::persist_touched(&[0; 4], &mut fs, &code).unwrap();
    let set = apdu(INS_SET_LED, 0x80, 0x03, &[]);
    let live = app.platform.led;
    assert_eq!(run(&mut app, &mut fs, &set).0, Sw::COMMAND_NOT_ALLOWED);
    assert_eq!(
        app.platform.led, live,
        "the live LED moved for a refused write"
    );
    assert!(!fs.has_data(EF_LED_CONF), "a refused write reached flash");

    let mut clear = vec![0x0B, 16];
    clear.extend_from_slice(&[0xA5; 16]);
    clear.extend_from_slice(&[0x0A, 16]);
    clear.extend_from_slice(&[0; 16]);
    rsk_devconf::persist_touched(&[0; 4], &mut fs, &clear).unwrap();
    assert_eq!(run(&mut app, &mut fs, &set).0, Sw::OK);
    assert!(fs.has_data(EF_LED_CONF));
}
