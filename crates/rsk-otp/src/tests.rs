// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::faults::{Cut, RemoveStuck};
use rsk_fs::storage::ram::RamStorage;

const SERIAL: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0, 0, 0];
const SERIAL_HASH: [u8; 32] = [0x22; 32];
/// Typed-ticket flag used to build non-chalresp test slots.
const TKT_APPEND_CR: u8 = 0x20;

/// Deterministic counter RNG for the at-rest seal-nonce round-trips.
struct CountRng(u8);
impl Rng for CountRng {
    fn fill(&mut self, b: &mut [u8]) {
        for x in b {
            *x = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

/// Presence stub the tests can flip to Declined.
struct TestPresence(Presence);
impl UserPresence for TestPresence {
    fn request(&mut self, _confirm: Confirm<'_>) -> Presence {
        self.0
    }
}

fn new_fs() -> Fs<RamStorage> {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    fs
}

fn select(app: &mut OtpApplet, fs: &mut Fs<RamStorage>) -> (Sw, Vec<u8>) {
    let mut out = [0u8; 256];
    let mut res = ResBuf::new(&mut out);
    let sw = Applet::select(app, false, fs, &mut res);
    (sw, res.as_slice().to_vec())
}

fn run(app: &mut OtpApplet, fs: &mut Fs<RamStorage>, raw: &[u8]) -> (Sw, Vec<u8>) {
    let mut out = [0u8; 1024];
    let mut res = ResBuf::new(&mut out);
    let apdu = Apdu::parse(raw).unwrap();
    let sw = Applet::process(app, &apdu, fs, &mut res);
    (sw, res.as_slice().to_vec())
}

fn otp_apdu(p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    assert!(data.len() < 256);
    let mut v = vec![0x00, INS_OTP, p1, p2];
    if !data.is_empty() {
        v.push(data.len() as u8);
        v.extend_from_slice(data);
    }
    v
}

/// Build a valid 52-byte config the way ykman does: fill the fields, then
/// store the complement of the CRC over the first 50 bytes.
fn build_config(
    fixed: &[u8],
    uid: &[u8; 6],
    key: &[u8; 16],
    acc: &[u8; 6],
    ext: u8,
    tkt: u8,
    cfg: u8,
) -> [u8; CONFIG_SIZE] {
    let mut c = [0u8; CONFIG_SIZE];
    c[..fixed.len()].copy_from_slice(fixed);
    c[OFF_UID..OFF_UID + 6].copy_from_slice(uid);
    c[OFF_AES_KEY..OFF_AES_KEY + 16].copy_from_slice(key);
    c[OFF_ACC_CODE..OFF_ACC_CODE + 6].copy_from_slice(acc);
    c[OFF_FIXED_SIZE] = fixed.len() as u8;
    c[OFF_EXT_FLAGS] = ext;
    c[OFF_TKT_FLAGS] = tkt;
    c[OFF_CFG_FLAGS] = cfg;
    let crc = !crc16(&c[..CONFIG_SIZE - 2]);
    c[CONFIG_SIZE - 2..].copy_from_slice(&crc.to_le_bytes());
    c
}

/// HMAC-SHA1 challenge-response config (the `ykman otp chalresp` layout):
/// 16 key bytes in the AES field, 4 in the UID head.
fn chalresp_config(key20: &[u8; 20], acc: &[u8; 6], cfg_extra: u8) -> [u8; CONFIG_SIZE] {
    let mut uid = [0u8; 6];
    uid[..4].copy_from_slice(&key20[16..]);
    let mut aes = [0u8; 16];
    aes.copy_from_slice(&key20[..16]);
    build_config(
        &[],
        &uid,
        &aes,
        acc,
        0,
        TKT_CHAL_RESP,
        CFG_CHAL_HMAC | cfg_extra,
    )
}

#[test]
fn slot_sealed_before_otp_burn_survives_the_burn() {
    // #12 regression: a slot programmed while the OTP MKEK is unburned is
    // sealed under the NO-OTP kbase. After the burn migrate_seal must recover
    // it via the pre-OTP arm and re-seal under the OTP arm — else the slot is
    // silently orphaned (the failure the other four applets already avoid).
    let mut fs = new_fs();
    let mut rng = CountRng(7);
    let nootp = Device {
        serial_hash: &SERIAL_HASH,
        serial_id: &SERIAL,
        otp_key: None,
    };
    let otp_key = [0x55u8; 32];
    let otp = Device {
        otp_key: Some(&otp_key),
        ..nootp
    };
    // Seal a real config under the pre-OTP (NO-OTP) arm.
    let cfg = chalresp_config(&[0xAB; 20], &[0; 6], 0);
    let fid = KeyFid::new(EF_OTP_SLOT1);
    assert!(seal::seal_put(&nootp, &mut fs, &mut rng, fid, &cfg));

    // The OTP-armed device cannot read it yet (different kbase)…
    let mut buf = [0u8; SLOT_SIZE];
    assert!(
        try_read_slot(&otp, &mut fs, EF_OTP_SLOT1, &mut buf)
            .unwrap()
            .is_none()
    );

    // …migrate_seal recovers and re-seals it under the OTP arm.
    migrate_seal(&otp, &mut fs, &mut rng);
    assert!(
        try_read_slot(&otp, &mut fs, EF_OTP_SLOT1, &mut buf)
            .unwrap()
            .is_some()
    );
    assert_eq!(&buf[..CONFIG_SIZE], &cfg[..]);

    // Idempotent: a second pass is a no-op and the slot still reads.
    migrate_seal(&otp, &mut fs, &mut rng);
    assert!(
        try_read_slot(&otp, &mut fs, EF_OTP_SLOT1, &mut buf)
            .unwrap()
            .is_some()
    );
}

#[test]
fn the_boot_pass_re_arms_the_lap_before_it_supersedes_a_pre_otp_slot() {
    // Standing before `run_at_rest_lap` in `firmware/src/main.rs` is not the same as
    // standing before every lap. A boot whose re-seal here was refused latched the
    // marker all the same, and the boot that finally migrates the slot supersedes
    // the chip-serial-rooted copy under a marker the lap gates on and nothing clears.
    let nootp = Device {
        serial_hash: &SERIAL_HASH,
        serial_id: &SERIAL,
        otp_key: None,
    };
    let otp_key = [0x55u8; 32];
    let otp = Device {
        otp_key: Some(&otp_key),
        ..nootp
    };
    let cfg = chalresp_config(&[0xAB; 20], &[0; 6], 0);
    let fid = KeyFid::new(EF_OTP_SLOT1);
    let mut rng = CountRng(7);
    let mut buf = [0u8; SLOT_SIZE];

    // The ORDER, on the one medium that can tell the two orderings apart.
    let (cut, medium) = Cut::new();
    let mut fs = Fs::new(cut);
    fs.scan();
    assert!(seal::seal_put(&nootp, &mut fs, &mut rng, fid, &cfg));
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    assert!(
        fs.has_data(rsk_fs::EF_HARDENED),
        "fixture: an earlier boot latched the marker"
    );
    medium.clear_ops();
    migrate_seal(&otp, &mut fs, &mut rng);
    medium.assert_re_armed_before(EF_OTP_SLOT1, |_| false, "migrate_seal's pre-OTP arm");
    assert!(
        !fs.has_data(rsk_fs::EF_HARDENED),
        "the re-seal superseded a chip-serial-rooted copy, so the lap must run again"
    );

    // The GATE. A medium refusing only `remove(EF_HARDENED)` reaches that same end
    // state with no reset in it, so the re-seal must not go ahead at all.
    let (stuck, medium) = RemoveStuck::new();
    let mut fs = Fs::new(stuck);
    fs.scan();
    assert!(seal::seal_put(&nootp, &mut fs, &mut rng, fid, &cfg));
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    medium.refuse(Some(rsk_fs::EF_HARDENED));
    migrate_seal(&otp, &mut fs, &mut rng);
    assert!(
        try_read_slot(&otp, &mut fs, EF_OTP_SLOT1, &mut buf)
            .unwrap()
            .is_none(),
        "the re-arm never landed, so the pre-OTP copy must stay UNSUPERSEDED — at \
         the cost the site states: no command opens this slot until a later boot"
    );
    assert!(
        medium.live(rsk_fs::EF_HARDENED),
        "fixture: the refusal really left the marker on the medium"
    );

    // The control, same medium, fault cleared: the migration DOES happen, so the
    // assertion above is about the gate and not about a pass that never fires.
    medium.refuse(None);
    migrate_seal(&otp, &mut fs, &mut rng);
    assert!(
        try_read_slot(&otp, &mut fs, EF_OTP_SLOT1, &mut buf)
            .unwrap()
            .is_some()
    );
    assert!(!medium.live(rsk_fs::EF_HARDENED));
}

#[test]
fn the_boot_pass_re_arms_the_lap_before_it_seals_a_cleartext_slot() {
    // The other arm of the same pass, over a copy weaker still: the legacy record
    // holds this slot's AES key in the clear, and sealing it in place appends over
    // it. `run_at_rest_lap`'s caller gates the lap on the OTP key, so this does too.
    let otp_key = [0x55u8; 32];
    let otp = Device {
        serial_hash: &SERIAL_HASH,
        serial_id: &SERIAL,
        otp_key: Some(&otp_key),
    };
    let cfg = chalresp_config(&[0x0B; 20], &[0; 6], 0);
    let mut rng = CountRng(1);

    let (cut, medium) = Cut::new();
    let mut fs = Fs::new(cut);
    fs.scan();
    fs.put(EF_OTP_SLOT1, &cfg).unwrap(); // the legacy plaintext write
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    medium.clear_ops();
    migrate_seal(&otp, &mut fs, &mut rng);
    medium.assert_re_armed_before(EF_OTP_SLOT1, |_| false, "migrate_seal's plaintext arm");
    assert!(!fs.has_data(rsk_fs::EF_HARDENED));

    // The gate, and its control on the same unpoisoned medium.
    let (stuck, medium) = RemoveStuck::new();
    let mut fs = Fs::new(stuck);
    fs.scan();
    fs.put(EF_OTP_SLOT1, &cfg).unwrap();
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    medium.refuse(Some(rsk_fs::EF_HARDENED));
    migrate_seal(&otp, &mut fs, &mut rng);
    let mut stored = [0u8; seal::MAX_BLOB];
    assert_eq!(
        fs.read_key(KeyFid::new(EF_OTP_SLOT1), &mut stored),
        Some(CONFIG_SIZE),
        "the re-arm never landed, so the cleartext config must stay UNSUPERSEDED — \
         at the same cost: plaintext fails the GCM auth `try_read_slot` performs"
    );
    medium.refuse(None);
    migrate_seal(&otp, &mut fs, &mut rng);
    let n = fs
        .read_key(KeyFid::new(EF_OTP_SLOT1), &mut stored)
        .expect("fixture: the slot is still there");
    assert!(n > CONFIG_SIZE, "the healthy medium does seal it");
    assert!(!medium.live(rsk_fs::EF_HARDENED));
}

fn configure(
    app: &mut OtpApplet,
    fs: &mut Fs<RamStorage>,
    p1: u8,
    p2: u8,
    config: &[u8; CONFIG_SIZE],
    acc: &[u8; 6],
) -> (Sw, Vec<u8>) {
    let mut d = config.to_vec();
    d.extend_from_slice(acc);
    run(app, fs, &otp_apdu(p1, p2, &d))
}

#[test]
fn crc16_residual() {
    // Programming-frame self-check: a stored ~CRC makes the whole-record
    // CRC equal the X.25 residual.
    let c = build_config(b"fix", &[1; 6], &[2; 16], &[0; 6], 0, 0, 0);
    assert!(check_crc(&c));
    let mut bad = c;
    bad[0] ^= 1;
    assert!(!check_crc(&bad));
}

#[test]
fn button_types_nitrokey_slots_3_and_4() {
    // Slots 3/4 (three/four BOOTSEL clicks) type a ticket just like 1/2:
    // configure over CCID with the P2 slot offset (P1=0x01, P2=2/3 →
    // EF 0xBB02/0xBB03); a fifth slot is rejected.
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    // Plain Yubico-OTP slot (tkt = cfg = 0): types a 44-char modhex + bumps the
    // use counter, so this also covers per-slot counter persistence on slot 3/4.
    let cfg = build_config(&[0, 1, 2, 3, 4, 5], &[1; 6], &[2; 16], &[0; 6], 0, 0, 0);
    assert_eq!(
        configure(&mut app, &mut fs, 0x01, 2, &cfg, &[0; 6]).0,
        Sw::OK
    );
    assert_eq!(
        configure(&mut app, &mut fs, 0x01, 3, &cfg, &[0; 6]).0,
        Sw::OK
    );

    let mut out = [0u8; ticket::MAX_TICKET];
    assert!(app.button_ticket(3, 0, [0, 0], &mut fs, &mut out).is_some());
    assert!(app.button_ticket(4, 0, [0, 0], &mut fs, &mut out).is_some());
    // Out of range — there is no fifth slot.
    assert!(app.button_ticket(5, 0, [0, 0], &mut fs, &mut out).is_none());
    // And a 0x14 extended status now lists all four programmed slots.
    let (_, body) = run(&mut app, &mut fs, &otp_apdu(0x14, 0, &[]));
    assert_eq!(
        body.iter().filter(|&&b| (0xB0..0xB4).contains(&b)).count(),
        2
    );
}

#[test]
fn select_status_and_config_seq() {
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let (sw, body) = select(&mut app, &mut fs);
    assert_eq!(sw, Sw::OK);
    // Empty device: 6-byte YubiKey status — version 5.8.0, seq 0, no valid/touch.
    assert_eq!(body, [5, 8, 0, 0, 0, 0]);

    // Program slot 1 (HMAC chalresp, no touch): VALID without TOUCH.
    let cfgd = chalresp_config(&[0xAA; 20], &[0; 6], 0);
    let (sw, body) = configure(&mut app, &mut fs, 0x01, 0, &cfgd, &[0; 6]);
    assert_eq!(sw, Sw::OK);
    assert_eq!(&body[..4], &[5, 8, 0, 1]); // seq bumped
    assert_eq!(body[4], CONFIG1_VALID);

    // Re-SELECT: seq resets to 1 (slots present).
    let (_, body) = select(&mut app, &mut fs);
    assert_eq!(body[3], 1);

    // A typed (non-chalresp) slot 2 sets VALID + TOUCH.
    let typed = build_config(b"public", &[3; 6], &[4; 16], &[0; 6], 0, TKT_APPEND_CR, 0);
    let (_, body) = configure(&mut app, &mut fs, 0x03, 0, &typed, &[0; 6]);
    assert_eq!(body[4], CONFIG1_VALID | CONFIG2_VALID | CONFIG2_TOUCH);
}

#[test]
fn configure_validates_crc_and_rfu() {
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let mut bad = chalresp_config(&[1; 20], &[0; 6], 0);
    bad[10] ^= 0xFF; // breaks the CRC
    let (sw, _) = configure(&mut app, &mut fs, 0x01, 0, &bad, &[0; 6]);
    assert_eq!(sw, SW_WRONG_DATA);

    let mut bad = chalresp_config(&[1; 20], &[0; 6], 0);
    bad[OFF_RFU] = 1; // rfu must be zero (CRC recomputed to stay valid)
    let crc = !crc16(&bad[..CONFIG_SIZE - 2]);
    bad[CONFIG_SIZE - 2..].copy_from_slice(&crc.to_le_bytes());
    let (sw, _) = configure(&mut app, &mut fs, 0x01, 0, &bad, &[0; 6]);
    assert_eq!(sw, SW_WRONG_DATA);

    // Too-short body.
    let (sw, _) = run(&mut app, &mut fs, &otp_apdu(0x01, 0, &[0u8; 20]));
    assert_eq!(sw, Sw::WRONG_LENGTH);
    // Slot-2 configure with nonzero P2 is invalid.
    let good = chalresp_config(&[1; 20], &[0; 6], 0);
    let (sw, _) = configure(&mut app, &mut fs, 0x03, 1, &good, &[0; 6]);
    assert_eq!(sw, Sw::INCORRECT_P1P2);
}

#[test]
fn access_code_protects_reconfig_and_delete() {
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let acc = [1, 2, 3, 4, 5, 6];
    let cfgd = chalresp_config(&[0xBB; 20], &acc, 0);
    let (sw, _) = configure(&mut app, &mut fs, 0x01, 0, &cfgd, &[0; 6]);
    assert_eq!(sw, Sw::OK);

    // Overwrite without the access code fails…
    let newc = chalresp_config(&[0xCC; 20], &[0; 6], 0);
    let (sw, _) = configure(&mut app, &mut fs, 0x01, 0, &newc, &[0; 6]);
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    // …and succeeds with it.
    let (sw, _) = configure(&mut app, &mut fs, 0x01, 0, &newc, &acc);
    assert_eq!(sw, Sw::OK);

    // Delete = all-zero config (plus the current access code — now none).
    let (sw, body) = configure(&mut app, &mut fs, 0x01, 0, &[0; CONFIG_SIZE], &[0; 6]);
    assert_eq!(sw, Sw::OK);
    assert_eq!(body[4], 0); // no valid slots
}

#[test]
fn hmac_chalresp_full_64() {
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let key20 = [0x0B; 20];
    let cfgd = chalresp_config(&key20, &[0; 6], 0); // no HMAC_LT64: full 64 bytes
    configure(&mut app, &mut fs, 0x01, 0, &cfgd, &[0; 6]);

    let chal = [0x5A; 64];
    let (sw, body) = run(&mut app, &mut fs, &otp_apdu(0x30, 0, &chal));
    assert_eq!(sw, Sw::OK);
    // Key = AES field (16) + full UID (6); trailing UID zeros are absorbed
    // by HMAC key padding, so this equals the plain 20-byte-key HMAC.
    assert_eq!(body, hmac_sha1(&key20, &chal));
}

/// run-26: `CFG_CHAL_HMAC` is a two-bit mask (`CHAL_YUBICO | 0x02`) and was tested
/// for ANY bit. `ykman otp hotp --digits 8` sets `CFG_OATH_HOTP8` = 0x02, and
/// `TKT_OATH_HOTP` is the same bit as `TKT_CHAL_RESP`, so such a slot entered the
/// HMAC arm — and, carrying no `CFG_CHAL_BTN_TRIG`, answered with no press at all,
/// turning a button-gated HOTP seed into a free chosen-message MAC oracle.
#[test]
fn oath_hotp_slot_is_not_a_challenge_response_oracle() {
    let mut fs = new_fs();
    // Panics if presence is ever requested: proves the absence of a touch request
    // is not what makes this pass.
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);

    // Exactly what `ykman otp hotp --digits 8` programs: OATH-HOTP ticket flags,
    // cfgFlags carrying only the 8-digit bit — no CHAL_YUBICO, no BTN_TRIG.
    let key20 = [0x0B; 20];
    let mut uid = [0u8; 6];
    uid[..4].copy_from_slice(&key20[16..]);
    let mut aes = [0u8; 16];
    aes.copy_from_slice(&key20[..16]);
    let cfgd = build_config(&[], &uid, &aes, &[0; 6], 0, TKT_OATH_HOTP, CFG_OATH_HOTP8);
    let (sw, body) = configure(&mut app, &mut fs, 0x01, 0, &cfgd, &[0; 6]);
    assert_eq!(sw, Sw::OK);
    // The slot really is programmed — otherwise the rejections below would pass
    // for the wrong reason — and ykman sees it as a touch slot, because it types
    // its code on a press rather than answering the host.
    assert_eq!(body[4], CONFIG1_VALID | CONFIG1_TOUCH);

    // Neither challenge-response function may serve it.
    let chal = [0x5A; 64];
    let (sw, _) = run(&mut app, &mut fs, &otp_apdu(0x30, 0, &chal)); // HMAC
    assert_eq!(sw, SW_WRONG_DATA, "HMAC arm must reject an OATH-HOTP slot");
    let (sw, _) = run(&mut app, &mut fs, &otp_apdu(0x20, 0, &chal)); // Yubico
    assert_eq!(
        sw, SW_WRONG_DATA,
        "Yubico arm must reject an OATH-HOTP slot"
    );

    // A real HMAC chal-resp slot (both mask bits) still works.
    let cfgd = chalresp_config(&key20, &[0; 6], 0);
    configure(&mut app, &mut fs, 0x03, 0, &cfgd, &[0; 6]);
    let (sw, body) = run(&mut app, &mut fs, &otp_apdu(0x38, 0, &chal));
    assert_eq!(sw, Sw::OK);
    assert_eq!(body, hmac_sha1(&key20, &chal));
}

#[test]
fn hmac_chalresp_lt64_trims_padding() {
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let key20 = [0x0B; 20];
    let cfgd = chalresp_config(&key20, &[0; 6], CFG_HMAC_LT64);
    configure(&mut app, &mut fs, 0x01, 0, &cfgd, &[0; 6]);

    // KeePassXC-style: short challenge padded by repeating the last byte.
    let mut chal = [0x01u8; 64];
    chal[..9].copy_from_slice(b"challenge");
    let (sw, body) = run(&mut app, &mut fs, &otp_apdu(0x30, 0, &chal));
    assert_eq!(sw, Sw::OK);
    assert_eq!(body, hmac_sha1(&key20, b"challenge"));

    // The classic trim quirk: a challenge ending in the pad byte loses its
    // own tail ("Hi There" + 'e' padding → "Hi Ther").
    let mut chal = [b'e'; 64];
    chal[..8].copy_from_slice(b"Hi There");
    let (_, body) = run(&mut app, &mut fs, &otp_apdu(0x30, 0, &chal));
    assert_eq!(body, hmac_sha1(&key20, b"Hi Ther"));
    // RFC 2202 case 1 pins the PRF itself for the trimmed message.
    assert_ne!(body, hmac_sha1(&key20, b"Hi There"));
}

#[test]
fn yubico_chalresp_mixes_serial() {
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let aes_key = [0x42; 16];
    let cfgd = build_config(
        &[],
        &[0; 6],
        &aes_key,
        &[0; 6],
        0,
        TKT_CHAL_RESP,
        CFG_CHAL_YUBICO,
    );
    configure(&mut app, &mut fs, 0x01, 0, &cfgd, &[0; 6]);

    let chal6 = [9, 8, 7, 6, 5, 4];
    let (sw, body) = run(&mut app, &mut fs, &otp_apdu(0x20, 0, &chal6));
    assert_eq!(sw, Sw::OK);
    let mut expect = [0u8; 16];
    expect[..6].copy_from_slice(&chal6);
    expect[6..].copy_from_slice(b"123456789A"); // serial_str10 of SERIAL
    aes128_encrypt_block(&aes_key, &mut expect);
    assert_eq!(body, expect);
}

#[test]
fn calculate_rejections_and_empty_slot() {
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    // Empty slot: bare OK, no body.
    let (sw, body) = run(&mut app, &mut fs, &otp_apdu(0x30, 0, &[0; 64]));
    assert_eq!((sw, body.len()), (Sw::OK, 0));

    // Non-chalresp slot rejects calculation.
    let typed = build_config(b"public", &[3; 6], &[4; 16], &[0; 6], 0, TKT_APPEND_CR, 0);
    configure(&mut app, &mut fs, 0x01, 0, &typed, &[0; 6]);
    let (sw, _) = run(&mut app, &mut fs, &otp_apdu(0x30, 0, &[0; 64]));
    assert_eq!(sw, SW_WRONG_DATA);

    // Short challenge bodies are length errors, not buffer overreads.
    let cfgd = chalresp_config(&[1; 20], &[0; 6], 0);
    configure(&mut app, &mut fs, 0x03, 0, &cfgd, &[0; 6]);
    let (sw, _) = run(&mut app, &mut fs, &otp_apdu(0x38, 0, &[0; 32]));
    assert_eq!(sw, Sw::WRONG_LENGTH);
    // Slot-2 variants demand P2 = 0.
    let (sw, _) = run(&mut app, &mut fs, &otp_apdu(0x38, 1, &[0; 64]));
    assert_eq!(sw, Sw::INCORRECT_P1P2);
    // Unknown INS / CLA.
    let (sw, _) = run(&mut app, &mut fs, &[0x00, 0x02, 0, 0]);
    assert_eq!(sw, Sw::INS_NOT_SUPPORTED);
    let (sw, _) = run(&mut app, &mut fs, &[0x80, 0x01, 0x10, 0]);
    assert_eq!(sw, Sw::CLA_NOT_SUPPORTED);
    // Unknown P1 answers a bare OK.
    let (sw, body) = run(&mut app, &mut fs, &otp_apdu(0x77, 0, &[]));
    assert_eq!((sw, body.len()), (Sw::OK, 0));
}

#[test]
fn touch_gated_chalresp_respects_presence() {
    let mut fs = new_fs();
    let presence = RefCell::new(TestPresence(Presence::Declined));
    let presence_dyn: &RefCell<dyn UserPresence> = &presence;
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, presence_dyn);
    let cfgd = chalresp_config(&[7; 20], &[0; 6], CFG_CHAL_BTN_TRIG);
    configure(&mut app, &mut fs, 0x01, 0, &cfgd, &[0; 6]);

    let (sw, _) = run(&mut app, &mut fs, &otp_apdu(0x30, 0, &[0; 64]));
    assert_eq!(sw, Sw::CONDITIONS_NOT_SATISFIED);
    presence.borrow_mut().0 = Presence::Confirmed;
    let (sw, body) = run(&mut app, &mut fs, &otp_apdu(0x30, 0, &[0; 64]));
    assert_eq!(sw, Sw::OK);
    assert_eq!(body.len(), 20);
}

#[test]
fn update_merges_flag_masks_only() {
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    // A typed Yubico-OTP slot (not chal-resp) with APPEND_CR.
    let orig = build_config(b"public", &[3; 6], &[4; 16], &[0; 6], 0, TKT_APPEND_CR, 0);
    configure(&mut app, &mut fs, 0x01, 0, &orig, &[0; 6]);

    // Update with different key material + flags: only the masked tkt/cfg
    // bits may change; the key/fixed/uid stay.
    let upd = build_config(
        b"other!", &[9; 6], &[9; 16], &[0; 6], 0, 0x02, /* APPEND_TAB1 */
        0xFF,
    );
    let mut d = upd.to_vec();
    d.extend_from_slice(&[0; 6]);
    let (sw, _) = run(&mut app, &mut fs, &otp_apdu(0x04, 0, &d));
    assert_eq!(sw, Sw::OK);

    // status-ext shows the merged flags and the ORIGINAL fixed part.
    let (_, body) = run(&mut app, &mut fs, &otp_apdu(0x14, 0, &[]));
    // [0xB0, len, 0xA0, 2, tkt, cfg, 0xC0, 6, fixed6...]
    assert_eq!(body[0], 0xB0);
    assert_eq!(body[4], 0x02); // tkt: only the update-mask bit survived
    assert_eq!(body[5], 0x0C); // cfg: only PACING bits taken from 0xFF
    assert_eq!(&body[8..14], b"public");

    // Update on an empty slot stores nothing but still returns status.
    let (sw, body) = run(&mut app, &mut fs, &otp_apdu(0x05, 0, &d));
    assert_eq!(sw, Sw::OK);
    assert_eq!(body[4] & CONFIG2_VALID, 0);
}

#[test]
fn update_validates_slot_bounds_crc_and_rfu() {
    // `configure_validates_crc_and_rfu` pins these rules on the CONFIGURE path.
    // UPDATE repeats every one of them — slot bound, length floor, both RFU
    // bytes, the CRC — and had none of them: seven mutations of that validation
    // survived the suite (the reverse pass, D2). The third time this session
    // that a rule was already tested one door over.
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let good = build_config(b"public", &[3; 6], &[4; 16], &[0; 6], 0, TKT_APPEND_CR, 0);
    let with_acc = |c: &[u8; CONFIG_SIZE]| {
        let mut d = c.to_vec();
        d.extend_from_slice(&[0; 6]);
        d
    };

    // Past the last slot, and exactly at it: the bound is `>`, not `>=`.
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &otp_apdu(0x04, SLOT_COUNT as u8, &with_acc(&good)),
    );
    assert_eq!(sw, Sw::INCORRECT_P1P2, "one past the last slot");
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &otp_apdu(0x04, SLOT_COUNT as u8 - 1, &with_acc(&good)),
    );
    assert_ne!(sw, Sw::INCORRECT_P1P2, "the last slot is addressable");

    // The length floor is `<`: exactly CONFIG_SIZE is enough.
    let (sw, _) = run(&mut app, &mut fs, &otp_apdu(0x04, 0, &[0u8; 20]));
    assert_eq!(sw, Sw::WRONG_LENGTH, "a body under CONFIG_SIZE");
    let (sw, _) = run(&mut app, &mut fs, &otp_apdu(0x04, 0, &good[..]));
    assert_ne!(sw, Sw::WRONG_LENGTH, "exactly CONFIG_SIZE is a body");

    // Each RFU byte alone, and the CRC alone, must refuse.
    for (label, idx) in [("first", OFF_RFU), ("second", OFF_RFU + 1)] {
        let mut bad = good;
        bad[idx] = 1;
        let crc = !crc16(&bad[..CONFIG_SIZE - 2]);
        bad[CONFIG_SIZE - 2..].copy_from_slice(&crc.to_le_bytes());
        let (sw, _) = run(&mut app, &mut fs, &otp_apdu(0x04, 0, &with_acc(&bad)));
        assert_eq!(sw, SW_WRONG_DATA, "{label} RFU byte set");
    }
    let mut bad = good;
    bad[10] ^= 0xFF;
    let (sw, _) = run(&mut app, &mut fs, &otp_apdu(0x04, 0, &with_acc(&bad)));
    assert_eq!(sw, SW_WRONG_DATA, "a broken CRC");

    // And the slot the update lands on is `base + p2`: configure slot 1, update
    // slot 1, and the merged flags must appear there.
    configure(&mut app, &mut fs, 0x01, 1, &good, &[0; 6]);
    let upd = build_config(b"public", &[3; 6], &[4; 16], &[0; 6], 0, 0x02, 0);
    let (sw, _) = run(&mut app, &mut fs, &otp_apdu(0x04, 1, &with_acc(&upd)));
    assert_eq!(sw, Sw::OK);
    let mut stored = [0u8; SLOT_SIZE];
    app.read_slot_m(&mut fs, EF_OTP_SLOT1 + 1, &mut stored)
        .expect("the update must land on the slot its P2 names");
    assert_eq!(stored[OFF_TKT_FLAGS], 0x02);
}

#[test]
fn only_a_slot_that_is_both_chal_resp_and_yubico_stays_silent_on_a_press() {
    // `cfg & CFG_CHAL_YUBICO != 0 && tkt & TKT_CHAL_RESP != 0` is what decides
    // that a challenge-response slot types nothing when the button is pressed.
    // Relaxed to `||` it silences a slot that has only one of the two bits — a
    // press that should have typed an OTP produces nothing. Nothing tested the
    // conjunction (the reverse pass, D2), because no slot carried one bit alone.
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let mut out = [0u8; 64];

    // One bit each, on two slots: both must still type.
    let yubico_only = build_config(b"public", &[3; 6], &[4; 16], &[0; 6], 0, 0, CFG_CHAL_YUBICO);
    configure(&mut app, &mut fs, 0x01, 0, &yubico_only, &[0; 6]);
    assert!(
        app.button_ticket(1, 0, [0, 0], &mut fs, &mut out).is_some(),
        "a slot with the Yubico bit but no chal-resp bit must still type"
    );

    let cr_only = build_config(b"public", &[3; 6], &[4; 16], &[0; 6], 0, TKT_CHAL_RESP, 0);
    configure(&mut app, &mut fs, 0x03, 0, &cr_only, &[0; 6]);
    assert!(
        app.button_ticket(2, 0, [0, 0], &mut fs, &mut out).is_some(),
        "a slot with the chal-resp bit but no Yubico bit must still type"
    );
}

#[test]
fn update_replaces_the_whole_ext_flag_byte() {
    // `EXTFLAG_UPDATE_MASK` is 0xFF — every extended-flag bit is updateable, so
    // an UPDATE REPLACES the byte rather than merging into it. The tkt and cfg
    // halves of that merge are pinned by `update_merges_flag_masks_only`
    // through `status-ext`, which carries no ext byte; this half was observable
    // nowhere and both of its mutations survived (the reverse pass, D2).
    // Read the stored record directly, the way the applet does.
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let orig = build_config(
        b"public",
        &[3; 6],
        &[4; 16],
        &[0; 6],
        0xA5,
        TKT_APPEND_CR,
        0,
    );
    configure(&mut app, &mut fs, 0x01, 0, &orig, &[0; 6]);

    let upd = build_config(
        b"other!",
        &[9; 6],
        &[9; 16],
        &[0; 6],
        0x5A,
        TKT_APPEND_CR,
        0,
    );
    let mut d = upd.to_vec();
    d.extend_from_slice(&[0; 6]);
    let (sw, _) = run(&mut app, &mut fs, &otp_apdu(0x04, 0, &d));
    assert_eq!(sw, Sw::OK);

    let mut stored = [0u8; SLOT_SIZE];
    app.read_slot_m(&mut fs, EF_OTP_SLOT1, &mut stored)
        .expect("the slot is configured");
    assert_eq!(
        stored[OFF_EXT_FLAGS], 0x5A,
        "every ext bit is updateable, so the update's byte must stand alone — \
         not ORed with what was there, and not masked to nothing"
    );
    // The neighbours the same merge must NOT have touched.
    assert_eq!(&stored[..OFF_ACC_CODE.min(6)], b"public");
}

#[test]
fn update_preserves_use_counter_tail() {
    // audit run-30: SLOT_UPDATE built a 52-byte (CONFIG_SIZE) record, dropping the
    // 8-byte tail — so the Yubico-OTP use counter / HOTP moving factor silently
    // rolled back on the next read, re-emitting already-consumed OTPs. The update
    // must carry the tail forward; only a full CONFIGURE resets it.
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let dev = Device {
        serial_hash: &SERIAL_HASH,
        serial_id: &SERIAL,
        otp_key: None,
    };
    let mut bump_rng = CountRng(9);

    // A plain Yubico-OTP typed slot (tkt = cfg = 0) — the kind power_up_bump advances.
    let cfg = build_config(b"public", &[1; 6], &[2; 16], &[0; 6], 0, 0, 0);
    assert_eq!(
        configure(&mut app, &mut fs, 0x01, 0, &cfg, &[0; 6]).0,
        Sw::OK
    );

    // Advance the use counter across three "power cycles".
    for _ in 0..3 {
        power_up_bump(&dev, &mut fs, &mut bump_rng);
    }
    let mut buf = [0u8; SLOT_SIZE];
    let n = try_read_slot(&dev, &mut fs, EF_OTP_SLOT1, &mut buf)
        .unwrap()
        .unwrap();
    assert_eq!(n, SLOT_SIZE);
    let before = u16::from_be_bytes([buf[CONFIG_SIZE], buf[CONFIG_SIZE + 1]]);
    assert_eq!(before, 3);

    // A routine SLOT_UPDATE (e.g. changing pacing bits) must not touch the counter.
    let upd = build_config(b"public", &[1; 6], &[2; 16], &[0; 6], 0, 0, 0xFF);
    let mut d = upd.to_vec();
    d.extend_from_slice(&[0; 6]);
    assert_eq!(run(&mut app, &mut fs, &otp_apdu(0x04, 0, &d)).0, Sw::OK);

    let n = try_read_slot(&dev, &mut fs, EF_OTP_SLOT1, &mut buf)
        .unwrap()
        .unwrap();
    assert_eq!(n, SLOT_SIZE, "update truncated the slot record");
    let after = u16::from_be_bytes([buf[CONFIG_SIZE], buf[CONFIG_SIZE + 1]]);
    assert_eq!(after, before, "update rolled the use counter back");
}

#[test]
fn swap_moves_configs_between_slots() {
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let key20 = [0x33; 20];
    let cfgd = chalresp_config(&key20, &[0; 6], 0);
    configure(&mut app, &mut fs, 0x01, 0, &cfgd, &[0; 6]);

    let (sw, body) = run(&mut app, &mut fs, &otp_apdu(0x06, 0, &[]));
    assert_eq!(sw, Sw::OK);
    assert_eq!(body[4], CONFIG2_VALID); // moved 1 → 2

    // The moved slot still calculates (now via the slot-2 variant).
    let chal = [0x11; 64];
    let (_, resp) = run(&mut app, &mut fs, &otp_apdu(0x38, 0, &chal));
    assert_eq!(resp, hmac_sha1(&key20, &chal));

    // Swap back with an explicit pair body — the offsets are relative to
    // slot 1 resp. slot 2, so [0, 0] is the plain 1↔2 swap.
    let (sw, body) = run(&mut app, &mut fs, &otp_apdu(0x06, 0, &[0, 0]));
    assert_eq!(sw, Sw::OK);
    assert_eq!(body[4], CONFIG1_VALID);
    let (sw, _) = run(&mut app, &mut fs, &otp_apdu(0x06, 0, &[0, 1, 2]));
    assert_eq!(sw, Sw::WRONG_LENGTH);
}

#[test]
fn swap_accepts_bare_ykman_access_code_frame() {
    // ykman/yubikit send `otp swap` as a BARE 6-byte access code (no slot-offset
    // bytes). RS-Key rejected that nc=6 frame as WRONG_LENGTH, so the host saw
    // "Failed to write". It must now swap slots 1<->2 and honour the code.
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let key20 = [0x44; 20];
    configure(
        &mut app,
        &mut fs,
        0x01,
        0,
        &chalresp_config(&key20, &[0; 6], 0),
        &[0; 6],
    );

    // The exact yubikit frame: a bare all-zero 6-byte code, no offsets.
    let (sw, body) = run(&mut app, &mut fs, &otp_apdu(0x06, 0, &[0u8; 6]));
    assert_eq!(sw, Sw::OK);
    assert_eq!(body[4], CONFIG2_VALID); // moved slot 1 -> slot 2
    let chal = [0x11; 64];
    let (_, resp) = run(&mut app, &mut fs, &otp_apdu(0x38, 0, &chal));
    assert_eq!(resp, hmac_sha1(&key20, &chal)); // the config genuinely moved
}

#[test]
fn swap_bare_code_is_matched_not_ignored() {
    // The bare-6-byte path still gates a protected slot (not a blanket accept):
    // a wrong code is refused, the exact code allows the swap.
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let acc = [9, 8, 7, 6, 5, 4];
    configure(
        &mut app,
        &mut fs,
        0x01,
        0,
        &chalresp_config(&[0x55; 20], &acc, 0),
        &[0; 6],
    );
    assert_eq!(
        run(&mut app, &mut fs, &otp_apdu(0x06, 0, &[1u8; 6])).0,
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(run(&mut app, &mut fs, &otp_apdu(0x06, 0, &acc)).0, Sw::OK);
}

#[test]
fn swap_refuses_protected_slot_without_access_code() {
    // run-5 (HIGH): SLOT_SWAP used to move/delete an access-code-protected slot
    // with no code — unlike configure/update — so an unauthenticated host could
    // silently break a protected chal-resp credential (and an out-of-range
    // offset orphaned it outside the addressable 1..=4 range). It must now
    // refuse without the matching code, and reject the out-of-range offset.
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let acc = [1, 2, 3, 4, 5, 6];
    let cfgd = chalresp_config(&[0x33; 20], &acc, 0);
    assert_eq!(
        configure(&mut app, &mut fs, 0x01, 0, &cfgd, &[0; 6]).0,
        Sw::OK
    );

    // Plain swap with no code is refused now that slot 1 is protected…
    let (sw, _) = run(&mut app, &mut fs, &otp_apdu(0x06, 0, &[]));
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    // …a wrong code is refused…
    let (sw, _) = run(
        &mut app,
        &mut fs,
        &otp_apdu(0x06, 0, &[0, 0, 9, 9, 9, 9, 9, 9]),
    );
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    // …and an out-of-range offset can no longer orphan the slot.
    let (sw, _) = run(&mut app, &mut fs, &otp_apdu(0x06, 0, &[0, 5]));
    assert_eq!(sw, Sw::INCORRECT_P1P2);
    // The credential is untouched: slot 1 still challenge-responds.
    let chal = [0x11; 64];
    let (sw, resp) = run(&mut app, &mut fs, &otp_apdu(0x30, 0, &chal));
    assert_eq!(sw, Sw::OK);
    assert_eq!(resp, hmac_sha1(&[0x33; 20], &chal));

    // With the correct code the swap succeeds (moves slot 1 → slot 2).
    let mut body = [0u8; 2 + ACC_CODE_SIZE];
    body[2..].copy_from_slice(&acc);
    let (sw, st) = run(&mut app, &mut fs, &otp_apdu(0x06, 0, &body));
    assert_eq!(sw, Sw::OK);
    assert_eq!(st[4], CONFIG2_VALID);
}

#[test]
fn serial_and_config_passthrough() {
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let (sw, body) = run(&mut app, &mut fs, &otp_apdu(0x10, 0, &[]));
    assert_eq!(sw, Sw::OK);
    // serial4: first 4 chip-id bytes, top 6 bits cleared (0x12 → 0x02).
    assert_eq!(body, [0x02, 0x34, 0x56, 0x78]);

    // GET CONFIG returns the management TLV (leading overall-length byte).
    let (sw, body) = run(&mut app, &mut fs, &otp_apdu(0x13, 0, &[]));
    assert_eq!(sw, Sw::OK);
    assert_eq!(body[0] as usize, body.len() - 1);
}

/// The DeviceInfo read ykman falls back to when CCID is unavailable
/// (`yubikit._ManagementOtpBackend.read_config` → slot 0x13), end to end
/// over the frame protocol: host frame in via [`hid::FrameRx`], dispatch
/// via `process_hid`, response out via [`hid::FrameTx`], validated exactly
/// as the host does (length byte + X.25 CRC residual).
#[test]
fn hid_frame_device_info_read() {
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);

    // read_config(page=0) sends a single zero page byte (already zero).
    let payload = [0u8; hid::PAYLOAD_SIZE];
    let reports = hid::split_frame(&payload, 0x13);
    let mut rx = hid::FrameRx::new();
    let mut frame = None;
    for r in &reports {
        if let hid::RxOutcome::Frame { slot, payload } = rx.feed(r) {
            frame = Some((slot, payload));
        }
    }
    let (slot, payload) = frame.expect("frame did not reassemble");
    assert_eq!(slot, 0x13);

    let mut out = [0u8; 64];
    let mut res = ResBuf::new(&mut out);
    let sw = app.process_hid(slot, &payload, &mut fs, &mut res);
    assert_eq!(sw, Sw::OK);
    let body = res.as_slice().to_vec();
    assert!(!body.is_empty(), "a read command must stream a body");

    // Drain the response reports the way `yubikit._read_frame` does.
    let mut tx = hid::FrameTx::new();
    tx.load(&body);
    let mut resp = Vec::new();
    let mut rep = [0u8; hid::REPORT_SIZE];
    let mut seq = 0u8;
    while tx.next(&mut rep) {
        let flag = rep[hid::REPORT_DATA];
        assert_ne!(flag & 0x40, 0, "response report must set RESP_PENDING");
        if flag & 0x1F == seq {
            resp.extend_from_slice(&rep[..hid::REPORT_DATA]);
            seq += 1;
        } else {
            assert_eq!(flag & 0x1F, 0, "sequence break that is not the end marker");
            break;
        }
    }
    // yubikit read_config: r_len = response[0]; check_crc(response[:r_len+3]).
    let r_len = resp[0] as usize;
    assert_eq!(r_len, body.len() - 1);
    assert_eq!(crc16(&resp[..r_len + 3]), 0xF0B8);
    assert_eq!(&resp[..r_len + 1], &body[..]);
}

/// Unhandled frame slots (0x11/0x12) and an empty-bodied SET_DEVICE_INFO (0x15)
/// answer OK with no body — the firmware glue then serves the idle status frame,
/// which yubikit turns into a clean CommandRejectedError("No data") instead of
/// blocking in `_read_frame`. (0x15's real DeviceConfig write is covered below.)
#[test]
fn hid_frame_unknown_command_answers_empty() {
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    for slot in [0x11u8, 0x12, 0x15] {
        let payload = [0u8; hid::PAYLOAD_SIZE];
        let mut out = [0u8; 64];
        let mut res = ResBuf::new(&mut out);
        let sw = app.process_hid(slot, &payload, &mut fs, &mut res);
        assert_eq!(sw, Sw::OK);
        assert!(
            res.as_slice().is_empty(),
            "slot {slot:#x} must not stream a body"
        );
    }
}

#[cfg(not(feature = "strict-config"))]
#[test]
fn hid_frame_set_device_info_round_trips_to_config() {
    // DEFAULT: SET_DEVICE_INFO (0x15) persists the DeviceConfig, and a later GET
    // CONFIG (0x13) echoes the written USB_ENABLED (0x0202 ⊆ SUPPORTED_CAPS) —
    // full ykman parity, the same EF_DEV_CONF the CCID WRITE CONFIG path uses.
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    // DeviceConfig.get_bytes(): [inner_len=4][TAG_USB_ENABLED=0x03, len=0x02, 0x0202].
    let mut payload = [0u8; hid::PAYLOAD_SIZE];
    payload[..5].copy_from_slice(&[0x04, 0x03, 0x02, 0x02, 0x02]);
    let mut out = [0u8; 64];
    let mut res = ResBuf::new(&mut out);
    assert_eq!(app.process_hid(0x15, &payload, &mut fs, &mut res), Sw::OK);
    assert!(res.as_slice().is_empty(), "a write streams no body");

    let mut out2 = [0u8; 256];
    let mut res2 = ResBuf::new(&mut out2);
    assert_eq!(
        app.process_hid(0x13, &[0u8; hid::PAYLOAD_SIZE], &mut fs, &mut res2),
        Sw::OK
    );
    assert!(
        res2.as_slice()
            .windows(4)
            .any(|w| w == [0x03, 0x02, 0x02, 0x02]),
        "0x13 GET CONFIG must echo the persisted USB_ENABLED"
    );
}

#[cfg(not(feature = "strict-config"))]
#[test]
fn hid_frame_set_device_info_bumps_program_sequence() {
    // ykman/yubikit confirm an OTP-transport config write by the program-sequence
    // byte in the status frame advancing (`_is_sequence_updated`), not by a response
    // body. Before the fix `ykman config usb` failed with CommandRejectedError("No
    // data") because SET_DEVICE_INFO left the sequence unchanged. A real (non-empty)
    // write must advance it exactly like a slot configure.
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let seq_before = app.hid_status_frame(&mut fs)[4];

    // DeviceConfig.get_bytes() for `config usb --disable PIV`: [len=4][03 02 02 2B].
    let mut payload = [0u8; hid::PAYLOAD_SIZE];
    payload[..5].copy_from_slice(&[0x04, 0x03, 0x02, 0x02, 0x2B]);
    let mut out = [0u8; 64];
    let mut res = ResBuf::new(&mut out);
    assert_eq!(app.process_hid(0x15, &payload, &mut fs, &mut res), Sw::OK);
    assert_eq!(
        app.hid_status_frame(&mut fs)[4],
        seq_before.wrapping_add(1),
        "SET_DEVICE_INFO must advance pgmSeq so ykman sees the write"
    );

    // An empty (no-op) write must NOT bump — yubikit's benign "No data" is correct
    // there, and a spurious bump would report a phantom config change.
    let seq_after = app.hid_status_frame(&mut fs)[4];
    let mut r2 = ResBuf::new(&mut out);
    assert_eq!(
        app.process_hid(0x15, &[0u8; hid::PAYLOAD_SIZE], &mut fs, &mut r2),
        Sw::OK
    );
    assert_eq!(
        app.hid_status_frame(&mut fs)[4],
        seq_after,
        "empty write is a no-op"
    );
}

#[cfg(feature = "strict-config")]
#[test]
fn hid_frame_set_device_info_ignored_under_strict() {
    // strict-config: a real SET_DEVICE_INFO (0x15) is swallowed (silent OK, no
    // body) and persists nothing — a hostile host cannot rewrite DeviceInfo over
    // the OTP keyboard transport.
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let mut before = [0u8; 256];
    let mut rb = ResBuf::new(&mut before);
    app.process_hid(0x13, &[0u8; hid::PAYLOAD_SIZE], &mut fs, &mut rb);
    let before = rb.as_slice().to_vec();

    let mut payload = [0u8; hid::PAYLOAD_SIZE];
    payload[..5].copy_from_slice(&[0x04, 0x03, 0x02, 0x02, 0x02]);
    let mut out = [0u8; 64];
    let mut res = ResBuf::new(&mut out);
    assert_eq!(app.process_hid(0x15, &payload, &mut fs, &mut res), Sw::OK);
    assert!(res.as_slice().is_empty());

    let mut after = [0u8; 256];
    let mut ra = ResBuf::new(&mut after);
    app.process_hid(0x13, &[0u8; hid::PAYLOAD_SIZE], &mut fs, &mut ra);
    assert_eq!(
        before,
        ra.as_slice(),
        "strict-config must not persist a 0x15 write"
    );
}

#[test]
fn configure_seals_secret_at_rest() {
    // A fresh configure must never leave the 16-byte AES key readable in
    // flash — it goes through the seal chokepoint, not a raw fs.put.
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let aes_key = [0x42; 16];
    let cfgd = build_config(
        &[],
        &[0; 6],
        &aes_key,
        &[0; 6],
        0,
        TKT_CHAL_RESP,
        CFG_CHAL_YUBICO,
    );
    configure(&mut app, &mut fs, 0x01, 0, &cfgd, &[0; 6]);

    let mut raw = [0u8; seal::MAX_BLOB];
    let n = fs.read_key(KeyFid::new(EF_OTP_SLOT1), &mut raw).unwrap();
    assert!(
        !raw[..n].windows(16).any(|w| w == aes_key),
        "AES slot key stored in plaintext at rest"
    );
}

#[test]
fn legacy_plaintext_slot_migrates_and_stays_usable() {
    // A pre-seal device stored the 52-byte config in the clear via fs.put.
    // migrate_seal re-seals it (so a flash dump no longer yields the AES /
    // HMAC secret) while chalresp keeps working, and is idempotent.
    let mut fs = new_fs();
    let key20 = [0x0B; 20];
    let cfg = chalresp_config(&key20, &[0; 6], 0);
    let fid = EF_OTP_SLOT1;
    fs.put(fid, &cfg).unwrap(); // legacy plaintext write

    let dev = Device {
        serial_hash: &SERIAL_HASH,
        serial_id: &SERIAL,
        otp_key: None,
    };
    let mut mrng = CountRng(1);
    migrate_seal(&dev, &mut fs, &mut mrng);

    // The stored bytes are now a sealed blob, not the config.
    let mut stored = [0u8; seal::MAX_BLOB];
    let n = fs.read_key(KeyFid::new(fid), &mut stored).unwrap();
    assert!(
        n > CONFIG_SIZE,
        "sealed blob must be longer than the config"
    );
    assert_ne!(
        &stored[..CONFIG_SIZE],
        &cfg[..],
        "config must not remain in the clear"
    );

    // The migrated slot still answers chalresp with the right MAC.
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let chal = [0x5A; 64];
    let (sw, body) = run(&mut app, &mut fs, &otp_apdu(0x30, 0, &chal));
    assert_eq!(sw, Sw::OK);
    assert_eq!(body, hmac_sha1(&key20, &chal));

    // Idempotent: a second pass leaves the sealed slot untouched.
    migrate_seal(&dev, &mut fs, &mut mrng);
    let (sw2, body2) = run(&mut app, &mut fs, &otp_apdu(0x30, 0, &chal));
    assert_eq!((sw2, body2), (Sw::OK, body));
}

#[cfg(not(feature = "strict-config"))]
#[test]
fn scanmap_scancode_maps_the_yubico_set_in_order() {
    // The yubikit DEFAULT_SCAN_MAP: 45 raw HID scancodes for the 45-char set, in
    // scan-map order (modhex lc, modhex uc with 0x80=shift, digits, ! \t \r).
    let default_map: [u8; 45] = [
        0x06, 0x05, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x11, 0x15, 0x17, 0x18,
        0x19, 0x86, 0x85, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x91, 0x95, 0x97,
        0x98, 0x99, 0x27, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x9e, 0x2b, 0x28,
    ];
    assert_eq!(scanmap_scancode(&default_map, b'c'), Some(0x06)); // index 0
    assert_eq!(scanmap_scancode(&default_map, b'v'), Some(0x19)); // index 15
    assert_eq!(scanmap_scancode(&default_map, b'C'), Some(0x86)); // index 16 (shift)
    assert_eq!(scanmap_scancode(&default_map, b'9'), Some(0x26)); // index 41
    assert_eq!(scanmap_scancode(&default_map, b'!'), Some(0x9e)); // index 42
    // Chars outside the covered set keep the ASCII path.
    assert_eq!(scanmap_scancode(&default_map, b'z'), None);
    assert_eq!(scanmap_scancode(&default_map, b'@'), None);
    // A short map is rejected (never partially remaps).
    assert_eq!(scanmap_scancode(&[0u8; 10], b'c'), None);
}

#[cfg(not(feature = "strict-config"))]
#[test]
fn scan_map_remaps_typed_button_ticket_output() {
    // DEFAULT: with a stored custom scan map, a typed OTP ticket comes out as RAW
    // scancodes (encode=false), every in-set char remapped through the table.
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    // A plain Yubico-OTP slot 1: types 44 modhex chars, all in the covered set.
    let cfg = build_config(&[0, 1, 2, 3, 4, 5], &[1; 6], &[2; 16], &[0; 6], 0, 0, 0);
    assert_eq!(
        configure(&mut app, &mut fs, 0x01, 0, &cfg, &[0; 6]).0,
        Sw::OK
    );

    // No scan map yet → ASCII-encoded output.
    let mut out = [0u8; ticket::MAX_TICKET];
    let (_, enc) = app.button_ticket(1, 0, [0, 0], &mut fs, &mut out).unwrap();
    assert!(enc, "no scan map → ASCII path");

    // Store a distinctive all-0x40 scan map via SLOT_SCAN_MAP (0x12).
    let mut payload = [0u8; hid::PAYLOAD_SIZE];
    payload[..45].fill(0x40);
    let mut o = [0u8; 64];
    let mut res = ResBuf::new(&mut o);
    assert_eq!(app.process_hid(0x12, &payload, &mut fs, &mut res), Sw::OK);

    // Now the ticket is raw scancodes, every byte remapped to 0x40.
    let (n, enc) = app.button_ticket(1, 0, [0, 0], &mut fs, &mut out).unwrap();
    assert!(!enc, "custom scan map → raw scancodes");
    assert!(
        n > 0 && out[..n].iter().all(|&b| b == 0x40),
        "every modhex char must be remapped through the scan map"
    );
}

#[cfg(not(feature = "strict-config"))]
#[test]
fn ndef_and_device_config_accept_and_store() {
    // DEFAULT: NDEF (0x08/0x09) and DEVICE_CONFIG (0x11) accept+store (inert on
    // USB-only HW) — the ykman calls succeed with an empty body and the records
    // persist to their FIDs.
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let mut payload = [0u8; hid::PAYLOAD_SIZE];
    payload[..3].copy_from_slice(&[0xAB, 0xCD, 0xEF]);
    for slot in [0x08u8, 0x09, 0x11] {
        let mut o = [0u8; 64];
        let mut res = ResBuf::new(&mut o);
        assert_eq!(app.process_hid(slot, &payload, &mut fs, &mut res), Sw::OK);
        assert!(res.as_slice().is_empty(), "slot {slot:#x} streams no body");
    }
    assert!(fs.has_data(EF_OTP_NDEF1));
    assert!(fs.has_data(EF_OTP_NDEF2));
    assert!(fs.has_data(EF_OTP_DEVCFG));
}

#[cfg(not(feature = "strict-config"))]
#[test]
fn scan_map_refuses_to_retarget_a_protected_slot() {
    // run-34 #22: the scan map decides what a slot TYPES — an all-zero map silences
    // a protected slot's OTP, an all-0x28 one makes it type Enters — so it is gated
    // like the slot writes it can neutralise.
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let acc = [1, 2, 3, 4, 5, 6];
    let cfg = build_config(&[0, 1, 2, 3, 4, 5], &[1; 6], &[2; 16], &acc, 0, 0, 0);
    assert_eq!(
        configure(&mut app, &mut fs, 0x01, 0, &cfg, &[0; 6]).0,
        Sw::OK
    );

    let write = |app: &mut OtpApplet, fs: &mut Fs<RamStorage>, code: Option<&[u8; 6]>, fill| {
        let mut payload = [0u8; hid::PAYLOAD_SIZE];
        payload[..SCANMAP_LEN].fill(fill);
        if let Some(c) = code {
            payload[SCANMAP_LEN..SCANMAP_LEN + 6].copy_from_slice(c);
        }
        let mut o = [0u8; 64];
        let mut res = ResBuf::new(&mut o);
        app.process_hid(0x12, &payload, fs, &mut res)
    };

    // No code, and the wrong code, are both refused — and nothing is stored.
    assert_eq!(
        write(&mut app, &mut fs, None, 0x40),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(
        write(&mut app, &mut fs, Some(&[9; 6]), 0x40),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    let mut map = [0u8; SCANMAP_LEN];
    assert!(
        fs.read(EF_OTP_SCANMAP, &mut map).is_none(),
        "map was stored"
    );

    // The slot's own code writes it.
    assert_eq!(write(&mut app, &mut fs, Some(&acc), 0x40), Sw::OK);
    assert_eq!(fs.read(EF_OTP_SCANMAP, &mut map), Some(SCANMAP_LEN));
    assert!(map.iter().all(|&b| b == 0x40));
}

#[cfg(not(feature = "strict-config"))]
#[test]
fn scan_map_on_an_unprotected_key_is_unchanged() {
    // The compatibility half: with no code set anywhere, a plain
    // `ykman otp set-scan-map` (45 bytes, no trailing code) still succeeds.
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let cfg = build_config(&[0, 1, 2, 3, 4, 5], &[1; 6], &[2; 16], &[0; 6], 0, 0, 0);
    assert_eq!(
        configure(&mut app, &mut fs, 0x01, 0, &cfg, &[0; 6]).0,
        Sw::OK
    );
    let mut payload = [0u8; hid::PAYLOAD_SIZE];
    payload[..SCANMAP_LEN].fill(0x41);
    let mut o = [0u8; 64];
    let mut res = ResBuf::new(&mut o);
    assert_eq!(app.process_hid(0x12, &payload, &mut fs, &mut res), Sw::OK);
}

#[cfg(not(feature = "strict-config"))]
#[test]
fn scan_map_is_a_function_slot() {
    // …so `ykman config usb --disable OTP` takes it inert with the rest, instead of
    // leaving a live write to what the (disabled) slots would type.
    assert!(is_function_slot(P1_SCAN_MAP));
}

/// The replay position a typed Yubico OTP carries — its clear public id, the
/// persisted use counter and the RAM session counter — decoded out of the modhex
/// ticket with the record's own AES key. A validation server orders OTPs by
/// exactly this triple, so a repeat inside one power cycle is a replay it accepts.
fn typed_position(otp: &[u8], key: &[u8; 16]) -> ([u8; 6], u16, u8) {
    let raw = crate::tests_support::demodhex(&otp[..44]);
    let mut pid = [0u8; 6];
    pid.copy_from_slice(&raw[..6]);
    let mut block = [0u8; 16];
    block.copy_from_slice(&raw[6..22]);
    crate::tests_support::aes128_decrypt_block(key, &mut block);
    // The block CRCs to the X.25 residual only under its own record's key — a
    // decode with the wrong one would read counters that trivially never repeat.
    assert_eq!(crc16(&block), 0xF0B8, "decoded with the wrong record's key");
    (pid, u16::from_le_bytes([block[6], block[7]]), block[11])
}

/// Press `slot`, decode what it typed as the record `pid`/`key` names, and fail
/// if that record has already typed this position in this power cycle.
fn press_once(
    app: &mut OtpApplet,
    fs: &mut Fs<RamStorage>,
    slot: u8,
    pid: &[u8; 6],
    key: &[u8; 16],
    seen: &mut Vec<([u8; 6], u16, u8)>,
) {
    let mut out = [0u8; ticket::MAX_TICKET];
    let (n, encode) = app.button_ticket(slot, 0, [0, 0], fs, &mut out).unwrap();
    assert_eq!((n, encode), (44, true), "slot {slot} typed no Yubico OTP");
    let pos = typed_position(&out[..n], key);
    assert_eq!(&pos.0, pid, "slot {slot} holds the wrong record");
    assert!(
        !seen.contains(&pos),
        "slot {slot} re-typed the replay position {pos:?}, already emitted this \
         power cycle: {seen:?}"
    );
    seen.push(pos);
}

#[test]
fn swap_carries_the_session_counter_with_its_record() {
    // The Yubico replay position is a PAIR: the 15-bit use counter that lives in
    // the slot RECORD, and the one-byte RAM session counter indexed by SLOT
    // NUMBER. SLOT_SWAP moved the record and left the session counter behind, so
    // the record was re-paired with the other slot's — and pressing the swapped
    // slot re-emitted a position already typed in this power cycle, i.e. the
    // position moved BACKWARDS. An unprotected slot's stored code is all-zero, so
    // the bare unauthenticated 0x06 frame below is all it takes.
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);

    let (pid_a, pid_b) = (b"aaaaaa", b"bbbbbb");
    let key_a = [0xA1u8; 16];
    let key_b = [0xB1u8; 16];
    // Plain typed Yubico-OTP slots (tkt = cfg = 0: neither OATH-HOTP, chal-resp,
    // short nor static), the only kind that carries a session counter at all.
    let cfg_a = build_config(pid_a, &[0x0A; 6], &key_a, &[0; 6], 0, 0, 0);
    let cfg_b = build_config(pid_b, &[0x0B; 6], &key_b, &[0; 6], 0, 0, 0);
    assert_eq!(
        configure(&mut app, &mut fs, 0x01, 0, &cfg_a, &[0; 6]).0,
        Sw::OK
    );
    assert_eq!(
        configure(&mut app, &mut fs, 0x03, 0, &cfg_b, &[0; 6]).0,
        Sw::OK
    );

    // Drive the two slots to different session counters first, so a swap that
    // leaves them behind hands the moved record a less-used one.
    let mut seen = Vec::new();
    for _ in 0..3 {
        press_once(&mut app, &mut fs, 1, pid_a, &key_a, &mut seen);
    }
    press_once(&mut app, &mut fs, 2, pid_b, &key_b, &mut seen);

    assert_eq!(run(&mut app, &mut fs, &otp_apdu(0x06, 0, &[])).0, Sw::OK);
    // A sits at slot 2 now and B at slot 1. Press the slots the other way round
    // this time, so the pair is ordered the other way at the swap back: a fix
    // that copies one counter onto the other survives only one of the two.
    for _ in 0..2 {
        press_once(&mut app, &mut fs, 2, pid_a, &key_a, &mut seen);
    }
    press_once(&mut app, &mut fs, 1, pid_b, &key_b, &mut seen);

    assert_eq!(run(&mut app, &mut fs, &otp_apdu(0x06, 0, &[])).0, Sw::OK);
    press_once(&mut app, &mut fs, 1, pid_a, &key_a, &mut seen);
    press_once(&mut app, &mut fs, 2, pid_b, &key_b, &mut seen);

    // RS-Key's 4-slot frame moves a record across a wider gap — `[a, b]` is
    // slots (1+a) ↔ (2+b), so `[0, 1]` is 1 ↔ 3 — and the counter has to follow
    // the FID, not the frame's slot names.
    let (pid_c, key_c) = (b"cccccc", [0xC1u8; 16]);
    let cfg_c = build_config(pid_c, &[0x0C; 6], &key_c, &[0; 6], 0, 0, 0);
    assert_eq!(
        configure(&mut app, &mut fs, 0x01, 2, &cfg_c, &[0; 6]).0,
        Sw::OK
    );
    for _ in 0..2 {
        press_once(&mut app, &mut fs, 3, pid_c, &key_c, &mut seen);
    }
    assert_eq!(
        run(&mut app, &mut fs, &otp_apdu(0x06, 0, &[0, 1])).0,
        Sw::OK
    );
    press_once(&mut app, &mut fs, 3, pid_a, &key_a, &mut seen);
    press_once(&mut app, &mut fs, 1, pid_c, &key_c, &mut seen);
}

#[test]
fn configure_does_not_rewind_the_session_counter() {
    // The sibling of the swap defect, and it goes the other way: a re-CONFIGURE
    // zeroes the record's persisted use counter, so the session counter of the
    // slot it lands in must NOT be reset with it — resetting both is what would
    // hand the same public id a position it already typed this power cycle.
    let mut fs = new_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let pid = b"aaaaaa";
    let key = [0xA1u8; 16];
    let cfg = build_config(pid, &[0x0A; 6], &key, &[0; 6], 0, 0, 0);
    assert_eq!(
        configure(&mut app, &mut fs, 0x01, 0, &cfg, &[0; 6]).0,
        Sw::OK
    );

    let mut seen = Vec::new();
    for _ in 0..3 {
        press_once(&mut app, &mut fs, 1, pid, &key, &mut seen);
    }
    // The same secret programmed over itself: the use counter starts again at 1.
    assert_eq!(
        configure(&mut app, &mut fs, 0x01, 0, &cfg, &[0; 6]).0,
        Sw::OK
    );
    press_once(&mut app, &mut fs, 1, pid, &key, &mut seen);
    assert_eq!(seen[3], (*pid, 1, 3), "the session counter was rewound");
}

// ---- the faulted read: a probe the medium refused is not an absent slot ----
//
// `Storage::read` answers `None` for an absent value AND for one it could not
// serve, and this applet spells *unprogrammed slot* as an absence — so every
// probe below decided something with the collapsed answer. The fixture is
// `rsk_fs::storage::faults::ProbeStuck`: one named fid's reads fail (or its
// `remove` is refused) while every other value still reads, so the setup and the
// observation cannot be what failed.

use rsk_fs::storage::faults::{MetaStuck, ProbeMedium, ProbeStuck};

/// An applet over a medium that can be told to refuse one slot, with the slot
/// records read back past `Fs`'s present cache.
fn faulted_fs() -> (Fs<ProbeStuck>, ProbeMedium) {
    let (backend, medium) = ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    (fs, medium)
}

fn run_f<S: Storage>(app: &mut OtpApplet, fs: &mut Fs<S>, raw: &[u8]) -> Sw {
    let mut out = [0u8; 1024];
    let mut res = ResBuf::new(&mut out);
    let apdu = Apdu::parse(raw).unwrap();
    Applet::process(app, &apdu, fs, &mut res)
}

fn configure_f<S: Storage>(
    app: &mut OtpApplet,
    fs: &mut Fs<S>,
    p1: u8,
    p2: u8,
    config: &[u8; CONFIG_SIZE],
    acc: &[u8; 6],
) -> Sw {
    let mut d = config.to_vec();
    d.extend_from_slice(acc);
    run_f(app, fs, &otp_apdu(p1, p2, &d))
}

/// The public id a slot's record still holds, read with the fault disarmed —
/// `None` for a slot that is gone. It is the whole point of these tests that the
/// observation reads the RECORD and not a status bit: `status()` is recomputed
/// off the same flash the command could not read.
fn slot_fixed<S: Storage>(app: &OtpApplet, fs: &mut Fs<S>, fid: u16) -> Option<[u8; 6]> {
    let mut buf = [0u8; SLOT_SIZE];
    let n = app.read_slot_m(fs, fid, &mut buf)?;
    assert!(n >= CONFIG_SIZE);
    let mut pid = [0u8; 6];
    pid.copy_from_slice(&buf[..6]);
    Some(pid)
}

#[test]
fn configure_refuses_a_slot_it_could_not_read() {
    // The access code is only demanded when the stored slot READS BACK, so a
    // refused probe presented the protected slot as a free one: the frame below
    // carries the wrong code and used to overwrite the record with its own.
    let (mut fs, medium) = faulted_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let acc = [1, 2, 3, 4, 5, 6];
    let mine = build_config(b"mineee", &[1; 6], &[2; 16], &acc, 0, 0, 0);
    assert_eq!(
        configure_f(&mut app, &mut fs, 0x01, 0, &mine, &[0; 6]),
        Sw::OK
    );

    let theirs = build_config(b"theirs", &[9; 6], &[8; 16], &[0; 6], 0, 0, 0);
    medium.stick_once(EF_OTP_SLOT1);
    let sw = configure_f(&mut app, &mut fs, 0x01, 0, &theirs, &[0; 6]);
    medium.stick(None);

    assert_eq!(
        slot_fixed(&app, &mut fs, EF_OTP_SLOT1),
        Some(*b"mineee"),
        "a slot the medium could not read was overwritten without its access code"
    );
    assert_eq!(sw, Sw::MEMORY_FAILURE);
    // The control: with the medium answering, the wrong code is still refused and
    // the right one still lands — the guard must not have become a blanket refusal.
    assert_eq!(
        configure_f(&mut app, &mut fs, 0x01, 0, &theirs, &[0; 6]),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert_eq!(
        configure_f(&mut app, &mut fs, 0x01, 0, &theirs, &acc),
        Sw::OK
    );
    assert_eq!(slot_fixed(&app, &mut fs, EF_OTP_SLOT1), Some(*b"theirs"));
}

#[test]
fn configure_reports_a_slot_delete_it_could_not_make() {
    // An all-zero config is the slot DELETE, and its reply is `status()` — taken
    // back off the same flash. A refused `remove` left the record live and the
    // status bit set, under an OK: the host is told without being told.
    let (mut fs, medium) = faulted_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let cfg = build_config(b"mineee", &[1; 6], &[2; 16], &[0; 6], 0, 0, 0);
    assert_eq!(
        configure_f(&mut app, &mut fs, 0x01, 0, &cfg, &[0; 6]),
        Sw::OK
    );

    medium.refuse_remove(Some(EF_OTP_SLOT1));
    let sw = configure_f(&mut app, &mut fs, 0x01, 0, &[0u8; CONFIG_SIZE], &[0; 6]);
    medium.refuse_remove(None);

    assert!(
        medium.value(EF_OTP_SLOT1).is_some(),
        "the fixture did not hold the record — this case would test nothing"
    );
    assert_eq!(
        sw,
        Sw::MEMORY_FAILURE,
        "a slot delete the medium refused was reported as done"
    );
    // The control: the same frame over a medium that answers really does delete.
    assert_eq!(
        configure_f(&mut app, &mut fs, 0x01, 0, &[0u8; CONFIG_SIZE], &[0; 6]),
        Sw::OK
    );
    assert!(medium.value(EF_OTP_SLOT1).is_none());
}

#[test]
fn configure_reports_a_completed_delete_as_done() {
    // The false alarm the delete guard's first cut introduced. `Fs::delete` drops
    // the EF_META record FIRST and removes the value anyway, so with EF_META
    // present — every provisioned device has one — and its read faulted, `delete`
    // answers `Err` over a slot that really did go. An OTP slot carries no head of
    // its own, so that arm is somebody ELSE's record being unreadable, and
    // reporting `6581` for it is an alarm over a completed erase. Measured before
    // the read-back: sw = 6581 with the record already gone from the medium.
    let (backend, medium) = MetaStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    // A device with metadata on it — without this the drop short-circuits to Ok
    // and the case cannot arise at all.
    fs.meta_add(0x1234, &[1, 2, 3]).unwrap();
    let cfg = build_config(b"mineee", &[1; 6], &[2; 16], &[0; 6], 0, 0, 0);
    assert_eq!(
        configure_f(&mut app, &mut fs, 0x01, 0, &cfg, &[0; 6]),
        Sw::OK
    );

    medium.stick(true);
    let sw = configure_f(&mut app, &mut fs, 0x01, 0, &[0u8; CONFIG_SIZE], &[0; 6]);
    medium.stick(false);

    assert!(
        !medium.live(EF_OTP_SLOT1),
        "the erase did not happen — this case would test nothing"
    );
    assert_eq!(
        sw,
        Sw::OK,
        "6581 over a slot that was really erased, because a blob it does not own \
         could not be read"
    );
}

#[test]
fn a_delete_refuses_when_it_cannot_read_the_record_back() {
    // The read-back that narrows the alarm must not become a second collapsing
    // probe. Drive both faults at once: the medium refuses the `remove` AND the
    // read-back probe of that same slot — `stick_after(fid, 1)` lets the gate's own
    // read through and takes the one after it, which is the read-back. A probe that
    // cannot answer has to count as LIVE; collapsing it to "gone" answers 9000 over
    // a record still on the medium, which is the alarm this whole guard exists for.
    let (mut fs, medium) = faulted_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let cfg = build_config(b"mineee", &[1; 6], &[2; 16], &[0; 6], 0, 0, 0);
    assert_eq!(
        configure_f(&mut app, &mut fs, 0x01, 0, &cfg, &[0; 6]),
        Sw::OK
    );

    medium.refuse_remove(Some(EF_OTP_SLOT1));
    medium.stick_after(EF_OTP_SLOT1, 1);
    let sw = configure_f(&mut app, &mut fs, 0x01, 0, &[0u8; CONFIG_SIZE], &[0; 6]);
    medium.refuse_remove(None);
    medium.stick(None);

    assert!(
        medium.value(EF_OTP_SLOT1).is_some(),
        "the fixture dropped the record — this case would test nothing"
    );
    assert_eq!(
        sw,
        Sw::MEMORY_FAILURE,
        "9000 over a record still in flash, because the read-back could not run"
    );
}

#[test]
fn update_reports_a_slot_it_could_not_read() {
    // UPDATE of an ABSENT slot is a no-op under an OK, so a refused probe answered
    // 9000 for a mutation that never ran — no data lost and no gate opened, but
    // the host's next status read is the only thing that would say so.
    let (mut fs, medium) = faulted_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let acc = [1, 2, 3, 4, 5, 6];
    let cfg = build_config(b"mineee", &[1; 6], &[2; 16], &acc, 0, 0, 0);
    assert_eq!(
        configure_f(&mut app, &mut fs, 0x01, 0, &cfg, &[0; 6]),
        Sw::OK
    );

    let upd = build_config(b"mineee", &[1; 6], &[2; 16], &acc, 0, TKT_APPEND_CR, 0);
    let mut d = upd.to_vec();
    d.extend_from_slice(&acc);
    medium.stick_once(EF_OTP_SLOT1);
    let sw = run_f(&mut app, &mut fs, &otp_apdu(0x04, 0, &d));
    medium.stick(None);

    let mut buf = [0u8; SLOT_SIZE];
    app.read_slot_m(&mut fs, EF_OTP_SLOT1, &mut buf).unwrap();
    assert_eq!(
        buf[OFF_TKT_FLAGS], 0,
        "the fixture let the update through — this case would test nothing"
    );
    assert_eq!(
        sw,
        Sw::MEMORY_FAILURE,
        "an update that never ran was reported as done"
    );
    // The control: over a medium that answers, the same frame updates the flags.
    assert_eq!(run_f(&mut app, &mut fs, &otp_apdu(0x04, 0, &d)), Sw::OK);
    app.read_slot_m(&mut fs, EF_OTP_SLOT1, &mut buf).unwrap();
    assert_eq!(buf[OFF_TKT_FLAGS], TKT_APPEND_CR);
}

#[test]
fn swap_refuses_a_slot_it_could_not_read() {
    // The destructive one. A slot read as absent loses its record TWICE: its own
    // `unmatched` gate is skipped (the frame below carries no code at all), the
    // other slot's `None` arm deletes that slot, and the other slot's record is
    // written over this one. One faulted probe, one bare unauthenticated 0x06
    // frame, and BOTH programmed slots are gone.
    let (mut fs, medium) = faulted_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let cfg_a = build_config(b"aaaaaa", &[1; 6], &[2; 16], &[0; 6], 0, 0, 0);
    let cfg_b = build_config(b"bbbbbb", &[3; 6], &[4; 16], &[9; 6], 0, 0, 0);
    assert_eq!(
        configure_f(&mut app, &mut fs, 0x01, 0, &cfg_a, &[0; 6]),
        Sw::OK
    );
    assert_eq!(
        configure_f(&mut app, &mut fs, 0x03, 0, &cfg_b, &[0; 6]),
        Sw::OK
    );

    medium.stick_once(EF_OTP_SLOT2);
    let sw = run_f(&mut app, &mut fs, &otp_apdu(0x06, 0, &[]));
    medium.stick(None);

    assert_eq!(
        (
            slot_fixed(&app, &mut fs, EF_OTP_SLOT1),
            slot_fixed(&app, &mut fs, EF_OTP_SLOT2)
        ),
        (Some(*b"aaaaaa"), Some(*b"bbbbbb")),
        "an unauthenticated swap destroyed a slot the medium could not read"
    );
    assert_eq!(sw, Sw::MEMORY_FAILURE);
    // The control: the protected slot's own gate still runs when the medium
    // answers — the bare frame is refused, and one code that clears BOTH slots
    // (they are unprotected once slot 2's own code has retired it) moves the pair.
    assert_eq!(
        run_f(&mut app, &mut fs, &otp_apdu(0x06, 0, &[])),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    let open_b = build_config(b"bbbbbb", &[3; 6], &[4; 16], &[0; 6], 0, 0, 0);
    assert_eq!(
        configure_f(&mut app, &mut fs, 0x03, 0, &open_b, &[9; 6]),
        Sw::OK
    );
    assert_eq!(run_f(&mut app, &mut fs, &otp_apdu(0x06, 0, &[])), Sw::OK);
    assert_eq!(slot_fixed(&app, &mut fs, EF_OTP_SLOT1), Some(*b"bbbbbb"));
    assert_eq!(slot_fixed(&app, &mut fs, EF_OTP_SLOT2), Some(*b"aaaaaa"));
}

#[test]
fn swap_reports_a_slot_delete_it_could_not_make() {
    // The swap's own `let _ = fs.delete(...)`: with slot 2 empty the move deletes
    // slot 1 and writes its record to slot 2, so a refused removal left ONE public
    // id in two slots holding one session counter — the replay position the other
    // slot then types is one that id has already typed this power cycle.
    let (mut fs, medium) = faulted_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let cfg_a = build_config(b"aaaaaa", &[1; 6], &[2; 16], &[0; 6], 0, 0, 0);
    assert_eq!(
        configure_f(&mut app, &mut fs, 0x01, 0, &cfg_a, &[0; 6]),
        Sw::OK
    );

    medium.refuse_remove(Some(EF_OTP_SLOT1));
    let sw = run_f(&mut app, &mut fs, &otp_apdu(0x06, 0, &[]));
    medium.refuse_remove(None);

    assert_eq!(
        (
            slot_fixed(&app, &mut fs, EF_OTP_SLOT1),
            slot_fixed(&app, &mut fs, EF_OTP_SLOT2)
        ),
        (Some(*b"aaaaaa"), None),
        "a swap the medium half-refused left one public id in two slots"
    );
    assert_eq!(sw, Sw::MEMORY_FAILURE);
    // The control: over a medium that answers, the record really does move.
    assert_eq!(run_f(&mut app, &mut fs, &otp_apdu(0x06, 0, &[])), Sw::OK);
    assert_eq!(
        (
            slot_fixed(&app, &mut fs, EF_OTP_SLOT1),
            slot_fixed(&app, &mut fs, EF_OTP_SLOT2)
        ),
        (None, Some(*b"aaaaaa"))
    );
}

#[test]
fn swap_reports_the_second_slot_delete_it_could_not_make() {
    // The other delete arm, and it is reached the other way round: with slot 1
    // empty the move writes slot 2's record to slot 1 and then deletes slot 2. A
    // refused removal there leaves the same one-id-in-two-slots state as its
    // sibling, and the record write has already landed, so what the guard buys is
    // that the host is TOLD — the torn half is older and stated in the threat
    // model. Its own test because the sibling's cannot reach this arm at all.
    let (mut fs, medium) = faulted_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let cfg_b = build_config(b"bbbbbb", &[3; 6], &[4; 16], &[0; 6], 0, 0, 0);
    assert_eq!(
        configure_f(&mut app, &mut fs, 0x03, 0, &cfg_b, &[0; 6]),
        Sw::OK
    );

    medium.refuse_remove(Some(EF_OTP_SLOT2));
    let sw = run_f(&mut app, &mut fs, &otp_apdu(0x06, 0, &[]));
    medium.refuse_remove(None);

    assert_eq!(
        slot_fixed(&app, &mut fs, EF_OTP_SLOT2),
        Some(*b"bbbbbb"),
        "the fixture dropped the record — this case would test nothing"
    );
    assert_eq!(
        sw,
        Sw::MEMORY_FAILURE,
        "a swap that left one public id in two slots was reported as done"
    );
    assert_eq!(
        slot_fixed(&app, &mut fs, EF_OTP_SLOT1),
        Some(*b"bbbbbb"),
        "the record write before the refused delete is the torn half, and it stands"
    );
    // The control: clear the duplicate, then the same frame over a medium that
    // answers really does move the record and drop the slot it came from.
    assert_eq!(
        configure_f(&mut app, &mut fs, 0x01, 0, &[0u8; CONFIG_SIZE], &[0; 6]),
        Sw::OK
    );
    assert_eq!(run_f(&mut app, &mut fs, &otp_apdu(0x06, 0, &[])), Sw::OK);
    assert_eq!(
        (
            slot_fixed(&app, &mut fs, EF_OTP_SLOT1),
            slot_fixed(&app, &mut fs, EF_OTP_SLOT2)
        ),
        (Some(*b"bbbbbb"), None)
    );
}

#[cfg(not(feature = "strict-config"))]
#[test]
fn scan_map_refuses_a_slot_it_could_not_read() {
    // `code_clears_every_slot` is the gate on the device-global writes, and the
    // scan map decides what a slot TYPES (run-34 #22). A refused probe presented
    // the protected slot as unprogrammed, so the gate cleared and the map landed
    // with the wrong code — retargeting a slot whose code was never presented.
    let (mut fs, medium) = faulted_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let acc = [1, 2, 3, 4, 5, 6];
    let cfg = build_config(b"mineee", &[1; 6], &[2; 16], &acc, 0, 0, 0);
    assert_eq!(
        configure_f(&mut app, &mut fs, 0x01, 0, &cfg, &[0; 6]),
        Sw::OK
    );

    let write = |app: &mut OtpApplet, fs: &mut Fs<ProbeStuck>, code: &[u8; 6]| {
        let mut payload = [0u8; hid::PAYLOAD_SIZE];
        payload[..SCANMAP_LEN].fill(0x40);
        payload[SCANMAP_LEN..SCANMAP_LEN + 6].copy_from_slice(code);
        let mut o = [0u8; 64];
        let mut res = ResBuf::new(&mut o);
        app.process_hid(P1_SCAN_MAP, &payload, fs, &mut res)
    };

    medium.stick_once(EF_OTP_SLOT1);
    let sw = write(&mut app, &mut fs, &[9; 6]);
    medium.stick(None);

    let mut map = [0u8; SCANMAP_LEN];
    assert!(
        fs.read(EF_OTP_SCANMAP, &mut map).is_none(),
        "a device-global write cleared a gate over a slot the medium could not read"
    );
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    // The control: the gate still opens for the slot's own code.
    assert_eq!(write(&mut app, &mut fs, &acc), Sw::OK);
    assert_eq!(fs.read(EF_OTP_SCANMAP, &mut map), Some(SCANMAP_LEN));
}

/// The stored use counter of slot 1, read with the fault disarmed.
fn stored_use_counter(dev: &Device, fs: &mut Fs<ProbeStuck>) -> u16 {
    let mut buf = [0u8; SLOT_SIZE];
    let n = try_read_slot(dev, fs, EF_OTP_SLOT1, &mut buf)
        .unwrap()
        .unwrap();
    assert_eq!(n, SLOT_SIZE, "the slot lost its counter tail");
    u16::from_be_bytes([buf[CONFIG_SIZE], buf[CONFIG_SIZE + 1]])
}

#[test]
fn power_up_bump_retries_a_slot_the_medium_refused() {
    // The RAM session counter restarts at zero every power cycle, so what keeps
    // this cycle's pairs out of the last one's is the boot bump of the PERSISTED
    // half. A refused probe skipped the slot entirely — and a fault that clears
    // before the first press then leaves the key typing positions it has already
    // typed. The press path types nothing while the medium is refusing, so the
    // window belongs to the TRANSIENT fault, which is the one a retry closes.
    let (mut fs, medium) = faulted_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let dev = Device {
        serial_hash: &SERIAL_HASH,
        serial_id: &SERIAL,
        otp_key: None,
    };
    let mut bump_rng = CountRng(9);
    // A plain typed Yubico-OTP slot — the only kind the bump advances.
    let cfg = build_config(b"public", &[1; 6], &[2; 16], &[0; 6], 0, 0, 0);
    assert_eq!(
        configure_f(&mut app, &mut fs, 0x01, 0, &cfg, &[0; 6]),
        Sw::OK
    );
    assert_eq!(stored_use_counter(&dev, &mut fs), 0);

    medium.stick_once(EF_OTP_SLOT1);
    power_up_bump(&dev, &mut fs, &mut bump_rng);
    medium.stick(None);
    assert_eq!(
        stored_use_counter(&dev, &mut fs),
        1,
        "the boot bump skipped a slot over one faulted read, so this power cycle \
         re-types the last one's positions"
    );

    // And the direction the counter must NOT move: a slot the medium serves is
    // advanced once per boot, never twice, and never at all for a HOTP slot.
    power_up_bump(&dev, &mut fs, &mut bump_rng);
    assert_eq!(stored_use_counter(&dev, &mut fs), 2);
    let hotp = build_config(b"", &[1; 6], &[2; 16], &[0; 6], 0, TKT_OATH_HOTP, 0);
    assert_eq!(
        configure_f(&mut app, &mut fs, 0x03, 0, &hotp, &[0; 6]),
        Sw::OK
    );
    medium.stick_once(EF_OTP_SLOT2);
    power_up_bump(&dev, &mut fs, &mut bump_rng);
    medium.stick(None);
    let mut buf = [0u8; SLOT_SIZE];
    try_read_slot(&dev, &mut fs, EF_OTP_SLOT2, &mut buf)
        .unwrap()
        .unwrap();
    assert_eq!(
        u16::from_be_bytes([buf[CONFIG_SIZE], buf[CONFIG_SIZE + 1]]),
        0,
        "the retry advanced an OATH-HOTP slot's moving factor"
    );
}

#[test]
fn a_slot_the_medium_never_serves_is_left_alone() {
    // The other arm of every guard above: a medium that keeps refusing must not
    // turn a read into a write. The bump gives up rather than looping, the press
    // types nothing, and the gates refuse instead of overwriting — so a stuck
    // slot is inert, which is the residual docs/threat-model.md states.
    let (mut fs, medium) = faulted_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let dev = Device {
        serial_hash: &SERIAL_HASH,
        serial_id: &SERIAL,
        otp_key: None,
    };
    let cfg = build_config(b"public", &[1; 6], &[2; 16], &[0; 6], 0, 0, 0);
    assert_eq!(
        configure_f(&mut app, &mut fs, 0x01, 0, &cfg, &[0; 6]),
        Sw::OK
    );
    let sealed = medium.value(EF_OTP_SLOT1).unwrap();

    medium.stick(Some(EF_OTP_SLOT1));
    power_up_bump(&dev, &mut fs, &mut CountRng(9));
    let mut out = [0u8; ticket::MAX_TICKET];
    assert!(app.button_ticket(1, 0, [0, 0], &mut fs, &mut out).is_none());
    medium.stick(None);
    assert_eq!(
        medium.value(EF_OTP_SLOT1).as_deref(),
        Some(&sealed[..]),
        "a slot the medium never served was rewritten anyway"
    );
}

// ---- the refused WRITE: the other half of the same replay window ----
//
// A read the medium refuses is loud; a write it refuses is silent. The record
// goes on reading perfectly, the press types, and the position it carries is one
// the counter should have moved past. `Fs::put` answers `NoMemory` on a full
// store, so this half needs no medium failure at all.

/// A RAM medium whose `write` of ONE chosen fid fails, for a chosen number of
/// attempts, while every read still serves the old value. Local rather than in
/// `rsk_fs::storage::faults` because it is the only fault shape in the tree that
/// has to leave a READ succeeding over the value a write could not replace.
struct WriteStuck {
    inner: rsk_fs::storage::ram::RamStorage,
    fid: std::rc::Rc<std::cell::Cell<Option<u16>>>,
    budget: std::rc::Rc<std::cell::Cell<u32>>,
}

impl Storage for WriteStuck {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.inner.read(fid, buf)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
        if self.fid.get() == Some(fid) && self.budget.get() > 0 {
            self.budget.set(self.budget.get() - 1);
            return Err(rsk_sdk::error::Error::MemoryFatal);
        }
        self.inner.write(fid, data)
    }
    fn remove(&mut self, fid: u16) -> Result<()> {
        self.inner.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.inner.size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(f)
    }
    fn last_error(&self) -> bool {
        false
    }
}

/// `(fs, refuse)` — call `refuse(Some(fid), n)` to fail the next `n` writes of
/// `fid`; `refuse(None, 0)` clears it.
#[allow(clippy::type_complexity)] // one test fixture, named at both use sites
fn write_stuck_fs() -> (
    Fs<WriteStuck>,
    std::rc::Rc<std::cell::Cell<Option<u16>>>,
    std::rc::Rc<std::cell::Cell<u32>>,
) {
    let fid = std::rc::Rc::new(std::cell::Cell::new(None));
    let budget = std::rc::Rc::new(std::cell::Cell::new(0u32));
    let mut fs = Fs::new(WriteStuck {
        inner: rsk_fs::storage::ram::RamStorage::new(),
        fid: fid.clone(),
        budget: budget.clone(),
    });
    fs.scan();
    (fs, fid, budget)
}

/// The typed position, or `None` when the press typed nothing.
fn press_position<S: Storage>(
    app: &mut OtpApplet,
    fs: &mut Fs<S>,
    slot: u8,
    key: &[u8; 16],
) -> Option<([u8; 6], u16, u8)> {
    let mut out = [0u8; ticket::MAX_TICKET];
    let (n, encode) = app.button_ticket(slot, 0, [0, 0], fs, &mut out)?;
    assert_eq!((n, encode), (44, true), "slot {slot} typed no Yubico OTP");
    Some(typed_position(&out[..n], key))
}

#[test]
fn a_press_types_nothing_when_it_cannot_persist_the_counter() {
    // The press-path write. The 15-bit use counter only moves when the one-byte
    // session counter WRAPS, so the press at the wrap owes flash an advance — and
    // typing the ticket without it re-emits: the next press reads the old counter
    // back and pairs it with session 0, which is this cycle's FIRST position.
    // Measured before the fix, and it is a repeat and not a skip.
    let (mut fs, fid, budget) = write_stuck_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let (pid, key) = (b"public", [0xA1u8; 16]);
    let cfg = build_config(pid, &[1; 6], &key, &[0; 6], 0, 0, 0);
    assert_eq!(
        configure_f(&mut app, &mut fs, 0x01, 0, &cfg, &[0; 6]),
        Sw::OK
    );

    // Walk one whole session: press 1 emits (1, 0) and stores the counter, and
    // press 256 is the one at the wrap.
    let mut seen = Vec::new();
    for i in 1..=255u32 {
        let pos = press_position(&mut app, &mut fs, 1, &key).unwrap();
        assert!(!seen.contains(&pos), "press {i} re-typed {pos:?}");
        seen.push(pos);
    }
    assert_eq!(seen[0], (*pid, 1, 0));

    // The wrap press, with the store refusing this slot for good.
    fid.set(Some(EF_OTP_SLOT1));
    budget.set(u32::MAX);
    // Both presses first, then the claims in order of what they are about: the
    // press AFTER the wrap is the one that repeats — with the wrap not stored the
    // slot reads the old counter back and pairs it with session 0, this cycle's
    // first position — so that assertion comes first and the failure says
    // "re-typed" rather than only "typed something".
    let wrap = press_position(&mut app, &mut fs, 1, &key);
    let after = press_position(&mut app, &mut fs, 1, &key);
    assert!(
        !after.is_some_and(|p| seen.contains(&p)),
        "the press after a refused counter write re-typed {after:?}, already \
         emitted this power cycle"
    );
    assert_eq!(
        wrap, None,
        "a press typed a position the store could not move past"
    );
    assert_eq!(after, None);

    // With the store answering again the wrap completes, into a FRESH position.
    fid.set(None);
    budget.set(0);
    let pos = press_position(&mut app, &mut fs, 1, &key).unwrap();
    assert_eq!(pos, (*pid, 1, 255), "the wrap press did not resume");
    assert!(!seen.contains(&pos));
    let next = press_position(&mut app, &mut fs, 1, &key).unwrap();
    assert_eq!(next, (*pid, 2, 0), "the counter did not carry the wrap");
    assert!(!seen.contains(&next));
}

#[test]
fn boot_bump_retries_a_refused_write_and_pins_what_it_cannot_close() {
    // The boot-bump write. Two arms, and they are different claims.
    let (mut fs, fid, budget) = write_stuck_fs();
    let presence = RefCell::new(AlwaysConfirm);
    let rng = RefCell::new(CountRng(7));
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    let dev = Device {
        serial_hash: &SERIAL_HASH,
        serial_id: &SERIAL,
        otp_key: None,
    };
    let (pid, key) = (b"public", [0xA1u8; 16]);
    let cfg = build_config(pid, &[1; 6], &key, &[0; 6], 0, 0, 0);
    assert_eq!(
        configure_f(&mut app, &mut fs, 0x01, 0, &cfg, &[0; 6]),
        Sw::OK
    );

    // Cycle 1: the bump lands, and one press takes the cycle's first position.
    let () = power_up_bump(&dev, &mut fs, &mut CountRng(9));
    let first = press_position(&mut app, &mut fs, 1, &key).unwrap();
    assert_eq!(first, (*pid, 1, 0));

    // Cycle 2 — a power cycle is a fresh applet, so the RAM session restarts at
    // zero. ONE refused write, which the retry outlasts: the counter moves and the
    // press cannot reach cycle 1's position.
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    fid.set(Some(EF_OTP_SLOT1));
    budget.set(1);
    let () = power_up_bump(&dev, &mut fs, &mut CountRng(9));
    fid.set(None);
    budget.set(0);
    let second = press_position(&mut app, &mut fs, 1, &key).unwrap();
    assert_ne!(
        second, first,
        "one refused boot write re-typed the last cycle's position"
    );
    assert_eq!(second, (*pid, 2, 0));

    // Cycle 3 — the RESIDUAL, pinned rather than described, and it is a CHOICE
    // and not a limit: a refusal the retry cannot outlast (a full store answers
    // `NoMemory` to every attempt) leaves the counter where it was, and the device
    // goes on typing rather than denying the press. Two closures exist, both real.
    // Whichever lands, this assertion has to go red — so the `let ()` above is
    // load-bearing. Measured: with the boot pass returning a stale-slot bitmask and
    // the applet wired to it, the residual WAS closed and this test stayed green
    // at 77 passed, because it called the boot pass as a bare statement and never
    // asked it anything. Binding the unit makes that signature change a compile
    // error here instead.
    let mut app = OtpApplet::new(SERIAL, SERIAL_HASH, None, &rng, &presence);
    fid.set(Some(EF_OTP_SLOT1));
    budget.set(u32::MAX);
    let () = power_up_bump(&dev, &mut fs, &mut CountRng(9));
    fid.set(None);
    budget.set(0);
    assert_eq!(
        press_position(&mut app, &mut fs, 1, &key),
        Some(second),
        "RESIDUAL CLOSED: update docs/threat-model.md's TM-HOST-OTP-REPLAY"
    );
}

#[test]
fn slot_status_kind_follows_the_config_flags() {
    // The no-host menu's read-only slot snapshot: one slot per kind, sealed
    // the way command programming seals them, then reported by flags alone.
    let otp_key = [0x55u8; 32];
    let dev = Device {
        serial_hash: &SERIAL_HASH,
        serial_id: &SERIAL,
        otp_key: Some(&otp_key),
    };
    let mut fs = new_fs();
    let mut rng = CountRng(1);

    // Slot 1: a standard typed Yubico-OTP ticket slot.
    let yubico = build_config(
        b"fix",
        &[1; 6],
        &[2; 16],
        &[0; 6],
        0,
        TKT_APPEND_CR,
        CFG_SHORT_TICKET,
    );
    // Slot 2: a static-password typing slot.
    let static_cfg = build_config(
        b"st",
        &[3; 6],
        &[4; 16],
        &[0; 6],
        0,
        TKT_APPEND_CR,
        CFG_STATIC_TICKET,
    );
    // Slot 4: an OATH-HOTP typing slot.
    let hotp = build_config(
        b"ho",
        &[5; 6],
        &[6; 16],
        &[0; 6],
        0,
        TKT_OATH_HOTP,
        CFG_OATH_HOTP8,
    );
    // Slot 3: a Yubico challenge-response slot (no button trigger).
    let chal = chalresp_config(&[0xAB; 20], &[0; 6], 0);

    let mut fids = [EF_OTP_SLOT1; 4];
    for i in 1..4 {
        fids[i] = fids[i - 1] + 1;
    }
    assert!(seal::seal_put(
        &dev,
        &mut fs,
        &mut rng,
        KeyFid::new(fids[0]),
        &yubico
    ));
    assert!(seal::seal_put(
        &dev,
        &mut fs,
        &mut rng,
        KeyFid::new(fids[1]),
        &static_cfg
    ));
    assert!(seal::seal_put(
        &dev,
        &mut fs,
        &mut rng,
        KeyFid::new(fids[2]),
        &chal
    ));
    assert!(seal::seal_put(
        &dev,
        &mut fs,
        &mut rng,
        KeyFid::new(fids[3]),
        &hotp
    ));

    let s = slot_status(&dev, &mut fs);
    assert_eq!(s[0].kind, SlotKind::YubicoOtp);
    assert!(s[0].touch, "a typed slot always demands the press");
    assert_eq!(s[1].kind, SlotKind::StaticPassword);
    assert_eq!(s[2].kind, SlotKind::ChallengeResponse);
    assert!(!s[2].touch, "challenge slot without the button trigger");
    assert_eq!(s[3].kind, SlotKind::OathHotp);
}

#[test]
fn slot_status_reports_unprogrammed_slots_as_empty() {
    let otp_key = [0x55u8; 32];
    let dev = Device {
        serial_hash: &SERIAL_HASH,
        serial_id: &SERIAL,
        otp_key: Some(&otp_key),
    };
    let mut fs = new_fs();
    let s = slot_status(&dev, &mut fs);
    assert!(s.iter().all(|x| x.kind == SlotKind::Empty && !x.touch));
}
