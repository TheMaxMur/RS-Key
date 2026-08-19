// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
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
    assert!(read_slot(&otp, &mut fs, EF_OTP_SLOT1, &mut buf).is_none());

    // …migrate_seal recovers and re-seals it under the OTP arm.
    migrate_seal(&otp, &mut fs, &mut rng);
    assert!(read_slot(&otp, &mut fs, EF_OTP_SLOT1, &mut buf).is_some());
    assert_eq!(&buf[..CONFIG_SIZE], &cfg[..]);

    // Idempotent: a second pass is a no-op and the slot still reads.
    migrate_seal(&otp, &mut fs, &mut rng);
    assert!(read_slot(&otp, &mut fs, EF_OTP_SLOT1, &mut buf).is_some());
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
    // Empty device: 6-byte YubiKey status — version 5.7.4, seq 0, no valid/touch.
    assert_eq!(body, [5, 7, 4, 0, 0, 0]);

    // Program slot 1 (HMAC chalresp, no touch): VALID without TOUCH.
    let cfgd = chalresp_config(&[0xAA; 20], &[0; 6], 0);
    let (sw, body) = configure(&mut app, &mut fs, 0x01, 0, &cfgd, &[0; 6]);
    assert_eq!(sw, Sw::OK);
    assert_eq!(&body[..4], &[5, 7, 4, 1]); // seq bumped
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
    let n = read_slot(&dev, &mut fs, EF_OTP_SLOT1, &mut buf).unwrap();
    assert_eq!(n, SLOT_SIZE);
    let before = u16::from_be_bytes([buf[CONFIG_SIZE], buf[CONFIG_SIZE + 1]]);
    assert_eq!(before, 3);

    // A routine SLOT_UPDATE (e.g. changing pacing bits) must not touch the counter.
    let upd = build_config(b"public", &[1; 6], &[2; 16], &[0; 6], 0, 0, 0xFF);
    let mut d = upd.to_vec();
    d.extend_from_slice(&[0; 6]);
    assert_eq!(run(&mut app, &mut fs, &otp_apdu(0x04, 0, &d)).0, Sw::OK);

    let n = read_slot(&dev, &mut fs, EF_OTP_SLOT1, &mut buf).unwrap();
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
