// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_devconf::SUPPORTED_CAPS;
use rsk_devconf::raw::{
    EF_DEV_CONF, EF_DEV_CONF_MAX, TAG_AUTO_EJECT_TIMEOUT, TAG_CHALRESP_TIMEOUT, TAG_CONFIG_LOCK,
    TAG_CONFIG_UNLOCK, TAG_DEVICE_FLAGS, TAG_FORM_FACTOR, TAG_NFC_ENABLED, TAG_NFC_RESTRICTED,
    TAG_REBOOT, TAG_SERIAL, TAG_USB_ENABLED, TAG_USB_SUPPORTED, TAG_VERSION,
};
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;
use rsk_sdk::Apdu;

struct DenyPresence;
impl UserPresence for DenyPresence {
    fn request(&mut self, _c: Confirm<'_>) -> Presence {
        Presence::Declined
    }
}

fn fs() -> Fs<RamStorage> {
    Fs::new(RamStorage::new())
}

fn select(app: &mut ManagementApplet<'_>, fs: &mut Fs<RamStorage>) -> (Sw, Vec<u8>) {
    let mut out = [0u8; 256];
    let mut res = ResBuf::new(&mut out);
    let sw = Applet::select(app, false, fs, &mut res);
    (sw, res.as_slice().to_vec())
}

fn process(app: &mut ManagementApplet<'_>, fs: &mut Fs<RamStorage>, raw: &[u8]) -> (Sw, Vec<u8>) {
    let mut out = [0u8; 256];
    let mut res = ResBuf::new(&mut out);
    let apdu = Apdu::parse(raw).unwrap();
    let sw = Applet::process(app, &apdu, fs, &mut res);
    (sw, res.as_slice().to_vec())
}

/// Walk a TLV blob, returning the value for `tag`.
fn tlv_get(blob: &[u8], tag: u8) -> Option<&[u8]> {
    let mut i = 0;
    while i + 2 <= blob.len() {
        let t = blob[i];
        let l = blob[i + 1] as usize;
        if i + 2 + l > blob.len() {
            return None;
        }
        if t == tag {
            return Some(&blob[i + 2..i + 2 + l]);
        }
        i += 2 + l;
    }
    None
}

#[test]
fn select_returns_version_string() {
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = ManagementApplet::new([0; 8], &presence);
    let mut fs = fs();
    let (sw, body) = select(&mut app, &mut fs);
    assert_eq!(sw, Sw::OK);
    assert_eq!(&body, b"5.7.4");
}

#[test]
fn read_config_reports_version_caps_serial() {
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = ManagementApplet::new([0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0], &presence);
    let mut fs = fs();
    let (sw, body) = process(&mut app, &mut fs, &[0x00, INS_READ_CONFIG, 0, 0, 0x00]);
    assert_eq!(sw, Sw::OK);
    // Leading overall-length byte.
    assert_eq!(body[0] as usize, body.len() - 1);
    let tlv = &body[1..];
    assert_eq!(tlv_get(tlv, TAG_VERSION), Some(&[5u8, 7, 4][..]));
    assert_eq!(
        tlv_get(tlv, TAG_USB_SUPPORTED),
        Some(&SUPPORTED_CAPS.to_be_bytes()[..])
    );
    // Serial MSB had its top 6 bits cleared (8-digit cap): 0x12 & 0x03 = 0x02.
    assert_eq!(
        tlv_get(tlv, TAG_SERIAL),
        Some(&[0x02, 0x34, 0x56, 0x78][..])
    );
    // Default tail present (no EF_DEV_CONF written yet).
    assert_eq!(
        tlv_get(tlv, TAG_USB_ENABLED),
        Some(&SUPPORTED_CAPS.to_be_bytes()[..])
    );
    assert_eq!(tlv_get(tlv, TAG_CONFIG_LOCK), Some(&[0x00][..]));
}

#[test]
fn read_config_matches_ccid_read_config() {
    // `read_config` must be byte-identical to the CCID INS_READ_CONFIG
    // DeviceInfo so ykman sees the same key on every interface.
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = ManagementApplet::new([0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0], &presence);
    let mut fs = fs();
    let (_, ccid) = process(&mut app, &mut fs, &[0x00, INS_READ_CONFIG, 0, 0, 0x00]);
    let mut out = [0u8; 256];
    let mut res = ResBuf::new(&mut out);
    assert_eq!(app.read_config(&mut fs, &mut res), Sw::OK);
    assert_eq!(res.as_slice(), &ccid[..]);
}

#[test]
fn write_then_read_config_roundtrips() {
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = ManagementApplet::new([0; 8], &presence);
    let mut fs = fs();
    // Enable only FIDO2 + U2F (TAG_USB_ENABLED = 0x0202).
    let blob = [TAG_USB_ENABLED, 0x02, 0x02, 0x02];
    let mut cmd = std::vec![
        0x00,
        INS_WRITE_CONFIG,
        0,
        0,
        (blob.len() + 1) as u8,
        blob.len() as u8
    ];
    cmd.extend_from_slice(&blob);
    let (sw, _) = process(&mut app, &mut fs, &cmd);
    assert_eq!(sw, Sw::OK);

    let (sw, body) = process(&mut app, &mut fs, &[0x00, INS_READ_CONFIG, 0, 0, 0x00]);
    assert_eq!(sw, Sw::OK);
    let tlv = &body[1..];
    // The stored blob is echoed after the fixed prefix.
    assert_eq!(tlv_get(tlv, TAG_USB_ENABLED), Some(&[0x02, 0x02][..]));
    // The lock is always reported unset (real hardware reports 0x0A as a 1-byte
    // boolean on read; we do not implement the lock — audit run-30).
    assert_eq!(tlv_get(tlv, TAG_CONFIG_LOCK), Some(&[0x00][..]));
}

#[test]
fn config_lock_code_is_stripped_and_not_echoed() {
    // ykman `config set-lock-code` sends a 16-byte code under tag 0x0A. We do not
    // implement the lock, and READ CONFIG echoes to any unauthenticated host over
    // three transports, so the code must never be stored or returned — otherwise a
    // secret the user typed leaks in cleartext (audit run-30).
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = ManagementApplet::new([0; 8], &presence);
    let mut fs = fs();
    // 0A 10 <16-byte code>, then a USB_ENABLED tag, as a fuller write might carry.
    let mut blob = std::vec![TAG_CONFIG_LOCK, 0x10];
    blob.extend_from_slice(&[0xAB; 16]);
    blob.extend_from_slice(&[TAG_USB_ENABLED, 0x02, 0x02, 0x02]);
    let mut cmd = std::vec![
        0x00,
        INS_WRITE_CONFIG,
        0,
        0,
        (blob.len() + 1) as u8,
        blob.len() as u8
    ];
    cmd.extend_from_slice(&blob);
    let (sw, _) = process(&mut app, &mut fs, &cmd);
    assert_eq!(sw, Sw::OK);

    // Nothing carrying the code is retained in flash.
    let mut stored = [0u8; EF_DEV_CONF_MAX];
    let n = fs.read(EF_DEV_CONF, &mut stored).unwrap_or(0);
    assert!(!stored[..n].windows(16).any(|w| w == [0xAB; 16]));

    let (sw, body) = process(&mut app, &mut fs, &[0x00, INS_READ_CONFIG, 0, 0, 0x00]);
    assert_eq!(sw, Sw::OK);
    let tlv = &body[1..];
    // The USB_ENABLED tag survives; the lock reads back unset; the raw code is gone.
    assert_eq!(tlv_get(tlv, TAG_USB_ENABLED), Some(&[0x02, 0x02][..]));
    assert_eq!(tlv_get(tlv, TAG_CONFIG_LOCK), Some(&[0x00][..]));
    assert!(!body.windows(16).any(|w| w == [0xAB; 16]));
}

#[test]
fn read_config_clamps_enabled_to_supported() {
    // A host can persist a USB_ENABLED mask wider than SUPPORTED_CAPS (a newer
    // ykman that knows capability bits this firmware lacks). READ CONFIG must
    // report enabled ⊆ supported, as a real YubiKey does, not echo the wider
    // mask verbatim. This models the exact blob a differential run found on a
    // live board: enabled = 0x3A3B while supported = 0x023B.
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = ManagementApplet::new([0; 8], &presence);
    let mut fs = fs();
    // An opaque host tag (0x0C), then USB_ENABLED = 0x3A3B (bits outside
    // SUPPORTED_CAPS), then two more host tags — the exact blob a live board had.
    let blob = [
        0x0C,
        0x00,
        TAG_USB_ENABLED,
        0x02,
        0x3A,
        0x3B,
        0x06,
        0x02,
        0x00,
        0x00,
        0x07,
        0x01,
        0x00,
    ];
    fs.put(EF_DEV_CONF, &blob).unwrap();
    let (sw, body) = process(&mut app, &mut fs, &[0x00, INS_READ_CONFIG, 0, 0, 0x00]);
    assert_eq!(sw, Sw::OK);
    let tlv = &body[1..];
    // enabled clamped: 0x3A3B & 0x023B == 0x023B == SUPPORTED_CAPS.
    assert_eq!(
        tlv_get(tlv, TAG_USB_ENABLED),
        Some(&SUPPORTED_CAPS.to_be_bytes()[..])
    );
    // Other host-written tags are still echoed verbatim.
    assert_eq!(tlv_get(tlv, 0x0C), Some(&[][..]));
    assert_eq!(tlv_get(tlv, 0x06), Some(&[0x00, 0x00][..]));
}

#[test]
fn write_config_rejects_oversized_blob() {
    // An inner blob larger than the read buffer must be refused, so it can
    // never become a sticky DoS that panics every later READ CONFIG.
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = ManagementApplet::new([0; 8], &presence);
    let mut fs = fs();
    let inner = EF_DEV_CONF_MAX + 1;
    let mut cmd = std::vec![
        0x00,
        INS_WRITE_CONFIG,
        0,
        0,
        (inner + 1) as u8, // Lc = leading length byte + inner
        inner as u8        // data[0] = inner (== nc - 1)
    ];
    cmd.extend_from_slice(&std::vec![0xAB; inner]);
    let (sw, _) = process(&mut app, &mut fs, &cmd);
    assert_eq!(sw, Sw::WRONG_DATA);
    // Nothing was persisted.
    assert!(fs.read(EF_DEV_CONF, &mut [0u8; 8]).is_none());
}

#[test]
fn read_config_survives_oversized_stored_blob() {
    // Regression: READ CONFIG used to slice `&conf[..len]` with `len` =
    // Storage::read's *full* stored length, so a >64-byte EF_DEV_CONF
    // panicked. write_config now rejects one, so seed it directly to model a
    // blob left by an older build or a corrupt flash — the read must clamp,
    // not panic.
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = ManagementApplet::new([0; 8], &presence);
    let mut fs = fs();
    fs.put(EF_DEV_CONF, &[0xAB; EF_DEV_CONF_MAX + 16]).unwrap();
    let (sw, body) = process(&mut app, &mut fs, &[0x00, INS_READ_CONFIG, 0, 0, 0x00]);
    assert_eq!(sw, Sw::OK);
    // Well-formed output, nothing sliced out of bounds.
    assert_eq!(body[0] as usize, body.len() - 1);
}

// Audit run-33. `ykman`'s `Tlv.parse_dict` is last-wins, so a stored duplicate of a
// device-owned tag would beat the authentic one this function emits first, and a
// malformed one (a 1-byte VERSION) makes `DeviceInfo.parse` raise — which hides the
// device from ykman for good, since EF_DEV_CONF survives authenticatorReset.
#[test]
fn write_config_refuses_device_owned_and_malformed_tags() {
    let presence = RefCell::new(AlwaysConfirm);
    let mut fs = fs();

    // Each of these is a well-formed TLV that a host must not be able to store.
    for blob in [
        &[TAG_VERSION, 0x01, 0x00][..],         // the ykman-wedging one
        &[TAG_VERSION, 0x03, 0x05, 0x07, 0x04], // a *valid-looking* forged version
        &[TAG_SERIAL, 0x04, 0x00, 0xBC, 0x61, 0x4E],
        &[TAG_USB_SUPPORTED, 0x02, 0xFF, 0xFF],
        &[TAG_FORM_FACTOR, 0x01, 0x81],
        &[0x03, 0x02, 0x02, 0x3B, 0xEE, 0x01, 0x00], // trailing unknown tag 0xEE
        &[0x03, 0x05, 0x02],                         // length overruns the blob
    ] {
        let mut app = ManagementApplet::new([0; 8], &presence);
        let mut cmd = std::vec![
            0x00,
            INS_WRITE_CONFIG,
            0,
            0,
            (blob.len() + 1) as u8,
            blob.len() as u8
        ];
        cmd.extend_from_slice(blob);
        let (sw, _) = process(&mut app, &mut fs, &cmd);
        assert_eq!(sw, Sw::WRONG_DATA, "accepted {blob:02x?}");
        assert!(fs.read(EF_DEV_CONF, &mut [0u8; 8]).is_none());
    }

    // The DeviceInfo response therefore carries each device-owned tag exactly once,
    // so first-match and last-match parsers agree on the identity.
    let mut app = ManagementApplet::new([0; 8], &presence);
    let (sw, body) = process(&mut app, &mut fs, &[0x00, INS_READ_CONFIG, 0, 0, 0x00]);
    assert_eq!(sw, Sw::OK);
    for tag in [TAG_USB_SUPPORTED, TAG_SERIAL, TAG_FORM_FACTOR, TAG_VERSION] {
        assert_eq!(tlv_count(&body[1..], tag), 1, "tag {tag:#04x} not unique");
    }
}

// Audit run-33: `ResBuf::extend` writes *nothing* on overflow, so a stored blob that
// fit the writer's cap but not the smallest transport's 64-byte response turned READ
// CONFIG into an empty `9000` forever. The writer cap is now derived from that
// consumer, and the echo is clamped against the caller's buffer too.
// A `ykman config set-lock-code` sends the old UNLOCK and the new CONFIG_LOCK in
// one request — 16 bytes each, neither of which is stored. Bounding the *request*
// against the stored-blob cap would refuse that legitimate write, so the cap
// applies to the stripped result.
#[test]
fn set_lock_code_sized_request_is_accepted() {
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = ManagementApplet::new([0; 8], &presence);
    let mut fs = fs();
    let mut blob = std::vec![TAG_CONFIG_UNLOCK, 0x10];
    blob.extend_from_slice(&[0x11; 16]);
    blob.push(TAG_CONFIG_LOCK);
    blob.push(0x10);
    blob.extend_from_slice(&[0x22; 16]);
    // …alongside the rest of ykman's writable set, which is what makes the request
    // exceed the stored cap while the config it actually stores stays tiny.
    blob.extend_from_slice(&[TAG_USB_ENABLED, 0x02, 0x02, 0x3B]);
    blob.extend_from_slice(&[TAG_AUTO_EJECT_TIMEOUT, 0x02, 0x00, 0x00]);
    blob.extend_from_slice(&[TAG_CHALRESP_TIMEOUT, 0x01, 0x0F]);
    blob.extend_from_slice(&[TAG_DEVICE_FLAGS, 0x01, 0x00]);
    blob.extend_from_slice(&[TAG_NFC_ENABLED, 0x02, 0x00, 0x00]);
    blob.extend_from_slice(&[TAG_NFC_RESTRICTED, 0x01, 0x00]);
    blob.extend_from_slice(&[TAG_REBOOT, 0x00]);
    assert!(
        blob.len() > EF_DEV_CONF_MAX,
        "the point is a request over the stored cap"
    );
    let mut cmd = std::vec![
        0x00,
        INS_WRITE_CONFIG,
        0,
        0,
        (blob.len() + 1) as u8,
        blob.len() as u8
    ];
    cmd.extend_from_slice(&blob);
    let (sw, _) = process(&mut app, &mut fs, &cmd);
    assert_eq!(
        sw,
        Sw::OK,
        "a legitimate set-lock-code write must not be refused"
    );
    // Only the enabled mask survives; neither 16-byte code reaches flash.
    let mut stored = [0u8; EF_DEV_CONF_MAX];
    let n = fs.read(EF_DEV_CONF, &mut stored).unwrap();
    assert!(n <= EF_DEV_CONF_MAX);
    assert!(
        !stored[..n]
            .windows(16)
            .any(|w| w == [0x11; 16] || w == [0x22; 16]),
        "neither lock code may reach flash"
    );
    assert_eq!(
        tlv_get(&stored[..n], TAG_USB_ENABLED),
        Some(&[0x02, 0x3B][..])
    );
}

/// How many times `tag` appears in a TLV blob.
fn tlv_count(blob: &[u8], tag: u8) -> usize {
    let mut i = 0;
    let mut n = 0;
    while i + 2 <= blob.len() {
        let l = blob[i + 1] as usize;
        if i + 2 + l > blob.len() {
            break;
        }
        if blob[i] == tag {
            n += 1;
        }
        i += 2 + l;
    }
    n
}

#[test]
fn write_config_rejects_bad_length() {
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = ManagementApplet::new([0; 8], &presence);
    let mut fs = fs();
    // First byte (3) disagrees with the actual remaining length (2).
    let (sw, _) = process(
        &mut app,
        &mut fs,
        &[0x00, INS_WRITE_CONFIG, 0, 0, 0x03, 0x03, 0xAA, 0xBB],
    );
    assert_eq!(sw, Sw::WRONG_DATA);
}

#[cfg(feature = "strict-config")]
#[test]
fn write_config_requires_user_presence() {
    // strict-config: a well-formed WRITE CONFIG is refused without a physical
    // confirmation, and nothing is persisted — a hostile USB host cannot rewrite
    // DeviceInfo. (The DEFAULT build is ungated; see the permissive twin below.)
    let presence = RefCell::new(DenyPresence);
    let mut app = ManagementApplet::new([0; 8], &presence);
    let mut fs = fs();
    let blob = [TAG_USB_ENABLED, 0x02, 0x02, 0x02];
    let mut cmd = std::vec![
        0x00,
        INS_WRITE_CONFIG,
        0,
        0,
        (blob.len() + 1) as u8,
        blob.len() as u8
    ];
    cmd.extend_from_slice(&blob);
    let (sw, _) = process(&mut app, &mut fs, &cmd);
    assert_eq!(sw, Sw::CONDITIONS_NOT_SATISFIED);
    assert!(
        fs.read(EF_DEV_CONF, &mut [0u8; 8]).is_none(),
        "nothing persisted without presence"
    );
}

#[cfg(not(feature = "strict-config"))]
#[test]
fn write_config_default_is_ungated_and_persists() {
    // DEFAULT (permissive) build: WRITE CONFIG succeeds with NO presence — full
    // YubiKey/ykman parity. Denying presence must not block it, and the blob must
    // land in EF_DEV_CONF so a later READ CONFIG echoes it.
    let presence = RefCell::new(DenyPresence);
    let mut app = ManagementApplet::new([0; 8], &presence);
    let mut fs = fs();
    let blob = [TAG_USB_ENABLED, 0x02, 0x02, 0x02];
    let mut cmd = std::vec![
        0x00,
        INS_WRITE_CONFIG,
        0,
        0,
        (blob.len() + 1) as u8,
        blob.len() as u8
    ];
    cmd.extend_from_slice(&blob);
    let (sw, _) = process(&mut app, &mut fs, &cmd);
    assert_eq!(sw, Sw::OK);
    let mut got = [0u8; 8];
    let n = fs
        .read(EF_DEV_CONF, &mut got)
        .expect("persisted without presence");
    assert_eq!(&got[..n], &blob);
}

#[test]
fn bad_cla_and_ins_rejected() {
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = ManagementApplet::new([0; 8], &presence);
    let mut fs = fs();
    let (sw, _) = process(&mut app, &mut fs, &[0x10, INS_READ_CONFIG, 0, 0, 0x00]);
    assert_eq!(sw, Sw::CLA_NOT_SUPPORTED);
    let (sw, _) = process(&mut app, &mut fs, &[0x00, 0xEE, 0, 0, 0x00]);
    assert_eq!(sw, Sw::INS_NOT_SUPPORTED);
    // RESET stays unsupported under strict-config; on the default build it is a
    // (presence-gated) device-wide reset, exercised by its own tests below.
    #[cfg(feature = "strict-config")]
    {
        let (sw, _) = process(&mut app, &mut fs, &[0x00, INS_RESET, 0, 0, 0x00]);
        assert_eq!(sw, Sw::INS_NOT_SUPPORTED);
    }
}

#[cfg(not(feature = "strict-config"))]
#[test]
fn device_reset_denied_without_presence() {
    // Even ungated everywhere else, a device-wide reset is presence-gated
    // (irreversible). A declined touch refuses it and queues nothing — and does
    // not touch the process-global reset flag.
    let presence = RefCell::new(DenyPresence);
    let mut app = ManagementApplet::new([0; 8], &presence);
    let mut fs = fs();
    for ins in [INS_RESET, 0x1F] {
        let (sw, _) = process(&mut app, &mut fs, &[0x00, ins, 0, 0, 0x00]);
        assert_eq!(sw, Sw::CONDITIONS_NOT_SATISFIED);
    }
}

#[cfg(not(feature = "strict-config"))]
#[test]
fn device_reset_signals_the_firmware_on_presence() {
    // The only test that touches the process-global DEVICE_RESET flag, so it can
    // drain/observe it without racing a sibling. ykman sends 0x1F; RS-Key's own
    // 0x1E is honoured too.
    let _ = take_device_reset(); // clear any stale value
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = ManagementApplet::new([0; 8], &presence);
    let mut fs = fs();
    let (sw, _) = process(&mut app, &mut fs, &[0x00, 0x1F, 0, 0, 0x00]);
    assert_eq!(sw, Sw::OK);
    assert!(
        take_device_reset(),
        "a presence-confirmed RESET queues the wipe"
    );
    assert!(!take_device_reset(), "take clears the flag");
}
