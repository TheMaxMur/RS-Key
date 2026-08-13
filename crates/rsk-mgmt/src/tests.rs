// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
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

#[test]
fn read_config_body_fits_the_smallest_transport_buffer() {
    let mut fs = fs();
    // Model an over-length blob from an older build (the writer refuses it now).
    fs.put(EF_DEV_CONF, &[0x03, 0x02, 0x02, 0x3B]).unwrap();
    let mut body = [0u8; MIN_CONFIG_RES_CAP];
    let mut res = ResBuf::new(&mut body);
    assert_eq!(config_tlv(&[0; 4], &mut fs, &mut res), Sw::OK);
    assert!(!res.as_slice().is_empty(), "empty body reported as success");
    assert_eq!(res.as_slice()[0] as usize, res.len() - 1);

    // A maximum-size stored blob still fits — that is what the cap is derived for.
    let mut blob = std::vec![0x08, (EF_DEV_CONF_MAX - 2) as u8];
    blob.extend_from_slice(&std::vec![0u8; EF_DEV_CONF_MAX - 2]);
    assert_eq!(blob.len(), EF_DEV_CONF_MAX);
    fs.put(EF_DEV_CONF, &blob).unwrap();
    let mut body = [0u8; MIN_CONFIG_RES_CAP];
    let mut res = ResBuf::new(&mut body);
    assert_eq!(config_tlv(&[0; 4], &mut fs, &mut res), Sw::OK);
    assert!(!res.as_slice().is_empty());
    assert_eq!(res.as_slice()[0] as usize, res.len() - 1);
}

/// Whether every byte of `blob` belongs to a complete TLV entry — what
/// `ykman`'s `Tlv.parse_dict` demands of a DeviceInfo body before it will parse at
/// all. A body with a half entry at the end hides the device from the tool for good.
fn tlv_whole(blob: &[u8]) -> bool {
    let mut i = 0;
    while i < blob.len() {
        let Some(&l) = blob.get(i + 1) else {
            return false;
        };
        i += 2 + l as usize;
    }
    i == blob.len()
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
fn config_tlv_clamps_a_lying_over_read() {
    // The Storage::read contract returns the value's *full* length while the
    // copy is truncated to the buffer, so every caller must clamp the
    // returned length to its buffer. Model a backend that reports far more
    // than the 64-byte buffer: config_tlv must clamp, not slice out of
    // bounds. (RamStorage honours the contract via the real length; this
    // exercises the clamp against an even larger claim.)
    struct OverRead;
    impl Storage for OverRead {
        fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
            (fid == EF_DEV_CONF).then(|| {
                buf.fill(0xAB);
                255 // claim far more than buf.len()
            })
        }
        fn write(&mut self, _: u16, _: &[u8]) -> rsk_sdk::error::Result<()> {
            Ok(())
        }
        fn remove(&mut self, _: u16) -> rsk_sdk::error::Result<()> {
            Ok(())
        }
        fn size(&mut self, fid: u16) -> Option<usize> {
            (fid == EF_DEV_CONF).then_some(255)
        }
        // A stub that yields no keys yet holds EF_DEV_CONF via read/size: report
        // "incomplete" so `scan` never fast-decides the held key absent.
        fn for_each_key(&mut self, _: &mut dyn FnMut(u16)) -> bool {
            false
        }
    }
    let mut fs = Fs::new(OverRead);
    let mut out = [0u8; 256];
    let mut res = ResBuf::new(&mut out);
    assert_eq!(config_tlv(&[0u8; 4], &mut fs, &mut res), Sw::OK);
    let body = res.as_slice();
    assert_eq!(body[0] as usize, body.len() - 1);
    // …and the clamp must not leave a half entry behind. 0xAB claims a 171-byte
    // value, so every echoed byte is the head of an entry that does not fit:
    // emitting any of it is the unparseable DeviceInfo the whole cap exists to
    // prevent, and the length byte agreeing does not make it parse.
    assert!(tlv_whole(&body[1..]), "body carries a truncated TLV entry");
}

#[test]
fn read_config_echoes_only_whole_entries_of_a_legacy_over_length_blob() {
    // Builds before `EF_DEV_CONF_MAX` shrank to what a response can carry stored up
    // to 64 bytes, and `EF_DEV_CONF` survives `authenticatorReset` — so an upgraded
    // device still holds one. Reading it through the smaller cap sliced it mid-entry
    // and produced exactly the DeviceInfo `ykman` refuses to parse.
    let mut fs = fs();
    // 12-byte entries, so the 42-byte cap falls *inside* one, then the capability
    // mask past it — the two things a narrowed read window each get wrong.
    let mut blob = std::vec![];
    while blob.len() + 4 < EF_DEV_CONF_READ_MAX {
        blob.push(TAG_DEVICE_FLAGS);
        blob.push(10);
        blob.extend_from_slice(&[0u8; 10]);
    }
    blob.extend_from_slice(&[TAG_USB_ENABLED, 2, 0x00, 0x3B]);
    assert!(blob.len() > EF_DEV_CONF_MAX && blob.len() <= EF_DEV_CONF_READ_MAX);
    fs.put(EF_DEV_CONF, &blob).unwrap();

    let mut body = [0u8; MIN_CONFIG_RES_CAP];
    let mut res = ResBuf::new(&mut body);
    assert_eq!(config_tlv(&[0; 4], &mut fs, &mut res), Sw::OK);
    let body = res.as_slice();
    assert_eq!(body[0] as usize, body.len() - 1);
    assert!(tlv_whole(&body[1..]), "body carries a truncated TLV entry");
    // The capability mask is read through the same widened window, or an applet the
    // owner disabled quietly comes back on the first boot after the upgrade.
    assert_eq!(read_enabled_caps(&mut fs), 0x3B & SUPPORTED_CAPS);
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

#[test]
fn enabled_from_conf_reads_usb_enabled_tag() {
    // ykman `config usb --disable PIV` persists USB_ENABLED = 0x022B (everything
    // supported minus PIV, 0x10). The parsed mask must have PIV cleared, the rest set.
    let conf = [TAG_USB_ENABLED, 0x02, 0x02, 0x2B];
    let mask = enabled_from_conf(&conf);
    assert_eq!(mask, 0x022B);
    assert!(!cap_enabled(mask, CAP_PIV));
    assert!(cap_enabled(mask, CAP_FIDO2));
    assert!(cap_enabled(mask, CAP_OPENPGP));
}

#[test]
fn enabled_from_conf_defaults_to_all_supported() {
    // No blob, or one without a USB_ENABLED tag → everything supported is enabled.
    assert_eq!(enabled_from_conf(&[]), SUPPORTED_CAPS);
    assert_eq!(enabled_from_conf(&[0x0C, 0x00]), SUPPORTED_CAPS);
}

#[test]
fn enabled_from_conf_clamps_to_supported() {
    // A mask wider than the firmware implements is clamped, mirroring READ CONFIG,
    // so a disabled applet can never be re-enabled into an unimplemented capability.
    let conf = [TAG_USB_ENABLED, 0x02, 0x3A, 0x3B];
    assert_eq!(enabled_from_conf(&conf), 0x3A3B & SUPPORTED_CAPS);
}

#[test]
fn enabled_from_conf_stops_on_malformed_length() {
    // A length running past the blob stops the walk (→ default), never slicing OOB.
    let conf = [TAG_USB_ENABLED, 0x05, 0x02];
    assert_eq!(enabled_from_conf(&conf), SUPPORTED_CAPS);
}

#[test]
fn cap_enabled_treats_zero_as_always_on() {
    // Management/vendor/rescue map to cap 0 — the re-enable path is never gated off.
    assert!(cap_enabled(0, 0));
    assert!(cap_enabled(CAP_FIDO2, 0));
    assert!(!cap_enabled(0, CAP_PIV));
    assert!(cap_enabled(CAP_PIV, CAP_PIV));
}

#[test]
fn read_enabled_caps_roundtrips_via_flash() {
    let mut fs = fs();
    assert_eq!(read_enabled_caps(&mut fs), SUPPORTED_CAPS); // absent → default
    persist_dev_conf(&mut fs, &[TAG_USB_ENABLED, 0x02, 0x02, 0x2B]).unwrap();
    assert_eq!(read_enabled_caps(&mut fs), 0x022B); // "disable PIV" round-trips
}

#[test]
fn persist_dev_conf_sets_dirty_latch() {
    // The firmware reloads its cached enabled mask when this fires. Only this test
    // reads the latch, so a concurrent sibling's persist (also a set) can't flip the
    // assert; the negative "take clears it" is left out to stay race-free.
    let mut fs = fs();
    let _ = take_dev_conf_dirty();
    persist_dev_conf(&mut fs, &[TAG_USB_ENABLED, 0x02, 0x02, 0x2B]).unwrap();
    assert!(
        take_dev_conf_dirty(),
        "a successful config write sets the latch"
    );
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

/// A stored record must never let the device and a host parser disagree about the
/// enabled mask. Duplicates split first-wins (this device) from last-wins (ykman's
/// `Tlv.parse_dict`), and a width other than two escapes both `enabled_from_conf`
/// and `clamp_usb_enabled` — the second permanently, since ykman then computes its
/// own writes from the unclamped value and re-emits a width the device ignores.
#[test]
fn write_config_refuses_a_record_two_parsers_would_read_differently() {
    // Length 1: the device ignores it, a host reads enabled = 0.
    assert!(!well_formed_writable(&[TAG_USB_ENABLED, 1, 0x00]));
    // Length 4: escapes the "enabled ⊆ supported" clamp.
    assert!(!well_formed_writable(&[
        TAG_USB_ENABLED,
        4,
        0xFF,
        0xFF,
        0xFF,
        0xFF
    ]));
    // Duplicate tag: first-wins vs last-wins.
    assert!(!well_formed_writable(&[
        TAG_USB_ENABLED,
        2,
        0x02,
        0x3B,
        TAG_USB_ENABLED,
        2,
        0x00,
        0x00
    ]));
    // What a real YubiKey sends still passes, including two distinct tags.
    assert!(well_formed_writable(&[TAG_USB_ENABLED, 2, 0x02, 0x3B]));
    assert!(well_formed_writable(&[
        TAG_USB_ENABLED,
        2,
        0x02,
        0x3B,
        TAG_DEVICE_FLAGS,
        1,
        0x00
    ]));
    assert!(well_formed_writable(&[]));
}

/// `dev_conf_unchanged` is the third reader of `EF_DEV_CONF`, and it was still
/// sized by the *write* cap while the other two moved to the read bound. A record
/// between the two limits — one an older, wider-writing build left behind — never
/// fitted its buffer, so every idempotent replay of it read as "changed" and
/// churned flash plus the audit ring, which is precisely what the function exists
/// to prevent (audit run-34 #35). Sweep the whole span, not one width.
#[test]
fn dev_conf_unchanged_recognises_a_record_wider_than_the_write_cap() {
    for len in [
        4usize,
        EF_DEV_CONF_MAX,
        EF_DEV_CONF_MAX + 1,
        EF_DEV_CONF_READ_MAX,
    ] {
        let mut fs = fs();
        // A well-formed TLV run of exactly `len` bytes: 0x03 0x02 <2 bytes>, padded
        // out with a repeated device-flags tag so the framing stays walkable.
        let mut blob = std::vec![TAG_USB_ENABLED, 0x02, 0x02, 0x3B];
        while blob.len() + 3 <= len {
            blob.extend_from_slice(&[TAG_DEVICE_FLAGS, 0x01, 0x00]);
        }
        while blob.len() < len {
            blob.push(0x00);
        }
        fs.put(EF_DEV_CONF, &blob).unwrap();
        assert!(
            dev_conf_unchanged(&mut fs, &blob),
            "a stored {len}-byte record must be recognised as already present"
        );
    }
}

/// A record an older build accepted must never be echoed as authoritative
/// DeviceInfo. `well_formed_writable` only ever guarded the *write*, so a 1-byte
/// `USB_ENABLED` stored by a pre-`9171ccf` build survived the upgrade and went on
/// being echoed verbatim — which is how one permanently hid the device from ykman,
/// while `enabled_from_conf` skipped the same value and enforced the default: one
/// record, two answers (audit run-34 #25). The echo is now synthesised from the
/// mask actually enforced, so it is always parseable and always agrees.
#[test]
fn read_config_never_echoes_a_record_its_own_writer_would_refuse() {
    for poisoned in [
        std::vec![TAG_USB_ENABLED, 0x01, 0x00], // 1-byte value
        std::vec![TAG_USB_ENABLED, 0x04, 0xFF, 0xFF, 0xFF, 0xFF], // 4-byte value
        std::vec![
            TAG_USB_ENABLED,
            0x02,
            0x00,
            0x3B,
            TAG_USB_ENABLED,
            0x02,
            0x00,
            0x00
        ],
    ] {
        let mut fs = fs();
        fs.put(EF_DEV_CONF, &poisoned).unwrap();
        let mut body = [0u8; MIN_CONFIG_RES_CAP];
        let mut res = ResBuf::new(&mut body);
        assert_eq!(config_tlv(&[0; 4], &mut fs, &mut res), Sw::OK);
        let body = res.as_slice();
        assert_eq!(body[0] as usize, body.len() - 1, "{poisoned:02x?}");
        assert!(tlv_whole(&body[1..]), "unparseable echo of {poisoned:02x?}");
        // The echo reports exactly what the device enforces.
        assert_eq!(
            enabled_from_conf(&body[1..]),
            read_enabled_caps(&mut fs),
            "echo and enforcement disagree over {poisoned:02x?}"
        );
    }
}

/// Audit run-35: a DeviceConfig write is a delta, not a replacement.
///
/// `ykman config set-lock-code` sends only the 0x0A lock TLV. Stripping it left an
/// empty blob, storing that wholesale left an EMPTY record, and `read_enabled_caps`
/// reads empty as "no record" and returns SUPPORTED_CAPS — so the owner's
/// `ykman config usb --disable` was silently undone by an unrelated command that
/// reported success.
#[test]
fn a_partial_write_config_keeps_the_fields_it_does_not_mention() {
    let mut fs: Fs<RamStorage> = Fs::new(RamStorage::new());

    // The owner disables everything but FIDO2/U2F.
    persist_dev_conf(&mut fs, &[TAG_USB_ENABLED, 2, 0x02, 0x02]).unwrap();
    let hardened = read_enabled_caps(&mut fs);
    assert_ne!(
        hardened, SUPPORTED_CAPS,
        "precondition: caps really narrowed"
    );

    // …then sets a lock code, which sends the 0x0A TLV and nothing else.
    let mut lock = vec![TAG_CONFIG_LOCK, 16];
    lock.extend_from_slice(&[0xAB; 16]);
    persist_dev_conf(&mut fs, &lock).unwrap();

    assert_eq!(
        read_enabled_caps(&mut fs),
        hardened,
        "a lock-code write re-enabled applications the owner disabled"
    );
}

/// The same rule in the other direction: a write that DOES carry a field replaces
/// that field, and leaves the others alone.
#[test]
fn a_write_config_replaces_only_the_tags_it_carries() {
    let mut fs: Fs<RamStorage> = Fs::new(RamStorage::new());
    persist_dev_conf(&mut fs, &[TAG_USB_ENABLED, 2, 0x02, 0x02]).unwrap();
    persist_dev_conf(&mut fs, &[TAG_USB_ENABLED, 2, 0x00, 0x3B]).unwrap();
    let mut buf = [0u8; 64];
    let n = fs.read(EF_DEV_CONF, &mut buf).unwrap();
    assert_eq!(
        &buf[..n],
        &[TAG_USB_ENABLED, 2, 0x00, 0x3B],
        "a restated tag must win, and must not be duplicated"
    );
}

/// Audit run-36: only `USB_ENABLED` had its value width bounded, so an
/// unauthenticated 40-byte `AUTO_EJECT_TIMEOUT` stored fine and then made every
/// later *partial* write — which is the only kind ykman sends — exceed the 42-byte
/// post-merge cap. The owner could never enable or disable an application again.
/// ykman can express at most two bytes for this tag, so bound it.
#[test]
fn an_oversized_config_entry_is_refused_so_it_cannot_wedge_the_owner() {
    let mut fs: Fs<RamStorage> = Fs::new(RamStorage::new());
    let mut bloat = vec![TAG_AUTO_EJECT_TIMEOUT, 38];
    bloat.extend(core::iter::repeat_n(0u8, 38));
    assert!(
        persist_dev_conf(&mut fs, &bloat).is_err(),
        "a 38-byte value for a 2-byte tag must be refused, not stored"
    );
    // And the owner's own write still lands.
    persist_dev_conf(&mut fs, &[TAG_USB_ENABLED, 2, 0x02, 0x1B]).unwrap();
}

/// The same lockout with no attacker at all: released firmware bounded writes at
/// 64 bytes with no shape validation, so a field device may already carry a record
/// the 42-byte post-merge cap refuses. Stored bytes must never veto the owner's
/// write — the merge evicts the oldest un-restated entries instead of refusing.
#[test]
fn a_legacy_oversized_record_cannot_veto_the_owners_write() {
    let mut fs: Fs<RamStorage> = Fs::new(RamStorage::new());
    let mut legacy = vec![TAG_AUTO_EJECT_TIMEOUT, 42];
    legacy.extend(core::iter::repeat_n(0u8, 42));
    fs.put(EF_DEV_CONF, &legacy).unwrap();

    persist_dev_conf(&mut fs, &[TAG_USB_ENABLED, 2, 0x00, 0x01]).unwrap();

    assert_eq!(
        read_enabled_caps(&mut fs),
        0x0001,
        "the owner's write did not take effect"
    );
}

/// `dev_conf_unchanged` exists so an idempotent replay costs no flash write and no
/// audit-journal entry. It compared the REQUEST against the whole stored record
/// while the writer stores a MERGE, so after `e7de26f` a partial blob — the only
/// kind ykman sends — could never match and every replay churned flash.
#[test]
fn an_idempotent_partial_write_is_recognised_as_unchanged() {
    let mut fs: Fs<RamStorage> = Fs::new(RamStorage::new());
    persist_dev_conf(&mut fs, &[TAG_DEVICE_FLAGS, 1, 0x80]).unwrap();
    persist_dev_conf(&mut fs, &[TAG_USB_ENABLED, 2, 0x02, 0x1B]).unwrap();

    assert!(
        dev_conf_unchanged(&mut fs, &[TAG_USB_ENABLED, 2, 0x02, 0x1B]),
        "a replay whose merge is byte-identical still read as changed"
    );
    assert!(
        !dev_conf_unchanged(&mut fs, &[TAG_USB_ENABLED, 2, 0x00, 0x01]),
        "a genuine change must still be seen as a change"
    );
}

/// Audit run-37: run-36's own `trim_to_cap` evicted whole entries by POSITION and
/// never looked at the tag. Nothing canonicalises the stored order, so `USB_ENABLED`
/// leads any record whose writer emitted it first — and it is the one stored entry
/// this firmware enforces, with an absence that resolves to SUPPORTED_CAPS. Any
/// request that strips to nothing (`ykman config set-lock-code`, or a WRITE CONFIG
/// with an empty body) then answered 9000 having discarded the owner's policy.
#[test]
fn trimming_an_over_cap_record_never_evicts_the_enabled_applications_policy() {
    // A record only a pre-cap build could store: over the 42-byte cap, policy first.
    let mut legacy = vec![TAG_USB_ENABLED, 2];
    legacy.extend_from_slice(&CAP_OATH.to_be_bytes());
    legacy.push(TAG_AUTO_EJECT_TIMEOUT);
    legacy.push(42);
    legacy.extend(core::iter::repeat_n(0u8, 42));
    assert!(legacy.len() > EF_DEV_CONF_MAX && legacy.len() <= EF_DEV_CONF_READ_MAX);

    // `set-lock-code` sends a lone 0x0A TLV; both it and an empty body strip to a
    // zero-length request, which leaves the trim free to evict the whole record.
    let mut lock = vec![TAG_CONFIG_LOCK, 16];
    lock.extend_from_slice(&[0xAB; 16]);

    for request in [&lock[..], &[][..]] {
        let mut fs: Fs<RamStorage> = Fs::new(RamStorage::new());
        fs.put(EF_DEV_CONF, &legacy).unwrap();
        assert_eq!(read_enabled_caps(&mut fs), CAP_OATH, "precondition");

        persist_dev_conf(&mut fs, request).unwrap();
        assert_eq!(
            read_enabled_caps(&mut fs),
            CAP_OATH,
            "the trim dropped the owner's policy, silently re-enabling everything"
        );
    }
}

/// The companion defect in the same commit: `overlay_dev_conf` assembles the merge
/// in a buffer the caller sizes, and sizing it by the STORED cap made it answer
/// `TooLong` before `trim_to_cap` could shrink anything. On a full-width legacy
/// record every write adding a tag the record lacks was refused — the very lockout
/// the trim was introduced to end.
#[test]
fn a_full_width_legacy_record_still_accepts_a_write_that_adds_a_tag() {
    let mut fs: Fs<RamStorage> = Fs::new(RamStorage::new());
    let mut legacy = vec![TAG_AUTO_EJECT_TIMEOUT, (EF_DEV_CONF_READ_MAX - 2) as u8];
    legacy.extend(core::iter::repeat_n(0u8, EF_DEV_CONF_READ_MAX - 2));
    assert_eq!(legacy.len(), EF_DEV_CONF_READ_MAX);
    fs.put(EF_DEV_CONF, &legacy).unwrap();

    let mut want = vec![TAG_USB_ENABLED, 2];
    want.extend_from_slice(&CAP_OTP.to_be_bytes());
    persist_dev_conf(&mut fs, &want).unwrap();

    assert_eq!(
        read_enabled_caps(&mut fs),
        CAP_OTP,
        "a full-width stored record vetoed the owner's write"
    );
}
