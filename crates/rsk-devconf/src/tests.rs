// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;

fn fs() -> Fs<RamStorage> {
    Fs::new(RamStorage::new())
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

/// `EF_DEV_CONF_MAX` is derived from the smallest response buffer so that "a stored
/// blob can never be one a consumer must silently drop" — a claim that only holds
/// while the cap is at or above the widest record the *writer's own validator*
/// accepts. That side was never checked, and it is the side that moves: since
/// `well_formed_writable` gained a per-tag width table (audit run-34 #25) the widest
/// storable record is 24 bytes against a 42-byte cap, so the cap's arithmetic can
/// drift 18 bytes in either direction unobserved. The tag set is scanned rather than
/// listed, so a new writable tag joins the record instead of ageing beside it.
#[test]
fn the_widest_record_the_validator_accepts_is_stored_and_echoed_whole() {
    let widest: Vec<u8> = (0u8..=255)
        .filter(|&t| writable_tag(t))
        // The lock tags never reach flash (`strip_config_lock`), so they cannot
        // widen the stored record however wide the request is.
        .filter(|&t| t != TAG_CONFIG_LOCK && t != TAG_CONFIG_UNLOCK)
        .flat_map(|t| {
            let len = match max_value_len(t) {
                Some(max) => max,
                // `USB_ENABLED` carries its exact width at the call site instead of
                // in the table. Any *other* unbounded writable tag makes the stored
                // record as wide as a host cares to send, which is the one way the
                // cap becomes the binding constraint again.
                None if t == TAG_USB_ENABLED => 2,
                None => panic!("writable tag {t:#04x} has no width bound"),
            };
            let mut e = vec![t, len as u8];
            e.extend(core::iter::repeat_n(0u8, len));
            e
        })
        .collect();
    assert!(well_formed_writable(&widest));
    assert!(
        widest.len() <= EF_DEV_CONF_MAX,
        "cap {EF_DEV_CONF_MAX} is below the {}-byte record the validator accepts",
        widest.len()
    );

    let mut fs = fs();
    persist_dev_conf(&mut fs, &widest).unwrap();
    let mut stored = [0u8; EF_DEV_CONF_READ_MAX];
    let n = fs.read(EF_DEV_CONF, &mut stored).unwrap();
    assert_eq!(
        &stored[..n],
        &widest[..],
        "the cap trimmed a record its own validator accepts"
    );

    // …and the smallest transport still echoes every entry of it.
    let mut body = [0u8; MIN_CONFIG_RES_CAP];
    let mut res = ResBuf::new(&mut body);
    assert_eq!(config_tlv(&[0; 4], &mut fs, &mut res), Sw::OK);
    let echoed = &res.as_slice()[1..];
    let mut i = 0;
    while i + 2 <= widest.len() {
        let (tag, len) = (widest[i], widest[i + 1] as usize);
        assert_eq!(
            tlv_get(echoed, tag).map(<[u8]>::len),
            Some(len),
            "the smallest response dropped tag {tag:#04x}"
        );
        i += 2 + len;
    }
}
