// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn ber_find_walks_top_level_tlvs() {
    // 4F (short) · 5F52 (2-byte tag) · C4 (short): ber_find must step over the
    // 2-byte-tag object to reach C4, and match the 2-byte tag itself.
    let d = [
        0x4F, 0x02, 0xAA, 0xBB, // 4F
        0x5F, 0x52, 0x01, 0x99, // 5F52
        0xC4, 0x03, 0x01, 0x02, 0x03, // C4
    ];
    assert_eq!(ber_find(&d, 0x4F), Some(&[0xAA, 0xBB][..]));
    assert_eq!(ber_find(&d, 0x5F52), Some(&[0x99][..]));
    assert_eq!(ber_find(&d, 0xC4), Some(&[0x01, 0x02, 0x03][..]));
    assert_eq!(ber_find(&d, 0x7F), None);
}

#[test]
fn ber_find_unwraps_6e_and_reads_pgp_fields() {
    // ber_find over a flat 6E body: 4F AID (serial = bytes 10..14) + C4 PW status.
    // A card nests C4 in 73, which `pgp_info` looks through.
    let inner = [
        0x4F, 0x10, // AID, 16 bytes
        0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x02, 0x00, 0x00, 0x06, 0xDE, 0xAD, 0xBE, 0xEF, 0x00,
        0x00, // serial DEADBEEF at 10..14
        0xC4, 0x07, 0x00, 0x7F, 0x00, 0x03, 0x02, 0x00, 0x03, // PW1=2, RC=0, PW3=3
    ];
    let mut d = vec![0x6E, inner.len() as u8];
    d.extend_from_slice(&inner);
    let body = ber_find(&d, 0x6E).unwrap();
    let aid = ber_find(body, 0x4F).unwrap();
    assert_eq!(&aid[10..14], &[0xDE, 0xAD, 0xBE, 0xEF]);
    let c4 = ber_find(body, 0xC4).unwrap();
    assert_eq!([c4[4], c4[5], c4[6]], [2, 0, 3]);
}

/// A `6E` shaped as a card sends it: `4F`, `5F52` and `7F74` at its top, then `73`
/// holding `C0`–`C3`, `C4` and a four-entry `C5`, both templates in the `82` length
/// form. The TUI read `C4`/`C5` from the top: no retries, and a key count of 0.
#[test]
fn pgp_info_reads_c4_and_c5_inside_73() {
    let mut aid = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0x00, 0x06].to_vec();
    aid.extend([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00]);
    let mut c5 = [0u8; 80];
    c5[20] = 0x11; // the decryption key only
    let mut dd = vec![0xC0, 0x0A];
    dd.extend([0x7D, 0x00, 0x0B, 0xFE, 0x08, 0x00, 0x00, 0xFF, 0x00, 0x00]);
    for tag in [0xC1, 0xC2, 0xC3] {
        dd.extend([tag, 0x06, 0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D]);
    }
    dd.extend([0xC4, 0x07, 0x00, 0x7F, 0x7F, 0x7F, 0x02, 0x00, 0x03]);
    dd.extend([0xC5, 80]);
    dd.extend(c5);
    let mut inner = vec![0x4F, 0x10];
    inner.extend(&aid);
    inner.extend([0x5F, 0x52, 0x01, 0x00, 0x7F, 0x74, 0x03, 0x81, 0x01, 0x20]);
    inner.extend([0x73, 0x82, 0x00, dd.len() as u8]);
    inner.extend(&dd);
    let mut d = vec![0x6E, 0x82, (inner.len() >> 8) as u8, inner.len() as u8];
    d.extend(&inner);
    let info = pgp_info(&d);
    assert_eq!(info.serial.as_deref(), Some("deadbeef"));
    assert_eq!(info.pin_retries, Some([2, 0, 3]));
    assert_eq!(info.keys_present, 1);
}

#[test]
fn ber_find_handles_long_form_length_and_truncation() {
    let mut d = vec![0xC5, 0x81, 0x3C]; // len 60 via 0x81
    d.extend(std::iter::repeat_n(0u8, 60));
    assert_eq!(ber_find(&d, 0xC5).map(<[u8]>::len), Some(60));
    // Length claims 4 but only 2 bytes present → None, never a panic.
    assert_eq!(ber_find(&[0x4F, 0x04, 0x01, 0x02], 0x4F), None);
}

#[test]
fn parse_led_stride2_and_stride3() {
    // stride 2: [steady, (color, brightness) × 4].
    let d2 = [1, 6, 16, 3, 32, 2, 64, 7, 8];
    let l = parse_led(&d2, 2).unwrap();
    assert!(l.steady);
    assert_eq!((l.idle, l.processing, l.touch, l.boot), (6, 3, 2, 7));
    // stride 3: [steady, (effect, color, brightness) × 4] — colour is the +1 byte.
    let d3 = [0, 1, 6, 16, 2, 3, 32, 0, 2, 64, 4, 7, 8];
    let l = parse_led(&d3, 3).unwrap();
    assert!(!l.steady);
    assert_eq!((l.idle, l.processing, l.touch, l.boot), (6, 3, 2, 7));
    // Too short for four blocks → None, never an index panic.
    assert!(parse_led(&[1, 6], 2).is_none());
}

#[test]
fn chain_get_response_reassembles_a_normal_chain() {
    // 4 data bytes then a 3-byte tail: 61 03 → C0 gives the rest and 90 00.
    let mut step = 0;
    let out = chain_get_response(
        |_apdu| {
            step += 1;
            Ok(match step {
                1 => (vec![0xDE, 0xAD, 0xBE, 0xEF], 0x61, 0x03),
                _ => (vec![0x01, 0x02, 0x03], 0x90, 0x00),
            })
        },
        0x00,
        0x6E,
    )
    .unwrap();
    assert_eq!(out, [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03]);
}

#[test]
fn chain_get_response_bounds_a_hostile_endless_61_00_stream() {
    // A counterfeit device that answers every GET RESPONSE with a bare 61 00
    // (no data) used to spin the synchronous TUI forever. The round cap must
    // stop it with an Err — a size cap alone can't (out never grows).
    let mut calls = 0u64;
    let r = chain_get_response(
        |_apdu| {
            calls += 1;
            Ok((vec![], 0x61, 0x00))
        },
        0x00,
        0x6E,
    );
    assert!(
        r.is_err(),
        "endless 61 00 stream must be rejected, not looped"
    );
    assert!(
        calls < 1000,
        "loop must be bounded, not spinning (got {calls} calls)"
    );
}

#[test]
fn chain_get_response_bounds_a_hostile_oversized_stream() {
    // A device that keeps sending full 255-byte bodies with 61 FF must be cut off
    // before out grows without bound.
    let r = chain_get_response(|_apdu| Ok((vec![0xAA; 255], 0x61, 0xFF)), 0x00, 0x6E);
    assert!(r.is_err(), "unbounded data stream must be rejected");
}

// --- device binding: which actions refuse to guess ----------------------------
// `tools/rsk`'s half of this is test_refuse_to_guess.py. Deleting the refusal
// here left the TUI suite green (audit run-34 #9), so pin the decision and the
// call sites that reach it.

#[test]
fn one_device_or_none_is_not_ambiguous() {
    assert!(refuse_ambiguous(0).is_ok());
    assert!(refuse_ambiguous(1).is_ok());
}

#[test]
fn two_devices_refuse_and_say_how_many() {
    let e = refuse_ambiguous(2).unwrap_err();
    assert!(e.starts_with("2 FIDO devices attached"), "{e}");
    assert!(e.contains("must not guess"), "{e}");
    assert!(
        refuse_ambiguous(7)
            .unwrap_err()
            .starts_with("7 FIDO devices")
    );
}

#[test]
fn every_hid_open_site_is_classified() {
    // `hid_open()` takes the first match, `hid_open_exclusive()` refuses to.
    // Which action gets which is the security decision, so it is pinned here
    // rather than left to whoever adds the next one.
    const SRC: &str = include_str!("device.rs");
    let mut sites = Vec::new();
    let mut current = "";
    for line in SRC.lines() {
        let t = line.trim_start();
        let is_signature = t.starts_with("fn ") || t.starts_with("pub fn ");
        if is_signature {
            let rest = t.trim_start_matches("pub ").trim_start_matches("fn ");
            current = rest.split(['(', '<']).next().unwrap_or("");
        } else if line.contains("hid_open_exclusive()") {
            sites.push((current, "exclusive"));
        } else if line.contains("hid_open()") {
            sites.push((current, "first-match"));
        }
    }
    assert_eq!(
        sites,
        vec![
            ("hid_open_exclusive", "first-match"), // the open behind the refusal
            // Identify deliberately takes the first match: it must point at the very
            // device this TUI is displaying, and every read here (snapshot, audit,
            // cred_count) resolves the same way. Refusing on two attached keys would
            // disable the one action whose job is telling two attached keys apart.
            ("identify", "first-match"),
            ("audit_read", "first-match"),
            ("verify_identity", "exclusive"),
            ("cred_count", "first-match"),
            ("fetch_backup_seed", "exclusive"),
            ("backup_finalize", "exclusive"),
            ("backup_restore", "exclusive"),
        ]
    );
}
