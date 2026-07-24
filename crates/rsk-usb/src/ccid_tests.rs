// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn msg(msg_type: u8, seq: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(msg_type);
    v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    v.push(0); // bSlot
    v.push(seq);
    v.push(0); // bStatus / RFU
    v.push(0);
    v.push(0); // abRFU1
    v.extend_from_slice(payload);
    v
}

#[test]
fn atr_identities_are_well_formed() {
    // A T=1 ATR ends with a TCK: the XOR of every byte after TS (T0..TCK) is 0.
    // Guard it for both — ATR_RSKEY is hand-derived from ATR_YUBIKEY (relabelled
    // "RS-Key", checksum recomputed), so a typo would ship a malformed ATR.
    for atr in [ATR_YUBIKEY, ATR_RSKEY] {
        assert_eq!(atr[1..].iter().fold(0u8, |a, &b| a ^ b), 0, "bad TCK");
    }
    // Identical protocol / card-capability bytes (only the historical label plus
    // the K length and TCK differ), so a host negotiates T=1 the same on either.
    assert_eq!(&ATR_YUBIKEY[2..14], &ATR_RSKEY[2..14]);
    // The default build carries the "RS-Key" label and never the "YubiKey" one.
    assert!(ATR_RSKEY.windows(6).any(|w| w == b"RS-Key"));
    assert!(ATR_RSKEY.windows(7).all(|w| w != b"YubiKey"));
    assert!(ATR_YUBIKEY.windows(7).any(|w| w == b"YubiKey"));
}

#[test]
fn slot_status_returns_ret_with_status() {
    let mut status = STATUS_INACTIVE;
    let mut out = [0u8; 64];
    let m = msg(CCID_SLOT_STATUS, 7, &[]);
    let n = process_message(&m, ATR_YUBIKEY, &mut status, &mut out);
    assert_eq!(n, 10);
    assert_eq!(out[0], CCID_SLOT_STATUS_RET);
    assert_eq!(&out[1..5], &[0, 0, 0, 0]); // dwLength 0
    assert_eq!(out[6], 7); // bSeq echoed
    assert_eq!(out[7], STATUS_INACTIVE);
}

#[test]
fn power_on_returns_atr_and_activates() {
    let mut status = STATUS_INACTIVE;
    let mut out = [0u8; 64];
    let m = msg(CCID_POWER_ON, 1, &[]);
    let n = process_message(&m, ATR_YUBIKEY, &mut status, &mut out);
    assert_eq!(n, 10 + ATR_YUBIKEY.len());
    assert_eq!(out[0], CCID_DATA_BLOCK_RET);
    assert_eq!(
        u32::from_le_bytes([out[1], out[2], out[3], out[4]]),
        ATR_YUBIKEY.len() as u32
    );
    assert_eq!(out[7], STATUS_ACTIVE);
    assert_eq!(&out[10..10 + ATR_YUBIKEY.len()], ATR_YUBIKEY);
    assert_eq!(status, STATUS_ACTIVE); // slot now powered
}

#[test]
fn power_off_deactivates() {
    let mut status = STATUS_ACTIVE;
    let mut out = [0u8; 64];
    let m = msg(CCID_POWER_OFF, 2, &[]);
    let n = process_message(&m, ATR_YUBIKEY, &mut status, &mut out);
    assert_eq!(n, 10);
    assert_eq!(out[0], CCID_SLOT_STATUS_RET);
    assert_eq!(out[7], STATUS_INACTIVE);
    assert_eq!(status, STATUS_INACTIVE);
}

#[test]
fn get_params_returns_t1() {
    let mut status = STATUS_ACTIVE;
    let mut out = [0u8; 64];
    for ty in [CCID_GET_PARAMS, CCID_SET_PARAMS, CCID_RESET_PARAMS] {
        let m = msg(ty, 3, &[]);
        let n = process_message(&m, ATR_YUBIKEY, &mut status, &mut out);
        assert_eq!(n, 17);
        assert_eq!(out[0], CCID_PARAMS_RET);
        assert_eq!(out[9], 0x01); // T=1
        assert_eq!(&out[10..17], &T1_PARAMS);
    }
}

#[test]
fn set_rate_returns_eight_zeros() {
    let mut status = STATUS_ACTIVE;
    let mut out = [0u8; 64];
    let m = msg(CCID_SET_RATE, 4, &[]);
    let n = process_message(&m, ATR_YUBIKEY, &mut status, &mut out);
    assert_eq!(n, 18);
    assert_eq!(out[0], CCID_SET_RATE_RET);
    assert_eq!(&out[10..18], &[0u8; 8]);
}

#[test]
fn xfr_block_located_and_framed() {
    // XfrBlock produces no response from `process_message` (it routes through
    // the worker in `Ccid::run`), but `xfr_apdu` locates its APDU, and
    // `run_xfr` frames the eventual response with `put_header` as checked here.
    let apdu = [0x00, 0xA4, 0x04, 0x00, 0x05, 0xF0, 0x00, 0x00, 0x00, 0x01];
    let m = msg(CCID_XFR_BLOCK, 5, &apdu);
    let mut status = STATUS_ACTIVE;
    let mut out = [0u8; 64];
    assert_eq!(process_message(&m, ATR_YUBIKEY, &mut status, &mut out), 0);

    let (a, b) = xfr_apdu(&m).expect("xfr apdu range");
    assert_eq!(&m[a..b], &apdu);

    // The body lands in out[HEADER..]; the header is framed over it.
    out[HEADER..HEADER + 2].copy_from_slice(&[0x90, 0x00]);
    put_header(&mut out, CCID_DATA_BLOCK_RET, 2, 5, STATUS_ACTIVE);
    assert_eq!(out[0], CCID_DATA_BLOCK_RET);
    assert_eq!(u32::from_le_bytes([out[1], out[2], out[3], out[4]]), 2);
    assert_eq!(out[6], 5); // seq echoed
    assert_eq!(&out[HEADER..HEADER + 2], &[0x90, 0x00]);
}

/// Host stand-in for the `xfr_apdu` / `secure_apdu` Kani proof: LCG-mutated raw
/// messages must never yield a range that would slice out of the message.
#[test]
fn apdu_ranges_stay_in_bounds_property_fuzz() {
    let mut lcg: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || -> u8 {
        lcg = lcg
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (lcg >> 33) as u8
    };
    for _ in 0..50000 {
        let len = (next() % (HEADER as u8 + 6)) as usize;
        let mut m = Vec::with_capacity(len);
        // Bias byte 0 toward the real message types so the Some paths are hit.
        for i in 0..len {
            m.push(match (i, next() & 1) {
                (0, 0) => CCID_XFR_BLOCK,
                (0, _) => CCID_SECURE,
                _ => next(),
            });
        }
        for (s, e) in [xfr_apdu(&m), secure_apdu(&m)].into_iter().flatten() {
            assert_eq!(s, HEADER);
            assert!(s <= e && e <= m.len());
            let _ = &m[s..e]; // must not panic
        }
    }
}

#[test]
fn unknown_type_no_response() {
    let mut status = STATUS_ACTIVE;
    let mut out = [0u8; 64];
    let m = msg(0x42, 6, &[]);
    let n = process_message(&m, ATR_YUBIKEY, &mut status, &mut out);
    assert_eq!(n, 0);
}

#[test]
fn short_message_ignored() {
    let mut status = STATUS_ACTIVE;
    let mut out = [0u8; 64];
    let n = process_message(&[0x65, 0, 0], ATR_YUBIKEY, &mut status, &mut out);
    assert_eq!(n, 0);
}

#[test]
fn functional_descriptor_is_54_bytes() {
    // 52-byte body + bLength + bDescriptorType = the 54 bytes the host expects.
    assert_eq!(CCID_FUNCTIONAL_DESC.len() + 2, 54);
}

#[test]
fn pin_support_offset_is_pinned() {
    // `bPINSupport` is body byte 50 (full descriptor byte 52, what every host
    // CCID driver reads); `bMaxCCIDBusySlots` is the last body byte. `Ccid::new`
    // patches index 50 — pin both so an off-by-one can't silently set the wrong
    // field (clobbering the slot count instead of advertising the pinpad).
    assert_eq!(CCID_FUNCTIONAL_DESC[50], 0x00); // bPINSupport, build-patched
    assert_eq!(CCID_FUNCTIONAL_DESC[51], 0x01); // bMaxCCIDBusySlots
}

#[test]
fn secure_message_located() {
    // PC_to_RDR_Secure (0x69) carrying an abPINDataStructure → its payload range;
    // a non-secure message yields None.
    let abdata = [0x00u8, 0x00, 0x82, 0x00, 0x00, 0x00, 0x00, 0x02];
    let m = msg(CCID_SECURE, 9, &abdata);
    let (a, b) = secure_apdu(&m).expect("secure range");
    assert_eq!(&m[a..b], &abdata);
    assert!(secure_apdu(&msg(CCID_XFR_BLOCK, 9, &abdata)).is_none());
}
