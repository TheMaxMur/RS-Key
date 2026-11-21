// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

const SERIAL: [u8; 8] = *b"RSKEMU\x00\x01";

#[test]
fn ecc_round_trips_and_corrects_one_bit() {
    for d in [0u16, 1, 0x1234, 0x8000, 0xFFFF, 0xA5C3] {
        let row = ecc_encode(d);
        assert_eq!(ecc_decode(row), (d, Ecc::Clean));
        for bit in 0..22 {
            assert_eq!(
                ecc_decode(row ^ (1 << bit)),
                (d, Ecc::Corrected),
                "{d:#x} bit {bit}"
            );
        }
        // Bit repair by polarity: the whole row inverted, 23:22 set.
        let brp = 0xC0_0000 | (!row & 0x3F_FFFF);
        assert_eq!(ecc_decode(brp).0, d);
    }
    assert_eq!(ecc_decode(ecc_encode(0x1234) ^ 0b11).1, Ecc::Uncorrectable);
}

/// The ROM's `s_otp_calculate_ecc` computes ECC of 0x0000 as 0; the
/// factory chip ID rows the model writes decode to the fake serial.
#[test]
fn factory_rows_carry_the_chip_id() {
    let rows = factory_rows(SERIAL);
    let id: Vec<u8> = (0..4)
        .flat_map(|i| ecc_decode(rows[i]).0.to_le_bytes())
        .collect();
    assert_eq!(id, SERIAL);
    assert_eq!(ecc_encode(0), 0);
}

#[test]
fn crit1_needs_three_of_eight_copies() {
    let mut rows = factory_rows(SERIAL);
    for c in 0..2 {
        rows[CRIT1_ROW + c] = 1;
    }
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    assert_eq!(OtpCore::new(rows.clone(), log.clone()).critical() & 1, 0);
    rows[CRIT1_ROW + 7] = 1;
    assert_eq!(OtpCore::new(rows, log).critical() & 1, 1);
}

#[test]
fn page_lock1_majority_loads_sw_lock() {
    let mut rows = factory_rows(SERIAL);
    // Page 58: S read-only, NS inaccessible, in two of three copies.
    rows[PAGE0_LOCK0_ROW + 2 * 58 + 1] = 0x00_0D0D;
    let otp = OtpCore::new(rows, Arc::new(Mutex::new(Vec::new())));
    assert_eq!(otp.sw_lock(58), 0xD);
    assert!(otp.readable(58 * 64));
    assert!(
        otp.readable(0xF80 + 2 * 58 + 1),
        "lock pages are always readable"
    );
}
