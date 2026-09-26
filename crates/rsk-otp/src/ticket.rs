// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Typed-ticket generation — what a button press "types" as keystrokes: a
//! 44-char modhex Yubico OTP (6-byte public id ‖ AES-128-ECB private block), an
//! OATH-HOTP 6/8-digit code, or a static password of raw scancodes. [`build`] does no I/O.

use rsk_crypto::{aes128_encrypt_block, hmac_sha1};
use rsk_secret::Secret;

use crate::{
    CFG_OATH_HOTP8, CFG_SHORT_TICKET, CFG_STATIC_TICKET, CONFIG_SIZE, FIXED_SIZE, KEY_SIZE,
    OFF_AES_KEY, OFF_CFG_FLAGS, OFF_TKT_FLAGS, OFF_UID, SlotRecord, TKT_APPEND_CR, TKT_OATH_HOTP,
    UID_SIZE, crc16,
};

/// The YubiKey modhex alphabet (keyboard-layout-independent).
const MODHEX: &[u8; 16] = b"cbdefghijklnrtuv";

/// Largest typed ticket: a 44-char Yubico-OTP modhex string plus a trailing CR.
pub const MAX_TICKET: usize = 64;

/// The outcome of [`build`]: the bytes to type and how, whether the slot record's
/// tail moved (the use counter / HOTP moving factor) and so has to be persisted, and
/// the new RAM session counter for this slot.
pub struct Typed {
    /// Number of valid bytes in the caller's `out` buffer.
    pub len: usize,
    /// `true` → `out` is ASCII to be mapped through the keycode table; `false` →
    /// `out` holds raw HID scancodes (a static password).
    pub encode: bool,
    /// The record's tail moved: persist it before typing, or the ticket repeats.
    pub persist: bool,
    /// The session counter to keep in RAM for this slot after this press.
    pub new_session: u8,
}

fn encode_modhex(input: &[u8], out: &mut [u8]) -> usize {
    let mut n = 0;
    for &b in input {
        out[n] = MODHEX[(b >> 4) as usize];
        out[n + 1] = MODHEX[(b & 0xF) as usize];
        n += 2;
    }
    n
}

/// RFC 4226 HOTP over an HMAC-SHA1 key and a 64-bit counter; writes the decimal
/// code (zero-padded to `digits`) into `out`, returning its length.
fn hotp(key: &[u8], counter: u64, digits: u32, out: &mut [u8]) -> usize {
    let mac = hmac_sha1(key, &counter.to_be_bytes());
    let off = (mac[19] & 0x0F) as usize;
    let bin = ((mac[off] & 0x7F) as u32) << 24
        | (mac[off + 1] as u32) << 16
        | (mac[off + 2] as u32) << 8
        | (mac[off + 3] as u32);
    let modulo = 10u32.pow(digits);
    let mut code = bin % modulo;
    let n = digits as usize;
    for i in (0..n).rev() {
        out[i] = b'0' + (code % 10) as u8;
        code /= 10;
    }
    n
}

/// Build the ticket a press on `slot` types, moving its tail as the press owes it;
/// a challenge-response slot types nothing, so the caller does not ask. `session` is
/// the slot's RAM session counter, `ts_secs` the uptime, `rnd` two fresh random bytes.
pub fn build(
    slot: &mut SlotRecord,
    session: u8,
    ts_secs: u32,
    rnd: [u8; 2],
    out: &mut [u8; MAX_TICKET],
) -> Typed {
    let cfg = &slot.expose()[..CONFIG_SIZE];
    let tkt = cfg[OFF_TKT_FLAGS];
    let cfgf = cfg[OFF_CFG_FLAGS];
    let append_cr = tkt & TKT_APPEND_CR != 0;

    if tkt & TKT_OATH_HOTP != 0 {
        // OATH-HOTP: the 20-byte key ykman packs = AES field ‖ first 4 UID
        // bytes. HMAC zero-padding makes shorter keys equivalent.
        let mut key = Secret::<[u8; KEY_SIZE + 4]>::zeroed();
        key.expose_mut()[..KEY_SIZE].copy_from_slice(&cfg[OFF_AES_KEY..OFF_AES_KEY + KEY_SIZE]);
        key.expose_mut()[KEY_SIZE..].copy_from_slice(&cfg[OFF_UID..OFF_UID + 4]);
        let imf = slot.press_hotp();
        let digits = if cfgf & CFG_OATH_HOTP8 != 0 { 8 } else { 6 };
        let mut len = hotp(key.expose(), imf, digits, out);
        if append_cr {
            out[len] = b'\r';
            len += 1;
        }
        return Typed {
            len,
            encode: true,
            persist: true,
            new_session: session,
        };
    }

    if cfgf & (CFG_SHORT_TICKET | CFG_STATIC_TICKET) != 0 {
        // Static password: the fixed ‖ uid ‖ key bytes are HID scancodes, typed
        // verbatim (SHORT_TICKET applies no truncation).
        let n = FIXED_SIZE + UID_SIZE + KEY_SIZE; // 38
        out[..n].copy_from_slice(&cfg[..n]);
        let mut len = n;
        if append_cr {
            out[len] = 0x28; // HID Enter scancode
            len += 1;
        }
        return Typed {
            len,
            encode: false,
            persist: false,
            new_session: session,
        };
    }

    // Yubico OTP. otpk = public id (6, clear) ‖ AES-ECB( private block 16 ).
    let (counter, new_session, persist) = slot.press_yubico(session);
    let cfg = &slot.expose()[..CONFIG_SIZE];
    let mut otpk = [0u8; 22];
    otpk[..6].copy_from_slice(&cfg[..6]); // public id prefix
    otpk[6..12].copy_from_slice(&cfg[OFF_UID..OFF_UID + UID_SIZE]);
    otpk[12..14].copy_from_slice(&counter.to_le_bytes());
    let ts = ts_secs >> 1;
    otpk[14] = ts as u8;
    otpk[15] = (ts >> 8) as u8;
    otpk[16] = (ts >> 16) as u8;
    otpk[17] = session;
    otpk[18..20].copy_from_slice(&rnd);
    let crc = !crc16(&otpk[6..20]);
    otpk[20..22].copy_from_slice(&crc.to_le_bytes());
    let mut key = Secret::<[u8; KEY_SIZE]>::zeroed();
    key.expose_mut()
        .copy_from_slice(&cfg[OFF_AES_KEY..OFF_AES_KEY + KEY_SIZE]);
    let mut block = [0u8; 16];
    block.copy_from_slice(&otpk[6..22]);
    aes128_encrypt_block(key.expose(), &mut block);
    otpk[6..22].copy_from_slice(&block);
    let mut len = encode_modhex(&otpk, out);
    if append_cr {
        out[len] = b'\r';
        len += 1;
    }
    Typed {
        len,
        encode: true,
        persist,
        new_session,
    }
}

#[cfg(test)]
#[path = "ticket_tests.rs"]
mod tests;
