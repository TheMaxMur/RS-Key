// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The OpenPGP data-object table: resolves each DO tag / FID to its source —
//! a ROM constant, the `rsk-fs` KV store, a computed/composite
//! [`dobj`](crate::dobj) builder, or an internal EF never served by GET DATA.

use crate::consts::*;

/// Historical bytes.
pub const HISTORICAL_BYTES: &[u8] = &[0x00, 0x31, 0x84, 0x73, 0x80, 0x01, 0xC0, 0x05, 0x90, 0x00];

/// Extended capabilities: no secure messaging, GET CHALLENGE (128), key import,
/// PW-status puttable, private DO, changeable algo attrs, AES, KDF-DO.
pub const EXTENDED_CAPABILITIES: &[u8] =
    &[0x7f, 0x00, 0x00, 0x80, 0x08, 0x00, 0x08, 0x00, 0x00, 0x01];

/// Extended length information: max cmd 0x07ff, max rsp 0x0800.
pub const EXLEN_INFO: &[u8] = &[0x02, 0x02, 0x07, 0xff, 0x02, 0x02, 0x08, 0x00];

/// General feature management: button present.
pub const FEATURE_MNGMNT: &[u8] = &[0x81, 0x01, 0x20];

/// Default PW status bytes written to `EF_PW_PRIV` at init: PW1 valid for
/// several PSO:CDS (0x01), max PW lengths 127/127/127, retry counters PW1/RC/PW3.
/// The resetting code ships DEACTIVATED (RC counter 0) per OpenPGP Card 3.4
/// §4.3.4 — it is enabled only when `PUT DATA 0xD3` sets a real reset code
/// (`put_reset_code`), so `RESET RETRY P1=0` cannot run against a default RC.
pub const PW_STATUS_DEFAULT: &[u8] = &[
    0x01,
    PIN_MAX_LEN as u8,
    PIN_MAX_LEN as u8,
    PIN_MAX_LEN as u8,
    PW_RETRIES_DEFAULT,
    0,
    PW_RETRIES_DEFAULT,
];

/// The computed/composite data objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuncDo {
    ChData,     // 0x65 emit_ch_data
    SecTpl,     // 0x7A emit_sec_tpl
    ChCert,     // 0x7F21 — GET/PUT routed to EF_CH_1/2/3 by the dispatcher (occurrence)
    Fp,         // 0xC5 emit_fp
    CaFp,       // 0xC6 emit_cafp
    Ts,         // 0xCD emit_ts
    KeyInfo,    // 0xDE emit_keyinfo
    AlgoInfo,   // 0xC1/0xC2/0xC3/0xFA emit_algoinfo
    AppData,    // 0x6E emit_app_data
    DiscreteDo, // 0x73 emit_discrete_do
    PwStatus,   // 0xC4 emit_pw_status
}

/// Where a DO's data comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoSource {
    Rom(&'static [u8]),
    Flash,
    Func(FuncDo),
    /// The AID-with-serial (`EF_FULL_AID`), assembled by the applet at init.
    FullAid,
    /// Internal EF (private storage): not reachable via GET DATA.
    Internal,
    /// No such file.
    None,
}

/// Resolve a DO tag / FID to its source.
pub fn source(fid: u16) -> DoSource {
    // Private-key and DEK slots are `KeyFid`s (sealed secrets), so they can't be
    // `u16` match patterns; like the other internal EFs they aren't GET-DATA-able.
    if fid == EF_PK_SIG.get()
        || fid == EF_PK_DEC.get()
        || fid == EF_PK_AUT.get()
        || fid == EF_DEK_PW1.get()
        || fid == EF_DEK_RC.get()
        || fid == EF_DEK_PW3.get()
    {
        return DoSource::Internal;
    }
    match fid {
        EF_FULL_AID => DoSource::FullAid,
        EF_HIST_BYTES => DoSource::Rom(HISTORICAL_BYTES),
        EF_EXT_CAP => DoSource::Rom(EXTENDED_CAPABILITIES),
        EF_EXLEN_INFO => DoSource::Rom(EXLEN_INFO),
        EF_GFM => DoSource::Rom(FEATURE_MNGMNT),

        EF_CH_DATA => DoSource::Func(FuncDo::ChData),
        EF_SEC_TPL => DoSource::Func(FuncDo::SecTpl),
        EF_CH_CERT => DoSource::Func(FuncDo::ChCert),
        EF_FP => DoSource::Func(FuncDo::Fp),
        EF_CA_FP => DoSource::Func(FuncDo::CaFp),
        EF_TS_ALL => DoSource::Func(FuncDo::Ts),
        EF_KEY_INFO => DoSource::Func(FuncDo::KeyInfo),
        EF_ALGO_SIG | EF_ALGO_DEC | EF_ALGO_AUT | EF_ALGO_INFO => DoSource::Func(FuncDo::AlgoInfo),
        EF_PW_STATUS => DoSource::Func(FuncDo::PwStatus),
        EF_APP_DATA => DoSource::Func(FuncDo::AppData),
        EF_DISCRETE_DO => DoSource::Func(FuncDo::DiscreteDo),

        // Flash-backed working DOs.
        EF_CH_NAME | EF_LOGIN_DATA | EF_LANG_PREF | EF_SEX | EF_URI_URL | EF_SIG_COUNT
        | EF_FP_SIG | EF_FP_DEC | EF_FP_AUT | EF_FP_CA1 | EF_FP_CA2 | EF_FP_CA3 | EF_TS_SIG
        | EF_TS_DEC | EF_TS_AUT | EF_UIF_SIG | EF_UIF_DEC | EF_UIF_AUT | EF_KDF | EF_RESET_CODE
        | EF_PRIV_DO_1 | EF_PRIV_DO_2 | EF_PRIV_DO_3 | EF_PRIV_DO_4 => DoSource::Flash,

        // Internal EFs (PINs, public-key DOs, base/PWPIV DEK, algo-priv,
        // chaining): not GET-DATA-able. The private-key + PW-DEK slots are
        // handled by the KeyFid guard above.
        EF_PW1 | EF_RC | EF_PW3 | EF_ALGO_PRIV1 | EF_ALGO_PRIV2 | EF_ALGO_PRIV3 | EF_PW_PRIV
        | EF_PW_RETRIES | EF_PB_SIG | EF_PB_DEC | EF_PB_AUT | EF_DEK | EF_DEK_PWPIV | EF_CH_1
        | EF_CH_2 | EF_CH_3 => DoSource::Internal,

        _ => DoSource::None,
    }
}

/// The 8-digit device serial as 4 packed-BCD bytes, matching how a real YubiKey
/// carries the serial in its OpenPGP AID (empirically `37 36 50 93` for device
/// 37365093). Hosts render the OpenPGP card serial as raw hex, so BCD makes it
/// read as the same decimal the device reports over PIV/OTP. The masked serial is
/// <= 8 digits (`serial[0] & 0x03`), so it always fits.
pub fn serial_bcd(serial: &[u8; 4]) -> [u8; 4] {
    let mut n = u32::from_be_bytes(*serial);
    let mut out = [0u8; 4];
    for byte in out.iter_mut().rev() {
        let lo = (n % 10) as u8;
        n /= 10;
        let hi = (n % 10) as u8;
        n /= 10;
        *byte = (hi << 4) | lo;
    }
    out
}

/// Build the 16-byte full AID: prefix + card-spec version + `manufacturer`
/// (bytes 8-9) + the 4-byte `serial` at offset 10.
pub fn full_aid(serial: &[u8; 4], manufacturer: u16) -> [u8; 16] {
    let mut aid = [0u8; 16];
    aid[..6].copy_from_slice(OPENPGP_AID);
    aid[6] = OPGP_VERSION_MAJOR;
    aid[7] = OPGP_VERSION_MINOR;
    aid[8..10].copy_from_slice(&manufacturer.to_be_bytes());
    aid[10..14].copy_from_slice(serial);
    aid
}

/// The device's full OpenPGP AID: the chip id masked to the 8-digit serial,
/// BCD-encoded (YubiKey convention), spliced under `manufacturer`.
pub fn aid_for(serial_id: &[u8; 8], manufacturer: u16) -> [u8; 16] {
    full_aid(&serial_bcd(&rsk_mgmt::serial4(*serial_id)), manufacturer)
}
