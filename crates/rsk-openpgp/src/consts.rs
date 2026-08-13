// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! OpenPGP applet constants: AID/ATR, instruction bytes, EF/DO FIDs, PIN modes,
//! status aliases, and DEK sizing.

use rsk_fs::KeyFid;
use rsk_sdk::Sw;

/// OpenPGP application identifier.
pub const OPENPGP_AID: &[u8] = &[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];

/// OpenPGP card spec version 3.4.
pub const OPGP_VERSION_MAJOR: u8 = 0x03;
pub const OPGP_VERSION_MINOR: u8 = 0x04;

/// OpenPGP AID manufacturer id (bytes 8-9). `0x0006` = Yubico, used by the
/// `VIDPID=Yubikey5` interop build so hosts show the same vendor as a real
/// YubiKey; `0xFFFE` = the unmanaged/test range for the default RS-Key identity,
/// which is not Yubico. Firmware picks it from the USB VID.
pub const OPGP_MFR_YUBICO: u16 = 0x0006;
pub const OPGP_MFR_UNMANAGED: u16 = 0xFFFE;

// Algorithm IDs (first byte of an algorithm-attributes DO).
pub const ALGO_RSA: u8 = 0x01;
pub const ALGO_ECDH: u8 = 0x12;
pub const ALGO_ECDSA: u8 = 0x13;
pub const ALGO_EDDSA: u8 = 0x16;
pub const ALGO_AES: u8 = 0x70;
pub const ALGO_AES_128: u8 = 0x71;
pub const ALGO_AES_192: u8 = 0x72;
pub const ALGO_AES_256: u8 = 0x74;

/// Default algorithm attribute when the slot has no `EF_ALGO_PRIV*` —
/// RSA-2048, gpg's default. dobj.rs's C1/C2/C3 GET DATA fallback
/// (`ATTR_RSA2K`) encodes the same default and must change with it.
pub(crate) const DEFAULT_ALGO: &[u8] = &[ALGO_RSA, 0x08, 0x00, 0x00, 0x20, 0x00];

/// Status 0x6A80 (wrong data).
pub(crate) const WRONG_DATA: Sw = Sw::INCORRECT_PARAMS;

/// ATR for the OpenPGP card.
pub const ATR_OPENPGP: &[u8] = &[
    0x3b, 0xda, 0x18, 0xff, 0x81, 0xb1, 0xfe, 0x75, 0x1f, 0x03, 0x00, 0x31, 0xf5, 0x73, 0xc0, 0x01,
    0x60, 0x00, 0x90, 0x00, 0x1c,
];

// ---------------- APDU instruction bytes ----------------
pub const INS_SELECT_DATA: u8 = 0xA5;
pub const INS_GET_DATA: u8 = 0xCA;
pub const INS_GET_NEXT_DATA: u8 = 0xCC;
pub const INS_VERIFY: u8 = 0x20;
pub const INS_CHANGE_PIN: u8 = 0x24;
pub const INS_RESET_RETRY: u8 = 0x2C;
pub const INS_KEYPAIR_GEN: u8 = 0x47;
pub const INS_PSO: u8 = 0x2A;
pub const INS_INTERNAL_AUT: u8 = 0x88;
pub const INS_SELECT: u8 = 0xA4;
pub const INS_CHALLENGE: u8 = 0x84;
pub const INS_TERMINATE_DF: u8 = 0xE6;
pub const INS_ACTIVATE_FILE: u8 = 0x44;
pub const INS_PUT_DATA: u8 = 0xDA;
pub const INS_PUT_DATA_ODD: u8 = 0xDB; // IMPORT (extended header list)
pub const INS_MSE: u8 = 0x22;
pub const INS_VERSION: u8 = 0xF1;

// ---------------- Internal EF FIDs (flash-backed) ----------------
pub const EF_PW1: u16 = 0x1081;
pub const EF_RC: u16 = 0x1082;
pub const EF_PW3: u16 = 0x1083;
pub const EF_ALGO_PRIV1: u16 = 0x10c1;
pub const EF_ALGO_PRIV2: u16 = 0x10c2;
pub const EF_ALGO_PRIV3: u16 = 0x10c3;
pub const EF_PW_PRIV: u16 = 0x10c4;
pub const EF_PW_RETRIES: u16 = 0x10c5;
pub const EF_PK_SIG: KeyFid = KeyFid::new(0x10d1); // private SIG key, DEK-sealed
pub const EF_PK_DEC: KeyFid = KeyFid::new(0x10d2); // private DEC key, DEK-sealed
pub const EF_PK_AUT: KeyFid = KeyFid::new(0x10d3); // private AUT key, DEK-sealed
pub const EF_PB_SIG: u16 = 0x10d4; // public-key DO = EF_PK_SIG + 3 (not secret)
pub const EF_PB_DEC: u16 = 0x10d5;
pub const EF_PB_AUT: u16 = 0x10d6;
/// Per-slot key origin backing DO `0xDE`'s status byte — `0x1000 | tag`, the
/// same private-companion convention `algo_tag_to_priv` uses for C1/C2/C3.
pub const EF_KEY_ORIGIN: u16 = 0x10de;
/// Asymmetric key slots (SIG, DEC, AUT) — the pairs DO `0xDE` reports and the
/// length of the `EF_KEY_ORIGIN` record.
pub const KEY_SLOTS: usize = 3;
pub const EF_DEK: u16 = 0x1099;
pub const EF_DEK_PW1: KeyFid = KeyFid::new(0x109a); // DEK wrapped under PW1
pub const EF_DEK_RC: KeyFid = KeyFid::new(0x109b); // DEK wrapped under reset code
pub const EF_DEK_PW3: KeyFid = KeyFid::new(0x109c); // DEK wrapped under PW3
pub const EF_DEK_PWPIV: u16 = 0x109d;
/// Staging slots for a DEK re-wrap, so that updating a PIN — two flash records,
/// the verifier and the DEK copy sealed under it — survives losing power between
/// them. Each holds `[target FID low byte] ‖ [the record the target takes]`.
///
/// **One slot per target, not one shared slot.** A shared one is silently
/// destroyed by the next PIN update of any kind: a PW3 change that tore leaves a
/// stage pending, and the very next PW1 change — even one the card *refuses* —
/// overwrites it, taking the recovery with it. Only the update that owns a slot
/// ever writes it. Retired by [`crate::pin::load_dek`] or by the commit that
/// completes the update.
pub const EF_DEK_STAGE_PW1: KeyFid = KeyFid::new(0x109e);
pub const EF_DEK_STAGE_RC: KeyFid = KeyFid::new(0x109f);
pub const EF_DEK_STAGE_PW3: KeyFid = KeyFid::new(0x10a1);
pub const EF_CH_1: u16 = 0x1f21;
pub const EF_CH_2: u16 = 0x1f22;
pub const EF_CH_3: u16 = 0x1f23;
/// How many occurrences DO 7F21 has (`EF_CH_1..EF_CH_3`) — the range SELECT DATA
/// accepts and the point GET NEXT DATA's walk stops at.
pub const CERT_OCCURRENCES: u8 = 3;
// Raising the count without adding the file compiles: the walk would reach FID
// 0x1f24, which `files::source` classifies as no DO at all and TERMINATE DF does
// not wipe. The occurrences are a contiguous range and this is what says so.
const _: () = assert!(EF_CH_1 + CERT_OCCURRENCES as u16 - 1 == EF_CH_3);

// ---------------- Data-object FIDs / tags (tag == FID) ----------------
// `//C` = computed/composite DO, `//S` = stored DO.
pub const EF_EXT_HEADER: u16 = 0x004d; // C — extended header list (IMPORT)
pub const EF_FULL_AID: u16 = 0x004f; // S
pub const EF_CH_NAME: u16 = 0x005b; // S
pub const EF_LOGIN_DATA: u16 = 0x005e; // S
pub const EF_CH_DATA: u16 = 0x0065; // C — cardholder related data
pub const EF_APP_DATA: u16 = 0x006e; // C — application related data
pub const EF_DISCRETE_DO: u16 = 0x0073; // C
pub const EF_SEC_TPL: u16 = 0x007a; // C — security support template
pub const EF_SIG_COUNT: u16 = 0x0093; // S — signature counter (3 bytes)
pub const EF_EXT_CAP: u16 = 0x00c0; // S — extended capabilities
pub const EF_ALGO_SIG: u16 = 0x00c1; // S — algorithm attributes (SIG)
pub const EF_ALGO_DEC: u16 = 0x00c2; // S
pub const EF_ALGO_AUT: u16 = 0x00c3; // S
pub const EF_PW_STATUS: u16 = 0x00c4; // S — PW status bytes (7)
pub const EF_FP: u16 = 0x00c5; // S — fingerprints (3×20)
pub const EF_CA_FP: u16 = 0x00c6; // S — CA fingerprints (3×20)
/// OpenPGP 3.4 §4.4.1 fixes a fingerprint at 20 bytes and a key-generation
/// timestamp at 4; `C5`/`C6`/`CD` are read-only concatenations of `KEY_SLOTS` of
/// them, so the writer's length gate and the reader's stride are one value.
pub const FP_LEN: usize = 20;
pub const TS_LEN: usize = 4;

/// The maxima OpenPGP 3.4 §4.4.1 gives the cardholder DOs it caps: the name `5B`
/// at 39 bytes, the language preference `5F2D` at 8 (four two-letter codes). The
/// sex DO `5F35` is one byte from the ISO 5218 code set; §4.4.3.4 enumerates it
/// rather than bounding it, which is why it is a value list and not a length.
///
/// The set is male / female / not-applicable. ISO 5218's fourth code, `'0'` (not
/// known), is **not** in it: a YubiKey 5.7.4 answers `6A80` to `PUT DATA 5F35 30`
/// and holds `'9'` itself (3/3, twice, across two independent resets).
pub const NAME_MAX: usize = 39;
pub const LANG_MAX: usize = 8;
pub const SEX_VALUES: &[u8] = b"129";
pub const EF_FP_SIG: u16 = 0x00c7; // S
pub const EF_FP_DEC: u16 = 0x00c8; // S
pub const EF_FP_AUT: u16 = 0x00c9; // S
pub const EF_FP_CA1: u16 = 0x00ca; // S
pub const EF_FP_CA2: u16 = 0x00cb; // S
pub const EF_FP_CA3: u16 = 0x00cc; // S
pub const EF_TS_ALL: u16 = 0x00cd; // S — generation timestamps (3×4)
pub const EF_TS_SIG: u16 = 0x00ce; // S
pub const EF_TS_DEC: u16 = 0x00cf; // S
pub const EF_TS_AUT: u16 = 0x00d0; // S
pub const EF_RESET_CODE: u16 = 0x00d3; // S — PUT redirects to EF_RC
/// The AES key for PSO:ENC/DEC — **card-level, not the DEC slot's**. 3.4 names it
/// by its commands, gives it no Key-Ref (§5 gives those to the three private keys
/// only), and §7.2.12's PSO:ENCIPHER takes no key reference at all, so this one DO
/// is the whole key material of a command that never touches the DEC slot.
pub const EF_AES_KEY: KeyFid = KeyFid::new(0x00d5); // S — DEK-sealed

/// The key widths DO `D5` takes, and the only widths `store_aes_key` will seal.
/// OpenPGP 3.4 §7.2.11 gives PSO:DEC/ENC an AES-128 or an AES-256 key and nothing
/// between. `load_aes_key`'s legacy predicate is wider (it also passes 24), which
/// is slack rather than history: no build ever wrote a record of that width.
pub const AES_KEY_LENS: [usize; 2] = [16, 32];

pub const EF_UIF_SIG: u16 = 0x00d6; // S — user-interaction flag (touch)
pub const EF_UIF_DEC: u16 = 0x00d7; // S
pub const EF_UIF_AUT: u16 = 0x00d8; // S

/// UIF flag byte "permanently enabled" (OpenPGP 3.4, D6/D7/D8 DO table): once
/// stored, PUT DATA may not change it — only a factory reset (TERMINATE DF, which
/// re-seeds `UIF_DEFAULT`) clears it. This is the only touch setting that holds
/// against a caller who already has PW3.
pub(crate) const UIF_PERMANENT: u8 = 0x02;

/// The touch-policy (UIF) DO for the private-key slot actually being used.
/// MANAGE SECURITY ENVIRONMENT can cross-wire the DEC/AUT slot references, so
/// the touch check must follow the repointed slot (`sess.pk_dec`/`sess.pk_aut`)
/// rather than the fixed command — otherwise a DECIPHER on an MSE-repointed AUT
/// key would enforce only the DEC key's touch policy, and vice-versa.
pub(crate) fn slot_uif(pk: KeyFid) -> u16 {
    if pk == EF_PK_SIG {
        EF_UIF_SIG
    } else if pk == EF_PK_AUT {
        EF_UIF_AUT
    } else {
        EF_UIF_DEC
    }
}

/// The public-key DO (`EF_PB_*`) for a private key slot — the layout invariant
/// is public-key DO FID = private slot FID + 3.
pub(crate) fn slot_pub_fid(pk: KeyFid) -> u16 {
    if pk == EF_PK_SIG {
        EF_PB_SIG
    } else if pk == EF_PK_AUT {
        EF_PB_AUT
    } else {
        EF_PB_DEC
    }
}

/// The algorithm-attribute EF for a private key slot — `EF_ALGO_PRIV{1,2,3}`
/// sits 0x10 below its `EF_PK_*` FID.
pub(crate) fn slot_algo_fid(pk: KeyFid) -> u16 {
    pk.get() - 0x10
}

/// The private companion EF of a C1/C2/C3 algorithm-attribute tag:
/// `EF_ALGO_PRIV{1,2,3}` = `0x1000 | tag`.
pub(crate) fn algo_tag_to_priv(tag: u16) -> u16 {
    0x1000 | tag
}

// Control-reference template tags (GENERATE / IMPORT) naming the key slot.
pub const CRT_SIG: u8 = 0xB6;
pub const CRT_DEC: u8 = 0xB8;
pub const CRT_AUT: u8 = 0xA4;

/// OpenPGP CRT tag selecting the key slot.
pub(crate) fn crt_slot(tag: u8) -> Option<KeyFid> {
    match tag {
        CRT_SIG => Some(EF_PK_SIG),
        CRT_DEC => Some(EF_PK_DEC),
        CRT_AUT => Some(EF_PK_AUT),
        _ => None,
    }
}
pub const EF_KEY_INFO: u16 = 0x00de; // S
pub const EF_KDF: u16 = 0x00f9; // C — KDF parameters
pub const EF_ALGO_INFO: u16 = 0x00fa; // C — algorithm info
pub const EF_LANG_PREF: u16 = 0x5f2d; // S
pub const EF_SEX: u16 = 0x5f35; // S
pub const EF_URI_URL: u16 = 0x5f50; // S
pub const EF_HIST_BYTES: u16 = 0x5f52; // S — historical bytes
pub const EF_CH_CERT: u16 = 0x7f21; // C
pub const EF_EXLEN_INFO: u16 = 0x7f66; // C — extended length info
pub const EF_GFM: u16 = 0x7f74; // C
pub const EF_PRIV_DO_1: u16 = 0x0101;
pub const EF_PRIV_DO_2: u16 = 0x0102;
pub const EF_PRIV_DO_3: u16 = 0x0103;
pub const EF_PRIV_DO_4: u16 = 0x0104;

// ---------------- PIN modes (VERIFY/CHANGE P2) ----------------
pub const PW1_MODE81: u8 = 0x81; // user PIN, signing
pub const PW1_MODE82: u8 = 0x82; // user PIN, other ops (PW2)
pub const PW3_MODE83: u8 = 0x83; // admin PIN

// ---------------- Sizes / fixed parameters ----------------
pub const IV_SIZE: usize = 16;
/// The sealed DEK plaintext is a 16-byte IV followed by the 32-byte key,
/// so it is 48 bytes (NOT 32).
pub const DEK_SIZE: usize = IV_SIZE + 32;
/// Sealed-blob size: 12-byte GCM nonce + ciphertext + 16-byte tag.
pub const fn pin_kdf_size(plaintext: usize) -> usize {
    12 + plaintext + 16
}
/// The wrapped DEK blob (76 bytes).
pub const DEK_AAD_SIZE: usize = pin_kdf_size(DEK_SIZE);
/// Format byte + wrapped DEK blob (77 bytes).
pub const DEK_FILE_SIZE: usize = 1 + DEK_AAD_SIZE;
/// Format-version byte at offset 0 of every wrapped-DEK record.
pub const DEK_FORMAT_V3: u8 = 0x03;
/// Format byte of a PIN verifier record `[len, 0x01, verifier(32)]`.
pub const PIN_FORMAT_V1: u8 = 0x01;
/// Default retry counters (PW1, RC, PW3) initialised by the applet.
pub const PW_RETRIES_DEFAULT: u8 = 3;
/// EF_PW_PRIV mirrors DO C4: `[flag, max-len ×3, retry PW1/RC/PW3]`. The PIN
/// fid's low nibble is its 1-based slot (also the EF_PW_RETRIES index).
pub const fn pw_retry_idx(fid: u16) -> usize {
    3 + (fid & 0xf) as usize
}
pub const PW1_RETRY_IDX: usize = pw_retry_idx(EF_PW1);
pub const PW3_RETRY_IDX: usize = pw_retry_idx(EF_PW3);
/// Default user PIN `123456`, admin PIN `12345678` (the OpenPGP defaults).
pub const PW1_DEFAULT: &[u8] = &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36];
pub const PW3_DEFAULT: &[u8] = &[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];
/// Reference-value length limits (OpenPGP 3.4 §4.2): PW1 at least 6, PW3 and the
/// resetting code at least 8. The maximum is the one DO C4 advertises — it is
/// `PW_STATUS_DEFAULT`'s max-length byte, so the card cannot refuse what it offers.
pub const PW1_MIN_LEN: usize = 6;
pub const PW3_MIN_LEN: usize = 8;
pub const PIN_MAX_LEN: usize = 127;
