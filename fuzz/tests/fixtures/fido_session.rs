// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

// Encoded independently with python-fido2; local test token 0x99 and CDH 0xCD.
const REGISTER: &[u8] = &[
    0x01, 0xa7, 0x01, 0x58, 0x20, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
    0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
    0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0x02, 0xa1, 0x62, 0x69, 0x64, 0x64, 0x61, 0x2e, 0x63, 0x6f, 0x03,
    0xa2, 0x62, 0x69, 0x64, 0x41, 0x09, 0x64, 0x6e, 0x61, 0x6d, 0x65, 0x64, 0x6e, 0x65, 0x78, 0x74,
    0x04, 0x81, 0xa2, 0x63, 0x61, 0x6c, 0x67, 0x26, 0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70, 0x75,
    0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79, 0x07, 0xa1, 0x62, 0x72, 0x6b, 0xf5, 0x08, 0x58,
    0x20, 0x44, 0xd0, 0xfd, 0x3b, 0xb3, 0x89, 0xb2, 0x79, 0x8f, 0x8a, 0x74, 0x42, 0xa4, 0xe8, 0xe3,
    0x54, 0x4b, 0x63, 0x54, 0x7b, 0xa3, 0x6c, 0xbe, 0x22, 0x9b, 0xc1, 0xfd, 0x6c, 0x44, 0x45, 0xaa,
    0x75, 0x09, 0x02,
];

const DISCOVER: &[u8] = &[
    0x02, 0xa4, 0x01, 0x64, 0x61, 0x2e, 0x63, 0x6f, 0x02, 0x58, 0x20, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
    0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
    0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0x05, 0xa1, 0x62, 0x75, 0x70,
    0xf4, 0x08, 0x06,
];

pub(crate) fn assertion_capacity(index: u8) -> Vec<u8> {
    let mut short = DISCOVER.to_vec();
    *short.last_mut().unwrap() = index;
    let mut input = vec![20];
    for command in [
        REGISTER,
        DISCOVER,
        &[8, index],
        &[8, 6],
        &[8, 6],
        &short,
        DISCOVER,
    ] {
        input.extend_from_slice(&u16::try_from(command.len()).unwrap().to_be_bytes());
        input.extend_from_slice(command);
    }
    input
}

// The `TOK1` route: magic, then variant / protocol / extra permissions / rpId
// binding. Each literal names the transition it drives in `fido_session_token.rs`.

/// Variant 0, protocol 2, no rpId: makeCredential spends mc|lbw; a second
/// makeCredential, a getAssertion, credentialManagement and authenticatorConfig
/// are then refused 0x33, the residual largeBlobWrite still commits, and only an
/// explicit reissue restores a usable getAssertion token.
pub(crate) const TOKEN_SPEND_MC: &[u8] = b"TOK1\x00\x00\x00\x00";

/// Variant 0, protocol 1, rpId-bound: the same spend under protocol 1 with an
/// rpId binding on the token.
pub(crate) const TOKEN_SPEND_MC_PROTO1_BOUND: &[u8] = b"TOK1\x00\x01\x00\x01";

/// Variant 1, protocol 2, rpId-bound: a getAssertion spend refreshes the usage
/// timer; the largeBlobWrite 25 s later is still inside the rolling window.
pub(crate) const TOKEN_RESIDUAL_LBW: &[u8] = b"TOK1\x01\x00\x00\x01";

/// Variant 2, protocol 2: an rp-A-bound makeCredential token refuses an rp-B
/// ceremony with 0x33 without spending, then succeeds for rp A.
pub(crate) const TOKEN_RP_REFUSAL: &[u8] = b"TOK1\x02\x00\x00\x01";

/// Variant 3, protocol 2: a non-consuming use 29 999 ms after issuance still
/// works and refreshes the timer; 30 000 ms after that use the getAssertion is
/// refused, and a fresh issuance works.
pub(crate) const TOKEN_INACTIVITY_EXPIRY: &[u8] = b"TOK1\x03\x00\x00\x00";

/// The fuzzer-found regression: a mutated rp-binding byte on the inactivity
/// variant. A scoped token cannot use the rp-less CM metadata refresh, so the
/// route keeps that probe unscoped; the timer transition must still hold.
pub(crate) const TOKEN_INACTIVITY_MUTATED_RP: &[u8] = b"TOK1\x03\xff\x02\x01";

/// Variant 4, protocol 2: 600 s from issuance retires the token under 20 s
/// credentialManagement refreshes; the stale getAssertion is refused and a fresh
/// issuance works.
pub(crate) const TOKEN_ABSOLUTE_EXPIRY: &[u8] = b"TOK1\x04\x00\x00\x00";

/// Variant 5, protocol 1: authenticatorReset clears the token; the pre-reset
/// getAssertion is refused, a new setPIN + issuance succeeds, and a new
/// makeCredential proves it.
pub(crate) const TOKEN_RESET_REVOCATION: &[u8] = b"TOK1\x05\x01\x00\x00";

/// Variant 6, protocol 2: a wrong-PIN token request revokes the standing token;
/// the old getAssertion is refused and a fresh issuance works.
pub(crate) const TOKEN_WRONG_PIN_REVOCATION: &[u8] = b"TOK1\x06\x00\x00\x00";

/// Variant 7, protocol 1: a ga-only token refuses mc and cm with 0x33 without
/// spending, spends on ga, refuses a second ga, then an explicit reissue works
/// and a cm-only token reaches credentialManagement but not getAssertion.
pub(crate) const TOKEN_REISSUE_AFTER_REFUSAL: &[u8] = b"TOK1\x07\x01\x00\x00";
/// Variant 7, protocol 2: the same permission-mask and reissue transitions.
pub(crate) const TOKEN_REISSUE_AFTER_REFUSAL_PROTO2: &[u8] = b"TOK1\x07\x00\x00\x00";

/// Variant 0 with cm|acfg added by byte 2: the token carries the extra requested
/// permissions (both pre-spend checks succeed), then the spend still clears them.
pub(crate) const TOKEN_SPEND_EXTRA_PERMS: &[u8] = b"TOK1\x00\x00\x24\x00";

pub(crate) const TOKEN_SEEDS: &[&[u8]] = &[
    TOKEN_SPEND_MC,
    TOKEN_SPEND_MC_PROTO1_BOUND,
    TOKEN_RESIDUAL_LBW,
    TOKEN_RP_REFUSAL,
    TOKEN_INACTIVITY_EXPIRY,
    TOKEN_INACTIVITY_MUTATED_RP,
    TOKEN_ABSOLUTE_EXPIRY,
    TOKEN_RESET_REVOCATION,
    TOKEN_WRONG_PIN_REVOCATION,
    TOKEN_REISSUE_AFTER_REFUSAL,
    TOKEN_REISSUE_AFTER_REFUSAL_PROTO2,
    TOKEN_SPEND_EXTRA_PERMS,
];
