// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `authenticatorGetInfo`: advertise the implemented surface — versions,
//! extensions, options, algorithms and limits. ML-DSA-44 is deliberately NOT in
//! `algorithms` (0x0A) by default: shipped Firefoxes (authenticator-rs before
//! 2026-06-02) hard-fail the whole getInfo parse on an unknown COSE id, while
//! makeCredential still negotiates -48 from the request's `pubKeyCredParams`;
//! the `advertise-pqc` feature opts back into the advertisement.
//!
//! EdDSA (-8), by contrast, IS advertised by default: the Windows WebAuthn API
//! (the path OpenSSH `ssh-keygen -t ed25519-sk` takes) intersects a request's
//! `pubKeyCredParams` with the advertised set and silently drops -8 when it is
//! unadvertised, so credential creation fails on Windows (it works on
//! macOS/Linux libfido2, which sends -8 directly). The `fido-conformance` feature
//! suppresses it for the FIDO conformance run (its verifySignatureCOSE can only
//! verify -7/-35/-36 self-attestations).

use minicbor::Encoder;
use minicbor::encode::{Error, Write};

use crate::consts::{
    AAGUID, ALG_EDDSA, ALG_ES256, ALG_ES384, ALG_ES512, ALG_MLDSA44, ALG_MLDSA65, FIRMWARE_VERSION,
    LARGE_BLOB_EXT, MAX_CRED_ID_LENGTH, MAX_CREDBLOB_LENGTH, MAX_CREDENTIAL_COUNT_IN_LIST,
    MAX_LARGE_BLOB_SIZE, MAX_MIN_PIN_RPIDS, MAX_MSG_SIZE,
};
use crate::cose::cose_public_key;
use crate::error::{CtapError, CtapResult};

/// Encode the getInfo response map into `out`; returns the byte length.
/// `pin_set` reflects whether a PIN is configured (`options.clientPin`);
/// `min_pin_len` / `force_change` mirror EF_MINPINLEN (0x0D / 0x0C).
///
/// `options.ep` (enterprise attestation) and `options.alwaysUv` are advertised and
/// reflect their enabled state: present-and-`false` = supported but disabled (the
/// reset default), present-and-`true` = enabled via `authenticatorConfig`
/// (`enableEnterpriseAttestation` / `toggleAlwaysUv`). Platforms (and the FIDO
/// conformance tool) only exercise those paths when the option is present. Keep in
/// sync with `metadata/rs-key.metadata.json`.
/// `builtin_uv` advertises `options.uv` (built-in user verification — the
/// trusted-display PIN pad): present only on a build that can collect a PIN on its
/// own UI, with the value tracking whether a PIN is configured. Standard (screenless)
/// keys pass `false` and the key is omitted entirely.
/// `remaining_rk` is the live free discoverable-credential count (getInfo 0x14).
// Each argument is a distinct getInfo input the caller already holds; a params
// struct would only relocate them, not reduce the surface.
#[allow(clippy::too_many_arguments)]
pub fn get_info(
    pin_set: bool,
    min_pin_len: u8,
    force_change: bool,
    ea_enabled: bool,
    always_uv: bool,
    builtin_uv: bool,
    remaining_rk: u16,
    out: &mut [u8],
) -> CtapResult {
    let mut enc = Encoder::new(minicbor::encode::write::Cursor::new(out));
    write_info(
        &mut enc,
        pin_set,
        min_pin_len,
        force_change,
        ea_enabled,
        always_uv,
        builtin_uv,
        remaining_rk,
    )
    .map_err(|_| CtapError::Other)?;
    Ok(enc.writer().position())
}

#[allow(clippy::too_many_arguments)] // mirrors get_info's distinct inputs (see above)
fn write_info<W: Write>(
    enc: &mut Encoder<W>,
    pin_set: bool,
    min_pin_len: u8,
    force_change: bool,
    ea_enabled: bool,
    always_uv: bool,
    builtin_uv: bool,
    remaining_rk: u16,
) -> Result<(), Error<W::Error>> {
    // Keys are ascending uints → CTAP canonical order (1-byte keys 0x01..0x16
    // first, then the 2-byte keys 0x1D, 0x1F). The `largeblob-ext` build drops
    // 0x0B with the command it describes.
    enc.map(19 + u64::from(!LARGE_BLOB_EXT))?;

    // 0x01 versions — advertise the full backward-compatible superset up to
    // FIDO_2_3 (the implemented surface: credMgmt, largeBlobs, credProtect,
    // minPINLength, hmac-secret-mc, thirdPartyPayment, authnrCfg,
    // pinUvAuthToken, perCredMgmtRO). CTAP minor versions add only, never break,
    // so a 2.3 device IS also a 2.0/2.1/2.2 device. The non-deprecated FIDO
    // conformance CTAP2.3 module is the target (it requires `FIDO_2_3`); the
    // deprecated 2.0 module size-checks ES512 at 64 bytes (a stale bug — P-521 is
    // 66) and omits hmac-secret-mc, both fixed in 2.1+/2.3.
    //
    // There is deliberately no `FIDO_2_2`: CTAP 2.2 never defined that string, and
    // CTAP 2.3 §6.4 spells it out — "MUST not be present in versions member". The
    // 2.2 surface is advertised through its option IDs and getInfo members instead.
    //
    // U2F_V2 (CTAP1) drops off while alwaysUv is on: §7.2.4 disables the CTAP1/U2F
    // interface (`process_u2f` refuses REGISTER/AUTHENTICATE), so getInfo must stop
    // claiming it. The conformance run is alwaysUv-off, so the list stays all five.
    // The same clause carves out the one case where it survives — "unless the
    // CTAP1/U2F authenticator is protected by a built-in user verification method",
    // i.e. a configured PIN pad, which `process_u2f` then runs on every REGISTER /
    // AUTHENTICATE. Capability alone is not enough: with no PIN set there is nothing
    // to verify against, so U2F goes away as on any screenless build.
    let u2f = !always_uv || (builtin_uv && pin_set);
    enc.u8(0x01)?.array(3 + u64::from(u2f))?;
    if u2f {
        enc.str("U2F_V2")?;
    }
    enc.str("FIDO_2_0")?.str("FIDO_2_1")?.str("FIDO_2_3")?;

    // 0x02 extensions — exactly one of the two large-blob designs (CTAP 2.3
    // §12.4 forbids both), so the list length does not change either way.
    enc.u8(0x02)?
        .array(7)?
        .str("credBlob")?
        .str("credProtect")?
        .str("hmac-secret")?
        .str(if LARGE_BLOB_EXT {
            "largeBlob"
        } else {
            "largeBlobKey"
        })?
        .str("minPinLength")?
        .str("hmac-secret-mc")?
        .str("thirdPartyPayment")?;

    // 0x03 aaguid
    enc.u8(0x03)?.bytes(&AAGUID)?;

    // 0x04 options — text keys in canonical order (length, then bytewise). "ep"
    // (enterprise attestation) sorts first among the 2-char keys; "uv" (built-in
    // user verification) sorts right after "up" (0x75 0x76 > 0x75 0x70) and is
    // present only when the build can collect a PIN on its own UI (the trusted
    // display); "alwaysUv" sorts first among the 8-char keys (before "credMgmt");
    // "perCredMgmtRO" (13) lands between "largeBlobs" (10) and "pinUvAuthToken"
    // (14); "makeCredUvNotRqd" is the longest key, so it sorts last.
    //
    // `largeBlobs` goes away entirely on a `largeblob-ext` build: §6.4 spells it
    // out — "This option MUST NOT be set to true if the largeBlob extension is
    // supported instead" — and false and absent mean the same thing here, so the
    // key is simply not emitted.
    enc.u8(0x04)?
        .map(11 + u64::from(!LARGE_BLOB_EXT) + u64::from(builtin_uv))?;
    enc.str("ep")?.bool(ea_enabled)?;
    enc.str("rk")?.bool(true)?;
    enc.str("up")?.bool(true)?;
    if builtin_uv {
        // Built-in UV verifies the same EF_PIN as clientPIN, so `true` = a PIN is
        // configured (ready), `false` = supported but not yet configured.
        enc.str("uv")?.bool(pin_set)?;
    }
    enc.str("alwaysUv")?.bool(always_uv)?;
    enc.str("credMgmt")?.bool(true)?;
    enc.str("authnrCfg")?.bool(true)?;
    enc.str("clientPin")?.bool(pin_set)?;
    if !LARGE_BLOB_EXT {
        enc.str("largeBlobs")?.bool(true)?;
    }
    // perCredMgmtRO (CTAP 2.2 §6.4): the `pcmr` permission may be requested, which
    // hands the platform the persistent pinUvAuthToken for read-only credential
    // management. Without this key §6.5.5.7.2/.3 require refusing `pcmr` outright.
    enc.str("perCredMgmtRO")?.bool(true)?;
    enc.str("pinUvAuthToken")?.bool(true)?;
    enc.str("setMinPINLength")?.bool(true)?;
    // makeCredUvNotRqd (§6.1.2 steps 7/10): a NON-discoverable credential may be
    // created with user presence only even while a PIN is set — what a real
    // YubiKey does, and what `userVerification: "discouraged"` relying parties
    // need (issue #51). Discoverable credentials still force UV, and so does
    // alwaysUv — which §6.4 requires the *advertisement* to reflect: "If the
    // alwaysUv option ID is present and true the authenticator MUST set the value
    // of makeCredUvNotRqd to false." §6.11.2 makes clearing it a step of
    // toggleAlwaysUv, which this device advertises (0x1F below).
    enc.str("makeCredUvNotRqd")?.bool(!always_uv)?;

    // 0x05 maxMsgSize
    enc.u8(0x05)?.u64(MAX_MSG_SIZE)?;

    // 0x06 pinUvAuthProtocols (protocol two preferred, then one).
    enc.u8(0x06)?.array(2)?.u8(2)?.u8(1)?;

    // 0x07 maxCredentialCountInList
    enc.u8(0x07)?.u64(MAX_CREDENTIAL_COUNT_IN_LIST)?;

    // 0x08 maxCredentialIdLength
    enc.u8(0x08)?.u64(MAX_CRED_ID_LENGTH)?;

    // 0x09 transports — the FIDO interface is reachable over USB-HID only. (The
    // device also presents a PC/SC smartcard interface, but the FIDO applet is on
    // HID, so the FIDO transport list is just "usb".)
    enc.u8(0x09)?.array(1)?.str("usb")?;

    // 0x0A algorithms — ES256 (-7), ES384 (-35), ES512 (-36), then EdDSA (-8).
    // `advertise-pqc` prepends ML-DSA-44 (off by default: shipped Firefoxes reject
    // the whole getInfo on an unknown COSE id).
    //
    // EdDSA (-8) is advertised by DEFAULT. Platforms that intersect a credential
    // request's `pubKeyCredParams` with the advertised set — notably the Windows
    // WebAuthn API (`webauthn.dll`), the path OpenSSH `ssh-keygen -t ed25519-sk`
    // takes — silently drop -8 when it is unadvertised, so the create fails
    // (macOS/Linux libfido2 sends -8 directly, so it works there). The
    // `fido-conformance` feature suppresses it: the FIDO conformance tool's shared
    // verifySignatureCOSE maps only -7/-35/-36 for elliptic curves, so it throws
    // "hashFunction missing" verifying a packed EdDSA self-attestation
    // (MakeCred-Resp P-06).
    //
    // ES256K (-47) stays unadvertised in EVERY profile for the same P-06 reason.
    // Both -8 and -47 remain fully implemented — makeCredential negotiates them
    // from a request regardless of advertisement (like ML-DSA-44). Keep the
    // advertised set in sync with the metadata (`authenticationAlgorithms` +
    // `authenticatorGetInfo.algorithms`); `tests/62` enforces it, and
    // `metadata/rs-key.conformance.metadata.json` is the EdDSA-free variant for
    // the `fido-conformance` build.
    let pqc = cfg!(feature = "advertise-pqc");
    let eddsa = cfg!(not(feature = "fido-conformance"));
    // Under `advertise-pqc` both ML-DSA sets are advertised, -65 (-49) before -44
    // (-48) so a relying party that ranks by list order prefers the stronger set.
    enc.u8(0x0A)?
        .array(3 + 2 * u64::from(pqc) + u64::from(eddsa))?;
    if pqc {
        cose_public_key(enc, ALG_MLDSA65)?;
        cose_public_key(enc, ALG_MLDSA44)?;
    }
    cose_public_key(enc, ALG_ES256)?;
    cose_public_key(enc, ALG_ES384)?;
    cose_public_key(enc, ALG_ES512)?;
    if eddsa {
        cose_public_key(enc, ALG_EDDSA)?;
    }

    // 0x0B maxSerializedLargeBlobArray — describes the array the
    // `authenticatorLargeBlobs` command serves, so it goes with that command.
    // §12.4 defines no equivalent ceiling for the extension: an over-long write
    // is answered by `written: false`, not by a published limit.
    if !LARGE_BLOB_EXT {
        enc.u8(0x0B)?.u64(MAX_LARGE_BLOB_SIZE as u64)?;
    }

    // 0x0C forceChangePin (EF_MINPINLEN[1]); enforced at token issuance (clientpin).
    enc.u8(0x0C)?.bool(force_change)?;

    // 0x0D minPINLength (EF_MINPINLEN[0], default MIN_PIN_LENGTH)
    enc.u8(0x0D)?.u8(min_pin_len)?;

    // 0x0E firmwareVersion
    enc.u8(0x0E)?.u32(FIRMWARE_VERSION)?;

    // 0x0F maxCredBlobLength
    enc.u8(0x0F)?.u64(MAX_CREDBLOB_LENGTH as u64)?;

    // 0x10 maxRPIDsForSetMinPINLength — how many RP-id hashes setMinPINLength's
    // minPinLengthRPIDs list accepts.
    enc.u8(0x10)?.u8(MAX_MIN_PIN_RPIDS as u8)?;

    // 0x14 remainingDiscoverableCredentials — live estimate of free resident-key
    // slots (capacity minus the occupied EF_CRED slots), supplied by the caller.
    enc.u8(0x14)?.u16(remaining_rk)?;

    // 0x16 attestationFormats — the attestation statement formats we emit. Only
    // "packed": makeCredential always carries basic attestation with the device x5c,
    // and an enterprise request swaps in the org chain. Keep in sync with the
    // metadata statements.
    enc.u8(0x16)?.array(1)?.str("packed")?;

    // 0x1D maxPINLength — max PIN length in Unicode code points. The PIN is padded
    // to 64 bytes on the wire, so the content is at most 63. A 2-byte CBOR key
    // (29 > 23), so it sorts after the 1-byte keys but before 0x1F → canonical.
    enc.u8(0x1D)?.u8(crate::clientpin::MAX_PIN_LENGTH as u8)?;

    // 0x1F authenticatorConfigCommands — the authenticatorConfig (0x0D) subcommands
    // we support: enableEnterpriseAttestation (0x01), toggleAlwaysUv (0x02),
    // setMinPINLength (0x03) and vendorPrototype (0xFF). The FIDO conformance
    // AuthenticatorConfig suite requires this member (its EA-enable test asserts the
    // array contains 0x01, the featureful profile requires 0x02, and its `before`
    // reads it). A 2-byte CBOR key (31 > 23), so it sorts after all 1-byte keys →
    // still canonical. Keep in sync with the metadata statement
    // (`authenticatorGetInfo.authenticatorConfigCommands`).
    //
    // 0xFF is listed because §6.11.7 says it must be: "authenticatorConfigCommands
    // MUST contain an array member with the value 0xFF if this subcommand is
    // supported", and `config.rs` implements it — it is the phy/soft-lock config arm
    // `docs/protocol.md` §9 publishes for PicoForge. Omitting it told a platform the
    // arm was absent while the wire spec documented it. Not an obscurity measure
    // either way: §6.11.7 also says "Vendors MUST NOT count on obscurity of the
    // vendorCommandId value as any sort of security", and the arm needs an `acfg`
    // token regardless. 0x15 (vendorPrototypeConfigCommands — *which* vendor command
    // ids exist) stays unadvertised; that member is optional and a YubiKey hides it.
    enc.u8(0x1F)?
        .array(4)?
        .u8(0x01)?
        .u8(0x02)?
        .u8(0x03)?
        .u8(0xFF)?;

    // 0x15 (vendorPrototypeConfigCommands) is never advertised; a real YubiKey
    // hides it too, so the default Yubikey5 VID/PID stays consistent.
    Ok(())
}

#[cfg(test)]
#[path = "getinfo_tests.rs"]
mod tests;
