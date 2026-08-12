// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The CTAP 2.3 §12.4 `largeBlob` **extension**: the whole blob rides inside the
//! `authenticatorGetAssertion` that reads or writes it, and is stored per
//! credential rather than in one platform-managed array. §12.4 is explicit —
//! "Authenticators MUST NOT support both extensions" — so this and the CTAP 2.1
//! pair (`largeBlobKey` + `authenticatorLargeBlobs`) are alternatives, chosen at
//! build time by [`crate::consts::LARGE_BLOB_EXT`].
//!
//! At rest a blob is `iv(12) ‖ ChaCha20-Poly1305(originalSize_le(4) ‖ blob) ‖
//! tag(16)` in `EF_CRED_BLOB + slot`, keyed off the device seed with the
//! credential's resident id as AAD. The seal is this device's addition, not the
//! spec's: the 2.1 array reaches the authenticator already encrypted by the
//! platform under the largeBlobKey, whereas a 2.3 blob arrives as compressed
//! *plaintext*, so without this it would sit readable in a flash dump. The AAD
//! doubles as the slot-reuse guard — a record left by a previous owner of the
//! slot fails to open rather than being served to the new credential.
//!
//! Both outputs go in `unsignedExtensionOutputs` (response `0x06` on
//! makeCredential, `0x08` on getAssertion), which is what §12.4 requires so the
//! RP-observable behaviour matches the 2.1 style.

use minicbor::encode::{Error, Write};
use minicbor::{Decoder, Encoder};
use rsk_crypto::{chacha20poly1305_decrypt, chacha20poly1305_encrypt};
use rsk_fs::{Fs, Storage};
use zeroize::Zeroize;

use crate::cbordec::def_map;
use crate::consts::{EF_CRED_BLOB, MAX_LARGE_BLOB_SIZE};
use crate::credential::{CRED_RESIDENT_LEN, IV_LEN, TAG_LEN, derive_chacha_key};
use crate::error::CtapError;
use crate::{Ctx, Rng};

/// Every decode failure inside this extension's inputs is `CTAP2_ERR_INVALID_CBOR`.
/// §12.4 says so for both commands — "If the input does not conform to the given
/// CDDL, return CTAP2_ERR_INVALID_CBOR" — and a wrong *type* is a CDDL violation
/// like any other. The shared [`crate::cbordec::cbor`] helper would answer
/// `CTAP2_ERR_CBOR_UNEXPECTED_TYPE` instead, which an external CTAP 2.3
/// conformance runner rejects (large-blob F-4/F-5).
fn cddl<T>(r: Result<T, minicbor::decode::Error>) -> Result<T, CtapError> {
    r.map_err(|_| CtapError::InvalidCbor)
}

/// Derive label for the per-credential blob box — its own domain, so this key can
/// never coincide with a cred-box, rpId or nickname key.
const BLOB_PROTO: &[u8] = b"RS-Key/EF_CRED_BLOB/largeBlob";
/// `originalSize` travels with the blob: §12.4 returns it verbatim on a read,
/// "as provided when it was written".
const SIZE_LEN: usize = 4;
/// What the seal costs on top of the blob itself.
const BOX_OVERHEAD: usize = IV_LEN + SIZE_LEN + TAG_LEN;
/// Largest blob one credential can hold. Deliberately not advertised: §12.4
/// defines no getInfo field for it, and answers an over-long write with
/// `written: false` — the same thing a full store says.
pub const MAX_CRED_LARGE_BLOB: usize = MAX_LARGE_BLOB_SIZE - BOX_OVERHEAD;

/// The `largeBlob` input to `authenticatorMakeCredential`
/// (`{support: "required" / "preferred"}`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum McInput {
    #[default]
    Absent,
    Preferred,
    Required,
}

/// The `largeBlob` input to `authenticatorGetAssertion`
/// (`{? read: true, ? write: bstr, ? originalSize: uint}`).
#[derive(Clone, Copy, Debug)]
pub enum GaInput<'a> {
    Absent,
    Read,
    Write { blob: &'a [u8], original_size: u64 },
}

/// Parse the makeCredential `largeBlob` extension value. §12.4 step 1: anything
/// that does not match the CDDL is `CTAP2_ERR_INVALID_CBOR` — including a
/// `support` string outside the two the CDDL names, and an absent `support`
/// (the member is not optional).
pub fn parse_mc(d: &mut Decoder<'_>) -> Result<McInput, CtapError> {
    let n = def_map(d)?;
    let mut out = McInput::Absent;
    for _ in 0..n {
        match cddl(d.str())? {
            "support" => {
                out = match cddl(d.str())? {
                    "required" => McInput::Required,
                    "preferred" => McInput::Preferred,
                    _ => return Err(CtapError::InvalidCbor),
                }
            }
            _ => return Err(CtapError::InvalidCbor),
        }
    }
    if out == McInput::Absent {
        return Err(CtapError::InvalidCbor);
    }
    Ok(out)
}

/// Parse the getAssertion `largeBlob` extension value. §12.4 step 2 admits
/// exactly two shapes — `read` alone, or `write` **and** `originalSize` — and
/// makes every other combination `CTAP2_ERR_INVALID_CBOR`.
pub fn parse_ga<'a>(d: &mut Decoder<'a>) -> Result<GaInput<'a>, CtapError> {
    let n = def_map(d)?;
    let mut read = false;
    let mut write: Option<&'a [u8]> = None;
    let mut original_size: Option<u64> = None;
    for _ in 0..n {
        match cddl(d.str())? {
            // The CDDL pins the value to `true`; `read: false` is not a member of
            // the type, so it is malformed rather than a request for nothing.
            "read" => {
                if !cddl(d.bool())? {
                    return Err(CtapError::InvalidCbor);
                }
                read = true;
            }
            "write" => write = Some(cddl(d.bytes())?),
            "originalSize" => original_size = Some(cddl(d.u64())?),
            _ => return Err(CtapError::InvalidCbor),
        }
    }
    match (read, write, original_size) {
        (true, None, None) => Ok(GaInput::Read),
        (false, Some(blob), Some(original_size)) => Ok(GaInput::Write {
            blob,
            original_size,
        }),
        _ => Err(CtapError::InvalidCbor),
    }
}

/// Run the §12.4 getAssertion leg for the credential the assertion selected, and
/// say what (if anything) belongs in `unsignedExtensionOutputs`. `slot` is `None`
/// for a non-resident credential, which keeps no on-device record at all;
/// `named` is whether the request carried a non-empty allowList; `up` is the
/// request's raw `up` option.
///
/// The staging buffer is `lba.temp`: only a `largeblob-ext` build parses this
/// extension, and there `authenticatorLargeBlobs` is refused outright, so its
/// accumulator is idle and lending it here keeps the extension free of a second
/// multi-KiB static.
#[allow(clippy::too_many_arguments)] // the selected credential plus the three §12.4 preconditions
pub fn process_ga<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    seed: &[u8; 32],
    input: GaInput<'_>,
    cred_id: &[u8; CRED_RESIDENT_LEN],
    slot: Option<u16>,
    named: bool,
    up: bool,
) -> GaOutput {
    match input {
        GaInput::Absent => GaOutput::Silent,
        // "Fetch any largeBlob data for selected credentials. If there is none
        // then stop processing this extension" — hence Silent, not an empty map.
        GaInput::Read => match slot.and_then(|slot| read(ctx, seed, cred_id, slot)) {
            Some((at, original_size)) => GaOutput::Blob { at, original_size },
            None => GaOutput::Silent,
        },
        GaInput::Write {
            blob,
            original_size,
        } => {
            // §12.4 makes a non-empty allowList the precondition for a write: the
            // platform must NAME the credential it is overwriting rather than let
            // discovery pick one. A non-resident credential has nowhere to put it.
            //
            // Raw `up` is required too, which the spec does not spell out but its
            // step 4.2 leaves to us ("the selected credential CAN store the large
            // blob data"). A write destroys the previous blob, and an `up:false`
            // pre-flight is the platform's silent discovery probe — no gesture was
            // asked for, so nothing on the device may be overwritten by it. A read
            // on the same probe IS served, matching what the CTAP 2.1 pair already
            // discloses ungated (docs/threat-model.md).
            let written = up
                && named
                && slot.is_some_and(|slot| write(ctx, seed, cred_id, slot, blob, original_size));
            GaOutput::Written(written)
        }
    }
}

/// Seal `blob` for `cred_id` and store it in that credential's slot. Returns
/// `false` (→ `written: false`) rather than an error whenever the blob cannot be
/// kept: §12.4 defines no failure status for a write, only the flag.
pub fn write<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    seed: &[u8; 32],
    cred_id: &[u8; CRED_RESIDENT_LEN],
    slot: u16,
    blob: &[u8],
    original_size: u64,
) -> bool {
    if blob.len() > MAX_CRED_LARGE_BLOB {
        return false;
    }
    let Ok(original_size) = u32::try_from(original_size) else {
        return false;
    };
    let scratch = &mut ctx.state.lba.temp;
    // A random IV, unlike the deterministic ones `credential::seal_nick` and
    // friends derive: a blob is mutable and rewritten in place, and a getAssertion
    // has the RNG in hand, so there is no reason to accept even that module's
    // deterministic-encryption residual here.
    let mut iv = [0u8; IV_LEN];
    ctx.rng.fill(&mut iv);
    let body = SIZE_LEN + blob.len();
    scratch[..IV_LEN].copy_from_slice(&iv);
    scratch[IV_LEN..IV_LEN + SIZE_LEN].copy_from_slice(&original_size.to_le_bytes());
    scratch[IV_LEN + SIZE_LEN..IV_LEN + body].copy_from_slice(blob);
    let mut key = derive_chacha_key(seed, BLOB_PROTO);
    let tag = chacha20poly1305_encrypt(&key, &iv, cred_id, &mut scratch[IV_LEN..IV_LEN + body]);
    key.zeroize();
    scratch[IV_LEN + body..IV_LEN + body + TAG_LEN].copy_from_slice(&tag);
    let stored = ctx
        .fs
        .put(EF_CRED_BLOB + slot, &scratch[..IV_LEN + body + TAG_LEN])
        .is_ok();
    scratch[..IV_LEN + body + TAG_LEN].fill(0);
    stored
}

/// Open the credential's stored blob into the staging buffer, returning where the
/// compressed blob landed and the `originalSize` written with it. `None` when
/// there is none, when the record is malformed, or when it belongs to a previous
/// owner of the slot — the AAD is the credential id, so a stale record simply
/// fails to authenticate.
///
/// The plaintext stays in the buffer after this returns — the caller encodes the
/// response straight out of it — and is only displaced by the next blob. Same
/// call as `crate::state::LargeBlobState::reset` makes about its own accumulator:
/// these are bytes the platform handed over or is about to receive, not device
/// secrets, and the BOOTSEL drop clears SRAM anyway.
pub fn read<S: Storage, R: Rng>(
    ctx: &mut Ctx<S, R>,
    seed: &[u8; 32],
    cred_id: &[u8; CRED_RESIDENT_LEN],
    slot: u16,
) -> Option<(core::ops::Range<usize>, u32)> {
    let scratch = &mut ctx.state.lba.temp;
    let n = ctx
        .fs
        .read(EF_CRED_BLOB + slot, scratch)?
        .min(scratch.len());
    if n < BOX_OVERHEAD {
        return None;
    }
    let mut iv = [0u8; IV_LEN];
    iv.copy_from_slice(&scratch[..IV_LEN]);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&scratch[n - TAG_LEN..n]);
    let body = IV_LEN..n - TAG_LEN;
    let mut key = derive_chacha_key(seed, BLOB_PROTO);
    let ok = chacha20poly1305_decrypt(&key, &iv, cred_id, &mut scratch[body.clone()], &tag).is_ok();
    key.zeroize();
    if !ok {
        return None;
    }
    let size_at = body.start;
    let original_size = u32::from_le_bytes([
        scratch[size_at],
        scratch[size_at + 1],
        scratch[size_at + 2],
        scratch[size_at + 3],
    ]);
    Some((size_at + SIZE_LEN..body.end, original_size))
}

/// Drop a credential's blob. Called wherever the credential itself goes, and on
/// the slot a new credential is about to occupy.
pub fn discard<S: Storage>(fs: &mut Fs<S>, slot: u16) {
    let _ = fs.delete(EF_CRED_BLOB + slot);
}

/// What a completed getAssertion extension leg has to say, and therefore which
/// `unsignedExtensionOutputs` entry it writes. `Silent` is §12.4's "if there is
/// none then stop processing this extension" — the field is omitted entirely,
/// not returned empty.
#[derive(Clone, Debug)]
pub enum GaOutput {
    Silent,
    Blob {
        at: core::ops::Range<usize>,
        original_size: u32,
    },
    Written(bool),
}

impl GaOutput {
    /// Whether this leg has anything to put in `unsignedExtensionOutputs`.
    pub fn emits(&self) -> bool {
        !matches!(self, GaOutput::Silent)
    }
}

/// Write the whole `unsignedExtensionOutputs` map (makeCredential response field
/// `0x06`): `{"largeBlob": {"supported": true}}`. One entry, because this is the
/// only extension on this device with an unsigned output.
pub fn write_mc_output<W: Write>(enc: &mut Encoder<W>) -> Result<(), Error<W::Error>> {
    enc.map(1)?.str("largeBlob")?.map(1)?;
    enc.str("supported")?.bool(true)?;
    Ok(())
}

/// Write the getAssertion `unsignedExtensionOutputs` field (`0x08`) and its whole
/// map — or nothing at all, which is what §12.4's "stop processing this
/// extension" means: an omitted field, not an empty map. `scratch` is the buffer
/// [`read`] decrypted into, which `at` indexes.
pub fn write_ga_output<W: Write>(
    enc: &mut Encoder<W>,
    out: &GaOutput,
    scratch: &[u8; MAX_LARGE_BLOB_SIZE],
) -> Result<(), Error<W::Error>> {
    // Each arm opens its own field so `Silent` can write nothing at all. Opening it
    // first and matching after would need an unreachable arm — a panic parked in
    // firmware to say what the type already says.
    match out {
        GaOutput::Silent => {}
        GaOutput::Blob { at, original_size } => {
            open_ga_field(enc, 2)?;
            enc.str("blob")?.bytes(&scratch[at.clone()])?;
            enc.str("originalSize")?.u32(*original_size)?;
        }
        GaOutput::Written(written) => {
            open_ga_field(enc, 1)?;
            enc.str("written")?.bool(*written)?;
        }
    }
    Ok(())
}

/// `8: {"largeBlob": {` — the field header shared by both getAssertion outputs.
/// `entries` is how many members the extension's own map carries.
fn open_ga_field<W: Write>(enc: &mut Encoder<W>, entries: u64) -> Result<(), Error<W::Error>> {
    enc.u8(8)?.map(1)?.str("largeBlob")?.map(entries)?;
    Ok(())
}

#[cfg(test)]
#[path = "largeblobext_tests.rs"]
mod tests;
