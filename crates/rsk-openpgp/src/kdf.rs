// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! PUT DATA KDF (`0xF9` → `EF_KDF`): the KDF-DO of OpenPGP Card 3.4 §4.4.4.5 and
//! the PW1/PW3 re-seed it carries.
//!
//! `gpg`'s `kdf-setup` writes this DO and from then on sends the KDF *output* as
//! the password on every VERIFY — it issues no CHANGE REFERENCE DATA of its own
//! (`g10/card-util.c::kdf_setup`), so the card is the only party that can move
//! the references. The DO's tags `87`/`88` carry the hashes of the two factory
//! passwords for exactly that purpose. A card that stored the DO and nothing else
//! answered `63Cx` to both references until they blocked (#104).

use zeroize::Zeroize;

use rsk_crypto::Device;
use rsk_fs::{Fs, Storage};
use rsk_sdk::Sw;

use crate::Rng;
use crate::consts::*;
use crate::pin::{self, Session};

/// `81 01 00` — "KDF off", what `init` seeds a factory card with and what
/// `kdf-setup off` sends.
const KDF_OFF: &[u8] = &[0x81, 0x01, 0x00];

/// One `tag length value` field of the DO: `(offset, tag, value length)`.
type Field = (usize, u8, usize);

/// Initial PW1 / PW3 hashes — the two fields the card acts on. The rest of the
/// DO describes a computation the *host* performs, and is stored verbatim.
const TAG_PW1_HASH: u8 = 0x87;
const TAG_PW3_HASH: u8 = 0x88;

/// `kdf-setup single`: one salt, shared by PW1 and PW3.
const SINGLE_SALT: [Field; 6] = [
    (0, 0x81, 1),  // KDF algorithm
    (3, 0x82, 1),  // hash algorithm
    (6, 0x83, 4),  // iteration count
    (12, 0x84, 8), // salt, PW1
    (22, TAG_PW1_HASH, 32),
    (56, TAG_PW3_HASH, 32),
];

/// A bare `kdf-setup`: a salt each for PW1, the resetting code and PW3.
const THREE_SALTS: [Field; 8] = [
    (0, 0x81, 1),
    (3, 0x82, 1),
    (6, 0x83, 4),
    (12, 0x84, 8), // salt, PW1
    (22, 0x85, 8), // salt, resetting code
    (32, 0x86, 8), // salt, PW3
    (42, TAG_PW1_HASH, 32),
    (76, TAG_PW3_HASH, 32),
];

/// The body length a layout describes. `gpg`'s `gen_kdf_data` emits fixed-width
/// fields, which is what lets the DO be validated by a table of offsets at all —
/// so the table and the length it accepts must be one number, not two.
const fn layout_len(layout: &[Field]) -> usize {
    let (off, _, len) = layout[layout.len() - 1];
    off + 2 + len
}
const SINGLE_SALT_LEN: usize = layout_len(&SINGLE_SALT);
const THREE_SALTS_LEN: usize = layout_len(&THREE_SALTS);
// `gpg`'s KDF_DATA_LENGTH_MIN / _MAX. Named here so a mis-typed offset above is a
// build failure rather than a DO this card takes and `gpg` never sends.
const _: () = assert!(SINGLE_SALT_LEN == 90 && THREE_SALTS_LEN == 110);

/// What a `PUT DATA F9` body asks the card to become.
enum Setting<'a> {
    /// KDF off: the references go back to the raw factory passwords.
    Off,
    /// KDF on: PW1 and PW3 become these hashes of the factory passwords.
    On { pw1: &'a [u8], pw3: &'a [u8] },
}

/// Validate a KDF-DO body and pick out the two initial hashes.
///
/// The three shapes `gpg` produces and nothing else — the DO is a fixed layout,
/// not a TLV stream to walk, and a body that only *resembles* one would re-seed
/// both references from bytes at guessed offsets. Gnuk's `rw_kdf` gates on the
/// same table; this also checks the length bytes, which cost nothing to compare
/// and are the half that says the field is the width the table claims.
fn parse(data: &[u8]) -> Option<Setting<'_>> {
    // Stricter than Gnuk in the one direction that cannot cost anything: it takes
    // an empty body as the DO's delete and drops the keystrings, i.e. an empty
    // PUT DATA `F9` silently returns both references to `123456` / `12345678`.
    // `gpg` never sends one — `kdf-setup off` is these three bytes — so refusing
    // it costs no host and removes a PIN reset a DO-clearing loop could trip.
    if data == KDF_OFF {
        return Some(Setting::Off);
    }
    let layout: &[Field] = match data.len() {
        SINGLE_SALT_LEN => &SINGLE_SALT,
        THREE_SALTS_LEN => &THREE_SALTS,
        _ => return None,
    };
    let mut pw1 = None;
    let mut pw3 = None;
    for &(off, tag, len) in layout {
        if *data.get(off)? != tag || *data.get(off + 1)? != len as u8 {
            return None;
        }
        let value = data.get(off + 2..off + 2 + len)?;
        match tag {
            TAG_PW1_HASH => pw1 = Some(value),
            TAG_PW3_HASH => pw3 = Some(value),
            _ => {}
        }
    }
    Some(Setting::On {
        pw1: pw1?,
        pw3: pw3?,
    })
}

/// Whether any private-key slot holds a key.
///
/// `try_has_key`, never `has_key`: a probe the medium could not answer must not
/// read as an empty slot here, or one faulted read would let the re-seed below
/// put the factory passwords back beside a live key.
fn any_key_present<S: Storage>(fs: &mut Fs<S>) -> Result<bool, Sw> {
    for slot in [EF_PK_SIG, EF_PK_DEC, EF_PK_AUT] {
        if fs.try_has_key(slot).map_err(|_| Sw::MEMORY_FAILURE)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// PUT DATA KDF (`0xF9` → `EF_KDF`): store the DO and move PW1/PW3 to the
/// reference values it declares. Requires PW3, like every other DO the admin
/// owns.
pub fn put_kdf<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &mut Session,
    rng: &mut dyn Rng,
    data: &[u8],
) -> Sw {
    if !sess.has_pw3 {
        return Sw::SECURITY_STATUS_NOT_SATISFIED;
    }
    let Some(setting) = parse(data) else {
        return Sw::WRONG_DATA;
    };
    // Gnuk's `rw_kdf` guard ("KDF DO can be changed only when no keys are
    // registered") and a YubiKey's, which answers `6985` here — "once a key has
    // been placed … any changes to the KDF settings will be prevented". The write
    // returns BOTH references to the values the DO names, which on a card that
    // already holds keys would hand `123456` to whoever asks for it next.
    match any_key_present(fs) {
        Ok(true) => return Sw::CONDITIONS_NOT_SATISFIED,
        Err(sw) => return sw,
        Ok(false) => {}
    }
    let (pw1, pw3): (&[u8], &[u8]) = match setting {
        Setting::Off => (PW1_DEFAULT, PW3_DEFAULT),
        Setting::On { pw1, pw3 } => (pw1, pw3),
    };
    // One open for both copies: `EF_DEK_PW1` and `EF_DEK_PW3` hold the same key.
    let mut dek = [0u8; DEK_SIZE];
    if let Err(sw) = pin::load_dek(dev, fs, sess, &mut dek) {
        // `decrypt_with_aad` writes the plaintext before it checks the tag, so a
        // refused open can still have left the DEK in this buffer.
        dek.zeroize();
        return sw;
    }
    let result = (|| {
        // Order is the tear budget. Every step is its own append, and no order
        // avoids a window where the DO and the verifiers disagree — a host reads
        // the DO to learn which of the two passwords to send. PW3 leads the
        // references so that window is one append wide: once the DO and PW3 agree,
        // the admin can simply re-run the command and the rest heals.
        fs.put(EF_KDF, data).map_err(|_| Sw::MEMORY_FAILURE)?;
        let pw3_session = pin::reseed_pin(dev, fs, rng, EF_PW3, pw3, &dek)?;
        let pw1_session = pin::reseed_pin(dev, fs, rng, EF_PW1, pw1, &dek)?;
        // The DO carries a salt for the resetting code (tag `85`) but no initial
        // hash for it, so an RC set under the old regime can only be deactivated —
        // `gpg` would send its KDF output to a verifier holding the raw value.
        pin::clear_reset_code(fs, sess)?;
        Ok((pw1_session, pw3_session))
    })();
    dek.zeroize();
    match &result {
        // The access statuses stand, as they do on a YubiKey; only the session
        // keys they carry are replaced. See `Session::adopt_reseeded`.
        Ok((pw1_session, pw3_session)) => {
            sess.adopt_reseeded(pw1_session, pw3_session);
            Sw::OK
        }
        // A failure can have landed some of the records and not others, so which
        // password each standing session key opens is exactly what is no longer
        // known. Drop them rather than leave one authorising work it cannot do.
        Err(sw) => {
            sess.has_pw1 = false;
            sess.has_pw2 = false;
            sess.has_pw3 = false;
            *sw
        }
    }
}

#[cfg(test)]
#[path = "kdf_tests.rs"]
mod tests;
