// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! WebAuthn §10.8: the factors used for this ceremony, including token provenance.

use minicbor::Encoder;
use minicbor::encode::{Error, Write};

const USER_VERIFY_PRESENCE_INTERNAL: u32 = 0x0001;
const USER_VERIFY_PASSCODE_INTERNAL: u32 = 0x0004;
const USER_VERIFY_NONE: u32 = 0x0200;
const USER_VERIFY_PASSCODE_EXTERNAL: u32 = 0x0800;
const KEY_PROTECTION_HARDWARE: u16 = 0x0002;
const MATCHER_PROTECTION_ON_CHIP: u16 = 0x0004;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Method {
    None,
    PasscodeExternal,
    PasscodeInternal,
}

pub(crate) fn write<W: Write>(
    enc: &mut Encoder<W>,
    method: Method,
    up: bool,
) -> Result<(), Error<W::Error>> {
    let verified = method != Method::None;
    enc.str("uvm")?.array(if up && verified { 2 } else { 1 })?;
    let entry = |enc: &mut Encoder<W>, factor| -> Result<(), Error<W::Error>> {
        enc.array(3)?
            .u32(factor)?
            .u16(KEY_PROTECTION_HARDWARE)?
            .u16(MATCHER_PROTECTION_ON_CHIP)?;
        Ok(())
    };
    if up {
        entry(enc, USER_VERIFY_PRESENCE_INTERNAL)?;
    }
    match method {
        Method::PasscodeExternal => entry(enc, USER_VERIFY_PASSCODE_EXTERNAL)?,
        Method::PasscodeInternal => entry(enc, USER_VERIFY_PASSCODE_INTERNAL)?,
        Method::None if !up => entry(enc, USER_VERIFY_NONE)?,
        Method::None => {}
    }
    Ok(())
}
