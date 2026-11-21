// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

use libfuzzer_sys::fuzz_target;
mod sha256_oracle;

fuzz_target!(|data: &[u8]| {
    sha256_oracle::check(data, rsk_crypto::sha256(data));
});
