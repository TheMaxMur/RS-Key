// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz OTP RX reports and independent TX load/poll/reload histories.

use libfuzzer_sys::fuzz_target;

mod otp_hid_oracle;

fuzz_target!(|data: &[u8]| otp_hid_oracle::replay(data));
