// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Bakes the FIDO2 AAGUID into the build. The fixed-base comb tables `ec.rs`
//! used to generate here now live in the shared `rsk-ec` crate.

use std::env;

fn main() {
    println!("cargo:rustc-env=PK_AAGUID={}", resolve_aaguid());
    println!("cargo:rerun-if-env-changed=AAGUID");
    println!("cargo:rerun-if-changed=build.rs");
}

/// Resolve the FIDO2 AAGUID: `AAGUID=<uuid-or-32-hex>` overrides the default
/// UUIDv5, returned as a bare 32-char lowercase-hex string for `consts.rs` to
/// const-parse into `[u8; 16]`. The default is
/// `uuid5(NAMESPACE_URL, "https://github.com/TheMaxMur/RS-Key")`. A build sets ONE
/// AAGUID for all its VID/PID flavors — the value identifies the firmware model,
/// not the USB branding (see consts.rs).
fn resolve_aaguid() -> String {
    const DEFAULT: &str = "2479c7bf-6b30-5683-9ec8-0e8171a918b7";
    let raw = env::var("AAGUID").unwrap_or_else(|_| DEFAULT.to_string());
    let hex = raw
        .chars()
        .filter(|&c| c != '-')
        .collect::<String>()
        .to_lowercase();
    assert!(
        hex.len() == 32 && hex.bytes().all(|b| b.is_ascii_hexdigit()),
        "AAGUID={raw:?} must be a UUID or 32 hex chars (16 bytes)"
    );
    hex
}
