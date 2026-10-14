// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

fn main() {
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    std::fs::write(out.join("memory.x"), include_bytes!("memory.x")).unwrap();
    println!("cargo:rustc-link-search={}", out.display());
    let import = std::env::var("RSK_TZ_IMPLIB").expect("build Secure first");
    println!("cargo:rustc-link-arg={import}");
    println!("cargo:rerun-if-changed={import}");
    let main = std::fs::read_to_string("../../src/main.rs").unwrap();
    let value = main
        .lines()
        .find_map(|line| line.trim().strip_prefix("let device_release: u16 = 0x"))
        .expect("firmware bcdDevice")
        .trim_end_matches(';');
    let bcd = u16::from_str_radix(value, 16).unwrap();
    std::fs::write(out.join("version.rs"), format!("// SPDX-License-Identifier: AGPL-3.0-only\n// Copyright (C) 2026 RS-Key contributors\npub const DEVICE_RELEASE: u16 = {bcd};\n")).unwrap();
    println!("cargo:rerun-if-changed=../../src/main.rs");
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-env-changed=RSK_TZ_IMPLIB");
    if std::env::var_os("CARGO_FEATURE_TEST_HOSTILE_ACCESS").is_some() {
        let address = std::env::var("RSK_TZ_PROBE_ADDRESS").expect("probe address");
        let address = u32::from_str_radix(address.trim_start_matches("0x"), 16).unwrap();
        std::fs::write(out.join("probe_address.rs"), format!("// SPDX-License-Identifier: AGPL-3.0-only\n// Copyright (C) 2026 RS-Key contributors\npub const PROBE_ADDRESS: u32 = {address};\n")).unwrap();
    }
    println!("cargo:rerun-if-env-changed=RSK_TZ_PROBE_ADDRESS");
}
