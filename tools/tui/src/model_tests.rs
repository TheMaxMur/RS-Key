// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn json_escapes_and_nulls() {
    let mut s = DeviceSnapshot::default();
    s.identity.serial = Some("ab\"cd".into());
    let j = s.to_json();
    assert!(j.contains("\"serial\":\"ab\\\"cd\""));
    assert!(j.contains("\"backup\":null"));
    assert!(j.contains("\"demo\":false"));
    // Valid-ish: balanced braces, starts/ends as object.
    assert!(j.starts_with('{') && j.ends_with('}'));
}

#[test]
fn json_str_escapes_controls_bidi_and_non_ascii() {
    // A hostile device product/version string must not smuggle DEL, an 8-bit C1
    // introducer, or a bidi override into a raw --json terminal view; every
    // control and non-ASCII char escapes to \u (astral chars as a surrogate pair).
    let out = json_str("a\u{7f}\u{9b}b\u{202e}c\u{1f600}");
    assert!(!out.contains('\u{7f}') && !out.contains('\u{9b}') && !out.contains('\u{202e}'));
    assert_eq!(out, "\"a\\u007f\\u009bb\\u202ec\\ud83d\\ude00\"");
}

#[test]
fn summary_without_device() {
    let s = DeviceSnapshot::default();
    assert_eq!(s.summary(), "no device detected");
    assert_eq!(s.overall_health(), Health::Unknown);
}

#[test]
fn security_status_classifies_health() {
    let mut s = DeviceSnapshot::default();
    s.fido.present = true;
    s.backup = Some(BackupState {
        sealed: false,
        has_seed: false,
    });
    s.lock = Some(LockState {
        locked: true,
        unlocked: false,
    });
    s.secure_boot = Some(SecureBootState {
        enabled: true,
        locked: false,
        bootkey: 1,
    });
    let rows = s.security_status();
    let by = |k: &str| rows.iter().find(|r| r.key == k).unwrap().health;
    assert_eq!(by("backup"), Health::Warn); // has_seed = false
    assert_eq!(by("seed lock"), Health::Warn); // locked, not unlocked
    assert_eq!(by("secure boot"), Health::Warn); // enabled, not locked
}

/// ATT_STATE leaves the chain hash out for a chain the device cannot read back
/// whole; that key used to show as a healthy "installed".
#[test]
fn an_org_key_without_a_chain_hash_warns_that_the_chain_is_unusable() {
    let att = |installed, chain: Option<&str>| AttestationState {
        installed,
        chain_sha256: chain.map(Into::into),
    };
    let mut s = DeviceSnapshot::default();
    for (a, health, label) in [
        (att(true, None), Health::Warn, "installed, chain unusable"),
        (att(true, Some("9f2c")), Health::Ok, "installed"),
        (att(false, None), Health::Unknown, "not installed"),
    ] {
        s.attestation = Some(a);
        let rows = s.security_status();
        let row = rows.iter().find(|r| r.key == "org attest").unwrap();
        assert_eq!((row.health, row.value.as_str()), (health, label));
    }
    s.attestation = Some(att(true, None));
    assert!(s.to_json().contains(
        "\"attestation\":{\"installed\":true,\"chain_unusable\":true,\"chain_sha256\":null}"
    ));
    s.attestation = Some(att(true, Some("9f2c")));
    assert!(s.to_json().contains(
        "\"attestation\":{\"installed\":true,\"chain_unusable\":false,\"chain_sha256\":\"9f2c\"}"
    ));
}

#[test]
fn log_redacts_known_secret_substrings() {
    let mut log = EventLog::default();
    log.push(LogLevel::Info, "pin was 1234 oops", &["1234"]);
    assert_eq!(log.iter().last().unwrap().text, "pin was [redacted] oops");
}

#[test]
fn log_is_bounded() {
    let mut log = EventLog::default();
    for i in 0..(EventLog::CAP + 50) {
        log.push(LogLevel::Info, format!("e{i}"), &[]);
    }
    assert_eq!(log.len(), EventLog::CAP);
    assert_eq!(
        log.iter().last().unwrap().text,
        format!("e{}", EventLog::CAP + 49)
    );
}
