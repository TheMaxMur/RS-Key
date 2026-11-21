// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn wide_record_lengths_remain_numbers_in_the_snapshot_json() {
    for width in [0, 255, 256, rsk_fs::MAX_VALUE_BYTES] {
        let raw = SecurityTraceSnapshot {
            pin_record_len: Some(width),
            pin_retries_raw: None,
            always_uv_record_len: Some(width),
            always_uv_raw: None,
            persistent_grant_record: false,
            backup_sealed_record: false,
            seed_plain_record: false,
            seed_encrypted_record: false,
            credential_slots_raw: 0,
            rp_slots_raw: 0,
            token_in_use_raw: false,
            token_permissions_raw: 0,
            token_has_rp_id_raw: false,
            token_user_present_raw: false,
            token_user_verified_raw: false,
            soft_lock_raw: false,
            pin_mismatches_raw: 0,
            cm_channel_raw: 0,
            cm_rp_counter_raw: 0,
            cm_rp_total_raw: 0,
            cm_cred_counter_raw: 0,
            cm_cred_total_raw: 0,
            warm_boot_raw: false,
            channel_raw: 0,
            keydev_ram_raw: false,
        };
        let mut bytes = Vec::new();
        snapshot(&mut bytes, raw).unwrap();
        let json = String::from_utf8(bytes).unwrap();
        assert!(json.starts_with(&format!("{{\"pin_record_len\":{width},\"pin_retries_raw\":null,\"always_uv_record_len\":{width},\"always_uv_raw\":null,")));
        assert!(json.ends_with("\"keydev_ram_raw\":false}"));
    }
}
