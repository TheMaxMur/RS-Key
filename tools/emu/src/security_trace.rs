// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! JSONL writer for the phase-4 formal trace gate. Only non-secret raw fields
//! cross this boundary; β and γ live outside the emulator.

use std::fs::File;
use std::io::{BufWriter, Result, Write};
use std::path::Path;

use rsk_device::SecurityTraceSnapshot;
use rsk_fido::AbstractTokenState;

pub struct Writer {
    out: BufWriter<File>,
    sequence: u64,
}

impl Writer {
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            out: BufWriter::new(File::create(path)?),
            sequence: 0,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &mut self,
        now_ms: u64,
        cid: u32,
        command: u8,
        status: u8,
        pre: SecurityTraceSnapshot,
        post: SecurityTraceSnapshot,
        abstract_pre: AbstractTokenState,
        abstract_post: AbstractTokenState,
    ) -> Result<()> {
        self.sequence += 1;
        write!(
            self.out,
            "{{\"schema\":2,\"sequence\":{},\"boundary\":{{\"mode\":\"coarse\",\"k\":8}},\"now_ms\":{},\"cid\":{},\"command_raw\":{},\"status_raw\":{},\"outcome_raw\":{},\"action_hint\":\"{}\",\"pre\":",
            self.sequence,
            now_ms,
            cid,
            command,
            status,
            status,
            action_hint(command),
        )?;
        snapshot(&mut self.out, pre)?;
        write!(self.out, ",\"post\":")?;
        snapshot(&mut self.out, post)?;
        write!(self.out, ",\"abstract_pre\":")?;
        abstract_token(&mut self.out, abstract_pre)?;
        write!(self.out, ",\"abstract_post\":")?;
        abstract_token(&mut self.out, abstract_post)?;
        writeln!(self.out, "}}")?;
        self.out.flush()
    }
}

fn action_hint(command: u8) -> &'static str {
    match command {
        0x01 => "makeCredential",
        0x02 => "getAssertion",
        0x06 => "clientPin",
        0x07 => "reset",
        0x0a => "credentialManagement",
        0x0d => "authenticatorConfig",
        _ => "stutter",
    }
}

fn option_u8(out: &mut impl Write, value: Option<u8>) -> Result<()> {
    match value {
        Some(value) => write!(out, "{value}"),
        None => write!(out, "null"),
    }
}

fn snapshot(out: &mut impl Write, s: SecurityTraceSnapshot) -> Result<()> {
    write!(out, "{{\"pin_record_len\":")?;
    option_u8(out, s.pin_record_len)?;
    write!(out, ",\"pin_retries_raw\":")?;
    option_u8(out, s.pin_retries_raw)?;
    write!(out, ",\"always_uv_record_len\":")?;
    option_u8(out, s.always_uv_record_len)?;
    write!(out, ",\"always_uv_raw\":")?;
    option_u8(out, s.always_uv_raw)?;
    write!(
        out,
        ",\"persistent_grant_record\":{},\"backup_sealed_record\":{},\"seed_plain_record\":{},\"seed_encrypted_record\":{},\"credential_slots_raw\":{},\"rp_slots_raw\":{},\"token_in_use_raw\":{},\"token_permissions_raw\":{},\"token_has_rp_id_raw\":{},\"token_user_present_raw\":{},\"token_user_verified_raw\":{},\"soft_lock_raw\":{},\"pin_mismatches_raw\":{},\"cm_channel_raw\":{},\"cm_rp_counter_raw\":{},\"cm_rp_total_raw\":{},\"cm_cred_counter_raw\":{},\"cm_cred_total_raw\":{},\"warm_boot_raw\":{},\"channel_raw\":{},\"keydev_ram_raw\":{}}}",
        s.persistent_grant_record,
        s.backup_sealed_record,
        s.seed_plain_record,
        s.seed_encrypted_record,
        s.credential_slots_raw,
        s.rp_slots_raw,
        s.token_in_use_raw,
        s.token_permissions_raw,
        s.token_has_rp_id_raw,
        s.token_user_present_raw,
        s.token_user_verified_raw,
        s.soft_lock_raw,
        s.pin_mismatches_raw,
        s.cm_channel_raw,
        s.cm_rp_counter_raw,
        s.cm_rp_total_raw,
        s.cm_cred_counter_raw,
        s.cm_cred_total_raw,
        s.warm_boot_raw,
        s.channel_raw,
        s.keydev_ram_raw,
    )
}

fn abstract_token(out: &mut impl Write, a: AbstractTokenState) -> Result<()> {
    write!(
        out,
        "{{\"live\":{},\"permission_mc\":{},\"permission_ga\":{},\"permission_cm\":{},\"permission_acfg\":{},\"rp_bound\":{},\"pin_set\":{},\"persistent_grant\":{}}}",
        a.live,
        a.permission_mc,
        a.permission_ga,
        a.permission_cm,
        a.permission_acfg,
        a.rp_bound,
        a.pin_set,
        a.persistent_grant,
    )
}
