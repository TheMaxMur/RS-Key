// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use rsk_crypto::{ct_eq, mac::HmacSha256};
use rsk_sdk::error::{Error, Result};
use rsk_secret::Secret;

use super::{Entry, authority::Bound, record::field};

const READ_DOMAIN: &[u8; 8] = b"RSKV2RD1";
const MOUNT_DOMAIN: &[u8; 8] = b"RSKV2RM1";
const FRAME_BYTES: usize = 204;
const MOUNT_FRAME_BYTES: usize = 140;

pub(super) struct ReadProof {
    pub(super) mac: HmacSha256,
    pub(super) key: Option<Secret<[u8; 32]>>,
    pub(super) serial_hash: [u8; 32],
}

impl ReadProof {
    pub(super) fn persisted_key(&self) -> Result<&[u8; 32]> {
        self.key
            .as_ref()
            .map(Secret::expose)
            .ok_or(Error::MemoryFatal)
    }

    pub(super) fn mount_tag(&self, bound: Bound) -> Result<[u8; 32]> {
        let mut frame = Secret::new([0; MOUNT_FRAME_BYTES]);
        field(frame.expose_mut(), 0, MOUNT_DOMAIN)?;
        field(frame.expose_mut(), 8, &self.serial_hash)?;
        field(frame.expose_mut(), 40, &bound.read_frame()?)?;
        Ok(self.mac.tag(frame.expose()))
    }

    pub(super) fn verify_mount(&self, bound: Bound, expected: &[u8; 32]) -> Result<()> {
        if ct_eq(&self.mount_tag(bound)?, expected) {
            Ok(())
        } else {
            Err(Error::MemoryFatal)
        }
    }

    pub(super) fn payload_tag(
        &self,
        bound: Bound,
        entry: Entry,
        digest: &[u8; 32],
    ) -> Result<[u8; 32]> {
        let mut frame = Secret::new([0; FRAME_BYTES]);
        field(frame.expose_mut(), 0, READ_DOMAIN)?;
        field(frame.expose_mut(), 8, &self.serial_hash)?;
        field(frame.expose_mut(), 40, &bound.read_frame()?)?;
        field(frame.expose_mut(), 140, &entry.encode()?)?;
        field(frame.expose_mut(), 172, digest)?;
        Ok(self.mac.tag(frame.expose()))
    }
}
