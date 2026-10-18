// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use rsk_crypto::hkdf_sha256;
use rsk_sdk::error::{Error, Result};
use rsk_secret::Secret;

const STORE_DOMAIN: &[u8] = b"STORE/V2/ROOT";
const NO_OTP_SALT: &[u8] = b"NO-OTP";

#[cfg(test)]
std::thread_local! {
    pub(super) static DERIVATIONS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// The root under which one journal was authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootArm {
    PreOtp,
    Otp,
}

impl RootArm {
    pub const fn code(self) -> u8 {
        match self {
            Self::PreOtp => 0,
            Self::Otp => 1,
        }
    }

    pub fn decode(code: u8) -> Result<Self> {
        match code {
            0 => Ok(Self::PreOtp),
            1 => Ok(Self::Otp),
            _ => Err(Error::MemoryFatal),
        }
    }
}

/// An unread fused row is distinct from a readable, never-provisioned row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootRead {
    Blank,
    Fused,
    Unreadable,
}

/// Only public serial bytes and an OTP reader survive between operations.
#[derive(Clone, Copy)]
pub struct KeySource {
    serial_hash: [u8; 32],
    read: fn(&mut [u8; 32]) -> RootRead,
    latched: bool,
}

impl KeySource {
    pub const fn new(
        serial_hash: [u8; 32],
        read: fn(&mut [u8; 32]) -> RootRead,
        latched: bool,
    ) -> Self {
        Self {
            serial_hash,
            read,
            latched,
        }
    }

    pub fn current_arm(self) -> Result<RootArm> {
        let mut root = Secret::<[u8; 32]>::zeroed();
        let rows = (self.read)(root.expose_mut());
        root.wipe();
        match rows {
            RootRead::Blank if !self.latched => Ok(RootArm::PreOtp),
            RootRead::Fused => Ok(RootArm::Otp),
            RootRead::Blank | RootRead::Unreadable => Err(Error::MemoryFatal),
        }
    }

    pub fn key(self, arm: RootArm) -> Result<Secret<[u8; 32]>> {
        let mut root = Secret::<[u8; 32]>::zeroed();
        let rows = (self.read)(root.expose_mut());
        let result = self
            .validate_arm(arm, rows)
            .and_then(|()| self.derive_key(arm, root.expose()));
        root.wipe();
        result
    }

    fn validate_arm(self, arm: RootArm, rows: RootRead) -> Result<()> {
        match (arm, rows, self.latched) {
            (RootArm::PreOtp, RootRead::Blank | RootRead::Fused, false)
            | (RootArm::Otp, RootRead::Fused, _) => Ok(()),
            (RootArm::PreOtp, _, true)
            | (_, RootRead::Unreadable, _)
            | (RootArm::Otp, RootRead::Blank, _) => Err(Error::MemoryFatal),
        }
    }

    fn derive_key(self, arm: RootArm, root: &[u8; 32]) -> Result<Secret<[u8; 32]>> {
        #[cfg(test)]
        DERIVATIONS.with(|count| count.set(count.get() + 1));
        let mut key = Secret::<[u8; 32]>::zeroed();
        let result = match arm {
            RootArm::PreOtp => hkdf_sha256(
                NO_OTP_SALT,
                &self.serial_hash,
                STORE_DOMAIN,
                key.expose_mut(),
            ),
            RootArm::Otp => hkdf_sha256(&self.serial_hash, root, STORE_DOMAIN, key.expose_mut()),
        };
        result.map_err(|_| Error::MemoryFatal)?;
        Ok(key)
    }

    pub(super) fn prepare_read(
        self,
        arm: RootArm,
        needs_key: bool,
    ) -> Result<super::read_proof::ReadProof> {
        let mut root = Secret::<[u8; 32]>::zeroed();
        let rows = (self.read)(root.expose_mut());
        self.validate_arm(arm, rows)?;
        let mac = rsk_crypto::mac::HmacSha256::new(match arm {
            RootArm::PreOtp => NO_OTP_SALT,
            RootArm::Otp => root.expose(),
        });
        let key = needs_key
            .then(|| self.derive_key(arm, root.expose()))
            .transpose()?;
        root.wipe();
        Ok(super::read_proof::ReadProof {
            mac,
            key,
            serial_hash: self.serial_hash,
        })
    }
}
