// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use embedded_storage_async::nor_flash::{
    ErrorType, MultiwriteNorFlash, NorFlash, NorFlashError, NorFlashErrorKind, ReadNorFlash,
};
use rsk_secret::Secret;

const READBACK_BYTES: usize = 256;

#[derive(Debug)]
pub enum VerifyError<E> {
    Flash(E),
    Mismatch,
}
impl<E: NorFlashError> NorFlashError for VerifyError<E> {
    fn kind(&self) -> NorFlashErrorKind {
        match self {
            Self::Flash(error) => error.kind(),
            Self::Mismatch => NorFlashErrorKind::Other,
        }
    }
}

#[derive(Clone)]
pub struct VerifiedFlash<F>(F);
impl<F: NorFlash> VerifiedFlash<F> {
    pub fn new(flash: F) -> Self {
        const {
            assert!(F::READ_SIZE > 0 && F::READ_SIZE <= READBACK_BYTES);
        }
        Self(flash)
    }
    async fn verify(
        &mut self,
        mut address: u32,
        len: usize,
        expected: Option<&[u8]>,
    ) -> Result<(), VerifyError<F::Error>> {
        let mut scratch = Secret::<[u8; READBACK_BYTES]>::zeroed();
        let mut done = 0;
        while done < len {
            let aligned = address - address % F::READ_SIZE as u32;
            let pad = (address - aligned) as usize;
            let take = (READBACK_BYTES / F::READ_SIZE * F::READ_SIZE - pad).min(len - done);
            let read = (pad + take).div_ceil(F::READ_SIZE) * F::READ_SIZE;
            self.0
                .read(aligned, &mut scratch.expose_mut()[..read])
                .await
                .map_err(VerifyError::Flash)?;
            let got = &scratch.expose()[pad..pad + take];
            let matches = match expected {
                Some(bytes) => bytes.get(done..done + take) == Some(got),
                None => got.iter().all(|&byte| byte == 0xFF),
            };
            if !matches {
                return Err(VerifyError::Mismatch);
            }
            done += take;
            address = address
                .checked_add(take as u32)
                .ok_or(VerifyError::Mismatch)?;
        }
        Ok(())
    }
}
impl<F: NorFlash> ErrorType for VerifiedFlash<F> {
    type Error = VerifyError<F::Error>;
}
impl<F: NorFlash> ReadNorFlash for VerifiedFlash<F> {
    const READ_SIZE: usize = F::READ_SIZE;
    async fn read(&mut self, address: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.0
            .read(address, bytes)
            .await
            .map_err(VerifyError::Flash)
    }
    fn capacity(&self) -> usize {
        self.0.capacity()
    }
}
impl<F: NorFlash> NorFlash for VerifiedFlash<F> {
    const WRITE_SIZE: usize = F::WRITE_SIZE;
    const ERASE_SIZE: usize = F::ERASE_SIZE;
    async fn write(&mut self, address: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        self.0
            .write(address, bytes)
            .await
            .map_err(VerifyError::Flash)?;
        self.verify(address, bytes.len(), Some(bytes)).await
    }
    async fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        self.0.erase(from, to).await.map_err(VerifyError::Flash)?;
        let len = to.checked_sub(from).ok_or(VerifyError::Mismatch)? as usize;
        self.verify(from, len, None).await
    }
}
impl<F: NorFlash + MultiwriteNorFlash> MultiwriteNorFlash for VerifiedFlash<F> {}
