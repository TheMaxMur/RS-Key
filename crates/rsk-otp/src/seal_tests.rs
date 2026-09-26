// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::{CONFIG_SIZE, SLOT_SIZE};

/// The runtime twin of the compile-time assertion in `seal.rs`: it walks the
/// whole plaintext domain (`CONFIG_SIZE..=SLOT_SIZE`) rather than only its
/// cheapest end, and names the length that collided. The const block is what
/// holds the shipping build; this is what says why it matters when it fires.
#[test]
fn sealed_length_never_looks_like_plaintext_exhaustive() {
    for plain in CONFIG_SIZE..=SLOT_SIZE {
        let sealed = NONCE_LEN + plain + TAG_LEN;
        assert!(
            !(CONFIG_SIZE..=SLOT_SIZE).contains(&sealed),
            "sealed len {sealed} for plaintext {plain} collides with the plaintext range \
             — migrate_seal would double-seal an already-sealed slot"
        );
    }
}

const SERIAL: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const HASH: [u8; 32] = [0x22; 32];
const FID: KeyFid = KeyFid::new(0xB001);

struct TestRng(u64);
impl Rng for TestRng {
    fn fill(&mut self, b: &mut [u8]) {
        for x in b.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *x = (self.0 >> 33) as u8;
        }
    }
}

fn fixture() -> (Device<'static>, Fs<rsk_fs::storage::ram::RamStorage>) {
    let mut fs = Fs::new(rsk_fs::storage::ram::RamStorage::new());
    fs.scan();
    (
        Device {
            serial_hash: &HASH,
            serial_id: &SERIAL,
            otp_key: None,
        },
        fs,
    )
}

/// A record too short to hold its own `nonce ‖ tag` framing cannot be a slot this
/// applet wrote, and `try_seal_read` must fold it to "not programmed" rather than
/// underflow `pt_len`. `Ok(None)`, never `Err`: the medium answered fine.
#[test]
fn a_record_shorter_than_its_framing_reads_as_unprogrammed() {
    let (dev, mut fs) = fixture();
    for n in [1usize, NONCE_LEN + TAG_LEN - 1] {
        let junk = std::vec![0xEEu8; n];
        fs.put_key(FID, Sealed::wrap(&junk)).unwrap();
        let mut out = Secret::<[u8; MAX_PLAIN]>::zeroed();
        assert_eq!(
            try_seal_read(&dev, &mut fs, FID, &mut out),
            Ok(None),
            "a {n}-byte record was not folded away"
        );
    }
}

/// The caller's buffer is measured against the plaintext the record claims, before
/// anything is decrypted into it.
#[test]
fn an_output_buffer_under_the_plaintext_reads_as_unprogrammed() {
    let (dev, mut fs) = fixture();
    let plain = [0x11u8; CONFIG_SIZE];
    let rec = SlotRecord::from_bytes(&plain).unwrap();
    assert!(seal_put(&dev, &mut fs, &mut TestRng(2), FID, &rec));
    let mut small = Secret::<[u8; CONFIG_SIZE - 1]>::zeroed();
    assert_eq!(try_seal_read(&dev, &mut fs, FID, &mut small), Ok(None));
    let mut exact = Secret::<[u8; CONFIG_SIZE]>::zeroed();
    assert_eq!(
        try_seal_read(&dev, &mut fs, FID, &mut exact),
        Ok(Some(CONFIG_SIZE))
    );
    assert_eq!(*exact.expose(), plain);
}
