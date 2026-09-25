// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

const SERIAL: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const HASH: [u8; 32] = [0x22; 32];
const FID: KeyFid = KeyFid::new(0xBA01);

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

/// The cap is checked before the nonce is drawn, so an over-long credential costs
/// no randomness and leaves no half-written record for the next read to find.
#[test]
fn a_credential_over_the_cap_is_refused_and_writes_nothing() {
    let (dev, mut fs) = fixture();
    let over = [0x5Au8; MAX_PLAIN + 1];
    assert!(!seal_put(&dev, &mut fs, &mut TestRng(1), FID, &over));
    assert!(!fs.has_key(FID), "a refused seal left a record behind");
}

/// A record too short to hold its own `nonce ‖ tag` framing cannot be a blob this
/// applet wrote. It reads as absent rather than underflowing `pt_len`.
#[test]
fn a_record_shorter_than_its_framing_reads_as_absent() {
    let (dev, mut fs) = fixture();
    for n in [1usize, NONCE_LEN + TAG_LEN - 1] {
        let junk = std::vec![0xEEu8; n];
        fs.put_key(FID, Sealed::wrap(&junk)).unwrap();
        let mut out = Secret::<[u8; MAX_PLAIN]>::zeroed();
        assert_eq!(
            seal_read(&dev, &mut fs, FID, &mut out),
            None,
            "a {n}-byte record was not refused"
        );
    }
}

/// The caller's buffer is measured against the plaintext the record claims, before
/// anything is decrypted into it.
#[test]
fn an_output_buffer_under_the_plaintext_reads_as_absent() {
    let (dev, mut fs) = fixture();
    let plain = [0x11u8; 40];
    assert!(seal_put(&dev, &mut fs, &mut TestRng(2), FID, &plain));
    let mut small = Secret::<[u8; 39]>::zeroed();
    assert_eq!(seal_read(&dev, &mut fs, FID, &mut small), None);
    let mut exact = Secret::<[u8; 40]>::zeroed();
    assert_eq!(seal_read(&dev, &mut fs, FID, &mut exact), Some(40));
    assert_eq!(*exact.expose(), plain);
}
