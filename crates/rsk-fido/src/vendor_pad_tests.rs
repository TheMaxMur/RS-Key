// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::PinEntry;
use crate::clientpin::{device_pin_retries_left, store_device_pin};
use crate::consts::{MAX_PIN_RETRIES, MIN_PIN_LENGTH};

struct Pad<'a> {
    entry: PinEntry,
    digits: &'a [u8],
    prompts: usize,
    touches: usize,
}

impl UserPresence for Pad<'_> {
    fn request(&mut self, _confirm: crate::Confirm<'_>) -> Presence {
        self.touches += 1;
        Presence::Confirmed
    }

    fn uv_available(&self) -> bool {
        true
    }

    fn collect_device_pin(&mut self, min: usize, out: &mut [u8]) -> PinEntry {
        assert_eq!(min, usize::from(MIN_PIN_LENGTH));
        assert!(out.iter().all(|&byte| byte == 0));
        out[..self.digits.len()].copy_from_slice(self.digits);
        self.prompts += 1;
        self.entry
    }
}

#[test]
fn a_non_entry_refuses_attestation_clear_without_spending_a_retry() {
    for (entry, error) in [
        (PinEntry::Declined, CtapError::OperationDenied),
        (PinEntry::Timeout, CtapError::UserActionTimeout),
        (PinEntry::Cancelled, CtapError::KeepAliveCancel),
        (PinEntry::Unsupported, CtapError::UnsupportedOption),
    ] {
        let (mut fs, mut rng, mut state) = setup();
        store_device_pin(&dev(), &mut fs, b"123456").unwrap();
        crate::seed::store_att_key(&dev(), &mut fs, &[3; 32]).unwrap();
        fs.put(EF_ATT_CHAIN, b"test chain").unwrap();
        handshake(&mut fs, &mut rng, &mut state);
        let mut pad = Pad {
            entry,
            digits: &[],
            prompts: 0,
            touches: 0,
        };
        let mut req = [0; 32];
        let n = one_byte_req(&mut req, VENDOR_ATT_CLEAR);
        assert_eq!(
            call(
                &mut fs,
                &mut rng,
                &mut state,
                &mut pad,
                &req[..n],
                &mut [0; 64]
            ),
            Err(error)
        );
        assert_eq!((pad.prompts, pad.touches), (1, 1));
        assert_eq!(device_pin_retries_left(&mut fs), Some(MAX_PIN_RETRIES));
        assert!(fs.has_key(EF_ATT_KEY));
        assert!(fs.has_data(EF_ATT_CHAIN));
    }
}

#[test]
fn a_wrong_pad_pin_blocks_clear_and_the_right_pin_restores_the_budget() {
    let (mut fs, mut rng, mut state) = setup();
    store_device_pin(&dev(), &mut fs, b"123456").unwrap();
    crate::seed::store_att_key(&dev(), &mut fs, &[3; 32]).unwrap();
    fs.put(EF_ATT_CHAIN, b"test chain").unwrap();
    let mut req = [0; 32];
    let n = one_byte_req(&mut req, VENDOR_ATT_CLEAR);
    for (digits, answer, left, touches) in [
        (
            &b"654321"[..],
            Err(CtapError::PinInvalid),
            MAX_PIN_RETRIES - 1,
            1,
        ),
        (&b"123456"[..], Ok(0), MAX_PIN_RETRIES, 2),
    ] {
        handshake(&mut fs, &mut rng, &mut state);
        let mut pad = Pad {
            entry: PinEntry::Entered(digits.len()),
            digits,
            prompts: 0,
            touches: 0,
        };
        assert_eq!(
            call(
                &mut fs,
                &mut rng,
                &mut state,
                &mut pad,
                &req[..n],
                &mut [0; 64]
            ),
            answer
        );
        assert_eq!((pad.prompts, pad.touches), (1, touches));
        assert_eq!(device_pin_retries_left(&mut fs), Some(left));
        assert_eq!(fs.has_key(EF_ATT_KEY), answer.is_err());
        assert_eq!(fs.has_data(EF_ATT_CHAIN), answer.is_err());
    }
}

#[test]
fn repeated_wrong_pad_pins_exhaust_the_persistent_budget() {
    let (mut fs, mut rng, mut state) = setup();
    store_device_pin(&dev(), &mut fs, b"123456").unwrap();
    crate::seed::store_att_key(&dev(), &mut fs, &[3; 32]).unwrap();
    let mut req = [0; 32];
    let n = one_byte_req(&mut req, VENDOR_ATT_CLEAR);
    for left in (0..MAX_PIN_RETRIES).rev().chain([0]) {
        handshake(&mut fs, &mut rng, &mut state);
        let mut pad = Pad {
            entry: PinEntry::Entered(6),
            digits: b"654321",
            prompts: 0,
            touches: 0,
        };
        assert_eq!(
            call(
                &mut fs,
                &mut rng,
                &mut state,
                &mut pad,
                &req[..n],
                &mut [0; 64]
            ),
            Err(if left == 0 {
                CtapError::PinBlocked
            } else {
                CtapError::PinInvalid
            })
        );
        assert_eq!(device_pin_retries_left(&mut fs), Some(left));
        assert_eq!((pad.prompts, pad.touches), (1, 1));
        assert!(fs.has_key(EF_ATT_KEY));
    }
}

#[test]
fn config_read_refuses_an_unknown_target_without_touch() {
    let (mut fs, mut rng, mut state) = setup();
    let mut req = [0; 32];
    let n = config_read_req(255, &mut req);
    let mut pad = Pad {
        entry: PinEntry::Unsupported,
        digits: &[],
        prompts: 0,
        touches: 0,
    };
    assert_eq!(
        call(
            &mut fs,
            &mut rng,
            &mut state,
            &mut pad,
            &req[..n],
            &mut [0; 64]
        ),
        Err(CtapError::InvalidParameter)
    );
    assert_eq!((pad.prompts, pad.touches), (0, 0));
}

#[test]
fn audit_status_is_ungated_even_when_a_device_pin_is_set() {
    let (mut fs, mut rng, mut state) = setup();
    store_device_pin(&dev(), &mut fs, b"123456").unwrap();
    let mut req = [0; 32];
    let n = audit_config_req(2, &mut req);
    let mut pad = Pad {
        entry: PinEntry::Unsupported,
        digits: &[],
        prompts: 0,
        touches: 0,
    };
    let mut out = [0; 64];
    let len = call(&mut fs, &mut rng, &mut state, &mut pad, &req[..n], &mut out).unwrap();
    let mut decoder = Decoder::new(&out[..len]);
    assert_eq!(decoder.map().unwrap(), Some(1));
    assert_eq!(decoder.u8().unwrap(), 1);
    assert!(!decoder.bool().unwrap());
    assert_eq!(decoder.position(), len);
    assert_eq!((pad.prompts, pad.touches), (0, 0));
    assert_eq!(device_pin_retries_left(&mut fs), Some(MAX_PIN_RETRIES));
}

#[test]
fn effective_phy_is_published_from_boot_defaults_without_a_stored_override() {
    const CHILD: &str = "RS_KEY_EFFECTIVE_PHY_TEST";
    if std::env::var_os(CHILD).is_none() {
        // Boot globals need a fresh process; the other tests model a headless boot.
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "vendor::tests::vendor_pad_tests::effective_phy_is_published_from_boot_defaults_without_a_stored_override",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let (mut fs, mut rng, mut state) = setup();
    assert_eq!(crate::config::effective_phy(), None);
    crate::config::set_effective_phy(25, 2, 30);
    let generation = fs.write_gen();
    let mut req = [0; 32];
    let n = config_read_req(CONFIG_TARGET_PHY, &mut req);
    let mut out = [0; 64];
    let len = call(
        &mut fs,
        &mut rng,
        &mut state,
        &mut AlwaysConfirm,
        &req[..n],
        &mut out,
    )
    .unwrap();
    let mut decoder = Decoder::new(&out[..len]);
    assert_eq!(decoder.map().unwrap(), Some(2));
    assert_eq!(decoder.u8().unwrap(), 1);
    assert_eq!(decoder.bytes().unwrap(), &[]);
    assert_eq!(decoder.u8().unwrap(), 2);
    assert_eq!(decoder.map().unwrap(), Some(3));
    for (tag, value) in [(4, 25), (12, 2), (8, 30)] {
        assert_eq!(decoder.u8().unwrap(), tag);
        assert_eq!(decoder.u8().unwrap(), value);
    }
    assert_eq!(decoder.position(), len);
    assert_eq!(fs.write_gen(), generation);
}
