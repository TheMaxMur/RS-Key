// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::ram::RamStorage;

struct SeqRng(u64);
impl Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

// Run process_cbor with a fresh context (empty flash).
fn dispatch(data: &[u8], out: &mut [u8]) -> usize {
    dispatch_seeded(data, out, false)
}

// As `dispatch`, optionally provisioning the seed and a persistent pinUvAuthToken
// first — the pair getInfo's `encIdentifier` (0x19) needs before it exists.
fn dispatch_seeded(data: &[u8], out: &mut [u8], with_token: bool) -> usize {
    let mut fs = Fs::new(RamStorage::new());
    let dev = Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
        latched: false,
    };
    let mut rng = SeqRng(1);
    if with_token {
        crate::seed::ensure_seed(&dev, &mut fs, &mut rng).unwrap();
        crate::seed::ensure_ppuat(&dev, &mut fs, &mut rng).unwrap();
    }
    let mut state = FidoState::new();
    let mut presence = AlwaysConfirm;
    let mut ctx = Ctx {
        dev,
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
        presence: &mut presence,
    };
    process_cbor(&mut ctx, data, out)
}

#[test]
fn dispatch_get_info_ok() {
    // Sized well clear of the response: `advertise-pqc` adds two ML-DSA algorithm
    // entries to it, and `process_cbor` answers a short buffer with a status byte
    // alone rather than a panic.
    let mut out = [0u8; 1024];
    let n = dispatch(&[consts::CTAP_GET_INFO], &mut out);
    assert!(n > 1);
    assert_eq!(out[0], CTAP2_OK);
    // Decode the map header instead of comparing its first byte. CBOR packs a count
    // into that byte only up to 23; from 24 the byte is 0xB8 ("one length byte
    // follows") for every count to 255, so the byte comparison this replaces went on
    // passing when the roster crossed 24 and could no longer tell 24 from anything
    // above it. `encIdentifier` (0x19) is absent here — no persistent token on an
    // empty flash — so the count is the unconditional one.
    let mut d = minicbor::Decoder::new(&out[1..n]);
    assert_eq!(
        d.map().unwrap().unwrap(),
        24 - u64::from(consts::LARGE_BLOB_EXT)
    );
}

#[test]
fn dispatch_unknown_command() {
    let mut out = [0u8; 64];
    let n = dispatch(&[0xEE], &mut out);
    assert_eq!(n, 1);
    assert_eq!(out[0], CtapError::InvalidCommand.as_u8());
}

#[test]
fn dispatch_empty_is_invalid_length() {
    let mut out = [0u8; 64];
    let n = dispatch(&[], &mut out);
    assert_eq!(n, 1);
    assert_eq!(out[0], CtapError::InvalidLength.as_u8());
}

#[test]
fn dispatch_get_assertion_routes_to_handler() {
    // getAssertion with empty params is malformed CBOR.
    let mut out = [0u8; 64];
    let n = dispatch(&[consts::CTAP_GET_ASSERTION], &mut out);
    assert_eq!(n, 1);
    assert_eq!(out[0], CtapError::InvalidCbor.as_u8());
}

/// The 0x19 and 0x1E payloads are built in `seed::` but assembled at the dispatch
/// site, where the seed, the token and the RNG live. This drives the real command so
/// the wiring is covered too: an encoder test passing `Some(..)` by hand would stay
/// green if `process_cbor` never asked for either value.
#[test]
fn dispatch_get_info_carries_the_encrypted_members_once_a_token_exists() {
    let mut plain = [0u8; 1024];
    let n = dispatch_seeded(&[consts::CTAP_GET_INFO], &mut plain, false);
    let mut with = [0u8; 1024];
    let m = dispatch_seeded(&[consts::CTAP_GET_INFO], &mut with, true);
    assert_eq!(plain[0], CTAP2_OK);
    assert_eq!(with[0], CTAP2_OK);

    let mut without = minicbor::Decoder::new(&plain[1..n]);
    let mut d = minicbor::Decoder::new(&with[1..m]);
    let entries = d.map().unwrap().unwrap();
    assert_eq!(
        entries,
        without.map().unwrap().unwrap() + 2,
        "a persistent token adds exactly encIdentifier and encCredStoreState"
    );

    let mut found = std::vec::Vec::new();
    for _ in 0..entries {
        match d.u32().unwrap() {
            k @ (0x19 | 0x1E) => found.push((k, d.bytes().unwrap().len())),
            _ => d.skip().unwrap(),
        }
    }
    assert_eq!(
        found,
        std::vec![
            (0x19, consts::ENC_GETINFO_MEMBER_LEN),
            (0x1E, consts::ENC_GETINFO_MEMBER_LEN)
        ],
        "both are iv(16) ‖ ct(16), and 0x19 sorts before 0x1E"
    );
    assert!(
        d.datatype().is_err(),
        "the declared count must consume the map"
    );
}

/// Whether the live audit-journal window records `ev`, read as the panel reads it.
/// The fault sweeps ask it: the journal swallows its own write failures, so a
/// command's `Ok` says nothing about whether its entry landed.
pub(crate) fn journals<S: Storage>(dev: &Device, fs: &mut Fs<S>, ev: u8) -> bool {
    let mut seen = false;
    crate::journal::for_each_event(dev, fs, |e| {
        seen |= e.event == ev;
        !seen
    });
    seen
}

/// Tests compare secrets by value: the bytes of a `Secret`, an `Option` of one or a
/// reference to one, and plain arrays passed through as they are. Test-only.
pub(crate) trait Bare {
    type Out: PartialEq + core::fmt::Debug;
    fn bare(self) -> Self::Out;
}
impl<const N: usize> Bare for rsk_secret::Secret<[u8; N]> {
    type Out = [u8; N];
    fn bare(self) -> [u8; N] {
        *self.expose()
    }
}
impl<const N: usize> Bare for &rsk_secret::Secret<[u8; N]> {
    type Out = [u8; N];
    fn bare(self) -> [u8; N] {
        *self.expose()
    }
}
impl<const N: usize> Bare for Option<rsk_secret::Secret<[u8; N]>> {
    type Out = Option<[u8; N]>;
    fn bare(self) -> Option<[u8; N]> {
        self.map(|s| *s.expose())
    }
}
impl<const N: usize> Bare for Option<&rsk_secret::Secret<[u8; N]>> {
    type Out = Option<[u8; N]>;
    fn bare(self) -> Option<[u8; N]> {
        self.map(|s| *s.expose())
    }
}
impl<const N: usize> Bare for [u8; N] {
    type Out = [u8; N];
    fn bare(self) -> [u8; N] {
        self
    }
}
impl<const N: usize> Bare for &[u8; N] {
    type Out = [u8; N];
    fn bare(self) -> [u8; N] {
        *self
    }
}
impl<const N: usize> Bare for Option<[u8; N]> {
    type Out = Option<[u8; N]>;
    fn bare(self) -> Option<[u8; N]> {
        self
    }
}
pub(crate) fn bare<T: Bare>(x: T) -> T::Out {
    x.bare()
}

/// Bytes from a hex vector — how the ARKG and previewSign references are written.
#[cfg(feature = "preview-sign")]
pub(crate) fn unhex(s: &str) -> std::vec::Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
