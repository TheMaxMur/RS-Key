// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::FidoState;
use minicbor::Encoder;
use minicbor::encode::write::Cursor;
use rsk_crypto::Device;
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

fn dev() -> Device<'static> {
    Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    }
}

const SEED: [u8; 32] = [0x5A; 32];
const CRED_A: [u8; CRED_RESIDENT_LEN] = [0xA1; CRED_RESIDENT_LEN];
const CRED_B: [u8; CRED_RESIDENT_LEN] = [0xB2; CRED_RESIDENT_LEN];

/// A test harness that owns the pieces `Ctx` borrows, so a test can write and
/// then read across two separate `Ctx` lifetimes.
struct Harness {
    fs: Fs<RamStorage>,
    state: FidoState,
    rng: SeqRng,
}

impl Harness {
    fn new() -> Self {
        Harness {
            fs: Fs::new(RamStorage::new()),
            state: FidoState::new(),
            rng: SeqRng(1),
        }
    }

    fn with<T>(&mut self, f: impl FnOnce(&mut Ctx<RamStorage, SeqRng>) -> T) -> T {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut self.fs,
            rng: &mut self.rng,
            state: &mut self.state,
            now_ms: 0,
        };
        f(&mut ctx)
    }

    fn write_blob(&mut self, cred: &[u8; CRED_RESIDENT_LEN], slot: u16, blob: &[u8]) -> bool {
        self.with(|ctx| write(ctx, &SEED, cred, slot, blob, blob.len() as u64 * 2))
    }

    /// Read the blob back as an owned copy — the real caller encodes straight out
    /// of the scratch, which a test cannot hold across two borrows.
    fn read_blob(&mut self, cred: &[u8; CRED_RESIDENT_LEN], slot: u16) -> Option<(Vec<u8>, u32)> {
        self.with(|ctx| {
            let (at, size) = read(ctx, &SEED, cred, slot)?;
            Some((ctx.state.lba.temp[at].to_vec(), size))
        })
    }
}

/// One extension-map value, so a test can spell an input map as data.
enum V<'a> {
    Str(&'a str),
    Bytes(&'a [u8]),
    U32(u32),
    Bool(bool),
}

/// Encode a CBOR map of `(key, value)` pairs — the extension input shape.
fn ext_map(entries: &[(&str, V)]) -> Vec<u8> {
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(entries.len() as u64).unwrap();
        for (k, v) in entries {
            e.str(k).unwrap();
            match v {
                V::Str(s) => e.str(s).unwrap(),
                V::Bytes(b) => e.bytes(b).unwrap(),
                V::U32(n) => e.u32(*n).unwrap(),
                V::Bool(b) => e.bool(*b).unwrap(),
            };
        }
        e.writer().position()
    };
    buf[..n].to_vec()
}

fn parse_mc_bytes(data: &[u8]) -> Result<McInput, CtapError> {
    parse_mc(&mut Decoder::new(data))
}

fn parse_ga_bytes(data: &[u8]) -> Result<GaInput<'_>, CtapError> {
    parse_ga(&mut Decoder::new(data))
}

#[test]
fn make_credential_accepts_the_two_support_levels() {
    let req = ext_map(&[("support", V::Str("required"))]);
    assert_eq!(parse_mc_bytes(&req), Ok(McInput::Required));
    let pref = ext_map(&[("support", V::Str("preferred"))]);
    assert_eq!(parse_mc_bytes(&pref), Ok(McInput::Preferred));
}

/// §12.4 step 1: the CDDL names exactly two support levels and no other member,
/// and `support` is not optional — everything else is INVALID_CBOR.
#[test]
fn make_credential_rejects_everything_outside_the_cddl() {
    let unknown_level = ext_map(&[("support", V::Str("mandatory"))]);
    assert_eq!(parse_mc_bytes(&unknown_level), Err(CtapError::InvalidCbor));

    let extra_member = ext_map(&[("support", V::Str("preferred")), ("read", V::Bool(true))]);
    assert_eq!(parse_mc_bytes(&extra_member), Err(CtapError::InvalidCbor));

    assert_eq!(parse_mc_bytes(&ext_map(&[])), Err(CtapError::InvalidCbor));
}

#[test]
fn get_assertion_accepts_a_lone_read_and_a_write_with_its_size() {
    let read_only = ext_map(&[("read", V::Bool(true))]);
    assert!(matches!(parse_ga_bytes(&read_only), Ok(GaInput::Read)));

    let write = ext_map(&[("write", V::Bytes(&[1, 2, 3])), ("originalSize", V::U32(9))]);
    assert!(matches!(
        parse_ga_bytes(&write),
        Ok(GaInput::Write {
            blob: &[1, 2, 3],
            original_size: 9
        })
    ));
}

/// §12.4 step 2 admits `read` alone or `write` + `originalSize`, and nothing
/// else: not the two mixed, not a half-write, not an empty map, not `read: false`
/// (the CDDL pins that value to `true`).
#[test]
fn get_assertion_rejects_every_other_member_combination() {
    let refused: [&[(&str, V)]; 5] = [
        &[
            ("read", V::Bool(true)),
            ("write", V::Bytes(&[1])),
            ("originalSize", V::U32(1)),
        ],
        &[("write", V::Bytes(&[1]))],
        &[("originalSize", V::U32(1))],
        &[],
        &[("read", V::Bool(false))],
    ];
    for entries in refused {
        let req = ext_map(entries);
        assert!(
            matches!(parse_ga_bytes(&req), Err(CtapError::InvalidCbor)),
            "accepted a member combination the CDDL forbids"
        );
    }
}

#[test]
fn a_written_blob_reads_back_with_its_original_size() {
    let mut h = Harness::new();
    let blob = [0x37u8; 300];
    assert!(h.write_blob(&CRED_A, 4, &blob));
    let (got, size) = h.read_blob(&CRED_A, 4).expect("the blob is there");
    assert_eq!(got, blob);
    assert_eq!(size, 600);
}

/// A rewrite replaces the blob rather than appending to it, and the record stays
/// openable — the write path reuses one buffer, so a shorter second blob must not
/// leave the tail of the first behind.
#[test]
fn a_rewrite_replaces_the_stored_blob() {
    let mut h = Harness::new();
    assert!(h.write_blob(&CRED_A, 0, &[0xEE; 400]));
    assert!(h.write_blob(&CRED_A, 0, &[0x11; 12]));
    let (got, size) = h.read_blob(&CRED_A, 0).unwrap();
    assert_eq!(got, [0x11; 12]);
    assert_eq!(size, 24);
}

/// The credential id is the AEAD's AAD, so a record left in a slot by a deleted
/// credential cannot be served to whoever takes the slot next.
#[test]
fn a_blob_does_not_survive_into_the_next_owner_of_the_slot() {
    let mut h = Harness::new();
    assert!(h.write_blob(&CRED_A, 9, b"secret"));
    assert!(h.read_blob(&CRED_B, 9).is_none());
    // …and the rightful owner still gets it, so the miss is authentication, not
    // a wiped record.
    assert!(h.read_blob(&CRED_A, 9).is_some());
}

#[test]
fn an_absent_or_corrupt_record_reads_as_nothing() {
    let mut h = Harness::new();
    assert!(h.read_blob(&CRED_A, 3).is_none());
    // A too-short record cannot even hold the seal, and a full-length one whose
    // bytes are junk fails the tag. Neither may panic.
    h.fs.put(EF_CRED_BLOB + 3, &[0u8; 8]).unwrap();
    assert!(h.read_blob(&CRED_A, 3).is_none());
    h.fs.put(EF_CRED_BLOB + 3, &[0xFFu8; 64]).unwrap();
    assert!(h.read_blob(&CRED_A, 3).is_none());
}

/// The largest blob that fits is stored; one byte more is refused with the flag
/// §12.4 defines, not an error.
#[test]
fn the_ceiling_is_the_largest_blob_the_record_can_hold() {
    let mut h = Harness::new();
    assert!(h.write_blob(&CRED_A, 1, &[0x5C; MAX_CRED_LARGE_BLOB]));
    assert_eq!(
        h.read_blob(&CRED_A, 1).unwrap().0.len(),
        MAX_CRED_LARGE_BLOB
    );
    assert!(!h.write_blob(&CRED_A, 2, &[0x5C; MAX_CRED_LARGE_BLOB + 1]));
    assert!(h.read_blob(&CRED_A, 2).is_none());
}

#[test]
fn discard_removes_the_record() {
    let mut h = Harness::new();
    assert!(h.write_blob(&CRED_A, 7, b"gone soon"));
    discard(&mut h.fs, 7);
    assert!(h.read_blob(&CRED_A, 7).is_none());
}

/// The stored bytes never contain the plaintext: a flash dump of a `largeblob-ext`
/// device must not hand over what the platform wrote (the 2.1 array arrives
/// already encrypted; a 2.3 blob does not).
#[test]
fn the_record_on_flash_is_sealed() {
    let mut h = Harness::new();
    let plain = b"ssh-cert-for-prod-bastion";
    assert!(h.write_blob(&CRED_A, 5, plain));
    let mut rec = [0u8; MAX_LARGE_BLOB_SIZE];
    let n = h.fs.read(EF_CRED_BLOB + 5, &mut rec).unwrap();
    assert!(
        !rec[..n].windows(plain.len()).any(|w| w == plain),
        "the plaintext blob is readable in the stored record"
    );
}
