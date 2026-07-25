// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::FidoState;
use crate::consts::LARGEBLOB_INITIAL;
use minicbor::Encoder;
use minicbor::encode::write::Cursor;
use rsk_crypto::Device;
use rsk_crypto::pinproto;
use rsk_fs::Fs;
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

const TOKEN: [u8; 32] = [0x99; 32];

fn armed(perms: u8) -> FidoState {
    let mut s = FidoState::new();
    s.paut.token = TOKEN;
    s.paut.permissions = perms;
    s.begin_using_token(false, 0);
    s
}

fn seeded_fs() -> Fs<RamStorage> {
    let mut fs = Fs::new(RamStorage::new());
    fs.put(EF_LARGEBLOB, &LARGEBLOB_INITIAL).unwrap();
    fs
}

/// `seeded_fs` plus a configured PIN — the state in which §6.10.2 requires a
/// verified pinUvAuthParam on every write.
fn seeded_fs_with_pin() -> Fs<RamStorage> {
    let mut fs = seeded_fs();
    let mut pin_file = [0u8; 35];
    pin_file[0] = 8; // retries
    pin_file[1] = 4; // length
    pin_file[2] = 1; // format
    fs.put(EF_PIN, &pin_file).unwrap();
    fs
}

fn run(fs: &mut Fs<RamStorage>, state: &mut FidoState, req: &[u8], out: &mut [u8]) -> CtapResult {
    let mut rng = SeqRng(1);
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs,
        rng: &mut rng,
        state,
        now_ms: 0,
    };
    large_blobs(&mut ctx, req, out)
}

// A valid serialized array: `body ‖ left16(SHA-256(body))`.
fn valid_blob(body: &[u8]) -> std::vec::Vec<u8> {
    let mut v = body.to_vec();
    v.extend_from_slice(&sha256(body)[..16]);
    v
}

fn get_request(get: u64, offset: u64) -> std::vec::Vec<u8> {
    let mut buf = [0u8; 32];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(2).unwrap();
        e.u8(0x01).unwrap().u64(get).unwrap();
        e.u8(0x03).unwrap().u64(offset).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

// A SET request, MACing over 0xff×32 ‖ 0x0c ‖ 0x00 ‖ offset_le ‖ sha256(set).
fn set_request(
    offset: u64,
    length: Option<u64>,
    set: &[u8],
    token: &[u8; 32],
) -> std::vec::Vec<u8> {
    let mut vd = [0u8; 70];
    vd[..32].fill(0xff);
    vd[32] = CTAP_LARGE_BLOBS;
    vd[34..38].copy_from_slice(&(offset as u32).to_le_bytes());
    vd[38..70].copy_from_slice(&sha256(set));
    let mut mac = [0u8; 32];
    let mlen = pinproto::authenticate(PinProto::Two, token, &vd, &mut mac).unwrap();

    let mut buf = [0u8; 1100];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(4 + u64::from(length.is_some())).unwrap();
        e.u8(0x02).unwrap().bytes(set).unwrap();
        e.u8(0x03).unwrap().u64(offset).unwrap();
        if let Some(l) = length {
            e.u8(0x04).unwrap().u64(l).unwrap();
        }
        e.u8(0x05).unwrap().bytes(&mac[..mlen]).unwrap();
        e.u8(0x06).unwrap().u8(2).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

fn get_bytes(out: &[u8], n: usize) -> std::vec::Vec<u8> {
    let mut d = Decoder::new(&out[..n]);
    assert_eq!(d.map().unwrap().unwrap(), 1);
    assert_eq!(d.u8().unwrap(), 0x01);
    d.bytes().unwrap().to_vec()
}

#[test]
fn get_default_blob() {
    let mut fs = seeded_fs();
    let mut state = FidoState::new();
    let mut out = [0u8; 128];
    // A fresh device returns the 17-byte CTAP2.1 default array.
    let n = run(&mut fs, &mut state, &get_request(1000, 0), &mut out).unwrap();
    assert_eq!(get_bytes(&out, n), LARGEBLOB_INITIAL.to_vec());
}

#[test]
fn get_zero_bytes_returns_empty_fragment() {
    // get=0 is a valid read of zero bytes (conformance LargeBlobs-1 P-2):
    // success with an empty fragment, not INVALID_PARAMETER.
    let mut fs = seeded_fs();
    let mut state = FidoState::new();
    let mut out = [0u8; 64];
    let n = run(&mut fs, &mut state, &get_request(0, 0), &mut out).unwrap();
    assert!(get_bytes(&out, n).is_empty());
}

#[test]
fn get_at_offset_truncates() {
    let mut fs = seeded_fs();
    let mut state = FidoState::new();
    let mut out = [0u8; 128];
    // Read 5 bytes from offset 2 → blob[2..7].
    let n = run(&mut fs, &mut state, &get_request(5, 2), &mut out).unwrap();
    assert_eq!(get_bytes(&out, n), LARGEBLOB_INITIAL[2..7].to_vec());
    // Read past the end clamps to size - offset.
    let n = run(&mut fs, &mut state, &get_request(1000, 15), &mut out).unwrap();
    assert_eq!(get_bytes(&out, n), LARGEBLOB_INITIAL[15..].to_vec());
}

#[test]
fn get_offset_beyond_size_rejected() {
    let mut fs = seeded_fs();
    let mut state = FidoState::new();
    let mut out = [0u8; 64];
    // The default blob is 17 bytes; offset 100 is past the end.
    assert_eq!(
        run(&mut fs, &mut state, &get_request(10, 100), &mut out),
        Err(CtapError::InvalidParameter)
    );
}

#[test]
fn set_single_fragment_roundtrips() {
    let mut fs = seeded_fs();
    let mut state = armed(PERM_LBW);
    let mut out = [0u8; 64];
    let blob = valid_blob(b"a serialized large-blob array payload");
    let req = set_request(0, Some(blob.len() as u64), &blob, &TOKEN);
    assert_eq!(run(&mut fs, &mut state, &req, &mut out), Ok(0));
    // Persisted verbatim.
    let mut stored = [0u8; 256];
    let sn = fs.read(EF_LARGEBLOB, &mut stored).unwrap();
    assert_eq!(&stored[..sn], &blob[..]);
    // And read back through GET.
    let n = run(&mut fs, &mut state, &get_request(1000, 0), &mut out).unwrap();
    assert_eq!(get_bytes(&out, n), blob);
}

#[test]
fn set_multi_fragment_assembles() {
    let mut fs = seeded_fs();
    let mut state = armed(PERM_LBW);
    let mut out = [0u8; 64];
    let blob = valid_blob(&[0xCD; 60]); // 76 bytes total
    let split = 50;
    let r1 = set_request(0, Some(blob.len() as u64), &blob[..split], &TOKEN);
    assert_eq!(run(&mut fs, &mut state, &r1, &mut out), Ok(0));
    // Not committed yet — flash still holds the previous (default) value.
    assert_eq!(fs.size(EF_LARGEBLOB), Some(LARGEBLOB_INITIAL.len()));
    let r2 = set_request(split as u64, None, &blob[split..], &TOKEN);
    assert_eq!(run(&mut fs, &mut state, &r2, &mut out), Ok(0));
    let mut stored = [0u8; 256];
    let sn = fs.read(EF_LARGEBLOB, &mut stored).unwrap();
    assert_eq!(&stored[..sn], &blob[..]);
}

#[test]
fn set_wrong_sequence_rejected() {
    let mut fs = seeded_fs();
    let mut state = armed(PERM_LBW);
    let mut out = [0u8; 64];
    let blob = valid_blob(&[0x01; 60]);
    let r1 = set_request(0, Some(blob.len() as u64), &blob[..50], &TOKEN);
    run(&mut fs, &mut state, &r1, &mut out).unwrap();
    // Resume at the wrong offset → INVALID_SEQ.
    let bad = set_request(99, None, &blob[50..], &TOKEN);
    assert_eq!(
        run(&mut fs, &mut state, &bad, &mut out),
        Err(CtapError::InvalidSeq)
    );
}

#[test]
fn set_integrity_failure_rejected() {
    let mut fs = seeded_fs();
    let mut state = armed(PERM_LBW);
    let mut out = [0u8; 64];
    let mut blob = valid_blob(&[0x22; 40]);
    let last = blob.len() - 1;
    blob[last] ^= 0xFF; // corrupt the trailing SHA-256 tag
    let req = set_request(0, Some(blob.len() as u64), &blob, &TOKEN);
    assert_eq!(
        run(&mut fs, &mut state, &req, &mut out),
        Err(CtapError::IntegrityFailure)
    );
}

#[test]
fn set_bad_mac_rejected() {
    let mut fs = seeded_fs_with_pin();
    let mut state = armed(PERM_LBW);
    let mut out = [0u8; 64];
    let blob = valid_blob(&[0x33; 30]);
    // MAC under the wrong token.
    let req = set_request(0, Some(blob.len() as u64), &blob, &[0x11; 32]);
    assert_eq!(
        run(&mut fs, &mut state, &req, &mut out),
        Err(CtapError::PinAuthInvalid)
    );
}

#[test]
fn set_without_lbw_permission_rejected() {
    let mut fs = seeded_fs_with_pin();
    // A correctly-MACed request but the token lacks largeBlobWrite.
    let mut state = armed(crate::state::PERM_MC);
    let mut out = [0u8; 64];
    let blob = valid_blob(&[0x44; 30]);
    let req = set_request(0, Some(blob.len() as u64), &blob, &TOKEN);
    assert_eq!(
        run(&mut fs, &mut state, &req, &mut out),
        Err(CtapError::PinAuthInvalid)
    );
}

#[test]
fn set_without_a_pin_needs_no_token() {
    // §6.10.2 gates the write on being "protected by some form of user verification
    // or the alwaysUv option ID is present and true"; the spec's note is explicit that
    // an array can be written without user verification while no PIN is configured.
    let mut fs = seeded_fs();
    let mut state = FidoState::new(); // no token in use at all
    let mut out = [0u8; 64];
    let blob = valid_blob(&[0x55; 40]);
    // MAC'd under a token nobody holds — irrelevant, the branch is skipped.
    let req = set_request(0, Some(blob.len() as u64), &blob, &[0x11; 32]);
    assert_eq!(run(&mut fs, &mut state, &req, &mut out), Ok(0));
    let mut stored = [0u8; 256];
    let sn = fs.read(EF_LARGEBLOB, &mut stored).unwrap();
    assert_eq!(&stored[..sn], &blob[..]);
}

#[test]
fn set_without_a_pin_still_needs_a_token_under_always_uv() {
    // The other half of the same condition: alwaysUv re-arms the requirement even
    // with no PIN configured.
    let mut fs = seeded_fs();
    fs.put(crate::consts::EF_ALWAYS_UV, &[1]).unwrap();
    let mut state = FidoState::new();
    let mut out = [0u8; 64];
    let blob = valid_blob(&[0x66; 40]);
    // A write carrying no pinUvAuthParam/protocol pair at all (keys 5 and 6 absent).
    let req = {
        let mut buf = [0u8; 1100];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(3).unwrap();
            e.u8(0x02).unwrap().bytes(&blob).unwrap();
            e.u8(0x03).unwrap().u64(0).unwrap();
            e.u8(0x04).unwrap().u64(blob.len() as u64).unwrap();
            e.writer().position()
        };
        buf[..n].to_vec()
    };
    assert_eq!(
        run(&mut fs, &mut state, &req, &mut out),
        Err(CtapError::PuatRequired)
    );
}

#[test]
fn get_rejects_write_only_parameters() {
    let mut fs = seeded_fs();
    let mut state = armed(PERM_LBW);
    let mut out = [0u8; 128];
    // §6.10.2: on a `get`, `length` and the pinUvAuthParam pair are all
    // CTAP1_ERR_INVALID_PARAMETER — including a length of zero, which is present.
    let with_len = {
        let mut buf = [0u8; 32];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(3).unwrap();
            e.u8(0x01).unwrap().u64(10).unwrap();
            e.u8(0x03).unwrap().u64(0).unwrap();
            e.u8(0x04).unwrap().u64(0).unwrap();
            e.writer().position()
        };
        buf[..n].to_vec()
    };
    assert_eq!(
        run(&mut fs, &mut state, &with_len, &mut out),
        Err(CtapError::InvalidParameter)
    );
    let with_param = {
        let mut buf = [0u8; 64];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut buf[..]));
            e.map(4).unwrap();
            e.u8(0x01).unwrap().u64(10).unwrap();
            e.u8(0x03).unwrap().u64(0).unwrap();
            e.u8(0x05).unwrap().bytes(&[0u8; 32]).unwrap();
            e.u8(0x06).unwrap().u8(2).unwrap();
            e.writer().position()
        };
        buf[..n].to_vec()
    };
    assert_eq!(
        run(&mut fs, &mut state, &with_param, &mut out),
        Err(CtapError::InvalidParameter)
    );
}

#[test]
fn get_over_max_fragment_length_rejected() {
    let mut fs = seeded_fs();
    let mut state = FidoState::new();
    let mut out = [0u8; 128];
    // §6.10.2: "If the value of get is greater than maxFragmentLength, return
    // CTAP1_ERR_INVALID_LENGTH" — not a silent clamp.
    let req = get_request(MAX_FRAGMENT_LENGTH as u64 + 1, 0);
    assert_eq!(
        run(&mut fs, &mut state, &req, &mut out),
        Err(CtapError::InvalidLength)
    );
    // Exactly maxFragmentLength is fine.
    let req = get_request(MAX_FRAGMENT_LENGTH as u64, 0);
    assert!(run(&mut fs, &mut state, &req, &mut out).is_ok());
}

#[test]
fn set_minimum_length_array_is_hash_checked() {
    let mut fs = seeded_fs();
    let mut state = armed(PERM_LBW);
    let mut out = [0u8; 64];
    // The 17-byte floor gets no exemption from the trailing-hash check.
    let mut bad = LARGEBLOB_INITIAL.to_vec();
    bad[16] ^= 0xff;
    let req = set_request(0, Some(bad.len() as u64), &bad, &TOKEN);
    assert_eq!(
        run(&mut fs, &mut state, &req, &mut out),
        Err(CtapError::IntegrityFailure)
    );
    // The genuine initial array still writes.
    let req = set_request(0, Some(17), &LARGEBLOB_INITIAL, &TOKEN);
    assert_eq!(run(&mut fs, &mut state, &req, &mut out), Ok(0));
}

#[test]
fn set_length_bounds_enforced() {
    let mut fs = seeded_fs();
    let mut state = armed(PERM_LBW);
    let mut out = [0u8; 64];
    // length < 17 → INVALID_PARAMETER.
    let req = set_request(0, Some(10), &[0u8; 10], &TOKEN);
    assert_eq!(
        run(&mut fs, &mut state, &req, &mut out),
        Err(CtapError::InvalidParameter)
    );
    // length > MAX_LARGE_BLOB_SIZE → LARGE_BLOB_STORAGE_FULL.
    let req = set_request(0, Some(MAX_LARGE_BLOB_SIZE as u64 + 1), &[0u8; 10], &TOKEN);
    assert_eq!(
        run(&mut fs, &mut state, &req, &mut out),
        Err(CtapError::LargeBlobStorageFull)
    );
}

#[test]
fn missing_offset_rejected() {
    let mut fs = seeded_fs();
    let mut state = armed(PERM_LBW);
    let mut out = [0u8; 64];
    // {0x01: 100} — get without offset.
    let req = std::vec![0xA1, 0x01, 0x18, 100];
    assert_eq!(
        run(&mut fs, &mut state, &req, &mut out),
        Err(CtapError::InvalidParameter)
    );
}

#[test]
fn neither_get_nor_set_rejected() {
    let mut fs = seeded_fs();
    let mut state = armed(PERM_LBW);
    let mut out = [0u8; 64];
    // {0x03: 0} — offset present, but no get and no set.
    let req = std::vec![0xA1, 0x03, 0x00];
    assert_eq!(
        run(&mut fs, &mut state, &req, &mut out),
        Err(CtapError::InvalidParameter)
    );
}

#[test]
fn both_get_and_set_rejected() {
    let mut fs = seeded_fs();
    let mut state = armed(PERM_LBW);
    let mut out = [0u8; 64];
    // {0x01: 10, 0x02: h'00', 0x03: 0} — get and set together.
    let req = std::vec![0xA3, 0x01, 0x0A, 0x02, 0x41, 0x00, 0x03, 0x00];
    assert_eq!(
        run(&mut fs, &mut state, &req, &mut out),
        Err(CtapError::InvalidParameter)
    );
}

#[test]
fn max_u64_key_rejected_not_overflow() {
    // Regression for the fuzz crash `a1 1b ff..ff`: a map whose key is
    // `u64::MAX`. The ascending-key watermark `key + 1` used to overflow
    // (panic under debug-assertions, silent wrap on-device); it must now
    // reject the request instead of either.
    let mut fs = seeded_fs();
    let mut state = armed(PERM_LBW);
    let mut out = [0u8; 64];
    // {u64::MAX: ...} — one entry, key 0xffff_ffff_ffff_ffff.
    let req = std::vec![
        0xA1, 0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    ];
    assert_eq!(
        run(&mut fs, &mut state, &req, &mut out),
        Err(CtapError::InvalidCbor)
    );
}
