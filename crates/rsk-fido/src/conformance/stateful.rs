// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP 2.2 §6 "exclusively preceded": a multi-call sequence does not survive an
//! unrelated command in the middle of it.
//!
//! The spec lets an authenticator "maintain state based on the assumption that
//! each stateful command is exclusively preceded by either another instance of
//! the same command, or by the corresponding state initializing command" — where
//! that phrase "means that no other authenticator operation occurs in between" —
//! and fail the sequence with `CTAP2_ERR_NOT_ALLOWED` when it is not. It names
//! exactly four: getNextAssertion, credentialManagement's two enumerate walkers,
//! and a largeBlobs `set` at a non-zero offset. This file drives all four through
//! `process_cbor`, which is the only layer where the rule is visible — each
//! command handler on its own cannot see what preceded it.
//!
//! Ported from Google OpenSK's `test_large_blob_stateful_interleaved` and
//! `test_channel_interleaving`, which pin the same rule (Apache-2.0; the
//! behaviour is the spec's, the code here is ours).

use super::{Authr, assert_ok, dev, field_at, pin_auth};
use crate::consts::{
    ALG_ES256, CM_ENUMERATE_RPS_BEGIN, CM_ENUMERATE_RPS_NEXT, CM_GET_CREDS_METADATA,
    CTAP_CREDENTIAL_MGMT, CTAP_GET_ASSERTION, CTAP_GET_INFO, CTAP_GET_NEXT_ASSERTION,
    CTAP_MAKE_CREDENTIAL, STATEFUL_WALK_IDLE_MS,
};
use crate::error::CtapError;
use crate::state::PERM_CM;
// Serving the CTAP 2.1 large-blob design, which a `largeblob-ext` build withdraws
// (§12.4), so these go with the tests that drive it.
use minicbor::Encoder;
use minicbor::encode::write::Cursor;
#[cfg(not(feature = "largeblob-ext"))]
use {
    super::assert_ok_empty,
    crate::consts::{CTAP_LARGE_BLOBS, CTAP_SELECTION, MAX_LARGE_BLOB_SIZE},
    crate::state::PERM_LBW,
    rsk_crypto::sha256,
};

const RP_ID: &str = "example.com";

/// A discoverable ES256 makeCredential over `rp` with user id `uid`.
fn mc_rk_on(rp: &str, uid: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(5).unwrap();
        e.u8(1).unwrap().bytes(&[0xCD; 32]).unwrap();
        e.u8(2).unwrap().map(1).unwrap();
        e.str("id").unwrap().str(rp).unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(uid).unwrap();
        e.str("name").unwrap().str("user").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        e.u8(7).unwrap().map(1).unwrap();
        e.str("rk").unwrap().bool(true).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// [`mc_rk_on`] over `RP_ID`.
fn mc_rk(uid: &[u8]) -> Vec<u8> {
    mc_rk_on(RP_ID, uid)
}

/// A getAssertion over `RP_ID` with no allowList.
fn ga() -> Vec<u8> {
    let mut buf = [0u8; 64];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(2).unwrap();
        e.u8(1).unwrap().str(RP_ID).unwrap();
        e.u8(2).unwrap().bytes(&[0xEF; 32]).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// A largeBlobs `set` fragment. `length` is sent only for the opening one, as
/// §6.10.2 requires (it is the total array size, not this fragment's).
#[cfg(not(feature = "largeblob-ext"))]
fn lb_set(set: &[u8], offset: u64, length: Option<u64>, param: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; 128];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(if length.is_some() { 5 } else { 4 }).unwrap();
        e.u8(2).unwrap().bytes(set).unwrap();
        e.u8(3).unwrap().u64(offset).unwrap();
        if let Some(l) = length {
            e.u8(4).unwrap().u64(l).unwrap();
        }
        e.u8(5).unwrap().bytes(param).unwrap();
        e.u8(6).unwrap().u64(2).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// The pinUvAuthParam a `set` fragment carries: MAC over
/// `0xff×32 ‖ 0x0c ‖ 0x00 ‖ offset_le(4) ‖ SHA-256(fragment)`.
#[cfg(not(feature = "largeblob-ext"))]
fn lb_param(token: &[u8; 32], offset: u32, fragment: &[u8]) -> Vec<u8> {
    let mut vd = [0u8; 70];
    vd[..32].fill(0xff);
    vd[32] = CTAP_LARGE_BLOBS;
    vd[34..38].copy_from_slice(&offset.to_le_bytes());
    vd[38..70].copy_from_slice(&sha256(fragment));
    pin_auth(token, &vd)
}

/// A credentialManagement request `{1: subCommand, 3: proto, 4: param}`; the
/// *Next* walkers carry no parameters of their own (§6.8).
fn cm(sub: u64, param: Option<&[u8]>) -> Vec<u8> {
    let mut buf = [0u8; 64];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(if param.is_some() { 3 } else { 1 }).unwrap();
        e.u8(1).unwrap().u64(sub).unwrap();
        if let Some(p) = param {
            e.u8(3).unwrap().u64(2).unwrap();
            e.u8(4).unwrap().bytes(p).unwrap();
        }
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// A `set` split across two fragments: an `authenticatorSelection` between them
/// abandons the transfer, so the second fragment's offset no longer matches what
/// the authenticator expects. OpenSK's `test_large_blob_stateful_interleaved`.
///
/// The large-blob buffer is the sequence with no other bound at all — no timer,
/// and on a PIN-less key no token either — so before this rule an interrupted
/// transfer stayed live until some later `offset == 0`.
// The CTAP 2.1 large-blob design, which a `largeblob-ext` build withdraws
// wholesale (§12.4: "Authenticators MUST NOT support both extensions").
#[cfg(not(feature = "largeblob-ext"))]
#[test]
fn an_unrelated_command_abandons_a_part_written_large_blob() {
    let mut a = Authr::fresh();
    let token = a.arm_token(PERM_LBW);
    let body = [0xA5u8; 40];
    let mut blob = body.to_vec();
    blob.extend_from_slice(&sha256(&body)[..16]); // 56 bytes total
    let split = 30;

    let p0 = lb_param(&token, 0, &blob[..split]);
    assert_ok_empty(&a.send(
        CTAP_LARGE_BLOBS,
        &lb_set(&blob[..split], 0, Some(blob.len() as u64), &p0),
    ));

    // Anything else in between — here the cheapest command there is.
    assert_ok_empty(&a.send(CTAP_SELECTION, &[]));

    let p1 = lb_param(&token, split as u32, &blob[split..]);
    let r = a.send(
        CTAP_LARGE_BLOBS,
        &lb_set(&blob[split..], split as u64, None, &p1),
    );
    assert_eq!(
        r.status,
        CtapError::InvalidSeq.as_u8(),
        "the interrupted transfer must not accept its next fragment"
    );

    // And the array on flash is untouched — a torn write commits nothing.
    let g = a.send(CTAP_LARGE_BLOBS, &lb_get_full());
    let mut d = field_at(&g.body, 1).expect("config fragment (0x01) present");
    assert_ne!(d.bytes().unwrap(), &blob[..], "nothing was committed");
}

#[cfg(not(feature = "largeblob-ext"))]
fn lb_get_full() -> Vec<u8> {
    let mut buf = [0u8; 32];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(2).unwrap();
        e.u8(1).unwrap().u64(MAX_LARGE_BLOB_SIZE as u64).unwrap();
        e.u8(3).unwrap().u64(0).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// A `getInfo` between `getAssertion` and `getNextAssertion` ends the walk.
/// OpenSK's `test_channel_interleaving`, minus the channel half — that one is
/// `get_next_assertion_refuses_a_second_channel`.
#[test]
fn an_unrelated_command_ends_the_assertion_walk() {
    let mut a = Authr::fresh();
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_rk(&[0xA1])));
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_rk(&[0xB2])));

    let g = a.send(CTAP_GET_ASSERTION, &ga());
    assert_ok(&g);
    let mut d = field_at(&g.body, 5).expect("numberOfCredentials (0x05) present");
    assert_eq!(d.u32().unwrap(), 2, "a walk is open");

    assert_ok(&a.send(CTAP_GET_INFO, &[]));

    let r = a.send(CTAP_GET_NEXT_ASSERTION, &[]);
    assert_eq!(
        r.status,
        CtapError::NotAllowed.as_u8(),
        "the walk did not survive the command in between"
    );
}

/// The same for the credential-management enumerate cursor. TWO relying parties,
/// so the walk genuinely has a second leg to lose — with one, *Begin* already
/// exhausts it and the *Next* answers `NotAllowed` whatever this rule does. That
/// is what the first draft of this test did, and it passed against the unfixed
/// tree.
#[test]
fn an_unrelated_command_ends_the_enumerate_walk() {
    let mut a = Authr::fresh();
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_rk_on("one.example", &[0xA1])));
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_rk_on("two.example", &[0xB2])));
    let token = a.arm_token(PERM_CM);
    let begin = cm(
        CM_ENUMERATE_RPS_BEGIN,
        Some(&pin_auth(&token, &[CM_ENUMERATE_RPS_BEGIN as u8])),
    );

    // Uninterrupted, the second leg is served — the control this test needs.
    let mut b = Authr::fresh();
    assert_ok(&b.send(CTAP_MAKE_CREDENTIAL, &mc_rk_on("one.example", &[0xA1])));
    assert_ok(&b.send(CTAP_MAKE_CREDENTIAL, &mc_rk_on("two.example", &[0xB2])));
    let btoken = b.arm_token(PERM_CM);
    let bbegin = cm(
        CM_ENUMERATE_RPS_BEGIN,
        Some(&pin_auth(&btoken, &[CM_ENUMERATE_RPS_BEGIN as u8])),
    );
    assert_ok(&b.send(CTAP_CREDENTIAL_MGMT, &bbegin));
    assert_ok(&b.send(CTAP_CREDENTIAL_MGMT, &cm(CM_ENUMERATE_RPS_NEXT, None)));

    // Interrupted, it is not.
    assert_ok(&a.send(CTAP_CREDENTIAL_MGMT, &begin));
    assert_ok(&a.send(CTAP_GET_INFO, &[]));
    let r = a.send(CTAP_CREDENTIAL_MGMT, &cm(CM_ENUMERATE_RPS_NEXT, None));
    assert_eq!(
        r.status,
        CtapError::NotAllowed.as_u8(),
        "the enumerate cursor did not survive the command in between"
    );
}

/// …and time ends it too, on a window of the walk's own. Driven under the
/// **persistent** token, which is the case with no other bound: §6.8.2's `pcmr`
/// token carries no usage timer, so before this the cursor stayed continuable for
/// the whole power cycle as long as nothing else was sent. A YubiKey 5.7.4 retires
/// the same cursor after a 35-second gap with its token still live (measured).
#[test]
fn an_idle_enumerate_walk_retires_on_its_own_timer() {
    let mut a = Authr::fresh();
    let rps = [
        "one.example",
        "two.example",
        "three.example",
        "four.example",
    ];
    for (i, rp) in rps.iter().enumerate() {
        assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_rk_on(rp, &[i as u8])));
    }
    let ppuat = crate::seed::ensure_ppuat(&dev(), &mut a.fs, &mut a.rng).unwrap();
    let begin = cm(
        CM_ENUMERATE_RPS_BEGIN,
        Some(&pin_auth(&ppuat, &[CM_ENUMERATE_RPS_BEGIN as u8])),
    );

    let r = a.send(CTAP_CREDENTIAL_MGMT, &begin);
    assert_ok(&r);
    let mut d = field_at(&r.body, 5).expect("totalRPs (0x05) present");
    assert_eq!(
        d.u32().unwrap(),
        4,
        "four RPs, so the leg refused below is a retirement and not an exhausted walk"
    );

    // Two legs, each after a gap that is most of the window — the second is served
    // only because the first pushed the deadline out.
    for _ in 0..2 {
        a.clock += STATEFUL_WALK_IDLE_MS - 5_000;
        assert_ok(&a.send(CTAP_CREDENTIAL_MGMT, &cm(CM_ENUMERATE_RPS_NEXT, None)));
    }

    a.clock += STATEFUL_WALK_IDLE_MS;
    assert_eq!(
        a.send(CTAP_CREDENTIAL_MGMT, &cm(CM_ENUMERATE_RPS_NEXT, None))
            .status,
        CtapError::NotAllowed.as_u8(),
        "an idle cursor must not stay walkable for the whole power cycle"
    );
}

/// The interrupting command may carry the same command *number* and still not be
/// a continuation: `getCredsMetadata` is credentialManagement, but it is not one
/// of the two *Next* walkers, so the cursor does not survive it. Measured on a
/// YubiKey 5.7.4 (Begin, getCredsMetadata, getNextRP → `0x30`), which implements
/// this rule for the enumerate cursor down to its own 30-second timer.
#[test]
fn a_non_continuing_subcommand_of_the_same_command_ends_the_enumerate_walk() {
    let mut a = Authr::fresh();
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_rk_on("one.example", &[0xA1])));
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_rk_on("two.example", &[0xB2])));
    let token = a.arm_token(PERM_CM);
    let begin = cm(
        CM_ENUMERATE_RPS_BEGIN,
        Some(&pin_auth(&token, &[CM_ENUMERATE_RPS_BEGIN as u8])),
    );
    assert_ok(&a.send(CTAP_CREDENTIAL_MGMT, &begin));

    let meta = cm(
        CM_GET_CREDS_METADATA,
        Some(&pin_auth(&token, &[CM_GET_CREDS_METADATA as u8])),
    );
    assert_ok(&a.send(CTAP_CREDENTIAL_MGMT, &meta));

    assert_eq!(
        a.send(CTAP_CREDENTIAL_MGMT, &cm(CM_ENUMERATE_RPS_NEXT, None))
            .status,
        CtapError::NotAllowed.as_u8(),
        "getCredsMetadata is credentialManagement, but it continues nothing"
    );
}

/// …and `largeBlobs` ends it too, though it is neither. Also measured on the
/// YubiKey (Begin, largeBlobs get, getNextRP → `0x30`).
// The CTAP 2.1 large-blob design, which a `largeblob-ext` build withdraws
// wholesale (§12.4: "Authenticators MUST NOT support both extensions").
#[cfg(not(feature = "largeblob-ext"))]
#[test]
fn a_large_blobs_command_ends_the_enumerate_walk() {
    let mut a = Authr::fresh();
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_rk_on("one.example", &[0xA1])));
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_rk_on("two.example", &[0xB2])));
    let token = a.arm_token(PERM_CM);
    let begin = cm(
        CM_ENUMERATE_RPS_BEGIN,
        Some(&pin_auth(&token, &[CM_ENUMERATE_RPS_BEGIN as u8])),
    );
    assert_ok(&a.send(CTAP_CREDENTIAL_MGMT, &begin));

    assert_ok(&a.send(CTAP_LARGE_BLOBS, &lb_get_full()));

    assert_eq!(
        a.send(CTAP_CREDENTIAL_MGMT, &cm(CM_ENUMERATE_RPS_NEXT, None))
            .status,
        CtapError::NotAllowed.as_u8(),
        "a largeBlobs read is not a credentialManagement continuation"
    );
}

/// The large-blob write keeps the looser *command* rule, deliberately: any
/// `largeBlobs` command continues it, including a read between two fragments. Its
/// time rule is the strict one — see the test below. A YubiKey retires this
/// sequence on nothing at all: not another command, not a non-continuing
/// largeBlobs, not a 35-second gap (all three measured). The failure mode is what
/// makes ours the safer side either way — a YubiKey has already dropped the stored
/// array by the time the second fragment arrives, while this one still holds the
/// old array intact.
// The CTAP 2.1 large-blob design, which a `largeblob-ext` build withdraws
// wholesale (§12.4: "Authenticators MUST NOT support both extensions").
#[cfg(not(feature = "largeblob-ext"))]
#[test]
fn a_large_blobs_read_does_not_abandon_the_write() {
    let mut a = Authr::fresh();
    let token = a.arm_token(PERM_LBW);
    let body = [0xA5u8; 40];
    let mut blob = body.to_vec();
    blob.extend_from_slice(&sha256(&body)[..16]);
    let split = 30;

    let p0 = lb_param(&token, 0, &blob[..split]);
    assert_ok_empty(&a.send(
        CTAP_LARGE_BLOBS,
        &lb_set(&blob[..split], 0, Some(blob.len() as u64), &p0),
    ));
    assert_ok(&a.send(CTAP_LARGE_BLOBS, &lb_get_full()));

    let p1 = lb_param(&token, split as u32, &blob[split..]);
    assert_ok_empty(&a.send(
        CTAP_LARGE_BLOBS,
        &lb_set(&blob[split..], split as u64, None, &p1),
    ));
}

/// A part-written array does not survive the idle window either. This is the
/// sequence that needs the timer most: on a PIN-less key its fragments carry no
/// token, so before this the only thing that could retire an abandoned transfer
/// was some *other* command arriving — send nothing and it sat in RAM for the
/// whole power cycle. The control is the same transfer with the same two
/// fragments and no gap, which commits.
// The CTAP 2.1 large-blob design, which a `largeblob-ext` build withdraws
// wholesale (§12.4: "Authenticators MUST NOT support both extensions").
#[cfg(not(feature = "largeblob-ext"))]
#[test]
fn an_idle_large_blob_write_is_abandoned() {
    let body = [0xA5u8; 40];
    let mut blob = body.to_vec();
    blob.extend_from_slice(&sha256(&body)[..16]); // 56 bytes total
    let split = 30;

    // Control: uninterrupted and unhurried-but-inside-the-window, the array commits.
    let mut b = Authr::fresh();
    let btoken = b.arm_token(PERM_LBW);
    let p0 = lb_param(&btoken, 0, &blob[..split]);
    assert_ok_empty(&b.send(
        CTAP_LARGE_BLOBS,
        &lb_set(&blob[..split], 0, Some(blob.len() as u64), &p0),
    ));
    b.clock += STATEFUL_WALK_IDLE_MS - 5_000;
    let p1 = lb_param(&btoken, split as u32, &blob[split..]);
    assert_ok_empty(&b.send(
        CTAP_LARGE_BLOBS,
        &lb_set(&blob[split..], split as u64, None, &p1),
    ));

    // The same transfer with the window elapsed: the second fragment has nothing
    // left to continue, and answers as an out-of-sequence one.
    let mut a = Authr::fresh();
    let token = a.arm_token(PERM_LBW);
    let p0 = lb_param(&token, 0, &blob[..split]);
    assert_ok_empty(&a.send(
        CTAP_LARGE_BLOBS,
        &lb_set(&blob[..split], 0, Some(blob.len() as u64), &p0),
    ));
    a.clock += STATEFUL_WALK_IDLE_MS;
    let p1 = lb_param(&token, split as u32, &blob[split..]);
    let r = a.send(
        CTAP_LARGE_BLOBS,
        &lb_set(&blob[split..], split as u64, None, &p1),
    );
    assert_eq!(
        r.status,
        CtapError::InvalidSeq.as_u8(),
        "an abandoned transfer must not accept its next fragment"
    );

    // And, as with the interrupted write, nothing was committed.
    let g = a.send(CTAP_LARGE_BLOBS, &lb_get_full());
    let mut d = field_at(&g.body, 1).expect("config fragment (0x01) present");
    assert_ne!(d.bytes().unwrap(), &blob[..], "nothing was committed");
}

/// The rule must not be wider than it says: a sequence continued by its own kind
/// is exactly the case the spec permits state for, so back-to-back legs still
/// work. Without this the three tests above would also pass on an authenticator
/// that had simply broken getNextAssertion.
#[test]
fn a_walk_survives_its_own_continuation() {
    let mut a = Authr::fresh();
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_rk(&[0xA1])));
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_rk(&[0xB2])));

    assert_ok(&a.send(CTAP_GET_ASSERTION, &ga()));
    assert_ok(&a.send(CTAP_GET_NEXT_ASSERTION, &[]));
    assert_eq!(
        a.send(CTAP_GET_NEXT_ASSERTION, &[]).status,
        CtapError::NotAllowed.as_u8(),
        "two credentials, so the third leg is the end of the list, not a retirement"
    );
}
