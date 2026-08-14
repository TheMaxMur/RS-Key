// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAP 2.3 §12.4 `largeBlob` on the wire, on a `largeblob-ext` build.
//!
//! Two things are checked here that no unit test can see. One is the swap §12.4
//! demands — "Authenticators MUST NOT support both extensions" — which is
//! observable only in getInfo and in what `authenticatorLargeBlobs` now answers.
//! The other is the round trip through `process_cbor`, where the blob has to
//! survive being written by one getAssertion and read by the next.

use super::{Authr, assert_ok, field_at};
use crate::consts::{
    ALG_ES256, CTAP_GET_ASSERTION, CTAP_LARGE_BLOBS, CTAP_MAKE_CREDENTIAL, MAX_LARGE_BLOB_SIZE,
};
use crate::error::CtapError;
use minicbor::Decoder;
use minicbor::Encoder;
use minicbor::encode::write::Cursor;

const RP_ID: &str = "example.com";

/// A makeCredential with the `largeBlob` extension asking for `support`, and
/// `rk` as given.
fn mc_large_blob(support: Option<&str>, rk: bool) -> Vec<u8> {
    let mut buf = [0u8; 256];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(5 + u64::from(support.is_some())).unwrap();
        e.u8(1).unwrap().bytes(&[0xCD; 32]).unwrap();
        e.u8(2).unwrap().map(1).unwrap();
        e.str("id").unwrap().str(RP_ID).unwrap();
        e.u8(3).unwrap().map(2).unwrap();
        e.str("id").unwrap().bytes(b"user-1").unwrap();
        e.str("name").unwrap().str("user").unwrap();
        e.u8(4).unwrap().array(1).unwrap().map(2).unwrap();
        e.str("alg").unwrap().i64(ALG_ES256).unwrap();
        e.str("type").unwrap().str("public-key").unwrap();
        if let Some(s) = support {
            e.u8(6).unwrap().map(1).unwrap();
            e.str("largeBlob").unwrap().map(1).unwrap();
            e.str("support").unwrap().str(s).unwrap();
        }
        e.u8(7).unwrap().map(1).unwrap();
        e.str("rk").unwrap().bool(rk).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// A getAssertion carrying a `largeBlob` read or write, optionally naming the
/// credential in an allowList (§12.4 makes a write conditional on one).
fn ga_large_blob(allow: Option<&[u8]>, write: Option<(&[u8], u64)>) -> Vec<u8> {
    ga_large_blob_up(allow, write, true)
}

/// [`ga_large_blob`] with the `up` option spelled out — `up: false` is the
/// platform's silent pre-flight probe.
fn ga_large_blob_up(allow: Option<&[u8]>, write: Option<(&[u8], u64)>, up: bool) -> Vec<u8> {
    let mut buf = vec![0u8; write.map_or(0, |(b, _)| b.len()) + 512];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut buf[..]));
        e.map(4 + u64::from(allow.is_some())).unwrap();
        e.u8(1).unwrap().str(RP_ID).unwrap();
        e.u8(2).unwrap().bytes(&[0xEF; 32]).unwrap();
        if let Some(id) = allow {
            e.u8(3).unwrap().array(1).unwrap().map(2).unwrap();
            e.str("id").unwrap().bytes(id).unwrap();
            e.str("type").unwrap().str("public-key").unwrap();
        }
        e.u8(4).unwrap().map(1).unwrap();
        e.str("largeBlob").unwrap();
        match write {
            None => {
                e.map(1).unwrap();
                e.str("read").unwrap().bool(true).unwrap();
            }
            Some((blob, size)) => {
                e.map(2).unwrap();
                e.str("write").unwrap().bytes(blob).unwrap();
                e.str("originalSize").unwrap().u64(size).unwrap();
            }
        }
        e.u8(5).unwrap().map(1).unwrap();
        e.str("up").unwrap().bool(up).unwrap();
        e.writer().position()
    };
    buf[..n].to_vec()
}

/// The `written` flag out of a getAssertion's unsigned extension output.
fn written_flag(body: &[u8]) -> bool {
    let value = unsigned_large_blob(body, 0x08).expect("unsignedExtensionOutputs (0x08)");
    let mut d = Decoder::new(&value);
    assert_eq!(d.map().unwrap(), Some(1));
    assert_eq!(d.str().unwrap(), "written");
    d.bool().unwrap()
}

/// The credentialId out of a makeCredential's attested credential data.
fn cred_id(body: &[u8]) -> Vec<u8> {
    let mut d = field_at(body, 2).expect("authData (0x02) present");
    let ad = d.bytes().unwrap();
    let cl = u16::from_be_bytes([ad[53], ad[54]]) as usize;
    ad[55..55 + cl].to_vec()
}

/// The `largeBlob` entry of an `unsignedExtensionOutputs` field, as a decoder
/// positioned on its value.
fn unsigned_large_blob(body: &[u8], key: u32) -> Option<Vec<u8>> {
    let mut d = field_at(body, key)?;
    // `field_at`'s decoder starts its own buffer at the field's value, so the
    // positions below index THAT, not `body`.
    let buf = d.input();
    let n = d.map().ok()??;
    for _ in 0..n {
        let k = d.str().ok()?;
        let vpos = d.position();
        if k == "largeBlob" {
            return Some(buf[vpos..].to_vec());
        }
        d.skip().ok()?;
    }
    None
}

/// getInfo's `extensions` array (0x02) as owned strings.
fn extensions(body: &[u8]) -> Vec<String> {
    let mut d = field_at(body, 0x02).expect("extensions (0x02) present");
    let n = d.array().unwrap().expect("definite-length array");
    (0..n).map(|_| d.str().unwrap().to_string()).collect()
}

#[test]
fn get_info_offers_the_extension_and_withdraws_the_pair() {
    let mut a = Authr::fresh();
    let info = a.get_info();
    assert_ok(&info);

    let ext = extensions(&info.body);
    assert!(
        ext.iter().any(|e| e == "largeBlob"),
        "the 2.3 extension must be advertised: {ext:?}"
    );
    assert!(
        !ext.iter().any(|e| e == "largeBlobKey"),
        "§12.4 forbids advertising both designs: {ext:?}"
    );

    // §6.4: "This option MUST NOT be set to true if the largeBlob extension is
    // supported instead" — and false is indistinguishable from absent, so the key
    // is simply not emitted.
    let mut opts = field_at(&info.body, 0x04).expect("options (0x04) present");
    let n = opts.map().unwrap().expect("definite-length map");
    for _ in 0..n {
        let k = opts.str().unwrap();
        assert_ne!(k, "largeBlobs", "the largeBlobs option must be withdrawn");
        opts.bool().unwrap();
    }

    assert!(
        field_at(&info.body, 0x0B).is_none(),
        "maxSerializedLargeBlobArray describes a command this build does not serve"
    );
}

#[test]
fn the_large_blobs_command_is_gone() {
    let mut a = Authr::fresh();
    let r = a.send(CTAP_LARGE_BLOBS, &[]);
    assert_eq!(r.status, CtapError::InvalidCommand.as_u8());
}

#[test]
fn a_discoverable_credential_reports_large_blob_support() {
    let mut a = Authr::fresh();
    let r = a.send(CTAP_MAKE_CREDENTIAL, &mc_large_blob(Some("required"), true));
    assert_ok(&r);
    let value = unsigned_large_blob(&r.body, 0x06).expect("unsignedExtensionOutputs (0x06)");
    let mut d = Decoder::new(&value);
    assert_eq!(d.map().unwrap(), Some(1));
    assert_eq!(d.str().unwrap(), "supported");
    assert!(d.bool().unwrap());
}

/// A non-discoverable credential keeps no on-device record, so there is nowhere
/// to hang a blob: `support: "required"` gets the storage-full status, while
/// `"preferred"` is served with no output rather than refused.
#[test]
fn a_required_blob_on_a_non_discoverable_credential_is_refused() {
    let mut a = Authr::fresh();
    let r = a.send(
        CTAP_MAKE_CREDENTIAL,
        &mc_large_blob(Some("required"), false),
    );
    assert_eq!(r.status, CtapError::LargeBlobStorageFull.as_u8());

    let r = a.send(
        CTAP_MAKE_CREDENTIAL,
        &mc_large_blob(Some("preferred"), false),
    );
    assert_ok(&r);
    assert!(
        field_at(&r.body, 0x06).is_none(),
        "an unmet `preferred` must not claim support"
    );
}

/// "However they MUST NOT return unsolicited output" — a request that never asked
/// gets no field 0x06, even though every discoverable credential here can hold a
/// blob.
#[test]
fn an_unasked_make_credential_says_nothing() {
    let mut a = Authr::fresh();
    let r = a.send(CTAP_MAKE_CREDENTIAL, &mc_large_blob(None, true));
    assert_ok(&r);
    assert!(field_at(&r.body, 0x06).is_none());
}

#[test]
fn a_named_credential_takes_a_blob_and_gives_it_back() {
    let mut a = Authr::fresh();
    let mc = a.send(CTAP_MAKE_CREDENTIAL, &mc_large_blob(Some("required"), true));
    assert_ok(&mc);
    let id = cred_id(&mc.body);

    let blob = [0x5Au8; 200];
    let w = a.send(
        CTAP_GET_ASSERTION,
        &ga_large_blob(Some(&id), Some((&blob, 777))),
    );
    assert_ok(&w);
    assert!(
        written_flag(&w.body),
        "a named credential must accept the blob"
    );

    let r = a.send(CTAP_GET_ASSERTION, &ga_large_blob(Some(&id), None));
    assert_ok(&r);
    let value = unsigned_large_blob(&r.body, 0x08).expect("unsignedExtensionOutputs (0x08)");
    let mut d = Decoder::new(&value);
    assert_eq!(d.map().unwrap(), Some(2));
    assert_eq!(d.str().unwrap(), "blob");
    assert_eq!(d.bytes().unwrap(), &blob[..]);
    assert_eq!(d.str().unwrap(), "originalSize");
    assert_eq!(d.u64().unwrap(), 777);
}

/// §12.4: a write lands only "if the authenticatorGetAssertion request included a
/// non-empty allowList". Discovery picking the credential is not good enough — the
/// platform has to name what it is overwriting.
#[test]
fn a_write_without_an_allow_list_is_refused() {
    let mut a = Authr::fresh();
    assert_ok(&a.send(CTAP_MAKE_CREDENTIAL, &mc_large_blob(Some("required"), true)));

    let w = a.send(CTAP_GET_ASSERTION, &ga_large_blob(None, Some((b"x", 1))));
    assert_ok(&w);
    assert!(
        !written_flag(&w.body),
        "an unnamed credential must not be written"
    );
}

/// "Fetch any largeBlob data for selected credentials. If there is none then stop
/// processing this extension" — the field is absent, not an empty map.
#[test]
fn a_read_with_nothing_stored_omits_the_output() {
    let mut a = Authr::fresh();
    let mc = a.send(CTAP_MAKE_CREDENTIAL, &mc_large_blob(Some("required"), true));
    assert_ok(&mc);
    let id = cred_id(&mc.body);

    let r = a.send(CTAP_GET_ASSERTION, &ga_large_blob(Some(&id), None));
    assert_ok(&r);
    assert!(
        field_at(&r.body, 0x08).is_none(),
        "an empty read must omit the field entirely"
    );
}

/// A blob too large for one flash record is refused by the flag §12.4 defines,
/// not by an error status — the same answer a full store gives.
#[test]
fn an_oversized_blob_answers_written_false() {
    let mut a = Authr::fresh();
    let mc = a.send(CTAP_MAKE_CREDENTIAL, &mc_large_blob(Some("required"), true));
    assert_ok(&mc);
    let id = cred_id(&mc.body);

    let blob = [0u8; MAX_LARGE_BLOB_SIZE];
    let w = a.send(
        CTAP_GET_ASSERTION,
        &ga_large_blob(Some(&id), Some((&blob, 1))),
    );
    assert_ok(&w);
    assert!(!written_flag(&w.body));
}

/// A silent `up:false` pre-flight may not destroy a stored blob. §12.4 leaves the
/// call to the authenticator — step 4.2 writes only if "the selected credential
/// can store the large blob data" — and no gesture was asked for on that probe.
/// A read on the same probe IS served: that discloses no more than the CTAP 2.1
/// pair already does ungated (docs/threat-model.md).
#[test]
fn a_silent_pre_flight_can_read_but_not_overwrite() {
    let mut a = Authr::fresh();
    let mc = a.send(CTAP_MAKE_CREDENTIAL, &mc_large_blob(Some("required"), true));
    assert_ok(&mc);
    let id = cred_id(&mc.body);
    assert_ok(&a.send(
        CTAP_GET_ASSERTION,
        &ga_large_blob(Some(&id), Some((b"original", 8))),
    ));

    let w = a.send(
        CTAP_GET_ASSERTION,
        &ga_large_blob_up(Some(&id), Some((b"clobbered", 9)), false),
    );
    assert_ok(&w);
    assert!(!written_flag(&w.body), "a probe must not overwrite a blob");

    let r = a.send(
        CTAP_GET_ASSERTION,
        &ga_large_blob_up(Some(&id), None, false),
    );
    assert_ok(&r);
    let value = unsigned_large_blob(&r.body, 0x08).expect("a read is served on a probe");
    let mut d = Decoder::new(&value);
    assert_eq!(d.map().unwrap(), Some(2));
    assert_eq!(d.str().unwrap(), "blob");
    assert_eq!(
        d.bytes().unwrap(),
        b"original",
        "the blob survived the probe"
    );
}

/// A credential deleted through the trusted-display path takes its blob with it,
/// and the slot's next occupant does not inherit it.
#[test]
fn deleting_the_credential_takes_the_blob() {
    let mut a = Authr::fresh();
    let mc = a.send(CTAP_MAKE_CREDENTIAL, &mc_large_blob(Some("required"), true));
    assert_ok(&mc);
    let id = cred_id(&mc.body);
    assert_ok(&a.send(
        CTAP_GET_ASSERTION,
        &ga_large_blob(Some(&id), Some((b"keep me", 7))),
    ));

    assert!(crate::passkeys::delete_cred(
        &mut a.fs,
        crate::consts::EF_CRED
    ));
    assert!(
        !a.fs.has_data(crate::consts::EF_CRED_BLOB),
        "the blob must not outlive the credential it belonged to"
    );
}
