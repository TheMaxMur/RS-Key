// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The widest records the key loaders admit and the empty/fuller edges of the
//! AES record. Expected widths are literals, not recomputed from the expression
//! under test: a mutant that shrinks, inflates or drops a clamp must fail here
//! rather than agree with itself.

use super::*;
use rsk_fs::storage::ram::RamStorage;
use rsk_rsa::crt::crt_plaintext;
use rsk_rsa::rsa_from_pqe;
use rsk_rsa::vectors::hex;
use rsk_rsa::wycheproof::{Outcome, decrypt};

struct Fill;
impl Rng for Fill {
    fn fill(&mut self, out: &mut [u8]) {
        out.fill(7);
    }
}

/// A provisioned store whose DEK is live and whose PW3 session can open it.
fn ready_store() -> (Device<'static>, Fs<RamStorage>, Session) {
    let dev = Device {
        serial_hash: &[0xab; 32],
        serial_id: &[1; 8],
        otp_key: None,
        latched: false,
    };
    let mut fs = Fs::new(RamStorage::new());
    crate::init::scan_files(&dev, &mut fs, &mut Fill).unwrap();
    let mut sess = Session::new();
    sess.adopt_reseeded(
        &dev.pin_derive_session(PW1_DEFAULT),
        &dev.pin_derive_session(PW3_DEFAULT),
    );
    sess.has_pw3 = true;
    (dev, fs, sess)
}

/// Wycheproof's RSA-4096 valid decryption case: five 256-byte CRT fields, the
/// largest producer the sealed layout carries, taken from the corpus rather than
/// from a round trip through the code under test.
fn max_rsa() -> (RsaKey, [&'static str; 5]) {
    let case = decrypt()
        .into_iter()
        .find(|c| c.bits == 4096 && c.tc_id == "1" && c.result == Outcome::Valid)
        .expect("Wycheproof has an RSA-4096 valid decryption case");
    let p = hex(case.crt[0]);
    let q = hex(case.crt[1]);
    assert_eq!((p.len(), q.len()), (256, 256), "RSA-4096 prime width");
    let key = rsa_from_pqe(&[0x01, 0x00, 0x01], &p, &q).unwrap();
    (key, case.crt)
}

/// Seal the corpus key through the public store, and with `tail` append one byte
/// the record's layout does not explain — so the loader's clamp, not the
/// writer's width, decides how much is decoded.
fn stored_max_rsa(
    tail: bool,
) -> (
    Device<'static>,
    Fs<RamStorage>,
    Session,
    RsaKey,
    [&'static str; 5],
) {
    let (dev, mut fs, sess) = ready_store();
    let (key, crt) = max_rsa();
    store_rsa_key(&dev, &mut fs, &sess, EF_PK_DEC, &key).unwrap();
    if tail {
        let mut record = Secret::<[u8; MAX_CRT_PLAIN + DEK_SEAL_OVERHEAD + 1]>::zeroed();
        let n = fs.read_key(EF_PK_DEC, record.expose_mut()).unwrap();
        assert_eq!(n, MAX_CRT_PLAIN + DEK_SEAL_OVERHEAD);
        record.expose_mut()[n] = 0xa5;
        fs.put_key(EF_PK_DEC, Sealed::wrap(&record.expose()[..n + 1]))
            .unwrap();
    }
    (dev, fs, sess, key, crt)
}

#[test]
fn an_empty_aes_record_is_absent_not_a_malformed_key() {
    let (dev, mut fs, sess) = ready_store();
    fs.put_key(EF_AES_KEY, Sealed::wrap(&[])).unwrap();
    let mut read = [0u8; 32];
    assert_eq!(
        fs.read_key(EF_AES_KEY, &mut read),
        Some(0),
        "the record stays live"
    );
    let generation = fs.write_gen();
    assert!(matches!(
        load_aes_key(&dev, &mut fs, &sess),
        Err(Sw::REFERENCE_NOT_FOUND)
    ));
    assert_eq!(fs.write_gen(), generation, "a refused load writes nothing");
}

#[test]
fn a_fuller_aes_record_keeps_its_genuine_prefix() {
    let (dev, mut fs, sess) = ready_store();
    let key = [0x5a; 32];
    store_aes_key(&dev, &mut fs, &sess, &key).unwrap();
    let mut record = Secret::<[u8; 32 + DEK_SEAL_OVERHEAD + 1]>::zeroed();
    let n = fs.read_key(EF_AES_KEY, record.expose_mut()).unwrap();
    assert_eq!(n, 32 + DEK_SEAL_OVERHEAD);
    record.expose_mut()[n] = 0xa5;
    fs.put_key(EF_AES_KEY, Sealed::wrap(&record.expose()[..n + 1]))
        .unwrap();
    let generation = fs.write_gen();
    let (loaded, len) = load_aes_key(&dev, &mut fs, &sess).unwrap();
    assert_eq!(len, 32);
    assert_eq!(loaded.expose(), &key);
    assert_eq!(
        fs.write_gen(),
        generation,
        "the prefix policy must not migrate"
    );
}

#[test]
fn a_maximum_rsa_key_stores_at_the_full_sealed_width() {
    let (dev, mut fs, sess) = ready_store();
    let (key, _) = max_rsa();
    assert_eq!(key.size(), 512, "RSA-4096 modulus width");
    let mut plain = [0u8; MAX_CRT_PLAIN];
    assert_eq!(crt_plaintext(&key, &mut plain).unwrap(), MAX_CRT_PLAIN);
    store_rsa_key(&dev, &mut fs, &sess, EF_PK_DEC, &key).unwrap();
    let mut sealed = Secret::<[u8; MAX_CRT_PLAIN + DEK_SEAL_OVERHEAD]>::zeroed();
    assert_eq!(
        fs.read_key(EF_PK_DEC, sealed.expose_mut()),
        Some(MAX_CRT_PLAIN + DEK_SEAL_OVERHEAD),
        "a 1280-byte plaintext seals to 1308 bytes"
    );
}

#[test]
fn the_maximum_rsa_key_reloads_for_both_decipher_and_signing() {
    let (dev, mut fs, sess, key, crt) = stored_max_rsa(false);
    let generation = fs.write_gen();
    let loaded = load_rsa_key(&dev, &mut fs, &sess, EF_PK_DEC).unwrap();
    assert_eq!(loaded.n_be(), key.n_be());
    let loaded_crt = load_rsa_crt(&dev, &mut fs, &sess, EF_PK_DEC).unwrap();
    assert_eq!(loaded_crt.modulus_len(), 512);
    assert_eq!(loaded_crt.p(), hex(crt[0]));
    assert_eq!(loaded_crt.q(), hex(crt[1]));
    assert_eq!(loaded_crt.dp(), hex(crt[2]));
    assert_eq!(loaded_crt.dq(), hex(crt[3]));
    assert_eq!(loaded_crt.qinv(), hex(crt[4]));
    assert_eq!(
        fs.write_gen(),
        generation,
        "a current-layout record is not migrated"
    );
}

#[test]
fn a_tail_beyond_the_maximum_rsa_record_is_ignored() {
    let (dev, mut fs, sess, key, _) = stored_max_rsa(true);
    let generation = fs.write_gen();
    let loaded = load_rsa_key(&dev, &mut fs, &sess, EF_PK_DEC).unwrap();
    assert_eq!(loaded.n_be(), key.n_be());
    let loaded_crt = load_rsa_crt(&dev, &mut fs, &sess, EF_PK_DEC).unwrap();
    assert_eq!(loaded_crt.modulus_len(), 512);
    assert_eq!(
        fs.write_gen(),
        generation,
        "the tail must not be mistaken for a layout"
    );
}
