// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::Sealed;
use rsk_fs::storage::ram::RamStorage;
use rsk_rsa::MAX_RSA_BYTES;
use rsk_sdk::Apdu;
use rsk_secret::Secret;

use crate::keys::load_dek_keys;

struct Fill;
impl Rng for Fill {
    fn fill(&mut self, out: &mut [u8]) {
        out.fill(7);
    }
}

/// A provisioned store whose DEK the admin session can open.
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

#[test]
fn an_absent_algorithm_attribute_reads_as_the_documented_default() {
    let (_, mut fs, _) = ready_store();
    let mut buf = [0u8; 16];
    assert_eq!(algo_id(&mut fs, EF_ALGO_PRIV1, &mut buf), DEFAULT_ALGO[0]);
    // An empty present record is the same absent slot, not a zero algorithm.
    fs.put(EF_ALGO_PRIV1, &[]).unwrap();
    let mut buf = [0u8; 16];
    assert_eq!(algo_id(&mut fs, EF_ALGO_PRIV1, &mut buf), DEFAULT_ALGO[0]);
}

#[test]
fn an_exact_size_aes_pso_output_is_not_refused() {
    let (dev, mut fs, sess) = ready_store();
    crate::keys::store_aes_key(&dev, &mut fs, &sess, &[0x5a; 32]).unwrap();
    let data = [0x11u8; 16];
    let mut ciphertext = [0u8; 17];
    assert_eq!(
        aes_pso(&dev, &mut fs, &sess, true, &data, &mut ciphertext),
        Ok(17)
    );
    assert_eq!(ciphertext[0], 0x02);
    let mut plain = [0u8; 16];
    assert_eq!(
        aes_pso(&dev, &mut fs, &sess, false, &ciphertext, &mut plain),
        Ok(16)
    );
    assert_eq!(plain, data);
}

#[test]
fn a_long_form_template_still_yields_its_peer_point() {
    // The A6 wrapper in BER long form moves the walker two bytes past the
    // single-byte case; the 7F49 header is only where it says it is.
    let valid = [0xa6, 0x81, 0x06, 0x7f, 0x49, 0x03, 0x86, 0x01, 0x04];
    assert_eq!(parse_ecdh_point(&valid), Some(&[0x04][..]));
}

#[test]
fn a_legacy_blob_with_unusable_primes_keeps_its_own_error() {
    let (dev, mut fs, mut sess) = ready_store();
    sess.has_pw2 = true;
    let (mut key, mut nk) = load_dek_keys(&dev, &mut fs, &sess).unwrap();
    let mut blob = Secret::<[u8; 64]>::zeroed();
    // P even and Q odd: a structurally valid two-field blob whose primes
    // `RsaKey::from_p_q` refuses. `crt_from_plain` answers BadBlob, and a walk
    // that treats every error as a width falls through to the parsing loader,
    // which answers WRONG_DATA instead.
    blob.expose_mut()[..32].fill(0x02);
    blob.expose_mut()[32..].fill(0x03);
    rsk_crypto::aes::aes_encrypt_cfb_256(key.expose(), nk.expose(), blob.expose_mut()).unwrap();
    key.wipe();
    nk.wipe();
    fs.put_key(EF_PK_DEC, Sealed::wrap(blob.expose())).unwrap();

    let request = [0u8, INS_PSO, 0x80, 0x86, 1, 0x00];
    let apdu = Apdu::parse(&request).unwrap();
    let mut out = [0u8; MAX_RSA_BYTES];
    assert_eq!(
        try_pso(
            &dev,
            &mut fs,
            &sess,
            &mut Fill,
            &mut crate::AlwaysConfirm,
            &apdu,
            &mut out
        ),
        Err(Sw::MEMORY_FAILURE)
    );
}
