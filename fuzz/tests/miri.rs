// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

// =========================================================================
// Miri integration tests — exercises each fuzz target's logic under the
// Rust Miri interpreter to detect undefined behaviour. Each test mirrors a
// fuzz target from fuzz_targets/ using fixed representative inputs.
//
// Run with:
//   MIRIFLAGS="-Zmiri-many-seeds -Zdeduplicate-diagnostics \
//              -Zmiri-strict-provenance" \
//     cargo +nightly miri test --manifest-path fuzz/Cargo.toml
//
// Or (with Nix):
//   MIRIFLAGS="..." nix develop .#fuzz -c cargo miri test
//
// Filter to a single target: add `-- miri_apdu`
// =========================================================================

use rsk_crypto::{Device, HmacDrbg, MlKem768Pair, base64url, chachapoly, sha256};
use rsk_crypto::{kdf::PinKdf, mldsa44_verify, mlkem768_encapsulate, pinproto};
use rsk_fido::credential::{CredExt, CredInput, credential_create, credential_load};
use rsk_fido::hmacsecret;
use rsk_fido::seed::{ensure_seed, load_keydev};
use rsk_fido::{Ctx, FidoState, Rng};
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;
use rsk_openpgp::consts::{PW1_DEFAULT, PW1_MODE81, PW1_MODE82, PW3_DEFAULT, PW3_MODE83};
use rsk_openpgp::keys::{Curve, MAX_RSA_DIGESTINFO, PrivKey, curve_from_attr, rsa_sign_em};
use rsk_openpgp::pso::parse_ecdh_point;
use rsk_openpgp::{OpenpgpApplet, scan_files};
use rsk_otp::hid::{FrameRx, FrameTx, REPORT_SIZE, RxOutcome};
use rsk_rescue::phy::{PHY_MAX_SIZE, PhyData};
use rsk_sdk::apdu::Apdu;
use rsk_sdk::tlv::{Tlv, find_tag};
use rsk_sdk::{Applet, ResBuf};
use rsk_usb::ccid::process_message;
use rsk_usb::ctaphid::{CTAP_MAX_MESSAGE, HID_RPT_SIZE, Outcome, Reassembler, TxFrames};

use core::cell::RefCell;

// -------------------------------------------------------------------------
// Shared RNG and helpers
// -------------------------------------------------------------------------

struct SeqRng(u64);
impl Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

struct CountRng(u8);
impl rsk_oath::Rng for CountRng {
    fn fill(&mut self, b: &mut [u8]) {
        for x in b.iter_mut() {
            *x = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}
impl rsk_openpgp::Rng for CountRng {
    fn fill(&mut self, b: &mut [u8]) {
        for x in b.iter_mut() {
            *x = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}
impl rsk_rescue::Rng for CountRng {
    fn fill(&mut self, b: &mut [u8]) {
        for x in b.iter_mut() {
            *x = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}
impl rsk_otp::Rng for CountRng {
    fn fill(&mut self, b: &mut [u8]) {
        for x in b.iter_mut() {
            *x = self.0;
            self.0 = self.0.wrapping_add(1);
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

// =========================================================================
// apdu
// =========================================================================

#[test]
fn miri_apdu() {
    for data in [
        &b""[..],
        b"\x00",
        b"\x00\xa4\x04\x00",
        b"\x00\xa4\x04\x00\x08\xa0\x00\x00\x05\x27\x21\x01\x01",
        b"\xff\xff\xff\xff\xff",
        b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a",
    ] {
        let _ = Apdu::parse(data);
    }
}

// =========================================================================
// tlv
// =========================================================================

#[test]
fn miri_tlv() {
    for data in [
        &b""[..],
        b"\x00\x01\xff",
        b"\x30\x04\x02\x01\x01\x02\x01\x02",
        b"\x5a\x02\xaa\xbb",
        b"\x80\x00",
        b"\x1f\xff",
        b"\xff\xff\xff\xff\xff",
    ] {
        for (_tag, _value) in Tlv::new(data) {}
        let _ = find_tag(data, 0x5A);
    }
}

// =========================================================================
// fs_meta
// =========================================================================

#[test]
fn miri_fs_meta() {
    use rsk_fs::{Fs, Storage};
    use rsk_sdk::error::Result;

    struct MetaBlob<'a>(&'a [u8]);
    impl Storage for MetaBlob<'_> {
        fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
            if fid != rsk_fs::EF_META {
                return None;
            }
            let n = self.0.len().min(buf.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            Some(self.0.len())
        }
        fn write(&mut self, _fid: u16, _data: &[u8]) -> Result<()> {
            Ok(())
        }
        fn remove(&mut self, _fid: u16) -> Result<()> {
            Ok(())
        }
        fn size(&mut self, fid: u16) -> Option<usize> {
            (fid == rsk_fs::EF_META).then_some(self.0.len())
        }
        // Non-enumerating stub: report "incomplete" so `scan` keeps confirm-on-miss.
        fn for_each_key(&mut self, _f: &mut dyn FnMut(u16)) -> bool {
            false
        }
    }

    for data in [&b""[..], b"\x00\x00", b"\xcf\x01\x01\x42"] {
        let mut fs = Fs::new(MetaBlob(data));
        let mut out = [0u8; 256];
        for fid in [0x0000, 0xCF01, 0xE010, 0xFFFF] {
            let _ = fs.meta_find(fid, &mut out);
        }
    }
}

// =========================================================================
// ctaphid
// =========================================================================

#[test]
fn miri_ctaphid() {
    for data in [
        &b""[..],
        &[0x12; 64],
        &[0x12; 128],
        &[0x12; 200],
        &[
            0x00, 0x01, 0x02, 0x03, 0x81, 0x00, 0x07, 0x08, // init
            0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
            0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
            0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
            0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
            0x12, // cont
            0x00, 0x07, 0x00, 0x07, 0x00, 0x07, // seq 1
            0x00, 0x07, 0x00, 0x07, 0x00, 0x07, // seq 2
        ][..],
    ] {
        let mut asm = Reassembler::new();
        for chunk in data.chunks(HID_RPT_SIZE) {
            let mut frame = [0u8; HID_RPT_SIZE];
            frame[..chunk.len()].copy_from_slice(chunk);
            if let Outcome::Message(_cid, _cmd) = asm.feed(&frame) {
                assert!(asm.message().len() <= CTAP_MAX_MESSAGE);
            }
        }
    }
}

// =========================================================================
// ctaphid_roundtrip
// =========================================================================

#[test]
fn miri_ctaphid_roundtrip() {
    const CID: u32 = 0x0100_0000;
    const CMD: u8 = 0x80 | 0x01;
    for data in [
        &b""[..],
        b"\x00",
        b"\x01\x02\x03",
        &[0x55; 256],
        &[0x55; 1000],
    ] {
        if data.len() > CTAP_MAX_MESSAGE {
            continue;
        }
        let mut asm = Reassembler::new();
        let mut last = Outcome::None;
        for frame in TxFrames::new(CID, CMD, data) {
            last = asm.feed(&frame);
        }
        match last {
            Outcome::Message(cid, cmd) => {
                assert_eq!(cid, CID);
                assert_eq!(cmd, CMD);
                assert_eq!(asm.message(), data);
            }
            other => panic!("framed message did not reassemble: {other:?}"),
        }
    }
}

// =========================================================================
// base64url
// =========================================================================

#[test]
fn miri_base64url() {
    for data in [&b""[..], b"hello", b"aGVsbG8", &[0xFF; 64], &[0x41; 128]] {
        let mut dbuf = [0u8; 8192];
        let _ = base64url::decode(&mut dbuf, data);

        let src = &data[..data.len().min(1024)];
        let mut ebuf = [0u8; 1400];
        let en = base64url::encode(&mut ebuf, src).expect("dst large enough");
        let mut back = [0u8; 1024];
        let dn = base64url::decode(&mut back, &ebuf[..en]).expect("self-encoded is valid");
        assert_eq!(&back[..dn], src);
    }
}

// =========================================================================
// aes_gcm
// =========================================================================

#[test]
fn miri_aes_gcm() {
    for data in [&[0u8; 64], &[1u8; 64]] {
        if data.len() < 44 {
            continue;
        }
        let key: [u8; 32] = data[..32].try_into().unwrap();
        let nonce: [u8; 12] = data[32..44].try_into().unwrap();
        let msg = &data[44..];
        let n = msg.len().min(64);
        let aad_len = msg.len().min(16);

        let mut buf = [0u8; 128];
        buf[..n].copy_from_slice(&msg[..n]);
        let mut aad = [0u8; 16];
        aad[..aad_len].copy_from_slice(&msg[..aad_len]);
        let aad = &aad[..aad_len];

        let tag = rsk_crypto::aes::aes256gcm_encrypt(&key, &nonce, aad, &mut buf[..n]);
        let mut dec = [0u8; 128];
        dec[..n].copy_from_slice(&buf[..n]);
        rsk_crypto::aes::aes256gcm_decrypt(&key, &nonce, aad, &mut dec[..n], &tag)
            .expect("round-trip authenticates");
        assert_eq!(&dec[..n], &msg[..n]);

        let mut bad = tag;
        bad[0] ^= 0xff;
        let mut dec2 = [0u8; 128];
        dec2[..n].copy_from_slice(&buf[..n]);
        assert!(
            rsk_crypto::aes::aes256gcm_decrypt(&key, &nonce, aad, &mut dec2[..n], &bad).is_err()
        );
    }
}

// =========================================================================
// chachapoly
// =========================================================================

#[test]
fn miri_chachapoly() {
    for data in [&[0u8; 64], &[2u8; 64]] {
        if data.len() < 44 {
            continue;
        }
        let key: [u8; 32] = data[..32].try_into().unwrap();
        let nonce: [u8; 12] = data[32..44].try_into().unwrap();
        let msg = &data[44..];
        let n = msg.len().min(64);
        let aad_len = msg.len().min(16);

        let mut buf = [0u8; 128];
        buf[..n].copy_from_slice(&msg[..n]);
        let mut aad = [0u8; 16];
        aad[..aad_len].copy_from_slice(&msg[..aad_len]);
        let aad = &aad[..aad_len];

        let tag = chachapoly::chacha20poly1305_encrypt(&key, &nonce, aad, &mut buf[..n]);
        let mut dec = [0u8; 128];
        dec[..n].copy_from_slice(&buf[..n]);
        chachapoly::chacha20poly1305_decrypt(&key, &nonce, aad, &mut dec[..n], &tag)
            .expect("round-trip authenticates");
        assert_eq!(&dec[..n], &msg[..n]);

        let mut bad = tag;
        bad[0] ^= 0xff;
        let mut dec2 = [0u8; 128];
        dec2[..n].copy_from_slice(&buf[..n]);
        assert!(
            chachapoly::chacha20poly1305_decrypt(&key, &nonce, aad, &mut dec2[..n], &bad).is_err()
        );
    }
}

// =========================================================================
// fido_cbor
// =========================================================================

#[test]
fn miri_fido_cbor() {
    for data in [
        &b"\x04\xa1\x01\xa5"[..], // getInfo
        &b"\xff"[..],
        b"\x01",
        &[],
    ] {
        let d = dev();
        let mut fs = Fs::new(RamStorage::new());
        let mut rng = SeqRng(1);
        let _ = ensure_seed(&d, &mut fs, &mut rng);
        let mut out = [0u8; 2048];
        let mut state = FidoState::new();
        let mut presence = rsk_fido::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: d,
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        let n = rsk_fido::process_cbor(&mut ctx, data, &mut out);
        assert!(n >= 1 && n <= out.len());
    }
}

// =========================================================================
// fido_vendor
// =========================================================================

#[test]
fn miri_fido_vendor() {
    use rsk_fido::seed::seal_seed_locked;
    use rsk_fido::vendor::vendor;

    for (data, soft_lock) in [(&b"\x00"[..], false), (b"\x01", true)] {
        let d = dev();
        let mut fs = Fs::new(RamStorage::new());
        let mut rng = SeqRng(1);
        let _ = ensure_seed(&d, &mut fs, &mut rng);
        if soft_lock {
            let blob = seal_seed_locked(&mut rng, &[0x4D; 32], &[0x5A; 32]);
            let _ = fs.put(rsk_fido::consts::EF_KEY_DEV_ENC.get(), &blob);
            let _ = fs.delete(rsk_fido::consts::EF_KEY_DEV.get());
        }
        let mut state = FidoState::new();
        state.mse_active = true;
        state.mse_key = [0x5A; 32];
        state.mse_pub = [0x04; 65];
        let mut out = [0u8; 2048];
        let mut presence = rsk_fido::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: d,
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        let n = vendor(&mut ctx, data, &mut out);
        if let Ok(len) = n {
            assert!(len <= out.len());
        }
    }
}

// =========================================================================
// fido_cred
// =========================================================================

#[test]
fn miri_fido_cred() {
    for data in [&b""[..], b"\x00", b"\x00\x01\x02", &[0xFF; 128]] {
        let seed = [0x42u8; 32];
        let rp_hash = [0x99u8; 32];
        let mut scratch = [0u8; 2048];
        assert!(credential_load(&seed, data, &rp_hash, &mut scratch).is_none());
    }
}

// =========================================================================
// fido_cred_ext
// =========================================================================

#[test]
fn miri_fido_cred_ext() {
    use rsk_fido::consts::MAX_CREDBLOB_LENGTH;
    for (flags, blob) in [(0u8, &b""[..]), (3, b"myblob"), (0x10, b""), (0xFF, b"x")] {
        let d = dev();
        let seed = [0x42u8; 32];
        let rp_hash = sha256(b"example.com");
        let iv = [0x11u8; 12];
        let ext = CredExt {
            cred_protect: (flags & 0x03) as u64,
            cred_blob: blob,
            hmac_secret: flags & 0x10 != 0,
            large_blob_key: flags & 0x20 != 0,
            third_party_payment: flags & 0x40 != 0,
        };
        let input = CredInput {
            rp_id: "example.com",
            user_id: &[1, 2, 3, 4],
            user_name: "u",
            user_display_name: "d",
            use_sign_count: true,
            rk: false,
            created_ms: 0,
            alg: -7,
            curve: 1,
            ext,
        };
        let mut out = [0u8; 1024];
        if let Ok(len) = credential_create(&seed, &d, &input, &rp_hash, &iv, &mut out) {
            let mut scratch = [0u8; 1024];
            let c = credential_load(&seed, &out[..len], &rp_hash, &mut scratch)
                .expect("a freshly sealed box must load");
            assert_eq!(c.ext.cred_protect, (flags & 0x03) as u64);
            assert_eq!(c.ext.hmac_secret, flags & 0x10 != 0);
            assert_eq!(c.ext.large_blob_key, flags & 0x20 != 0);
            assert_eq!(c.ext.third_party_payment, flags & 0x40 != 0);
            if !blob.is_empty() && blob.len() < MAX_CREDBLOB_LENGTH {
                assert_eq!(c.ext.cred_blob, blob);
            } else {
                assert!(c.ext.cred_blob.is_empty());
            }
        }
    }
}

// =========================================================================
// fido_hmac_secret
// =========================================================================

#[test]
fn miri_fido_hmac_secret() {
    for data in [&b""[..], b"\x00", b"\xa1\x02\x58\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"] {
        if let Ok(req) = hmacsecret::parse_bytes(data) {
            let mut rng = SeqRng(1);
            let ephemeral = [0x11u8; 32];
            let seed = [0x42u8; 32];
            let cred_id = [0x55u8; 80];
            let mut out = [0u8; 80];
            let _ = hmacsecret::eval(&req, &ephemeral, &seed, &cred_id, false, &mut rng, &mut out);
        }
    }
}

// =========================================================================
// fido_credmgmt
// =========================================================================

#[test]
fn miri_fido_credmgmt() {
    use rsk_fido::credential::credential_store;
    use rsk_fido::credmgmt::cred_mgmt;
    use rsk_fido::state::PERM_CM;

    for data in [&b""[..], b"\x08\xa1\x02\xa1", b"\x05\xa1\x03\xa1\x05\xa1"] {
        let d = dev();
        let mut fs = Fs::new(RamStorage::new());
        let mut rng = SeqRng(1);
        let _ = ensure_seed(&d, &mut fs, &mut rng);
        let rp_hash = sha256(b"a.co");
        if let Some(seed) = load_keydev(&d, &mut fs) {
            let input = CredInput {
                rp_id: "a.co",
                user_id: &[1, 2],
                user_name: "u",
                user_display_name: "",
                use_sign_count: true,
                rk: true,
                created_ms: 1,
                alg: -7,
                curve: 1,
                ext: CredExt {
                    cred_protect: 0,
                    cred_blob: &[],
                    hmac_secret: false,
                    large_blob_key: false,
                    third_party_payment: false,
                },
            };
            let mut cred_box = [0u8; 512];
            if let Ok(len) =
                credential_create(&seed, &d, &input, &rp_hash, &[0x11; 12], &mut cred_box)
            {
                let _ = credential_store(
                    &seed,
                    &d,
                    &mut fs,
                    &cred_box[..len],
                    &rp_hash,
                    "a.co",
                    &[1, 2],
                    &[],
                );
            }
        }
        let mut state = FidoState::new();
        state.paut.token = [0x99; 32];
        state.paut.permissions = PERM_CM;
        state.begin_using_token(false, 0);
        let mut out = [0u8; 2048];
        let mut presence = rsk_fido::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: d,
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 2,
        };
        if let Ok(n) = cred_mgmt(&mut ctx, data, &mut out) {
            assert!(n <= out.len());
        }
    }
}

// =========================================================================
// fido_u2f
// =========================================================================

#[test]
fn miri_fido_u2f() {
    for data in [
        &b"\x00\x03\x00\x00\x00\x00\x00"[..], // version
        b"\x00\x01\x00\x00\x00\x40\x00\x00",  // register-like
    ] {
        let Ok(apdu) = Apdu::parse(data) else {
            continue;
        };
        let d = dev();
        let mut fs = Fs::new(RamStorage::new());
        let mut rng = SeqRng(1);
        let _ = ensure_seed(&d, &mut fs, &mut rng);
        let mut out = [0u8; 2048];
        let mut state = FidoState::new();
        let mut presence = rsk_fido::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: d,
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        let (_sw, n) = rsk_fido::u2f::process_u2f(&mut ctx, &apdu, &mut out);
        assert!(n <= out.len());
    }
}

// =========================================================================
// fido_largeblobs
// =========================================================================

#[test]
fn miri_fido_largeblobs() {
    use rsk_fido::largeblobs::large_blobs;
    use rsk_fido::state::PERM_LBW;

    for data in [&b""[..], b"\x01", b"\x00"] {
        let d = dev();
        let mut fs = Fs::new(RamStorage::new());
        let mut rng = SeqRng(1);
        let _ = ensure_seed(&d, &mut fs, &mut rng);
        let mut state = FidoState::new();
        state.paut.token = [0x99; 32];
        state.paut.permissions = PERM_LBW;
        state.begin_using_token(false, 0);
        let mut out = [0u8; 2048];
        let mut presence = rsk_fido::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: d,
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 2,
        };
        if let Ok(n) = large_blobs(&mut ctx, data, &mut out) {
            assert!(n <= out.len());
        }
    }
}

// =========================================================================
// pin_kdf
// =========================================================================

#[test]
fn miri_pin_kdf() {
    for data in [&b""[..], b"short", b"123456", &[0xFF; 64]] {
        let d = dev();
        let _ = d.hash_multi(data);
        let _ = d.double_hash_pin(data);
        let _ = d.derive_kver(data);
        let _ = d.pin_derive_verifier(data);
        let _ = d.pin_derive_session(data);

        let token = [0x33u8; 32];
        let nonce = [0x44u8; 12];
        let pt = &data[..data.len().min(32)];
        let mut out = [0u8; 12 + 32 + 16];
        if let Ok(n) = d.encrypt_with_aad(&token, pt, PinKdf::V2, &nonce, &mut out) {
            let mut back = [0u8; 32];
            let m = d
                .decrypt_with_aad(&token, &out[..n], PinKdf::V2, &mut back)
                .expect("round-trip authenticates");
            assert_eq!(&back[..m], pt);
        }
    }
}

// =========================================================================
// pinproto
// =========================================================================

#[test]
fn miri_pinproto() {
    use rsk_crypto::pinproto::PinProto;

    let shared = [0x5Au8; 64];
    for proto in [PinProto::One, PinProto::Two] {
        let scalar = [0x11u8; 32];
        let mut out = [0u8; 64];
        let _ = pinproto::ecdh(proto, &scalar, &[0x5A; 32], &[0xA5; 32], &mut out);

        for ct in [&b""[..], &[0u8; 32], &[0u8; 64]] {
            let mut pt = [0u8; 256];
            let _ = pinproto::decrypt(proto, &shared, ct, &mut pt);
        }

        let data = [0x42u8; 16];
        let iv = [0x77u8; 16];
        let mut ct = [0u8; 32 + 16];
        if let Ok(n) = pinproto::encrypt(proto, &shared, &iv, &data, &mut ct) {
            let mut back = [0u8; 32];
            let m = pinproto::decrypt(proto, &shared, &ct[..n], &mut back).expect("round-trip");
            assert_eq!(&back[..m], &data);
        }

        let _ = pinproto::verify(proto, &shared, &data, &data);
    }
}

// =========================================================================
// openpgp_apdu
// =========================================================================

#[test]
fn miri_openpgp_apdu() {
    const SERIAL_ID: [u8; 8] = [0xAA, 0xBB, 0xCC, 0xDD, 5, 6, 7, 8];
    const SERIAL_HASH: [u8; 32] = [0x22; 32];

    fn run(app: &mut OpenpgpApplet, fs: &mut Fs<RamStorage>, raw: &[u8]) {
        if let Ok(apdu) = Apdu::parse(raw) {
            let mut buf = [0u8; 2048];
            let mut res = ResBuf::new(&mut buf);
            let _ = app.process(&apdu, fs, &mut res);
        }
    }

    let d = Device {
        serial_hash: &SERIAL_HASH,
        serial_id: &SERIAL_ID,
        otp_key: None,
    };
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    if scan_files(&d, &mut fs, &mut CountRng(0)).is_err() {
        return;
    }
    let rng = RefCell::new(CountRng(0));
    let presence = RefCell::new(rsk_openpgp::AlwaysConfirm);
    let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);

    for (mode, pin) in [
        (PW3_MODE83, PW3_DEFAULT),
        (PW1_MODE81, PW1_DEFAULT),
        (PW1_MODE82, PW1_DEFAULT),
    ] {
        let mut v = vec![
            0x00,
            rsk_openpgp::consts::INS_VERIFY,
            0x00,
            mode,
            pin.len() as u8,
        ];
        v.extend_from_slice(pin);
        run(&mut app, &mut fs, &v);
    }

    for data in [
        &b"\x00\xa4\x04\x00"[..],
        b"\x00\xca\x00\x00",
        b"\x00\xc0\x00\x00",
        &[
            0x00, 0x20, 0x00, 0x81, 0x06, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        ],
    ] {
        run(&mut app, &mut fs, data);
    }
}

// =========================================================================
// openpgp_import
// =========================================================================

#[test]
fn miri_openpgp_import() {
    use rsk_openpgp::importdata::{parse_ehl_body, parse_ehl_head};
    for data in [
        &b""[..],
        b"\x00\x00\x00\x00\x00\x00\x00",
        b"\x4d\x00\x7f\x48\x00\x00\x00",
        b"\x00\x00\x7f\x48\x00\x00\x00\x00\x00\x00\x00",
    ] {
        if let Ok((_fid, pos)) = parse_ehl_head(data) {
            let _ = parse_ehl_body(data, pos);
        }
    }
}

// =========================================================================
// openpgp_ecdh
// =========================================================================

#[test]
fn miri_openpgp_ecdh() {
    let p256 = PrivKey::from_scalar(Curve::P256, &[0x11; 32]).unwrap();
    let x25519 = PrivKey::from_scalar(Curve::X25519, &[0x22; 32]).unwrap();
    let mut out = [0u8; 64];

    for data in [
        &b""[..],
        b"\x00",
        &[0x04u8; 65],
        b"\xa6\x0e\x7f\x49\x0c\x86\x0a\x41\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    ] {
        if let Some(point) = parse_ecdh_point(data) {
            let _ = p256.ecdh(point, &mut out);
            let _ = x25519.ecdh(point, &mut out);
        }
        let _ = p256.ecdh(data, &mut out);
        let _ = x25519.ecdh(data, &mut out);
    }
}

// =========================================================================
// openpgp_ec_key
// =========================================================================

#[test]
fn miri_openpgp_ec_key() {
    const CURVES: [Curve; 5] = [
        Curve::P256,
        Curve::P384,
        Curve::P521,
        Curve::K256,
        Curve::Ed25519,
    ];

    for data in [
        &b"\x00"[..],
        b"\x00\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",
        b"\x00\x05\x2b\x81\x04\x00\x22",
        b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    ] {
        if data.is_empty() {
            continue;
        }
        let _ = curve_from_attr(data);
        let curve = CURVES[data[0] as usize % CURVES.len()];
        if let Some(key) = PrivKey::from_scalar(curve, &data[1..]) {
            let mut pt = [0u8; 200];
            let _ = key.public_point(&mut pt);
        }
    }
}

// =========================================================================
// openpgp_rsa_sign
// =========================================================================

#[test]
fn miri_openpgp_rsa_sign() {
    for data in [
        &b""[..],
        b"\x00",
        b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        b"\x00\x00\x00\x00\x00\x00",
    ] {
        let mut em = [0u8; MAX_RSA_DIGESTINFO];
        if let Some(n) = rsa_sign_em(data, &mut em) {
            assert!(n <= MAX_RSA_DIGESTINFO);
        }
    }
}

// =========================================================================
// ccid
// =========================================================================

#[test]
fn miri_ccid() {
    const ATR: &[u8] = &[0x3b, 0xda, 0x18, 0xff, 0x81, 0xb1, 0xfe, 0x75, 0x1f, 0x03];
    for data in [
        &b""[..],
        b"\x62\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        b"\x63\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        b"\x6f\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        &[
            0x6f, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa4, 0x04, 0x00,
            0x00,
        ],
    ] {
        let mut status = 0u8;
        let mut out = [0u8; 2048];
        let _ = process_message(data, ATR, &mut status, &mut out);
    }
}

// =========================================================================
// drbg
// =========================================================================

#[test]
fn miri_drbg() {
    for (seed, len) in [
        (&b""[..], 0usize),
        (b"\x01\x02\x03\x04\x05\x06\x07\x08", 32),
        (b"\xff", 16),
        (&[0xAA; 64], 255),
    ] {
        let mut a = HmacDrbg::new(seed);
        let mut b = HmacDrbg::new(seed);
        let mut out_a = [0u8; 256];
        let mut out_b = [0u8; 256];
        a.fill(&mut out_a[..len]);
        b.fill(&mut out_b[..len]);
        assert_eq!(out_a[..len], out_b[..len]);

        a.reseed(seed);
        let mut more = [0u8; 64];
        a.fill(&mut more);
    }
}

// =========================================================================
// pqc
// =========================================================================

#[test]
fn miri_pqc() {
    use rsk_crypto::mlkem::{MLKEM768_CT_LEN, MLKEM768_EK_LEN, MLKEM768_SEED_LEN};
    use rsk_crypto::{MLDSA44_PK_LEN, MLDSA44_SIG_LEN};

    for data in [&[0u8; 16], &[0x42u8; 16]] {
        let mut pk = [0u8; MLDSA44_PK_LEN];
        let mut sig = [0u8; MLDSA44_SIG_LEN];
        let mut ek = [0u8; MLKEM768_EK_LEN];
        let mut ct = [0u8; MLKEM768_CT_LEN];

        for (dst, chunk) in [
            (&mut pk[..], 0),
            (&mut sig[..], 1),
            (&mut ek[..], 2),
            (&mut ct[..], 3),
        ] {
            for (i, b) in dst.iter_mut().enumerate() {
                *b = data
                    .get((i + chunk) % data.len().max(1))
                    .copied()
                    .unwrap_or(chunk as u8);
            }
        }

        let _ = mldsa44_verify(&pk, data, &sig);
        let _ = mlkem768_encapsulate(&ek, &[0u8; 32]);

        let mut seed = [0u8; MLKEM768_SEED_LEN];
        let n = data.len().min(MLKEM768_SEED_LEN);
        seed[..n].copy_from_slice(&data[..n]);
        let pair = MlKem768Pair::from_seed(&seed);
        let _ = pair.decapsulate(&ct);
    }
}

// =========================================================================
// mgmt_apdu
// =========================================================================

#[test]
fn miri_mgmt_apdu() {
    use rsk_mgmt::{AlwaysConfirm, ManagementApplet};
    let presence = RefCell::new(AlwaysConfirm);
    for data in [
        &b"\x00\xa4\x04\x00"[..],
        b"\x00\xcb\x00\x00",
        b"\x00\xcc\x00\x00\x04\x01\x02\x03\x04",
        b"\x00\xcb\x00\x00",
    ] {
        let mut fs = Fs::new(RamStorage::new());
        fs.scan();
        let mut app = ManagementApplet::new([0x12, 0x34, 0x56, 0x78, 1, 2, 3, 4], &presence);
        if let Ok(apdu) = Apdu::parse(data) {
            let mut buf = [0u8; 256];
            let mut res = ResBuf::new(&mut buf);
            let _ = app.process(&apdu, &mut fs, &mut res);
        }
    }
}

// =========================================================================
// mgmt_config
// =========================================================================

#[test]
fn miri_mgmt_config() {
    use rsk_mgmt::{AlwaysConfirm, ManagementApplet};

    fn run(app: &mut ManagementApplet<'_>, fs: &mut Fs<RamStorage>, raw: &[u8]) {
        if let Ok(apdu) = Apdu::parse(raw) {
            let mut buf = [0u8; 256];
            let mut res = ResBuf::new(&mut buf);
            let _ = app.process(&apdu, fs, &mut res);
        }
    }

    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = ManagementApplet::new([0x12, 0x34, 0x56, 0x78, 1, 2, 3, 4], &presence);
    // Write blobs of several lengths — including past the 64-byte read buffer,
    // the case that used to panic READ CONFIG — then read each back.
    for inner in [0usize, 4, 64, 65, 200] {
        let mut cmd = std::vec![0x00, 0x1C, 0, 0, (inner + 1) as u8, inner as u8];
        cmd.resize(cmd.len() + inner, 0xAB);
        run(&mut app, &mut fs, &cmd);
        run(&mut app, &mut fs, &[0x00, 0x1D, 0, 0, 0x00]);
    }
}

// =========================================================================
// cross_applet
// =========================================================================

#[test]
fn miri_cross_applet() {
    use core::cell::RefCell;
    use rsk_mgmt::ManagementApplet;
    use rsk_oath::OathApplet;
    use rsk_openpgp::OpenpgpApplet;
    use rsk_otp::OtpApplet;
    use rsk_piv::PivApplet;
    use rsk_sdk::Dispatcher;

    struct R(u64);
    impl rsk_openpgp::Rng for R {
        fn fill(&mut self, b: &mut [u8]) {
            for x in b.iter_mut() {
                self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
                *x = (self.0 >> 33) as u8;
            }
        }
    }
    impl rsk_oath::Rng for R {
        fn fill(&mut self, b: &mut [u8]) {
            for x in b.iter_mut() {
                self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
                *x = (self.0 >> 33) as u8;
            }
        }
    }
    impl rsk_otp::Rng for R {
        fn fill(&mut self, b: &mut [u8]) {
            for x in b.iter_mut() {
                self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
                *x = (self.0 >> 33) as u8;
            }
        }
    }

    fn sel(aid: &[u8]) -> std::vec::Vec<u8> {
        let mut v = std::vec![0x00u8, 0xA4, 0x04, 0x00, aid.len() as u8];
        v.extend_from_slice(aid);
        v
    }

    const SID: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 1, 2, 3, 4];
    const SH: [u8; 32] = [0x22; 32];

    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    let rng = RefCell::new(R(1));
    let pgp_pres = RefCell::new(rsk_openpgp::AlwaysConfirm);
    let oath_pres = RefCell::new(rsk_oath::AlwaysConfirm);
    let otp_pres = RefCell::new(rsk_otp::AlwaysConfirm);
    let mgmt_pres = RefCell::new(rsk_mgmt::AlwaysConfirm);
    let mut openpgp = OpenpgpApplet::new(SID, SH, None, &rng, &pgp_pres);
    let mut management = ManagementApplet::new(SID, &mgmt_pres);
    let mut oath = OathApplet::new(SID, SH, None, &rng, &oath_pres);
    let mut otp = OtpApplet::new(SID, SH, None, &rng, &otp_pres);
    let mut piv = PivApplet::new(SID, SH, None, &rng, &pgp_pres);
    let mut disp = Dispatcher::new();
    let mut applets: [&mut dyn Applet<Fs<RamStorage>>; 5] =
        [&mut openpgp, &mut management, &mut oath, &mut otp, &mut piv];

    // Switch through every applet, do a benign op on each, then exercise the
    // chaining seam (a chained segment followed by a SELECT — the dispatcher
    // absorbs the SELECT as the final chained command).
    let seq: std::vec::Vec<std::vec::Vec<u8>> = std::vec![
        sel(rsk_openpgp::consts::OPENPGP_AID),
        std::vec![0x00, 0xCA, 0x00, 0x6E, 0x00], // openpgp GET DATA
        sel(rsk_piv::PIV_AID),
        std::vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x06], // piv GET DATA
        sel(rsk_mgmt::MANAGEMENT_AID),
        std::vec![0x00, 0x1C, 0x00, 0x00, 0x05, 0x04, 0x03, 0x02, 0x02, 0x02], // write config
        std::vec![0x00, 0x1D, 0x00, 0x00, 0x00],                               // read config
        sel(rsk_oath::OATH_AID),
        std::vec![0x00, 0xA1, 0x00, 0x00, 0x00], // oath list
        sel(rsk_otp::OTP_AID),
        std::vec![0x10, 0x01, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC], // a chained segment …
        sel(rsk_piv::PIV_AID),                                     // … then SELECT mid-chain
    ];
    let mut resp = [0u8; 2048];
    for raw in &seq {
        let mut res = ResBuf::new(&mut resp);
        let _ = disp.process(raw, &mut applets, &mut fs, &mut res);
    }
}

// =========================================================================
// oath_apdu
// =========================================================================

#[test]
fn miri_oath_apdu() {
    use rsk_oath::OathApplet;

    fn run(app: &mut OathApplet, fs: &mut Fs<RamStorage>, raw: &[u8]) {
        if let Ok(apdu) = Apdu::parse(raw) {
            let mut buf = [0u8; 4096];
            let mut res = ResBuf::new(&mut buf);
            let _ = app.process(&apdu, fs, &mut res);
        }
    }

    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    let rng = RefCell::new(CountRng(0));
    let touch = RefCell::new(rsk_oath::AlwaysConfirm);
    let mut app = OathApplet::new([1, 2, 3, 4, 5, 6, 7, 8], [0x22; 32], None, &rng, &touch);

    // Seed one TOTP credential.
    run(
        &mut app,
        &mut fs,
        &[
            0x00, 0x01, 0, 0, 0x1E, 0x71, 0x04, b't', b'o', b't', b'p', 0x73, 0x16, 0x21, 6, b'1',
            b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'1', b'2', b'3', b'4', b'5',
            b'6', b'7', b'8', b'9', b'0',
        ],
    );

    for data in [
        &b"\x00\xa4\x04\x00"[..],
        b"\x00\xa1\x00\x00",
        b"\x00\x02\x00\x00\x0a\x71\x04totp",
        b"\x00\xa2\x00\x00\x0a\x71\x04totp\x02",
    ] {
        run(&mut app, &mut fs, data);
    }
}

// =========================================================================
// otp_apdu
// =========================================================================

#[test]
fn miri_otp_apdu() {
    use rsk_otp::{AlwaysConfirm, OtpApplet};

    fn crc16(data: &[u8]) -> u16 {
        let mut crc: u16 = 0xFFFF;
        for &b in data {
            crc ^= b as u16;
            for _ in 0..8 {
                let lsb = crc & 1;
                crc >>= 1;
                if lsb == 1 {
                    crc ^= 0x8408;
                }
            }
        }
        crc
    }

    fn run(app: &mut OtpApplet, fs: &mut Fs<RamStorage>, raw: &[u8]) {
        if let Ok(apdu) = Apdu::parse(raw) {
            let mut buf = [0u8; 1024];
            let mut res = ResBuf::new(&mut buf);
            let _ = app.process(&apdu, fs, &mut res);
        }
    }

    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    let rng = RefCell::new(CountRng(0));
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = OtpApplet::new([1, 2, 3, 4, 5, 6, 7, 8], [0x22; 32], None, &rng, &presence);

    let mut cfg = [0u8; 52];
    cfg[22..38].copy_from_slice(&[0xAB; 16]);
    cfg[46] = 0x40;
    cfg[47] = 0x26;
    let crc = !crc16(&cfg[..50]);
    cfg[50..].copy_from_slice(&crc.to_le_bytes());
    let mut put = vec![0x00, 0x01, 0x01, 0x00, 58];
    put.extend_from_slice(&cfg);
    put.extend_from_slice(&[0; 6]);
    run(&mut app, &mut fs, &put);

    for data in [
        &b"\x00\xa4\x04\x00"[..],
        b"\x00\xa2\x02\x00\x08\x01\x02\x03\x04\x05\x06\x07\x08",
    ] {
        run(&mut app, &mut fs, data);
    }
}

// =========================================================================
// otp_hid
// =========================================================================

#[test]
fn miri_otp_hid() {
    for data in [
        &b""[..],
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        &[0x12; 32],
        &[0x12; 64],
        &[0xFF; 16],
    ] {
        let mut rx = FrameRx::new();
        let mut tx = FrameTx::new();
        for chunk in data.chunks(REPORT_SIZE) {
            let mut report = [0u8; REPORT_SIZE];
            report[..chunk.len()].copy_from_slice(chunk);
            match rx.feed(&report) {
                RxOutcome::Frame { slot: _, payload } => {
                    tx.load(&payload);
                    let mut out = [0u8; REPORT_SIZE];
                    let mut guard = 0;
                    while tx.next(&mut out) {
                        guard += 1;
                        assert!(guard < 64, "FrameTx must terminate");
                    }
                }
                RxOutcome::None | RxOutcome::Reset | RxOutcome::BadCrc => {}
            }
        }
    }
}

// =========================================================================
// piv_apdu
// =========================================================================

#[test]
fn miri_piv_apdu() {
    use rsk_piv::{AlwaysConfirm, PivApplet};

    fn run(app: &mut PivApplet, fs: &mut Fs<RamStorage>, raw: &[u8]) -> Vec<u8> {
        if let Ok(apdu) = Apdu::parse(raw) {
            let mut buf = [0u8; 4096];
            let mut res = ResBuf::new(&mut buf);
            let _ = app.process(&apdu, fs, &mut res);
            return res.as_slice().to_vec();
        }
        Vec::new()
    }

    const DEFAULT_PIN: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF];
    const DEFAULT_MGM: [u8; 24] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, //
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    ];

    fn auth_mgm(app: &mut PivApplet, fs: &mut Fs<RamStorage>) {
        use aes::cipher::generic_array::GenericArray;
        use aes::cipher::{BlockDecrypt, KeyInit};
        let wit = run(
            app,
            fs,
            &[0x00, 0x87, 0x0A, 0x9B, 0x04, 0x7C, 0x02, 0x80, 0x00],
        );
        if wit.len() < 20 {
            return;
        }
        let cipher = aes::Aes192::new(GenericArray::from_slice(&DEFAULT_MGM));
        let mut w = [0u8; 16];
        w.copy_from_slice(&wit[4..20]);
        let mut blk = GenericArray::clone_from_slice(&w);
        cipher.decrypt_block(&mut blk);
        let mut msg = vec![0x00, 0x87, 0x0A, 0x9B, 0x24, 0x7C, 0x22, 0x80, 0x10];
        msg.extend_from_slice(&blk);
        msg.push(0x81);
        msg.push(0x10);
        msg.extend_from_slice(&[0xA5; 16]);
        let _ = run(app, fs, &msg);
    }

    let rng = RefCell::new(CountRng(0));
    let pres = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new([1, 2, 3, 4, 5, 6, 7, 8], [0x22; 32], None, &rng, &pres);
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();

    {
        let mut buf = [0u8; 256];
        let mut res = ResBuf::new(&mut buf);
        let _ = Applet::select(&mut app, false, &mut fs, &mut res);
    }
    auth_mgm(&mut app, &mut fs);

    let mut verify = vec![0x00, 0x20, 0x00, 0x80, 0x08];
    verify.extend_from_slice(&DEFAULT_PIN);
    let _ = run(&mut app, &mut fs, &verify);

    for data in [
        &b"\x00\xa4\x04\x00"[..],
        b"\x00\xcb\x3f\xff\x05\x5c\x03\x5f\xc1\x06",
        b"\x00\xcb\x3f\xff\x05\x5c\x03\x5f\xc1\x09",
    ] {
        let _ = run(&mut app, &mut fs, data);
    }
}

// =========================================================================
// rescue_apdu
// =========================================================================

#[test]
fn miri_rescue_apdu() {
    use rsk_rescue::rollback::{ROLLBACK_REQUIRED_BIT, RollbackRaw};
    use rsk_rescue::{Confirm, Platform, Presence, RescueApplet, SecureBootStatus, UserPresence};

    const SERIAL_ID: [u8; 8] = [0xAA, 0xBB, 0xCC, 0xDD, 5, 6, 7, 8];
    const SERIAL_HASH: [u8; 32] = [0x22; 32];

    struct AlwaysConfirm;
    impl UserPresence for AlwaysConfirm {
        fn request(&mut self, _c: Confirm<'_>) -> Presence {
            Presence::Confirmed
        }
    }

    struct FakePlatform {
        time: Option<u32>,
        flags0: [u32; 3],
    }
    impl Platform for FakePlatform {
        fn secure_boot_status(&self) -> SecureBootStatus {
            // enabled: true keeps the rollback-require arm's deepest path
            // reachable, mirroring the fuzz harness.
            SecureBootStatus {
                enabled: true,
                locked: false,
                bootkey: 0,
            }
        }
        fn now(&self) -> Option<u32> {
            self.time
        }
        fn set_time(&mut self, epoch: u32) {
            self.time = Some(epoch);
        }
        fn request_reboot(&mut self, _bootsel: bool) {}
        fn read_page58_lock_raw(&self) -> Option<u32> {
            Some(0)
        }
        fn lock_page58(&mut self) -> bool {
            true
        }
        fn read_rollback_raw(&self) -> Option<RollbackRaw> {
            Some(RollbackRaw {
                flags0: self.flags0,
                version0: [0b111; 3],
                version1: [0; 3],
            })
        }
        fn set_rollback_required(&mut self) -> bool {
            for row in self.flags0.iter_mut() {
                *row |= ROLLBACK_REQUIRED_BIT;
            }
            true
        }
    }

    for data in [
        &b"\x00\xa4\x04\x00"[..],
        b"\x00\xcb\x00\x00",
        b"\x00\xcc\x00\x00\x04\x01\x02\x03\x04",
        b"\x80\x1b\x48\x00\x06ROLLBK\x00", // rollback-require, full burn path
        b"\x80\x1b\x48\x00\x06ROLLBX\x00", // bad magic
        b"\x80\x1e\x06\x00\x00",           // anti-rollback state read
        &[0x00; 10],
    ] {
        let mut fs = Fs::new(RamStorage::new());
        fs.scan();
        let rng = RefCell::new(CountRng(0));
        let platform = RefCell::new(FakePlatform {
            time: None,
            flags0: [0; 3],
        });
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = RescueApplet::new(
            SERIAL_ID,
            SERIAL_HASH,
            None,
            None,
            &rng,
            &platform,
            &presence,
            64 * 1024,
            4 * 1024 * 1024,
        );
        if let Ok(apdu) = Apdu::parse(data) {
            let mut buf = [0u8; 2048];
            let mut res = ResBuf::new(&mut buf);
            let _ = app.process(&apdu, &mut fs, &mut res);
        }
    }
}

// =========================================================================
// phy_tlv
// =========================================================================

#[test]
fn miri_phy_tlv() {
    for data in [
        &b""[..],
        b"\x00",
        b"\x01\x01\x02",
        b"\x02\x02\xa5\xa5",
        b"\x03\x01\x00\x04\x01\x01\x05\x04\x00\x00\x00\x00",
    ] {
        let phy = PhyData::parse(data);
        let mut buf = [0u8; PHY_MAX_SIZE];
        let n = phy.serialize(&mut buf).expect("PHY_MAX_SIZE always fits");
        assert_eq!(PhyData::parse(&buf[..n]), phy);
    }
}

// =========================================================================
// seed_blob
// =========================================================================

#[test]
fn miri_seed_blob() {
    use rsk_fido::seed::{load_keydev, migrate_keydev_boot, migrate_keydev_pin};

    const EF_KEY_DEV: u16 = 0xCC00;
    const OTP: [u8; 32] = [0x5A; 32];

    let dev_old = Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    };
    let dev_new = Device {
        otp_key: Some(&OTP),
        ..dev_old
    };

    for data in [
        &b"\x01"[..],
        b"\x03",
        b"\x11",
        b"\x13",
        &[0x01; 32],
        &[0x03; 48],
    ] {
        if data.is_empty() || data.len() > 64 {
            continue;
        }
        let mut fs = Fs::new(RamStorage::new());
        if fs.put(EF_KEY_DEV, data).is_err() {
            continue;
        }
        if matches!(data[0], 0x03 | 0x11 | 0x13) {
            assert_eq!(load_keydev(&dev_old, &mut fs), None);
        }
        if data[0] == 0x13 {
            assert_eq!(load_keydev(&dev_new, &mut fs), None);
        }
        let _ = load_keydev(&dev_old, &mut fs);
        let _ = load_keydev(&dev_new, &mut fs);
        let _ = migrate_keydev_pin(&dev_old, &mut fs, &[0x42; 16]);
        let _ = migrate_keydev_pin(&dev_new, &mut fs, &[0x42; 16]);
        let _ = migrate_keydev_boot(&dev_new, &mut fs);
        let after_one = load_keydev(&dev_new, &mut fs);
        let _ = migrate_keydev_boot(&dev_new, &mut fs);
        assert_eq!(after_one, load_keydev(&dev_new, &mut fs));
    }
}

// =========================================================================
// fido_session
// =========================================================================

#[test]
fn miri_fido_session() {
    use rsk_fido::consts::{
        CTAP_CLIENT_PIN, CTAP_CREDENTIAL_MGMT, CTAP_GET_INFO, CTAP_LARGE_BLOBS, CTAP_RESET,
        CTAP_SELECTION,
    };
    use rsk_fido::credential::credential_store;
    use rsk_fido::state::{PERM_ACFG, PERM_CM, PERM_GA, PERM_LBW, PERM_MC, PERM_PCMR};

    let d = Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    };
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    let _ = ensure_seed(&d, &mut fs, &mut rng);
    let rp_hash = sha256(b"a.co");
    if let Some(seed) = load_keydev(&d, &mut fs) {
        let input = CredInput {
            rp_id: "a.co",
            user_id: &[1, 2],
            user_name: "u",
            user_display_name: "",
            use_sign_count: true,
            rk: true,
            created_ms: 1,
            alg: -7,
            curve: 1,
            ext: CredExt {
                cred_protect: 0,
                cred_blob: &[],
                hmac_secret: false,
                large_blob_key: false,
                third_party_payment: false,
            },
        };
        let mut cred_box = [0u8; 512];
        if let Ok(len) = credential_create(&seed, &d, &input, &rp_hash, &[0x11; 12], &mut cred_box)
        {
            let _ = credential_store(
                &seed,
                &d,
                &mut fs,
                &cred_box[..len],
                &rp_hash,
                "a.co",
                &[1, 2],
                &[],
            );
        }
    }

    let mut state = FidoState::new();
    state.paut.token = [0x99; 32];
    state.paut.permissions = PERM_MC | PERM_GA | PERM_CM | PERM_LBW | PERM_ACFG | PERM_PCMR;
    state.begin_using_token(false, 0);

    // One session: token-armed queries, a reset mid-way, then getInfo must
    // still succeed against the wiped store.
    let msgs: [&[u8]; 7] = [
        &[CTAP_GET_INFO],
        &[CTAP_SELECTION],
        &[CTAP_CLIENT_PIN, 0xa1, 0x02, 0x01],
        &[CTAP_CREDENTIAL_MGMT, 0xa1, 0x01, 0x01],
        &[CTAP_LARGE_BLOBS, 0xa1, 0x01, 0x00],
        &[CTAP_RESET],
        &[CTAP_GET_INFO],
    ];
    let mut presence = rsk_fido::AlwaysConfirm;
    let mut out = [0u8; 2048];
    let mut now_ms: u64 = 2;
    for msg in msgs {
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: d,
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms,
        };
        let w = rsk_fido::process_cbor(&mut ctx, msg, &mut out);
        assert!(w >= 1 && w <= out.len());
        if msg.first() == Some(&CTAP_GET_INFO) {
            assert_eq!(out[0], rsk_fido::CTAP2_OK);
        }
        now_ms += 997;
    }
}

// =========================================================================
// fs_ops
// =========================================================================

#[test]
fn miri_fs_ops() {
    const F1: u16 = 0xB001;
    const F2: u16 = 0xB002;

    let mut fs = Fs::new(RamStorage::new());
    fs.scan();

    // put / clamped read: full length back, copy truncated to the view.
    let v1: Vec<u8> = (0..200u16).map(|j| j as u8).collect();
    fs.put(F1, &v1).unwrap();
    let mut small = [0u8; 16];
    assert_eq!(fs.read(F1, &mut small), Some(200));
    assert_eq!(&small[..], &v1[..16]);

    // meta: add, replace, the META_MAX NoMemory boundary, find, delete.
    fs.meta_add(F1, &[0x11; 8]).unwrap();
    fs.meta_add(F1, &[0x22; 8]).unwrap();
    assert!(fs.meta_add(F2, &[0x33; 1024]).is_err()); // 4 + 1024 + existing > META_MAX
    let mut out = [0u8; 4];
    assert_eq!(fs.meta_find(F1, &mut out), Some(8));
    assert_eq!(out, [0x22; 4]);
    assert_eq!(fs.meta_find(F2, &mut out), None);

    // Reboot: same image, fresh scan; data and meta survive.
    let storage = fs.into_storage();
    let mut fs = Fs::new(storage);
    fs.scan();
    assert_eq!(fs.size(F1), Some(200));
    assert_eq!(fs.meta_find(F1, &mut out), Some(8));

    // The live key set is exactly the files plus EF_META while meta lives.
    let mut live = std::collections::BTreeSet::new();
    fs.for_each_key(&mut |f| {
        live.insert(f);
    });
    assert_eq!(
        live,
        std::collections::BTreeSet::from([F1, rsk_fs::EF_META])
    );

    // delete drops contents and metadata; EF_META clears once empty.
    fs.delete(F1).unwrap();
    assert_eq!(fs.read(F1, &mut small), None);
    assert_eq!(fs.meta_find(F1, &mut out), None);
    let mut live = std::collections::BTreeSet::new();
    fs.for_each_key(&mut |f| {
        live.insert(f);
    });
    assert!(live.is_empty());
}

// =========================================================================
// power_cut
// =========================================================================

#[test]
fn miri_power_cut() {
    use std::cell::Cell;
    use std::rc::Rc;

    use embassy_futures::block_on;
    use embedded_storage_async::nor_flash::{
        ErrorType, MultiwriteNorFlash, NorFlash, ReadNorFlash,
    };
    use rsk_fs::Storage;
    use sequential_storage::cache::Cache;
    use sequential_storage::cache::key_pointers::ArrayKeyPointers;
    use sequential_storage::cache::page_pointers::ArrayPagePointers;
    use sequential_storage::cache::page_states::ArrayPageStates;
    use sequential_storage::map::{MapConfig, MapStorage};
    use sequential_storage::mock_flash::{
        MockFlashBase, MockFlashError, Operation, WriteCountCheck,
    };

    type Mock = MockFlashBase<6, 4, 1024>;
    const MAIN: core::ops::Range<u32> = 0..(4 * 4096);
    const CNT: core::ops::Range<u32> = (4 * 4096)..(6 * 4096);

    type MainCache = Cache<ArrayPageStates<4>, ArrayPagePointers<4>, ArrayKeyPointers<u16, 8>, u16>;
    type CntCache = Cache<ArrayPageStates<2>, ArrayPagePointers<2>, ArrayKeyPointers<u16, 4>, u16>;

    #[derive(Clone)]
    struct SharedMock {
        flash: Rc<RefCell<Mock>>,
        dead: Rc<Cell<bool>>,
    }
    impl ErrorType for SharedMock {
        type Error = MockFlashError;
    }
    impl ReadNorFlash for SharedMock {
        const READ_SIZE: usize = <Mock as ReadNorFlash>::READ_SIZE;
        async fn read(
            &mut self,
            offset: u32,
            bytes: &mut [u8],
        ) -> core::result::Result<(), Self::Error> {
            block_on(self.flash.borrow_mut().read(offset, bytes))
        }
        fn capacity(&self) -> usize {
            self.flash.borrow().capacity()
        }
    }
    impl NorFlash for SharedMock {
        const WRITE_SIZE: usize = <Mock as NorFlash>::WRITE_SIZE;
        const ERASE_SIZE: usize = <Mock as NorFlash>::ERASE_SIZE;
        async fn erase(&mut self, from: u32, to: u32) -> core::result::Result<(), Self::Error> {
            if self.dead.get() {
                return Err(MockFlashError::EarlyShutoff(from, Operation::Erase));
            }
            let r = block_on(self.flash.borrow_mut().erase(from, to));
            if matches!(r, Err(MockFlashError::EarlyShutoff(..))) {
                self.dead.set(true);
            }
            r
        }
        async fn write(
            &mut self,
            offset: u32,
            bytes: &[u8],
        ) -> core::result::Result<(), Self::Error> {
            if self.dead.get() {
                return Err(MockFlashError::EarlyShutoff(offset, Operation::Write));
            }
            let r = block_on(self.flash.borrow_mut().write(offset, bytes));
            if matches!(r, Err(MockFlashError::EarlyShutoff(..))) {
                self.dead.set(true);
            }
            r
        }
    }
    impl MultiwriteNorFlash for SharedMock {}

    struct TortureStorage {
        main: MapStorage<u16, SharedMock, MainCache>,
        counter: MapStorage<u16, SharedMock, CntCache>,
        buf: [u8; 2048],
    }
    impl TortureStorage {
        fn new(flash: SharedMock) -> Self {
            Self {
                main: MapStorage::new(
                    flash.clone(),
                    MapConfig::new(MAIN),
                    MainCache::new(
                        ArrayPageStates::new(),
                        ArrayPagePointers::new(),
                        ArrayKeyPointers::new(),
                    ),
                ),
                counter: MapStorage::new(
                    flash,
                    MapConfig::new(CNT),
                    CntCache::new(
                        ArrayPageStates::new(),
                        ArrayPagePointers::new(),
                        ArrayKeyPointers::new(),
                    ),
                ),
                buf: [0; 2048],
            }
        }
    }
    impl Storage for TortureStorage {
        fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
            let value = if fid == 0xC000 {
                block_on(self.counter.fetch_item::<&[u8]>(&mut self.buf, &fid)).ok()??
            } else {
                block_on(self.main.fetch_item::<&[u8]>(&mut self.buf, &fid)).ok()??
            };
            let n = value.len().min(buf.len());
            buf[..n].copy_from_slice(&value[..n]);
            Some(value.len())
        }
        fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
            if fid == 0xC000 {
                block_on(self.counter.store_item::<&[u8]>(&mut self.buf, &fid, &data))
            } else {
                block_on(self.main.store_item::<&[u8]>(&mut self.buf, &fid, &data))
            }
            .map_err(|_| rsk_sdk::error::Error::MemoryFatal)
        }
        fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
            if fid == 0xC000 {
                block_on(self.counter.remove_item(&mut self.buf, &fid))
            } else {
                block_on(self.main.remove_item(&mut self.buf, &fid))
            }
            .map_err(|_| rsk_sdk::error::Error::MemoryFatal)
        }
        fn size(&mut self, fid: u16) -> Option<usize> {
            let value = if fid == 0xC000 {
                block_on(self.counter.fetch_item::<&[u8]>(&mut self.buf, &fid)).ok()??
            } else {
                block_on(self.main.fetch_item::<&[u8]>(&mut self.buf, &fid)).ok()??
            };
            Some(value.len())
        }
        // Non-enumerating stub: report "incomplete" so `scan` keeps confirm-on-miss.
        fn for_each_key(&mut self, _f: &mut dyn FnMut(u16)) -> bool {
            false
        }
    }

    let flash = Rc::new(RefCell::new(Mock::new(
        WriteCountCheck::Disabled,
        None,
        true,
    )));
    let dead = Rc::new(Cell::new(false));
    let shared = SharedMock {
        flash: flash.clone(),
        dead: dead.clone(),
    };

    // Commit two files (one per partition) under stable power.
    let mut fs = Fs::new(TortureStorage::new(shared.clone()));
    fs.scan();
    let old = [0xA5u8; 24];
    fs.put(0xB000, &old).unwrap();
    fs.put(0xC000, &[1, 2, 3, 4]).unwrap();

    // Cut the power somewhere inside the next put, then reboot (fresh caches
    // over the same bytes) until the mount survives. The interrupted file
    // must read back as exactly old or new; the committed one must be intact.
    flash.borrow_mut().bytes_until_shutoff = Some(10);
    let new = [0x5Au8; 24];
    let r = fs.put(0xB000, &new);
    assert!(r.is_err() || !dead.get());
    loop {
        dead.set(false);
        fs = Fs::new(TortureStorage::new(shared.clone()));
        fs.scan();
        if !dead.get() {
            break;
        }
    }
    let mut buf = [0u8; 64];
    let n = fs.read(0xB000, &mut buf).expect("file lost after cut");
    assert!(buf[..n] == old || buf[..n] == new, "torn put: garbage");
    assert_eq!(fs.read(0xC000, &mut buf), Some(4));
    assert_eq!(&buf[..4], &[1, 2, 3, 4]);
}

// =========================================================================
// mldsa_verify
// =========================================================================

#[test]
fn miri_mldsa_verify() {
    use rsk_crypto::{
        MLDSA44_PK_LEN, MLDSA44_SIG_LEN, MLDSA65_PK_LEN, MLDSA65_SIG_LEN, mldsa65_verify,
    };
    // One input: the decoders (both param sets) reject early on garbage, so this
    // is the parse-path UB check, not the arithmetic (Miri interprets every byte).
    for data in [&[0x42u8; 8][..]] {
        let mut pk44 = [0u8; MLDSA44_PK_LEN];
        let mut sig44 = [0u8; MLDSA44_SIG_LEN];
        let mut pk65 = [0u8; MLDSA65_PK_LEN];
        let mut sig65 = [0u8; MLDSA65_SIG_LEN];
        for (i, b) in pk44.iter_mut().enumerate() {
            *b = data[i % data.len()];
        }
        for (i, b) in sig44.iter_mut().enumerate() {
            *b = data[(i + 1) % data.len()];
        }
        for (i, b) in pk65.iter_mut().enumerate() {
            *b = data[(i + 2) % data.len()];
        }
        for (i, b) in sig65.iter_mut().enumerate() {
            *b = data[(i + 3) % data.len()];
        }
        assert!(!mldsa44_verify(&pk44, data, &sig44));
        assert!(!mldsa65_verify(&pk65, data, &sig65));
    }
}

// =========================================================================
// mldsa_roundtrip
// =========================================================================

#[test]
fn miri_mldsa_roundtrip() {
    use rsk_crypto::{MLDSA44_SIG_LEN, MlDsa44, MlDsa65};
    // ML-DSA keygen + the rejection-loop sign are far too slow under Miri (each
    // keygen streams matrix A via SHAKE; a full sign runs the loop several times).
    // `rsk-mldsa` is `no unsafe`, so Miri adds nothing the fuzzer's ASAN/UBSAN
    // does not already cover on this exact path. Keep the body compiled by the
    // gate's `cargo check --tests`, but do not execute it under the interpreter.
    if cfg!(miri) {
        return;
    }
    let seed = [0x42u8; 32];
    let rnd = [0x11u8; 32];
    let msg = b"miri roundtrip";

    // Full -44 sign + verify + tamper (the sign→verify property), plus -65 keygen.
    let k44 = MlDsa44::from_seed(&seed);
    let pk44 = k44.public_key();
    let mut small = [0u8; MLDSA44_SIG_LEN - 1];
    assert!(k44.sign(msg, &rnd, &mut small).is_err());
    let mut sig44 = [0u8; MLDSA44_SIG_LEN];
    assert_eq!(k44.sign(msg, &rnd, &mut sig44).unwrap(), MLDSA44_SIG_LEN);
    assert!(mldsa44_verify(&pk44, msg, &sig44));
    sig44[0] ^= 1;
    assert!(!mldsa44_verify(&pk44, msg, &sig44));
    let _ = MlDsa65::from_seed(&seed).public_key();
}

// =========================================================================
// fido_cred_pqc
// =========================================================================

#[test]
fn miri_fido_cred_pqc() {
    use rsk_crypto::sha256;
    use rsk_fido::consts::{ALG_MLDSA44, ALG_MLDSA65, CURVE_MLDSA44, CURVE_MLDSA65};
    use rsk_fido::credential::{CredExt, CredInput, credential_create, credential_load};
    use rsk_fido::ec::CredKey;

    let d = dev();
    let seed = [0x42u8; 32];
    let rp_hash = sha256(b"example.com");
    let iv = [0x11u8; 12];
    let input = CredInput {
        rp_id: "example.com",
        user_id: &[1, 2, 3, 4],
        user_name: "u",
        user_display_name: "d",
        use_sign_count: true,
        rk: false,
        created_ms: 0,
        alg: ALG_MLDSA65,
        curve: CURVE_MLDSA65 as i64,
        ext: CredExt {
            cred_protect: 0,
            cred_blob: &[],
            hmac_secret: false,
            large_blob_key: false,
            third_party_payment: false,
        },
    };
    // Box round-trip for -65 (metadata alg/curve codec only — cheap under miri).
    let mut out = [0u8; 2048];
    if let Ok(len) = credential_create(&seed, &d, &input, &rp_hash, &iv, &mut out) {
        let mut scratch = [0u8; 2048];
        let c = credential_load(&seed, &out[..len], &rp_hash, &mut scratch).expect("loads");
        assert_eq!(c.alg, ALG_MLDSA65);
        assert_eq!(c.curve, CURVE_MLDSA65 as i64);
    }
    // from_raw(-44) + cose_public exercises an ML-DSA keygen + the AKP-encode;
    // skip it under Miri (keygen is far too slow there, `rsk-mldsa` is `no unsafe`
    // and the fuzzer covers this), but keep it compiled by `cargo check --tests`.
    if !cfg!(miri) {
        let raw = [0x33u8; 66];
        if let Some(key) = CredKey::from_raw(CURVE_MLDSA44 as i64, &raw) {
            assert_eq!(key.alg(), ALG_MLDSA44);
            let mut cbor = [0u8; 4096];
            let mut enc =
                minicbor::Encoder::new(minicbor::encode::write::Cursor::new(&mut cbor[..]));
            let _ = key.cose_public(&mut enc);
        }
    }
}

// =========================================================================
// display_label
// =========================================================================

#[test]
fn miri_display_label() {
    use embedded_graphics::{
        Pixel,
        draw_target::DrawTarget,
        geometry::{OriginDimensions, Size},
        pixelcolor::Rgb565,
    };
    use rsk_ui::{ConfirmPrompt, LABEL_MAX, Label, PANEL_H, PANEL_W, Screen};

    struct Sink;
    impl OriginDimensions for Sink {
        fn size(&self) -> Size {
            Size::new(PANEL_W as u32, PANEL_H as u32)
        }
    }
    impl DrawTarget for Sink {
        type Color = Rgb565;
        type Error = core::convert::Infallible;
        fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
        where
            I: IntoIterator<Item = Pixel<Self::Color>>,
        {
            for _ in pixels {}
            Ok(())
        }
    }

    for data in [
        &b""[..],
        b"example.com",
        &[0xE2, 0x80, 0xAE, b'a'][..], // a bidi override + text
        &[0x1b; 60],                   // 60 ESC bytes → truncated + all '?'
    ] {
        let (primary, secondary) = data.split_at(data.len() / 2);
        for l in [Label::clamp(primary), Label::clamp_domain(primary)] {
            assert!(l.as_str().bytes().all(|b| (0x20..=0x7E).contains(&b)));
            assert!(l.as_str().len() <= LABEL_MAX);
        }
        let prompt = ConfirmPrompt::new("Approve?", primary, secondary);
        let mut sink = Sink;
        let _ = rsk_ui::render::render(&mut sink, &Screen::Confirm(prompt));
    }
}
