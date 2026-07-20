// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Brainpool known-answer tests: drive the real applet key API
//! (`PrivKey::from_scalar` → `public_point` / `ecdh` / `sign`) and check it
//! byte-exact against independent OpenSSL 3.6 vectors (public point + ECDH), plus
//! a deterministic sign → verify roundtrip. Vectors were generated with
//! `openssl genpkey …:brainpoolP256r1/P384r1` + `openssl pkeyutl -derive`.

use alloc::vec::Vec;

use crate::Rng;
use crate::keys::{Curve, PrivKey};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

struct FixedRng(u8);
impl Rng for FixedRng {
    fn fill(&mut self, buf: &mut [u8]) {
        buf.fill(self.0);
    }
}

// --- brainpoolP256r1 (OpenSSL 3.6) -------------------------------------------
const BP256_A_PRIV: &str = "97328ceb81dfd9cf8602805df091f4bcd85ba7a287d4b20a98316fb237ed640d";
const BP256_A_PUB: &str = "04756a5c7cfe319f52f26ae7ccd1096ef14c23910ef83744dfb84155cf16f8494f120ab0b81fe9bb8572bdb28a133100360a26d3362d65f3d0c10b74f1871da9c1";
const BP256_B_PUB: &str = "041a1e98a2d940dc225516ade5f678fefbae9a022d9e4524f14561bda3fdb2dc2d7260f221706dc46c9531e5aaf375d8df526a9e5a53135659c24760627ff68463";
const BP256_SHARED: &str = "8503b327c6ea97eaa247541d8c9e36f4e3098a3e746a371ec58a5dc430d8734c";

// --- brainpoolP384r1 (OpenSSL 3.6) -------------------------------------------
const BP384_A_PRIV: &str = "4fc3682dd381e575f2d39ecce793b5987057ef32e83258e22006607f8d43e4df9d8bf6a40dcbbc60aa3989118e9d4cd5";
const BP384_A_PUB: &str = "04761f53734ac07068429ef1fe9231df08412b2f3a97bb48b678bde59dd8f751f6998bd1ce22a771517a864d70a6843155254a27af67fa9095a1d1d3fbce15464f570994be81c5d6fb4de532d4562d87155b0f9e18e09e9d4183d2a0cef0220375";
const BP384_B_PUB: &str = "0466919143368237c0f794e545993494b3ad29528ef33a2dd64047748c495401c638d5a551edcf2dd810ee112b665e3ed444cba57be9e4fbc277eedc876f84893697367b739f5734b54ea97c1f089495fdc1c3b95e05f2ab25f5c5356e715a1c1c";
const BP384_SHARED: &str = "351b0af09e6ccf79abd607c7122daf8012523c6af3e548c57b2866366fbdc1f54cc28f0df7ab18bb44b5fdffa9941850";

#[test]
fn bp256_pubkey_kat() {
    let k = PrivKey::from_scalar(Curve::Bp256, &unhex(BP256_A_PRIV)).unwrap();
    let mut out = [0u8; 133];
    let n = k.public_point(&mut out).unwrap();
    assert_eq!(out[..n], unhex(BP256_A_PUB)[..]);
}

#[test]
fn bp384_pubkey_kat() {
    let k = PrivKey::from_scalar(Curve::Bp384, &unhex(BP384_A_PRIV)).unwrap();
    let mut out = [0u8; 133];
    let n = k.public_point(&mut out).unwrap();
    assert_eq!(out[..n], unhex(BP384_A_PUB)[..]);
}

#[test]
fn bp256_ecdh_kat() {
    let k = PrivKey::from_scalar(Curve::Bp256, &unhex(BP256_A_PRIV)).unwrap();
    let mut out = [0u8; 66];
    let n = k.ecdh(&unhex(BP256_B_PUB), &mut out).unwrap();
    assert_eq!(out[..n], unhex(BP256_SHARED)[..]);
}

#[test]
fn bp384_ecdh_kat() {
    let k = PrivKey::from_scalar(Curve::Bp384, &unhex(BP384_A_PRIV)).unwrap();
    let mut out = [0u8; 66];
    let n = k.ecdh(&unhex(BP384_B_PUB), &mut out).unwrap();
    assert_eq!(out[..n], unhex(BP384_SHARED)[..]);
}

#[test]
fn bp256_sign_roundtrip() {
    use ecdsa::signature::hazmat::PrehashVerifier;
    let k = PrivKey::from_scalar(Curve::Bp256, &unhex(BP256_A_PRIV)).unwrap();
    let prehash = [0x42u8; 32];
    let mut sig = [0u8; 132];
    let n = k.sign(&prehash, &mut FixedRng(0), &mut sig).unwrap();
    assert_eq!(n, 64);
    let vk = ecdsa::VerifyingKey::<bp256::BrainpoolP256r1>::from_sec1_bytes(&unhex(BP256_A_PUB))
        .unwrap();
    let s = bp256::r1::ecdsa::Signature::from_slice(&sig[..n]).unwrap();
    vk.verify_prehash(&prehash, &s).unwrap();
}

#[test]
fn bp384_sign_roundtrip() {
    use ecdsa::signature::hazmat::PrehashVerifier;
    let k = PrivKey::from_scalar(Curve::Bp384, &unhex(BP384_A_PRIV)).unwrap();
    let prehash = [0x42u8; 48];
    let mut sig = [0u8; 132];
    let n = k.sign(&prehash, &mut FixedRng(0), &mut sig).unwrap();
    assert_eq!(n, 96);
    let vk = ecdsa::VerifyingKey::<bp384::BrainpoolP384r1>::from_sec1_bytes(&unhex(BP384_A_PUB))
        .unwrap();
    let s = bp384::r1::ecdsa::Signature::from_slice(&sig[..n]).unwrap();
    vk.verify_prehash(&prehash, &s).unwrap();
}

#[test]
fn bp256_generate_then_sign_verifies() {
    use ecdsa::signature::hazmat::PrehashVerifier;
    let k = PrivKey::generate(Curve::Bp256, &mut FixedRng(0x11)).unwrap();
    let mut pub_pt = [0u8; 133];
    let pn = k.public_point(&mut pub_pt).unwrap();
    let prehash = [0x7bu8; 32];
    let mut sig = [0u8; 132];
    let n = k.sign(&prehash, &mut FixedRng(0), &mut sig).unwrap();
    let vk = ecdsa::VerifyingKey::<bp256::BrainpoolP256r1>::from_sec1_bytes(&pub_pt[..pn]).unwrap();
    let s = bp256::r1::ecdsa::Signature::from_slice(&sig[..n]).unwrap();
    vk.verify_prehash(&prehash, &s).unwrap();
}
