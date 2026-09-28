// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::tests::unhex;
use p256::elliptic_curve::PrimeField;

// draft-bradleylundberg-cfrg-arkg-11 A.1 (ARKG-P256), as python-fido2 2.2.1's
// `tests/test_arkg.py` carries them: the seed from ikm_bl = 00..1f, ikm_kem = 20..3f.
const IKM_BL: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const IKM_KEM: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
const SK_BL: &str = "d959500a78ccf850ce46c80a8c5043c9a2e33844232b3829df37d05b3069f455";
const SK_KEM: &str = "74e0a4cd81ca2d24246ff75bfd6d4fb7f9dfc938372627feb2c2348f8b1493b5";
const PK_BL: &str = "046d3bdf31d0db48988f16d47048fdd24123cd286e42d0512daa9f726b4ecf18df65ed42169c69675f936ff7de5f9bd93adbc8ea73036b16e8d90adbfabdaddba7";
const PK_KEM: &str = "04c38bbdd7286196733fa177e43b73cfd3d6d72cd11cc0bb2c9236cf85a42dcff5dfa339c1e07dfcdfda8d7be2a5a3c7382991f387dfe332b1dd8da6e0622cfb35";

/// `(ctx, kh, sk', pk')`: the three A.1 derivations. The third shares the first's
/// ikm, so its KEM point is the same and only ctx (hence the tag) differs.
const A1: [(&[u8], &str, &str, &str); 3] = [
    (
        b"ARKG-P256.test vectors",
        "27987995f184a44cfa548d104b0a461d0487fc739dbcdabc293ac5469221da91b220e04c681074ec4692a76ffacb9043dec2847ea9060fd42da267f66852e63589f0c00dc88f290d660c65a65a50c86361",
        "775d7fe9a6dfba43ce671cb38afca3d272c4d14aff97bd67559eb500a092e5e7",
        "04572a111ce5cfd2a67d56a0f7c684184b16ccd212490dc9c5b579df749647d107dac2a1b197cc10d2376559ad6df6bc107318d5cfb90def9f4a1f5347e086c2cd",
    ),
    (
        b"ARKG-P256.test vectors",
        "b7507a82771776fbac41a18d94e19a7e0457fd1e438280c127dd55a6138d1baf0a35e3e9671f7e42d8345f47374afa83247a078fa2196cd69497aed59ef92c05cb6b03d306ec24f2f4ff2db09cd95d1b11",
        "6228e470290e9d7cc0feff32a74caafa14c608c956337eba23997f5904cff226",
        "04ea7d962c9f44ffe8b18f1058a471f394ef81b674948eefc1865b5c021cf858f577f9632b84220e4a1444a20b9430b86731c37e4dcb285eda38d76bf758918d86",
    ),
    (
        b"ARKG-P256.test vectors.0",
        "81c4e65b552e52350b49864b98b87d510487fc739dbcdabc293ac5469221da91b220e04c681074ec4692a76ffacb9043dec2847ea9060fd42da267f66852e63589f0c00dc88f290d660c65a65a50c86361",
        "2a97f4232f9abba32fbfc28c6686f8afd2d851c2a95a3ed2f0a384b9ad55068d",
        "04b79b65d6bbb419ff97006a1bd52e3f4ad53042173992423e06e52987a037cb61dd82b126b162e4e7e8dc5c9fd86e82769d402a1968c7c547ef53ae4f96e10b0e",
    ),
];

// The ctx length's two edges over the A.1 seed, derived by python-fido2 2.2.1's
// `ARKG_P256_PLACEHOLDER.derive_public_key` and cross-checked against an
// independent ARKG-Derive-Private-Key (scratch `gen_vectors.py`).
const CTX_EMPTY_KH: &str = "8b6f7f4a26fc9db5ac3cd514ebffd8a90403d91459604201f0296d10ba80f75f191aa247e351822a59d55bb2a5305d6546ada1b6c4ef97cb3299255fc9f3803695199522f01fc60fa76772a96793755558";
const CTX_EMPTY_SK: &str = "b4f7899a92b21e73cece05566981b7fc8cffb2d83f62aed2e05a1eb2b370b8c5";
const CTX_EMPTY_PK: &str = "041cc879d62aca86e90f5e3cda820941c2eb17db91798b65b134fb35006f12eaf3624833a9f4d5ba9a8977976254cf0ee342e6e527adb7583c8c78545280b5450a";
const CTX_64_KH: &str = "3af11597e44858810ffed16625a9ed80046530c95f87a1f1edc40208392b933805521bf97f0914eeadad40cbcda700218b74e15fd229d3364004b3a5dd3cc9a47331f8bf61b84a80602acd3e1900404ab6";
const CTX_64_SK: &str = "7a4edceecab62deba9142bc782b84f71a56217bb9a7c07be95cd2d89f1ef2b69";
const CTX_64_PK: &str = "04bf7ce8d1e0a6ebaa5667c279a79059c37df89a6fe08eeec8be87f8dafba0f29ca8561a03387138d82d712a62e7f66901c1ebfd7ac0a5554be753935f4442baf1";

/// The ikm each A.1 derivation encapsulated with, in [`A1`]'s order.
const A1_IKM: [&str; 3] = [
    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
];

/// ARKG-Derive-Public-Key (§2.3), the relying party's half — what the tests play
/// the relying party with. `(pk', kh)` for the public seed `(pk_bl, pk_kem)`.
pub(crate) fn derive_public_key(
    pk_bl: &[u8; POINT_LEN],
    pk_kem: &[u8; POINT_LEN],
    ikm: &[u8],
    ctx: &[u8],
) -> ([u8; POINT_LEN], std::vec::Vec<u8>) {
    let ctx_len = [u8::try_from(ctx.len()).unwrap()];
    let mut kem_buf = [0u8; CTX_PRIME_MAX];
    let ctx_kem = cat(&mut kem_buf, &[CTX_KEM, &ctx_len, ctx]).unwrap();
    // KEM-Encaps (§3.2) over Sub-Kem-Encaps (§3.3): an ephemeral key from ikm.
    let sk_e = nonzero(hash_to_scalar(ikm, &[KEM_KG, KEM_ECDH, DST_EXT]).unwrap()).unwrap();
    let c = public_point(&sk_e).unwrap();
    let k_prime = ecdh(&sk_e, pk_kem).unwrap();
    let mut info = [0u8; INFO_MAX];
    let mut mk = [0u8; SHA256_LEN];
    let info_mk = cat(&mut info, &[KEM_MAC, KEM_ECDH, DST_EXT, ctx_kem]).unwrap();
    hkdf_sha256(&[], k_prime.expose(), info_mk, &mut mk).unwrap();
    let mut kh = hmac_sha256(&mk, &c)[..TAG_LEN].to_vec();
    kh.extend_from_slice(&c);
    let mut k = [0u8; SHA256_LEN];
    let info_k = cat(&mut info, &[KEM_SHARED, KEM_ECDH, DST_EXT, ctx_kem]).unwrap();
    hkdf_sha256(&[], k_prime.expose(), info_k, &mut k).unwrap();
    // BL-Blind-Public-Key (§3.1): pk_bl + tau·G.
    let mut bl_buf = [0u8; CTX_PRIME_MAX];
    let ctx_bl = cat(&mut bl_buf, &[CTX_BL, &ctx_len, ctx]).unwrap();
    let tau = hash_to_scalar(&k, &[BL_PRF, DST_EXT, ctx_bl]).unwrap();
    let point = p256::Sec1Point::from_bytes(pk_bl).unwrap();
    let pk = Option::<p256::PublicKey>::from(p256::PublicKey::from_sec1_point(&point)).unwrap();
    let blinded = (pk.to_projective() + rsk_ec::comb_mul_p256(&tau))
        .to_affine()
        .to_sec1_point(false);
    (<[u8; POINT_LEN]>::try_from(blinded.as_bytes()).unwrap(), kh)
}

fn a1_seed() -> PrivateSeed {
    derive_seed(&unhex(IKM_BL), &unhex(IKM_KEM)).unwrap()
}

/// The relying party's half reproduces the draft too, so the previewSign tests can
/// trust it for seeds the draft never saw.
#[test]
fn derive_public_key_matches_the_draft() {
    let pk_bl = <[u8; POINT_LEN]>::try_from(unhex(PK_BL)).unwrap();
    let pk_kem = <[u8; POINT_LEN]>::try_from(unhex(PK_KEM)).unwrap();
    for ((ctx, kh, _, pk), ikm) in A1.into_iter().zip(A1_IKM) {
        let (got_pk, got_kh) = derive_public_key(&pk_bl, &pk_kem, &unhex(ikm), ctx);
        assert_eq!(got_kh, unhex(kh), "kh for ikm {ikm}");
        assert_eq!(got_pk.to_vec(), unhex(pk), "pk' for ikm {ikm}");
    }
}

fn repr(sk: &NonZeroScalar) -> std::vec::Vec<u8> {
    sk.to_repr().to_vec()
}

fn ctx_64() -> std::vec::Vec<u8> {
    (0x80..0xC0).collect()
}

/// `sk'` for `(kh, ctx)` over the A.1 seed, and the point it makes.
fn derive(kh: &str, ctx: &[u8]) -> Option<(std::vec::Vec<u8>, std::vec::Vec<u8>)> {
    let sk = derive_private_key(&a1_seed(), &unhex(kh), ctx)?;
    let point = public_point(&sk).unwrap().to_vec();
    Some((repr(sk.expose()), point))
}

#[test]
fn derive_seed_matches_the_draft() {
    let seed = a1_seed();
    assert_eq!(repr(seed.bl.expose()), unhex(SK_BL), "sk_bl");
    assert_eq!(repr(seed.kem.expose()), unhex(SK_KEM), "sk_kem");
    let (bl, kem) = seed.public().unwrap();
    assert_eq!(bl.to_vec(), unhex(PK_BL), "pk_bl");
    assert_eq!(kem.to_vec(), unhex(PK_KEM), "pk_kem");
}

#[test]
fn derive_private_key_matches_the_draft() {
    for (ctx, kh, sk, pk) in A1 {
        let (got_sk, got_pk) = derive(kh, ctx).expect("a handle the draft minted opens");
        assert_eq!(got_sk, unhex(sk), "sk' for {kh}");
        assert_eq!(
            got_pk,
            unhex(pk),
            "pk' for {kh}: the key the relying party derived"
        );
    }
}

/// Both ends of §2.4's ctx bound derive what python-fido2 derived, and one byte
/// past it aborts before any KEM work.
#[test]
fn ctx_of_zero_and_sixty_four_bytes_derive_the_reference_keys() {
    let (sk, pk) = derive(CTX_EMPTY_KH, b"").unwrap();
    assert_eq!((sk, pk), (unhex(CTX_EMPTY_SK), unhex(CTX_EMPTY_PK)));
    let (sk, pk) = derive(CTX_64_KH, &ctx_64()).unwrap();
    assert_eq!((sk, pk), (unhex(CTX_64_SK), unhex(CTX_64_PK)));

    let mut long = ctx_64();
    long.push(0);
    assert!(derive(CTX_64_KH, &long).is_none(), "a 65-byte ctx aborts");
}

#[test]
fn a_handle_is_bound_to_its_ctx() {
    // A.1's first and third handles share their KEM point; each tag holds only
    // under its own ctx.
    let (ctx1, kh1, ..) = A1[0];
    let (ctx3, kh3, ..) = A1[2];
    assert!(derive(kh1, ctx3).is_none());
    assert!(derive(kh3, ctx1).is_none());
}

#[test]
fn a_tampered_handle_aborts() {
    let (ctx, kh, ..) = A1[0];
    let good = unhex(kh);
    let seed = a1_seed();
    // Every byte counts: the first sixteen are the tag, the rest are the point
    // the tag is over — a flip there fails the curve check or the MAC.
    for i in 0..good.len() {
        let mut bad = good.clone();
        bad[i] ^= 0x01;
        assert!(
            derive_private_key(&seed, &bad, ctx).is_none(),
            "a flip at byte {i} must abort"
        );
    }
    // The wrong shapes: short, long, and a compressed point in the right length.
    assert!(derive_private_key(&seed, &good[..good.len() - 1], ctx).is_none());
    let mut long = good.clone();
    long.push(0);
    assert!(derive_private_key(&seed, &long, ctx).is_none());
    let mut compressed = good.clone();
    compressed[TAG_LEN] = 0x02;
    assert!(derive_private_key(&seed, &compressed, ctx).is_none());
}

/// Only an uncompressed point on the curve reaches the multiplication.
#[test]
fn ecdh_takes_only_uncompressed_points_on_the_curve() {
    let seed = a1_seed();
    let (bl, kem) = seed.public().unwrap();
    assert!(ecdh(&seed.kem, &bl).is_some());
    assert!(ecdh(&seed.kem, &kem).is_some());
    let mut off = bl;
    off[POINT_LEN - 1] ^= 0x01;
    assert!(ecdh(&seed.kem, &off).is_none(), "off the curve");
    assert!(
        ecdh(&seed.kem, &[0; POINT_LEN]).is_none(),
        "not an encoding"
    );
}

/// The derived key is the relying party's: `sk_bl + tau`, never either seed half.
#[test]
fn the_derived_key_is_neither_seed_half() {
    let (_, kh, sk, _) = A1[0];
    let seed = a1_seed();
    let got = derive_private_key(&seed, &unhex(kh), A1[0].0).unwrap();
    assert_ne!(repr(got.expose()), repr(seed.bl.expose()));
    assert_ne!(repr(got.expose()), repr(seed.kem.expose()));
    assert_eq!(repr(got.expose()), unhex(sk));
}

#[test]
fn cat_refuses_what_does_not_fit() {
    let mut buf = [0u8; 4];
    assert_eq!(cat(&mut buf, &[b"ab", b"cd"]), Some(&b"abcd"[..]));
    assert_eq!(cat(&mut buf, &[b"ab", b"cde"]), None);
    assert_eq!(cat(&mut buf, &[]), Some(&b""[..]));
}
