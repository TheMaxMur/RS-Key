// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::ram::RamStorage;

fn dev() -> Device<'static> {
    Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    }
}

const SEED: [u8; 32] = [0x42; 32];
const IV: [u8; 12] = [0x11; 12];

fn input() -> CredInput<'static> {
    CredInput {
        rp_id: "example.com",
        user_id: &[0xDE, 0xAD, 0xBE, 0xEF],
        user_name: "alice",
        user_display_name: "Alice Smith",
        use_sign_count: true,
        rk: false,
        created_ms: 12345,
        alg: ALG_ES256,
        curve: CURVE_P256 as i64,
        ext: CredExt::default(),
    }
}

#[test]
fn create_load_roundtrip() {
    let d = dev();
    let rp_hash = sha256(b"example.com");
    let mut out = [0u8; 512];
    let len = credential_create(&SEED, &d, &input(), &rp_hash, &IV, &mut out).unwrap();
    // Prefix-free: the box now opens with the iv and carries no cleartext marker.
    assert_eq!(&out[..IV_LEN], &IV);
    assert_ne!(&out[..PROTO_LEN], CRED_PROTO);

    let mut scratch = [0u8; 512];
    let c = credential_load(&SEED, &out[..len], &rp_hash, &mut scratch).unwrap();
    assert_eq!(c.rp_id, "example.com");
    assert_eq!(c.user_id, &[0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(c.user_name, "alice");
    assert_eq!(c.user_display_name, "Alice Smith");
    assert!(c.use_sign_count);
    assert_eq!(c.alg, ALG_ES256);
    assert_eq!(c.curve, CURVE_P256 as i64);
}

#[test]
fn non_p256_alg_curve_roundtrip() {
    use crate::consts::{ALG_ES512, CURVE_P521};
    let d = dev();
    let rp_hash = sha256(b"example.com");
    let mut inp = input();
    inp.alg = ALG_ES512;
    inp.curve = CURVE_P521 as i64;
    let mut out = [0u8; 512];
    let len = credential_create(&SEED, &d, &inp, &rp_hash, &IV, &mut out).unwrap();
    let mut scratch = [0u8; 512];
    let c = credential_load(&SEED, &out[..len], &rp_hash, &mut scratch).unwrap();
    assert_eq!(c.alg, ALG_ES512);
    assert_eq!(c.curve, CURVE_P521 as i64);
}

#[test]
fn curve_explicit_alg_on_p256_survives_the_box() {
    use crate::consts::{ALG_ES256, ALG_ESP256, CURVE_P256};
    let d = dev();
    let rp_hash = sha256(b"example.com");
    let mut out = [0u8; 512];
    let mut scratch = [0u8; 512];

    // P-256 is the default curve, so the alg used to be dropped on the way in and
    // reconstructed as ES256 — which is right for -7 and wrong for -9. credMgmt
    // re-emits the COSE key from the record, so a dropped -9 would come back as -7
    // long after the RP was told otherwise.
    let mut inp = input();
    inp.alg = ALG_ESP256;
    inp.curve = CURVE_P256 as i64;
    let len = credential_create(&SEED, &d, &inp, &rp_hash, &IV, &mut out).unwrap();
    let c = credential_load(&SEED, &out[..len], &rp_hash, &mut scratch).unwrap();
    assert_eq!(c.alg, ALG_ESP256);
    assert_eq!(c.curve, CURVE_P256 as i64);

    // And the classic spelling still writes no alg at all, so a box an older build
    // wrote — which carries no key 9 — keeps decoding as ES256/P-256.
    let mut plain = input();
    plain.alg = ALG_ES256;
    plain.curve = CURVE_P256 as i64;
    let plen = credential_create(&SEED, &d, &plain, &rp_hash, &IV, &mut out).unwrap();
    let p = credential_load(&SEED, &out[..plen], &rp_hash, &mut scratch).unwrap();
    assert_eq!(p.alg, ALG_ES256);
    assert!(
        plen < len,
        "the default pair must still cost no record bytes"
    );
}

#[test]
fn extensions_roundtrip_through_box() {
    let d = dev();
    let rp_hash = sha256(b"example.com");
    let mut inp = input();
    inp.rk = true;
    inp.ext = CredExt {
        cred_protect: 2,
        cred_blob: &[0xBE, 0xEF, 0x42],
        hmac_secret: true,
        large_blob_key: true,
        third_party_payment: true,
    };
    let mut out = [0u8; 512];
    let len = credential_create(&SEED, &d, &inp, &rp_hash, &IV, &mut out).unwrap();

    let mut scratch = [0u8; 512];
    let c = credential_load(&SEED, &out[..len], &rp_hash, &mut scratch).unwrap();
    assert_eq!(c.ext.cred_protect, 2);
    assert_eq!(c.ext.cred_blob, &[0xBE, 0xEF, 0x42]);
    assert!(c.ext.hmac_secret);
    assert!(c.ext.large_blob_key);
    assert!(c.ext.third_party_payment);
    assert!(c.rk);
}

#[test]
fn oversized_cred_blob_is_dropped() {
    let d = dev();
    let rp_hash = sha256(b"example.com");
    let big = [0u8; MAX_CREDBLOB_LENGTH + 1];
    let mut inp = input();
    inp.ext.cred_blob = &big;
    let mut out = [0u8; 512];
    let len = credential_create(&SEED, &d, &inp, &rp_hash, &IV, &mut out).unwrap();
    let mut scratch = [0u8; 512];
    let c = credential_load(&SEED, &out[..len], &rp_hash, &mut scratch).unwrap();
    assert!(
        c.ext.cred_blob.is_empty(),
        "oversized credBlob is not sealed"
    );
}

#[test]
fn wrong_rp_hash_fails_to_decrypt() {
    let d = dev();
    let rp_hash = sha256(b"example.com");
    let mut out = [0u8; 512];
    let len = credential_create(&SEED, &d, &input(), &rp_hash, &IV, &mut out).unwrap();
    let other = sha256(b"evil.com");
    let mut scratch = [0u8; 512];
    assert!(credential_load(&SEED, &out[..len], &other, &mut scratch).is_none());
}

#[test]
fn tampered_box_fails() {
    let d = dev();
    let rp_hash = sha256(b"example.com");
    let mut out = [0u8; 512];
    let len = credential_create(&SEED, &d, &input(), &rp_hash, &IV, &mut out).unwrap();
    out[IV_LEN] ^= 0x01; // flip the first ciphertext byte
    let mut scratch = [0u8; 512];
    assert!(credential_load(&SEED, &out[..len], &rp_hash, &mut scratch).is_none());
}

#[test]
fn box_has_no_cleartext_fingerprint() {
    // The point of the format: two credentials for the SAME rp+user share no fixed
    // prefix — the id is indistinguishable from random, like a YubiKey's. A flash
    // dump or a colluding RP can't fingerprint the model/device off a leading marker.
    let d = dev();
    let rp_hash = sha256(b"example.com");
    let mut a = [0u8; 512];
    let mut b = [0u8; 512];
    let la = credential_create(&SEED, &d, &input(), &rp_hash, &[0x11; 12], &mut a).unwrap();
    let lb = credential_create(&SEED, &d, &input(), &rp_hash, &[0x22; 12], &mut b).unwrap();
    assert_ne!(&a[..PROTO_LEN], CRED_PROTO, "no f1d00202 marker");
    assert_ne!(&b[..PROTO_LEN], CRED_PROTO);
    assert_ne!(&a[..4], &b[..4], "different ivs → different leading bytes");
    // A non-rk box must not look like a resident id either.
    assert!(!is_resident(&a[..la]));
    assert!(!is_resident(&b[..lb]));
}

#[test]
fn legacy_is22_box_still_loads() {
    // A credential a relying party registered before the prefix-free format: the
    // f1d00202-prefixed, silent-tagged proto-0x02 box. Its ciphertext + poly tag
    // are byte-identical to the new format (same key label, iv, AAD, plaintext) —
    // only the 4-byte prefix and the silent tag (over the longer prefix) differ.
    let d = dev();
    let rp_hash = sha256(b"example.com");
    let mut newbox = [0u8; 512];
    let nlen = credential_create(&SEED, &d, &input(), &rp_hash, &IV, &mut newbox).unwrap();
    let core = nlen - SILENT_TAG_LEN; // iv ‖ ct ‖ poly
    let mut old = [0u8; 512];
    old[..PROTO_LEN].copy_from_slice(CRED_PROTO);
    old[PROTO_LEN..PROTO_LEN + core].copy_from_slice(&newbox[..core]);
    let st = silent_tag(&d, &old[..PROTO_LEN + core], &rp_hash);
    old[PROTO_LEN + core..PROTO_LEN + core + SILENT_TAG_LEN].copy_from_slice(&st);
    let olen = PROTO_LEN + core + SILENT_TAG_LEN;
    assert_eq!(&old[..PROTO_LEN], CRED_PROTO); // it IS the legacy framing

    let mut scratch = [0u8; 512];
    let c = credential_load(&SEED, &old[..olen], &rp_hash, &mut scratch).unwrap();
    assert_eq!(c.rp_id, "example.com");
    assert_eq!(c.user_id, &[0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(c.user_name, "alice");
}

#[test]
fn legacy_non_silent_box_still_loads() {
    // The oldest framing: proto ‖ iv ‖ ct ‖ poly, no silent tag, key from the
    // on-wire proto. Confirm the fallback trial still opens it.
    let rp_hash = sha256(b"example.com");
    let older_proto = b"\xf1\xd0\x02\x01";
    let mut boxbuf = [0u8; 512];
    boxbuf[..PROTO_LEN].copy_from_slice(older_proto);
    boxbuf[PROTO_LEN..HEAD_LEN].copy_from_slice(&IV);
    let rs = {
        let mut enc = Encoder::new(Cursor::new(&mut boxbuf[HEAD_LEN..512 - TAG_LEN]));
        encode_body(&mut enc, &input()).unwrap();
        enc.writer().position()
    };
    let mut key = derive_chacha_key(&SEED, older_proto);
    let tag = chacha20poly1305_encrypt(&key, &IV, &rp_hash, &mut boxbuf[HEAD_LEN..HEAD_LEN + rs]);
    key.zeroize();
    boxbuf[HEAD_LEN + rs..HEAD_LEN + rs + TAG_LEN].copy_from_slice(&tag);
    let blen = HEAD_LEN + rs + TAG_LEN;

    let mut scratch = [0u8; 512];
    let c = credential_load(&SEED, &boxbuf[..blen], &rp_hash, &mut scratch).unwrap();
    assert_eq!(c.rp_id, "example.com");
    assert_eq!(c.user_name, "alice");
}

#[test]
fn hmac_key_deterministic_uv_halves_differ() {
    let box1 = [0x55u8; 80];
    let mut box2 = box1;
    box2[40] ^= 0xFF;
    let k1 = derive_hmac_key(&SEED, &box1);
    assert_eq!(k1, derive_hmac_key(&SEED, &box1), "deterministic");
    // The CredRandomWithUV ([32..64]) and CredRandomWithoutUV ([0..32]) differ.
    assert_ne!(&k1[..32], &k1[32..]);
    // A different box yields a different cred_random.
    assert_ne!(k1, derive_hmac_key(&SEED, &box2));
    // The proto prefix (first 4 bytes) is folded in, so it is path-sensitive.
    assert_ne!(
        derive_hmac_key(&SEED, &box1),
        derive_hmac_key(&[0x43; 32], &box1)
    );
}

#[test]
fn large_blob_key_deterministic_and_box_sensitive() {
    let box1 = [0x55u8; 80];
    let mut box2 = box1;
    box2[10] ^= 0xFF;
    let k1 = derive_large_blob_key(&SEED, &box1);
    assert_eq!(k1, derive_large_blob_key(&SEED, &box1));
    assert_ne!(k1, derive_large_blob_key(&SEED, &box2));
    assert_ne!(k1, derive_hmac_key(&SEED, &box1)[..32]);
}

/// A pre-v4 (v1/v2/v3) resident id, as older firmware wrote it:
/// `serial-derived(4) ‖ f1d00203 ‖ version ‖ 00 ‖ HMAC-chain(32)`. Used to prove
/// the v4 dispatch keeps those already-provisioned ids working.
fn legacy_resident_id(cred_id: &[u8], d: &Device, version: u8) -> [u8; CRED_RESIDENT_LEN] {
    const HEADER: usize = 10; // serial(4) ‖ f1d00203(4) ‖ version(1) ‖ 00
    let mut outk = [0u8; CRED_RESIDENT_LEN];
    let h0 = hmac_sha256(&[0u8; 32], d.serial_id);
    outk[..32].copy_from_slice(&h0);
    outk[4..8].copy_from_slice(CRED_PROTO_RESIDENT);
    outk[RESIDENT_VERSION_IDX] = version;
    outk[9] = 0;
    let mut chain = [0u8; 32];
    chain.copy_from_slice(&outk[HEADER..]);
    chain = hmac_sha256(&chain, b"SLIP-0022");
    chain = hmac_sha256(&chain, &cred_id[..PROTO_LEN]);
    chain = hmac_sha256(&chain, b"resident");
    chain = hmac_sha256(&chain, cred_id);
    outk[HEADER..].copy_from_slice(&chain);
    outk
}

#[test]
fn resident_id_is_random_and_carries_no_fingerprint() {
    let d = dev();
    let r1 = derive_resident(&[0x55u8; 80], &d);
    let r2 = derive_resident(&[0xAAu8; 80], &d);
    // Deterministic per box, 42 bytes.
    assert_eq!(r1, derive_resident(&[0x55u8; 80], &d));
    assert_eq!(r1.len(), CRED_RESIDENT_LEN);
    // No legacy model marker, and never mistakable for a legacy id.
    assert_ne!(&r1[4..8], CRED_PROTO_RESIDENT);
    assert!(!is_resident(&r1));
    // No device-constant header: the old scheme put HMAC(0,serial)[..4] at [0..4],
    // shared by every id on the device (a cross-RP correlation handle). Gone now.
    let old_header = hmac_sha256(&[0u8; 32], d.serial_id);
    assert_ne!(&r1[..4], &old_header[..4]);
    // Two credentials on the SAME device share no fixed prefix — like a YubiKey's.
    assert_ne!(&r1[..10], &r2[..10]);
    // ...and share nothing ANYWHERE, not just in the prefix this test used to check.
    assert!(
        r1.iter().zip(r2.iter()).filter(|(a, b)| a == b).count() < CRED_RESIDENT_LEN / 2,
        "two ids from one device must not correlate"
    );

    // run-26: no byte may be recomputable from the others. The previous scheme set
    // id[32..42] = HMAC(id[0..32], "resident-id")[..10] — keyed by the *published*
    // half — so any RP holding an id could verify that relation offline and
    // fingerprint the model. Every byte must be keyed by a secret the RP never sees.
    for id in [&r1, &r2] {
        let head: [u8; 32] = id[..32].try_into().unwrap();
        let derived = hmac_sha256(&head, b"resident-id");
        assert_ne!(
            &id[32..],
            &derived[..CRED_RESIDENT_LEN - 32],
            "the tail must not be a public function of the head"
        );
    }
}

/// The id must change if the device secret does — otherwise it is keyed by
/// something an attacker could supply, not by the device.
#[test]
fn resident_id_is_bound_to_the_device_secret() {
    let mut other = dev();
    other.serial_id = &[0x99u8; 8];
    let same_box = [0x55u8; 80];
    assert_ne!(
        derive_resident(&same_box, &dev()),
        derive_resident(&same_box, &other)
    );
}

#[test]
fn legacy_resident_ids_still_dispatch_correctly() {
    let d = dev();
    let box1 = [0x55u8; 80];
    // v3 legacy id: marker present, version ≥ v2 → keys off the stable id.
    let v3 = legacy_resident_id(&box1, &d, RESIDENT_VERSION_V3);
    assert!(is_resident(&v3));
    assert_eq!(resident_key_input(&box1, Some(&v3[..])), &v3[..]);
    // v1 legacy id: marker present, version 0 → keys off the BOX (old pubkey verifies).
    let v1 = legacy_resident_id(&box1, &d, 0);
    assert!(is_resident(&v1));
    assert_eq!(resident_key_input(&box1, Some(&v1[..])), &box1[..]);
    // v4 id: no marker → keys off the id, never mistaken for v1-off-box.
    let v4 = derive_resident(&box1, &d);
    assert!(!is_resident(&v4));
    assert_eq!(resident_key_input(&box1, Some(&v4[..])), &v4[..]);
}

// A v4 resident id is the key input regardless of the (resealed) box, so the
// signing / hmac-secret / largeBlobKey derivations are identical across an
// updateUserInformation box swap; a legacy v1 id still follows the box; a
// non-resident box has no id. Also pins per-credential key uniqueness.
#[test]
fn resident_key_input_reseal_stable_and_v1_follows_box() {
    use crate::keyderiv::fido_load_key;
    let d = dev();
    // Two DIFFERENT boxes, as an updateUserInformation reseal (fresh IV) yields.
    let box1 = [0x55u8; 80];
    let box2 = [0xAAu8; 80];

    let rid = derive_resident(&box1, &d);
    assert!(!is_resident(&rid)); // v4, prefix-free

    // v4: the key input is the STABLE id, independent of the box.
    let ki1 = resident_key_input(&box1, Some(&rid[..]));
    let ki2 = resident_key_input(&box2, Some(&rid[..]));
    assert_eq!(ki1, &rid[..]);
    assert_eq!(ki2, &rid[..]);
    assert_eq!(
        fido_load_key(&SEED, ki1),
        fido_load_key(&SEED, ki2),
        "signing key stable across reseal"
    );
    assert_eq!(
        derive_hmac_key(&SEED, ki1),
        derive_hmac_key(&SEED, ki2),
        "hmac-secret stable across reseal"
    );
    assert_eq!(
        derive_large_blob_key(&SEED, ki1),
        derive_large_blob_key(&SEED, ki2),
        "largeBlobKey stable across reseal"
    );

    // Legacy v1 (marker, version 0): the key input is the box, so an older
    // credential's RP-stored pubkey keeps verifying — no regression.
    let v1 = legacy_resident_id(&box1, &d, 0);
    assert_eq!(resident_key_input(&box1, Some(&v1[..])), &box1[..]);
    assert_eq!(resident_key_input(&box2, Some(&v1[..])), &box2[..]);

    // Non-resident credential: no resident id → the box.
    assert_eq!(resident_key_input(&box1, None), &box1[..]);

    // Uniqueness: two distinct credentials get distinct ids → distinct keys.
    let rid_other = derive_resident(&box2, &d);
    assert_ne!(rid, rid_other);
    assert_ne!(
        fido_load_key(&SEED, &rid[..]),
        fido_load_key(&SEED, &rid_other[..])
    );
}

#[test]
fn store_then_dedup_and_rp_count() {
    let d = dev();
    let mut fs: Fs<RamStorage> = Fs::new(RamStorage::new());
    let rp_hash = sha256(b"example.com");

    let mut out = [0u8; 512];
    let len = credential_create(&SEED, &d, &input(), &rp_hash, &IV, &mut out).unwrap();
    credential_store(
        &SEED,
        &d,
        &mut fs,
        &out[..len],
        &rp_hash,
        "example.com",
        &[0xDE, 0xAD, 0xBE, 0xEF],
        &[],
    )
    .unwrap();

    // Stored in the first EF_CRED slot: rp_hash ‖ resident(v3) ‖ len(=0) ‖ box.
    assert!(fs.has_data(EF_CRED));
    let mut rec = [0u8; 1024];
    let n = fs.read(EF_CRED, &mut rec).unwrap();
    assert_eq!(&rec[..32], &rp_hash[..]);
    assert_eq!(n, RECORD_PREFIX + 1 + len);
    // EF_RP created with count 1.
    let mut rp = [0u8; 256];
    let m = fs.read(EF_RP, &mut rp).unwrap();
    assert_eq!(rp[0], 1);
    assert_eq!(&rp[1..33], &rp_hash[..]);
    // The rpId domain tail is boxed under the seed: not cleartext on flash,
    // but it un-boxes back to the original domain.
    assert_ne!(&rp[RP_PREFIX..m], b"example.com");
    let mut scratch = [0u8; 256];
    let (domain, was_boxed) =
        unseal_rp_id(&SEED, &rp_hash, &rp[RP_PREFIX..m], &mut scratch).unwrap();
    assert_eq!(domain, "example.com");
    assert!(was_boxed);

    // Re-registering the SAME user reuses the slot (no new RP record / count bump).
    let iv2 = [0x22u8; 12];
    let len2 = credential_create(&SEED, &d, &input(), &rp_hash, &iv2, &mut out).unwrap();
    credential_store(
        &SEED,
        &d,
        &mut fs,
        &out[..len2],
        &rp_hash,
        "example.com",
        &[0xDE, 0xAD, 0xBE, 0xEF],
        &[],
    )
    .unwrap();
    assert!(!fs.has_data(EF_CRED + 1)); // still one credential slot used
    let m2 = fs.read(EF_RP, &mut rp).unwrap();
    assert_eq!(rp[0], 1, "same user must not bump the rp count");
    assert_eq!(m2, m);
}

#[test]
fn v3_record_roundtrips_box_and_cached_pubkey() {
    let d = dev();
    let rp_hash = sha256(b"example.com");
    let mut boxbuf = [0u8; 512];
    let box_len = credential_create(&SEED, &d, &input(), &rp_hash, &IV, &mut boxbuf).unwrap();

    // Store with a cached point (a 65-byte stand-in): the record must carry the
    // length-prefixed trailer, and both the box and the point must read back.
    let point = [0x04u8; 65];
    let mut fs: Fs<RamStorage> = Fs::new(RamStorage::new());
    credential_store(
        &SEED,
        &d,
        &mut fs,
        &boxbuf[..box_len],
        &rp_hash,
        "example.com",
        &[1, 2, 3],
        &point,
    )
    .unwrap();

    let mut rec = [0u8; 1024];
    let n = fs.read(EF_CRED, &mut rec).unwrap();
    assert_eq!(n, RECORD_PREFIX + 1 + point.len() + box_len);
    assert_eq!(cred_record_pubkey(&rec[..n]), Some(&point[..]));
    // The box after the trailer still decrypts to the stored credential.
    let mut scratch = [0u8; 1024];
    assert!(credential_load(&SEED, cred_record_box(&rec[..n]), &rp_hash, &mut scratch).is_some());
}

#[test]
fn nick_seal_roundtrip_and_binds_to_rp() {
    let rp_hash = sha256(b"github.com");
    let mut out = [0u8; NICK_BOX_MAX];
    let len = seal_nick(&SEED, &rp_hash, "Work GitHub", &mut out).unwrap();
    // Not cleartext on flash.
    assert!(!out[..len].windows(11).any(|w| w == b"Work GitHub"));

    let mut plain = [0u8; RP_NICK_MAX_LEN];
    let got = unseal_nick(&SEED, &rp_hash, &out[..len], &mut plain).unwrap();
    assert_eq!(got, "Work GitHub");

    // The rpIdHash is the AEAD's AAD, so the box won't open under another RP — this
    // is the slot-reuse guard a stale leftover hits.
    let other = sha256(b"evil.com");
    let mut p2 = [0u8; RP_NICK_MAX_LEN];
    assert!(unseal_nick(&SEED, &other, &out[..len], &mut p2).is_none());
}

#[test]
fn nick_rename_draws_a_fresh_iv() {
    // The synthetic IV is plaintext-bound, so renaming to a different value uses a
    // different IV — never reusing a nonce against a changed plaintext.
    let rp_hash = sha256(b"github.com");
    let mut a = [0u8; NICK_BOX_MAX];
    let mut b = [0u8; NICK_BOX_MAX];
    seal_nick(&SEED, &rp_hash, "first", &mut a).unwrap();
    seal_nick(&SEED, &rp_hash, "secnd", &mut b).unwrap();
    assert_ne!(
        a[..IV_LEN],
        b[..IV_LEN],
        "different plaintext → different IV"
    );
}

#[test]
fn nick_too_long_is_rejected_by_seal() {
    let rp_hash = sha256(b"github.com");
    let mut out = [0u8; NICK_BOX_MAX + 64];
    let long = [b'a'; RP_NICK_MAX_LEN + 1];
    let long = core::str::from_utf8(&long).unwrap();
    assert!(seal_nick(&SEED, &rp_hash, long, &mut out).is_err());
}

// `truncate_utf8` must never panic and must return a char-boundary byte-prefix
// no longer than `max`. The function's domain is small, so prove it by
// EXHAUSTION over a stress alphabet spanning every UTF-8 length class (1..4
// bytes), for every string of up to 3 such chars and every cap 0..=input len.
#[test]
fn truncate_utf8_is_exhaustively_safe() {
    // ASCII 'a' (1B), 'é' (2B), '€' (3B), '𝔸' (4B) — one representative per class.
    let alphabet = ['a', 'é', '€', '𝔸'];
    let mut corpus = std::vec::Vec::new();
    corpus.push(std::string::String::new());
    for &a in &alphabet {
        corpus.push(a.to_string());
        for &b in &alphabet {
            corpus.push(std::format!("{a}{b}"));
            for &c in &alphabet {
                corpus.push(std::format!("{a}{b}{c}"));
            }
        }
    }
    for s in &corpus {
        for max in 0..=s.len() + 1 {
            let t = truncate_utf8(s, max);
            assert!(t.len() <= max, "{s:?} @ {max}: len {} > cap", t.len());
            assert!(
                s.as_bytes().starts_with(t.as_bytes()),
                "{s:?} @ {max}: not a prefix"
            );
            // The cut is a real char boundary: `t` re-parses as the char prefix
            // that fits, and dropping one more char would exceed `max`.
            assert!(s.starts_with(t));
            if t.len() < s.len() {
                let next = s[..].chars().nth(t.chars().count()).unwrap();
                assert!(
                    t.len() + next.len_utf8() > max,
                    "{s:?} @ {max}: truncated too early"
                );
            }
        }
    }
}

#[test]
fn remaining_rk_clamps_by_shared_file_budget() {
    let mut fs: Fs<RamStorage> = Fs::new(RamStorage::new());
    // Plenty of free files → the EF_CRED headroom (256 − used) binds, as before.
    assert_eq!(remaining_rk(&mut fs, 10), MAX_RESIDENT_CREDENTIALS - 10);

    // Drain the shared dynamic-file budget down to 40 free — a stand-in for a device
    // whose PIV keys / OATH creds have eaten the shared store. Now free/2 = 20 < 256,
    // so the honest estimate clamps to the file budget, not the EF_CRED headroom
    // (this is exactly the getInfo-0x14 over-report the HW stress test exposed).
    for i in 0..(rsk_fs::MAX_DYNAMIC_FILES as u16 - 40) {
        fs.put(0xD000 + i, b"x").unwrap();
    }
    assert_eq!(fs.free_dynamic(), 40);
    assert_eq!(remaining_rk(&mut fs, 0), 20);
}

/// `Storage` whose `write` starts failing after `budget` successes — a store that
/// fills, or a power cut, part-way through a non-transactional registration.
#[derive(Clone, Default)]
struct FailWriteAfter {
    inner: RamStorage,
    budget: usize,
}

impl rsk_fs::Storage for FailWriteAfter {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.inner.read(fid, buf)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
        if self.budget == 0 {
            return Err(rsk_sdk::error::Error::NoMemory);
        }
        self.budget -= 1;
        self.inner.write(fid, data)
    }
    fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
        self.inner.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.inner.size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(f)
    }
}

/// Audit run-35: a registration that fails part-way must never leave a credential
/// record without its EF_RP entry.
///
/// `credential_store` is three sequential flash writes and reports failure of the
/// last as failure of the whole. With EF_CRED committed first, a failure at the
/// EF_RP write left a live discoverable passkey that `enumerateRPs` and the
/// trusted-display Passkeys view — both EF_RP walks — can neither list nor delete,
/// while `getAssertion` (an EF_CRED scan) authenticates with it. The dedup makes it
/// permanent. Asserted for EVERY failure point, not just the one that reproduces.
#[test]
fn a_failed_registration_never_leaves_a_credential_without_its_rp() {
    let d = dev();
    let rp_hash = sha256(b"example.com");
    let mut out = [0u8; 512];
    let len = credential_create(&SEED, &d, &input(), &rp_hash, &IV, &mut out).unwrap();

    let mut saw_partial = false;
    for budget in 0..6 {
        let mut fs: Fs<FailWriteAfter> = Fs::new(FailWriteAfter {
            inner: RamStorage::new(),
            budget,
        });
        let r = credential_store(
            &SEED,
            &d,
            &mut fs,
            &out[..len],
            &rp_hash,
            "example.com",
            &[0xDE, 0xAD, 0xBE, 0xEF],
            &[],
        );
        if r.is_ok() {
            continue;
        }
        saw_partial = true;
        // The invariant: a stored credential implies a stored RP entry for it.
        if fs.has_data(EF_CRED) {
            assert!(
                fs.has_data(EF_RP),
                "write budget {budget} left a credential with no EF_RP record — \
                 invisible to every enumeration and revocation surface"
            );
        }
    }
    assert!(
        saw_partial,
        "vacuous: no write budget produced a partial registration"
    );
}
