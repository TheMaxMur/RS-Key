// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::faults::{Cut, RemoveStuck};
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
    let st = silent_tag(&d, &old[..PROTO_LEN + core], &rp_hash).unwrap();
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
    let tag = chacha20poly1305_encrypt(
        key.expose(),
        &IV,
        &rp_hash,
        &mut boxbuf[HEAD_LEN..HEAD_LEN + rs],
    );
    key.wipe();
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
    assert_eq!(
        crate::bare(&k1),
        crate::bare(derive_hmac_key(&SEED, &box1)),
        "deterministic"
    );
    // The CredRandomWithUV ([32..64]) and CredRandomWithoutUV ([0..32]) differ.
    assert_ne!(&k1.expose()[..32], &k1.expose()[32..]);
    // A different box yields a different cred_random.
    assert_ne!(crate::bare(&k1), crate::bare(derive_hmac_key(&SEED, &box2)));
    // The proto prefix (first 4 bytes) is folded in, so it is path-sensitive.
    assert_ne!(
        crate::bare(derive_hmac_key(&SEED, &box1)),
        crate::bare(derive_hmac_key(&[0x43; 32], &box1))
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
    assert_ne!(k1, derive_hmac_key(&SEED, &box1).expose()[..32]);
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
        crate::bare(fido_load_key(&SEED, ki1)),
        crate::bare(fido_load_key(&SEED, ki2)),
        "signing key stable across reseal"
    );
    assert_eq!(
        crate::bare(derive_hmac_key(&SEED, ki1)),
        crate::bare(derive_hmac_key(&SEED, ki2)),
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
        crate::bare(fido_load_key(&SEED, &rid[..])),
        crate::bare(fido_load_key(&SEED, &rid_other[..]))
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

/// The mirror of the case above, and the half it does not assert. A registration
/// that fails must leave NOTHING — not the credential the host was told it did
/// not get, and not an EF_RP entry over one that never landed. `decrement_rp`
/// deletes the record at count 0 alone and the count is bumped once per credential
/// that lands, so an entry left over one that never landed floors at 1: the slot
/// is unreusable short of `authenticatorReset` while `enumerateRPs` and the
/// Passkeys view both keep listing an RP with nothing in it.
///
/// Asserted UNCONDITIONALLY at every failing budget, not inside an
/// `if has_data(EF_RP)`. The conditional shape passes when the branch is never
/// entered, and with the rollbacks in place the branch is never entered — the
/// rule that matters would then be carried rather than checked.
#[test]
fn a_failed_registration_leaves_neither_the_credential_nor_its_rp_entry() {
    let d = dev();
    let rp_hash = sha256(b"example.com");
    let mut out = [0u8; 512];
    let len = credential_create(&SEED, &d, &input(), &rp_hash, &IV, &mut out).unwrap();

    let mut saw_partial = false;
    for budget in 0..8 {
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
        assert!(
            !fs.has_data(EF_CRED),
            "write budget {budget} answered an error over a credential that is live"
        );
        assert!(
            !fs.has_data(EF_RP),
            "write budget {budget} left an EF_RP record with no credential — \
             the count floors at 1 and the slot never comes back"
        );
    }
    assert!(
        saw_partial,
        "vacuous: no write budget produced a partial registration"
    );
}

/// The rollback's GUARD, which the case above cannot reach: on a RE-registration
/// of an (rp, user) the store already holds, `bump_rp` raises an existing count
/// from n to n+1 and creates nothing, so a failure must return it to n and must
/// NOT delete the record. Dropping `if new_record` entirely left the suite green
/// and recreated audit run-35's defect — a live discoverable credential with no
/// EF_RP entry, invisible to `enumerateRPs` and to the Passkeys view while
/// `getAssertion` authenticates with it happily.
#[test]
fn a_failed_re_registration_does_not_delete_the_rp_the_first_one_created() {
    let d = dev();
    let rp_hash = sha256(b"example.com");
    let mut out = [0u8; 512];
    let len = credential_create(&SEED, &d, &input(), &rp_hash, &IV, &mut out).unwrap();

    // One landed registration, then the same (rp, user) again on a store that
    // runs out of writes part-way. `new_record` is false on the second call.
    let mut saw_partial = false;
    for budget in 0..8 {
        let mut warm: Fs<FailWriteAfter> = Fs::new(FailWriteAfter {
            inner: RamStorage::new(),
            budget: usize::MAX,
        });
        credential_store(
            &SEED,
            &d,
            &mut warm,
            &out[..len],
            &rp_hash,
            "example.com",
            &[0xDE, 0xAD, 0xBE, 0xEF],
            &[],
        )
        .unwrap();
        assert!(warm.has_data(EF_RP) && warm.has_data(EF_CRED));
        // The budget belongs to the SECOND call, so the backend is carried over
        // rather than the `Fs`: `into_storage` is the only way across.
        let mut fs: Fs<FailWriteAfter> = Fs::new(FailWriteAfter {
            inner: warm.into_storage().inner,
            budget,
        });
        // A fresh `Fs` has an empty present/decided bitmap, and `credential_store`
        // reads it to decide `new_record`. Without the scan the second call is a
        // FIRST registration over a store that already holds one, which is a
        // different case than the one this test is about — measured: it deleted
        // the record and the assertion below fired for the wrong reason.
        fs.scan();
        if credential_store(
            &SEED,
            &d,
            &mut fs,
            &out[..len],
            &rp_hash,
            "example.com",
            &[0xDE, 0xAD, 0xBE, 0xEF],
            &[],
        )
        .is_ok()
        {
            continue;
        }
        saw_partial = true;
        assert!(
            fs.has_data(EF_RP),
            "write budget {budget} deleted the RP record the FIRST registration \
             created — the credential still there is then unlistable and \
             undeletable, which is audit run-35"
        );
    }
    assert!(
        saw_partial,
        "vacuous: no write budget produced a partial re-registration"
    );
}

/// The consequence `Fs::present_slots` answers for: `credential_store` writes the
/// first slot the bitmap calls free without re-reading it, so after a boot scan a
/// read fault cut short it minted straight over a live discoverable credential.
/// KEY_STORE_FULL is the honest answer on a store it cannot enumerate.
#[test]
fn a_truncated_scan_does_not_let_a_new_credential_land_on_a_live_one() {
    use rsk_fs::storage::faults::TruncatedWalk;
    let d = dev();
    let rp_hash = sha256(b"example.com");
    let mut fs = Fs::new(TruncatedWalk::new());
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
    let mut first = [0u8; 1024];
    let n = fs.read(EF_CRED, &mut first).unwrap();

    // A reboot whose enumeration faults: slot 0 holds a live credential the walk
    // never yielded.
    let mut fs = Fs::new(fs.into_storage());
    fs.scan();
    let other = sha256(b"other.example");
    let len2 = credential_create(&SEED, &d, &input(), &other, &IV, &mut out).unwrap();
    assert_eq!(
        credential_store(
            &SEED,
            &d,
            &mut fs,
            &out[..len2],
            &other,
            "other.example",
            &[0x01, 0x02],
            &[],
        ),
        Err(Error::NoMemory),
        "a store that cannot enumerate itself must refuse, not pick slot 0"
    );
    let mut still = [0u8; 1024];
    assert_eq!(fs.read(EF_CRED, &mut still), Some(n));
    assert_eq!(
        still[..n],
        first[..n],
        "the live credential was overwritten"
    );
}

/// `bump_cred_store_state` reads the tag it advances with the collapsing `Fs::read`,
/// whose `None` covers "never written" and "the flash could not serve it" alike, and
/// the absent arm is the ZERO tag — right for the first, a replay for the second. So
/// a faulted probe writes 1 over the live value and starts the sequence again from a
/// prefix the platform has already been served: it is handed a tag it is holding, so
/// it keeps the cache this record exists to make it drop.
///
/// Refused rather than clamped, because the bump runs BEFORE the write it describes:
/// its `Err` aborts the store change too, so tag and store stay in step.
#[test]
fn a_faulted_cred_state_probe_does_not_replay_the_store_tag() {
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    // Three store changes: 1, 2 and 3 are each a tag the platform has been served.
    let mut seen = Vec::new();
    for _ in 0..3 {
        bump_cred_store_state(&mut fs).unwrap();
        seen.push(medium.value(EF_CRED_STATE).unwrap());
    }
    assert_eq!(
        seen[2],
        3u128.to_le_bytes(),
        "control: three changes, tag 3"
    );

    medium.stick_once(EF_CRED_STATE);
    let bumped = bump_cred_store_state(&mut fs);
    medium.stick(None);

    let after = medium.value(EF_CRED_STATE).unwrap();
    assert!(
        !seen[..2].contains(&after),
        "a faulted probe replayed tag {} — a platform holding it is told nothing changed",
        u128::from_le_bytes(after[..].try_into().unwrap())
    );
    assert_eq!(
        after, seen[2],
        "a refused bump must leave the tag where it was"
    );
    assert_eq!(
        bumped,
        Err(Error::MemoryFatal),
        "a bump that could not read the tag it advances must refuse"
    );
}

/// `bump_rp` finds the rp's existing EF_RP record with the collapsing `Fs::read`,
/// whose `None` covers "this slot is a different rp" and "the flash could not serve
/// this slot" alike — and the absent arm falls through to the free-slot path. So one
/// faulted probe of the record that DOES hold this rpIdHash files a SECOND record
/// for the same rp. Nothing merges them again: `decrement_rp` `break`s at its first
/// match, so it only ever drains one of the pair, and while both stand
/// `enumerateRPs` counts the rp twice. Worse, when the first record reaches zero it
/// deletes EF_RPNICK at ITS slot — destroying the rp's nickname while the rp is
/// still live under the duplicate.
#[test]
fn a_faulted_rp_probe_does_not_file_a_second_record_for_the_same_rp() {
    let d = dev();
    let rp_hash = sha256(b"example.com");
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    let mut out = [0u8; 512];
    let store = |fs: &mut Fs<_>, out: &[u8], user: &[u8]| {
        credential_store(&SEED, &d, fs, out, &rp_hash, "example.com", user, &[])
    };
    let records_for_rp = |medium: &rsk_fs::storage::faults::ProbeMedium| {
        (0..MAX_RESIDENT_CREDENTIALS)
            .filter(|i| {
                medium
                    .value(EF_RP + i)
                    .is_some_and(|v| v.len() >= RP_PREFIX && v[1..RP_PREFIX] == rp_hash[..])
            })
            .collect::<Vec<u16>>()
    };

    let mut first = input();
    first.user_id = &[0x01];
    let len = credential_create(&SEED, &d, &first, &rp_hash, &IV, &mut out).unwrap();
    store(&mut fs, &out[..len], first.user_id).unwrap();
    assert_eq!(
        records_for_rp(&medium),
        vec![0],
        "control: one registration, one EF_RP record"
    );

    // A second user at the same rp: `bump_rp` must land on EF_RP+0, whose read faults.
    let mut second = input();
    second.user_id = &[0x02];
    let len2 = credential_create(&SEED, &d, &second, &rp_hash, &IV, &mut out).unwrap();
    medium.stick(Some(EF_RP));
    let stored = store(&mut fs, &out[..len2], second.user_id);
    medium.stick(None);

    assert_eq!(
        records_for_rp(&medium),
        vec![0],
        "a faulted probe filed a SECOND EF_RP record for one rpIdHash — enumerateRPs \
         lists the rp twice and no decrement_rp ever merges the pair"
    );
    assert_eq!(
        stored,
        Err(Error::MemoryFatal),
        "a registration that could not read the rp index must refuse, not duplicate it"
    );
}

/// …and the refusal reaches no further than the slot that could have been this rp.
///
/// The first shape of the fix returned on the faulted probe where it happened, which
/// made ONE unreadable EF_RP record deny every resident registration on the device —
/// for every relying party, including ones whose own record reads perfectly. Measured
/// that way before it was narrowed: registering at `other.example` with `example.com`'s
/// slot stuck answered `Err(MemoryFatal)`, and `makeCredential` reported that to the
/// platform as `KeyStoreFull` — "delete some passkeys", which cannot help a flash
/// fault and destroys data to no end.
#[test]
fn a_faulted_probe_of_another_rps_slot_does_not_deny_this_registration() {
    let d = dev();
    let mine = sha256(b"example.com");
    let other = sha256(b"other.example");
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    let mut out = [0u8; 512];

    // Slot 0 goes to `other.example`, slot 1 to `example.com`: the fault lands on a
    // record that belongs to somebody else.
    for (hash, id, user) in [
        (&other, "other.example", 0x01u8),
        (&mine, "example.com", 0x02),
    ] {
        let mut req = input();
        req.user_id = core::slice::from_ref(&user);
        let len = credential_create(&SEED, &d, &req, hash, &IV, &mut out).unwrap();
        credential_store(&SEED, &d, &mut fs, &out[..len], hash, id, &[user], &[]).unwrap();
    }
    let before = medium
        .value(EF_RP + 1)
        .expect("example.com's record is on the medium");
    assert_eq!(
        before[0], 1,
        "control: one credential for example.com so far"
    );

    let mut third = input();
    third.user_id = &[0x03];
    let len = credential_create(&SEED, &d, &third, &mine, &IV, &mut out).unwrap();
    medium.stick(Some(EF_RP)); // other.example's slot, not this rp's
    let stored = credential_store(
        &SEED,
        &d,
        &mut fs,
        &out[..len],
        &mine,
        "example.com",
        &[0x03],
        &[],
    );
    medium.stick(None);

    assert_eq!(
        stored,
        Ok(()),
        "a slot belonging to another rp cannot hide this one, so it must not refuse"
    );
    assert_eq!(
        medium.value(EF_RP + 1).map(|v| v[0]),
        Some(2),
        "the second credential for example.com must be counted on its own record"
    );
}

#[test]
fn the_boot_pass_re_arms_the_lap_before_it_boxes_a_cleartext_rp_id() {
    // This pass converges over boots BY DESIGN: it returns whole while the seed is
    // PIN-wrapped or the device soft-locked, and skips a record whose read faulted.
    // So the boot that boxes an rpId is routinely NOT the boot that latched the
    // marker, and what the box supersedes is the domain in the clear.
    const OTP: [u8; 32] = [0x77; 32];
    let otp_dev = Device {
        otp_key: Some(&OTP),
        ..dev()
    };
    let rp_hash = sha256(b"example.com");
    let mut rec = [0u8; RP_REC_MAX];
    rec[0] = 1;
    rec[1..RP_PREFIX].copy_from_slice(&rp_hash);
    rec[RP_PREFIX..RP_PREFIX + 11].copy_from_slice(b"example.com");
    let legacy = rec[..RP_PREFIX + 11].to_vec();
    let mut buf = [0u8; RP_REC_MAX];
    let mut scratch = [0u8; RP_REC_MAX];

    // The ORDER, on the one medium that can tell the two orderings apart.
    let (cut, medium) = Cut::new();
    let mut fs = Fs::new(cut);
    fs.scan();
    crate::seed::encrypt_keydev_f1(&otp_dev, &mut fs, &SEED).unwrap();
    fs.put(EF_RP, &legacy).unwrap();
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    assert!(
        fs.has_data(rsk_fs::EF_HARDENED),
        "fixture: an earlier boot latched the marker"
    );
    medium.clear_ops();
    migrate_rp_seal(&otp_dev, &mut fs);
    medium.assert_re_armed_before(EF_RP, |_| false, "migrate_rp_seal");
    assert!(
        !fs.has_data(rsk_fs::EF_HARDENED),
        "the box superseded a cleartext rpId, so the lap must run again"
    );
    let n = fs.read(EF_RP, &mut buf).unwrap();
    assert_eq!(
        unseal_rp_id(&SEED, &rp_hash, &buf[RP_PREFIX..n], &mut scratch),
        Some(("example.com", true)),
        "fixture: the record really is boxed now"
    );

    // The GATE. A medium refusing only `remove(EF_HARDENED)` reaches that same end
    // state with no reset in it, so the box must not go ahead at all.
    let (stuck, medium) = RemoveStuck::new();
    let mut fs = Fs::new(stuck);
    fs.scan();
    crate::seed::encrypt_keydev_f1(&otp_dev, &mut fs, &SEED).unwrap();
    fs.put(EF_RP, &legacy).unwrap();
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    medium.refuse(Some(rsk_fs::EF_HARDENED));
    migrate_rp_seal(&otp_dev, &mut fs);
    let n = fs.read(EF_RP, &mut buf).unwrap();
    assert_eq!(
        unseal_rp_id(&SEED, &rp_hash, &buf[RP_PREFIX..n], &mut scratch),
        Some(("example.com", false)),
        "the re-arm never landed, so the cleartext record must stay in force instead \
         of being superseded under a marker nothing will clear"
    );
    assert!(
        medium.live(rsk_fs::EF_HARDENED),
        "fixture: the refusal really left the marker on the medium"
    );

    // The control, same medium, fault cleared: the box DOES happen, so the assertion
    // above is about the gate and not about a pass that never fires.
    medium.refuse(None);
    migrate_rp_seal(&otp_dev, &mut fs);
    let n = fs.read(EF_RP, &mut buf).unwrap();
    assert_eq!(
        unseal_rp_id(&SEED, &rp_hash, &buf[RP_PREFIX..n], &mut scratch),
        Some(("example.com", true))
    );
    assert!(!medium.live(rsk_fs::EF_HARDENED));
}
