// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Fuzz the FIDO post-quantum credential path — the newest code in the tree and
//! the surface the `mldsa_*` targets do NOT reach. Two boundaries:
//!  1. The credential-box `(alg, curve)` codec: `credential_create` →
//!     `credential_load` with an ML-DSA (or EC, for contrast) pair must round-trip
//!     those fields and never panic (`encode_body`/`parse_body`, the fields the
//!     P-256-only `fido_cred_ext` target never sets).
//!  2. `CredKey` dispatch: `from_raw` across curves including ML-DSA-44/-65, then
//!     `sign` into a `MAX_SIG_LEN` buffer and `cose_public` (the AKP COSE-key CBOR
//!     the relying party receives) — neither may panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use minicbor::Encoder;
use minicbor::encode::write::Cursor;
use rsk_crypto::{Device, sha256};
use rsk_fido::Rng;
use rsk_fido::consts::{
    ALG_EDDSA, ALG_ES256, ALG_ES512, ALG_MLDSA44, ALG_MLDSA65, CURVE_ED25519, CURVE_MLDSA44,
    CURVE_MLDSA65, CURVE_P256, CURVE_P521,
};
use rsk_fido::credential::{CredExt, CredInput, credential_create, credential_load};
use rsk_fido::ec::{CredKey, MAX_SIG_LEN};

struct CountRng(u8);
impl Rng for CountRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

/// (alg, curve) pairs — the ML-DSA sets are the new surface; the EC pairs are
/// contrast so the box codec is exercised across the default and stored branches.
const PAIRS: &[(i64, i64)] = &[
    (ALG_MLDSA44, CURVE_MLDSA44 as i64),
    (ALG_MLDSA65, CURVE_MLDSA65 as i64),
    (ALG_EDDSA, CURVE_ED25519 as i64),
    (ALG_ES256, CURVE_P256 as i64),
    (ALG_ES512, CURVE_P521 as i64),
];

fuzz_target!(|data: &[u8]| {
    let dev = Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    };
    let seed = [0x42u8; 32];
    let rp_hash = sha256(b"example.com");
    let iv = [0x11u8; 12];

    let (alg, curve) = PAIRS[data.first().copied().unwrap_or(0) as usize % PAIRS.len()];
    let flags = data.get(1).copied().unwrap_or(0);
    let ext = CredExt {
        cred_protect: (flags & 0x03) as u64,
        cred_blob: data.get(2..).unwrap_or(&[]),
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
        alg,
        curve,
        ext,
    };

    // 1) The box alg/curve codec must round-trip.
    let mut out = [0u8; 2048];
    if let Ok(len) = credential_create(&seed, &dev, &input, &rp_hash, &iv, &mut out) {
        let mut scratch = [0u8; 2048];
        let c = credential_load(&seed, &out[..len], &rp_hash, &mut scratch)
            .expect("a freshly sealed box must load");
        assert_eq!(c.alg, alg, "alg round-trips through the box");
        assert_eq!(c.curve, curve, "curve round-trips through the box");
    }

    // 2) CredKey dispatch: from_raw → sign + cose_public across curves, no panic.
    let mut raw = [0u8; 66];
    for (i, b) in raw.iter_mut().enumerate() {
        *b = data.get(i % data.len().max(1)).copied().unwrap_or(i as u8);
    }
    for &(_, curve) in PAIRS {
        if let Some(key) = CredKey::from_raw(curve, &raw) {
            let mut rng = CountRng(data.first().copied().unwrap_or(1));
            let mut sig = [0u8; MAX_SIG_LEN];
            let n = key.sign(data, &mut rng, &mut sig);
            assert!(n <= MAX_SIG_LEN);
            let mut cbor = [0u8; 4096];
            let mut enc = Encoder::new(Cursor::new(&mut cbor[..]));
            let _ = key.cose_public(key.alg(), &mut enc);
        }
    }
});
