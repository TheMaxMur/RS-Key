// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Fuzz `authenticatorCredentialManagement` parsing/walk/auth on arbitrary
//! params, with a CM-armed token and a resident credential provisioned so the
//! enumerate / delete / update paths are reachable. It must never panic and must
//! always stay within the output buffer.

use libfuzzer_sys::fuzz_target;
use rsk_crypto::{Device, sha256};
use rsk_fido::credential::{CredExt, CredInput, credential_create, credential_store};
use rsk_fido::credmgmt::cred_mgmt;
use rsk_fido::seed::{ensure_seed, load_keydev};
use rsk_fido::state::PERM_CM;
use rsk_fido::{Ctx, FidoState, Rng};
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;

struct SeqRng(u64);
impl Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let dev = Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
        latched: false,
    };
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    let _ = ensure_seed(&dev, &mut fs, &mut rng);

    // Provision one resident credential directly (no CBOR needed).
    let rp_hash = sha256(b"a.co");
    if let Some(seed) = load_keydev(&dev, &mut fs) {
        let input = CredInput {
            rp_id: "a.co",
            user_id: &[1, 2],
            user_name: "u",
            user_display_name: "",
            use_sign_count: true,
            rk: true,
            created_ms: 1,
            alg: -7,  // ES256
            curve: 1, // P-256
            ext: CredExt {
                cred_protect: 0,
                cred_blob: &[],
                hmac_secret: false,
                large_blob_key: false,
                third_party_payment: false,
            },
        };
        let mut cred_box = [0u8; 512];
        if let Ok(len) = credential_create(
            seed.expose(),
            &dev,
            &input,
            &rp_hash,
            &[0x11; 12],
            &mut cred_box,
        ) {
            let _ = credential_store(
                seed.expose(),
                &dev,
                &mut fs,
                &cred_box[..len],
                &rp_hash,
                "a.co",
                &[1, 2],
                &[],
            );
        }
    }

    // Arm a credentialManagement token (the fuzzer won't forge a valid MAC, but
    // the parse / walk / permission paths must stay panic-free regardless).
    let mut state = FidoState::new();
    state.paut.token = [0x99; 32];
    state.paut.permissions = PERM_CM;
    state.begin_using_token(false, 0);

    let mut out = [0u8; 2048];
    let mut presence = rsk_fido::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev,
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 2,
    };
    if let Ok(n) = cred_mgmt(&mut ctx, data, &mut out) {
        assert!(n <= out.len());
    }
});
