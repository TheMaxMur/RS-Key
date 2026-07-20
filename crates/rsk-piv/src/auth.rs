// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! GENERAL AUTHENTICATE (INS 0x87): management-key mutual/single auth (3DES/AES
//! witness–challenge–response), slot private-key operations (raw RSA — blinded
//! with a CRT-fault check — and ECDSA over a host digest), and ECDH via tag
//! 0x85 (the operation `ykman calculate_secret` performs). Every private-key
//! operation enforces the key's stored touch policy ([`check_touch`]), requested
//! once per logical operation (mutual auth touches at the witness step only);
//! a witness mismatch fails closed; symmetric operations are 9B-only.

use rsa::BigUint;
use rsk_crypto::{
    Device, aes_ecb_decrypt_block, aes_ecb_encrypt_block, des3_decrypt_block, des3_encrypt_block,
};
use rsk_fs::{Fs, Storage};
use rsk_openpgp::keys::Curve;
use rsk_openpgp::{Presence, Rng, UserPresence};
use rsk_sdk::tlv::find_tag;
use rsk_sdk::{ResBuf, Sw};
use zeroize::Zeroize;

use crate::files::*;
use crate::keygen;
use crate::seal;
use crate::x509;
use crate::{ChallengeKind, Session, WRONG_DATA, ct_eq, dyn_auth_resp};

/// Largest RSA modulus this applet stores/signs (RSA-4096 = 512 bytes).
const MAX_RSA_BYTES: usize = 2 * rsk_rsa_asm::MAX_MOD;

enum Dir {
    Encrypt,
    Decrypt,
}

/// Enforce the slot/management-key touch policy before a private-key operation.
/// `ALWAYS` and `CACHED` require a physical touch (CACHED is treated as ALWAYS —
/// with no wall clock the 15-second cache window cannot be honoured, so it errs
/// strict); a non-confirmation fails the operation. `NEVER`/`DEFAULT`/`AUTO`
/// pass through.
fn check_touch(policy: u8, presence: &mut dyn UserPresence) -> Result<(), Sw> {
    if matches!(policy, TOUCHPOLICY_ALWAYS | TOUCHPOLICY_CACHED) {
        match presence.request(rsk_sdk::Confirm::titled("Use PIV key?")) {
            Presence::Confirmed => Ok(()),
            _ => Err(Sw::SECURITY_STATUS_NOT_SATISFIED),
        }
    } else {
        Ok(())
    }
}

/// One ECB block under the management key; `data` is `chal_len` bytes.
fn mgm_crypt(algo: u8, key: &[u8], data: &mut [u8], dir: Dir) -> Result<(), Sw> {
    match algo {
        ALGO_3DES => {
            let key: &[u8; 24] = key.try_into().map_err(|_| Sw::MEMORY_FAILURE)?;
            let block: &mut [u8; 8] = data.try_into().map_err(|_| WRONG_DATA)?;
            match dir {
                Dir::Encrypt => des3_encrypt_block(key, block),
                Dir::Decrypt => des3_decrypt_block(key, block),
            }
            Ok(())
        }
        _ => {
            let block: &mut [u8; 16] = data.try_into().map_err(|_| WRONG_DATA)?;
            match dir {
                Dir::Encrypt => aes_ecb_encrypt_block(key, block),
                Dir::Decrypt => aes_ecb_decrypt_block(key, block),
            }
            .map_err(|_| Sw::MEMORY_FAILURE)
        }
    }
}

/// Shared context for one GENERAL AUTHENTICATE call: the session, device, flash,
/// RNG and presence, plus the resolved per-request parameters. The four tag
/// operations are methods so each takes only its own tag data (and the response
/// buffer), keeping [`general_authenticate`] a thin dispatcher.
struct GenAuth<'c, S: Storage> {
    sess: &'c mut Session,
    dev: &'c Device<'c>,
    fs: &'c mut Fs<S>,
    rng: &'c mut dyn Rng,
    presence: &'c mut dyn UserPresence,
    algo: u8,
    key_ref: u8,
    touch_policy: u8,
    chal_len: usize,
}

impl<S: Storage> GenAuth<'_, S> {
    /// t80 mutual auth: step 1 (empty witness) returns an encrypted witness under
    /// the management key; step 2 verifies the returned witness and answers the
    /// host challenge. Only a `MutualWitness` this device issued may be verified.
    fn mutual_auth(
        &mut self,
        mgm: &[u8],
        w: &[u8],
        host_chal: Option<&[u8]>,
        res: &mut ResBuf,
    ) -> Result<(), Sw> {
        if w.is_empty() {
            // Mutual auth step 1: return the encrypted witness. The touch is
            // requested here (the start of the handshake) so step 2 needs no
            // second one.
            if self.key_ref != SLOT_CARDMGM {
                return Err(Sw::INCORRECT_P1P2);
            }
            check_touch(self.touch_policy, self.presence)?;
            self.rng.fill(&mut self.sess.challenge[..self.chal_len]);
            let mut enc = [0u8; 16];
            enc[..self.chal_len].copy_from_slice(&self.sess.challenge[..self.chal_len]);
            mgm_crypt(self.algo, mgm, &mut enc[..self.chal_len], Dir::Encrypt)?;
            self.sess.has_challenge = true;
            self.sess.chal_kind = ChallengeKind::MutualWitness;
            self.sess.chal_algo = self.algo;
            dyn_auth_resp(res, TAG_AUTH_WITNESS, &enc[..self.chal_len])?;
            return Ok(());
        }
        // Mutual auth step 2: host returns the decrypted witness + its own
        // challenge; verify, then answer with the encrypted host challenge.
        if self.key_ref != SLOT_CARDMGM {
            return Err(Sw::INCORRECT_P1P2);
        }
        // Only a witness this device issued *encrypted* (mutual step 1) may be
        // verified here — never a plaintext single-auth challenge.
        if !self.sess.has_challenge
            || self.sess.chal_kind != ChallengeKind::MutualWitness
            || self.sess.chal_algo != self.algo
        {
            return Err(Sw::INCORRECT_PARAMS);
        }
        let host_chal = host_chal
            .filter(|c| !c.is_empty())
            .ok_or(Sw::INCORRECT_PARAMS)?;
        self.sess.has_challenge = false;
        self.sess.chal_kind = ChallengeKind::None;
        if w.len() != self.chal_len || !ct_eq(w, &self.sess.challenge[..self.chal_len]) {
            return Err(Sw::DATA_INVALID);
        }
        self.sess.has_mgm = true;
        if host_chal.len() != self.chal_len {
            return Err(Sw::DATA_INVALID);
        }
        let mut enc = [0u8; 16];
        enc[..self.chal_len].copy_from_slice(host_chal);
        mgm_crypt(self.algo, mgm, &mut enc[..self.chal_len], Dir::Encrypt)?;
        dyn_auth_resp(res, TAG_AUTH_RESPONSE, &enc[..self.chal_len])?;
        Ok(())
    }

    /// t81 single auth step 1: issue a plaintext challenge for the host to
    /// encrypt and return (verified in [`single_auth_verify`]).
    fn single_challenge(&mut self, res: &mut ResBuf) -> Result<(), Sw> {
        self.rng.fill(&mut self.sess.challenge[..self.chal_len]);
        self.sess.has_challenge = true;
        self.sess.chal_kind = ChallengeKind::SingleChallenge;
        self.sess.chal_algo = self.algo;
        dyn_auth_resp(
            res,
            TAG_AUTH_CHALLENGE,
            &self.sess.challenge[..self.chal_len],
        )?;
        Ok(())
    }

    /// t81 slot private-key operation over the host-supplied challenge `c`: raw
    /// RSA (blinded, CRT-fault-checked), ECDSA over the digest, or PureEdDSA over
    /// the message. Symmetric algos are refused — see the arm's oracle note.
    fn slot_key_op(&mut self, c: &[u8], res: &mut ResBuf) -> Result<(), Sw> {
        match self.algo {
            ALGO_RSA1024 | ALGO_RSA2048 | ALGO_RSA3072 | ALGO_RSA4096 => {
                check_touch(self.touch_policy, self.presence)?;
                let crt = seal::load_rsa_crt(self.dev, self.fs, key_fid(self.key_ref))?;
                if c.len() != crt.modulus_len() {
                    return Err(Sw::INCORRECT_PARAMS);
                }
                let mut out = [0u8; MAX_RSA_BYTES];
                let n = rsa_sign_crt(&crt, c, self.rng, &mut out)?;
                dyn_auth_resp(res, TAG_AUTH_RESPONSE, &out[..n])?;
                out.zeroize();
            }
            ALGO_ECCP256 | ALGO_ECCP384 => {
                check_touch(self.touch_policy, self.presence)?;
                let key = seal::load_ec_key(self.dev, self.fs, key_fid(self.key_ref))?;
                let want = keygen::curve_for_algo(self.algo).ok_or(Sw::INCORRECT_P1P2)?;
                if key.curve() != want {
                    return Err(Sw::INCORRECT_P1P2);
                }
                let mut raw = [0u8; 96];
                let rn = key.sign(c, self.rng, &mut raw)?;
                let mut der = [0u8; 112];
                let dn = x509::ecdsa_sig_der(&raw[..rn], &mut der)?;
                dyn_auth_resp(res, TAG_AUTH_RESPONSE, &der[..dn])?;
            }
            ALGO_ED25519 => {
                check_touch(self.touch_policy, self.presence)?;
                let key = seal::load_ec_key(self.dev, self.fs, key_fid(self.key_ref))?;
                if key.curve() != Curve::Ed25519 {
                    return Err(Sw::INCORRECT_P1P2);
                }
                // PureEdDSA signs the raw message `c`; the 64-byte signature is
                // returned bare (no ASN.1 wrapping).
                let mut sig = [0u8; 64];
                let n = key.sign(c, self.rng, &mut sig)?;
                dyn_auth_resp(res, TAG_AUTH_RESPONSE, &sig[..n])?;
            }
            ALGO_3DES | ALGO_AES128 | ALGO_AES192 | ALGO_AES256 => {
                // "Internal authenticate" — encrypting caller-chosen data under
                // the 9B management key — has no legitimate PIV consumer, and
                // chained with the single-auth challenge (81-empty -> 81 below)
                // it is an oracle that forges `has_mgm` with zero key knowledge:
                // E(mgm, R) submitted as the 82 response decrypts back to R.
                // The only sanctioned symmetric flows are mutual-witness (t80)
                // and single-auth (t81-empty challenge -> t82 verify). Refuse.
                return Err(Sw::INCORRECT_P1P2);
            }
            _ => return Err(WRONG_DATA),
        }
        Ok(())
    }

    /// t82 single auth step 2: verify the host-encrypted challenge. Only a
    /// `SingleChallenge` this device issued in plaintext may be answered here.
    fn single_auth_verify(&mut self, mgm: &[u8], r: &[u8]) -> Result<(), Sw> {
        if self.key_ref != SLOT_CARDMGM {
            return Err(Sw::INCORRECT_P1P2);
        }
        if !self.sess.has_challenge
            || self.sess.chal_kind != ChallengeKind::SingleChallenge
            || self.sess.chal_algo != self.algo
        {
            return Err(Sw::INCORRECT_PARAMS);
        }
        check_touch(self.touch_policy, self.presence)?;
        self.sess.has_challenge = false;
        self.sess.chal_kind = ChallengeKind::None;
        if r.len() != self.chal_len {
            return Err(Sw::DATA_INVALID);
        }
        let mut dec = [0u8; 16];
        dec[..self.chal_len].copy_from_slice(r);
        mgm_crypt(self.algo, mgm, &mut dec[..self.chal_len], Dir::Decrypt)?;
        if !ct_eq(&dec[..self.chal_len], &self.sess.challenge[..self.chal_len]) {
            return Err(Sw::DATA_INVALID);
        }
        self.sess.has_mgm = true;
        Ok(())
    }

    /// t85 ECDH ("exponentiation") for the key-management slots — NIST ECDH or
    /// X25519 (`ykman calculate_secret`). Enforces the key's touch policy first.
    fn ecdh_op(&mut self, pp: &[u8], res: &mut ResBuf) -> Result<(), Sw> {
        if !is_key(self.key_ref) {
            return Err(Sw::INCORRECT_P1P2);
        }
        if !matches!(self.algo, ALGO_ECCP256 | ALGO_ECCP384 | ALGO_X25519) {
            return Err(Sw::INCORRECT_P1P2);
        }
        check_touch(self.touch_policy, self.presence)?;
        let key = seal::load_ec_key(self.dev, self.fs, key_fid(self.key_ref))?;
        let want = keygen::curve_for_algo(self.algo).ok_or(Sw::INCORRECT_P1P2)?;
        if key.curve() != want {
            return Err(Sw::INCORRECT_P1P2);
        }
        let mut shared = [0u8; 48];
        let n = key.ecdh(pp, &mut shared)?;
        dyn_auth_resp(res, TAG_AUTH_RESPONSE, &shared[..n])?;
        shared.zeroize();
        Ok(())
    }
}

/// Raw RSA private-key operation `sⁱᵍ = cᵈ mod n`, computed over the cached CRT
/// parameters with the UMAAL asm ([`rsk_rsa_asm::sign_crt`]). Base-blinded
/// `(c·rᵉ)ᵈ·r⁻¹ mod n` with a fresh random `r`, so the variable-time modexp
/// cannot become a timing oracle; then Bellcore fault-checked (`sⁱᵍᵉ ≡ c mod n`)
/// so a faulted CRT half — or an asm/marshaling bug — can never leave as a valid
/// signature. Writes the `modulus_len`-byte big-endian signature to `out`.
fn rsa_sign_crt(
    crt: &seal::RsaCrt,
    c: &[u8],
    rng: &mut dyn Rng,
    out: &mut [u8],
) -> Result<usize, Sw> {
    use num_bigint_dig::ModInverse;
    use zeroize::Zeroizing;
    let mlen = crt.modulus_len();
    // num-bigint-dig's BigUint has no zeroizing Drop (its heap limbs are freed
    // un-wiped), so every secret value here rides in a `Zeroizing` that scrubs it
    // on drop — on the success path and every `?`/error return alike.
    let p = Zeroizing::new(BigUint::from_bytes_be(crt.p()));
    let q = Zeroizing::new(BigUint::from_bytes_be(crt.q()));
    let n = &*p * &*q;
    let m = BigUint::from_bytes_be(c);

    // Modulus little-endian + the public exponent 65537 (big-endian), for the asm
    // public-exponent modexp that both blinding (`rᵉ`) and the fault check
    // (`sⁱᵍᵉ`) use — the two full-width modexps that otherwise ran on num-bigint.
    let e_be = [0x01u8, 0x00, 0x01];
    let mut n_le = [0u8; MAX_RSA_BYTES];
    let nb = n.to_bytes_le();
    n_le[..nb.len()].copy_from_slice(&nb);
    let pub_pow = |base: &BigUint| -> Option<BigUint> {
        let mut b_le = [0u8; MAX_RSA_BYTES];
        let bb = base.to_bytes_le();
        b_le[..bb.len()].copy_from_slice(&bb);
        let mut o_le = [0u8; MAX_RSA_BYTES];
        let ok = rsk_rsa_asm::modexp_pub(&b_le[..mlen], &e_be, &n_le[..mlen], &mut o_le[..mlen]);
        let out = ok.then(|| BigUint::from_bytes_le(&o_le[..mlen]));
        b_le.zeroize();
        o_le.zeroize();
        out
    };

    // Fresh blinding factor r, invertible mod n (retry on the negligible chance
    // r shares a factor with n — that candidate is a multiple of p or q, so wipe
    // it too rather than free a value that reveals a prime factor).
    let (r, r_inv) = loop {
        let mut rb = [0u8; MAX_RSA_BYTES];
        rng.fill(&mut rb[..mlen]);
        let mut cand = BigUint::from_bytes_be(&rb[..mlen]) % &n;
        rb.zeroize();
        match (&cand).mod_inverse(&n).and_then(|i| i.to_biguint()) {
            Some(inv) => break (Zeroizing::new(cand), Zeroizing::new(inv)),
            None => cand.zeroize(),
        }
    };
    let blinded = Zeroizing::new((&m * pub_pow(&r).ok_or(Sw::EXEC_ERROR)?) % &n);

    // CRT private op on the blinded message, then unblind.
    let mut base_le = [0u8; MAX_RSA_BYTES];
    let mut bl = blinded.to_bytes_le();
    base_le[..bl.len()].copy_from_slice(&bl);
    bl.zeroize();
    let mut sig_le = [0u8; MAX_RSA_BYTES];
    rsk_rsa_asm::sign_crt(
        &base_le[..mlen],
        crt.dp(),
        crt.dq(),
        crt.p(),
        crt.q(),
        crt.qinv(),
        &mut sig_le[..mlen],
    );
    let s_blind = Zeroizing::new(BigUint::from_bytes_le(&sig_le[..mlen]));
    let s = (&*s_blind * &*r_inv) % &n;
    base_le.zeroize();
    sig_le.zeroize();

    // Bellcore fault check: a correct signature satisfies sⁱᵍᵉ ≡ c (mod n).
    if pub_pow(&s).ok_or(Sw::EXEC_ERROR)? != m {
        return Err(Sw::EXEC_ERROR);
    }
    let sb = s.to_bytes_be();
    if sb.len() > mlen {
        return Err(Sw::EXEC_ERROR);
    }
    let off = mlen - sb.len();
    out[..off].fill(0);
    out[off..mlen].copy_from_slice(&sb);
    Ok(mlen)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn general_authenticate<S: Storage>(
    sess: &mut Session,
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    presence: &mut dyn UserPresence,
    algo: u8,
    key_ref: u8,
    data: &[u8],
    res: &mut ResBuf,
) -> Sw {
    if data.is_empty() {
        return Sw::WRONG_LENGTH;
    }
    if data[0] != TAG_DYN_AUTH {
        return WRONG_DATA;
    }
    let Some(dyn_auth) = find_tag(data, TAG_DYN_AUTH as u16) else {
        return WRONG_DATA;
    };
    if dyn_auth.is_empty() {
        return WRONG_DATA;
    }

    // Management-key sanity (algo class + stored length).
    let mut mgm_key = [0u8; 32];
    let mut mgm_len = 0usize;
    if key_ref == SLOT_CARDMGM {
        let Some(want) = mgm_key_len(algo) else {
            return Sw::INCORRECT_P1P2;
        };
        mgm_len = match seal::seal_read(dev, fs, key_fid(SLOT_CARDMGM), &mut mgm_key) {
            Ok(n) => n,
            Err(_) => return Sw::MEMORY_FAILURE,
        };
        if mgm_len != want {
            mgm_key.zeroize();
            return Sw::INCORRECT_P1P2;
        }
    }

    let mut meta = [0u8; 8];
    // A key/mgmt slot's meta is [algo, pin_policy, touch_policy, (origin)] — every
    // writer emits >= 3 bytes; reject a short record rather than read policy from
    // the zero-fill (matches info::read_slot's n >= 3 guard).
    match fs.meta_find(key_fid(key_ref).get(), &mut meta) {
        Some(n) if n >= 3 => {}
        _ => {
            mgm_key.zeroize();
            return Sw::REFERENCE_NOT_FOUND;
        }
    }
    let mut pinpol = meta[1];
    if pinpol == PINPOLICY_DEFAULT {
        pinpol = if key_ref == SLOT_SIGNATURE {
            PINPOLICY_ALWAYS
        } else {
            PINPOLICY_ONCE
        };
    }
    if (pinpol == PINPOLICY_ALWAYS || pinpol == PINPOLICY_ONCE) && is_key(key_ref) && !sess.has_pin
    {
        mgm_key.zeroize();
        return Sw::SECURITY_STATUS_NOT_SATISFIED;
    }
    // Touch policy of the key being used (slot key, or 9B management key).
    let touch_policy = meta[2];

    let chal_len: usize = if algo == ALGO_3DES { 8 } else { 16 };
    let t80 = find_tag(dyn_auth, TAG_AUTH_WITNESS as u16);
    let t81 = find_tag(dyn_auth, TAG_AUTH_CHALLENGE as u16);
    let t82 = find_tag(dyn_auth, TAG_AUTH_RESPONSE as u16);
    let t85 = find_tag(dyn_auth, TAG_AUTH_EXPONENTIATION as u16);

    let sw = {
        let mut ga = GenAuth {
            sess: &mut *sess,
            dev,
            fs: &mut *fs,
            rng: &mut *rng,
            presence: &mut *presence,
            algo,
            key_ref,
            touch_policy,
            chal_len,
        };
        if let Some(w) = t80 {
            ga.mutual_auth(&mgm_key[..mgm_len], w, t81, res)
        } else if let Some(c) = t81 {
            if c.is_empty() {
                ga.single_challenge(res)
            } else {
                ga.slot_key_op(c, res)
            }
        } else if let Some(r) = t82.filter(|r| !r.is_empty()) {
            ga.single_auth_verify(&mgm_key[..mgm_len], r)
        } else if let Some(pp) = t85.filter(|p| !p.is_empty()) {
            ga.ecdh_op(pp, res)
        } else {
            Ok(())
        }
    };
    mgm_key.zeroize();

    match sw {
        Ok(()) => {
            // pin-policy ALWAYS re-locks the PIN after each use — but only for an
            // actual key-slot sign, mirroring the `is_key` check that gated it
            // above. The 9B management key also stores pin-policy ALWAYS, and its
            // mutual auth is not a PIN-gated op, so it must not clear has_pin (else
            // a VERIFY-then-mgmt-auth-then-sign client, e.g. age-plugin-yubikey,
            // hits 6982 on the slot sign).
            if pinpol == PINPOLICY_ALWAYS && is_key(key_ref) {
                sess.has_pin = false;
            }
            Sw::OK
        }
        Err(e) => e,
    }
}
