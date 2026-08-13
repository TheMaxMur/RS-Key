// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! GENERAL AUTHENTICATE (INS 0x87): management-key mutual/single auth (3DES/AES
//! witness–challenge–response), slot private-key operations (raw RSA — blinded
//! with a CRT-fault check — and ECDSA over a host digest), and ECDH via tag
//! 0x85 (the operation `ykman calculate_secret` performs). Every private-key
//! operation enforces the key's stored touch policy ([`check_touch`]), requested
//! once per logical operation (mutual auth touches at the witness step only);
//! a witness mismatch fails closed; symmetric operations are 9B-only.

use rsk_crypto::{
    Device, aes_ecb_decrypt_block, aes_ecb_encrypt_block, des3_decrypt_block, des3_encrypt_block,
};
use rsk_fs::{Fs, Storage};
use rsk_openpgp::keys::PrivKey;
use rsk_openpgp::rsa_crt;
use rsk_openpgp::{Presence, Rng, UserPresence};
use rsk_sdk::tlv::{Tlv, find_tag};
use rsk_sdk::{ResBuf, Sw};
use zeroize::Zeroize;

use crate::files::*;
use crate::keygen;
use crate::seal;
use crate::x509;
use crate::{ChallengeKind, Session, WRONG_DATA, ct_eq, dyn_auth_resp};

enum Dir {
    Encrypt,
    Decrypt,
}

/// Enforce the slot/management-key touch policy before a private-key operation.
/// `NEVER` passes through; every other byte — `ALWAYS`, `CACHED` (treated as
/// ALWAYS: with no wall clock the 15-second window cannot be honoured, so it errs
/// strict) and anything an older build stored — requires a physical touch, and a
/// non-confirmation fails the operation.
fn check_touch(policy: u8, presence: &mut dyn UserPresence) -> Result<(), Sw> {
    // `NEVER` is the only value that skips the prompt. Listing the values that
    // *require* one instead made every other byte — an explicit `DEFAULT`, or a
    // record an older build stored verbatim — mean "no touch", while `info`
    // rendered it "Default" and the attestation extension carried it as written
    // (audit run-34 #18). New keys can no longer hold such a byte; this is the
    // read side of the same invariant, so a legacy one is not a hole either.
    if policy == TOUCHPOLICY_NEVER {
        return Ok(());
    }
    match presence.request(rsk_sdk::Confirm::titled("Use PIV key?")) {
        Presence::Confirmed => Ok(()),
        _ => Err(Sw::SECURITY_STATUS_NOT_SATISFIED),
    }
}

/// Whether the session satisfies a key slot's resolved pin policy. `NEVER` is the
/// only value that skips the PIN — naming the two that *require* one let an
/// unrecognised byte mean "no PIN" (audit run-34 #18).
fn pin_satisfied(sess: &Session, pinpol: u8) -> bool {
    match pinpol {
        PINPOLICY_NEVER => true,
        // "verified every time immediately before" (SP 800-73-4 pt1 §3.2.1 Table 5):
        // the VERIFY must also be unspent — see [`GenAuth::spend_pin`].
        PINPOLICY_ALWAYS => sess.has_pin && sess.pin_fresh,
        _ => sess.has_pin,
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
    /// The algorithm the slot's key was stored under (`meta[0]`).
    slot_algo: u8,
    key_ref: u8,
    pin_policy: u8,
    touch_policy: u8,
    chal_len: usize,
}

impl<S: Storage> GenAuth<'_, S> {
    /// Spend the PIN freshness an ALWAYS slot reads. Measured on a YubiKey 5.7.4: a
    /// private-key operation at any PIN-gated slot closes every ALWAYS slot, and
    /// nothing clears the PIN's own status — 9B included, hence `is_key`.
    fn spend_pin(&mut self) {
        if self.pin_policy != PINPOLICY_NEVER && is_key(self.key_ref) {
            self.sess.pin_fresh = false;
        }
    }

    /// The slot's EC key, bound to the algorithm the host asked for — and the point
    /// of no return for [`Self::spend_pin`]. Measured on a YubiKey 5.7.4: once a
    /// request reaches the key the freshness is gone whether the computation then
    /// succeeds or not (a garbage ECDH point costs it), while a wrong algorithm, an
    /// unprovisioned slot or a denied touch never reaches it and costs nothing.
    fn load_ec(&mut self) -> Result<PrivKey, Sw> {
        let key = seal::load_ec_key(self.dev, self.fs, key_fid(self.key_ref))?;
        // Defence in depth: [`Self::algo_is_the_keys`] already refused a mismatch
        // before this call, off the stored head rather than the sealed key.
        let want = keygen::curve_for_algo(self.algo).ok_or(WRONG_DATA)?;
        if key.curve() != want {
            return Err(WRONG_DATA);
        }
        self.spend_pin();
        Ok(key)
    }

    /// The requested algorithm must be the one the slot's key was stored under.
    /// Judged before the touch and before the load, so a mismatch neither prompts
    /// nor spends: measured on a YubiKey 5.7.4, 2 runs over nine cells — a P-256
    /// slot addressed as ECCP384, RSA-2048 or Ed25519, an ECDH asked at `9B` or at
    /// an RSA/AES slot, and an empty `81` at a key slot under any symmetric
    /// algorithm — every one of them `6A80`, spending nothing. Ours answered
    /// `6A86`, and `6581` for the RSA arm, whose seal read ran first. Without it
    /// the RSA arm also had no algorithm check at all: an RSA-2048 request at an
    /// RSA-3072 slot loaded the 3072 key and spent before refusing on length.
    fn algo_is_the_keys(&self) -> Result<(), Sw> {
        if self.algo == self.slot_algo {
            Ok(())
        } else {
            Err(WRONG_DATA)
        }
    }

    /// Start a management-key handshake: record the outstanding challenge and
    /// drop any standing 9B status — measured on a YubiKey 5.7.4, a step 1
    /// revokes and nothing else at 9B does. 9B-only; both callers check.
    fn begin_handshake(&mut self, kind: ChallengeKind) {
        self.sess.has_challenge = true;
        self.sess.chal_kind = kind;
        self.sess.chal_algo = self.algo;
        self.sess.has_mgm = false;
    }

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
                return Err(WRONG_DATA);
            }
            check_touch(self.touch_policy, self.presence)?;
            self.rng.fill(&mut self.sess.challenge[..self.chal_len]);
            let mut enc = [0u8; 16];
            enc[..self.chal_len].copy_from_slice(&self.sess.challenge[..self.chal_len]);
            mgm_crypt(self.algo, mgm, &mut enc[..self.chal_len], Dir::Encrypt)?;
            self.begin_handshake(ChallengeKind::MutualWitness);
            dyn_auth_resp(res, TAG_AUTH_WITNESS, &enc[..self.chal_len])?;
            return Ok(());
        }
        // Mutual auth step 2: host returns the decrypted witness + its own
        // challenge; verify, then answer with the encrypted host challenge.
        if self.key_ref != SLOT_CARDMGM {
            return Err(WRONG_DATA);
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
    /// encrypt and return (verified in [`Self::single_auth_verify`]).
    fn single_challenge(&mut self, res: &mut ResBuf) -> Result<(), Sw> {
        self.rng.fill(&mut self.sess.challenge[..self.chal_len]);
        self.begin_handshake(ChallengeKind::SingleChallenge);
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
        self.algo_is_the_keys()?;
        match self.algo {
            ALGO_RSA1024 | ALGO_RSA2048 | ALGO_RSA3072 | ALGO_RSA4096 => {
                check_touch(self.touch_policy, self.presence)?;
                let crt = seal::load_rsa_crt(self.dev, self.fs, key_fid(self.key_ref))?;
                self.spend_pin();
                if c.len() != crt.modulus_len() {
                    return Err(Sw::INCORRECT_PARAMS);
                }
                let mut out = [0u8; rsa_crt::MAX_RSA_BYTES];
                let n = rsa_crt::sign_crt(&crt, c, self.rng, &mut out)?;
                dyn_auth_resp(res, TAG_AUTH_RESPONSE, &out[..n])?;
                out.zeroize();
            }
            ALGO_ECCP256 | ALGO_ECCP384 => {
                check_touch(self.touch_policy, self.presence)?;
                let key = self.load_ec()?;
                let mut raw = [0u8; 96];
                let rn = key.sign(c, self.rng, &mut raw)?;
                let mut der = [0u8; 112];
                let dn = x509::ecdsa_sig_der(&raw[..rn], &mut der)?;
                dyn_auth_resp(res, TAG_AUTH_RESPONSE, &der[..dn])?;
            }
            ALGO_ED25519 => {
                check_touch(self.touch_policy, self.presence)?;
                let key = self.load_ec()?;
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
                return Err(WRONG_DATA);
            }
            _ => return Err(WRONG_DATA),
        }
        Ok(())
    }

    /// t82 single auth step 2: verify the host-encrypted challenge. Only a
    /// `SingleChallenge` this device issued in plaintext may be answered here.
    fn single_auth_verify(&mut self, mgm: &[u8], r: &[u8]) -> Result<(), Sw> {
        if self.key_ref != SLOT_CARDMGM {
            return Err(WRONG_DATA);
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
            return Err(WRONG_DATA);
        }
        self.algo_is_the_keys()?;
        if !matches!(self.algo, ALGO_ECCP256 | ALGO_ECCP384 | ALGO_X25519) {
            return Err(WRONG_DATA);
        }
        check_touch(self.touch_policy, self.presence)?;
        // The point is judged by the curve, after the key is loaded and the
        // freshness spent — including an empty one. Measured on a YubiKey 5.7.4:
        // an unusable point still closes every ALWAYS slot, because the request
        // reached the key; what it cannot do is come back as anything but 6A80.
        let key = self.load_ec()?;
        let mut shared = [0u8; 48];
        let n = key.ecdh(pp, &mut shared).map_err(|_| WRONG_DATA)?;
        dyn_auth_resp(res, TAG_AUTH_RESPONSE, &shared[..n])?;
        shared.zeroize();
        Ok(())
    }
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
    // One word for this command's whole framing. A YubiKey 5.7.4 answers `6A80`
    // to an empty body, to a wrong template tag and to a one-byte body alike, and
    // never `6700` — the same spelling `0x0920` gave VERIFY's P1 axis. This
    // command has no ACL of its own, being the authentication, so its framing is
    // all it can answer for.
    if data.is_empty() || data[0] != TAG_DYN_AUTH {
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
        // Same class, same word as every other "this key is not that algorithm"
        // cell: a YubiKey answers 6A80 to any body at 9B under a non-9B algorithm
        // (measured, 2 runs, and E42 §6.9's sweep).
        let Some(want) = mgm_key_len(algo) else {
            return WRONG_DATA;
        };
        mgm_len = match seal::seal_read(dev, fs, key_fid(SLOT_CARDMGM), &mut mgm_key) {
            Ok(n) => n,
            Err(_) => return Sw::MEMORY_FAILURE,
        };
        if mgm_len != want {
            mgm_key.zeroize();
            return WRONG_DATA;
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
    // The management key's *declared* algorithm must be the one being used. Only
    // its stored length was checked, and 3DES and AES-192 are both 24 bytes — so an
    // AES-192 key completed a full 3DES mutual authentication, the one algorithm
    // `fips-profile` provisioning refuses (audit run-34 #19).
    // `INCORRECT_PARAMS`, the same status the `chal_algo` binding below answers, so
    // one class of "this key is not that algorithm" has one status word.
    if key_ref == SLOT_CARDMGM && meta[0] != algo {
        mgm_key.zeroize();
        return Sw::INCORRECT_PARAMS;
    }
    // Only a record an OLDER build wrote can still hold an unresolved `0` here — no
    // host may send one (E80) — and it has to mean what the store-time resolver
    // means, or a legacy slot and a new one behave differently at the same slot
    // with nothing to notice it. Hence one owner for the table. Any other byte is
    // taken as stored, so an undefined one reaches `pin_satisfied`'s closed arm.
    let pinpol = if meta[1] == PINPOLICY_DEFAULT {
        keygen::default_pin_policy(key_ref)
    } else {
        meta[1]
    };
    if is_key(key_ref) && !pin_satisfied(sess, pinpol) {
        mgm_key.zeroize();
        return Sw::SECURITY_STATUS_NOT_SATISFIED;
    }
    // Touch policy of the key being used (slot key, or 9B management key).
    let touch_policy = meta[2];

    let chal_len: usize = if algo == ALGO_3DES { 8 } else { 16 };
    let op = first_operation(dyn_auth);

    let sw = {
        let mut ga = GenAuth {
            sess: &mut *sess,
            dev,
            fs: &mut *fs,
            rng: &mut *rng,
            presence: &mut *presence,
            algo,
            slot_algo: meta[0],
            key_ref,
            pin_policy: pinpol,
            touch_policy,
            chal_len,
        };
        match op {
            Some((TAG_AUTH_WITNESS, w)) => {
                let host_chal = find_tag(dyn_auth, TAG_AUTH_CHALLENGE as u16);
                ga.mutual_auth(&mgm_key[..mgm_len], w, host_chal, res)
            }
            // Empty at 9B opens the single-auth handshake; at a key slot it is a
            // private-key operation over an empty challenge, which is what the
            // oracle answers with a signature where we answered random bytes.
            Some((TAG_AUTH_CHALLENGE, c)) if c.is_empty() && key_ref == SLOT_CARDMGM => {
                ga.single_challenge(res)
            }
            Some((TAG_AUTH_CHALLENGE, c)) => ga.slot_key_op(c, res),
            Some((TAG_AUTH_RESPONSE, r)) => ga.single_auth_verify(&mgm_key[..mgm_len], r),
            Some((TAG_AUTH_EXPONENTIATION, pp)) => ga.ecdh_op(pp, res),
            // No operation tag the card recognises. A YubiKey answers 6A80 to
            // every such body — an unknown tag, a truncated TLV, a lone empty
            // response placeholder — where we used to answer 9000 and do nothing.
            _ => Err(WRONG_DATA),
        }
    };
    mgm_key.zeroize();

    match sw {
        Ok(()) => Sw::OK,
        Err(e) => e,
    }
}

/// The operation this dynamic-auth template asks for: the FIRST tag in body order
/// that names one. Measured on a YubiKey 5.7.4, 3 runs: `7C .. 82 00 81 00 85 <pt>`
/// signs and the same body with `85` before `81` agrees, so precedence is position
/// and not a fixed table — `find_tag` per tag is order-blind, and an ordinary ECDH
/// body carrying an empty `81` returned random bytes instead of a shared secret.
///
/// An EMPTY `82` is the response placeholder every conformant body opens with, not
/// a request to verify one; a non-empty `82` is single-auth step 2.
fn first_operation(dyn_auth: &[u8]) -> Option<(u8, &[u8])> {
    const WITNESS: u16 = TAG_AUTH_WITNESS as u16;
    const CHALLENGE: u16 = TAG_AUTH_CHALLENGE as u16;
    const RESPONSE: u16 = TAG_AUTH_RESPONSE as u16;
    const EXPONENTIATION: u16 = TAG_AUTH_EXPONENTIATION as u16;
    Tlv::new(dyn_auth)
        .find(|&(t, v)| match t {
            WITNESS | CHALLENGE | EXPONENTIATION => true,
            RESPONSE => !v.is_empty(),
            _ => false,
        })
        .map(|(t, v)| (t as u8, v))
}
