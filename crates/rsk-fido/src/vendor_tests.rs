// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::seed::{ensure_seed, load_keydev};
use crate::{AlwaysConfirm, FidoState, Presence, UserPresence};
use rsk_crypto::Device;
use rsk_crypto::MlKem768Pair;
use rsk_crypto::mlkem::MLKEM768_SEED_LEN;
use rsk_crypto::pinproto::PinProto;
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

struct Decline;
impl UserPresence for Decline {
    fn request(&mut self, _confirm: crate::Confirm<'_>) -> Presence {
        Presence::Timeout
    }
}

/// Confirms every prompt and counts them — lets a test prove a command asks for
/// two *separately named* ceremonies rather than one.
struct CountingPresence {
    calls: usize,
}
impl UserPresence for CountingPresence {
    fn request(&mut self, _confirm: crate::Confirm<'_>) -> Presence {
        self.calls += 1;
        Presence::Confirmed
    }
}

fn dev() -> Device<'static> {
    Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    }
}

/// The full host channel: the 32-byte key and 65-byte device pubkey (AAD), so
/// tests can encrypt/decrypt blobs exactly as the real host tool does.
struct Host {
    key: [u8; 32],
    aad: [u8; 65],
}

fn call(
    fs: &mut Fs<RamStorage>,
    rng: &mut SeqRng,
    state: &mut FidoState,
    presence: &mut dyn UserPresence,
    req: &[u8],
    out: &mut [u8],
) -> CtapResult {
    let mut ctx = Ctx {
        dev: dev(),
        fs,
        rng,
        state,
        now_ms: 0,
        presence,
    };
    vendor(&mut ctx, req, out)
}

fn build_mse(buf: &mut [u8], hx: &[u8; 32], hy: &[u8; 32]) -> usize {
    build_mse_coords(buf, hx, hy)
}

/// The same request with the coordinates carried as arbitrary byte strings, so a
/// test can send one that is not 32 bytes long.
fn build_mse_coords(buf: &mut [u8], hx: &[u8], hy: &[u8]) -> usize {
    let mut e = Encoder::new(Cursor::new(buf));
    e.map(2)
        .unwrap()
        .u8(1)
        .unwrap()
        .u64(VENDOR_MSE)
        .unwrap()
        .u8(2)
        .unwrap()
        .map(1)
        .unwrap()
        .u8(1)
        .unwrap()
        .map(5)
        .unwrap()
        .u8(1)
        .unwrap()
        .u8(2)
        .unwrap()
        .u8(3)
        .unwrap()
        .i64(-25)
        .unwrap()
        .i8(-1)
        .unwrap()
        .u8(1)
        .unwrap()
        .i8(-2)
        .unwrap()
        .bytes(hx)
        .unwrap()
        .i8(-3)
        .unwrap()
        .bytes(hy)
        .unwrap();
    e.writer().position()
}

/// Run the MSE handshake host-side and return the derived channel.
fn handshake(fs: &mut Fs<RamStorage>, rng: &mut SeqRng, state: &mut FidoState) -> Host {
    let host_scalar = [0x42u8; 32];
    let (hx, hy) = P256Key::from_scalar(&host_scalar).unwrap().public_xy();
    let mut req = [0u8; 200];
    let n = build_mse(&mut req, &hx, &hy);
    let mut out = [0u8; 200];
    let r = call(fs, rng, state, &mut AlwaysConfirm, &req[..n], &mut out).unwrap();

    // parse {1: COSE_Key{...,-2:dx,-3:dy}}
    let mut d = Decoder::new(&out[..r]);
    assert_eq!(d.map().unwrap(), Some(1));
    assert_eq!(d.u8().unwrap(), 1);
    let c = d.map().unwrap().unwrap();
    let (mut dx, mut dy) = ([0u8; 32], [0u8; 32]);
    for _ in 0..c {
        match d.i32().unwrap() {
            -2 => dx.copy_from_slice(d.bytes().unwrap()),
            -3 => dy.copy_from_slice(d.bytes().unwrap()),
            _ => {
                d.skip().unwrap();
            }
        }
    }
    let z = ecdh_raw(&host_scalar, &dx, &dy).unwrap();
    let mut aad = [0u8; 65];
    aad[0] = 0x04;
    aad[1..33].copy_from_slice(&dx);
    aad[33..].copy_from_slice(&dy);
    let mut key = [0u8; 32];
    hkdf_sha256(&[], &z, &aad, &mut key).unwrap();
    Host { key, aad }
}

/// MSE request with the optional ML-KEM-768 encapsulation key in
/// subCommandParams key 2 — `{1: MSE, 2: {1: COSE_Key, 2: ek}}`.
fn build_mse_hybrid(buf: &mut [u8], hx: &[u8; 32], hy: &[u8; 32], ek: &[u8]) -> usize {
    let mut e = Encoder::new(Cursor::new(buf));
    e.map(2)
        .unwrap()
        .u8(1)
        .unwrap()
        .u64(VENDOR_MSE)
        .unwrap()
        .u8(2)
        .unwrap()
        .map(2)
        .unwrap()
        .u8(1)
        .unwrap()
        .map(5)
        .unwrap()
        .u8(1)
        .unwrap()
        .u8(2)
        .unwrap()
        .u8(3)
        .unwrap()
        .i64(-25)
        .unwrap()
        .i8(-1)
        .unwrap()
        .u8(1)
        .unwrap()
        .i8(-2)
        .unwrap()
        .bytes(hx)
        .unwrap()
        .i8(-3)
        .unwrap()
        .bytes(hy)
        .unwrap()
        .u8(2)
        .unwrap()
        .bytes(ek)
        .unwrap();
    e.writer().position()
}

/// Run the hybrid MSE handshake host-side: send a P-256 pubkey plus a fresh
/// ML-KEM-768 encapsulation key, then recompute the channel key from the ECDH
/// secret and the decapsulated ML-KEM secret exactly as [`mlkem_leg`] does.
fn handshake_pq(fs: &mut Fs<RamStorage>, rng: &mut SeqRng, state: &mut FidoState) -> Host {
    let host_scalar = [0x42u8; 32];
    let (hx, hy) = P256Key::from_scalar(&host_scalar).unwrap().public_xy();

    // The host is the decapsulator: it keeps the ML-KEM keypair and ships ek.
    let pair = MlKem768Pair::from_seed(&[0x55u8; MLKEM768_SEED_LEN]);
    let ek = pair.encapsulation_key();

    let mut req = [0u8; 1400];
    let n = build_mse_hybrid(&mut req, &hx, &hy, &ek);
    let mut out = [0u8; 1400];
    let r = call(fs, rng, state, &mut AlwaysConfirm, &req[..n], &mut out).unwrap();

    // parse {1: COSE_Key{...,-2:dx,-3:dy}, 2: ct}
    let mut d = Decoder::new(&out[..r]);
    assert_eq!(d.map().unwrap(), Some(2));
    assert_eq!(d.u8().unwrap(), 1);
    let c = d.map().unwrap().unwrap();
    let (mut dx, mut dy) = ([0u8; 32], [0u8; 32]);
    for _ in 0..c {
        match d.i32().unwrap() {
            -2 => dx.copy_from_slice(d.bytes().unwrap()),
            -3 => dy.copy_from_slice(d.bytes().unwrap()),
            _ => {
                d.skip().unwrap();
            }
        }
    }
    assert_eq!(d.u8().unwrap(), 2);
    let mut ct = [0u8; MLKEM768_CT_LEN];
    ct.copy_from_slice(d.bytes().unwrap());

    let z = ecdh_raw(&host_scalar, &dx, &dy).unwrap();
    let ss = pair.decapsulate(&ct);
    let mut aad = [0u8; 65];
    aad[0] = 0x04;
    aad[1..33].copy_from_slice(&dx);
    aad[33..].copy_from_slice(&dy);

    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(&z);
    ikm[32..].copy_from_slice(&ss);
    let mut info = [0u8; 65 + MLKEM768_CT_LEN];
    info[..65].copy_from_slice(&aad);
    info[65..].copy_from_slice(&ct);
    let mut key = [0u8; 32];
    hkdf_sha256(MSE_PQ_SALT, &ikm, &info, &mut key).unwrap();
    Host { key, aad }
}

fn one_byte_req(buf: &mut [u8], subcmd: u64) -> usize {
    let mut e = Encoder::new(Cursor::new(buf));
    e.map(1).unwrap().u8(1).unwrap().u64(subcmd).unwrap();
    e.writer().position()
}

fn load_req(buf: &mut [u8], blob: &[u8]) -> usize {
    let mut e = Encoder::new(Cursor::new(buf));
    e.map(2)
        .unwrap()
        .u8(1)
        .unwrap()
        .u64(VENDOR_BACKUP_LOAD)
        .unwrap()
        .u8(2)
        .unwrap()
        .map(1)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(blob)
        .unwrap();
    e.writer().position()
}

fn setup() -> (Fs<RamStorage>, SeqRng, FidoState) {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    (fs, rng, FidoState::new())
}

#[cfg(feature = "fips-profile")]
#[test]
fn fips_backup_export_refused() {
    let (mut fs, mut rng, mut st) = setup();
    st.mse_active = true; // even over a live channel the seed is sealed in
    let mut req = [0u8; 16];
    let n = one_byte_req(&mut req, VENDOR_BACKUP_EXPORT);
    let mut out = [0u8; 64];
    assert_eq!(
        call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out
        ),
        Err(CtapError::NotAllowed)
    );
}

/// ChaCha-wrap a 32-byte value for the channel (the ATT_IMPORT/LOAD shape).
fn wrap32(host: &Host, value: &[u8; 32]) -> [u8; 60] {
    let nonce = [0x24u8; 12];
    let mut ct = *value;
    let tag = chacha20poly1305_encrypt(&host.key, &nonce, &host.aad, &mut ct);
    let mut blob = [0u8; 60];
    blob[..12].copy_from_slice(&nonce);
    blob[12..44].copy_from_slice(&ct);
    blob[44..].copy_from_slice(&tag);
    blob
}

fn att_import_req(buf: &mut [u8], blob: &[u8; 60], chain: &[u8]) -> usize {
    let mut e = Encoder::new(Cursor::new(buf));
    e.map(2)
        .unwrap()
        .u8(1)
        .unwrap()
        .u64(VENDOR_ATT_IMPORT)
        .unwrap();
    e.u8(2).unwrap().map(2).unwrap();
    e.u8(1).unwrap().bytes(blob).unwrap();
    e.u8(2).unwrap().bytes(chain).unwrap();
    e.writer().position()
}

#[test]
fn att_import_state_clear_roundtrip() {
    let (mut fs, mut rng, mut st) = setup();
    let host = handshake(&mut fs, &mut rng, &mut st);

    // Import an org key + two fake-TLV certs over the channel.
    let org_scalar = [0x21u8; 32];
    let blob = wrap32(&host, &org_scalar);
    let chain: &[u8] = &[0x30, 0x03, 1, 2, 3, 0x30, 0x02, 7, 7];
    let mut req = [0u8; 256];
    let n = att_import_req(&mut req, &blob, chain);
    let mut out = [0u8; 128];
    call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut AlwaysConfirm,
        &req[..n],
        &mut out,
    )
    .unwrap();

    // The stored key decrypts back to the imported scalar; STATE says so.
    assert_eq!(
        crate::seed::load_att_key(&dev(), &mut fs).unwrap(),
        org_scalar
    );
    let n = one_byte_req(&mut req, VENDOR_ATT_STATE);
    let r = call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut AlwaysConfirm,
        &req[..n],
        &mut out,
    )
    .unwrap();
    let mut d = Decoder::new(&out[..r]);
    assert_eq!(d.map().unwrap(), Some(2));
    assert_eq!(d.u8().unwrap(), 1);
    assert!(d.bool().unwrap());

    // CLEAR drops both and STATE flips back. Its own handshake: IMPORT above spent
    // the channel.
    handshake(&mut fs, &mut rng, &mut st);
    let n = one_byte_req(&mut req, VENDOR_ATT_CLEAR);
    call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut AlwaysConfirm,
        &req[..n],
        &mut out,
    )
    .unwrap();
    assert!(crate::seed::load_att_key(&dev(), &mut fs).is_none());
    let n = one_byte_req(&mut req, VENDOR_ATT_STATE);
    let r = call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut AlwaysConfirm,
        &req[..n],
        &mut out,
    )
    .unwrap();
    let mut d = Decoder::new(&out[..r]);
    assert_eq!(d.map().unwrap(), Some(1));
    assert_eq!(d.u8().unwrap(), 1);
    assert!(!d.bool().unwrap());

    // A malformed chain is refused before any gate is consumed.
    let n = att_import_req(&mut req, &blob, &[0xFF, 0x01]);
    assert_eq!(
        call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out
        ),
        Err(CtapError::InvalidParameter)
    );
}

/// Build `n` fake DER SEQUENCEs of `body` bytes each, long-form length.
fn fake_chain(n: usize, body: usize, out: &mut [u8]) -> usize {
    let mut dst = 0;
    for _ in 0..n {
        out[dst] = 0x30;
        out[dst + 1] = 0x82;
        out[dst + 2..dst + 4].copy_from_slice(&(body as u16).to_be_bytes());
        out[dst + 4..dst + 4 + body].fill(0x41);
        dst += 4 + body;
    }
    dst
}

/// **Regression for the PIN-dependent chain cap.** `MAX_RAW_SUBPARA` is a scratch
/// buffer for the pinUvAuth MAC, so its length check lived on the PIN branch only:
/// a PIN-less device accepted chains a PIN-protected one refused `RequestTooLarge`,
/// and a long enough one minted a makeCredential reply CTAPHID could not carry.
/// `ATT_CHAIN_MAX` now folds that ceiling in, and `att_chain_pack` runs before
/// either gate — so the answer no longer depends on how the caller authenticated.
/// Both halves assert the SAME verdict on the SAME request; that is the point.
#[test]
fn oversized_chain_is_refused_the_same_with_and_without_a_pin() {
    let mut chain = [0u8; 3600];
    let clen = fake_chain(3, 1196, &mut chain);
    assert!(
        clen > crate::cert::ATT_CHAIN_MAX,
        "the probe must exceed the cap"
    );

    for pin in [false, true] {
        let (mut fs, mut rng, mut st) = setup();
        let host = handshake(&mut fs, &mut rng, &mut st);
        let blob = wrap32(&host, &[0x21u8; 32]);
        if pin {
            fs.put(EF_PIN, &[8, 4, 1]).unwrap();
        }
        let mut req = [0u8; 4096];
        let n = att_import_req(&mut req, &blob, &chain[..clen]);
        let mut out = [0u8; 128];
        let r = call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out,
        );
        assert_eq!(
            r,
            Err(CtapError::InvalidParameter),
            "chain of {clen} B, pin={pin}: refused by att_chain_pack either way"
        );
    }
}

/// The cap is the tightest of three ceilings, so the worst-case makeCredential
/// reply fits one CTAPHID message with room to spare. A build-time assert in
/// `cert.rs` holds the invariant; this states the margin in one place a reader
/// will find it.
#[test]
fn the_widest_credential_fits_one_ctaphid_message() {
    let worst = crate::makecredential::MC_RESPONSE_SANS_CHAIN + crate::cert::ATT_CHAIN_MAX;
    assert!(
        worst <= crate::consts::MAX_MSG_SIZE as usize,
        "worst-case makeCredential {worst} B exceeds maxMsgSize"
    );
}

#[test]
fn att_import_without_pin_demands_the_named_confirmation() {
    // A PIN-less device waives `gate`'s PIN half, and MSE is ungated — so the whole
    // attestation identity used to move on one unlabelled touch. The extra ceremony
    // names it, and declining that alone refuses the import.
    let (mut fs, mut rng, mut st) = setup();
    let host = handshake(&mut fs, &mut rng, &mut st);
    let blob = wrap32(&host, &[0x21u8; 32]);
    let chain: &[u8] = &[0x30, 0x03, 1, 2, 3];
    let mut req = [0u8; 256];
    let n = att_import_req(&mut req, &blob, chain);
    let mut out = [0u8; 128];
    assert_eq!(
        call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut Decline,
            &req[..n],
            &mut out
        ),
        Err(CtapError::OperationDenied)
    );
    assert!(crate::seed::load_att_key(&dev(), &mut fs).is_none());

    // Confirmed, it is two prompts: the named handover, then `gate`'s own. The
    // declined attempt above spent the channel, so re-handshake — and re-wrap the
    // blob, since the new channel derives a different key.
    let host = handshake(&mut fs, &mut rng, &mut st);
    let blob = wrap32(&host, &[0x21u8; 32]);
    let n = att_import_req(&mut req, &blob, chain);
    let mut counting = CountingPresence { calls: 0 };
    call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut counting,
        &req[..n],
        &mut out,
    )
    .unwrap();
    assert_eq!(counting.calls, 2);
    assert!(crate::seed::load_att_key(&dev(), &mut fs).is_some());
}

// Off the fips profile only: fips refuses export outright (see `fips_backup_export_refused`).
#[cfg(not(feature = "fips-profile"))]
#[test]
fn mse_then_export_roundtrips_seed() {
    let (mut fs, mut rng, mut st) = setup();
    let seed = load_keydev(&dev(), &mut fs).unwrap();
    let host = handshake(&mut fs, &mut rng, &mut st);

    let mut req = [0u8; 32];
    let n = one_byte_req(&mut req, VENDOR_BACKUP_EXPORT);
    let mut out = [0u8; 128];
    let r = call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut AlwaysConfirm,
        &req[..n],
        &mut out,
    )
    .unwrap();

    // {1: blob(60)} — decrypt it host-side.
    let mut d = Decoder::new(&out[..r]);
    assert_eq!(d.map().unwrap(), Some(1));
    assert_eq!(d.u8().unwrap(), 1);
    let blob = d.bytes().unwrap();
    assert_eq!(blob.len(), LOCK_BLOB_LEN);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[..12]);
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&blob[12..44]);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&blob[44..]);
    chacha20poly1305_decrypt(&host.key, &nonce, &host.aad, &mut buf, &tag).unwrap();
    assert_eq!(buf, seed);
}

// Audit run-33: `MSE` and `BACKUP_EXPORT` are separate CTAPHID transactions, so a
// second process on its own CID can re-key the channel in between and have the
// device encrypt the master seed under *its* key. The channel binding must make the
// export refuse rather than misaddress the seed.
#[cfg(not(feature = "fips-profile"))]
#[test]
fn export_refused_after_another_channel_rekeys_the_mse() {
    // A CTAPHID channel id is written by the sender into its own frame header, so
    // an interloper forges the victim's CID rather than using its own — binding to
    // `mse_cid` alone would compare the attacker's bytes against themselves. What
    // holds is that the channel is one-shot: the re-key is refused and the channel
    // dropped, so the export can never encrypt under the interloper's key.
    for interloper_cid in [1u32, 2] {
        let (mut fs, mut rng, mut st) = setup();

        // The victim's tool runs its handshake on channel 1.
        st.channel = 1;
        let host = handshake(&mut fs, &mut rng, &mut st);
        let victim_key = st.mse_key;
        assert_eq!(victim_key, host.key);

        // The interloper re-keys — on its own CID, or forging the victim's.
        st.channel = interloper_cid;
        let mut req = [0u8; 200];
        let their_scalar = [0x7Eu8; 32];
        let (hx, hy) = P256Key::from_scalar(&their_scalar).unwrap().public_xy();
        let n = build_mse(&mut req, &hx, &hy);
        let mut out = [0u8; 200];
        assert_eq!(
            call(
                &mut fs,
                &mut rng,
                &mut st,
                &mut AlwaysConfirm,
                &req[..n],
                &mut out
            ),
            Err(CtapError::NotAllowed),
            "a live channel must never be re-keyed (interloper cid {interloper_cid})"
        );
        // Refused *and* dropped: neither party can spend it.
        assert!(!st.mse_active);
        assert_ne!(st.mse_key, victim_key);

        // The victim's export, still on channel 1, now fails closed rather than
        // encrypting the seed to whoever re-keyed.
        st.channel = 1;
        let n = one_byte_req(&mut req, VENDOR_BACKUP_EXPORT);
        assert_eq!(
            call(
                &mut fs,
                &mut rng,
                &mut st,
                &mut AlwaysConfirm,
                &req[..n],
                &mut out
            ),
            Err(CtapError::NotAllowed)
        );
    }
}

#[test]
fn a_gated_subcommand_spends_the_mse_channel() {
    // One handshake, one gated use: without this an interloper that squats the
    // channel after a legitimate consumer would inherit a live key.
    let (mut fs, mut rng, mut st) = setup();
    handshake(&mut fs, &mut rng, &mut st);
    assert!(st.mse_active);

    let mut req = [0u8; 32];
    let n = one_byte_req(&mut req, VENDOR_BACKUP_EXPORT);
    let mut out = [0u8; 128];
    let _ = call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut AlwaysConfirm,
        &req[..n],
        &mut out,
    );
    assert!(!st.mse_active, "the consumer must spend the channel");
    assert_eq!(st.mse_key, [0u8; 32]);

    // A declined touch spends it too — a failed ceremony must not leave the
    // channel live for the next caller to pick up.
    handshake(&mut fs, &mut rng, &mut st);
    assert!(st.mse_active);
    assert_eq!(
        call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut Decline,
            &req[..n],
            &mut out
        ),
        Err(CtapError::OperationDenied)
    );
    assert!(!st.mse_active);
}

// Off the fips profile only: fips refuses export outright (see `fips_backup_export_refused`).
#[cfg(not(feature = "fips-profile"))]
#[test]
fn mse_hybrid_then_export_roundtrips_seed() {
    // End-to-end proof of the hybrid channel: if the device-side ML-KEM
    // encapsulate + HKDF agrees with the host-side decapsulate + HKDF, the
    // seed exported over the channel decrypts to the real seed.
    let (mut fs, mut rng, mut st) = setup();
    let seed = load_keydev(&dev(), &mut fs).unwrap();
    let host = handshake_pq(&mut fs, &mut rng, &mut st);

    let mut req = [0u8; 32];
    let n = one_byte_req(&mut req, VENDOR_BACKUP_EXPORT);
    let mut out = [0u8; 128];
    let r = call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut AlwaysConfirm,
        &req[..n],
        &mut out,
    )
    .unwrap();

    let mut d = Decoder::new(&out[..r]);
    assert_eq!(d.map().unwrap(), Some(1));
    assert_eq!(d.u8().unwrap(), 1);
    let blob = d.bytes().unwrap();
    assert_eq!(blob.len(), LOCK_BLOB_LEN);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[..12]);
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&blob[12..44]);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&blob[44..]);
    chacha20poly1305_decrypt(&host.key, &nonce, &host.aad, &mut buf, &tag).unwrap();
    assert_eq!(buf, seed);
}

#[test]
fn hybrid_channel_key_differs_from_classical() {
    // Same fresh device (same RNG seed → same P-256 ephemeral and ECDH
    // secret): the PQ leg must still derive a different channel key, proving
    // the ML-KEM secret and the domain salt actually participate.
    let (mut fs1, mut rng1, mut st1) = setup();
    let classical = handshake(&mut fs1, &mut rng1, &mut st1);
    let (mut fs2, mut rng2, mut st2) = setup();
    let hybrid = handshake_pq(&mut fs2, &mut rng2, &mut st2);
    assert_ne!(classical.key, hybrid.key);
}

#[test]
fn mse_rejects_short_mlkem_ek() {
    // An encapsulation key one byte short is rejected before any channel
    // forms — no half-open hybrid state.
    let (mut fs, mut rng, mut st) = setup();
    let (hx, hy) = P256Key::from_scalar(&[0x42u8; 32]).unwrap().public_xy();
    let short_ek = [0u8; MLKEM768_EK_LEN - 1];
    let mut req = [0u8; 1400];
    let n = build_mse_hybrid(&mut req, &hx, &hy, &short_ek);
    let mut out = [0u8; 1400];
    let e = call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut AlwaysConfirm,
        &req[..n],
        &mut out,
    );
    assert_eq!(e, Err(CtapError::InvalidParameter));
    assert!(!st.mse_active);
}

#[test]
fn mse_rejects_unreduced_mlkem_ek() {
    // Right length, non-reduced coefficients → ML-KEM encapsulate fails; the
    // vendor layer maps that to InvalidParameter, no channel established.
    let (mut fs, mut rng, mut st) = setup();
    let (hx, hy) = P256Key::from_scalar(&[0x42u8; 32]).unwrap().public_xy();
    let bad_ek = [0xFFu8; MLKEM768_EK_LEN];
    let mut req = [0u8; 1400];
    let n = build_mse_hybrid(&mut req, &hx, &hy, &bad_ek);
    let mut out = [0u8; 1400];
    let e = call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut AlwaysConfirm,
        &req[..n],
        &mut out,
    );
    assert_eq!(e, Err(CtapError::InvalidParameter));
    assert!(!st.mse_active);
}

#[test]
fn load_installs_seed_and_rebuilds_attestation() {
    let (mut fs, mut rng, mut st) = setup();
    let old = load_keydev(&dev(), &mut fs).unwrap();
    let host = handshake(&mut fs, &mut rng, &mut st);

    // Encrypt a fresh seed host-side into a blob.
    let new_seed = [0x33u8; 32];
    let nonce = [0x07u8; 12];
    let mut buf = new_seed;
    let tag = chacha20poly1305_encrypt(&host.key, &nonce, &host.aad, &mut buf);
    let mut blob = [0u8; LOCK_BLOB_LEN];
    blob[..12].copy_from_slice(&nonce);
    blob[12..44].copy_from_slice(&buf);
    blob[44..].copy_from_slice(&tag);

    let mut req = [0u8; 128];
    let n = load_req(&mut req, &blob);
    let mut out = [0u8; 16];
    call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut AlwaysConfirm,
        &req[..n],
        &mut out,
    )
    .unwrap();

    assert_ne!(new_seed, old);
    assert_eq!(load_keydev(&dev(), &mut fs), Some(new_seed));
    assert!(fs.has_data(EF_EE_DEV)); // attestation rebuilt over the new seed
}

#[test]
fn export_refused_after_finalize() {
    let (mut fs, mut rng, mut st) = setup();
    let _ = handshake(&mut fs, &mut rng, &mut st);
    let mut req = [0u8; 32];
    let mut out = [0u8; 128];

    let n = one_byte_req(&mut req, VENDOR_BACKUP_FINALIZE);
    call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut AlwaysConfirm,
        &req[..n],
        &mut out,
    )
    .unwrap();

    let n = one_byte_req(&mut req, VENDOR_BACKUP_EXPORT);
    let e = call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut AlwaysConfirm,
        &req[..n],
        &mut out,
    );
    assert_eq!(e, Err(CtapError::NotAllowed));
}

// Off the fips profile only: under fips export is refused with `NotAllowed` before the touch
// gate, masking this `OperationDenied` path (the fips refusal is `fips_backup_export_refused`).
#[cfg(not(feature = "fips-profile"))]
#[test]
fn export_refused_without_touch() {
    let (mut fs, mut rng, mut st) = setup();
    let _ = handshake(&mut fs, &mut rng, &mut st);
    let mut req = [0u8; 32];
    let n = one_byte_req(&mut req, VENDOR_BACKUP_EXPORT);
    let mut out = [0u8; 128];
    let e = call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut Decline,
        &req[..n],
        &mut out,
    );
    assert_eq!(e, Err(CtapError::OperationDenied));
}

#[test]
fn export_without_mse_is_not_allowed() {
    let (mut fs, mut rng, mut st) = setup();
    let mut req = [0u8; 32];
    let n = one_byte_req(&mut req, VENDOR_BACKUP_EXPORT);
    let mut out = [0u8; 128];
    let e = call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut AlwaysConfirm,
        &req[..n],
        &mut out,
    );
    assert_eq!(e, Err(CtapError::NotAllowed));
}

#[test]
fn load_rejects_tampered_blob() {
    let (mut fs, mut rng, mut st) = setup();
    let host = handshake(&mut fs, &mut rng, &mut st);
    let nonce = [0x07u8; 12];
    let mut buf = [0x33u8; 32];
    let tag = chacha20poly1305_encrypt(&host.key, &nonce, &host.aad, &mut buf);
    let mut blob = [0u8; LOCK_BLOB_LEN];
    blob[..12].copy_from_slice(&nonce);
    blob[12..44].copy_from_slice(&buf);
    blob[44..].copy_from_slice(&tag);
    blob[20] ^= 0xFF; // flip a ciphertext byte

    let mut req = [0u8; 128];
    let n = load_req(&mut req, &blob);
    let mut out = [0u8; 16];
    let e = call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut AlwaysConfirm,
        &req[..n],
        &mut out,
    );
    assert_eq!(e, Err(CtapError::IntegrityFailure));
}

// Off the fips profile only: under fips export is refused with `NotAllowed` before the PIN/token
// check, masking this `PuatRequired` path (the fips refusal is `fips_backup_export_refused`).
#[cfg(not(feature = "fips-profile"))]
#[test]
fn export_with_pin_requires_token() {
    let (mut fs, mut rng, mut st) = setup();
    fs.put(EF_PIN, &[8, 4, 1]).unwrap(); // PIN present → token required
    let _ = handshake(&mut fs, &mut rng, &mut st);
    let mut req = [0u8; 32];
    let n = one_byte_req(&mut req, VENDOR_BACKUP_EXPORT);
    let mut out = [0u8; 128];
    let e = call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut AlwaysConfirm,
        &req[..n],
        &mut out,
    );
    assert_eq!(e, Err(CtapError::PuatRequired));
}

#[test]
fn backup_state_reports_flags() {
    let (mut fs, mut rng, mut st) = setup();
    assert_eq!(
        state_flags(&mut fs, &mut rng, &mut st),
        (false, true, false, false) // not sealed, has seed, not locked, not unlocked
    );
}

#[test]
fn backup_status_mirrors_the_host_flags() {
    let (mut fs, _rng, _st) = setup();
    // Fresh: a seed is present, the export window is open (not sealed), not locked.
    let s = backup_status(&mut fs);
    assert!(s.has_seed && !s.sealed && !s.locked);
    assert!(!backup_sealed(&mut fs));
    // `exportable` tracks the build profile, not the store.
    assert_eq!(s.exportable, !cfg!(feature = "fips-profile"));
    // Sealing on-device flips the flag, exactly like host finalize.
    assert!(mark_backup_sealed(&mut fs));
    let s = backup_status(&mut fs);
    assert!(s.has_seed && s.sealed);
    assert!(backup_sealed(&mut fs));
}

// ---- soft-lock ----

/// Read BACKUP_STATE and return `(sealed, has_seed, locked, unlocked)`.
fn state_flags(
    fs: &mut Fs<RamStorage>,
    rng: &mut SeqRng,
    st: &mut FidoState,
) -> (bool, bool, bool, bool) {
    let mut req = [0u8; 16];
    let n = one_byte_req(&mut req, VENDOR_BACKUP_STATE);
    let mut out = [0u8; 64];
    let r = call(fs, rng, st, &mut AlwaysConfirm, &req[..n], &mut out).unwrap();
    let mut d = Decoder::new(&out[..r]);
    assert_eq!(d.map().unwrap(), Some(4));
    let mut flags = [false; 4];
    for f in flags.iter_mut() {
        d.u8().unwrap();
        *f = d.bool().unwrap();
    }
    (flags[0], flags[1], flags[2], flags[3])
}

/// Host side of the channel: wrap 32 bytes as nonce ‖ ct ‖ tag.
fn host_wrap(host: &Host, key: &[u8; 32], nonce: &[u8; 12]) -> [u8; LOCK_BLOB_LEN] {
    let mut ct = *key;
    let tag = chacha20poly1305_encrypt(&host.key, nonce, &host.aad, &mut ct);
    let mut blob = [0u8; LOCK_BLOB_LEN];
    blob[..12].copy_from_slice(nonce);
    blob[12..44].copy_from_slice(&ct);
    blob[44..].copy_from_slice(&tag);
    blob
}

const ACFG_TOKEN: [u8; 32] = [0x77; 32];

/// Arm an acfg-permission pinUvAuthToken on `st` (authenticatorConfig always
/// demands one) without disturbing the MSE channel fields.
fn arm_acfg(st: &mut FidoState) {
    st.paut.token = ACFG_TOKEN;
    st.paut.permissions = PERM_ACFG;
    st.begin_using_token(false, 0);
}

/// Build a MAC'd `authenticatorConfig` vendor request
/// `{1: 0xFF, 2: {1: vendor_id, 2: param?}, 3: 2, 4: mac}`.
fn config_vendor_req(vendor_id: u64, param: Option<&[u8]>, buf: &mut [u8]) -> usize {
    use rsk_crypto::pinproto;

    let mut sub = [0u8; 128];
    let sub_len = {
        let mut e = Encoder::new(Cursor::new(&mut sub[..]));
        match param {
            Some(p) => {
                e.map(2).unwrap();
                e.u8(1).unwrap().u64(vendor_id).unwrap();
                e.u8(2).unwrap().bytes(p).unwrap();
            }
            None => {
                e.map(1).unwrap();
                e.u8(1).unwrap().u64(vendor_id).unwrap();
            }
        }
        e.writer().position()
    };

    let mut vp = [0u8; 32 + 2 + 128];
    vp[..32].fill(0xff);
    vp[32] = crate::consts::CTAP_CONFIG;
    vp[33] = 0xFF;
    vp[34..34 + sub_len].copy_from_slice(&sub[..sub_len]);
    let mut mac = [0u8; 32];
    let mlen =
        pinproto::authenticate(PinProto::Two, &ACFG_TOKEN, &vp[..34 + sub_len], &mut mac).unwrap();

    // Assemble by hand — the raw subCommandParams bytes are spliced verbatim.
    let mut n = 0;
    buf[n] = 0xA4; // map(4)
    n += 1;
    buf[n..n + 3].copy_from_slice(&[0x01, 0x18, 0xFF]); // 1: 0xFF
    n += 3;
    buf[n] = 0x02; // 2: subCommandParams
    n += 1;
    buf[n..n + sub_len].copy_from_slice(&sub[..sub_len]);
    n += sub_len;
    buf[n..n + 2].copy_from_slice(&[0x03, 0x02]); // 3: protocol 2
    n += 2;
    buf[n..n + 3].copy_from_slice(&[0x04, 0x58, mlen as u8]); // 4: mac
    n += 3;
    buf[n..n + mlen].copy_from_slice(&mac[..mlen]);
    n + mlen
}

fn run_config(
    fs: &mut Fs<RamStorage>,
    rng: &mut SeqRng,
    st: &mut FidoState,
    presence: &mut dyn UserPresence,
    req: &[u8],
) -> CtapResult {
    let mut out = [0u8; 64];
    let mut ctx = Ctx {
        dev: dev(),
        fs,
        rng,
        state: st,
        now_ms: 0,
        presence,
    };
    crate::config::authenticator_config(&mut ctx, req, &mut out)
}

/// Drive a vendor UNLOCK with `lock_key` wrapped for the current channel.
fn run_unlock(
    fs: &mut Fs<RamStorage>,
    rng: &mut SeqRng,
    st: &mut FidoState,
    lock_key: &[u8; 32],
    host: &Host,
    nonce_seed: u8,
) -> CtapResult {
    let blob = host_wrap(host, lock_key, &[nonce_seed; 12]);
    let mut req = [0u8; 128];
    let n = {
        let mut e = Encoder::new(Cursor::new(&mut req[..]));
        e.map(2).unwrap();
        e.u8(1).unwrap().u64(VENDOR_UNLOCK).unwrap();
        e.u8(2).unwrap().map(1).unwrap().u8(1).unwrap();
        e.bytes(&blob).unwrap();
        e.writer().position()
    };
    let mut out = [0u8; 16];
    call(fs, rng, st, &mut AlwaysConfirm, &req[..n], &mut out)
}

const LOCK_KEY: [u8; 32] = [0xA7; 32];

/// setup + handshake + armed token + AUT_ENABLE; returns the original seed
/// and the live channel.
fn locked_setup() -> (Fs<RamStorage>, SeqRng, FidoState, Host, [u8; 32]) {
    let (mut fs, mut rng, mut st) = setup();
    let seed = load_keydev(&dev(), &mut fs).unwrap();
    let host = handshake(&mut fs, &mut rng, &mut st);
    arm_acfg(&mut st);
    let blob = host_wrap(&host, &LOCK_KEY, &[0x11; 12]);
    let mut req = [0u8; 192];
    let n = config_vendor_req(crate::consts::CONFIG_AUT_ENABLE, Some(&blob), &mut req);
    run_config(&mut fs, &mut rng, &mut st, &mut AlwaysConfirm, &req[..n]).unwrap();
    // AUT_ENABLE spends the channel (it is one-shot), so hand callers a fresh one
    // — every one of them goes on to run another gated subcommand.
    let host = handshake(&mut fs, &mut rng, &mut st);
    (fs, rng, st, host, seed)
}

#[test]
fn lock_enable_wraps_seed_and_drops_plain() {
    let (mut fs, mut rng, mut st, _host, _seed) = locked_setup();
    assert!(!fs.has_data(EF_KEY_DEV.get()));
    assert_eq!(fs.size(EF_KEY_DEV_ENC.get()), Some(LOCK_BLOB_LEN));
    // No RAM copy after enable — operations are locked out immediately.
    assert!(st.keydev_dec.is_none());
    assert_eq!(load_keydev(&dev(), &mut fs), None);
    assert_eq!(
        state_flags(&mut fs, &mut rng, &mut st),
        (false, false, true, false)
    );
}

#[test]
fn unlock_restores_operations_for_the_session() {
    let (mut fs, mut rng, mut st, host, seed) = locked_setup();
    run_unlock(&mut fs, &mut rng, &mut st, &LOCK_KEY, &host, 0x22).unwrap();
    assert_eq!(st.keydev_dec, Some(seed));
    // The op-level loader sees the RAM copy; flash stays wrapped.
    let mut presence = AlwaysConfirm;
    let mut ctx = Ctx {
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut st,
        now_ms: 0,
        presence: &mut presence,
    };
    assert_eq!(ctx.load_keydev(), Some(seed));
    assert!(!fs.has_data(EF_KEY_DEV.get()));
    assert_eq!(
        state_flags(&mut fs, &mut rng, &mut st),
        (false, false, true, true)
    );
}

#[test]
fn unlock_with_wrong_key_fails() {
    let (mut fs, mut rng, mut st, host, _seed) = locked_setup();
    let e = run_unlock(&mut fs, &mut rng, &mut st, &[0x5C; 32], &host, 0x23);
    assert_eq!(e, Err(CtapError::InvalidParameter));
    assert!(st.keydev_dec.is_none());
}

#[test]
fn unlock_when_not_locked_is_integrity_failure() {
    let (mut fs, mut rng, mut st) = setup();
    let host = handshake(&mut fs, &mut rng, &mut st);
    let e = run_unlock(&mut fs, &mut rng, &mut st, &LOCK_KEY, &host, 0x24);
    assert_eq!(e, Err(CtapError::IntegrityFailure));
}

#[test]
fn disable_restores_plain_seed() {
    let (mut fs, mut rng, mut st, host, seed) = locked_setup();
    run_unlock(&mut fs, &mut rng, &mut st, &LOCK_KEY, &host, 0x25).unwrap();
    let mut req = [0u8; 192];
    let n = config_vendor_req(crate::consts::CONFIG_AUT_DISABLE, None, &mut req);
    run_config(&mut fs, &mut rng, &mut st, &mut AlwaysConfirm, &req[..n]).unwrap();
    assert!(!fs.has_data(EF_KEY_DEV_ENC.get()));
    assert!(st.keydev_dec.is_none()); // no stale RAM copy
    assert_eq!(load_keydev(&dev(), &mut fs), Some(seed));
    assert_eq!(
        state_flags(&mut fs, &mut rng, &mut st),
        (false, true, false, false)
    );
}

#[test]
fn disable_without_unlock_is_pin_auth_invalid() {
    let (mut fs, mut rng, mut st, _host, _seed) = locked_setup();
    let mut req = [0u8; 192];
    let n = config_vendor_req(crate::consts::CONFIG_AUT_DISABLE, None, &mut req);
    let e = run_config(&mut fs, &mut rng, &mut st, &mut AlwaysConfirm, &req[..n]);
    assert_eq!(e, Err(CtapError::PinAuthInvalid));
    assert!(fs.has_data(EF_KEY_DEV_ENC.get()));
}

#[test]
fn enable_twice_is_not_allowed() {
    let (mut fs, mut rng, mut st, host, _seed) = locked_setup();
    let blob = host_wrap(&host, &LOCK_KEY, &[0x33; 12]);
    let mut req = [0u8; 192];
    let n = config_vendor_req(crate::consts::CONFIG_AUT_ENABLE, Some(&blob), &mut req);
    let e = run_config(&mut fs, &mut rng, &mut st, &mut AlwaysConfirm, &req[..n]);
    assert_eq!(e, Err(CtapError::NotAllowed));
}

#[test]
fn enable_without_mse_is_not_allowed() {
    let (mut fs, mut rng, mut st) = setup();
    arm_acfg(&mut st);
    let blob = [0u8; LOCK_BLOB_LEN];
    let mut req = [0u8; 192];
    let n = config_vendor_req(crate::consts::CONFIG_AUT_ENABLE, Some(&blob), &mut req);
    let e = run_config(&mut fs, &mut rng, &mut st, &mut AlwaysConfirm, &req[..n]);
    assert_eq!(e, Err(CtapError::NotAllowed));
    assert!(fs.has_data(EF_KEY_DEV.get()));
}

#[test]
fn enable_without_touch_changes_nothing() {
    let (mut fs, mut rng, mut st) = setup();
    let host = handshake(&mut fs, &mut rng, &mut st);
    arm_acfg(&mut st);
    let blob = host_wrap(&host, &LOCK_KEY, &[0x44; 12]);
    let mut req = [0u8; 192];
    let n = config_vendor_req(crate::consts::CONFIG_AUT_ENABLE, Some(&blob), &mut req);
    let e = run_config(&mut fs, &mut rng, &mut st, &mut Decline, &req[..n]);
    assert_eq!(e, Err(CtapError::OperationDenied));
    assert!(fs.has_data(EF_KEY_DEV.get()));
    assert!(!fs.has_data(EF_KEY_DEV_ENC.get()));
}

#[test]
fn unknown_vendor_id_is_invalid_subcommand() {
    let (mut fs, mut rng, mut st) = setup();
    arm_acfg(&mut st);
    let mut req = [0u8; 192];
    let n = config_vendor_req(0xDEAD_BEEF, None, &mut req);
    let e = run_config(&mut fs, &mut rng, &mut st, &mut AlwaysConfirm, &req[..n]);
    assert_eq!(e, Err(CtapError::InvalidSubcommand));
}

#[test]
fn backup_load_refused_while_locked() {
    let (mut fs, mut rng, mut st, host, _seed) = locked_setup();
    let blob = host_wrap(&host, &[0x66; 32], &[0x55; 12]);
    let mut req = [0u8; 128];
    let n = load_req(&mut req, &blob);
    let mut out = [0u8; 16];
    let e = call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut AlwaysConfirm,
        &req[..n],
        &mut out,
    );
    assert_eq!(e, Err(CtapError::NotAllowed));
}

// Off the fips profile only: fips refuses export outright (see `fips_backup_export_refused`).
#[cfg(not(feature = "fips-profile"))]
#[test]
fn backup_export_serves_the_unlocked_ram_copy() {
    let (mut fs, mut rng, mut st, host, seed) = locked_setup();
    run_unlock(&mut fs, &mut rng, &mut st, &LOCK_KEY, &host, 0x26).unwrap();
    // UNLOCK spent that channel; the export needs its own.
    let host = handshake(&mut fs, &mut rng, &mut st);
    let mut req = [0u8; 32];
    let n = one_byte_req(&mut req, VENDOR_BACKUP_EXPORT);
    let mut out = [0u8; 128];
    let r = call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut AlwaysConfirm,
        &req[..n],
        &mut out,
    )
    .unwrap();
    let mut d = Decoder::new(&out[..r]);
    assert_eq!(d.map().unwrap(), Some(1));
    assert_eq!(d.u8().unwrap(), 1);
    let blob = d.bytes().unwrap();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[..12]);
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&blob[12..44]);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&blob[44..]);
    chacha20poly1305_decrypt(&host.key, &nonce, &host.aad, &mut buf, &tag).unwrap();
    assert_eq!(buf, seed);
}

#[test]
fn reset_clears_the_lock_and_regenerates() {
    let (mut fs, mut rng, mut st, _host, old_seed) = locked_setup();
    let mut presence = AlwaysConfirm;
    let mut ctx = Ctx {
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut st,
        now_ms: 0,
        presence: &mut presence,
    };
    crate::reset::reset(&mut ctx).unwrap();
    assert!(!fs.has_data(EF_KEY_DEV_ENC.get()));
    let new_seed = load_keydev(&dev(), &mut fs).unwrap();
    assert_ne!(new_seed, old_seed); // fresh identity — the recovery path
}

#[test]
fn ensure_seed_does_not_regenerate_under_lock() {
    let (mut fs, mut rng, mut st, host, seed) = locked_setup();
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    assert!(!fs.has_data(EF_KEY_DEV.get())); // boot on a locked device: no regen
    run_unlock(&mut fs, &mut rng, &mut st, &LOCK_KEY, &host, 0x27).unwrap();
    assert_eq!(st.keydev_dec, Some(seed)); // blob untouched, same seed
}

// ---- CONFIG_WRITE (0x0C): device config over the FIDO vendor channel ----

/// A small, opaque device-config TLV. READ CONFIG echoes it (minus any config-lock
/// tag) and then appends the unset CONFIG_LOCK, so its bytes appear in the body of
/// the DeviceInfo TLV — see [`dev_conf_readback`] / [`dev_conf_contains`].
const DEV_CONF_BLOB: &[u8] = &[0x03, 0x02, 0x02, 0x00];

/// Build a `VENDOR_CONFIG_WRITE` request `{1: subcmd, 2: {1: target, 2: blob}
/// [, 3: 2, 4: mac]}`. With `authed`, splice a PERM_ACFG pinUvAuth MAC over
/// `0xff×32 ‖ 0x41 ‖ subcmd ‖ subCommandParams` (as `pin_gate` verifies it).
fn config_write_req(target: u64, blob: &[u8], authed: bool, buf: &mut [u8]) -> usize {
    use rsk_crypto::pinproto;

    // subCommandParams captured verbatim — the MAC and parse() both see these bytes.
    let mut sub = [0u8; 256];
    let sub_len = {
        let mut e = Encoder::new(Cursor::new(&mut sub[..]));
        e.map(2).unwrap();
        e.u8(1).unwrap().u64(target).unwrap();
        e.u8(2).unwrap().bytes(blob).unwrap();
        e.writer().position()
    };

    let mut n = 0;
    buf[n] = 0xA0 | if authed { 4 } else { 2 }; // map(2) or map(4)
    n += 1;
    buf[n..n + 2].copy_from_slice(&[0x01, VENDOR_CONFIG_WRITE as u8]); // 1: subcommand
    n += 2;
    buf[n] = 0x02; // 2: subCommandParams
    n += 1;
    buf[n..n + sub_len].copy_from_slice(&sub[..sub_len]);
    n += sub_len;
    if authed {
        let mut vp = [0u8; 32 + 2 + 256];
        let vp_len = crate::state::puat_subcommand_msg(
            &mut vp,
            CTAP_VENDOR,
            VENDOR_CONFIG_WRITE as u8,
            &sub[..sub_len],
        );
        let mut mac = [0u8; 32];
        let mlen =
            pinproto::authenticate(PinProto::Two, &ACFG_TOKEN, &vp[..vp_len], &mut mac).unwrap();
        buf[n..n + 2].copy_from_slice(&[0x03, 0x02]); // 3: protocol 2
        n += 2;
        buf[n..n + 3].copy_from_slice(&[0x04, 0x58, mlen as u8]); // 4: mac (byte string)
        n += 3;
        buf[n..n + mlen].copy_from_slice(&mac[..mlen]);
        n += mlen;
    }
    n
}

/// Read the persisted device config back through the CCID READ CONFIG TLV — the
/// FIDO write lands in the same `EF_DEV_CONF`, so the blob is the TLV's suffix.
fn dev_conf_readback(fs: &mut Fs<RamStorage>) -> std::vec::Vec<u8> {
    let mut out = [0u8; 128];
    let mut res = rsk_sdk::ResBuf::new(&mut out);
    rsk_mgmt::config_tlv(&[0u8; 4], fs, &mut res);
    res.as_slice().to_vec()
}

/// Whether the READ CONFIG TLV carries `blob` anywhere in its body. The persisted
/// blob is no longer the TLV suffix — READ CONFIG now always reports CONFIG_LOCK
/// unset after it (audit run-30) — so match a window, not the tail.
fn dev_conf_contains(fs: &mut Fs<RamStorage>, blob: &[u8]) -> bool {
    dev_conf_readback(fs).windows(blob.len()).any(|w| w == blob)
}

#[test]
fn config_write_persists_dev_conf_visible_to_ccid() {
    let (mut fs, mut rng, mut st) = setup();
    let mut req = [0u8; 96];
    let n = config_write_req(CONFIG_TARGET_DEV_CONF, DEV_CONF_BLOB, false, &mut req);
    let mut out = [0u8; 16];
    // No PIN set → pin_gate is a no-op; a touch is still required (AlwaysConfirm).
    assert_eq!(
        call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out
        ),
        Ok(0)
    );
    // The FIDO write is visible to the CCID READ CONFIG path — one shared EF.
    assert!(dev_conf_contains(&mut fs, DEV_CONF_BLOB));
}

#[cfg(feature = "strict-config")]
#[test]
fn config_write_requires_touch() {
    let (mut fs, mut rng, mut st) = setup();
    let mut req = [0u8; 96];
    let n = config_write_req(CONFIG_TARGET_DEV_CONF, DEV_CONF_BLOB, false, &mut req);
    let mut out = [0u8; 16];
    assert_eq!(
        call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut Decline,
            &req[..n],
            &mut out
        ),
        Err(CtapError::OperationDenied)
    );
    assert!(!dev_conf_contains(&mut fs, DEV_CONF_BLOB)); // declined → nothing persisted
}

#[test]
fn config_write_rejects_oversized_blob() {
    let (mut fs, mut rng, mut st) = setup();
    let big = [0u8; 200]; // > DEV_CONF_WRITE_MAX (128)
    let mut req = [0u8; 320];
    let n = config_write_req(CONFIG_TARGET_DEV_CONF, &big, false, &mut req);
    let mut out = [0u8; 16];
    assert_eq!(
        call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out
        ),
        Err(CtapError::InvalidLength)
    );
}

#[test]
fn config_write_unknown_target_rejected() {
    let (mut fs, mut rng, mut st) = setup();
    let mut req = [0u8; 96];
    let n = config_write_req(0x99, &[0x01], false, &mut req);
    let mut out = [0u8; 16];
    assert_eq!(
        call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out
        ),
        Err(CtapError::InvalidParameter)
    );
}

#[cfg(feature = "strict-config")]
#[test]
fn config_write_with_pin_requires_token() {
    let (mut fs, mut rng, mut st) = setup();
    fs.put(EF_PIN, &[8, 4, 1]).unwrap(); // PIN present → a pinUvAuthToken is required
    let mut req = [0u8; 96];
    let n = config_write_req(CONFIG_TARGET_DEV_CONF, DEV_CONF_BLOB, false, &mut req); // no token
    let mut out = [0u8; 16];
    assert_eq!(
        call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out
        ),
        Err(CtapError::PuatRequired)
    );
}

#[cfg(not(feature = "strict-config"))]
#[test]
fn config_write_default_ungated_persists_without_touch_or_token() {
    // DEFAULT (permissive) build: CONFIG_WRITE persists with NO touch and NO
    // token, even with a PIN set — full ykman/host parity. `Decline` denies the
    // touch and no pinUvAuthToken is supplied; the write must still succeed.
    let (mut fs, mut rng, mut st) = setup();
    fs.put(EF_PIN, &[8, 4, 1]).unwrap();
    let mut req = [0u8; 96];
    let n = config_write_req(CONFIG_TARGET_DEV_CONF, DEV_CONF_BLOB, false, &mut req);
    let mut out = [0u8; 16];
    assert_eq!(
        call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut Decline,
            &req[..n],
            &mut out
        ),
        Ok(0)
    );
    assert!(dev_conf_contains(&mut fs, DEV_CONF_BLOB));
}

#[test]
fn config_write_with_pin_and_token_succeeds() {
    let (mut fs, mut rng, mut st) = setup();
    fs.put(EF_PIN, &[8, 4, 1]).unwrap();
    arm_acfg(&mut st);
    let mut req = [0u8; 96];
    let n = config_write_req(CONFIG_TARGET_DEV_CONF, DEV_CONF_BLOB, true, &mut req);
    let mut out = [0u8; 16];
    assert_eq!(
        call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out
        ),
        Ok(0)
    );
    assert!(dev_conf_contains(&mut fs, DEV_CONF_BLOB));
}

#[test]
fn config_write_persists_phy_over_fido() {
    let (mut fs, mut rng, mut st) = setup();
    // A phy record setting the touch-wait timeout (tag 0x08) — the same record
    // the CCID rescue WRITE 0x1C persists.
    let phy = rsk_phy::PhyData {
        presence_timeout: Some(45),
        ..Default::default()
    };
    let mut blob = [0u8; rsk_phy::PHY_MAX_SIZE];
    let blen = phy.serialize(&mut blob).unwrap();
    let mut req = [0u8; 128];
    let n = config_write_req(CONFIG_TARGET_PHY, &blob[..blen], false, &mut req);
    let mut out = [0u8; 16];
    assert_eq!(
        call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out
        ),
        Ok(0)
    );
    // The FIDO write lands in EF_PHY; boot / the CCID rescue READ path sees it.
    assert_eq!(rsk_phy::load(&mut fs).unwrap().presence_timeout, Some(45));
}

/// Build a `VENDOR_CONFIG_READ` request `{1: subcmd, 2: {1: target}}` (ungated).
fn config_read_req(target: u64, buf: &mut [u8]) -> usize {
    let mut e = Encoder::new(Cursor::new(buf));
    e.map(2).unwrap();
    e.u8(1).unwrap().u64(VENDOR_CONFIG_READ).unwrap();
    e.u8(2)
        .unwrap()
        .map(1)
        .unwrap()
        .u8(1)
        .unwrap()
        .u64(target)
        .unwrap();
    e.writer().position()
}

#[test]
fn config_read_returns_the_phy_record_ungated() {
    let (mut fs, mut rng, mut st) = setup();
    // Seed a phy record through the write path.
    let phy = rsk_phy::PhyData {
        presence_timeout: Some(30),
        ..Default::default()
    };
    let mut blob = [0u8; rsk_phy::PHY_MAX_SIZE];
    let blen = phy.serialize(&mut blob).unwrap();
    let mut wreq = [0u8; 128];
    let wn = config_write_req(CONFIG_TARGET_PHY, &blob[..blen], false, &mut wreq);
    let mut wout = [0u8; 16];
    call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut AlwaysConfirm,
        &wreq[..wn],
        &mut wout,
    )
    .unwrap();

    // CONFIG_READ is ungated — no PIN, no touch (Decline would refuse a gate).
    let mut rreq = [0u8; 32];
    let rn = config_read_req(CONFIG_TARGET_PHY, &mut rreq);
    let mut rout = [0u8; 128];
    let r = call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut Decline,
        &rreq[..rn],
        &mut rout,
    )
    .unwrap();

    // Response {1: blob, 2: effective}; the blob parses back to the record just
    // written. Key 2 is empty here — the EFFECTIVE_PHY static is seeded only at
    // firmware boot, never in a host test.
    let mut d = Decoder::new(&rout[..r]);
    assert_eq!(d.map().unwrap(), Some(2));
    assert_eq!(d.u8().unwrap(), 1);
    let got = d.bytes().unwrap();
    assert_eq!(rsk_phy::PhyData::parse(got).presence_timeout, Some(30));
    assert_eq!(d.u8().unwrap(), 2);
    assert_eq!(d.map().unwrap(), Some(0));
}

#[test]
fn config_write_read_led_block_over_fido() {
    let (mut fs, mut rng, mut st) = setup();
    // A distinctive 17-byte block [steady, (effect, color, brightness, speed)×4].
    let mut led = [0u8; rsk_led::CONF_LEN];
    for (i, b) in led.iter_mut().enumerate() {
        *b = i as u8 + 1;
    }
    let mut wreq = [0u8; 96];
    let wn = config_write_req(CONFIG_TARGET_LED, &led, false, &mut wreq);
    let mut wout = [0u8; 16];
    call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut AlwaysConfirm,
        &wreq[..wn],
        &mut wout,
    )
    .unwrap();

    // Read the block back (ungated). Live-apply of the atomics is a firmware
    // handler concern (reload after 0x41) — exercised on-device, not here.
    let mut rreq = [0u8; 32];
    let rn = config_read_req(CONFIG_TARGET_LED, &mut rreq);
    let mut rout = [0u8; 64];
    let r = call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut Decline,
        &rreq[..rn],
        &mut rout,
    )
    .unwrap();
    let mut d = Decoder::new(&rout[..r]);
    assert_eq!(d.map().unwrap(), Some(1));
    assert_eq!(d.u8().unwrap(), 1);
    assert_eq!(d.bytes().unwrap(), &led[..]);
}

#[test]
fn config_write_led_rejects_short_block() {
    let (mut fs, mut rng, mut st) = setup();
    let short = [0u8; 4]; // < CONF_LEN (17)
    let mut req = [0u8; 64];
    let n = config_write_req(CONFIG_TARGET_LED, &short, false, &mut req);
    let mut out = [0u8; 16];
    assert_eq!(
        call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out
        ),
        Err(CtapError::InvalidLength)
    );
}

#[test]
fn audit_read_without_pin_requires_touch() {
    let (mut fs, mut rng, mut st) = setup(); // no PIN configured → pin_gate is a no-op
    let mut req = [0u8; 16];
    let n = one_byte_req(&mut req, VENDOR_AUDIT_READ);
    let mut out = [0u8; 3072];
    // A silent host on a no-PIN device must not be able to harvest the journal.
    assert_eq!(
        call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut Decline,
            &req[..n],
            &mut out
        ),
        Err(CtapError::OperationDenied)
    );
    // The user's physical touch unlocks the same read.
    assert!(
        call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out
        )
        .is_ok()
    );
}

/// Build a `VENDOR_AUDIT_CONFIG` request `{1: subcmd, 2: {1: target}}`.
fn audit_config_req(target: u64, buf: &mut [u8]) -> usize {
    let mut e = Encoder::new(Cursor::new(buf));
    e.map(2).unwrap();
    e.u8(1).unwrap().u64(VENDOR_AUDIT_CONFIG).unwrap();
    e.u8(2)
        .unwrap()
        .map(1)
        .unwrap()
        .u8(1)
        .unwrap()
        .u64(target)
        .unwrap();
    e.writer().position()
}

#[test]
fn audit_config_rejects_unknown_target() {
    let (mut fs, mut rng, mut st) = setup(); // no PIN → pin_gate is a no-op
    let mut req = [0u8; 32];
    // 0/1/2 are the only defined ops; a 3 must not silently alias to enable.
    let n = audit_config_req(3, &mut req);
    let mut out = [0u8; 32];
    assert_eq!(
        call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out
        ),
        Err(CtapError::InvalidParameter)
    );
    // The rejected op changed nothing: journalling stays OFF by default.
    assert!(!crate::journal::is_enabled(&mut fs));
}

/// The journal window and chain head, as `rsk audit verify` recomputes them from an
/// export: `(start, seq_next, head)`. An eviction moves `start`; a coalesced repeat
/// moves only the head, since it rewrites the newest entry in place.
fn journal_state(fs: &mut Fs<RamStorage>) -> (u32, u32, [u8; 32]) {
    let (head, m) = crate::journal::chain_head(&dev(), fs);
    (m.start, m.seq_next, head)
}

#[test]
fn idempotent_config_write_appends_no_journal_entry() {
    // CONFIG_WRITE is ungated on the default build and is the only journalled event
    // a silent host can drive on demand, so a replay that changes nothing must not
    // touch the journal at all — not a ring slot, not even a repeat count.
    let (mut fs, mut rng, mut st) = setup();
    fs.put(crate::consts::EF_AUDIT_ENABLED, &[1]).unwrap();
    let mut out = [0u8; 16];
    let mut req = [0u8; 96];
    let n = config_write_req(CONFIG_TARGET_DEV_CONF, DEV_CONF_BLOB, false, &mut req);

    call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut AlwaysConfirm,
        &req[..n],
        &mut out,
    )
    .unwrap();
    let before = journal_state(&mut fs);
    assert!(before.1 >= 2, "EV_BOOT + EV_CONFIG_WRITE"); // the first write is real

    for _ in 0..4 {
        assert_eq!(
            call(
                &mut fs,
                &mut rng,
                &mut st,
                &mut AlwaysConfirm,
                &req[..n],
                &mut out
            ),
            Ok(0)
        );
    }
    assert_eq!(journal_state(&mut fs), before, "a replay changes nothing");

    // A blob that really changes the record is persisted and recorded — folded into
    // the same entry (a run of config writes costs one slot), so the head moves
    // while the window stays put.
    const CHANGED: &[u8] = &[0x03, 0x02, 0x02, 0x01];
    let n = config_write_req(CONFIG_TARGET_DEV_CONF, CHANGED, false, &mut req);
    call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut AlwaysConfirm,
        &req[..n],
        &mut out,
    )
    .unwrap();
    let after = journal_state(&mut fs);
    assert!(dev_conf_contains(&mut fs, CHANGED));
    assert_eq!((after.0, after.1), (before.0, before.1), "no slot spent");
    assert_ne!(after.2, before.2, "but the write is recorded");
}

#[test]
fn config_write_flood_cannot_evict_the_audit_ring() {
    // The audit finding, verbatim: ~130 unauthenticated CONFIG_WRITEs flush the
    // 128-slot ring. Every write here really changes its record (alternating blob),
    // and the targets alternate too, so neither a byte-equality check nor a
    // same-target rule would stop it. The run must cost exactly one slot.
    let (mut fs, mut rng, mut st) = setup();
    let mut out = [0u8; 32];

    // Turn the log on through the gated vendor command: EV_BOOT + EV_AUDIT_CFG are
    // the prior evidence the flood must not push out.
    let mut req = [0u8; 128];
    let n = audit_config_req(1, &mut req);
    call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut AlwaysConfirm,
        &req[..n],
        &mut out,
    )
    .unwrap();
    assert_eq!(journal_state(&mut fs).1, 2);

    let mut led = [0u8; rsk_led::CONF_LEN];
    let mut blob = [0u8; rsk_phy::PHY_MAX_SIZE];
    for i in 0..200u8 {
        led[0] = i;
        let n = config_write_req(CONFIG_TARGET_LED, &led, false, &mut req);
        call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out,
        )
        .unwrap();

        let phy = rsk_phy::PhyData {
            presence_timeout: Some(i + 1),
            ..Default::default()
        };
        let blen = phy.serialize(&mut blob).unwrap();
        let n = config_write_req(CONFIG_TARGET_PHY, &blob[..blen], false, &mut req);
        call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out,
        )
        .unwrap();
    }

    // 400 writes, three slots: the enable and the boot that preceded them survive.
    let (start, seq_next, _) = journal_state(&mut fs);
    assert_eq!((start, seq_next), (0, 3), "the flood evicted nothing");
    let mut seen = std::vec::Vec::new();
    crate::journal::for_each_event(&dev(), &mut fs, |e| {
        seen.push(e.event);
        true
    });
    assert_eq!(
        seen,
        std::vec![
            crate::journal::EV_CONFIG_WRITE,
            crate::journal::EV_AUDIT_CFG,
            crate::journal::EV_BOOT
        ]
    );
    // The writes themselves still landed — coalescing is a journal rule, not a
    // write filter.
    let mut cur = [0u8; rsk_led::CONF_LEN];
    assert_eq!(fs.read(EF_LED_CONF, &mut cur), Some(rsk_led::CONF_LEN));
    assert_eq!(cur, led);
    assert_eq!(rsk_phy::load(&mut fs).unwrap().presence_timeout, Some(200));
}

#[test]
fn phy_config_write_repairs_an_unreadable_record() {
    // The no-op check must compare against a record that actually loaded: an absent
    // or unreadable EF_PHY reads as `None`, and a host writing the default values to
    // repair it would otherwise be answered `Ok` with nothing stored.
    let (mut fs, mut rng, mut st) = setup();
    let mut blob = [0u8; rsk_phy::PHY_MAX_SIZE];
    let blen = rsk_phy::PhyData::default().serialize(&mut blob).unwrap();
    let mut req = [0u8; 128];
    let n = config_write_req(CONFIG_TARGET_PHY, &blob[..blen], false, &mut req);
    let mut out = [0u8; 16];
    assert_eq!(
        call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out
        ),
        Ok(0)
    );
    assert!(rsk_phy::load(&mut fs).is_some(), "record written");
}

#[test]
fn idempotent_phy_and_led_config_writes_append_no_journal_entry() {
    // The same replay test for the other two targets. PHY compares the *merge*
    // result (that is what lands), so a partial record that overlays to no change
    // counts as a replay; the reboot latch is skipped with it — a re-enumeration
    // applies a changed USB identity, and it is a free host-driven reboot otherwise.
    let (mut fs, mut rng, mut st) = setup();
    fs.put(crate::consts::EF_AUDIT_ENABLED, &[1]).unwrap();
    let mut out = [0u8; 16];

    let phy = rsk_phy::PhyData {
        presence_timeout: Some(45),
        ..Default::default()
    };
    let mut blob = [0u8; rsk_phy::PHY_MAX_SIZE];
    let blen = phy.serialize(&mut blob).unwrap();
    let mut req = [0u8; 128];
    let n = config_write_req(CONFIG_TARGET_PHY, &blob[..blen], false, &mut req);
    call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut AlwaysConfirm,
        &req[..n],
        &mut out,
    )
    .unwrap();
    let before = journal_state(&mut fs);
    call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut AlwaysConfirm,
        &req[..n],
        &mut out,
    )
    .unwrap();
    assert_eq!(journal_state(&mut fs), before);
    assert_eq!(rsk_phy::load(&mut fs).unwrap().presence_timeout, Some(45));

    let mut led = [0u8; rsk_led::CONF_LEN];
    for (i, b) in led.iter_mut().enumerate() {
        *b = i as u8 + 1;
    }
    let mut req = [0u8; 96];
    let n = config_write_req(CONFIG_TARGET_LED, &led, false, &mut req);
    call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut AlwaysConfirm,
        &req[..n],
        &mut out,
    )
    .unwrap();
    let before = journal_state(&mut fs);
    call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut AlwaysConfirm,
        &req[..n],
        &mut out,
    )
    .unwrap();
    assert_eq!(journal_state(&mut fs), before);

    // A changed LED block is still written and recorded — into the entry the run
    // already owns, so the head moves and the window does not.
    led[0] ^= 0xFF;
    let n = config_write_req(CONFIG_TARGET_LED, &led, false, &mut req);
    call(
        &mut fs,
        &mut rng,
        &mut st,
        &mut AlwaysConfirm,
        &req[..n],
        &mut out,
    )
    .unwrap();
    let after = journal_state(&mut fs);
    assert_eq!((after.0, after.1), (before.0, before.1));
    assert_ne!(after.2, before.2);
    let mut cur = [0u8; rsk_led::CONF_LEN];
    assert_eq!(fs.read(EF_LED_CONF, &mut cur), Some(rsk_led::CONF_LEN));
    assert_eq!(cur, led);
}

/// A subcommand `0x41` does not implement answers INVALID_PARAMETER, mirroring
/// credentialManagement — which is what a YubiKey 5.7.4 gives for its own `0x41`.
/// Not INVALID_SUBCOMMAND: that stays the answer for an unknown `vendorCommandId`
/// under `CONFIG_VENDOR`, where the spec names it explicitly.
#[test]
fn undefined_vendor_subcommand_is_invalid_parameter() {
    let (mut fs, mut rng, mut st) = setup();
    let mut req = [0u8; 32];
    let mut out = [0u8; 64];
    for subcmd in [0x00u64, 0x0F, 0x7F] {
        let n = one_byte_req(&mut req, subcmd);
        let e = call(
            &mut fs,
            &mut rng,
            &mut st,
            &mut AlwaysConfirm,
            &req[..n],
            &mut out,
        );
        assert_eq!(
            e,
            Err(CtapError::InvalidParameter),
            "vendor subcommand {subcmd:#04x}"
        );
    }
}

/// E1's third site. The MSE channel parses a platform COSE key of its own, and it
/// carried the same right-align: a host whose bignum drops a genuine leading zero
/// sent 31 bytes and had them shifted into a *different* point. Mined so the
/// stripped byte really is a leading zero — take one off an arbitrary coordinate
/// and the point leaves the curve, so the request is refused either way and the
/// probe proves nothing.
#[test]
fn mse_coordinate_must_be_exactly_32_bytes() {
    let (mut hx, mut hy) = ([0u8; 32], [0u8; 32]);
    for i in 1u32..100_000 {
        let mut scalar = [0u8; 32];
        scalar[28..].copy_from_slice(&i.to_be_bytes());
        let (x, y) = P256Key::from_scalar(&scalar).unwrap().public_xy();
        if x[0] == 0 {
            (hx, hy) = (x, y);
            break;
        }
    }
    assert_eq!(hx[0], 0, "no scalar with a leading-zero x in range");

    let mut req = [0u8; 200];
    let mut out = [0u8; 200];

    // Control: this very key at full width opens the channel, so each refusal
    // below is the coordinate's length and not a failed key agreement.
    let (mut fs, mut rng, mut state) = setup();
    let n = build_mse_coords(&mut req, &hx, &hy);
    call(
        &mut fs,
        &mut rng,
        &mut state,
        &mut AlwaysConfirm,
        &req[..n],
        &mut out,
    )
    .unwrap();

    let padded = [&[0u8][..], &hx[..]].concat();
    for (label, x) in [("stripped to 31", &hx[1..]), ("padded to 33", &padded[..])] {
        let (mut fs, mut rng, mut state) = setup();
        let n = build_mse_coords(&mut req, x, &hy);
        assert_eq!(
            call(
                &mut fs,
                &mut rng,
                &mut state,
                &mut AlwaysConfirm,
                &req[..n],
                &mut out
            ),
            Err(CtapError::InvalidParameter),
            "x {label}"
        );
    }
}

/// The `0x41` channel's own copy of the protocol rule. No oracle exists for a
/// vendor command, so the rule is its siblings': a present-but-unsupported
/// `pinUvAuthProtocol` — `0` included — is INVALID_PARAMETER, judged before the
/// token it belongs to is found missing.
#[test]
fn an_unsupported_protocol_is_judged_before_the_missing_token() {
    for proto in [0u64, 3, 255] {
        let (mut fs, mut rng, mut st) = setup();
        fs.put(EF_PIN, &[8, 4, 1]).unwrap();
        let _ = handshake(&mut fs, &mut rng, &mut st);
        let mut req = [0u8; 32];
        let n = {
            let mut e = Encoder::new(Cursor::new(&mut req[..]));
            e.map(2)
                .unwrap()
                .u8(1)
                .unwrap()
                .u64(VENDOR_BACKUP_EXPORT)
                .unwrap()
                .u8(3)
                .unwrap()
                .u64(proto)
                .unwrap();
            e.writer().position()
        };
        let mut out = [0u8; 128];
        assert_eq!(
            call(
                &mut fs,
                &mut rng,
                &mut st,
                &mut AlwaysConfirm,
                &req[..n],
                &mut out
            ),
            Err(CtapError::InvalidParameter),
            "protocol {proto}"
        );
    }
}
