// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Yubico's OpenPGP attestation: ATTEST signs an X.509 statement about a key the card
//! generated with the attestation key (reference `81`), which the card minted under its
//! DEK, and DO `FC` holds that key's self-signed certificate: the root a verifier pins.

use zeroize::Zeroize;

use rsk_crypto::Device;
use rsk_ec::{Curve, MAX_EC_POINT, MAX_EC_PUBDO, PrivKey, make_ec_pubkey_do};
use rsk_fs::{Fs, KeyFid, Storage};
use rsk_sdk::apdu::CLA_PROPRIETARY;
use rsk_sdk::{Apdu, Sw, UserPresence};
use rsk_x509::{Cert, MAX_CERT, Signer, Spki};

use crate::Rng;
use crate::consts::*;
use crate::keypairgen::read_advertised_algo;
use crate::keys::{
    EcRng, ec_sw, load_ec_key, load_rsa_key, rsa_sw, spend_one_shot_pw1, store_ec_key_under,
};
use crate::origin;
use crate::pin::{Session, load_dek};

/// The attestation key's common name, and the stem of every one it signs.
const ATT_CN: &[u8] = b"RS-Key OPGP Attestation";

/// Yubico's OpenPGP attestation extensions, `1.3.6.1.4.1.41482.5.<n>`.
const fn yubico_oid(n: u8) -> [u8; 10] {
    [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x05, n]
}
const OID_CARDHOLDER: [u8; 10] = yubico_oid(1);
const OID_SOURCE: [u8; 10] = yubico_oid(2);
const OID_VERSION: [u8; 10] = yubico_oid(3);
const OID_FINGERPRINT: [u8; 10] = yubico_oid(4);
const OID_GENERATED: [u8; 10] = yubico_oid(5);
const OID_SIG_COUNTER: [u8; 10] = yubico_oid(6);
const OID_SERIAL: [u8; 10] = yubico_oid(7);
const OID_UIF: [u8; 10] = yubico_oid(8);
const OID_FORM_FACTOR: [u8; 10] = yubico_oid(9);

/// `.2`, the key's source: generated on the card, the only kind ATTEST attests.
const SOURCE_GENERATED: &[u8] = &[0x02, 0x01, 0x01];

fn x509_sw(e: rsk_x509::Error) -> Sw {
    e.sw(ec_sw, rsa_sw)
}

/// Mint the attestation key under `dek`, its public-key DO and its self-signed
/// certificate `FC`. A tear leaves the three incomplete, which [`attest`] reads as
/// unprovisioned and mints again.
pub(crate) fn provision<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    rng: &mut dyn Rng,
    dek: &[u8; DEK_SIZE],
) -> Result<(), Sw> {
    let key = PrivKey::generate(Curve::P384, &mut EcRng(rng)).ok_or(Sw::EXEC_ERROR)?;
    let mut point = [0u8; MAX_EC_POINT];
    let plen = key.public_point(&mut point).map_err(ec_sw)?;
    let point = &point[..plen];
    let mut cert = [0u8; MAX_CERT];
    let root = Cert {
        subject_cn: ATT_CN,
        issuer_cn: ATT_CN,
        spki: Spki::Ec {
            curve: Curve::P384,
            point,
        },
        sha384: true,
        ca_pathlen: Some(0),
        key_usage: true,
        extra: &[],
    };
    let n = rsk_x509::build(&root, &Signer::Ec(&key), rng, &mut cert).map_err(x509_sw)?;
    store_ec_key_under(dev, fs, dek, EF_PK_ATT, &key)?;
    let mut pub_do = [0u8; MAX_EC_PUBDO];
    let pn = make_ec_pubkey_do(point, &mut pub_do);
    fs.put(EF_PB_ATT, &pub_do[..pn])
        .map_err(|_| Sw::MEMORY_FAILURE)?;
    fs.put(EF_ATT_CERT, &cert[..n])
        .map_err(|_| Sw::MEMORY_FAILURE)
}

/// Whether the key, its public-key DO and `FC` are all present. A probe the flash
/// cannot answer refuses: minting over a key it missed would replace it.
fn provisioned<S: Storage>(fs: &mut Fs<S>) -> Result<bool, Sw> {
    let fault = |_| Sw::MEMORY_FAILURE;
    Ok(fs.try_has_key(EF_PK_ATT).map_err(fault)?
        && fs.try_has_data(EF_PB_ATT).map_err(fault)?
        && fs.try_has_data(EF_ATT_CERT).map_err(fault)?)
}

/// A fixed-width DO for the statement: zero-filled when absent, as `C5`/`CD` show it.
fn read_fixed<S: Storage, const N: usize>(fs: &mut Fs<S>, fid: u16) -> Result<[u8; N], Sw> {
    let mut v = [0u8; N];
    fs.try_read(fid, &mut v).map_err(|_| Sw::MEMORY_FAILURE)?;
    Ok(v)
}

/// ATTEST, judged in a YubiKey 5.8.0's order: PW1 (mode 81), the class (`6E00`), P2
/// and a body (`6A80`), the attestation key's touch (D9), P1 (`6A80`), and the key,
/// absent or imported (`6985`). The statement replaces the key's `7F21` occurrence.
pub fn attest<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &mut Session,
    rng: &mut dyn Rng,
    presence: &mut dyn UserPresence,
    apdu: &Apdu,
    serial: [u8; 4],
) -> Sw {
    if !sess.has_pw1 {
        return Sw::SECURITY_STATUS_NOT_SATISFIED;
    }
    if apdu.cla != CLA_PROPRIETARY {
        return Sw::CLA_NOT_SUPPORTED;
    }
    if apdu.p2 != 0 || apdu.nc != 0 {
        return Sw::WRONG_DATA;
    }
    if let Err(sw) = crate::check_uif(fs, EF_UIF_ATT, presence) {
        return sw;
    }
    // Past the touch a YubiKey spends a one-shot PW1 whatever the answer; the
    // statement itself still needs PW1 standing, to open the DEK.
    let r = write_statement(dev, fs, sess, rng, apdu.p1, serial);
    spend_one_shot_pw1(fs, sess);
    match r {
        Ok(()) => Sw::OK,
        Err(sw) => sw,
    }
}

fn write_statement<S: Storage>(
    dev: &Device,
    fs: &mut Fs<S>,
    sess: &Session,
    rng: &mut dyn Rng,
    key_ref: u8,
    serial: [u8; 4],
) -> Result<(), Sw> {
    let (pk, occurrence, label, fp, ts): (KeyFid, u16, &[u8], u16, u16) = match key_ref {
        KEY_REF_SIG => (EF_PK_SIG, 2, b" SIG", EF_FP_SIG, EF_TS_SIG),
        KEY_REF_DEC => (EF_PK_DEC, 1, b" DEC", EF_FP_DEC, EF_TS_DEC),
        KEY_REF_AUT => (EF_PK_AUT, 0, b" AUT", EF_FP_AUT, EF_TS_AUT),
        _ => return Err(Sw::WRONG_DATA),
    };
    let held = fs.try_has_key(pk).map_err(|_| Sw::MEMORY_FAILURE)?;
    if !held || origin::of(fs, pk) != origin::ORIGIN_GENERATED {
        return Err(Sw::CONDITIONS_NOT_SATISFIED);
    }
    // A card provisioned before this build has no attestation key, and only a
    // verified PIN can open the DEK it must be sealed under.
    if !provisioned(fs)? {
        let mut dek = [0u8; DEK_SIZE];
        let r = load_dek(dev, fs, sess, &mut dek).and_then(|()| provision(dev, fs, rng, &dek));
        dek.zeroize();
        r?;
    }
    let signer = load_ec_key(dev, fs, sess, EF_PK_ATT)?;

    // A name an older build let past NAME_MAX goes in cut to it, all a YubiKey holds.
    let mut name = [0u8; 2 + NAME_MAX];
    let stored = fs.try_read(EF_CH_NAME, &mut name[2..]);
    let name_len = stored
        .map_err(|_| Sw::MEMORY_FAILURE)?
        .unwrap_or(0)
        .min(NAME_MAX);
    name[..2].copy_from_slice(&[0x0C, name_len as u8]);
    let mut fp_der = [
        0x04,
        FP_LEN as u8,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    fp_der[2..].copy_from_slice(&read_fixed::<S, FP_LEN>(fs, fp)?);
    let mut ts_der = [0x04, TS_LEN as u8, 0, 0, 0, 0];
    ts_der[2..].copy_from_slice(&read_fixed::<S, TS_LEN>(fs, ts)?);
    let uif = read_fixed::<S, 1>(fs, slot_uif(pk))?;
    let counter = read_fixed::<S, 3>(fs, EF_SIG_COUNT)?;
    let (major, minor, patch) = rsk_sdk::FIRMWARE_VERSION;
    let (mut serial_der, mut counter_der) = ([0u8; 7], [0u8; 7]);
    let serial_len = rsk_x509::der_uint(&serial, &mut serial_der).map_err(x509_sw)?;
    let counter_len = rsk_x509::der_uint(&counter, &mut counter_der).map_err(x509_sw)?;
    // The order a YubiKey 5.8.0 writes them in. `.6` is the signature key's
    // alone; on the other two `.2` takes its place and the list is one shorter.
    let mut extensions: [(&[u8], &[u8]); 9] = [
        (&OID_VERSION, &[0x04, 0x03, major, minor, patch]),
        (&OID_SERIAL, &serial_der[..serial_len]),
        (&OID_UIF, &[0x04, 0x01, uif[0]]),
        (&OID_FORM_FACTOR, &[0x04, 0x01, rsk_sdk::FORM_FACTOR]),
        (&OID_CARDHOLDER, &name[..2 + name_len]),
        (&OID_FINGERPRINT, &fp_der),
        (&OID_GENERATED, &ts_der),
        (&OID_SIG_COUNTER, &counter_der[..counter_len]),
        (&OID_SOURCE, SOURCE_GENERATED),
    ];
    let count = if pk == EF_PK_SIG {
        9
    } else {
        extensions[7] = extensions[8];
        8
    };
    let extra = &extensions[..count];

    let mut subject = [0u8; ATT_CN.len() + 4];
    subject[..ATT_CN.len()].copy_from_slice(ATT_CN);
    subject[ATT_CN.len()..].copy_from_slice(label);
    let leaf = |spki| Cert {
        subject_cn: &subject,
        issuer_cn: ATT_CN,
        spki,
        sha384: true,
        ca_pathlen: None,
        key_usage: false,
        extra,
    };
    let mut algo = [0u8; 16];
    let rsa = read_advertised_algo(fs, pk, &mut algo)?[0] == ALGO_RSA;
    let mut cert = [0u8; MAX_CERT];
    let built = if rsa {
        let key = load_rsa_key(dev, fs, sess, pk)?;
        let (n, e) = (key.n_be(), key.e_be());
        rsk_x509::build(
            &leaf(Spki::Rsa { n: &n, e: &e }),
            &Signer::Ec(&signer),
            rng,
            &mut cert,
        )
    } else {
        let key = load_ec_key(dev, fs, sess, pk)?;
        let mut point = [0u8; MAX_EC_POINT];
        let plen = key.public_point(&mut point).map_err(ec_sw)?;
        let point = &point[..plen];
        let curve = key.curve();
        let spki = match curve {
            Curve::Ed25519 | Curve::X25519 => Spki::Rfc8410 { curve, point },
            _ => Spki::Ec { curve, point },
        };
        rsk_x509::build(&leaf(spki), &Signer::Ec(&signer), rng, &mut cert)
    };
    let n = built.map_err(x509_sw)?;
    fs.put(EF_CH_1 + occurrence, &cert[..n])
        .map_err(|_| Sw::MEMORY_FAILURE)
}

#[cfg(test)]
#[path = "attest_tests.rs"]
mod tests;
