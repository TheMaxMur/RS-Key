// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Yubico's OpenPGP attestation against a YubiKey 5.8.0's answers: the refusal
//! order, where each statement lands and what it says, the attestation key's own
//! DOs, and the one root (`FC`) every statement verifies under.

use core::cell::RefCell;

use p384::ecdsa::signature::hazmat::PrehashVerifier;
use rsk_fs::storage::ram::RamStorage;
use rsk_sdk::{Applet, Confirm, Presence};
use x509_parser::certificate::X509Certificate;
use x509_parser::public_key::PublicKey;

use super::*;
use crate::OpenpgpApplet;
use crate::test_tlv::children;

const SERIAL_ID: [u8; 8] = [0xAA, 0xBB, 0xCC, 0xDD, 5, 6, 7, 8];
const P256: &[u8] = &[ALGO_ECDSA, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const P256_ECDH: &[u8] = &[ALGO_ECDH, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const ATT_TEMPLATE: &[u8] = &[CRT_SIG, 0x03, CRT_KEY_REF, 0x01, KEY_REF_ATT];

/// A `dobj` attribute template without its length byte: the value PUT DATA takes.
fn attr(template: &[u8]) -> &[u8] {
    &template[1..]
}

struct Lcg(u64);
impl Rng for Lcg {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (self.0 >> 33) as u8;
        }
    }
}

/// Answers every touch request the same way.
struct Touch(Presence);
impl UserPresence for Touch {
    fn request(&mut self, _confirm: Confirm<'_>) -> Presence {
        self.0
    }
}

/// Answers every touch with `answer`, and counts how many it was asked for.
struct Counting {
    answer: core::cell::Cell<Presence>,
    asked: core::cell::Cell<u32>,
}
impl UserPresence for Counting {
    fn request(&mut self, _confirm: Confirm<'_>) -> Presence {
        self.asked.set(self.asked.get() + 1);
        self.answer.get()
    }
}

fn provisioned_fs<S: Storage>(storage: S) -> Fs<S> {
    let mut fs = Fs::new(storage);
    fs.scan();
    let dev = Device {
        serial_hash: &[0x22; 32],
        serial_id: &SERIAL_ID,
        otp_key: None,
        latched: false,
    };
    crate::init::scan_files(&dev, &mut fs, &mut Lcg(1)).unwrap();
    fs
}

/// A card after its first boot, factory PINs, touches answered with `touch`.
fn with_card_on<S: Storage>(
    fs: &mut Fs<S>,
    touch: Presence,
    f: impl FnOnce(&mut OpenpgpApplet, &mut Fs<S>),
) {
    let rng = RefCell::new(Lcg(2));
    let presence = RefCell::new(Touch(touch));
    let mut app = OpenpgpApplet::new(SERIAL_ID, [0x22; 32], None, &rng, &presence);
    f(&mut app, fs);
}

fn with_card(f: impl FnOnce(&mut OpenpgpApplet, &mut Fs<RamStorage>)) {
    with_card_on(
        &mut provisioned_fs(RamStorage::new()),
        Presence::Confirmed,
        f,
    );
}

fn run<S: Storage>(app: &mut OpenpgpApplet, fs: &mut Fs<S>, raw: &[u8]) -> (Vec<u8>, Sw) {
    let apdu = Apdu::parse(raw).unwrap();
    let mut buf = [0u8; 2048];
    let mut res = rsk_sdk::ResBuf::new(&mut buf);
    let sw = app.process(&apdu, fs, &mut res);
    (res.as_slice().to_vec(), sw)
}

fn cmd(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut a = vec![cla, ins, p1, p2];
    if !data.is_empty() {
        a.push(data.len() as u8);
        a.extend_from_slice(data);
    }
    a
}

fn verify<S: Storage>(app: &mut OpenpgpApplet, fs: &mut Fs<S>, mode: u8) {
    let pin = if mode == PW3_MODE83 {
        PW3_DEFAULT
    } else {
        PW1_DEFAULT
    };
    assert_eq!(run(app, fs, &cmd(0, INS_VERIFY, 0, mode, pin)).1, Sw::OK);
}

fn put<S: Storage>(app: &mut OpenpgpApplet, fs: &mut Fs<S>, tag: u16, data: &[u8]) -> Sw {
    run(
        app,
        fs,
        &cmd(0, INS_PUT_DATA, (tag >> 8) as u8, tag as u8, data),
    )
    .1
}

fn get<S: Storage>(app: &mut OpenpgpApplet, fs: &mut Fs<S>, tag: u16) -> (Vec<u8>, Sw) {
    let mut a = cmd(0, INS_GET_DATA, (tag >> 8) as u8, tag as u8, &[]);
    a.push(0x00);
    run(app, fs, &a)
}

fn attest<S: Storage>(app: &mut OpenpgpApplet, fs: &mut Fs<S>, key_ref: u8) -> Sw {
    run(app, fs, &[CLA_PROPRIETARY, INS_ATTEST, key_ref, 0x00]).1
}

/// The `7F21` occurrence `occ` (0 = AUT's, 2 = SIG's).
fn occurrence<S: Storage>(app: &mut OpenpgpApplet, fs: &mut Fs<S>, occ: u8) -> Vec<u8> {
    let select = [0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21];
    assert_eq!(
        run(app, fs, &cmd(0, INS_SELECT_DATA, occ, 0x04, &select)).1,
        Sw::OK
    );
    let (cert, sw) = get(app, fs, EF_CH_CERT);
    assert_eq!(sw, Sw::OK);
    cert
}

/// PUT the slot's algorithm attribute, then GENERATE: the public-key DO.
fn generate<S: Storage>(app: &mut OpenpgpApplet, fs: &mut Fs<S>, crt: u8, attr: &[u8]) -> Vec<u8> {
    let tag = match crt {
        CRT_SIG => EF_ALGO_SIG,
        CRT_DEC => EF_ALGO_DEC,
        _ => EF_ALGO_AUT,
    };
    assert_eq!(put(app, fs, tag, attr), Sw::OK);
    let (pub_do, sw) = run(app, fs, &cmd(0, INS_KEYPAIR_GEN, 0x80, 0x00, &[crt, 0x00]));
    assert_eq!(sw, Sw::OK);
    pub_do
}

/// The `86` point inside a `7F49` public-key DO.
fn point(pub_do: &[u8]) -> &[u8] {
    let mut pos = 2;
    crate::importdata::tag_len(pub_do, &mut pos).unwrap();
    assert_eq!(pub_do[pos], 0x86);
    pos += 1;
    let n = crate::importdata::tag_len(pub_do, &mut pos).unwrap();
    &pub_do[pos..pos + n]
}

fn parse(der: &[u8]) -> X509Certificate<'_> {
    let (rest, cert) = x509_parser::parse_x509_certificate(der).unwrap();
    assert!(rest.is_empty(), "trailing bytes after the certificate");
    cert
}

fn spki_key(cert: &X509Certificate) -> Vec<u8> {
    cert.tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .to_vec()
}

/// The root every statement verifies under, checked against its own signature.
fn root<S: Storage>(app: &mut OpenpgpApplet, fs: &mut Fs<S>) -> p384::ecdsa::VerifyingKey {
    let (fc, sw) = get(app, fs, EF_ATT_CERT);
    assert_eq!(sw, Sw::OK);
    let cert = parse(&fc);
    let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(&spki_key(&cert)).unwrap();
    signed_by(&cert, &vk);
    vk
}

fn signed_by(cert: &X509Certificate, vk: &p384::ecdsa::VerifyingKey) {
    assert_eq!(
        cert.signature_algorithm.algorithm.to_id_string(),
        "1.2.840.10045.4.3.3"
    );
    let sig = p384::ecdsa::Signature::from_der(&cert.signature_value.data).unwrap();
    let digest = rsk_crypto::sha384(cert.tbs_certificate.as_ref());
    vk.verify_prehash(&digest, &sig).unwrap();
}

/// Every extension, as `(OID, value, critical)`, in order.
fn extensions(cert: &X509Certificate) -> Vec<(String, Vec<u8>, bool)> {
    cert.extensions()
        .iter()
        .map(|e| (e.oid.to_id_string(), e.value.to_vec(), e.critical))
        .collect()
}

fn yubico(n: u8) -> String {
    format!("1.3.6.1.4.1.41482.5.{n}")
}

/// What a statement carries after Yubico's extensions: no keyUsage, as a YubiKey's
/// carries none. Ours put `digitalSignature` on a DEC key unless it was X25519.
const LEAF_STANDARD: [&str; 3] = ["2.5.29.19", "2.5.29.14", "2.5.29.35"];

#[test]
fn every_card_holds_an_attestation_key_and_its_root_from_the_first_boot() {
    with_card(|app, fs| {
        let (key_info, _) = get(app, fs, EF_KEY_INFO);
        assert_eq!(key_info[6..], [KEY_REF_ATT, origin::ORIGIN_GENERATED]);
        // FC reads with no PIN verified, as on a YubiKey.
        let (fc, sw) = get(app, fs, EF_ATT_CERT);
        assert_eq!(sw, Sw::OK);
        let cert = parse(&fc);
        let name = "C=ES, O=RS-Key, CN=RS-Key OPGP Attestation";
        assert_eq!(cert.subject().to_string(), name);
        assert_eq!(cert.issuer().to_string(), name);
        let bc = cert.basic_constraints().unwrap().unwrap();
        assert!(bc.value.ca && bc.value.path_len_constraint == Some(0));
        let ku = cert.key_usage().unwrap().expect("a CA keeps its keyUsage");
        assert!(ku.critical && ku.value.digital_signature() && ku.value.key_cert_sign());
        let alg = &cert.tbs_certificate.subject_pki.algorithm;
        let curve = alg.parameters.as_ref().unwrap().as_oid().unwrap();
        assert_eq!(curve.to_id_string(), "1.3.132.0.34", "P-384");
        let read = cmd(0, INS_KEYPAIR_GEN, 0x81, 0x00, ATT_TEMPLATE);
        let (pub_do, sw) = run(app, fs, &read);
        assert_eq!(sw, Sw::OK);
        assert_eq!(point(&pub_do), &spki_key(&cert)[..], "one key, two DOs");
        root(app, fs);
    });
}

/// Measured on a YubiKey 5.8.0: PW1 in mode 81 before anything else, the class
/// included; then `6E00` for class `00`; `6A80` for any P1-P2 or body; `6985` for
/// a slot with no key, or with one a host imported.
#[test]
fn attest_refuses_in_a_yubikeys_order() {
    with_card(|app, fs| {
        let at = |app: &mut _, fs: &mut _, cla, p1, p2, data: &[u8]| {
            run(app, fs, &cmd(cla, INS_ATTEST, p1, p2, data)).1
        };
        let wrong: [(u8, u8, u8, &[u8]); 6] = [
            (0x80, 0x04, 0x00, &[]),
            (0x80, 0x01, 0x01, &[]),
            (0x80, 0x00, 0x00, &[]),
            (0x80, 0x81, 0x00, &[]),
            (0x00, 0x01, 0x00, &[]),
            (0x80, 0x01, 0x00, &[0x00]),
        ];
        for (cla, p1, p2, data) in wrong {
            let sw = at(app, fs, cla, p1, p2, data);
            assert_eq!(
                sw,
                Sw::SECURITY_STATUS_NOT_SATISFIED,
                "{cla:02X} {p1:02X} {p2:02X}"
            );
        }
        verify(app, fs, PW3_MODE83);
        let sw = at(app, fs, 0x80, 0x01, 0x00, &[]);
        assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED, "PW3 alone");
        verify(app, fs, PW1_MODE82);
        let sw = at(app, fs, 0x80, 0x01, 0x00, &[]);
        assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED, "PW1 in mode 82");

        verify(app, fs, PW1_MODE81);
        assert_eq!(at(app, fs, 0x00, 0x01, 0x00, &[]), Sw::CLA_NOT_SUPPORTED);
        for (_, p1, p2, data) in wrong.into_iter().filter(|w| w.0 == 0x80) {
            assert_eq!(
                at(app, fs, 0x80, p1, p2, data),
                Sw::WRONG_DATA,
                "{p1:02X} {p2:02X}"
            );
        }
        for key_ref in [KEY_REF_SIG, KEY_REF_DEC, KEY_REF_AUT] {
            assert_eq!(attest(app, fs, key_ref), Sw::CONDITIONS_NOT_SATISFIED);
        }
        assert_eq!(put(app, fs, EF_ALGO_DEC, P256_ECDH), Sw::OK);
        let body = [
            &[
                CRT_DEC, 0x00, 0x7F, 0x48, 0x02, 0x92, 0x20, 0x5F, 0x48, 0x20,
            ][..],
            &[0x11; 32],
        ]
        .concat();
        let import = cmd(
            0,
            INS_PUT_DATA_ODD,
            0x3F,
            0xFF,
            &[&[0x4D, body.len() as u8][..], &body].concat(),
        );
        assert_eq!(run(app, fs, &import).1, Sw::OK);
        assert_eq!(
            attest(app, fs, KEY_REF_DEC),
            Sw::CONDITIONS_NOT_SATISFIED,
            "imported"
        );
        assert!(occurrence(app, fs, 1).is_empty());
    });
}

#[test]
fn a_generated_key_is_attested_as_a_yubikey_attests_it() {
    with_card(|app, fs| {
        verify(app, fs, PW3_MODE83);
        let sig = generate(app, fs, CRT_SIG, P256);
        assert_eq!(put(app, fs, EF_CH_NAME, b"Doe<<John"), Sw::OK);
        assert_eq!(put(app, fs, EF_FP_SIG, &[0xF1; FP_LEN]), Sw::OK);
        assert_eq!(put(app, fs, EF_TS_SIG, &[0x69, 0xD7, 0xE2, 0x23]), Sw::OK);
        verify(app, fs, PW1_MODE81);
        let read_att = cmd(0, INS_KEYPAIR_GEN, 0x81, 0x00, ATT_TEMPLATE);
        let (att_key, fc) = (run(app, fs, &read_att).0, get(app, fs, EF_ATT_CERT).0);
        let (body, sw) = run(app, fs, &[CLA_PROPRIETARY, INS_ATTEST, KEY_REF_SIG, 0x00]);
        assert_eq!(
            (body.len(), sw),
            (0, Sw::OK),
            "no body, the certificate goes to 7F21"
        );
        assert!(occurrence(app, fs, 0).is_empty() && occurrence(app, fs, 1).is_empty());
        assert_eq!(attest(app, fs, KEY_REF_SIG), Sw::OK, "again");
        let same = (run(app, fs, &read_att).0, get(app, fs, EF_ATT_CERT).0);
        assert_eq!(same, (att_key, fc), "the root a verifier pins stays put");

        let der = occurrence(app, fs, 2);
        let cert = parse(&der);
        let stem = "C=ES, O=RS-Key, CN=RS-Key OPGP Attestation";
        assert_eq!(cert.subject().to_string(), format!("{stem} SIG"));
        assert_eq!(cert.issuer().to_string(), stem);
        assert_eq!(spki_key(&cert), point(&sig));
        signed_by(&cert, &root(app, fs));
        let bc = cert.basic_constraints().unwrap().unwrap();
        assert!(!bc.value.ca, "a statement is no CA");

        let (major, minor, patch) = rsk_sdk::FIRMWARE_VERSION;
        let serial = rsk_sdk::serial4(SERIAL_ID);
        assert_eq!(
            serial[0] & 0x80,
            0,
            "no sign pad, as the value below assumes"
        );
        let want: [(u8, Vec<u8>); 9] = [
            (3, vec![0x04, 0x03, major, minor, patch]),
            (7, [&[0x02, 0x04][..], &serial].concat()),
            (8, vec![0x04, 0x01, 0x00]),
            (9, vec![0x04, 0x01, rsk_sdk::FORM_FACTOR]),
            (1, [&[0x0C, 0x09][..], b"Doe<<John"].concat()),
            (4, [&[0x04, 0x14][..], &[0xF1; FP_LEN]].concat()),
            (5, vec![0x04, 0x04, 0x69, 0xD7, 0xE2, 0x23]),
            (6, vec![0x02, 0x01, 0x00]),
            (2, vec![0x02, 0x01, 0x01]),
        ];
        let got = extensions(&cert);
        for (i, (n, value)) in want.iter().enumerate() {
            assert_eq!(got[i], (yubico(*n), value.clone(), false), "extension {i}");
        }
        let rest: Vec<_> = got[want.len()..].iter().map(|e| e.0.as_str()).collect();
        assert_eq!(rest, LEAF_STANDARD);
    });
}

/// DEC's statement lands in the second occurrence and AUT's in the first, neither
/// carries `.6`, and SIG's counts the signatures made so far. `.8` is the attested
/// key's own touch policy.
#[test]
fn each_statement_lands_in_its_keys_occurrence() {
    with_card(|app, fs| {
        verify(app, fs, PW3_MODE83);
        generate(app, fs, CRT_SIG, P256);
        let dec = generate(app, fs, CRT_DEC, P256_ECDH);
        let aut = generate(app, fs, CRT_AUT, P256);
        assert_eq!(put(app, fs, EF_UIF_SIG, &[0x01, 0x20]), Sw::OK);
        // Each key's own fingerprint, generation time and touch flag, told apart.
        let own = [
            (EF_FP_DEC, EF_TS_DEC, EF_UIF_DEC, 0x0D, 0x01),
            (EF_FP_AUT, EF_TS_AUT, EF_UIF_AUT, 0x0A, 0x02),
        ];
        for (fp, ts, uif, byte, flag) in own {
            assert_eq!(put(app, fs, fp, &[byte; FP_LEN]), Sw::OK);
            assert_eq!(put(app, fs, ts, &[byte; TS_LEN]), Sw::OK);
            assert_eq!(put(app, fs, uif, &[flag, 0x20]), Sw::OK);
        }
        verify(app, fs, PW1_MODE81);
        let mut cds = cmd(0, INS_PSO, 0x9E, 0x9A, &[0x42; 32]);
        cds.push(0x00);
        assert_eq!(run(app, fs, &cds).1, Sw::OK);
        verify(app, fs, PW1_MODE81);

        let statements = [(KEY_REF_DEC, 1, "DEC", &dec), (KEY_REF_AUT, 0, "AUT", &aut)];
        for ((key_ref, occ, label, pub_do), (_, _, _, byte, flag)) in
            statements.into_iter().zip(own)
        {
            assert_eq!(attest(app, fs, key_ref), Sw::OK);
            let der = occurrence(app, fs, occ);
            let cert = parse(&der);
            assert!(
                cert.subject()
                    .to_string()
                    .ends_with(&format!("Attestation {label}"))
            );
            assert_eq!(spki_key(&cert), point(pub_do));
            let got = extensions(&cert);
            let oids: Vec<_> = got.iter().map(|e| e.0.clone()).collect();
            let want: Vec<_> = [3, 7, 8, 9, 1, 4, 5, 2].into_iter().map(yubico).collect();
            assert_eq!(oids[..8], want[..], "{label}");
            assert_eq!(oids[8..], LEAF_STANDARD, "{label}");
            assert_eq!(got[2].1, [0x04, 0x01, flag], "{label} .8");
            assert_eq!(
                got[5].1,
                [&[0x04, 0x14][..], &[byte; FP_LEN]].concat(),
                "{label} .4"
            );
            assert_eq!(
                got[6].1,
                [&[0x04, 0x04][..], &[byte; TS_LEN]].concat(),
                "{label} .5"
            );
        }
        assert!(occurrence(app, fs, 2).is_empty(), "SIG not yet attested");
        assert_eq!(attest(app, fs, KEY_REF_SIG), Sw::OK);
        let der = occurrence(app, fs, 2);
        let got = extensions(&parse(&der));
        assert_eq!(
            got[2],
            (yubico(8), vec![0x04, 0x01, 0x01], false),
            "touch on"
        );
        assert_eq!(
            got[7],
            (yubico(6), vec![0x02, 0x01, 0x01], false),
            "one signature"
        );
    });
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Every key a slot holds is stated with its own public key: the curve's OID, the
/// RFC 8410 OIDs, an RSA key's modulus.
#[test]
fn every_key_a_slot_holds_is_attested_with_its_own_public_key() {
    let curves: [(&[u8], &str, &str); 8] = [
        (P256, "1.2.840.10045.2.1", "1.2.840.10045.3.1.7"),
        (
            attr(crate::dobj::ATTR_P384R1),
            "1.2.840.10045.2.1",
            "1.3.132.0.34",
        ),
        (
            attr(crate::dobj::ATTR_P521R1),
            "1.2.840.10045.2.1",
            "1.3.132.0.35",
        ),
        (
            attr(crate::dobj::ATTR_P256K1),
            "1.2.840.10045.2.1",
            "1.3.132.0.10",
        ),
        (
            attr(crate::dobj::ATTR_BP256R1),
            "1.2.840.10045.2.1",
            "1.3.36.3.3.2.8.1.1.7",
        ),
        (
            attr(crate::dobj::ATTR_BP384R1),
            "1.2.840.10045.2.1",
            "1.3.36.3.3.2.8.1.1.11",
        ),
        (attr(crate::dobj::ATTR_ED25519), "1.3.101.112", ""),
        (attr(crate::dobj::ATTR_CV25519), "1.3.101.110", ""),
    ];
    for (attr, algorithm, curve) in curves {
        with_card(|app, fs| {
            verify(app, fs, PW3_MODE83);
            let (crt, key_ref, occ) = if attr[0] == ALGO_ECDH {
                (CRT_DEC, KEY_REF_DEC, 1)
            } else {
                (CRT_SIG, KEY_REF_SIG, 2)
            };
            let pub_do = generate(app, fs, crt, attr);
            verify(app, fs, PW1_MODE81);
            assert_eq!(attest(app, fs, key_ref), Sw::OK, "{algorithm} {curve}");
            let der = occurrence(app, fs, occ);
            let cert = parse(&der);
            let alg = &cert.tbs_certificate.subject_pki.algorithm;
            assert_eq!(alg.algorithm.to_id_string(), algorithm);
            let named = alg.parameters.as_ref().and_then(|p| p.as_oid().ok());
            assert_eq!(named.map(|o| o.to_id_string()).unwrap_or_default(), curve);
            assert_eq!(spki_key(&cert), point(&pub_do), "{curve}");
            signed_by(&cert, &root(app, fs));
        });
    }

    // RSA through the path the firmware takes: its own prime search, then
    // `rsa_generate_finish`, which records the key as generated.
    with_card(|app, fs| {
        verify(app, fs, PW3_MODE83);
        let key = rsk_rsa::rsa_from_pqe(
            rsk_rsa::RSA_PUB_EXP_BE,
            &hex(rsk_rsa::vectors::P_HEX),
            &hex(rsk_rsa::vectors::Q_HEX),
        )
        .unwrap();
        let mut out = [0u8; 600];
        let (_, sw) = app.rsa_generate_finish(fs, &mut Lcg(3), EF_PK_SIG, &key, &mut out);
        assert_eq!(sw, Sw::OK);
        verify(app, fs, PW1_MODE81);
        assert_eq!(attest(app, fs, KEY_REF_SIG), Sw::OK);
        let der = occurrence(app, fs, 2);
        let cert = parse(&der);
        match cert.tbs_certificate.subject_pki.parsed().unwrap() {
            PublicKey::RSA(k) => {
                let modulus: Vec<u8> = k.modulus.iter().copied().skip_while(|&b| b == 0).collect();
                assert_eq!(modulus, hex(rsk_rsa::vectors::N_HEX));
            }
            other => panic!("not an RSA key: {other:?}"),
        }
        signed_by(&cert, &root(app, fs));
    });
}

/// A card an older build provisioned has no attestation key, and nothing but a
/// verified PIN opens the DEK to seal one under: the first ATTEST mints it. A card
/// torn between the key and FC mints it again the same way.
#[test]
fn a_card_without_its_attestation_key_mints_one_at_the_first_attest() {
    for torn in [false, true] {
        with_card(|app, fs| {
            let read = cmd(0, INS_KEYPAIR_GEN, 0x81, 0x00, ATT_TEMPLATE);
            let (before, _) = run(app, fs, &read);
            if torn {
                fs.delete(EF_ATT_CERT).unwrap();
            } else {
                fs.delete_key(EF_PK_ATT).unwrap();
                fs.delete(EF_PB_ATT).unwrap();
                fs.delete(EF_ATT_CERT).unwrap();
                assert_eq!(get(app, fs, EF_KEY_INFO).0[6..], [KEY_REF_ATT, 0x00]);
                assert_eq!(run(app, fs, &read).1, Sw::MEMORY_FAILURE);
            }
            assert_eq!(get(app, fs, EF_ATT_CERT), (vec![], Sw::OK));

            verify(app, fs, PW3_MODE83);
            generate(app, fs, CRT_SIG, P256);
            verify(app, fs, PW1_MODE81);
            assert_eq!(attest(app, fs, KEY_REF_SIG), Sw::OK, "torn: {torn}");
            let (after, sw) = run(app, fs, &read);
            assert_eq!(sw, Sw::OK);
            assert_ne!(after, before, "a new key, torn: {torn}");
            assert_eq!(get(app, fs, EF_KEY_INFO).0[6..], [KEY_REF_ATT, 0x01]);
            let der = occurrence(app, fs, 2);
            signed_by(&parse(&der), &root(app, fs));
        });
    }
}

/// A probe the flash cannot answer is not an absent key: minting there would
/// replace the key the probe missed.
#[test]
fn a_probe_the_flash_cannot_answer_mints_nothing() {
    for stuck in [EF_PK_ATT.get(), EF_PB_ATT, EF_ATT_CERT] {
        let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
        let mut fs = provisioned_fs(backend);
        with_card_on(&mut fs, Presence::Confirmed, |app, fs| {
            let read = cmd(0, INS_KEYPAIR_GEN, 0x81, 0x00, ATT_TEMPLATE);
            let (before, _) = run(app, fs, &read);
            verify(app, fs, PW3_MODE83);
            generate(app, fs, CRT_SIG, P256);
            verify(app, fs, PW1_MODE81);
            medium.stick_once(stuck);
            assert_eq!(
                attest(app, fs, KEY_REF_SIG),
                Sw::MEMORY_FAILURE,
                "{stuck:04X}"
            );
            medium.stick(None);
            assert_eq!(run(app, fs, &read), (before, Sw::OK), "{stuck:04X}");
            assert!(occurrence(app, fs, 2).is_empty());
            assert_eq!(attest(app, fs, KEY_REF_SIG), Sw::OK, "control, {stuck:04X}");
        });
    }
}

#[test]
fn terminate_mints_a_new_attestation_identity() {
    with_card(|app, fs| {
        let read = cmd(0, INS_KEYPAIR_GEN, 0x81, 0x00, ATT_TEMPLATE);
        let (key, _) = run(app, fs, &read);
        let (fc, _) = get(app, fs, EF_ATT_CERT);
        verify(app, fs, PW3_MODE83);
        assert_eq!(run(app, fs, &cmd(0, INS_TERMINATE_DF, 0, 0, &[])).1, Sw::OK);
        assert_eq!(
            run(app, fs, &cmd(0, INS_ACTIVATE_FILE, 0, 0, &[])).1,
            Sw::OK
        );
        let (new_key, sw) = run(app, fs, &read);
        assert_eq!(sw, Sw::OK);
        assert_ne!(new_key, key);
        assert_ne!(get(app, fs, EF_ATT_CERT).0, fc);
        root(app, fs);
        assert_eq!(get(app, fs, EF_KEY_INFO).0[6..], [KEY_REF_ATT, 0x01]);
    });
}

/// D9 is the attestation key's touch policy: ATTEST asks for the touch it sets,
/// a refused touch writes nothing, and the permanent value holds against PW3.
#[test]
fn attest_asks_for_the_touch_d9_sets() {
    let mut fs = provisioned_fs(RamStorage::new());
    with_card_on(&mut fs, Presence::Timeout, |app, fs| {
        assert_eq!(get(app, fs, EF_UIF_ATT), (vec![0x00, 0x20], Sw::OK));
        verify(app, fs, PW3_MODE83);
        generate(app, fs, CRT_SIG, P256);
        assert_eq!(put(app, fs, EF_UIF_ATT, &[0x01, 0x20]), Sw::OK);
        verify(app, fs, PW1_MODE81);
        assert_eq!(attest(app, fs, KEY_REF_SIG), Sw::SECURE_MESSAGE_EXEC_ERROR);
        assert!(occurrence(app, fs, 2).is_empty());
        assert_eq!(put(app, fs, EF_UIF_ATT, &[0x00, 0x20]), Sw::OK);
        assert_eq!(attest(app, fs, KEY_REF_SIG), Sw::OK, "no touch asked");
        assert_eq!(put(app, fs, EF_UIF_ATT, &[UIF_PERMANENT, 0x20]), Sw::OK);
        let sw = put(app, fs, EF_UIF_ATT, &[0x00, 0x20]);
        assert_eq!(sw, Sw::CONDITIONS_NOT_SATISFIED, "permanent");
    });
}

/// What a YubiKey 5.8.0 answered, one DO at a time: `DB`/`DC`/`DD` take PUT DATA at
/// their fixed widths and show only through C5/C6/CD, `DA` takes neither command,
/// and `FC` reads freely. A YubiKey also takes a host's `FC`; RS-Key does not.
#[test]
fn the_attestation_dos_answer_as_a_yubikey_does() {
    with_card(|app, fs| {
        assert_eq!(
            put(app, fs, EF_FP_ATT, &[0xDB; FP_LEN]),
            Sw::SECURITY_STATUS_NOT_SATISFIED
        );
        verify(app, fs, PW3_MODE83);
        for (tag, len, aggregate) in [
            (EF_FP_ATT, FP_LEN, EF_FP),
            (EF_FP_CA4, FP_LEN, EF_CA_FP),
            (EF_TS_ATT, TS_LEN, EF_TS_ALL),
        ] {
            let value = vec![tag as u8; len];
            assert_eq!(put(app, fs, tag, &value), Sw::OK, "{tag:02X}");
            assert_eq!(
                put(app, fs, tag, &value[1..]),
                Sw::WRONG_DATA,
                "{tag:02X} short"
            );
            let (app_data, sw) = get(app, fs, EF_APP_DATA);
            assert_eq!(sw, Sw::OK);
            let related = children(&children(&app_data)[0].1);
            let dd = related.into_iter().find(|c| c.0 == EF_DISCRETE_DO).unwrap();
            let all = children(&dd.1)
                .into_iter()
                .find(|c| c.0 == aggregate)
                .unwrap()
                .1;
            assert_eq!(all.len(), 4 * len);
            assert_eq!(all[3 * len..], value[..], "{tag:02X} in its aggregate");
            assert_eq!(get(app, fs, tag).1, Sw::WRONG_P1P2, "{tag:02X} read alone");
        }
        assert_eq!(get(app, fs, EF_ALGO_ATT).1, Sw::WRONG_P1P2);
        assert_eq!(
            put(app, fs, EF_ALGO_ATT, attr(crate::dobj::ATTR_P384R1)),
            Sw::WRONG_P1P2
        );
        let (fc, _) = get(app, fs, EF_ATT_CERT);
        assert_eq!(put(app, fs, EF_ATT_CERT, &fc[..200]), Sw::WRONG_P1P2);
        assert_eq!(put(app, fs, EF_ATT_CERT, &[]), Sw::WRONG_P1P2);
        assert_eq!(get(app, fs, EF_ATT_CERT).0, fc);
    });
}

/// 73 carries the attestation key where a YubiKey 5.8.0 does — `DA` after the three
/// attributes, a fourth entry in C5/C6/CD and pair in DE, `D9` last — with its 7F66
/// after DE. `FA` lists the one algorithm `DA` holds.
#[test]
fn the_application_data_places_the_attestation_key_as_a_yubikey_does() {
    with_card(|app, fs| {
        let (app_data, _) = get(app, fs, EF_APP_DATA);
        let related = &children(&app_data)[0].1;
        let inner = children(
            &children(related)
                .into_iter()
                .find(|c| c.0 == EF_DISCRETE_DO)
                .unwrap()
                .1,
        );
        let tags: Vec<u16> = inner.iter().map(|c| c.0).collect();
        assert_eq!(
            tags,
            [
                0xC0, 0xC1, 0xC2, 0xC3, 0xDA, 0xC4, 0xC5, 0xC6, 0xCD, 0xDE, 0x7F66, 0xD6, 0xD7,
                0xD8, 0xD9
            ]
        );
        let value = |tag| inner.iter().find(|c| c.0 == tag).unwrap().1.clone();
        assert_eq!(value(EF_ALGO_ATT), attr(crate::dobj::ATTR_P384R1));
        assert_eq!(value(EF_FP).len(), 80);
        assert_eq!(value(EF_CA_FP).len(), 80);
        assert_eq!(value(EF_TS_ALL).len(), 16);
        assert_eq!(value(EF_KEY_INFO)[6..], [KEY_REF_ATT, 0x01]);
        assert_eq!(value(EF_UIF_ATT), [0x00, 0x20]);

        let (info, _) = get(app, fs, EF_ALGO_INFO);
        let listed = children(&children(&info)[0].1);
        let att: Vec<_> = listed.iter().filter(|c| c.0 == EF_ALGO_ATT).collect();
        assert_eq!(att.len(), 1);
        assert_eq!(att[0].1, attr(crate::dobj::ATTR_P384R1));
        assert_eq!(listed.last().unwrap().0, EF_ALGO_ATT, "after AUT's list");
    });
}

/// PUT DATA refuses `FC` in the writer itself, not only in the dispatch that asks
/// `writable` first, as it does every tag it routes elsewhere.
#[test]
fn put_data_refuses_fc_to_a_direct_caller() {
    let mut fs = provisioned_fs(RamStorage::new());
    let mut sess = Session::new();
    sess.has_pw3 = true;
    let sw = crate::putdata::put_data(&mut fs, &sess, EF_ATT_CERT, &[0x30, 0x00]);
    assert_eq!(sw, Sw::WRONG_P1P2);
}

/// Every record the attestation adds is the applet's, so its reset and the device
/// wipe take it; D9 goes last with the other touch flags it is re-seeded beside.
#[test]
fn the_attestation_records_are_the_applets() {
    use crate::terminate::{is_openpgp_fid, is_openpgp_gate_fid};
    for fid in [
        EF_PK_ATT.get(),
        EF_PB_ATT,
        EF_ATT_CERT,
        EF_UIF_ATT,
        EF_FP_ATT,
        EF_FP_CA4,
        EF_TS_ATT,
    ] {
        assert!(is_openpgp_fid(fid), "{fid:04X}");
    }
    assert!(is_openpgp_gate_fid(EF_UIF_ATT));
    assert!(
        !is_openpgp_gate_fid(EF_PK_ATT.get()),
        "a secret, swept first"
    );
}

/// With D9 on, a YubiKey 5.8.0 judges PW1, the class, P2 and a body before the touch
/// and P1 and the key after it, and a touch that times out spends no one-shot PW1:
/// the ATTEST after it asks again, where a spent PW1 would answer `6982`.
#[test]
fn the_attestation_touch_comes_between_p2_and_p1() {
    let mut fs = provisioned_fs(RamStorage::new());
    let rng = RefCell::new(Lcg(2));
    let presence = RefCell::new(Counting {
        answer: core::cell::Cell::new(Presence::Timeout),
        asked: core::cell::Cell::new(0),
    });
    let mut app = OpenpgpApplet::new(SERIAL_ID, [0x22; 32], None, &rng, &presence);
    let (app, fs) = (&mut app, &mut fs);
    let at = |app: &mut OpenpgpApplet, fs: &mut Fs<RamStorage>, cla, p1, p2, data: &[u8]| {
        run(app, fs, &cmd(cla, INS_ATTEST, p1, p2, data)).1
    };
    let asked = || presence.borrow().asked.get();
    verify(app, fs, PW3_MODE83);
    generate(app, fs, CRT_SIG, P256);
    assert_eq!(put(app, fs, EF_UIF_ATT, &[0x01, 0x20]), Sw::OK);
    assert_eq!(put(app, fs, EF_PW_STATUS, &[0x00]), Sw::OK, "one-shot PW1");
    let locked = Sw::SECURITY_STATUS_NOT_SATISFIED;
    assert_eq!(
        (at(app, fs, 0x80, KEY_REF_SIG, 0, &[]), asked()),
        (locked, 0)
    );

    verify(app, fs, PW1_MODE81);
    for (cla, p2, data, want) in [
        (0x00, 0x00, &[][..], Sw::CLA_NOT_SUPPORTED),
        (0x80, 0x01, &[], Sw::WRONG_DATA),
        (0x80, 0x00, &[0x00], Sw::WRONG_DATA),
    ] {
        assert_eq!(at(app, fs, cla, KEY_REF_SIG, p2, data), want);
    }
    assert_eq!(asked(), 0, "no touch before P2 and the body");
    for p1 in [0x04, 0x81, KEY_REF_DEC, KEY_REF_SIG] {
        let sw = at(app, fs, 0x80, p1, 0, &[]);
        assert_eq!(sw, Sw::SECURE_MESSAGE_EXEC_ERROR, "{p1:02X}");
    }
    assert_eq!(asked(), 4, "a touch before P1 and the key, PW1 unspent");

    presence.borrow().answer.set(Presence::Confirmed);
    for (p1, want) in [
        (0x04, Sw::WRONG_DATA),
        (KEY_REF_DEC, Sw::CONDITIONS_NOT_SATISFIED),
        (KEY_REF_SIG, Sw::OK),
    ] {
        verify(app, fs, PW1_MODE81);
        assert_eq!(at(app, fs, 0x80, p1, 0, &[]), want, "{p1:02X}");
    }
    assert_eq!(asked(), 7);
}

/// Under the one-shot PW status (`C4` flag `00`) a YubiKey 5.8.0 spends PW1 on every
/// ATTEST past its touch, served or refused, and on none refused before it.
#[test]
fn attest_spends_a_one_shot_pw1_where_a_yubikey_does() {
    with_card(|app, fs| {
        verify(app, fs, PW3_MODE83);
        generate(app, fs, CRT_SIG, P256);
        generate(app, fs, CRT_AUT, P256);
        assert_eq!(put(app, fs, EF_PW_STATUS, &[0x00]), Sw::OK);
        let locked = Sw::SECURITY_STATUS_NOT_SATISFIED;
        let cases: [(&str, Vec<u8>, Sw, Sw); 8] = [
            (
                "P1 04",
                cmd(0x80, INS_ATTEST, 0x04, 0, &[]),
                Sw::WRONG_DATA,
                locked,
            ),
            (
                "P2 01",
                cmd(0x80, INS_ATTEST, 0x01, 1, &[]),
                Sw::WRONG_DATA,
                Sw::OK,
            ),
            (
                "a body",
                cmd(0x80, INS_ATTEST, 0x01, 0, &[0]),
                Sw::WRONG_DATA,
                Sw::OK,
            ),
            (
                "class 00",
                cmd(0x00, INS_ATTEST, 0x01, 0, &[]),
                Sw::CLA_NOT_SUPPORTED,
                Sw::OK,
            ),
            (
                "empty DEC",
                cmd(0x80, INS_ATTEST, KEY_REF_DEC, 0, &[]),
                Sw::CONDITIONS_NOT_SATISFIED,
                locked,
            ),
            (
                "AUT",
                cmd(0x80, INS_ATTEST, KEY_REF_AUT, 0, &[]),
                Sw::OK,
                locked,
            ),
            (
                "SIG",
                cmd(0x80, INS_ATTEST, KEY_REF_SIG, 0, &[]),
                Sw::OK,
                locked,
            ),
            (
                "GET DATA",
                cmd(0x00, INS_GET_DATA, 0x00, 0x6E, &[]),
                Sw::OK,
                Sw::OK,
            ),
        ];
        for (label, apdu, first, then) in cases {
            verify(app, fs, PW1_MODE81);
            assert_eq!(run(app, fs, &apdu).1, first, "{label}");
            assert_eq!(attest(app, fs, KEY_REF_SIG), then, "ATTEST after {label}");
        }
        // PW1 no. 82 has no one-shot rule, and neither kind of ATTEST takes it down.
        let mut auth = cmd(0, INS_INTERNAL_AUT, 0, 0, &[0x42; 32]);
        auth.push(0x00);
        verify(app, fs, PW1_MODE81);
        verify(app, fs, PW1_MODE82);
        assert_eq!(attest(app, fs, KEY_REF_SIG), Sw::OK);
        assert_eq!(
            run(app, fs, &auth).1,
            Sw::OK,
            "PW1 no. 82 after a served ATTEST"
        );
        assert_eq!(attest(app, fs, KEY_REF_SIG), locked);
        verify(app, fs, PW1_MODE81);
        assert_eq!(attest(app, fs, 0x04), Sw::WRONG_DATA);
        assert_eq!(
            run(app, fs, &auth).1,
            Sw::OK,
            "PW1 no. 82 after a refused one"
        );
    });
}

/// A name an older build stored past 39 bytes goes into `.1` cut to 39, the most a
/// YubiKey holds, rather than turning every ATTEST on that card into a refusal.
#[test]
fn an_over_long_stored_name_is_attested_cut_to_what_a_yubikey_holds() {
    with_card(|app, fs| {
        fs.put(EF_CH_NAME, &[b'N'; NAME_MAX + 6]).unwrap();
        verify(app, fs, PW3_MODE83);
        generate(app, fs, CRT_SIG, P256);
        verify(app, fs, PW1_MODE81);
        assert_eq!(attest(app, fs, KEY_REF_SIG), Sw::OK);
        let der = occurrence(app, fs, 2);
        let name = extensions(&parse(&der))
            .into_iter()
            .find(|e| e.0 == yubico(1))
            .unwrap()
            .1;
        assert_eq!(
            name,
            [&[0x0C, NAME_MAX as u8][..], &[b'N'; NAME_MAX]].concat()
        );
    });
}

/// A KDF-DO write re-wraps the DEK the attestation key is sealed under and keeps the
/// DEK itself, so the key the first boot minted still signs afterwards.
#[test]
fn a_kdf_change_keeps_the_attestation_key() {
    with_card(|app, fs| {
        let read = cmd(0, INS_KEYPAIR_GEN, 0x81, 0x00, ATT_TEMPLATE);
        let (before, _) = run(app, fs, &read);
        verify(app, fs, PW3_MODE83);
        assert_eq!(put(app, fs, EF_KDF, &[0x81, 0x01, 0x00]), Sw::OK);
        generate(app, fs, CRT_SIG, P256);
        verify(app, fs, PW1_MODE81);
        assert_eq!(attest(app, fs, KEY_REF_SIG), Sw::OK);
        assert_eq!(run(app, fs, &read), (before, Sw::OK));
        let der = occurrence(app, fs, 2);
        signed_by(&parse(&der), &root(app, fs));
    });
}

#[test]
fn certificate_errors_keep_the_signers_status_word() {
    use rsk_ec::EcError;
    for (error, expected) in [
        (rsk_x509::Error::Encoding, Sw::EXEC_ERROR),
        (rsk_x509::Error::Ec(EcError::Failed), Sw::EXEC_ERROR),
        (rsk_x509::Error::Ec(EcError::BadPoint), Sw::WRONG_DATA),
        (
            rsk_x509::Error::Ec(EcError::RejectedPoint),
            Sw::MEMORY_FAILURE,
        ),
        (
            rsk_x509::Error::Ec(EcError::Unsupported),
            Sw::FUNC_NOT_SUPPORTED,
        ),
    ] {
        assert_eq!(x509_sw(error), expected);
    }
}

#[test]
fn yubico_attestation_extensions_share_the_registered_oid_prefix() {
    let oid: fn(u8) -> [u8; 10] = core::hint::black_box(yubico_oid);
    for (suffix, expected) in [
        (1, OID_CARDHOLDER),
        (2, OID_SOURCE),
        (3, OID_VERSION),
        (4, OID_FINGERPRINT),
        (5, OID_GENERATED),
        (6, OID_SIG_COUNTER),
        (7, OID_SERIAL),
        (8, OID_UIF),
        (9, OID_FORM_FACTOR),
    ] {
        assert_eq!(oid(suffix), expected);
        assert_eq!(
            &expected[..9],
            &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xc4, 0x0a, 0x05]
        );
        assert_eq!(expected[9], suffix);
    }
}

#[test]
fn a_root_private_key_without_its_public_do_is_not_a_provisioned_root() {
    let mut fs = provisioned_fs(RamStorage::new());
    fs.put_key(EF_PK_ATT, rsk_fs::Sealed::wrap(b"retained private key"))
        .unwrap();
    fs.force_delete(EF_PB_ATT).unwrap();
    let generation = fs.write_gen();
    assert_eq!(provisioned(&mut fs), Ok(false));
    assert_eq!(fs.write_gen(), generation);
}
