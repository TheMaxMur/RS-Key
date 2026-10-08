// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use x509_parser::certificate::X509Certificate;
use x509_parser::der_parser::asn1_rs::Tag;
use x509_parser::extensions::ParsedExtension;
use x509_parser::public_key::PublicKey;

/// A deterministic byte stream for serials and keys.
struct TestRng(u64);

impl TestRng {
    fn next(&mut self) -> u8 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) as u8
    }
}

impl Rng for TestRng {
    fn fill(&mut self, buf: &mut [u8]) {
        buf.iter_mut().for_each(|b| *b = self.next());
    }
}

impl rsk_ec::Rng for TestRng {
    fn fill(&mut self, buf: &mut [u8]) {
        buf.iter_mut().for_each(|b| *b = self.next());
    }
}

fn key(curve: Curve, seed: u64) -> (PrivKey, Vec<u8>) {
    let k = PrivKey::generate(curve, &mut TestRng(seed)).unwrap();
    let mut pt = [0u8; MAX_EC_POINT];
    let n = k.public_point(&mut pt).unwrap();
    (k, pt[..n].to_vec())
}

fn issue(c: &Cert, signer: &PrivKey) -> Vec<u8> {
    let mut out = [0u8; MAX_CERT];
    let n = build(c, signer, &mut TestRng(7), &mut out).unwrap();
    out[..n].to_vec()
}

fn parse(der: &[u8]) -> X509Certificate<'_> {
    let (rest, cert) = x509_parser::parse_x509_certificate(der).unwrap();
    assert!(rest.is_empty(), "trailing bytes after the certificate");
    cert
}

fn oids(cert: &X509Certificate) -> Vec<String> {
    cert.extensions()
        .iter()
        .map(|e| e.oid.to_id_string())
        .collect()
}

/// The SPKI's algorithm OID, and the curve OID an EC key carries as its parameter.
fn spki_oids(cert: &X509Certificate) -> (String, Option<String>) {
    let alg = &cert.tbs_certificate.subject_pki.algorithm;
    let curve = alg.parameters.as_ref().and_then(|p| p.as_oid().ok());
    (
        alg.algorithm.to_id_string(),
        curve.map(|o| o.to_id_string()),
    )
}

fn ski(cert: &X509Certificate) -> Vec<u8> {
    cert.extensions()
        .iter()
        .find_map(|e| match e.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(id) => Some(id.0.to_vec()),
            _ => None,
        })
        .unwrap()
}

fn aki(cert: &X509Certificate) -> Vec<u8> {
    cert.extensions()
        .iter()
        .find_map(|e| match e.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(a) => {
                Some(a.key_identifier.clone()?.0.to_vec())
            }
            _ => None,
        })
        .unwrap()
}

/// A self-signed P-256 certificate: v3, a positive 20-byte serial, the profile's
/// names and validity, the three standard extensions of a leaf over the key's own
/// SHA-1 (no keyUsage), and an ECDSA-SHA256 signature the key verifies.
#[test]
fn a_self_signed_ec_certificate_parses_and_verifies() {
    let (k, pt) = key(Curve::P256, 1);
    let der = issue(
        &Cert {
            subject_cn: b"Test Subject",
            issuer_cn: b"Test Subject",
            spki: Spki::Ec {
                curve: Curve::P256,
                point: &pt,
            },
            sha384: false,
            ca_pathlen: None,
            extra: &[],
        },
        &k,
    );
    let cert = parse(&der);
    assert_eq!(cert.version().0, 2);
    assert_eq!(
        spki_oids(&cert),
        (
            "1.2.840.10045.2.1".into(),
            Some("1.2.840.10045.3.1.7".into())
        )
    );
    let serial = cert.raw_serial();
    assert_eq!((serial.len(), serial[0] & 0xC0), (20, 0x40));
    assert_eq!(
        cert.subject().to_string(),
        "C=ES, O=RS-Key, CN=Test Subject"
    );
    assert_eq!(cert.issuer().to_string(), "C=ES, O=RS-Key, CN=Test Subject");
    assert_eq!(
        cert.validity().not_before.to_datetime().unix_timestamp(),
        1_711_324_800
    );
    assert_eq!(
        cert.validity().not_after.to_datetime().unix_timestamp(),
        3_313_526_399
    );
    assert_eq!(oids(&cert), ["2.5.29.19", "2.5.29.14", "2.5.29.35"]);
    for e in cert.extensions() {
        match e.parsed_extension() {
            ParsedExtension::BasicConstraints(bc) => assert!(!bc.ca && !e.critical),
            ParsedExtension::SubjectKeyIdentifier(id) => assert_eq!(id.0, sha1(&pt)),
            ParsedExtension::AuthorityKeyIdentifier(aki) => {
                assert_eq!(aki.key_identifier.as_ref().unwrap().0, sha1(&pt))
            }
            other => panic!("unexpected extension {other:?}"),
        }
    }
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&pt).unwrap();
    let sig = p256::ecdsa::Signature::from_der(&cert.signature_value.data).unwrap();
    vk.verify_prehash(&sha256(cert.tbs_certificate.as_ref()), &sig)
        .unwrap();
}

/// An issued certificate carries the caller's extensions in the order given, ahead
/// of a leaf's three standard ones — the shape of an attestation statement — names
/// its subject's key in the SKI and its issuer's in the AKI, and an issuer asked
/// for SHA-384 signs over it.
#[test]
fn an_issued_certificate_carries_the_callers_extensions_in_order() {
    let (issuer, issuer_pt) = key(Curve::P384, 2);
    let (_, subject_pt) = key(Curve::P256, 3);
    let first: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x05, 0x03];
    let second: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x05, 0x07];
    let der = issue(
        &Cert {
            subject_cn: b"Attested",
            issuer_cn: b"Attester",
            spki: Spki::Ec {
                curve: Curve::P256,
                point: &subject_pt,
            },
            sha384: true,
            ca_pathlen: None,
            extra: &[
                (first, &[0x04, 0x03, 5, 8, 0]),
                (second, &[0x02, 0x01, 0x07]),
            ],
        },
        &issuer,
    );
    let cert = parse(&der);
    assert_eq!(cert.issuer().to_string(), "C=ES, O=RS-Key, CN=Attester");
    assert_eq!(
        oids(&cert),
        [
            "1.3.6.1.4.1.41482.5.3",
            "1.3.6.1.4.1.41482.5.7",
            "2.5.29.19",
            "2.5.29.14",
            "2.5.29.35"
        ]
    );
    let ext = cert.extensions();
    assert_eq!(
        (ext[0].value, ext[0].critical),
        (&[0x04, 0x03, 5, 8, 0][..], false)
    );
    assert_eq!(
        (ext[1].value, ext[1].critical),
        (&[0x02, 0x01, 0x07][..], false)
    );
    assert_eq!(ski(&cert), sha1(&subject_pt));
    assert_eq!(aki(&cert), sha1(&issuer_pt));
    assert_eq!(
        cert.signature_algorithm.algorithm.to_id_string(),
        "1.2.840.10045.4.3.3"
    );
    let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(&issuer_pt).unwrap();
    let sig = p384::ecdsa::Signature::from_der(&cert.signature_value.data).unwrap();
    vk.verify_prehash(&sha384(cert.tbs_certificate.as_ref()), &sig)
        .unwrap();
}

/// A CA certificate says so in a critical basicConstraints with its path length,
/// and only then asserts keyCertSign (RFC 5280 §4.2.1.3).
#[test]
fn a_ca_certificate_marks_itself() {
    let (k, pt) = key(Curve::P384, 4);
    let der = issue(
        &Cert {
            subject_cn: b"Root",
            issuer_cn: b"Root",
            spki: Spki::Ec {
                curve: Curve::P384,
                point: &pt,
            },
            sha384: true,
            ca_pathlen: Some(1),
            extra: &[],
        },
        &k,
    );
    let cert = parse(&der);
    assert_eq!(
        spki_oids(&cert),
        ("1.2.840.10045.2.1".into(), Some("1.3.132.0.34".into()))
    );
    let bc = cert.basic_constraints().unwrap().unwrap();
    assert!(bc.critical && bc.value.ca && bc.value.path_len_constraint == Some(1));
    let ku = cert.key_usage().unwrap().unwrap();
    assert!(ku.critical && ku.value.digital_signature() && ku.value.key_cert_sign());
}

/// An RSA subject key, as an attestation statement names one, reads back from the
/// SPKI as `{ n, e }` under NULL parameters, and its key identifier is the SHA-1
/// of those key bits.
#[test]
fn an_rsa_subject_key_reads_back_as_n_and_e() {
    let (issuer, issuer_pt) = key(Curve::P384, 5);
    let mut n = vec![0xC5u8];
    n.extend((1u8..=127).map(|b| b.wrapping_mul(37)));
    let e = [0x01, 0x00, 0x01];
    let der = issue(
        &Cert {
            subject_cn: b"RSA",
            issuer_cn: b"Attester",
            spki: Spki::Rsa { n: &n, e: &e },
            sha384: true,
            ca_pathlen: None,
            extra: &[],
        },
        &issuer,
    );
    let cert = parse(&der);
    let spki = &cert.tbs_certificate.subject_pki;
    assert_eq!(spki_oids(&cert).0, "1.2.840.113549.1.1.1");
    assert_eq!(
        spki.algorithm.parameters.as_ref().map(|p| p.tag()),
        Some(Tag::Null)
    );
    let trim = |b: &[u8]| {
        b.iter()
            .copied()
            .skip_while(|&x| x == 0)
            .collect::<Vec<_>>()
    };
    match spki.parsed().unwrap() {
        PublicKey::RSA(k) => {
            assert_eq!(trim(k.modulus), trim(&n));
            assert_eq!(trim(k.exponent), trim(&e));
        }
        other => panic!("not an RSA key: {other:?}"),
    }
    assert_eq!(ski(&cert), sha1(spki.subject_public_key.data.as_ref()));
    assert_eq!(aki(&cert), sha1(&issuer_pt));
    let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(&issuer_pt).unwrap();
    let sig = p384::ecdsa::Signature::from_der(&cert.signature_value.data).unwrap();
    vk.verify_prehash(&sha384(cert.tbs_certificate.as_ref()), &sig)
        .unwrap();
}

/// RFC 8410 keys carry the bare algorithm OID, id-X25519 or id-Ed25519, with no
/// parameters, and the raw 32-byte key as the subjectPublicKey.
#[test]
fn rfc8410_keys_carry_their_bare_oid() {
    let (issuer, _) = key(Curve::P256, 6);
    for (curve, seed, oid) in [
        (Curve::X25519, 8, "1.3.101.110"),
        (Curve::Ed25519, 11, "1.3.101.112"),
    ] {
        let (_, pt) = key(curve, seed);
        let der = issue(
            &Cert {
                subject_cn: b"RFC 8410",
                issuer_cn: b"Attester",
                spki: Spki::Rfc8410 { curve, point: &pt },
                sha384: false,
                ca_pathlen: None,
                extra: &[],
            },
            &issuer,
        );
        let cert = parse(&der);
        let spki = &cert.tbs_certificate.subject_pki;
        assert_eq!(spki_oids(&cert), (oid.into(), None), "{curve:?}");
        assert!(spki.algorithm.parameters.is_none(), "{curve:?}");
        assert_eq!(spki.subject_public_key.data.as_ref(), &pt[..], "{curve:?}");
    }
}

/// The serial is twenty bytes and positive whatever the randomness says: the top
/// bit is cleared, and the one below it set so no leading zero is trimmed away.
#[test]
fn the_serial_is_twenty_positive_bytes_whatever_the_rng_gives() {
    struct Fixed(u8);
    impl Rng for Fixed {
        fn fill(&mut self, buf: &mut [u8]) {
            buf.fill(self.0);
        }
    }
    let (k, pt) = key(Curve::P256, 10);
    for (byte, first) in [(0x00, 0x40), (0xFF, 0x7F)] {
        let mut out = [0u8; MAX_CERT];
        let c = Cert {
            subject_cn: b"S",
            issuer_cn: b"S",
            spki: Spki::Ec {
                curve: Curve::P256,
                point: &pt,
            },
            sha384: false,
            ca_pathlen: None,
            extra: &[],
        };
        let n = build(&c, &k, &mut Fixed(byte), &mut out).unwrap();
        let cert = parse(&out[..n]);
        let serial = cert.raw_serial();
        assert_eq!(
            (serial.len(), serial[0]),
            (20, first),
            "rng byte {byte:02X}"
        );
    }
}

/// Every short-Weierstrass curve an OpenPGP slot can hold names its own OID.
#[test]
fn each_curve_names_its_oid() {
    let (signer, _) = key(Curve::P256, 12);
    for (curve, oid) in [
        (Curve::P256, "1.2.840.10045.3.1.7"),
        (Curve::P384, "1.3.132.0.34"),
        (Curve::P521, "1.3.132.0.35"),
        (Curve::K256, "1.3.132.0.10"),
        (Curve::Bp256, "1.3.36.3.3.2.8.1.1.7"),
        (Curve::Bp384, "1.3.36.3.3.2.8.1.1.11"),
    ] {
        let (_, pt) = key(curve, 13);
        let der = issue(
            &Cert {
                subject_cn: b"S",
                issuer_cn: b"I",
                spki: Spki::Ec { curve, point: &pt },
                sha384: false,
                ca_pathlen: None,
                extra: &[],
            },
            &signer,
        );
        let cert = parse(&der);
        assert_eq!(
            spki_oids(&cert),
            ("1.2.840.10045.2.1".into(), Some(oid.into())),
            "{curve:?}"
        );
        assert_eq!(
            cert.tbs_certificate
                .subject_pki
                .subject_public_key
                .data
                .as_ref(),
            &pt[..]
        );
    }
}

/// What the profile cannot encode is refused, not written short: a buffer under
/// `MAX_CERT`, a curve with no OID here, and a curve RFC 8410 does not name.
#[test]
fn what_the_profile_cannot_encode_is_refused() {
    let (k, pt) = key(Curve::P256, 9);
    let cert = |curve| Cert {
        subject_cn: b"S",
        issuer_cn: b"S",
        spki: Spki::Ec { curve, point: &pt },
        sha384: false,
        ca_pathlen: None,
        extra: &[],
    };
    let mut short = [0u8; MAX_CERT - 1];
    assert_eq!(
        build(&cert(Curve::P256), &k, &mut TestRng(1), &mut short),
        Err(Error::Encoding)
    );
    let mut out = [0u8; MAX_CERT];
    assert_eq!(
        build(&cert(Curve::Ed25519), &k, &mut TestRng(1), &mut out),
        Err(Error::Encoding)
    );
    let raw = Cert {
        spki: Spki::Rfc8410 {
            curve: Curve::P256,
            point: &pt,
        },
        ..cert(Curve::P256)
    };
    assert_eq!(
        build(&raw, &k, &mut TestRng(1), &mut out),
        Err(Error::Encoding)
    );
}

/// An INTEGER is minimal and sign-safe: leading zeros go, one zero stays, and a top
/// bit set gets a pad; a buffer too short for it is refused.
#[test]
fn der_uint_is_minimal_and_sign_safe() {
    let mut out = [0u8; 8];
    for (value, want) in [
        (&[][..], &[0x02, 0x01, 0x00][..]),
        (&[0x00, 0x00, 0x00], &[0x02, 0x01, 0x00]),
        (&[0x00, 0x00, 0x01], &[0x02, 0x01, 0x01]),
        (&[0x00, 0x00, 0x80], &[0x02, 0x02, 0x00, 0x80]),
        (
            &[0x02, 0xBB, 0xCC, 0xDD],
            &[0x02, 0x04, 0x02, 0xBB, 0xCC, 0xDD],
        ),
        (
            &[0x80, 0x00, 0x00, 0x01],
            &[0x02, 0x05, 0x00, 0x80, 0x00, 0x00, 0x01],
        ),
    ] {
        let n = der_uint(value, &mut out).unwrap();
        assert_eq!(&out[..n], want, "{value:02X?}");
    }
    assert_eq!(der_uint(&[0x80], &mut [0u8; 3]), Err(Error::Encoding));
}

/// Each refusal reaches the caller's own status word, the encoder's included.
#[test]
fn a_refusal_maps_to_the_callers_status_word() {
    let ec = |_| Sw::new(0x6E, 0xC0);
    assert_eq!(Error::Encoding.sw(ec), Sw::EXEC_ERROR);
    assert_eq!(Error::Ec(EcError::Failed).sw(ec), Sw::new(0x6E, 0xC0));
}

/// `r ‖ s` becomes two minimal, sign-safe INTEGERs; an odd length is refused.
#[test]
fn ecdsa_der_is_minimal_and_sign_safe() {
    let mut raw = [0u8; 64];
    raw[0] = 0x80;
    raw[33] = 0x01;
    let mut out = [0u8; 80];
    let n = ecdsa_der(&raw, &mut out).unwrap();
    let mut want = vec![0x30, 0x44, 0x02, 0x21, 0x00, 0x80];
    want.extend_from_slice(&[0; 31]);
    want.extend_from_slice(&[0x02, 0x1F, 0x01]);
    want.extend_from_slice(&[0; 30]);
    assert_eq!(&out[..n], &want[..]);
    assert_eq!(ecdsa_der(&[1, 2, 3], &mut out), Err(Error::Encoding));
    let before = out;
    assert_eq!(ecdsa_der(&[], &mut out), Err(Error::Encoding));
    assert_eq!(out, before);
}
