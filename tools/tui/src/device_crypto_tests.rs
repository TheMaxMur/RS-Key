// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn bytes<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2);
    core::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
}

fn peer() -> ([u8; 32], [u8; 32]) {
    (
        bytes("5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c"),
        bytes("8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032"),
    )
}

#[test]
fn ecdh_matches_an_openssl_vector_and_refuses_invalid_peers() {
    // Public fixture scalars 2 and 3; expected shared x computed by OpenSSL.
    let scalar = bytes::<32>("0000000000000000000000000000000000000000000000000000000000000002");
    let sk = SecretKey::from_slice(&scalar).unwrap();
    let (x, y) = peer();
    let expected = bytes::<32>("b01a172a76a4602c92d3242cb897dde3024c740debb215b4c6b0aae93c2291a9");
    assert_eq!(ecdh_raw(&sk, &x, &y), Some(expected));
    for (bad_x, bad_y) in [([0; 32], [0; 32]), ([0xff; 32], y), (x, [0xff; 32])] {
        assert_eq!(ecdh_raw(&sk, &bad_x, &bad_y), None);
    }
    assert_eq!(ecdh_raw(&sk, &x, &y), Some(expected));
}

#[test]
fn generated_keys_publish_their_coordinates_and_agree() {
    let (a, ax, ay) = ecdh_pub();
    let (b, bx, by) = ecdh_pub();
    assert_ne!((ax, ay), (bx, by));
    for (key, x, y) in [(&a, ax, ay), (&b, bx, by)] {
        let point = Sec1Point::from_affine_coordinates((&x).into(), (&y).into(), false);
        let public = Option::<PublicKey>::from(PublicKey::from_sec1_point(&point)).unwrap();
        assert_eq!(public, key.public_key());
    }
    let shared = ecdh_raw(&a, &bx, &by).unwrap();
    assert_eq!(ecdh_raw(&b, &ax, &ay), Some(shared));
}

#[test]
fn verifies_an_openssl_signature_and_refuses_changed_messages() {
    let (x, y) = peer();
    let point = Sec1Point::from_affine_coordinates((&x).into(), (&y).into(), false);
    let public = VerifyingKey::from_sec1_bytes(point.as_bytes()).unwrap();
    let signature = bytes::<71>(
        "304502204cc489d9683a20056fede8f8d5505ec03721f6f0404ac66858edbc257cecbf0c022100e17784dacc2e2ebad747c19ef7c6809a46479050c6ad8631f6a6527f003b71e4",
    );
    let signature = Signature::from_der(&signature).unwrap();
    let message = b"RS-Key TUI crypto migration";
    public.verify(message, &signature).unwrap();
    let mut changed = *message;
    changed[0] ^= 1;
    assert!(public.verify(&changed, &signature).is_err());
}

struct Candidates {
    used: usize,
}

impl p256::elliptic_curve::rand_core::TryRng for Candidates {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for byte in dst {
            *byte = match self.used / 32 {
                0 => 0,
                1 => 0xff,
                2 => 1,
                _ => panic!("valid candidate was rejected"),
            };
            self.used += 1;
        }
        Ok(())
    }
}

impl p256::elliptic_curve::rand_core::TryCryptoRng for Candidates {}

#[test]
fn ecdh_generation_retries_zero_and_out_of_range_candidates() {
    let mut rng = Candidates { used: 0 };
    let key = generate_ecdh_key(&mut rng);
    assert_eq!(key.to_bytes().as_slice(), &[1; 32]);
    assert_eq!(rng.used, 96);
}
