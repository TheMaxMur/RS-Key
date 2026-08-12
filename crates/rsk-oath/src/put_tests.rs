// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! E34: PUT must accept exactly the credential bodies a YubiKey 5.7.4 accepts,
//! and store nothing when it refuses. Every expectation below is a measured card
//! cell (worklog TRACK-oath §7); the `9000` rows are the controls that keep the
//! refusals honest.

use super::*;

/// A TLV of any length: the parent's `tlv` only writes the short form, and the
/// out-of-bounds cases here are exactly the ones that need `0x81`.
fn tlv_any(tag: u8, val: &[u8]) -> Vec<u8> {
    if val.len() < 128 {
        return tlv(tag, val);
    }
    let mut v = vec![tag, 0x81, val.len() as u8];
    v.extend_from_slice(val);
    v
}

/// A well-formed body, then whatever the case under test appends or replaces.
fn body(name: &[u8], ty_alg: u8, digits: u8, secret: &[u8]) -> Vec<u8> {
    let mut d = tlv_any(TAG_NAME, name);
    let mut key = vec![ty_alg, digits];
    key.extend_from_slice(secret);
    d.extend(tlv(TAG_KEY, &key));
    d
}

fn fixture() -> (Fs<RamStorage>, RefCell<CountRng>, RefCell<AlwaysConfirm>) {
    (
        new_fs(),
        RefCell::new(CountRng(7)),
        RefCell::new(AlwaysConfirm),
    )
}

/// Credential names LIST reports, so a refusal can be checked as "nothing
/// stored" rather than only as a status word.
fn stored(app: &mut OathApplet, fs: &mut Fs<RamStorage>) -> Vec<Vec<u8>> {
    let (sw, out) = run(app, fs, &apdu(INS_LIST, 0, 0, &[]));
    assert_eq!(sw, Sw::OK);
    let mut names = Vec::new();
    let mut i = 0;
    while i + 2 <= out.len() {
        let len = out[i + 1] as usize;
        names.push(out[i + 3..i + 2 + len].to_vec());
        i += 2 + len;
    }
    names
}

#[test]
fn put_takes_only_the_three_algorithm_nibbles_that_exist() {
    let (mut fs, rng, touch) = fixture();
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    for ty in [OATH_TYPE_HOTP, OATH_TYPE_TOTP] {
        for lo in 0u8..=0xF {
            let name = [b'a', ty, lo];
            let sw = put(&mut app, &mut fs, &body(&name, ty | lo, 6, SECRET_SHA1));
            let want = if (1..=3).contains(&lo) {
                Sw::OK
            } else {
                Sw::INCORRECT_PARAMS
            };
            assert_eq!(sw, want, "type {ty:#04x} algorithm nibble {lo:#x}");
        }
    }
    // Six controls stored, ten refusals stored nothing.
    assert_eq!(stored(&mut app, &mut fs).len(), 6);
}

#[test]
fn put_takes_only_the_hotp_and_totp_type_nibbles() {
    let (mut fs, rng, touch) = fixture();
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    for hi in (0u8..=0xF).map(|h| h << 4) {
        let name = [b't', hi];
        let sw = put(
            &mut app,
            &mut fs,
            &body(&name, hi | ALG_HMAC_SHA1, 6, SECRET_SHA1),
        );
        let want = if hi == OATH_TYPE_HOTP || hi == OATH_TYPE_TOTP {
            Sw::OK
        } else {
            Sw::INCORRECT_PARAMS
        };
        assert_eq!(sw, want, "type nibble {hi:#04x}");
    }
    assert_eq!(stored(&mut app, &mut fs).len(), 2);
}

#[test]
fn put_takes_only_six_seven_or_eight_digits() {
    let (mut fs, rng, touch) = fixture();
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    for d in 0u8..=255 {
        let name = [b'd', d];
        let sw = put(&mut app, &mut fs, &body(&name, 0x21, d, SECRET_SHA1));
        let want = if (6..=8).contains(&d) {
            Sw::OK
        } else {
            Sw::INCORRECT_PARAMS
        };
        assert_eq!(sw, want, "digits {d}");
    }
    assert_eq!(stored(&mut app, &mut fs).len(), 3);
}

#[test]
fn put_bounds_the_key_tlv_to_sixteen_through_sixtysix() {
    let (mut fs, rng, touch) = fixture();
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let long = [b'S'; 80];
    for klen in [0usize, 1, 2, 3, 8, 15, 16, 17, 40, 65, 66, 67, 80] {
        let mut key = vec![0x21u8, 6];
        key.extend_from_slice(&long[..klen.saturating_sub(2)]);
        key.truncate(klen);
        let name = [b'k', klen as u8];
        let mut d = tlv(TAG_NAME, &name);
        d.extend(tlv(TAG_KEY, &key));
        let sw = put(&mut app, &mut fs, &d);
        let want = if (16..=66).contains(&klen) {
            Sw::OK
        } else {
            Sw::INCORRECT_PARAMS
        };
        assert_eq!(sw, want, "KEY TLV of {klen} bytes");
    }
    // A 2-byte KEY is an EMPTY HMAC secret: every RS-Key would answer the same
    // code for the same challenge, computable offline by anyone.
    let mut d = tlv(TAG_NAME, b"empty-secret");
    d.extend(tlv(TAG_KEY, &[0x21, 6]));
    assert_eq!(put(&mut app, &mut fs, &d), Sw::INCORRECT_PARAMS);
    assert!(
        !stored(&mut app, &mut fs)
            .iter()
            .any(|n| n == b"empty-secret")
    );
}

#[test]
fn put_bounds_the_name_to_one_through_sixtyfour() {
    let (mut fs, rng, touch) = fixture();
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    for len in [0usize, 1, 2, 63, 64, 65, 66, 100, 200] {
        let name = vec![b'n'; len];
        let sw = put(&mut app, &mut fs, &body(&name, 0x21, 6, SECRET_SHA1));
        let want = if (1..=64).contains(&len) {
            Sw::OK
        } else {
            Sw::INCORRECT_PARAMS
        };
        assert_eq!(sw, want, "name of {len} bytes");
    }
    let names = stored(&mut app, &mut fs);
    assert!(
        names.iter().all(|n| (1..=64).contains(&n.len())),
        "an out-of-range name reached the store: {names:?}",
    );
}

#[test]
fn put_refuses_a_tag_it_would_not_serve_back() {
    let (mut fs, rng, touch) = fixture();
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    for (label, extra) in [
        ("unknown tag 0x99", tlv(0x99, &[0x00])),
        ("the algorithm tag 0x7B", tlv(TAG_ALGO, &[0x01])),
        ("a 200-byte junk tag", tlv_any(0x9A, &[0xAA; 200])),
        ("a 2-byte BER tag form", tlv(0x7F, &[0xAA])),
    ] {
        let mut d = body(b"junk", 0x21, 6, SECRET_SHA1);
        d.extend(extra);
        assert_eq!(put(&mut app, &mut fs, &d), Sw::INCORRECT_PARAMS, "{label}");
    }
    assert!(stored(&mut app, &mut fs).is_empty());

    // The password-safe fields are RS-Key's own extension, not a YubiKey tag,
    // and must keep working — the allow-list carries them.
    let mut d = body(b"pws", 0x21, 6, SECRET_SHA1);
    d.extend(tlv(TAG_PWS_LOGIN, b"user"));
    d.extend(tlv(TAG_PWS_PASSWORD, b"hunter2"));
    d.extend(tlv(TAG_PWS_METADATA, b"meta"));
    assert_eq!(put(&mut app, &mut fs, &d), Sw::OK);
}

#[test]
fn put_refuses_duplicates_and_key_before_name() {
    let (mut fs, rng, touch) = fixture();
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let key = {
        let mut k = vec![0x21u8, 6];
        k.extend_from_slice(SECRET_SHA1);
        k
    };
    let cases: [(&str, Vec<u8>); 7] = [
        ("KEY before NAME", {
            let mut d = tlv(TAG_KEY, &key);
            d.extend(tlv(TAG_NAME, b"o1"));
            d
        }),
        ("PROPERTY before KEY", {
            let mut d = tlv(TAG_NAME, b"o6");
            d.extend([TAG_PROPERTY, 0x02]);
            d.extend(tlv(TAG_KEY, &key));
            d
        }),
        ("IMF before PROPERTY", {
            let mut d = tlv(TAG_NAME, b"o7");
            let mut hkey = key.clone();
            hkey[0] = 0x11;
            d.extend(tlv(TAG_KEY, &hkey));
            d.extend(tlv(TAG_IMF, &[0, 0, 0, 1]));
            d.extend([TAG_PROPERTY, 0x02]);
            d
        }),
        ("two NAME TLVs", {
            let mut d = tlv(TAG_NAME, b"o2");
            d.extend(tlv(TAG_NAME, b"o2b"));
            d.extend(tlv(TAG_KEY, &key));
            d
        }),
        ("two KEY TLVs", {
            let mut d = tlv(TAG_NAME, b"o3");
            d.extend(tlv(TAG_KEY, &key));
            d.extend(tlv(TAG_KEY, &key));
            d
        }),
        ("two property bytes", {
            let mut d = tlv(TAG_NAME, b"o4");
            d.extend(tlv(TAG_KEY, &key));
            d.extend([TAG_PROPERTY, 0x01, TAG_PROPERTY, 0x02]);
            d
        }),
        ("two IMF TLVs", {
            let mut d = tlv(TAG_NAME, b"o5");
            let mut hkey = key.clone();
            hkey[0] = 0x11;
            d.extend(tlv(TAG_KEY, &hkey));
            d.extend(tlv(TAG_IMF, &[0, 0, 0, 1]));
            d.extend(tlv(TAG_IMF, &[0, 0, 0, 2]));
            d
        }),
    ];
    for (label, d) in cases {
        assert_eq!(put(&mut app, &mut fs, &d), Sw::INCORRECT_PARAMS, "{label}");
    }
    assert!(stored(&mut app, &mut fs).is_empty());
}

#[test]
fn put_refuses_trailing_junk_and_a_malformed_property() {
    let (mut fs, rng, touch) = fixture();
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    for (label, tail) in [
        ("a trailing FF", vec![0xFF]),
        (
            "a property written as a real TLV",
            vec![TAG_PROPERTY, 0x01, 0x02],
        ),
        ("a property tag with no byte after it", vec![TAG_PROPERTY]),
        ("a truncated TLV", vec![TAG_PWS_LOGIN, 0x08, 0x01]),
    ] {
        let mut d = body(b"tail", 0x21, 6, SECRET_SHA1);
        d.extend(tail);
        assert_eq!(put(&mut app, &mut fs, &d), Sw::INCORRECT_PARAMS, "{label}");
    }
    assert!(stored(&mut app, &mut fs).is_empty());
    // The bare `78 vv` pair ykman really sends is the accepted form.
    let mut d = body(b"prop", 0x21, 6, SECRET_SHA1);
    d.extend([TAG_PROPERTY, PROP_TOUCH]);
    assert_eq!(put(&mut app, &mut fs, &d), Sw::OK);
}

#[test]
fn put_takes_an_imf_only_on_hotp_and_only_four_bytes() {
    let (mut fs, rng, touch) = fixture();
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    for len in [0usize, 1, 2, 3, 4, 5, 8] {
        let mut d = body(b"h", 0x11, 6, SECRET_SHA1);
        d.extend(tlv(TAG_IMF, &vec![0x01; len]));
        let want = if len == 4 {
            Sw::OK
        } else {
            Sw::INCORRECT_PARAMS
        };
        assert_eq!(put(&mut app, &mut fs, &d), want, "HOTP, IMF of {len} bytes");
    }
    // No IMF at all is the ykman default and must stay accepted.
    assert_eq!(
        put(&mut app, &mut fs, &body(b"h", 0x11, 6, SECRET_SHA1)),
        Sw::OK
    );
    // TOTP has no moving factor to seed.
    let mut d = body(b"t", 0x21, 6, SECRET_SHA1);
    d.extend(tlv(TAG_IMF, &[0, 0, 0, 1]));
    assert_eq!(put(&mut app, &mut fs, &d), Sw::INCORRECT_PARAMS);
}

#[test]
fn a_refused_put_leaves_the_working_credential_alone() {
    // The sharpest cell in E34 (worklog §7.7a): PUT overwrites by name, so
    // accepting junk does not merely occupy a free slot — it replaces a working
    // credential with a permanently dead one, under `9000`, secret unrecoverable.
    let (mut fs, rng, touch) = fixture();
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(
        put(&mut app, &mut fs, &body(b"atom", 0x21, 8, SECRET_SHA1)),
        Sw::OK
    );
    let good = calc_code(&mut app, &mut fs, b"atom", 1, 8);
    assert_eq!(good, 94287082); // RFC 6238, T = 1

    for (label, d) in [
        ("digits 9", body(b"atom", 0x21, 9, SECRET_SHA1)),
        ("algorithm nibble F", body(b"atom", 0x2F, 8, SECRET_SHA1)),
        ("a 4-byte KEY TLV", body(b"atom", 0x21, 8, b"ab")),
        ("an unknown tag", {
            let mut d = body(b"atom", 0x21, 8, SECRET_SHA1);
            d.extend(tlv(0x99, &[0]));
            d
        }),
    ] {
        assert_eq!(put(&mut app, &mut fs, &d), Sw::INCORRECT_PARAMS, "{label}");
        assert_eq!(
            calc_code(&mut app, &mut fs, b"atom", 1, 8),
            good,
            "a refused PUT ({label}) damaged the stored credential",
        );
    }
    assert_eq!(stored(&mut app, &mut fs), vec![b"atom".to_vec()]);
}

#[test]
fn rename_bounds_the_new_name_like_put() {
    // Otherwise PUT's 1..=64 rule is one RENAME away from being bypassed.
    let (mut fs, rng, touch) = fixture();
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(
        put(&mut app, &mut fs, &body(b"src", 0x21, 6, SECRET_SHA1)),
        Sw::OK
    );
    for (label, new) in [("empty", vec![]), ("65 bytes", vec![b'x'; 65])] {
        let mut d = tlv(TAG_NAME, b"src");
        d.extend(tlv(TAG_NAME, &new));
        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_RENAME, 0, 0, &d));
        assert_eq!(sw, Sw::INCORRECT_PARAMS, "RENAME onto an {label} name");
        assert_eq!(stored(&mut app, &mut fs), vec![b"src".to_vec()]);
    }
    let mut d = tlv(TAG_NAME, b"src");
    d.extend(tlv(TAG_NAME, &[b'x'; 64]));
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_RENAME, 0, 0, &d));
    assert_eq!(sw, Sw::OK, "64 bytes is the accepted maximum");
}

#[test]
fn verify_code_reduces_by_the_stored_digit_count() {
    // `digits = 7` is a legal value the card computes a real 7-digit code for,
    // so bounding digits to {6,7,8} does not on its own fix the modulus: slot-0
    // VERIFY CODE reduced everything that was not 6 to 8 digits.
    for digits in [6u8, 7, 8] {
        let (mut fs, rng, touch) = fixture();
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        assert_eq!(
            put(&mut app, &mut fs, &body(b"h", 0x11, digits, SECRET_SHA1)),
            Sw::OK
        );
        // RFC 4226 counter 0 with the appendix-B secret, before truncation.
        let full = 1_284_755_224u32;
        for (label, width) in [("the stored width", digits), ("a wrong width", 15 - digits)] {
            let code = full % 10u32.pow(width as u32);
            let mut d = tlv(TAG_NAME, b"h");
            d.extend(tlv(TAG_RESPONSE, &code.to_be_bytes()));
            let (sw, _) = run(&mut app, &mut fs, &apdu(INS_VERIFY_CODE, 0, 0, &d));
            let want = if width == digits {
                Sw::OK
            } else {
                SW_WRONG_DATA
            };
            assert_eq!(sw, want, "digits={digits}, presented {label} ({width})");
        }
    }
}

#[test]
fn calculate_all_never_emits_a_truncated_response_tlv() {
    // PUT can no longer store an unknown algorithm, but a build before this one
    // could: such a credential made CALCULATE ALL emit a `0x76` TLV one byte long
    // where the protocol says five, under `9000`.
    let (mut fs, rng, touch) = fixture();
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let dev = Device {
        serial_hash: &[0x22; 32],
        serial_id: &SERIAL,
        otp_key: None,
    };
    let mut blob = tlv(TAG_NAME, b"legacy");
    let mut key = vec![0x2Fu8, 6];
    key.extend_from_slice(SECRET_SHA1);
    blob.extend(tlv(TAG_KEY, &key));
    assert!(seal::seal_put(
        &dev,
        &mut fs,
        &mut CountRng(3),
        KeyFid::new(EF_OATH_CRED),
        &blob
    ));

    let (sw, out) = run(
        &mut app,
        &mut fs,
        &apdu(INS_CALC_ALL, 0, 1, &tlv(TAG_CHALLENGE, &1u64.to_be_bytes())),
    );
    assert_eq!(sw, Sw::OK);
    // [71 06 "legacy"][tag len digits] — the value tag must not claim to be a
    // response it did not compute.
    let entry = &out[8..];
    assert_eq!(
        (entry[0], entry[1]),
        (TAG_NO_RESPONSE, 1),
        "CALCULATE ALL framed an uncomputable credential as a response: {entry:02X?}",
    );
}
