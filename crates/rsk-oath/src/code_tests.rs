// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! E65: the four bytes a truncated response carries. A YubiKey 5.7.4 puts the
//! RFC 4226 dynamic truncation *reduced to the credential's digit count* on the
//! wire — measured at 6 and 8 digits, on CALCULATE and CALCULATE ALL alike
//! (worklog TRACK-oathfido §E65). Nothing here reduces host-side: a model that
//! does cannot tell the reduced code from the raw truncation, which is why the
//! existing vectors never saw this.

use super::*;

fn fixture() -> (Fs<RamStorage>, RefCell<CountRng>, RefCell<AlwaysConfirm>) {
    (
        new_fs(),
        RefCell::new(CountRng(7)),
        RefCell::new(AlwaysConfirm),
    )
}

/// The four code bytes of a CALCULATE response, verbatim.
fn calc_bytes(
    app: &mut OathApplet,
    fs: &mut Fs<RamStorage>,
    name: &[u8],
    chal: u64,
) -> (u8, [u8; 4]) {
    let mut d = tlv(TAG_NAME, name);
    d.extend(tlv(TAG_CHALLENGE, &chal.to_be_bytes()));
    let (sw, body) = run(app, fs, &apdu(INS_CALCULATE, 0, 0x01, &d));
    assert_eq!(sw, Sw::OK);
    assert_eq!(body[0], TAG_RESPONSE + 1);
    assert_eq!(body[1], 5);
    (body[2], [body[3], body[4], body[5], body[6]])
}

#[test]
fn a_truncated_code_is_the_decimal_the_rfc_publishes() {
    // RFC 4226 appendix D, counter 0 with the reference secret: the truncation
    // is 1_284_755_224 and the six-digit HOTP is 755224. The card sends the
    // second one; the difference is invisible to any host that reduces itself.
    let (mut fs, rng, touch) = fixture();
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(
        put(
            &mut app,
            &mut fs,
            &put_data(b"h", 0x11, 6, SECRET_SHA1, false, None)
        ),
        Sw::OK
    );
    let (digits, code) = calc_bytes(&mut app, &mut fs, b"h", 0);
    assert_eq!(digits, 6);
    assert_eq!(code, 755_224u32.to_be_bytes());
}

#[test]
fn the_bulk_read_truncates_the_same_way() {
    // RFC 6238 appendix B, SHA-1 at T = 1, eight digits: 94287082, whose
    // truncation is 1_094_287_082 — so eight digits is a discriminator here too.
    let (mut fs, rng, touch) = fixture();
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(
        put(
            &mut app,
            &mut fs,
            &put_data(b"t", 0x21, 8, SECRET_SHA1, false, None)
        ),
        Sw::OK
    );
    let (sw, body) = run(
        &mut app,
        &mut fs,
        &apdu(
            INS_CALC_ALL,
            0,
            0x01,
            &tlv(TAG_CHALLENGE, &1u64.to_be_bytes()),
        ),
    );
    assert_eq!(sw, Sw::OK);
    let at = 2 + body[1] as usize;
    assert_eq!(&body[at..at + 3], &[TAG_RESPONSE + 1, 5, 8]);
    assert_eq!(&body[at + 3..at + 7], &94_287_082u32.to_be_bytes());
    // And the individual read of the same credential answers the same bytes.
    assert_eq!(
        calc_bytes(&mut app, &mut fs, b"t", 1).1,
        94_287_082u32.to_be_bytes()
    );
}

#[test]
fn a_code_this_applet_computed_verifies_against_this_applet() {
    // VERIFY CODE compares `truncation % 10^digits`, so an unreduced CALCULATE
    // makes the applet refuse its own answer. Slot 0 is the one VERIFY CODE
    // reads, and CALCULATE burns the HOTP counter — the re-PUT puts the moving
    // factor back where the calculated code was taken.
    let (mut fs, rng, touch) = fixture();
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    for digits in [6u8, 7, 8] {
        let cred = put_data(b"h", 0x11, digits, SECRET_SHA1, false, None);
        assert_eq!(put(&mut app, &mut fs, &cred), Sw::OK);
        let (_, code) = calc_bytes(&mut app, &mut fs, b"h", 0);
        assert_eq!(put(&mut app, &mut fs, &cred), Sw::OK);
        let mut d = tlv(TAG_NAME, b"h");
        d.extend(tlv(TAG_RESPONSE, &code));
        let (sw, _) = run(&mut app, &mut fs, &apdu(INS_VERIFY_CODE, 0, 0, &d));
        assert_eq!(sw, Sw::OK, "digits {digits}");
    }
}

#[test]
fn a_width_from_before_put_bounded_it_still_answers() {
    // Digits outside 6..=8 have no modulus (`10^digits` overflows past 9), and
    // only a record older than PUT's bound can carry one. Such a credential
    // keeps answering with the bare truncation rather than becoming unreadable.
    let (mut fs, rng, touch) = fixture();
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let mut blob = tlv(TAG_NAME, b"old");
    let mut key = vec![0x21u8, 12];
    key.extend_from_slice(SECRET_SHA1);
    blob.extend(tlv(TAG_KEY, &key));
    fs.put(EF_OATH_CRED, &blob).unwrap();
    let dev = Device {
        serial_hash: &[0x22; 32],
        serial_id: &SERIAL,
        otp_key: None,
    };
    migrate_seal(&dev, &mut fs, &mut CountRng(1));

    let mac = hmac_sha1(SECRET_SHA1, &1u64.to_be_bytes());
    let off = (mac[19] & 0xF) as usize;
    let raw = [mac[off] & 0x7F, mac[off + 1], mac[off + 2], mac[off + 3]];
    let (digits, code) = calc_bytes(&mut app, &mut fs, b"old", 1);
    assert_eq!(digits, 12);
    assert_eq!(code, raw);
}
