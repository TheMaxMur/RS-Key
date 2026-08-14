// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! E32: the YKOATH `only increasing` property (bit 0) — a per-credential
//! high-water mark on the challenge. Every expectation is a measured YubiKey
//! 5.7.4 cell (worklog TRACK-oath §6), including the two the card decides in a
//! way no spec text does: the whole-command abort in CALCULATE ALL, and the
//! bytewise right-zero-extended comparison.

use super::*;

/// PUT a TOTP credential carrying `prop` as the bare `78 vv` pair ykman sends.
fn put_prop(app: &mut OathApplet, fs: &mut Fs<RamStorage>, name: &[u8], prop: Option<u8>) -> Sw {
    let mut d = tlv(TAG_NAME, name);
    let mut key = vec![0x21u8, 6];
    key.extend_from_slice(SECRET_SHA1);
    d.extend(tlv(TAG_KEY, &key));
    if let Some(p) = prop {
        d.extend([TAG_PROPERTY, p]);
    }
    put(app, fs, &d)
}

/// CALCULATE at an arbitrary-width challenge; `None` when it is refused.
fn calc_at(
    app: &mut OathApplet,
    fs: &mut Fs<RamStorage>,
    name: &[u8],
    chal: &[u8],
    p2: u8,
) -> Option<u32> {
    let mut d = tlv(TAG_NAME, name);
    d.extend(tlv(TAG_CHALLENGE, chal));
    let (sw, body) = run(app, fs, &apdu(INS_CALCULATE, 0, p2, &d));
    if sw != Sw::OK {
        assert_eq!(sw, Sw::WRONG_DATA, "a refusal must read as 6A80");
        return None;
    }
    Some(u32::from_be_bytes([body[3], body[4], body[5], body[6]]) % 10u32.pow(body[2] as u32))
}

fn calc(app: &mut OathApplet, fs: &mut Fs<RamStorage>, name: &[u8], chal: u64) -> Option<u32> {
    calc_at(app, fs, name, &chal.to_be_bytes(), 0x01)
}

fn fixture() -> (Fs<RamStorage>, RefCell<CountRng>) {
    (new_fs(), RefCell::new(CountRng(7)))
}

#[test]
fn only_increasing_refuses_a_challenge_at_or_below_the_mark() {
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(put_prop(&mut app, &mut fs, b"inc", Some(0x01)), Sw::OK);
    assert_eq!(put_prop(&mut app, &mut fs, b"plain", None), Sw::OK);

    // The card's deciding sequence, control in the same loop: row 6 is a NEW
    // high and still computes, so this is a live comparison and not a latch.
    for (chal, refused) in [
        (100u64, false),
        (101, false),
        (50, true),
        (101, true), // exactly the mark — strictly greater, so refused
        (1, true),
        (200, false),
        (199, true),
        (200, true),
    ] {
        let got = calc(&mut app, &mut fs, b"inc", chal);
        assert_eq!(got.is_none(), refused, "inc at challenge {chal}");
        assert!(
            calc(&mut app, &mut fs, b"plain", chal).is_some(),
            "the control must compute at every challenge ({chal})",
        );
    }
}

#[test]
fn a_fresh_only_increasing_credential_starts_at_zero() {
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(put_prop(&mut app, &mut fs, b"f", Some(0x01)), Sw::OK);
    assert!(calc(&mut app, &mut fs, b"f", 0).is_none(), "challenge 0");
    assert!(calc(&mut app, &mut fs, b"f", 1).is_some(), "challenge 1");
    assert!(
        calc(&mut app, &mut fs, b"f", 1).is_none(),
        "challenge 1 again"
    );
    assert!(calc(&mut app, &mut fs, b"f", 2).is_some(), "challenge 2");
}

#[test]
fn the_mark_is_per_credential() {
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(put_prop(&mut app, &mut fs, b"a", Some(0x01)), Sw::OK);
    assert_eq!(put_prop(&mut app, &mut fs, b"b", Some(0x01)), Sw::OK);
    assert!(calc(&mut app, &mut fs, b"a", 1000).is_some());
    // b is untouched by a's mark, and then keeps its own.
    assert!(calc(&mut app, &mut fs, b"b", 500).is_some());
    assert!(calc(&mut app, &mut fs, b"b", 400).is_none());
    assert!(calc(&mut app, &mut fs, b"a", 600).is_none());
}

#[test]
fn a_refused_calculate_does_not_move_the_mark() {
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(put_prop(&mut app, &mut fs, b"m", Some(0x01)), Sw::OK);
    assert!(calc(&mut app, &mut fs, b"m", 100).is_some());
    assert!(calc(&mut app, &mut fs, b"m", 50).is_none());
    assert!(calc(&mut app, &mut fs, b"m", 60).is_none());
    // Still exactly 100: 100 is refused and 101 is served.
    assert!(calc(&mut app, &mut fs, b"m", 100).is_none());
    assert!(calc(&mut app, &mut fs, b"m", 101).is_some());
}

#[test]
fn the_mark_persists_follows_a_rename_and_is_cleared_by_a_reput() {
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(put_prop(&mut app, &mut fs, b"m1", Some(0x01)), Sw::OK);
    assert!(calc(&mut app, &mut fs, b"m1", 900).is_some());

    // A new session must not forget it: the mark is on flash, not in RAM.
    Applet::deselect(&mut app, &mut fs);
    select(&mut app, &mut fs);
    assert!(calc(&mut app, &mut fs, b"m1", 800).is_none());

    let mut d = tlv(TAG_NAME, b"m1");
    d.extend(tlv(TAG_NAME, b"m2"));
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_RENAME, 0, 0, &d)).0,
        Sw::OK
    );
    assert!(
        calc(&mut app, &mut fs, b"m2", 800).is_none(),
        "after RENAME"
    );

    // A re-PUT is a new credential under that name, so the mark goes with it.
    assert_eq!(put_prop(&mut app, &mut fs, b"m2", Some(0x01)), Sw::OK);
    assert!(
        calc(&mut app, &mut fs, b"m2", 800).is_some(),
        "after re-PUT"
    );
}

#[test]
fn the_comparison_is_bytewise_right_zero_extended() {
    // Ten mixed-width rows measured on the card (worklog §6.5). One rule fits
    // all of them: zero-extend both sides on the right, compare unsigned,
    // require strictly greater — which is plain numeric `>` at TOTP's 8 bytes.
    let cases: [(&[u8], &[u8], bool); 8] = [
        (&[0, 0, 0, 0, 0, 0, 0x03, 0xE8], &[0, 0, 0x03, 0xE8], true),
        (&[0, 0, 0x03, 0xE8], &[0, 0, 0x03, 0xE8, 0, 0, 0, 0], false),
        (&[0, 0, 0x03, 0xE8, 0, 0, 0, 0], &[0, 0, 0x03, 0xE8], false),
        (&[0x01], &[0, 0, 0, 0, 0, 0, 0, 0x02], false),
        (&[0x01], &[0x02], true),
        (&[0x01], &[0xFF; 32], true),
        (&[0xFF; 32], &[0xFF; 8], false),
        (
            &[0xFF; 8],
            &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01],
            true,
        ),
    ];
    for (mark, chal, computes) in cases {
        let (mut fs, rng) = fixture();
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        assert_eq!(put_prop(&mut app, &mut fs, b"c", Some(0x01)), Sw::OK);
        assert!(
            calc_at(&mut app, &mut fs, b"c", mark, 0x01).is_some(),
            "setting the mark {mark:02X?}",
        );
        assert_eq!(
            calc_at(&mut app, &mut fs, b"c", chal, 0x01).is_some(),
            computes,
            "mark {mark:02X?} then challenge {chal:02X?}",
        );
    }
}

#[test]
fn a_challenge_wider_than_the_card_accepts_is_refused() {
    // The card takes 0..=64 bytes on both read paths and answers 6A80 from 65.
    // The mark is exactly that wide, so an only-increasing credential lands on
    // the card's own answer rather than recording a challenge it cannot hold.
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(put_prop(&mut app, &mut fs, b"w", Some(0x01)), Sw::OK);
    assert!(calc_at(&mut app, &mut fs, b"w", &[0xFF; 64], 0x01).is_some());
    let mut d = tlv(TAG_NAME, b"w");
    d.extend(tlv(TAG_CHALLENGE, &[0x01; 65]));
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_CALCULATE, 0, 0x01, &d));
    assert_eq!(sw, Sw::WRONG_DATA, "65-byte challenge");
}

#[test]
fn the_property_is_inert_for_hotp_and_above_bit_one() {
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    // HOTP ignores the challenge, so there is nothing to run backwards; the
    // card computes normally and keeps no mark.
    let mut d = tlv(TAG_NAME, b"h");
    let mut key = vec![0x11u8, 6];
    key.extend_from_slice(SECRET_SHA1);
    d.extend(tlv(TAG_KEY, &key));
    d.extend([TAG_PROPERTY, 0x01]);
    assert_eq!(put(&mut app, &mut fs, &d), Sw::OK);
    assert_eq!(calc(&mut app, &mut fs, b"h", 5), Some(755224));
    assert_eq!(calc(&mut app, &mut fs, b"h", 5), Some(287082));

    // Bits 2..7 are ignored, as on the card: `78 FC` computes forever.
    assert_eq!(put_prop(&mut app, &mut fs, b"hi", Some(0xFC)), Sw::OK);
    assert!(calc(&mut app, &mut fs, b"hi", 100).is_some());
    assert!(calc(&mut app, &mut fs, b"hi", 50).is_some());
}

#[test]
fn the_full_response_read_path_enforces_it_too() {
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(put_prop(&mut app, &mut fs, b"p0", Some(0x01)), Sw::OK);
    let mut d = tlv(TAG_NAME, b"p0");
    d.extend(tlv(TAG_CHALLENGE, &500u64.to_be_bytes()));
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_CALCULATE, 0, 0, &d)).0,
        Sw::OK
    );
    let mut d = tlv(TAG_NAME, b"p0");
    d.extend(tlv(TAG_CHALLENGE, &400u64.to_be_bytes()));
    let (sw, _) = run(&mut app, &mut fs, &apdu(INS_CALCULATE, 0, 0, &d));
    assert_eq!(sw, Sw::WRONG_DATA);
}

#[test]
fn calculate_all_fails_whole_and_leaves_the_prefix_advanced() {
    // Measured twice on the card, plus a reversed-order control: the walk
    // commits each mark as it goes and aborts the ENTIRE response at the first
    // offender in store order — plain credentials collateral, body empty.
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    for name in [&b"aa"[..], b"bb", b"cc"] {
        assert_eq!(put_prop(&mut app, &mut fs, name, Some(0x01)), Sw::OK);
    }
    assert_eq!(put_prop(&mut app, &mut fs, b"zz", None), Sw::OK);
    assert!(calc(&mut app, &mut fs, b"aa", 1000).is_some());
    assert!(calc(&mut app, &mut fs, b"bb", 2000).is_some());
    assert!(calc(&mut app, &mut fs, b"cc", 1000).is_some());

    let chal = tlv(TAG_CHALLENGE, &1500u64.to_be_bytes());
    let (sw, body) = run(&mut app, &mut fs, &apdu(INS_CALC_ALL, 0, 0x01, &chal));
    assert_eq!(sw, Sw::WRONG_DATA, "bb is at 2000, above the challenge");
    assert!(body.is_empty(), "the whole command fails, body {body:02X?}");

    // aa comes before bb in store order, so its mark already moved to 1500.
    assert!(
        calc(&mut app, &mut fs, b"aa", 1200).is_none(),
        "aa advanced"
    );
    // cc sits after the offender and was never reached.
    assert!(
        calc(&mut app, &mut fs, b"cc", 1200).is_some(),
        "cc untouched"
    );

    // Above every mark: all of them compute, and every mark advances.
    let chal = tlv(TAG_CHALLENGE, &3000u64.to_be_bytes());
    let (sw, body) = run(&mut app, &mut fs, &apdu(INS_CALC_ALL, 0, 0x01, &chal));
    assert_eq!(sw, Sw::OK);
    assert_eq!(count_tag(&body, TAG_NAME), 4);
    for name in [&b"aa"[..], b"bb", b"cc"] {
        assert!(
            calc(&mut app, &mut fs, name, 2900).is_none(),
            "{name:?} at 3000"
        );
    }
    // A plain credential is never marked by the bulk read.
    assert!(calc(&mut app, &mut fs, b"zz", 1).is_some());
}

/// Seal `blob` into a credential slot the way a build before this one left it —
/// the only way to get a body PUT now refuses.
fn plant(fs: &mut Fs<RamStorage>, slot: u16, blob: &[u8]) {
    let dev = Device {
        serial_hash: &[0x22; 32],
        serial_id: &SERIAL,
        otp_key: None,
    };
    assert!(seal::seal_put(
        &dev,
        fs,
        &mut CountRng(3),
        KeyFid::new(EF_OATH_CRED + slot),
        blob
    ));
}

#[test]
fn a_record_with_no_room_for_a_mark_does_not_fail_the_whole_bulk_read() {
    // An older build kept unrecognised tags verbatim, so a stored body can be
    // near CRED_MAX or already carry a `D0` of another width. Neither can hold
    // this credential's mark — but one such record must not take CALCULATE ALL
    // down for every other account on the key, with an empty body and no way to
    // tell which one is at fault.
    let key = {
        let mut k = vec![0x21u8, 6];
        k.extend_from_slice(SECRET_SHA1);
        k
    };
    for (label, tail) in [
        ("no room for a mark", {
            // 1 tag + 1 length byte + 64 must not fit what is left of CRED_MAX.
            let mut v = Vec::new();
            for _ in 0..4 {
                v.extend([0x99, 0x81, 200]);
                v.extend([0xAA; 200]);
            }
            v.extend([0x99, 0x81, 118]);
            v.extend([0xAA; 118]);
            v
        }),
        ("a planted mark of another width", {
            let mut v = vec![TAG_LAST_CHAL, 8];
            v.extend([0xFF; 8]);
            v
        }),
    ] {
        let (mut fs, rng) = fixture();
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        let mut blob = tlv(TAG_NAME, b"old");
        blob.extend(tlv(TAG_KEY, &key));
        blob.extend(tlv(TAG_PROPERTY, &[0x01]));
        blob.extend(tail);
        plant(&mut fs, 0, &blob);
        assert_eq!(put_prop(&mut app, &mut fs, b"live", None), Sw::OK);

        let chal = tlv(TAG_CHALLENGE, &1500u64.to_be_bytes());
        let (sw, body) = run(&mut app, &mut fs, &apdu(INS_CALC_ALL, 0, 0x01, &chal));
        assert_eq!(sw, Sw::OK, "{label}: one old record failed the bulk read");
        assert_eq!(count_tag(&body, TAG_NAME), 2, "{label}");
        // It gets no code on this path either — enforcing it is impossible, so
        // serving it would be the one place the property does not hold.
        assert_eq!(count_tag(&body, TAG_NO_RESPONSE), 1, "{label}: {body:02X?}");
        assert_eq!(count_tag(&body, TAG_RESPONSE + 1), 1, "{label}");
        // And its own CALCULATE still fails closed.
        assert!(calc(&mut app, &mut fs, b"old", 1500).is_none(), "{label}");
        assert!(calc(&mut app, &mut fs, b"live", 1500).is_some(), "{label}");
    }
}

#[test]
fn mark_has_room_matches_raise_mark() {
    // Two owners of one question: the bulk read's skip and `raise_mark`'s own
    // `emit_tlv` arithmetic. Whenever the predicate says a mark fits, the write
    // must succeed — and when it says it does not, the write must fail.
    for used in [0usize, 100, 900, 957, 958, 959, 1000, CRED_MAX] {
        let mut blob = [0u8; CRED_MAX];
        let mut n = used;
        assert_eq!(
            mark_has_room(&blob[..used]),
            raise_mark(&mut blob, &mut n, &[1u8; 8]),
            "a blob of {used} bytes",
        );
    }
}

#[test]
fn calculate_all_does_not_mark_a_credential_it_does_not_compute() {
    // A touch-gated credential is only advertised (tag 7C), not computed — so
    // its mark must not move, or the CALCULATE the host sends next at that same
    // challenge would refuse the press it just asked for.
    let (mut fs, rng) = fixture();
    let touch = RefCell::new(StubPresence(Presence::Confirmed, 0));
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(
        put_prop(&mut app, &mut fs, b"t", Some(PROP_TOUCH | 0x01)),
        Sw::OK
    );
    let chal = tlv(TAG_CHALLENGE, &1500u64.to_be_bytes());
    let (sw, body) = run(&mut app, &mut fs, &apdu(INS_CALC_ALL, 0, 0x01, &chal));
    assert_eq!(sw, Sw::OK);
    assert_eq!(count_tag(&body, TAG_TOUCH_RESPONSE), 1);
    assert!(
        calc(&mut app, &mut fs, b"t", 1500).is_some(),
        "the bulk read consumed a challenge it never computed",
    );
}

/// PUT the touch+only-increasing credential the two tests below share. It lives
/// in `fs`, not in an applet, so a later [`calc_touched`] finds the mark the
/// earlier one left — a re-PUT would rebuild the blob and drop it.
fn put_touched(fs: &mut Fs<RamStorage>, rng: &RefCell<CountRng>) {
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, rng, &touch);
    assert_eq!(
        put_prop(&mut app, fs, b"ti", Some(PROP_TOUCH | PROP_INCREASING)),
        Sw::OK
    );
}

/// CALCULATE on that credential with `outcome` as the press. Its own applet
/// each time: `StubPresence` cannot change its mind, and the press outcome is
/// what these rows vary.
fn calc_touched(
    fs: &mut Fs<RamStorage>,
    rng: &RefCell<CountRng>,
    outcome: Presence,
    chals: &[u64],
) -> Vec<Sw> {
    let touch = RefCell::new(StubPresence(outcome, 0));
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, rng, &touch);
    chals
        .iter()
        .map(|c| {
            let mut d = tlv(TAG_NAME, b"ti");
            d.extend(tlv(TAG_CHALLENGE, &c.to_be_bytes()));
            run(&mut app, fs, &apdu(INS_CALCULATE, 0, 0x01, &d)).0
        })
        .collect()
}

#[test]
fn the_touch_gate_runs_before_the_mark() {
    // Measured on the card by *not* pressing (worklog ORACLE-oathfido): a
    // touch+increasing credential blocks for the full button wait and answers
    // `6982` — and a later, LOWER challenge blocks again instead of answering
    // `6A80` instantly, which is how the card says the un-pressed call left the
    // mark exactly where it was. The control in the same run: an increasing-only
    // credential answers `6A80` in 0.00 s at that same lower challenge.
    let (mut fs, rng) = fixture();
    put_touched(&mut fs, &rng);
    assert_eq!(
        calc_touched(&mut fs, &rng, Presence::Declined, &[0x50, 0x40]),
        [
            Sw::SECURITY_STATUS_NOT_SATISFIED,
            Sw::SECURITY_STATUS_NOT_SATISFIED
        ],
        "a refused press must not be reported as a backwards challenge",
    );
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(put_prop(&mut app, &mut fs, b"inc", Some(0x01)), Sw::OK);
    assert!(calc(&mut app, &mut fs, b"inc", 0x50).is_some());
    assert!(
        calc(&mut app, &mut fs, b"inc", 0x40).is_none(),
        "the control must fire, or the rows above prove nothing",
    );
    // Neither refused press moved the credential's mark: a *confirmed* press at
    // the lower challenge still computes, on the same stored credential.
    assert_eq!(
        calc_touched(&mut fs, &rng, Presence::Confirmed, &[0x40])[0],
        Sw::OK,
    );
}

#[test]
fn a_confirmed_press_advances_the_mark() {
    // The other half, which no session without a finger can read off the card:
    // everything measured there is consistent with a successful press behaving
    // like any other successful CALCULATE, and that is what this side does.
    let (mut fs, rng) = fixture();
    put_touched(&mut fs, &rng);
    assert_eq!(
        calc_touched(&mut fs, &rng, Presence::Confirmed, &[0x50, 0x40, 0x60]),
        [Sw::OK, Sw::WRONG_DATA, Sw::OK],
    );
}
