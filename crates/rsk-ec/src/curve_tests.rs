// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

const ALL: [Curve; 8] = [
    Curve::P256,
    Curve::P384,
    Curve::P521,
    Curve::K256,
    Curve::Bp256,
    Curve::Bp384,
    Curve::Ed25519,
    Curve::X25519,
];

#[test]
fn curve_id_tags_are_frozen() {
    // These bytes are `kdata[0]` of every sealed EC key blob already on a
    // provisioned device — both applets'. Written out one by one rather than
    // round-tripped, so a renumbering cannot pass by being self-consistent: it
    // would leave every existing key unloadable (`from_id` gives the wrong
    // curve, and `PrivKey::from_scalar` then the wrong scalar width).
    assert_eq!(Curve::P256.id(), 3);
    assert_eq!(Curve::P384.id(), 4);
    assert_eq!(Curve::P521.id(), 5);
    assert_eq!(Curve::Bp256.id(), 6);
    assert_eq!(Curve::Bp384.id(), 7);
    assert_eq!(Curve::K256.id(), 12);
    assert_eq!(Curve::Ed25519.id(), 30);
    assert_eq!(Curve::X25519.id(), 31);
}

#[test]
fn curve_id_round_trips_and_rejects_unknown_tags() {
    for c in ALL {
        assert_eq!(Curve::from_id(c.id()), Some(c), "{c:?} must survive a seal");
    }
    // Nothing outside the table decodes — an unknown tag must refuse, not alias
    // onto a neighbouring curve.
    let known: [u8; 8] = ALL.map(Curve::id);
    for b in 0..=u8::MAX {
        if !known.contains(&b) {
            assert_eq!(Curve::from_id(b), None, "tag {b} must not decode");
        }
    }
}
