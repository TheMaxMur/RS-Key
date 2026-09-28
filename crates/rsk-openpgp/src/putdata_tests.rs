// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::Rng;
use crate::init::scan_files;
use crate::pin::verify;
use rsk_crypto::Device;
use rsk_fs::storage::ram::RamStorage;

struct CountRng(u8);
impl Rng for CountRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

fn dev() -> Device<'static> {
    Device {
        serial_hash: &[0x44; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
        latched: false,
    }
}

fn setup() -> (Fs<RamStorage>, Session) {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    (fs, Session::new())
}

fn admin<S: Storage>(fs: &mut Fs<S>, sess: &mut Session) {
    assert_eq!(
        verify(
            &dev(),
            fs,
            sess,
            &mut CountRng(0),
            0x00,
            PW3_MODE83,
            PW3_DEFAULT
        ),
        Sw::OK
    );
}

#[test]
fn write_login_requires_pw3() {
    let (mut fs, mut sess) = setup();
    // Without admin auth → denied.
    assert_eq!(
        put_data(&mut fs, &sess, EF_LOGIN_DATA, b"alice"),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    admin(&mut fs, &mut sess);
    assert_eq!(put_data(&mut fs, &sess, EF_LOGIN_DATA, b"alice"), Sw::OK);
    let mut buf = [0u8; 16];
    let n = fs.read(EF_LOGIN_DATA, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"alice");
}

#[test]
fn empty_data_deletes() {
    let (mut fs, mut sess) = setup();
    admin(&mut fs, &mut sess);
    put_data(&mut fs, &sess, EF_CH_NAME, b"Doe<<John");
    assert!(fs.has_data(EF_CH_NAME));
    assert_eq!(put_data(&mut fs, &sess, EF_CH_NAME, &[]), Sw::OK);
    assert!(!fs.has_data(EF_CH_NAME));
}

#[test]
fn algo_attr_redirects_to_priv_storage() {
    let (mut fs, mut sess) = setup();
    admin(&mut fs, &mut sess);
    // PUT C1 writes EF_ALGO_PRIV1 (0x1000 | 0x00C1).
    let attr = [0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]; // P-256 ECDSA
    assert_eq!(put_data(&mut fs, &sess, EF_ALGO_SIG, &attr), Sw::OK);
    assert!(fs.has_data(EF_ALGO_PRIV1));
    assert!(!fs.has_data(EF_ALGO_SIG));
}

#[test]
fn changing_algo_attr_invalidates_the_key_pair() {
    let (mut fs, mut sess) = setup();
    admin(&mut fs, &mut sess);
    let p256 = [0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    let ed25519 = [0x16, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
    assert_eq!(put_data(&mut fs, &sess, EF_ALGO_SIG, &p256), Sw::OK);
    fs.put(EF_PK_SIG.get(), &[0xAA; 16]).unwrap();
    fs.put(EF_PB_SIG, &[0xBB; 16]).unwrap();

    assert_eq!(put_data(&mut fs, &sess, EF_ALGO_SIG, &p256), Sw::OK);
    assert!(fs.has_data(EF_PK_SIG.get()));
    assert!(fs.has_data(EF_PB_SIG));

    assert_eq!(put_data(&mut fs, &sess, EF_ALGO_SIG, &ed25519), Sw::OK);
    assert!(!fs.has_data(EF_PK_SIG.get()));
    assert!(!fs.has_data(EF_PB_SIG));
}

/// What a YubiKey 5.8.0 does with an RSA attribute: any exponent length from 17
/// bits (65537's) is taken and stored as 17; 16 bits, a sixth byte other than the
/// standard import format, or a value that is not six bytes long is `6A80`.
#[test]
fn rsa_attributes_take_any_exponent_length_from_17_bits_and_store_17() {
    let (mut fs, mut sess) = setup();
    admin(&mut fs, &mut sess);
    for e_bits in [[0x00, 0x11], [0x00, 0x18], [0x00, 0x20], [0x01, 0x00]] {
        let attr = [ALGO_RSA, 0x0C, 0x00, e_bits[0], e_bits[1], 0x00];
        assert_eq!(
            put_data(&mut fs, &sess, EF_ALGO_SIG, &attr),
            Sw::OK,
            "{attr:02x?}"
        );
        let mut stored = [0u8; 8];
        let n = fs.read(EF_ALGO_PRIV1, &mut stored).unwrap();
        assert_eq!(&stored[..n], &[ALGO_RSA, 0x0C, 0x00, 0x00, 0x11, 0x00]);
    }
    for attr in [
        &[ALGO_RSA, 0x08, 0x00, 0x00, 0x10, 0x00][..],
        &[ALGO_RSA, 0x08, 0x00, 0x00, 0x11, 0x01],
        &[ALGO_RSA, 0x08, 0x00, 0x00, 0x11, 0x03],
        &[ALGO_RSA, 0x08, 0x00, 0x00, 0x11],
        &[ALGO_RSA, 0x08, 0x00, 0x00, 0x11, 0x00, 0x00],
    ] {
        assert_eq!(
            put_data(&mut fs, &sess, EF_ALGO_SIG, attr),
            Sw::WRONG_DATA,
            "{attr:02x?}"
        );
    }
}

/// The key stays when only the exponent length differs — the stored value does not
/// change — and goes when the size does, as on a YubiKey 5.8.0. An attribute an
/// older build stored as sent (e length 32) counts as the same one.
#[test]
fn another_exponent_length_keeps_the_key_and_another_size_retires_it() {
    let (mut fs, mut sess) = setup();
    admin(&mut fs, &mut sess);
    fs.put(EF_ALGO_PRIV1, &[ALGO_RSA, 0x08, 0x00, 0x00, 0x20, 0x00])
        .unwrap();
    fs.put(EF_PK_SIG.get(), &[0xAA; 16]).unwrap();
    fs.put(EF_PB_SIG, &[0xBB; 16]).unwrap();

    for e_bits in [0x11, 0x20] {
        let attr = [ALGO_RSA, 0x08, 0x00, 0x00, e_bits, 0x00];
        assert_eq!(put_data(&mut fs, &sess, EF_ALGO_SIG, &attr), Sw::OK);
        assert!(
            fs.has_data(EF_PK_SIG.get()),
            "e length {e_bits:#04x} retired the key"
        );
        assert!(fs.has_data(EF_PB_SIG));
    }
    let rsa3k = [ALGO_RSA, 0x0C, 0x00, 0x00, 0x11, 0x00];
    assert_eq!(put_data(&mut fs, &sess, EF_ALGO_SIG, &rsa3k), Sw::OK);
    assert!(!fs.has_data(EF_PK_SIG.get()));
    assert!(!fs.has_data(EF_PB_SIG));
}

/// Only C1/C2/C3 are attributes: a six-byte value that happens to read as RSA is
/// stored as sent anywhere else.
#[test]
fn a_value_shaped_like_an_rsa_attribute_is_stored_as_sent_elsewhere() {
    let (mut fs, mut sess) = setup();
    admin(&mut fs, &mut sess);
    let value = [ALGO_RSA, 0x08, 0x00, 0x00, 0x20, 0x00];
    assert_eq!(put_data(&mut fs, &sess, EF_LOGIN_DATA, &value), Sw::OK);
    let mut stored = [0u8; 8];
    let n = fs.read(EF_LOGIN_DATA, &mut stored).unwrap();
    assert_eq!(&stored[..n], &value);
}

#[test]
fn priv_do_1_accepts_pw2() {
    let (mut fs, mut sess) = setup();
    // PW2 (PW1 in mode 82) authorizes private DO 1.
    assert_eq!(
        verify(
            &dev(),
            &mut fs,
            &mut sess,
            &mut CountRng(0),
            0x00,
            PW1_MODE82,
            PW1_DEFAULT
        ),
        Sw::OK
    );
    assert_eq!(put_data(&mut fs, &sess, EF_PRIV_DO_1, b"secret"), Sw::OK);
    // ...but a normal DO still needs PW3.
    assert_eq!(
        put_data(&mut fs, &sess, EF_LOGIN_DATA, b"x"),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
}

#[test]
fn put_pw_status_updates_flag_in_place() {
    let (mut fs, mut sess) = setup();
    // Without admin auth → denied.
    assert_eq!(
        put_pw_status(&mut fs, &sess, &[0x00]),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    admin(&mut fs, &mut sess);
    // Clear the "PW1 valid for multiple signatures" flag; retry counters survive.
    assert_eq!(put_pw_status(&mut fs, &sess, &[0x00]), Sw::OK);
    let mut pw = [0u8; 7];
    let n = fs.read(EF_PW_PRIV, &mut pw).unwrap();
    assert_eq!(n, 7);
    assert_eq!(pw[0], 0x00);
    // RC (index 5) ships deactivated at 0; PW1/PW3 counters at 3.
    assert_eq!(&pw[4..7], &[3, 0, 3], "retry counters preserved");
}

#[test]
fn put_pw_status_writes_only_the_flag() {
    // §4.4.2: the max-length bytes "should not be changed", and the three retry
    // counters after them are read-only outright — zeroing those would block
    // every PIN across a power cycle, recoverable only by a key-destroying
    // TERMINATE DF. A YubiKey 5.7.4 enforces both by taking a ONE-byte write of
    // 00 or 01 and nothing else. The DO must be unchanged after each refusal:
    // an announced maximum the card does not enforce is a lie about itself.
    let (mut fs, mut sess) = setup();
    admin(&mut fs, &mut sess);
    let start = [
        0x01,
        PIN_MAX_LEN as u8,
        PIN_MAX_LEN as u8,
        PIN_MAX_LEN as u8,
        3,
        0,
        3,
    ];
    let mut pw = [0u8; 7];
    assert_eq!(fs.read(EF_PW_PRIV, &mut pw), Some(7));
    assert_eq!(pw, start);

    for bad in [
        &[][..],
        &[0x02],
        &[0x07],
        &[0xFF],
        &[0x01, 0x06],
        &[0x01, 0x06, 0x06, 0x06],
        &[0x01, 0x06, 0x06, 0x06, 0x03, 0x00, 0x03],
        &[0x01, 0x7F, 0x7F, 0x7F, 0, 0, 0],
    ] {
        assert_eq!(
            put_pw_status(&mut fs, &sess, bad),
            Sw::WRONG_DATA,
            "{bad:02X?}"
        );
        assert_eq!(fs.read(EF_PW_PRIV, &mut pw), Some(7));
        assert_eq!(pw, start, "a refused PUT C4 changed the DO: {bad:02X?}");
    }

    // The one accepted form moves the flag and nothing else.
    assert_eq!(put_pw_status(&mut fs, &sess, &[0x00]), Sw::OK);
    assert_eq!(fs.read(EF_PW_PRIV, &mut pw), Some(7));
    assert_eq!(
        pw,
        [
            0x00,
            PIN_MAX_LEN as u8,
            PIN_MAX_LEN as u8,
            PIN_MAX_LEN as u8,
            3,
            0,
            3
        ]
    );
}

#[test]
fn generic_put_data_does_not_handle_specials() {
    // The reset code / PW status are routed away from the generic DO write.
    let (mut fs, mut sess) = setup();
    admin(&mut fs, &mut sess);
    assert_eq!(
        put_data(&mut fs, &sess, EF_RESET_CODE, b"x"),
        Sw::CONDITIONS_NOT_SATISFIED
    );
    assert_eq!(
        put_data(&mut fs, &sess, EF_PW_STATUS, &[0x00]),
        Sw::CONDITIONS_NOT_SATISFIED
    );
}

#[test]
fn an_unwritable_tag_is_a_wrong_p1p2() {
    // The tag IS P1P2 for this command, so a tag PUT DATA cannot write is a wrong
    // parameter and not a missing object — measured on a YubiKey 5.7.4, which
    // answers `6B00` to an unknown tag and to the computed aggregates alike, **with
    // PW3 verified**. Before that the card says only `6982`, which is why this test
    // authenticates first and why the ordering is asserted separately (E81).
    let (mut fs, mut sess) = setup();
    admin(&mut fs, &mut sess);
    assert_eq!(put_data(&mut fs, &sess, 0x4242, b"x"), Sw::WRONG_P1P2);
    for tag in [EF_FP, EF_CA_FP, EF_TS_ALL] {
        assert_eq!(put_data(&mut fs, &sess, tag, b"x"), Sw::WRONG_P1P2);
    }
}

#[test]
fn an_overlong_pw_status_record_cannot_panic_put_pw_status() {
    // Same clamp as `pin::check_pin`: `Fs::read` reports the stored length, so an
    // EF_PW_PRIV longer than the array would panic the `&pw[..n]` write-back.
    let (mut fs, mut sess) = setup();
    admin(&mut fs, &mut sess);
    let mut overlong = crate::files::PW_STATUS_DEFAULT.to_vec();
    overlong.resize(16, 0xAA);
    fs.put(EF_PW_PRIV, &overlong).unwrap();

    assert_eq!(put_pw_status(&mut fs, &sess, &[0x00]), Sw::OK);
    let mut pw = [0u8; 7];
    assert_eq!(fs.read(EF_PW_PRIV, &mut pw), Some(7));
    assert_eq!(&pw[4..7], &[3, 0, 3], "retry counters preserved");
}

#[test]
fn put_aes_key_is_pw3_gated_on_a_direct_call() {
    // The dispatcher gates every PUT DATA before it routes here, so this arm's own
    // `has_pw3` is dominated on the wire and nothing exercised it — the sibling
    // handlers all have a direct-call test and this one did not. It is a `pub`
    // function; its precondition is its own.
    let (mut fs, mut sess) = setup();
    let key = [0x11u8; 32];
    assert_eq!(
        put_aes_key(&dev(), &mut fs, &sess, &key),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    admin(&mut fs, &mut sess);
    assert_eq!(put_aes_key(&dev(), &mut fs, &sess, &key), Sw::OK);
}

fn user(fs: &mut Fs<RamStorage>, sess: &mut Session) {
    for mode in [PW1_MODE81, PW1_MODE82] {
        assert_eq!(
            verify(&dev(), fs, sess, &mut CountRng(0), 0x00, mode, PW1_DEFAULT),
            Sw::OK
        );
    }
}

#[test]
fn the_pw_status_byte_refuses_a_user_status() {
    // Co-refutation found this one: `put_pw_status`'s own PW3 gate could be
    // removed with every test still green, because the only session the file
    // ever offered it was a VIRGIN one — which the dispatch's `write_authorized`
    // refuses anyway. A defence in depth nothing distinguishes from its
    // neighbour is a defence nothing measures, so this presents the case the
    // outer gate does not cover: PW1 and PW2 up, PW3 down.
    //
    // It matters because C4 is the one-shot flag's only writer: a user status
    // that could clear it would sign for ever on a single PW1 VERIFY — the rule
    // `the_one_shot_pw_status_spends_pw1_at_the_signature` pins, taken from
    // underneath rather than through the door it watches.
    let (mut fs, mut sess) = setup();
    user(&mut fs, &mut sess);
    assert!(sess.has_pw1 && sess.has_pw2 && !sess.has_pw3);
    assert_eq!(
        put_pw_status(&mut fs, &sess, &[0x00]),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    let mut pw = [0u8; 7];
    let n = fs.read(EF_PW_PRIV, &mut pw).unwrap();
    assert_eq!(pw[..n][0], 0x01, "the flag moved on a user status");
    admin(&mut fs, &mut sess);
    assert_eq!(put_pw_status(&mut fs, &sess, &[0x00]), Sw::OK);
}

/// Refines `RSKeyAppletPolicies!AttributeChangeInvalidatesTheKey` — SEC-POL-003.
/// The invalidation is guarded by a read of the stored attribute and a probe of
/// the key slot, and `Fs` answers the same "absent" for a record that is not there
/// and for one the flash could not serve — so a faulted probe let the attribute
/// move out from under a key that stayed. Aimed at the PRIVATE fid the attribute
/// is stored under (`algo_tag_to_priv`), not the wire tag: 0xC1 is P1P2, never a
/// record, so a fault there reaches nothing.
#[test]
fn a_faulted_probe_does_not_skip_the_attribute_invalidation() {
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    let mut sess = Session::new();
    admin(&mut fs, &mut sess);
    let p256 = [0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    let stored = algo_tag_to_priv(EF_ALGO_SIG);

    // Each arm is one unreadable record, and each would let the same write through:
    // an unreadable attribute resolves to DEFAULT_ALGO, which is what the host is
    // writing, so the change reads as a no-op; an unreadable key slot reads as
    // already empty, so there is nothing to retire.
    for aim in [stored, EF_PK_SIG.get()] {
        assert_eq!(put_data(&mut fs, &sess, EF_ALGO_SIG, &p256), Sw::OK);
        fs.put(EF_PK_SIG.get(), &[0xAA; 16]).unwrap();
        medium.stick(Some(aim));
        assert_eq!(
            put_data(&mut fs, &sess, EF_ALGO_SIG, DEFAULT_ALGO),
            Sw::MEMORY_FAILURE,
            "a faulted {aim:#06x} probe let the attribute change past the invalidation"
        );
        medium.stick(None);
        assert_eq!(
            medium.value(stored).as_deref(),
            Some(&p256[..]),
            "a refusal may not leave the attribute changed"
        );
        assert!(fs.has_data(EF_PK_SIG.get()), "nor the key half-retired");
    }

    // The invalidation itself still runs when every probe answers.
    assert_eq!(put_data(&mut fs, &sess, EF_ALGO_SIG, DEFAULT_ALGO), Sw::OK);
    assert!(!fs.has_data(EF_PK_SIG.get()));
}

/// The invalidation retires the public half of the slot as well as the sealed key,
/// and it probes that half with its own `try_has_data`. The key probe three lines
/// above catches a persistent fault first, so a test aimed at the key slot never
/// runs this guard — which is how it came to be held by nothing. Aimed at
/// `EF_PB_SIG` directly: the key is retired (correctly, the attribute did change)
/// and then the public half must survive rather than be read as already gone.
#[test]
fn a_faulted_public_slot_probe_does_not_skip_its_retirement() {
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    let mut sess = Session::new();
    admin(&mut fs, &mut sess);
    let p256 = [0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    assert_eq!(put_data(&mut fs, &sess, EF_ALGO_SIG, &p256), Sw::OK);
    fs.put(EF_PK_SIG.get(), &[0xAA; 16]).unwrap();
    fs.put(EF_PB_SIG, &[0xBB; 16]).unwrap();

    medium.stick(Some(EF_PB_SIG));
    let sw = put_data(&mut fs, &sess, EF_ALGO_SIG, DEFAULT_ALGO);
    medium.stick(None);
    assert!(
        fs.has_data(EF_PB_SIG),
        "a faulted probe left the public half standing over a retired key"
    );
    assert_eq!(
        sw,
        Sw::MEMORY_FAILURE,
        "an invalidation that could not read the half it retires must refuse"
    );

    // With every probe answering, the retirement completes.
    assert_eq!(put_data(&mut fs, &sess, EF_ALGO_SIG, DEFAULT_ALGO), Sw::OK);
    assert!(!fs.has_data(EF_PB_SIG));
}
