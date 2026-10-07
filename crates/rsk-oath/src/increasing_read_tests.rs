// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::faults::ProbeStuck;

#[test]
fn a_transient_preflight_read_cannot_emit_an_unmarked_bulk_code() {
    let (backend, medium) = ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    let mut credential = put_data(b"monotonic", 0x21, 6, SECRET_SHA1, false, None);
    credential.extend([TAG_PROPERTY, PROP_INCREASING]);
    assert_eq!(put(&mut app, &mut fs, &credential), Sw::OK);
    let before = medium.value(EF_OATH_CRED);
    medium.stick_once(EF_OATH_CRED);
    let request = apdu(INS_CALC_ALL, 0, 1, &tlv(TAG_CHALLENGE, &1u64.to_be_bytes()));
    assert_eq!(
        run(&mut app, &mut fs, &request),
        (Sw::MEMORY_FAILURE, vec![]),
        "a code cannot precede its only-increasing mark"
    );
    assert_eq!(medium.value(EF_OATH_CRED), before);
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_SEND_REMAINING, 0, 0, &[])),
        (Sw::INS_NOT_SUPPORTED, vec![])
    );
    let mut expected = tlv(TAG_NAME, b"monotonic");
    expected.extend([TAG_RESPONSE + 1, 5, 6]);
    expected.extend(287082u32.to_be_bytes());
    assert_eq!(run(&mut app, &mut fs, &request), (Sw::OK, expected));
    assert_ne!(medium.value(EF_OATH_CRED), before);
    assert_eq!(run(&mut app, &mut fs, &request), (Sw::WRONG_DATA, vec![]));
}

#[test]
fn persistent_preflight_faults_keep_the_unread_suffix_unmarked() {
    for failed in 0..3 {
        let (backend, medium) = ProbeStuck::new();
        let mut fs = Fs::new(backend);
        fs.scan();
        let rng = RefCell::new(CountRng(7));
        let touch = RefCell::new(AlwaysConfirm);
        let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
        for name in [b"a", b"b", b"c"] {
            let mut credential = put_data(name, 0x21, 6, SECRET_SHA1, false, None);
            credential.extend([TAG_PROPERTY, PROP_INCREASING]);
            assert_eq!(put(&mut app, &mut fs, &credential), Sw::OK);
        }
        let before = [0, 1, 2].map(|i| medium.value(EF_OATH_CRED + i));
        medium.stick(Some(EF_OATH_CRED + failed));
        for challenge in [1u64, 2] {
            let request = apdu(
                INS_CALC_ALL,
                0,
                1,
                &tlv(TAG_CHALLENGE, &challenge.to_be_bytes()),
            );
            assert_eq!(
                run(&mut app, &mut fs, &request),
                (Sw::MEMORY_FAILURE, vec![])
            );
            for (i, original) in before.iter().enumerate() {
                let current = medium.value(EF_OATH_CRED + i as u16);
                if i < usize::from(failed) {
                    assert_ne!(&current, original);
                    let mut request = tlv(TAG_NAME, &[b'a' + i as u8]);
                    request.extend(tlv(TAG_CHALLENGE, &challenge.to_be_bytes()));
                    assert_eq!(
                        run(&mut app, &mut fs, &apdu(INS_CALCULATE, 0, 1, &request)),
                        (Sw::WRONG_DATA, vec![]),
                        "the committed prefix must refuse its persisted challenge"
                    );
                } else {
                    assert_eq!(&current, original);
                }
            }
        }
        medium.stick(None);
        let request = apdu(INS_CALC_ALL, 0, 1, &tlv(TAG_CHALLENGE, &3u64.to_be_bytes()));
        let mut expected = Vec::new();
        for name in [b"a", b"b", b"c"] {
            expected.extend(tlv(TAG_NAME, name));
            expected.extend([TAG_RESPONSE + 1, 5, 6]);
            expected.extend(969429u32.to_be_bytes());
        }
        assert_eq!(run(&mut app, &mut fs, &request), (Sw::OK, expected));
        assert_eq!(run(&mut app, &mut fs, &request), (Sw::WRONG_DATA, vec![]));
    }
}
