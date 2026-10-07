// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::faults::ProbeStuck;

#[test]
fn deleting_the_last_partly_sent_entry_refuses_and_discards_the_list_tail() {
    let mut fs = new_fs();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(
        put(
            &mut app,
            &mut fs,
            &put_data(b"credential", 0x21, 6, SECRET_SHA1, false, None)
        ),
        Sw::OK
    );
    let mut expected = vec![TAG_NAME_LIST, 11, 0x21];
    expected.extend(b"credential");
    let (sw, first) = run_fw(&mut app, &mut fs, &[0, INS_LIST, 0, 0, 4]);
    assert_eq!(sw.sw1(), 0x61);
    assert_eq!(first, expected[..4]);
    let (sw, rest) = run_fw(&mut app, &mut fs, &apdu(INS_SEND_REMAINING, 0, 0, &[]));
    assert_eq!(sw, Sw::OK);
    assert_eq!([first, rest].concat(), expected);
    assert_eq!(
        run_fw(&mut app, &mut fs, &[0, INS_LIST, 0, 0, 4]).0.sw1(),
        0x61
    );
    let mut other = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(
        run(
            &mut other,
            &mut fs,
            &apdu(INS_DELETE, 0, 0, &tlv(TAG_NAME, b"credential"))
        ),
        (Sw::OK, vec![])
    );
    assert_eq!(
        run_fw(&mut app, &mut fs, &apdu(INS_SEND_REMAINING, 0, 0, &[])),
        (Sw::MEMORY_FAILURE, vec![])
    );
    assert_eq!(
        run_fw(&mut app, &mut fs, &apdu(INS_SEND_REMAINING, 0, 0, &[])),
        (Sw::INS_NOT_SUPPORTED, vec![])
    );
    assert_eq!(
        run_fw(&mut app, &mut fs, &apdu(INS_LIST, 0, 0, &[])),
        (Sw::OK, vec![])
    );
}

#[test]
fn a_recovered_truncated_scan_confirms_absence_without_mutating_a_neighbor() {
    let (backend, medium) = ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    let rng = RefCell::new(CountRng(7));
    let touch = RefCell::new(AlwaysConfirm);
    let mut app = OathApplet::new(SERIAL, [0x22; 32], None, &rng, &touch);
    assert_eq!(
        put(
            &mut app,
            &mut fs,
            &put_data(b"present", 0x21, 6, SECRET_SHA1, false, None)
        ),
        Sw::OK
    );
    let before = medium.value(EF_OATH_CRED);
    medium.truncate_walk(true);
    fs.scan();
    medium.truncate_walk(false);
    let generation = fs.write_gen();
    let missing = [
        tlv(TAG_NAME, b"absent"),
        tlv(TAG_CHALLENGE, &1u64.to_be_bytes()),
    ]
    .concat();
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_CALCULATE, 0, 1, &missing)),
        (Sw::DATA_INVALID, vec![])
    );
    assert_eq!(medium.value(EF_OATH_CRED), before);
    assert_eq!(fs.write_gen(), generation);
    let present = [
        tlv(TAG_NAME, b"present"),
        tlv(TAG_CHALLENGE, &1u64.to_be_bytes()),
    ]
    .concat();
    let mut expected = vec![TAG_RESPONSE + 1, 5, 6];
    expected.extend(287082u32.to_be_bytes());
    assert_eq!(
        run(&mut app, &mut fs, &apdu(INS_CALCULATE, 0, 1, &present)),
        (Sw::OK, expected)
    );
    assert_eq!(medium.value(EF_OATH_CRED), before);
    assert_eq!(fs.write_gen(), generation);
}
