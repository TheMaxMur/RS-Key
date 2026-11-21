// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn an_absent_or_blocked_pin_refuses_before_peer_key_derivation() {
    for blocked in [false, true] {
        let (mut fs, mut rng, mut state, _) = setup_with_pin(PIN);
        let platform = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
        if blocked {
            let mut record = [0; PIN_FILE_LEN];
            assert_eq!(fs.read(EF_PIN, &mut record), Some(PIN_FILE_LEN));
            record[0] = 0;
            fs.put(EF_PIN, &record).unwrap();
        } else {
            fs.delete(EF_PIN).unwrap();
        }
        let generation = fs.write_gen();
        let request =
            platform.get_token_perms_req_coords(PIN, PERM_GA as u64, &[0; 31], &platform.y);
        assert_eq!(
            run(&mut fs, &mut rng, &mut state, &request, &mut [0; 256]),
            Err(if blocked {
                CtapError::PinBlocked
            } else {
                CtapError::PinNotSet
            })
        );
        assert_eq!(fs.write_gen(), generation);
        assert!(!state.paut.in_use);
    }
}

#[test]
fn no_truncated_owner_pin_record_can_be_overwritten_by_unauthenticated_set_pin() {
    let (mut reference, _, _, _) = setup_with_pin(PIN);
    let mut pin = [0; PIN_FILE_LEN];
    assert_eq!(reference.read(EF_PIN, &mut pin), Some(PIN_FILE_LEN));
    let storage = reference.into_storage();
    for len in 0..PIN_FILE_LEN {
        let mut fs = Fs::new(storage.clone());
        fs.scan();
        fs.put(EF_PIN, &pin[..len]).unwrap();
        let mut rng = SeqRng(91);
        let mut state = FidoState::new();
        let platform = key_agreement(&mut fs, &mut rng, &mut state, PinProto::Two, 2);
        let generation = fs.write_gen();
        assert_eq!(
            run(
                &mut fs,
                &mut rng,
                &mut state,
                &platform.set_pin_req(NEW_PIN),
                &mut [0; 256]
            ),
            Err(CtapError::NotAllowed),
            "stored length {len}"
        );
        assert_eq!(fs.write_gen(), generation);
        let mut actual = [0; PIN_FILE_LEN];
        assert_eq!(fs.read(EF_PIN, &mut actual), Some(len));
        assert_eq!(&actual[..len], &pin[..len]);
    }
}
