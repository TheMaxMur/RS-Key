// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::faults::ProbeStuck;

fn get_info<S: Storage>(
    fs: &mut Fs<S>,
    rng: &mut SeqRng,
    state: &mut crate::FidoState,
) -> [Option<[u8; ENC_GETINFO_MEMBER_LEN]>; 2] {
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = crate::Ctx {
        presence: &mut presence,
        dev: dev(),
        fs,
        rng,
        state,
        now_ms: 10,
    };
    let mut out = [0; 2048];
    let length = crate::process_cbor(&mut ctx, &[crate::consts::CTAP_GET_INFO], &mut out);
    assert_eq!(out[0], 0);
    let mut decoder = minicbor::Decoder::new(&out[1..length]);
    let mut members = [None; 2];
    for _ in 0..decoder.map().unwrap().unwrap() {
        match decoder.u8().unwrap() {
            0x19 => members[0] = Some(decoder.bytes().unwrap().try_into().unwrap()),
            0x1e => members[1] = Some(decoder.bytes().unwrap().try_into().unwrap()),
            _ => decoder.skip().unwrap(),
        }
    }
    members
}

#[test]
fn commands_load_one_fresh_grant_and_keep_both_iv_streams_independent() {
    let (backend, medium) = ProbeStuck::new();
    let mut fs = Fs::new(backend);
    let mut rng = SeqRng(71);
    let mut state = crate::FidoState::new();
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let token = load_ppuat(&dev(), &mut fs).unwrap();
    let generation = fs.write_gen();
    medium.stick_after(EF_PAUTHTOKEN.get(), 1);
    let first = get_info(&mut fs, &mut rng, &mut state);
    let [Some(first_id), Some(first_css)] = first else {
        panic!("one getInfo must not read its grant a second time");
    };
    assert!(
        load_ppuat(&dev(), &mut fs).is_none(),
        "exactly one read consumed the skip"
    );
    let [Some(next_id), Some(next_css)] = get_info(&mut fs, &mut rng, &mut state) else {
        panic!("the next command must recover after a transient read fault");
    };
    assert_ne!(&first_id[..16], &first_css[..16]);
    assert_ne!(&first_id[..16], &next_id[..16]);
    assert_ne!(&first_css[..16], &next_css[..16]);
    let id = open_enc_identifier(token.expose(), &first_id);
    let css = open_enc_cred_store_state(token.expose(), &first_css);
    assert_eq!(id, open_enc_identifier(token.expose(), &next_id));
    assert_eq!(css, open_enc_cred_store_state(token.expose(), &next_css));
    assert_eq!(fs.write_gen(), generation);

    clear_ppuat(&mut fs).unwrap();
    assert_eq!(get_info(&mut fs, &mut rng, &mut state), [None; 2]);
    let replacement = ensure_ppuat(&dev(), &mut fs, &mut rng).unwrap();
    assert_ne!(token.expose(), replacement.expose());
    let [Some(new_id), Some(new_css)] = get_info(&mut fs, &mut rng, &mut state) else {
        panic!("a replacement grant must key both members on the next command");
    };
    assert_eq!(id, open_enc_identifier(replacement.expose(), &new_id));
    assert_eq!(
        css,
        open_enc_cred_store_state(replacement.expose(), &new_css)
    );
    assert_ne!(id, open_enc_identifier(token.expose(), &new_id));
    assert_ne!(css, open_enc_cred_store_state(token.expose(), &new_css));
}

#[test]
fn a_transient_grant_fault_omits_both_members_without_retry_or_writes() {
    let (backend, medium) = ProbeStuck::new();
    let mut fs = Fs::new(backend);
    let mut rng = SeqRng(73);
    let mut state = crate::FidoState::new();
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    assert!(
        get_info(&mut fs, &mut rng, &mut state)
            .iter()
            .all(Option::is_some)
    );
    let sealed = medium.value(EF_PAUTHTOKEN.get());
    let generation = fs.write_gen();
    medium.stick_once(EF_PAUTHTOKEN.get());
    assert_eq!(get_info(&mut fs, &mut rng, &mut state), [None; 2]);
    assert_eq!(medium.value(EF_PAUTHTOKEN.get()), sealed);
    assert_eq!(fs.write_gen(), generation);
    assert!(
        get_info(&mut fs, &mut rng, &mut state)
            .iter()
            .all(Option::is_some)
    );
}

#[test]
fn seed_and_tag_faults_leave_the_other_get_info_member_available() {
    for (fid, expected) in [
        (EF_KEY_DEV.get(), [false, true]),
        (crate::consts::EF_CRED_STATE, [true, false]),
    ] {
        let (backend, medium) = ProbeStuck::new();
        let mut fs = Fs::new(backend);
        let mut rng = SeqRng(79);
        let mut state = crate::FidoState::new();
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        assert!(
            get_info(&mut fs, &mut rng, &mut state)
                .iter()
                .all(Option::is_some)
        );
        let generation = fs.write_gen();
        medium.stick_once(fid);
        assert_eq!(
            get_info(&mut fs, &mut rng, &mut state).map(|value| value.is_some()),
            expected
        );
        assert_eq!(fs.write_gen(), generation);
        assert!(
            get_info(&mut fs, &mut rng, &mut state)
                .iter()
                .all(Option::is_some)
        );
    }
}
