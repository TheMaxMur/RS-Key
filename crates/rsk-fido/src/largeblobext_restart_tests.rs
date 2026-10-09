// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::cut::sweep_restarts;
use rsk_fs::storage::faults::Cut;

fn apply(fs: &mut Fs<Cut>, blob: &[u8]) -> bool {
    let mut state = FidoState::new();
    let mut rng = SeqRng(71);
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        dev: dev(),
        fs,
        state: &mut state,
        rng: &mut rng,
        presence: &mut presence,
        now_ms: 10,
    };
    matches!(
        process_ga(
            &mut ctx,
            &SEED,
            GaInput::Write {
                blob,
                original_size: 93
            },
            &CRED_A,
            Some(0),
            true,
            true
        ),
        GaOutput::Written(true)
    )
}

#[test]
fn selected_credential_blob_creation_and_replacement_survive_both_boots() {
    for replace in [false, true] {
        let provision = || {
            let (storage, medium) = Cut::new();
            let mut fs = Fs::new(storage);
            fs.scan();
            if replace {
                assert!(apply(&mut fs, b"before"));
            }
            fs.put(EF_CRED_BLOB + 1, b"neighbor blob").unwrap();
            (fs, medium)
        };
        let (_, baseline) = provision();
        let before = baseline.value(EF_CRED_BLOB);
        let (mut reference, medium) = provision();
        assert!(apply(&mut reference, b"after"));
        let after = medium.value(EF_CRED_BLOB);
        assert!(!sweep_restarts(
            provision,
            |fs| apply(fs, b"after"),
            |_| {},
            |fs, _, _, completed, medium| {
                let actual = medium.value(EF_CRED_BLOB);
                assert!(actual == before || actual == after);
                if completed {
                    assert_eq!(actual, after);
                }
                let mut state = FidoState::new();
                let mut rng = SeqRng(7);
                let mut presence = crate::AlwaysConfirm;
                let mut ctx = Ctx {
                    dev: dev(),
                    fs,
                    state: &mut state,
                    rng: &mut rng,
                    presence: &mut presence,
                    now_ms: 10,
                };
                if let Some((at, size)) = read(&mut ctx, &SEED, &CRED_A, 0) {
                    assert_eq!(size, 93);
                    assert!([&b"before"[..], &b"after"[..]].contains(&&ctx.state.lba.temp[at]));
                } else {
                    assert!(!replace && !completed);
                }
                assert!(read(&mut ctx, &SEED, &CRED_B, 0).is_none());
                assert_eq!(
                    medium.value(EF_CRED_BLOB + 1).as_deref(),
                    Some(&b"neighbor blob"[..])
                );
            }
        ));
    }
}
