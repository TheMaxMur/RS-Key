// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::cut::sweep_restarts;
use rsk_fs::storage::faults::Cut;

#[test]
fn nickname_creation_replacement_and_clear_keep_whole_values_over_two_boots() {
    for operation in 0..3 {
        let provision = || {
            let (storage, medium) = Cut::new();
            let mut fs = Fs::new(storage);
            fs.scan();
            ensure_seed(&dev(), &mut fs, &mut SeqRng(1)).unwrap();
            let seed = load_keydev(&dev(), &mut fs).unwrap();
            add(
                &mut fs,
                seed.expose(),
                1,
                "github.com",
                b"alice",
                "Alice",
                "Alice",
                0,
            );
            add(
                &mut fs,
                seed.expose(),
                2,
                "other.example",
                b"bob",
                "Bob",
                "Bob",
                0,
            );
            if operation != 0 {
                assert!(set_rp_nickname(
                    &dev(),
                    &mut fs,
                    &sha256(b"github.com"),
                    "Before"
                ));
            }
            assert!(set_rp_nickname(
                &dev(),
                &mut fs,
                &sha256(b"other.example"),
                "Neighbor"
            ));
            (fs, medium)
        };
        let (_, baseline) = provision();
        let before = baseline.value(EF_RPNICK);
        let neighbor = baseline.value(EF_RPNICK + 1);
        let credential = baseline.value(EF_CRED);
        let command = |fs: &mut Fs<Cut>| {
            set_rp_nickname(
                &dev(),
                fs,
                &sha256(b"github.com"),
                if operation == 2 { "" } else { "After" },
            )
        };
        let (mut reference, medium) = provision();
        assert!(command(&mut reference));
        let after = medium.value(EF_RPNICK);
        assert_ne!(before, after);
        assert!(!sweep_restarts(
            provision,
            command,
            |_| {},
            |fs, _, _, completed, medium| {
                let actual = medium.value(EF_RPNICK);
                assert!(actual == before || actual == after);
                if completed && operation != 2 {
                    assert_eq!(actual, after);
                }
                assert_eq!(medium.value(EF_RPNICK + 1), neighbor);
                assert_eq!(medium.value(EF_CRED), credential);
                let mut visited = 0;
                assert_eq!(
                    for_each_rp(&dev(), fs, |rp| {
                        if rp.rp_id == "github.com" {
                            visited += 1;
                            assert_eq!(rp.count, 1);
                        }
                    }),
                    2
                );
                assert_eq!(visited, 1);
            }
        ));
    }
}
