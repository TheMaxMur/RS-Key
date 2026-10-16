// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn an_overwrite_with_free_journal_space_needs_no_checkpoint_repair() {
    let flash = FaultFlash::new();
    let mut store = mount_authenticated(&flash);
    store.initialize_blank().unwrap();
    store.write(CRED, b"old owner").unwrap();
    store.write(CRED + 1, b"neighbor").unwrap();
    flash.arm(&[]);
    store.write(CRED, b"new owner").unwrap();
    assert!(
        flash.events().iter().all(|event| event.0 != Io::Erase),
        "a bounded overwrite with ample journal space must not repack authority"
    );
    let mut reboot = mount_authenticated(&flash);
    for (fid, expected) in [(CRED, &b"new owner"[..]), (CRED + 1, &b"neighbor"[..])] {
        assert_eq!(
            authenticated_value(&mut reboot, fid).unwrap().as_deref(),
            Some(expected)
        );
    }
}
