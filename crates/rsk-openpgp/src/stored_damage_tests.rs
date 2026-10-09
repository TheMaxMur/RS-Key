// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[test]
fn malformed_stored_uif_cannot_make_a_signature_touchless() {
    for malformed in [&[][..], &[0][..], &[0, 0x20, 0][..]] {
        let rng = RefCell::new(CountRng(7));
        let presence = RefCell::new(Fixed(crate::Presence::Timeout));
        let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
        let mut fs = make_fs();
        setup_uif_sig(&mut app, &mut fs);
        fs.put(consts::EF_UIF_SIG, malformed).unwrap();
        let generation = fs.write_gen();
        assert_eq!(
            pso_cds(&mut app, &mut fs),
            (vec![], Sw::SECURE_MESSAGE_EXEC_ERROR)
        );
        assert_eq!(fs.write_gen(), generation);
        assert_eq!(fs.read(consts::EF_SIG_COUNT, &mut [0; 3]), Some(3));
        let mut counter = [0; 3];
        fs.read(consts::EF_SIG_COUNT, &mut counter);
        assert_eq!(counter, [0; 3]);
    }
}

#[test]
fn malformed_signature_counters_never_publish_or_restart_a_signature_sequence() {
    for malformed in [&[][..], &[0][..], &[0, 0][..], &[0, 0, 7, 0][..]] {
        let rng = RefCell::new(CountRng(7));
        let presence = RefCell::new(crate::AlwaysConfirm);
        let mut app = OpenpgpApplet::new(SERIAL_ID, SERIAL_HASH, None, &rng, &presence);
        let mut fs = make_fs();
        setup_uif_sig(&mut app, &mut fs);
        fs.put(consts::EF_SIG_COUNT, malformed).unwrap();
        let generation = fs.write_gen();
        assert_eq!(pso_cds(&mut app, &mut fs), (vec![], Sw::MEMORY_FAILURE));
        let mut after = [0; 4];
        assert_eq!(
            fs.read(consts::EF_SIG_COUNT, &mut after),
            Some(malformed.len())
        );
        assert_eq!(&after[..malformed.len()], malformed);
        assert_eq!(fs.write_gen(), generation);
    }
}
