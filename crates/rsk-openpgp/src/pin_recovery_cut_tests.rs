// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

const NEW_PIN: &[u8] = b"87654321";

fn pin_target(p2: u8) -> (&'static [u8], KeyFid) {
    match p2 {
        PW1_MODE81 => (PW1_DEFAULT, EF_DEK_PW1),
        PW3_MODE83 => (PW3_DEFAULT, EF_DEK_PW3),
        _ => panic!("unsupported fixture PIN mode"),
    }
}

fn changed_pin(p2: u8, budget: u32) -> (Fs<Cut>, CutMedium, Secret<[u8; DEK_SIZE]>, u32) {
    let (mut fs, medium) = setup_cut();
    let (old, _) = pin_target(p2);
    let mut session = Session::new();
    let mut rng = CountRng(7);
    assert_eq!(
        verify(&dev(), &mut fs, &mut session, &mut rng, 0, p2, old),
        Sw::OK
    );
    let mut expected = Secret::<[u8; DEK_SIZE]>::zeroed();
    load_dek(&dev(), &mut fs, &session, &mut expected).unwrap();
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    fs.put(0xB000, b"another applet").unwrap();
    let mut data = old.to_vec();
    data.extend_from_slice(NEW_PIN);
    medium.clear_ops();
    medium.arm(budget);
    let sw = change_pin(&dev(), &mut fs, &mut session, &mut rng, 0, p2, &data);
    assert!(matches!(sw, Sw::OK | Sw::MEMORY_FAILURE), "{sw:?}");
    let cost = u32::try_from(medium.ops().len()).unwrap();
    medium.arm(u32::MAX);
    let mut fs = Fs::new(fs.into_storage());
    fs.scan();
    (fs, medium, expected, cost)
}

fn authenticate(fs: &mut Fs<Cut>, p2: u8) -> (Session, &'static [u8]) {
    let mut session = Session::new();
    let sw = verify(&dev(), fs, &mut session, &mut CountRng(7), 0, p2, NEW_PIN);
    if sw == Sw::OK {
        return (session, NEW_PIN);
    }
    assert_eq!(sw, Sw::SECURITY_STATUS_NOT_SATISFIED);
    let (old, _) = pin_target(p2);
    assert_eq!(
        verify(&dev(), fs, &mut session, &mut CountRng(7), 0, p2, old),
        Sw::OK,
        "neither PIN survived the interrupted command"
    );
    (session, old)
}

#[test]
fn pin_changes_and_their_recovery_survive_every_pair_of_record_cuts() {
    for p2 in [PW1_MODE81, PW3_MODE83] {
        let (_, _, _, command_cost) = changed_pin(p2, u32::MAX);
        assert!(command_cost > 0);
        let mut refused_recovery = false;
        let mut completed_recovery = false;
        let mut old_pin = false;
        let mut new_pin = false;
        for first in 0..=command_cost {
            let (mut fs, medium, expected, _) = changed_pin(p2, first);
            let (session, standing) = authenticate(&mut fs, p2);
            old_pin |= standing != NEW_PIN;
            new_pin |= standing == NEW_PIN;
            medium.clear_ops();
            let mut out = Secret::<[u8; DEK_SIZE]>::zeroed();
            load_dek(&dev(), &mut fs, &session, &mut out).unwrap();
            assert_eq!(out.expose(), expected.expose());
            let recovery_cost = u32::try_from(medium.ops().len()).unwrap();
            for second in 0..=recovery_cost {
                let (mut fs, medium, expected, _) = changed_pin(p2, first);
                let (session, standing) = authenticate(&mut fs, p2);
                medium.clear_ops();
                medium.arm(second);
                let mut out = Secret::new([0xA5; DEK_SIZE]);
                match load_dek(&dev(), &mut fs, &session, &mut out) {
                    Ok(()) => {
                        assert_eq!(out.expose(), expected.expose());
                        completed_recovery |= recovery_cost != 0;
                    }
                    Err(sw) => {
                        assert_eq!(sw, Sw::MEMORY_FAILURE);
                        assert_eq!(out.expose(), &[0; DEK_SIZE]);
                        refused_recovery = true;
                    }
                }
                medium.arm(u32::MAX);
                let mut fs = Fs::new(fs.into_storage());
                fs.scan();
                let mut session = Session::new();
                assert_eq!(
                    verify(
                        &dev(),
                        &mut fs,
                        &mut session,
                        &mut CountRng(7),
                        0,
                        p2,
                        standing
                    ),
                    Sw::OK,
                    "{p2:02X}, cuts {first}/{second}: the standing PIN changed"
                );
                let mut recovered = Secret::<[u8; DEK_SIZE]>::zeroed();
                load_dek(&dev(), &mut fs, &session, &mut recovered).unwrap();
                assert_eq!(recovered.expose(), expected.expose());
                let (_, target) = pin_target(p2);
                let stage = stage_fid(target).unwrap();
                assert!(medium.value(stage.get()).is_none());
                assert_eq!(medium.value(0xB000).unwrap(), b"another applet");
            }
        }
        assert!(
            old_pin && new_pin,
            "{p2:02X}: both committed PIN states must be reached"
        );
        assert!(
            refused_recovery && completed_recovery,
            "{p2:02X}: both recovery outcomes must be reached"
        );
    }
}
