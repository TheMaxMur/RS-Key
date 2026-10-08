// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::cut::sweep_restarts;
use rsk_fs::storage::faults::{Cut, CutMedium};

fn device() -> Device<'static> {
    Device {
        serial_hash: &[0x22; 32],
        serial_id: &SERIAL_ID,
        otp_key: None,
        latched: false,
    }
}

fn fixture(missing: u16) -> (Fs<Cut>, CutMedium) {
    let (storage, medium) = Cut::new();
    let mut fs = provisioned_fs(storage);
    with_card_on(&mut fs, Presence::Confirmed, |app, fs| {
        verify(app, fs, PW3_MODE83);
        generate(app, fs, CRT_SIG, P256);
    });
    fs.put(0xB000, b"another applet").unwrap();
    fs.meta_add(0xB000, b"metadata").unwrap();
    fs.force_delete(missing).unwrap();
    (fs, medium)
}

fn request(fs: &mut Fs<Cut>) -> Sw {
    let mut answer = Sw::MEMORY_FAILURE;
    with_card_on(fs, Presence::Confirmed, |app, fs| {
        let sw = run(app, fs, &cmd(0, INS_VERIFY, 0, PW1_MODE81, PW1_DEFAULT)).1;
        if sw == Sw::OK {
            answer = attest(app, fs, KEY_REF_SIG);
        }
    });
    answer
}

#[test]
fn root_repair_and_its_second_interruption_always_finish_with_one_verifiable_chain() {
    for missing in [EF_PB_ATT, EF_ATT_CERT, EF_PK_ATT.get()] {
        assert!(sweep_restarts(
            || fixture(missing),
            |fs| request(fs) == Sw::OK,
            |fs| {
                let _ = crate::init::scan_files(&device(), fs, &mut Lcg(91));
                let _ = request(fs);
            },
            |fs, first, second, _, medium| {
                with_card_on(fs, Presence::Confirmed, |app, fs| {
                    verify(app, fs, PW1_MODE81);
                    let vk = root(app, fs);
                    let signer = load_ec_key(&device(), fs, &app.sess, EF_PK_ATT).unwrap();
                    let mut point = [0; MAX_EC_POINT];
                    let point_len = signer.public_point(&mut point).unwrap();
                    assert_eq!(
                        &point[..point_len],
                        vk.to_sec1_point(false).as_bytes(),
                        "cuts {first}/{second}: published root names another private key"
                    );
                    let mut cached = [0; MAX_EC_PUBDO];
                    let n = fs.read(EF_PB_ATT, &mut cached).unwrap();
                    assert_eq!(super::point(&cached[..n]), &point[..point_len]);
                    let der = occurrence(app, fs, 2);
                    signed_by(&parse(&der), &vk);
                });
                assert_eq!(
                    medium.value(0xB000).as_deref(),
                    Some(&b"another applet"[..])
                );
                let mut meta = [0; 8];
                assert_eq!(fs.meta_find(0xB000, &mut meta), Some(8));
                assert_eq!(&meta, b"metadata");
            }
        ));
    }
}

struct NoEntropy;
impl Rng for NoEntropy {
    fn fill(&mut self, _: &mut [u8]) {
        panic!("a complete root must not be regenerated");
    }
}

#[test]
fn a_complete_mismatch_from_an_older_build_is_repaired_without_replacing_its_key() {
    let (mut donor, donor_medium) = fixture(EF_PB_ATT);
    with_card_on(&mut donor, Presence::Confirmed, |app, fs| {
        verify(app, fs, PW1_MODE81);
        let mut dek = Secret::<[u8; DEK_SIZE]>::zeroed();
        load_dek(&device(), fs, &app.sess, &mut dek).unwrap();
        provision(&device(), fs, &mut Lcg(91), dek.expose()).unwrap();
    });
    let preceding = donor_medium.value(EF_ATT_CERT).unwrap();
    let cache = donor_medium.value(EF_PB_ATT).unwrap();
    let provision = || {
        let (mut fs, medium) = fixture(EF_PB_ATT);
        fs.put(EF_PB_ATT, &cache).unwrap();
        fs.put(EF_ATT_CERT, &preceding).unwrap();
        (fs, medium)
    };
    let (_, baseline) = provision();
    let key = baseline.value(EF_PK_ATT.get()).unwrap();
    assert!(sweep_restarts(
        provision,
        |fs| request(fs) == Sw::OK,
        |fs| {
            let _ = request(fs);
        },
        |fs, _, _, _, medium| {
            assert_eq!(medium.value(EF_PK_ATT.get()), Some(key.clone()));
            with_card_on(fs, Presence::Confirmed, |app, fs| {
                verify(app, fs, PW1_MODE81);
                let vk = root(app, fs);
                let der = occurrence(app, fs, 2);
                signed_by(&parse(&der), &vk);
                let generation = fs.write_gen();
                let signer = ensure_signer(&device(), fs, &app.sess, &mut NoEntropy).unwrap();
                assert_eq!(fs.write_gen(), generation);
                let mut point = [0; MAX_EC_POINT];
                let n = signer.public_point(&mut point).unwrap();
                assert_eq!(&point[..n], vk.to_sec1_point(false).as_bytes());
            });
        }
    ));
}

#[test]
fn a_new_root_never_retains_the_preceding_certificate_at_any_command_cut() {
    let mut reached = [false; 2];
    for budget in 0..16 {
        let (mut fs, medium) = fixture(EF_PK_ATT.get());
        medium.arm(budget);
        let completed = request(&mut fs) == Sw::OK;
        let cut = medium.was_cut();
        reached[usize::from(!cut)] = true;
        medium.arm(u32::MAX);
        let mut fs = Fs::new(fs.into_storage());
        fs.scan();
        if fs.has_key(EF_PK_ATT) {
            with_card_on(&mut fs, Presence::Confirmed, |app, fs| {
                verify(app, fs, PW1_MODE81);
                let key = load_ec_key(&device(), fs, &app.sess, EF_PK_ATT).unwrap();
                let mut point = [0; MAX_EC_POINT];
                let n = key.public_point(&mut point).unwrap();
                if let Some(cert) = medium.value(EF_ATT_CERT) {
                    assert_eq!(
                        spki_key(&parse(&cert)),
                        point[..n],
                        "cut {budget}: preceding root survived replacement"
                    );
                }
            });
        }
        if !cut {
            assert!(completed);
            break;
        }
    }
    assert_eq!(reached, [true; 2]);
}

#[test]
fn root_identity_repair_refuses_unread_records_without_replacing_them() {
    for fid in [EF_PK_ATT.get(), EF_PB_ATT, EF_ATT_CERT] {
        let (storage, medium) = rsk_fs::storage::faults::ProbeStuck::new();
        let mut fs = provisioned_fs(storage);
        let before: Vec<_> = [EF_PK_ATT.get(), EF_PB_ATT, EF_ATT_CERT]
            .map(|fid| medium.value(fid))
            .into();
        with_card_on(&mut fs, Presence::Confirmed, |app, fs| {
            verify(app, fs, PW1_MODE81);
            medium.stick(Some(fid));
            assert!(ensure_signer(&device(), fs, &app.sess, &mut NoEntropy).is_err());
            medium.stick(None);
        });
        let after: Vec<_> = [EF_PK_ATT.get(), EF_PB_ATT, EF_ATT_CERT]
            .map(|fid| medium.value(fid))
            .into();
        assert_eq!(after, before);
    }
}

#[test]
fn repairing_only_the_public_do_preserves_the_pinned_root_and_uses_no_entropy() {
    let (mut fs, medium) = fixture(EF_PB_ATT);
    let key = medium.value(EF_PK_ATT.get());
    let certificate = medium.value(EF_ATT_CERT);
    with_card_on(&mut fs, Presence::Confirmed, |app, fs| {
        verify(app, fs, PW1_MODE81);
        let signer = ensure_signer(&device(), fs, &app.sess, &mut NoEntropy).unwrap();
        let mut public = [0; MAX_EC_POINT];
        let n = signer.public_point(&mut public).unwrap();
        assert_eq!(root(app, fs).to_sec1_point(false).as_bytes(), &public[..n]);
        let cached = medium.value(EF_PB_ATT).unwrap();
        assert_eq!(point(&cached), &public[..n]);
    });
    assert_eq!(medium.value(EF_PK_ATT.get()), key);
    assert_eq!(medium.value(EF_ATT_CERT), certificate);
}
