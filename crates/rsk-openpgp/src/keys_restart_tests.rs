// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::cut::sweep_restarts;
use rsk_fs::storage::faults::{Cut, CutMedium};

struct Fill;
impl Rng for Fill {
    fn fill(&mut self, out: &mut [u8]) {
        out.fill(7);
    }
}
fn dev() -> Device<'static> {
    Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
        latched: false,
    }
}
fn owner(fs: &mut Fs<Cut>) -> Option<Session> {
    let mut session = Session::new();
    (crate::pin::verify(
        &dev(),
        fs,
        &mut session,
        &mut Fill,
        0,
        PW3_MODE83,
        PW3_DEFAULT,
    ) == Sw::OK)
        .then_some(session)
}
fn legacy(plain: &[u8], fid: KeyFid) -> (Fs<Cut>, CutMedium) {
    let (storage, medium) = Cut::new();
    let mut fs = Fs::new(storage);
    fs.scan();
    crate::init::scan_files(&dev(), &mut fs, &mut Fill).unwrap();
    let session = owner(&mut fs).unwrap();
    let (key, iv) = load_dek_keys(&dev(), &mut fs, &session).unwrap();
    let mut cipher = plain.to_vec();
    rsk_crypto::aes::aes_encrypt_cfb_256(key.expose(), iv.expose(), &mut cipher).unwrap();
    fs.put_key(fid, Sealed::wrap(&cipher)).unwrap();
    fs.put(0xB000, b"another applet").unwrap();
    (fs, medium)
}

#[test]
fn first_use_and_repeat_use_upgrade_ec_and_aes_cfb_without_changing_the_key() {
    for kind in 0..2 {
        let fid = if kind == 0 { EF_PK_SIG } else { EF_AES_KEY };
        let plain = if kind == 0 {
            [&[Curve::P256.id()][..], &[0x11; 32]].concat()
        } else {
            vec![0x33; 32]
        };
        let load = |fs: &mut Fs<Cut>| {
            let Some(session) = owner(fs) else {
                return false;
            };
            if kind == 0 {
                load_ec_key(&dev(), fs, &session, fid)
                    .map(|key| {
                        assert_eq!(key.scalar(), &[0x11; 32]);
                    })
                    .is_ok()
            } else {
                load_aes_key(&dev(), fs, &session)
                    .map(|(key, n)| assert_eq!(&key.expose()[..n], &plain))
                    .is_ok()
            }
        };
        assert!(sweep_restarts(
            || legacy(&plain, fid),
            load,
            |fs| {
                let _ = load(fs);
            },
            |fs, _, _, _, medium| {
                assert_eq!(
                    medium.value(fid.get()).unwrap().len(),
                    plain.len() + DEK_SEAL_OVERHEAD
                );
                let session = owner(fs).unwrap();
                let generation = fs.write_gen();
                if kind == 0 {
                    assert_eq!(
                        load_ec_key(&dev(), fs, &session, fid).unwrap().scalar(),
                        &[0x11; 32]
                    );
                } else {
                    let (key, n) = load_aes_key(&dev(), fs, &session).unwrap();
                    assert_eq!(&key.expose()[..n], plain);
                }
                assert_eq!(generation, fs.write_gen());
                assert_eq!(
                    medium.value(0xB000).as_deref(),
                    Some(&b"another applet"[..])
                );
            }
        ));
    }
}

#[test]
fn both_legacy_rsa_layouts_and_both_loaders_keep_their_modulus_after_two_cuts() {
    use rsk_rsa::vectors::{P_HEX, Q_HEX, hex};
    let key = rsk_rsa::rsa_from_pqe(&[1, 0, 1], &hex(P_HEX), &hex(Q_HEX)).unwrap();
    let mut crt = [0; MAX_CRT_PLAIN];
    let n = rsk_rsa::crt::crt_plaintext(&key, &mut crt).unwrap();
    for plain in [&crt[..key.size()], &crt[..n]] {
        for fast in [false, true] {
            let load = |fs: &mut Fs<Cut>| {
                let Some(session) = owner(fs) else {
                    return false;
                };
                if fast {
                    load_rsa_crt(&dev(), fs, &session, EF_PK_SIG).is_ok()
                } else {
                    load_rsa_key(&dev(), fs, &session, EF_PK_SIG)
                        .map(|loaded| assert_eq!(loaded.n_be(), key.n_be()))
                        .is_ok()
                }
            };
            assert!(sweep_restarts(
                || legacy(plain, EF_PK_SIG),
                load,
                |fs| {
                    let _ = load(fs);
                },
                |fs, _, _, _, medium| {
                    assert_eq!(
                        medium.value(EF_PK_SIG.get()).unwrap().len(),
                        n + DEK_SEAL_OVERHEAD
                    );
                    let session = owner(fs).unwrap();
                    let generation = fs.write_gen();
                    assert_eq!(
                        load_rsa_key(&dev(), fs, &session, EF_PK_SIG)
                            .unwrap()
                            .n_be(),
                        key.n_be()
                    );
                    load_rsa_crt(&dev(), fs, &session, EF_PK_SIG).unwrap();
                    assert_eq!(generation, fs.write_gen());
                    assert_eq!(
                        medium.value(0xB000).as_deref(),
                        Some(&b"another applet"[..])
                    );
                }
            ));
        }
    }
}
