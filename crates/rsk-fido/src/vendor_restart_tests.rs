// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::cut::sweep_restarts;
use rsk_fs::storage::faults::{Cut, CutMedium};

const NEIGHBOR: u16 = 0xB000;

fn fixture() -> (Fs<Cut>, CutMedium) {
    let (storage, medium) = Cut::new();
    let mut fs = Fs::new(storage);
    fs.scan();
    ensure_seed(&dev(), &mut fs, &mut SeqRng(1)).unwrap();
    fs.put(NEIGHBOR, b"another applet").unwrap();
    fs.meta_add(NEIGHBOR, b"metadata").unwrap();
    (fs, medium)
}

fn config<S: Storage>(
    fs: &mut Fs<S>,
    rng: &mut SeqRng,
    state: &mut FidoState,
    req: &[u8],
) -> CtapResult {
    let mut presence = AlwaysConfirm;
    let mut ctx = Ctx {
        dev: dev(),
        fs,
        rng,
        state,
        presence: &mut presence,
        now_ms: 0,
    };
    crate::config::authenticator_config(&mut ctx, req, &mut [0; 64])
}

fn unlock<S: Storage>(
    fs: &mut Fs<S>,
    rng: &mut SeqRng,
    state: &mut FidoState,
    host: &Host,
) -> CtapResult {
    let blob = host_wrap(host, &LOCK_KEY, &[0x22; 12]);
    let mut raw = [0; 128];
    let mut e = Encoder::new(Cursor::new(raw.as_mut_slice()));
    e.map(2)
        .unwrap()
        .u8(1)
        .unwrap()
        .u64(VENDOR_UNLOCK)
        .unwrap()
        .u8(2)
        .unwrap()
        .map(1)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&blob)
        .unwrap();
    let n = e.writer().position();
    call(fs, rng, state, &mut AlwaysConfirm, &raw[..n], &mut [0; 16])
}

fn set_lock(fs: &mut Fs<Cut>, enable: bool) -> bool {
    let mut rng = SeqRng(71);
    let mut state = FidoState::new();
    let host = handshake(fs, &mut rng, &mut state);
    arm_acfg(&mut state);
    if !enable {
        if !fs.has_key(EF_KEY_DEV_ENC) {
            return true;
        }
        if crate::seed::lock_engaged(fs) && unlock(fs, &mut rng, &mut state, &host).is_err() {
            return false;
        }
    } else if crate::seed::lock_engaged(fs) {
        return true;
    }
    let blob = host_wrap(&host, &LOCK_KEY, &[0x11; 12]);
    let mut raw = [0; 192];
    let n = config_vendor_req(
        if enable {
            crate::consts::CONFIG_AUT_ENABLE
        } else {
            crate::consts::CONFIG_AUT_DISABLE
        },
        enable.then_some(&blob),
        &mut raw,
    );
    config(fs, &mut rng, &mut state, &raw[..n]).is_ok()
}

fn retained(fs: &mut Fs<Cut>, medium: &CutMedium) {
    assert_eq!(
        medium.value(NEIGHBOR).as_deref(),
        Some(&b"another applet"[..])
    );
    let mut meta = [0; 8];
    assert_eq!(fs.meta_find(NEIGHBOR, &mut meta), Some(8));
    assert_eq!(&meta, b"metadata");
}

#[test]
fn soft_lock_prefixes_and_owner_replay_preserve_the_seed_through_both_cuts() {
    for enable in [false, true] {
        let seed = std::cell::RefCell::new(None);
        let provision = || {
            let (mut fs, medium) = fixture();
            *seed.borrow_mut() = load_keydev(&dev(), &mut fs);
            if !enable {
                assert!(set_lock(&mut fs, true));
            }
            (fs, medium)
        };
        let inspect = |fs: &mut Fs<Cut>| {
            let plain = load_keydev(&dev(), fs);
            let mut wrapped = [0; LOCK_BLOB_LEN];
            let sealed = fs
                .read_key(EF_KEY_DEV_ENC, &mut wrapped)
                .and_then(|n| crate::seed::open_seed_locked(&LOCK_KEY, &wrapped[..n]));
            assert!(plain.is_some() || sealed.is_some());
            for value in [plain, sealed].into_iter().flatten() {
                assert_eq!(value.expose(), seed.borrow().as_ref().unwrap().expose());
            }
            assert_eq!(
                crate::seed::lock_engaged(fs),
                fs.has_key(EF_KEY_DEV_ENC) && !fs.has_key(EF_KEY_DEV)
            );
        };
        assert!(sweep_restarts(
            provision,
            |fs| set_lock(fs, enable),
            |fs| {
                let _ = ensure_seed(&dev(), fs, &mut SeqRng(91));
                inspect(fs);
                if !enable
                    && fs.has_key(EF_KEY_DEV_ENC)
                    && fs.has_key(EF_KEY_DEV)
                    && !set_lock(fs, true)
                {
                    return;
                }
                let _ = set_lock(fs, enable);
            },
            |fs, _, _, _, medium| {
                inspect(fs);
                assert_eq!(crate::seed::lock_engaged(fs), enable);
                assert_eq!(fs.has_key(EF_KEY_DEV), !enable);
                assert_eq!(fs.has_key(EF_KEY_DEV_ENC), enable);
                retained(fs, medium);
            }
        ));
    }
}

fn chain(scalar: &[u8; 32]) -> Vec<u8> {
    let key = P256Key::from_scalar(scalar).unwrap();
    let mut out = [0; 1024];
    let n = crate::cert::build_attestation_cert(&key, &[1; 16], &mut out).unwrap();
    out[..n].to_vec()
}

fn import(fs: &mut Fs<Cut>, scalar: &[u8; 32], chain: &[u8]) -> bool {
    let mut rng = SeqRng(71);
    let mut state = FidoState::new();
    let host = handshake(fs, &mut rng, &mut state);
    let blob = wrap32(&host, scalar);
    let mut raw = [0; 2048];
    let n = att_import_req(&mut raw, &blob, chain);
    let result = call(
        fs,
        &mut rng,
        &mut state,
        &mut AlwaysConfirm,
        &raw[..n],
        &mut [0; 16],
    );
    assert!(!state.mse_live(), "import retained its single-use channel");
    result.is_ok()
}

#[test]
fn an_attestation_import_and_its_owner_reimport_finish_the_intended_key_and_chain() {
    let old_key = [0x21; 32];
    let new_key = [0x33; 32];
    let old_chain = chain(&old_key);
    let new_chain = chain(&new_key);
    for replacing in [false, true] {
        let provision = || {
            let (mut fs, medium) = fixture();
            if replacing {
                assert!(import(&mut fs, &old_key, &old_chain));
            }
            (fs, medium)
        };
        let (_, baseline) = provision();
        let old = baseline.value(EF_ATT_KEY.get());
        let old_packed = baseline.value(EF_ATT_CHAIN);
        let mut reference = provision().0;
        assert!(import(&mut reference, &new_key, &new_chain));
        let mut raw_key = [0; 128];
        let n = reference.read_key(EF_ATT_KEY, &mut raw_key).unwrap();
        let new = raw_key[..n].to_vec();
        let mut raw_chain = [0; 2048];
        let n = reference.read(EF_ATT_CHAIN, &mut raw_chain).unwrap();
        let packed = raw_chain[..n].to_vec();
        assert!(sweep_restarts(
            provision,
            |fs| import(fs, &new_key, &new_chain),
            |fs| {
                let mut key = [0; 128];
                let key = fs.read_key(EF_ATT_KEY, &mut key).map(|n| key[..n].to_vec());
                let mut bytes = [0; 2048];
                let chain = fs
                    .read(EF_ATT_CHAIN, &mut bytes)
                    .map(|n| bytes[..n].to_vec());
                assert!(key == old || key.as_ref() == Some(&new));
                assert!(chain == old_packed || chain.as_ref() == Some(&packed));
                if key.as_ref() == Some(&new) {
                    assert_eq!(chain.as_ref(), Some(&packed));
                }
                let _ = import(fs, &new_key, &new_chain);
            },
            |fs, _, _, _, medium| {
                assert_eq!(
                    crate::seed::load_att_key(&dev(), fs).unwrap().expose(),
                    &new_key
                );
                assert_eq!(medium.value(EF_ATT_CHAIN), Some(packed.clone()));
                let point = crate::cert::att_chain_cert(&packed, 0).unwrap();
                assert!(crate::cert::matches_template(
                    point,
                    &P256Key::from_scalar(&new_key).unwrap()
                ));
                retained(fs, medium);
            }
        ));
    }
}

#[test]
fn backup_finalize_and_audit_configuration_are_durable_without_replaying_on_boot() {
    for command in [VENDOR_BACKUP_FINALIZE, VENDOR_AUDIT_CONFIG] {
        for enabled in [false, true] {
            if command == VENDOR_BACKUP_FINALIZE && !enabled {
                continue;
            }
            let provision = || {
                let (mut fs, medium) = fixture();
                if !enabled {
                    crate::journal::set_enabled(&mut fs, true).unwrap();
                }
                (fs, medium)
            };
            assert!(!sweep_restarts(
                provision,
                |fs| {
                    let mut raw = [0; 64];
                    let n = if command == VENDOR_BACKUP_FINALIZE {
                        one_byte_req(&mut raw, command)
                    } else {
                        audit_config_req(u64::from(enabled), &mut raw)
                    };
                    call(
                        fs,
                        &mut SeqRng(71),
                        &mut FidoState::new(),
                        &mut AlwaysConfirm,
                        &raw[..n],
                        &mut [0; 64],
                    )
                    .is_ok()
                },
                |fs| {
                    let _ = ensure_seed(&dev(), fs, &mut SeqRng(91));
                },
                |fs, _, _, completed, medium| {
                    if completed {
                        if command == VENDOR_BACKUP_FINALIZE {
                            assert!(backup_sealed(fs));
                        } else {
                            assert_eq!(crate::journal::is_enabled(fs), enabled);
                        }
                    }
                    crate::journal::chain_head(&dev(), fs).unwrap();
                    retained(fs, medium);
                }
            ));
        }
    }
}
