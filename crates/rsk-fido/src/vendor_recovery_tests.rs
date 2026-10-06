// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::consts::{CRED_STATE_LEN, EF_COUNTER, EF_LARGEBLOB, LARGEBLOB_INITIAL};
use p256::ecdsa::{Signature, SigningKey, signature::Verifier};
use rsk_fs::cut::{Snap, sweep_recovery};
use rsk_fs::storage::faults::{Cut, CutMedium};
use rsk_sdk::tlv::Tlv;

const OLD_SEED: [u8; 32] = [0x5A; 32];
const NEW_SEED: [u8; 32] = [0x33; 32];
const COUNTER: u32 = 73;
const LED_RECORD: [u8; LED_CONF_LEN] = [0x11; LED_CONF_LEN];

fn provision<S: Storage>(fs: &mut Fs<S>) -> [u8; CRED_STATE_LEN] {
    crate::seed::encrypt_keydev_f1(&dev(), fs, &OLD_SEED).unwrap();
    ensure_seed(&dev(), fs, &mut SeqRng(1)).unwrap();
    crate::credential::renew_store_state(fs, &mut SeqRng(3)).unwrap();
    fs.put(EF_BACKUP_SEALED, &[1]).unwrap();
    fs.put(EF_LED_CONF, &LED_RECORD).unwrap();
    fs.put_counter(EF_COUNTER, &COUNTER.to_le_bytes()).unwrap();
    crate::credential::cred_store_state(fs).unwrap()
}

fn cut_fixture() -> (Fs<Cut>, CutMedium) {
    let (storage, medium) = Cut::new();
    let mut fs = Fs::new(storage);
    provision(&mut fs);
    (fs, medium)
}

fn load<S: Storage>(fs: &mut Fs<S>) -> CtapResult {
    let mut rng = SeqRng(7);
    let mut state = FidoState::new();
    let host = handshake(fs, &mut rng, &mut state);
    let mut request = [0; 128];
    let n = load_req(&mut request, &wrap32(&host, &NEW_SEED));
    call(
        fs,
        &mut rng,
        &mut state,
        &mut AlwaysConfirm,
        &request[..n],
        &mut [0; 16],
    )
}

fn certificate_binds_seed(cert: &[u8], seed: &[u8; 32]) {
    let outer: Vec<_> = Tlv::new(cert).collect();
    assert_eq!(outer.len(), 1);
    assert_eq!(outer[0].0, 0x30);
    let fields: Vec<_> = Tlv::new(outer[0].1).collect();
    assert_eq!(fields.len(), 3);
    assert_eq!((fields[0].0, fields[1].0, fields[2].0), (0x30, 0x30, 3));
    let body: Vec<_> = Tlv::new(fields[0].1).collect();
    let spki: Vec<_> = Tlv::new(body[6].1).collect();
    assert_eq!((body[6].0, spki[0].0, spki[1].0), (0x30, 0x30, 3));
    assert_eq!(spki[1].1[0], 0);
    assert_eq!(fields[2].1[0], 0);
    let reference = SigningKey::from_bytes(&p256::FieldBytes::from(*seed)).unwrap();
    let public = reference.verifying_key().to_sec1_point(false);
    assert_eq!(
        &spki[1].1[1..],
        public.as_bytes(),
        "a replacement seed retained the old certificate"
    );
    let signature = Signature::from_der(&fields[2].1[1..]).unwrap();
    let tbs_len = rsk_sdk::tlv::len_tag(0x30, u16::try_from(fields[0].1.len()).unwrap());
    reference
        .verifying_key()
        .verify(&outer[0].1[..tbs_len], &signature)
        .expect("the surviving certificate must verify under the live seed");
}

fn check<S: Storage>(fs: &mut Fs<S>, old_tag: &[u8; CRED_STATE_LEN]) -> bool {
    let seed = load_keydev(&dev(), fs).unwrap();
    assert!(seed.expose() == &OLD_SEED || seed.expose() == &NEW_SEED);
    let replaced = seed.expose() == &NEW_SEED;
    if replaced {
        assert_ne!(
            &crate::credential::cred_store_state(fs).unwrap(),
            old_tag,
            "a replacement seed retained the old credential store state"
        );
    }
    let mut cert = [0; 512];
    if let Some(n) = fs.read(EF_EE_DEV, &mut cert) {
        certificate_binds_seed(&cert[..n], seed.expose());
    }
    assert!(
        backup_sealed(fs),
        "seed replacement reopened the export window"
    );
    let mut record = [0; LED_CONF_LEN];
    assert_eq!(fs.read(EF_LED_CONF, &mut record), Some(LED_RECORD.len()));
    assert_eq!(record, LED_RECORD);
    assert_eq!(crate::seed::global_sign_counter(fs), Ok(COUNTER));
    let mut large_blob = [0; 32];
    assert_eq!(
        fs.read(EF_LARGEBLOB, &mut large_blob),
        Some(LARGEBLOB_INITIAL.len())
    );
    assert_eq!(&large_blob[..LARGEBLOB_INITIAL.len()], LARGEBLOB_INITIAL);
    replaced
}

#[test]
fn every_seed_load_cut_keeps_the_certificate_bound_to_the_live_seed() {
    let (mut fs, _) = cut_fixture();
    let old_tag = crate::credential::cred_store_state(&mut fs).unwrap();
    rsk_fs::cut::sweep(
        cut_fixture,
        |fs| match load(fs) {
            Ok(0) => true,
            Err(CtapError::Other) => false,
            other => panic!("unexpected load result: {other:?}"),
        },
        |fs, _, completed, _| {
            let replaced = check(fs, &old_tag);
            if completed {
                assert!(replaced, "load succeeded without replacing the seed");
                assert!(
                    fs.has_data(EF_EE_DEV),
                    "load succeeded without a certificate"
                );
            }
            ensure_seed(&dev(), fs, &mut SeqRng(11)).unwrap();
            assert_eq!(check(fs, &old_tag), replaced, "recovery changed the seed");
            assert!(fs.has_data(EF_EE_DEV));
        },
    );
}

#[test]
fn interrupted_seed_load_and_certificate_recovery_converge_without_rekeying() {
    let mut reference = Fs::new(RamStorage::new());
    let initial_tag = provision(&mut reference);
    sweep_recovery(
        |fs| {
            provision(fs);
        },
        |fs, _| {
            let _ = load(fs);
        },
        |fs| {
            let _ = ensure_seed(&dev(), fs, &mut SeqRng(11));
        },
        |fs: &mut Fs<Snap>, _, _| {
            check(fs, &initial_tag);
            assert!(fs.has_data(EF_EE_DEV));
            let generation = fs.write_gen();
            ensure_seed(&dev(), fs, &mut SeqRng(13)).unwrap();
            assert_eq!(fs.write_gen(), generation, "settled recovery wrote again");
        },
    );
}
