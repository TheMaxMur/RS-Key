// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_crypto::{aes256gcm_decrypt, hkdf_sha256};
use rsk_ec::{Curve, PrivKey};
use rsk_piv::files::{
    EF_ATTESTATION_CERT, EF_PIN, EF_PUK, EF_RETRIES, SLOT_ATTESTATION, SLOT_CARDMGM, key_fid,
    pubkey_fid,
};
use rsk_piv::{AlwaysConfirm, PivApplet};
use rsk_sdk::tlv::{Tlv, find_tag};
use rsk_sdk::{Applet, ResBuf, Sw};
use rsk_secret::Secret;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const F9_PLAIN_LEN: usize = 1 + 48;
const F9_SEALED_LEN: usize = NONCE_LEN + F9_PLAIN_LEN + TAG_LEN;
const INFO_PIV_KEYS: &[u8] = b"PIV/KEYS";
const NEIGHBOR: u16 = 0xb001;
const HASH: [u8; 32] = [0xa5; 32];
const SERIAL: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const INS_GET_METADATA: u8 = 0xf7;

#[derive(Clone, Copy, Debug)]
enum Provision {
    First,
    Recreate,
    Repair,
    Empty,
}

pub struct Outcome {
    pub interrupted: bool,
    pub recovery_interrupted: bool,
    pub operation_stats: sequential_storage::mock_flash::FlashStatsResult,
    pub recovery_stats: sequential_storage::mock_flash::FlashStatsResult,
}

fn identity() -> rsk_crypto::Device<'static> {
    rsk_crypto::Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
        latched: false,
    }
}

fn budget(data: &[u8], offset: usize) -> u32 {
    u16::from_be_bytes([
        data.get(offset).copied().unwrap_or(0),
        data.get(offset + 1).copied().unwrap_or(0),
    ])
    .into()
}

fn select(fs: &mut Fs<TortureStorage>, rng: &RefCell<ResetRng>) -> Sw {
    let presence = RefCell::new(AlwaysConfirm);
    let mut app = PivApplet::new(SERIAL, HASH, None, rng, &presence);
    let mut out = [0xa5; 256];
    let mut response = ResBuf::new(&mut out);
    let sw = Applet::select(&mut app, false, fs, &mut response);
    if sw != Sw::OK {
        assert!(response.as_slice().is_empty());
        assert_eq!(out, [0xa5; 256]);
    }
    sw
}

fn remount(dev: &mut MockDevice) -> Fs<TortureStorage> {
    dev.shared.flash.borrow_mut().bytes_until_shutoff = None;
    dev.revive();
    let mut fs = dev.boot();
    fs.scan();
    fs
}

fn point(fs: &mut Fs<TortureStorage>) -> Option<Vec<u8>> {
    let mut blob = Secret::<[u8; F9_SEALED_LEN]>::zeroed();
    let n = fs.read_key(key_fid(SLOT_ATTESTATION), blob.expose_mut())?;
    assert_eq!(n, F9_SEALED_LEN, "a cut published a partial F9 key");
    let mut nonce = [0; NONCE_LEN];
    nonce.copy_from_slice(&blob.expose()[..NONCE_LEN]);
    let mut tag = [0; TAG_LEN];
    tag.copy_from_slice(&blob.expose()[n - TAG_LEN..n]);
    let dev = identity();
    let mut root = dev.derive_kbase();
    let mut key = Secret::<[u8; 32]>::zeroed();
    hkdf_sha256(
        dev.serial_hash,
        root.expose(),
        INFO_PIV_KEYS,
        key.expose_mut(),
    )
    .unwrap();
    root.wipe();
    // An independent record decoder keeps the oracle outside PIV's key loader.
    let plain = &mut blob.expose_mut()[NONCE_LEN..n - TAG_LEN];
    aes256gcm_decrypt(key.expose(), &nonce, dev.serial_hash, plain, &tag).unwrap();
    key.wipe();
    assert_eq!(plain[0], Curve::P384.id());
    let private = PrivKey::from_scalar(Curve::P384, &plain[1..]).unwrap();
    let mut public = [0; 97];
    assert_eq!(private.public_point(&mut public).unwrap(), public.len());
    Some(public.to_vec())
}

fn check(fs: &mut Fs<TortureStorage>, rng: &RefCell<ResetRng>, complete: bool) {
    let public = point(fs);
    let mut object = [0; 1024];
    let certificate = fs.read(EF_ATTESTATION_CERT, &mut object).filter(|n| *n > 0);
    if complete {
        assert!(
            public.is_some() && certificate.is_some(),
            "a healthy SELECT left F9 incomplete"
        );
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, rng, &presence);
        let mut out = [0; 256];
        let mut response = ResBuf::new(&mut out);
        assert_eq!(
            app.process(
                &rsk_sdk::apdu::Apdu::parse(&[0, INS_GET_METADATA, 0, SLOT_ATTESTATION]).unwrap(),
                fs,
                &mut response,
            ),
            Sw::OK
        );
        let metadata = find_tag(response.as_slice(), 4).unwrap();
        assert_eq!(
            find_tag(metadata, 0x86).unwrap(),
            public.as_deref().unwrap(),
            "healthy F9 recovery published a preceding public cache"
        );
    }
    if let (Some(public), Some(n)) = (public, certificate) {
        let der = find_tag(&object[..n], 0x70).unwrap();
        let outer: Vec<_> = Tlv::new(der).collect();
        assert_eq!(outer.len(), 1);
        let fields: Vec<_> = Tlv::new(outer[0].1).collect();
        let tbs: Vec<_> = Tlv::new(fields[0].1).collect();
        let spki: Vec<_> = Tlv::new(tbs[6].1).collect();
        assert_eq!(spki[1].0, 3);
        assert_eq!(
            spki[1].1,
            [&[0], public.as_slice()].concat(),
            "a cut retained the preceding certificate over the current F9 key"
        );
    }
}

fn check_preserved(
    fs: &mut Fs<TortureStorage>,
    flash: &Rc<RefCell<Mock>>,
    gates: &[(u16, Vec<u8>)],
    counter: &[u8],
) {
    assert_eq!(record(fs, NEIGHBOR), b"unrelated record");
    let mut metadata = [0; 32];
    let n = fs.meta_find(NEIGHBOR, &mut metadata).unwrap();
    assert_eq!(&metadata[..n], b"unrelated metadata");
    for (fid, before) in gates {
        assert_eq!(
            &record(fs, *fid),
            before,
            "F9 recovery changed gate {fid:04x}"
        );
    }
    assert_eq!(rsk_fido::seed::global_sign_counter(fs), Ok(73));
    assert_eq!(
        &flash.borrow().as_bytes()[COUNTER_RANGE.start as usize..COUNTER_RANGE.end as usize],
        counter
    );
}

pub fn run(data: &[u8]) -> Outcome {
    let flash = Rc::new(RefCell::new(Mock::new(WriteCountCheck::Twice, None, true)));
    let mut dev = MockDevice {
        shared: SharedMock {
            flash: flash.clone(),
            dead: Rc::new(Cell::new(false)),
        },
        boots: 0,
    };
    let mode = match data.first().copied().unwrap_or(0) & 3 {
        0 => Provision::First,
        1 => Provision::Recreate,
        2 => Provision::Repair,
        _ => Provision::Empty,
    };
    let rng = RefCell::new(ResetRng(data.get(1).copied().unwrap_or(7)));
    let mut fs = dev.boot();
    fs.scan();
    assert_eq!(select(&mut fs, &rng), Sw::OK, "PIV seeding must complete");
    let original_key = record(&mut fs, key_fid(SLOT_ATTESTATION).get());
    match mode {
        Provision::First => {
            fs.delete_key(key_fid(SLOT_ATTESTATION)).unwrap();
            fs.delete(EF_ATTESTATION_CERT).unwrap();
        }
        Provision::Recreate => {
            fs.delete_key(key_fid(SLOT_ATTESTATION)).unwrap();
        }
        Provision::Repair => {
            fs.delete(EF_ATTESTATION_CERT).unwrap();
        }
        Provision::Empty => {
            fs.put(EF_ATTESTATION_CERT, &[]).unwrap();
        }
    }
    if data.first().is_some_and(|b| b & 4 != 0)
        && matches!(mode, Provision::Repair | Provision::Empty)
    {
        fs.put(pubkey_fid(SLOT_ATTESTATION), &[0x5a; 97]).unwrap();
    }
    fs.put(NEIGHBOR, b"unrelated record").unwrap();
    fs.meta_add(NEIGHBOR, b"unrelated metadata").unwrap();
    let gates = [EF_PIN, EF_PUK, EF_RETRIES, key_fid(SLOT_CARDMGM).get()]
        .map(|fid| (fid, record(&mut fs, fid)));
    fs.put_counter(rsk_fido::consts::EF_COUNTER, &73u32.to_le_bytes())
        .unwrap();
    for value in 0..data.get(6).copied().unwrap_or(0) % 32 {
        fs.put(0xb000, &[value; 1024]).unwrap();
    }
    let counter_bytes = flash.borrow().as_bytes()
        [COUNTER_RANGE.start as usize..COUNTER_RANGE.end as usize]
        .to_vec();
    let before = flash.borrow().stats_snapshot();
    flash.borrow_mut().bytes_until_shutoff = Some(budget(data, 2));
    let sw = select(&mut fs, &rng);
    let operation_stats = before.compare_to(flash.borrow().stats_snapshot());
    let interrupted = dev.dead();
    if !interrupted {
        assert_eq!(sw, Sw::OK, "healthy {mode:?} provisioning was refused");
    }
    fs = remount(&mut dev);
    check_preserved(&mut fs, &flash, &gates, &counter_bytes);
    check(&mut fs, &rng, !interrupted);
    let committed_key = record(&mut fs, key_fid(SLOT_ATTESTATION).get());
    let before = flash.borrow().stats_snapshot();
    flash.borrow_mut().bytes_until_shutoff = Some(budget(data, 4));
    let sw = select(&mut fs, &rng);
    let recovery_stats = before.compare_to(flash.borrow().stats_snapshot());
    let recovery_interrupted = dev.dead();
    if !recovery_interrupted {
        assert_eq!(sw, Sw::OK, "healthy F9 recovery was refused");
    }
    fs = remount(&mut dev);
    check_preserved(&mut fs, &flash, &gates, &counter_bytes);
    check(&mut fs, &rng, !recovery_interrupted);
    let recovered_key = record(&mut fs, key_fid(SLOT_ATTESTATION).get());
    if !committed_key.is_empty() {
        assert_eq!(
            recovered_key, committed_key,
            "recovery replaced committed F9"
        );
    }
    assert_eq!(select(&mut fs, &rng), Sw::OK);
    check(&mut fs, &rng, true);
    if !recovered_key.is_empty() {
        assert_eq!(
            record(&mut fs, key_fid(SLOT_ATTESTATION).get()),
            recovered_key,
            "healthy retry replaced committed F9"
        );
    }
    if matches!(mode, Provision::Repair | Provision::Empty) {
        assert_eq!(
            record(&mut fs, key_fid(SLOT_ATTESTATION).get()),
            original_key,
            "certificate recovery replaced the existing F9 key"
        );
    }
    let key = record(&mut fs, key_fid(SLOT_ATTESTATION).get());
    fs = remount(&mut dev);
    let generation = fs.write_gen();
    assert_eq!(select(&mut fs, &rng), Sw::OK);
    check(&mut fs, &rng, true);
    assert_eq!(
        fs.write_gen(),
        generation,
        "settled F9 provisioning was not idempotent"
    );
    assert_eq!(record(&mut fs, key_fid(SLOT_ATTESTATION).get()), key);
    check_preserved(&mut fs, &flash, &gates, &counter_bytes);
    Outcome {
        interrupted,
        recovery_interrupted,
        operation_stats,
        recovery_stats,
    }
}
