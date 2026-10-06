// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fido::consts::{
    EF_BACKUP_SEALED, EF_COUNTER, EF_CRED_STATE, EF_EE_DEV, EF_LARGEBLOB, LARGEBLOB_INITIAL,
    VENDOR_BACKUP_LOAD,
};
use rsk_fido::ec::P256Key;
use rsk_sdk::tlv::Tlv;
use rsk_secret::Secret;

const OLD_SEED: [u8; 32] = [0x5A; 32];
const MSE_KEY: [u8; 32] = [0x42; 32];
const MSE_AAD: [u8; 65] = [4; 65];
const SIGN_COUNTER: u32 = 73;
pub const ERASE_BYTES: usize = <Mock as NorFlash>::ERASE_SIZE;

pub struct Outcome {
    pub interrupted: bool,
    pub recovery_interrupted: bool,
    pub replaced: bool,
    pub load_stats: sequential_storage::mock_flash::FlashStatsResult,
}

fn budget(data: &[u8], offset: usize) -> u32 {
    u16::from_be_bytes([
        data.get(offset).copied().unwrap_or(0),
        data.get(offset + 1).copied().unwrap_or(0),
    ])
    .into()
}

fn check(fs: &mut Fs<TortureStorage>, identity: &rsk_crypto::Device, new: &[u8; 32]) -> bool {
    let seed = rsk_fido::seed::load_keydev(identity, fs).expect("a cut lost the device seed");
    assert!(
        seed.expose() == &OLD_SEED || seed.expose() == new,
        "torn seed"
    );
    let replaced = seed.expose() == new;
    if replaced {
        let mut tag = [0; rsk_fido::consts::CRED_STATE_LEN];
        assert_eq!(fs.read(EF_CRED_STATE, &mut tag), Some(tag.len()));
        assert_ne!(
            tag,
            [0x21; rsk_fido::consts::CRED_STATE_LEN],
            "stale store tag"
        );
    }
    let mut cert = [0; 512];
    if let Some(n) = fs.read(EF_EE_DEV, &mut cert) {
        let outer: Vec<_> = Tlv::new(&cert[..n]).collect();
        assert_eq!(outer.len(), 1);
        let fields: Vec<_> = Tlv::new(outer[0].1).collect();
        let body: Vec<_> = Tlv::new(fields[0].1).collect();
        let spki: Vec<_> = Tlv::new(body[6].1).collect();
        let key = P256Key::from_scalar(seed.expose()).unwrap();
        let (x, y) = key.public_xy();
        let mut public = vec![0, 4];
        public.extend_from_slice(&x);
        public.extend_from_slice(&y);
        assert_eq!(
            spki[1].1, public,
            "a cut retained the superseded certificate"
        );
    }
    assert!(rsk_fido::vendor::backup_sealed(fs), "a cut reopened backup");
    assert_eq!(rsk_fido::seed::global_sign_counter(fs), Ok(SIGN_COUNTER));
    let mut blob = [0; 32];
    assert_eq!(
        fs.read(EF_LARGEBLOB, &mut blob),
        Some(LARGEBLOB_INITIAL.len())
    );
    assert_eq!(&blob[..LARGEBLOB_INITIAL.len()], LARGEBLOB_INITIAL);
    replaced
}

/// Bytes select pre-cut churn, LOAD's cut, recovery's cut and the new seed.
pub fn run(data: &[u8]) -> Outcome {
    let flash = Rc::new(RefCell::new(Mock::new(WriteCountCheck::Twice, None, true)));
    let mut dev = MockDevice {
        shared: SharedMock {
            flash: flash.clone(),
            dead: Rc::new(Cell::new(false)),
        },
        boots: 0,
    };
    let identity = rsk_crypto::Device {
        serial_hash: &[0xA5; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
        latched: false,
    };
    let mut fs = dev.boot();
    fs.scan();
    let mut rng = ResetRng(1);
    rsk_fido::seed::encrypt_keydev_f1(&identity, &mut fs, &OLD_SEED).unwrap();
    rsk_fido::seed::ensure_seed(&identity, &mut fs, &mut rng).unwrap();
    fs.put(EF_CRED_STATE, &[0x21; rsk_fido::consts::CRED_STATE_LEN])
        .unwrap();
    fs.put(EF_BACKUP_SEALED, &[1]).unwrap();
    fs.put_counter(EF_COUNTER, &SIGN_COUNTER.to_le_bytes())
        .unwrap();
    for value in 0..data.get(1).copied().unwrap_or(0) % 64 {
        fs.put(0xB000, &[value; 1024]).unwrap();
    }

    let mut new = [0x33; 32];
    new[31] = data.get(6).copied().unwrap_or(0x33);
    let nonce = [0x24; 12];
    let mut wrapped = Secret::new(new);
    let tag =
        rsk_crypto::chacha20poly1305_encrypt(&MSE_KEY, &nonce, &MSE_AAD, wrapped.expose_mut());
    let mut blob = [0; 60];
    blob[..12].copy_from_slice(&nonce);
    blob[12..44].copy_from_slice(wrapped.expose());
    blob[44..].copy_from_slice(&tag);
    wrapped.wipe();
    let mut request = [0; 128];
    let mut e = minicbor::Encoder::new(minicbor::encode::write::Cursor::new(&mut request[..]));
    e.map(2)
        .unwrap()
        .u8(1)
        .unwrap()
        .u64(VENDOR_BACKUP_LOAD)
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
    let mut state = rsk_fido::FidoState::new();
    state.establish_mse_for_test(MSE_KEY, MSE_AAD);
    let before = flash.borrow().stats_snapshot();
    flash.borrow_mut().bytes_until_shutoff = Some(budget(data, 2));
    let result = rsk_fido::vendor::vendor(
        &mut rsk_fido::Ctx {
            dev: identity,
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
            presence: &mut rsk_fido::AlwaysConfirm,
        },
        &request[..n],
        &mut [0; 16],
    );
    let load_stats = before.compare_to(flash.borrow().stats_snapshot());
    assert!(state.take_mse().is_none(), "LOAD kept its spent channel");
    assert!(
        matches!(result, Ok(0) | Err(rsk_fido::CtapError::Other)),
        "{result:?}"
    );
    let interrupted = dev.dead();
    flash.borrow_mut().bytes_until_shutoff = None;
    dev.revive();
    fs = dev.boot();
    fs.scan();
    let replaced = check(&mut fs, &identity, &new);
    if result.is_ok() {
        assert!(replaced, "LOAD succeeded without the new seed");
        assert!(
            fs.has_data(EF_EE_DEV),
            "LOAD succeeded without its certificate"
        );
    }

    flash.borrow_mut().bytes_until_shutoff = Some(budget(data, 4));
    let _ = rsk_fido::seed::ensure_seed(&identity, &mut fs, &mut rng);
    let recovery_interrupted = dev.dead();
    flash.borrow_mut().bytes_until_shutoff = None;
    dev.revive();
    fs = dev.boot();
    fs.scan();
    assert_eq!(
        check(&mut fs, &identity, &new),
        replaced,
        "recovery rekeyed the device"
    );
    rsk_fido::seed::ensure_seed(&identity, &mut fs, &mut rng).unwrap();
    assert_eq!(check(&mut fs, &identity, &new), replaced);
    assert!(fs.has_data(EF_EE_DEV));
    let generation = fs.write_gen();
    rsk_fido::seed::ensure_seed(&identity, &mut fs, &mut rng).unwrap();
    assert_eq!(fs.write_gen(), generation, "settled recovery wrote again");
    Outcome {
        interrupted,
        recovery_interrupted,
        replaced,
        load_stats,
    }
}
