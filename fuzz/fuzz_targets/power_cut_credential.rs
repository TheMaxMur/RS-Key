// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use minicbor::{Encoder, encode::write::Cursor};
use rsk_fido::consts::{EF_ALWAYS_UV, EF_COUNTER, EF_CRED};
use rsk_fido::seed::{cred_sign_counter, ensure_seed, report_sign_counter, set_cred_sign_counter};

pub const MODE_PREFIX: u8 = 0x90;
pub const CASE_COUNT: u8 = 3;
const NEIGHBOR: u16 = 0xB001;

pub struct Outcome {
    pub interrupted: bool,
    pub recovery_interrupted: bool,
    pub operation_stats: sequential_storage::mock_flash::FlashStatsResult,
    pub recovery_stats: sequential_storage::mock_flash::FlashStatsResult,
}

fn identity() -> rsk_crypto::Device<'static> {
    rsk_crypto::Device {
        serial_hash: &[0x22; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
        latched: false,
    }
}

fn request(rp: &str, user: &[u8], name: &str) -> Vec<u8> {
    let mut out = [0; 512];
    let mut e = Encoder::new(Cursor::new(out.as_mut_slice()));
    e.map(5).unwrap().u8(1).unwrap().bytes(&[0xCD; 32]).unwrap();
    e.u8(2)
        .unwrap()
        .map(1)
        .unwrap()
        .str("id")
        .unwrap()
        .str(rp)
        .unwrap();
    e.u8(3)
        .unwrap()
        .map(2)
        .unwrap()
        .str("id")
        .unwrap()
        .bytes(user)
        .unwrap()
        .str("name")
        .unwrap()
        .str(name)
        .unwrap();
    e.u8(4)
        .unwrap()
        .array(1)
        .unwrap()
        .map(2)
        .unwrap()
        .str("alg")
        .unwrap()
        .i64(rsk_fido::consts::ALG_ES256)
        .unwrap()
        .str("type")
        .unwrap()
        .str("public-key")
        .unwrap();
    e.u8(7)
        .unwrap()
        .map(1)
        .unwrap()
        .str("rk")
        .unwrap()
        .bool(true)
        .unwrap();
    let n = e.writer().position();
    out[..n].to_vec()
}

fn execute(fs: &mut Fs<TortureStorage>, req: &[u8], seed: u8) -> bool {
    let mut rng = ResetRng(seed);
    let mut state = rsk_fido::FidoState::new();
    let mut presence = rsk_fido::AlwaysConfirm;
    let mut ctx = rsk_fido::Ctx {
        dev: identity(),
        fs,
        rng: &mut rng,
        state: &mut state,
        presence: &mut presence,
        now_ms: 10,
    };
    rsk_fido::makecredential::make_credential(&mut ctx, req, &mut [0; 1024]).is_ok()
}

fn value(fs: &mut Fs<TortureStorage>, fid: u16) -> Option<Vec<u8>> {
    let mut out = [0; rsk_fs::MAX_VALUE_BYTES];
    fs.try_read(fid, &mut out)
        .unwrap()
        .map(|n| out[..n].to_vec())
}

fn recover(fs: &mut Fs<TortureStorage>) -> bool {
    ensure_seed(&identity(), fs, &mut ResetRng(91)).is_ok()
        && rsk_fido::credmgmt::settle_rp_records(fs).is_ok()
}

fn check(
    fs: &mut Fs<TortureStorage>,
    target: u16,
    neighbor: u16,
    before: &Option<Vec<u8>>,
    after: &Option<Vec<u8>>,
    other: &Option<Vec<u8>>,
) {
    let actual = value(fs, EF_CRED + target);
    assert!(
        actual == *before || actual == *after,
        "neither complete credential survived"
    );
    if actual.is_some() {
        let counter = report_sign_counter(fs, target).unwrap();
        if actual == *before {
            assert_eq!(counter, 73, "the preceding key's counter rolled back");
        } else if before.is_some() {
            assert!(counter == 73 || counter == 1);
        } else {
            assert_eq!(counter, 1);
        }
    }
    assert_eq!(value(fs, EF_CRED + neighbor), *other);
    assert_eq!(cred_sign_counter(fs, neighbor), Ok(Some(59)));
    assert_eq!(rsk_fido::seed::global_sign_counter(fs), Ok(73));
    assert_eq!(value(fs, NEIGHBOR).as_deref(), Some(&b"other applet"[..]));
    let mut meta = [0; 14];
    assert_eq!(fs.meta_find(NEIGHBOR, &mut meta), Some(14));
    assert_eq!(&meta, b"other metadata");
}

pub fn run(data: &[u8]) -> Outcome {
    let mode = data.get(1).copied().unwrap_or(0) % CASE_COUNT;
    let replacing = mode != 0;
    let (target, neighbor) = if replacing { (0, 1) } else { (1, 0) };
    let flash = Rc::new(RefCell::new(Mock::new(WriteCountCheck::Twice, None, true)));
    let mut dev = MockDevice {
        shared: SharedMock {
            flash: flash.clone(),
            dead: Rc::new(Cell::new(false)),
        },
        boots: 0,
    };
    let mut fs = dev.boot();
    fs.scan();
    fs.put(EF_ALWAYS_UV, &[0]).unwrap();
    ensure_seed(&identity(), &mut fs, &mut ResetRng(1)).unwrap();
    if replacing {
        assert!(execute(&mut fs, &request("example.com", &[1], "old"), 7));
    }
    assert!(execute(
        &mut fs,
        &request("other.example", &[9], "neighbor"),
        17
    ));
    if replacing {
        set_cred_sign_counter(&mut fs, target, if mode == 2 { 0 } else { 73 }).unwrap();
    }
    set_cred_sign_counter(&mut fs, neighbor, 59).unwrap();
    fs.put_counter(EF_COUNTER, &73u32.to_le_bytes()).unwrap();
    fs.put(NEIGHBOR, b"other applet").unwrap();
    fs.meta_add(NEIGHBOR, b"other metadata").unwrap();
    for i in 0..data.get(6).copied().unwrap_or(0) % 32 {
        fs.put(0xB000, &[i; 1024]).unwrap();
    }
    let before = value(&mut fs, EF_CRED + target);
    let other = value(&mut fs, EF_CRED + neighbor);
    let req = request(
        if replacing {
            "example.com"
        } else {
            "created.example"
        },
        &[1],
        "new",
    );
    let mut reference = diagnostic_mount(&dev);
    assert!(execute(&mut reference, &req, 91));
    let after = value(&mut reference, EF_CRED + target);
    assert_ne!(before, after);
    let budget = |offset| {
        u32::from(u16::from_be_bytes([
            data.get(offset).copied().unwrap_or(0),
            data.get(offset + 1).copied().unwrap_or(0),
        ]))
    };
    let start = flash.borrow().stats_snapshot();
    flash.borrow_mut().bytes_until_shutoff = Some(budget(2));
    let completed = execute(&mut fs, &req, 91);
    let operation_stats = start.compare_to(flash.borrow().stats_snapshot());
    let interrupted = dev.dead();
    if !interrupted {
        assert!(completed);
    }
    let mut observed = diagnostic_mount(&dev);
    check(&mut observed, target, neighbor, &before, &after, &other);
    let start = flash.borrow().stats_snapshot();
    fs = recovery_mount(&mut dev, budget(4));
    let recovered = recover(&mut fs);
    let recovery_stats = start.compare_to(flash.borrow().stats_snapshot());
    let recovery_interrupted = dev.dead();
    if !recovery_interrupted {
        assert!(recovered);
    }
    flash.borrow_mut().bytes_until_shutoff = None;
    dev.revive();
    fs = dev.boot();
    fs.scan();
    assert!(recover(&mut fs));
    check(&mut fs, target, neighbor, &before, &after, &other);
    let target_rp = rsk_crypto::sha256(if replacing {
        b"example.com"
    } else {
        b"created.example"
    });
    let mut counts = [0; 2];
    let neighbor_rp = rsk_crypto::sha256(b"other.example");
    rsk_fido::passkeys::for_each_rp(&identity(), &mut fs, |rp| {
        if rp.rp_id_hash == target_rp {
            counts[0] += usize::from(rp.count);
        } else {
            assert_eq!(rp.rp_id_hash, neighbor_rp);
            counts[1] += usize::from(rp.count);
        }
    });
    assert_eq!(
        counts,
        [usize::from(value(&mut fs, EF_CRED + target).is_some()), 1]
    );
    if completed {
        assert_eq!(value(&mut fs, EF_CRED + target), after);
        assert_eq!(report_sign_counter(&mut fs, target), Ok(1));
    }
    let generation = fs.write_gen();
    assert!(recover(&mut fs));
    assert_eq!(fs.write_gen(), generation, "settled boot wrote again");
    Outcome {
        interrupted,
        recovery_interrupted,
        operation_stats,
        recovery_stats,
    }
}
