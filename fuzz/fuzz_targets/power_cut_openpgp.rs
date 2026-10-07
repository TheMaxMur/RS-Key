// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_crypto::PinKdf;
use rsk_fs::Sealed;
use rsk_openpgp::consts::*;
use rsk_openpgp::pin::{Session, change_pin, load_dek, put_reset_code, reset_retry, verify};
use rsk_sdk::Sw;
use rsk_secret::Secret;

const NEW_PIN: &[u8] = b"24681357";
const OLD_CODE: &[u8] = b"resetme0";
const NEW_CODE: &[u8] = b"resetnew1";
const PW1_RETRY_AT: usize = 4;
const RC_RETRY_AT: usize = 5;
const PW3_RETRY_AT: usize = 6;

#[derive(Clone, Copy, Debug)]
enum Command {
    ChangePw1,
    ChangePw3,
    ResetAdmin,
    ResetCode,
    SetCode,
    RevokeCode,
}

pub struct Outcome {
    pub interrupted: bool,
    pub recovery_interrupted: bool,
    pub operation_stats: sequential_storage::mock_flash::FlashStatsResult,
    pub recovery_stats: sequential_storage::mock_flash::FlashStatsResult,
}

fn identity() -> rsk_crypto::Device<'static> {
    rsk_crypto::Device {
        serial_hash: &[0xA5; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
        latched: false,
    }
}

fn initialise(fs: &mut Fs<TortureStorage>, expected: &Secret<[u8; DEK_SIZE]>) {
    for (fid, pin, nonce) in [(EF_DEK_PW1, PW1_DEFAULT, 1), (EF_DEK_PW3, PW3_DEFAULT, 2)] {
        let mut box_bytes = [0; DEK_FILE_SIZE];
        box_bytes[0] = DEK_FORMAT_V3;
        let mut session = identity().pin_derive_session(pin);
        identity()
            .encrypt_with_aad(
                session.expose(),
                expected.expose(),
                PinKdf::V2,
                &[nonce; 12],
                &mut box_bytes[1..],
            )
            .unwrap();
        session.wipe();
        fs.put_key(fid, Sealed::wrap(&box_bytes)).unwrap();
    }
    // Both copies landed before the first-boot verifier writes; this also avoids
    // generating an unrelated attestation key in every PIN durability input.
    rsk_openpgp::scan_files(&identity(), fs, &mut ResetRng(1)).unwrap();
}

fn admin(fs: &mut Fs<TortureStorage>, sess: &mut Session, rng: &mut ResetRng) -> Sw {
    verify(&identity(), fs, sess, rng, 0, PW3_MODE83, PW3_DEFAULT)
}

fn require(sw: Sw) -> Result<(), Sw> {
    if sw == Sw::OK { Ok(()) } else { Err(sw) }
}

fn execute(
    fs: &mut Fs<TortureStorage>,
    sess: &mut Session,
    rng: &mut ResetRng,
    cmd: Command,
) -> Sw {
    match cmd {
        Command::ChangePw1 => change_pin(
            &identity(),
            fs,
            sess,
            rng,
            0,
            PW1_MODE81,
            &[PW1_DEFAULT, NEW_PIN].concat(),
        ),
        Command::ChangePw3 => change_pin(
            &identity(),
            fs,
            sess,
            rng,
            0,
            PW3_MODE83,
            &[PW3_DEFAULT, NEW_PIN].concat(),
        ),
        Command::ResetAdmin => reset_retry(&identity(), fs, sess, rng, 2, PW1_MODE81, NEW_PIN),
        Command::ResetCode => reset_retry(
            &identity(),
            fs,
            sess,
            rng,
            0,
            PW1_MODE81,
            &[OLD_CODE, NEW_PIN].concat(),
        ),
        Command::SetCode => put_reset_code(&identity(), fs, sess, rng, NEW_CODE),
        Command::RevokeCode => put_reset_code(&identity(), fs, sess, rng, &[]),
    }
}

fn standing_pin(fs: &mut Fs<TortureStorage>, fid: u16, old: &'static [u8]) -> &'static [u8] {
    let mut reference = [0; 34];
    assert_eq!(fs.read(fid, &mut reference), Some(reference.len()));
    let new = identity().pin_derive_verifier(NEW_PIN);
    if reference[2..] == new.expose()[..] {
        assert_eq!(usize::from(reference[0]), NEW_PIN.len());
        NEW_PIN
    } else {
        assert_eq!(
            &reference[2..],
            identity().pin_derive_verifier(old).expose()
        );
        assert_eq!(usize::from(reference[0]), old.len());
        old
    }
}

fn recover(
    fs: &mut Fs<TortureStorage>,
    rng: &mut ResetRng,
    cmd: Command,
    out: &mut Secret<[u8; DEK_SIZE]>,
) -> Result<(), Sw> {
    rsk_openpgp::scan_files(&identity(), fs, rng).map_err(|_| Sw::MEMORY_FAILURE)?;
    let mut sess = Session::new();
    if matches!(cmd, Command::RevokeCode) {
        require(admin(fs, &mut sess, rng))?;
        load_dek(&identity(), fs, &sess, out)?;
        require(put_reset_code(&identity(), fs, &mut sess, rng, &[]))?;
        for fid in [EF_RC, EF_DEK_RC.get(), EF_DEK_STAGE_RC.get()] {
            assert_eq!(fs.read(fid, &mut [0; DEK_FILE_SIZE]), None);
        }
        let mut counters = [0; 8];
        fs.read(EF_PW_PRIV, &mut counters).unwrap();
        assert_eq!(counters[RC_RETRY_AT], 0);
        sess.reset();
        assert_eq!(
            reset_retry(
                &identity(),
                fs,
                &mut sess,
                rng,
                0,
                PW1_MODE81,
                &[OLD_CODE, NEW_PIN].concat(),
            ),
            Sw::REFERENCE_NOT_FOUND,
        );
        assert!(!sess.has_rc && !sess.has_pw1 && !sess.has_pw3);
        return Ok(());
    }
    if matches!(cmd, Command::SetCode) {
        require(admin(fs, &mut sess, rng))?;
        load_dek(&identity(), fs, &sess, out)?;
        require(put_reset_code(&identity(), fs, &mut sess, rng, NEW_CODE))?;
        sess.reset();
        require(reset_retry(
            &identity(),
            fs,
            &mut sess,
            rng,
            0,
            PW1_MODE81,
            &[NEW_CODE, PW1_DEFAULT].concat(),
        ))?;
        return load_dek(&identity(), fs, &sess, out);
    }
    let (fid, mode, old) = if matches!(cmd, Command::ChangePw3) {
        (EF_PW3, PW3_MODE83, PW3_DEFAULT)
    } else {
        (EF_PW1, PW1_MODE81, PW1_DEFAULT)
    };
    let pin = standing_pin(fs, fid, old);
    let mut counters = [0; 8];
    fs.read(EF_PW_PRIV, &mut counters).unwrap();
    let at = if fid == EF_PW1 {
        PW1_RETRY_AT
    } else {
        PW3_RETRY_AT
    };
    let pin = if counters[at] == 0 && fid == EF_PW1 {
        require(admin(fs, &mut sess, rng))?;
        require(reset_retry(
            &identity(),
            fs,
            &mut sess,
            rng,
            2,
            PW1_MODE81,
            NEW_PIN,
        ))?;
        NEW_PIN
    } else {
        pin
    };
    sess.reset();
    require(verify(&identity(), fs, &mut sess, rng, 0, mode, pin))?;
    load_dek(&identity(), fs, &sess, out)
}

fn budget(data: &[u8], offset: usize) -> u32 {
    u16::from_be_bytes([
        data.get(offset).copied().unwrap_or(0),
        data.get(offset + 1).copied().unwrap_or(0),
    ])
    .into()
}

fn revive(dev: &mut MockDevice) -> Fs<TortureStorage> {
    dev.shared.flash.borrow_mut().bytes_until_shutoff = None;
    dev.revive();
    let mut fs = dev.boot();
    fs.scan();
    fs
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
    let cmd = match data.get(1).copied().unwrap_or(0) % 6 {
        0 => Command::ChangePw1,
        1 => Command::ChangePw3,
        2 => Command::ResetAdmin,
        3 => Command::ResetCode,
        4 => Command::SetCode,
        _ => Command::RevokeCode,
    };
    let mut expected = Secret::<[u8; DEK_SIZE]>::zeroed();
    for (i, byte) in expected.expose_mut().iter_mut().enumerate() {
        *byte = u8::try_from(i).unwrap();
    }
    let mut fs = dev.boot();
    fs.scan();
    initialise(&mut fs, &expected);
    fs.put(0xB001, b"unrelated record").unwrap();
    fs.put_counter(rsk_fido::consts::EF_COUNTER, &73u32.to_le_bytes())
        .unwrap();
    let mut rng = ResetRng(7);
    let mut sess = Session::new();
    if matches!(
        cmd,
        Command::ResetAdmin | Command::ResetCode | Command::SetCode | Command::RevokeCode
    ) {
        assert_eq!(admin(&mut fs, &mut sess, &mut rng), Sw::OK);
    }
    if matches!(cmd, Command::ResetCode | Command::RevokeCode)
        || (matches!(cmd, Command::SetCode) && data.first().is_some_and(|b| b & 1 != 0))
    {
        assert_eq!(
            put_reset_code(&identity(), &mut fs, &mut sess, &mut rng, OLD_CODE),
            Sw::OK
        );
    }
    if matches!(cmd, Command::ResetCode) {
        sess.reset();
    }
    if matches!(cmd, Command::RevokeCode) && data.first().is_some_and(|b| b & 1 != 0) {
        let mut stage = Secret::<[u8; 1 + DEK_FILE_SIZE]>::zeroed();
        stage.expose_mut()[0] = u8::try_from(EF_DEK_RC.get() & 0xff).unwrap();
        assert_eq!(
            fs.read_key(EF_DEK_RC, &mut stage.expose_mut()[1..]),
            Some(DEK_FILE_SIZE),
        );
        fs.put_key(EF_DEK_STAGE_RC, Sealed::wrap(stage.expose()))
            .unwrap();
    }
    if matches!(cmd, Command::ResetAdmin | Command::ResetCode)
        && data.first().is_some_and(|b| b & 2 != 0)
    {
        let mut counters = [0; 8];
        let n = fs.read(EF_PW_PRIV, &mut counters).unwrap();
        counters[PW1_RETRY_AT] = 0;
        fs.put(EF_PW_PRIV, &counters[..n]).unwrap();
    }
    for value in 0..data.get(6).copied().unwrap_or(0) % 32 {
        fs.put(0xB000, &[value; 1024]).unwrap();
    }
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    let counter_bytes = flash.borrow().as_bytes()
        [COUNTER_RANGE.start as usize..COUNTER_RANGE.end as usize]
        .to_vec();
    let before = flash.borrow().stats_snapshot();
    flash.borrow_mut().bytes_until_shutoff = Some(budget(data, 2));
    let sw = execute(&mut fs, &mut sess, &mut rng, cmd);
    let operation_stats = before.compare_to(flash.borrow().stats_snapshot());
    let interrupted = dev.dead();
    if !interrupted {
        assert_eq!(sw, Sw::OK, "a healthy {cmd:?} was refused");
    }
    fs = revive(&mut dev);
    let before = flash.borrow().stats_snapshot();
    flash.borrow_mut().bytes_until_shutoff = Some(budget(data, 4));
    let mut out = Secret::<[u8; DEK_SIZE]>::zeroed();
    let recovered = recover(&mut fs, &mut rng, cmd, &mut out);
    let recovery_stats = before.compare_to(flash.borrow().stats_snapshot());
    let recovery_interrupted = dev.dead();
    if recovered.is_ok() {
        assert_eq!(out.expose(), expected.expose());
    }
    if !recovery_interrupted {
        recovered.expect("healthy recovery must keep the standing PIN and original DEK");
    }
    fs = revive(&mut dev);
    let mut out = Secret::<[u8; DEK_SIZE]>::zeroed();
    recover(&mut fs, &mut rng, cmd, &mut out)
        .expect("second healthy recovery must reopen the original DEK");
    assert_eq!(out.expose(), expected.expose());
    fs = revive(&mut dev);
    assert_eq!(record(&mut fs, 0xB001), b"unrelated record");
    assert_eq!(rsk_fido::seed::global_sign_counter(&mut fs), Ok(73));
    assert_eq!(
        flash.borrow().as_bytes()[COUNTER_RANGE.start as usize..COUNTER_RANGE.end as usize],
        counter_bytes
    );
    Outcome {
        interrupted,
        recovery_interrupted,
        operation_stats,
        recovery_stats,
    }
}
