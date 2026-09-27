// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

/// A 9B key and what it is used under.
#[derive(Clone, Copy, Debug)]
struct Mgm {
    algo: u8,
    touch: u8,
    key: &'static [u8],
}

const FACTORY: Mgm = Mgm {
    algo: ALGO_AES192,
    touch: TOUCHPOLICY_NEVER,
    key: &DEFAULT_MGM,
};
const AES256_KEY: [u8; 32] = [0x5A; 32];
const AES192_KEY: [u8; 24] = [0x3C; 24];
const AES192_KEY_2: [u8; 24] = [0xC3; 24];
const TDES_KEY: [u8; 24] = [0x69; 24];

fn dev() -> Device<'static> {
    Device {
        serial_hash: &HASH,
        serial_id: &SERIAL,
        otp_key: None,
    }
}

/// Whether a mutual authentication on 9B with `m`'s key under its algorithm
/// completes.
fn authenticates<S: Storage>(app: &mut PivApplet, fs: &mut Fs<S>, m: Mgm) -> bool {
    let n = if m.algo == ALGO_3DES { 8 } else { 16 };
    let (sw, wit) = run(
        app,
        fs,
        INS_AUTHENTICATE,
        m.algo,
        SLOT_CARDMGM,
        &[0x7C, 0x02, 0x80, 0x00],
    );
    let Some(w) = wit.get(4..4 + n).filter(|_| sw == Sw::OK) else {
        return false;
    };
    let mut w = w.to_vec();
    if m.algo == ALGO_3DES {
        rsk_crypto::des3_decrypt_block(
            m.key.try_into().unwrap(),
            w.as_mut_slice().try_into().unwrap(),
        );
    } else {
        rsk_crypto::aes_ecb_decrypt_block(m.key, w.as_mut_slice().try_into().unwrap()).unwrap();
    }
    let len = u8::try_from(n).unwrap();
    let mut msg = vec![0x7C, 4 + 2 * len, 0x80, len];
    msg.extend_from_slice(&w);
    msg.extend_from_slice(&[0x81, len]);
    msg.extend(std::iter::repeat_n(0xA5, n));
    run(app, fs, INS_AUTHENTICATE, m.algo, SLOT_CARDMGM, &msg).0 == Sw::OK
}

/// The touch policy `m` authenticates under: `NEVER` if it does with the touch
/// declined, `ALWAYS` if only with it, `None` if not at all.
fn touch_in_force<S: Storage>(
    app: &mut PivApplet,
    fs: &mut Fs<S>,
    pres: &RefCell<Scripted>,
    m: Mgm,
) -> Option<u8> {
    pres.borrow_mut().confirm = false;
    let bare = authenticates(app, fs, m);
    pres.borrow_mut().confirm = true;
    if bare {
        Some(TOUCHPOLICY_NEVER)
    } else {
        authenticates(app, fs, m).then_some(TOUCHPOLICY_ALWAYS)
    }
}

/// The algorithm and touch policy `GET METADATA 9B` reports.
fn metadata<S: Storage>(app: &mut PivApplet, fs: &mut Fs<S>) -> (u8, u8) {
    let (sw, md) = run(app, fs, INS_GET_METADATA, 0, SLOT_CARDMGM, &[]);
    assert_eq!(sw, Sw::OK);
    (
        find_tag(&md, 0x01).unwrap()[0],
        find_tag(&md, 0x02).unwrap()[1],
    )
}

/// Authenticate with `from`, then SET MANAGEMENT KEY to `to`.
fn change<S: Storage>(app: &mut PivApplet, fs: &mut Fs<S>, from: Mgm, to: Mgm) -> Sw {
    assert!(
        authenticates(app, fs, from),
        "{from:?} does not authenticate"
    );
    let mut body = vec![to.algo, SLOT_CARDMGM, u8::try_from(to.key.len()).unwrap()];
    body.extend_from_slice(to.key);
    let p2 = if to.touch == TOUCHPOLICY_ALWAYS {
        0xFE
    } else {
        0xFF
    };
    run(app, fs, INS_SET_MGMKEY, 0xFF, p2, &body).0
}

/// SET MANAGEMENT KEY once wrote the key and its algorithm head as two records, and
/// a cut between them could leave either under the other's algorithm or touch
/// policy. Cut at every mutation, then a new boot's SELECT: exactly one key
/// authenticates, under its own algorithm, behind its own touch policy.
#[test]
fn a_torn_management_key_change_leaves_one_whole_key() {
    let tdes = Mgm {
        algo: ALGO_3DES,
        touch: TOUCHPOLICY_NEVER,
        key: &TDES_KEY,
    };
    let aes192_touch = Mgm {
        algo: ALGO_AES192,
        touch: TOUCHPOLICY_ALWAYS,
        key: &AES192_KEY,
    };
    let aes256 = |touch| Mgm {
        algo: ALGO_AES256,
        touch,
        key: &AES256_KEY,
    };
    let mut changes = vec![
        (FACTORY, aes256(TOUCHPOLICY_ALWAYS)),
        (
            aes192_touch,
            Mgm {
                touch: TOUCHPOLICY_NEVER,
                key: &AES192_KEY_2,
                ..aes192_touch
            },
        ),
        (tdes, aes256(TOUCHPOLICY_NEVER)),
    ];
    // The FIPS-style profile takes no new 3DES key; the one planted above it serves.
    if cfg!(not(feature = "fips-profile")) {
        changes.push((FACTORY, tdes));
    }
    for (from, to) in changes {
        let rng = RefCell::new(TestRng(7));
        let pres = RefCell::new(Scripted { confirm: true });
        let app_on = || PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        rsk_fs::cut::sweep(
            || {
                let (mut fs, medium) = new_cut_fs();
                select(&mut app_on(), &mut fs);
                files::mgm_put(
                    &dev(),
                    &mut fs,
                    &mut TestRng(5),
                    from.algo,
                    from.touch,
                    from.key,
                )
                .unwrap();
                fs.meta_add(
                    key_fid(SLOT_CARDMGM).get(),
                    &[from.algo, MGM_PIN_POLICY, from.touch],
                )
                .unwrap();
                (fs, medium)
            },
            |fs| {
                let mut app = app_on();
                select(&mut app, fs);
                change(&mut app, fs, from, to) == Sw::OK
            },
            |fs, budget, completed, medium| {
                let mut app = app_on();
                select(&mut app, fs);
                let new = touch_in_force(&mut app, fs, &pres, to);
                let old = touch_in_force(&mut app, fs, &pres, from);
                assert!(
                    new.is_some() != old.is_some(),
                    "{from:?} to {to:?}, budget {budget}: new {new:?}, old {old:?} — {:?}",
                    medium.ops()
                );
                assert!(
                    !completed || new.is_some(),
                    "{to:?}, budget {budget}: answered OK and the new key is not in force"
                );
                let (m, touch) = if new.is_some() {
                    (to, new)
                } else {
                    (from, old)
                };
                assert_eq!(
                    touch,
                    Some(m.touch),
                    "{from:?} to {to:?}, budget {budget}: the key in force is behind another touch policy"
                );
                assert_eq!(metadata(&mut app, fs), (m.algo, m.touch));
            },
        );
    }
}

/// A change whose key write the flash refuses answers 6581 and leaves the old key
/// in force as it was, touch policy included, in the same power cycle: no boot
/// pass comes between it and the next command.
#[test]
fn a_refused_key_write_leaves_the_old_key_as_it_was() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(Scripted { confirm: true });
    let (mut fs, refuse) = refusing();
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut app, &mut fs);
    let from = Mgm {
        algo: ALGO_AES192,
        touch: TOUCHPOLICY_ALWAYS,
        key: &AES192_KEY,
    };
    let to = Mgm {
        algo: ALGO_AES256,
        touch: TOUCHPOLICY_NEVER,
        key: &AES256_KEY,
    };
    assert_eq!(change(&mut app, &mut fs, FACTORY, from), Sw::OK);
    refuse.set(Some(key_fid(SLOT_CARDMGM).get()));
    assert_eq!(change(&mut app, &mut fs, from, to), Sw::MEMORY_FAILURE);
    refuse.set(None);
    assert_eq!(
        touch_in_force(&mut app, &mut fs, &pres, from),
        Some(TOUCHPOLICY_ALWAYS),
        "the key a refused change kept lost its touch gate"
    );
    assert_eq!(touch_in_force(&mut app, &mut fs, &pres, to), None);
    assert_eq!(metadata(&mut app, &mut fs), (from.algo, from.touch));
}

/// A card on a medium that refuses writes to whichever fid the returned cell names.
fn refusing() -> (Fs<RefuseWrite>, Rc<Cell<Option<u16>>>) {
    let refuse = Rc::new(Cell::new(None));
    let mut fs = Fs::new(RefuseWrite {
        inner: RamStorage::new(),
        refuse: Rc::clone(&refuse),
        refuse_remove: Rc::new(Cell::new(None)),
    });
    fs.scan();
    (fs, refuse)
}

const AES256_TOUCH: Mgm = Mgm {
    algo: ALGO_AES256,
    touch: TOUCHPOLICY_ALWAYS,
    key: &AES256_KEY,
};

/// The head is a cache of the record: a change whose head write the flash refuses
/// has landed, so it answers 9000, and the new key serves under its own algorithm
/// and touch policy until the next boot rewrites the head.
#[test]
fn a_refused_head_write_answers_for_the_key_that_landed() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(Scripted { confirm: true });
    let (mut fs, refuse) = refusing();
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut app, &mut fs);
    assert_eq!(
        files::mgm_read(&dev(), &mut fs).unwrap().policy,
        None,
        "the factory key is sealed alone, the shape an older build reads"
    );
    refuse.set(Some(rsk_fs::EF_META));
    assert_eq!(
        change(&mut app, &mut fs, FACTORY, AES256_TOUCH),
        Sw::OK,
        "a key that landed was answered as refused"
    );
    refuse.set(None);
    assert_eq!(
        touch_in_force(&mut app, &mut fs, &pres, AES256_TOUCH),
        Some(TOUCHPOLICY_ALWAYS)
    );
    assert_eq!(touch_in_force(&mut app, &mut fs, &pres, FACTORY), None);
    assert_eq!(
        metadata(&mut app, &mut fs),
        (ALGO_AES256, TOUCHPOLICY_ALWAYS)
    );
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut app, &mut fs);
    let mut head = [0u8; 8];
    fs.meta_find(key_fid(SLOT_CARDMGM).get(), &mut head);
    assert_eq!(head[..3], [ALGO_AES256, MGM_PIN_POLICY, TOUCHPOLICY_ALWAYS]);
}

/// On-panel protect re-keys 9B keeping its touch gate, which it must read from the
/// record: over a head a refused write left stale it would drop the gate.
#[test]
fn protecting_the_key_over_a_stale_head_keeps_the_records_touch_gate() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(Scripted { confirm: true });
    let (mut fs, refuse) = refusing();
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut app, &mut fs);
    refuse.set(Some(rsk_fs::EF_META));
    assert_eq!(change(&mut app, &mut fs, FACTORY, AES256_TOUCH), Sw::OK);
    refuse.set(None);
    assert_eq!(protect_mgm_key(&dev(), &mut fs, &mut TestRng(9)), Sw::OK);
    assert_eq!(
        files::mgm_read(&dev(), &mut fs).unwrap().policy,
        Some((ALGO_AES256, TOUCHPOLICY_ALWAYS))
    );
}

/// An older build sealed the key alone and wrote its head after, so a cut between
/// them left a new key under the old algorithm. The boot pass gives the head the
/// algorithm the key's length names and keeps its touch policy; a key-only record
/// whose head agrees is served from the head and left as it is.
#[test]
fn an_older_builds_key_only_record_serves_and_its_torn_head_is_repaired() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(Scripted { confirm: true });
    let mut fs = new_fs();
    select(
        &mut PivApplet::new(SERIAL, HASH, None, &rng, &pres),
        &mut fs,
    );
    let fid = key_fid(SLOT_CARDMGM);
    let plant = |fs: &mut Fs<RamStorage>, key: &[u8], head: [u8; 3]| {
        seal::seal_put(&dev(), fs, &mut TestRng(3), fid, key).unwrap();
        fs.meta_add(fid.get(), &head).unwrap();
    };
    let whole = Mgm {
        algo: ALGO_AES192,
        touch: TOUCHPOLICY_ALWAYS,
        key: &AES192_KEY,
    };
    plant(
        &mut fs,
        &AES192_KEY,
        [ALGO_AES192, MGM_PIN_POLICY, TOUCHPOLICY_ALWAYS],
    );
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut app, &mut fs);
    assert_eq!(
        touch_in_force(&mut app, &mut fs, &pres, whole),
        Some(TOUCHPOLICY_ALWAYS)
    );
    assert_eq!(files::mgm_read(&dev(), &mut fs).unwrap().policy, None);

    plant(
        &mut fs,
        &AES256_KEY,
        [ALGO_AES192, MGM_PIN_POLICY, TOUCHPOLICY_ALWAYS],
    );
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut app, &mut fs);
    let torn = Mgm {
        algo: ALGO_AES256,
        touch: TOUCHPOLICY_ALWAYS,
        key: &AES256_KEY,
    };
    assert_eq!(
        touch_in_force(&mut app, &mut fs, &pres, torn),
        Some(TOUCHPOLICY_ALWAYS)
    );
    assert_eq!(metadata(&mut app, &mut fs), (torn.algo, torn.touch));
}

/// A sealed 9B record of neither shape is refused as a store fault, not served as
/// a key.
#[test]
fn a_management_record_of_neither_shape_is_a_store_fault() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(Scripted { confirm: true });
    let mut fs = new_fs();
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut app, &mut fs);
    for bad in [
        &[0x11u8; 20][..],
        &[0xFF, TOUCHPOLICY_NEVER, 0x5A, 0x5A][..],
    ] {
        seal::seal_put(&dev(), &mut fs, &mut TestRng(3), key_fid(SLOT_CARDMGM), bad).unwrap();
        let (sw, _) = run(
            &mut app,
            &mut fs,
            INS_AUTHENTICATE,
            ALGO_AES192,
            SLOT_CARDMGM,
            &[0x7C, 0x02, 0x80, 0x00],
        );
        assert_eq!(sw, Sw::MEMORY_FAILURE, "{bad:02X?}");
    }
}

/// The same change with one read of the head failing: it refuses before it writes,
/// and the old key still authenticates.
#[test]
fn a_faulted_head_read_refuses_a_management_key_change_before_it_writes() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(AlwaysConfirm);
    let (backend, medium) = rsk_fs::storage::faults::ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut app, &mut fs);
    assert!(authenticates(&mut app, &mut fs, FACTORY));
    let key_before = medium.value(key_fid(SLOT_CARDMGM).get());
    medium.stick_once(rsk_fs::EF_META);
    let mut body = vec![ALGO_AES256, SLOT_CARDMGM, 32];
    body.extend_from_slice(&AES256_KEY);
    let sw = run(&mut app, &mut fs, INS_SET_MGMKEY, 0xFF, 0xFF, &body).0;
    assert_eq!(sw, Sw::MEMORY_FAILURE);
    assert_eq!(
        medium.value(key_fid(SLOT_CARDMGM).get()),
        key_before,
        "a refused change wrote the key"
    );
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut app, &mut fs);
    assert!(authenticates(&mut app, &mut fs, FACTORY));
}

/// The boot pass rewrites a head the record disagrees with, and a flash that
/// refuses that write must not fail SELECT: the head is a cache, and a refused
/// SELECT takes certificates, slot keys and RESET down with it.
#[test]
fn a_head_refresh_the_flash_refuses_does_not_fail_select() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(Scripted { confirm: true });
    let (mut fs, refuse) = refusing();
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut app, &mut fs);
    refuse.set(Some(rsk_fs::EF_META));
    assert_eq!(change(&mut app, &mut fs, FACTORY, AES256_TOUCH), Sw::OK);
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    let mut out = [0u8; 256];
    let mut res = ResBuf::new(&mut out);
    assert_eq!(
        Applet::select(&mut app, false, &mut fs, &mut res),
        Sw::OK,
        "SELECT refused over a cache refresh the flash refused"
    );
    assert_eq!(
        touch_in_force(&mut app, &mut fs, &pres, AES256_TOUCH),
        Some(TOUCHPOLICY_ALWAYS)
    );
}

/// On-panel protect over a record the flash would not serve once: it refuses with
/// nothing written, where the head's word could have dropped the touch gate only
/// the record carries, and the retry keeps it.
#[test]
fn protect_over_a_record_it_could_not_read_refuses_rather_than_drop_the_gate() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(Scripted { confirm: true });
    let (backend, medium) = ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut app, &mut fs);
    // A change whose head write was refused: the record gates, the head does not.
    let fid = key_fid(SLOT_CARDMGM);
    files::mgm_put(
        &dev(),
        &mut fs,
        &mut TestRng(5),
        ALGO_AES256,
        TOUCHPOLICY_ALWAYS,
        &AES256_KEY,
    )
    .unwrap();
    let mut head = [0u8; 8];
    fs.meta_find(fid.get(), &mut head);
    assert_eq!(head[2], TOUCHPOLICY_NEVER, "control: the head is stale");
    let before = medium.value(fid.get());
    medium.stick_once(fid.get());
    assert_eq!(
        protect_mgm_key(&dev(), &mut fs, &mut TestRng(9)),
        Sw::MEMORY_FAILURE
    );
    assert_eq!(
        medium.value(fid.get()),
        before,
        "a refused protect re-keyed"
    );
    assert_eq!(protect_mgm_key(&dev(), &mut fs, &mut TestRng(9)), Sw::OK);
    assert_eq!(
        files::mgm_read(&dev(), &mut fs).unwrap().policy,
        Some((ALGO_AES256, TOUCHPOLICY_ALWAYS))
    );
}

/// SET MANAGEMENT KEY reads the escrow record before it writes the key, as it does
/// the head: one read of ADMIN DATA the flash failed once answered 6581 over a new
/// key already in force, which a host that generated that key then threw away.
#[test]
fn a_faulted_escrow_read_refuses_a_key_change_before_it_writes() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(Scripted { confirm: true });
    let (backend, medium) = ProbeStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut app, &mut fs);
    // ADMIN DATA a host left with no escrow flag.
    fs.put(EF_PIVMAN_DATA, &[0x80, 0x03, 0x81, 0x01, 0x00])
        .unwrap();
    let to = Mgm {
        algo: ALGO_AES256,
        touch: TOUCHPOLICY_NEVER,
        key: &AES256_KEY,
    };
    assert!(authenticates(&mut app, &mut fs, FACTORY));
    medium.stick_once(EF_PIVMAN_DATA);
    let mut body = vec![to.algo, SLOT_CARDMGM, 32];
    body.extend_from_slice(to.key);
    let sw = run(&mut app, &mut fs, INS_SET_MGMKEY, 0xFF, 0xFF, &body).0;
    assert_eq!(
        (sw, authenticates(&mut app, &mut fs, to)),
        (Sw::MEMORY_FAILURE, false),
        "a refused change landed its key"
    );
    assert!(authenticates(&mut app, &mut fs, FACTORY));
}

/// Spend `ins`'s counter with a wrong `body` until the card says it is blocked.
fn spend<S: Storage>(app: &mut PivApplet, fs: &mut Fs<S>, ins: u8, body: &[u8]) {
    for _ in 0..4 {
        if run(app, fs, ins, 0, 0x80, body).0 == Sw::PIN_BLOCKED {
            return;
        }
    }
    panic!("the counter never blocked");
}

/// A head the flash will not take at SELECT is owed, not dropped: SELECT answers,
/// and the next one writes it once the flash does, in the same power cycle.
#[test]
fn a_head_the_flash_refuses_at_select_is_written_by_the_next_select() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(Scripted { confirm: true });
    let (mut fs, refuse) = refusing();
    refuse.set(Some(rsk_fs::EF_META));
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut app, &mut fs);
    assert!(
        !authenticates(&mut app, &mut fs, FACTORY),
        "control: the factory key has no head"
    );
    refuse.set(None);
    select(&mut app, &mut fs);
    assert!(authenticates(&mut app, &mut fs, FACTORY));
}

/// A RESET that could not give the factory key its head did not reset: it answers
/// 6581, where it answered 9000 over a management slot that refused every key, and
/// the next SELECT writes the head once the flash takes it.
#[test]
fn a_reset_whose_head_is_refused_reports_it_and_the_next_select_repairs_it() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(Scripted { confirm: true });
    let (mut fs, refuse) = refusing();
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut app, &mut fs);
    assert_eq!(change(&mut app, &mut fs, FACTORY, AES256_TOUCH), Sw::OK);
    spend(&mut app, &mut fs, INS_VERIFY, b"11111111");
    spend(&mut app, &mut fs, INS_RESET_RETRY, b"1111111122222222");
    refuse.set(Some(rsk_fs::EF_META));
    assert_eq!(
        run(&mut app, &mut fs, INS_RESET, 0, 0, &[]).0,
        Sw::MEMORY_FAILURE
    );
    // What the 6581 is about: the wipe went through (EF_META held the 9B head
    // alone, so it was removed, not rewritten) and the re-minted key has no head.
    let mut head = [0u8; 8];
    assert!(
        fs.has_key(key_fid(SLOT_CARDMGM)),
        "the factory key was minted"
    );
    assert_eq!(fs.meta_find(key_fid(SLOT_CARDMGM).get(), &mut head), None);
    refuse.set(None);
    select(&mut app, &mut fs);
    assert!(authenticates(&mut app, &mut fs, FACTORY));
}

/// On-panel protect over a record no arm opens re-keys the slot, as it always
/// has, taking the head's touch policy: the one way out a corrupt 9B has short
/// of a PIV reset.
#[test]
fn protect_over_a_record_no_arm_opens_re_keys_under_the_heads_touch() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(Scripted { confirm: true });
    let mut fs = new_fs();
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut app, &mut fs);
    let fid = key_fid(SLOT_CARDMGM);
    seal::seal_put(&dev(), &mut fs, &mut TestRng(3), fid, &[0x11; 20]).unwrap();
    fs.meta_add(
        fid.get(),
        &[ALGO_AES192, MGM_PIN_POLICY, TOUCHPOLICY_ALWAYS],
    )
    .unwrap();
    assert!(
        files::mgm_read(&dev(), &mut fs).is_err(),
        "control: corrupt"
    );
    assert_eq!(protect_mgm_key(&dev(), &mut fs, &mut TestRng(9)), Sw::OK);
    assert_eq!(
        files::mgm_read(&dev(), &mut fs).unwrap().policy,
        Some((ALGO_AES256, TOUCHPOLICY_ALWAYS))
    );
}

/// A RAM medium that refuses EF_META writes while `refuse_meta` is set, and fails
/// one planned read: `(fid, skip)` lets `skip` reads of `fid` through first.
struct Flaky {
    inner: RamStorage,
    refuse_meta: Rc<Cell<bool>>,
    fail_read: Rc<Cell<Option<(u16, u32)>>>,
    err: bool,
}

impl Storage for Flaky {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.err = false;
        if let Some((f, skip)) = self.fail_read.get()
            && f == fid
        {
            if skip == 0 {
                self.fail_read.set(None);
                self.err = true;
                return None;
            }
            self.fail_read.set(Some((f, skip - 1)));
        }
        self.inner.read(fid, buf)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
        if fid == rsk_fs::EF_META && self.refuse_meta.get() {
            return Err(rsk_sdk::error::Error::MemoryFatal);
        }
        self.inner.write(fid, data)
    }
    fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
        self.inner.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.err = false;
        self.inner.size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(f)
    }
    fn last_error(&self) -> bool {
        self.err
    }
}

/// An owed head, then a SELECT whose one read of the 9B key the flash failed: it
/// must not latch the files as ensured, or the healthy SELECT after it never
/// writes the head and 9B refuses every key until a reboot.
#[test]
fn a_select_that_could_not_read_the_key_leaves_its_head_owed() {
    let rng = RefCell::new(TestRng(7));
    let pres = RefCell::new(Scripted { confirm: true });
    let refuse = Rc::new(Cell::new(true));
    let fail = Rc::new(Cell::new(None));
    let mut fs = Fs::new(Flaky {
        inner: RamStorage::new(),
        refuse_meta: refuse.clone(),
        fail_read: fail.clone(),
        err: false,
    });
    fs.scan();
    let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
    select(&mut app, &mut fs);
    assert!(!app.files_ensured, "control: the head is owed");
    refuse.set(false);
    fail.set(Some((key_fid(SLOT_CARDMGM).get(), 0)));
    select(&mut app, &mut fs);
    assert!(
        fail.get().is_none(),
        "control: the planned read fault landed"
    );
    select(&mut app, &mut fs);
    assert!(authenticates(&mut app, &mut fs, FACTORY));
}
