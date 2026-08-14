// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! What the PIN doors do when the flash stops accepting writes.
//!
//! One property, over all three: if an attempt costs nothing, the card's answer
//! must not tell a right secret from a wrong one — otherwise the retry counter
//! has stopped being the gate and the PIN is guessable at leisure. `check_ref`
//! spends and reads the counter back before it compares, which is what holds it;
//! comparing first left the `LyingStorage` half of that window open.
//!
//! Driven through the real APDUs with `DyingStorage` (the software half of
//! `tools/emu --power-cut`, ported from `rsk-openpgp`'s `pin_tests.rs`) rather
//! than by hand-building a torn store, so the property is stated over the
//! commands a host can actually send.

use super::*;
use rsk_fs::storage::ram::RamStorage;

use std::cell::Cell;
use std::rc::Rc;
use std::vec::Vec;

const SERIAL: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const HASH: [u8; 32] = [0x22; 32];
/// Same length as the defaults and equally well-formed, so only the comparison
/// separates them.
const WRONG_PIN: [u8; 8] = [b'9', b'9', b'9', b'9', b'9', b'9', 0xFF, 0xFF];
const WRONG_PUK: [u8; 8] = [b'9', b'9', b'9', b'9', b'9', b'9', b'9', b'9'];
const NEW_PIN: [u8; 8] = [b'6', b'5', b'4', b'3', b'2', b'1', 0xFF, 0xFF];

struct TestRng(u64);
impl Rng for TestRng {
    fn fill(&mut self, b: &mut [u8]) {
        for x in b.iter_mut() {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *x = (self.0 >> 33) as u8;
        }
    }
}

/// A flash that stops accepting writes once its budget runs out. Reads keep
/// working, which is what a card does after a failed write.
struct DyingStorage {
    inner: RamStorage,
    budget: Rc<Cell<usize>>,
}

impl DyingStorage {
    fn new() -> (Self, Rc<Cell<usize>>) {
        let budget = Rc::new(Cell::new(usize::MAX));
        (
            Self {
                inner: RamStorage::new(),
                budget: budget.clone(),
            },
            budget,
        )
    }
    fn spend(&mut self) -> rsk_sdk::error::Result<()> {
        match self.budget.get() {
            0 => Err(rsk_sdk::error::Error::MemoryFatal),
            n => {
                self.budget.set(n - 1);
                Ok(())
            }
        }
    }
}

impl rsk_fs::Storage for DyingStorage {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.inner.read(fid, buf)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
        self.spend()?;
        self.inner.write(fid, data)
    }
    fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
        self.spend()?;
        self.inner.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.inner.size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(f)
    }
}

/// A flash whose writes **succeed and store nothing** — the glitched or partly
/// programmed page `rsk-fido` reads its retry counter back against, and the one
/// failure [`DyingStorage`] cannot express: there, a refused write is at least
/// reported. Here the card believes it spent the attempt.
struct LyingStorage {
    inner: RamStorage,
    lying: Rc<Cell<bool>>,
}

impl LyingStorage {
    fn new() -> (Self, Rc<Cell<bool>>) {
        let lying = Rc::new(Cell::new(false));
        (
            Self {
                inner: RamStorage::new(),
                lying: lying.clone(),
            },
            lying,
        )
    }
}

impl rsk_fs::Storage for LyingStorage {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.inner.read(fid, buf)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
        if self.lying.get() {
            return Ok(());
        }
        self.inner.write(fid, data)
    }
    fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
        self.inner.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.inner.size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(f)
    }
}

/// A provisioned card whose flash can be made to refuse writes mid-command.
struct Card {
    fs: Fs<DyingStorage>,
    tap: Rc<Cell<usize>>,
}

fn card() -> Card {
    let (storage, tap) = DyingStorage::new();
    let mut fs = Fs::new(storage);
    fs.scan();
    Card { fs, tap }
}

impl Card {
    /// Provision the default files with the flash healthy — the failure window
    /// under test is the command, not the setup.
    fn select(&mut self, app: &mut PivApplet) {
        let mut out = [0u8; 256];
        let mut res = ResBuf::new(&mut out);
        assert_eq!(Applet::select(app, false, &mut self.fs, &mut res), Sw::OK);
    }

    fn run(&mut self, app: &mut PivApplet, ins: u8, p2: u8, data: &[u8]) -> Sw {
        let mut raw = std::vec![0x00, ins, 0x00, p2, data.len() as u8];
        raw.extend_from_slice(data);
        let apdu = Apdu::parse(&raw).unwrap();
        let mut out = [0u8; 1024];
        let mut res = ResBuf::new(&mut out);
        Applet::process(app, &apdu, &mut self.fs, &mut res)
    }

    fn left(&mut self, retry: usize) -> u8 {
        retries_left(&mut self.fs, retry).unwrap()
    }
}

/// One command that compares a stored reference: the right secret, a wrong one
/// of the same shape, and the counter the attempt spends.
struct Door {
    name: &'static str,
    ins: u8,
    p2: u8,
    retry: usize,
    right: Vec<u8>,
    wrong: Vec<u8>,
}

/// All three of them. Every property below is stated over the whole set — the
/// ordering `check_ref` fixes is shared, so testing one door proves nothing
/// about the other two.
fn doors() -> [Door; 3] {
    let chg = |old: &[u8]| [old, &NEW_PIN[..]].concat();
    [
        Door {
            name: "VERIFY",
            ins: INS_VERIFY,
            p2: REF_PIN,
            retry: RETRY_PIN,
            right: DEFAULT_PIN.to_vec(),
            wrong: WRONG_PIN.to_vec(),
        },
        Door {
            name: "CHANGE REFERENCE DATA",
            ins: INS_CHANGE_PIN,
            p2: REF_PIN,
            retry: RETRY_PIN,
            right: chg(&DEFAULT_PIN),
            wrong: chg(&WRONG_PIN),
        },
        Door {
            name: "RESET RETRY COUNTER",
            ins: INS_RESET_RETRY,
            p2: REF_PIN,
            retry: RETRY_PUK,
            right: chg(&DEFAULT_PUK),
            wrong: chg(&WRONG_PUK),
        },
    ]
}

/// The anti-oracle property, bounded-exhaustive over every point the flash can
/// die during the command: **either the card's answer does not distinguish the
/// right secret from a wrong one, or the wrong attempt spent a retry.** Its
/// negation is a guessing oracle with the counter frozen, which is the whole of
/// what a compare-then-spend ordering risks.
#[test]
fn a_failing_write_never_buys_a_free_distinguishable_answer() {
    for Door {
        name,
        ins,
        p2,
        retry,
        right,
        wrong,
    } in doors()
    {
        for budget in 0..6 {
            let rng = RefCell::new(TestRng(3));
            let pres = RefCell::new(AlwaysConfirm);

            let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
            let mut good = card();
            good.select(&mut app);
            good.tap.set(budget);
            let sw_right = good.run(&mut app, ins, p2, &right);

            let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
            let mut bad = card();
            bad.select(&mut app);
            bad.tap.set(budget);
            let before = bad.left(retry);
            let sw_wrong = bad.run(&mut app, ins, p2, &wrong);
            let after = bad.left(retry);

            assert!(
                sw_right == sw_wrong || after < before,
                "{name} at budget {budget}: right={sw_right:?} wrong={sw_wrong:?}, \
                 counter {before} -> {after} — a distinguishable answer for free"
            );
        }
    }
}

/// The same property stated the way an attacker would use it: a long run of
/// wrong secrets against a card whose flash refuses every write must either
/// spend the budget or answer exactly what the right secret answers.
///
/// `0..6` above walks the window; this one holds the worst case open and repeats
/// it, which is what "unbounded" means. One card throughout, so a state the
/// first attempt leaves behind is inherited by the rest.
#[test]
fn a_dead_flash_is_not_an_unlimited_guessing_oracle() {
    const ATTEMPTS: usize = 40;
    for Door {
        name,
        ins,
        p2,
        retry,
        right,
        wrong,
    } in doors()
    {
        let rng = RefCell::new(TestRng(5));
        let pres = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        let mut c = card();
        c.select(&mut app);
        // Not one more write from here on.
        c.tap.set(0);
        let start = c.left(retry);
        let answers: Vec<Sw> = (0..ATTEMPTS)
            .map(|_| c.run(&mut app, ins, p2, &wrong))
            .collect();
        let sw_right = c.run(&mut app, ins, p2, &right);
        let end = c.left(retry);
        assert!(
            end < start || answers.iter().all(|&sw| sw == sw_right),
            "{name}: {ATTEMPTS} wrong secrets cost nothing ({start} -> {end}) and \
             answered {:?} where the right one answers {sw_right:?}",
            answers[0]
        );
    }
}

/// The same property against a flash that lies rather than refuses — the case
/// the two above cannot reach, and the one that was open. Comparing before
/// spending meant a write that quietly stored nothing left the card answering
/// `63Cx` to every wrong PIN and `9000` to the right one, at full speed, with
/// the counter pinned at its start value: the retry budget had stopped being a
/// budget. `check_ref` now spends and reads back first, so the card refuses
/// before it has compared anything.
#[test]
fn a_lying_write_is_caught_before_the_comparison() {
    const ATTEMPTS: usize = 40;
    for Door {
        name,
        ins,
        p2,
        retry,
        right,
        wrong,
    } in doors()
    {
        let (storage, lying) = LyingStorage::new();
        let mut fs = Fs::new(storage);
        fs.scan();
        let rng = RefCell::new(TestRng(13));
        let pres = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &pres);
        {
            let mut out = [0u8; 256];
            let mut res = ResBuf::new(&mut out);
            assert_eq!(Applet::select(&mut app, false, &mut fs, &mut res), Sw::OK);
        }
        lying.set(true);
        let start = retries_left(&mut fs, retry).unwrap();
        let run = |app: &mut PivApplet, fs: &mut Fs<LyingStorage>, data: &[u8]| {
            let mut raw = std::vec![0x00, ins, 0x00, p2, data.len() as u8];
            raw.extend_from_slice(data);
            let a = Apdu::parse(&raw).unwrap();
            let mut o = [0u8; 1024];
            let mut r = ResBuf::new(&mut o);
            Applet::process(app, &a, fs, &mut r)
        };
        let answers: Vec<Sw> = (0..ATTEMPTS)
            .map(|_| run(&mut app, &mut fs, &wrong))
            .collect();
        let sw_right = run(&mut app, &mut fs, &right);
        let end = retries_left(&mut fs, retry).unwrap();
        assert!(
            end < start || answers.iter().all(|&sw| sw == sw_right),
            "{name}: a store that silently keeps nothing let {ATTEMPTS} wrong secrets \
             answer {:?} against the right one's {sw_right:?}, counter {start} -> {end}",
            answers[0]
        );
    }
}
