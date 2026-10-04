// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    ShortReadback(usize),
    RefuseReset,
    RefuseVerifier(u16),
}

struct ReferenceStorage {
    inner: RamStorage,
    fault: Rc<Cell<Fault>>,
    retry_writes: usize,
    pending: bool,
    hits: Rc<Cell<usize>>,
}

impl Storage for ReferenceStorage {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        if fid == EF_RETRIES && self.pending {
            self.pending = false;
            let Fault::ShortReadback(len) = self.fault.get() else {
                unreachable!();
            };
            let mut record = [0; 4];
            assert_eq!(self.inner.read(fid, &mut record), Some(record.len()));
            buf[..len].copy_from_slice(&record[..len]);
            self.hits.set(self.hits.get() + 1);
            return Some(len);
        }
        self.inner.read(fid, buf)
    }

    fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
        if self.fault.get() != Fault::None && fid == EF_RETRIES {
            self.retry_writes += 1;
            if self.fault.get() == Fault::RefuseReset && self.retry_writes == 2 {
                self.hits.set(self.hits.get() + 1);
                return Err(rsk_sdk::error::Error::MemoryFatal);
            }
            self.pending = matches!(self.fault.get(), Fault::ShortReadback(_));
        }
        if self.fault.get() == Fault::RefuseVerifier(fid) {
            self.hits.set(self.hits.get() + 1);
            return Err(rsk_sdk::error::Error::MemoryFatal);
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

#[derive(Clone, Copy, Debug)]
enum Command {
    Verify,
    ChangePin,
    ChangePuk,
    Unblock,
}

impl Command {
    fn reference(self) -> (u16, usize) {
        match self {
            Self::Verify | Self::ChangePin => (EF_PIN, RETRY_PIN),
            Self::ChangePuk | Self::Unblock => (EF_PUK, RETRY_PUK),
        }
    }

    fn send<S: Storage>(self, app: &mut PivApplet, fs: &mut Fs<S>) -> (Sw, Vec<u8>) {
        const NEW_PIN: [u8; PIN_WIRE_LEN] = *b"87654321";
        match self {
            Self::Verify => run(app, fs, INS_VERIFY, 0, REF_PIN, &DEFAULT_PIN),
            Self::ChangePin => run(
                app,
                fs,
                INS_CHANGE_PIN,
                0,
                REF_PIN,
                &[DEFAULT_PIN, NEW_PIN].concat(),
            ),
            Self::ChangePuk => run(
                app,
                fs,
                INS_CHANGE_PIN,
                0,
                REF_PUK,
                &[DEFAULT_PUK, NEW_PIN].concat(),
            ),
            Self::Unblock => run(
                app,
                fs,
                INS_RESET_RETRY,
                0,
                REF_PIN,
                &[DEFAULT_PUK, NEW_PIN].concat(),
            ),
        }
    }
}

const COMMANDS: [Command; 4] = [
    Command::Verify,
    Command::ChangePin,
    Command::ChangePuk,
    Command::Unblock,
];

fn fault_fs() -> (Fs<ReferenceStorage>, Rc<Cell<Fault>>, Rc<Cell<usize>>) {
    let fault = Rc::new(Cell::new(Fault::None));
    let hits = Rc::new(Cell::new(0));
    let mut fs = Fs::new(ReferenceStorage {
        inner: RamStorage::new(),
        fault: fault.clone(),
        hits: hits.clone(),
        pending: false,
        retry_writes: 0,
    });
    fs.scan();
    (fs, fault, hits)
}

fn record<S: Storage>(fs: &mut Fs<S>, fid: u16) -> Vec<u8> {
    let mut bytes = [0; 128];
    let n = fs.read(fid, &mut bytes).unwrap();
    bytes[..n].to_vec()
}

fn standing_status(app: &PivApplet, command: Command) {
    let verified = !matches!(command, Command::Verify);
    assert_eq!(app.sess.has_pin, verified);
    assert_eq!(app.sess.pin_fresh, verified);
    assert!(app.sess.has_mgm);
}

#[test]
fn short_retry_readbacks_cannot_authorize_the_last_attempt() {
    for command in COMMANDS {
        for len in 0..4 {
            let rng = RefCell::new(TestRng(7));
            let presence = RefCell::new(AlwaysConfirm);
            let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
            let (mut fs, fault, hits) = fault_fs();
            select(&mut app, &mut fs);
            auth_mgm(&mut app, &mut fs);
            verify_pin(&mut app, &mut fs);
            let pin = record(&mut fs, EF_PIN);
            let puk = record(&mut fs, EF_PUK);
            let (_, retry) = command.reference();
            set_retries_left(&mut fs, retry, 1).unwrap();
            fault.set(Fault::ShortReadback(len));
            assert_eq!(
                command.send(&mut app, &mut fs),
                (Sw::MEMORY_FAILURE, vec![]),
                "{command:?}, {len} bytes: a short read-back cannot confirm the spent retry"
            );
            assert_eq!(hits.get(), 1);
            standing_status(&app, command);
            fault.set(Fault::None);
            assert_eq!(retries_left(&mut fs, retry), Ok(0));
            assert_eq!(record(&mut fs, EF_PIN), pin);
            assert_eq!(record(&mut fs, EF_PUK), puk);
            assert_eq!(command.send(&mut app, &mut fs), (Sw::PIN_BLOCKED, vec![]));
            set_retries_left(&mut fs, retry, DEFAULT_RETRIES).unwrap();
            assert_eq!(command.send(&mut app, &mut fs), (Sw::OK, vec![]));
        }
    }
}

#[test]
fn a_refused_retry_reset_cannot_authorize_a_correct_reference() {
    for command in COMMANDS {
        let rng = RefCell::new(TestRng(7));
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
        let (mut fs, fault, hits) = fault_fs();
        select(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
        verify_pin(&mut app, &mut fs);
        let pin = record(&mut fs, EF_PIN);
        let puk = record(&mut fs, EF_PUK);
        let (_, retry) = command.reference();
        fault.set(Fault::RefuseReset);
        assert_eq!(
            command.send(&mut app, &mut fs),
            (Sw::MEMORY_FAILURE, vec![]),
            "{command:?}: restoring the budget is part of a successful reference check"
        );
        assert_eq!(hits.get(), 1);
        standing_status(&app, command);
        fault.set(Fault::None);
        assert_eq!(retries_left(&mut fs, retry), Ok(DEFAULT_RETRIES - 1));
        assert_eq!(record(&mut fs, EF_PIN), pin);
        assert_eq!(record(&mut fs, EF_PUK), puk);
        assert_eq!(command.send(&mut app, &mut fs), (Sw::OK, vec![]));
    }
}

#[test]
fn refused_verifier_replacements_keep_the_old_references_usable() {
    for command in [Command::ChangePin, Command::ChangePuk, Command::Unblock] {
        let rng = RefCell::new(TestRng(7));
        let presence = RefCell::new(AlwaysConfirm);
        let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
        let (mut fs, fault, hits) = fault_fs();
        select(&mut app, &mut fs);
        auth_mgm(&mut app, &mut fs);
        verify_pin(&mut app, &mut fs);
        let pin = record(&mut fs, EF_PIN);
        let puk = record(&mut fs, EF_PUK);
        let (fid, retry) = command.reference();
        let target = if matches!(command, Command::Unblock) {
            EF_PIN
        } else {
            fid
        };
        fault.set(Fault::RefuseVerifier(target));
        assert_eq!(
            command.send(&mut app, &mut fs),
            (Sw::MEMORY_FAILURE, vec![])
        );
        assert_eq!(hits.get(), 1);
        standing_status(&app, command);
        fault.set(Fault::None);
        assert_eq!(retries_left(&mut fs, retry), Ok(DEFAULT_RETRIES));
        assert_eq!(record(&mut fs, EF_PIN), pin);
        assert_eq!(record(&mut fs, EF_PUK), puk);
        verify_pin(&mut app, &mut fs);
        assert_eq!(command.send(&mut app, &mut fs), (Sw::OK, vec![]));
    }
}

#[test]
fn malformed_verifier_lengths_do_not_spend_a_reference_attempt() {
    for command in COMMANDS {
        for len in [0, 1, 2, PIN_REC_LEN - 1, PIN_REC_LEN + 1, 65] {
            let rng = RefCell::new(TestRng(7));
            let presence = RefCell::new(AlwaysConfirm);
            let mut app = PivApplet::new(SERIAL, HASH, None, &rng, &presence);
            let mut fs = new_fs();
            select(&mut app, &mut fs);
            auth_mgm(&mut app, &mut fs);
            verify_pin(&mut app, &mut fs);
            let (fid, _) = command.reference();
            let original = record(&mut fs, fid);
            let mut malformed = original.clone();
            malformed.resize(len, 0);
            fs.put(fid, &malformed).unwrap();
            let retries = record(&mut fs, EF_RETRIES);
            let generation = fs.write_gen();
            let absent = matches!(command, Command::Verify) && len == 0;
            assert_eq!(
                command.send(&mut app, &mut fs),
                (
                    if absent {
                        Sw::REFERENCE_NOT_FOUND
                    } else {
                        Sw::MEMORY_FAILURE
                    },
                    vec![]
                ),
                "{command:?}, verifier length {len}"
            );
            if absent {
                assert!(app.sess.has_pin && app.sess.pin_fresh && app.sess.has_mgm);
            } else {
                standing_status(&app, command);
            }
            assert_eq!(record(&mut fs, EF_RETRIES), retries);
            assert_eq!(record(&mut fs, fid), malformed);
            assert_eq!(fs.write_gen(), generation);
            fs.put(fid, &original).unwrap();
            assert_eq!(command.send(&mut app, &mut fs), (Sw::OK, vec![]));
        }
    }
}
