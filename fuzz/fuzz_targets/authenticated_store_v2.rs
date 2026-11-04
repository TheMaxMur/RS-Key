// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Stateful v2 lifecycle and fault histories for `authenticated_store`.
//!
//! Every row runs the real `Managed` backend over `MockFlashBase` with the
//! production `VerifiedFlash` verification enabled, so a write that does not
//! land is caught by the same read-back the device uses. The oracle is the
//! harness's own acknowledged-operation log, never the backend's directory: an
//! `Err` may still mean the medium committed, so the only accepted states are
//! the acknowledged one or the one the failed command asked for.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use embassy_futures::block_on;
use embedded_storage_async::nor_flash::{ErrorType, MultiwriteNorFlash, NorFlash, ReadNorFlash};
use rsk_fs::Storage;
use rsk_fs::storage::{StorageAction, StorageState};
use rsk_rescue::{Platform, RescueApplet, Rng, SecureBootStatus};
use rsk_sdk::error::{Error, Result};
use rsk_sdk::{Apdu, Applet, Confirm, Presence, ResBuf, Sw, UserPresence};
use rsk_store::authenticated::{FORMAT, KeySource, Managed, RootRead};
use sequential_storage::cache::{Cache, Uncached};
use sequential_storage::map::{MapConfig, MapStorage};
use sequential_storage::mock_flash::{MockFlashBase, MockFlashError, Operation, WriteCountCheck};

use super::{COUNTER, MAIN, NEIGHBOR, OWNER};

pub const MAGIC: &[u8; 4] = b"V2H1";
const MANIFEST_FID: u16 = 0xCEF8;
const ACTIVATION_FID: u16 = 0xCEFD;
const IMPORT_MAGIC: &[u8; 8] = b"RSKIMP02";
const ACTIVATION_MAGIC: &[u8; 8] = b"RSKACT02";
const CHECKPOINT_MAGIC: &[u8; 8] = b"RSKCAT02";
const KV_BUF: usize = 4080;

type Flash = MockFlashBase<40, 4, 1024>;
type StoreCache = Cache<Uncached, Uncached, Uncached, u16>;
type ManagedStore = Managed<Medium, StoreCache>;
type RawMap = MapStorage<u16, Medium, StoreCache>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum RootMode {
    Blank,
    Fused,
}

thread_local! {
    static ROOT: Cell<RootMode> = const { Cell::new(RootMode::Blank) };
}

fn set_root(mode: RootMode) {
    ROOT.with(|root| root.set(mode));
}

fn root_read(out: &mut [u8; 32]) -> RootRead {
    match ROOT.with(Cell::get) {
        RootMode::Blank => RootRead::Blank,
        RootMode::Fused => {
            out.fill(0x11);
            RootRead::Fused
        }
    }
}

fn source() -> KeySource {
    KeySource::new([0x43; 32], root_read, false)
}

#[derive(Default)]
struct Counts {
    read_refused: Cell<u32>,
    write_refused: Cell<u32>,
    erase_refused: Cell<u32>,
    silent: Cell<u32>,
    torn: Cell<u32>,
    cuts: Cell<u32>,
    programs: Cell<u32>,
    reads: Cell<u32>,
    erases: Cell<u32>,
    bytes: Cell<u32>,
}

impl Counts {
    fn reset(&self) {
        self.read_refused.set(0);
        self.write_refused.set(0);
        self.erase_refused.set(0);
        self.silent.set(0);
        self.torn.set(0);
        self.cuts.set(0);
        self.programs.set(0);
        self.reads.set(0);
        self.erases.set(0);
        self.bytes.set(0);
    }
    fn bump(cell: &Cell<u32>) {
        cell.set(cell.get().saturating_add(1));
    }
}

struct Faults {
    reads: Cell<u32>,
    reads_after_silent: Cell<u32>,
    writes: Cell<u32>,
    erases: Cell<u32>,
    silent: Cell<u32>,
    torn: Cell<u32>,
    torn_prefix: Cell<usize>,
    range: Cell<Option<(u32, u32)>>,
    cuts: Counts,
}

impl Faults {
    fn new() -> Self {
        Self {
            reads: Cell::new(0),
            reads_after_silent: Cell::new(0),
            writes: Cell::new(0),
            erases: Cell::new(0),
            silent: Cell::new(0),
            torn: Cell::new(0),
            torn_prefix: Cell::new(0),
            range: Cell::new(None),
            cuts: Counts::default(),
        }
    }

    fn hits(&self, address: u32) -> bool {
        match self.range.get() {
            Some((start, end)) => (start..end).contains(&address),
            None => true,
        }
    }

    fn take(cell: &Cell<u32>) -> bool {
        let left = cell.get();
        if left == 0 {
            return false;
        }
        cell.set(left - 1);
        true
    }
}

#[derive(Clone)]
struct Medium {
    flash: Rc<RefCell<Flash>>,
    faults: Rc<Faults>,
}

impl Medium {
    fn new() -> Self {
        Self {
            flash: Rc::new(RefCell::new(Flash::new(
                WriteCountCheck::Disabled,
                None,
                true,
            ))),
            faults: Rc::new(Faults::new()),
        }
    }

    fn image(&self) -> Vec<u8> {
        self.flash.borrow().as_bytes().to_vec()
    }

    fn restore(&self, image: &[u8]) {
        self.flash
            .borrow_mut()
            .as_bytes_mut()
            .copy_from_slice(image);
        self.flash.borrow_mut().bytes_until_shutoff = None;
        self.clear_faults();
        self.faults.cuts.reset();
    }

    fn clear_faults(&self) {
        let f = &self.faults;
        f.reads.set(0);
        f.reads_after_silent.set(0);
        f.writes.set(0);
        f.erases.set(0);
        f.silent.set(0);
        f.torn.set(0);
        f.torn_prefix.set(0);
        f.range.set(None);
        self.flash.borrow_mut().bytes_until_shutoff = None;
    }

    fn arm_reads(&self, count: u32) {
        self.faults.reads.set(count);
    }
    fn arm_writes(&self, count: u32) {
        self.faults.writes.set(count);
    }
    /// Refuse the read-back that follows a silent program, so the two halves of
    /// one interrupted slot program are ordered rather than racing.
    fn arm_read_after_silent(&self, count: u32) {
        self.faults.reads_after_silent.set(count);
    }
    fn arm_erases(&self, count: u32) {
        self.faults.erases.set(count);
    }
    fn arm_silent(&self, count: u32) {
        self.faults.silent.set(count);
    }
    fn arm_torn(&self, count: u32, prefix: usize) {
        self.faults.torn.set(count);
        self.faults.torn_prefix.set(prefix);
    }
    fn only_range(&self, range: core::ops::Range<u32>) {
        self.faults.range.set(Some((range.start, range.end)));
    }
    fn arm_cut(&self, budget: Option<u32>) {
        self.flash.borrow_mut().bytes_until_shutoff = budget;
    }
    fn programs(&self) -> u32 {
        self.faults.cuts.programs.get()
    }
    fn counts(&self) -> &Counts {
        &self.faults.cuts
    }

    fn note_program(&self) {
        Counts::bump(&self.faults.cuts.programs);
    }

    fn note_cut(&self, result: &core::result::Result<(), MockFlashError>) {
        if matches!(result, Err(MockFlashError::EarlyShutoff(..))) {
            Counts::bump(&self.faults.cuts.cuts);
        }
    }
}

impl ErrorType for Medium {
    type Error = MockFlashError;
}

impl ReadNorFlash for Medium {
    const READ_SIZE: usize = <Flash as ReadNorFlash>::READ_SIZE;

    async fn read(
        &mut self,
        address: u32,
        out: &mut [u8],
    ) -> core::result::Result<(), Self::Error> {
        let faults = Rc::clone(&self.faults);
        Counts::bump(&faults.cuts.reads);
        faults
            .cuts
            .bytes
            .set(faults.cuts.bytes.get().saturating_add(out.len() as u32));
        if faults.reads_after_silent.get() > 0
            && faults.cuts.silent.get() > 0
            && faults.hits(address)
        {
            Faults::take(&faults.reads_after_silent);
            Counts::bump(&faults.cuts.read_refused);
            return Err(MockFlashError::EarlyShutoff(address, Operation::Read));
        }
        if faults.reads.get() > 0 && faults.hits(address) {
            Faults::take(&faults.reads);
            Counts::bump(&faults.cuts.read_refused);
            return Err(MockFlashError::EarlyShutoff(address, Operation::Read));
        }
        block_on(self.flash.borrow_mut().read(address, out))
    }

    fn capacity(&self) -> usize {
        self.flash.borrow().capacity()
    }
}

impl NorFlash for Medium {
    const WRITE_SIZE: usize = <Flash as NorFlash>::WRITE_SIZE;
    const ERASE_SIZE: usize = <Flash as NorFlash>::ERASE_SIZE;

    async fn write(&mut self, address: u32, value: &[u8]) -> core::result::Result<(), Self::Error> {
        let faults = Rc::clone(&self.faults);
        faults
            .cuts
            .bytes
            .set(faults.cuts.bytes.get().saturating_add(value.len() as u32));
        if faults.writes.get() > 0 && faults.hits(address) {
            Faults::take(&faults.writes);
            Counts::bump(&faults.cuts.write_refused);
            return Err(MockFlashError::EarlyShutoff(address, Operation::Write));
        }
        if faults.silent.get() > 0 && faults.hits(address) {
            Faults::take(&faults.silent);
            Counts::bump(&faults.cuts.silent);
            return Ok(());
        }
        if faults.torn.get() > 0 && faults.hits(address) {
            Faults::take(&faults.torn);
            Counts::bump(&faults.cuts.torn);
            let aligned = value.len() & !(Flash::WRITE_SIZE - 1);
            let prefix = faults.torn_prefix.get().min(aligned);
            // A fault that programmes every byte is a silent success, not a tear.
            assert!(
                prefix != 0 && prefix < value.len(),
                "the torn fault did not tear the {} byte program",
                value.len()
            );
            self.note_program();
            let result = block_on(self.flash.borrow_mut().write(address, &value[..prefix]));
            self.note_cut(&result);
            return result;
        }
        self.note_program();
        let result = block_on(self.flash.borrow_mut().write(address, value));
        self.note_cut(&result);
        result
    }

    async fn erase(&mut self, from: u32, to: u32) -> core::result::Result<(), Self::Error> {
        let faults = Rc::clone(&self.faults);
        Counts::bump(&faults.cuts.erases);
        faults.cuts.bytes.set(
            faults
                .cuts
                .bytes
                .get()
                .saturating_add(to.saturating_sub(from)),
        );
        if faults.erases.get() > 0 && faults.hits(from) {
            Faults::take(&faults.erases);
            Counts::bump(&faults.cuts.erase_refused);
            return Err(MockFlashError::EarlyShutoff(from, Operation::Erase));
        }
        self.note_program();
        let result = block_on(self.flash.borrow_mut().erase(from, to));
        self.note_cut(&result);
        result
    }
}

impl MultiwriteNorFlash for Medium {}

fn managed(medium: &Medium) -> ManagedStore {
    Managed::new_unmounted(
        medium.clone(),
        MAIN,
        COUNTER,
        source(),
        Cache::<Uncached, Uncached, Uncached, u16>::new_uncached,
    )
}

fn mounted(medium: &Medium) -> ManagedStore {
    let mut store = managed(medium);
    store.mount().unwrap();
    store
}

fn initialized(medium: &Medium, epoch: [u8; 16]) -> ManagedStore {
    let mut store = managed(medium);
    store.administer(StorageAction::Initialize, epoch).unwrap();
    store
}

fn read_value(store: &mut ManagedStore, fid: u16) -> Result<Option<Vec<u8>>> {
    let mut out = [0u8; rsk_fs::MAX_VALUE_BYTES];
    let length = store.read(fid, &mut out);
    if store.last_error() {
        return Err(Error::MemoryFatal);
    }
    Ok(length.map(|length| out[..length].to_vec()))
}

fn expect(store: &mut ManagedStore, fid: u16, wanted: &[u8]) {
    assert_eq!(
        read_value(store, fid).unwrap().as_deref(),
        Some(wanted),
        "fid {fid:#06x} does not hold the acknowledged value"
    );
}

fn raw_map(medium: &Medium, range: core::ops::Range<u32>) -> RawMap {
    MapStorage::new(
        medium.clone(),
        MapConfig::try_new(range).unwrap(),
        Cache::new_uncached(),
    )
}

fn raw_fetch(medium: &Medium, fid: u16) -> Option<Vec<u8>> {
    let mut map = raw_map(medium, MAIN);
    let mut buffer = [0u8; KV_BUF];
    block_on(map.fetch_item_unrepaired::<&[u8]>(&mut buffer, &fid))
        .ok()
        .flatten()
        .map(<[u8]>::to_vec)
}

fn raw_remove(medium: &Medium, fid: u16) {
    raw_remove_in(medium, MAIN, fid);
}

fn raw_remove_in(medium: &Medium, range: core::ops::Range<u32>, fid: u16) {
    let mut map = raw_map(medium, range);
    let mut buffer = [0u8; KV_BUF];
    block_on(map.remove_item(&mut buffer, &fid)).unwrap();
}

fn raw_store(medium: &Medium, fid: u16, value: &[u8]) {
    let mut map = raw_map(medium, MAIN);
    let mut buffer = [0u8; KV_BUF];
    block_on(map.store_item::<&[u8]>(&mut buffer, &fid, &value)).unwrap();
}

fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    haystack
        .windows(needle.len())
        .enumerate()
        .filter_map(|(index, window)| (window == needle).then_some(index))
        .collect()
}

const LEGACY_COUNTERS: [[u8; 4]; 4] = [
    [9, 8, 7, 6],
    [1, 2, 3, 4],
    [0x5A, 0x5B, 0x5C, 0x5D],
    [0xC1, 0xC2, 0xC3, 0xC4],
];

fn write_legacy(medium: &Medium, owner: &[u8]) {
    let mut buffer = [0u8; KV_BUF];
    let mut main = raw_map(medium, MAIN);
    block_on(main.store_item::<&[u8]>(&mut buffer, &OWNER, &owner)).unwrap();
    block_on(main.store_item::<&[u8]>(
        &mut buffer,
        &NEIGHBOR,
        &b"acknowledged neighbor".as_slice(),
    ))
    .unwrap();
    let mut counters = raw_map(medium, COUNTER);
    for (fid, value) in rsk_fs::counter::COUNTER_FIDS.iter().zip(LEGACY_COUNTERS) {
        block_on(counters.store_item::<&[u8]>(&mut buffer, &fid.get(), &value.as_slice())).unwrap();
    }
}

fn assert_legacy(store: &mut ManagedStore, owner: &[u8]) {
    expect(store, OWNER, owner);
    expect(store, NEIGHBOR, b"acknowledged neighbor");
    for (fid, value) in rsk_fs::counter::COUNTER_FIDS.iter().zip(LEGACY_COUNTERS) {
        expect(store, fid.get(), &value);
    }
}

fn activation(medium: &Medium) -> Option<Vec<u8>> {
    raw_fetch(medium, ACTIVATION_FID)
}

fn assert_activation(medium: &Medium, epoch: [u8; 16]) {
    let mut wanted = [0xFFu8; 32];
    wanted[..8].copy_from_slice(ACTIVATION_MAGIC);
    wanted[8] = FORMAT;
    wanted[16..].copy_from_slice(&epoch);
    assert_eq!(
        activation(medium).as_deref(),
        Some(&wanted[..]),
        "activation witness is not the canonical epoch record"
    );
}

/// Cut a fresh legacy import after its manifest is durable, before cleanup.
/// Returns the cut image, or `None` when no budget reached that window.
fn cut_import(medium: &Medium, owner: &[u8]) -> Option<Vec<u8>> {
    write_legacy(medium, owner);
    let base = medium.image();
    let mut manifest_only = None;
    for budget in [768u32, 1280, 2048, 3072, 4096, 6144, 8192, 12288] {
        medium.restore(&base);
        medium.arm_cut(Some(budget));
        let mut store = managed(medium);
        let result = store.boot([0x41; 16]);
        medium.arm_cut(None);
        let image = medium.image();
        if result.is_err() && raw_fetch(medium, MANIFEST_FID).is_some() {
            if !find_all(&image, CHECKPOINT_MAGIC).is_empty() {
                return Some(image);
            }
            manifest_only.get_or_insert(image);
        }
    }
    manifest_only
}

/// Select and drop the import's manifest, then write a different legacy owner.
fn damage_manifest_and_legacy(medium: &Medium, cut: &[u8], changed: &[u8]) {
    medium.restore(cut);
    let offsets = find_all(&medium.image(), IMPORT_MAGIC);
    assert!(!offsets.is_empty(), "cut image has no manifest witness");
    let at = offsets[0] + 16;
    medium.flash.borrow_mut().as_bytes_mut()[at] ^= 0x40;
    raw_store(medium, OWNER, changed);
}

#[derive(Clone, Copy)]
struct CountRng(u8);

impl Rng for CountRng {
    fn fill(&mut self, bytes: &mut [u8]) {
        for byte in bytes.iter_mut() {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

struct TestPlatform {
    reboot: bool,
}

impl Platform for TestPlatform {
    fn secure_boot_status(&self) -> SecureBootStatus {
        SecureBootStatus {
            enabled: false,
            locked: false,
            bootkey: 0xFF,
        }
    }
    fn now(&self) -> Option<u32> {
        Some(0)
    }
    fn set_time(&mut self, _epoch: u32) {}
    fn request_reboot(&mut self, _bootsel: bool) {
        self.reboot = true;
    }
    fn read_page58_lock_raw(&self) -> Option<u32> {
        Some(0)
    }
    fn pre_otp_left(&self) -> Option<u16> {
        Some(0)
    }
    fn lock_page58(&mut self) -> bool {
        false
    }
    fn read_rollback_raw(&self) -> Option<rsk_rescue::rollback::RollbackRaw> {
        None
    }
    fn set_rollback_required(&mut self) -> bool {
        false
    }
}

struct TestPresence(bool);

impl UserPresence for TestPresence {
    fn request(&mut self, _confirm: Confirm<'_>) -> Presence {
        if self.0 {
            Presence::Confirmed
        } else {
            Presence::Declined
        }
    }
}

fn storage_apdu(p1: u8, p2: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x80, 0x20, p1, p2, u8::try_from(payload.len()).unwrap()];
    bytes.extend_from_slice(payload);
    bytes
}

fn rescue_call(
    fs: &mut rsk_fs::Fs<ManagedStore>,
    app: &mut RescueApplet<'_>,
    p1: u8,
    p2: u8,
    payload: &[u8],
) -> rsk_sdk::Sw {
    let bytes = storage_apdu(p1, p2, payload);
    let apdu = Apdu::parse(&bytes).unwrap();
    let mut buffer = [0u8; 512];
    let mut response = ResBuf::new(&mut buffer);
    app.process(&apdu, fs, &mut response)
}

struct RescueRig {
    rng: RefCell<CountRng>,
    platform: RefCell<TestPlatform>,
    presence: RefCell<TestPresence>,
}

impl RescueRig {
    fn new(confirmed: bool) -> Self {
        Self {
            rng: RefCell::new(CountRng(0)),
            platform: RefCell::new(TestPlatform { reboot: false }),
            presence: RefCell::new(TestPresence(confirmed)),
        }
    }
    fn applet(&self) -> RescueApplet<'_> {
        RescueApplet::new(
            [0xAA, 0xBB, 0xCC, 0xDD, 5, 6, 7, 8],
            [0x22; 32],
            None,
            None,
            &self.rng,
            &self.platform,
            &self.presence,
            0x20000,
            0x400000,
        )
    }
    fn reboot(&self) -> bool {
        self.platform.borrow().reboot
    }
}

/// Run the acknowledged log for one `owner`/`neighbour` pair, including the
/// four public counters, and return the store for the next step.
fn tracked_store(medium: &Medium, epoch: [u8; 16], owner: &[u8]) -> ManagedStore {
    let mut store = initialized(medium, epoch);
    store.write(OWNER, owner).unwrap();
    store.write(NEIGHBOR, b"acknowledged neighbor").unwrap();
    for (fid, value) in rsk_fs::counter::COUNTER_FIDS.iter().zip(LEGACY_COUNTERS) {
        store.write(fid.get(), &value).unwrap();
    }
    store
}

fn assert_tracked(store: &mut ManagedStore, owner: &[u8]) {
    expect(store, OWNER, owner);
    expect(store, NEIGHBOR, b"acknowledged neighbor");
    for (fid, value) in rsk_fs::counter::COUNTER_FIDS.iter().zip(LEGACY_COUNTERS) {
        expect(store, fid.get(), &value);
    }
}

fn legacy_boot(medium: &Medium) {
    set_root(RootMode::Blank);
    write_legacy(medium, b"legacy owner");
    let epoch = [0x41; 16];
    let mut store = managed(medium);
    store.boot(epoch).unwrap();
    assert_legacy(&mut store, b"legacy owner");
    assert_activation(medium, epoch);
    assert_eq!(raw_fetch(medium, MANIFEST_FID), None);
    assert!(!store.root_closed());

    let mut cold = mounted(medium);
    assert_legacy(&mut cold, b"legacy owner");
    assert_activation(medium, epoch);
    // A second boot is a mount, not another import.
    let mut again = managed(medium);
    again.boot([0x99; 16]).unwrap();
    assert_legacy(&mut again, b"legacy owner");
    assert_activation(medium, epoch);

    // A counter record planted only in the main partition stays absent: the
    // counter partition is the only authority for a counter FID.
    let routed = Medium::new();
    write_legacy(&routed, b"routed owner");
    let wrong = rsk_fs::counter::EF_SIG_COUNT.get();
    raw_remove_in(&routed, COUNTER, wrong);
    raw_store(&routed, wrong, b"main-only counter");
    let mut routed_store = managed(&routed);
    routed_store.boot([0x44; 16]).unwrap();
    expect(&mut routed_store, OWNER, b"routed owner");
    assert_eq!(
        read_value(&mut routed_store, wrong).unwrap(),
        None,
        "a counter in the wrong partition must remain absent"
    );
}

fn legacy_administer(medium: &Medium) {
    set_root(RootMode::Blank);
    write_legacy(medium, b"fs legacy");
    let epoch = [0x42; 16];
    let mut fs = rsk_fs::Fs::new(managed(medium));
    assert_eq!(fs.storage_state(), StorageState::Recovery);
    fs.administer_storage(StorageAction::ImportLegacy, epoch)
        .unwrap();
    fs.scan();
    assert_eq!(fs.storage_state(), StorageState::Ready);
    let mut store = fs.into_storage();
    assert_legacy(&mut store, b"fs legacy");
    assert_activation(medium, epoch);
}

fn legacy_rescue(medium: &Medium) {
    set_root(RootMode::Blank);
    write_legacy(medium, b"rescue legacy");
    let rig = RescueRig::new(true);
    let mut app = rig.applet();
    let mut fs = rsk_fs::Fs::new(managed(medium));
    let before = medium.programs();

    assert_eq!(
        rescue_call(&mut fs, &mut app, 2, 0, b"IMPORTV2"),
        Sw::INCORRECT_P1P2
    );
    assert_eq!(
        rescue_call(&mut fs, &mut app, 1, 1, b"IMPORTV2"),
        Sw::INCORRECT_P1P2
    );
    assert_eq!(
        rescue_call(&mut fs, &mut app, 1, 0, b"IMPORTV2X"),
        Sw::DATA_INVALID
    );
    assert_eq!(
        rescue_call(&mut fs, &mut app, 0, 0, b"INITV2"),
        Sw::CONDITIONS_NOT_SATISFIED,
        "INITV2 re-initialized non-blank legacy media"
    );
    assert_eq!(medium.programs(), before, "a refused rescue gate wrote");

    let denied = RescueRig::new(false);
    let mut denied_app = denied.applet();
    assert_eq!(
        rescue_call(&mut fs, &mut denied_app, 1, 0, b"IMPORTV2"),
        Sw::CONDITIONS_NOT_SATISFIED
    );
    assert!(!denied.reboot());
    assert_eq!(medium.programs(), before, "denied presence wrote");

    assert_eq!(rescue_call(&mut fs, &mut app, 1, 0, b"IMPORTV2"), Sw::OK);
    assert!(rig.reboot());
    assert_eq!(fs.storage_state(), StorageState::Ready);
    assert_eq!(
        rescue_call(&mut fs, &mut app, 1, 0, b"IMPORTV2"),
        Sw::CONDITIONS_NOT_SATISFIED,
        "a mounted store may not be imported again"
    );

    let mut store = fs.into_storage();
    assert_legacy(&mut store, b"rescue legacy");
    assert_activation(medium, rescue_epoch(16));
}

fn legacy_rescue_initialize() {
    let medium = Medium::new();
    set_root(RootMode::Blank);
    let rig = RescueRig::new(true);
    let mut app = rig.applet();
    let mut fs = rsk_fs::Fs::new(managed(&medium));
    assert_eq!(
        rescue_call(&mut fs, &mut app, 2, 0, b"INITV2"),
        Sw::INCORRECT_P1P2
    );
    assert_eq!(
        rescue_call(&mut fs, &mut app, 0, 1, b"INITV2"),
        Sw::INCORRECT_P1P2
    );
    assert_eq!(
        rescue_call(&mut fs, &mut app, 0, 0, b"INITV3"),
        Sw::DATA_INVALID
    );
    assert_eq!(
        rescue_call(&mut fs, &mut app, 0, 0, b"IMPORTV2"),
        Sw::DATA_INVALID
    );
    assert_eq!(rescue_call(&mut fs, &mut app, 0, 0, b"INITV2"), Sw::OK);
    assert!(rig.reboot());
    let mut store = fs.into_storage();
    assert_eq!(read_value(&mut store, OWNER).unwrap(), None);
    assert_activation(&medium, rescue_epoch(0));
    store.write(OWNER, b"init owner").unwrap();
    drop(store);

    // A non-blank store refuses INITV2 instead of becoming empty.
    let nonblank = RescueRig::new(true);
    let mut nonblank_app = nonblank.applet();
    let mut nonblank_fs = rsk_fs::Fs::new(managed(&medium));
    assert_eq!(
        rescue_call(&mut nonblank_fs, &mut nonblank_app, 0, 0, b"INITV2"),
        Sw::CONDITIONS_NOT_SATISFIED
    );
    assert!(!nonblank.reboot());
    let mut recovered = mounted(&medium);
    expect(&mut recovered, OWNER, b"init owner");
    assert_activation(&medium, rescue_epoch(0));
}

fn legacy_manifest_cut(medium: &Medium) {
    set_root(RootMode::Blank);
    let Some(cut) = cut_import(medium, b"cut owner") else {
        panic!("no import budget reached the manifest window");
    };
    medium.restore(&cut);
    let mut interrupted = managed(medium);
    interrupted.mount().unwrap();
    assert_legacy(&mut interrupted, b"cut owner");
    let mut recovered = mounted(medium);
    assert_legacy(&mut recovered, b"cut owner");
    assert_eq!(raw_fetch(medium, MANIFEST_FID), None);
    let mut cold = mounted(medium);
    assert_legacy(&mut cold, b"cut owner");
}

fn manifest_corrupt(medium: &Medium) {
    set_root(RootMode::Blank);
    let Some(cut) = cut_import(medium, b"witness owner") else {
        panic!("no import budget reached the manifest window");
    };
    damage_manifest_and_legacy(medium, &cut, b"replayed owner");
    let before = medium.programs();
    let mut store = managed(medium);
    assert!(store.mount().is_err());
    assert_eq!(store.state(), StorageState::Recovery);
    assert!(
        store
            .administer(StorageAction::ImportLegacy, [0x44; 16])
            .is_err()
    );
    assert!(
        store
            .administer(StorageAction::Initialize, [0x45; 16])
            .is_err()
    );
    assert_eq!(
        medium.programs(),
        before,
        "a damaged v2 authority was re-imported or re-initialized"
    );
    let mut after = managed(medium);
    assert!(after.boot([0x46; 16]).is_err());
}

fn activation_witness(medium: &Medium) {
    set_root(RootMode::Blank);
    write_legacy(medium, b"activation owner");
    let epoch = [0x47; 16];
    let mut store = managed(medium);
    store.boot(epoch).unwrap();
    assert_activation(medium, epoch);

    // Lose the payload, then corrupt it: both are reconstructible from the
    // authenticated directory, and neither may re-initialize the store.
    raw_remove(medium, ACTIVATION_FID);
    let mut repaired = mounted(medium);
    assert_legacy(&mut repaired, b"activation owner");
    assert_activation(medium, epoch);

    let offsets = find_all(&medium.image(), ACTIVATION_MAGIC);
    assert!(!offsets.is_empty());
    for offset in offsets {
        medium.flash.borrow_mut().as_bytes_mut()[offset + 8] ^= 0x80;
    }
    let mut again = mounted(medium);
    assert_legacy(&mut again, b"activation owner");
    assert_activation(medium, epoch);
    assert_ne!(
        read_value(&mut again, OWNER).unwrap(),
        Some(Vec::new()),
        "a damaged witness re-initialized the store empty"
    );
}

fn root_rekey(medium: &Medium) {
    set_root(RootMode::Blank);
    let epoch = [0x48; 16];
    let store = tracked_store(medium, epoch, b"pre-otp owner");
    assert!(!store.root_closed());
    drop(store);

    set_root(RootMode::Fused);
    let mut otp = mounted(medium);
    assert!(otp.root_closed());
    assert_tracked(&mut otp, b"pre-otp owner");
    assert_activation(medium, epoch);
    drop(otp);

    // Idempotent: a second OTP mount neither rekeys nor loses anything.
    let mut again = mounted(medium);
    assert!(again.root_closed());
    assert_tracked(&mut again, b"pre-otp owner");
    drop(again);

    // The pre-OTP root is revoked: the same medium no longer opens under it.
    set_root(RootMode::Blank);
    let mut old = managed(medium);
    assert!(old.mount().is_err(), "the pre-OTP arm still opens");
    let mut revoked = managed(medium);
    assert!(
        revoked
            .administer(StorageAction::ImportLegacy, [0x98; 16])
            .is_err(),
        "the pre-OTP arm re-imported the OTP-rooted records"
    );
    assert!(
        revoked
            .administer(StorageAction::Initialize, [0x98; 16])
            .is_err(),
        "the pre-OTP arm re-initialised the OTP-rooted store"
    );

    // A changed epoch cannot be injected into an established store.
    set_root(RootMode::Fused);
    let mut booted = managed(medium);
    booted.boot([0x99; 16]).unwrap();
    assert_tracked(&mut booted, b"pre-otp owner");
    assert_activation(medium, epoch);
}

fn rekey_faults(medium: &Medium, history: &[u8]) {
    set_root(RootMode::Blank);
    let epoch = [0x49; 16];
    let store = tracked_store(medium, epoch, b"rekey owner");
    drop(store);

    set_root(RootMode::Fused);
    // `history[2]` selects two or three independent write faults; each mount
    // must fail on its own armed write, not on a latched predecessor.
    let faults = 2 + u32::from(history.get(2).copied().unwrap_or(0) & 1);
    for index in 0..faults {
        medium.arm_writes(1);
        let mut mount = managed(medium);
        assert!(
            mount.mount().is_err(),
            "rekey write fault {index} did not fail"
        );
        assert_eq!(
            medium.counts().write_refused.get(),
            index + 1,
            "rekey fault {index} did not fire independently"
        );
        drop(mount);
    }

    medium.clear_faults();
    // A cut on the first recovery program is a third independent event.
    medium.arm_cut(Some(0));
    let mut cut = managed(medium);
    let result = cut.mount();
    medium.arm_cut(None);
    assert!(
        result.is_err() || medium.counts().cuts.get() >= 1,
        "the recovery cut was never observed"
    );
    drop(cut);

    medium.clear_faults();
    let mut recovered = mounted(medium);
    assert!(recovered.root_closed());
    assert_tracked(&mut recovered, b"rekey owner");
    assert_activation(medium, epoch);
}

fn compaction(medium: &Medium) {
    set_root(RootMode::Blank);
    let epoch = [0x4A; 16];
    let mut store = tracked_store(medium, epoch, b"compact owner");
    let mut owners = Vec::new();
    // 40 × 512 B keeps the ring just under its reclaim reserve; `compact` drives
    // head a full lap, which is the reclaim under test.
    for index in 0..40u8 {
        let fid = OWNER + 0x10 + u16::from(index);
        let value = [index; 512];
        store.write(fid, &value).unwrap();
        owners.push((fid, value));
    }
    store.compact().unwrap();
    for (fid, value) in &owners {
        expect(&mut store, *fid, value);
    }
    assert_tracked(&mut store, b"compact owner");
    drop(store);

    let mut cold = mounted(medium);
    for (fid, value) in &owners {
        expect(&mut cold, *fid, value);
    }
    assert_tracked(&mut cold, b"compact owner");
    assert_activation(medium, epoch);
    let mut again = mounted(medium);
    assert_tracked(&mut again, b"compact owner");
    assert_activation(medium, epoch);
}

fn capacity(medium: &Medium) {
    set_root(RootMode::Blank);
    let epoch = [0x4B; 16];
    let mut store = initialized(medium, epoch);
    for (fid, value) in rsk_fs::counter::COUNTER_FIDS.iter().zip(LEGACY_COUNTERS) {
        store.write(fid.get(), &value).unwrap();
    }
    let mut acked = Vec::new();
    let mut exhausted = false;
    for index in 0..16u8 {
        let fid = OWNER + 0x100 + u16::from(index);
        let value = vec![index; rsk_fs::MAX_VALUE_BYTES];
        match store.write(fid, &value) {
            Ok(()) => acked.push((fid, value)),
            Err(_) => {
                exhausted = true;
                break;
            }
        }
    }
    assert!(exhausted, "the capacity scan never reached the ceiling");
    assert!(!acked.is_empty());
    drop(store);

    let mut recovered = mounted(medium);
    for (fid, value) in &acked {
        expect(&mut recovered, *fid, value);
    }
    for (fid, value) in rsk_fs::counter::COUNTER_FIDS.iter().zip(LEGACY_COUNTERS) {
        expect(&mut recovered, fid.get(), &value);
    }
    let (last_fid, _) = *acked.last().unwrap();
    recovered.remove(last_fid).unwrap();
    recovered.compact().unwrap();
    let replacement = OWNER + 0x300;
    recovered.write(replacement, &[0x5A; 512]).unwrap();
    expect(&mut recovered, replacement, &[0x5A; 512]);
    for (fid, value) in acked.iter().take(acked.len() - 1) {
        expect(&mut recovered, *fid, value);
    }
    for (fid, value) in rsk_fs::counter::COUNTER_FIDS.iter().zip(LEGACY_COUNTERS) {
        expect(&mut recovered, fid.get(), &value);
    }
    assert_activation(medium, epoch);
}

fn assert_old_or_new(store: &mut ManagedStore, fid: u16, old: &[u8], new: &[u8]) -> bool {
    let value = read_value(store, fid)
        .unwrap_or_else(|_| panic!("fid {fid:#06x} is unreadable after recovery"));
    match value {
        Some(value) => {
            assert!(
                value == old || value == new,
                "fid {fid:#06x} holds a value that is neither whole old nor whole new"
            );
            value == new
        }
        None => panic!("fid {fid:#06x} vanished after a failed update"),
    }
}

fn fault_silent_read(medium: &Medium) {
    set_root(RootMode::Blank);
    let epoch = [0x50; 16];
    let mut store = tracked_store(medium, epoch, b"fault owner");
    medium.only_range(MAIN);
    medium.arm_silent(1);
    medium.arm_read_after_silent(1);
    let result = store.write(OWNER, b"silent update");
    assert_eq!(
        medium.counts().silent.get(),
        1,
        "the silent write did not fire"
    );
    assert!(
        medium.counts().read_refused.get() >= 1,
        "the refused read-back did not fire"
    );
    medium.clear_faults();
    drop(store);

    let mut recovered = mounted(medium);
    let new = assert_old_or_new(&mut recovered, OWNER, b"fault owner", b"silent update");
    if result.is_ok() {
        assert!(new, "an acknowledged silent write was not the new value");
    }
    expect(&mut recovered, NEIGHBOR, b"acknowledged neighbor");
    for (fid, value) in rsk_fs::counter::COUNTER_FIDS.iter().zip(LEGACY_COUNTERS) {
        expect(&mut recovered, fid.get(), &value);
    }
    // Removable fault: the next two mounts agree.
    let mut again = mounted(medium);
    assert_eq!(
        assert_old_or_new(&mut again, OWNER, b"fault owner", b"silent update"),
        new,
        "the second mount changed the recovered value"
    );
    expect(&mut again, NEIGHBOR, b"acknowledged neighbor");
}

fn fault_torn(medium: &Medium) {
    set_root(RootMode::Blank);
    let epoch = [0x51; 16];
    let mut store = tracked_store(medium, epoch, b"torn owner");
    medium.only_range(MAIN);
    // The first program is the 8-byte item header, so one word is a real tear.
    medium.arm_torn(1, 4);
    let result = store.write(OWNER, b"torn update");
    assert_eq!(medium.counts().torn.get(), 1, "the torn write did not fire");
    medium.clear_faults();
    drop(store);

    let mut recovered = mounted(medium);
    let new = assert_old_or_new(&mut recovered, OWNER, b"torn owner", b"torn update");
    if result.is_ok() {
        assert!(new, "an acknowledged torn write was not the new value");
    }
    expect(&mut recovered, NEIGHBOR, b"acknowledged neighbor");
    let mut again = mounted(medium);
    assert_eq!(
        assert_old_or_new(&mut again, OWNER, b"torn owner", b"torn update"),
        new,
        "the second mount changed the recovered value"
    );
    expect(&mut again, NEIGHBOR, b"acknowledged neighbor");
}

fn fault_read_write_erase(medium: &Medium) {
    set_root(RootMode::Blank);
    let epoch = [0x52; 16];
    let store = tracked_store(medium, epoch, b"refusal owner");
    drop(store);

    medium.arm_reads(1);
    let mut reader = managed(medium);
    assert!(
        reader.mount().is_err(),
        "the read refusal did not abort mount"
    );
    assert_eq!(medium.counts().read_refused.get(), 1);
    drop(reader);

    let mut writer = mounted(medium);
    medium.arm_writes(1);
    assert!(writer.write(NEIGHBOR, b"refused").is_err());
    assert_eq!(medium.counts().write_refused.get(), 1);
    drop(writer);

    let mut compactor = mounted(medium);
    medium.arm_erases(1);
    let _ = compactor.compact();
    assert_eq!(medium.counts().erase_refused.get(), 1);
    medium.clear_faults();
    drop(compactor);

    let mut recovered = mounted(medium);
    expect(&mut recovered, OWNER, b"refusal owner");
    expect(&mut recovered, NEIGHBOR, b"acknowledged neighbor");
    assert_activation(medium, epoch);
}

fn fault_cuts(medium: &Medium) {
    set_root(RootMode::Blank);
    let epoch = [0x53; 16];
    let mut store = tracked_store(medium, epoch, b"cut owner");
    medium.arm_cut(Some(192));
    let result = store.write(OWNER, b"command cut");
    medium.arm_cut(None);
    assert!(
        medium.counts().cuts.get() >= 1,
        "the command cut was never observed"
    );
    drop(store);

    medium.arm_cut(Some(0));
    let mut recovery = managed(medium);
    let recovery_result = recovery.mount();
    medium.arm_cut(None);
    assert!(
        medium.counts().cuts.get() >= 2,
        "the recovery cut was hidden by the first fault"
    );
    drop(recovery);

    let mut recovered = mounted(medium);
    assert_old_or_new(&mut recovered, OWNER, b"cut owner", b"command cut");
    if result.is_ok() {
        expect(&mut recovered, OWNER, b"command cut");
    }
    expect(&mut recovered, NEIGHBOR, b"acknowledged neighbor");
    let _ = recovery_result;
    assert_activation(medium, epoch);
}

fn corrupt_during_rekey(medium: &Medium) {
    set_root(RootMode::Blank);
    let epoch = [0x54; 16];
    let store = tracked_store(medium, epoch, b"rekey witness");
    drop(store);
    set_root(RootMode::Fused);
    medium.arm_cut(Some(2048));
    let mut rekey = managed(medium);
    let result = rekey.mount();
    medium.arm_cut(None);
    assert!(result.is_err() || medium.counts().cuts.get() >= 1);
    drop(rekey);

    let checkpoints = find_all(&medium.image(), CHECKPOINT_MAGIC);
    assert!(!checkpoints.is_empty());
    medium.flash.borrow_mut().as_bytes_mut()[checkpoints[0] + 20] ^= 0x80;
    medium.clear_faults();
    let mut damaged = managed(medium);
    let observation = damaged.mount();
    if observation.is_ok() {
        assert_tracked(&mut damaged, b"rekey witness");
        assert_activation(medium, epoch);
    }
    // The pre-OTP arm never opens the rekeyed record again.
    set_root(RootMode::Blank);
    let mut old = managed(medium);
    assert!(old.mount().is_err());
}

fn corrupt_during_compaction(medium: &Medium) {
    set_root(RootMode::Blank);
    let epoch = [0x55; 16];
    let store = tracked_store(medium, epoch, b"compact witness");
    drop(store);
    let mut compactor = mounted(medium);
    medium.arm_cut(Some(1024));
    let result = compactor.compact();
    medium.arm_cut(None);
    assert!(result.is_err() || medium.counts().cuts.get() >= 1);
    drop(compactor);
    medium.clear_faults();
    let mut recovered = mounted(medium);
    assert_tracked(&mut recovered, b"compact witness");
    assert_activation(medium, epoch);
}

pub fn run(data: &[u8]) {
    // The caller may pass the history with or without its `V2H1` routing magic.
    let history = data.strip_prefix(MAGIC).unwrap_or(data);
    let kind = history.first().copied().unwrap_or(0) % 16;
    let medium = Medium::new();
    match kind {
        0 => legacy_boot(&medium),
        1 => legacy_administer(&medium),
        2 => legacy_rescue(&medium),
        3 => legacy_rescue_initialize(),
        4 => legacy_manifest_cut(&medium),
        5 => manifest_corrupt(&medium),
        6 => activation_witness(&medium),
        7 => root_rekey(&medium),
        8 => rekey_faults(&medium, history),
        9 => compaction(&medium),
        10 => capacity(&medium),
        11 => fault_silent_read(&medium),
        12 => fault_torn(&medium),
        13 => fault_read_write_erase(&medium),
        14 => fault_cuts(&medium),
        15 => {
            if history.get(1).copied().unwrap_or(0) & 1 == 0 {
                corrupt_during_rekey(&medium);
            } else {
                corrupt_during_compaction(&medium);
            }
        }
        _ => unreachable!(),
    }
    medium.clear_faults();
}

/// The rescue rig fills its epoch from a counting `Rng`; the refused INITV2
/// consumes the first draw, so IMPORTV2's epoch starts at `start`.
fn rescue_epoch(start: u8) -> [u8; 16] {
    let mut epoch = [0u8; 16];
    for (index, byte) in epoch.iter_mut().enumerate() {
        *byte = start.wrapping_add(u8::try_from(index).unwrap());
    }
    epoch
}
