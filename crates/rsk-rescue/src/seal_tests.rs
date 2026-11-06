// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

fn seal_at_boot(page: &mut Page, left: Option<u16>, scrubbed: bool) -> Status {
    super::seal_at_boot(page, left, scrubbed, false).status
}
use crate::otp_lock::{PAGE58_LOCK_VALUE, PRE_OTP_KEY_UNREADABLE, PRE_OTP_UNCHECKED};

struct Page {
    rows: [u32; 4096],
    test: bool,
    read_fault: Option<usize>,
    ecc_fault: Option<usize>,
    burn: u32,
    write_ok: bool,
    writes: usize,
    readback_fault: bool,
    corrected: Option<(usize, u16)>,
    replace_lock: Option<u32>,
}

impl Page {
    fn blank() -> Self {
        Self {
            rows: [0; 4096],
            test: false,
            read_fault: None,
            ecc_fault: None,
            burn: PAGE58_LATCH_VALUE,
            write_ok: true,
            writes: 0,
            readback_fault: false,
            corrected: None,
            replace_lock: None,
        }
    }

    fn provisioned() -> Self {
        let mut page = Self::blank();
        for base in [DEVK_ROW, MKEK_ROW] {
            for i in 0..KEY_ROWS {
                page.rows[base + i] = 0x351111;
                page.rows[base + CHAFF_OFFSET + i] = 0xCAEEEE;
            }
        }
        page
    }
}

impl Otp for Page {
    fn test_keys(&self) -> bool {
        self.test
    }
    fn read_raw(&mut self, row: usize) -> Option<u32> {
        if self.read_fault == Some(row) || self.readback_fault && self.writes != 0 {
            None
        } else {
            Some(self.rows[row])
        }
    }
    fn read_ecc(&mut self, row: usize) -> Option<u16> {
        if let Some((at, word)) = self.corrected
            && at == row
        {
            return Some(word);
        }
        (self.ecc_fault != Some(row)).then_some(self.rows[row] as u16)
    }
    fn burn_lock(&mut self, value: u32) -> bool {
        self.writes += 1;
        let before = self.rows[PAGE58_LOCK1_ROW];
        if [0, 8, 16]
            .iter()
            .filter(|bit| before & (1 << *bit) != 0)
            .count()
            >= 2
        {
            return false;
        }
        if value & !before & 0x010101 != 0 {
            assert_eq!(
                before & PAGE58_LOCK_VALUE,
                PAGE58_LOCK_VALUE,
                "latch before access lock"
            );
        }
        self.rows[PAGE58_LOCK1_ROW] |= value & self.burn;
        if let Some(raw) = self.replace_lock {
            self.rows[PAGE58_LOCK1_ROW] = raw;
        }
        self.write_ok
    }
}

#[test]
fn secure_read_only_without_the_access_lock_quarantines_before_migration() {
    let mut page = Page::provisioned();
    page.rows[PAGE58_LOCK1_ROW] = 0x010100;
    let outcome = super::seal_at_boot(&mut page, Some(0), true, false);
    assert!(
        outcome.quarantine,
        "Secure read-only alone is not a sealed access lock"
    );
    assert_eq!(outcome.status, Status::IncompleteLock);
    assert_eq!(check_provisioning(&mut page), Err(Status::IncompleteLock));
    assert_eq!(page.writes, 0);
}

#[test]
fn blank_and_fake_keys_never_write() {
    let mut page = Page::blank();
    assert_eq!(
        seal_at_boot(&mut page, Some(0), true),
        Status::Unprovisioned
    );
    assert_eq!(page.writes, 0);
    page.test = true;
    assert_eq!(seal_at_boot(&mut page, Some(0), true), Status::TestKeys);
    assert_eq!(page.writes, 0);
    let mut page = Page::provisioned();
    page.test = true;
    assert_eq!(seal_at_boot(&mut page, Some(0), true), Status::TestKeys);
    assert_eq!(page.writes, 0);
}

#[test]
fn first_boot_and_old_lock_finish_once_without_presence() {
    for raw in [0, PAGE58_LOCK_VALUE] {
        let mut page = Page::provisioned();
        page.rows[PAGE58_LOCK1_ROW] = raw;
        assert_eq!(seal_at_boot(&mut page, Some(0), true), Status::Sealed);
        assert_eq!(page.rows[PAGE58_LOCK1_ROW], PAGE58_LATCH_VALUE);
        let writes = if raw == 0 { 2 } else { 1 };
        assert_eq!(page.writes, writes);
        assert_eq!(seal_at_boot(&mut page, Some(0), true), Status::Sealed);
        assert_eq!(page.writes, writes);
    }
}

#[test]
fn migration_and_scrub_failures_leave_fuses_untouched() {
    for left in [
        None,
        Some(1),
        Some(2),
        Some(4),
        Some(8),
        Some(16),
        Some(32),
        Some(0x8000),
        Some(PRE_OTP_UNCHECKED),
        Some(PRE_OTP_KEY_UNREADABLE),
    ] {
        let mut page = Page::provisioned();
        assert_eq!(
            seal_at_boot(&mut page, left, true),
            Status::MigrationPending
        );
        assert_eq!(page.writes, 0);
        assert_eq!(page.rows[PAGE58_LOCK1_ROW], 0);
        assert_eq!(
            seal_at_boot(&mut page, Some(0), false),
            Status::ScrubPending
        );
        assert_eq!(page.writes, 0);
        assert_eq!(seal_at_boot(&mut page, Some(0), true), Status::Sealed);
    }
}

#[test]
fn every_torn_key_or_chaff_prefix_stays_unsealed() {
    let order = [
        DEVK_ROW,
        MKEK_ROW,
        DEVK_ROW + CHAFF_OFFSET,
        MKEK_ROW + CHAFF_OFFSET,
    ];
    let complete = Page::provisioned();
    for count in 0..KEY_ROWS * order.len() {
        let mut page = Page::blank();
        for index in 0..count {
            let row = order[index / KEY_ROWS] + index % KEY_ROWS;
            page.rows[row] = complete.rows[row];
        }
        assert_ne!(
            seal_at_boot(&mut page, Some(0), true),
            Status::Sealed,
            "cut {count}"
        );
        assert_eq!(page.writes, 0, "cut {count}");
    }
}

#[test]
fn every_key_chaff_and_lock_read_failure_refuses_burn() {
    let rows = (DEVK_ROW..DEVK_ROW + KEY_ROWS * 4).chain([PAGE58_LOCK1_ROW]);
    for row in rows {
        let mut page = Page::provisioned();
        page.read_fault = Some(row);
        assert_eq!(
            seal_at_boot(&mut page, Some(0), true),
            Status::ReadFailed,
            "row {row}"
        );
        assert_eq!(page.writes, 0);
    }
    for row in DEVK_ROW..MKEK_ROW + KEY_ROWS {
        let mut page = Page::provisioned();
        page.ecc_fault = Some(row);
        assert_eq!(seal_at_boot(&mut page, Some(0), true), Status::ReadFailed);
        assert_eq!(page.writes, 0);
    }
}

#[test]
fn invalid_devk_and_foreign_lock_are_never_sealed() {
    for value in [0, 0xFFFF] {
        let mut page = Page::provisioned();
        page.rows[DEVK_ROW..DEVK_ROW + KEY_ROWS].fill(value);
        assert_eq!(seal_at_boot(&mut page, Some(0), true), Status::Incomplete);
        assert_eq!(page.writes, 0);
    }
    for bit in 0..32 {
        if PAGE58_LATCH_VALUE & (1 << bit) != 0 {
            continue;
        }
        let mut page = Page::provisioned();
        page.rows[PAGE58_LOCK1_ROW] = 1 << bit;
        assert_eq!(seal_at_boot(&mut page, Some(0), true), Status::ForeignLock);
        assert_eq!(page.writes, 0);
    }
}

#[test]
fn every_partial_latch_can_resume_only_after_migration_and_scrub() {
    let mut subset = PAGE58_LATCH_VALUE;
    loop {
        let mut page = Page::provisioned();
        page.rows[PAGE58_LOCK1_ROW] = subset;
        let blocked = [0, 8, 16]
            .iter()
            .filter(|bit| subset & (1 << *bit) != 0)
            .count()
            >= 2;
        if !blocked {
            assert_eq!(
                seal_at_boot(&mut page, Some(1), true),
                Status::MigrationPending
            );
            assert_eq!(page.writes, 0);
            assert_eq!(
                seal_at_boot(&mut page, Some(0), false),
                Status::ScrubPending
            );
            assert_eq!(page.writes, 0);
        }
        let partial_closed = subset != PAGE58_LATCH_VALUE && arms_closed(subset);
        let invalid = blocked && !arms_closed(subset);
        let outcome = super::seal_at_boot(&mut page, Some(0), true, arms_closed(subset));
        assert_eq!(outcome.quarantine, invalid);
        assert_eq!(
            outcome.status,
            if invalid {
                Status::IncompleteLock
            } else if partial_closed {
                Status::PartialLatch
            } else {
                Status::Sealed
            }
        );
        assert_eq!(
            page.rows[PAGE58_LOCK1_ROW],
            if blocked { subset } else { PAGE58_LATCH_VALUE }
        );
        if blocked {
            assert_eq!(page.writes, 0);
        }
        if subset == 0 {
            break;
        }
        subset = (subset - 1) & PAGE58_LATCH_VALUE;
    }
}

#[test]
fn every_access_lock_cut_preserves_secure_writes_for_retry() {
    let mut subset = PAGE58_LOCK_VALUE;
    loop {
        let mut page = Page::provisioned();
        page.burn = subset;
        assert_eq!(seal_at_boot(&mut page, Some(0), true), Status::WriteFailed);
        assert_eq!(page.rows[PAGE58_LOCK1_ROW], subset);
        page.burn = PAGE58_LATCH_VALUE;
        assert_eq!(seal_at_boot(&mut page, Some(0), true), Status::Sealed);
        assert_eq!(page.rows[PAGE58_LOCK1_ROW], PAGE58_LATCH_VALUE);
        if subset == 0 {
            break;
        }
        subset = (subset - 1) & PAGE58_LOCK_VALUE;
    }
}

#[test]
fn every_final_latch_cut_keeps_all_access_lock_copies() {
    for bits in 0..8 {
        let copies = (bits & 1) | ((bits & 2) << 7) | ((bits & 4) << 14);
        let raw = PAGE58_LOCK_VALUE | copies;
        let mut page = Page::provisioned();
        page.rows[PAGE58_LOCK1_ROW] = PAGE58_LOCK_VALUE;
        page.burn = raw;
        let outcome = super::seal_at_boot(&mut page, Some(0), true, false);
        assert_eq!(page.rows[PAGE58_LOCK1_ROW], raw);
        assert!(!outcome.quarantine);
        assert_eq!(outcome.restart, bits.count_ones() >= 2);
        page.burn = PAGE58_LATCH_VALUE;
        let expected = if bits.count_ones() == 2 {
            Status::PartialLatch
        } else {
            Status::Sealed
        };
        assert_eq!(seal_at_boot(&mut page, Some(0), true), expected);
    }
}

#[test]
fn unexpected_secure_only_burn_readback_quarantines_immediately() {
    let mut page = Page::provisioned();
    page.replace_lock = Some(0x010100);
    let outcome = super::seal_at_boot(&mut page, Some(0), true, false);
    assert_eq!(outcome.status, Status::IncompleteLock);
    assert!(outcome.quarantine);
    assert!(!outcome.restart);
    assert_eq!(page.writes, 1);
}

#[test]
fn failed_write_or_readback_never_reports_success() {
    let mut page = Page::provisioned();
    page.write_ok = false;
    assert_eq!(seal_at_boot(&mut page, Some(0), true), Status::WriteFailed);
    page.write_ok = true;
    assert_eq!(seal_at_boot(&mut page, Some(0), true), Status::Sealed);
    assert_eq!(page.writes, 2);
    let mut page = Page::provisioned();
    page.readback_fault = true;
    assert_eq!(seal_at_boot(&mut page, Some(0), true), Status::ReadFailed);
    page.readback_fault = false;
    assert_eq!(seal_at_boot(&mut page, Some(0), true), Status::Sealed);
    assert_eq!(page.writes, 2);
}

#[test]
fn partial_and_failed_burns_refresh_bindings_without_retry_loops() {
    for raw in [0, 0x3D3C3C, 0x3D3D3C, PAGE58_LATCH_VALUE] {
        let mut page = Page::provisioned();
        page.rows[PAGE58_LOCK1_ROW] = PAGE58_LOCK_VALUE;
        page.burn = raw;
        page.write_ok = false;
        let result = super::seal_at_boot(&mut page, Some(0), true, false);
        assert_eq!(result.restart, arms_closed(raw));
        assert!(!result.quarantine);
        assert_eq!(result.status, Status::WriteFailed);
        let result = super::seal_at_boot(&mut page, Some(0), true, arms_closed(raw));
        assert!(
            !result.restart,
            "persistent write failures must not reboot-loop"
        );
    }
    let mut page = Page::provisioned();
    page.readback_fault = true;
    let result = super::seal_at_boot(&mut page, Some(0), true, false);
    assert_eq!(
        result,
        Outcome {
            status: Status::ReadFailed,
            restart: false,
            quarantine: true
        }
    );
}

#[test]
fn corrupted_raw_ecc_never_becomes_a_root_or_a_sealed_page() {
    for row in DEVK_ROW..MKEK_ROW + KEY_ROWS {
        let mut page = Page::provisioned();
        page.rows[row] ^= 3 << 16;
        page.rows[row + CHAFF_OFFSET] = page.rows[row] ^ RAW_MASK;
        assert_eq!(check_provisioning(&mut page), Err(Status::Incomplete));
        assert_eq!(seal_at_boot(&mut page, Some(0), true), Status::Incomplete);
        assert_eq!(page.writes, 0);
    }
}

#[test]
fn immutable_page_retains_hardware_ecc_correction() {
    for bit in 0..22 {
        let mut page = Page::provisioned();
        page.rows[PAGE58_LOCK1_ROW] = PAGE58_LATCH_VALUE;
        page.rows[MKEK_ROW] ^= 1 << bit;
        page.corrected = Some((MKEK_ROW, 0x1111));
        assert_eq!(check_provisioning(&mut page), Ok(Some(PAGE58_LATCH_VALUE)));
        assert_eq!(seal_at_boot(&mut page, Some(0), true), Status::Sealed);
        assert_eq!(page.writes, 0);
        page.rows[MKEK_ROW] ^= 1 << ((bit + 1) % 22);
        assert_eq!(check_provisioning(&mut page), Err(Status::Incomplete));
    }
}

#[test]
fn corrected_keys_still_need_complete_chaff_before_sealing() {
    let mut page = Page::provisioned();
    page.rows[MKEK_ROW] ^= 1;
    page.corrected = Some((MKEK_ROW, 0x1111));
    assert_eq!(check_provisioning(&mut page), Err(Status::Incomplete));
    page.rows[MKEK_ROW + CHAFF_OFFSET] = page.rows[MKEK_ROW] ^ RAW_MASK;
    assert_eq!(check_provisioning(&mut page), Ok(Some(0)));
    let last = MKEK_ROW + CHAFF_OFFSET + KEY_ROWS - 1;
    let complete = page.rows[last];
    page.rows[last] = 0;
    assert_eq!(seal_at_boot(&mut page, Some(0), true), Status::Incomplete);
    assert_eq!(page.writes, 0);
    page.rows[last] = complete;
    assert_eq!(seal_at_boot(&mut page, Some(0), true), Status::Sealed);
}

#[test]
fn polarity_repair_and_chaff_are_checked_independently() {
    let mut page = Page::provisioned();
    page.rows[MKEK_ROW] = 0xCAEEEE;
    page.rows[MKEK_ROW + CHAFF_OFFSET] = 0x351111;
    page.corrected = Some((MKEK_ROW, 0x1111));
    assert_eq!(check_provisioning(&mut page), Ok(Some(0)));
    page.rows[MKEK_ROW] |= 0x11;
    page.rows[MKEK_ROW + CHAFF_OFFSET] = page.rows[MKEK_ROW] ^ RAW_MASK;
    assert_eq!(check_provisioning(&mut page), Err(Status::Incomplete));
    let mut page = Page::provisioned();
    page.rows[MKEK_ROW + CHAFF_OFFSET] = RAW_MASK;
    assert_eq!(check_provisioning(&mut page), Err(Status::Incomplete));
}

#[test]
fn absent_mkek_and_out_of_range_devk_refuse_even_with_valid_ecc_and_chaff() {
    for (base, raw) in [(MKEK_ROW, 0), (DEVK_ROW, 0x1EFFFF)] {
        let mut page = Page::provisioned();
        for row in base..base + KEY_ROWS {
            page.rows[row] = raw;
            page.rows[row + CHAFF_OFFSET] = raw ^ RAW_MASK;
        }
        assert_eq!(check_provisioning(&mut page), Err(Status::Incomplete));
        assert_eq!(seal_at_boot(&mut page, Some(0), true), Status::Incomplete);
        assert_eq!(page.writes, 0);
    }
}

#[test]
fn contradictory_post_write_latch_quarantines_root_reads() {
    for raw in [0, PAGE58_LATCH_VALUE | 2] {
        let mut page = Page::provisioned();
        page.rows[PAGE58_LOCK1_ROW] = PAGE58_LOCK_VALUE;
        page.replace_lock = Some(raw);
        let outcome = super::seal_at_boot(&mut page, Some(0), true, false);
        assert_eq!(outcome.status, Status::ForeignLock);
        assert!(outcome.quarantine);
        assert!(!outcome.restart);
    }
}

#[test]
fn an_existing_closed_latch_refreshes_open_ram_bindings_too() {
    let mut page = Page::provisioned();
    page.rows[PAGE58_LOCK1_ROW] = PAGE58_LATCH_VALUE;
    let outcome = super::seal_at_boot(&mut page, Some(0), true, false);
    assert_eq!(outcome.status, Status::Sealed);
    assert!(outcome.restart);
    assert_eq!(page.writes, 0);
}

struct ScrubStorage {
    inner: rsk_fs::storage::ram::RamStorage,
    fault: u8,
    compacted: bool,
}

impl rsk_fs::Storage for ScrubStorage {
    fn read(&mut self, fid: u16, out: &mut [u8]) -> Option<usize> {
        self.inner.read(fid, out)
    }
    fn write(&mut self, fid: u16, bytes: &[u8]) -> rsk_sdk::error::Result<()> {
        if self.fault == 3 && fid == rsk_fs::EF_HARDENED {
            return Err(rsk_sdk::error::Error::MemoryFatal);
        }
        if fid == rsk_fs::EF_HARDENED && self.fault == 4 {
            return self.inner.write(fid, &[2]);
        }
        if fid == rsk_fs::EF_HARDENED && self.fault == 5 {
            return self.inner.write(fid, &[1, 0]);
        }
        self.inner.write(fid, bytes)
    }
    fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
        if self.fault == 1 && fid == rsk_fs::EF_HARDENED {
            return Ok(());
        }
        self.inner.remove(fid)
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.inner.size(fid)
    }
    fn for_each_key(&mut self, visit: &mut dyn FnMut(u16)) -> bool {
        self.inner.for_each_key(visit)
    }
    fn compact(&mut self) -> rsk_sdk::error::Result<()> {
        if self.fault == 2 {
            return Err(rsk_sdk::error::Error::MemoryFatal);
        }
        self.compacted = true;
        Ok(())
    }
}

#[test]
fn final_scrub_cannot_reuse_a_stale_marker_or_ignore_a_failed_step() {
    use rsk_fs::Storage;
    for fault in 0..=5 {
        let mut inner = rsk_fs::storage::ram::RamStorage::new();
        inner.write(rsk_fs::EF_HARDENED, &[1]).unwrap();
        inner.write(0xB000, b"keep").unwrap();
        let mut fs = rsk_fs::Fs::new(ScrubStorage {
            inner,
            fault,
            compacted: false,
        });
        fs.scan();
        assert_eq!(scrub_before_seal(&mut fs), fault == 0);
        let mut storage = fs.into_storage();
        assert_eq!(storage.compacted, fault == 0 || fault >= 3);
        let mut value = [0; 4];
        assert_eq!(storage.read(0xB000, &mut value), Some(4));
        assert_eq!(&value, b"keep");
        storage.fault = 0;
        let mut rebooted = rsk_fs::Fs::new(storage);
        rebooted.scan();
        assert!(scrub_before_seal(&mut rebooted));
        assert!(rebooted.into_storage().compacted);
    }
}

#[test]
fn a_lock_without_either_root_key_is_incomplete_not_an_unprovisioned_page() {
    for raw in [PAGE58_LOCK_VALUE, PAGE58_LATCH_VALUE, 0x010100, 1] {
        let mut page = Page::blank();
        page.rows[PAGE58_LOCK1_ROW] = raw;
        let before = page.rows;
        assert_eq!(check_provisioning(&mut page), Err(Status::Incomplete));
        assert_eq!(seal_at_boot(&mut page, Some(0), true), Status::Incomplete);
        assert_eq!(page.rows, before);
        assert_eq!(page.writes, 0);
    }
}
