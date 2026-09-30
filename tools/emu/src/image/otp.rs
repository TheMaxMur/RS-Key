// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! OTP to the depth the bootrom and the image use it: 4096 rows of 24 bits that
//! only burn 0 -> 1, the ECC and raw apertures, page locks from PAGEn_LOCK1,
//! SBPI programming as the ROM's `otp_access` does it, CRITICAL from its copies.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rp2350_emu::peripherals::apply_alias_rmw;
use rp2350_emu::{MmioCtx, MmioDevice};

use super::Log;

pub const OTP_BASE: u32 = 0x4012_0000;
pub const OTP_DATA_BASE: u32 = 0x4013_0000;
pub const OTP_DATA_MOUNT_SIZE: u32 = 0x1_0000;
pub const ROWS: usize = 4096;

pub const CHIPID0_ROW: usize = 0x000;
pub const CRIT0_ROW: usize = 0x038;
pub const CRIT1_ROW: usize = 0x040;
pub const KEY1_VALID_ROW: usize = 0xF79;
pub const PAGE0_LOCK0_ROW: usize = 0xF80;

// ---------------------------------------------------------------------------
// ECC (varm_otp.c `otp_ecc_parity_table`, `s_otp_calculate_ecc`)
// ---------------------------------------------------------------------------

const PARITY: [u32; 6] = [
    0b0000001010110101011011,
    0b0000000011011001101101,
    0b0000001100011110001110,
    0b0000000000011111110000,
    0b0000001111100000000000,
    0b0111111111111111111111,
];

/// 16 data bits -> the 22-bit row the ROM programs for an ECC write.
pub fn ecc_encode(data: u16) -> u32 {
    let mut p = data as u32;
    for (i, m) in PARITY.iter().enumerate() {
        p |= ((p & m).count_ones() & 1) << (16 + i);
    }
    p
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ecc {
    Clean,
    Corrected,
    Uncorrectable,
}

/// Decode a raw row as the ECC aperture does.
pub fn ecc_decode(raw: u32) -> (u16, Ecc) {
    let mut v = raw & 0x3F_FFFF;
    if (raw >> 22) & 3 == 3 {
        v = !raw & 0x3F_FFFF; // bit repair by polarity
    }
    if ecc_encode(v as u16) == v {
        return (v as u16, Ecc::Clean);
    }
    for bit in 0..22 {
        let t = v ^ (1 << bit);
        if ecc_encode(t as u16) == t {
            return (t as u16, Ecc::Corrected);
        }
    }
    (v as u16, Ecc::Uncorrectable)
}

// ---------------------------------------------------------------------------
// The array and the controller state both mounts share
// ---------------------------------------------------------------------------

pub struct OtpCore {
    pub rows: Vec<u32>,
    sw_lock: [u32; 64],
    usr: u32,
    critical: u32,
    key_valid: u32,
    debugen: u32,
    debugen_lock: u32,
    archsel: u32,
    bootdis: u32,
    other: BTreeMap<u32, u32>,
    sbpi_wdata: [u32; 4],
    sbpi_rdata: [u32; 4],
    sbpi_status: u32,
    dap: [u8; 64],
    pmc: [u8; 64],
    /// (cycle, row, before, after) of every fuse burn this run.
    pub burns: Vec<(u64, usize, u32, u32)>,
    pub denied_reads: u64,
    pub faults: u64,
    first_read: std::collections::HashSet<(usize, u8)>,
    log: Log,
}

/// Bitwise 2-of-3 majority of the three bytes of a lock row.
fn vote3(row: u32) -> u32 {
    let (a, b, c) = (row & 0xFF, (row >> 8) & 0xFF, (row >> 16) & 0xFF);
    (a & b) | (a & c) | (b & c)
}

/// Bitwise "at least 3 of 8" over eight copies.
fn vote3of8(copies: &[u32]) -> u32 {
    let mut out = 0;
    for bit in 0..24 {
        let n = copies.iter().filter(|&&c| c & (1 << bit) != 0).count();
        if n >= 3 {
            out |= 1 << bit;
        }
    }
    out
}

impl OtpCore {
    pub fn new(rows: Vec<u32>, log: Log) -> Self {
        assert_eq!(rows.len(), ROWS);
        let mut c = Self {
            rows,
            sw_lock: [0; 64],
            usr: 1,
            critical: 0,
            key_valid: 0,
            debugen: 0,
            debugen_lock: 0,
            archsel: 0,
            bootdis: 0,
            other: BTreeMap::new(),
            sbpi_wdata: [0; 4],
            sbpi_rdata: [0; 4],
            sbpi_status: 0,
            dap: [0; 64],
            pmc: [0; 64],
            burns: Vec::new(),
            denied_reads: 0,
            faults: 0,
            first_read: Default::default(),
            log,
        };
        c.power_up();
        c
    }

    /// The OTP power-up sequence: critical flags, key validity and the
    /// page locks load from the array.
    pub fn power_up(&mut self) {
        let crit1 = vote3of8(&self.rows[CRIT1_ROW..CRIT1_ROW + 8]);
        let crit0 = vote3of8(&self.rows[CRIT0_ROW..CRIT0_ROW + 8]);
        self.critical = (crit1 & 0x7F) | ((crit0 & 0x3) << 16);
        self.key_valid = 0;
        for k in 0..6 {
            // KEYn_VALID rows are RBIT-3 in one row: bit 0 of each byte.
            if vote3(self.rows[KEY1_VALID_ROW + k]) & 1 != 0 {
                self.key_valid |= 1 << (k + 1);
            }
        }
        for page in 0..64 {
            let lock0 = vote3(self.rows[PAGE0_LOCK0_ROW + 2 * page]);
            let lock1 = vote3(self.rows[PAGE0_LOCK0_ROW + 2 * page + 1]);
            let mut s = lock1 & 3;
            let mut ns = (lock1 >> 2) & 3;
            // A registered key that has not been entered (keys are never
            // entered here) gates the page to NO_KEY_STATE.
            let (key_r, key_w) = ((lock0 >> 3) & 7, lock0 & 7);
            let registered = |k: u32| k != 0 && self.key_valid & (1 << k) != 0;
            if registered(key_r) {
                let st = if lock0 & 0x40 != 0 { 3 } else { 1 };
                s = s.max(st);
                ns = ns.max(st);
            } else if registered(key_w) {
                s = s.max(1);
                ns = ns.max(1);
            }
            self.sw_lock[page] = s | (ns << 2);
        }
        self.usr = 1;
        self.sbpi_status = 0;
    }

    #[cfg(test)]
    pub fn critical(&self) -> u32 {
        self.critical
    }

    #[cfg(test)]
    pub fn sw_lock(&self, page: usize) -> u32 {
        self.sw_lock[page]
    }

    fn note(&self, cycle: u64, text: String) {
        self.log
            .lock()
            .unwrap()
            .push((cycle, format!("OTP: {text}")));
    }

    /// Whether a Secure read of `row` is permitted.
    fn readable(&self, row: usize) -> bool {
        let page = row / 64;
        page >= 62 || self.sw_lock[page] & 3 < 2
    }

    fn seen(&mut self, row: usize, view: u8, cycle: u64) {
        if self.first_read.insert((row, view)) && self.first_read.len() <= 400 {
            let name = ["ECC", "raw", "ECC guarded", "raw guarded"][view as usize];
            self.note(cycle, format!("first {name} read of row {row:#05x}"));
        }
    }

    /// A data-aperture read. `offset` is from 0x4013_0000.
    fn data_read(&mut self, offset: u32, size: u8, ctx: &mut MmioCtx) -> u32 {
        let view = (offset >> 14) as u8; // 0 ECC, 1 raw, 2 ECC guarded, 3 raw guarded
        let guarded = view >= 2;
        let off = offset & 0x3FFF;
        if self.usr & 1 == 0 {
            // DCTRL clear: the USER interface belongs to SBPI.
            self.faults += 1;
            ctx.bus_fault();
            return 0;
        }
        if view & 1 == 1 {
            let row = (off / 4) as usize;
            self.seen(row, view, ctx.cycle);
            let v = if self.readable(row) {
                self.rows[row] & 0xFF_FFFF
            } else {
                self.denied_reads += 1;
                if guarded {
                    self.faults += 1;
                    ctx.bus_fault();
                    return 0;
                }
                0xFFFF_FFFF
            };
            return v >> ((offset & 3) * 8);
        }
        // ECC view: row r at byte 2r; a word covers rows r, r+1.
        let first = (off / 2) as usize;
        let nrows = if size == 4 { 2 } else { 1 };
        let mut v = 0u32;
        for k in 0..nrows {
            let row = first + k;
            if row >= ROWS {
                break;
            }
            self.seen(row, view, ctx.cycle);
            if !self.readable(row) {
                self.denied_reads += 1;
                if guarded {
                    self.faults += 1;
                    ctx.bus_fault();
                    return 0;
                }
                return 0xFFFF_FFFF;
            }
            let (d, ecc) = ecc_decode(self.rows[row]);
            if ecc == Ecc::Uncorrectable && guarded {
                self.faults += 1;
                ctx.bus_fault();
                return 0;
            }
            v |= (d as u32) << (16 * k);
        }
        if size == 1 && off & 1 != 0 {
            v >>= 8;
        }
        v
    }

    fn sbpi_exec(&mut self, instr: u32, cycle: u64) {
        let is_wr = instr & (1 << 29) != 0;
        let has_payload = instr & (1 << 28) != 0;
        let size_m1 = (instr >> 24) & 0xF;
        let target = (instr >> 16) & 0xFF;
        let cmd = (instr >> 8) & 0xFF;
        let wdata = if size_m1 == 0 {
            instr & 0xFF
        } else {
            self.sbpi_wdata[0] & 0xFF
        };
        const TARGET_DAP: u32 = 0x02;
        const TARGET_PMC: u32 = 0x3A;
        if self.usr & 1 != 0 {
            self.note(
                cycle,
                format!("SBPI instruction {instr:#010x} with USR.DCTRL set"),
            );
        }
        match (is_wr, has_payload) {
            (true, true) if cmd & 0xC0 == 0xC0 => {
                let reg = (cmd & 0x3F) as usize;
                match target {
                    TARGET_DAP => self.dap[reg] = wdata as u8,
                    TARGET_PMC => self.pmc[reg] = wdata as u8,
                    _ => self.note(cycle, format!("SBPI write to unknown target {target:#x}")),
                }
            }
            (false, true) if cmd & 0xC0 == 0x80 => {
                let reg = (cmd & 0x3F) as usize;
                // PMC CTRL_STATUS bit 7 is "busy": programming here is
                // instant, so it always reads idle.
                self.sbpi_rdata[0] = match target {
                    TARGET_DAP => self.dap[reg] as u32,
                    TARGET_PMC if reg == 0x3F => 0,
                    TARGET_PMC => self.pmc[reg] as u32,
                    _ => 0,
                };
                self.sbpi_status |= 1; // RDATA_VLD
            }
            (true, false) if target == TARGET_PMC && cmd == 0x01 => {
                // START: program the row the DAP holds.
                let row = (self.dap[0x3C] as usize | ((self.dap[0x3D] as usize) << 8)) & (ROWS - 1);
                let data = self.dap[0x00] as u32
                    | (self.dap[0x01] as u32) << 8
                    | (self.dap[0x20] as u32) << 16;
                let before = self.rows[row];
                self.rows[row] |= data;
                self.burns.push((cycle, row, before, self.rows[row]));
                self.note(
                    cycle,
                    format!(
                        "burn row {row:#05x}: {before:#08x} -> {:#08x}",
                        self.rows[row]
                    ),
                );
            }
            (true, false) if target == TARGET_PMC && cmd == 0x02 => {} // STOP
            _ => self.note(cycle, format!("unmodelled SBPI instruction {instr:#010x}")),
        }
        self.sbpi_status |= 1 << 4; // INSTR_DONE
    }

    fn ctrl_read(&mut self, offset: u32) -> u32 {
        match offset & !3 {
            o @ 0x000..=0x0FC => self.sw_lock[(o / 4) as usize],
            o @ 0x114..=0x120 => std::mem::take(&mut self.sbpi_rdata[((o - 0x114) / 4) as usize]),
            0x124 => self.sbpi_status,
            0x128 => self.usr,
            0x12C => 0x0F,      // DBG: PSM_DONE | BOOT_DONE | ROSC_UP_SEEN | ROSC_UP
            0x138..=0x144 => 0, // CRT_KEY_Wn: write-only
            0x148 => self.critical,
            0x14C => self.key_valid,
            0x150 => self.debugen,
            0x154 => self.debugen_lock,
            0x158 => self.archsel,
            0x15C => 0, // ARCHSEL_STATUS: both Arm
            0x160 => self.bootdis,
            o => *self.other.get(&o).unwrap_or(&0),
        }
    }

    fn ctrl_write(&mut self, offset: u32, value: u32, alias: u32, cycle: u64) {
        let rmw = |old: u32| {
            let mut v = old;
            apply_alias_rmw(&mut v, value, alias);
            v
        };
        match offset & !3 {
            o @ 0x000..=0x0FC => {
                // Locks only advance: writes OR in.
                let i = (o / 4) as usize;
                let before = self.sw_lock[i];
                self.sw_lock[i] |= rmw(before) & 0xF;
                if self.sw_lock[i] != before {
                    self.note(
                        cycle,
                        format!("SW_LOCK{i} {before:#x} -> {:#x}", self.sw_lock[i]),
                    );
                }
            }
            0x100 => {
                let v = rmw(0);
                if v & (1 << 30) != 0 {
                    self.sbpi_exec(v, cycle);
                }
            }
            o @ 0x104..=0x110 => self.sbpi_wdata[((o - 0x104) / 4) as usize] = rmw(0),
            0x124 => self.sbpi_status &= !value, // W1C
            0x128 => self.usr = rmw(self.usr) & 0x11,
            0x150 => {
                let v = rmw(self.debugen) & 0x10F;
                self.debugen = (v & !self.debugen_lock) | (self.debugen & self.debugen_lock);
            }
            0x154 => self.debugen_lock |= rmw(self.debugen_lock) & 0x10F,
            0x158 => self.archsel = rmw(self.archsel) & 3,
            0x160 => {
                // BOOTDIS: NOW is W1C, NEXT sets.
                let v = rmw(self.bootdis);
                self.bootdis = (self.bootdis & !(value & 1)) | (v & 2);
            }
            o => {
                let old = *self.other.get(&o).unwrap_or(&0);
                self.other.insert(o, rmw(old));
            }
        }
    }
}

pub type SharedOtp = Arc<Mutex<OtpCore>>;

/// The controller block at 0x4012_0000.
pub struct OtpCtrl(pub SharedOtp);
/// The four data apertures at 0x4013_0000.
pub struct OtpData(pub SharedOtp);

impl MmioDevice for OtpCtrl {
    fn read(&mut self, offset: u32, _size: u8, _ctx: &mut MmioCtx) -> u32 {
        self.0.lock().unwrap().ctrl_read(offset) >> ((offset & 3) * 8)
    }
    fn write(&mut self, offset: u32, value: u32, _size: u8, alias: u32, ctx: &mut MmioCtx) {
        let v = value << ((offset & 3) * 8);
        self.0
            .lock()
            .unwrap()
            .ctrl_write(offset, v, alias, ctx.cycle);
    }
}

impl MmioDevice for OtpData {
    fn read(&mut self, offset: u32, size: u8, ctx: &mut MmioCtx) -> u32 {
        self.0.lock().unwrap().data_read(offset, size, ctx)
    }
    fn write(&mut self, offset: u32, value: u32, _size: u8, _alias: u32, ctx: &mut MmioCtx) {
        self.0.lock().unwrap().note(
            ctx.cycle,
            format!("ignored data-aperture write {value:#x} at +{offset:#x}"),
        );
    }
}

// ---------------------------------------------------------------------------
// Backing file
// ---------------------------------------------------------------------------

/// A fresh part: blank, except the factory chip ID (ECC rows) — the serial
/// the firmware derives from `get_chipid`, in little-endian byte order.
pub fn factory_rows(serial: [u8; 8]) -> Vec<u32> {
    let mut rows = vec![0u32; ROWS];
    for (i, pair) in serial.chunks(2).enumerate() {
        rows[CHIPID0_ROW + i] = ecc_encode(u16::from_le_bytes([pair[0], pair[1]]));
    }
    rows
}

pub fn load_rows(path: &Path, serial: [u8; 8]) -> Result<(Vec<u32>, bool), String> {
    if !path.exists() {
        return Ok((factory_rows(serial), true));
    }
    let b = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if b.len() != ROWS * 4 {
        return Err(format!(
            "{}: {} bytes, expected {}",
            path.display(),
            b.len(),
            ROWS * 4
        ));
    }
    Ok((
        b.chunks(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect(),
        false,
    ))
}

pub fn save_rows(path: &Path, rows: &[u32]) -> Result<(), String> {
    let b: Vec<u8> = rows.iter().flat_map(|r| r.to_le_bytes()).collect();
    std::fs::write(path, b).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
#[path = "otp_tests.rs"]
mod tests;
