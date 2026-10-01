// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The QMI's direct mode in front of a bit-level 25-series SPI NOR (W25Q32JV
//! command set, 4 MB). The array is the bus's XIP backing, so what the ROM's
//! erase and program leave is what XIP reads; misuse is logged, not absorbed.

use std::collections::VecDeque;

use rp2350_emu::peripherals::apply_alias_rmw;
use rp2350_emu::{MmioCtx, MmioDevice};

use super::Log;

pub const QMI_BASE: u32 = 0x400D_0000;

const DIRECT_CSR: u32 = 0x00;
const DIRECT_TX: u32 = 0x04;
const DIRECT_RX: u32 = 0x08;
const M0_TIMING: u32 = 0x0C;
const M1_WCMD: u32 = 0x30;
const ATRANS0: u32 = 0x34;
const ATRANS7: u32 = 0x50;

const CSR_EN: u32 = 1 << 0;
const CSR_BUSY: u32 = 1 << 1;
const CSR_ASSERT_CS0N: u32 = 1 << 2;
const CSR_ASSERT_CS1N: u32 = 1 << 3;
const CSR_AUTO_CS0N: u32 = 1 << 6;
const CSR_AUTO_CS1N: u32 = 1 << 7;
const CSR_TXFULL: u32 = 1 << 10;
const CSR_TXEMPTY: u32 = 1 << 11;
const CSR_RXEMPTY: u32 = 1 << 16;
const CSR_RXFULL: u32 = 1 << 17;
/// The RW fields: EN, ASSERT_CSxN, AUTO_CSxN, CLKDIV, RXDELAY.
const CSR_RW: u32 =
    CSR_EN | CSR_ASSERT_CS0N | CSR_ASSERT_CS1N | CSR_AUTO_CS0N | CSR_AUTO_CS1N | 0xFFC0_0000;
const CSR_RESET: u32 = 0x0180_0000; // CLKDIV = 6

const TX_NOPUSH: u32 = 1 << 20;
const TX_OE: u32 = 1 << 19;
const TX_DWIDTH: u32 = 1 << 18;

const FIFO_DEPTH: usize = 4;

/// Reset values of M0/M1 TIMING, RFMT, RCMD, WFMT, WCMD.
const M_RESET: [u32; 5] = [
    0x4000_0004,
    0x0000_1000,
    0x0000_A003,
    0x0000_1000,
    0x0000_A002,
];

// ---------------------------------------------------------------------------
// The flash part
// ---------------------------------------------------------------------------

pub const FLASH_BYTES: usize = 4 * 1024 * 1024;
const JEDEC_ID: [u8; 3] = [0xEF, 0x40, 0x16]; // Winbond W25Q32JV
/// The factory unique ID `4Bh` returns; obviously an emulator's.
const UNIQUE_ID: [u8; 8] = *b"RSKEMUF1";

/// Typical W25Q32JV timings, ns (datasheet AC characteristics).
const T_PAGE_PROGRAM_NS: u64 = 400_000;
const T_SECTOR_ERASE_NS: u64 = 45_000_000;
const T_BLOCK32_ERASE_NS: u64 = 120_000_000;
const T_BLOCK64_ERASE_NS: u64 = 150_000_000;
const T_CHIP_ERASE_NS: u64 = 10_000_000_000;
const T_WRITE_STATUS_NS: u64 = 10_000_000;

const SR1_WIP: u8 = 1 << 0;
const SR1_WEL: u8 = 1 << 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Collecting the 8 command bits on SD0.
    Command,
    /// Collecting `total` address(+mode) bits on `lanes` lanes.
    Address { lanes: u8, total: u8 },
    /// `left` dummy clocks before the data phase.
    Dummy { left: u32 },
    /// The flash drives data on `lanes` lanes.
    DataOut { lanes: u8 },
    /// The host drives data bytes on SD0.
    DataIn,
    /// Nothing more to do in this transaction.
    Done,
}

/// One pending array operation, applied at CS rise.
#[derive(Clone, Copy, Debug)]
enum ArrayOp {
    Erase { addr: u32, len: u32, ns: u64 },
    Program { page: u32, first: u8 },
}

struct PendingArray {
    offset: u32,
    before: Vec<u8>,
    after: Vec<u8>,
    order: Vec<usize>,
    started: u64,
    ends: u64,
    what: &'static str,
}

impl PendingArray {
    fn prefix(&self, count: usize) -> Vec<u8> {
        let mut bytes = self.before.clone();
        for &at in self.order.iter().take(count) {
            bytes[at] = self.after[at];
        }
        bytes
    }
}

pub struct NorFlash {
    selected: bool,
    phase: Phase,
    cmd: u8,
    /// Bits of the field being collected.
    shift: u32,
    bits: u8,
    addr: u32,
    /// Output byte being shifted out and its remaining bits.
    out_byte: u8,
    out_bits: u8,
    /// Data bytes the host clocked in this transaction (program / WRSR).
    data_in: Vec<u8>,
    /// Bits of a partial byte clocked after the last whole one.
    stray_bits: u32,
    sr: [u8; 3],
    busy_until: u64,
    busy_what: &'static str,
    /// EBh/BBh continuous-read mode (mode bits 0xAx on the last read).
    continuous: bool,
    power_down: bool,
    reset_enabled: bool,
    /// The current command was refused (busy / powered down / unknown):
    /// CS rise does nothing.
    refused: bool,
    pub stats: FlashStats,
    pending: Option<PendingArray>,
    capture_faults: bool,
    cut_after: Option<u64>,
    pub cut_cycle: Option<u64>,
    cut_prefix: usize,
    cut_delay: Option<u64>,
    pub cut_at: Option<u64>,
    log: Log,
}

#[derive(Default, Debug)]
pub struct FlashStats {
    /// Array operations applied (program + erase), for the runner to
    /// know when to persist.
    pub array_ops: u64,
    pub commands: u64,
    pub programmed_pages: u64,
    pub programmed_bytes: u64,
    pub erased_bytes: u64,
    pub status_polls: u64,
    pub protocol_events: u64,
}

impl NorFlash {
    pub fn new(log: Log) -> Self {
        Self {
            selected: false,
            phase: Phase::Command,
            cmd: 0,
            shift: 0,
            bits: 0,
            addr: 0,
            out_byte: 0,
            out_bits: 0,
            data_in: Vec::new(),
            stray_bits: 0,
            sr: [0, 0, 0],
            busy_until: 0,
            busy_what: "",
            continuous: false,
            power_down: false,
            reset_enabled: false,
            refused: false,
            stats: FlashStats::default(),
            pending: None,
            capture_faults: false,
            cut_after: None,
            cut_cycle: None,
            cut_prefix: 0,
            cut_delay: None,
            cut_at: None,
            log,
        }
    }

    fn event(&mut self, cycle: u64, text: String) {
        self.stats.protocol_events += 1;
        if self.stats.protocol_events <= 64 {
            self.log
                .lock()
                .unwrap()
                .push((cycle, format!("FLASH: {text}")));
        }
    }

    pub fn busy(&self, now: u64) -> bool {
        now < self.busy_until
    }

    pub fn select(&mut self, _now: u64) {
        self.selected = true;
        self.shift = 0;
        self.bits = 0;
        self.out_bits = 0;
        self.data_in.clear();
        self.stray_bits = 0;
        self.refused = false;
        self.phase = if self.continuous {
            // Continuous read: the address comes first, the command is the
            // one that entered the mode.
            let lanes = if self.cmd == 0xEB { 4 } else { 2 };
            Phase::Address { lanes, total: 32 }
        } else {
            Phase::Command
        };
    }

    pub fn deselect(&mut self, ctx: &mut MmioCtx) {
        if !self.selected {
            return;
        }
        self.selected = false;
        let now = ctx.cycle;
        if self.refused {
            return;
        }
        if self.phase == Phase::Command {
            if self.bits != 0 {
                // e.g. the ROM's 2-clock F5h/FFh QPI exits: a partial
                // command byte, ignored by an SPI-mode part.
            }
            return;
        }
        let whole = self.stray_bits == 0;
        let op = match self.cmd {
            0x06 if whole => {
                self.sr[0] |= SR1_WEL;
                None
            }
            0x04 if whole => {
                self.sr[0] &= !SR1_WEL;
                None
            }
            0x02 => {
                if matches!(self.phase, Phase::Address { .. }) || self.data_in.is_empty() || !whole
                {
                    self.event(
                        now,
                        format!("page program {:#08x} not executed (truncated)", self.addr),
                    );
                    None
                } else {
                    Some(ArrayOp::Program {
                        page: self.addr & !0xFF,
                        first: self.addr as u8,
                    })
                }
            }
            c @ (0x20 | 0x52 | 0xD8 | 0xC7 | 0x60) => {
                let chip = c == 0xC7 || c == 0x60;
                let complete = whole && (chip || self.phase == Phase::Done);
                if !complete {
                    self.event(
                        now,
                        format!("erase {c:#04x} {:#08x} not executed (truncated)", self.addr),
                    );
                    None
                } else {
                    let (len, ns) = match c {
                        0x20 => (4096, T_SECTOR_ERASE_NS),
                        0x52 => (32 * 1024, T_BLOCK32_ERASE_NS),
                        0xD8 => (64 * 1024, T_BLOCK64_ERASE_NS),
                        _ => (FLASH_BYTES as u32, T_CHIP_ERASE_NS),
                    };
                    let addr = if chip { 0 } else { self.addr & !(len - 1) };
                    Some(ArrayOp::Erase { addr, len, ns })
                }
            }
            0x01 | 0x31 | 0x11 if whole && !self.data_in.is_empty() => {
                if self.sr[0] & SR1_WEL == 0 {
                    self.event(now, "write status without WEL ignored".into());
                } else {
                    let first = match self.cmd {
                        0x01 => 0,
                        0x31 => 1,
                        _ => 2,
                    };
                    for (i, &b) in self.data_in.iter().enumerate().take(3 - first) {
                        // WIP/WEL are read-only.
                        self.sr[first + i] = if first + i == 0 { b & !0x03 } else { b };
                    }
                    self.sr[0] &= !SR1_WEL;
                    self.start_busy(ctx, T_WRITE_STATUS_NS, "write status");
                }
                None
            }
            0x66 if whole => {
                self.reset_enabled = true;
                return;
            }
            0x99 if whole && self.reset_enabled => {
                self.sr[0] &= !SR1_WEL;
                self.continuous = false;
                None
            }
            0xB9 if whole => {
                self.power_down = true;
                None
            }
            0xAB if whole => {
                self.power_down = false;
                None
            }
            0xEB | 0xBB => {
                // Mode bits 0xAx keep the part in continuous-read mode.
                None
            }
            _ => None,
        };
        self.reset_enabled = false;
        if let Some(op) = op {
            if self.sr[0] & SR1_WEL == 0 {
                self.event(now, format!("{op:?} without WEL ignored"));
            } else {
                self.apply(op, ctx);
            }
        }
    }

    fn start_busy(&mut self, ctx: &MmioCtx, ns: u64, what: &'static str) {
        let hz = ctx.sys_clk_hz.max(1) as u64;
        self.busy_until = ctx.cycle + ns * hz / 1_000_000_000;
        self.busy_what = what;
    }

    fn apply(&mut self, op: ArrayOp, ctx: &mut MmioCtx) {
        if self.cut_cycle.is_some() {
            return;
        }
        self.sr[0] &= !SR1_WEL;
        self.stats.array_ops += 1;
        match op {
            ArrayOp::Erase { addr, len, ns } => {
                let ff = vec![0xFFu8; len as usize];
                let Some(before) = ctx.flash().get(addr as usize..addr as usize + len as usize)
                else {
                    self.event(
                        ctx.cycle,
                        format!("erase outside flash at {addr:#x}, length {len}"),
                    );
                    return;
                };
                let before = self.capture_faults.then(|| before.to_vec());
                ctx.write_flash(addr, &ff);
                self.stats.erased_bytes += len as u64;
                self.start_busy(ctx, ns, "erase");
                self.pending = before.map(|before| PendingArray {
                    offset: addr,
                    before,
                    after: ff,
                    order: (0..len as usize).collect(),
                    started: ctx.cycle,
                    ends: self.busy_until,
                    what: "erase",
                });
            }
            ArrayOp::Program { page, first } => {
                // More than 256 bytes: the last 256 win (W25Q).
                let n = self.data_in.len();
                let skip = n.saturating_sub(256);
                let mut buf: Vec<u8> = ctx
                    .flash()
                    .get(page as usize..page as usize + 256)
                    .map(<[u8]>::to_vec)
                    .unwrap_or_else(|| vec![0xFF; 256]);
                let before = self.capture_faults.then(|| buf.clone());
                let mut order = Vec::new();
                for (i, &b) in self.data_in[skip..].iter().enumerate() {
                    let at = (first as usize + skip + i) & 0xFF;
                    buf[at] &= b; // NOR: bits only go 1 -> 0
                    if self.capture_faults {
                        order.push(at);
                    }
                }
                self.stats.programmed_pages += 1;
                self.stats.programmed_bytes += (n - skip) as u64;
                self.start_busy(ctx, T_PAGE_PROGRAM_NS, "program");
                if let Some(after) = self.cut_delay.take() {
                    self.cut_at = Some(ctx.cycle.saturating_add(after));
                }
                let Some(before) = before else {
                    ctx.write_flash(page, &buf);
                    return;
                };
                let pending = PendingArray {
                    offset: page,
                    before,
                    after: buf,
                    order,
                    started: ctx.cycle,
                    ends: self.busy_until,
                    what: "program",
                };
                let cut = self.cut_after.filter(|&n| n <= pending.order.len() as u64);
                let bytes = match cut {
                    Some(n) => {
                        self.cut_cycle = Some(ctx.cycle);
                        self.cut_prefix = n as usize;
                        pending.prefix(n as usize)
                    }
                    None => pending.after.clone(),
                };
                self.cut_after = self
                    .cut_after
                    .map(|n| n.saturating_sub(pending.order.len() as u64));
                ctx.write_flash(page, &bytes);
                self.pending = Some(pending);
            }
        }
    }

    pub fn arm_cut(&mut self, bytes: u64) {
        self.capture_faults = true;
        self.cut_after = Some(bytes);
        self.cut_cycle = None;
        self.cut_delay = None;
        self.cut_at = None;
    }

    pub fn cut_armed(&self) -> bool {
        self.cut_after.is_some() || self.cut_delay.is_some() || self.cut_at.is_some()
    }

    pub fn arm_program_cycles(&mut self, cycles: u64) {
        self.capture_faults = true;
        self.cut_after = None;
        self.cut_cycle = None;
        self.cut_delay = Some(cycles);
        self.cut_at = None;
    }

    pub fn arm_cycles(&mut self) {
        self.capture_faults = true;
        self.cut_after = None;
        self.cut_cycle = None;
        self.cut_delay = None;
        self.cut_at = None;
    }

    /// A deterministic prefix fault model, not an analog model of NOR cells.
    pub fn tear(&mut self, cycle: u64) -> Option<(u32, Vec<u8>, String)> {
        let pending = self.pending.take()?;
        if self.cut_cycle.is_some() {
            return Some((
                pending.offset,
                pending.prefix(self.cut_prefix),
                format!(
                    "program-byte address={:#x} bytes={}/{}",
                    pending.offset,
                    self.cut_prefix,
                    pending.order.len()
                ),
            ));
        }
        if cycle >= pending.ends {
            return None;
        }
        let elapsed = cycle.saturating_sub(pending.started);
        let count = (elapsed * pending.order.len() as u64 / (pending.ends - pending.started).max(1))
            as usize;
        let description = format!(
            "{} address={:#x} bytes={count}/{}",
            pending.what,
            pending.offset,
            pending.order.len()
        );
        Some((pending.offset, pending.prefix(count), description))
    }

    /// Byte the flash drives for the current read command at `self.addr`.
    fn next_read_byte(&mut self, ctx: &MmioCtx) -> u8 {
        let b = match self.cmd {
            0x05 => {
                self.stats.status_polls += 1;
                self.sr[0] | if self.busy(ctx.cycle) { SR1_WIP } else { 0 }
            }
            0x35 => self.sr[1],
            0x15 => self.sr[2],
            0x9F => *JEDEC_ID.get(self.addr as usize).unwrap_or(&0xFF),
            0x4B => *UNIQUE_ID.get(self.addr as usize).unwrap_or(&0xFF),
            0x90 => [0xEF, 0x15][(self.addr & 1) as usize],
            0xAB => 0x15,
            0x5A => 0xFF, // no SFDP table
            _ => {
                let a = (self.addr as usize) % FLASH_BYTES;
                *ctx.flash().get(a).unwrap_or(&0xFF)
            }
        };
        self.addr = self.addr.wrapping_add(1);
        b
    }

    /// Enter the phase after the command byte.
    fn after_command(&mut self, ctx: &MmioCtx) {
        self.stats.commands += 1;
        let busy = self.busy(ctx.cycle);
        if busy && self.cmd != 0x05 && self.cmd != 0x35 && self.cmd != 0x15 {
            self.event(
                ctx.cycle,
                format!(
                    "command {:#04x} while busy ({}) ignored",
                    self.cmd, self.busy_what
                ),
            );
            self.phase = Phase::Done;
            self.refused = true;
            return;
        }
        if self.power_down && self.cmd != 0xAB {
            self.event(
                ctx.cycle,
                format!("command {:#04x} while powered down ignored", self.cmd),
            );
            self.phase = Phase::Done;
            self.refused = true;
            return;
        }
        self.addr = 0;
        self.phase = match self.cmd {
            0x03 | 0x0B | 0x3B | 0x6B | 0x02 | 0x20 | 0x52 | 0xD8 | 0x5A => Phase::Address {
                lanes: 1,
                total: 24,
            },
            0x90 => Phase::Address {
                lanes: 1,
                total: 24,
            },
            0xBB => Phase::Address {
                lanes: 2,
                total: 32,
            },
            0xEB => Phase::Address {
                lanes: 4,
                total: 32,
            },
            0x05 | 0x35 | 0x15 | 0x9F => Phase::DataOut { lanes: 1 },
            0x4B => Phase::Dummy { left: 32 },
            0xAB => Phase::Dummy { left: 24 },
            0x01 | 0x31 | 0x11 => Phase::DataIn,
            0x06 | 0x04 | 0x66 | 0x99 | 0xB9 | 0xC7 | 0x60 | 0x50 => Phase::Done,
            // Continuous-read exit / NOP.
            0xFF => Phase::Done,
            other => {
                self.event(ctx.cycle, format!("unsupported command {other:#04x}"));
                self.refused = true;
                Phase::Done
            }
        };
    }

    fn after_address(&mut self, ctx: &MmioCtx) {
        let (lanes_data, dummy) = match self.cmd {
            0x03 => (1, 0),
            0x0B | 0x5A => (1, 8),
            0x3B => (2, 8),
            0x6B => (4, 8),
            0xBB => (2, 0),
            0xEB => (4, 4),
            0x90 => (1, 0),
            0x02 => {
                self.phase = Phase::DataIn;
                return;
            }
            _ => {
                // Erase: complete once CS rises now.
                self.phase = Phase::Done;
                return;
            }
        };
        if matches!(self.cmd, 0xBB | 0xEB) {
            // 24 address bits then 8 mode bits.
            let mode = (self.addr & 0xFF) as u8;
            self.addr >>= 8;
            self.continuous = mode & 0xF0 == 0xA0;
        }
        self.addr &= 0x00FF_FFFF;
        if self.cmd == 0x90 {
            self.addr &= 1;
        }
        let _ = ctx;
        self.phase = if dummy > 0 {
            Phase::Dummy { left: dummy }
        } else {
            Phase::DataOut { lanes: lanes_data }
        };
    }

    /// One SCK cycle. `lanes_in` are the SDx levels the host drives,
    /// `oe` which lanes it drives. Returns the levels the flash drives
    /// (floating lanes read high).
    pub fn clock(&mut self, lanes_in: u8, oe: u8, ctx: &MmioCtx) -> u8 {
        if !self.selected {
            return 0xF;
        }
        let sd0 = lanes_in & oe & 1;
        match self.phase {
            Phase::Command => {
                self.shift = (self.shift << 1) | sd0 as u32;
                self.bits += 1;
                if self.bits == 8 {
                    self.cmd = self.shift as u8;
                    self.shift = 0;
                    self.bits = 0;
                    self.after_command(ctx);
                }
                0xF
            }
            Phase::Address { lanes, total } => {
                let v = (lanes_in & oe) as u32 & ((1u32 << lanes) - 1);
                self.shift = (self.shift << lanes) | v;
                self.bits += lanes;
                if self.bits >= total {
                    self.addr = self.shift;
                    self.shift = 0;
                    self.bits = 0;
                    self.after_address(ctx);
                }
                0xF
            }
            Phase::Dummy { left } => {
                if left <= 1 {
                    self.phase = Phase::DataOut {
                        lanes: match self.cmd {
                            0x3B => 2,
                            0x6B | 0xEB => 4,
                            _ => 1,
                        },
                    };
                } else {
                    self.phase = Phase::Dummy { left: left - 1 };
                }
                0xF
            }
            Phase::DataOut { lanes } => {
                if self.out_bits == 0 {
                    self.out_byte = self.next_read_byte(ctx);
                    self.out_bits = 8;
                }
                self.out_bits -= lanes;
                let v = (self.out_byte >> self.out_bits) & ((1u8 << lanes) - 1);
                if lanes == 1 {
                    // MISO is SD1; SD0 floats.
                    0xD | (v << 1)
                } else {
                    v | (0xF & !((1u8 << lanes) - 1))
                }
            }
            Phase::DataIn => {
                self.shift = (self.shift << 1) | sd0 as u32;
                self.bits += 1;
                self.stray_bits = self.bits as u32;
                if self.bits == 8 {
                    self.data_in.push(self.shift as u8);
                    self.shift = 0;
                    self.bits = 0;
                    self.stray_bits = 0;
                }
                0xF
            }
            Phase::Done => {
                self.stray_bits += 1;
                if self.stray_bits == 8 {
                    self.stray_bits = 0;
                }
                0xF
            }
        }
    }

    /// Fold the XIP read configuration in when direct mode is entered: an
    /// EBh/BBh read with mode bits 0xAx leaves the part in continuous-read
    /// mode after the XIP accesses in between.
    pub fn xip_config_used(&mut self, rfmt: u32, rcmd: u32) {
        let suffix_len = (rfmt >> 14) & 3;
        let prefix = (rcmd & 0xFF) as u8;
        let suffix = (rcmd >> 8) as u8;
        if suffix_len != 0 && matches!(prefix, 0xEB | 0xBB) && suffix & 0xF0 == 0xA0 {
            self.cmd = prefix;
            self.continuous = true;
        }
    }
}

// ---------------------------------------------------------------------------
// The QMI
// ---------------------------------------------------------------------------

pub struct Qmi {
    csr: u32,
    tx: VecDeque<u32>,
    rx: VecDeque<u32>,
    m: [[u32; 5]; 2],
    atrans: [u32; 8],
    cs0: bool,
    pub flash: NorFlash,
    pub xip_config_log: Vec<(u64, u32, u32)>,
    log: Log,
}

impl Qmi {
    pub fn new(log: Log) -> Self {
        Self {
            csr: CSR_RESET,
            tx: VecDeque::new(),
            rx: VecDeque::new(),
            m: [M_RESET; 2],
            atrans: std::array::from_fn(|i| 0x0400_0000 | ((i as u32 & 3) << 10)),
            cs0: false,
            flash: NorFlash::new(log.clone()),
            xip_config_log: Vec::new(),
            log,
        }
    }

    /// The M0 read format and command XIP accesses would use.
    pub fn m0_read(&self) -> (u32, u32) {
        (self.m[0][1], self.m[0][2])
    }

    fn note(&self, cycle: u64, text: String) {
        self.log
            .lock()
            .unwrap()
            .push((cycle, format!("QMI: {text}")));
    }

    fn csr_read(&self) -> u32 {
        let mut v = self.csr;
        v &= !CSR_BUSY;
        if self.tx.len() >= FIFO_DEPTH {
            v |= CSR_TXFULL;
        }
        if self.tx.is_empty() {
            v |= CSR_TXEMPTY;
        }
        v |= (self.tx.len().min(7) as u32) << 12;
        if self.rx.is_empty() {
            v |= CSR_RXEMPTY;
        }
        if self.rx.len() >= FIFO_DEPTH {
            v |= CSR_RXFULL;
        }
        v |= (self.rx.len().min(7) as u32) << 18;
        v
    }

    /// Drive CS0 to `want`, telling the flash about edges.
    fn set_cs0(&mut self, want: bool, ctx: &mut MmioCtx) {
        if want != self.cs0 {
            self.cs0 = want;
            if want {
                self.flash.select(ctx.cycle);
            } else {
                self.flash.deselect(ctx);
            }
        }
    }

    /// Shift one TX entry; returns the RX word.
    fn shift_entry(&mut self, entry: u32, ctx: &mut MmioCtx) -> u32 {
        let width = match (entry >> 16) & 3 {
            0 => 1u8,
            1 => 2,
            _ => 4,
        };
        let oe = entry & TX_OE != 0 || width == 1;
        let nbytes = if entry & TX_DWIDTH != 0 { 2 } else { 1 };
        let cs1_only = self.csr & CSR_ASSERT_CS1N != 0 && !self.cs0;
        let mut rx = 0u32;
        for byte_i in 0..nbytes {
            let byte = (entry >> (8 * byte_i)) as u8;
            let mut got = 0u8;
            let clocks = 8 / width;
            for c in 0..clocks {
                let shift = 8 - width * (c + 1);
                let lanes = (byte >> shift) & ((1u8 << width) - 1);
                let oe_mask = if width == 1 {
                    1
                } else if oe {
                    (1u8 << width) - 1
                } else {
                    0
                };
                let sd = if cs1_only {
                    0xF
                } else {
                    self.flash.clock(lanes, oe_mask, ctx)
                };
                let sample = if width == 1 {
                    (sd >> 1) & 1
                } else {
                    sd & ((1u8 << width) - 1)
                };
                got = (got << width) | sample;
            }
            rx |= (got as u32) << (8 * byte_i);
        }
        rx
    }

    /// Shift everything the FIFOs allow.
    fn pump(&mut self, ctx: &mut MmioCtx) {
        if self.csr & CSR_EN == 0 {
            return;
        }
        let auto = self.csr & CSR_AUTO_CS0N != 0 && self.csr & CSR_ASSERT_CS0N == 0;
        while let Some(&entry) = self.tx.front() {
            if entry & TX_NOPUSH == 0 && self.rx.len() >= FIFO_DEPTH {
                break; // the interface stalls on a full RX FIFO
            }
            self.tx.pop_front();
            if auto {
                self.set_cs0(true, ctx);
            }
            let word = self.shift_entry(entry, ctx);
            if entry & TX_NOPUSH == 0 {
                self.rx.push_back(word);
            }
        }
        if auto {
            self.set_cs0(false, ctx);
        }
    }

    fn after_csr_write(&mut self, old: u32, ctx: &mut MmioCtx) {
        if old & CSR_EN == 0 && self.csr & CSR_EN != 0 {
            let (rfmt, rcmd) = self.m0_read();
            self.flash.xip_config_used(rfmt, rcmd);
        }
        if (old ^ self.csr) & (CSR_AUTO_CS0N | CSR_AUTO_CS1N) != 0
            && self.csr & (CSR_AUTO_CS0N | CSR_AUTO_CS1N) != 0
        {
            self.note(
                ctx.cycle,
                format!("AUTO_CS in use (DIRECT_CSR {:#010x})", self.csr),
            );
        }
        let assert = self.csr & CSR_ASSERT_CS0N != 0;
        self.set_cs0(assert, ctx);
        self.pump(ctx);
    }
}

impl MmioDevice for Qmi {
    fn read(&mut self, offset: u32, _size: u8, ctx: &mut MmioCtx) -> u32 {
        let word = match offset & !3 {
            DIRECT_CSR => self.csr_read(),
            DIRECT_RX => match self.rx.pop_front() {
                Some(v) => {
                    let v2 = v;
                    self.pump(ctx);
                    v2
                }
                None => {
                    self.flash
                        .event(ctx.cycle, "DIRECT_RX read with the RX FIFO empty".into());
                    0
                }
            },
            o @ M0_TIMING..=M1_WCMD => {
                let i = ((o - M0_TIMING) / 4) as usize;
                self.m[i / 5][i % 5]
            }
            o @ ATRANS0..=ATRANS7 => self.atrans[((o - ATRANS0) / 4) as usize],
            _ => 0,
        };
        word >> ((offset & 3) * 8)
    }

    fn write(&mut self, offset: u32, value: u32, size: u8, alias: u32, ctx: &mut MmioCtx) {
        let value = if size < 4 {
            value << ((offset & 3) * 8)
        } else {
            value
        };
        match offset & !3 {
            DIRECT_CSR => {
                let old = self.csr;
                let mut v = self.csr;
                apply_alias_rmw(&mut v, value, alias);
                self.csr = (v & CSR_RW) | (old & !CSR_RW);
                self.after_csr_write(old, ctx);
            }
            DIRECT_TX => {
                if self.tx.len() >= FIFO_DEPTH {
                    self.flash.event(
                        ctx.cycle,
                        "DIRECT_TX write with the TX FIFO full (dropped)".into(),
                    );
                } else {
                    self.tx.push_back(value & 0x001F_FFFF);
                }
                self.pump(ctx);
            }
            o @ M0_TIMING..=M1_WCMD => {
                let i = ((o - M0_TIMING) / 4) as usize;
                let r = &mut self.m[i / 5][i % 5];
                apply_alias_rmw(r, value, alias);
                if i % 5 == 1 || i % 5 == 2 {
                    let (rfmt, rcmd) = (self.m[0][1], self.m[0][2]);
                    if self.xip_config_log.last().map(|&(_, f, c)| (f, c)) != Some((rfmt, rcmd)) {
                        self.xip_config_log.push((ctx.cycle, rfmt, rcmd));
                    }
                }
            }
            o @ ATRANS0..=ATRANS7 => {
                let i = ((o - ATRANS0) / 4) as usize;
                apply_alias_rmw(&mut self.atrans[i], value, alias);
                let identity = 0x0400_0000 | ((i as u32 & 3) << 10);
                if self.atrans[i] != identity {
                    self.note(
                        ctx.cycle,
                        format!(
                            "ATRANS{i} <- {:#010x}: non-identity translation is NOT modelled",
                            self.atrans[i]
                        ),
                    );
                }
            }
            _ => {}
        }
        let _ = CSR_TXEMPTY;
    }
}

#[cfg(test)]
#[path = "qspi_tests.rs"]
mod tests;
