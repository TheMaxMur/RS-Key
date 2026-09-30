// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The USB controller in device mode: the firmware drives its registers and
//! DPRAM (pico-sdk `usb.h`, `usb_device_dpram.h`), and the host controller in
//! `hc.rs` drives the bus side one token at a time through `UsbCore`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use rp2350_emu::peripherals::apply_alias_rmw;
use rp2350_emu::{MmioCtx, MmioDevice};

use super::Log;

pub const USBCTRL_DPRAM_BASE: u32 = 0x5010_0000;
pub const USBCTRL_REGS_BASE: u32 = 0x5011_0000;
const USBCTRL_IRQ: u32 = 14;
const DPRAM_SIZE: usize = 4096;

#[cfg(test)]
const ADDR_ENDP_REG: u32 = 0x00;
const MAIN_CTRL: u32 = 0x40;
const SOF_RD: u32 = 0x48;
const SIE_CTRL: u32 = 0x4C;
const SIE_STATUS: u32 = 0x50;
const BUFF_STATUS: u32 = 0x58;
const BUFF_CPU_SHOULD_HANDLE: u32 = 0x5C;
const EP_ABORT: u32 = 0x60;
const EP_ABORT_DONE: u32 = 0x64;
const EP_STALL_ARM: u32 = 0x68;
const EP_STATUS_STALL_NAK: u32 = 0x70;
const USB_MUXING: u32 = 0x74;
const USB_PWR: u32 = 0x78;
const INTR: u32 = 0x8C;
const INTE: u32 = 0x90;
const INTF: u32 = 0x94;
const INTS: u32 = 0x98;

const MAIN_CTRL_CONTROLLER_EN: u32 = 1 << 0;
const MAIN_CTRL_HOST_NDEVICE: u32 = 1 << 1;
const SIE_CTRL_EP0_INT_1BUF: u32 = 1 << 29;
const SIE_CTRL_EP0_DOUBLE_BUF: u32 = 1 << 30;
const SIE_CTRL_PULLUP_EN: u32 = 1 << 16;

const ST_DATA_SEQ_ERROR: u32 = 1 << 31;
const ST_ACK_REC: u32 = 1 << 30;
const ST_BUS_RESET: u32 = 1 << 19;
const ST_TRANS_COMPLETE: u32 = 1 << 18;
const ST_SETUP_REC: u32 = 1 << 17;
const ST_CONNECTED: u32 = 1 << 16;
const ST_RX_OVERFLOW: u32 = 1 << 26;
const ST_VBUS_DETECTED: u32 = 1 << 0;
/// Bits a write of 1 clears (everything but the live status fields).
const ST_W1C: u32 = 0xFF8F_1810;

const IN_EPX_STOPPED_ON_NAK: u32 = 1 << 23;
const IN_EP_STALL_NAK: u32 = 1 << 19;
const IN_ABORT_DONE: u32 = 1 << 18;
const IN_DEV_SOF: u32 = 1 << 17;
const IN_SETUP_REQ: u32 = 1 << 16;
const IN_DEV_RESUME: u32 = 1 << 15;
const IN_DEV_SUSPEND: u32 = 1 << 14;
const IN_DEV_CONN_DIS: u32 = 1 << 13;
const IN_BUS_RESET: u32 = 1 << 12;
const IN_VBUS_DETECT: u32 = 1 << 11;
const IN_ERROR_RX_OVERFLOW: u32 = 1 << 7;
const IN_ERROR_DATA_SEQ: u32 = 1 << 5;
const IN_BUFF_STATUS: u32 = 1 << 4;
const IN_TRANS_COMPLETE: u32 = 1 << 3;

// Buffer control (per buffer 0; buffer 1 is the upper half).
const BC_FULL: u32 = 1 << 15;
const BC_LAST: u32 = 1 << 14;
const BC_PID: u32 = 1 << 13;
/// Written 1 in buffer 0's half: the buffer selector goes back to buffer 0.
const BC_RESET_SELECTOR: u32 = 1 << 12;
const BC_STALL: u32 = 1 << 11;
const BC_AVAILABLE: u32 = 1 << 10;
const BC_LEN: u32 = 0x3FF;

// Endpoint control.
const EC_ENABLE: u32 = 1 << 31;
const EC_DOUBLE_BUFFERED: u32 = 1 << 30;
const EC_INTERRUPT_PER_BUFF: u32 = 1 << 29;
const EC_INTERRUPT_PER_DOUBLE_BUFF: u32 = 1 << 28;
const EC_TYPE_ISO: u32 = 1;

/// How a token went.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Handshake {
    Ack,
    Nak,
    Stall,
    /// No answer: wrong address, disabled endpoint, or detached.
    Timeout,
}

#[derive(Default, Debug)]
pub struct UsbStats {
    pub setups: u64,
    pub in_data: u64,
    pub out_data: u64,
    pub naks: u64,
    pub stalls: u64,
    pub timeouts: u64,
    pub protocol_events: u64,
}

pub struct UsbCore {
    dpram: Vec<u8>,
    addr_endp: [u32; 16],
    main_ctrl: u32,
    sof: u32,
    sie_ctrl: u32,
    sie_status: u32,
    buff_status: u32,
    ep_abort: u32,
    ep_abort_done: u32,
    ep_stall_arm: u32,
    ep_status_stall_nak: u32,
    buff_cpu_should_handle: u32,
    /// Next buffer (0/1) of each double-buffered endpoint, by `[ep][dir_in]`.
    selector: [[u8; 2]; 16],
    usb_muxing: u32,
    usb_pwr: u32,
    inte: u32,
    intf: u32,
    lat_sof: bool,
    lat_trans_complete: bool,
    lat_conn: bool,
    other: BTreeMap<u32, u32>,
    /// Host side: VBUS present, and whether a bus reset has been seen.
    pub host_vbus: bool,
    reset_seen: bool,
    pub pullup_at: Option<u64>,
    pub polls_after_pullup: u64,
    /// Falsification aid: USBCTRL_IRQ does not reach the cores before this
    /// cycle.
    pub irq_hold_until: u64,
    pub stats: UsbStats,
    log: Log,
}

pub type SharedUsb = Arc<Mutex<UsbCore>>;

impl UsbCore {
    pub fn new(log: Log) -> Self {
        Self {
            dpram: vec![0; DPRAM_SIZE],
            addr_endp: [0; 16],
            main_ctrl: 0,
            sof: 0,
            sie_ctrl: 0,
            sie_status: 0,
            buff_status: 0,
            ep_abort: 0,
            ep_abort_done: 0,
            ep_stall_arm: 0,
            ep_status_stall_nak: 0,
            buff_cpu_should_handle: 0,
            selector: [[0; 2]; 16],
            usb_muxing: 0,
            usb_pwr: 0,
            inte: 0,
            intf: 0,
            lat_sof: false,
            lat_trans_complete: false,
            lat_conn: false,
            other: BTreeMap::new(),
            host_vbus: true,
            reset_seen: false,
            pullup_at: None,
            polls_after_pullup: 0,
            irq_hold_until: 0,
            stats: UsbStats::default(),
            log,
        }
    }

    fn note(&self, cycle: u64, text: String) {
        self.log
            .lock()
            .unwrap()
            .push((cycle, format!("USB: {text}")));
    }

    /// A protocol misuse a real controller would punish.
    fn event(&mut self, cycle: u64, text: String) {
        self.stats.protocol_events += 1;
        if self.stats.protocol_events <= 32 {
            self.note(cycle, format!("protocol: {text}"));
        }
    }

    fn rd32(&self, off: usize) -> u32 {
        u32::from_le_bytes(self.dpram[off..off + 4].try_into().unwrap())
    }

    fn wr32(&mut self, off: usize, v: u32) {
        self.dpram[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn vbus_detected(&self) -> bool {
        const VBUS_DETECT: u32 = 1 << 2;
        const VBUS_DETECT_OVERRIDE_EN: u32 = 1 << 3;
        if self.usb_pwr & VBUS_DETECT_OVERRIDE_EN != 0 {
            self.usb_pwr & VBUS_DETECT != 0
        } else {
            self.host_vbus
        }
    }

    /// The device presents its pull-up to the host.
    pub fn attached(&self) -> bool {
        self.main_ctrl & MAIN_CTRL_CONTROLLER_EN != 0
            && self.main_ctrl & MAIN_CTRL_HOST_NDEVICE == 0
            && self.sie_ctrl & SIE_CTRL_PULLUP_EN != 0
            && self.usb_muxing & 0x9 == 0x9 // TO_PHY | SOFTCON
    }

    fn sie_status_value(&self) -> u32 {
        let mut s = self.sie_status;
        if self.vbus_detected() {
            s |= ST_VBUS_DETECTED;
        }
        if self.attached() && self.reset_seen {
            s |= ST_CONNECTED;
        }
        s
    }

    fn intr(&self) -> u32 {
        let s = self.sie_status_value();
        let mut r = 0;
        let map = [
            (ST_SETUP_REC, IN_SETUP_REQ),
            (ST_BUS_RESET, IN_BUS_RESET),
            (ST_VBUS_DETECTED, IN_VBUS_DETECT),
            (ST_DATA_SEQ_ERROR, IN_ERROR_DATA_SEQ),
            (ST_RX_OVERFLOW, IN_ERROR_RX_OVERFLOW),
        ];
        for (st, bit) in map {
            if s & st != 0 {
                r |= bit;
            }
        }
        if self.buff_status != 0 {
            r |= IN_BUFF_STATUS;
        }
        if self.lat_trans_complete {
            r |= IN_TRANS_COMPLETE;
        }
        if self.lat_sof {
            r |= IN_DEV_SOF;
        }
        if self.lat_conn {
            r |= IN_DEV_CONN_DIS;
        }
        if self.ep_abort_done != 0 {
            r |= IN_ABORT_DONE;
        }
        if self.ep_status_stall_nak != 0 {
            r |= IN_EP_STALL_NAK;
        }
        let _ = (IN_DEV_RESUME, IN_DEV_SUSPEND, IN_EPX_STOPPED_ON_NAK);
        r
    }

    fn ints(&self) -> u32 {
        (self.intr() | self.intf) & self.inte
    }

    fn reg_read(&mut self, offset: u32, cycle: u64) -> u32 {
        match offset & !3 {
            o @ 0x00..=0x3C => self.addr_endp[(o / 4) as usize],
            MAIN_CTRL => self.main_ctrl,
            SOF_RD => {
                self.lat_sof = false;
                self.sof
            }
            SIE_CTRL => self.sie_ctrl,
            SIE_STATUS => {
                if self.pullup_at.is_some() {
                    self.polls_after_pullup += 1;
                    if self.polls_after_pullup == 1 {
                        self.note(
                            cycle,
                            "SIE_STATUS read after attach — usb_task polling the bus".into(),
                        );
                    }
                }
                self.sie_status_value()
            }
            BUFF_STATUS => self.buff_status,
            BUFF_CPU_SHOULD_HANDLE => self.buff_cpu_should_handle,
            EP_ABORT => self.ep_abort,
            EP_ABORT_DONE => self.ep_abort_done,
            EP_STALL_ARM => self.ep_stall_arm,
            EP_STATUS_STALL_NAK => self.ep_status_stall_nak,
            USB_MUXING => self.usb_muxing,
            USB_PWR => self.usb_pwr,
            INTR => self.intr(),
            INTE => self.inte,
            INTF => self.intf,
            INTS => self.ints(),
            o => *self.other.get(&o).unwrap_or(&0),
        }
    }

    fn reg_write(&mut self, offset: u32, value: u32, alias: u32, cycle: u64) {
        let rmw = |old: u32| {
            let mut v = old;
            apply_alias_rmw(&mut v, value, alias);
            v
        };
        // A 1 clears a W1C bit through any alias: the alias becomes per-bit
        // write strobes, and pico-sdk, TinyUSB and the bootrom's nsboot all
        // clear SIE_STATUS / BUFF_STATUS through the CLR one.
        let w1c = value;
        match offset & !3 {
            o @ 0x00..=0x3C => {
                let i = (o / 4) as usize;
                self.addr_endp[i] = rmw(self.addr_endp[i]);
                if i == 0 {
                    self.note(
                        cycle,
                        format!("ADDR_ENDP <- address {}", self.addr_endp[0] & 0x7F),
                    );
                }
            }
            MAIN_CTRL => {
                self.main_ctrl = rmw(self.main_ctrl);
                if self.main_ctrl & MAIN_CTRL_HOST_NDEVICE != 0 {
                    self.event(cycle, "host mode selected (not modelled)".into());
                }
            }
            SIE_CTRL => {
                let before = self.sie_ctrl;
                self.sie_ctrl = rmw(before);
                if self.sie_ctrl & SIE_CTRL_EP0_DOUBLE_BUF != 0 {
                    self.event(cycle, "EP0 double buffering (not modelled)".into());
                }
                if self.sie_ctrl & SIE_CTRL_PULLUP_EN != 0 && self.pullup_at.is_none() {
                    self.pullup_at = Some(cycle);
                    self.note(cycle, "SIE_CTRL.PULLUP_EN set — attached".into());
                }
                if before & SIE_CTRL_PULLUP_EN != 0 && self.sie_ctrl & SIE_CTRL_PULLUP_EN == 0 {
                    self.note(cycle, "SIE_CTRL.PULLUP_EN cleared — detached".into());
                    self.reset_seen = false;
                    self.lat_conn = true;
                }
            }
            SIE_STATUS => {
                self.sie_status &= !(w1c & ST_W1C);
                if w1c & ST_CONNECTED != 0 {
                    self.lat_conn = false;
                }
                if w1c & ST_TRANS_COMPLETE != 0 {
                    self.lat_trans_complete = false;
                }
            }
            BUFF_STATUS => self.buff_status &= !w1c,
            EP_ABORT => {
                self.ep_abort = rmw(self.ep_abort);
                // Nothing is ever in flight between host slots: done at once.
                self.ep_abort_done |= self.ep_abort;
            }
            EP_ABORT_DONE => self.ep_abort_done &= !w1c,
            EP_STALL_ARM => self.ep_stall_arm = rmw(self.ep_stall_arm) & 3,
            EP_STATUS_STALL_NAK => self.ep_status_stall_nak &= !w1c,
            USB_MUXING => self.usb_muxing = rmw(self.usb_muxing),
            USB_PWR => self.usb_pwr = rmw(self.usb_pwr),
            INTR => {
                if w1c & IN_TRANS_COMPLETE != 0 {
                    self.lat_trans_complete = false;
                }
            }
            INTE => self.inte = rmw(self.inte),
            INTF => self.intf = rmw(self.intf),
            INTS | SOF_RD | BUFF_CPU_SHOULD_HANDLE => {}
            o => {
                let v = rmw(*self.other.get(&o).unwrap_or(&0));
                self.other.insert(o, v);
            }
        }
    }

    // --- host side -------------------------------------------------------

    fn addressed(&mut self, addr: u8) -> bool {
        if !self.attached() {
            return false;
        }
        addr as u32 == self.addr_endp[0] & 0x7F
    }

    /// Bus reset from the host (SE0 >= 2.5 us).
    pub fn host_bus_reset(&mut self, cycle: u64) {
        self.sie_status |= ST_BUS_RESET;
        if !self.reset_seen {
            self.lat_conn = true;
        }
        self.reset_seen = true;
        self.note(cycle, "host: bus reset".into());
    }

    /// Start of frame.
    pub fn host_sof(&mut self, frame: u32) {
        if self.attached() {
            self.sof = frame & 0x7FF;
            self.lat_sof = true;
        }
    }

    pub fn host_setup(&mut self, addr: u8, pkt: [u8; 8], _cycle: u64) -> Handshake {
        if !self.addressed(addr) {
            self.stats.timeouts += 1;
            return Handshake::Timeout;
        }
        self.dpram[0..8].copy_from_slice(&pkt);
        self.sie_status |= ST_SETUP_REC;
        self.ep_stall_arm = 0;
        self.stats.setups += 1;
        Handshake::Ack
    }

    fn buf_ctrl_off(ep: u8, dir_in: bool) -> usize {
        0x80 + ep as usize * 8 + if dir_in { 0 } else { 4 }
    }

    fn ep_ctrl_off(ep: u8, dir_in: bool) -> usize {
        0x08 + (ep as usize - 1) * 8 + if dir_in { 0 } else { 4 }
    }

    /// Endpoint control word, or `None` (with the reason logged) when the
    /// controller would not answer this endpoint.
    fn endpoint(&mut self, ep: u8, dir_in: bool, cycle: u64) -> Option<u32> {
        if ep == 0 {
            return Some(0);
        }
        let ec = self.rd32(Self::ep_ctrl_off(ep, dir_in));
        if ec & EC_ENABLE == 0 {
            self.event(
                cycle,
                format!(
                    "token to disabled EP{ep} {}",
                    if dir_in { "IN" } else { "OUT" }
                ),
            );
            return None;
        }
        if (ec >> 26) & 3 == EC_TYPE_ISO || ec & EC_INTERRUPT_PER_DOUBLE_BUFF != 0 {
            self.event(
                cycle,
                format!("EP{ep}: isochronous / interrupt per double buffer (not modelled)"),
            );
        }
        Some(ec)
    }

    fn stalled(&self, ep: u8, dir_in: bool, bc: u32) -> bool {
        if bc & BC_STALL == 0 {
            return false;
        }
        if ep == 0 {
            let arm = if dir_in { 1 } else { 2 };
            self.ep_stall_arm & arm != 0
        } else {
            true
        }
    }

    /// The buffer a token on this endpoint uses: which (0/1), the shift of
    /// its half in the buffer control word, and its data address.
    fn buffer(&self, ep: u8, dir_in: bool, ec: u32) -> (u8, u32, usize) {
        if ep == 0 {
            return (0, 0, 0x100);
        }
        let which = if ec & EC_DOUBLE_BUFFERED != 0 {
            self.selector[ep as usize][dir_in as usize]
        } else {
            0
        };
        (
            which,
            16 * which as u32,
            (ec & 0xFFC0) as usize + 64 * which as usize,
        )
    }

    fn buffer_done(&mut self, ep: u8, dir_in: bool, ec: u32, last: bool, which: u8) {
        let irq = if ep == 0 {
            self.sie_ctrl & SIE_CTRL_EP0_INT_1BUF != 0
        } else {
            ec & EC_INTERRUPT_PER_BUFF != 0
        };
        let bit = 1 << (ep as u32 * 2 + if dir_in { 0 } else { 1 });
        if irq {
            self.buff_status |= bit;
            self.buff_cpu_should_handle =
                (self.buff_cpu_should_handle & !bit) | if which == 1 { bit } else { 0 };
        }
        if ep != 0 && ec & EC_DOUBLE_BUFFERED != 0 {
            self.selector[ep as usize][dir_in as usize] ^= 1;
        }
        if last {
            self.sie_status |= ST_TRANS_COMPLETE;
            self.lat_trans_complete = true;
        }
        self.sie_status |= ST_ACK_REC;
    }

    /// An IN token: the data and its DATA PID, or the handshake.
    pub fn host_in(&mut self, addr: u8, ep: u8, cycle: u64) -> Result<(u8, Vec<u8>), Handshake> {
        if !self.addressed(addr) {
            self.stats.timeouts += 1;
            return Err(Handshake::Timeout);
        }
        let Some(ec) = self.endpoint(ep, true, cycle) else {
            self.stats.timeouts += 1;
            return Err(Handshake::Timeout);
        };
        let bco = Self::buf_ctrl_off(ep, true);
        let word = self.rd32(bco);
        if self.stalled(ep, true, word) {
            self.stats.stalls += 1;
            return Err(Handshake::Stall);
        }
        let (which, shift, base) = self.buffer(ep, true, ec);
        let bc = (word >> shift) & 0xFFFF;
        if bc & BC_AVAILABLE == 0 {
            self.stats.naks += 1;
            return Err(Handshake::Nak);
        }
        if bc & BC_FULL == 0 {
            self.event(cycle, format!("EP{ep} IN buffer AVAILABLE but not FULL"));
        }
        let len = (bc & BC_LEN) as usize;
        if base + len > DPRAM_SIZE || len > 1023 {
            self.event(
                cycle,
                format!("EP{ep} IN buffer {base:#x}+{len} leaves DPRAM"),
            );
            return Err(Handshake::Stall);
        }
        let data = self.dpram[base..base + len].to_vec();
        let pid = ((bc & BC_PID) != 0) as u8;
        self.wr32(bco, word & !((BC_AVAILABLE | BC_FULL) << shift));
        self.buffer_done(ep, true, ec, bc & BC_LAST != 0, which);
        self.stats.in_data += 1;
        Ok((pid, data))
    }

    /// An OUT token with its DATA packet.
    pub fn host_out(&mut self, addr: u8, ep: u8, pid: u8, data: &[u8], cycle: u64) -> Handshake {
        if !self.addressed(addr) {
            self.stats.timeouts += 1;
            return Handshake::Timeout;
        }
        let Some(ec) = self.endpoint(ep, false, cycle) else {
            self.stats.timeouts += 1;
            return Handshake::Timeout;
        };
        let bco = Self::buf_ctrl_off(ep, false);
        let word = self.rd32(bco);
        if self.stalled(ep, false, word) {
            self.stats.stalls += 1;
            return Handshake::Stall;
        }
        let (which, shift, base) = self.buffer(ep, false, ec);
        let bc = (word >> shift) & 0xFFFF;
        if bc & BC_AVAILABLE == 0 {
            self.stats.naks += 1;
            return Handshake::Nak;
        }
        let want_pid = ((bc & BC_PID) != 0) as u8;
        if pid != want_pid {
            self.sie_status |= ST_DATA_SEQ_ERROR;
            self.event(
                cycle,
                format!("EP{ep} OUT DATA{pid} where the buffer expects DATA{want_pid}: dropped"),
            );
            return Handshake::Ack;
        }
        let max = (bc & BC_LEN) as usize;
        let n = data.len().min(max);
        if data.len() > max {
            self.sie_status |= ST_RX_OVERFLOW;
            self.event(
                cycle,
                format!("EP{ep} OUT {} bytes into a {max}-byte buffer", data.len()),
            );
        }
        if base + n > DPRAM_SIZE {
            self.event(
                cycle,
                format!("EP{ep} OUT buffer {base:#x}+{n} leaves DPRAM"),
            );
            return Handshake::Stall;
        }
        self.dpram[base..base + n].copy_from_slice(&data[..n]);
        let half = (bc & !(BC_AVAILABLE | BC_LEN)) | BC_FULL | n as u32;
        self.wr32(bco, (word & !(0xFFFF << shift)) | half << shift);
        self.buffer_done(ep, false, ec, bc & BC_LAST != 0, which);
        self.stats.out_data += 1;
        Handshake::Ack
    }
}

/// The register block at 0x5011_0000.
pub struct UsbRegs(pub SharedUsb);
/// The DPRAM at 0x5010_0000.
pub struct UsbDpram(pub SharedUsb);

impl MmioDevice for UsbRegs {
    fn read(&mut self, offset: u32, _size: u8, ctx: &mut MmioCtx) -> u32 {
        self.0.lock().unwrap().reg_read(offset, ctx.cycle) >> ((offset & 3) * 8)
    }
    fn write(&mut self, offset: u32, value: u32, _size: u8, alias: u32, ctx: &mut MmioCtx) {
        let v = value << ((offset & 3) * 8);
        self.0
            .lock()
            .unwrap()
            .reg_write(offset, v, alias, ctx.cycle);
    }
    fn tick(&mut self, _sys_clks: u32, ctx: &mut MmioCtx) {
        let u = self.0.lock().unwrap();
        if u.ints() != 0 && ctx.cycle >= u.irq_hold_until {
            ctx.raise_irqs |= 1 << USBCTRL_IRQ;
        }
    }
}

impl MmioDevice for UsbDpram {
    fn read(&mut self, offset: u32, size: u8, _ctx: &mut MmioCtx) -> u32 {
        let u = self.0.lock().unwrap();
        let o = offset as usize;
        let mut b = [0u8; 4];
        let n = size as usize;
        if o + n <= DPRAM_SIZE {
            b[..n].copy_from_slice(&u.dpram[o..o + n]);
        }
        u32::from_le_bytes(b)
    }
    fn write(&mut self, offset: u32, value: u32, size: u8, _alias: u32, _ctx: &mut MmioCtx) {
        let mut u = self.0.lock().unwrap();
        let o = offset as usize;
        let n = size as usize;
        if o + n <= DPRAM_SIZE {
            u.dpram[o..o + n].copy_from_slice(&value.to_le_bytes()[..n]);
        }
        // Buffer 0's half of a buffer control word: a 1 in
        // BC_RESET_SELECTOR sends the double-buffer selector back to 0.
        if (0x80..0x100).contains(&o)
            && o.is_multiple_of(4)
            && n >= 2
            && value & BC_RESET_SELECTOR != 0
        {
            let (ep, dir_in) = ((o - 0x80) / 8, (o - 0x80).is_multiple_of(8));
            u.selector[ep][dir_in as usize] = 0;
        }
    }
}

#[cfg(test)]
#[path = "usb_tests.rs"]
mod tests;
