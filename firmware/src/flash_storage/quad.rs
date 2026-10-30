// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::AsyncFlash;
use core::cell::RefCell;
use embassy_futures::block_on;
use embedded_storage_async::nor_flash::ReadNorFlash;
use rsk_store::flash_quad::{CONTINUOUS_SUFFIX, QUAD_READ, ReadMode, ReadStep};

const SAMPLE_OFFSET: u32 = 0x100;
const SAMPLE_BYTES: usize = 128;
const CLKDIV: u8 = 2;
const READY_POLLS: usize = 100_000;

pub(super) struct Engine {
    sample: [u8; SAMPLE_BYTES],
    probe: [u8; SAMPLE_BYTES],
    ready: bool,
}
impl Engine {
    pub(super) fn new(flash: &RefCell<AsyncFlash>) -> Self {
        let mut this = Self {
            sample: [0; SAMPLE_BYTES],
            probe: [0; SAMPLE_BYTES],
            ready: false,
        };
        if !matches!(option_env!("BOARD"), Some("waveshare-one"))
            || super::FLASH_SIZE != 4 * 1024 * 1024
        {
            return this;
        }
        if block_on(flash.borrow_mut().read(SAMPLE_OFFSET, &mut this.sample)).is_err() {
            return this;
        }
        this.ready = cortex_m::interrupt::free(|_| enable_volatile_quad());
        this
    }
    pub(super) fn ensure_mode(&mut self) {
        if !self.ready {
            return;
        }
        let qmi = rp_pac::QMI.mem(0);
        if qmi.rcmd().read().prefix() == QUAD_READ
            && qmi.rcmd().read().suffix() == CONTINUOUS_SUFFIX
            && qmi.rfmt().read().0 == read_format(rp_pac::qmi::vals::PrefixLen::None).0
            && qmi.timing().read().clkdiv() == CLKDIV
        {
            return;
        }
        if let Some(valid) = crate::core1::with_xip_idle(|| {
            cortex_m::interrupt::free(|_| apply(&self.sample, &mut self.probe))
        }) {
            self.ready = valid;
        }
    }
}

#[inline(always)]
fn halt() -> ! {
    crate::trustzone::fault::fence();
    loop {
        core::hint::spin_loop();
    }
}

#[derive(Clone, Copy)]
enum Wait {
    Idle,
    Transmit,
    Receive,
}

#[inline(always)]
fn wait(condition: Wait) -> bool {
    for _ in 0..READY_POLLS {
        let status = rp_pac::QMI.direct_csr().read();
        let ready = match condition {
            Wait::Idle => !status.busy(),
            Wait::Transmit => !status.txfull(),
            Wait::Receive => !status.rxempty(),
        };
        if ready {
            return true;
        }
    }
    false
}

#[inline(always)]
fn command(code: u8, payload: Option<u8>, bytes: &mut [u8]) -> bool {
    let qmi = rp_pac::QMI;
    let saved = qmi.direct_csr().read();
    let mut direct = saved;
    direct.set_clkdiv(12);
    direct.set_en(true);
    direct.set_assert_cs0n(false);
    direct.set_assert_cs1n(false);
    direct.set_auto_cs0n(false);
    direct.set_auto_cs1n(false);
    qmi.direct_csr().write_value(direct);
    let result = 'transfer: {
        if !wait(Wait::Idle) {
            break 'transfer false;
        }
        for _ in 0..4 {
            if qmi.direct_csr().read().rxempty() {
                break;
            }
            qmi.direct_rx().read();
        }
        if !qmi.direct_csr().read().rxempty() {
            break 'transfer false;
        }
        direct.set_assert_cs0n(true);
        qmi.direct_csr().write_value(direct);
        let mut tx = rp_pac::qmi::regs::DirectTx::default();
        tx.set_data(u16::from(code));
        tx.set_nopush(true);
        qmi.direct_tx().write_value(tx);
        if let Some(byte) = payload {
            if !wait(Wait::Transmit) {
                break 'transfer false;
            }
            tx.set_data(u16::from(byte));
            qmi.direct_tx().write_value(tx);
        }
        for byte in bytes {
            if !wait(Wait::Transmit) {
                break 'transfer false;
            }
            qmi.direct_tx().write_value(Default::default());
            if !wait(Wait::Receive) {
                break 'transfer false;
            }
            let Ok(value) = u8::try_from(qmi.direct_rx().read().direct_rx()) else {
                break 'transfer false;
            };
            *byte = value;
        }
        wait(Wait::Idle)
    };
    if !wait(Wait::Idle) {
        halt()
    }
    direct.set_assert_cs0n(false);
    qmi.direct_csr().write_value(direct);
    qmi.direct_csr().write_value(saved);
    result
}

// SAFETY: startup copies this routine into executable read-only SRAM. Its only
// caller runs before core1 starts, with interrupts masked and no flash DMA.
#[unsafe(link_section = ".data.ram_func")]
#[inline(never)]
fn enable_volatile_quad() -> bool {
    struct Port;
    impl rsk_store::flash_quad::Commands for Port {
        #[inline(always)]
        fn transfer(&mut self, code: u8, payload: Option<u8>, bytes: &mut [u8]) -> bool {
            command(code, payload, bytes)
        }
    }
    rsk_store::flash_quad::enable(&mut Port)
}

#[inline(always)]
fn read_format(prefix: rp_pac::qmi::vals::PrefixLen) -> rp_pac::qmi::regs::Rfmt {
    use rp_pac::qmi::vals;
    let mut format = rp_pac::qmi::regs::Rfmt::default();
    format.set_prefix_width(vals::PrefixWidth::S);
    format.set_prefix_len(prefix);
    format.set_addr_width(vals::AddrWidth::Q);
    format.set_suffix_width(vals::SuffixWidth::Q);
    format.set_suffix_len(vals::SuffixLen::_8);
    format.set_dummy_width(vals::DummyWidth::Q);
    format.set_dummy_len(vals::DummyLen::_16);
    format.set_data_width(vals::DataWidth::Q);
    format.set_dtr(false);
    format
}

// SAFETY: core1 is not started or has acknowledged interrupt-masked SRAM parking.
// The caller masks core0 interrupts; changes, probe reads and restores stay in SRAM.
#[unsafe(link_section = ".data.ram_func")]
#[inline(never)]
fn apply(expected: &[u8; SAMPLE_BYTES], sample: &mut [u8; SAMPLE_BYTES]) -> bool {
    use rp_pac::qmi::vals;
    let qmi = rp_pac::QMI;
    let mem = qmi.mem(0);
    let saved_csr = qmi.direct_csr().read();
    let saved_timing = mem.timing().read();
    let saved_format = mem.rfmt().read();
    let saved_command = mem.rcmd().read();
    let mut direct = saved_csr;
    direct.set_en(true);
    let mode = rsk_store::flash_quad::continuous_read(|step| match step {
        ReadStep::Prepare => {
            // An unknown original protocol cannot be safely reconstructed on rollback.
            if saved_format.prefix_len() != vals::PrefixLen::_8
                || saved_command.suffix() & 0x30 == 0x20
            {
                return false;
            }
            qmi.direct_csr().write_value(direct);
            if !wait(Wait::Idle) {
                qmi.direct_csr().write_value(saved_csr);
                return false;
            }
            mem.rfmt().write_value(read_format(vals::PrefixLen::_8));
            let mut command = rp_pac::qmi::regs::Rcmd::default();
            command.set_prefix(QUAD_READ);
            command.set_suffix(CONTINUOUS_SUFFIX);
            mem.rcmd().write_value(command);
            let mut timing = saved_timing;
            timing.set_clkdiv(CLKDIV);
            mem.timing().write_value(timing);
            qmi.direct_csr().write_value(saved_csr);
            true
        }
        ReadStep::Prime => {
            // The first word latches A0h; another prefixed transaction would be invalid.
            super::stream::read(SAMPLE_OFFSET, &mut [0; 4]).is_ok()
        }
        ReadStep::OmitPrefix => {
            qmi.direct_csr().write_value(direct);
            if !wait(Wait::Idle) {
                return false;
            }
            mem.rfmt().write_value(read_format(vals::PrefixLen::None));
            qmi.direct_csr().write_value(saved_csr);
            true
        }
        ReadStep::Probe => {
            let read = super::stream::read(SAMPLE_OFFSET, sample);
            let difference = sample.iter().zip(expected).fold(0, |a, (x, y)| a | (x ^ y));
            read.is_ok() && difference == 0
        }
        ReadStep::Release => {
            qmi.direct_csr().write_value(direct);
            if !wait(Wait::Idle) {
                return false;
            }
            // P25Q32H §10.23: eight clocks with all IO high exit enhanced read.
            direct.set_clkdiv(12);
            direct.set_auto_cs0n(false);
            direct.set_auto_cs1n(false);
            direct.set_assert_cs1n(false);
            direct.set_assert_cs0n(true);
            qmi.direct_csr().write_value(direct);
            let mut tx = rp_pac::qmi::regs::DirectTx::default();
            tx.set_data(0xffff);
            tx.set_iwidth(vals::Iwidth::Q);
            tx.set_dwidth(true);
            tx.set_oe(true);
            tx.set_nopush(true);
            for _ in 0..2 {
                if !wait(Wait::Transmit) {
                    return false;
                }
                qmi.direct_tx().write_value(tx);
            }
            if !wait(Wait::Idle) {
                return false;
            }
            direct.set_assert_cs0n(false);
            qmi.direct_csr().write_value(direct);
            true
        }
        ReadStep::Restore => {
            mem.timing().write_value(saved_timing);
            mem.rfmt().write_value(saved_format);
            mem.rcmd().write_value(saved_command);
            qmi.direct_csr().write_value(saved_csr);
            true
        }
    });
    match mode {
        ReadMode::Continuous => true,
        ReadMode::Unchanged | ReadMode::Restored => false,
        ReadMode::Fatal => halt(),
    }
}
