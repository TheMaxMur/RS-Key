// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! One power-up of the emulated RP2350: picoem's cores and bus, the chip models
//! mounted over its stubs, the real bootrom and the flash. A power cycle or a
//! warm reset is a new `Chip` over the same flash and OTP.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use rp2350_emu::{Config, CortexM33, Emulator, MmioAliasing, MmioHandle};

use super::Log;
use super::bootram::{self, BootRam};
use super::elf::Elf;
use super::flash::Flash;
use super::inspect::Stack;
use super::ioqspi::{IO_QSPI_BASE, IoQspi};
use super::otp::{self, OtpCore, OtpCtrl, OtpData, SharedOtp};
use super::psm::{PSM_BASE, Psm};
use super::qspi::{self, Qmi};
use super::sha256::{SHA256_BASE, Sha256};
use super::trng::{TRNG_BASE, Trng};
use super::usb::{self, SharedUsb, UsbCore, UsbDpram, UsbRegs};
use super::watchdog::{WATCHDOG_BASE, Watchdog};

/// The quantum while a core runs; a parked chip is stepped in larger ones.
pub const RUN_QUANTUM: u32 = 64;
const WATCHDOG_SCRATCH0: u32 = WATCHDOG_BASE + 0x0C;
pub const SCRATCH_REGS: usize = 8;
/// AIRCR.SYSRESETREQ, which `SCB::sys_reset` writes (with VECTKEY).
const AIRCR_SYSRESETREQ: u32 = 1 << 2;
/// The bootrom points the Non-secure VTOR into the mask ROM just before it enters
/// nsboot; no image does, so that store marks a boot into the bootloader.
const ROM_END: u32 = 0x8000;
/// QSPI SS and SD1 in SIO GPIO_HI_IN: the BOOTSEL button pulls SS low, and SD1
/// low picks the USB bootloader over the UART one.
const QSPI_CSN: u32 = 1 << 27;
const QSPI_SD1: u32 = 1 << 29;
/// `rom_data::reboot`'s flags in r0: a reboot into BOOTSEL.
const REBOOT_TYPE_BOOTSEL: u32 = 0x2;
const IPSR_HARDFAULT: u32 = 3;
const CPACR_CP7: u32 = 0x3 << 14;

/// Why the chip stopped running what it was running.
#[derive(Debug, PartialEq, Eq)]
pub enum Stop {
    /// It asked for a reset; `bootsel` when into the bootloader.
    Reboot { bootsel: bool },
    /// The bootrom handed the chip to nsboot, its USB bootloader.
    Nsboot(String),
    /// A HardFault or a panic: nothing answers until a power cycle.
    Dead(String),
}

pub struct Chip {
    emu: Emulator,
    pub usb: SharedUsb,
    otp: SharedOtp,
    log: Log,
    elf: Arc<Elf>,
    bootsel: Arc<AtomicBool>,
    h_psm: MmioHandle,
    h_qmi: MmioHandle,
    h_bootram: MmioHandle,
    h_watchdog: MmioHandle,
    hardfault: Option<u32>,
    panic_fn: Option<u32>,
    core1_released_seen: u32,
    core1_hold: bool,
    nsboot_seen: bool,
    qmi_ops_seen: u64,
    otp_burns_seen: usize,
    emu_ns: f64,
    stacks: Option<[Stack; 2]>,
}

impl Chip {
    /// Power the chip up over `flash` and the OTP `rows`, into the bootrom's reset
    /// vector. `scratch` is the watchdog scratch a warm reset keeps; a power-on
    /// clears it.
    pub fn power_up(
        rom: &[u8],
        elf: Arc<Elf>,
        seed: &[u8],
        flash: &Flash,
        rows: Vec<u32>,
        scratch: Option<[u32; SCRATCH_REGS]>,
    ) -> Result<Self, String> {
        let mut emu = rp2350_emu::EmulatorBuilder::new(Config::default())
            .step_quantum(RUN_QUANTUM)
            .build()
            .map_err(|e| e.to_string())?;
        emu.load_bootrom(rom);
        emu.load_flash(flash.bytes());
        emu.reset();

        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let m = |e: rp2350_emu::MountError| e.to_string();
        let atomic = MmioAliasing::Atomic;
        emu.mount_mmio(TRNG_BASE, 0x1000, atomic, Trng::new(seed))
            .map_err(m)?;
        emu.mount_mmio(SHA256_BASE, 0x1000, atomic, Sha256::new())
            .map_err(m)?;
        let otp: SharedOtp = Arc::new(Mutex::new(OtpCore::new(rows, log.clone())));
        let data = OtpData(otp.clone());
        emu.mount_mmio(
            otp::OTP_DATA_BASE,
            otp::OTP_DATA_MOUNT_SIZE,
            MmioAliasing::Flat,
            data,
        )
        .map_err(m)?;
        emu.mount_mmio(otp::OTP_BASE, 0x1000, atomic, OtpCtrl(otp.clone()))
            .map_err(m)?;
        let usb: SharedUsb = Arc::new(Mutex::new(UsbCore::new(log.clone())));
        emu.mount_mmio(usb::USBCTRL_REGS_BASE, 0x1000, atomic, UsbRegs(usb.clone()))
            .map_err(m)?;
        let dpram = UsbDpram(usb.clone());
        emu.mount_mmio(usb::USBCTRL_DPRAM_BASE, 0x1000, MmioAliasing::Flat, dpram)
            .map_err(m)?;
        let h_bootram = emu
            .mount_mmio(bootram::BOOTRAM_BASE, 0x1000, atomic, BootRam::new())
            .map_err(m)?;
        let h_watchdog = emu
            .mount_mmio(WATCHDOG_BASE, 0x1000, atomic, Watchdog::new())
            .map_err(m)?;
        let psm = Psm::new(Arc::clone(&emu.bus.atomics));
        let h_psm = emu.mount_mmio(PSM_BASE, 0x10, atomic, psm).map_err(m)?;
        let bootsel = Arc::new(AtomicBool::new(false));
        let io = IoQspi::new(bootsel.clone());
        emu.mount_mmio(IO_QSPI_BASE, 0x1000, atomic, io)
            .map_err(m)?;
        let qmi = Qmi::new(log.clone());
        let h_qmi = emu
            .mount_mmio(qspi::QMI_BASE, 0x1000, atomic, qmi)
            .map_err(m)?;

        if let Some(scratch) = scratch {
            for (i, v) in scratch.iter().enumerate() {
                emu.bus.write32(WATCHDOG_SCRATCH0 + 4 * i as u32, *v, 0);
            }
        }
        emu.bus
            .set_gpio_external_in_hi(QSPI_CSN, QSPI_CSN | QSPI_SD1);

        Ok(Self {
            emu,
            usb,
            otp,
            log,
            hardfault: elf.symbol(&["HardFault_"]).map(|s| s.value & !1),
            panic_fn: elf.symbol(&["rust_begin_unwind"]).map(|s| s.value & !1),
            elf,
            bootsel,
            h_psm,
            h_qmi,
            h_bootram,
            h_watchdog,
            core1_released_seen: 0,
            core1_hold: false,
            nsboot_seen: false,
            qmi_ops_seen: 0,
            otp_burns_seen: 0,
            emu_ns: 0.0,
            stacks: None,
        })
    }

    /// Emulated time since this power-up.
    pub fn now_ns(&self) -> u64 {
        self.emu_ns as u64
    }

    pub fn cycles(&self) -> u64 {
        self.emu.cycles()
    }

    /// Cycles in `ns` of emulated time at the current clock, at least one.
    pub fn cycles_in(&self, ns: u64) -> u64 {
        (ns as f64 * f64::from(self.emu.bus.sys_clk_hz()) / 1e9).max(1.0) as u64
    }

    /// Both cores asleep or held: only an interrupt can change anything.
    pub fn parked(&self) -> bool {
        (0..2).all(|c| {
            let core = self.emu.core(c);
            core.is_wfe_waiting() || core.is_halted()
        })
    }

    /// Hold the BOOTSEL button down, or let it go: the bootrom samples it through
    /// SIO, the image through IO_QSPI.
    pub fn press_bootsel(&mut self, down: bool) {
        self.bootsel.store(down, Ordering::Relaxed);
        let level = if down { 0 } else { QSPI_CSN };
        self.emu
            .bus
            .set_gpio_external_in_hi(level, QSPI_CSN | QSPI_SD1);
    }

    /// The watchdog scratch registers, which a warm reset keeps.
    pub fn scratch(&mut self) -> [u32; SCRATCH_REGS] {
        let mut s = [0u32; SCRATCH_REGS];
        for (i, v) in s.iter_mut().enumerate() {
            *v = self.emu.bus.read32(WATCHDOG_SCRATCH0 + 4 * i as u32, 0);
        }
        s
    }

    /// Run `cycles` of emulated time.
    pub fn step(&mut self, cycles: u32) -> Result<(), String> {
        let cycles = cycles.max(1);
        self.emu.step_quantum = cycles;
        self.emu.step().map_err(|e| e.to_string())?;
        if let Some(stacks) = &mut self.stacks {
            for (c, stack) in stacks.iter_mut().enumerate() {
                stack.sample(self.emu.core(c).regs.sp());
            }
        }
        self.emu_ns += f64::from(cycles) * 1e9 / f64::from(self.emu.bus.sys_clk_hz());
        if self.core1_hold {
            self.core1_hold = false;
            self.emu.bus.atomics.clear_halted(1);
        }
        Ok(())
    }

    /// The chip-level work picoem leaves to its host — core 1's power — and
    /// whatever ends this run.
    pub fn check(&mut self) -> Option<Stop> {
        let (off, released) = {
            let p = self.emu.bus.mmio_device::<Psm>(self.h_psm)?;
            (p.core1_off, p.core1_released)
        };
        if released != self.core1_released_seen && !off {
            reset_core1(&mut self.emu);
            self.core1_hold = true;
        }
        self.core1_released_seen = released;

        if self.emu.shutdown_requested {
            // The bootrom's reboot entry, halted on with its flags still in r0.
            let bootsel = (0..2).any(|c| {
                let core = self.emu.core(c);
                core.is_halted() && core.regs.r[0] & REBOOT_TYPE_BOOTSEL != 0
            });
            return Some(Stop::Reboot { bootsel });
        }
        if self.emu.bus.watchdog_reset_requested()
            || self
                .emu
                .bus
                .mmio_device::<Watchdog>(self.h_watchdog)?
                .reset_requested
        {
            return Some(Stop::Reboot { bootsel: false });
        }
        for c in 0..2 {
            let core = self.emu.core(c);
            let pc = core.regs.pc();
            if core.regs.ipsr() == IPSR_HARDFAULT || Some(pc) == self.hardfault {
                let why = format!(
                    "core {c} took a HardFault (CFSR {:#010x}), lr {}",
                    core.ppb.cfsr,
                    self.where_is(core.regs.lr())
                );
                return Some(Stop::Dead(why));
            }
            if Some(pc) == self.panic_fn {
                let lr = self.where_is(core.regs.lr());
                return Some(Stop::Dead(format!("core {c} panicked, called from {lr}")));
            }
            if core.ppb.aircr & AIRCR_SYSRESETREQ != 0 {
                return Some(Stop::Reboot { bootsel: false });
            }
        }
        let ns_vtor = self.emu.core(0).ppb.ns.vtor;
        if !self.nsboot_seen && ns_vtor != 0 && ns_vtor < ROM_END {
            self.nsboot_seen = true;
            let ram = self.emu.bus.mmio_device::<BootRam>(self.h_bootram);
            return Some(Stop::Nsboot(
                ram.map(BootRam::describe_always).unwrap_or_default(),
            ));
        }
        None
    }

    /// Where both cores are, for `--trace`: a hang shows as a place.
    pub fn whereabouts(&self) -> String {
        let core = |c: usize| {
            let core = self.emu.core(c);
            let state = if core.is_halted() {
                " (halted)"
            } else if core.is_wfe_waiting() {
                " (asleep)"
            } else {
                ""
            };
            format!("core {c} at {}{state}", self.where_is(core.regs.pc()))
        };
        format!("{}; {}", core(0), core(1))
    }

    fn where_is(&self, pc: u32) -> String {
        match self.elf.function_at(pc) {
            Some(s) => format!("{pc:#010x} {}", s.name),
            None => format!("{pc:#010x}"),
        }
    }

    /// Bring `flash` (and its file) up to what the QMI model erased or programmed.
    pub fn sync_flash(&mut self, flash: &mut Flash) -> Result<(), String> {
        let ops = self
            .emu
            .bus
            .mmio_device::<Qmi>(self.h_qmi)
            .map_or(0, |q| q.flash.stats.array_ops);
        if ops != self.qmi_ops_seen {
            self.qmi_ops_seen = ops;
            flash.sync_from(self.emu.bus.memory.xip_bytes())?;
        }
        Ok(())
    }

    /// The OTP rows, when a burn changed them since the last call.
    pub fn otp_burned(&mut self) -> Option<Vec<u32>> {
        let o = self.otp.lock().unwrap();
        if o.burns.len() == self.otp_burns_seen {
            return None;
        }
        self.otp_burns_seen = o.burns.len();
        Some(o.rows.clone())
    }

    pub fn otp_rows(&self) -> Vec<u32> {
        self.otp.lock().unwrap().rows.clone()
    }

    /// The lines the models logged since the last call.
    pub fn drain_log(&mut self) -> Vec<(u64, String)> {
        std::mem::take(&mut *self.log.lock().unwrap())
    }
}

/// What silicon does when PSM releases core 1: a fresh core at the bootrom's
/// reset vector, to wait there for the launch handshake. It starts held for one
/// quantum, in which picoem brings its clock (0 when made) up to the chip's.
fn reset_core1(emu: &mut Emulator) {
    let sp = emu.bus.memory.rom_read32(0);
    let pc = emu.bus.memory.rom_read32(4);
    let atomics = Arc::clone(&emu.bus.atomics);
    let (rb_s, rb_ns, hooks) = {
        let c0 = emu.core(0);
        (
            c0.bootrom_reboot_hook_pc_s,
            c0.bootrom_reboot_hook_pc_ns,
            c0.rom_call_hooks.clone(),
        )
    };
    let mut c1 = CortexM33::new(1, atomics);
    c1.regs.msp = sp;
    c1.regs.r[13] = sp;
    c1.regs.set_pc(pc & !1);
    c1.bootrom_reboot_hook_pc_s = rb_s;
    c1.bootrom_reboot_hook_pc_ns = rb_ns;
    c1.rom_call_hooks = hooks;
    c1.ppb.cpacr |= CPACR_CP7;
    emu.cores.expect_arm_mut()[1] = c1;
    emu.bus.atomics.set_halted(1);
    emu.bus.atomics.clear_wfe_waiting(1);
    emu.bus.atomics.set_irq_pending(1, 0);
}

#[path = "probe.rs"]
mod probe;
