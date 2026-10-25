// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use rp_pac::accessctrl::regs::Access;
use rp_pac::common::{RW, Reg};

const PASSWORD: u32 = 0xacce_0000;
const CORE0: u32 = 1 << 4;
const CORE1: u32 = 1 << 5;
const DMA: u32 = 1 << 6;
const SECURE_PRIVILEGED: u32 = 1 << 3;
const NONSECURE_PRIVILEGED: u32 = 1 << 1;
const SECURE_CORES: u32 = CORE0 | CORE1 | SECURE_PRIVILEGED;
const SECURE_DMA: u32 = SECURE_CORES | DMA;
const SHARED_MEMORY: u32 = SECURE_DMA | NONSECURE_PRIVILEGED;
const SECURE_CORE0: u32 = CORE0 | SECURE_PRIVILEGED;
const NS_TIMER: u32 = SECURE_CORE0 | NONSECURE_PRIVILEGED;

fn grant(register: Reg<Access, RW>, permissions: u32) {
    register.write(|value| value.0 = PASSWORD | permissions);
    assert_eq!(register.read().0 & 0xff, permissions);
}

pub fn configure_bus_masters() {
    let access = rp_pac::ACCESSCTRL;
    access.gpio_nsmask0().write_value(0);
    access.gpio_nsmask1().write(|value| value.0 = 0);
    assert_eq!(access.gpio_nsmask0().read(), 0);
    assert_eq!(access.gpio_nsmask1().read().0, 0);
    access.force_core_ns().write(|value| value.0 = PASSWORD);
    assert_eq!(access.force_core_ns().read().0 & 3, 0);

    grant(access.rom(), SECURE_CORES);
    // Fatal cleanup must reach USB from either Secure core without borrowing its driver.
    grant(access.usbctrl(), SECURE_CORES);
    grant(access.xip_main(), SHARED_MEMORY);
    for bank in 0..8 {
        grant(access.sram(bank), SHARED_MEMORY);
    }
    for bank in 8..10 {
        grant(access.sram(bank), SECURE_DMA);
    }

    for register in [
        access.dma(),
        access.coresight_trace(),
        access.coresight_periph(),
        access.sysinfo(),
        access.resets(),
        access.io_bank0(),
        access.io_bank1(),
        access.pads_bank0(),
        access.pads_qspi(),
        access.busctrl(),
        access.adc0(),
        access.hstx(),
        access.i2c0(),
        access.i2c1(),
        access.pwm(),
        access.timer0(),
        access.uart0(),
        access.uart1(),
        access.otp(),
        access.tbman(),
        access.powman(),
        access.sha256(),
        access.syscfg(),
        access.clocks(),
        access.xosc(),
        access.rosc(),
        access.pll_sys(),
        access.pll_usb(),
        access.ticks(),
        access.watchdog(),
        access.rsm(),
        access.xip_ctrl(),
        access.xip_qmi(),
        access.xip_aux(),
    ] {
        grant(register, SECURE_CORE0);
    }
    grant(access.trng(), SECURE_CORES);
    for register in [
        access.pio0(),
        access.pio1(),
        access.pio2(),
        access.spi0(),
        access.spi1(),
    ] {
        grant(register, SECURE_DMA);
    }
    grant(access.timer1(), NS_TIMER);

    for channel in 0..16 {
        rp_pac::DMA.seccfg_ch(channel).modify(|value| {
            value.set_s(true);
            value.set_p(true);
            value.set_lock(true);
        });
        let security = rp_pac::DMA.seccfg_ch(channel).read();
        assert!(security.s() && security.p() && security.lock());
    }
    for irq in 0..4 {
        rp_pac::DMA.seccfg_irq(irq).write(|value| {
            value.set_s(true);
            value.set_p(true);
        });
        let security = rp_pac::DMA.seccfg_irq(irq).read();
        assert!(security.s() && security.p());
    }
    rp_pac::DMA.seccfg_misc().write(|value| {
        value.set_sniff_s(true);
        value.set_sniff_p(true);
        for timer in 0..4 {
            value.set_timer_s(timer, true);
            value.set_timer_p(timer, true);
        }
    });
    access.lock().write(|value| value.0 = PASSWORD | 0xf);
    assert_eq!(access.lock().read().0 & 0xf, 0xf);
    cortex_m::asm::dsb();
    cortex_m::asm::isb();
}
