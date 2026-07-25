// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The clientPIN soft-lock canary: does the FIDO applet still owe a power cycle?
//!
//! CTAP 2.1 §6.5.5.6 stops accepting PIN attempts after three consecutive failures
//! until the authenticator is power-cycled. The point of that rule is that a host
//! cannot serve itself the reset — it takes a physical replug the user would notice,
//! so unattended malware cannot burn the whole eight-attempt budget in one go.
//!
//! `FidoState::needs_power_cycle` lives in RAM and is rebuilt clear on every boot,
//! and a host CAN request a warm reboot ungated (the vendor applet's `INS_REBOOT`
//! P1=0, the rescue applet's twin, and the phy config-write auto-reboot) — so the
//! flag evaporated exactly when it mattered. A watchdog scratch register survives
//! `SCB::sys_reset` but is cleared by a power-on reset, which is precisely the
//! distinction the spec draws, so the lock now outlives a software reboot and only
//! a real power cycle clears it.
//!
//! `scratch2` is used rather than `scratch4..7`, which the bootrom claims for its
//! own boot/`reset_to_usb_boot` signalling. The magic value means an
//! undefined-at-cold-boot register cannot read as "locked".

/// "RSKL" — a value an undefined register is overwhelmingly unlikely to hold.
const CANARY: u32 = 0x5253_4B4C;

/// Record whether the soft lock is engaged, so it survives a warm reboot.
pub fn set(engaged: bool) {
    rp_pac::WATCHDOG
        .scratch2()
        .write_value(if engaged { CANARY } else { 0 });
}

/// Whether a soft lock was engaged before the last (warm) reset.
pub fn engaged() -> bool {
    rp_pac::WATCHDOG.scratch2().read() == CANARY
}
