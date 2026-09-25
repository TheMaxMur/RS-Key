// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The applet wiring: which applets exist, in what order, what capability gates
//! each, and how a CTAPHID or CCID message reaches one.
//!
//! This lived in `firmware/src/{handler,ccid_handler}.rs` — the last piece of the
//! device that was not host-testable and not reachable by `tools/emu`, so the
//! emulator carried a second implementation of it. Two copies of the routing
//! rules is two chances to answer differently, and the rules here are the ones
//! that decide whether a U2F command can land on the vendor applet, whether a
//! disabled application is really invisible, and which records a device-wide wipe
//! is allowed to take first.
//!
//! What genuinely belongs to the board — the second core's prime search, the LED
//! atomics, the watchdog register that carries the clientPIN soft lock across a
//! warm reset — sits behind [`Hooks`], whose defaults are exact no-ops. A host
//! build inherits every one of them and behaves like a device that has none of
//! that hardware, which is what it is.

// Host test builds link `std`: the RAM `Fs` the wiring is exercised over wants a
// heap, and no test code reaches the firmware image.
#![cfg_attr(not(test), no_std)]
#![deny(clippy::disallowed_methods, clippy::disallowed_types)]

extern crate alloc;

use alloc::boxed::Box;

use rsk_fido::state::PinLock;

mod ccid;
mod ccid_fido;
pub mod click;
mod ctap;
pub mod presence;
pub mod reboot;

pub use ccid::CcidApplets;
// The records a device-wide wipe removes last: the trusted display's factory reset.
pub use ccid::gates_wiped_last;
pub use ctap::AppletHandler;
#[cfg(feature = "security-trace")]
pub use ctap::SecurityTraceSnapshot;

/// What [`Hooks::rsa_search`] answers. Named so an implementor can spell it
/// without taking `rsk_rsa` and `alloc` into its own scope.
pub type SearchResult = Option<Option<Box<rsk_rsa::RsaKey>>>;

/// What the reset that started this power cycle left behind.
///
/// CTAP 2.1 §6.5.5.6 stops accepting PIN attempts until the authenticator is
/// power-cycled, and §6.6 opens the `authenticatorReset` window only just after a
/// power-up — so both need to know whether this boot was warm, which is a fact
/// only the board can report. The default is a cold boot with no lock: on a build
/// with nothing to remember it, every boot is genuinely a first one.
#[derive(Clone, Copy, Default)]
pub struct BootState {
    /// It was a warm reset (`sys_reset`), not a power-on.
    pub warm: bool,
    /// The clientPIN soft lock as of the last dispatch before that reset.
    pub lock: PinLock,
}

/// The board underneath the applets. Every method defaults to what a build with
/// no such hardware does, so a host build implements none of them and a device
/// implements exactly what it has.
pub trait Hooks<S: rsk_fs::Storage> {
    /// A vendor CBOR command wrote the LED block; re-apply it outside the file
    /// system. On the device its live copy is a set of atomics the flash record
    /// does not reach.
    fn config_written(&mut self, _fs: &mut rsk_fs::Fs<S>) {}

    /// Queue a warm reboot, to run once the response has flushed. A phy write asks
    /// for one because the USB identity is only read at boot; a build that cannot
    /// re-enumerate does nothing, which is also what `OPT_DISABLE_POWER_RESET`
    /// asks for on a device.
    fn request_reboot(&mut self) {}

    /// Persist the clientPIN soft lock, so a host-requested warm reboot cannot
    /// launder it (the point of §6.5.5.6 is that only a physical power cycle
    /// clears it, and a host can ask for a warm one ungated).
    fn store_pin_lock(&mut self, _lock: PinLock) {}

    /// The lock and the warm/cold verdict this boot inherited. Called once, when
    /// the handler is built.
    fn boot_state(&mut self) -> BootState {
        BootState::default()
    }

    /// The on-device pad committed a new clientPIN since the last command, so the
    /// session token the old PIN authorized has to end. Trusted-display only.
    fn local_pin_changed(&mut self) -> bool {
        false
    }

    /// Take over an RSA `GENERATE`: the firmware runs the prime search on both
    /// cores while the transport streams time extensions. Three answers, and the
    /// difference between the first two is load-bearing:
    ///
    /// - `None` — no accelerator here. The command falls through to normal
    ///   dispatch and the applet's own single-core path runs: same key, same
    ///   store, just slower. A host build wants exactly this.
    /// - `Some(None)` — the accelerator ran and found nothing; the command
    ///   reports `EXEC_ERROR`.
    /// - `Some(Some(key))` — the key.
    fn rsa_search(&mut self, _nbits: usize, _rng: &mut dyn rsk_sdk::Rng) -> SearchResult {
        None
    }
}

/// End the host's session token once the trusted display re-keyed or rejected the
/// clientPIN, or wiped the device. Both transports call this before they dispatch:
/// whichever reads the one-shot signal first ends the token in the state they share.
pub(crate) fn reset_token_on_local_pin_change<S: rsk_fs::Storage, R: rsk_sdk::Rng>(
    hooks: &core::cell::RefCell<dyn Hooks<S>>,
    fido_state: &core::cell::RefCell<rsk_fido::FidoState>,
    rng: &core::cell::RefCell<R>,
) {
    if hooks.borrow_mut().local_pin_changed() {
        let mut rngb = rng.borrow_mut();
        fido_state.borrow_mut().reset_pin_uv_auth_token(&mut *rngb);
        // The host path also clears `needs_power_cycle` here; that field is
        // crate-private and leaving the RAM soft lock armed only fails closed
        // (host clientPIN stays blocked until a replug), so it stays as it is.
    }
}

/// Hand the clientPIN soft lock to the board after a dispatch on either transport. It is
/// RAM-only, and a host can ask for `SCB::sys_reset` ungated (vendor or rescue 0x1F P1=00,
/// the phy config-write reboot): a lock left behind refunds the §6.5.5.6 retry budget.
pub(crate) fn persist_pin_lock<S: rsk_fs::Storage>(
    hooks: &core::cell::RefCell<dyn Hooks<S>>,
    fido_state: &core::cell::RefCell<rsk_fido::FidoState>,
) {
    hooks
        .borrow_mut()
        .store_pin_lock(fido_state.borrow().pin_lock());
}

/// Re-apply what a vendor (0x41) config write left outside the file system — the LED
/// atomics, and a warm reboot for a changed USB identity. Both transports call this
/// after every command: the signal is the write itself, however it was framed.
pub(crate) fn apply_vendor_config<S: rsk_fs::Storage>(
    hooks: &core::cell::RefCell<dyn Hooks<S>>,
    fs: &core::cell::RefCell<rsk_fs::Fs<S>>,
    fido_state: &core::cell::RefCell<rsk_fido::FidoState>,
) {
    let (led, phy) = {
        let mut state = fido_state.borrow_mut();
        (state.take_led_written(), state.take_phy_written())
    };
    if led {
        hooks.borrow_mut().config_written(&mut fs.borrow_mut());
    }
    if phy {
        let phy = rsk_phy::load(&mut fs.borrow_mut()).unwrap_or_default();
        if phy.opts & rsk_phy::OPT_DISABLE_POWER_RESET == 0 {
            hooks.borrow_mut().request_reboot();
        }
    }
}

// The wiring names `rsk_sdk::Rng` / `rsk_sdk::UserPresence` directly. Two
// supertraits stood here only to reconcile one byte-identical declaration per
// applet; the declarations moved into `rsk-sdk`, so the glue went with them.

#[cfg(test)]
mod tests;
