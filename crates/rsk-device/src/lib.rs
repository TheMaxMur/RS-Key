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

extern crate alloc;

use alloc::boxed::Box;

use rsk_fido::state::PinLock;

mod ccid;
mod ctap;
pub mod presence;

pub use ccid::CcidApplets;
// The union is only reachable where a device-wide wipe is: `Management RESET` on
// the permissive build, and the trusted display's factory reset. The same gate the
// function itself carries, or a strict non-display build fails to re-export it.
#[cfg(any(not(feature = "strict-config"), feature = "display"))]
pub use ccid::gates_wiped_last;
pub use ctap::AppletHandler;

/// What [`Hooks::rsa_search`] answers. Named so an implementor can spell it
/// without taking `rsa` and `alloc` into its own scope.
pub type SearchResult = Option<Option<Box<rsa::RsaPrivateKey>>>;

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
    /// A vendor CBOR command wrote the device configuration; re-apply whatever
    /// lives outside the file system. On the device that is the LED block, whose
    /// live copy is a set of atomics the flash record does not reach.
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
    fn rsa_search(&mut self, _nbits: usize, _rng: &mut dyn rsk_openpgp::Rng) -> SearchResult {
        None
    }
}

/// The randomness every applet in the set needs. One bound so the wiring names it
/// once; the concrete type is the device TRNG or the emulator's DRBG.
pub trait Rng:
    rsk_fido::Rng + rsk_openpgp::Rng + rsk_oath::Rng + rsk_otp::Rng + rsk_rescue::Rng
{
}

impl<T> Rng for T where
    T: rsk_fido::Rng + rsk_openpgp::Rng + rsk_oath::Rng + rsk_otp::Rng + rsk_rescue::Rng
{
}

/// The one physical presence source, behind every applet's own trait. The
/// firmware's BOOTSEL button (or its screen) implements all of them; so does the
/// emulator's terminal prompt.
pub trait UserPresence:
    rsk_fido::UserPresence
    + rsk_openpgp::UserPresence
    + rsk_oath::UserPresence
    + rsk_otp::UserPresence
    + rsk_mgmt::UserPresence
    + rsk_rescue::UserPresence
    + rsk_vendor::UserPresence
{
}

impl<T> UserPresence for T where
    T: rsk_fido::UserPresence
        + rsk_openpgp::UserPresence
        + rsk_oath::UserPresence
        + rsk_otp::UserPresence
        + rsk_mgmt::UserPresence
        + rsk_rescue::UserPresence
        + rsk_vendor::UserPresence
{
}

#[cfg(test)]
mod tests;
