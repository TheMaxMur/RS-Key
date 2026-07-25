// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! What a warm reset must not launder: the clientPIN soft lock, and the fact that
//! the reset happened at all.
//!
//! CTAP 2.1 §6.5.5.6 stops accepting PIN attempts after three consecutive failures
//! until the authenticator is power-cycled. The point of that rule is that a host
//! cannot serve itself the reset — it takes a physical replug the user would notice,
//! so unattended malware cannot burn the whole eight-attempt budget in one go.
//!
//! [`rsk_fido::state::PinLock`] lives in RAM and is rebuilt clear on every boot,
//! and a host CAN request a warm reboot ungated (the vendor applet's `INS_REBOOT`
//! P1=0, the rescue applet's twin, and the phy config-write auto-reboot) — so it
//! evaporated exactly when it mattered. A watchdog scratch register survives
//! `SCB::sys_reset` but is cleared by a power-on reset, which is precisely the
//! distinction the spec draws, so the lock now outlives a software reboot and only
//! a real power cycle clears it. The *whole* lock moves: carrying the engaged flag
//! without the mismatch batch that arms it let a host stop at two wrong PINs and
//! reboot to restart the batch.
//!
//! The tag also answers "was this power cycle entered warm?" ([`Boot::warm`]),
//! which is what CTAP 2.1 §6.6's `authenticatorReset` power-up window has to key
//! on — `Instant::now()` restarts on a host-requested reboot. One register carries
//! both without interference: the tag is what makes the lock bytes trustworthy in
//! the first place, and every writer here writes the whole word.
//!
//! `scratch2` is used rather than `scratch4..7`, which the bootrom claims for its
//! own boot/`reset_to_usb_boot` signalling. The magic value means an
//! undefined-at-cold-boot register cannot read as "locked" or as "warm".

use rsk_fido::consts::PIN_MISMATCH_LIMIT;
use rsk_fido::state::PinLock;

/// "RSK" — a tag an undefined register is overwhelmingly unlikely to hold.
const TAG: u32 = 0x5253_4B00;
const TAG_MASK: u32 = 0xFFFF_FF00;
/// Low byte: the soft lock. Bit 7 is the engaged flag, the rest the mismatch batch.
const ENGAGED: u32 = 0x80;
const MISMATCH_MASK: u32 = 0x7F;

/// What the reset that started this power cycle left behind.
pub struct Boot {
    /// It was a warm reset (`sys_reset`), not a power-on: anything keying on "just
    /// powered up" must refuse to trust the restarted uptime.
    pub warm: bool,
    /// The clientPIN soft lock as of the last CBOR dispatch before that reset.
    pub lock: PinLock,
}

/// Record the soft lock, so it survives a warm reboot.
pub fn set(lock: PinLock) {
    rp_pac::WATCHDOG.scratch2().write_value(encode(lock));
}

/// Read what the last reset left, then re-arm the tag for this power cycle so the
/// *next* reset is recognised as warm even if no clientPIN command ever ran. Call
/// once at boot: a second call would report its own arming as a warm reset.
pub fn restore_and_arm() -> Boot {
    let boot = decode(rp_pac::WATCHDOG.scratch2().read());
    set(boot.lock);
    boot
}

const fn encode(lock: PinLock) -> u32 {
    TAG | if lock.engaged { ENGAGED } else { 0 } | in_range(lock.mismatches) as u32
}

const fn decode(v: u32) -> Boot {
    if v & TAG_MASK != TAG {
        return Boot {
            warm: false,
            lock: PinLock {
                engaged: false,
                mismatches: 0,
            },
        };
    }
    let mismatches = in_range((v & MISMATCH_MASK) as u8);
    Boot {
        warm: true,
        lock: PinLock {
            // Derived, not read from bit 7: the pre-0x0854 canary aliases into this
            // tag with the bit clear, and a batch at the limit is a locked
            // authenticator whatever the byte says (CTAP 2.1 §6.5.5.6).
            engaged: v & ENGAGED != 0 || mismatches >= PIN_MISMATCH_LIMIT,
            mismatches,
        },
    }
}

/// Hold a stored batch to the spec's range — the old canary's low byte is junk, and
/// a batch the crate can never reach is not one to restore.
const fn in_range(mismatches: u8) -> u8 {
    if mismatches > PIN_MISMATCH_LIMIT {
        PIN_MISMATCH_LIMIT
    } else {
        mismatches
    }
}

/// `firmware/` has no host tests, so the decode's cases are checked at build time.
/// The pre-0x0854 canary is the one that matters: it is what a device whose lock was
/// engaged before the upgrade carries into this firmware.
const LEGACY_CANARY: u32 = 0x5253_4B4C;
const _: () = assert!(decode(LEGACY_CANARY).warm);
const _: () = assert!(decode(LEGACY_CANARY).lock.engaged);
const _: () = assert!(decode(LEGACY_CANARY).lock.mismatches == PIN_MISMATCH_LIMIT);
// A power-on reset leaves no tag: cold boot, no lock, whatever the register held.
const _: () = assert!(!decode(0).warm && !decode(0).lock.engaged);
const _: () = assert!(!decode(!TAG).warm && !decode(!TAG).lock.engaged);
// Every lock the crate can produce survives the round trip (it arms the flag at the
// limit, so "a full batch, not engaged" is not one of them).
const fn round_trips(lock: PinLock) -> bool {
    let back = decode(encode(lock)).lock;
    back.engaged == lock.engaged && back.mismatches == lock.mismatches
}
const _: () = assert!(round_trips(PinLock {
    engaged: false,
    mismatches: 0
}));
const _: () = assert!(round_trips(PinLock {
    engaged: false,
    mismatches: PIN_MISMATCH_LIMIT - 1
}));
const _: () = assert!(round_trips(PinLock {
    engaged: true,
    mismatches: 0
}));
const _: () = assert!(round_trips(PinLock {
    engaged: true,
    mismatches: PIN_MISMATCH_LIMIT
}));
