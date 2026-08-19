// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

#![no_main]

//! Stateful cross-applet fuzzing over the *shipped* wiring. Every other applet
//! target drives ONE applet from a fresh state; this one builds the real
//! [`rsk_device::CcidApplets`] — the same eight-applet registration, in the same
//! order, that the firmware and `tools/emu` run — over one shared flash `Fs`, RNG
//! and presence source, then replays an attacker-chosen sequence of transport
//! verbs against it. Selection, chaining, each applet's PIN/MSE/auth state, the
//! cached capability mask and the file system all persist across the sequence.
//!
//! It used to hand-roll a five-applet `Dispatcher` of its own, which is precisely
//! what `crates/rsk-device/Cargo.toml` says that crate exists to prevent: a second
//! copy of the routing rules is two chances to answer differently. Worse, the AIDs
//! are magic values a mutator cannot invent — two independent measurements put the
//! old target at ZERO applet dispatches over ~10M executions, so its whole premise
//! (state leaking across the seam between applets) had never once been exercised.
//! SELECT is a reserved opcode now, so an input starts *inside* an applet instead
//! of bouncing off `FILE_NOT_FOUND`, and the 926 lines of pre-auth transport
//! wiring around the dispatcher — the cap gating, `reset_card`, `reset_chaining`,
//! the ungated CTAPHID WRITE CONFIG, the OTP keyboard interface, the device-wide
//! wipe — are in the fuzz build for the first time.
//!
//! Each record starts with an opcode byte:
//!
//! | byte | verb |
//! |---|---|
//! | `0x00`–`0x06` | SELECT applet *k* by its registered AID, in registration order |
//! | `0xF0` | `ctap_mgmt(cmd, body)` — READ / WRITE CONFIG over the FIDO transport |
//! | `0xF1` | `reset_card()` — the ICC power transition |
//! | `0xF2` | `reset_chaining()` — what the out-of-band on-pad VERIFY does first |
//! | `0xF3` | `refresh_enabled()` — re-read the capability mask from flash |
//! | `0xF4` | `factory_wipe()` — the device-wide reset |
//! | `0xF5` | `handle_otp_hid(slot, payload)` — the keyboard interface |
//! | `0xF6` | WRITE CONFIG `USB_ENABLED = be16(hi, lo)` — the capability mask |
//! | anything else | a raw APDU, framed by `apdu_frame::next_frame`: one length byte then that many bytes, or `0xFF` for the extended-Lc escape |
//!
//! Beyond not panicking, the oracle is the set of rules this crate owns and no
//! applet can enforce for itself: a reply always carries its status word and fits
//! one CCID frame; an application the capability mask has disabled answers
//! `FILE_NOT_FOUND` to SELECT and an ungated one never does; a card reset leaves
//! nothing selected for the PIN pad to paint for; READ CONFIG never goes silent;
//! the mask never reports a capability this build does not have; a factory wipe
//! takes `EF_DEV_CONF` with it, so disabling every application stays recoverable;
//! and an OTP function slot is inert while OTP is off.

use core::cell::RefCell;

use libfuzzer_sys::fuzz_target;
use rsk_device::{CcidApplets, Hooks};
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;
use rsk_sdk::{Apdu, Sw};

mod apdu_frame;
use apdu_frame::next_frame;

const SERIAL_ID: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 1, 2, 3, 4];
const SERIAL_HASH: [u8; 32] = [0x22; 32];
const KV_TOTAL: u32 = 64 * 1024;
const FLASH_SIZE: u32 = 4 * 1024 * 1024;
const OPENPGP_MFR: u16 = 0x1234;

/// OpenPGP `GENERATE ASYMMETRIC KEY` and PIV `GENERATE` are both INS `0x47`.
const INS_GENERATE: u8 = 0x47;
/// The ykman vendor commands the FIDO transport serves: READ CONFIG must always
/// answer, and WRITE CONFIG is its ungated twin on the default build.
const CTAP_READ_CONFIG: u8 = 0x42;
const CTAP_WRITE_CONFIG: u8 = 0x43;
/// DeviceInfo's `USB_ENABLED` tag — mirrors `rsk-mgmt`'s crate-private
/// `TAG_USB_ENABLED`, the one writable field that decides which applets exist.
const TAG_USB_ENABLED: u8 = 0x03;
/// The four PIN references the trusted display's pad can be asked to collect.
const PIN_REFS: [u8; 4] = [
    rsk_openpgp::consts::PW1_MODE81,
    rsk_openpgp::consts::PW1_MODE82,
    rsk_openpgp::consts::PW3_MODE83,
    rsk_usb::secure_pin::PIV_PIN_P2,
];

/// The eight applets in **registration order** — the order `CcidApplets` builds
/// them in, which is what the dispatcher's enable mask is indexed by — each with
/// the capability bit that gates it. `0` = ungated: management is the re-enable
/// path and vendor/rescue are the recovery ones, so a disable is never final.
/// FIDO's entry carries two bits because one AID serves two applications, and
/// `cap_enabled` is an ANY test.
const APPLETS: [(&[u8], u16); 8] = [
    (rsk_vendor::VENDOR_AID, 0),
    (rsk_openpgp::consts::OPENPGP_AID, rsk_mgmt::CAP_OPENPGP),
    (rsk_mgmt::MANAGEMENT_AID, 0),
    (rsk_oath::OATH_AID, rsk_mgmt::CAP_OATH),
    (rsk_otp::OTP_AID, rsk_mgmt::CAP_OTP),
    (rsk_piv::PIV_AID, rsk_mgmt::CAP_PIV),
    (rsk_rescue::RESCUE_AID, 0),
    (
        rsk_fido::consts::FIDO_AID,
        rsk_mgmt::CAP_FIDO2 | rsk_mgmt::CAP_U2F,
    ),
];

const OP_SELECT_MAX: u8 = 7;
const OP_CTAP_MGMT: u8 = 0xF0;
const OP_RESET_CARD: u8 = 0xF1;
const OP_RESET_CHAINING: u8 = 0xF2;
const OP_REFRESH: u8 = 0xF3;
const OP_FACTORY_WIPE: u8 = 0xF4;
const OP_OTP_HID: u8 = 0xF5;
const OP_SET_CAPS: u8 = 0xF6;

/// The board underneath the wiring. Every [`Hooks`] method stays at its default,
/// which is what a build with none of that hardware does — and `rsa_search`'s
/// `None` is load-bearing here: see the GENERATE skip in the replay loop.
struct Board;
impl Hooks<RamStorage> for Board {}

/// One physical button behind all eight applet traits, as on the device. Confirms
/// instantly so the presence-gated commands stay reachable for the fuzzer.
struct Finger;

macro_rules! impl_presence {
    ($($m:ident),+ $(,)?) => {$(
        impl $m::UserPresence for Finger {
            fn request(&mut self, _confirm: $m::Confirm<'_>) -> $m::Presence {
                $m::Presence::Confirmed
            }
        }
    )+};
}

impl_presence!(
    rsk_fido,
    rsk_openpgp,
    rsk_oath,
    rsk_otp,
    rsk_mgmt,
    rsk_rescue,
    rsk_vendor,
);

/// Deterministic host RNG; one instance feeds every applet, mirroring the single
/// shared TRNG on device.
struct SeqRng(u64);

impl SeqRng {
    fn next(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

macro_rules! impl_rng {
    ($($t:path),+ $(,)?) => {$(
        impl $t for SeqRng {
            fn fill(&mut self, buf: &mut [u8]) {
                self.next(buf)
            }
        }
    )+};
}

impl_rng!(
    rsk_fido::Rng,
    rsk_openpgp::Rng,
    rsk_oath::Rng,
    rsk_otp::Rng,
    rsk_rescue::Rng,
);

/// The rescue applet's board: no secure boot, no fuse this may burn, a session
/// clock. Its deep OTP-lock / rollback arms belong to the dedicated `rescue_apdu`
/// target; what this one wants is that the applet is reachable at all.
#[derive(Default)]
struct RescueBoard {
    time: Option<u32>,
}

impl rsk_rescue::Platform for RescueBoard {
    fn secure_boot_status(&self) -> rsk_rescue::SecureBootStatus {
        rsk_rescue::SecureBootStatus {
            enabled: false,
            locked: false,
            bootkey: 0xFF,
        }
    }
    fn now(&self) -> Option<u32> {
        self.time
    }
    fn set_time(&mut self, epoch: u32) {
        self.time = Some(epoch);
    }
    fn request_reboot(&mut self, _bootsel: bool) {}
    fn read_page58_lock_raw(&self) -> Option<u32> {
        Some(0)
    }
    fn lock_page58(&mut self) -> bool {
        false
    }
    fn read_rollback_raw(&self) -> Option<rsk_rescue::rollback::RollbackRaw> {
        Some(rsk_rescue::rollback::RollbackRaw {
            flags0: [0; 3],
            version0: [0; 3],
            version1: [0; 3],
        })
    }
    fn set_rollback_required(&mut self) -> bool {
        false
    }
}

/// The vendor applet's board: every method defaults to "this build has none of
/// that hardware", which is exactly what a host build is.
struct VendorBoard;
impl rsk_vendor::Platform for VendorBoard {}

/// The status word of a response APDU, checked on the way past. Body + SW has to
/// fit one CCID `XfrBlock`: sizing that buffer to the whole CCID message once let
/// a long OATH LIST overrun the frame, and `run_xfr` dropped the tail with it.
fn status(res: &[u8]) -> Sw {
    let n = res.len();
    assert!(n >= 2, "a response APDU always carries its status word");
    assert!(
        n + rsk_usb::ccid::HEADER <= rsk_usb::ccid::MAX_CCID_MSG,
        "a {n}-byte response does not fit one CCID frame"
    );
    Sw::new(res[n - 2], res[n - 1])
}

/// One byte at `*i`, advancing past it; `0` once the input runs out.
fn byte(data: &[u8], i: &mut usize) -> u8 {
    let b = data.get(*i).copied().unwrap_or(0);
    *i = (*i + 1).min(data.len());
    b
}

/// A length-prefixed slice at `*i`, advancing past it. A truncated tail yields
/// what is left rather than nothing — a short command is still worth issuing.
fn chunk<'a>(data: &'a [u8], i: &mut usize) -> &'a [u8] {
    let n = byte(data, i) as usize;
    let end = (*i + n).min(data.len());
    let s = &data[*i..end];
    *i = end;
    s
}

fuzz_target!(|data: &[u8]| {
    let fs = RefCell::new(Fs::new(RamStorage::new()));
    fs.borrow_mut().scan();
    let rng = RefCell::new(SeqRng(1));
    let board = RefCell::new(Board);
    let finger = RefCell::new(Finger);
    let rescue = RefCell::new(RescueBoard::default());
    // The device's one FIDO session state, as the worker holds it.
    let fido_state = RefCell::new(rsk_fido::FidoState::new());

    let mut ccid = CcidApplets::new(
        &fs,
        &rng,
        &board,
        &finger,
        &fido_state,
        &rescue,
        VendorBoard,
        SERIAL_ID,
        SERIAL_HASH,
        None,
        None,
        KV_TOTAL,
        FLASH_SIZE,
        OPENPGP_MFR,
    );

    let mut i = 0;
    while i < data.len() {
        let op = byte(data, &mut i);
        match op {
            0..=OP_SELECT_MAX => {
                let (aid, cap) = APPLETS[op as usize];
                // Longest registered AID is PIV's 11 bytes; 32 leaves room for a
                // longer one without this becoming a second ceiling to maintain.
                let mut sel = [0u8; 5 + 32];
                sel[..4].copy_from_slice(&[0x00, 0xA4, 0x04, 0x00]);
                sel[4] = aid.len() as u8;
                sel[5..5 + aid.len()].copy_from_slice(aid);
                let enabled = ccid.caps_enabled(cap);
                let sw = status(ccid.handle_apdu(&sel[..5 + aid.len()], 0));
                // No applet's own `select` answers FILE_NOT_FOUND, so this is
                // exactly the gate: `ykman config usb --disable X` really removes
                // X, and the three ungated applets can never be removed at all.
                assert_eq!(
                    sw == Sw::FILE_NOT_FOUND,
                    !enabled,
                    "applet {op} (cap {cap:#06x}) answered {sw:?} while enabled={enabled}"
                );
            }
            OP_CTAP_MGMT => {
                let cmd = byte(data, &mut i);
                let body = chunk(data, &mut i);
                let served = ccid.ctap_mgmt(cmd, body).map(<[u8]>::len);
                // READ CONFIG is how ykman identifies the key when only the FIDO
                // interface is present; if the sequence can silence it, the host
                // loses the surface it would re-enable the others from.
                if cmd == CTAP_READ_CONFIG {
                    assert!(
                        matches!(served, Some(n) if n > 0),
                        "READ CONFIG went silent over CTAPHID"
                    );
                }
            }
            OP_RESET_CARD => {
                ccid.reset_card();
                for p2 in PIN_REFS {
                    // Nothing is selected, so the pad must not be painted for any
                    // reference — audit run-36, where the check ran on the VERIFY
                    // and so stopped the authentication but not the screen.
                    assert!(!ccid.pin_ref_ready(p2), "pin pad armed for {p2:#04x}");
                }
            }
            OP_RESET_CHAINING => ccid.reset_chaining(),
            OP_REFRESH => {
                let mask = ccid.refresh_enabled();
                assert_eq!(
                    mask & !rsk_mgmt::SUPPORTED_CAPS,
                    0,
                    "the mask enables a capability this build does not have"
                );
            }
            OP_FACTORY_WIPE => {
                if ccid.factory_wipe() {
                    // The wipe is not allowed to spare `EF_DEV_CONF`, or an owner
                    // who disabled every application has no way back.
                    assert_eq!(
                        rsk_mgmt::read_enabled_caps(&mut fs.borrow_mut()),
                        rsk_mgmt::SUPPORTED_CAPS,
                        "a factory wipe left the enabled-applications record behind"
                    );
                }
            }
            OP_OTP_HID => {
                let slot = byte(data, &mut i);
                let body = chunk(data, &mut i);
                let mut payload = [0u8; 64];
                let n = body.len().min(payload.len());
                payload[..n].copy_from_slice(&body[..n]);
                let otp_on = ccid.caps_enabled(rsk_mgmt::CAP_OTP);
                let (_, len, _) = ccid.handle_otp_hid(slot, &payload);
                if !otp_on && rsk_otp::is_function_slot(slot) {
                    assert_eq!(
                        len, 0,
                        "function slot {slot:#04x} answered while OTP is off"
                    );
                }
            }
            OP_SET_CAPS => {
                // The cap mask is this target's second magic value after the AIDs:
                // no run ever invented `03 02 <hi> <lo>` — 190 787 generated executions
                // reached neither gated clause, only three evictable corpus seeds did.
                let hi = byte(data, &mut i);
                let lo = byte(data, &mut i);
                let blob = [0x04, TAG_USB_ENABLED, 0x02, hi, lo];
                let _ = ccid.ctap_mgmt(CTAP_WRITE_CONFIG, &blob);
            }
            // A raw APDU. The length is its own byte rather than the opcode's:
            // reserving `0x00`–`0x06` would otherwise make every 4-, 5- and
            // 6-byte APDU — case 1 and case 2 — unreachable.
            _ => {
                // `next_frame`, not `chunk`: this is the only target that reaches
                // the dispatcher's 2038-byte chaining buffer and its GET RESPONSE
                // tail, and neither is reachable from a one-byte length.
                let Some((frame, tail)) = next_frame(&data[i..]) else {
                    break;
                };
                i = data.len() - tail.len();
                let raw = frame.as_slice();
                // Skip GENERATE. `Hooks::rsa_search` defaults to `None` ("no
                // accelerator"), so the command falls through to the applet's own
                // single-core prime search, which runs inline and hangs the fuzzer.
                if matches!(Apdu::parse(raw), Ok(p) if p.ins == INS_GENERATE) {
                    continue;
                }
                let _ = status(ccid.handle_apdu(raw, 0));
            }
        }
    }
});
