// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::FidoState;
use crate::consts::{EF_CRED, EF_LARGEBLOB, EF_PIN, EF_RP, RESET_WINDOW_MS};
use crate::seed::{bump_sign_counter, get_sign_counter, load_keydev};
use rsk_crypto::Device;
use rsk_fs::Fs;
use rsk_fs::storage::ram::RamStorage;

struct SeqRng(u64);
impl Rng for SeqRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
    }
}

fn dev() -> Device<'static> {
    Device {
        serial_hash: &[0xAB; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    }
}

#[test]
fn reset_wipes_state_and_regenerates() {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    // Provisioned state: a PIN, a resident credential, an advanced counter,
    // and a non-default large blob.
    fs.put(EF_PIN, &[8, 4, 1, 0, 0]).unwrap();
    fs.put(EF_CRED, &[0u8; 100]).unwrap();
    fs.put(EF_LARGEBLOB, &[0xAB; 50]).unwrap();
    // The trusted-display device PIN: a host reset must clear it too (recovery path).
    fs.put(EF_DEVICE_PIN, &[8, 4, 1, 0, 0]).unwrap();
    // The enterprise-attestation RP list is enterprise policy, and a reset is what
    // hands the key to someone else — it goes with the rest of the FIDO state.
    fs.put(crate::consts::EF_EA_RPIDS, &[0x11u8; 32]).unwrap();
    // An OpenPGP file (EF_PW3 = 0x1083) shares the Fs and must survive a FIDO
    // reset — it sits in the 0x10xx range right next to FIDO's own files.
    fs.put(0x1083, &[0xAB; 34]).unwrap();
    bump_sign_counter(&mut fs).unwrap();
    bump_sign_counter(&mut fs).unwrap();
    assert_eq!(get_sign_counter(&mut fs), 2);
    // A per-credential signature-counter entry must also be wiped by reset.
    crate::seed::set_cred_sign_counter(&mut fs, 0, 7).unwrap();
    assert_eq!(crate::seed::cred_sign_counter(&mut fs, 0), Some(7));

    let mut state = FidoState::new();
    state.paut.permissions = 0x07;

    let n = {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        reset(&mut ctx).unwrap()
    };
    assert_eq!(n, 0);
    // Files wiped, counter reset, seed regenerated and PIN-free again.
    assert!(!fs.has_data(EF_PIN));
    assert!(!fs.has_data(EF_CRED));
    // The device PIN is cleared by the reset (so a forgotten one is recoverable).
    assert!(!fs.has_data(EF_DEVICE_PIN));
    assert!(!fs.has_data(crate::consts::EF_EA_RPIDS));
    // The OpenPGP file is untouched by the FIDO reset.
    assert!(
        fs.has_data(0x1083),
        "OpenPGP files must survive a FIDO reset"
    );
    assert_eq!(get_sign_counter(&mut fs), 0);
    assert_eq!(crate::seed::cred_sign_counter(&mut fs, 0), None);
    assert!(load_keydev(&dev(), &mut fs).is_some());
    // Large blob wiped and re-initialised to the CTAP2.1 default.
    let mut lb = [0u8; 64];
    let ln = fs.read(EF_LARGEBLOB, &mut lb).unwrap();
    assert_eq!(&lb[..ln], &crate::consts::LARGEBLOB_INITIAL);
    // Session state cleared.
    assert_eq!(state.paut.permissions, 0);
}

#[test]
fn factory_reset_keeps_only_attestation() {
    use crate::consts::{EF_ATT_CHAIN, EF_ATT_KEY, EF_KEY_DEV};
    // The org attestation (device identity) survives an on-device factory reset.
    assert!(survives_factory_reset(EF_ATT_KEY.get()));
    assert!(survives_factory_reset(EF_ATT_CHAIN));
    // User secrets and the device seed do not.
    assert!(!survives_factory_reset(EF_PIN));
    assert!(!survives_factory_reset(EF_CRED));
    assert!(!survives_factory_reset(EF_KEY_DEV.get()));
}

struct Fixed(crate::Presence);
impl crate::UserPresence for Fixed {
    fn request(&mut self, _confirm: crate::Confirm<'_>) -> crate::Presence {
        self.0
    }
}

#[test]
fn reset_aborts_without_touch() {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    fs.put(EF_PIN, &[8, 4, 1, 0, 0]).unwrap();
    let mut state = FidoState::new();
    let r = {
        let mut presence = Fixed(crate::Presence::Timeout);
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        reset(&mut ctx)
    };
    assert_eq!(r, Err(CtapError::UserActionTimeout));
    // A declined touch wipes nothing.
    assert!(fs.has_data(EF_PIN));
}

/// §6.6 splits the two ways the gesture can fail: an explicit refusal is
/// OPERATION_DENIED ("the platform SHOULD NOT repeat the command"), a silent timeout
/// is USER_ACTION_TIMEOUT ("the platform MAY repeat"). Either way nothing is wiped.
#[test]
fn reset_decline_is_denied_not_timed_out() {
    for (presence, want) in [
        (crate::Presence::Declined, CtapError::OperationDenied),
        (crate::Presence::Timeout, CtapError::UserActionTimeout),
        (crate::Presence::Cancelled, CtapError::KeepAliveCancel),
    ] {
        let mut fs = Fs::new(RamStorage::new());
        let mut rng = SeqRng(1);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        fs.put(EF_PIN, &[8, 4, 1, 0, 0]).unwrap();
        let mut state = FidoState::new();
        let r = {
            let mut p = Fixed(presence);
            let mut ctx = Ctx {
                presence: &mut p,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 0,
            };
            reset(&mut ctx)
        };
        assert_eq!(r, Err(want));
        assert!(fs.has_data(EF_PIN));
    }
}

/// A presence backend that paints the [`crate::Confirm`] — the trusted display,
/// which CTAP 2.1 §6.6 exempts from the power-up window.
struct Displayed;
impl crate::UserPresence for Displayed {
    fn request(&mut self, _confirm: crate::Confirm<'_>) -> crate::Presence {
        crate::Presence::Confirmed
    }
    fn shows_confirm(&self) -> bool {
        true
    }
}

/// Counts touch requests, so a test can prove the window refuses *before* raising
/// the "Erase everything?" ceremony.
struct CountingPresence {
    calls: usize,
}
impl crate::UserPresence for CountingPresence {
    fn request(&mut self, _confirm: crate::Confirm<'_>) -> crate::Presence {
        self.calls += 1;
        crate::Presence::Confirmed
    }
}

/// Reset a provisioned store at `now_ms`; returns the result and whether `EF_PIN`
/// survived (a refused reset must wipe nothing).
fn reset_at(
    now_ms: u64,
    warm_boot: bool,
    presence: &mut dyn crate::UserPresence,
) -> (CtapResult, bool) {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    fs.put(EF_PIN, &[8, 4, 1, 0, 0]).unwrap();
    let mut state = FidoState::new();
    state.warm_boot = warm_boot;
    let r = {
        let mut ctx = Ctx {
            presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms,
        };
        reset(&mut ctx)
    };
    (r, fs.has_data(EF_PIN))
}

#[test]
fn reset_window_is_measured_from_power_up() {
    // CTAP 2.1 §6.6: honored just inside the window, refused past it.
    assert_eq!(
        reset_at(RESET_WINDOW_MS - 1, false, &mut crate::AlwaysConfirm).0,
        Ok(0)
    );
    let (r, kept) = reset_at(RESET_WINDOW_MS + 1, false, &mut crate::AlwaysConfirm);
    assert_eq!(r, Err(CtapError::NotAllowed));
    assert!(kept, "a late reset must wipe nothing");
}

#[test]
fn a_warm_boot_closes_the_reset_window() {
    // `sys_reset` is host-requestable ungated, so the restarted uptime must not
    // hand a silent host a fresh window — not even at now_ms = 0.
    let (r, kept) = reset_at(0, true, &mut crate::AlwaysConfirm);
    assert_eq!(r, Err(CtapError::NotAllowed));
    assert!(kept);
}

#[test]
fn a_display_backend_is_exempt_from_the_reset_window() {
    // §6.6 conditions the window on an authenticator with no display: this one
    // paints "Erase everything?", so the touch already names what it approves.
    assert_eq!(
        reset_at(RESET_WINDOW_MS * 100, true, &mut Displayed).0,
        Ok(0)
    );
}

#[test]
fn a_late_reset_is_refused_before_the_touch() {
    let mut p = CountingPresence { calls: 0 };
    let (r, kept) = reset_at(RESET_WINDOW_MS + 1, false, &mut p);
    assert_eq!(r, Err(CtapError::NotAllowed));
    assert_eq!(
        p.calls, 0,
        "an out-of-window host must not raise the ceremony"
    );
    assert!(kept);
}

#[test]
fn reset_wipes_false_absent_credential_without_looping() {
    // A torn-migration false-absent resident credential: live in the backend but
    // with a clear present bit (build the store, then wrap it WITHOUT a scan). The
    // pre-fix reset removed FIDO files with the present-cache-gated `delete`, which
    // skipped such a key while `for_each_key` (reading the backend directly) kept
    // re-yielding it — an infinite wipe loop that hung the device. `force_delete`
    // removes unconditionally, so the wipe terminates. Reaching the asserts below
    // (rather than hanging) IS the regression check.
    let cred = EF_CRED + 3;
    let ram = {
        let mut seed_fs = Fs::new(RamStorage::new());
        let mut rng = SeqRng(1);
        ensure_seed(&dev(), &mut seed_fs, &mut rng).unwrap();
        seed_fs.put(cred, &[0u8; 100]).unwrap();
        seed_fs.into_storage()
    };
    let mut fs = Fs::new(ram); // no scan → every file, incl. the cred, is false-absent
    let mut rng = SeqRng(2);
    let mut state = FidoState::new();
    {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        reset(&mut ctx).unwrap();
    }
    assert!(
        !fs.has_data(cred),
        "reset must wipe even a false-absent credential"
    );
    // And it still fully re-provisions afterwards.
    assert!(load_keydev(&dev(), &mut fs).is_some());
}

/// Yields one fid many times per pass, the way the log-structured backend does for
/// a file with superseded versions, and counts how often the sweep asks to remove
/// it. `remove` succeeds every time — the real store's does, on a present key and
/// on an absent one alike — so a sweep that failed to de-dup would still return
/// `Ok` here. The count is what pins the contract.
struct DuplicateVersions {
    live: bool,
    removes: u32,
}

impl rsk_fs::Storage for DuplicateVersions {
    fn read(&mut self, _fid: u16, _buf: &mut [u8]) -> Option<usize> {
        None
    }
    fn write(&mut self, _fid: u16, _data: &[u8]) -> rsk_sdk::error::Result<()> {
        Ok(())
    }
    fn remove(&mut self, _fid: u16) -> rsk_sdk::error::Result<()> {
        self.removes += 1;
        self.live = false;
        Ok(())
    }
    fn size(&mut self, _fid: u16) -> Option<usize> {
        None
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        if self.live {
            for _ in 0..64 {
                f(EF_CRED);
            }
        }
        true
    }
}

/// `Fs::for_each_key` documents that one fid can be yielded more than once (one
/// stored item per superseded version, until reclaim) and that a batching caller
/// must de-dup. Without that, the 64-slot batch fills with copies of a single fid
/// and the sweep asks to delete it 64 times.
#[test]
fn reset_sweep_de_dupes_stored_versions() {
    let mut fs = Fs::new(DuplicateVersions {
        live: true,
        removes: 0,
    });
    let mut rng = SeqRng(1);
    let mut state = FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
    };
    assert_eq!(sweep(&mut ctx, is_fido_fid), Ok(()));
    assert_eq!(
        fs.into_storage().removes,
        1,
        "64 stored versions of one fid must cost one delete, not 64"
    );
}

struct ReYielding;

impl rsk_fs::Storage for ReYielding {
    fn read(&mut self, _fid: u16, _buf: &mut [u8]) -> Option<usize> {
        None
    }
    fn write(&mut self, _fid: u16, _data: &[u8]) -> rsk_sdk::error::Result<()> {
        Ok(())
    }
    fn remove(&mut self, _fid: u16) -> rsk_sdk::error::Result<()> {
        Ok(())
    }
    fn size(&mut self, _fid: u16) -> Option<usize> {
        None
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        f(EF_CRED);
        true
    }
}

#[test]
fn reset_sweep_fails_when_storage_does_not_converge() {
    let mut fs = Fs::new(ReYielding);
    let mut rng = SeqRng(1);
    let mut state = FidoState::new();
    let mut presence = crate::AlwaysConfirm;
    let mut ctx = Ctx {
        presence: &mut presence,
        dev: dev(),
        fs: &mut fs,
        rng: &mut rng,
        state: &mut state,
        now_ms: 0,
    };
    assert_eq!(sweep(&mut ctx, is_fido_fid), Err(CtapError::Other));
}

/// `RESET_MAX_DELETES` is written as `4 * MAX_RESIDENT_CREDENTIALS + 14`, and the
/// 14 is a hand-count of `is_fido_fid`'s fixed arm. Count the predicate instead of
/// trusting it: add a record there and the bound silently stops covering the
/// applet, whose failure mode is a reset that gives up on a FULL device — the one
/// place a stale constant costs the most.
#[test]
fn reset_bound_is_exactly_the_fid_space() {
    let live = (0..=u16::MAX).filter(|&fid| is_fido_fid(fid)).count();
    assert_eq!(
        live as u32, RESET_MAX_DELETES,
        "the bound must equal the number of fids the sweep can legitimately delete"
    );
}

/// Audit run-36 class sweep: `is_fido_gate_fid` is the set `reset` defers to its
/// second phase *and* the set the device-wide `Fs::factory_wipe` inherits, so a
/// record that gates the applet but is missing from it gets deleted ahead of the
/// secrets it protects.
///
/// `EF_BACKUP_SEALED` is the one that was missing. It is never re-provisioned — its
/// *absence* is the permissive state, like OATH's access code — and what it gates is
/// the master seed: the one-time `BACKUP_EXPORT` window and, on a display build, the
/// on-device recovery-phrase reveal. It sat in the same phase as `EF_KEY_DEV`, so a
/// torn wipe could take the marker first and re-open a window the owner had closed
/// over a seed that was still live.
///
/// `EF_PAUTHTOKEN` is the record that was in the set without meeting its rule: a
/// grant's absence is the RESTRICTIVE state, so deferring it produced a tear of the
/// opposite kind — a live `pcmr` grant over a deleted PIN.
#[test]
fn the_gate_set_defers_every_record_whose_absence_is_permissive() {
    use crate::consts::{
        EF_ALWAYS_UV, EF_BACKUP_SEALED, EF_DEVICE_PIN, EF_EA_RPIDS, EF_KEY_DEV, EF_MINPINLEN,
        EF_PAUTHTOKEN,
    };
    for fid in [
        EF_PIN,
        EF_DEVICE_PIN,
        EF_ALWAYS_UV,
        EF_MINPINLEN,
        EF_BACKUP_SEALED,
    ] {
        assert!(is_fido_gate_fid(fid), "{fid:#06x} gates the applet");
        assert!(
            is_fido_fid(fid),
            "{fid:#06x} is deferred but not FIDO-owned, so no sweep would take it"
        );
    }
    // The secrets themselves must stay in phase 1 — deferring the seed would invert
    // the rule and delete the gate first — and so must a grant, whose absence denies
    // rather than permits.
    for fid in [
        EF_KEY_DEV.get(),
        EF_CRED,
        EF_LARGEBLOB,
        EF_PAUTHTOKEN.get(),
        EF_EA_RPIDS,
    ] {
        assert!(
            !is_fido_gate_fid(fid),
            "{fid:#06x} is a secret or a grant, not a gate"
        );
        assert!(
            is_fido_fid(fid),
            "{fid:#06x} is not deferred, so the sweep must own it"
        );
    }
}

/// `Storage` that enumerates in INSERTION order — the flash ring's oldest-first
/// yield, which `RamStorage`'s `HashMap` does not model — and whose `remove` starts
/// failing after `budget` deletions, standing in for a power cut mid-wipe. Mirrors
/// `rsk_piv`'s `TearAfter`; ring order is the whole point of a two-phase sweep, so a
/// `HashMap`-backed harness cannot test one.
#[derive(Clone)]
struct TearAfter {
    items: Vec<(u16, Vec<u8>)>,
    budget: usize,
}

impl rsk_fs::Storage for TearAfter {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        let v = &self.items.iter().find(|(k, _)| *k == fid)?.1;
        let n = v.len().min(buf.len());
        buf[..n].copy_from_slice(&v[..n]);
        Some(v.len())
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
        match self.items.iter_mut().find(|(k, _)| *k == fid) {
            Some(e) => e.1 = data.to_vec(),
            None => self.items.push((fid, data.to_vec())),
        }
        Ok(())
    }
    fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
        if self.budget == 0 {
            return Err(rsk_sdk::error::Error::MemoryFatal);
        }
        self.budget -= 1;
        self.items.retain(|(k, _)| *k != fid);
        Ok(())
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.items
            .iter()
            .find(|(k, _)| *k == fid)
            .map(|(_, v)| v.len())
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        for (k, _) in &self.items {
            f(*k);
        }
        true
    }
}

/// The ordering `is_fido_gate_fid` buys, asserted on `reset` itself — the phase of
/// the run-35 class fix that shipped with no test at all. For every tear point, a
/// surviving *owner's* seed implies a surviving backup-sealed marker: otherwise the
/// next `BACKUP_EXPORT` hands out a master seed the owner had already sealed away.
///
/// The marker is written before the seed here, which is the order that matters and
/// is reachable in the field: `sequential-storage` re-appends a live item at the ring
/// head on page GC, and `migrate_keydev_pin` re-seals `EF_KEY_DEV` on a PIN verify —
/// either moves the seed *behind* a marker written when the owner first backed up.
#[test]
fn a_torn_reset_never_unseals_a_surviving_seed() {
    use crate::consts::{EF_BACKUP_SEALED, EF_KEY_DEV};

    let mut owner_seed = [0u8; 128];
    let owner_n;
    let base = {
        let mut fs = Fs::new(TearAfter {
            items: Vec::new(),
            budget: usize::MAX,
        });
        fs.scan();
        // Marker first, so it is the oldest entry in the ring.
        fs.put(EF_BACKUP_SEALED, &[1]).unwrap();
        let mut rng = SeqRng(9);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        fs.put(EF_CRED, &[0u8; 100]).unwrap();
        owner_n = fs.read(EF_KEY_DEV.get(), &mut owner_seed).unwrap();
        fs.into_storage()
    };
    let live = base.items.len();

    let mut saw_survivor = false;
    for budget in 0..live {
        let mut fs = Fs::new(TearAfter {
            budget,
            ..base.clone()
        });
        fs.scan();
        let mut rng = SeqRng(3);
        let mut state = FidoState::new();
        {
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 0,
            };
            let _ = reset(&mut ctx);
        }
        // "Live" is not "survived": a completed reset re-provisions a FRESH seed, and
        // sealing that one would be wrong. Only the owner's own record counts.
        let mut now = [0u8; 128];
        let n = fs.read(EF_KEY_DEV.get(), &mut now).unwrap_or(0);
        if (&now[..n], n) != (&owner_seed[..owner_n], owner_n) {
            continue;
        }
        saw_survivor = true;
        assert!(
            fs.has_data(EF_BACKUP_SEALED),
            "tear at {budget} left the owner's seed live with the export window re-opened"
        );
    }
    assert!(
        saw_survivor,
        "vacuous: no tear point left the owner's seed behind, so nothing was proved"
    );
}

/// One discoverable credential, written by the code that writes them in the field
/// (`credential_store`, which also creates the `EF_RP` entry). Returns the rpIdHash.
fn provision_passkey<S: rsk_fs::Storage>(fs: &mut Fs<S>, seed: &[u8; 32]) -> [u8; 32] {
    use crate::consts::{ALG_ES256, CURVE_P256};
    use crate::credential::{CredExt, CredInput, credential_create, credential_store};
    use rsk_crypto::sha256;

    let rp_id_hash = sha256(b"example.com");
    let input = CredInput {
        rp_id: "example.com",
        user_id: &[0xDE, 0xAD, 0xBE, 0xEF],
        user_name: "alice",
        user_display_name: "Alice Smith",
        use_sign_count: true,
        rk: true,
        created_ms: 1,
        alg: ALG_ES256,
        curve: CURVE_P256 as i64,
        ext: CredExt::default(),
    };
    let mut cred_id = [0u8; 512];
    let n =
        credential_create(seed, &dev(), &input, &rp_id_hash, &[0x11; 12], &mut cred_id).unwrap();
    credential_store(
        seed,
        &dev(),
        fs,
        &cred_id[..n],
        &rp_id_hash,
        "example.com",
        input.user_id,
        &[],
    )
    .unwrap();
    rp_id_hash
}

/// The premise the wipe order rests on. `credential_load` is the chokepoint every
/// reader of a stored record goes through — `getAssertion`, credMgmt's enumerate
/// and `credential_store`'s own dedup — and its key is an HMAC chain over the seed,
/// so a regenerated seed makes a record a torn wipe left behind unopenable.
#[test]
fn a_surviving_credential_is_dead_once_the_seed_is_replaced() {
    use crate::consts::EF_KEY_DEV;
    use crate::credential::{cred_record_box, credential_load};

    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(5);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let owner = load_keydev(&dev(), &mut fs).unwrap();
    let rp_id_hash = provision_passkey(&mut fs, &owner);

    let mut rec = [0u8; 1024];
    let n = fs.read(EF_CRED, &mut rec).unwrap();
    let mut scratch = [0u8; 1024];
    assert!(
        credential_load(
            &owner,
            cred_record_box(&rec[..n]),
            &rp_id_hash,
            &mut scratch
        )
        .is_some(),
        "the record must open under the seed that wrote it, or this proves nothing"
    );

    // Exactly the state the lead delete guarantees: seed gone, record left behind.
    fs.force_delete(EF_KEY_DEV.get()).unwrap();
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let fresh = load_keydev(&dev(), &mut fs).unwrap();
    assert_ne!(
        fresh, owner,
        "ensure_seed must mint a new seed, not reuse it"
    );
    assert!(
        credential_load(
            &fresh,
            cred_record_box(&rec[..n]),
            &rp_id_hash,
            &mut scratch
        )
        .is_none(),
        "a stranded credential must not open under the regenerated seed"
    );
}

/// A provisioned store — seed, one discoverable credential, a PIN — with the seed
/// moved to `seed_fid` and to the ring TAIL. That order is the field-reachable one
/// the sibling test above argues for: page GC re-appends a live item at the head,
/// and `migrate_keydev_pin` re-seals the seed on a PIN verify. Returns the store
/// and the owner's seed record, which is what tells "survived" from "re-minted".
fn provisioned_with_seed_last(seed_fid: u16) -> (TearAfter, Vec<u8>) {
    use crate::consts::EF_KEY_DEV;

    let mut fs = Fs::new(TearAfter {
        items: Vec::new(),
        budget: usize::MAX,
    });
    fs.scan();
    let mut rng = SeqRng(11);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let seed = load_keydev(&dev(), &mut fs).unwrap();
    provision_passkey(&mut fs, &seed);
    fs.put(EF_PIN, &[8, 4, 1, 0, 0]).unwrap();
    let mut st = fs.into_storage();
    let at = st
        .items
        .iter()
        .position(|(k, _)| *k == EF_KEY_DEV.get())
        .unwrap();
    let (_, blob) = st.items.remove(at);
    let owner_seed = blob.clone();
    st.items.push((seed_fid, blob));
    (st, owner_seed)
}

/// The fids `base` still holds, in ring order.
fn fids(store: &TearAfter) -> Vec<u16> {
    store.items.iter().map(|(k, _)| *k).collect()
}

/// The owner's seed record, if `seed_fid` still holds exactly it. A completed wipe
/// re-mints a FRESH seed, and that one opens nothing, so only the owner's own bytes
/// mean the credentials are still readable.
fn owner_seed_survived<S: rsk_fs::Storage>(fs: &mut Fs<S>, seed_fid: u16, owner: &[u8]) -> bool {
    let mut now = [0u8; 128];
    let n = fs.read(seed_fid, &mut now).unwrap_or(0).min(now.len());
    now[..n] == *owner
}

/// The wipe's own promise — "the seed leads, so a surviving credential record is
/// cryptographically dead" — asserted instead of asserted-in-a-comment. Nothing
/// used to order `EF_KEY_DEV` ahead of the batch: `for_each_key` yields in ring
/// order, so a cut between the `EF_RP` delete and the `EF_CRED` one left a live
/// discoverable passkey with no rp entry — one `enumerateRPs` and the display's
/// Passkeys view cannot list, `enumerateCredentials` (per-rp) cannot reach, and
/// `getAssertion` signs with happily (TLA+ `NoUnmanageableCredential`, depth 13).
/// The strand itself still happens; what the order buys is that the survivor no
/// longer opens.
fn a_torn_reset_keeps_the_seed_ahead_of_the_wipe(seed_fid: u16) {
    let (base, owner_seed) = provisioned_with_seed_last(seed_fid);
    let live = base.items.len();

    for budget in 0..live {
        let mut fs = Fs::new(TearAfter {
            budget,
            ..base.clone()
        });
        fs.scan();
        let mut rng = SeqRng(3);
        let mut state = FidoState::new();
        {
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 0,
            };
            let _ = reset(&mut ctx);
        }
        if !owner_seed_survived(&mut fs, seed_fid, &owner_seed) {
            continue;
        }
        assert_eq!(
            fids(&fs.into_storage()),
            fids(&base),
            "tear at {budget} ({seed_fid:#06x}) deleted a record while the owner's seed \
             was still readable — a survivor of that prefix still opens"
        );
    }

    // The loop's subject has to be a wipe that really wipes, or every prefix would
    // pass by doing nothing at all.
    let mut fs = Fs::new(TearAfter {
        budget: usize::MAX,
        ..base.clone()
    });
    fs.scan();
    let mut rng = SeqRng(3);
    let mut state = FidoState::new();
    {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        reset(&mut ctx).unwrap();
    }
    assert!(!fs.has_data(EF_CRED), "the control run kept a credential");
    assert!(
        !owner_seed_survived(&mut fs, seed_fid, &owner_seed),
        "the control run kept the owner's seed"
    );
}

#[test]
fn a_torn_reset_never_starts_while_the_seed_is_still_readable() {
    use crate::consts::{EF_KEY_DEV, EF_KEY_DEV_ENC};
    // Both shapes the seed takes on flash. `EF_KEY_DEV_ENC` is the soft lock's copy
    // and is what a locked device's credentials still hang on, so a wipe that leads
    // with `EF_KEY_DEV` alone would strand them there.
    a_torn_reset_keeps_the_seed_ahead_of_the_wipe(EF_KEY_DEV.get());
    a_torn_reset_keeps_the_seed_ahead_of_the_wipe(EF_KEY_DEV_ENC.get());
}

/// The device-wide `Fs::factory_wipe` — the Management RESET and the trusted
/// display's factory reset — bypasses [`reset`] entirely, so the rule has to reach
/// it through an exported predicate. Same shape audit run-36 settled on for OATH's
/// access code (`rsk_oath::tests::the_exported_lock_predicate_protects_the_device_
/// wide_wipe`): assert the predicate really buys the ordering on that path.
#[test]
fn the_exported_seed_predicate_protects_the_device_wide_wipe() {
    use crate::consts::EF_KEY_DEV;

    let (base, owner_seed) = provisioned_with_seed_last(EF_KEY_DEV.get());
    let live = base.items.len();

    for budget in 0..live {
        let mut fs = Fs::new(TearAfter {
            budget,
            ..base.clone()
        });
        fs.scan();
        let _ = fs.factory_wipe(survives_factory_reset, is_fido_seed_fid, is_fido_gate_fid);
        if !owner_seed_survived(&mut fs, EF_KEY_DEV.get(), &owner_seed) {
            continue;
        }
        assert_eq!(
            fids(&fs.into_storage()),
            fids(&base),
            "budget {budget}: the device-wide wipe deleted a record while the seed that \
             opens it was still on flash"
        );
    }

    let mut fs = Fs::new(TearAfter {
        budget: usize::MAX,
        ..base.clone()
    });
    fs.scan();
    fs.factory_wipe(survives_factory_reset, is_fido_seed_fid, is_fido_gate_fid)
        .unwrap();
    assert!(!fs.has_data(EF_CRED), "the control run kept a credential");
    assert!(
        !fs.has_data(EF_KEY_DEV.get()),
        "the control run kept the seed"
    );
}

/// `FIDO_SEED_FIDS` is the lead phase of both wipes, so a record missing from it
/// gets deleted alongside the credentials it protects, and one wrongly IN it would
/// be taken before the gates it should follow.
#[test]
fn the_seed_set_is_exactly_the_two_records_a_credential_hangs_on() {
    use crate::consts::{EF_KEY_DEV, EF_KEY_DEV_ENC};
    assert_eq!(FIDO_SEED_FIDS, [EF_KEY_DEV.get(), EF_KEY_DEV_ENC.get()]);
    for fid in FIDO_SEED_FIDS {
        assert!(is_fido_seed_fid(fid));
        assert!(is_fido_fid(fid), "the sweep must own what the lead deletes");
        assert!(!is_fido_gate_fid(fid), "a secret is not a gate");
        assert!(
            !survives_factory_reset(fid),
            "the seed is not device identity"
        );
    }
    for fid in [EF_CRED, EF_RP, EF_PIN, EF_LARGEBLOB] {
        assert!(!is_fido_seed_fid(fid), "{fid:#06x} does not lead the wipe");
    }
}

/// A provisioned store carrying the two records E77's torn state is made of, in the
/// order the field writes them: the PIN is established first, and the `pcmr` grant
/// is only minted on a later getPinToken, so the PIN is the older ring entry and a
/// single-phase sweep reaches it first.
fn provisioned_with_a_grant() -> TearAfter {
    let mut fs = Fs::new(TearAfter {
        items: Vec::new(),
        budget: usize::MAX,
    });
    fs.scan();
    let mut rng = SeqRng(17);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let seed = load_keydev(&dev(), &mut fs).unwrap();
    provision_passkey(&mut fs, &seed);
    let mut pin_file = [0u8; crate::clientpin::PIN_FILE_LEN];
    pin_file[0] = 8; // retries
    pin_file[1] = 4; // min length
    pin_file[2] = 1;
    fs.put(EF_PIN, &pin_file).unwrap();
    crate::seed::ensure_ppuat(&dev(), &mut fs, &mut rng).unwrap();
    fs.into_storage()
}

/// The grant in `EF_PAUTHTOKEN` is a *permission*, so unlike every other record the
/// wipe defers, its absence is the RESTRICTIVE state. Batched with `EF_PIN` it made
/// both wipes producers of the torn state E77 closes at the consumer: a cut between
/// the two leaves a live `pcmr` grant with no PIN behind it, and the holder goes on
/// reading the credential directory of everything registered afterwards. `credmgmt`
/// refusing it is one `if` on one build; no prefix of a wipe should be able to
/// produce the state at all.
fn no_wipe_prefix_leaves_a_grant_without_its_pin(
    mut wipe: impl FnMut(&mut Fs<TearAfter>) -> bool,
    what: &str,
) {
    use crate::consts::{EF_KEY_DEV, EF_PAUTHTOKEN};

    let base = provisioned_with_a_grant();
    let live = base.items.len();

    let mut saw_grant = false;
    // `reset`'s lead phase force-deletes both seed shapes whether or not they are
    // there, and the harness charges budget for an absent one, so the tear points
    // run past the number of items the store holds.
    for budget in 0..live + FIDO_SEED_FIDS.len() {
        let mut fs = Fs::new(TearAfter {
            budget,
            ..base.clone()
        });
        fs.scan();
        wipe(&mut fs);
        if !fs.has_data(EF_PAUTHTOKEN.get()) {
            continue;
        }
        // Only a prefix that got as far as the lead delete counts as a tear point:
        // budget 0 leaves the store untouched and would satisfy the guard below
        // without proving the loop ever reached a partial wipe.
        saw_grant |= !fs.has_data(EF_KEY_DEV.get());
        assert!(
            fs.has_data(EF_PIN),
            "{what}: tear at {budget} left a credMgmt grant standing over a deleted PIN"
        );
    }
    assert!(
        saw_grant,
        "vacuous: no partial wipe left the grant behind, so nothing was proved"
    );

    // The subject has to be a wipe that really wipes — and one that reaches its LAST
    // phase, or the loop's property holds for the trivial reason that no PIN is ever
    // deleted.
    let mut fs = Fs::new(TearAfter {
        budget: usize::MAX,
        ..base.clone()
    });
    fs.scan();
    assert!(wipe(&mut fs), "the control run did not report success");
    assert!(!fs.has_data(EF_CRED), "the control run kept a credential");
    assert!(
        !fs.has_data(EF_PAUTHTOKEN.get()),
        "the control run kept the grant"
    );
    assert!(!fs.has_data(EF_PIN), "the control run never reached a gate");
}

#[test]
fn a_torn_reset_never_leaves_a_grant_without_its_pin() {
    no_wipe_prefix_leaves_a_grant_without_its_pin(
        |fs| {
            let mut rng = SeqRng(3);
            let mut state = FidoState::new();
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 0,
            };
            reset(&mut ctx).is_ok()
        },
        "authenticatorReset",
    );
}

#[test]
fn a_torn_device_wide_wipe_never_leaves_a_grant_without_its_pin() {
    no_wipe_prefix_leaves_a_grant_without_its_pin(
        |fs| {
            fs.factory_wipe(survives_factory_reset, is_fido_seed_fid, is_fido_gate_fid)
                .is_ok()
        },
        "factory_wipe",
    );
}

/// The live session dies BEFORE the first flash write of the wipe: `reset` calls
/// `ctx.state.reset()` ahead of the seed deletion, so a cut at ANY point of the
/// flash work leaves no RAM copy of a seed nothing stores. Asserted for every
/// tear budget including 0 — the E76 regression moved the state reset behind the
/// flash work, where the earliest tear returns with the session still live, and
/// co-refutation measured that nothing at the code level noticed: the torn-reset
/// harness tears the flash but never asked when the SESSION died.
#[test]
fn a_torn_reset_never_leaves_the_session_running_on_a_wiped_seed() {
    let base = {
        let mut fs = Fs::new(TearAfter {
            items: Vec::new(),
            budget: usize::MAX,
        });
        fs.scan();
        let mut rng = SeqRng(11);
        ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
        fs.put(EF_CRED, &[0u8; 100]).unwrap();
        fs.into_storage()
    };
    let live = base.items.len();

    for budget in 0..=live {
        let mut fs = Fs::new(TearAfter {
            budget,
            ..base.clone()
        });
        fs.scan();
        let mut rng = SeqRng(3);
        let mut state = FidoState::new();
        // The RAM copy the wipe must not leave behind, planted the way
        // `Ctx::load_keydev` caches it.
        state.keydev_dec = Some([0x5A; 32]);
        {
            let mut presence = crate::AlwaysConfirm;
            let mut ctx = Ctx {
                presence: &mut presence,
                dev: dev(),
                fs: &mut fs,
                rng: &mut rng,
                state: &mut state,
                now_ms: 0,
            };
            let _ = reset(&mut ctx);
        }
        assert!(
            state.keydev_dec.is_none(),
            "tear at {budget} returned with the session still holding the seed \
             the wipe was destroying"
        );
    }
}

#[test]
fn a_reset_sweeps_more_secrets_than_one_batch_holds() {
    // `sweep` deletes in 64-key batches, and nothing drove it past the first
    // one: the bound that keeps `keys[n]` in range was untested, and the
    // mutation that breaks it is an out-of-bounds index, not a wrong answer.
    // PIV has this test for its own reset (`reset_sweeps_more_files_than_one_batch`);
    // FIDO's sweep is the same shape and had none — sweep by class, not by site.
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(3);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    for i in 0..80u16 {
        fs.put(EF_CRED + i, &[0xC0; 8]).unwrap();
    }
    let mut state = FidoState::new();
    {
        let mut presence = crate::AlwaysConfirm;
        let mut ctx = Ctx {
            presence: &mut presence,
            dev: dev(),
            fs: &mut fs,
            rng: &mut rng,
            state: &mut state,
            now_ms: 0,
        };
        reset(&mut ctx).unwrap();
    }
    for i in 0..80u16 {
        assert!(
            !fs.has_data(EF_CRED + i),
            "0x{:04X} survived a reset that spans two batches",
            EF_CRED + i
        );
    }
}
