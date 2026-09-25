// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use rsk_fs::storage::faults::{Cut, CutMedium, RemoveStuck};
use rsk_fs::storage::ram::RamStorage;

struct CountRng(u8);
impl Rng for CountRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }
}

fn dev() -> Device<'static> {
    Device {
        serial_hash: &[0x11; 32],
        serial_id: &[1, 2, 3, 4, 5, 6, 7, 8],
        otp_key: None,
    }
}

fn seeded() -> Fs<RamStorage> {
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    fs
}

/// Every fid `scan_files` seeds, DERIVED by running it over an empty medium
/// rather than named. A watch list narrower than the function under test is what
/// let `EF_KDF` and `EF_SIG_COUNT` be re-seeded beside a live key unnoticed.
fn records_scan_files_seeds() -> Vec<u16> {
    let mut fs = seeded();
    let mut fids: Vec<u16> = Vec::new();
    fs.for_each_key(&mut |fid| {
        if !fids.contains(&fid) {
            fids.push(fid);
        }
    });
    fids.sort_unstable();
    fids
}

fn apdu() -> Apdu<'static> {
    Apdu {
        cla: 0x00,
        ins: INS_TERMINATE_DF,
        p1: 0x00,
        p2: 0x00,
        nc: 0,
        ne: 0,
        data: &[],
        extended: false,
    }
}

#[test]
fn openpgp_fids_classified_disjoint_from_fido() {
    // OpenPGP internal EFs + a few DO tags.
    for fid in [
        EF_PW1,
        EF_PW3,
        EF_PK_SIG.get(),
        EF_DEK,
        EF_LOGIN_DATA,
        EF_FP,
        EF_SEX,
    ] {
        assert!(is_openpgp_fid(fid), "{fid:#06x} should be OpenPGP");
    }
    // FIDO FIDs (see rsk-fido `is_fido_fid`) must NOT be classified as OpenPGP.
    for fid in [
        0x1080u16, 0x1090, 0x1091, 0x1100, 0x1101, 0xC000, 0xCC00, 0xCF00, 0xD000,
    ] {
        assert!(!is_openpgp_fid(fid), "{fid:#06x} is FIDO, not OpenPGP");
    }
}

/// The device-wide `Fs::factory_wipe` defers each applet's gate records to a second
/// phase, and it can only defer what the applet exports. The set has to cover every
/// record `scan_files` re-seeds — DERIVED from that function here, because a list
/// narrower than it is what let `EF_KDF` be re-seeded to KDF-none beside a live
/// private key — and every member has to be a fid this applet actually owns: a gate
/// arm naming someone else's fid would defer a record another applet's phase-1
/// sweep already accounts for (audit run-36).
#[test]
fn every_record_scan_files_reseeds_is_swept_last_and_openpgp_owned() {
    for fid in records_scan_files_seeds() {
        // The two DEK copies are the exception that carries the rule: they ARE the
        // secret, so they lead the wipe, and `scan_files` re-mints them only with
        // both PW verifiers absent — a state no phase-1 abort can leave behind.
        if fid == EF_DEK_PW1.get() || fid == EF_DEK_PW3.get() {
            continue;
        }
        // The attestation key, its public-key DO and FC are secrets like the DEK copies
        // and go first with them; any a torn sweep leaves is minted again by an ATTEST.
        if fid == EF_PK_ATT.get() || fid == EF_PB_ATT || fid == EF_ATT_CERT {
            continue;
        }
        assert!(
            is_openpgp_gate_fid(fid),
            "{fid:#06x} is re-seeded by scan_files yet swept in phase 1"
        );
        assert!(
            is_openpgp_fid(fid),
            "{fid:#06x} is deferred but not OpenPGP-owned"
        );
    }
    // The one PW verifier `scan_files` never seeds — the reset code stays deactivated
    // until PUT DATA 0xD3 — so the derivation above cannot see it.
    assert!(
        is_openpgp_gate_fid(EF_RC),
        "the RC verifier must be deferred"
    );
    // FIDO's EF_PIN (0x1080) interleaves with OpenPGP PW1 (0x1081) in the 0x10xx
    // region; the deferred set must not reach across into it.
    assert!(!is_openpgp_gate_fid(0x1080));
    // Secrets, not gates: deferring these would invert the rule.
    for fid in [EF_PK_SIG.get(), EF_DEK, EF_LOGIN_DATA] {
        assert!(
            !is_openpgp_gate_fid(fid),
            "{fid:#06x} is a secret, not a gate"
        );
    }
}

#[test]
fn terminate_wipes_openpgp_and_reseeds() {
    let mut fs = seeded();
    // User data that a terminate must erase.
    fs.put(EF_PK_SIG.get(), &[0xAB; 40]).unwrap();
    fs.put(EF_LOGIN_DATA, b"alice").unwrap();
    // A FIDO file sharing the Fs must SURVIVE (0x1080 = FIDO EF_PIN).
    fs.put(0x1080, &[8, 4, 1, 0, 0]).unwrap();
    // PW3 verified → terminate permitted.
    assert_eq!(
        terminate_df(&dev(), &mut fs, &mut CountRng(0), true, &apdu()),
        Sw::OK
    );

    assert!(!fs.has_data(EF_PK_SIG.get()), "imported key must be wiped");
    assert!(!fs.has_data(EF_LOGIN_DATA), "login data must be wiped");
    assert!(
        fs.has_data(0x1080),
        "FIDO file must survive an OpenPGP terminate"
    );
    // Defaults re-seeded.
    assert!(fs.has_data(EF_DEK_PW1.get()));
    let mut pw = [0u8; 7];
    fs.read(EF_PW_PRIV, &mut pw);
    assert_eq!(pw[0], 0x01);
}

#[test]
fn terminate_refused_without_pw3_while_unblocked() {
    let mut fs = seeded();
    // Default PW3 retry counter is 3 (> 0) and PW3 not verified → refused.
    assert_eq!(
        terminate_df(&dev(), &mut fs, &mut CountRng(0), false, &apdu()),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
    assert!(fs.has_data(EF_DEK_PW1.get()), "nothing wiped on refusal");
}

#[test]
fn terminate_allowed_without_pw3_when_admin_blocked() {
    let mut fs = seeded();
    // Drive the PW3 retry counter to 0 (admin PIN blocked).
    let mut pw = [0u8; 7];
    let n = fs.read(EF_PW_PRIV, &mut pw).unwrap();
    pw[6] = 0;
    fs.put(EF_PW_PRIV, &pw[..n]).unwrap();
    assert_eq!(
        terminate_df(&dev(), &mut fs, &mut CountRng(0), false, &apdu()),
        Sw::OK
    );
}

#[test]
fn terminate_allowed_when_the_admin_verifier_is_unusable() {
    let mut fs = seeded();
    // A card carrying the pre-fix zero-length PW3 verifier: check_pin refuses it
    // before the retry decrement, so its counter never reaches 0 and the applet
    // would otherwise have no way back.
    let mut rec = [0u8; 64];
    let n = fs.read(EF_PW3, &mut rec).unwrap();
    rec[0] = 0;
    fs.put(EF_PW3, &rec[..n]).unwrap();
    assert_eq!(
        terminate_df(&dev(), &mut fs, &mut CountRng(0), false, &apdu()),
        Sw::OK
    );
}

#[test]
fn terminate_rejects_p1p2_and_data() {
    let mut fs = seeded();
    let mut bad = apdu();
    bad.p1 = 0x01;
    assert_eq!(
        terminate_df(&dev(), &mut fs, &mut CountRng(0), true, &bad),
        Sw::INCORRECT_P1P2
    );
    let data = [0u8; 2];
    let withdata = Apdu {
        nc: 2,
        data: &data,
        ..apdu()
    };
    assert_eq!(
        terminate_df(&dev(), &mut fs, &mut CountRng(0), true, &withdata),
        Sw::WRONG_LENGTH
    );
}

/// TERMINATE DF's sweep is the third of the four the delete-caller audit covers,
/// and the metadata half reaches it the same way: EF_META is ONE blob shared by
/// every applet, so a fault reading it fails an OpenPGP removal over a fid that
/// carries no record of its own. Folding that into `Fs::force_delete`'s single
/// answer let the sweep `?` it out of the loop after the first file — and
/// `terminate_df` skipped the re-seed on a failed wipe (it re-seeds unconditionally
/// since 0x098A), so the card was left holding the private-key records the command
/// says it destroyed.
///
/// Returns the answer and the imported secrets still live ON THE MEDIUM. Those are
/// the fids `scan_files` never puts back, so they read the same on both arms; the
/// present cache would not, since a delete marks absent whether or not the backend
/// `remove` ran.
fn terminate_with_ef_meta_stuck(stuck: bool) -> (Sw, Vec<&'static str>) {
    let (backend, medium) = rsk_fs::storage::faults::MetaStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    let named: [(&'static str, u16); 5] = [
        ("pk_sig", EF_PK_SIG.get()),
        ("pk_dec", EF_PK_DEC.get()),
        ("pk_aut", EF_PK_AUT.get()),
        ("login", EF_LOGIN_DATA),
        ("fp", EF_FP),
    ];
    for (_, fid) in named {
        fs.put(fid, &[0xAB; 40]).unwrap();
    }
    // A PIV head — that crate mints the only ones — so EF_META is live and the
    // sweep's metadata drops read it rather than short-circuiting on absence.
    fs.meta_add(0x9A00, &[0xAA, 0x01, 0x02, 0x03]).unwrap();

    medium.stick(stuck);
    let answered = terminate_df(&dev(), &mut fs, &mut CountRng(0), true, &apdu());
    medium.stick(false);

    let survivors = named
        .iter()
        .filter(|&&(_, fid)| medium.live(fid))
        .map(|&(name, _)| name)
        .collect();
    (answered, survivors)
}

/// Both halves are the assertion: the range is empty, AND the answer is `6581`.
/// The status alone passed the defect, because the aborting sweep answered `6581`
/// too.
#[test]
fn a_faulted_metadata_drop_never_stops_the_wipe_and_never_passes_as_clean() {
    assert_eq!(
        terminate_with_ef_meta_stuck(false),
        (Sw::OK, vec![]),
        "the control: nothing armed, so the wipe takes the range and says so"
    );
    assert_eq!(
        terminate_with_ef_meta_stuck(true),
        (Sw::MEMORY_FAILURE, vec![]),
        "under a faulted EF_META the wipe still owes the WHOLE range — a survivor \
         here is a private key TERMINATE reported destroyed — and it still owes an \
         error for the record it could not prove dropped"
    );
}

/// `scan_files` runs from boot and from TERMINATE DF alone, so a TERMINATE that
/// skips it leaves the applet with no `EF_PW_PRIV` and every later TERMINATE
/// answering `6A88` for the rest of the power cycle. The sweep now has a third
/// outcome — the range is clear, one metadata drop could not be proven — and it
/// must not be collapsed with the aborted one (PIV's `reset_files` has separated
/// them since 0x0987).
///
/// Returns the first answer, the gate records back ON THE MEDIUM, and the answer
/// to a retry — with the fault cleared when `persistent` is false.
fn terminate_then_retry(persistent: bool) -> (Sw, Vec<&'static str>, Sw) {
    let (backend, medium) = rsk_fs::storage::faults::MetaStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    fs.put(EF_PK_SIG.get(), &[0xAB; 40]).unwrap();
    // A PIV head — that crate mints the only ones — so EF_META is live and the
    // sweep's metadata drops read it rather than short-circuiting on absence.
    fs.meta_add(0x9A00, &[0xAA, 0x01, 0x02, 0x03]).unwrap();

    medium.stick(true);
    let first = terminate_df(&dev(), &mut fs, &mut CountRng(0), true, &apdu());
    medium.stick(persistent);
    let gates: [(&'static str, u16); 4] = [
        ("PW1", EF_PW1),
        ("PW3", EF_PW3),
        ("PW_PRIV", EF_PW_PRIV),
        ("PW_RETRIES", EF_PW_RETRIES),
    ];
    let reprovisioned = gates
        .iter()
        .filter(|&&(_, fid)| medium.live(fid))
        .map(|&(name, _)| name)
        .collect();
    let retry = terminate_df(&dev(), &mut fs, &mut CountRng(0), true, &apdu());
    medium.stick(false);
    (first, reprovisioned, retry)
}

#[test]
fn a_completed_wipe_reseeds_the_applet_even_when_a_record_could_not_be_proven_dropped() {
    assert_eq!(
        terminate_then_retry(false),
        (
            Sw::MEMORY_FAILURE,
            vec!["PW1", "PW3", "PW_PRIV", "PW_RETRIES"],
            Sw::OK
        ),
        "a TRANSIENT fault: the wipe still owes an error, but the applet is whole \
         again and the next TERMINATE succeeds — not 6A88 until the next reboot"
    );
    assert_eq!(
        terminate_then_retry(true),
        (
            Sw::MEMORY_FAILURE,
            vec!["PW1", "PW3", "PW_PRIV", "PW_RETRIES"],
            Sw::MEMORY_FAILURE
        ),
        "a PERSISTENT fault: re-seeding must not turn the honest failure into a \
         REFERENCE_NOT_FOUND the host reads as a missing applet"
    );
}

/// The unconditional re-seed is only safe because every record `scan_files` seeds
/// goes LAST. A sweep that failed in phase 1 never reached them, so `scan_files`
/// finds the owner's values present and writes nothing — no touch-OFF UIF flag and
/// no KDF-none back over a private key the surviving DEK can still open.
///
/// Driving `scan_files`' `UIF_DEFAULT` write unconditionally fails **three** tests,
/// not this one alone: `boot_settles_a_sex_code_outside_the_value_list` and
/// `a_refused_sex_repair_leaves_the_old_byte_and_retries` count writes, so three
/// extra ones break the wear budget too. All three fail in the same direction.
///
/// Returns the answer, the imported secret still live ON THE MEDIUM, and every
/// record `scan_files` seeds that changed across the whole command.
fn terminate_with_a_refused_secret_removal() -> (Sw, bool, Vec<String>) {
    let (backend, medium) = rsk_fs::storage::faults::RemoveStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    fs.put(EF_PK_SIG.get(), &[0xAB; 40]).unwrap();
    // Owner-set values `scan_files`' defaults would overwrite: touch-ON (the
    // OpenPGP analog of FIDO's alwaysUv), a KDF the PW verifiers are taken over,
    // and a signature counter that only ever climbs.
    fs.put(EF_UIF_SIG, &[0x01, 0x20]).unwrap();
    fs.put(EF_KDF, &[0x81, 0x01, 0x03, 0x82, 0x01, 0x08])
        .unwrap();
    fs.put(EF_SIG_COUNT, &[0x00, 0x12, 0x34]).unwrap();
    fs.put(EF_SEX, &[0x31]).unwrap();
    let watched = records_scan_files_seeds();
    let before: Vec<Option<Vec<u8>>> = watched.iter().map(|&fid| read_all(&mut fs, fid)).collect();

    medium.refuse(Some(EF_PK_SIG.get()));
    let answered = terminate_df(&dev(), &mut fs, &mut CountRng(9), true, &apdu());
    medium.refuse(None);

    // Removing a record is what the wipe is FOR, so an absent one is not a finding;
    // a record still standing on a value the owner never wrote is, because that
    // value can only have come from the re-seed (EF_DEK_PW3 is deleted here).
    let mut defaulted = Vec::new();
    for (&fid, was) in watched.iter().zip(before) {
        let now = read_all(&mut fs, fid);
        if now.is_some() && now != was {
            defaulted.push(format!("{fid:#06x} {was:02x?} -> {now:02x?}"));
        }
    }
    (answered, medium.live(EF_PK_SIG.get()), defaulted)
}

fn read_all<S: rsk_fs::Storage>(fs: &mut Fs<S>, fid: u16) -> Option<Vec<u8>> {
    let mut buf = [0u8; 64];
    fs.read(fid, &mut buf)
        .map(|n| buf[..n.min(buf.len())].to_vec())
}

#[test]
fn a_wipe_that_aborted_in_phase_one_is_reseeded_without_touching_a_single_seeded_record() {
    // WHICH records phase 1 reached before the refusal is a fresh flash-ring order
    // per run (`RamStorage` walks a HashMap), so one run samples one abort point.
    // The phase assignment that makes every one of them safe is asserted above.
    for _ in 0..16 {
        assert_eq!(
            terminate_with_a_refused_secret_removal(),
            (Sw::MEMORY_FAILURE, true, Vec::<String>::new()),
            "phase 1 stopped on the refused removal, so the private key is still \
             there and the answer says so — and the re-seed that now runs anyway \
             must not have put a factory default over any record the owner holds"
        );
    }
}

/// `WIPE_MAX_DELETES` is the sweep's progress guard — the comment on it names
/// itself PIV's mirror — and nothing reached it here: `DyingStorage` ERRORS once
/// its budget runs out, which stops the wipe at a `?` before the valve is ever
/// consulted. So the one fault the budget exists for, a medium that answers `Ok`
/// and keeps the record, was undriven in this applet and in OATH.
///
/// `deleted` rises a whole batch at a time, so `>` → `==` lets it step PAST the
/// budget without ever equalling it and the valve stops guarding. Five undead
/// records: 5 divides none of the four applets' budgets (512 · 768 · 257 · 1039),
/// which is the point — FIDO's and PIV's runaways re-yield ONE fid, and 1 divides
/// everything, so the mutant trips one delete early there and both of those tests
/// pass it by construction.
#[test]
fn a_wipe_that_never_converges_stops_inside_its_delete_budget() {
    const UNDEAD: [u16; 5] = [
        EF_PK_SIG.get(),
        EF_PK_DEC.get(),
        EF_PK_AUT.get(),
        EF_LOGIN_DATA,
        EF_FP,
    ];
    // The premise, made checkable rather than argued: `deleted` rises a whole
    // UNDEAD per pass, so a batch that DIVIDES the budget lets `==` fire on the
    // nose and this test stops seeing the valve — silently, suite still green.
    const _: () = assert!(
        !WIPE_MAX_DELETES.is_multiple_of(UNDEAD.len() as u32),
        "the batch divides the delete budget, so this test cannot falsify the valve"
    );
    let (backend, count) = rsk_fs::storage::faults::Undead::new(2 * WIPE_MAX_DELETES);
    let mut fs = Fs::new(backend);
    fs.scan();
    for fid in UNDEAD {
        fs.put(fid, &[0xAB; 40]).unwrap();
    }
    assert_eq!(
        wipe_openpgp(&mut fs),
        Err(Sw::MEMORY_FAILURE),
        "a wipe the medium never lets converge must fail, not run on"
    );
    assert!(
        count.removals() <= WIPE_MAX_DELETES,
        "the valve let the wipe spend {} deletions on a budget of {WIPE_MAX_DELETES}",
        count.removals()
    );
}

/// The wrap to a second batch, which nothing in this crate crossed: every fixture
/// above puts FIVE records live against a [`SWEEP_BATCH`] of 64, so the bound that
/// keeps `keys[k]` in range was untested — and what breaks it is an out-of-bounds
/// index in a `no_std` image, not a wrong answer. Measured: delete
/// `k < keys.len()` and this crate reported 199 passed, 0 failed. OATH's sweep is
/// the same shape and had the same hole; FIDO, PIV and `Fs::factory_wipe` already
/// have this test. Sweep by class, not by site.
///
/// The fill lives in `is_openpgp_fid`'s `0x7f00..0x8000` window because it has to
/// land in phase 1: `is_openpgp_gate_fid` names nothing there, so all of it wraps
/// the batch that the eleven phase-2 records never would. Sized OFF the batch, and
/// held to the window — a fill that outgrew it would survive the wipe honestly and
/// report the wrap as broken.
#[test]
fn a_wipe_clears_more_files_than_one_batch_holds() {
    const WINDOW: u16 = 0x7f00;
    const WINDOW_LEN: u16 = 0x8000 - WINDOW;
    const FILL: u16 = SWEEP_BATCH as u16 + 16;
    const _: () = assert!(FILL as u32 <= WIPE_MAX_DELETES && FILL <= WINDOW_LEN);
    let mut fs = Fs::new(RamStorage::new());
    fs.scan();
    for i in 0..FILL {
        assert!(!is_openpgp_gate_fid(WINDOW + i));
        fs.put(WINDOW + i, &[0xAB; 40]).unwrap();
    }
    assert_eq!(wipe_openpgp(&mut fs), Ok(()));
    for i in 0..FILL {
        assert!(
            !fs.has_data(WINDOW + i),
            "0x{:04X} survived a wipe that spans two batches",
            WINDOW + i
        );
    }
}

/// An un-yielded fid is not an absent fid: a walk the medium truncated must fail the
/// wipe rather than read the empty batch as "the range is clear" — which is a wipe
/// answering success over key material it never looked at.
///
/// Forcing the `complete` arm true left 615 / 118 / 197 passing: PIV owned this guard
/// and the other three did not, because the only fixture that truncates a walk was
/// PIV's own local one. It is `rsk_fs::storage::faults::TruncatedWalk` now.
#[test]
fn a_truncated_enumeration_fails_the_wipe_instead_of_reading_it_as_clear() {
    let mut fs = Fs::new(rsk_fs::storage::faults::TruncatedWalk::new());
    fs.scan();
    fs.put(EF_PK_SIG.get(), &[0xAB; 40]).unwrap();
    assert_eq!(wipe_openpgp(&mut fs), Err(Sw::MEMORY_FAILURE));
    let mut buf = [0u8; 40];
    assert_eq!(
        fs.read(EF_PK_SIG.get(), &mut buf),
        Some(40),
        "the private key was never swept"
    );
}

/// The `?` under the valve — a refused backend removal must STOP the wipe, because
/// `for_each_key` re-yields the fid the medium kept. Nothing in any of the four
/// applets could see it: swallow the `?` and the loop spins on that fid straight
/// into the VALVE, which answers the SAME error, so `let _ = gone.value;` left
/// 197 / 615 / 118 / 140 passing. The removal COUNT is the observation that
/// separates them — one batch against a whole budget.
#[test]
fn a_refused_removal_stops_the_wipe_instead_of_spinning_into_the_valve() {
    const LIVE: [u16; 5] = [
        EF_PK_SIG.get(),
        EF_PK_DEC.get(),
        EF_PK_AUT.get(),
        EF_LOGIN_DATA,
        EF_FP,
    ];
    let (backend, medium) = rsk_fs::storage::faults::RemoveStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    for fid in LIVE {
        fs.put(fid, &[0xAB; 40]).unwrap();
    }
    // Which of the batch is reached first is a fresh HashMap order per run, so the
    // stop lands anywhere in 1..=LIVE.len() — the bound is what has to hold.
    medium.refuse(Some(EF_PK_SIG.get()));
    assert_eq!(
        wipe_openpgp(&mut fs),
        Err(Sw::MEMORY_FAILURE),
        "a removal the medium refused must fail the wipe"
    );
    assert!(
        medium.attempts() <= LIVE.len() as u32,
        "the wipe asked for {} removals over {} files: it carried on past the refusal \
         and the delete budget, not the `?`, is what stopped it",
        medium.attempts(),
        LIVE.len()
    );
}

/// [`seeded`] on a medium that logs the order of the appends it serves — the only
/// place the re-arm of the at-rest lap can be seen to land BEFORE the tombstone it
/// covers rather than after it.
fn seeded_cut() -> (Fs<Cut>, CutMedium) {
    let (cut, medium) = Cut::new();
    let mut fs = Fs::new(cut);
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    (fs, medium)
}

/// The wipe path's own re-arm, which no applet wipe in the tree had: measured at
/// five wipe-sweep delete sites across four applets, none re-armed. A tombstone
/// appends like a re-seal, and PW1 / PW3 / RC migrate only on their own verify
/// (`migrate_pin_kbase`) — so a TERMINATE can leave a chip-serial-rooted verifier
/// dumpable under a marker the lap gates on. Best-effort, and that is the whole
/// difference from the gated sites: refusing here would leave the keys live.
#[test]
fn a_terminate_re_arms_the_at_rest_lap_before_the_first_tombstone() {
    let (mut fs, medium) = seeded_cut();
    fs.put(EF_PK_SIG.get(), &[0xAB; 40]).unwrap();
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    assert!(
        fs.has_data(rsk_fs::EF_HARDENED),
        "fixture: an earlier boot latched the marker"
    );

    medium.clear_ops();
    assert_eq!(
        terminate_df(&dev(), &mut fs, &mut CountRng(0), true, &apdu()),
        Sw::OK
    );
    medium.assert_re_armed_before(EF_PW1, |_| false, "OpenPGP TERMINATE DF");
    assert!(
        !fs.has_data(rsk_fs::EF_HARDENED),
        "the wipe tombstoned a possibly chip-serial-rooted verifier, so the lap \
         must run again"
    );

    // The best-effort half, and the direction that separates a wipe from every
    // gated site: a medium refusing only `remove(EF_HARDENED)` must still WIPE.
    let (backend, medium) = RemoveStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    fs.put(EF_PK_SIG.get(), &[0xAB; 40]).unwrap();
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    medium.refuse(Some(rsk_fs::EF_HARDENED));
    let answered = terminate_df(&dev(), &mut fs, &mut CountRng(0), true, &apdu());
    assert!(
        !medium.live(EF_PK_SIG.get()),
        "the refused re-arm stopped the wipe, which leaves the private keys LIVE — \
         the one direction a wipe must never fail in"
    );
    assert_eq!(answered, Sw::OK);
    assert!(
        medium.live(rsk_fs::EF_HARDENED),
        "fixture: the refusal really left the marker on the medium"
    );
}

/// The head re-arm is BEST-EFFORT, so its refusal leaves the marker latched over
/// every tombstone the sweep then appends — the residual the gated sites do not
/// carry. A single-shot refusal is the only kind the pass recovers from, and the
/// retry after the sweep is what recovers it; a persistent one is still a residual.
#[test]
fn a_terminate_retries_the_re_arm_after_the_sweep() {
    let (backend, medium) = RemoveStuck::new();
    let mut fs = Fs::new(backend);
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    fs.put(EF_PK_SIG.get(), &[0xAB; 40]).unwrap();
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    assert!(
        medium.live(rsk_fs::EF_HARDENED),
        "fixture: an earlier boot latched the marker"
    );
    // Only the HEAD re-arm is refused; the medium serves every mutation after it.
    medium.refuse_once(rsk_fs::EF_HARDENED);

    let answered = terminate_df(&dev(), &mut fs, &mut CountRng(0), true, &apdu());
    assert!(
        !medium.live(rsk_fs::EF_HARDENED),
        "the head re-arm was refused and nothing retried it, so the marker stands \
         over the verifier this wipe just tombstoned and no later boot ever laps"
    );
    assert_eq!(answered, Sw::OK);
    assert!(!medium.live(EF_PK_SIG.get()), "the wipe still ran");

    // The control on the same medium, with the refusal made PERSISTENT instead:
    // the marker survives, so the assertion above is about the retry landing and
    // not about a marker the fixture never latched.
    fs.put(EF_PK_SIG.get(), &[0xAB; 40]).unwrap();
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    medium.refuse(Some(rsk_fs::EF_HARDENED));
    assert_eq!(
        terminate_df(&dev(), &mut fs, &mut CountRng(0), true, &apdu()),
        Sw::OK
    );
    assert!(
        medium.live(rsk_fs::EF_HARDENED),
        "fixture: a persistent refusal really does leave the marker standing"
    );
}

/// Both faults of the residual in one medium, because neither alone reaches it: a
/// SINGLE-SHOT refusal of `refuse_once`'s removal — the only kind a retry recovers
/// — and a walk that truncates for good once `truncate_after` has been tombstoned.
/// `RemoveStuck` and `TruncatedWalk` carry one each and cannot be composed.
struct RefusedThenTruncated {
    inner: RamStorage,
    refuse_once: Option<u16>,
    truncate_after: Option<u16>,
    truncated: bool,
}

impl Storage for RefusedThenTruncated {
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
        self.inner.read(fid, buf)
    }
    fn write(&mut self, fid: u16, data: &[u8]) -> rsk_sdk::error::Result<()> {
        self.inner.write(fid, data)
    }
    fn remove(&mut self, fid: u16) -> rsk_sdk::error::Result<()> {
        if self.refuse_once == Some(fid) {
            self.refuse_once = None;
            return Err(rsk_sdk::error::Error::MemoryFatal);
        }
        self.inner.remove(fid)?;
        self.truncated |= self.truncate_after == Some(fid);
        Ok(())
    }
    fn size(&mut self, fid: u16) -> Option<usize> {
        self.inner.size(fid)
    }
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
        if self.truncated {
            return false;
        }
        self.inner.for_each_key(f)
    }
}

/// What one arm of [`a_terminate_that_faults_mid_sweep_still_re_arms_the_lap`]
/// left behind: the host's answer, and what the MEDIUM kept — never `Fs::has_data`,
/// since a refused removal is exactly where the present cache and the medium part.
/// `EF_PW1` is read off the walk's own trigger rather than the medium, because
/// `scan_files` runs whatever the wipe answered and re-seeds a default over it.
struct Residue {
    answered: Sw,
    marker: bool,
    keys: bool,
    verifier_tombstoned: bool,
}

fn terminate_under(refuse_once: Option<u16>, truncate_after: Option<u16>) -> Residue {
    let mut fs = Fs::new(RefusedThenTruncated {
        inner: RamStorage::new(),
        refuse_once,
        truncate_after,
        truncated: false,
    });
    fs.scan();
    scan_files(&dev(), &mut fs, &mut CountRng(0)).unwrap();
    fs.put(EF_PK_SIG.get(), &[0xAB; 40]).unwrap();
    fs.put(rsk_fs::EF_HARDENED, &[1]).unwrap();
    // Neither fault fires during setup — it writes and never removes these — so
    // the arms differ only in what the TERMINATE meets.
    assert!(
        fs.has_data(rsk_fs::EF_HARDENED) && fs.has_data(EF_PW1),
        "fixture"
    );
    let answered = terminate_df(&dev(), &mut fs, &mut CountRng(0), true, &apdu());
    let mut medium = fs.into_storage();
    Residue {
        answered,
        marker: medium.inner.exists(rsk_fs::EF_HARDENED),
        keys: medium.inner.exists(EF_PK_SIG.get()),
        verifier_tombstoned: medium.truncated,
    }
}

/// The refusal the retry exists for, met by the wipe fault the retry stands below:
/// the sweep carries `?` and two `return Err`, so an early return skips the retry,
/// and the conjunction is exactly the case it was written for. Both controls run
/// in this case rather than their own, so the claim is about the CONJUNCTION and
/// not about either fault.
#[test]
fn a_terminate_that_faults_mid_sweep_still_re_arms_the_lap() {
    let subject = terminate_under(Some(rsk_fs::EF_HARDENED), Some(EF_PW1));
    assert!(
        !subject.marker,
        "the head re-arm was refused and the sweep then faulted, so the only retry \
         left is one the fault returns past — the marker stands over a possibly \
         chip-serial-rooted verifier this wipe tombstoned and no boot ever laps"
    );
    assert!(
        subject.verifier_tombstoned && !subject.keys,
        "fixture: the verifier really was tombstoned under that marker, over keys \
         the wipe had already taken"
    );
    assert_eq!(
        subject.answered,
        Sw::MEMORY_FAILURE,
        "the faulted sweep is still reported, so the re-arm changed no answer"
    );

    // CONTROL A: the head refusal alone. The sweep completes, so the retry is
    // reached — the refusal is not by itself what leaves the marker.
    let head_only = terminate_under(Some(rsk_fs::EF_HARDENED), None);
    assert!(!head_only.marker, "control: a refusal the retry recovers");
    assert_eq!(head_only.answered, Sw::OK);

    // CONTROL B: the sweep fault alone. The head re-arm lands, so the fault has no
    // latched marker to leave behind.
    let sweep_only = terminate_under(None, Some(EF_PW1));
    assert!(
        !sweep_only.marker,
        "control: the head re-arm already landed"
    );
    assert_eq!(sweep_only.answered, Sw::MEMORY_FAILURE);
}
