// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;
use crate::Rng;
use crate::consts::{ALG_ES256, CURVE_P256};
use crate::credential::{CredExt, CredInput, credential_create, credential_store};
use crate::seed::{ensure_seed, load_keydev};
use rsk_crypto::sha256;
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

fn provisioned() -> (Fs<RamStorage>, [u8; 32]) {
    let mut fs = Fs::new(RamStorage::new());
    let mut rng = SeqRng(1);
    ensure_seed(&dev(), &mut fs, &mut rng).unwrap();
    let seed = load_keydev(&dev(), &mut fs).unwrap();
    (fs, seed)
}

// Register a resident credential the way makeCredential's storage primitive does
// (a sealed box + an EF_CRED record + the boxed EF_RP domain).
#[allow(clippy::too_many_arguments)]
fn add(
    fs: &mut Fs<RamStorage>,
    seed: &[u8; 32],
    iv_byte: u8,
    rp_id: &str,
    uid: &[u8],
    name: &str,
    dname: &str,
    cred_protect: u64,
) {
    let rp_hash = sha256(rp_id.as_bytes());
    let iv = [iv_byte; 12];
    let inp = CredInput {
        rp_id,
        user_id: uid,
        user_name: name,
        user_display_name: dname,
        use_sign_count: false,
        rk: true,
        created_ms: 1,
        alg: ALG_ES256,
        curve: CURVE_P256 as i64,
        ext: CredExt {
            cred_protect,
            ..CredExt::default()
        },
    };
    let mut boxbuf = [0u8; 512];
    let len = credential_create(seed, &dev(), &inp, &rp_hash, &iv, &mut boxbuf).unwrap();
    credential_store(seed, &dev(), fs, &boxbuf[..len], &rp_hash, rp_id, uid, &[]).unwrap();
}

#[test]
fn lists_rps_with_credential_counts() {
    let (mut fs, seed) = provisioned();
    add(
        &mut fs,
        &seed,
        1,
        "github.com",
        b"u-alice",
        "alice",
        "Alice",
        0,
    );
    add(&mut fs, &seed, 2, "github.com", b"u-bob", "bob", "Bob", 0);
    add(
        &mut fs,
        &seed,
        3,
        "google.com",
        b"u-carol",
        "carol",
        "Carol",
        0,
    );

    let mut seen = std::vec::Vec::new();
    let total = for_each_rp(&dev(), &mut fs, |rp| {
        seen.push((rp.rp_id.to_string(), rp.count));
    });
    assert_eq!(total, 2);
    seen.sort();
    assert_eq!(
        seen,
        std::vec![("github.com".to_string(), 2), ("google.com".to_string(), 1)]
    );
}

#[test]
fn lists_accounts_under_one_rp() {
    let (mut fs, seed) = provisioned();
    add(
        &mut fs,
        &seed,
        1,
        "github.com",
        b"u-alice",
        "alice",
        "Alice",
        0,
    );
    add(&mut fs, &seed, 2, "github.com", b"u-bob", "bob", "Bob", 2);
    add(
        &mut fs,
        &seed,
        3,
        "google.com",
        b"u-carol",
        "carol",
        "Carol",
        0,
    );

    let gh = sha256(b"github.com");
    let mut names = std::vec::Vec::new();
    let total = for_each_cred(&dev(), &mut fs, &gh, |a| {
        names.push(a.user_name.to_string());
    });
    assert_eq!(total, 2);
    names.sort();
    assert_eq!(names, std::vec!["alice".to_string(), "bob".to_string()]);
}

#[test]
fn surfaces_cred_protect_level() {
    let (mut fs, seed) = provisioned();
    add(&mut fs, &seed, 1, "bank.example", b"u1", "neo", "Neo", 3);
    let h = sha256(b"bank.example");
    let mut levels = std::vec::Vec::new();
    for_each_cred(&dev(), &mut fs, &h, |a| levels.push(a.cred_protect));
    assert_eq!(levels, std::vec![3]);
}

#[test]
fn true_total_even_when_visitor_keeps_fewer() {
    let (mut fs, seed) = provisioned();
    add(&mut fs, &seed, 1, "a.example", b"u", "n", "N", 0);
    add(&mut fs, &seed, 2, "b.example", b"u", "n", "N", 0);
    add(&mut fs, &seed, 3, "c.example", b"u", "n", "N", 0);

    let mut kept = 0;
    let total = for_each_rp(&dev(), &mut fs, |_| {
        if kept < 1 {
            kept += 1;
        }
    });
    assert_eq!(total, 3, "return is the true total");
    assert_eq!(kept, 1, "visitor may keep a subset");
}

/// `for_each_rp` skips a slot at `n < RP_PREFIX || buf[0] == 0`, and neither half
/// was tested (the reverse mutation pass, D2). Both shapes are reachable from a
/// torn write, and neither may be read as a relying party: a record too short
/// for its own header would have its rpIdHash copied out of the buffer's stale
/// tail, and a zero count is the emptied slot every enumeration must pass over.
///
/// The boundary itself is deliberately NOT pinned here. A record of exactly
/// `RP_PREFIX` bytes — header, no payload — is enumerated today, because
/// `unseal_rp_id` falls through to its legacy cleartext domain and an empty tail
/// decodes as the empty string. Measured, not assumed: it arrives as a relying
/// party whose `rp_id` is `""`. Whether that should be skipped is a decision,
/// and a test that pinned either side would cement an accident.
#[test]
fn a_malformed_rp_slot_is_skipped_by_the_enumeration() {
    for (label, rec) in [
        ("empty", std::vec![]),
        ("one byte", std::vec![1u8]),
        ("one short of the header", std::vec![1u8; RP_PREFIX - 1]),
        ("zero count", {
            let mut v = std::vec![0u8; RP_PREFIX + 8];
            v[0] = 0;
            v
        }),
    ] {
        let (mut fs, seed) = provisioned();
        add(&mut fs, &seed, 1, "good.example", b"u", "n", "N", 0);
        fs.put(EF_RP + 1, &rec).unwrap();
        let mut calls = 0;
        let total = for_each_rp(&dev(), &mut fs, |_| calls += 1);
        assert_eq!(total, 1, "{label}: the malformed slot must not be counted");
        assert_eq!(calls, 1, "{label}: nor visited");
    }
}

#[test]
fn empty_when_unprovisioned() {
    let mut fs = Fs::new(RamStorage::new());
    let mut calls = 0;
    let total = for_each_rp(&dev(), &mut fs, |_| calls += 1);
    assert_eq!(total, 0);
    assert_eq!(calls, 0);
}

#[test]
fn empty_for_rp_with_no_credentials() {
    let (mut fs, seed) = provisioned();
    add(&mut fs, &seed, 1, "github.com", b"u", "n", "N", 0);
    let unknown = sha256(b"nope.example");
    let mut calls = 0;
    let total = for_each_cred(&dev(), &mut fs, &unknown, |_| calls += 1);
    assert_eq!(total, 0);
    assert_eq!(calls, 0);
}

fn fids_under(fs: &mut Fs<RamStorage>, rp_id: &str) -> std::vec::Vec<u16> {
    let h = sha256(rp_id.as_bytes());
    let mut fids = std::vec::Vec::new();
    for_each_cred(&dev(), fs, &h, |a| fids.push(a.ef_cred_fid));
    fids
}

#[test]
fn delete_drops_cred_and_decrements_rp() {
    let (mut fs, seed) = provisioned();
    add(&mut fs, &seed, 1, "github.com", b"u-a", "a", "A", 0);
    add(&mut fs, &seed, 2, "github.com", b"u-b", "b", "B", 0);
    add(&mut fs, &seed, 3, "google.com", b"u-c", "c", "C", 0);

    let gh = fids_under(&mut fs, "github.com");
    assert_eq!(gh.len(), 2);
    assert!(delete_cred(&mut fs, gh[0]));

    // The other github account survives, google is untouched.
    assert_eq!(fids_under(&mut fs, "github.com").len(), 1);
    assert_eq!(fids_under(&mut fs, "google.com").len(), 1);
    // The EF_RP count was decremented (2 → 1), so the RP still lists once.
    let mut counts = std::vec::Vec::new();
    for_each_rp(&dev(), &mut fs, |rp| {
        counts.push((rp.rp_id.to_string(), rp.count));
    });
    counts.sort();
    assert_eq!(
        counts,
        std::vec![("github.com".to_string(), 1), ("google.com".to_string(), 1)]
    );
}

#[test]
fn delete_last_cred_removes_rp() {
    let (mut fs, seed) = provisioned();
    add(&mut fs, &seed, 1, "solo.example", b"u", "n", "N", 0);
    add(&mut fs, &seed, 2, "keep.example", b"u", "n", "N", 0);

    let solo = fids_under(&mut fs, "solo.example");
    assert_eq!(solo.len(), 1);
    assert!(delete_cred(&mut fs, solo[0]));

    // The RP record is gone with its last credential, so the walk no longer
    // surfaces it — only the untouched RP remains.
    let mut seen = std::vec::Vec::new();
    let total = for_each_rp(&dev(), &mut fs, |rp| seen.push(rp.rp_id.to_string()));
    assert_eq!(total, 1);
    assert_eq!(seen, std::vec!["keep.example".to_string()]);
}

/// The fourth path that changes the discoverable set, and the one the roadmap for
/// `encCredStoreState` did not list: a delete driven from the trusted display, not
/// from a host. A platform holding the persistent token must see the same tag move
/// it would have seen for `deleteCredential`, or its cache outlives a credential the
/// owner removed on the device itself.
#[test]
fn an_on_device_delete_moves_the_store_tag() {
    use crate::credential::cred_store_state;

    let (mut fs, seed) = provisioned();
    add(&mut fs, &seed, 1, "github.com", b"u", "n", "N", 0);
    let before = cred_store_state(&mut fs);

    let gh = fids_under(&mut fs, "github.com");
    assert_eq!(gh.len(), 1);
    assert!(delete_cred(&mut fs, gh[0]));
    assert_ne!(cred_store_state(&mut fs), before);
}

/// A refused on-device delete must not move the tag either way it can be refused —
/// out of range, or an empty slot. Both return before the bump, so nothing is
/// written and nothing is claimed.
#[test]
fn a_refused_on_device_delete_leaves_the_tag_alone() {
    use crate::credential::cred_store_state;

    let (mut fs, seed) = provisioned();
    add(&mut fs, &seed, 1, "github.com", b"u", "n", "N", 0);
    let before = cred_store_state(&mut fs);
    assert!(!delete_cred(&mut fs, EF_CRED - 1));
    assert!(!delete_cred(&mut fs, EF_CRED + 200));
    assert_eq!(cred_store_state(&mut fs), before);
}

#[test]
fn delete_bad_fid_is_noop() {
    let (mut fs, seed) = provisioned();
    add(&mut fs, &seed, 1, "github.com", b"u", "n", "N", 0);
    // Out of range below / at the EF_RP boundary, and an in-range but empty slot.
    assert!(!delete_cred(&mut fs, EF_CRED - 1));
    assert!(!delete_cred(&mut fs, EF_CRED + MAX_RESIDENT_CREDENTIALS));
    assert!(!delete_cred(&mut fs, EF_CRED + 200));
    // The real credential is still there — nothing was removed.
    assert_eq!(fids_under(&mut fs, "github.com").len(), 1);
}

// --- Device-local RP nicknames -----------------------------------------

/// The nickname as `for_each_rp` surfaces it for `rp_id`.
fn nick_of(fs: &mut Fs<RamStorage>, rp_id: &str) -> Option<std::string::String> {
    let want = sha256(rp_id.as_bytes());
    let mut out = None;
    for_each_rp(&dev(), fs, |rp| {
        if rp.rp_id_hash == want {
            out = rp.nickname.map(|s| s.to_string());
        }
    });
    out
}

#[test]
fn nickname_defaults_to_none_then_roundtrips() {
    let (mut fs, seed) = provisioned();
    add(&mut fs, &seed, 1, "github.com", b"u", "n", "N", 0);
    let gh = sha256(b"github.com");
    assert_eq!(
        nick_of(&mut fs, "github.com"),
        None,
        "unset → rpId fallback"
    );

    assert!(set_rp_nickname(&dev(), &mut fs, &gh, "Work GitHub"));
    assert_eq!(
        nick_of(&mut fs, "github.com").as_deref(),
        Some("Work GitHub")
    );
}

#[test]
fn nickname_update_then_clear() {
    let (mut fs, seed) = provisioned();
    add(&mut fs, &seed, 1, "github.com", b"u", "n", "N", 0);
    let gh = sha256(b"github.com");
    assert!(set_rp_nickname(&dev(), &mut fs, &gh, "first"));
    assert!(set_rp_nickname(&dev(), &mut fs, &gh, "second"));
    assert_eq!(nick_of(&mut fs, "github.com").as_deref(), Some("second"));
    // An empty nickname clears it — the RP reverts to its rpId.
    assert!(set_rp_nickname(&dev(), &mut fs, &gh, ""));
    assert_eq!(nick_of(&mut fs, "github.com"), None);
}

#[test]
fn nickname_on_unknown_rp_is_rejected() {
    let (mut fs, _seed) = provisioned();
    let ghost = sha256(b"nobody.example");
    assert!(!set_rp_nickname(&dev(), &mut fs, &ghost, "ghost"));
}

#[test]
fn nickname_too_long_is_rejected_and_not_stored() {
    let (mut fs, seed) = provisioned();
    add(&mut fs, &seed, 1, "github.com", b"u", "n", "N", 0);
    let gh = sha256(b"github.com");
    let long = "a".repeat(RP_NICK_MAX_LEN + 1);
    assert!(!set_rp_nickname(&dev(), &mut fs, &gh, &long));
    assert_eq!(nick_of(&mut fs, "github.com"), None);
    // Exactly the cap is accepted.
    let max = "b".repeat(RP_NICK_MAX_LEN);
    assert!(set_rp_nickname(&dev(), &mut fs, &gh, &max));
    assert_eq!(
        nick_of(&mut fs, "github.com").as_deref(),
        Some(max.as_str())
    );
}

#[test]
fn nickname_is_per_rp_and_survives_a_new_account() {
    let (mut fs, seed) = provisioned();
    add(&mut fs, &seed, 1, "github.com", b"u-a", "a", "A", 0);
    add(&mut fs, &seed, 2, "google.com", b"u-b", "b", "B", 0);
    let gh = sha256(b"github.com");
    let gg = sha256(b"google.com");
    assert!(set_rp_nickname(&dev(), &mut fs, &gh, "GH"));
    assert!(set_rp_nickname(&dev(), &mut fs, &gg, "GG"));
    // Adding another github account (bumps the count) must not disturb the nickname.
    add(&mut fs, &seed, 3, "github.com", b"u-c", "c", "C", 0);
    assert_eq!(nick_of(&mut fs, "github.com").as_deref(), Some("GH"));
    assert_eq!(nick_of(&mut fs, "google.com").as_deref(), Some("GG"));
}

#[test]
fn nickname_is_dropped_when_its_rp_disappears() {
    let (mut fs, seed) = provisioned();
    add(&mut fs, &seed, 1, "solo.example", b"u", "n", "N", 0);
    let h = sha256(b"solo.example");
    assert!(set_rp_nickname(&dev(), &mut fs, &h, "Solo"));

    // Delete the only credential — the RP (and its nickname) go away.
    let solo = fids_under(&mut fs, "solo.example");
    assert!(delete_cred(&mut fs, solo[0]));

    // Re-create the same RP; it must NOT inherit the old nickname.
    add(&mut fs, &seed, 2, "solo.example", b"u2", "n2", "N2", 0);
    assert_eq!(
        nick_of(&mut fs, "solo.example"),
        None,
        "a fresh RP at a reused slot is unnamed"
    );
}

#[test]
fn nickname_is_sealed_at_rest() {
    let (mut fs, seed) = provisioned();
    add(&mut fs, &seed, 1, "github.com", b"u", "n", "N", 0);
    let gh = sha256(b"github.com");
    assert!(set_rp_nickname(&dev(), &mut fs, &gh, "secretname"));
    // The cleartext must not appear in any EF_RPNICK slot's bytes.
    let mut rec = [0u8; 256];
    let mut found_cleartext = false;
    for i in 0..MAX_RESIDENT_CREDENTIALS {
        if let Some(n) = fs.read(EF_RPNICK + i, &mut rec) {
            let n = n.min(rec.len());
            if rec[..n]
                .windows(b"secretname".len())
                .any(|w| w == b"secretname")
            {
                found_cleartext = true;
            }
        }
    }
    assert!(!found_cleartext, "nickname must be sealed, not cleartext");
}

// ---- Adversarial property sweep over nickname + stored-record bytes ------
//
// Two attacker surfaces, both deterministic so the gate runs them:
//   1. arbitrary `nick` bytes into `set_rp_nickname` (length-bound + isolation),
//   2. arbitrary bytes written straight into an EF_RPNICK slot, then decoded by
//      `for_each_rp` / `unseal_nick` — modelling a corrupt/forged flash record.
use crate::credential::{NICK_BOX_MAX, seal_nick, unseal_nick};

// A cheap splitmix64 PRNG so the sweep is reproducible without `rand`.
struct Prng(u64);
impl Prng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn bytes(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let r = self.next().to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&r[..n]);
        }
    }
}

/// `set_rp_nickname` must never truncate-and-store: a nickname one byte over the
/// cap is rejected, and the rejection must leave NO record (it must not bleed into
/// the slot as a truncated value). At exactly the cap it stores and round-trips.
#[test]
fn fuzz_nickname_length_bound_is_reject_not_truncate() {
    let mut prng = Prng(0xDEAD_BEEF);
    for _ in 0..2_000 {
        let (mut fs, seed) = provisioned();
        add(&mut fs, &seed, 1, "github.com", b"u", "n", "N", 0);
        let gh = sha256(b"github.com");

        // Build an ASCII nickname of an attacker-chosen length around the cap.
        let len = (prng.next() % (RP_NICK_MAX_LEN as u64 + 4)) as usize;
        let mut raw = [0u8; RP_NICK_MAX_LEN + 4];
        prng.bytes(&mut raw[..len]);
        for b in raw[..len].iter_mut() {
            *b = b'a' + (*b % 26); // keep it valid UTF-8 / printable
        }
        let nick = core::str::from_utf8(&raw[..len]).unwrap();

        let ok = set_rp_nickname(&dev(), &mut fs, &gh, nick);
        assert_eq!(
            ok,
            nick.len() <= RP_NICK_MAX_LEN,
            "store accepted iff within the cap"
        );

        let got = nick_of(&mut fs, "github.com");
        if nick.is_empty() {
            assert_eq!(got, None, "empty nick clears, leaves no name");
        } else if nick.len() <= RP_NICK_MAX_LEN {
            assert_eq!(
                got.as_deref(),
                Some(nick),
                "stored nick round-trips exactly"
            );
        } else {
            // Over-long: rejected. There must be NO truncated remnant in the slot.
            assert_eq!(got, None, "an over-long nick must store nothing");
        }
    }
}

/// Decoding an arbitrary/corrupt EF_RPNICK record must never panic and must never
/// surface a name for a slot whose box does not authenticate under its RP. We write
/// junk of every length — including > NICK_BOX_MAX, the slice that would OOB-panic
/// if `for_each_rp` dropped its `m.min(NICK_BOX_MAX)` clamp — straight into the slot
/// behind the real RP, then walk it.
#[test]
fn fuzz_corrupt_stored_record_never_panics_or_names() {
    let mut prng = Prng(0x0BAD_F00D);
    for _ in 0..4_000 {
        let (mut fs, seed) = provisioned();
        add(&mut fs, &seed, 7, "github.com", b"u", "n", "N", 0);

        // Junk length spans short (< IV+TAG), exact box sizes, and oversize.
        let len = (prng.next() % (NICK_BOX_MAX as u64 + 40)) as usize;
        let mut junk = [0u8; NICK_BOX_MAX + 40];
        prng.bytes(&mut junk[..len]);
        // Slot 0 is where github.com's EF_RP lands (first occupied slot).
        fs.put(EF_RPNICK, &junk[..len]).unwrap();

        // The decode walk must complete and the RP must fall back to its rpId:
        // forged bytes can't open under github.com's rpIdHash (the AEAD AAD).
        let got = nick_of(&mut fs, "github.com");
        assert_eq!(got, None, "a corrupt/forged record must never name an RP");
    }
}

/// `unseal_nick` directly, over adversarial (tail, rpIdHash, out-buffer) shapes:
/// every length and a too-small `out` must yield `None`, never panic; only a
/// genuine box under the matching rpIdHash opens, and never as a foreign RP.
#[test]
fn fuzz_unseal_nick_shapes_never_panic() {
    let mut prng = Prng(0xC0FF_EE42);
    let seed = [0x5A; 32];
    let rp_a = [0x11; 32];
    let rp_b = [0x22; 32];

    // A real box for rp_a, opened back only under rp_a — never under rp_b.
    let mut real = [0u8; NICK_BOX_MAX];
    let rlen = seal_nick(&seed, &rp_a, "Work GitHub", &mut real).unwrap();
    let mut p = [0u8; RP_NICK_MAX_LEN];
    assert_eq!(
        unseal_nick(&seed, &rp_a, &real[..rlen], &mut p),
        Some("Work GitHub")
    );
    let mut p2 = [0u8; RP_NICK_MAX_LEN];
    assert_eq!(unseal_nick(&seed, &rp_b, &real[..rlen], &mut p2), None);

    for _ in 0..20_000 {
        let len = (prng.next() % (NICK_BOX_MAX as u64 + 16)) as usize;
        let mut tail = [0u8; NICK_BOX_MAX + 16];
        prng.bytes(&mut tail[..len]);
        // Vary the output buffer size too: a ct longer than `out` must be `None`,
        // not an OOB copy.
        let out_cap = (prng.next() % (RP_NICK_MAX_LEN as u64 + 1)) as usize;
        let mut out = [0u8; RP_NICK_MAX_LEN];
        // Random junk practically never authenticates → always None, never panic.
        let r = unseal_nick(&seed, &rp_a, &tail[..len], &mut out[..out_cap]);
        assert!(r.is_none(), "random bytes must not forge a valid nickname");
    }
}
