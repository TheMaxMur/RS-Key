// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

struct Echo {
    selected: bool,
}
// Context-free applet: the unit type stands in for "no file system".
impl Applet<()> for Echo {
    fn aid(&self) -> &'static [u8] {
        &[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]
    }
    fn select(&mut self, _reselect: bool, _ctx: &mut (), _res: &mut ResBuf) -> Sw {
        self.selected = true;
        Sw::OK
    }
    fn process(&mut self, apdu: &Apdu, _ctx: &mut (), res: &mut ResBuf) -> Sw {
        if apdu.ins == 0x10 {
            res.extend(apdu.data);
            Sw::OK
        } else {
            Sw::INS_NOT_SUPPORTED
        }
    }
}

/// An applet that records the `reselect` flag it was handed, which is what the
/// dispatcher's `current == Some(i)` decides and what PIV and OpenPGP branch on
/// to keep or drop their session. Every other fake here ignores the flag, which
/// is exactly why inverting that comparison was killed by no test (D2).
struct FlagWatcher<'c> {
    aid: &'static [u8],
    seen: &'c std::cell::Cell<Option<bool>>,
}
impl Applet<()> for FlagWatcher<'_> {
    fn aid(&self) -> &'static [u8] {
        self.aid
    }
    fn select(&mut self, reselect: bool, _ctx: &mut (), _res: &mut ResBuf) -> Sw {
        self.seen.set(Some(reselect));
        Sw::OK
    }
    fn process(&mut self, _apdu: &Apdu, _ctx: &mut (), _res: &mut ResBuf) -> Sw {
        Sw::OK
    }
}

#[test]
fn reselect_is_true_only_for_the_applet_already_current() {
    const AID_A: &[u8] = &[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];
    const AID_B: &[u8] = &[0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10];
    let (fa, fb) = (std::cell::Cell::new(None), std::cell::Cell::new(None));
    let mut a = FlagWatcher {
        aid: AID_A,
        seen: &fa,
    };
    let mut b = FlagWatcher {
        aid: AID_B,
        seen: &fb,
    };
    let mut applets: [&mut dyn Applet<()>; 2] = [&mut a, &mut b];
    let mut disp = Dispatcher::new();
    let mut out = [0u8; 64];

    for (aid, cell, want, why) in [
        (AID_A, &fa, false, "the first SELECT is fresh"),
        (
            AID_A,
            &fa,
            true,
            "selecting the applet already current is a RESELECT",
        ),
        (
            AID_B,
            &fb,
            false,
            "selecting a different applet is never a reselect",
        ),
        (
            AID_A,
            &fa,
            false,
            "coming back after another applet is a fresh select",
        ),
    ] {
        let mut apdu = std::vec![0x00u8, 0xA4, 0x04, 0x00, aid.len() as u8];
        apdu.extend_from_slice(aid);
        let mut res = ResBuf::new(&mut out);
        assert_eq!(disp.process(&apdu, &mut applets, &mut (), &mut res), Sw::OK);
        assert_eq!(cell.get(), Some(want), "{why}");
    }
}

#[test]
fn select_then_dispatch() {
    let mut echo = Echo { selected: false };
    let mut applets: [&mut dyn Applet<()>; 1] = [&mut echo];
    let mut disp = Dispatcher::new();
    let mut out = [0u8; 64];
    let mut res = ResBuf::new(&mut out);

    // Unknown command before any selection.
    assert_eq!(
        disp.process(&[0x00, 0x10, 0, 0], &mut applets, &mut (), &mut res),
        Sw::FILE_NOT_FOUND
    );

    // SELECT by AID.
    let mut sel = vec![0x00, 0xA4, 0x04, 0x00, 0x08];
    sel.extend_from_slice(&[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]);
    assert_eq!(disp.process(&sel, &mut applets, &mut (), &mut res), Sw::OK);
    assert_eq!(disp.current(), Some(0));

    // Now an echo command.
    let cmd = [0x00, 0x10, 0x00, 0x00, 0x03, 0xDE, 0xAD, 0xBE];
    assert_eq!(disp.process(&cmd, &mut applets, &mut (), &mut res), Sw::OK);
    assert_eq!(res.as_slice(), &[0xDE, 0xAD, 0xBE]);
}

#[test]
fn clear_selection_drops_the_applet() {
    // Models the CTAPHID_INIT fix: after a SELECT sticks, clear_selection()
    // must drop it so the next command is NOT routed to the old applet (the
    // U2F-hijack bug — a sticky vendor SELECT swallowed U2F traffic).
    let mut echo = Echo { selected: false };
    let mut applets: [&mut dyn Applet<()>; 1] = [&mut echo];
    let mut disp = Dispatcher::new();
    let mut out = [0u8; 64];
    let mut res = ResBuf::new(&mut out);

    let mut sel = vec![0x00, 0xA4, 0x04, 0x00, 0x08];
    sel.extend_from_slice(&[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]);
    assert_eq!(disp.process(&sel, &mut applets, &mut (), &mut res), Sw::OK);
    assert_eq!(disp.current(), Some(0));

    disp.clear_selection();
    assert_eq!(disp.current(), None);

    // The same command that worked while selected now finds nothing selected.
    let cmd = [0x00, 0x10, 0x00, 0x00, 0x03, 0xDE, 0xAD, 0xBE];
    assert_eq!(
        disp.process(&cmd, &mut applets, &mut (), &mut res),
        Sw::FILE_NOT_FOUND
    );
}

#[test]
fn command_chaining_reassembles() {
    let mut echo = Echo { selected: false };
    let mut applets: [&mut dyn Applet<()>; 1] = [&mut echo];
    let mut disp = Dispatcher::new();
    let mut out = [0u8; 64];
    let mut res = ResBuf::new(&mut out);

    let mut sel = vec![0x00, 0xA4, 0x04, 0x00, 0x08];
    sel.extend_from_slice(&[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]);
    assert_eq!(disp.process(&sel, &mut applets, &mut (), &mut res), Sw::OK);

    // Two chaining segments (CLA bit 0x10) are acknowledged with no body…
    assert_eq!(
        disp.process(
            &[0x10, 0x10, 0, 0, 0x02, 0xAA, 0xBB],
            &mut applets,
            &mut (),
            &mut res
        ),
        Sw::OK
    );
    assert!(res.is_empty());
    assert_eq!(
        disp.process(
            &[0x10, 0x10, 0, 0, 0x02, 0xCC, 0xDD],
            &mut applets,
            &mut (),
            &mut res
        ),
        Sw::OK
    );
    // …then the final non-chained segment dispatches the reassembled command.
    assert_eq!(
        disp.process(
            &[0x00, 0x10, 0, 0, 0x01, 0xEE],
            &mut applets,
            &mut (),
            &mut res
        ),
        Sw::OK
    );
    assert_eq!(res.as_slice(), &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
}

#[test]
fn clear_chaining_drops_a_stale_incoming_chain() {
    // Models the RSA-keygen fast path: it short-circuits `process` for a
    // GENERATE, so an interrupted incoming command chain must be reset — else
    // the stale segments would prepend onto the next command.
    let mut echo = Echo { selected: false };
    let mut applets: [&mut dyn Applet<()>; 1] = [&mut echo];
    let mut disp = Dispatcher::new();
    let mut out = [0u8; 64];
    let mut res = ResBuf::new(&mut out);

    let mut sel = vec![0x00, 0xA4, 0x04, 0x00, 0x08];
    sel.extend_from_slice(&[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]);
    assert_eq!(disp.process(&sel, &mut applets, &mut (), &mut res), Sw::OK);

    // A chaining segment accumulates 0xAA 0xBB…
    assert_eq!(
        disp.process(
            &[0x10, 0x10, 0, 0, 0x02, 0xAA, 0xBB],
            &mut applets,
            &mut (),
            &mut res
        ),
        Sw::OK
    );
    // …then a fast-path interruption resets the incoming chain.
    disp.clear_chaining();

    // The next non-chained echo returns ONLY its own byte — the stale 0xAA 0xBB
    // is gone (without the reset it would echo 0xAA 0xBB 0xEE).
    assert_eq!(
        disp.process(
            &[0x00, 0x10, 0, 0, 0x01, 0xEE],
            &mut applets,
            &mut (),
            &mut res
        ),
        Sw::OK
    );
    assert_eq!(res.as_slice(), &[0xEE]);
}

#[test]
fn select_unknown_aid() {
    let mut echo = Echo { selected: false };
    let mut applets: [&mut dyn Applet<()>; 1] = [&mut echo];
    let mut disp = Dispatcher::new();
    let mut out = [0u8; 16];
    let mut res = ResBuf::new(&mut out);
    let sel = [0x00, 0xA4, 0x04, 0x00, 0x02, 0x12, 0x34];
    assert_eq!(
        disp.process(&sel, &mut applets, &mut (), &mut res),
        Sw::FILE_NOT_FOUND
    );
}

// Mimics OpenPGP/PIV: a current applet whose own SELECT handler answers a
// non-6D00 status (6A88, exactly as OpenPGP's `cmd_select` does) for a SELECT it
// does not recognise. Used to prove the dispatcher shadows it on a by-FID SELECT.
struct PickySelect;
impl Applet<()> for PickySelect {
    fn aid(&self) -> &'static [u8] {
        &[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x03]
    }
    fn select(&mut self, _reselect: bool, _ctx: &mut (), _res: &mut ResBuf) -> Sw {
        Sw::OK
    }
    fn process(&mut self, apdu: &Apdu, _ctx: &mut (), _res: &mut ResBuf) -> Sw {
        if apdu.ins == 0xA4 {
            Sw::REFERENCE_NOT_FOUND // 6A88 — what OpenPGP returns for a foreign SELECT
        } else {
            Sw::INS_NOT_SUPPORTED
        }
    }
}

#[test]
fn select_by_fid_is_unsupported_like_a_yubikey() {
    // GnuPG scdaemon probes a card with `SELECT 3F00` (P1=0x00, select the ISO
    // master file). A real YubiKey answers 6D00, which is the trigger for scdaemon
    // to recognise it and read its serial from the management applet. RS-Key is
    // applet-only (no MF), so the dispatcher must answer 6D00 *before* dispatch —
    // otherwise the current applet (OpenPGP) returns 6A88 and scdaemon shows a raw
    // serial and drops PIV (issue #44).
    let mut app = PickySelect;
    let mut applets: [&mut dyn Applet<()>; 1] = [&mut app];
    let mut disp = Dispatcher::new();
    let mut out = [0u8; 16];
    let mut res = ResBuf::new(&mut out);

    // 00 A4 00 0C 02 3F 00 — SELECT the master file by FID.
    let sel_mf = [0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00];

    // Answered 6D00 even with no applet selected.
    assert_eq!(
        disp.process(&sel_mf, &mut applets, &mut (), &mut res),
        Sw::INS_NOT_SUPPORTED
    );

    // Select the applet by AID (P1=0x04 still works), then probe by FID: the
    // dispatcher shadows the applet's 6A88 with 6D00.
    let sel_aid = [
        0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x03,
    ];
    assert_eq!(
        disp.process(&sel_aid, &mut applets, &mut (), &mut res),
        Sw::OK
    );
    assert_eq!(
        disp.process(&sel_mf, &mut applets, &mut (), &mut res),
        Sw::INS_NOT_SUPPORTED
    );
    // The by-AID selection survives — the FID probe did not deselect it.
    assert_eq!(disp.current(), Some(0));
}

// Models the OATH applet: INS 0xA4 is CALCULATE ALL (its own command, `p1=0 p2=1`),
// NOT a SELECT. The first cut of the issue-#44 fix blanket-shadowed `A4 p1=0` and
// wrongly returned 6D00 here, breaking OATH calculate-all (Yubico Authenticator).
struct Oathish;
impl Applet<()> for Oathish {
    fn aid(&self) -> &'static [u8] {
        &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01]
    }
    fn select(&mut self, _reselect: bool, _ctx: &mut (), _res: &mut ResBuf) -> Sw {
        Sw::OK
    }
    fn process(&mut self, apdu: &Apdu, _ctx: &mut (), res: &mut ResBuf) -> Sw {
        if apdu.ins == 0xA4 && apdu.p1 == 0x00 && apdu.p2 == 0x01 {
            res.push(0x99); // a CALCULATE ALL response body
            Sw::OK
        } else {
            Sw::INS_NOT_SUPPORTED
        }
    }
}

#[test]
fn oath_calculate_all_is_not_shadowed_by_the_select_mf_rule() {
    // INS 0xA4 is overloaded: OATH CALCULATE ALL is `00 A4 00 01 …`. The SELECT-MF
    // 6D00 rule (issue #44) keys on P2=0x0C, so CALCULATE ALL (P2=0x01) still
    // reaches the applet — a regression guard for the Yubico Authenticator.
    let mut app = Oathish;
    let mut applets: [&mut dyn Applet<()>; 1] = [&mut app];
    let mut disp = Dispatcher::new();
    let mut out = [0u8; 16];
    let mut res = ResBuf::new(&mut out);

    let sel = [
        0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01,
    ];
    assert_eq!(disp.process(&sel, &mut applets, &mut (), &mut res), Sw::OK);

    // CALCULATE ALL (A4 p1=00 p2=01) routes to the applet.
    let calc_all = [0x00, 0xA4, 0x00, 0x01, 0x02, 0x74, 0x00];
    assert_eq!(
        disp.process(&calc_all, &mut applets, &mut (), &mut res),
        Sw::OK
    );
    assert_eq!(res.as_slice(), &[0x99]);

    // But the master-file SELECT (P2=0x0C) is still shadowed with 6D00.
    let sel_mf = [0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00];
    assert_eq!(
        disp.process(&sel_mf, &mut applets, &mut (), &mut res),
        Sw::INS_NOT_SUPPORTED
    );
}

// Returns `body_len` bytes (value = index & 0xFF) for GET DATA (INS 0xCA);
// `chain` toggles opt-in to dispatcher response chaining.
struct Chunky {
    body_len: usize,
    chain: bool,
}
impl Applet<()> for Chunky {
    fn aid(&self) -> &'static [u8] {
        &[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x02]
    }
    fn select(&mut self, _reselect: bool, _ctx: &mut (), _res: &mut ResBuf) -> Sw {
        Sw::OK
    }
    fn response_chaining(&self) -> bool {
        self.chain
    }
    fn process(&mut self, apdu: &Apdu, _ctx: &mut (), res: &mut ResBuf) -> Sw {
        if apdu.ins == 0xCA {
            for i in 0..self.body_len {
                res.push((i & 0xFF) as u8);
            }
            Sw::OK
        } else {
            Sw::INS_NOT_SUPPORTED
        }
    }
}

fn select_chunky(disp: &mut Dispatcher, applets: &mut [&mut dyn Applet<()>], res: &mut ResBuf) {
    let sel = [
        0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x02,
    ];
    assert_eq!(disp.process(&sel, applets, &mut (), res), Sw::OK);
}

#[test]
fn short_le_response_is_chained_with_get_response() {
    let mut c = Chunky {
        body_len: 269,
        chain: true,
    };
    let mut applets: [&mut dyn Applet<()>; 1] = [&mut c];
    let mut disp = Dispatcher::new();
    let mut out = [0u8; 512];
    let mut res = ResBuf::new(&mut out);
    select_chunky(&mut disp, &mut applets, &mut res);

    // GET DATA, short Le=256 → first 256 bytes + 61 0D (13 more available).
    let sw = disp.process(
        &[0x00, 0xCA, 0x00, 0x00, 0x00],
        &mut applets,
        &mut (),
        &mut res,
    );
    assert_eq!(sw, Sw::new(0x61, 0x0D));
    assert_eq!(res.len(), 256);
    let mut got = res.as_slice().to_vec();

    // GET RESPONSE (Le=256) → remaining 13 bytes + 9000.
    let sw = disp.process(
        &[0x00, 0xC0, 0x00, 0x00, 0x00],
        &mut applets,
        &mut (),
        &mut res,
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(res.len(), 13);
    got.extend_from_slice(res.as_slice());

    let want: Vec<u8> = (0..269).map(|i| (i & 0xFF) as u8).collect();
    assert_eq!(got, want);
}

#[test]
fn get_response_honours_a_smaller_le() {
    let mut c = Chunky {
        body_len: 300,
        chain: true,
    };
    let mut applets: [&mut dyn Applet<()>; 1] = [&mut c];
    let mut disp = Dispatcher::new();
    let mut out = [0u8; 512];
    let mut res = ResBuf::new(&mut out);
    select_chunky(&mut disp, &mut applets, &mut res);

    // 300 > 256 → 256 + 61 2C (44 left).
    let sw = disp.process(
        &[0x00, 0xCA, 0x00, 0x00, 0x00],
        &mut applets,
        &mut (),
        &mut res,
    );
    assert_eq!(sw, Sw::new(0x61, 44));
    // Ask for only 20 of the 44 → 20 bytes + 61 18 (24 left).
    let sw = disp.process(
        &[0x00, 0xC0, 0x00, 0x00, 0x14],
        &mut applets,
        &mut (),
        &mut res,
    );
    assert_eq!(sw, Sw::new(0x61, 24));
    assert_eq!(res.len(), 20);
    // Drain the rest.
    let sw = disp.process(
        &[0x00, 0xC0, 0x00, 0x00, 0x00],
        &mut applets,
        &mut (),
        &mut res,
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(res.len(), 24);
}

#[test]
fn case3_no_le_large_response_is_chained() {
    // Regression (age-plugin-yubikey empty-slot bug): yubikey.rs sends GET DATA as
    // a case-3 APDU (command data, NO Le) and relies on 61xx response chaining to
    // read a slot certificate larger than 256 bytes. A no-Le command must chain,
    // not dump the whole oversized body — the client's short-APDU receive buffer
    // can't hold it, so it drops the slot and the identity shows as "(Empty)".
    let mut c = Chunky {
        body_len: 305,
        chain: true,
    };
    let mut applets: [&mut dyn Applet<()>; 1] = [&mut c];
    let mut disp = Dispatcher::new();
    let mut out = [0u8; 512];
    let mut res = ResBuf::new(&mut out);
    select_chunky(&mut disp, &mut applets, &mut res);

    // Case-3 GET DATA (Lc=3 data, no Le), body 305 > 256 → 256 bytes + 61 31 (49 left).
    let sw = disp.process(
        &[0x00, 0xCA, 0x00, 0x00, 0x03, 0x5F, 0xC1, 0x0D],
        &mut applets,
        &mut (),
        &mut res,
    );
    assert_eq!(
        sw,
        Sw::new(0x61, 49),
        "a no-Le command must chain a large body, not return it whole"
    );
    assert_eq!(res.len(), 256);
    let mut got = res.as_slice().to_vec();

    // GET RESPONSE drains the 49-byte tail.
    let sw = disp.process(
        &[0x00, 0xC0, 0x00, 0x00, 0x00],
        &mut applets,
        &mut (),
        &mut res,
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(res.len(), 49);
    got.extend_from_slice(res.as_slice());
    let want: Vec<u8> = (0..305).map(|i| (i & 0xFF) as u8).collect();
    assert_eq!(got, want);
}

#[test]
fn case3_no_le_small_response_is_not_chained() {
    // The flip side: a no-Le response that fits in the short maximum is returned
    // whole with 9000 — no needless chaining for the common small object.
    let mut c = Chunky {
        body_len: 40,
        chain: true,
    };
    let mut applets: [&mut dyn Applet<()>; 1] = [&mut c];
    let mut disp = Dispatcher::new();
    let mut out = [0u8; 512];
    let mut res = ResBuf::new(&mut out);
    select_chunky(&mut disp, &mut applets, &mut res);

    let sw = disp.process(
        &[0x00, 0xCA, 0x00, 0x00, 0x03, 0x5F, 0xC1, 0x0D],
        &mut applets,
        &mut (),
        &mut res,
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(res.len(), 40);
}

#[test]
fn extended_le_response_is_not_chained() {
    let mut c = Chunky {
        body_len: 269,
        chain: true,
    };
    let mut applets: [&mut dyn Applet<()>; 1] = [&mut c];
    let mut disp = Dispatcher::new();
    let mut out = [0u8; 512];
    let mut res = ResBuf::new(&mut out);
    select_chunky(&mut disp, &mut applets, &mut res);
    // Extended Le (65536) ≥ body → whole body, status unchanged.
    let sw = disp.process(
        &[0x00, 0xCA, 0x00, 0x00, 0x00, 0x00, 0x00],
        &mut applets,
        &mut (),
        &mut res,
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(res.len(), 269);
}

#[test]
fn set_enabled_hides_a_disabled_applet() {
    // A cleared enable bit makes an applet invisible: its AID matches nothing on
    // SELECT (FILE_NOT_FOUND), exactly as `ykman config usb --disable X` intends,
    // while its still-enabled neighbour selects and dispatches normally.
    let mut echo = Echo { selected: false }; // index 0
    let mut chunk = Chunky {
        body_len: 3,
        chain: false,
    }; // index 1
    let mut applets: [&mut dyn Applet<()>; 2] = [&mut echo, &mut chunk];
    let mut disp = Dispatcher::new();
    let mut out = [0u8; 64];
    let mut res = ResBuf::new(&mut out);

    disp.set_enabled(0b10); // disable index 0 (Echo), keep index 1 (Chunky)

    let mut sel0 = vec![0x00, 0xA4, 0x04, 0x00, 0x08];
    sel0.extend_from_slice(&[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]);
    assert_eq!(
        disp.process(&sel0, &mut applets, &mut (), &mut res),
        Sw::FILE_NOT_FOUND
    );
    assert_eq!(disp.current(), None);

    let sel1 = [
        0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x02,
    ];
    assert_eq!(disp.process(&sel1, &mut applets, &mut (), &mut res), Sw::OK);
    assert_eq!(disp.current(), Some(1));

    // Re-enable Echo and confirm it selects again — a disable is reversible.
    disp.set_enabled(u32::MAX);
    assert_eq!(disp.process(&sel0, &mut applets, &mut (), &mut res), Sw::OK);
    assert_eq!(disp.current(), Some(0));
}

#[test]
fn disabling_the_current_applet_makes_it_unreachable() {
    // The contrived window: an applet is selected, then disabled before its next
    // command (config changed over another transport). Dispatch-to-current
    // re-checks the enable bit, so the command finds nothing.
    let mut echo = Echo { selected: false };
    let mut applets: [&mut dyn Applet<()>; 1] = [&mut echo];
    let mut disp = Dispatcher::new();
    let mut out = [0u8; 64];
    let mut res = ResBuf::new(&mut out);

    let mut sel = vec![0x00, 0xA4, 0x04, 0x00, 0x08];
    sel.extend_from_slice(&[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]);
    assert_eq!(disp.process(&sel, &mut applets, &mut (), &mut res), Sw::OK);
    assert_eq!(disp.current(), Some(0));

    disp.set_enabled(0); // disabled since SELECT
    let cmd = [0x00, 0x10, 0x00, 0x00, 0x03, 0xDE, 0xAD, 0xBE];
    assert_eq!(
        disp.process(&cmd, &mut applets, &mut (), &mut res),
        Sw::FILE_NOT_FOUND
    );
}

#[test]
fn opt_out_applet_is_never_chained() {
    let mut c = Chunky {
        body_len: 269,
        chain: false,
    };
    let mut applets: [&mut dyn Applet<()>; 1] = [&mut c];
    let mut disp = Dispatcher::new();
    let mut out = [0u8; 512];
    let mut res = ResBuf::new(&mut out);
    select_chunky(&mut disp, &mut applets, &mut res);
    // Short Le, but opted out → full body returned, no 61xx.
    let sw = disp.process(
        &[0x00, 0xCA, 0x00, 0x00, 0x00],
        &mut applets,
        &mut (),
        &mut res,
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(res.len(), 269);
    // A stray GET RESPONSE with nothing pending falls through to the applet.
    let sw = disp.process(
        &[0x00, 0xC0, 0x00, 0x00, 0x00],
        &mut applets,
        &mut (),
        &mut res,
    );
    assert_eq!(sw, Sw::INS_NOT_SUPPORTED);
}

/// The held GET RESPONSE tail carries no owner, and needs none: every APDU that is
/// not a GET RESPONSE with bytes outstanding — a SELECT included — drops it before
/// anything is dispatched, so one applet's response can never be drained after a
/// switch to another. Pinned because the binding here is temporal, and a reader
/// looking for an owner field will not find one.
#[test]
fn a_select_drops_a_held_response_tail() {
    let mut chunk = Chunky {
        body_len: 269,
        chain: true,
    };
    let mut echo = Echo { selected: false };
    let mut applets: [&mut dyn Applet<()>; 2] = [&mut chunk, &mut echo];
    let mut disp = Dispatcher::new();
    let mut out = [0u8; 512];
    let mut res = ResBuf::new(&mut out);

    select_chunky(&mut disp, &mut applets, &mut res);
    // A body over the short Le leaves 13 bytes held for GET RESPONSE.
    assert_eq!(
        disp.process(
            &[0x00, 0xCA, 0x00, 0x00, 0x00],
            &mut applets,
            &mut (),
            &mut res
        ),
        Sw::new(0x61, 0x0D)
    );

    let sel_echo = [
        0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01,
    ];
    assert_eq!(
        disp.process(&sel_echo, &mut applets, &mut (), &mut res),
        Sw::OK
    );

    // The tail is gone, so GET RESPONSE reaches the newly selected applet — which
    // has no such instruction — instead of serving the previous applet's bytes.
    assert_eq!(
        disp.process(
            &[0x00, 0xC0, 0x00, 0x00, 0x00],
            &mut applets,
            &mut (),
            &mut res
        ),
        Sw::INS_NOT_SUPPORTED
    );
    assert!(
        res.is_empty(),
        "a previous applet's response tail survived a SELECT"
    );
}

/// An applet with a PIN-like security status, to prove a card reset clears it.
struct Verifiable {
    verified: bool,
}
impl Applet<()> for Verifiable {
    fn aid(&self) -> &'static [u8] {
        &[0xA0, 0x00, 0x00, 0x03, 0x08]
    }
    fn select(&mut self, _reselect: bool, _ctx: &mut (), _res: &mut ResBuf) -> Sw {
        self.verified = false;
        Sw::OK
    }
    fn deselect(&mut self, _ctx: &mut ()) {
        self.verified = false;
    }
    fn process(&mut self, apdu: &Apdu, _ctx: &mut (), _res: &mut ResBuf) -> Sw {
        match apdu.ins {
            // VERIFY: set the security status.
            0x20 => {
                self.verified = true;
                Sw::OK
            }
            // A privileged operation, allowed only while verified.
            0x87 if self.verified => Sw::OK,
            0x87 => Sw::SECURITY_STATUS_NOT_SATISFIED,
            // A SELECT that reaches `process` instead of the dispatcher, answered
            // the way OpenPGP's `cmd_select` does: prefix-match, so a buffer that
            // merely *starts* with this AID is accepted (audit run-37).
            0xA4 if apdu.data.starts_with(self.aid()) => Sw::OK,
            _ => Sw::INS_NOT_SUPPORTED,
        }
    }
}

/// run-26: an ICC power transition must clear the applet's security status, not
/// just the selection. `SCardDisconnect(SCARD_RESET_CARD)` is how a host forces
/// re-authentication, and OpenPGP 3.4 (VERIFY) plus NIST SP 800-73pt2-5 §2.3 both
/// require a reset to drop the verified PIN and return to the default application —
/// otherwise the next process to connect inherits an unlocked card.
#[test]
fn reset_card_clears_selection_and_security_status() {
    let mut piv = Verifiable { verified: false };
    let mut applets: [&mut dyn Applet<()>; 1] = [&mut piv];
    let mut disp = Dispatcher::new();
    let mut out = [0u8; 64];

    let aid = [0xA0, 0x00, 0x00, 0x03, 0x08];
    let mut select = vec![0x00, 0xA4, 0x04, 0x00, aid.len() as u8];
    select.extend_from_slice(&aid);

    // Select, verify, and confirm the privileged command is allowed.
    let mut res = ResBuf::new(&mut out);
    assert_eq!(
        disp.process(&select, &mut applets, &mut (), &mut res),
        Sw::OK
    );
    let mut res = ResBuf::new(&mut out);
    assert_eq!(
        disp.process(&[0x00, 0x20, 0, 0], &mut applets, &mut (), &mut res),
        Sw::OK
    );
    let mut res = ResBuf::new(&mut out);
    assert_eq!(
        disp.process(&[0x00, 0x87, 0, 0], &mut applets, &mut (), &mut res),
        Sw::OK
    );

    // The power transition.
    disp.reset_card(&mut applets, &mut ());

    // No applet is current, so the command does not even reach it...
    let mut res = ResBuf::new(&mut out);
    assert_eq!(
        disp.process(&[0x00, 0x87, 0, 0], &mut applets, &mut (), &mut res),
        Sw::FILE_NOT_FOUND
    );
    // ...and re-selecting without verifying is refused: the status really is gone,
    // which `clear_selection` alone would not have achieved.
    let mut res = ResBuf::new(&mut out);
    assert_eq!(
        disp.process(&select, &mut applets, &mut (), &mut res),
        Sw::OK
    );
    let mut res = ResBuf::new(&mut out);
    assert_eq!(
        disp.process(&[0x00, 0x87, 0, 0], &mut applets, &mut (), &mut res),
        Sw::SECURITY_STATUS_NOT_SATISFIED
    );
}

/// A SELECT terminates a live incoming chain instead of finishing it.
///
/// `chaining` is sticky, has no timeout and survives across PC/SC connections, so
/// one `CLA 0x10` APDU left by any process made the *next* process's opening
/// SELECT the chain terminator: the SELECT silently did not happen, and the victim
/// went on operating against whatever applet was already current — with PIV's
/// per-operation touch prompt naming the injector's data (audit run-34 #26).
#[test]
fn a_select_terminates_a_dangling_chain_instead_of_finishing_it() {
    let mut echo = Echo { selected: false };
    let mut applets: [&mut dyn Applet<()>; 1] = [&mut echo];
    let mut disp = Dispatcher::new();
    let mut out = [0u8; 64];
    let mut res = ResBuf::new(&mut out);

    let mut sel = vec![0x00, 0xA4, 0x04, 0x00, 0x08];
    sel.extend_from_slice(&[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]);
    assert_eq!(disp.process(&sel, &mut applets, &mut (), &mut res), Sw::OK);

    // An attacker leaves a chain segment dangling…
    assert_eq!(
        disp.process(
            &[0x10, 0x10, 0, 0, 0x02, 0xAA, 0xBB],
            &mut applets,
            &mut (),
            &mut res
        ),
        Sw::OK
    );
    // …and the victim's opening SELECT must be a SELECT, not the terminator.
    assert_eq!(disp.process(&sel, &mut applets, &mut (), &mut res), Sw::OK);
    assert!(
        !res.as_slice().starts_with(&[0xAA, 0xBB]),
        "the SELECT was swallowed as a chain terminator"
    );
    // The dangling segments are gone, so the next command carries only its own data.
    assert_eq!(
        disp.process(
            &[0x00, 0x10, 0, 0, 0x01, 0xEE],
            &mut applets,
            &mut (),
            &mut res
        ),
        Sw::OK
    );
    assert_eq!(res.as_slice(), &[0xEE], "stale segments prepended");
}

/// …and INS `0xA4` alone must NOT count as a SELECT: it is also YKOATH's
/// CALCULATE ALL (P1 `0x00`), so matching on the instruction byte would break
/// OATH — the reason this predicate tests the whole shape.
#[test]
fn is_select_matches_the_shape_not_the_instruction() {
    let sel = |p1, p2| {
        let raw = [0x00u8, 0xA4, p1, p2, 0x01, 0xAA];
        is_select(&Apdu::parse(&raw).unwrap())
    };
    assert!(sel(0x04, 0x00));
    assert!(sel(0x04, 0x04));
    // YKOATH CALCULATE ALL, and SELECT-by-path/FID variants no applet answers.
    assert!(!sel(0x00, 0x01));
    assert!(!sel(0x00, 0x00));
    assert!(!sel(0x04, 0x0C));
    // A different instruction entirely.
    let raw = [0x00u8, 0x10, 0x04, 0x00, 0x01, 0xAA];
    assert!(!is_select(&Apdu::parse(&raw).unwrap()));
}

/// Audit run-35: the SELECT terminator fix closed one instruction shape. A
/// dangling chain must not prefix ANY other command — the victim's own APDU was
/// otherwise appended to the attacker's buffer and dispatched as one, so a PIV
/// GENERAL AUTHENTICATE signed injected data under the victim's touch.
#[test]
fn a_dangling_chain_never_prefixes_another_command() {
    let mut disp = Dispatcher::new();
    let mut echo = Echo { selected: false };
    let mut applets: [&mut dyn Applet<()>; 1] = [&mut echo];
    let mut out = [0u8; 256];
    let mut res = ResBuf::new(&mut out);

    let mut sel = vec![0x00, 0xA4, 0x04, 0x00, 0x08];
    sel.extend_from_slice(&[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]);
    assert_eq!(disp.process(&sel, &mut applets, &mut (), &mut res), Sw::OK);

    // The attacker leaves one chaining segment behind.
    assert_eq!(
        disp.process(
            &[0x10, 0x10, 0, 0, 0x02, 0xAA, 0xBB],
            &mut applets,
            &mut (),
            &mut res
        ),
        Sw::OK
    );
    // The victim's next command is a DIFFERENT header. It must be refused, not
    // absorbed as the chain's final segment.
    assert_eq!(
        disp.process(
            &[0x00, 0x10, 0x01, 0, 0x01, 0xEE],
            &mut applets,
            &mut (),
            &mut res
        ),
        Sw::LAST_CHAIN_EXPECTED,
        "an unrelated command was absorbed as the chain terminator"
    );
    // …and the chain is gone, so the retry carries only the victim's own data.
    let mut out2 = [0u8; 256];
    let mut res2 = ResBuf::new(&mut out2);
    assert_eq!(
        disp.process(
            &[0x00, 0x10, 0x01, 0, 0x01, 0xEE],
            &mut applets,
            &mut (),
            &mut res2
        ),
        Sw::OK
    );
    assert_eq!(
        res2.as_slice(),
        &[0xEE],
        "the attacker's prefix survived into the victim's command"
    );
}

/// The legitimate terminator — same header, chaining bit clear — still completes
/// the chain. This is what OpenPGP RSA IMPORT sends, so a header-matching rule
/// that broke it would break on-card key import.
#[test]
fn the_openers_own_final_segment_still_completes_the_chain() {
    let mut disp = Dispatcher::new();
    let mut echo = Echo { selected: false };
    let mut applets: [&mut dyn Applet<()>; 1] = [&mut echo];
    let mut out = [0u8; 256];
    let mut res = ResBuf::new(&mut out);

    let mut sel = vec![0x00, 0xA4, 0x04, 0x00, 0x08];
    sel.extend_from_slice(&[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]);
    assert_eq!(disp.process(&sel, &mut applets, &mut (), &mut res), Sw::OK);

    assert_eq!(
        disp.process(
            &[0x10, 0x10, 0x22, 0x33, 0x02, 0xAA, 0xBB],
            &mut applets,
            &mut (),
            &mut res
        ),
        Sw::OK
    );
    let mut out2 = [0u8; 256];
    let mut res2 = ResBuf::new(&mut out2);
    assert_eq!(
        disp.process(
            &[0x00, 0x10, 0x22, 0x33, 0x01, 0xCC],
            &mut applets,
            &mut (),
            &mut res2
        ),
        Sw::OK
    );
    assert_eq!(
        res2.as_slice(),
        &[0xAA, 0xBB, 0xCC],
        "chain reassembly broke"
    );
}

/// Audit run-37: the SELECT carve-out fired only on a header MISMATCH, and
/// `10 A4 04 00` masks to exactly the header every SELECT-by-AID carries — the one
/// header an attacker would pick. The victim's SELECT was absorbed as that chain's
/// final segment and dispatched to the still-current applet, which prefix-matched
/// its own AID at offset 0 and answered 9000 with its PIN latch intact, so the
/// SELECT away silently did not happen.
#[test]
fn a_stranded_select_header_chain_does_not_swallow_the_next_select() {
    let mut piv = Verifiable { verified: false };
    let mut echo = Echo { selected: false };
    let mut disp = Dispatcher::new();
    let mut out = [0u8; 64];

    let sel_piv = [0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08];
    let sel_echo = [
        0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01,
    ];
    {
        let mut applets: [&mut dyn Applet<()>; 2] = [&mut piv, &mut echo];
        let mut res = ResBuf::new(&mut out);

        // The victim selects an applet and verifies its PIN.
        assert_eq!(
            disp.process(&sel_piv, &mut applets, &mut (), &mut res),
            Sw::OK
        );
        assert_eq!(
            disp.process(&[0x00, 0x20, 0, 0], &mut applets, &mut (), &mut res),
            Sw::OK
        );

        // The attacker strands one segment carrying the current applet's own AID.
        assert_eq!(
            disp.process(
                &[0x10, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08],
                &mut applets,
                &mut (),
                &mut res
            ),
            Sw::OK
        );

        // The victim's next SELECT must select, not terminate the chain.
        assert_eq!(
            disp.process(&sel_echo, &mut applets, &mut (), &mut res),
            Sw::OK
        );
        assert_eq!(
            disp.current(),
            Some(1),
            "the SELECT was swallowed as a chain terminator"
        );
    }
    assert!(
        echo.selected,
        "the victim's SELECT never reached its applet"
    );
    assert!(
        !piv.verified,
        "the previous applet kept its verified PIN across a SELECT away"
    );
}

/// …and the segments are bound to the opener too, not only the terminator. Without
/// that, a second process splices its own data into a live chain and the victim's
/// own final APDU dispatches the concatenation — the run-34 #26 primitive, reached
/// from the other end.
#[test]
fn a_mid_chain_header_change_drops_the_chain() {
    let mut echo = Echo { selected: false };
    let mut applets: [&mut dyn Applet<()>; 1] = [&mut echo];
    let mut disp = Dispatcher::new();
    let mut out = [0u8; 64];
    let mut res = ResBuf::new(&mut out);

    let mut sel = vec![0x00, 0xA4, 0x04, 0x00, 0x08];
    sel.extend_from_slice(&[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]);
    assert_eq!(disp.process(&sel, &mut applets, &mut (), &mut res), Sw::OK);

    // The victim opens a chain…
    assert_eq!(
        disp.process(
            &[0x10, 0x10, 0x22, 0x33, 0x02, 0xAA, 0xBB],
            &mut applets,
            &mut (),
            &mut res
        ),
        Sw::OK
    );
    // …and a segment with a different header must not join it.
    assert_eq!(
        disp.process(
            &[0x10, 0x10, 0x44, 0x55, 0x02, 0xCC, 0xDD],
            &mut applets,
            &mut (),
            &mut res
        ),
        Sw::LAST_CHAIN_EXPECTED,
        "a foreign segment was spliced into a live chain"
    );
    // The chain is gone, so the victim's own terminator is now a plain command
    // carrying only its own data.
    let mut out2 = [0u8; 64];
    let mut res2 = ResBuf::new(&mut out2);
    assert_eq!(
        disp.process(
            &[0x00, 0x10, 0x22, 0x33, 0x01, 0xEE],
            &mut applets,
            &mut (),
            &mut res2
        ),
        Sw::OK
    );
    assert_eq!(
        res2.as_slice(),
        &[0xEE],
        "the injected segments survived into the victim's command"
    );
}

/// SELECT-by-AID is ISO 7816-4 truncated matching: the requested AID must be a
/// PREFIX of a registered one, first match wins. The test used to be the other
/// way round — the candidate had to *start with* a registered AID — so every
/// applet answered to `its AID followed by anything`, and on PIV that selected
/// the AID SP 800-85A-4 C.1.1.2 names as invalid.
#[test]
fn select_matches_an_aid_by_prefix() {
    const ECHO_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];
    const OATH_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];
    let mut echo = Echo { selected: false };
    let mut oath = Oathish;
    let mut apps: [&mut dyn Applet<()>; 2] = [&mut echo, &mut oath];
    let mut d = Dispatcher::new();

    fn sel(aid: &[u8]) -> std::vec::Vec<u8> {
        let mut v = std::vec![0x00u8, 0xA4, 0x04, 0x00, aid.len() as u8];
        v.extend_from_slice(aid);
        v.push(0x00);
        v
    }
    fn go(d: &mut Dispatcher, apps: &mut [&mut dyn Applet<()>], raw: &[u8]) -> Sw {
        let mut buf = [0u8; 64];
        let mut res = ResBuf::new(&mut buf);
        d.process(raw, apps, &mut (), &mut res)
    }

    // The whole AID, and every prefix of it, select.
    for n in 1..=ECHO_AID.len() {
        assert_eq!(
            go(&mut d, &mut apps, &sel(&ECHO_AID[..n])),
            Sw::OK,
            "a {n}-byte prefix must select"
        );
    }
    // One byte MORE than the AID does not — the case that used to pass, and the
    // shape that let PIV answer to the AID SP 800-85A-4 calls invalid.
    let mut over = ECHO_AID.to_vec();
    over.push(0xFF);
    assert_eq!(go(&mut d, &mut apps, &sel(&over)), Sw::FILE_NOT_FOUND);
    // Nor does a value that diverges inside the AID.
    let mut wrong = ECHO_AID.to_vec();
    let last = wrong.len() - 1;
    wrong[last] ^= 0x01;
    assert_eq!(go(&mut d, &mut apps, &sel(&wrong)), Sw::FILE_NOT_FOUND);
    // An empty candidate is a prefix of everything, and is refused rather than
    // treated as ISO's "select the default application".
    assert_eq!(
        go(&mut d, &mut apps, &[0x00, 0xA4, 0x04, 0x00, 0x00]),
        Sw::FILE_NOT_FOUND
    );
    // A prefix both applets share resolves to the FIRST registered one, so the
    // registration order in `rsk-device` decides — worth pinning, because it is
    // the one thing about this rule a host cannot predict from its own AID.
    assert_eq!(
        ECHO_AID[..3],
        OATH_AID[..3],
        "the fixture needs a shared prefix"
    );
    assert_eq!(go(&mut d, &mut apps, &sel(&ECHO_AID[..3])), Sw::OK);
    assert_eq!(d.current(), Some(0), "the lower index wins a shared prefix");
}

/// The class byte, measured on a YubiKey 5.7.4 across PIV, OpenPGP and OATH: a
/// class asking for secure messaging is `6E00`, and the chaining bit is looked at
/// FIRST — `1C`, `90` and `FF` are plain segments there, not SM refusals.
#[test]
fn a_secure_messaging_class_is_refused() {
    let mut echo = Echo { selected: false };
    let mut apps: [&mut dyn Applet<()>; 1] = [&mut echo];
    let mut d = Dispatcher::new();

    fn go(d: &mut Dispatcher, apps: &mut [&mut dyn Applet<()>], raw: &[u8]) -> (Sw, usize) {
        let mut buf = [0u8; 64];
        let mut res = ResBuf::new(&mut buf);
        let sw = d.process(raw, apps, &mut (), &mut res);
        (sw, res.len())
    }
    let mut sel = std::vec![0x00u8, 0xA4, 0x04, 0x00, 0x08];
    sel.extend_from_slice(&[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]);
    assert_eq!(go(&mut d, &mut apps, &sel).0, Sw::OK);

    // 04 and 84 are the two the oracle could be asked directly (macOS PC/SC
    // refuses to transmit the rest); 0C and 8C are the ISO SM encodings the same
    // rule covers, and the applet must never see any of them.
    for cla in [0x04u8, 0x84, 0x0C, 0x8C, 0x4C] {
        assert_eq!(
            go(&mut d, &mut apps, &[cla, 0x10, 0, 0, 0x02, 0xAA, 0xBB]),
            (Sw::CLA_NOT_SUPPORTED, 0),
            "CLA {cla:02X} asks for secure messaging"
        );
    }
    // A SELECT is not privileged: the class is judged before the command is.
    let mut sm_sel = sel.clone();
    sm_sel[0] = 0x04;
    assert_eq!(
        go(&mut d, &mut apps, &sm_sel).0,
        Sw::CLA_NOT_SUPPORTED,
        "SELECT at an SM class"
    );

    // Everything the oracle serves must still be served, byte for byte.
    for cla in [0x00u8, 0x80, 0x40, 0xC0] {
        assert_eq!(
            go(&mut d, &mut apps, &[cla, 0x10, 0, 0, 0x02, 0xAA, 0xBB]),
            (Sw::OK, 2),
            "CLA {cla:02X} carries no SM indication"
        );
    }
    // …and the chaining bit still wins over it. `1C` answered as `6882`/`6E00`
    // would CREATE a divergence: the card takes it as an ordinary segment.
    for cla in [0x1Cu8, 0x90, 0xFF] {
        assert_eq!(
            go(&mut d, &mut apps, &[cla, 0x10, 0, 0, 0x02, 0xAA, 0xBB]),
            (Sw::OK, 0),
            "CLA {cla:02X} is a chaining segment"
        );
        d.clear_chaining();
    }
}

/// A chain that outgrows the reassembly buffer is a length error, and it is the
/// same length error whichever segment reaches the ceiling. The intermediate
/// segment answered `6E00` (CLA not supported) while the final one — fifty lines
/// down, same condition — answered `6700`, so one command had two answers and one
/// of them told the host its class byte was wrong. A YubiKey 5.7.4 answers `6700`
/// on the intermediate segment too, measured on a chained OpenPGP `PUT DATA` at
/// 3350 bytes and up (its own ceiling is around 3060 accumulated), both
/// authenticated and not.
#[test]
fn a_chain_past_the_reassembly_buffer_is_a_length_error_at_either_end() {
    let mut echo = Echo { selected: false };
    let mut applets: [&mut dyn Applet<()>; 1] = [&mut echo];
    let mut disp = Dispatcher::new();
    let mut out = [0u8; 64];
    let mut res = ResBuf::new(&mut out);

    let mut sel = vec![0x00, 0xA4, 0x04, 0x00, 0x08];
    sel.extend_from_slice(&[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]);
    assert_eq!(disp.process(&sel, &mut applets, &mut (), &mut res), Sw::OK);

    // Fill the buffer with whole segments, then overflow it on the next one.
    let seg = |n: usize| {
        let mut a = vec![0x10u8, 0x10, 0, 0, n as u8];
        a.extend(core::iter::repeat_n(0xA5, n));
        a
    };
    let mut sent = 0usize;
    while sent + 255 < CHAIN_BUF_SIZE {
        assert_eq!(
            disp.process(&seg(255), &mut applets, &mut (), &mut res),
            Sw::OK,
            "segment at {sent}"
        );
        sent += 255;
    }
    let over = CHAIN_BUF_SIZE - sent;
    assert!(
        over <= 255,
        "the last whole segment left {over} bytes of room"
    );
    assert_eq!(
        disp.process(&seg(over), &mut applets, &mut (), &mut res),
        Sw::WRONG_LENGTH,
        "an intermediate segment past the buffer"
    );

    // …and the chain is gone, so the next command starts clean rather than
    // dispatching the abandoned prefix. The probe carries a DIFFERENT P1: with
    // the segments' own header it masks to the chain's, so a dispatcher that
    // kept `chaining` would absorb it as a legitimate terminator and answer the
    // same `9000` with the same one byte — this assertion could not fail.
    assert_eq!(
        disp.process(
            &[0x00, 0x10, 0x01, 0, 0x01, 0xEE],
            &mut applets,
            &mut (),
            &mut res
        ),
        Sw::OK
    );
    assert_eq!(res.as_slice(), &[0xEE]);
    assert!(!disp.chaining && disp.chain_len == 0, "no chain survives");

    // The FINAL segment's overflow, which already answered `6700` — asserted so
    // the two ends cannot drift apart again.
    let mut sent = 0usize;
    while sent + 255 < CHAIN_BUF_SIZE {
        assert_eq!(
            disp.process(&seg(255), &mut applets, &mut (), &mut res),
            Sw::OK
        );
        sent += 255;
    }
    let mut last = vec![0x00u8, 0x10, 0, 0, 255];
    last.extend(core::iter::repeat_n(0xA5, 255));
    assert_eq!(
        disp.process(&last, &mut applets, &mut (), &mut res),
        Sw::WRONG_LENGTH,
        "a final segment past the buffer"
    );
}
