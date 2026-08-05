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
