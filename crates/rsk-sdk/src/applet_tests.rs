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
