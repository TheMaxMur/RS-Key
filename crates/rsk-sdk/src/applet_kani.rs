// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Kani harnesses for the dispatcher, and the home of the `cfg(kani)` shrink of
//! [`CHAIN_BUF_SIZE`]/[`RESP_CHAIN_CAP`] that makes them runnable.
//!
//! **Why the shrink is sound.** Not because the sizes are "only read through
//! overflow guards": source coverage shows both guard branches UNCOVERED at 16
//! and at 2038 alike. It is the *window*. A raw APDU of at most 6 bytes with a
//! short `Lc` needs `5 + Nc <= 6`, so `Nc <= 1` per command and `chain_len <= 2`
//! over the pair — as far under 16 as under 2038, reaching the same branches by
//! the same route. The shrink therefore cannot change which paths are proven; it
//! changes only how many bits CBMC blasts to get there.
//!
//! **Why it is not optional.** At the real sizes the harness peaks at 17.5 GiB
//! and then spends 656 s in propositional reduction before CBMC's allocator
//! dies — above the whole memory of the `ubuntu-latest` runner the daily row
//! uses. Worse, it dies printing `VERIFICATION:- FAILED` with *no* `Failed
//! Checks:` line, which a grep for `FAILED` reads as a property violation.
//!
//! **The shrink and [`two_command_sequence_never_splices`]'s `unwind(6)` are one
//! knob, not two:** at 2038 the run also hits `Not unwinding loop memcmp.0
//! iteration 6`, where the 16-byte build needs 2. Changing either means
//! re-measuring both.
//!
//! Firmware is unaffected — rustc never sets `cfg(kani)`, so the image is
//! byte-identical and no `bcdDevice` bump is owed.

use super::*;

/// Two bytes is the shortest AID a non-empty SELECT candidate can prefix both
/// wholly and partially; every extra byte only widens the SELECT search's
/// comparison.
const STUB_AID: [u8; 2] = [0xA0, 0x01];

/// A concrete SELECT for [`STUB_AID`]. The symbolic part of the proof starts
/// from a *selected* card because that is the only state in which the applet
/// can be reached at all: with nothing selected every dispatch path answers
/// `FILE_NOT_FOUND` without calling the applet, so a two-command symbolic
/// sequence could not express a splice even in a dispatcher that permitted one.
const SELECT_STUB: [u8; 7] = [0x00, 0xA4, 0x04, 0x00, 0x02, 0xA0, 0x01];

/// Records what the dispatcher actually handed the applet, and nothing else:
/// it writes no response body and opts out of response chaining, so the only
/// state the proof observes is the dispatcher's own.
struct Stub {
    /// `Some(nc)` once `process` has run; the harness clears it between
    /// commands so the last command's dispatch is distinguishable.
    seen_nc: Option<usize>,
    selected: bool,
}

impl Applet<()> for Stub {
    fn aid(&self) -> &'static [u8] {
        &STUB_AID
    }
    fn select(&mut self, _reselect: bool, _ctx: &mut (), _res: &mut ResBuf) -> Sw {
        self.selected = true;
        Sw::OK
    }
    fn process(&mut self, apdu: &Apdu, _ctx: &mut (), _res: &mut ResBuf) -> Sw {
        self.seen_nc = Some(apdu.nc);
        Sw::OK
    }
}

/// The ISO 7816-4 §5.1.1.1 identity of a chain: the header with the chaining
/// bit masked out, so an opener and its terminator compare equal.
fn masked_hdr(a: &Apdu) -> (u8, u8, u8, u8) {
    (a.cla & !0x10, a.ins, a.p1, a.p2)
}

/// The dispatcher's buffer accounting, checked after every command.
///
/// ⚠️ Only the first two lines carry weight here. [`Stub`] leaves
/// `response_chaining()` at its default `false`, so `maybe_chain` never buffers
/// and `serve_pending` is never reached: `pending_off` and `pending_len` are
/// identically 0 and the last two assertions are vacuous. They are kept as the
/// shape a second, chaining stub would have to satisfy, not as evidence about
/// the outgoing half — which this proof does not cover at all.
fn buffers_sane(d: &Dispatcher) {
    assert!(d.chain_len <= CHAIN_BUF_SIZE);
    // A dropped chain leaves nothing behind — every refusal path must clear the
    // length as well as the flag, or the bytes stay reachable by a later reopen.
    assert!(d.chaining || d.chain_len == 0);
    assert!(d.pending_off <= d.pending_len);
    assert!(d.pending_len <= RESP_CHAIN_CAP);
}

/// Drive the real [`Dispatcher`] over a selected card and EVERY pair of raw
/// command APDUs up to 6 bytes each: it never panics, its buffer accounting
/// stays in bounds, **the applet is never handed bytes from a command it did
/// not itself terminate**, a secure-messaging class reaches no applet, and a
/// SELECT-by-AID is always a SELECT.
///
/// The third clause is the invariant with the worst history in this file, and
/// it is stated over the *sequence* rather than over any one branch: whatever
/// the first command was, the `Nc` the applet sees for the second is that
/// command's own `Nc` — unless the pair is a legitimate ISO 7816-4 chain (the
/// first sets `CLA 0x10`, the second clears it and repeats the header, and the
/// second is not a SELECT), in which case it is exactly the sum. There is no
/// third possibility, so no sequence can splice one client's data onto
/// another's command (audit run-34 #26, and run-35 for the non-SELECT half).
///
/// The fourth pins the class-byte rule the dispatcher now owns for every
/// applet: `CLA & 0x0C` without the chaining bit is refused before dispatch,
/// so a client that believes it negotiated secure messaging can never be
/// answered in the clear. It is also why the fifth clause has to exclude those
/// classes — a SELECT is not exempt from it.
///
/// The fifth is run-37 stated positively: a well-formed SELECT for a
/// registered AID reaches the applet, whatever chain state it walks into.
/// `10 A4 04 00` masks to every SELECT-by-AID's own header, so a rule that
/// only fired on a header *mismatch* let a stranded segment swallow the SELECT
/// and leave the previous applet current and still PIN-verified.
///
/// `Nc` is never assumed: it follows from the raw bytes (a short-`Lc` command
/// needs `5 + Nc <= 6`, so `Nc <= 1` here), which is also where the unwind
/// bound comes from — the longest loop is `zeroize` over the reassembled chain,
/// at most `1 + 1` bytes, and the widest fixed-size comparison is the 4-byte
/// chain header, so 4 iterations, bound 6.
#[kani::proof]
#[kani::unwind(6)]
fn two_command_sequence_never_splices() {
    // 6 bytes is the shortest APDU carrying a data field (`4 + Lc + 1`), and one
    // byte of an attacker's data is all a splice needs; a wider window costs
    // solver memory without reaching a state the narrow one cannot.
    const N: usize = 6;
    let raw1: [u8; N] = kani::any();
    let raw2: [u8; N] = kani::any();
    let n1: usize = kani::any();
    let n2: usize = kani::any();
    // The only assumption: each command is at most N raw bytes. Everything
    // shorter is included, so the under-4-byte parse rejection is covered too.
    kani::assume(n1 <= N);
    kani::assume(n2 <= N);

    let mut stub = Stub {
        seen_nc: None,
        selected: false,
    };
    let mut disp = Dispatcher::new();
    let mut out = [0u8; N];
    let mut res = ResBuf::new(&mut out);

    {
        let mut applets: [&mut dyn Applet<()>; 1] = [&mut stub];
        assert_eq!(
            disp.process(&SELECT_STUB, &mut applets, &mut (), &mut res),
            Sw::OK
        );
        disp.process(&raw1[..n1], &mut applets, &mut (), &mut res);
    }
    buffers_sane(&disp);

    stub.seen_nc = None;
    stub.selected = false;
    {
        let mut applets: [&mut dyn Applet<()>; 1] = [&mut stub];
        disp.process(&raw2[..n2], &mut applets, &mut (), &mut res);
    }
    buffers_sane(&disp);

    let a1 = Apdu::parse(&raw1[..n1]);
    let a2 = Apdu::parse(&raw2[..n2]);

    if let Some(n) = stub.seen_nc {
        let Ok(y) = a2 else {
            panic!("a command that does not parse reached the applet");
        };
        let terminator = match a1 {
            Ok(x) => {
                x.is_chaining()
                    && !y.is_chaining()
                    && !is_select(&y)
                    && masked_hdr(&x) == masked_hdr(&y)
                    && n == x.nc + y.nc
            }
            Err(_) => false,
        };
        assert!(
            n == y.nc || terminator,
            "the applet was handed a body that is not the command's own"
        );
        // Both sides of that disjunction have to be reachable, or the clause is
        // satisfied by an implementation that never dispatches anything.
        kani::cover!(terminator);
        kani::cover!(n == y.nc && n > 0);
    }

    if let Ok(y) = a2
        && !y.is_chaining()
        && y.is_secure_messaging()
    {
        assert!(
            stub.seen_nc.is_none() && !stub.selected,
            "a secure-messaging class reached the applet"
        );
        // …including the SELECT shape, which is the exemption a class check is
        // most likely to grow.
        kani::cover!(is_select(&y));
    }

    if let Ok(y) = a2
        && !y.is_chaining()
        && !y.is_secure_messaging()
        && is_select(&y)
        && !y.data.is_empty()
        && STUB_AID.starts_with(y.data)
    {
        assert_eq!(
            disp.current(),
            Some(0),
            "a SELECT for a registered AID did not select it"
        );
        assert!(stub.selected, "the SELECT never reached the applet");
        // …including when it walks into a live chain, which is the run-37 case.
        kani::cover!(a1.map(|x| x.is_chaining()).unwrap_or(false));
    }
}
