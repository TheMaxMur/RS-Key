// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The `Applet` trait plus AID-based SELECT and APDU dispatch.

use zeroize::Zeroize;

use crate::apdu::{Apdu, NE_SHORT_MAX};
use crate::sw::Sw;

/// A response buffer an applet writes its RAPDU body into. The status word is
/// appended by the dispatcher.
pub struct ResBuf<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> ResBuf<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        ResBuf { buf, len: 0 }
    }
    pub fn clear(&mut self) {
        self.len = 0;
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }
    /// Append one byte; returns false if the buffer is full.
    pub fn push(&mut self, b: u8) -> bool {
        if self.len < self.buf.len() {
            self.buf[self.len] = b;
            self.len += 1;
            true
        } else {
            false
        }
    }
    /// Append a slice; returns false (and writes nothing) if it would overflow.
    pub fn extend(&mut self, data: &[u8]) -> bool {
        if self.len + data.len() <= self.buf.len() {
            self.buf[self.len..self.len + data.len()].copy_from_slice(data);
            self.len += data.len();
            true
        } else {
            false
        }
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
    /// Shorten the body to `n` bytes (no-op when already `≤ n`).
    pub fn truncate(&mut self, n: usize) {
        if n < self.len {
            self.len = n;
        }
    }
}

/// A selectable smartcard applet.
///
/// `C` is a shared context (the file system in `firmware`) the dispatcher threads
/// into every call, so applets hold no `static mut` device state.
pub trait Applet<C> {
    /// The application identifier, without a length prefix. SELECT matches when
    /// this is a prefix of the requested AID.
    fn aid(&self) -> &'static [u8];
    /// Called on SELECT. `reselect` is true when this applet was already current.
    /// `res` receives the SELECT response body (e.g. an OpenPGP FCI); leave it
    /// empty for applets that return no data.
    fn select(&mut self, reselect: bool, ctx: &mut C, res: &mut ResBuf) -> Sw;
    /// Handle a non-SELECT command APDU.
    fn process(&mut self, apdu: &Apdu, ctx: &mut C, res: &mut ResBuf) -> Sw;
    /// Called when another applet is selected.
    fn deselect(&mut self, _ctx: &mut C) {}
    /// Whether the dispatcher may apply ISO 7816-4 outgoing response chaining
    /// (a `61xx` status + GET RESPONSE `0xC0` follow-ups) when a response body
    /// exceeds the command's short `Le`. Default off — only applets whose host
    /// stacks speak standard GET RESPONSE opt in (OpenPGP for `gpg`/`scdaemon`,
    /// PIV for OpenSC/`ykman`). OATH has its own SEND REMAINING (`0xA5`) scheme
    /// and stays off; the vendor/rescue tools use extended `Le` so never need it.
    fn response_chaining(&self) -> bool {
        false
    }
}

const CHAIN_BUF_SIZE: usize = 2038;
/// Holds the unsent tail of a response while the host fetches it with GET
/// RESPONSE. Sized to the largest response buffer a caller passes (the CCID
/// handler's 2046-byte body cap).
const RESP_CHAIN_CAP: usize = 2048;

/// `61 XX` bytes-remaining; SW2 saturates to `00` (= 256+ left) per ISO 7816-4.
const fn bytes_remaining(left: usize) -> Sw {
    Sw::new(0x61, if left > 0xFF { 0 } else { left as u8 })
}

/// Routes APDUs to applets: SELECT-by-AID, command chaining (CLA bit 0x10),
/// outgoing response chaining (`61xx` / GET RESPONSE), and dispatch to the
/// current applet.
/// A well-formed SELECT-by-AID.
///
/// Matched by *shape*, never by INS alone: `0xA4` is also YKOATH's CALCULATE ALL
/// (P1 `0x00`), so a blanket intercept on the instruction byte would break OATH.
fn is_select(apdu: &Apdu) -> bool {
    apdu.ins == 0xA4 && apdu.p1 == 0x04 && (apdu.p2 == 0x00 || apdu.p2 == 0x04)
}

pub struct Dispatcher {
    current: Option<usize>,
    chaining: bool,
    chain: [u8; CHAIN_BUF_SIZE],
    chain_len: usize,
    /// Outgoing response chaining: when an opted-in applet's body exceeds the
    /// command's short `Le`, the first `Le` bytes ship with `61xx` and this
    /// holds the remainder for the GET RESPONSE (`0xC0`) follow-ups.
    pending: [u8; RESP_CHAIN_CAP],
    pending_len: usize,
    pending_off: usize,
    pending_sw: Sw,
    /// Bit `i` set → applet index `i` is selectable; cleared → invisible. Set by
    /// [`Self::set_enabled`] from the persisted enabled-applications config;
    /// defaults to all-active so callers that never restrict are unaffected.
    enabled: u32,
}

impl Default for Dispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Dispatcher {
    pub const fn new() -> Self {
        Dispatcher {
            current: None,
            chaining: false,
            chain: [0u8; CHAIN_BUF_SIZE],
            chain_len: 0,
            pending: [0u8; RESP_CHAIN_CAP],
            pending_len: 0,
            pending_off: 0,
            pending_sw: Sw::OK,
            enabled: u32::MAX,
        }
    }

    /// Index of the currently selected applet, if any.
    pub fn current(&self) -> Option<usize> {
        self.current
    }

    /// Restrict which registered applets are selectable: bit `i` set → applet
    /// index `i` is active; cleared → invisible (SELECT and any command to it
    /// return `FILE_NOT_FOUND`, exactly as if it were not registered). Indices
    /// `≥ 32` are always active. The firmware sets this from the persisted
    /// enabled-applications config, so `ykman config usb --disable X` really
    /// removes X's applet rather than only hiding it from the DeviceInfo report.
    pub fn set_enabled(&mut self, mask: u32) {
        self.enabled = mask;
    }

    /// Whether applet index `i` is currently active (see [`Self::set_enabled`]).
    fn selectable(&self, i: usize) -> bool {
        i >= 32 || self.enabled & (1 << i) != 0
    }

    /// Drop any selected applet. Used when a fresh logical session begins (a
    /// CTAPHID_INIT): U2F/CTAP1 has no SELECT of its own and must not inherit a
    /// vendor-AID selection left over from an earlier session on this transport.
    pub fn clear_selection(&mut self) {
        self.current = None;
    }

    /// Return the card to a clean state after an ICC reset: deselect the current
    /// applet — so it drops its security status, which [`clear_selection`] alone
    /// does not — and discard any buffered chain or pending response.
    ///
    /// `clear_selection` exists for CTAPHID_INIT, where only the *selection* is
    /// stale. A power transition is stronger: OpenPGP 3.4 (VERIFY) and NIST
    /// SP 800-73pt2-5 §2.3 both require a reset to clear the applet's verified PIN
    /// state and return to the default application.
    pub fn reset_card<C>(&mut self, applets: &mut [&mut dyn Applet<C>], ctx: &mut C) {
        if let Some(i) = self.current.take()
            && let Some(applet) = applets.get_mut(i)
        {
            applet.deselect(ctx);
        }
        self.clear_pending();
        self.clear_chaining();
    }

    /// Process one raw command APDU against `applets` (in registration order),
    /// threading the shared `ctx` into the dispatched applet, writing the
    /// response body into `res` and returning the status word.
    pub fn process<C>(
        &mut self,
        raw: &[u8],
        applets: &mut [&mut dyn Applet<C>],
        ctx: &mut C,
        res: &mut ResBuf,
    ) -> Sw {
        res.clear();
        let apdu = match Apdu::parse(raw) {
            Ok(a) => a,
            Err(_) => return Sw::WRONG_LENGTH,
        };

        // GET RESPONSE (0xC0): hand back the next slice of a chained response
        // before touching the applets — it is a transport command, not theirs.
        if apdu.ins == 0xC0 && self.pending_off < self.pending_len {
            return self.serve_pending(apdu.ne, res);
        }
        // Any other command abandons a partially-read chained response.
        self.clear_pending();

        // Command chaining: accumulate and acknowledge.
        if apdu.is_chaining() {
            if !self.chaining {
                self.chain_len = 0;
            }
            if self.chain_len + apdu.nc >= self.chain.len() {
                // The accumulated segments may already hold key material.
                self.chain[..self.chain_len].zeroize();
                self.chain_len = 0;
                self.chaining = false;
                return Sw::CLA_NOT_SUPPORTED;
            }
            self.chain[self.chain_len..self.chain_len + apdu.nc].copy_from_slice(apdu.data);
            self.chain_len += apdu.nc;
            self.chaining = true;
            return Sw::OK;
        }
        // A SELECT is never a chain continuation, so it terminates one instead of
        // finishing it. `chaining` is sticky, has no timeout and survives across
        // PC/SC connections, so a single `CLA 0x10` APDU made the *next* process's
        // opening SELECT the terminator: that SELECT silently did not happen and
        // the victim went on operating against the attacker's applet, with PIV's
        // per-operation touch prompt naming the injector's data (audit run-34 #26).
        // The old code asserted "SELECT is never chained" in a comment and enforced
        // nothing.
        if self.chaining && is_select(&apdu) {
            self.chain[..self.chain_len].zeroize();
            self.chain_len = 0;
            self.chaining = false;
        }

        // A non-chained APDU after chaining segments is the final one: append its
        // data and dispatch the reassembled command (needed by OpenPGP RSA IMPORT,
        // whose extended header list exceeds 255 bytes).
        if self.chaining {
            if self.chain_len + apdu.nc > self.chain.len() {
                self.chain[..self.chain_len].zeroize();
                self.chain_len = 0;
                self.chaining = false;
                return Sw::WRONG_LENGTH;
            }
            self.chain[self.chain_len..self.chain_len + apdu.nc].copy_from_slice(apdu.data);
            let total = self.chain_len + apdu.nc;
            self.chaining = false;
            self.chain_len = 0;
            let combined = Apdu {
                cla: apdu.cla,
                ins: apdu.ins,
                p1: apdu.p1,
                p2: apdu.p2,
                nc: total,
                ne: apdu.ne,
                data: &self.chain[..total],
            };
            // A disabled current applet is unreachable, like a dropped selection.
            let cur = self.current.filter(|&i| self.selectable(i));
            let chain_ok = cur.map(|i| applets[i].response_chaining()).unwrap_or(false);
            let sw = match cur {
                Some(i) => applets[i].process(&combined, ctx, res),
                None => Sw::FILE_NOT_FOUND,
            };
            // A chained command can carry private-key IMPORT data.
            self.chain[..total].zeroize();
            return self.maybe_chain(sw, apdu.ne, chain_ok, res);
        }

        // SELECT by AID. A disabled applet is skipped, so its AID matches nothing
        // (→ FILE_NOT_FOUND) just as if it were never registered.
        if is_select(&apdu) {
            let found = applets.iter().enumerate().position(|(i, app)| {
                let aid = app.aid();
                self.selectable(i) && apdu.data.len() >= aid.len() && &apdu.data[..aid.len()] == aid
            });
            return match found {
                Some(i) => {
                    let reselect = self.current == Some(i);
                    if let Some(c) = self.current
                        && c != i
                    {
                        applets[c].deselect(ctx);
                    }
                    self.current = Some(i);
                    let chain_ok = applets[i].response_chaining();
                    let sw = applets[i].select(reselect, ctx, res);
                    self.maybe_chain(sw, apdu.ne, chain_ok, res)
                }
                None => Sw::FILE_NOT_FOUND,
            };
        }

        // The master-file SELECT (`00 A4 00 0C …`, GnuPG scdaemon's `3F00` probe)
        // must answer 6D00 like a YubiKey, or scdaemon skips its YubiKey detection
        // and shows a raw serial (issue #44). Key on P2=0x0C (SELECT, no response
        // data): INS 0xA4 is overloaded — OATH reuses it for CALCULATE ALL
        // (`A4 p1=00 p2=01`), which must still reach the applet, not be shadowed.
        if apdu.ins == 0xA4 && apdu.p1 == 0x00 && apdu.p2 == 0x0C {
            return Sw::INS_NOT_SUPPORTED;
        }

        // Dispatch to the selected applet (unless it was disabled since SELECT).
        match self.current {
            Some(i) if self.selectable(i) => {
                let chain_ok = applets[i].response_chaining();
                let sw = applets[i].process(&apdu, ctx, res);
                self.maybe_chain(sw, apdu.ne, chain_ok, res)
            }
            _ => Sw::FILE_NOT_FOUND,
        }
    }

    /// Drop any held GET RESPONSE remainder, scrubbing it (it can be PSO output).
    /// Public so a transport that short-circuits [`Self::process`] (the firmware's
    /// dual-core RSA-keygen fast path) can drop a stale chained-response tail the
    /// way a normal dispatch would.
    pub fn clear_pending(&mut self) {
        if self.pending_len > 0 {
            self.pending[..self.pending_len].zeroize();
        }
        self.pending_len = 0;
        self.pending_off = 0;
    }

    /// Drop any half-accumulated incoming command chain, scrubbing it (chained
    /// segments can hold private-key IMPORT data). Public for the same reason as
    /// [`Self::clear_pending`]: a transport that short-circuits [`Self::process`]
    /// (the RSA-keygen fast path) must reset the incoming chaining state too, so a
    /// stale chain cannot concatenate onto a later command.
    pub fn clear_chaining(&mut self) {
        if self.chain_len > 0 {
            self.chain[..self.chain_len].zeroize();
        }
        self.chain_len = 0;
        self.chaining = false;
    }

    /// Serve the next chunk of a chained response to a GET RESPONSE (`0xC0`).
    /// Returns `61xx` while bytes remain, then the original status word.
    fn serve_pending(&mut self, ne: usize, res: &mut ResBuf) -> Sw {
        let want = if ne == 0 { NE_SHORT_MAX } else { ne };
        let remaining = self.pending_len - self.pending_off;
        let take = want.min(remaining);
        res.extend(&self.pending[self.pending_off..self.pending_off + take]);
        self.pending_off += take;
        let left = self.pending_len - self.pending_off;
        if left > 0 {
            bytes_remaining(left)
        } else {
            let sw = self.pending_sw;
            self.clear_pending();
            sw
        }
    }

    /// If an opted-in applet's success body overruns the command's short `Le`,
    /// hold the tail for GET RESPONSE and ship the first `Le` bytes with `61xx`.
    /// Otherwise the response (and status) pass through unchanged — so extended
    /// `Le` consumers (ykman, our APDU tests) and non-chaining applets are
    /// byte-for-byte unaffected.
    ///
    /// `ne == 0` is a case-3 command (data, no `Le`): ISO 7816-4 still caps its
    /// response at the short maximum, so a larger body must chain via `61xx` too.
    /// yubikey.rs / age-plugin read slot certs this way and drop any slot whose
    /// cert overruns 256 bytes if we dump it whole instead of chaining.
    fn maybe_chain(&mut self, sw: Sw, ne: usize, chaining_ok: bool, res: &mut ResBuf) -> Sw {
        let ne = if ne == 0 { NE_SHORT_MAX } else { ne };
        if !chaining_ok || !sw.is_ok() || res.len() <= ne {
            return sw;
        }
        let tail_len = res.len() - ne;
        if tail_len > self.pending.len() {
            // Cannot buffer the remainder; leave the response intact (legacy).
            return sw;
        }
        self.pending[..tail_len].copy_from_slice(&res.as_slice()[ne..]);
        self.pending_len = tail_len;
        self.pending_off = 0;
        self.pending_sw = sw;
        res.truncate(ne);
        bytes_remaining(tail_len)
    }
}

#[cfg(test)]
#[path = "applet_tests.rs"]
mod tests;
