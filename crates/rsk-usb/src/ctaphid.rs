// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! CTAPHID transport. Frames are 64-byte HID reports:
//! - INIT frame:  cid(4) | cmd(1, bit7=1) | bcnt_hi(1) | bcnt_lo(1) | data(57)
//! - CONT frame:  cid(4) | seq(1, bit7=0) | data(59)
//!
//! [`Reassembler`] (RX) and [`TxFrames`] (TX) are pure and HAL-free — unit-tested
//! and fuzzed on the host; [`CtapHid`] is the async wrapper around them. Native
//! commands (INIT, PING, WINK, LOCK, VERSION, UUID, CANCEL) are answered in the
//! transport; MSG (U2F APDU) and CBOR (CTAP2) route to a [`MsgHandler`].

use core::future::Future;

use embassy_futures::select::{Either, Either3, select, select3};
use embassy_time::{Instant, Timer};
use embassy_usb::class::hid::{HidReader, HidWriter};
use embassy_usb::driver::Driver;

pub const HID_RPT_SIZE: usize = 64;
const INIT_DATA: usize = HID_RPT_SIZE - 7; // 57
const CONT_DATA: usize = HID_RPT_SIZE - 5; // 59

pub const CID_BROADCAST: u32 = 0xffff_ffff;
pub const TYPE_INIT: u8 = 0x80;

// Command constants keep the TYPE_INIT bit set. Public because the transport's
// second implementation — `tools/emu`, which speaks CTAPHID over a socket — has
// to name the same commands, and a protocol vocabulary defined twice is a
// vocabulary that drifts.
pub const CTAPHID_PING: u8 = TYPE_INIT | 0x01;
pub const CTAPHID_MSG: u8 = TYPE_INIT | 0x03;
pub const CTAPHID_LOCK: u8 = TYPE_INIT | 0x04;
pub const CTAPHID_INIT: u8 = TYPE_INIT | 0x06;
pub const CTAPHID_WINK: u8 = TYPE_INIT | 0x08;
pub const CTAPHID_CBOR: u8 = TYPE_INIT | 0x10;
pub const CTAPHID_CANCEL: u8 = TYPE_INIT | 0x11;
pub const CTAPHID_SYNC: u8 = TYPE_INIT | 0x3c;
pub const CTAPHID_ERROR: u8 = TYPE_INIT | 0x3f;
pub const CTAPHID_VERSION: u8 = TYPE_INIT | 0x61;
pub const CTAPHID_UUID: u8 = TYPE_INIT | 0x62;
pub const CTAPHID_KEEPALIVE: u8 = TYPE_INIT | 0x3b; // 0xBB
pub const CTAPHID_VENDOR_FIRST: u8 = TYPE_INIT | 0x40;

// Low-level CTAP1 error codes.
pub const ERR_INVALID_CMD: u8 = 0x01;
pub const ERR_INVALID_PAR: u8 = 0x02;
pub const ERR_INVALID_LEN: u8 = 0x03;
pub const ERR_INVALID_SEQ: u8 = 0x04;
pub const ERR_MSG_TIMEOUT: u8 = 0x05;
pub const ERR_CHANNEL_BUSY: u8 = 0x06;
pub const ERR_INVALID_CHANNEL: u8 = 0x0b;

// KEEPALIVE status byte: the authenticator is still processing the request.
pub const STATUS_PROCESSING: u8 = 0x01;
// KEEPALIVE status byte: waiting for a user-presence touch (clients show "touch
// your security key"); selected over PROCESSING via the `up_pending` hook.
pub const STATUS_UPNEEDED: u8 = 0x02;
// Stream a KEEPALIVE this often while the worker runs a long synchronous op
// (slow P-521, flash GC) — well under any host CTAP timeout.
pub const KEEPALIVE_MS: u64 = 100;

/// Which keepalive status to stream while a request is in flight, or `None` to
/// stay silent. U2F (MSG) is fast apart from the touch wait, and U2FHID hosts —
/// including the FIDO conformance tool — mishandle a `PROCESSING` keepalive sent
/// before a quick MSG response (check-only, unknown handle): they read it as the
/// response's first frame and desync ("sequence out of order"). So for MSG only
/// ever signal UP-needed; CBOR (CTAP2) keeps `PROCESSING` for its genuinely slow
/// operations (P-521, resident makeCredential, flash GC).
pub fn keepalive_status(is_cbor: bool, up_pending: bool) -> Option<u8> {
    if up_pending {
        Some(STATUS_UPNEEDED)
    } else if is_cbor {
        Some(STATUS_PROCESSING)
    } else {
        None
    }
}

/// Whether a report read while a request is in flight is a `CTAPHID_CANCEL` for
/// the active channel `cid` — the signal to abort the worker's user-presence
/// wait. `n` is the number of bytes read. The transport reads frames
/// concurrently with the worker only to catch this; everything else is ignored.
///
/// Public because `tools/emu` has to make the same judgement on its own socket:
/// the CANCEL rule is one sentence of protocol, and a second copy of it is a
/// second thing to keep in step.
pub fn is_cancel_frame(frame: &[u8; HID_RPT_SIZE], n: usize, cid: u32) -> bool {
    n >= 5
        && frame[4] == CTAPHID_CANCEL
        && u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]) == cid
}
// Abort an in-progress reassembly if the next frame is this late.
const RX_TIMEOUT_MS: u64 = 500;
// Abandon a response if the host stops draining the IN endpoint for this long.
// `HidWriter::write` only completes once the host reads the report, so a client
// that walks away mid-response would otherwise block the transport task forever
// (it then stops reading OUT → every further host write NAKs → the whole FIDO
// interface wedges until a replug). The host polls FIDO HID every few ms, so a
// gap this long means it is gone.
use crate::TX_TIMEOUT_MS;

pub const CTAPHID_IF_VERSION: u8 = 2;
pub const CAPFLAG_WINK: u8 = 0x01;
pub const CAPFLAG_LOCK: u8 = 0x02;
pub const CAPFLAG_CBOR: u8 = 0x04;

// Device version reported in CTAPHID_INIT / CTAPHID_VERSION — the shared firmware
// version (default 5.7.4). ykman/yubikit read these three bytes from the INIT
// response as the device firmware version and require >= 4.1.0 before they will
// read the YubiKey Management DeviceInfo over the FIDO interface.
const VERSION_MAJOR: u8 = rsk_sdk::FIRMWARE_VERSION.0;
const VERSION_MINOR: u8 = rsk_sdk::FIRMWARE_VERSION.1;
const VERSION_BUILD: u8 = rsk_sdk::FIRMWARE_VERSION.2;

// The first channel id CTAPHID_INIT hands out; each further allocation takes the
// next one (§11.2.9.1.3 wants a *unique* CID per requesting application).
const FIRST_CID: u32 = 0x0100_0000;

/// Hands out unique channel ids. §11.2.9.1.3: an INIT on the broadcast CID "requests
/// the device to allocate a unique 32-bit channel identifier (CID) that can be used
/// by the requesting application during its lifetime" — sharing one id between two
/// applications lets either one resynchronise the other's channel.
pub struct CidAllocator(u32);

impl Default for CidAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl CidAllocator {
    pub const fn new() -> Self {
        Self(FIRST_CID)
    }

    /// The next free id, skipping the two reserved values (0 and the broadcast CID)
    /// as the counter wraps.
    pub fn allocate(&mut self) -> u32 {
        let cid = self.0;
        self.0 = match self.0.wrapping_add(1) {
            0 | CID_BROADCAST => FIRST_CID,
            n => n,
        };
        cid
    }
}

/// The `CTAPHID_LOCK` state: an exclusive claim on the device by one channel until
/// `until_ms`. §11.2.9.2.2 — "as long as the lock is active, any other channel trying
/// to send a message will fail"; the lock time is bounded so a crashed application
/// cannot hold the device forever.
#[derive(Default)]
pub struct ChannelLock {
    cid: u32,
    until_ms: u64,
}

/// The largest lock a platform may ask for, in seconds (§11.2.9.2.2).
pub const LOCK_MAX_SECONDS: u8 = 10;

impl ChannelLock {
    /// Take (`seconds > 0`) or release (`seconds == 0`) the lock for `cid`. A release
    /// by anyone but the owner is ignored — it is not theirs to give up.
    pub fn arm(&mut self, cid: u32, seconds: u8, now_ms: u64) {
        if seconds == 0 {
            if self.cid == cid {
                self.until_ms = 0;
            }
            return;
        }
        self.cid = cid;
        self.until_ms = now_ms + u64::from(seconds) * 1000;
    }

    /// Whether `cmd` arriving on `cid` must be turned away because another channel
    /// holds the lock. §11.2.9.2.2 — "as long as the lock is active, any other
    /// channel trying to send a message will fail" — and a `CTAPHID_INIT` sent to
    /// resynchronise some *other* allocated channel (§11.2.9.1.3's first function)
    /// is such a message: letting it through would hand a second application the
    /// one command that discards state, which is what the lock exists to prevent.
    ///
    /// The single carve-out is an INIT on the BROADCAST cid — §11.2.9.1.3's second
    /// function, asking for a channel id. That is not traffic on a channel, and
    /// refusing it would leave a newly-started application with no id to be turned
    /// away *on*, so it could not tell a locked device from a broken one.
    pub fn refuses(&self, cid: u32, cmd: u8, now_ms: u64) -> bool {
        if cmd == CTAPHID_INIT && cid == CID_BROADCAST {
            return false;
        }
        self.blocks(cid, now_ms)
    }

    /// Ownership and expiry alone, without the command-shaped carve-out above.
    fn blocks(&self, cid: u32, now_ms: u64) -> bool {
        now_ms < self.until_ms && self.cid != cid
    }
}

// 16-byte device UUID returned by CTAPHID_UUID ("rs-key" + version).
// TODO: derive from chip serial.
pub const DEVICE_UUID: [u8; 16] = [
    0x72, 0x73, 0x2d, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

/// Maximum CTAPHID message: one INIT frame + up to 128 CONT frames.
pub const CTAP_MAX_MESSAGE: usize = INIT_DATA + 128 * CONT_DATA; // 7609

/// Standard FIDO U2F / CTAPHID HID report descriptor (usage page 0xF1D0,
/// 64-byte IN/OUT reports).
pub const FIDO_REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance 0xF1D0)
    0x09, 0x01, //       Usage (CTAPHID)
    0xA1, 0x01, //       Collection (Application)
    0x09, 0x20, //         Usage (Data In)
    0x15, 0x00, //         Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //         Report Size (8)
    0x95, 0x40, //         Report Count (64)
    0x81, 0x02, //         Input (Data,Var,Abs)
    0x09, 0x21, //         Usage (Data Out)
    0x15, 0x00, //         Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //         Report Size (8)
    0x95, 0x40, //         Report Count (64)
    0x91, 0x02, //         Output (Data,Var,Abs)
    0xC0, //             End Collection
];

/// Routes reassembled CTAPHID_MSG / CTAPHID_CBOR messages to the applet layer,
/// keeping this transport HAL-free. `firmware` implements it by handing the
/// message to a compute worker on a lower-priority executor, so this transport
/// task stays responsive and streams keepalives while slow crypto/flash runs.
#[allow(async_fn_in_trait)] // crate-internal, single-threaded executor — no Send bound needed
pub trait MsgHandler {
    /// Handle a U2F (ISO-7816) command APDU, writing the response APDU (body +
    /// SW1 SW2) into `out`; returns its length. `cid` is the channel it arrived on:
    /// the MSG applet selection is cross-message state, and U2F has no SELECT of
    /// its own, so a selection made on one channel must not decide where another
    /// channel's REGISTER lands (audit run-34 #27).
    async fn handle_msg(&mut self, cid: u32, apdu: &[u8], out: &mut [u8]) -> usize;

    /// Handle a CTAP2 CBOR message (`command_byte ‖ params`), writing the response
    /// (status byte + optional CBOR) into `out`; returns its length. `cid` is the
    /// channel the message arrived on — cross-message state that must not be
    /// usable by a second process on its own channel (the seed-backup MSE key)
    /// binds to it.
    async fn handle_cbor(&mut self, cid: u32, data: &[u8], out: &mut [u8]) -> usize;

    /// Handle a vendor-specific CTAPHID command — `cmd` is the *logical* command
    /// number (the `TYPE_INIT` bit already stripped). Used for the YubiKey
    /// Management DeviceInfo read that `ykman` / Yubico Authenticator issue over
    /// the FIDO interface. Write the response body into `out` and return its
    /// length, or `None` to reject with `CTAPHID_ERROR(ERR_INVALID_CMD)`. The
    /// default rejects every vendor command.
    async fn handle_vendor(&mut self, _cmd: u8, _data: &[u8], _out: &mut [u8]) -> Option<usize> {
        None
    }

    /// Called when a `CTAPHID_INIT` starts a fresh logical session, so the handler
    /// can drop any applet it had selected over this (MSG) transport. U2F/CTAP1 has
    /// no SELECT and must not inherit a prior vendor-AID selection; without this a
    /// sticky selection silently routes U2F REGISTER/AUTHENTICATE/VERSION to the
    /// vendor applet (→ `0x6D00`). Default: no-op.
    fn reset_app_selection(&mut self) {}

    /// Whether this build has something to identify itself *with* — an LED, a
    /// panel. It gates the `CAPABILITY_WINK` bit ([`init_capabilities`]), because
    /// §11.2.9.2.1 defines that bit as "implements CTAPHID_WINK" and the command
    /// as producing "some visual or audible identification". Default: no, so a
    /// build that forgets to override this under-claims rather than lies.
    fn can_wink(&self) -> bool {
        false
    }

    /// Perform that identification — "a short burst of flashes". Must return
    /// promptly: the reply is written straight after, and the burst belongs to
    /// whatever renders it. Default: no-op, paired with `can_wink` = false.
    fn wink(&mut self) {}
}

/// The capability byte for an `INIT` reply. WINK is claimed only when the handler
/// has an indicator to flash: an invisible wink is worse than an unset bit,
/// because the host offers the command precisely to tell two identical-looking
/// keys apart, and a silent success tells the user the wrong key is the right one.
/// LOCK is unconditional — [`ChannelLock`] implements the command, and a host
/// reads this bit to decide whether to attempt it at all, so leaving it clear
/// does not make the device safer, it hides a working command.
/// `NMSG` stays clear — CTAPHID_MSG (U2F) is implemented.
pub fn init_capabilities(can_wink: bool) -> u8 {
    CAPFLAG_CBOR | CAPFLAG_LOCK | if can_wink { CAPFLAG_WINK } else { 0 }
}

/// Run the identification burst where there is something to run it on, and report
/// the reply the caller must frame. §11.2.9.2.1 defines `CAPFLAG_WINK` as
/// "implements CTAPHID_WINK", so a build that leaves the bit clear
/// ([`init_capabilities`]) refuses the command: answering an empty success frame
/// would have the same device say "I have no indicator" and "yes, I winked".
fn perform_wink<H: MsgHandler>(handler: &mut H) -> (u8, &'static [u8]) {
    if !handler.can_wink() {
        return (CTAPHID_ERROR, &[ERR_INVALID_CMD]);
    }
    handler.wink();
    (CTAPHID_WINK, &[])
}

/// What the transport should do after [`Reassembler::feed`] consumes a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Frame consumed: the message is still incomplete, or a stray continuation
    /// (no transaction in progress) was ignored.
    None,
    /// Reply with `CTAPHID_ERROR(code)` on channel `cid`.
    Error(u32, u8),
    /// Message `(cid, cmd)` is complete; its payload is [`Reassembler::message`].
    Message(u32, u8),
}

/// Stateful CTAPHID frame reassembler — the pure core of the RX path.
///
/// Performs the channel/length/sequence checks: feed it whole 64-byte reports
/// and act on the returned [`Outcome`]. Holds the message buffer so it carries
/// no borrows and is trivial to unit-test and fuzz.
pub struct Reassembler {
    msg: [u8; CTAP_MAX_MESSAGE],
    cid: u32,
    cmd: u8,
    bcnt: usize,
    cur: usize,
    seq: u8,
    in_tx: bool,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    pub const fn new() -> Self {
        Self {
            msg: [0u8; CTAP_MAX_MESSAGE],
            cid: 0,
            cmd: 0,
            bcnt: 0,
            cur: 0,
            seq: 0,
            in_tx: false,
        }
    }

    /// Payload of the most recently completed message (`msg[..bcnt]`). Valid
    /// until the next [`feed`](Self::feed).
    pub fn message(&self) -> &[u8] {
        &self.msg[..self.bcnt]
    }

    /// Whether a multi-frame message is mid-reassembly (awaiting continuations).
    pub fn in_progress(&self) -> bool {
        self.in_tx
    }

    /// The channel of the in-progress transaction (for a timeout reply).
    pub fn current_cid(&self) -> u32 {
        self.cid
    }

    /// Drop an in-progress reassembly (e.g. on a receive timeout).
    pub fn abort(&mut self) {
        self.in_tx = false;
    }

    /// Wipe the buffered message — MSG/CBOR payloads carry PINs and key
    /// material, and the buffer otherwise holds them until the next message.
    pub fn scrub(&mut self) {
        use zeroize::Zeroize;
        self.msg[..self.bcnt].zeroize();
        self.bcnt = 0;
    }

    /// Consume one HID report. `f` is always a full 64-byte report; the caller
    /// drops short USB reads before calling.
    pub fn feed(&mut self, f: &[u8; HID_RPT_SIZE]) -> Outcome {
        let cid = u32::from_le_bytes([f[0], f[1], f[2], f[3]]);
        let type_byte = f[4];
        let is_init = type_byte & TYPE_INIT != 0;

        // Channel validation.
        if cid == 0 || (cid == CID_BROADCAST && !(is_init && type_byte == CTAPHID_INIT)) {
            return Outcome::Error(cid, ERR_INVALID_CHANNEL);
        }

        if is_init {
            let cmd = type_byte;
            // Mid-transaction, an init-type frame that is not CTAPHID_INIT is a
            // protocol violation — judged BEFORE the bcnt field, which is
            // meaningless in such a frame. A continuation frame whose seq byte has
            // the INIT bit set lands here (FIDO conformance HID-1 F-4 corrupts the
            // last frame's seq to CTAPHID_PING+1 = 0x82); its "bcnt" is then random
            // payload bytes, so validating length first wrongly returned
            // ERR_INVALID_LEN whenever those bytes exceeded the max (~88% of runs).
            if self.in_tx && cmd != CTAPHID_INIT {
                if self.cid != cid {
                    // A different channel cannot interrupt — busy; the owning
                    // channel's in-progress transaction is left intact.
                    return Outcome::Error(cid, ERR_CHANNEL_BUSY);
                }
                // Same channel: an init-type frame where a continuation was
                // expected is out of sequence; abort the transaction.
                self.in_tx = false;
                return Outcome::Error(cid, ERR_INVALID_SEQ);
            }
            let bcnt = ((f[5] as usize) << 8) | f[6] as usize;
            if bcnt > CTAP_MAX_MESSAGE {
                return Outcome::Error(cid, ERR_INVALID_LEN);
            }
            self.cid = cid;
            self.cmd = cmd;
            self.bcnt = bcnt;
            self.seq = 0;
            let n = bcnt.min(INIT_DATA);
            self.msg[..n].copy_from_slice(&f[7..7 + n]);
            self.cur = n;
            self.in_tx = bcnt > INIT_DATA;
        } else {
            // Continuation frame.
            if !self.in_tx {
                return Outcome::None; // stray CONT with no INIT
            }
            if cid != self.cid {
                return Outcome::Error(cid, ERR_CHANNEL_BUSY);
            }
            let seq = type_byte & !TYPE_INIT;
            if seq != self.seq {
                self.in_tx = false;
                return Outcome::Error(cid, ERR_INVALID_SEQ);
            }
            // `saturating_sub`: the in_tx state machine keeps cur < bcnt, but a
            // saturating subtraction makes the no-underflow self-evident across
            // refactors (a wrapped count here would index past the message).
            let n = CONT_DATA.min(self.bcnt.saturating_sub(self.cur));
            self.msg[self.cur..self.cur + n].copy_from_slice(&f[5..5 + n]);
            self.cur += n;
            self.seq = self.seq.wrapping_add(1);
        }

        if self.cur >= self.bcnt {
            self.in_tx = false;
            Outcome::Message(self.cid, self.cmd)
        } else {
            Outcome::None
        }
    }
}

/// Splits an outgoing message into 64-byte HID frames (one INIT then CONT
/// frames), the pure mirror of the RX path. Always yields at least the INIT
/// frame, even for an empty payload.
pub struct TxFrames<'a> {
    cid: [u8; 4],
    cmd: u8,
    data: &'a [u8],
    off: usize,
    seq: u8,
    started: bool,
}

impl<'a> TxFrames<'a> {
    pub fn new(cid: u32, cmd: u8, data: &'a [u8]) -> Self {
        Self {
            cid: cid.to_le_bytes(),
            cmd,
            data,
            off: 0,
            seq: 0,
            started: false,
        }
    }
}

impl Iterator for TxFrames<'_> {
    type Item = [u8; HID_RPT_SIZE];

    fn next(&mut self) -> Option<Self::Item> {
        let total = self.data.len();
        let mut frame = [0u8; HID_RPT_SIZE];
        frame[0..4].copy_from_slice(&self.cid);

        if !self.started {
            self.started = true;
            frame[4] = self.cmd; // already carries the TYPE_INIT bit
            frame[5] = (total >> 8) as u8;
            frame[6] = (total & 0xff) as u8;
            let n = total.min(INIT_DATA);
            frame[7..7 + n].copy_from_slice(&self.data[..n]);
            self.off = n;
            return Some(frame);
        }

        if self.off >= total {
            return None;
        }

        frame[4] = self.seq & !TYPE_INIT;
        let n = CONT_DATA.min(total - self.off);
        frame[5..5 + n].copy_from_slice(&self.data[self.off..self.off + n]);
        self.off += n;
        self.seq = self.seq.wrapping_add(1);
        Some(frame)
    }
}

/// CTAPHID transport bound to a 64-byte IN/OUT HID interface, dispatching MSG to `H`.
pub struct CtapHid<'d, D: Driver<'d>, H: MsgHandler> {
    reader: HidReader<'d, D, HID_RPT_SIZE>,
    writer: HidWriter<'d, D, HID_RPT_SIZE>,
    handler: H,
    asm: Reassembler,
    /// Response scratch the handler writes into (then framed onto the wire). A full
    /// CTAPHID message worth, so even a max-size response fits.
    scratch: [u8; CTAP_MAX_MESSAGE],
    /// Whether the worker is currently blocked waiting for a user-presence touch —
    /// selects the `KEEPALIVE` status byte (`UPNEEDED` vs `PROCESSING`). The firmware
    /// reads its worker flag; a `|| false` stand-in keeps the status at `PROCESSING`.
    up_pending: fn() -> bool,
    /// Signal the worker (on its own executor) to abort an in-flight touch wait,
    /// invoked when a `CTAPHID_CANCEL` arrives for the channel being processed.
    /// The aborted command returns `CTAP2_ERR_KEEPALIVE_CANCEL`. A `|| {}` stand-in
    /// (no button → instant confirmation) makes it a no-op.
    request_cancel: fn(),
    /// Source of the unique CIDs `CTAPHID_INIT` hands out.
    cids: CidAllocator,
    /// The current `CTAPHID_LOCK` holder, if any.
    lock: ChannelLock,
}

impl<'d, D: Driver<'d>, H: MsgHandler> CtapHid<'d, D, H> {
    pub fn new(
        reader: HidReader<'d, D, HID_RPT_SIZE>,
        writer: HidWriter<'d, D, HID_RPT_SIZE>,
        handler: H,
        up_pending: fn() -> bool,
        request_cancel: fn(),
    ) -> Self {
        Self {
            reader,
            writer,
            handler,
            asm: Reassembler::new(),
            scratch: [0; CTAP_MAX_MESSAGE],
            up_pending,
            request_cancel,
            cids: CidAllocator::new(),
            lock: ChannelLock::default(),
        }
    }

    /// Read frames forever, reassemble messages, answer native commands. While a
    /// multi-frame message is mid-reassembly, the wait for the next frame is bound
    /// to `RX_TIMEOUT_MS`; on timeout the transaction is aborted with
    /// `CTAPHID_ERROR(MSG_TIMEOUT)`.
    pub async fn run(&mut self) -> ! {
        let mut frame = [0u8; HID_RPT_SIZE];
        loop {
            if self.asm.in_progress() {
                match select(
                    self.reader.read(&mut frame),
                    Timer::after_millis(RX_TIMEOUT_MS),
                )
                .await
                {
                    Either::First(Ok(n)) if n == HID_RPT_SIZE => self.on_frame(&frame).await,
                    Either::First(_) => {}
                    Either::Second(_) => {
                        let cid = self.asm.current_cid();
                        self.asm.abort();
                        write_message(&mut self.writer, cid, CTAPHID_ERROR, &[ERR_MSG_TIMEOUT])
                            .await;
                    }
                }
            } else {
                // Only a full 64-byte report is a valid CTAPHID frame; a short
                // read would leave stale bytes in the buffer's tail, which
                // `feed` (a `&[u8; 64]`) would otherwise parse as payload.
                match self.reader.read(&mut frame).await {
                    Ok(n) if n == HID_RPT_SIZE => self.on_frame(&frame).await,
                    _ => {}
                }
            }
        }
    }

    async fn on_frame(&mut self, f: &[u8; HID_RPT_SIZE]) {
        match self.asm.feed(f) {
            Outcome::None => {}
            Outcome::Error(cid, code) => {
                write_message(&mut self.writer, cid, CTAPHID_ERROR, &[code]).await;
            }
            Outcome::Message(cid, cmd)
                if self.lock.refuses(cid, cmd, Instant::now().as_millis()) =>
            {
                write_message(&mut self.writer, cid, CTAPHID_ERROR, &[ERR_CHANNEL_BUSY]).await;
            }
            Outcome::Message(cid, cmd) => self.dispatch(cid, cmd).await,
        }
    }

    async fn dispatch(&mut self, cid: u32, cmd: u8) {
        match cmd {
            CTAPHID_INIT => {
                // A fresh session: drop any applet selected over this transport so
                // U2F (which has no SELECT) can't inherit a prior vendor selection.
                self.handler.reset_app_selection();
                // resp: nonce(8) | newcid(4) | iface(1) | major | minor | build | caps
                let nonce = self.asm.message();
                let mut resp = [0u8; 17];
                let k = nonce.len().min(8);
                resp[..k].copy_from_slice(&nonce[..k]);
                // §11.2.9.1.3: on the broadcast CID this allocates a fresh channel;
                // on an already-allocated one it only resynchronises that channel,
                // and the response names the CID it arrived on.
                let assigned = if cid == CID_BROADCAST {
                    self.cids.allocate()
                } else {
                    cid
                };
                resp[8..12].copy_from_slice(&assigned.to_le_bytes());
                resp[12] = CTAPHID_IF_VERSION;
                resp[13] = VERSION_MAJOR;
                resp[14] = VERSION_MINOR;
                resp[15] = VERSION_BUILD;
                resp[16] = init_capabilities(self.handler.can_wink());
                write_message(&mut self.writer, cid, CTAPHID_INIT, &resp).await;
            }
            CTAPHID_PING | CTAPHID_SYNC => {
                write_message(&mut self.writer, cid, cmd, self.asm.message()).await;
            }
            CTAPHID_WINK => {
                let (rsp, body) = perform_wink(&mut self.handler);
                write_message(&mut self.writer, cid, rsp, body).await;
            }
            CTAPHID_LOCK => {
                // §11.2.9.2.2: BCNT 1, a lock time of 0..10 seconds, 0 releasing it.
                match self.asm.message() {
                    [secs] if *secs <= LOCK_MAX_SECONDS => {
                        self.lock.arm(cid, *secs, Instant::now().as_millis());
                        write_message(&mut self.writer, cid, CTAPHID_LOCK, &[]).await;
                    }
                    [_] => {
                        write_message(&mut self.writer, cid, CTAPHID_ERROR, &[ERR_INVALID_PAR])
                            .await;
                    }
                    _ => {
                        write_message(&mut self.writer, cid, CTAPHID_ERROR, &[ERR_INVALID_LEN])
                            .await;
                    }
                }
            }
            CTAPHID_VERSION => {
                write_message(
                    &mut self.writer,
                    cid,
                    CTAPHID_VERSION,
                    &[VERSION_MAJOR, VERSION_MINOR, VERSION_BUILD, 0],
                )
                .await;
            }
            CTAPHID_UUID => {
                write_message(&mut self.writer, cid, CTAPHID_UUID, &DEVICE_UUID).await;
            }
            CTAPHID_CANCEL => {
                // A CANCEL is never acknowledged (CTAPHID spec). With no
                // transaction in flight it is simply ignored; one that arrives
                // mid-transaction is observed inside `run_with_keepalive`, which
                // aborts the worker's touch wait so the in-flight CBOR/MSG
                // command answers CTAP2_ERR_KEEPALIVE_CANCEL itself.
            }
            CTAPHID_MSG => {
                self.run_with_keepalive(cid, false).await;
            }
            CTAPHID_CBOR => {
                // A CBOR message must carry at least the command byte.
                if self.asm.message().is_empty() {
                    write_message(&mut self.writer, cid, CTAPHID_ERROR, &[ERR_INVALID_LEN]).await;
                } else {
                    self.run_with_keepalive(cid, true).await;
                }
            }
            cmd if cmd >= CTAPHID_VENDOR_FIRST => {
                self.run_vendor(cid, cmd).await;
            }
            _ => {
                write_message(&mut self.writer, cid, CTAPHID_ERROR, &[ERR_INVALID_CMD]).await;
            }
        }
    }

    /// Hand the reassembled message to the (async) handler — which forwards it to
    /// the compute worker on a lower-priority executor — streaming a
    /// `CTAPHID_KEEPALIVE` every [`KEEPALIVE_MS`] while it runs, then frame the
    /// response. `is_cbor` selects CBOR vs MSG (U2F). The handler future borrows
    /// `handler`/`asm`/`scratch`; the keepalive uses `writer` — disjoint fields, so
    /// `select` drives both concurrently and the keepalive keeps flowing while the
    /// worker blocks on slow crypto / flash GC.
    async fn run_with_keepalive(&mut self, cid: u32, is_cbor: bool) {
        let Self {
            reader,
            handler,
            writer,
            asm,
            scratch,
            up_pending,
            request_cancel,
            ..
        } = self;
        let up_pending = *up_pending;
        let request_cancel = *request_cancel;
        let data = asm.message();
        // Frames read while the worker runs are inspected only for CTAPHID_CANCEL,
        // never reassembled (the message buffer is in use), so a scratch buffer
        // disjoint from `asm` is enough.
        let mut watch = [0u8; HID_RPT_SIZE];
        let n = {
            let mut fut = core::pin::pin!(async {
                if is_cbor {
                    handler.handle_cbor(cid, data, scratch).await
                } else {
                    handler.handle_msg(cid, data, scratch).await
                }
            });
            loop {
                // Only watch the reader for CTAPHID_CANCEL while a touch is
                // pending. That is the only window the platform sends CANCEL, and
                // the only time it is not pipelining the next request. Reading
                // frames during fast/crypto processing would consume — and then
                // drop — a pipelined next command (e.g. the rapid getPinToken loop
                // in conformance ClientPin-GetRetries), wedging the transport. So
                // off the touch wait we race only the worker and the keepalive,
                // exactly like before the CANCEL support was added.
                if up_pending() {
                    match select3(
                        fut.as_mut(),
                        Timer::after_millis(KEEPALIVE_MS),
                        reader.read(&mut watch),
                    )
                    .await
                    {
                        Either3::First(n) => break n,
                        Either3::Second(_) => {
                            if let Some(status) = keepalive_status(is_cbor, up_pending()) {
                                write_message(writer, cid, CTAPHID_KEEPALIVE, &[status]).await;
                            }
                        }
                        // A CTAPHID_CANCEL on the active channel aborts the worker's
                        // touch wait; the command then returns KEEPALIVE_CANCEL
                        // itself. Any other mid-flight frame is ignored.
                        Either3::Third(read) => {
                            if matches!(read, Ok(k) if is_cancel_frame(&watch, k, cid)) {
                                request_cancel();
                            }
                        }
                    }
                } else {
                    match select(fut.as_mut(), Timer::after_millis(KEEPALIVE_MS)).await {
                        Either::First(n) => break n,
                        Either::Second(_) => {
                            if let Some(status) = keepalive_status(is_cbor, up_pending()) {
                                write_message(writer, cid, CTAPHID_KEEPALIVE, &[status]).await;
                            }
                        }
                    }
                }
            }
        };
        let cmd = if is_cbor { CTAPHID_CBOR } else { CTAPHID_MSG };
        write_message(writer, cid, cmd, &scratch[..n]).await;
        // Request and response both carried secrets (PINs, tokens, key blobs).
        use zeroize::Zeroize;
        scratch[..n].zeroize();
        asm.scrub();
    }

    /// Serve a vendor CTAPHID command through the handler (the worker, which owns
    /// flash). Mirrors [`Self::run_with_keepalive`]'s field split; vendor commands
    /// are quick flash reads and none of them is presence-gated, so no keepalive is
    /// streamed — one that ever gains a touch gate belongs in `run_with_keepalive`,
    /// which is also where CTAPHID_CANCEL is observed. The handler sees the logical
    /// command number (`TYPE_INIT` stripped); on success we reply with the original
    /// command byte, otherwise `CTAPHID_ERROR(ERR_INVALID_CMD)`.
    async fn run_vendor(&mut self, cid: u32, cmd: u8) {
        let Self {
            handler,
            writer,
            asm,
            scratch,
            ..
        } = self;
        let data = asm.message();
        match handler.handle_vendor(cmd & !TYPE_INIT, data, scratch).await {
            Some(n) => {
                write_message(writer, cid, cmd, &scratch[..n]).await;
                // Same discipline as `run_with_keepalive`: neither the request nor
                // the response stays resident past the frame that carried it.
                use zeroize::Zeroize;
                scratch[..n].zeroize();
            }
            None => write_message(writer, cid, CTAPHID_ERROR, &[ERR_INVALID_CMD]).await,
        }
        asm.scrub();
    }
}

/// One outgoing 64-byte HID report. The future completes only once the host
/// drains the report from the IN endpoint — exactly where the FIDO interface can
/// wedge (see [`write_frames`]). Splitting it behind a trait lets a host test
/// substitute a sink that never completes, proving the timeout abandons a stalled
/// write instead of blocking the transport task forever.
#[allow(async_fn_in_trait)] // crate-internal, single-threaded executor — no Send bound needed
trait FrameSink {
    async fn write_frame(&mut self, frame: &[u8; HID_RPT_SIZE]);
}

impl<'d, D: Driver<'d>> FrameSink for HidWriter<'d, D, HID_RPT_SIZE> {
    async fn write_frame(&mut self, frame: &[u8; HID_RPT_SIZE]) {
        // A write error (endpoint disabled / reset) ends the response the same as
        // a timeout: there is nothing more to send for this transaction.
        let _ = self.write(frame).await;
    }
}

/// Frame `data` into one INIT frame plus CONT frames and write them out, bounding
/// each frame write by a fresh `timeout` future.
///
/// If the host abandons the transaction mid-response (a cancelled/timed-out
/// client, or a wedged host HID handle), an unbounded `write().await` would block
/// this transport task forever — it would stop draining the OUT endpoint, NAKing
/// every further host write and wedging the whole FIDO interface until a replug.
/// On timeout we abandon the rest of the response and return to reading.
///
/// Generic over the sink and a timeout-future factory so the abandon-on-stall
/// path is exercised on the host without a USB driver or an embassy time driver
/// (see the `write_frames_*` tests).
async fn write_frames<S, T, F>(sink: &mut S, cid: u32, cmd: u8, data: &[u8], mut timeout: F)
where
    S: FrameSink,
    F: FnMut() -> T,
    T: Future<Output = ()>,
{
    for frame in TxFrames::new(cid, cmd, data) {
        match select(sink.write_frame(&frame), timeout()).await {
            Either::First(_) => {}
            Either::Second(_) => return, // host stopped draining IN — abandon response
        }
    }
}

/// [`write_frames`] with the production timeout: bound every frame to
/// [`TX_TIMEOUT_MS`] of host-drain time.
async fn write_message<'d, D: Driver<'d>>(
    writer: &mut HidWriter<'d, D, HID_RPT_SIZE>,
    cid: u32,
    cmd: u8,
    data: &[u8],
) {
    write_frames(writer, cid, cmd, data, || {
        Timer::after_millis(TX_TIMEOUT_MS)
    })
    .await;
}

#[cfg(test)]
#[path = "ctaphid_tests.rs"]
mod tests;
