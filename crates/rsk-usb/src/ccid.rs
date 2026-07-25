// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! USB CCID transport (bulk smart-card, class 0x0B): the host's PC/SC stack
//! powers the card on (answered with an ATR), polls slot status, negotiates the
//! T=1 parameters, and exchanges APDUs in `XfrBlock` messages. Each CCID message
//! is a 10-byte header
//!
//! ```text
//! bMessageType(1) | dwLength(4, LE) | bSlot(1) | bSeq(1) | bStatus(1) | bError(1) | bChain(1)
//! ```
//!
//! followed by `dwLength` payload bytes (an APDU for `XfrBlock`).
//!
//! [`process_message`] is the pure, HAL-free core (host-tested); [`Ccid`] is the
//! async wrapper that accumulates a full message off bulk OUT, runs it, and
//! answers on bulk IN, routing APDUs to an [`ApduHandler`]. A single command is
//! handled per transfer (PC/SC waits for each response).

use embassy_futures::select::{Either, select};
use embassy_time::Timer;
use embassy_usb::Builder;
use embassy_usb::driver::{Driver, Endpoint, EndpointError, EndpointIn, EndpointOut};

// CCID bulk-OUT message types (Bulk-OUT, PC → reader).
const CCID_SET_PARAMS: u8 = 0x61;
const CCID_POWER_ON: u8 = 0x62;
const CCID_POWER_OFF: u8 = 0x63;
const CCID_SLOT_STATUS: u8 = 0x65;
const CCID_GET_PARAMS: u8 = 0x6C;
const CCID_RESET_PARAMS: u8 = 0x6D;
const CCID_XFR_BLOCK: u8 = 0x6F;
const CCID_SECURE: u8 = 0x69;
const CCID_SET_RATE: u8 = 0x73;

// CCID bulk-IN message types (Bulk-IN, reader → PC).
const CCID_DATA_BLOCK_RET: u8 = 0x80;
const CCID_SLOT_STATUS_RET: u8 = 0x81;
const CCID_PARAMS_RET: u8 = 0x82;
const CCID_SET_RATE_RET: u8 = 0x84;

/// `bStatus` after power-off / reset: ICC present, inactive.
const STATUS_INACTIVE: u8 = 1;
/// `bStatus` after power-on: ICC present, active.
const STATUS_ACTIVE: u8 = 0;
/// `bStatus` for a time-extension `RDR_to_PC_DataBlock` (bmCommandStatus = "time
/// extension requested").
const STATUS_TIMEEXT: u8 = 0x80;
/// `bStatus` the secure-PIN path reports when the card actually ran the VERIFY
/// (even a wrong-PIN status word is a *successful* command — the card answered).
/// The transport substitutes the live slot status for this value.
pub const SECURE_STATUS_OK: u8 = STATUS_ACTIVE;
/// `bStatus` with `bmCommandStatus = failed` (ICC active): the secure-PIN entry
/// did not produce a card response (the user cancelled or it timed out).
pub const SECURE_STATUS_FAILED: u8 = 0x40;
/// CCID `bError`: the user cancelled PIN entry on the pad → `SCARD_W_CANCELLED_BY_USER`.
pub const SECURE_ERR_CANCELLED: u8 = 0xEF;
/// CCID `bError`: PIN entry on the pad timed out → `SCARD_E_TIMEOUT`.
pub const SECURE_ERR_TIMEOUT: u8 = 0xF0;
/// Time-extension cadence while a long op runs — well under the T=1 block waiting
/// time, so the host's transaction never times out.
const WTX_INTERVAL_MS: u64 = 200;
/// Abandon a bulk-IN response if the host stops draining it for this long. A
/// client that walks away mid-response must not block the CCID task forever in
/// `write_transfer().await` — that would stop the bulk-OUT read and wedge the
/// interface (the same failure mode the FIDO transport guards against). PC/SC
/// reads each response promptly, so a gap this long means the host is gone.
use crate::TX_TIMEOUT_MS;

const HEADER: usize = 10;
/// `dwMaxCCIDMessageLength` from the class descriptor.
pub const MAX_CCID_MSG: usize = 2048;
/// `wMaxPacketSize` of the three CCID endpoints (full-speed USB). A bulk-IN
/// transfer whose length is an exact multiple needs a terminating ZLP — keep
/// the `is_multiple_of` modulus and the endpoint allocations in lockstep.
const EP_PACKET_SIZE: usize = 64;

/// ATR presented on the Yubico-identity build (effective VID == Yubico): a real
/// YubiKey 5's answer-to-reset, byte-for-byte, so `ykman`/`ykmd` and the Windows
/// "YubiKey Smart Card" minidriver treat the card exactly like a YubiKey. The
/// historical bytes carry a card-capabilities compact-TLV + the "YubiKey" label.
pub const ATR_YUBIKEY: &[u8] = &[
    0x3b, 0xfd, 0x13, 0x00, 0x00, 0x81, 0x31, 0xfe, 0x15, 0x80, 0x73, 0xc0, 0x21, 0xc0, 0x57, 0x59,
    0x75, 0x62, 0x69, 0x4b, 0x65, 0x79, 0x40,
];

/// ATR presented on the default RS-Key build (non-Yubico VID): identical T=1 card
/// capabilities to [`ATR_YUBIKEY`], but the historical-byte label is "RS-Key", not
/// "YubiKey" — the card does not impersonate a YubiKey when it is not carrying the
/// Yubico USB identity (mirrors the VID-gated iManufacturer / OpenPGP AID). The
/// last byte is the recomputed TCK (XOR checksum over T0..historical bytes).
pub const ATR_RSKEY: &[u8] = &[
    0x3b, 0xfc, 0x13, 0x00, 0x00, 0x81, 0x31, 0xfe, 0x15, 0x80, 0x73, 0xc0, 0x21, 0xc0, 0x56, 0x52,
    0x53, 0x2d, 0x4b, 0x65, 0x79, 0x4b,
];

/// T=1 parameters returned for Get/Set/Reset Parameters (`bmFindexDindex,
/// bmTCCKST1, bGuardTimeT1, bmWaitingIntegersT1, bClockStop, bIFSC, bNadValue`).
/// `bmWaitingIntegersT1` uses BWI=9 (0x95) so the block waiting time (~50 s)
/// covers the un-keepalive'd parts of on-card RSA keygen and flash-GC stalls.
const T1_PARAMS: [u8; 7] = [0x11, 0x10, 0xFE, 0x95, 0x03, 0xFE, 0x00];

/// CCID functional (class) descriptor, type `0x21`, body only — embassy prepends
/// the `bLength`/`bDescriptorType` bytes. 5 V, T=0/T=1, auto params, single slot,
/// `dwMaxCCIDMessageLength = 2048`.
const CCID_FUNCTIONAL_DESC: &[u8] = &[
    0x10, 0x01, // bcdCCID 1.10
    0x00, // bMaxSlotIndex (one slot)
    0x01, // bVoltageSupport (5 V)
    0x03, 0x00, 0x00, 0x00, // dwProtocols (T=0 | T=1)
    0xFC, 0x0D, 0x00, 0x00, // dwDefaultClock 3580 kHz
    0xFC, 0x0D, 0x00, 0x00, // dwMaximumClock
    0x00, // bNumClockSupported
    0x80, 0x25, 0x00, 0x00, // dwDataRate 9600 bps
    0x80, 0x25, 0x00, 0x00, // dwMaxDataRate
    0x00, // bNumDataRatesSupported
    0xFE, 0x00, 0x00, 0x00, // dwMaxIFSD 254
    0x00, 0x00, 0x00, 0x00, // dwSynchProtocols
    0x00, 0x00, 0x00, 0x00, // dwMechanical
    0x40, 0x08, 0x04, 0x00, // dwFeatures (auto params/clock, short APDU exchange)
    0x00, 0x08, 0x00, 0x00, // dwMaxCCIDMessageLength 2048
    0xFF, // bClassGetResponse (echo)
    0xFF, // bClassEnvelope (echo)
    0x00, 0x00, // wLcdLayout (none)
    0x00, // bPINSupport (none)
    0x01, // bMaxCCIDBusySlots
];
const CCID_DESC_TYPE: u8 = 0x21;

/// USB class for smart-card / CCID devices.
const USB_CLASS_SMART_CARD: u8 = 0x0B;

/// Slot-change notification body sent once on connect over the interrupt IN
/// endpoint (`RDR_to_PC_NotifySlotChange`: slot 0 present and just changed).
const SLOT_CHANGE_PRESENT: &[u8] = &[0x50, 0x03];

/// Routes an APDU carried in a CCID `XfrBlock` to the applet layer, keeping this
/// transport HAL-free. `firmware` implements it by handing the APDU to a compute
/// worker on a lower-priority executor, so this transport task stays responsive
/// and streams CCID time-extensions while a slow op (RSA keygen, flash GC) runs.
#[allow(async_fn_in_trait)] // crate-internal, single-threaded executor — no Send bound needed
pub trait ApduHandler {
    /// Process a command APDU, writing the response APDU (body + SW1 SW2) into
    /// `out`; returns its length.
    async fn handle_apdu(&mut self, apdu: &[u8], out: &mut [u8]) -> usize;

    /// Process a `PC_to_RDR_Secure` `abPINDataStructure` (CCID pinpad): the PIN is
    /// collected on the device's own UI — never present in `data` — the VERIFY runs
    /// internally, and only the resulting status word is written to `out`. Defaults
    /// to "unsupported" (no on-device pad), so a standard button build needs no
    /// implementation; a display build overrides it.
    async fn handle_secure(&mut self, _data: &[u8], _out: &mut [u8]) -> SecureResult {
        SecureResult {
            len: 0,
            status: SECURE_STATUS_FAILED,
            error: 0,
        }
    }

    /// Return the card to a clean, unauthenticated state: deselect the current
    /// applet and drop its security status, plus any buffered chain / pending
    /// response.
    ///
    /// Called on an ICC power transition. `SCardDisconnect(SCARD_RESET_CARD)` is the
    /// host's primitive for forcing re-authentication — middleware uses it exactly so
    /// the next consumer must present the PIN again — and OpenPGP 3.4 (VERIFY) and
    /// NIST SP 800-73pt2-5 §2.3 both require a reset to clear the security status and
    /// return to the default application. Without this the previously selected applet
    /// stayed current with `has_pin`/`has_pw2`/`validated` intact, so a second local
    /// process inherited a verified session it never authenticated for.
    async fn reset_card(&mut self) {}
}

/// Outcome of [`ApduHandler::handle_secure`]. The transport frames it as an
/// `RDR_to_PC_DataBlock`: `len` body bytes (the card's VERIFY response — the
/// status word) with `status`/`error` driving `bStatus`/`bError`, so a pad
/// cancel/timeout surfaces as the right PC/SC error while a wrong PIN surfaces as
/// the card's own status word in a *successful* command.
pub struct SecureResult {
    pub len: usize,
    pub status: u8,
    pub error: u8,
}

/// If `msg` is an `XfrBlock`, the `(start, end)` byte range of its APDU payload.
fn xfr_apdu(msg: &[u8]) -> Option<(usize, usize)> {
    if msg.len() < HEADER || msg[0] != CCID_XFR_BLOCK {
        return None;
    }
    let dw = u32::from_le_bytes([msg[1], msg[2], msg[3], msg[4]]) as usize;
    Some((HEADER, HEADER + dw.min(msg.len() - HEADER)))
}

/// If `msg` is a `PC_to_RDR_Secure`, the `(start, end)` byte range of its
/// `abPINDataStructure` payload (the CCID pinpad VERIFY request).
fn secure_apdu(msg: &[u8]) -> Option<(usize, usize)> {
    if msg.len() < HEADER || msg[0] != CCID_SECURE {
        return None;
    }
    let dw = u32::from_le_bytes([msg[1], msg[2], msg[3], msg[4]]) as usize;
    Some((HEADER, HEADER + dw.min(msg.len() - HEADER)))
}

/// Write the 10-byte CCID response header.
fn put_header(out: &mut [u8], msg_type: u8, length: u32, seq: u8, status: u8) {
    out[0] = msg_type;
    out[1..5].copy_from_slice(&length.to_le_bytes());
    out[5] = 0; // bSlot
    out[6] = seq; // bSeq (echoed)
    out[7] = status; // bStatus
    out[8] = 0; // bError
    out[9] = 0; // bChainParameter
}

/// Handle one complete CCID message (header + payload) and write the response
/// into `out`, returning its length. `status` is the slot's `bStatus`, updated
/// by power on/off. Returns 0 (no response) for an unknown message type.
pub fn process_message(msg: &[u8], atr: &[u8], status: &mut u8, out: &mut [u8]) -> usize {
    if msg.len() < HEADER || out.len() < HEADER {
        return 0;
    }
    let seq = msg[6];
    let cap = out.len() - HEADER;

    match msg[0] {
        CCID_SLOT_STATUS => {
            put_header(out, CCID_SLOT_STATUS_RET, 0, seq, *status);
            HEADER
        }
        CCID_POWER_ON => {
            let n = atr.len().min(cap);
            put_header(out, CCID_DATA_BLOCK_RET, n as u32, seq, STATUS_ACTIVE);
            out[HEADER..HEADER + n].copy_from_slice(&atr[..n]);
            *status = STATUS_ACTIVE;
            HEADER + n
        }
        CCID_POWER_OFF => {
            *status = STATUS_INACTIVE;
            put_header(out, CCID_SLOT_STATUS_RET, 0, seq, *status);
            HEADER
        }
        CCID_SET_PARAMS | CCID_GET_PARAMS | CCID_RESET_PARAMS => {
            put_header(out, CCID_PARAMS_RET, T1_PARAMS.len() as u32, seq, *status);
            out[9] = 0x01; // bProtocolNum = T=1
            out[HEADER..HEADER + T1_PARAMS.len()].copy_from_slice(&T1_PARAMS);
            HEADER + T1_PARAMS.len()
        }
        CCID_SET_RATE => {
            put_header(out, CCID_SET_RATE_RET, 8, seq, *status);
            out[HEADER..HEADER + 8].fill(0);
            HEADER + 8
        }
        // XfrBlock needs the worker, so `Ccid::run` handles it asynchronously
        // (`run_xfr` frames the response with `put_header`); it never reaches here.
        _ => 0,
    }
}

/// CCID transport bound to a bulk OUT/IN pair plus an interrupt IN endpoint,
/// dispatching `XfrBlock` APDUs to `H`.
pub struct Ccid<'d, D: Driver<'d>, H: ApduHandler> {
    read_ep: D::EndpointOut,
    write_ep: D::EndpointIn,
    int_ep: D::EndpointIn,
    handler: H,
    status: u8,
    atr: &'static [u8],
    rx: [u8; MAX_CCID_MSG],
    tx: [u8; MAX_CCID_MSG],
}

impl<'d, D: Driver<'d>, H: ApduHandler> Ccid<'d, D, H> {
    /// Allocate the CCID interface (class 0x0B, 3 endpoints: bulk OUT, bulk IN,
    /// interrupt IN) on `builder` and build the transport. `atr` is the card's
    /// answer-to-reset (e.g. [`ATR_YUBIKEY`]). `pin_support` sets the descriptor's
    /// `bPINSupport` byte: `0x00` (no pinpad) on a standard build, `0x01` (VERIFY)
    /// on a display build so a host driver drives on-device PIN entry. Every host
    /// CCID stack reads this byte straight from the descriptor; it is the single
    /// switch that lights up secure PIN entry.
    pub fn new(
        builder: &mut Builder<'d, D>,
        handler: H,
        atr: &'static [u8],
        pin_support: u8,
    ) -> Self {
        let mut func = builder.function(USB_CLASS_SMART_CARD, 0, 0);
        let mut iface = func.interface();
        let mut alt = iface.alt_setting(USB_CLASS_SMART_CARD, 0, 0, None);
        // `bPINSupport` is body byte 50 (full descriptor byte 52, the offset every
        // host CCID driver reads). Patch a stack copy — embassy copies the bytes
        // into the config descriptor during this call, so it needn't be `'static`.
        let mut desc = [0u8; CCID_FUNCTIONAL_DESC.len()];
        desc.copy_from_slice(CCID_FUNCTIONAL_DESC);
        desc[50] = pin_support;
        alt.descriptor(CCID_DESC_TYPE, &desc);
        let read_ep = alt.endpoint_bulk_out(None, EP_PACKET_SIZE as u16);
        let write_ep = alt.endpoint_bulk_in(None, EP_PACKET_SIZE as u16);
        let int_ep = alt.endpoint_interrupt_in(None, EP_PACKET_SIZE as u16, 10);
        drop(func);

        Self {
            read_ep,
            write_ep,
            int_ep,
            handler,
            status: STATUS_INACTIVE,
            atr,
            rx: [0; MAX_CCID_MSG],
            tx: [0; MAX_CCID_MSG],
        }
    }

    /// Read messages forever, answer each one. Announces the card as present on
    /// the interrupt endpoint once the interface is enabled — best-effort (raced
    /// against a timeout) so a host that powers the slot on before polling the
    /// interrupt endpoint can never deadlock the bulk loop; PC/SC rediscovers the
    /// card via Slot Status regardless.
    pub async fn run(&mut self) -> ! {
        self.read_ep.wait_enabled().await;
        let _ = select(
            self.int_ep.write(SLOT_CHANGE_PRESENT),
            Timer::after_millis(50),
        )
        .await;
        loop {
            match self.read_message().await {
                Some(total) => {
                    // An XfrBlock APDU goes to the worker (async) with a streamed
                    // CCID time-extension; the protocol messages (power/params/…)
                    // are pure and answered inline.
                    if let Some((a, b)) = xfr_apdu(&self.rx[..total]) {
                        self.run_xfr(a, b).await;
                    } else if let Some((a, b)) = secure_apdu(&self.rx[..total]) {
                        self.run_secure(a, b).await;
                    } else {
                        // A power transition is the host asking for a clean card;
                        // clear the applet security status before answering, so the
                        // ATR it gets back really does describe a fresh session.
                        if matches!(self.rx.first(), Some(&CCID_POWER_ON | &CCID_POWER_OFF)) {
                            self.handler.reset_card().await;
                        }
                        let n = process_message(
                            &self.rx[..total],
                            self.atr,
                            &mut self.status,
                            &mut self.tx,
                        );
                        if n > 0 {
                            // A short packet (or ZLP on an exact multiple) ends the
                            // bulk IN transfer for the host.
                            let zlp = n.is_multiple_of(EP_PACKET_SIZE);
                            let _ = select(
                                self.write_ep.write_transfer(&self.tx[..n], zlp),
                                Timer::after_millis(TX_TIMEOUT_MS),
                            )
                            .await;
                        }
                    }
                }
                None => {
                    // Bad framing: reply "6F 00" (wrong length) and resync.
                    put_header(&mut self.tx, CCID_DATA_BLOCK_RET, 2, 0, self.status);
                    self.tx[HEADER] = 0x6F;
                    self.tx[HEADER + 1] = 0x00;
                    let _ = select(
                        self.write_ep.write_transfer(&self.tx[..HEADER + 2], false),
                        Timer::after_millis(TX_TIMEOUT_MS),
                    )
                    .await;
                }
            }
        }
    }

    /// Run an XfrBlock APDU (`self.rx[a..b]`) via the (async) handler — which hands
    /// it to the worker on a lower-priority executor — streaming a CCID
    /// time-extension every [`WTX_INTERVAL_MS`] while it runs, then frame and send
    /// the response. The handler future borrows `handler`/`rx`/`tx`; the WTX uses
    /// `write_ep` — disjoint fields, so the time-extensions keep flowing while the
    /// worker blocks on the slow op (on-card RSA keygen, flash GC).
    async fn run_xfr(&mut self, a: usize, b: usize) {
        let Self {
            handler,
            write_ep,
            rx,
            tx,
            status,
            ..
        } = self;
        let seq = rx[6];
        let n = {
            let mut fut = core::pin::pin!(handler.handle_apdu(&rx[a..b], &mut tx[HEADER..]));
            loop {
                match select(fut.as_mut(), Timer::after_millis(WTX_INTERVAL_MS)).await {
                    Either::First(n) => break n,
                    Either::Second(_) => {
                        let mut wtx = [0u8; HEADER];
                        put_header(&mut wtx, CCID_DATA_BLOCK_RET, 0, seq, STATUS_TIMEEXT);
                        let _ = select(
                            write_ep.write_transfer(&wtx, false),
                            Timer::after_millis(TX_TIMEOUT_MS),
                        )
                        .await;
                    }
                }
            }
        };
        // handle_apdu wrote the body into tx[HEADER..]; frame the response header.
        let n = n.min(tx.len() - HEADER);
        put_header(tx, CCID_DATA_BLOCK_RET, n as u32, seq, *status);
        let total = HEADER + n;
        let zlp = total.is_multiple_of(EP_PACKET_SIZE);
        let _ = select(
            write_ep.write_transfer(&tx[..total], zlp),
            Timer::after_millis(TX_TIMEOUT_MS),
        )
        .await;
        // The APDU can carry an imported private key; the response a deciphered
        // session key. Wipe both once the transfer is on the wire.
        use zeroize::Zeroize;
        rx[a..b].zeroize();
        tx[..total].zeroize();
    }

    /// Run a `PC_to_RDR_Secure` (`self.rx[a..b]` = the `abPINDataStructure`) via the
    /// handler — which collects the PIN on the device's screen and runs the VERIFY —
    /// streaming a CCID time-extension every [`WTX_INTERVAL_MS`] while the user
    /// types (the same keepalive that covers a slow keygen), then frame the reply.
    /// The handler chooses `bStatus`/`bError`: a card result (`SECURE_STATUS_OK`)
    /// frames a normal DataBlock with the live slot status; a pad cancel/timeout
    /// frames a failed DataBlock with the matching `bError`.
    async fn run_secure(&mut self, a: usize, b: usize) {
        let Self {
            handler,
            write_ep,
            rx,
            tx,
            status,
            ..
        } = self;
        let seq = rx[6];
        let result = {
            let mut fut = core::pin::pin!(handler.handle_secure(&rx[a..b], &mut tx[HEADER..]));
            loop {
                match select(fut.as_mut(), Timer::after_millis(WTX_INTERVAL_MS)).await {
                    Either::First(r) => break r,
                    Either::Second(_) => {
                        let mut wtx = [0u8; HEADER];
                        put_header(&mut wtx, CCID_DATA_BLOCK_RET, 0, seq, STATUS_TIMEEXT);
                        let _ = select(
                            write_ep.write_transfer(&wtx, false),
                            Timer::after_millis(TX_TIMEOUT_MS),
                        )
                        .await;
                    }
                }
            }
        };
        let n = result.len.min(tx.len() - HEADER);
        // A card result reports SECURE_STATUS_OK → use the live slot status; a pad
        // cancel/timeout carries its own failed status and bError.
        let hdr_status = if result.status == SECURE_STATUS_OK {
            *status
        } else {
            result.status
        };
        put_header(tx, CCID_DATA_BLOCK_RET, n as u32, seq, hdr_status);
        tx[8] = result.error; // bError (put_header clears it; set the pad cancel/timeout code)
        let total = HEADER + n;
        let zlp = total.is_multiple_of(EP_PACKET_SIZE);
        let _ = select(
            write_ep.write_transfer(&tx[..total], zlp),
            Timer::after_millis(TX_TIMEOUT_MS),
        )
        .await;
        // The request carries no PIN (collected on-device), but the response holds
        // the card status; wipe both buffers once the reply is on the wire.
        use zeroize::Zeroize;
        rx[a..b].zeroize();
        tx[..total].zeroize();
    }

    /// Accumulate bulk OUT packets into `self.rx` until a full CCID message is
    /// present; returns its total length, or `None` if `dwLength` overflows the
    /// buffer (the caller answers with an error block).
    async fn read_message(&mut self) -> Option<usize> {
        let mut w = 0usize;
        loop {
            let n = match self.read_ep.read(&mut self.rx[w..]).await {
                Ok(n) => n,
                Err(EndpointError::BufferOverflow) => return None,
                Err(_) => continue, // disabled/reset: keep waiting
            };
            w += n;
            if w >= HEADER {
                let dw =
                    u32::from_le_bytes([self.rx[1], self.rx[2], self.rx[3], self.rx[4]]) as usize;
                if dw > MAX_CCID_MSG - HEADER {
                    return None;
                }
                if w >= HEADER + dw {
                    return Some(HEADER + dw);
                }
            }
            if w == self.rx.len() {
                return None;
            }
        }
    }
}

/// Kani proof harnesses (`cargo kani -p rsk-usb`): exhaustive over every input
/// up to the stated bound, where the unit tests only sample.
#[cfg(kani)]
#[path = "ccid_kani.rs"]
mod proofs;

#[cfg(test)]
#[path = "ccid_tests.rs"]
mod tests;
