// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use super::*;

use std::cell::Cell;
use std::collections::VecDeque;
use std::sync::mpsc::Receiver;

use embassy_futures::join::join;
use embassy_futures::select::{Either, select};
use embassy_time::{Duration, Instant, Timer};
use rsk_fido::consts::{CTAP_MAKE_CREDENTIAL, CTAP_SELECTION};
use rsk_fido::{CTAP2_OK, CtapError};
use rsk_usb::ctaphid::{
    CAPFLAG_CBOR, CAPFLAG_LOCK, CAPFLAG_WINK, CID_BROADCAST, CTAPHID_CANCEL, CTAPHID_CBOR,
    CTAPHID_ERROR, CTAPHID_INIT, CTAPHID_KEEPALIVE, CTAPHID_LOCK, CTAPHID_PING, ERR_CHANNEL_BUSY,
    ERR_INVALID_CMD, KEEPALIVE_MS, RX_TIMEOUT_MS, STATUS_UPNEEDED, TYPE_INIT,
};

/// `bDescriptorType` of an interface descriptor.
const DT_INTERFACE: u8 = 0x04;

/// Build the config descriptor the way [`serve`] does and hand back the bytes.
///
/// Everything borrows the buffer, so the whole device is built and dropped inside
/// this function; what comes out is what a host would read.
fn config_descriptor() -> Vec<u8> {
    let mut config_desc = [0u8; CONFIG_DESC_LEN];
    let mut bos = [0u8; BOS_DESC_LEN];
    let mut msos = [0u8; MSOS_DESC_LEN];
    let mut control = [0u8; CONTROL_BUF_LEN];
    let mut kbd_state = HidState::new();
    let mut fido_state = HidState::new();
    let (jobs, _rx) = crate::device::job_queue();
    let used = {
        let (driver, _port) = crate::usbip_driver::new();
        let mut builder = Builder::new(
            driver,
            usb_config(false),
            &mut config_desc,
            &mut bos,
            &mut msos,
            &mut control,
        );
        let classes = declare(
            &mut builder,
            &mut kbd_state,
            &mut fido_state,
            None,
            &jobs,
            rsk_usb::ccid::ATR_RSKEY,
        );
        let usb = builder.build();
        let used = usb.buffer_usage().config_descriptor_used;
        drop(usb);
        drop(classes);
        used
    };
    config_desc[..used].to_vec()
}

/// One interface as the config descriptor declares it.
#[derive(Debug, PartialEq, Eq)]
struct Iface {
    triple: [u8; 3],
    /// `wDescriptorLength` from the HID class descriptor, for a HID interface.
    hid_report_len: Option<usize>,
    endpoints: Vec<u8>,
}

/// Walk the config descriptor once and pull out every interface, in order.
///
/// The walk is class-aware because descriptor type `0x21` is both HID's class
/// descriptor and CCID's functional one — reading it blind would count the card
/// reader as a third HID.
fn interfaces_in(desc: &[u8]) -> Vec<Iface> {
    const DT_HID: u8 = 0x21;
    const DT_ENDPOINT: u8 = 0x05;
    let mut out: Vec<Iface> = Vec::new();
    let mut i = 0;
    while i + 1 < desc.len() {
        let len = desc[i] as usize;
        if len < 2 || i + len > desc.len() {
            break;
        }
        let body = &desc[i..i + len];
        match body[1] {
            DT_INTERFACE if len >= 9 => out.push(Iface {
                triple: [body[5], body[6], body[7]],
                hid_report_len: None,
                endpoints: Vec::new(),
            }),
            DT_HID if len >= 9 => {
                if let Some(f) = out.last_mut().filter(|f| f.triple[0] == 0x03) {
                    f.hid_report_len = Some(u16::from_le_bytes([body[7], body[8]]) as usize);
                }
            }
            DT_ENDPOINT if len >= 7 => {
                if let Some(f) = out.last_mut() {
                    f.endpoints.push(body[2]);
                }
            }
            _ => {}
        }
        i += len;
    }
    out
}

/// The list a USB/IP client is handed before it imports anything must be the list
/// the descriptors declare, in the same order.
///
/// Both were written from the same intent, which is exactly why one can drift
/// from the other without a compiler noticing — and the ORDER is issue #55's whole
/// content: KeePassXC went blind on Linux when the keyboard interface stopped
/// being interface 0.
#[test]
fn the_devlist_matches_the_descriptors() {
    let declared: Vec<[u8; 3]> = interfaces_in(&config_descriptor())
        .iter()
        .map(|f| f.triple)
        .collect();
    assert_eq!(declared, INTERFACES.to_vec());
}

/// …and the count the kernel is told before it reads anything is that same list's.
#[test]
fn the_device_info_counts_the_interfaces_it_has() {
    let d = device_info(false);
    assert_eq!(
        d.num_interfaces as usize,
        interfaces_in(&config_descriptor()).len()
    );
    assert_eq!(d.id_vendor, VID);
    assert_eq!(d.id_product, PID);
    // …and `--yubico` is one identity or none: the tools that look for it match
    // the VID, and read the PID out of the PC/SC reader name.
    let yk = device_info(true);
    assert_eq!(yk.id_vendor, YUBICO_VID);
    assert_eq!(yk.id_product, YUBICO_PID);
    assert_eq!(d.bcd_device, crate::bcd::BCD_DEVICE);
}

/// The keyboard is interface 0 and FIDO is interface 1. Stated separately from
/// the order test because it is the property, not a consequence — and because
/// the class triples cannot say it: both are plain HID, so the only thing on the
/// wire that tells them apart is which report descriptor each one points at.
///
/// `ykpers`/`ykcore`'s libusb backend claims interface 0 and sends the OTP frame
/// reports there without looking at anything else; issue #55 was that interface
/// being FIDO's.
#[test]
fn the_keyboard_is_interface_zero_and_fido_is_one() {
    let ifaces = interfaces_in(&config_descriptor());
    let hid: Vec<Option<usize>> = ifaces.iter().map(|f| f.hid_report_len).collect();
    assert_eq!(
        hid,
        vec![
            Some(rsk_usb::kbd::KEYBOARD_REPORT_DESCRIPTOR.len()),
            Some(FIDO_REPORT_DESCRIPTOR.len()),
            None,
        ]
    );
}

/// Every endpoint the descriptors declare has its own address, and none of them
/// is endpoint 0 — that is the control pipe, and an interface landing on it would
/// answer descriptor reads with its own data.
#[test]
fn every_declared_endpoint_has_its_own_address() {
    let addrs: Vec<u8> = interfaces_in(&config_descriptor())
        .iter()
        .flat_map(|f| f.endpoints.clone())
        .collect();
    assert!(!addrs.is_empty());
    assert!(addrs.iter().all(|&a| a & 0x0f != 0), "{addrs:02x?}");
    let mut sorted = addrs.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        addrs.len(),
        "duplicate address in {addrs:02x?}"
    );
}

/// The emulator must not present itself as a real key by accident: same VID/PID
/// so hosts treat it the same, and a product string that says which it is.
#[test]
fn the_product_string_says_it_is_an_emulator() {
    assert!(PRODUCT.contains("emulator"));
}

// The FIDO interface on the wire: the image's own `CtapHid` behind the declaration
// `serve` makes, with URBs handed straight to the driver in place of a kernel.
// "hid-1 P-n" names the FIDO conformance tool's CTAP 2.3 HID-1 case a test carries.

/// `SET_CONFIGURATION(1)`: what enables the interrupt endpoints. `vhci_hcd`
/// answers SET_ADDRESS itself, so a host puts nothing else on the wire first.
const SET_CONFIGURATION: [u8; 8] = [0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];

/// §11.2.9.1.3's "does NOT implement CTAPHID_MSG" bit — which the device never
/// sets, so `rsk-usb` has no name for it.
const CAPABILITY_NMSG: u8 = 0x08;

/// Interrupt IN URBs the host keeps queued, as a kernel keeps one pending on a HID
/// endpoint at all times: a report written with none queued waits out the
/// transport's TX timeout and is dropped.
const IN_URBS: usize = 4;

/// How long a reply may take. Microseconds in practice; generous for a loaded CI.
const REPLY_MS: u64 = 2_000;

/// A silence long enough to hear both timers the transport runs — the keepalive
/// and the receive timeout — had either been left running.
const QUIET_MS: u64 = RX_TIMEOUT_MS + 2 * KEEPALIVE_MS;

const NONCE: [u8; 8] = *b"nonce!!!";

/// A touch wait nobody answers: whether it is running, and whether the transport
/// has asked it to end. Thread-local because the transport's hooks are `fn()`
/// pointers, and each test runs its stack and its host on its own thread.
#[derive(Default)]
struct Touch {
    pending: Cell<bool>,
    cancelled: Cell<bool>,
}

thread_local! {
    static TOUCH: Touch = Touch::default();
}

fn touch_pending() -> bool {
    TOUCH.with(|t| t.pending.get())
}

fn cancel_touch() {
    TOUCH.with(|t| t.cancelled.set(true));
}

/// Stands in for the device thread: makeCredential and authenticatorSelection wait
/// for a touch until cancelled, then answer as the applets do; the rest answer at
/// once. A vendor command answers its own number, so a command misrouted there
/// comes back as a success rather than an error.
struct Scripted;

impl MsgHandler for Scripted {
    async fn handle_msg(&mut self, _cid: u32, _apdu: &[u8], _out: &mut [u8]) -> usize {
        unreachable!("no case here sends CTAPHID_MSG")
    }

    async fn handle_cbor(&mut self, _cid: u32, data: &[u8], out: &mut [u8]) -> usize {
        out[0] = match data.first() {
            Some(&(CTAP_MAKE_CREDENTIAL | CTAP_SELECTION)) => wait_for_touch().await,
            _ => CTAP2_OK,
        };
        1
    }

    async fn handle_vendor(
        &mut self,
        _cid: u32,
        cmd: u8,
        _data: &[u8],
        out: &mut [u8],
    ) -> Option<usize> {
        out[0] = cmd;
        Some(1)
    }
}

/// Gives up where a presence wait would time out, so a CANCEL that never lands
/// fails the test instead of hanging it.
async fn wait_for_touch() -> u8 {
    TOUCH.with(|t| {
        t.pending.set(true);
        t.cancelled.set(false);
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while !TOUCH.with(|t| t.cancelled.get()) && Instant::now() < deadline {
        Timer::after_millis(1).await;
    }
    TOUCH.with(|t| t.pending.set(false));
    if TOUCH.with(|t| t.cancelled.get()) {
        CtapError::KeepAliveCancel as u8
    } else {
        CtapError::UserActionTimeout as u8
    }
}

/// The frames a host sends for one message. Written out here rather than borrowed
/// from `TxFrames`, so the device's own framing is not also the test's oracle.
fn request(cid: u32, cmd: u8, payload: &[u8]) -> Vec<[u8; HID_RPT_SIZE]> {
    let mut init = [0u8; HID_RPT_SIZE];
    init[..4].copy_from_slice(&cid.to_le_bytes());
    init[4] = cmd;
    init[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    let (head, rest) = payload.split_at(payload.len().min(HID_RPT_SIZE - 7));
    init[7..7 + head.len()].copy_from_slice(head);
    let mut frames = vec![init];
    for (seq, part) in rest.chunks(HID_RPT_SIZE - 5).enumerate() {
        let mut cont = [0u8; HID_RPT_SIZE];
        cont[..4].copy_from_slice(&cid.to_le_bytes());
        cont[4] = seq as u8;
        cont[5..5 + part.len()].copy_from_slice(part);
        frames.push(cont);
    }
    frames
}

/// One message as a host reassembles it off the IN endpoint; `data.len()` is BCNT.
#[derive(Debug, PartialEq, Eq)]
struct Reply {
    cid: u32,
    cmd: u8,
    data: Vec<u8>,
}

/// The host's half of the wire: URBs into the driver, completions back out.
struct Host {
    port: crate::usbip_driver::Port,
    rets: Receiver<Ret>,
    seqnum: u32,
    ep_in: u8,
    ep_out: u8,
    /// The interrupt IN URBs in flight, oldest first.
    reading: VecDeque<u32>,
    /// Reports read and not yet looked at.
    reports: VecDeque<[u8; HID_RPT_SIZE]>,
    /// Every other completion, by sequence number and status.
    done: Vec<(u32, i32)>,
}

impl Host {
    fn submit(&mut self, ep: u8, dir_in: bool, setup: [u8; 8], out: Vec<u8>, want: usize) -> u32 {
        self.seqnum += 1;
        let seqnum = self.seqnum;
        self.port.submit(Urb {
            seqnum,
            ep,
            dir_in,
            setup,
            out,
            want,
        });
        seqnum
    }

    fn read_ahead(&mut self) {
        let seqnum = self.submit(self.ep_in, true, [0; 8], Vec::new(), HID_RPT_SIZE);
        self.reading.push_back(seqnum);
    }

    /// Take every completion posted so far: a report is queued and its URB
    /// replaced; anything else is remembered for [`Self::configure`].
    fn pump(&mut self) {
        while let Ok(ret) = self.rets.try_recv() {
            let Ret::Submit {
                seqnum,
                status,
                data,
                ..
            } = ret
            else {
                continue;
            };
            if self.reading.front() == Some(&seqnum) {
                self.reading.pop_front();
                assert_eq!(status, 0, "the FIDO IN endpoint halted");
                let report = data.try_into().expect("a whole 64-byte report");
                self.reports.push_back(report);
                self.read_ahead();
            } else {
                self.done.push((seqnum, status));
            }
        }
    }

    async fn configure(&mut self) {
        let seqnum = self.submit(0, false, SET_CONFIGURATION, Vec::new(), 0);
        let deadline = Instant::now() + Duration::from_millis(REPLY_MS);
        loop {
            self.pump();
            if let Some(&(_, status)) = self.done.iter().find(|(s, _)| *s == seqnum) {
                assert_eq!(status, 0, "SET_CONFIGURATION refused");
                break;
            }
            assert!(
                Instant::now() < deadline,
                "SET_CONFIGURATION never answered"
            );
            Timer::after_millis(1).await;
        }
        for _ in 0..IN_URBS {
            self.read_ahead();
        }
    }

    fn send(&mut self, frames: &[[u8; HID_RPT_SIZE]]) {
        for frame in frames {
            self.submit(self.ep_out, false, [0; 8], frame.to_vec(), HID_RPT_SIZE);
        }
    }

    /// The next report, if one comes within `ms`.
    async fn report(&mut self, ms: u64) -> Option<[u8; HID_RPT_SIZE]> {
        let deadline = Instant::now() + Duration::from_millis(ms);
        loop {
            self.pump();
            if let Some(report) = self.reports.pop_front() {
                return Some(report);
            }
            if Instant::now() >= deadline {
                return None;
            }
            Timer::after_millis(1).await;
        }
    }

    /// The next whole message, continuation frames and all.
    async fn reply(&mut self) -> Reply {
        let init = self.report(REPLY_MS).await.expect("no reply");
        let cid = u32::from_le_bytes(init[..4].try_into().unwrap());
        let cmd = init[4];
        assert_ne!(
            cmd & TYPE_INIT,
            0,
            "a reply opens with an INIT frame: {init:02x?}"
        );
        let bcnt = u16::from_be_bytes([init[5], init[6]]) as usize;
        let mut data = init[7..].to_vec();
        for seq in 0u8.. {
            if data.len() >= bcnt {
                break;
            }
            let cont = self
                .report(REPLY_MS)
                .await
                .expect("the reply stopped short");
            assert_eq!(
                cont[..4],
                cid.to_le_bytes(),
                "a continuation on another channel"
            );
            assert_eq!(cont[4], seq, "continuations out of order");
            data.extend_from_slice(&cont[5..]);
        }
        data.truncate(bcnt);
        Reply { cid, cmd, data }
    }

    async fn transact(&mut self, cid: u32, cmd: u8, payload: &[u8]) -> Reply {
        self.send(&request(cid, cmd, payload));
        self.reply().await
    }

    /// A channel of our own, allocated on the broadcast CID.
    async fn open_channel(&mut self) -> u32 {
        let r = self.transact(CID_BROADCAST, CTAPHID_INIT, &NONCE).await;
        assert_eq!((r.cid, r.cmd), (CID_BROADCAST, CTAPHID_INIT), "{r:02x?}");
        u32::from_le_bytes(r.data[8..12].try_into().unwrap())
    }
}

/// Build the device as `serve` does — its descriptors, its FIDO interface, its
/// `CtapHid` — with [`Scripted`] in place of the device thread, attach and
/// configure a host, and run `script` against the FIDO interface.
fn on_the_wire<T>(script: impl AsyncFnOnce(&mut Host) -> T) -> T {
    fn leak<V>(v: V) -> &'static mut V {
        Box::leak(Box::new(v))
    }
    let (jobs, _requests) = crate::device::job_queue();
    let (driver, port) = crate::usbip_driver::new();
    let mut builder = Builder::new(
        driver,
        usb_config(false),
        leak([0; CONFIG_DESC_LEN]),
        leak([0; BOS_DESC_LEN]),
        leak([0; MSOS_DESC_LEN]),
        leak([0; CONTROL_BUF_LEN]),
    );
    let (_kbd, fido, _ccid) = declare(
        &mut builder,
        leak(HidState::new()),
        leak(HidState::new()),
        None,
        &jobs,
        rsk_usb::ccid::ATR_RSKEY,
    );
    let mut usb = builder.build();
    let (reader, writer) = fido.split();
    let mut ctap = CtapHid::new(reader, writer, Scripted, touch_pending, cancel_touch);

    let fido_eps = interfaces_in(&config_descriptor()).swap_remove(1).endpoints;
    let ep = |dir_in: bool| {
        let addr = fido_eps.iter().find(|&&a| (a & 0x80 != 0) == dir_in);
        addr.expect("the FIDO interface has both endpoints") & 0x0f
    };
    let (tx, rets) = std::sync::mpsc::channel();
    let mut host = Host {
        port,
        rets,
        seqnum: 0,
        ep_in: ep(true),
        ep_out: ep(false),
        reading: VecDeque::new(),
        reports: VecDeque::new(),
        done: Vec::new(),
    };
    host.port.attach(tx);
    let run = async {
        host.configure().await;
        script(&mut host).await
    };
    match crate::park::block_on(select(run, join(usb.run(), ctap.run()))) {
        Either::First(out) => out,
        Either::Second(_) => unreachable!("the USB stack never returns"),
    }
}

/// hid-1 P-1: an idle device sends nothing — not after the attach, and not once a
/// transaction is over, when a timer left running would show.
#[test]
fn an_idle_device_sends_nothing() {
    on_the_wire(async |host: &mut Host| {
        assert_eq!(
            host.report(QUIET_MS).await,
            None,
            "a report before any request"
        );
        let cid = host.open_channel().await;
        host.transact(cid, CTAPHID_PING, b"one").await;
        assert_eq!(
            host.report(QUIET_MS).await,
            None,
            "a report after the reply"
        );
    });
}

/// hid-1 P-2: a continuation frame with no message before it is ignored
/// (§11.2.5.4) — no error reply for a host to desync on, and no harm to the channel.
#[test]
fn a_stray_continuation_frame_gets_no_answer() {
    on_the_wire(async |host: &mut Host| {
        let cid = host.open_channel().await;
        let mut stray = [0x5a; HID_RPT_SIZE];
        stray[..4].copy_from_slice(&cid.to_le_bytes());
        stray[4] = 0;
        host.send(&[stray]);
        assert_eq!(
            host.report(QUIET_MS).await,
            None,
            "a stray frame was answered"
        );
        let echo = host.transact(cid, CTAPHID_PING, b"after").await;
        assert_eq!(echo.data, b"after");
    });
}

/// hid-1 P-3: an INIT on the broadcast channel, field by field (§11.2.9.1.3). The
/// LOCK bit is U2FHID's CAPFLAG_LOCK, which CTAP 2.3's table omits; the conformance
/// tool reads it to decide whether to test CTAPHID_LOCK at all.
#[test]
fn an_init_on_the_broadcast_channel_allocates_a_channel() {
    on_the_wire(async |host: &mut Host| {
        let r = host.transact(CID_BROADCAST, CTAPHID_INIT, &NONCE).await;
        assert_eq!(
            (r.cid, r.cmd, r.data.len()),
            (CID_BROADCAST, CTAPHID_INIT, 17),
            "{r:02x?}"
        );
        assert_eq!(r.data[..8], NONCE, "the nonce comes back");
        let cid = u32::from_le_bytes(r.data[8..12].try_into().unwrap());
        assert!(cid != 0 && cid != CID_BROADCAST, "allocated {cid:#010x}");
        assert_eq!(r.data[12], 2, "CTAPHID protocol version");
        let caps = r.data[16];
        assert_ne!(caps & CAPFLAG_CBOR, 0, "CTAPHID_CBOR is implemented");
        assert_eq!(caps & CAPABILITY_NMSG, 0, "CTAPHID_MSG is implemented");
        let known = CAPFLAG_WINK | CAPFLAG_LOCK | CAPFLAG_CBOR | CAPABILITY_NMSG;
        assert_eq!(
            caps & !known,
            0,
            "reserved capability bits set: {caps:#04x}"
        );
    });
}

/// hid-1 P-7: an INIT on the channel of an unfinished message aborts it
/// (§11.2.5.3) and answers as a resync does — on that channel, naming it.
#[test]
fn an_init_mid_message_aborts_it_and_resyncs_the_channel() {
    on_the_wire(async |host: &mut Host| {
        let cid = host.open_channel().await;
        let mut ping = request(cid, CTAPHID_PING, &[0x3c; 512]);
        ping.pop();
        host.send(&ping);
        let r = host.transact(cid, CTAPHID_INIT, &NONCE).await;
        assert_eq!(
            (r.cid, r.cmd, r.data.len()),
            (cid, CTAPHID_INIT, 17),
            "{r:02x?}"
        );
        assert_eq!(r.data[..8], NONCE, "the nonce comes back");
        assert_eq!(
            r.data[8..12],
            cid.to_le_bytes(),
            "a resync names its own channel"
        );
        assert_eq!(r.data[12], 2, "CTAPHID protocol version");
        // Nothing of the abandoned PING is left to answer ahead of the next one.
        let echo = host.transact(cid, CTAPHID_PING, b"again").await;
        assert_eq!(echo.data, b"again");
    });
}

/// hid-1 P-8: PING echoes its payload byte for byte. It ends in a zero inside a
/// continuation frame's zero padding, where a length read off the data would stop.
#[test]
fn a_ping_ending_in_zero_comes_back_whole() {
    on_the_wire(async |host: &mut Host| {
        let cid = host.open_channel().await;
        let mut payload: Vec<u8> = (1..=58).collect();
        payload[57] = 0;
        let r = host.transact(cid, CTAPHID_PING, &payload).await;
        assert_eq!(
            r,
            Reply {
                cid,
                cmd: CTAPHID_PING,
                data: payload
            }
        );
    });
}

/// hid-1 P-9: a request waiting for a touch streams `KEEPALIVE(UPNEEDED)` on its
/// own channel (§11.2.9.1.7) — one keepalive is a status, only a stream keeps a
/// platform from timing the request out.
#[test]
fn a_touch_wait_streams_upneeded_keepalives() {
    on_the_wire(async |host: &mut Host| {
        let cid = host.open_channel().await;
        host.send(&request(cid, CTAPHID_CBOR, &[CTAP_MAKE_CREDENTIAL]));
        let keepalive = Reply {
            cid,
            cmd: CTAPHID_KEEPALIVE,
            data: vec![STATUS_UPNEEDED],
        };
        for _ in 0..3 {
            assert_eq!(host.reply().await, keepalive);
        }
    });
}

/// hid-1 P-10: another channel's CANCEL leaves a touch wait running, this channel's
/// ends it with the request's own `KEEPALIVE_CANCEL`, and no CANCEL is answered
/// (§11.2.9.1.5). P-15 is the same exchange with authenticatorSelection, whose
/// applet half is `selection_cancelled_maps_keepalive_cancel`.
#[test]
fn a_cancel_ends_a_touch_wait_and_is_never_answered_itself() {
    on_the_wire(async |host: &mut Host| {
        let cid = host.open_channel().await;
        let stranger = host.open_channel().await;
        host.send(&request(cid, CTAPHID_CBOR, &[CTAP_MAKE_CREDENTIAL]));
        let keepalive = Reply {
            cid,
            cmd: CTAPHID_KEEPALIVE,
            data: vec![STATUS_UPNEEDED],
        };
        assert_eq!(host.reply().await, keepalive);

        // Two, because the first may have left before the CANCEL was read.
        host.send(&request(stranger, CTAPHID_CANCEL, &[]));
        for _ in 0..2 {
            let r = host.reply().await;
            assert_eq!(r, keepalive, "a stranger's CANCEL ended the wait");
        }

        host.send(&request(cid, CTAPHID_CANCEL, &[]));
        let mut r = host.reply().await;
        while r == keepalive {
            r = host.reply().await;
        }
        let cancelled = vec![CtapError::KeepAliveCancel as u8];
        assert_eq!(
            r,
            Reply {
                cid,
                cmd: CTAPHID_CBOR,
                data: cancelled
            }
        );

        host.send(&request(cid, CTAPHID_CANCEL, &[]));
        assert_eq!(host.report(QUIET_MS).await, None, "a CANCEL was answered");
    });
}

/// hid-1 P-13: LOCK(0) is acknowledged on its own channel with an empty body
/// (§11.2.9.2.2), and only after INIT has advertised the command.
#[test]
fn a_lock_release_is_acknowledged_with_an_empty_body() {
    on_the_wire(async |host: &mut Host| {
        let init = host.transact(CID_BROADCAST, CTAPHID_INIT, &NONCE).await;
        assert_ne!(
            init.data[16] & CAPFLAG_LOCK,
            0,
            "CTAPHID_LOCK is advertised"
        );
        let cid = u32::from_le_bytes(init.data[8..12].try_into().unwrap());
        let r = host.transact(cid, CTAPHID_LOCK, &[0]).await;
        assert_eq!(
            r,
            Reply {
                cid,
                cmd: CTAPHID_LOCK,
                data: vec![]
            }
        );
    });
}

/// hid-1 P-14: while one channel holds the lock another channel's INIT is turned
/// away busy, and once it is released the same INIT resyncs that channel.
#[test]
fn a_held_lock_turns_away_another_channels_init_until_released() {
    on_the_wire(async |host: &mut Host| {
        let owner = host.open_channel().await;
        let other = host.open_channel().await;
        let locked = Reply {
            cid: owner,
            cmd: CTAPHID_LOCK,
            data: vec![],
        };
        assert_eq!(host.transact(owner, CTAPHID_LOCK, &[8]).await, locked);
        let busy = Reply {
            cid: other,
            cmd: CTAPHID_ERROR,
            data: vec![ERR_CHANNEL_BUSY],
        };
        assert_eq!(host.transact(other, CTAPHID_INIT, &NONCE).await, busy);

        assert_eq!(host.transact(owner, CTAPHID_LOCK, &[0]).await, locked);
        let r = host.transact(other, CTAPHID_INIT, &NONCE).await;
        assert_eq!(
            (r.cid, r.cmd, r.data.len()),
            (other, CTAPHID_INIT, 17),
            "{r:02x?}"
        );
        assert_eq!(r.data[..8], NONCE, "the nonce comes back");
        assert_eq!(
            r.data[8..12],
            other.to_le_bytes(),
            "a resync names its own channel"
        );
        assert_eq!(r.data[12], 2, "CTAPHID protocol version");
    });
}

/// hid-1 F-1: a command byte CTAPHID leaves unassigned below the vendor range
/// (§11.2.9.3) is ERR_INVALID_CMD. [`Scripted`] answers any vendor command, so
/// one misrouted there would come back as a success.
#[test]
fn an_unassigned_command_is_invalid() {
    on_the_wire(async |host: &mut Host| {
        let cid = host.open_channel().await;
        let r = host.transact(cid, TYPE_INIT | 0x21, &[]).await;
        assert_eq!(
            r,
            Reply {
                cid,
                cmd: CTAPHID_ERROR,
                data: vec![ERR_INVALID_CMD]
            }
        );
    });
}
