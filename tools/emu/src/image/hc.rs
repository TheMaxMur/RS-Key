// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The host's side of the bus on the emulated clock: attach, reset, address, SOF
//! each millisecond, and transfers as tokens — interrupt pipes once per interval,
//! bulk and control back to back with NAK retries — with the host's data toggles.

use std::collections::{HashMap, VecDeque};

use super::usb::{Handshake, SharedUsb};

const BIT_NS: f64 = 1e9 / 12e6;
/// Inter-packet delay and bus turnaround, generously.
const GAP_NS: u64 = 1_000;
const NAK_RETRY_NS: u64 = 10_000;
const FRAME_NS: u64 = 1_000_000;
/// USB 2.0 §7.1.7.3 and §9.2.6.3: attach debounce, the reset a hub drives,
/// the recovery after it, and the one after SET_ADDRESS.
const DEBOUNCE_NS: u64 = 100_000_000;
const RESET_NS: u64 = 20_000_000;
const RESET_RECOVERY_NS: u64 = 10_000_000;
const SET_ADDRESS_RECOVERY_NS: u64 = 2_000_000;
/// While detached, how often the port looks for the pull-up.
const ATTACH_POLL_NS: u64 = 1_000_000;
/// The address this host assigns.
pub const ADDRESS: u8 = 7;
const EP0_MPS: usize = 64;
/// A SETUP unanswered this many times is a device that is not there.
const SETUP_TRIES: u8 = 3;
const CONTROL: (u8, bool) = (0, false);
/// The transfer id of the host's own SET_ADDRESS.
const SET_ADDRESS_ID: u64 = 0;

const REQ_SET_ADDRESS: u8 = 0x05;
const REQ_SET_CONFIGURATION: u8 = 0x09;
const REQ_CLEAR_FEATURE: u8 = 0x01;
const REQ_SET_INTERFACE: u8 = 0x0B;
const REQ_TYPE_MASK: u8 = 0x60;
const RECIPIENT_ENDPOINT: u8 = 0x02;
const RECIPIENT_INTERFACE: u8 = 0x01;
const FEATURE_ENDPOINT_HALT: u16 = 0;

/// Wire time of a packet of `n` bytes: sync, PID, payload with average bit
/// stuffing, CRC and EOP.
fn pkt_ns(n: usize) -> u64 {
    ((8.0 + n as f64 * 8.0 * 1.1 + 3.0) * BIT_NS) as u64
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Bulk,
    Interrupt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub kind: Kind,
    pub mps: usize,
    /// In frames; interrupt endpoints only.
    pub interval: u8,
    pub interface: u8,
}

/// One transfer, as a USB/IP URB or a socket's request describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub ep: u8,
    pub dir_in: bool,
    /// The SETUP packet; EP0 only, and its bit 7 decides the direction there.
    pub setup: [u8; 8],
    pub out: Vec<u8>,
    /// IN: the most the host will take.
    pub want: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The IN data, or empty once all of an OUT's data was taken.
    Done(Vec<u8>),
    Stall,
    /// Nothing answered: detached, reset under the transfer, or powered off.
    Gone,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Completion {
    pub id: u64,
    pub outcome: Outcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Port {
    Detached { poll_at: u64 },
    Debounce { until: u64 },
    Reset { until: u64 },
    Recovery { until: u64 },
    Addressing,
    AddressRecovery { until: u64 },
    Ready,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Setup {
        tries: u8,
    },
    DataIn,
    DataOut,
    StatusIn,
    StatusOut,
    /// The last transaction is on the wire; its buffer IRQ can still run.
    Complete,
    /// A bulk or interrupt transfer's packets.
    Data,
}

struct Active {
    id: u64,
    t: Transfer,
    stage: Stage,
    data: Vec<u8>,
    sent: usize,
    /// The control data stage's DATA PID.
    pid: u8,
    next_ns: u64,
}

impl Active {
    fn control_in(&self) -> bool {
        self.t.setup[0] & 0x80 != 0
    }

    fn w_length(&self) -> usize {
        usize::from(u16::from_le_bytes([self.t.setup[6], self.t.setup[7]]))
    }
}

enum Step {
    Next(u64),
    Finish(Outcome),
}

pub struct Hc {
    usb: SharedUsb,
    port: Port,
    addr: u8,
    frame: u32,
    /// The next SOF, once the port is enabled.
    next_sof: Option<u64>,
    toggles: HashMap<(u8, bool), u8>,
    endpoints: HashMap<(u8, bool), Endpoint>,
    queues: HashMap<(u8, bool), VecDeque<(u64, Transfer)>>,
    active: HashMap<(u8, bool), Active>,
    done: Vec<Completion>,
    next_id: u64,
    /// Protocol trouble a real host would log.
    pub notes: Vec<String>,
}

impl Hc {
    pub fn new(usb: SharedUsb) -> Self {
        Self {
            usb,
            port: Port::Detached { poll_at: 0 },
            addr: 0,
            frame: 0,
            next_sof: None,
            toggles: HashMap::new(),
            endpoints: HashMap::new(),
            queues: HashMap::new(),
            active: HashMap::new(),
            done: Vec::new(),
            next_id: SET_ADDRESS_ID + 1,
            notes: Vec::new(),
        }
    }

    pub fn set_endpoints(&mut self, eps: impl IntoIterator<Item = ((u8, bool), Endpoint)>) {
        self.endpoints = eps.into_iter().collect();
    }

    /// The device is addressed: transfers flow.
    pub fn ready(&self) -> bool {
        self.port == Port::Ready
    }

    pub fn submit(&mut self, t: Transfer) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let key = if t.ep == 0 { CONTROL } else { (t.ep, t.dir_in) };
        self.queues.entry(key).or_default().push_back((id, t));
        id
    }

    /// Drop a transfer the owner gave up on; `true` if it had not completed.
    pub fn cancel(&mut self, id: u64) -> bool {
        for q in self.queues.values_mut() {
            if let Some(i) = q.iter().position(|(qid, _)| *qid == id) {
                q.remove(i);
                return true;
            }
        }
        let key = self
            .active
            .iter()
            .find(|(_, a)| a.id == id)
            .map(|(k, _)| *k);
        key.and_then(|k| self.active.remove(&k)).is_some()
    }

    /// Everything still pending, completed `Gone`: the device is going away.
    pub fn fail_all(&mut self) -> Vec<Completion> {
        let mut ids: Vec<u64> = self.active.drain().map(|(_, a)| a.id).collect();
        for (_, q) in self.queues.drain() {
            ids.extend(q.into_iter().map(|(id, _)| id));
        }
        ids.sort_unstable();
        let mut out = std::mem::take(&mut self.done);
        out.extend(
            ids.into_iter()
                .filter(|&id| id != SET_ADDRESS_ID)
                .map(|id| Completion {
                    id,
                    outcome: Outcome::Gone,
                }),
        );
        out
    }

    fn may_start(&self, key: (u8, bool)) -> bool {
        self.port == Port::Ready || (self.port == Port::Addressing && key == CONTROL)
    }

    /// When [`Self::poll`] next has something to do.
    pub fn next_event(&self) -> u64 {
        let port = match self.port {
            Port::Detached { poll_at } => poll_at,
            Port::Debounce { until }
            | Port::Reset { until }
            | Port::Recovery { until }
            | Port::AddressRecovery { until } => until,
            Port::Addressing | Port::Ready => u64::MAX,
        };
        let active = self.active.values().map(|a| a.next_ns).min();
        let startable = self
            .queues
            .iter()
            .any(|(k, q)| !q.is_empty() && !self.active.contains_key(k) && self.may_start(*k));
        let now = if startable { Some(0) } else { None };
        [Some(port), self.next_sof, active, now]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(u64::MAX)
    }

    /// Do everything due at `now` (emulated ns; `cycle` stamps the device's log)
    /// and hand back what completed.
    pub fn poll(&mut self, now: u64, cycle: u64) -> Vec<Completion> {
        self.port_step(now, cycle);
        if let Some(sof) = self.next_sof
            && now >= sof
        {
            let frames = (now - sof) / FRAME_NS + 1;
            self.frame = ((u64::from(self.frame) + frames) & 0x7FF) as u32;
            self.next_sof = Some(sof + frames * FRAME_NS);
            self.usb.lock().unwrap().host_sof(self.frame);
        }
        let mut keys: Vec<(u8, bool)> = self.queues.keys().copied().collect();
        keys.sort_unstable();
        for key in keys {
            self.service(key, now, cycle);
        }
        std::mem::take(&mut self.done)
    }

    fn port_step(&mut self, now: u64, cycle: u64) {
        let attached = self.usb.lock().unwrap().attached();
        if !attached && !matches!(self.port, Port::Detached { .. }) {
            self.detach(now);
            return;
        }
        self.port = match self.port {
            Port::Detached { poll_at } if now >= poll_at => {
                if attached {
                    Port::Debounce {
                        until: now + DEBOUNCE_NS,
                    }
                } else {
                    Port::Detached {
                        poll_at: now + ATTACH_POLL_NS,
                    }
                }
            }
            Port::Debounce { until } if now >= until => {
                self.bus_reset(cycle);
                Port::Reset {
                    until: now + RESET_NS,
                }
            }
            Port::Reset { until } if now >= until => {
                self.next_sof = Some(now);
                Port::Recovery {
                    until: now + RESET_RECOVERY_NS,
                }
            }
            Port::Recovery { until } if now >= until => {
                let set_address = Transfer {
                    ep: 0,
                    dir_in: false,
                    setup: [0x00, REQ_SET_ADDRESS, ADDRESS, 0, 0, 0, 0, 0],
                    out: Vec::new(),
                    want: 0,
                };
                let q = self.queues.entry(CONTROL).or_default();
                q.push_front((SET_ADDRESS_ID, set_address));
                Port::Addressing
            }
            Port::AddressRecovery { until } if now >= until => Port::Ready,
            p => p,
        };
    }

    fn bus_reset(&mut self, cycle: u64) {
        self.usb.lock().unwrap().host_bus_reset(cycle);
        self.addr = 0;
        self.next_sof = None;
        self.toggles.clear();
    }

    fn detach(&mut self, now: u64) {
        let failed = self.fail_all();
        self.done = failed;
        self.addr = 0;
        self.next_sof = None;
        self.toggles.clear();
        self.port = Port::Detached {
            poll_at: now + ATTACH_POLL_NS,
        };
    }

    fn endpoint(&self, key: (u8, bool)) -> Endpoint {
        self.endpoints.get(&key).copied().unwrap_or(Endpoint {
            kind: Kind::Bulk,
            mps: 64,
            interval: 1,
            interface: 0,
        })
    }

    /// When an interrupt pipe may try again: the frame `interval` frames on.
    fn next_interval(&self, now: u64, interval: u8) -> u64 {
        let sof = self.next_sof.unwrap_or(now + FRAME_NS);
        sof + u64::from(interval.max(1) - 1) * FRAME_NS
    }

    fn service(&mut self, key: (u8, bool), now: u64, cycle: u64) {
        if !self.active.contains_key(&key) {
            if !self.may_start(key) {
                return;
            }
            let Some((id, t)) = self.queues.get_mut(&key).and_then(VecDeque::pop_front) else {
                return;
            };
            let (stage, next_ns) = if key == CONTROL {
                (Stage::Setup { tries: 0 }, now)
            } else if self.endpoint(key).kind == Kind::Interrupt {
                (Stage::Data, self.next_interval(now, 1))
            } else {
                (Stage::Data, now)
            };
            let a = Active {
                id,
                t,
                stage,
                data: Vec::new(),
                sent: 0,
                pid: 1,
                next_ns,
            };
            self.active.insert(key, a);
        }
        let Some(mut a) = self.active.remove(&key) else {
            return;
        };
        if a.next_ns > now {
            self.active.insert(key, a);
            return;
        }
        let step = if matches!(a.stage, Stage::Complete) {
            Step::Finish(Outcome::Done(std::mem::take(&mut a.data)))
        } else if key == CONTROL {
            self.control_token(&mut a, now, cycle)
        } else {
            self.data_token(key, &mut a, now, cycle)
        };
        match step {
            Step::Next(t) => {
                a.next_ns = t;
                self.active.insert(key, a);
            }
            Step::Finish(outcome) => self.finish(a, outcome, now),
        }
    }

    fn control_token(&mut self, a: &mut Active, now: u64, cycle: u64) -> Step {
        let addr = self.addr;
        let usb = self.usb.clone();
        let mut u = usb.lock().unwrap();
        match a.stage {
            Stage::Setup { tries } => match u.host_setup(addr, a.t.setup, cycle) {
                Handshake::Ack => {
                    a.pid = 1;
                    a.stage = if a.control_in() && a.w_length() > 0 {
                        Stage::DataIn
                    } else if !a.control_in() && !a.t.out.is_empty() {
                        Stage::DataOut
                    } else {
                        Stage::StatusIn
                    };
                    Step::Next(now + pkt_ns(3) + GAP_NS + pkt_ns(11) + GAP_NS + pkt_ns(1))
                }
                _ if tries + 1 < SETUP_TRIES => {
                    a.stage = Stage::Setup { tries: tries + 1 };
                    Step::Next(now + NAK_RETRY_NS)
                }
                _ => Step::Finish(Outcome::Gone),
            },
            Stage::DataIn => match u.host_in(addr, 0, cycle) {
                Ok((pid, d)) => {
                    if pid == a.pid {
                        a.pid ^= 1;
                        let short = d.len() < EP0_MPS;
                        a.data.extend_from_slice(&d);
                        if short || a.data.len() >= a.w_length() {
                            a.stage = Stage::StatusOut;
                        }
                    } else {
                        self.notes
                            .push(format!("EP0 IN DATA{pid} where DATA{} was due", a.pid));
                    }
                    Step::Next(now + pkt_ns(3) + GAP_NS + pkt_ns(d.len() + 3) + GAP_NS)
                }
                Err(hs) => self.refused(hs, now + NAK_RETRY_NS),
            },
            Stage::DataOut => {
                let end = (a.sent + EP0_MPS).min(a.t.out.len());
                match u.host_out(addr, 0, a.pid, &a.t.out[a.sent..end], cycle) {
                    Handshake::Ack => {
                        let n = end - a.sent;
                        a.pid ^= 1;
                        a.sent = end;
                        if a.sent == a.t.out.len() {
                            a.stage = Stage::StatusIn;
                        }
                        Step::Next(now + pkt_ns(3) + GAP_NS + pkt_ns(n + 3) + GAP_NS)
                    }
                    hs => self.refused(hs, now + NAK_RETRY_NS),
                }
            }
            Stage::StatusIn => match u.host_in(addr, 0, cycle) {
                Ok((pid, d)) => {
                    if pid != 1 || !d.is_empty() {
                        self.notes
                            .push(format!("status stage DATA{pid} with {} bytes", d.len()));
                    }
                    a.data.clear();
                    Self::packet_complete(a, now, 0)
                }
                Err(hs) => self.refused(hs, now + NAK_RETRY_NS),
            },
            Stage::StatusOut => match u.host_out(addr, 0, 1, &[], cycle) {
                Handshake::Ack => {
                    a.data.truncate(a.t.want.min(a.w_length()));
                    Self::packet_complete(a, now, 0)
                }
                hs => self.refused(hs, now + NAK_RETRY_NS),
            },
            Stage::Data | Stage::Complete => Step::Finish(Outcome::Gone),
        }
    }

    fn packet_complete(a: &mut Active, now: u64, length: usize) -> Step {
        // A follow-up command before the ACK races nsboot's pending buffer IRQ.
        a.stage = Stage::Complete;
        Step::Next(Self::packet_end(now, length))
    }

    fn packet_end(now: u64, length: usize) -> u64 {
        now + pkt_ns(3) + GAP_NS + pkt_ns(length + 3) + GAP_NS + pkt_ns(1)
    }

    fn data_token(&mut self, key: (u8, bool), a: &mut Active, now: u64, cycle: u64) -> Step {
        let ep = self.endpoint(key);
        let retry = match ep.kind {
            Kind::Bulk => now + NAK_RETRY_NS,
            Kind::Interrupt => self.next_interval(now, ep.interval),
        };
        let toggle = *self.toggles.get(&key).unwrap_or(&0);
        let usb = self.usb.clone();
        let mut u = usb.lock().unwrap();
        if key.1 {
            match u.host_in(self.addr, key.0, cycle) {
                Ok((pid, d)) => {
                    let spent = Self::packet_end(now, d.len());
                    let next = match ep.kind {
                        Kind::Bulk => spent,
                        Kind::Interrupt => retry,
                    };
                    if pid != toggle {
                        // A host takes a repeated toggle for a retransmission it
                        // already has: acknowledged, and dropped.
                        self.notes.push(format!(
                            "EP{} IN DATA{pid} where DATA{toggle} was due",
                            key.0
                        ));
                        return Step::Next(next);
                    }
                    self.toggles.insert(key, toggle ^ 1);
                    let short = d.len() < ep.mps;
                    a.data.extend_from_slice(&d);
                    if short || a.data.len() >= a.t.want {
                        return Self::packet_complete(a, now, d.len());
                    }
                    Step::Next(next)
                }
                Err(hs) => self.refused(hs, retry),
            }
        } else {
            let end = (a.sent + ep.mps).min(a.t.out.len());
            match u.host_out(self.addr, key.0, toggle, &a.t.out[a.sent..end], cycle) {
                Handshake::Ack => {
                    self.toggles.insert(key, toggle ^ 1);
                    let length = end - a.sent;
                    let spent = Self::packet_end(now, length);
                    a.sent = end;
                    if a.sent == a.t.out.len() {
                        return Self::packet_complete(a, now, length);
                    }
                    Step::Next(match ep.kind {
                        Kind::Bulk => spent,
                        Kind::Interrupt => retry,
                    })
                }
                hs => self.refused(hs, retry),
            }
        }
    }

    fn refused(&self, hs: Handshake, retry: u64) -> Step {
        match hs {
            Handshake::Nak => Step::Next(retry),
            Handshake::Stall => Step::Finish(Outcome::Stall),
            Handshake::Ack | Handshake::Timeout => Step::Finish(Outcome::Gone),
        }
    }

    fn finish(&mut self, a: Active, outcome: Outcome, now: u64) {
        if a.t.ep == 0 && outcome == Outcome::Done(Vec::new()) {
            self.snoop(&a.t.setup);
        }
        if a.id == SET_ADDRESS_ID {
            self.port = if matches!(outcome, Outcome::Done(_)) {
                Port::AddressRecovery {
                    until: now + SET_ADDRESS_RECOVERY_NS,
                }
            } else {
                // Refused its address: start over, as a hub would.
                Port::Debounce { until: now }
            };
            return;
        }
        self.done.push(Completion { id: a.id, outcome });
    }

    /// What a completed standard request changes on the host's side of the pipe.
    fn snoop(&mut self, setup: &[u8; 8]) {
        if setup[0] & REQ_TYPE_MASK != 0 {
            return; // class or vendor: HID's SET_PROTOCOL shares SET_INTERFACE's number
        }
        let value = u16::from_le_bytes([setup[2], setup[3]]);
        let index = u16::from_le_bytes([setup[4], setup[5]]);
        let recipient = setup[0] & 0x1F;
        match setup[1] {
            REQ_SET_ADDRESS if setup[0] == 0 => self.addr = (value & 0x7F) as u8,
            REQ_SET_CONFIGURATION if setup[0] == 0 => self.toggles.clear(),
            REQ_CLEAR_FEATURE
                if recipient == RECIPIENT_ENDPOINT && value == FEATURE_ENDPOINT_HALT =>
            {
                self.toggles
                    .remove(&((index & 0x0F) as u8, index & 0x80 != 0));
            }
            REQ_SET_INTERFACE if recipient == RECIPIENT_INTERFACE => {
                let iface = (index & 0xFF) as u8;
                let keys: Vec<_> = self
                    .endpoints
                    .iter()
                    .filter(|(_, e)| e.interface == iface)
                    .map(|(k, _)| *k)
                    .collect();
                for k in keys {
                    self.toggles.remove(&k);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
#[path = "hc_tests.rs"]
mod tests;
