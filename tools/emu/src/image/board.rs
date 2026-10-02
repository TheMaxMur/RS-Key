// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The chip thread: power, emulated time held to the wall clock, and the host
//! that owns the bus — the socket bridge behind `tests/emu.py`'s ports, or a
//! USB/IP client — one at a time, as one key moves between two computers.

use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rsk_usb::ccid::{CCID_DATA_BLOCK_RET, HEADER, MAX_CCID_MSG, STATUS_TIMEEXT, WTX_INTERVAL_MS};
use rsk_usb::ctaphid::{CID_BROADCAST, CTAPHID_INIT, CTAPHID_KEEPALIVE, STATUS_UPNEEDED};

use super::chip::{Chip, RUN_QUANTUM, SCRATCH_REGS, Stop};
use super::desc::{self, Device};
use super::elf::Elf;
use super::flash::Flash;
use super::hc::{Completion, Hc, Outcome, Transfer};
use super::inspect::{self, Command};
use super::otp;
use super::sockets::{self, CcidReply, Report, Request, UsbipInfo, UsbipPort};
use super::trng::next_boot_seed;
use crate::usbip::{BUSID, ESHUTDOWN, Ret, Urb, UsbDeviceInfo};

/// The longest step a parked chip takes: an interrupt raised inside one is taken
/// at its end.
const PARKED_STEP_NS: u64 = 1_000_000;
/// While a core runs, the wall clock and the chip-level checks are looked at
/// every this many steps.
const CHECK_EVERY: u64 = 16;
/// The longest the thread sleeps while emulated time is ahead of the wall.
const WAIT_SLICE: Duration = Duration::from_millis(2);
const DEAD_WAIT: Duration = Duration::from_secs(3600);
const TOUCH_NS: u64 = 500_000_000;
/// How often `--trace` says where the cores are.
const WHEREABOUTS_EVERY: Duration = Duration::from_secs(5);
/// Twenty-five missed time extensions: no answer is coming.
const CCID_SILENCE_NS: u64 = 25 * WTX_INTERVAL_MS * 1_000_000;
/// bmCommandStatus, the top two bits of a CCID answer's bStatus.
const COMMAND_STATUS: u8 = 0xC0;
const SEED_LEN: usize = 32;
/// Broadcast INITs whose answer may still be on its way, per device.
const PENDING_INITS: usize = 16;
/// Reports held for a device that is still enumerating.
const HELD_REPORTS: usize = 4096;
const USB_SPEED_FULL: u32 = 2;
const GET_DESCRIPTOR: u8 = 0x06;
const SET_CONFIGURATION: u8 = 0x09;
const DESC_DEVICE: u8 = 0x01;
const DESC_CONFIG: u8 = 0x02;
const DESC_REPORT: u8 = 0x22;
const CONFIG_HEADER_LEN: u16 = 9;
const DEVICE_DESC_LEN: u16 = 18;
/// bmRequestType for a standard IN request to an interface.
const TO_INTERFACE_IN: u8 = 0x81;
const REPORT_LEN: usize = 64;

pub struct Options {
    pub image: PathBuf,
    pub rom: Option<PathBuf>,
    pub store: Option<PathBuf>,
    pub host: String,
    pub fido_port: u16,
    pub ccid_port: u16,
    pub usbip: Option<String>,
    pub touch: bool,
    pub seed: Option<Vec<u8>>,
    pub serial: [u8; 8],
    pub trace: bool,
    pub inspect_port: Option<u16>,
}

/// Why a power-up ended, and so what the next one keeps.
#[derive(Debug, PartialEq, Eq)]
enum End {
    /// A reset the image asked for: the watchdog scratch survives it.
    Warm {
        bootsel: bool,
    },
    PowerCycle,
}

#[derive(Default)]
enum BootMode {
    #[default]
    Image,
    UsbBootloader,
}

impl BootMode {
    fn handover(&self) -> End {
        match self {
            Self::Image => End::PowerCycle,
            Self::UsbBootloader => End::Warm { bootsel: true },
        }
    }
}

enum Flow {
    Run,
    End(End),
    Dead,
}

enum Owner {
    Sockets,
    Usbip {
        rets: Sender<Ret>,
        /// Transfer id -> the URB's seqnum, direction and OUT length.
        urbs: HashMap<u64, (u32, bool, usize)>,
    },
}

/// The socket bridge configuring the device, a request at a time.
enum Configure {
    Idle,
    Device(u64),
    Config9 {
        id: u64,
        device: Vec<u8>,
    },
    Config {
        id: u64,
        device: Vec<u8>,
    },
    Report {
        id: u64,
        dev: Device,
        hid: Vec<u8>,
        i: usize,
    },
    SetConfig {
        id: u64,
        dev: Device,
    },
    Done,
    Failed,
}

impl Configure {
    fn waits_on(&self, done: u64) -> bool {
        match self {
            Self::Device(id)
            | Self::Config9 { id, .. }
            | Self::Config { id, .. }
            | Self::Report { id, .. }
            | Self::SetConfig { id, .. } => *id == done,
            Self::Idle | Self::Done | Self::Failed => false,
        }
    }
}

/// CTAPHID replies go to the connection that owns their channel, as hidraw hands
/// each reader the replies to its own; a broadcast INIT's to whoever sent its
/// nonce; anything unclaimed to every connection, as hidraw does.
#[derive(Default)]
struct HidRoutes {
    conns: HashMap<u64, Sender<Report>>,
    owners: HashMap<[u8; 4], u64>,
    inits: VecDeque<(u64, [u8; 8])>,
}

fn cid(r: &Report) -> [u8; 4] {
    [r[0], r[1], r[2], r[3]]
}

fn nonce(r: &Report) -> [u8; 8] {
    let mut n = [0u8; 8];
    n.copy_from_slice(&r[7..15]);
    n
}

impl HidRoutes {
    fn close(&mut self, conn: u64) {
        self.conns.remove(&conn);
        self.owners.retain(|_, c| *c != conn);
        self.inits.retain(|(c, _)| *c != conn);
    }

    fn outgoing(&mut self, conn: u64, r: &Report) {
        if cid(r) != CID_BROADCAST.to_be_bytes() {
            self.owners.insert(cid(r), conn);
        } else if r[4] == CTAPHID_INIT {
            self.inits.push_back((conn, nonce(r)));
            if self.inits.len() > PENDING_INITS {
                self.inits.pop_front();
            }
        }
    }

    fn incoming(&mut self, r: Report) {
        let to = if cid(&r) == CID_BROADCAST.to_be_bytes() && r[4] == CTAPHID_INIT {
            let at = self.inits.iter().position(|(_, n)| *n == nonce(&r));
            let conn = at.and_then(|i| self.inits.remove(i)).map(|(c, _)| c);
            if let Some(c) = conn {
                self.owners.insert([r[15], r[16], r[17], r[18]], c);
            }
            conn
        } else {
            self.owners.get(&cid(&r)).copied()
        };
        match to.and_then(|c| self.conns.get(&c).map(|tx| (c, tx.send(r).is_ok()))) {
            Some((_, true)) => {}
            Some((c, false)) => self.close(c),
            None => {
                for tx in self.conns.values() {
                    let _ = tx.send(r);
                }
            }
        }
    }
}

fn is_time_extension(m: &[u8]) -> bool {
    m.len() >= HEADER && m[0] == CCID_DATA_BLOCK_RET && m[7] & COMMAND_STATUS == STATUS_TIMEEXT
}

struct CcidFlight {
    reply: Sender<CcidReply>,
    out_id: Option<u64>,
    in_id: u64,
    /// When the device last answered, once the message is all out.
    quiet_since: Option<u64>,
}

struct Board {
    opts: Options,
    rom: Vec<u8>,
    elf: Arc<Elf>,
    seed: Vec<u8>,
    flash: Flash,
    otp_path: Option<PathBuf>,
    rx: Receiver<Request>,
    tx: Sender<Request>,
    chip: Chip,
    hc: Hc,
    origin: Instant,
    owner: Owner,
    bootsel: bool,
    device: Option<Device>,
    configure: Configure,
    hid: HidRoutes,
    held: VecDeque<Report>,
    fido_in: Option<u64>,
    ccid_queue: VecDeque<(Vec<u8>, Sender<CcidReply>)>,
    ccid: Option<CcidFlight>,
    replugs: Vec<Sender<()>>,
    press_until: Option<u64>,
    usbip_info: Option<Arc<Mutex<UsbipInfo>>>,
    boot_mode: BootMode,
    announced: bool,
    last_whereabouts: Instant,
    /// A keepalive has already said the key wants a touch.
    touch_asked: bool,
    cut_cycles: Option<u64>,
    cut_at: Option<u64>,
    last_cut: String,
    power_ups: u64,
}

/// Serve the image until the process is killed.
pub fn run(opts: Options) -> Result<(), String> {
    let mut board = Board::new(opts)?;
    loop {
        let end = board.serve()?;
        board.unplug()?;
        let scratch = match end {
            End::Warm { .. } => Some(board.chip.scratch()),
            End::PowerCycle => {
                board.hid.owners.clear();
                board.hid.inits.clear();
                None
            }
        };
        board.bootsel = matches!(end, End::Warm { bootsel: true });
        board.power_up(scratch)?;
    }
}

impl Board {
    fn new(opts: Options) -> Result<Self, String> {
        let read = |p: &PathBuf| std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()));
        let elf = Arc::new(Elf::parse(&read(&opts.image)?)?);
        let rom = match &opts.rom {
            Some(p) => read(p)?,
            None => rp2350_emu::load_pinned_silicon_bootrom()
                .map_err(|e| format!("the bootrom picoem pins: {e}"))?,
        };
        let seed = match &opts.seed {
            Some(s) => s.clone(),
            None => {
                let mut s = vec![0u8; SEED_LEN];
                std::fs::File::open("/dev/urandom")
                    .and_then(|mut f| f.read_exact(&mut s))
                    .map_err(|e| format!("no entropy from /dev/urandom: {e}"))?;
                s
            }
        };
        let (flash, fresh) = Flash::open(opts.store.as_deref(), &elf)?;
        let otp_path = opts.store.as_ref().map(|p| {
            let mut s = p.clone().into_os_string();
            s.push(".otp");
            PathBuf::from(s)
        });
        let rows = match &otp_path {
            Some(p) => {
                let (rows, _) = otp::load_rows(p, opts.serial)?;
                otp::save_rows(p, &rows)?;
                rows
            }
            None => otp::factory_rows(opts.serial),
        };
        let rom_name = match &opts.rom {
            Some(p) => p.display().to_string(),
            None => "picoem's pinned A4 bootrom".into(),
        };
        let store = match &opts.store {
            Some(p) if fresh => format!("{} (new)", p.display()),
            Some(p) => format!("{} (kept)", p.display()),
            None => "memory".into(),
        };
        eprintln!(
            "emu: image {} on an emulated RP2350 — {rom_name}, flash and OTP in {store}",
            opts.image.display()
        );

        let (tx, rx) = mpsc::channel();
        let bind = |port: u16, what: &str| {
            TcpListener::bind((opts.host.as_str(), port))
                .map_err(|e| format!("cannot bind the {what} port {}:{port}: {e}", opts.host))
        };
        if opts.fido_port != 0 {
            let l = bind(opts.fido_port, "fido")?;
            let (host, port) = (&opts.host, opts.fido_port);
            eprintln!("emu: CTAPHID on {host}:{port} (64-byte reports, both ways)");
            let chip = tx.clone();
            std::thread::spawn(move || sockets::listen_hid(l, chip));
        }
        if opts.ccid_port != 0 {
            let l = bind(opts.ccid_port, "ccid")?;
            let (host, port) = (&opts.host, opts.ccid_port);
            eprintln!("emu: CCID messages on {host}:{port} (the image's identity)");
            let chip = tx.clone();
            std::thread::spawn(move || sockets::listen_ccid(l, chip));
        }
        if opts.touch {
            let ms = TOUCH_NS / 1_000_000;
            eprintln!("emu: each line on the terminal holds BOOTSEL down for {ms} ms");
            sockets::read_touches(tx.clone());
        }
        if let Some(port) = opts.inspect_port {
            let listener = TcpListener::bind(("127.0.0.1", port))
                .map_err(|e| format!("cannot bind inspection port: {e}"))?;
            eprintln!(
                "emu: image inspection on {}",
                listener.local_addr().map_err(|e| e.to_string())?
            );
            let chip = tx.clone();
            std::thread::spawn(move || inspect::listen(listener, chip));
        }

        let chip = Chip::power_up(&rom, elf.clone(), &seed, &flash, rows, None)?;
        let hc = Hc::new(chip.usb.clone());
        Ok(Self {
            opts,
            rom,
            elf,
            seed,
            flash,
            otp_path,
            rx,
            tx,
            chip,
            hc,
            origin: Instant::now(),
            owner: Owner::Sockets,
            bootsel: false,
            device: None,
            configure: Configure::Idle,
            hid: HidRoutes::default(),
            held: VecDeque::new(),
            fido_in: None,
            ccid_queue: VecDeque::new(),
            ccid: None,
            replugs: Vec::new(),
            press_until: None,
            usbip_info: None,
            boot_mode: BootMode::Image,
            announced: false,
            last_whereabouts: Instant::now(),
            touch_asked: false,
            cut_cycles: None,
            cut_at: None,
            last_cut: "none".into(),
            power_ups: 1,
        })
    }

    /// The device leaves the bus: its flash and fuses are kept, and whatever was
    /// in flight to it fails.
    fn unplug(&mut self) -> Result<(), String> {
        self.chip.sync_flash(&mut self.flash)?;
        self.save_otp(&self.chip.otp_rows())?;
        self.configure = Configure::Failed;
        for c in self.hc.fail_all() {
            self.completed(c, 0);
        }
        self.held.clear();
        self.fido_in = None;
        if let Some(f) = self.ccid.take() {
            let _ = f.reply.send(CcidReply::Gone);
        }
        for (_, reply) in self.ccid_queue.drain(..) {
            let _ = reply.send(CcidReply::Gone);
        }
        Ok(())
    }

    fn power_up(&mut self, scratch: Option<[u32; SCRATCH_REGS]>) -> Result<(), String> {
        let rows = self.chip.otp_rows();
        // Replaying one entropy stream can regenerate the key a reset just deleted.
        let seed = next_boot_seed(&self.seed);
        let chip = Chip::power_up(
            &self.rom,
            self.elf.clone(),
            &seed,
            &self.flash,
            rows,
            scratch,
        )?;
        self.chip = chip;
        self.boot_mode = BootMode::Image;
        self.announced = false;
        self.seed = seed.to_vec();
        self.power_ups += 1;
        self.cut_at = None;
        self.cut_cycles = None;
        self.hc = Hc::new(self.chip.usb.clone());
        if let (Owner::Usbip { .. }, Some(dev)) = (&self.owner, &self.device) {
            self.hc.set_endpoints(dev.endpoints());
        }
        if self.bootsel {
            self.chip.press_bootsel(true);
        }
        self.configure = Configure::Idle;
        self.press_until = None;
        self.origin = Instant::now();
        Ok(())
    }

    fn save_otp(&self, rows: &[u32]) -> Result<(), String> {
        match &self.otp_path {
            Some(p) => otp::save_rows(p, rows),
            None => Ok(()),
        }
    }

    fn wall_ns(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    /// Run this power-up until it ends. Emulated time never runs ahead of the
    /// wall clock, so every timeout the image keeps means what it means on a desk.
    fn serve(&mut self) -> Result<End, String> {
        let mut dead = false;
        let mut next = self.next_event();
        let mut steps = 0u64;
        loop {
            let mut asked = false;
            while let Ok(r) = self.rx.try_recv() {
                asked = true;
                if let Some(end) = self.request(r, dead) {
                    return Ok(end);
                }
            }
            let parked = self.chip.parked();
            let now = self.chip.now_ns();
            let ahead = if parked || steps.is_multiple_of(CHECK_EVERY) {
                now.saturating_sub(self.wall_ns())
            } else {
                0
            };
            if dead || ahead > 0 {
                let wait = if dead {
                    DEAD_WAIT
                } else {
                    Duration::from_nanos(ahead).min(WAIT_SLICE)
                };
                match self.rx.recv_timeout(wait) {
                    Ok(r) => {
                        if let Some(end) = self.request(r, dead) {
                            return Ok(end);
                        }
                        next = self.next_event();
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => {
                        return Err("every transport is gone".into());
                    }
                }
                continue;
            }
            if asked {
                next = self.next_event();
            }
            if self.cut_at.is_some_and(|at| self.chip.cycles() >= at)
                || self.chip.program_cut().is_some()
            {
                let cycle = self.chip.cycles();
                let flash = self.chip.cut_flash();
                self.last_cut = format!("cycle={cycle} flash={flash}");
                self.chip.sync_flash(&mut self.flash)?;
                if let Some(store) = &self.opts.store {
                    let mut path = store.clone().into_os_string();
                    path.push(".cut");
                    self.flash.snapshot(&PathBuf::from(path))?;
                }
                eprintln!("emu: power cut {}", self.last_cut);
                return Ok(End::PowerCycle);
            }
            let cycles = if self.chip.measuring()
                || self.cut_at.is_some()
                || self.chip.program_cut_armed()
            {
                1
            } else if parked {
                let ns = next.saturating_sub(now).clamp(1, PARKED_STEP_NS);
                u32::try_from(self.chip.cycles_in(ns)).unwrap_or(u32::MAX)
            } else {
                RUN_QUANTUM
            };
            self.chip.step(cycles)?;
            steps += 1;
            if self.cut_at.is_some_and(|at| self.chip.cycles() >= at)
                || self.chip.program_cut().is_some()
            {
                continue;
            }
            if parked || steps.is_multiple_of(CHECK_EVERY) {
                if let Some(stop) = self.chip.check() {
                    match self.stopped(stop) {
                        Flow::Run => {}
                        Flow::End(end) => return Ok(end),
                        Flow::Dead => dead = true,
                    }
                }
                self.chip.sync_flash(&mut self.flash)?;
                if let Some(rows) = self.chip.otp_burned() {
                    self.save_otp(&rows)?;
                }
                self.drain_log();
            }
            let now = self.chip.now_ns();
            if now >= next {
                self.poll(now);
                next = self.next_event();
            }
        }
    }

    fn next_event(&self) -> u64 {
        let silence = self
            .ccid
            .as_ref()
            .and_then(|f| f.quiet_since)
            .map(|t| t + CCID_SILENCE_NS);
        [Some(self.hc.next_event()), self.press_until, silence]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(u64::MAX)
    }

    fn drain_log(&mut self) {
        let lines = self.chip.drain_log();
        if !self.opts.trace {
            return;
        }
        for (cycle, line) in lines {
            eprintln!("emu: [cycle {cycle}] {line}");
        }
        if self.last_whereabouts.elapsed() >= WHEREABOUTS_EVERY {
            self.last_whereabouts = Instant::now();
            let ms = self.chip.now_ns() / 1_000_000;
            eprintln!("emu: [{ms} ms] {}", self.chip.whereabouts());
        }
    }

    fn stopped(&mut self, stop: Stop) -> Flow {
        match stop {
            Stop::Reboot { bootsel } => {
                let into = if bootsel { " into BOOTSEL" } else { "" };
                eprintln!("emu: the image rebooted{into}");
                Flow::End(End::Warm { bootsel })
            }
            Stop::Nsboot(_) if self.bootsel => {
                self.chip.press_bootsel(false);
                self.bootsel = false;
                self.boot_mode = BootMode::UsbBootloader;
                eprintln!("emu: in the USB bootloader until a power cycle");
                Flow::Run
            }
            Stop::Nsboot(why) => {
                self.boot_mode = BootMode::UsbBootloader;
                eprintln!("emu: the bootrom launched no image and entered BOOTSEL: {why}");
                Flow::Run
            }
            Stop::Dead(why) => {
                eprintln!("emu: the image stopped: {why}; nothing answers until a replug");
                if let Err(e) = self.unplug() {
                    eprintln!("emu: {e}");
                }
                self.answer_replugs();
                Flow::Dead
            }
        }
    }

    fn request(&mut self, r: Request, dead: bool) -> Option<End> {
        let bridged = !dead && matches!(self.owner, Owner::Sockets);
        if matches!(r, Request::HidReport { .. } | Request::Ccid { .. })
            && let Some(after) = self.cut_cycles.take()
        {
            self.cut_at = Some(self.chip.cycles().saturating_add(after));
        }
        match r {
            Request::Inspect { command, reply } => {
                let result = self.inspect(command, dead);
                let _ = reply.send(result);
            }
            Request::HidOpen { conn, reports } => {
                self.hid.conns.insert(conn, reports);
            }
            Request::HidClose { conn } => self.hid.close(conn),
            Request::HidReport { conn, report } => {
                self.hid.outgoing(conn, &report);
                match (&self.configure, self.fido_out()) {
                    _ if !bridged => {}
                    (Configure::Done, Some(ep)) => {
                        self.hc.submit(out(ep, &report));
                    }
                    (Configure::Done | Configure::Failed, _) => {}
                    _ if self.held.len() < HELD_REPORTS => self.held.push_back(report),
                    _ => {}
                }
            }
            Request::Ccid { msg, reply } => {
                if bridged && !matches!(self.configure, Configure::Failed) {
                    self.ccid_queue.push_back((msg, reply));
                    self.ccid_next();
                } else {
                    let _ = reply.send(CcidReply::Gone);
                }
            }
            Request::Replug { done } => {
                eprintln!("emu: replug — a power cycle");
                self.replugs.push(done);
                return Some(End::PowerCycle);
            }
            Request::Touch => {
                self.chip.press_bootsel(true);
                self.press_until = Some(self.chip.now_ns() + TOUCH_NS);
            }
            Request::UsbipAttach { rets } => {
                let urbs = HashMap::new();
                self.owner = Owner::Usbip { rets, urbs };
                return Some(self.boot_mode.handover());
            }
            Request::Urb(urb) => self.submit_urb(urb, dead),
            Request::Unlink { seqnum, pending } => {
                let mut found = false;
                if let Owner::Usbip { urbs, .. } = &mut self.owner {
                    let id = urbs.iter().find(|(_, u)| u.0 == seqnum).map(|(id, _)| *id);
                    if let Some(id) = id {
                        urbs.remove(&id);
                        found = self.hc.cancel(id);
                    }
                }
                let _ = pending.send(found);
            }
            Request::UsbipDetach => {
                self.owner = Owner::Sockets;
                return Some(self.boot_mode.handover());
            }
        }
        None
    }

    fn inspect(&mut self, command: Command, dead: bool) -> Result<String, String> {
        match command {
            Command::Status => Ok(format!(
                "cycle={} ready={} dead={} bootloader={} power_ups={} programmed_bytes={} last_cut={}",
                self.chip.cycles(),
                matches!(self.configure, Configure::Done),
                dead,
                matches!(self.boot_mode, BootMode::UsbBootloader),
                self.power_ups,
                self.chip.programmed_bytes(),
                self.last_cut
            )),
            Command::Begin if !matches!(self.configure, Configure::Done) || dead => {
                Err("device is not ready".into())
            }
            Command::Begin => self.chip.begin_measurement(),
            Command::End => self.chip.end_measurement(),
            Command::Scan(pattern) => Ok(self.chip.scan_sram(&pattern)),
            Command::Read { address, length } => Ok(self.chip.read_sram(address, length)),
            Command::Plant { address, bytes } => {
                self.chip.plant_sram(address, &bytes);
                Ok(format!("planted={} address={address:#x}", bytes.len()))
            }
            Command::CutCycles(after) => {
                self.chip.arm_cycles();
                self.cut_at = None;
                self.cut_cycles = Some(after);
                Ok(format!("armed=cycles after={after} starts=next-transfer"))
            }
            Command::CutProgram(bytes) => {
                self.cut_cycles = None;
                self.cut_at = None;
                self.chip.arm_program_cut(bytes);
                Ok(format!("armed=program bytes={bytes}"))
            }
            Command::CutProgramCycles(cycles) => {
                self.cut_cycles = None;
                self.cut_at = None;
                self.chip.arm_program_cycles(cycles);
                Ok(format!("armed=program-cycles after={cycles}"))
            }
        }
    }

    fn submit_urb(&mut self, urb: Urb, dead: bool) {
        let Owner::Usbip { rets, urbs } = &mut self.owner else {
            return;
        };
        if dead {
            let _ = rets.send(gone(urb.seqnum));
            return;
        }
        // On EP0 the SETUP packet says which way the data stage runs.
        let dir_in = if urb.ep == 0 {
            urb.setup[0] & 0x80 != 0
        } else {
            urb.dir_in
        };
        let out_len = urb.out.len();
        let id = self.hc.submit(Transfer {
            ep: urb.ep,
            dir_in,
            setup: urb.setup,
            out: urb.out,
            want: urb.want,
        });
        urbs.insert(id, (urb.seqnum, dir_in, out_len));
    }

    fn fido_out(&self) -> Option<u8> {
        self.device.as_ref()?.fido.map(|(_, o)| o)
    }

    fn poll(&mut self, now: u64) {
        if self.press_until.is_some_and(|t| now >= t) {
            self.chip.press_bootsel(false);
            self.press_until = None;
        }
        for c in self.hc.poll(now, self.chip.cycles()) {
            self.completed(c, now);
        }
        for n in self.hc.notes.drain(..) {
            eprintln!("emu: host: {n}");
        }
        if matches!(self.configure, Configure::Idle) && self.hc.ready() {
            match self.owner {
                Owner::Sockets => {
                    let t = get_descriptor(DESC_DEVICE, 0, DEVICE_DESC_LEN);
                    self.configure = Configure::Device(self.hc.submit(t));
                }
                Owner::Usbip { .. } => {
                    self.configure = Configure::Done;
                    self.answer_replugs();
                }
            }
        }
        let silent = self.ccid.as_ref().and_then(|f| {
            let q = f.quiet_since?;
            (now >= q + CCID_SILENCE_NS).then_some(f.in_id)
        });
        if let Some(in_id) = silent {
            self.hc.cancel(in_id);
            if let Some(f) = self.ccid.take() {
                let _ = f.reply.send(CcidReply::Unanswered);
            }
            self.ccid_next();
        }
    }

    fn completed(&mut self, c: Completion, now: u64) {
        if self.configure.waits_on(c.id) {
            self.configured_step(c);
            return;
        }
        if let Owner::Usbip { rets, urbs } = &mut self.owner {
            if let Some((seqnum, dir_in, out_len)) = urbs.remove(&c.id) {
                let _ = rets.send(match c.outcome {
                    Outcome::Done(data) if dir_in => Ret::in_data(seqnum, data),
                    Outcome::Done(_) => Ret::out_done(seqnum, out_len),
                    Outcome::Stall => Ret::stall(seqnum),
                    Outcome::Gone => gone(seqnum),
                });
            }
            return;
        }
        if Some(c.id) == self.fido_in {
            self.fido_in = None;
            if let Outcome::Done(data) = c.outcome {
                self.fido_report(&data);
            }
            return;
        }
        self.ccid_completed(c, now);
    }

    fn fido_report(&mut self, data: &[u8]) {
        let mut r = [0u8; REPORT_LEN];
        let n = data.len().min(REPORT_LEN);
        r[..n].copy_from_slice(&data[..n]);
        let wants = r[4] == CTAPHID_KEEPALIVE && r[7] == STATUS_UPNEEDED;
        if self.opts.touch && wants && !self.touch_asked {
            eprintln!("emu: the key wants a touch — press Enter");
        }
        self.touch_asked = wants;
        self.hid.incoming(r);
        self.poll_fido();
    }

    fn ccid_completed(&mut self, c: Completion, now: u64) {
        let in_ep = self.ccid_in_ep();
        let Some(f) = &mut self.ccid else { return };
        if f.out_id == Some(c.id) {
            f.out_id = None;
            if matches!(c.outcome, Outcome::Done(_)) {
                f.quiet_since = Some(now);
                return;
            }
        } else if f.in_id == c.id {
            if let Outcome::Done(m) = &c.outcome
                && is_time_extension(m)
            {
                let _ = f.reply.send(CcidReply::Wtx(m.clone()));
                f.in_id = self.hc.submit(ccid_in(in_ep));
                f.quiet_since = Some(now);
                return;
            }
        } else {
            return;
        }
        let Some(f) = self.ccid.take() else { return };
        if let Some(id) = f.out_id {
            self.hc.cancel(id);
        }
        if f.in_id != c.id {
            self.hc.cancel(f.in_id);
        }
        let _ = f.reply.send(match c.outcome {
            Outcome::Done(m) => CcidReply::Final(m),
            Outcome::Stall | Outcome::Gone => CcidReply::Gone,
        });
        self.ccid_next();
    }

    fn ccid_in_ep(&self) -> u8 {
        self.device
            .as_ref()
            .and_then(Device::ccid)
            .map_or(0, |(_, i)| i)
    }

    /// Put the next CCID message on the bus once the last one is answered.
    fn ccid_next(&mut self) {
        if self.ccid.is_some() || !matches!(self.configure, Configure::Done) {
            return;
        }
        let Some((bulk_out, bulk_in)) = self.device.as_ref().and_then(Device::ccid) else {
            for (_, reply) in self.ccid_queue.drain(..) {
                let _ = reply.send(CcidReply::Gone);
            }
            return;
        };
        let Some((msg, reply)) = self.ccid_queue.pop_front() else {
            return;
        };
        let out_id = self.hc.submit(out(bulk_out, &msg));
        let in_id = self.hc.submit(ccid_in(bulk_in));
        self.ccid = Some(CcidFlight {
            reply,
            out_id: Some(out_id),
            in_id,
            quiet_since: None,
        });
    }

    fn poll_fido(&mut self) {
        if let Some((fido_in, _)) = self.device.as_ref().and_then(|d| d.fido) {
            self.fido_in = Some(self.hc.submit(Transfer {
                ep: fido_in,
                dir_in: true,
                setup: [0; 8],
                out: Vec::new(),
                want: REPORT_LEN,
            }));
        }
    }

    fn answer_replugs(&mut self) {
        for done in self.replugs.drain(..) {
            let _ = done.send(());
        }
    }

    /// One step of the socket bridge's configuration, on its transfer's answer.
    fn configured_step(&mut self, c: Completion) {
        let state = std::mem::replace(&mut self.configure, Configure::Failed);
        let Outcome::Done(data) = c.outcome else {
            eprintln!(
                "emu: the device refused its configuration ({:?})",
                c.outcome
            );
            self.answer_replugs();
            return;
        };
        self.configure = match state {
            Configure::Device(_) => {
                let t = get_descriptor(DESC_CONFIG, 0, CONFIG_HEADER_LEN);
                let id = self.hc.submit(t);
                Configure::Config9 { id, device: data }
            }
            Configure::Config9 { device, .. } if data.len() >= 4 => {
                let total = u16::from_le_bytes([data[2], data[3]]);
                let id = self.hc.submit(get_descriptor(DESC_CONFIG, 0, total));
                Configure::Config { id, device }
            }
            Configure::Config { device, .. } => match Device::new(device, data) {
                Ok(dev) => {
                    self.hc.set_endpoints(dev.endpoints());
                    let hid: Vec<u8> = dev
                        .interfaces
                        .iter()
                        .filter(|i| i.report_len.is_some())
                        .map(|i| i.number)
                        .collect();
                    self.next_report(dev, hid, 0)
                }
                Err(e) => {
                    eprintln!("emu: {e}");
                    Configure::Failed
                }
            },
            Configure::Report {
                mut dev, hid, i, ..
            } => {
                if desc::is_fido_report(&data)
                    && let Some(iface) = dev.interfaces.iter().find(|x| x.number == hid[i])
                {
                    dev.fido = iface.interrupt_pair();
                }
                self.next_report(dev, hid, i + 1)
            }
            Configure::SetConfig { dev, .. } => {
                self.device = Some(dev);
                self.ready();
                Configure::Done
            }
            _ => Configure::Failed,
        };
        match self.configure {
            Configure::Done => self.ccid_next(),
            Configure::Failed => self.answer_replugs(),
            _ => {}
        }
    }

    /// Read the next HID interface's report descriptor, or configure the device
    /// once they are all read.
    fn next_report(&mut self, dev: Device, hid: Vec<u8>, i: usize) -> Configure {
        let Some(&iface) = hid.get(i) else {
            let value = u16::from(dev.configuration_value());
            let id = self.hc.submit(Transfer {
                ep: 0,
                dir_in: false,
                setup: setup(0x00, SET_CONFIGURATION, value, 0, 0),
                out: Vec::new(),
                want: 0,
            });
            return Configure::SetConfig { id, dev };
        };
        let len = dev
            .interfaces
            .iter()
            .find(|x| x.number == iface)
            .and_then(|x| x.report_len)
            .unwrap_or(0);
        let mut t = get_descriptor(DESC_REPORT, 0, len);
        t.setup[0] = TO_INTERFACE_IN;
        t.setup[4] = iface;
        let id = self.hc.submit(t);
        Configure::Report { id, dev, hid, i }
    }

    /// The socket bridge has a configured device: say so, and start its pipes.
    fn ready(&mut self) {
        let Some(dev) = self.device.clone() else {
            return;
        };
        if !self.announced {
            self.announced = true;
            let what = format!(
                "{:04x}:{:04x} bcdDevice {:04x}, {} interfaces",
                dev.vid(),
                dev.pid(),
                dev.bcd(),
                dev.interfaces.len()
            );
            if dev.fido.is_none() && dev.ccid().is_none() {
                eprintln!("emu: the device on the bus ({what}) has no FIDO or CCID interface");
            } else {
                eprintln!("emu: device ready — {what}");
            }
        }
        let info = UsbipInfo {
            device: usbip_device(&dev),
            interfaces: dev.interfaces.iter().map(|i| i.class).collect(),
        };
        if let Some(shared) = &self.usbip_info {
            *shared.lock().unwrap() = info;
        } else if let Some(addr) = self.opts.usbip.clone() {
            let shared = Arc::new(Mutex::new(info));
            self.usbip_info = Some(shared.clone());
            let mut port = UsbipPort {
                chip: self.tx.clone(),
                info: shared,
            };
            std::thread::spawn(move || {
                if let Err(e) = crate::usbip_server::listen(&addr, &mut port) {
                    eprintln!("emu: cannot serve USB/IP on {addr}: {e}");
                }
            });
        }
        self.answer_replugs();
        self.poll_fido();
        if let Some(ep) = self.fido_out() {
            for r in std::mem::take(&mut self.held) {
                self.hc.submit(out(ep, &r));
            }
        }
    }
}

fn setup(bm: u8, request: u8, value: u16, index: u16, len: u16) -> [u8; 8] {
    let (v, i, l) = (value.to_le_bytes(), index.to_le_bytes(), len.to_le_bytes());
    [bm, request, v[0], v[1], i[0], i[1], l[0], l[1]]
}

fn get_descriptor(kind: u8, index: u8, len: u16) -> Transfer {
    let value = u16::from(kind) << 8 | u16::from(index);
    Transfer {
        ep: 0,
        dir_in: true,
        setup: setup(0x80, GET_DESCRIPTOR, value, 0, len),
        out: Vec::new(),
        want: usize::from(len),
    }
}

fn out(ep: u8, data: &[u8]) -> Transfer {
    Transfer {
        ep,
        dir_in: false,
        setup: [0; 8],
        out: data.to_vec(),
        want: 0,
    }
}

fn ccid_in(ep: u8) -> Transfer {
    Transfer {
        ep,
        dir_in: true,
        setup: [0; 8],
        out: Vec::new(),
        want: HEADER + MAX_CCID_MSG,
    }
}

fn gone(seqnum: u32) -> Ret {
    Ret::Submit {
        seqnum,
        status: ESHUTDOWN,
        actual_length: 0,
        data: Vec::new(),
    }
}

fn usbip_device(dev: &Device) -> UsbDeviceInfo {
    let [class, subclass, protocol] = dev.class();
    UsbDeviceInfo {
        path: "/sys/devices/rsk-emu/usb1/1-1",
        busid: BUSID,
        busnum: 1,
        devnum: 1,
        speed: USB_SPEED_FULL,
        id_vendor: dev.vid(),
        id_product: dev.pid(),
        bcd_device: dev.bcd(),
        device_class: class,
        device_subclass: subclass,
        device_protocol: protocol,
        configuration_value: dev.configuration_value(),
        num_configurations: dev.descriptor[17],
        num_interfaces: u8::try_from(dev.interfaces.len()).unwrap_or(u8::MAX),
    }
}

#[cfg(test)]
#[path = "board_tests.rs"]
mod tests;
