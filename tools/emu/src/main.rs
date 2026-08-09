// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! `rsk-emu` — the RS-Key applet stack on a socket, with no hardware under it.
//!
//! It runs the same `crates/rsk-*` code a real key runs, so a host tool can
//! drive FIDO2/U2F, PIV, OpenPGP, OATH and the rescue interface without a board.
//! It is a development and CI tool, **not** a security key: there is no secure
//! boot, no OTP root, no fuses, no tamper resistance, and the seed sits in a
//! file. What it emulates is behaviour, not the device.
//!
//! ```text
//! rsk-emu --store ./my.store --touch
//! ```

mod ccid;
mod device;
mod display;
mod hid;
mod otp_kbd;
mod park;
mod platform;
mod presence;
mod rng;
mod shots;
mod signals;
mod store;
mod usbip;
mod usbip_driver;
mod usbip_stack;

use std::io::BufRead;
use std::net::TcpListener;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use device::Config;
use signals::Signals;

const DEFAULT_FIDO_PORT: u16 = 7799;
const DEFAULT_CCID_PORT: u16 = 7800;

/// The emulator's own serial. Deliberately not a chip id shape a real board can
/// produce: everything a device derives — the OpenPGP AID, the seal context, the
/// Management serial — keys off this, and emulator-made material must be
/// recognisable as such.
const DEFAULT_SERIAL: [u8; 8] = *b"RSKEMU\x00\x01";

/// Reported store and flash sizes. The applets only ever report these back.
const KV_TOTAL: u32 = 512 * 1024;
const FLASH_SIZE: u32 = 4 * 1024 * 1024;

const USAGE: &str = "\
rsk-emu — RS-Key software emulator (no hardware)

usage: rsk-emu [options]

  --host <addr>       bind address (default 127.0.0.1)
  --fido-port <n>     CTAPHID port, 0 disables (default 7799)
  --ccid-port <n>     APDU/card port, 0 disables (default 7800)
  --store <path>      persist the file system here (default: memory only)
  --touch             ask for every user presence on the terminal
  --display           open the trusted display in a window; presence is an
                      on-screen hold, exactly as on a screen board
  --screenshots <dir> write the docs' display screens as PNGs and exit
  --usbip [addr]      serve USB/IP (default 127.0.0.1:3240) so a Linux host can
                      attach the emulator as a REAL USB device
  --trace             log every command and its status
  --yubico            present the Yubico identity: USB VID/PID and descriptor
                      strings, the ATR, and the OpenPGP AID vendor, as the
                      VIDPID=Yubikey5 build does. ykman looks for that VID.
  --power-cut <n>     cut the flash's power after n bytes of writes; every op
                      after that fails, as it does on a chip that lost its supply
  --seed <hex>        seed the DRBG deterministically — every key becomes
                      predictable; for reproducible tests only
  --serial <16 hex>   device serial (default RSKEMU\\x00\\x01)
  -h, --help          this
";

fn main() {
    let mut host = String::from("127.0.0.1");
    let mut fido_port = DEFAULT_FIDO_PORT;
    let mut ccid_port = DEFAULT_CCID_PORT;
    let mut cfg = Config {
        store: None,
        touch: false,
        display: false,
        usbip: None,
        seed: None,
        serial: DEFAULT_SERIAL,
        kv_total: KV_TOTAL,
        flash_size: FLASH_SIZE,
        trace: false,
        yubico: false,
        power_cut: None,
    };

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |name: &str| {
            args.next()
                .unwrap_or_else(|| die(&format!("{name} needs a value")))
        };
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return;
            }
            "--host" => host = value("--host"),
            "--fido-port" => fido_port = parse_port(&value("--fido-port")),
            "--ccid-port" => ccid_port = parse_port(&value("--ccid-port")),
            "--store" => cfg.store = Some(value("--store").into()),
            "--touch" => cfg.touch = true,
            "--display" => cfg.display = true,
            // Renders and exits: no store, no sockets, nothing to serve.
            "--screenshots" => shots::run(&value("--screenshots")),
            "--usbip" => {
                cfg.usbip = Some(match args.next() {
                    Some(a) if !a.starts_with("--") => a,
                    _ => format!("127.0.0.1:{}", usbip::PORT),
                })
            }
            "--trace" => cfg.trace = true,
            "--yubico" => cfg.yubico = true,
            "--power-cut" => cfg.power_cut = Some(parse_u32(&value("--power-cut"))),
            "--seed" => cfg.seed = Some(parse_hex(&value("--seed"), None)),
            "--serial" => {
                let raw = parse_hex(&value("--serial"), Some(8));
                cfg.serial.copy_from_slice(&raw);
            }
            other => die(&format!("unknown argument {other:?}\n\n{USAGE}")),
        }
    }

    if fido_port == 0 && ccid_port == 0 {
        die("both transports are disabled — nothing to serve");
    }
    if cfg.seed.is_some() {
        eprintln!("emu: DETERMINISTIC SEED — every key this run mints is predictable");
    }

    let (jobs_tx, jobs_rx) = mpsc::channel();
    let signals = Arc::new(Signals::default());

    // The terminal is the only input the prompt has, so it is read once, here,
    // and handed to the device thread — two readers of stdin would race for the
    // same line.
    let lines = cfg.touch.then(|| {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in std::io::stdin().lock().lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
        rx
    });

    if fido_port != 0 {
        let listener = bind(&host, fido_port, "fido");
        let shared = Arc::new(hid::Shared {
            jobs: jobs_tx.clone(),
            signals: signals.clone(),
            cids: Mutex::new(rsk_usb::ctaphid::CidAllocator::new()),
            lock: Mutex::new(rsk_usb::ctaphid::ChannelLock::default()),
            boot: Instant::now(),
        });
        eprintln!("emu: CTAPHID on {host}:{fido_port} (64-byte reports, both ways)");
        std::thread::spawn(move || listen_hid(listener, shared));
    }
    if ccid_port != 0 {
        let listener = bind(&host, ccid_port, "ccid");
        let jobs = jobs_tx.clone();
        // The same rule the firmware applies to its effective VID: a default build
        // must not answer with a YubiKey's ATR, and a Yubico-identity one must.
        let atr: &'static [u8] = if cfg.yubico {
            rsk_usb::ccid::ATR_YUBIKEY
        } else {
            rsk_usb::ccid::ATR_RSKEY
        };
        eprintln!(
            "emu: CCID messages on {host}:{ccid_port} ({} identity)",
            if cfg.yubico { "Yubico" } else { "RS-Key" }
        );
        std::thread::spawn(move || ccid::listen(listener, jobs, atr));
    }
    // The USB stack needs a sender of its own and is started below (after the
    // last `cfg` read), so its clone is taken here — before the original is
    // dropped, which is what lets the device thread's loop end when every
    // transport has gone.
    let usbip_jobs = jobs_tx.clone();
    drop(jobs_tx);

    if let Some(addr) = cfg.usbip.clone() {
        // Its own thread, holding the USB stack's executor: the device thread runs
        // the applets, this one runs the transports, exactly as the board splits
        // them across two executors.
        let jobs = usbip_jobs;
        let signals = signals.clone();
        let yubico = cfg.yubico;
        std::thread::spawn(move || usbip_stack::serve(addr, jobs, signals, yubico));
    }

    device::run(cfg, jobs_rx, signals, lines);
}

fn listen_hid(listener: TcpListener, shared: Arc<hid::Shared>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let shared = shared.clone();
        std::thread::spawn(move || {
            if let Err(e) = hid::serve(stream, shared) {
                eprintln!("emu: fido client: {e}");
            }
        });
    }
}

fn bind(host: &str, port: u16, what: &str) -> TcpListener {
    TcpListener::bind((host, port))
        .unwrap_or_else(|e| die(&format!("cannot bind the {what} port {host}:{port}: {e}")))
}

fn parse_u32(s: &str) -> u32 {
    s.parse()
        .unwrap_or_else(|_| die(&format!("not a byte count: {s:?}")))
}

fn parse_port(s: &str) -> u16 {
    s.parse()
        .unwrap_or_else(|_| die(&format!("not a port: {s:?}")))
}

/// Decode hex, optionally demanding an exact byte length.
fn parse_hex(s: &str, want: Option<usize>) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        die(&format!("not hex: {s:?}"));
    }
    let out: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("checked above"))
        .collect();
    match want {
        Some(n) if out.len() != n => die(&format!("expected {n} bytes of hex, got {}", out.len())),
        _ => out,
    }
}

fn die(msg: &str) -> ! {
    eprintln!("rsk-emu: {msg}");
    std::process::exit(2)
}
