// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! Opt-in laboratory control, separate from the USB device the image exposes.

#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Sender};

use super::sockets::Request;

pub const SRAM_BASE: u32 = 0x2000_0000;
pub const SRAM_LEN: u32 = 520 * 1024;
pub const PAINT: u8 = 0xA5;
const MAX_LINE: u64 = 4096;

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Status,
    Begin,
    End,
    Scan(Vec<u8>),
    Plant { address: u32, bytes: Vec<u8> },
    CutCycles(u64),
    CutProgram(u64),
    CutProgramCycles(u64),
}

pub fn parse(line: &str) -> Result<Command, String> {
    let args: Vec<_> = line.split_whitespace().collect();
    let number = |s: &str| s.parse::<u64>().map_err(|_| "invalid unsigned count");
    match args.as_slice() {
        ["status"] => Ok(Command::Status),
        ["begin"] => Ok(Command::Begin),
        ["end"] => Ok(Command::End),
        ["scan", hex] => Ok(Command::Scan(pattern(hex)?)),
        ["plant", addr, hex] => {
            let address = u32::from_str_radix(addr.trim_start_matches("0x"), 16)
                .map_err(|_| "invalid SRAM address")?;
            let bytes = pattern(hex)?;
            if address < SRAM_BASE
                || u64::from(address) + bytes.len() as u64 > u64::from(SRAM_BASE + SRAM_LEN)
            {
                return Err("plant leaves SRAM".into());
            }
            Ok(Command::Plant { address, bytes })
        }
        ["cut-cycles", n] => Ok(Command::CutCycles(number(n)?)),
        ["cut-program", n] => Ok(Command::CutProgram(number(n)?)),
        ["cut-program-cycles", n] => Ok(Command::CutProgramCycles(number(n)?)),
        _ => Err("expected status, begin, end, scan HEX, plant ADDRESS HEX, cut-cycles N, cut-program N or cut-program-cycles N".into()),
    }
}

fn pattern(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() < 2 || hex.len() > 512 || !hex.len().is_multiple_of(2) {
        return Err("pattern needs 1..256 bytes in hex".into());
    }
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let s = std::str::from_utf8(pair).map_err(|_| "invalid hex")?;
            u8::from_str_radix(s, 16).map_err(|_| "invalid hex".into())
        })
        .collect()
}

pub fn listen(listener: TcpListener, chip: Sender<Request>) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let chip = chip.clone();
        std::thread::spawn(move || {
            if let Err(e) = serve(stream, &chip) {
                eprintln!("emu: inspection client: {e}");
            }
        });
    }
}

fn serve(mut stream: TcpStream, chip: &Sender<Request>) -> std::io::Result<()> {
    let mut line = String::new();
    BufReader::new(stream.try_clone()?)
        .take(MAX_LINE + 1)
        .read_line(&mut line)?;
    let result = if line.len() as u64 > MAX_LINE || !line.ends_with('\n') {
        Err("inspection request too long or unterminated".into())
    } else {
        parse(&line).and_then(|command| {
            let (reply, rx) = mpsc::channel();
            chip.send(Request::Inspect { command, reply })
                .map_err(|_| "chip is gone")?;
            rx.recv().map_err(|_| String::from("chip is gone"))?
        })
    };
    match result {
        Ok(body) => writeln!(stream, "ok {body}"),
        Err(e) => writeln!(stream, "error {e}"),
    }
}

#[derive(Clone)]
pub struct Stack {
    pub low: u32,
    pub top: u32,
    pub initial_sp: u32,
    pub min_sp: u32,
}

impl Stack {
    pub fn sample(&mut self, sp: u32) {
        self.min_sp = self.min_sp.min(sp);
    }
}

#[cfg(test)]
#[path = "inspect_tests.rs"]
mod tests;
