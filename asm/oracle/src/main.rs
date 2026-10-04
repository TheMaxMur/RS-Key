// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

use rsk_usb::ccid::{process_message, put_header, secure_apdu, xfr_apdu, ATR_RSKEY};
use rsk_usb::ctaphid::{
    init_capabilities, is_cancel_frame, keepalive_status, ChannelLock, CidAllocator, Outcome,
    Reassembler, TxFrames, CTAPHID_CANCEL, CTAPHID_CBOR, CTAPHID_ERROR, CTAPHID_LOCK,
    CTAPHID_MSG, CTAPHID_PING, CTAPHID_WINK, CTAPHID_IF_VERSION, ERR_CHANNEL_BUSY,
    ERR_INVALID_CMD, ERR_INVALID_LEN, ERR_INVALID_PAR, KEEPALIVE_MS, LOCK_MAX_SECONDS,
    HID_RPT_SIZE,
};
use std::io::Read;

const TX_CAP: usize = 7609; // CTAP_MAX_MESSAGE: 57 + 128*59
const CID_BROADCAST: u32 = 0xFFFF_FFFF;
const INIT_CMD: u8 = 0x86;

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in 0..b.len() / 2 {
        let pair = std::str::from_utf8(&b[2 * i..2 * i + 2]).ok()?;
        out.push(u8::from_str_radix(pair, 16).ok()?);
    }
    Some(out)
}

fn hex_str(b: &[u8]) -> String {
    let mut s = String::with_capacity(2 * b.len());
    for byte in b {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();
    let mut re = Reassembler::new();
    let mut allocator = CidAllocator::new();
    let mut lock = ChannelLock::default();
    let mut clock_now: u64 = 0; // clock for Q lock guards; advanced by L lines
    let mut wait_active = false; // M10 worker-wait state, the C wst's mirror
    let mut wait_next: u64 = 0;
    let mut wait_up = false;
    let mut wait_cbor = false;
    // CCID (M13): the slot bStatus (an unpowered slot reports STATUS_INACTIVE)
    // and the ATR the card presents, both pinned against the C harness's
    let mut ccid_status: u8 = 1;
    let mut ccid_atr: Vec<u8> = ATR_RSKEY.to_vec();
    let mut out = String::new();

    'lines: for line in input.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }

        if let Some(rest) = l.strip_prefix("T ") {
            let parts: Vec<&str> = rest.split(' ').collect();
            if parts.len() < 2 || parts[0].len() != 8 || parts[1].len() != 2 {
                out.push_str("X parse\n");
                continue;
            }
            let (cid, cmd, data) = (
                u32::from_str_radix(parts[0], 16),
                u8::from_str_radix(parts[1], 16),
                parse_hex(parts.get(2).copied().unwrap_or("")),
            );
            let (cid, cmd, data) = match (cid, cmd, data) {
                (Ok(c), Ok(m), Some(d)) if d.len() <= TX_CAP => (c, m, d),
                _ => {
                    out.push_str("X parse\n");
                    continue;
                }
            };
            for f in TxFrames::new(cid, cmd, &data) {
                out.push_str("F ");
                for b in f {
                    out.push_str(&format!("{:02x}", b));
                }
                out.push('\n');
            }
            continue;
        }

        if let Some(rest) = l.strip_prefix("I ") {
            let parts: Vec<&str> = rest.split(' ').collect();
            let (can_wink, nonce) = match parts.as_slice() {
                [w, h] if (*w == "0" || *w == "1") && h.len() == 16 => match parse_hex(h) {
                    Some(b) if b.len() == 8 => (*w == "1", b),
                    _ => {
                        out.push_str("X parse\n");
                        continue;
                    }
                },
                _ => {
                    out.push_str("X parse\n");
                    continue;
                }
            };
            let cid = allocator.allocate();
            let mut payload = nonce;
            payload.extend_from_slice(&cid.to_le_bytes());
            payload.push(CTAPHID_IF_VERSION);
            let (maj, min, bld) = rsk_sdk::FIRMWARE_VERSION;
            payload.extend_from_slice(&[maj, min, bld]);
            payload.push(init_capabilities(can_wink));
            assert_eq!(payload.len(), 17);
            for f in TxFrames::new(CID_BROADCAST, INIT_CMD, &payload) {
                out.push_str("F ");
                for b in f {
                    out.push_str(&format!("{:02x}", b));
                }
                out.push('\n');
            }
            continue;
        }

        // keepalive status: "K <is_cbor 0|1> <up_pending 0|1>" -> "S 00|01|02"
        if let Some(rest) = l.strip_prefix("K ") {
            let parts: Vec<&str> = rest.split(' ').collect();
            match parts.as_slice() {
                [a, b] if (*a == "0" || *a == "1") && (*b == "0" || *b == "1") => {
                    let is_cbor = *a == "1";
                    let up_pending = *b == "1";
                    let s = match keepalive_status(is_cbor, up_pending) {
                        None => 0u8,
                        Some(v) => v,
                    };
                    out.push_str(&format!("S {:02x}\n", s));
                }
                _ => {
                    out.push_str("X parse\n");
                }
            }
            continue;
        }

        // cancel detection: "C <128-hex frame> <n dec> <cid 8-hex>" -> "C 0|1"
        if let Some(rest) = l.strip_prefix("C ") {
            let parts: Vec<&str> = rest.split(' ').collect();
            let parse = match parts.as_slice() {
                [frame_h, n_s, cid_s] if frame_h.len() == 128 && cid_s.len() == 8 => {
                    let frame = parse_hex(frame_h);
                    let n = n_s.parse::<u32>().ok().filter(|n| *n <= 64);
                    let cid = u32::from_str_radix(cid_s, 16).ok();
                    match (frame, n, cid) {
                        (Some(f), Some(n), Some(c)) if f.len() == 64 => {
                            let mut arr = [0u8; 64];
                            arr.copy_from_slice(&f);
                            is_cancel_frame(&arr, n as usize, c)
                        }
                        _ => {
                            out.push_str("X parse\n");
                            continue;
                        }
                    }
                }
                _ => {
                    out.push_str("X parse\n");
                    continue;
                }
            };
            out.push_str(if parse { "C 1\n" } else { "C 0\n" });
            continue;
        }

        // channel lock: "L arm|refuse ..." lines (see difftest.c for the
        // grammar); an arm persists the lock, a refuse prints "R 0|1".
        if let Some(rest) = l.strip_prefix("L ") {
            let parts: Vec<&str> = rest.split(' ').collect();
            match parts.as_slice() {
                ["arm", cid_s, secs_s, now_s] if cid_s.len() == 8 => {
                    let cid = u32::from_str_radix(cid_s, 16);
                    let secs = secs_s.parse::<u32>().ok().filter(|s| *s <= 255);
                    let now = now_s.parse::<u64>().ok();
                    match (cid, secs, now) {
                        (Ok(c), Some(s), Some(n)) => {
                            clock_now = n;
                            lock.arm(c, s as u8, n)
                        }
                        _ => {
                            out.push_str("X parse\n");
                        }
                    }
                }
                ["refuse", cid_s, cmd_s, now_s] if cid_s.len() == 8 && cmd_s.len() == 2 => {
                    let cid = u32::from_str_radix(cid_s, 16);
                    let cmd = u8::from_str_radix(cmd_s, 16);
                    let now = now_s.parse::<u64>().ok();
                    let r = match (cid, cmd, now) {
                        (Ok(c), Ok(m), Some(n)) => {
                            clock_now = n;
                            lock.refuses(c, m, n)
                        }
                        _ => {
                            out.push_str("X parse\n");
                            continue;
                        }
                    };
                    out.push_str(if r { "R 1\n" } else { "R 0\n" });
                }
                _ => {
                    out.push_str("X parse\n");
                }
            }
            continue;
        }

        // dispatcher verdicts (M9): "Q <can_wink 0|1> <cmd 2hex> <cid 8hex>
        // [body-hex]" -> "Q <code 2hex>" (00 = route/no-transport-response,
        // else the error code); an immediate error verdict also frames
        // CTAPHID_ERROR through TxFrames. A missing body field is the empty
        // body (the line trim swallows a bare empty 4th field), mirroring how
        // this harness models T's bare-INIT empty payload. This is the Rust
        // mirror of the table in asm/ctaphid_dispatch.S; provenance per row:
        //   wink:        pinned by wink_is_refused_where_the_capability_bit_is_clear.
        //   lock:        <=10 arm + empty-LOCK reply are the shipping dispatch's
        //                code path; len!=1 / >10 are spec-claimed (no unit pins).
        //   empty CBOR:  spec-claimed (dispatch ctaphid.rs:714-717).
        //   lock guard:  the shipping on_frame guards every Message with
        //                lock.refuses -> ERR_CHANNEL_BUSY (doc-pinned, and the
        //                same refuses the twin'd ctaphid_lock_refuses).
        if let Some(rest) = l.strip_prefix("Q ") {
            let parts: Vec<&str> = rest.split(' ').collect();
            // empty body = the 3-field line; a body occupies the 4th field
            let (w, cmd_s, cid_s, body_s) = match parts.as_slice() {
                [w, cmd_s, cid_s] if w.len() == 1 && (*w == "0" || *w == "1")
                    && cmd_s.len() == 2 && cid_s.len() == 8 => (*w, *cmd_s, *cid_s, ""),
                [w, cmd_s, cid_s, body_s] if w.len() == 1 && (*w == "0" || *w == "1")
                    && cmd_s.len() == 2 && cid_s.len() == 8 => {
                    (*w, *cmd_s, *cid_s, *body_s)
                }
                _ => {
                    out.push_str("X parse\n");
                    continue;
                }
            };
            let can_wink = w == "1";
            let cmd = u8::from_str_radix(cmd_s, 16).ok();
            let cid = u32::from_str_radix(cid_s, 16).ok();
            let body = parse_hex(body_s);
            let build = match (cmd, cid, body) {
                (Some(c), Some(ci), Some(b)) if b.len() <= TX_CAP => {
                    let (code, err) = match c {
                        CTAPHID_CANCEL => (0x00, false), // never acknowledged
                        CTAPHID_PING | CTAPHID_MSG | CTAPHID_CBOR => {
                            if lock.refuses(ci, c, clock_now) {
                                (ERR_CHANNEL_BUSY, true)
                            } else if c == CTAPHID_CBOR && b.is_empty() {
                                (ERR_INVALID_LEN, true)
                            } else {
                                (0x00, false) // route
                            }
                        }
                        CTAPHID_LOCK => {
                            if b.len() != 1 {
                                (ERR_INVALID_LEN, true)
                            } else if b[0] > LOCK_MAX_SECONDS {
                                (ERR_INVALID_PAR, true)
                            } else {
                                lock.arm(ci, b[0], clock_now);
                                (0x00, false) // arm; no reply-from-here
                            }
                        }
                        CTAPHID_WINK => {
                            if can_wink {
                                (0x00, false) // empty wink reply
                            } else {
                                (ERR_INVALID_CMD, true)
                            }
                        }
                        _ => (ERR_INVALID_CMD, true), // unknown command
                    };
                    let mut s = format!("Q {:02x}\n", code);
                    if err {
                        for fr in TxFrames::new(ci, CTAPHID_ERROR, &[code]) {
                            s.push_str("F ");
                            for byte in fr {
                                s.push_str(&format!("{:02x}", byte));
                            }
                            s.push('\n');
                        }
                    }
                    s
                }
                _ => "X parse\n".to_string(),
            };
            out.push_str(&build);
            continue;
        }

        // worker-wait orchestration (M10): the Rust mirror of the table in
        // asm/ctaphid_wait.S. "W start <is_cbor> <now_ms>" arms the cadence,
        // "W up <0|1>" sets the worker's touch flag, "W tick <now_ms>" emits
        // one "W ka <status>" per KEEPALIVE_MS deadline crossed (00 = the
        // U2F fast-op silence — the keepalive_status() call is the shipping
        // pub twin, live), "W frame <128hex> <n> <cid>" -> "W r 0|1|2",
        // "W done" ends the wait. Provenance: the read-only-while-up_pending
        // gating and the drop/queue split are body-sourced (shipping
        // run_with_keepalive, ctaphid.rs:737-813); the chained
        // next += KEEPALIVE_MS restart and the non-strict (now >= next) due
        // boundary are mirror-defined. The tick catch-up cap matches the C
        // harness's.
        if let Some(rest) = l.strip_prefix("W ") {
            let parts: Vec<&str> = rest.split(' ').collect();
            match parts.as_slice() {
                ["start", w, now_s] if w.len() == 1 && (*w == "0" || *w == "1") => {
                    match now_s.parse::<u64>() {
                        Ok(n) => {
                            wait_cbor = *w == "1";
                            wait_active = true;
                            wait_next = n + KEEPALIVE_MS;
                        }
                        _ => out.push_str("X parse\n"),
                    }
                    continue;
                }
                ["up", w] if w.len() == 1 && (*w == "0" || *w == "1") => {
                    wait_up = *w == "1";
                    continue;
                }
                ["tick", now_s] => match now_s.parse::<u64>() {
                    Ok(n) => {
                        for _ in 0..65536 {
                            if !wait_active || n < wait_next {
                                break;
                            }
                            let s = keepalive_status(wait_cbor, wait_up);
                            out.push_str(&format!(
                                "W ka {:02x}\n",
                                s.unwrap_or(0)
                            ));
                            wait_next += KEEPALIVE_MS;
                        }
                    }
                    _ => out.push_str("X parse\n"),
                },
                ["frame", hex, n_s, cid_s]
                    if hex.len() == 128 && cid_s.len() == 8 =>
                {
                    let frame = parse_hex(hex);
                    let n = n_s.parse::<u32>().ok().filter(|v| *v <= 64);
                    let cid = u32::from_str_radix(cid_s, 16).ok();
                    let r = match (frame, n, cid) {
                        (Some(f), Some(n), Some(c)) if f.len() == 64 => {
                            let mut arr = [0u8; 64];
                            arr.copy_from_slice(&f);
                            if !wait_up {
                                0 // queued: off the touch wait, unread
                            } else if is_cancel_frame(&arr, n as usize, c) {
                                2 // cancel: signal the worker's touch wait
                            } else {
                                1 // dropped: read mid-wait, not this cancel
                            }
                        }
                        _ => {
                            out.push_str("X parse\n");
                            continue;
                        }
                    };
                    out.push_str(&format!("W r {}\n", r));
                }
                ["done"] => {
                    wait_active = false;
                }
                _ => out.push_str("X parse\n"),
            }
            continue;
        }

        // CCID (M13): the live rsk-usb functions — process_message, the two
        // payload rangers and put_header — run against the asm twin. The
        // state mirrors the C harness's: a slot bStatus and the ATR bytes
        // the card presents, both starting at ATR_RSKEY/unpowered.
        if let Some(rest) = l.strip_prefix("A ") {
            let parts: Vec<&str> = rest.split(' ').collect();
            let atr = match parts.as_slice() {
                [h] if h.len() % 2 == 0 && h.len() / 2 <= 256 => parse_hex(h),
                _ => None,
            };
            match atr {
                Some(b) => ccid_atr = b,
                _ => out.push_str("X parse\n"),
            }
            continue;
        }
        if let Some(rest) = l.strip_prefix("N ") {
            let parts: Vec<&str> = rest.split(' ').collect();
            let v = match parts.as_slice() {
                [h] if h.len() == 2 => u8::from_str_radix(h, 16).ok(),
                _ => None,
            };
            match v {
                Some(b) => ccid_status = b,
                _ => out.push_str("X parse\n"),
            }
            continue;
        }
        if let Some(rest) = l.strip_prefix("H ") {
            let parts: Vec<&str> = rest.split(' ').collect();
            let parsed = match parts.as_slice() {
                // 2-hex type/seq/status, exactly — the C parser's widths
                [t, len_s, sq, st]
                    if t.len() == 2 && sq.len() == 2 && st.len() == 2 =>
                {
                    let len = len_s.parse::<u64>().ok().filter(|v| *v <= 0xffff_ffff);
                    match (
                        u8::from_str_radix(t, 16).ok(),
                        len,
                        u8::from_str_radix(sq, 16).ok(),
                        u8::from_str_radix(st, 16).ok(),
                    ) {
                        (Some(t), Some(len), Some(sq), Some(st)) => Some((t, len, sq, st)),
                        _ => None,
                    }
                }
                _ => None,
            };
            let mut hbuf = [0u8; 10];
            match parsed {
                Some((t, len, sq, st)) => {
                    put_header(&mut hbuf, t, len as u32, sq, st);
                    out.push_str(&format!("H {}\n", hex_str(&hbuf)));
                }
                _ => out.push_str("X parse\n"),
            }
            continue;
        }
        for tag in ["X", "E"] {
            if let Some(rest) = l.strip_prefix(tag).filter(|r| r.starts_with(' ')) {
                let rest = &rest[1..]; // past the separator the prefix kept
                let parts: Vec<&str> = rest.split(' ').collect();
                let msg = match parts.as_slice() {
                    [h] if h.len() % 2 == 0 && h.len() / 2 <= TX_CAP => parse_hex(h),
                    _ => None,
                };
                let msg = match msg {
                    Some(m) => m,
                    _ => {
                        out.push_str("X parse\n");
                        continue 'lines;
                    }
                };
                let r = if *tag == *"X" { xfr_apdu(&msg) } else { secure_apdu(&msg) };
                match r {
                    Some((s, e)) => out.push_str(&format!("{} 1 {} {}\n", tag, s, e)),
                    None => out.push_str(&format!("{} 0\n", tag)),
                }
                continue 'lines;
            }
        }
        if let Some(rest) = l.strip_prefix("M ") {
            let parts: Vec<&str> = rest.split(' ').collect();
            let parsed = match parts.as_slice() {
                [cap_s, h] if h.len() % 2 == 0 && h.len() / 2 <= TX_CAP => {
                    match (cap_s.parse::<usize>().ok(), parse_hex(h)) {
                        (Some(cap), msg) if cap <= 2048 => Some((cap, msg)),
                        _ => None,
                    }
                }
                _ => None,
            };
            let (cap, msg) = match parsed {
                Some((cap, Some(msg))) => (cap, msg),
                _ => {
                    out.push_str("X parse\n");
                    continue;
                }
            };
            let mut obuf = vec![0u8; cap];
            let n = process_message(&msg, &ccid_atr, &mut ccid_status, &mut obuf);
            if n > 0 {
                out.push_str(&format!("M {} {}\n", n, hex_str(&obuf[..n])));
            } else {
                out.push_str("M 0\n");
            }
            continue;
        }

        let mut rpt = [0u8; HID_RPT_SIZE];
        let b = l.as_bytes();
        let mut ok = true;
        for i in 0..HID_RPT_SIZE {
            if b.len() < 2 * i + 2 {
                ok = false;
                break;
            }
            rpt[i] = match u8::from_str_radix(&l[2 * i..2 * i + 2], 16) {
                Ok(v) => v,
                Err(_) => {
                    ok = false;
                    break;
                }
            };
        }
        if !ok {
            out.push_str("X parse\n");
            continue;
        }

        match re.feed(&rpt) {
            Outcome::None => {
                if re.in_progress() {
                    out.push_str("B\n");
                } else {
                    out.push_str("I\n");
                }
            }
            Outcome::Error(cid, code) => {
                out.push_str(&format!("E {:08x} {:02x}\n", cid, code));
            }
            Outcome::Message(cid, cmd) => {
                let m = re.message();
                out.push_str(&format!("D {:08x} {:02x} {:x} ", cid, cmd, m.len()));
                for byte in m {
                    out.push_str(&format!("{:02x}", byte));
                }
                out.push('\n');
            }
        }
    }
    print!("{out}");
}
