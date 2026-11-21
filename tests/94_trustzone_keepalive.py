#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Measure real CTAPHID keepalives from a TrustZone firmware image over emulator TCP."""

import argparse
import json
import socket
import time


def receive(sock):
    report = bytearray()
    while len(report) < 64:
        part = sock.recv(64 - len(report))
        if not part:
            raise AssertionError("emulator closed the HID socket")
        report.extend(part)
    return bytes(report)


def send(sock, cid, command, body):
    assert len(body) <= 57
    sock.sendall((cid + bytes([command]) + len(body).to_bytes(2, "big") + body).ljust(64, b"\0"))


def image_time(port):
    with socket.create_connection(("127.0.0.1", port), timeout=20) as sock:
        sock.sendall(b"status\n")
        line = bytearray()
        while not line.endswith(b"\n"):
            part = sock.recv(4096)
            assert part, "image clock socket closed"
            line.extend(part)
        words = line.decode().split()
        assert words[0] == "ok", line.decode()
        values = dict(word.split("=", 1) for word in words[1:])
        return int(values["emulated_ns"]) / 1_000_000_000


def measure(address, inspect_port):
    with socket.create_connection(address, timeout=20) as sock:
        nonce = b"tz-alive"
        send(sock, b"\xff" * 4, 0x86, nonce)
        init = receive(sock)
        assert init[4] == 0x86 and init[7:15] == nonce, "CTAPHID INIT failed"
        cid = init[15:19]
        wall_started = time.monotonic()
        started = image_time(inspect_port)
        send(sock, cid, 0x90, b"\x04")
        keepalives = []
        while True:
            report = receive(sock)
            assert report[:4] == cid, "reply changed CTAPHID channel"
            if report[4] == 0xBB:
                assert report[5:8] == b"\x00\x01\x01", "expected PROCESSING keepalive"
                keepalives.append(image_time(inspect_port) - started)
                continue
            assert report[4] == 0x90, f"getInfo returned command {report[4]:#x}"
            size = int.from_bytes(report[5:7], "big")
            body = bytearray(report[7:])
            sequence = 0
            while len(body) < size:
                report = receive(sock)
                assert report[:4] == cid and report[4] == sequence, "response framing failed"
                body.extend(report[5:])
                sequence += 1
            body = bytes(body[:size])
            assert body[0] == 0, f"getInfo failed with CTAP status {body[0]:#x}"
            assert body[1] >> 5 == 5 and b"FIDO_2_1" in body[1:], "Secure applet returned an invalid getInfo"
            elapsed = image_time(inspect_port) - started
            wall_elapsed = time.monotonic() - wall_started
            break
        assert 2.8 <= elapsed <= 4, f"long Secure operation took {elapsed:.3f}s on the image clock"
        assert len(keepalives) >= 10, f"only {len(keepalives)} keepalives during Secure work"
        gaps = [b - a for a, b in zip([0.0] + keepalives, keepalives + [elapsed])]
        assert max(gaps) <= 0.5, f"USB starved for {max(gaps):.3f}s"
        return {"image_elapsed_s": round(elapsed, 3), "wall_elapsed_s": round(wall_elapsed, 3), "keepalives": len(keepalives), "image_max_gap_s": round(max(gaps), 3)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True, help="loopback image-emulator HID port")
    parser.add_argument("--inspect-port", type=int, required=True, help="same image emulator's clock socket")
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()
    assert args.runs > 0
    for run in range(args.runs):
        print(json.dumps({"run": run + 1, **measure(("127.0.0.1", args.port), args.inspect_port)}), flush=True)
