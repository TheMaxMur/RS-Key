#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Run a disposable loopback image emulator; never opens physical key handles."""

import argparse
from pathlib import Path
import socket
import subprocess
import tempfile
import time


def arguments():
    parser = argparse.ArgumentParser(description="Verify a hostile NS read is refused.")
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--ns-image", type=Path, required=True)
    parser.add_argument("--emulator", type=Path, required=True)
    parser.add_argument("--address", type=lambda value: int(value, 16), required=True)
    parser.add_argument("--cfsr", type=lambda value: int(value, 16), default=0x8200)
    parser.add_argument("--base-port", type=int, default=19359)
    return parser.parse_args()


def inspect(port, command):
    with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
        connection.sendall((command + "\n").encode())
        with connection.makefile("rb") as stream:
            return stream.readline(4096).decode().strip()


def main():
    args = arguments()
    assert 1024 <= args.base_port <= 65533
    ports = tuple(range(args.base_port, args.base_port + 3))
    for port in ports:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))
    symbols = subprocess.check_output(
        ["arm-none-eabi-nm", "-n", str(args.ns_image.resolve())], text=True,
    )
    marker = int(next(line.split()[0] for line in symbols.splitlines()
                      if line.endswith(" RSK_NS_PROBE_PROGRESS")), 16)
    assert 0x20070000 <= marker < 0x20080000
    with tempfile.NamedTemporaryFile(prefix="rsk-hostile-image-", suffix=".log", mode="w+") as log:
        proc = subprocess.Popen(
            [str(args.emulator.resolve()), "--image", str(args.image.resolve()),
             "--fido-port", str(ports[0]), "--ccid-port", str(ports[1]),
             "--inspect-port", str(ports[2])], stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                assert proc.poll() is None, "emulator exited before fault observation"
                try:
                    status = inspect(ports[2], "status")
                    progress = inspect(ports[2], f"read {marker:x} 4")
                    assert progress != "ok 02000000", "protected read succeeded: post-probe marker reached"
                    if "dead=true" in status:
                        break
                except ConnectionRefusedError:
                    pass
                time.sleep(0.02)
            else:
                raise AssertionError("hostile image did not fault")
            progress = inspect(ports[2], f"read {marker:x} 4")
            assert progress == "ok 01000000", progress
            log.seek(0)
            fault = log.read()
            assert f"BFAR 0x{args.address:08x}" in fault, "fault address differs from the protected read"
            assert f"CFSR 0x{args.cfsr:08x}" in fault, "fault status differs from the expected access denial"
            print(f"PASS: protected read at 0x{args.address:08x} refused with NS MPU off; post-read marker unreachable.", flush=True)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


if __name__ == "__main__":
    main()
