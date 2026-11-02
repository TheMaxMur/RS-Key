#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Run a disposable loopback image emulator; never opens physical key handles."""

import argparse
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time


def arguments():
    parser = argparse.ArgumentParser(description="Verify a hostile NS access is refused.")
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--ns-image", type=Path, required=True)
    parser.add_argument("--emulator", type=Path, required=True)
    parser.add_argument("--address", type=lambda value: int(value, 16), required=True)
    parser.add_argument("--access", choices=("read", "write"), default="read")
    parser.add_argument("--cfsr", type=lambda value: int(value, 16), default=0x8200)
    parser.add_argument("--require-fenced", action="store_true")
    parser.add_argument("--base-port", type=int, default=19359)
    return parser.parse_args()


def inspect(port, command):
    with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
        connection.sendall((command + "\n").encode())
        with connection.makefile("rb") as stream:
            return stream.readline(4096).decode().strip()


def load_probe(image, access):
    listing = subprocess.check_output(["arm-none-eabi-nm", "-n", str(image.resolve())], text=True)
    symbols = {line.split()[-1]: int(line.split()[0], 16) for line in listing.splitlines()
               if line.endswith((" RSK_NS_PROBE_PROGRESS", " RSK_NS_PROBE_ACCESS"))}
    marker, entry = symbols["RSK_NS_PROBE_PROGRESS"], symbols["RSK_NS_PROBE_ACCESS"]
    assert 0x20070000 <= marker < 0x20080000
    listing = subprocess.check_output(
        ["arm-none-eabi-objdump", "-d", f"--start-address={entry}",
         f"--stop-address={entry + 4}", str(image.resolve())], text=True,
    )
    instruction = re.search(r"^\s*([0-9a-f]+):\s+(?:[0-9a-f]{4}\s+)+([a-z][a-z0-9.]*)", listing, re.M)
    assert instruction and int(instruction[1], 16) == entry, "hostile probe instruction missing"
    expected = {"read": "ldr", "write": "str"}[access]
    assert instruction[2].removesuffix(".w") == expected, f"hostile {access} probe is not {expected.upper()}"
    return marker


def main():
    args = arguments()
    marker = load_probe(args.ns_image, args.access)
    assert 1024 <= args.base_port <= 65533
    ports = tuple(range(args.base_port, args.base_port + 3))
    for port in ports:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))
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
                    assert progress != "ok 02000000", f"protected {args.access} succeeded: post-probe marker reached"
                    if "dead=true" in status:
                        break
                except ConnectionRefusedError:
                    pass
                time.sleep(0.02)
            else:
                raise AssertionError("hostile image did not fault")
            if args.require_fenced:
                assert "fatal_fenced=true" in inspect(ports[2], "status"), "USB/DPRAM remained live after Secure fatal cleanup"
            progress = inspect(ports[2], f"read {marker:x} 4")
            assert progress == "ok 01000000", progress
            log.seek(0)
            fault = log.read()
            assert f"BFAR 0x{args.address:08x}" in fault, f"fault address differs from the protected {args.access}"
            assert f"CFSR 0x{args.cfsr:08x}" in fault, "fault status differs from the expected access denial"
            print(f"PASS: protected {args.access} at 0x{args.address:08x} refused with NS MPU off; post-{args.access} marker unreachable.", flush=True)
        except AssertionError:
            log.seek(0)
            print(log.read(), end="", flush=True)
            raise
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


if __name__ == "__main__":
    main()
