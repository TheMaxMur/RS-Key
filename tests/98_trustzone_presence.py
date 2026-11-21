#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Exercise real Secure presence and crypto on an explicit loopback image."""

import argparse
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import time
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location("crypto_probe", Path(__file__).with_name("95_trustzone_crypto_keepalive.py"))
crypto = importlib.util.module_from_spec(spec)
spec.loader.exec_module(crypto)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--emulator", type=Path, required=True)
    parser.add_argument("--base-port", type=int, default=19259)
    args = parser.parse_args()
    assert 1024 <= args.base_port <= 65533
    fido, ccid, inspect = range(args.base_port, args.base_port + 3)
    import socket
    for port in (fido, ccid, inspect):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))
    with tempfile.TemporaryFile(mode="w+") as log:
        proc = subprocess.Popen([str(args.emulator.resolve()), "--image", str(args.image.resolve()),
            "--touch", "--fido-port", str(fido), "--ccid-port", str(ccid),
            "--inspect-port", str(inspect)], stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT)
        class Touch:
            count = 0
            def before_request(self):
                start = int(crypto.inspect(inspect, "status")["emulated_ns"])
                deadline = time.monotonic() + 60
                while int(crypto.inspect(inspect, "status")["emulated_ns"]) - start < 500_000_000:
                    assert proc.poll() is None and time.monotonic() < deadline, "image clock stopped"
                    time.sleep(0.01)
            def __call__(self):
                assert proc.poll() is None
                proc.stdin.write(b"\n")
                proc.stdin.flush()
                self.count += 1
        touch = Touch()
        try:
            crypto.wait_ready(inspect)
            options = SimpleNamespace(fido_port=fido, ccid_port=ccid, inspect_port=inspect, runs=1, on_up=touch)
            crypto.check_rsa(options)
            crypto.check_mldsa(options)
            assert touch.count == 6, f"expected presence for each credential/assertion, got {touch.count}"
            print("PASS: six Secure user-presence waits, eight verified crypto operations and bounded keepalive gaps.", flush=True)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


if __name__ == "__main__":
    main()
