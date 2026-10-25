#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Build disposable Core1 fault images and verify terminal USB fencing."""

import argparse
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time


def inspect(port, command):
    with socket.create_connection(("127.0.0.1", port), timeout=20) as link:
        link.sendall(command.encode() + b"\n")
        return link.makefile("rb").readline(4096).decode().strip()


def symbol(image, suffix):
    listing = subprocess.check_output(["arm-none-eabi-nm", "-C", str(image)], text=True)
    return int(next(line.split()[0] for line in listing.splitlines() if line.endswith(suffix)), 16)


def probe(tree, emulator, base_port, fenced):
    image = tree / "target/trustzone/combined.elf"
    marker = symbol(image, "::core1::CORE1_FAULT_MARKER")
    ns = tree / "target/trustzone/nonsecure/thumbv8m.main-none-eabihf/release/firmware-ns"
    armed = symbol(ns, " RSK_NS_PROBE_PROGRESS")
    with tempfile.TemporaryFile(mode="w+") as log, tempfile.TemporaryFile(mode="w+") as client_log:
        proc = subprocess.Popen([str(emulator), "--image", str(image), "--fido-port", str(base_port),
            "--ccid-port", str(base_port + 1), "--inspect-port", str(base_port + 2)], stdout=log, stderr=subprocess.STDOUT)
        client = None
        try:
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                assert proc.poll() is None, "emulator stopped before the Core1 fault fixture was armed"
                try:
                    if inspect(base_port + 2, f"read {armed:x} 4") == "ok 01000000":
                        break
                except ConnectionRefusedError:
                    pass
                time.sleep(0.01)
            else:
                raise AssertionError("NS never armed its nonzero IN packet")
            client = subprocess.Popen(["python", str(tree / "tests/95_trustzone_crypto_keepalive.py"),
                "--suite", "rsa", "--runs", "1", "--fido-port", str(base_port),
                "--ccid-port", str(base_port + 1), "--inspect-port", str(base_port + 2)],
                stdout=client_log, stderr=subprocess.STDOUT)
            while time.monotonic() < deadline:
                if inspect(base_port + 2, f"read {marker:x} 4") == "ok 01000000":
                    break
                assert client.poll() is None, "RSA client stopped before Core1 entered the fault path"
                time.sleep(0.01)
            else:
                raise AssertionError("Core1 never reached the fault fixture")
            settle = time.monotonic() + (30 if fenced else 3)
            status = ""
            while time.monotonic() < settle:
                status = inspect(base_port + 2, "status")
                if "fatal_fenced=true" in status:
                    break
                time.sleep(0.02)
            if fenced:
                assert "dead=true" in status and "fatal_fenced=true" in status, status
            else:
                assert "fatal_fenced=false" in status, "Core0-only grant unexpectedly allowed Core1 cleanup"
            print(f"PASS: Core1 terminal USB fence={fenced}, with a pre-armed packet and observed Core1 marker.", flush=True)
        finally:
            for child in [client, proc]:
                if child is not None:
                    child.terminate()
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emulator", type=Path, required=True)
    parser.add_argument("--base-port", type=int, default=18459)
    args = parser.parse_args()
    assert 1024 <= args.base_port <= 65533
    for port in range(args.base_port, args.base_port + 3):
        with socket.socket() as link:
            link.bind(("127.0.0.1", port))
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="rskey-core1-fault-") as folder:
        tree = Path(folder) / "source"
        subprocess.run(["git", "clone", "--local", "--no-hardlinks", str(root), str(tree)], check=True)
        names = subprocess.check_output(["git", "diff", "--name-only", "HEAD", "-z"], cwd=root).decode().split("\0")
        names += subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard", "-z"], cwd=root).decode().split("\0")
        for name in filter(None, names):
            source, target = root / name, tree / name
            if source.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
            elif target.exists():
                target.unlink()
        core = tree / "firmware/src/core1.rs"
        body = core.read_text()
        needle = "fn search(job: &Job) {"
        assert body.count(needle) == 1
        body = body.replace(needle, "#[used]\nstatic CORE1_FAULT_MARKER: AtomicU32 = AtomicU32::new(0);\n\n" + needle +
            "\n    if rp_pac::SIO.cpuid().read() == 1 {\n        CORE1_FAULT_MARKER.store(1, Ordering::Release);\n        crate::trustzone::fault::halt();\n    }")
        core.write_text(body)
        ns_probe = tree / "firmware/trustzone/nonsecure/src/probe.rs"
        body = ns_probe.read_text()
        assert body.count("    run();") == 1
        ns_probe.write_text(body.replace("    run();", "    RSK_NS_PROBE_PROGRESS.store(1, Ordering::Release);"))
        env = os.environ | {"RSK_TZ_PROBE_ADDRESS": "0x50110000", "RSK_TZ_NO_TOUCH": "1",
            "LED_KIND": "none", "FLASH_SIZE": "4M", "CARGO_BUILD_JOBS": "2"}
        for fenced in [True, False]:
            if not fenced:
                policy = tree / "firmware/src/trustzone/security_policy.rs"
                body = policy.read_text()
                needle = "grant(access.usbctrl(), SECURE_CORES);"
                assert body.count(needle) == 1
                policy.write_text(body.replace(needle, "grant(access.usbctrl(), SECURE_CORE0);"))
            subprocess.run(["bash", "firmware/trustzone/build.sh"], cwd=tree, env=env, check=True)
            probe(tree, args.emulator.resolve(), args.base_port, fenced)
    print("PASS: Core1 cleanup works; removing only its USB grant leaves the fence incomplete.", flush=True)


if __name__ == "__main__":
    main()
