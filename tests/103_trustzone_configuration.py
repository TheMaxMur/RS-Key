#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Verify EP0 status ACK/SETUP ordering on disposable loopback-only images."""

import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

STATUS_DELAY_CYCLES = 8_000_000
READY_TIMEOUT_S = 180


def inspect(port, command):
    with socket.create_connection(("127.0.0.1", port), timeout=READY_TIMEOUT_S) as link:
        link.sendall((command + "\n").encode())
        return link.makefile("rb").readline(4096).decode().strip()


def probe(image, emulator, base, next_setup, accepted):
    symbols = subprocess.check_output(["arm-none-eabi-nm", "-n", str(image)], text=True)
    marker = int(next(line.split()[0] for line in symbols.splitlines()
                      if line.endswith(" RSK_USB_ADMITTED")), 16)
    assert 0x20000000 <= marker < 0x20070000
    with tempfile.TemporaryFile(mode="w+") as log:
        proc = subprocess.Popen([str(emulator), "--image", str(image),
            "--fido-port", str(base), "--ccid-port", str(base + 1),
            "--inspect-port", str(base + 2)], stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + READY_TIMEOUT_S
            while time.monotonic() < deadline:
                assert proc.poll() is None, "configuration fixture stopped during boot"
                try:
                    status = inspect(base + 2, "status")
                except ConnectionRefusedError:
                    time.sleep(0.01)
                    continue
                assert "dead=false" in status, status
                if "ready=true" in status:
                    break
                time.sleep(0.005)
            else:
                raise AssertionError("configuration status was never ACKed")
            before = inspect(base + 2, f"read {marker:x} 4")
            assert before == "ok 00000000", "missed the deferred status-completion window"
            if next_setup:
                result = inspect(base + 2, "usb-control 0003010000000000")
                assert result == "ok control=accepted", result
            deadline = time.monotonic() + READY_TIMEOUT_S
            while time.monotonic() < deadline:
                admission = inspect(base + 2, f"read {marker:x} 4")
                if next_setup or admission == "ok 01000000":
                    break
                time.sleep(0.01)
            assert admission == ("ok 01000000" if accepted else "ok 00000000"), admission
            with socket.create_connection(("127.0.0.1", base), timeout=5) as hid:
                hid.settimeout(5)
                nonce = b"tz-race!"
                hid.sendall(b"\xff" * 4 + b"\x86\0\x08" + nonce + bytes(49))
                try:
                    reply = hid.recv(64)
                except socket.timeout:
                    reply = b""
            if accepted:
                assert len(reply) == 64 and reply[7:15] == nonce, "configured HID did not answer INIT"
            else:
                assert reply == b"", "removed ACK handling unexpectedly preserved HID"
            print(json.dumps({"next_SETUP_accepted": next_setup, "Secure_configured": accepted,
                              "HID_INIT_bytes": len(reply)}), flush=True)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def fixture(root, tree):
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
    usb = tree / "firmware/src/trustzone/usb.rs"
    body = usb.read_text()
    needle = "mod endpoints;"
    assert body.count(needle) == 1
    body = body.replace(needle, needle + "\n#[unsafe(no_mangle)]\npub static RSK_USB_ADMITTED: "
        "core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);")
    needle = "    bulk::observe(state);"
    assert body.count(needle) == 1
    usb.write_text(body.replace(needle, "    RSK_USB_ADMITTED.store(u32::from(state.bus_epoch.accepts("
        "state.bus_epoch.current())), core::sync::atomic::Ordering::Relaxed);\n" + needle))
    control = tree / "firmware/src/trustzone/usb/control.rs"
    body = control.read_text()
    needle = "                            let value = future.as_mut().poll(cx);\n                            observe();"
    assert body.count(needle) == 1
    body = body.replace(needle, """                            let value = future.as_mut().poll(cx);
                            static DELAYED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
                            if operation == abi::CTRL_ACCEPT && value.is_pending()
                                && with_controller(|state| state.setup == [0, 9, 1, 0, 0, 0, 0, 0])
                                && !DELAYED.swap(true, core::sync::atomic::Ordering::Relaxed) {
                                cortex_m::asm::delay(DELAY_CYCLES);
                            }
                            observe();""".replace("DELAY_CYCLES", str(STATUS_DELAY_CYCLES)))
    control.write_text(body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emulator", type=Path, required=True)
    parser.add_argument("--base-port", type=int, default=19699)
    args = parser.parse_args()
    assert 1024 <= args.base_port <= 65533
    for port in range(args.base_port, args.base_port + 3):
        with socket.socket() as link:
            link.bind(("127.0.0.1", port))
    emulator = args.emulator.resolve()
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="rskey-configuration-") as folder:
        tree = Path(folder) / "source"
        fixture(root, tree)
        env = os.environ | {"RSK_TZ_NO_TOUCH": "1", "LED_KIND": "none", "FLASH_SIZE": "4M",
                            "CARGO_BUILD_JOBS": "2"}
        subprocess.run(["bash", "scripts/build.sh"], cwd=tree, env=env, check=True)
        image = tree / "target/trustzone/combined.elf"
        probe(image, emulator, args.base_port, next_setup=False, accepted=True)
        probe(image, emulator, args.base_port, next_setup=True, accepted=True)
        usb = tree / "firmware/src/trustzone/usb.rs"
        body = usb.read_text()
        start = body.index("    // A completed configuration survives suspend;")
        end = body.index("    if let Some(reason) = fresh {", start)
        acknowledgement = body[start:end]
        body = body[:start] + body[end:]
        needle = "    for _ in 0..4 {"
        assert body.count(needle) == 1
        usb.write_text(body.replace(needle, acknowledgement + needle))
        subprocess.run(["bash", "scripts/build.sh"], cwd=tree, env=env, check=True)
        probe(image, emulator, args.base_port, next_setup=False, accepted=True)
        probe(image, emulator, args.base_port, next_setup=True, accepted=False)
    print("PASS: ACK-before-SETUP preserves HID; reversed ordering fails only the raced case.", flush=True)


if __name__ == "__main__":
    main()
