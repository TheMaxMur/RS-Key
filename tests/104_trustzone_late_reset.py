#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Reset between the Secure raw snapshot and HAL acknowledgement, in an image."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


configuration = module("configuration", "103_trustzone_configuration.py")
sessions = module("sessions", "96_trustzone_sessions.py")


def symbol(image, name):
    listing = subprocess.check_output(["arm-none-eabi-nm", "-n", str(image)], text=True)
    address = int(next(line.split()[0] for line in listing.splitlines()
                       if line.endswith(" " + name)), 16)
    assert 0x20000000 <= address < 0x20070000
    return address


def probe(tree, emulator, base, revoked):
    image = tree / "target/trustzone/combined.elf"
    admitted = symbol(image, "RSK_USB_ADMITTED")
    pause = symbol(image, "RSK_USB_SNAPSHOT_PAUSE")
    epoch = symbol(image, "RSK_USB_EPOCH")
    inspect = lambda command: configuration.inspect(base + 2, command)

    def read(address):
        answer = inspect(f"read {address:x} 4")
        assert answer.startswith("ok "), answer
        return int.from_bytes(bytes.fromhex(answer[3:]), "little")

    def wait(predicate, message):
        deadline = time.monotonic() + configuration.READY_TIMEOUT_S
        while time.monotonic() < deadline:
            assert proc.poll() is None, "late reset image stopped"
            try:
                if predicate():
                    return
            except ConnectionRefusedError:
                pass
            time.sleep(0.005)
        raise AssertionError(message)

    with tempfile.TemporaryFile(mode="w+") as log:
        proc = subprocess.Popen([str(emulator), "--image", str(image),
            "--fido-port", str(base), "--ccid-port", str(base + 1),
            "--inspect-port", str(base + 2)], stdout=log, stderr=subprocess.STDOUT)
        piv = fresh = hid = None
        try:
            wait(lambda: "ready=true" in inspect("status") and read(admitted) == 1,
                 "initial configuration did not complete")
            piv = sessions.Ccid(base + 1, base + 2)
            piv.authorize()
            hid = sessions.Hid(base, base + 2)
            before = read(epoch)
            assert inspect(f"plant {pause:x} 01000000").startswith("ok ")
            hid.send(0x81, b"late-reset")
            wait(lambda: read(pause) == 2, "did not enter the post-snapshot IRQ pause")
            result = inspect("usb-reset")
            assert result.startswith("ok ") and "power_ups=1" in result, result
            wait(lambda: "ready=true" in inspect("status") and read(admitted) == 1,
                 "USB did not reconfigure after the late reset")
            after = read(epoch)
            fresh = sessions.Ccid(base + 1, base + 2, activate=False)
            _, pin_status = fresh.raw_apdu(0x20, 0, 0x80)
            print(json.dumps({"late_HAL_reset_revoked": revoked, "epochs": [before, after],
                              "PIN_status_before_SELECT": f"{pin_status:04X}"}), flush=True)
            if revoked:
                assert after > before, "late HAL reset failed to advance Secure epoch"
                assert pin_status != 0x9000, "PIN authority survived the late reset"
                fresh.assert_auth_cleared()
            else:
                assert after == before, "negative control missed the post-snapshot reset window"
                assert pin_status == 0x9000, "negative control did not preserve the old PIN authority"
        finally:
            for client in (piv, fresh, hid):
                if client is not None:
                    client.sock.close()
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emulator", type=Path, required=True)
    parser.add_argument("--base-port", type=int, default=19709)
    args = parser.parse_args()
    assert 1024 <= args.base_port <= 65533
    for port in range(args.base_port, args.base_port + 3):
        with socket.socket() as link:
            link.bind(("127.0.0.1", port))
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="rskey-late-reset-") as folder:
        tree = Path(folder) / "source"
        configuration.fixture(root, tree)
        usb = tree / "firmware/src/trustzone/usb.rs"
        body = usb.read_text()
        needle = "mod endpoints;"
        assert body.count(needle) == 1
        body = body.replace(needle, needle + "\n#[unsafe(no_mangle)]\n"
            "pub static RSK_USB_SNAPSHOT_PAUSE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);\n"
            "#[unsafe(no_mangle)]\npub static RSK_USB_EPOCH: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);")
        needle = "    let status = rp_pac::USB.sie_status().read();"
        assert body.count(needle) == 2
        body = body.replace(needle, needle + "\n    if RSK_USB_SNAPSHOT_PAUSE.compare_exchange(1, 2, "
            "core::sync::atomic::Ordering::Relaxed, core::sync::atomic::Ordering::Relaxed).is_ok() {\n"
            f"        cortex_m::asm::delay({configuration.STATUS_DELAY_CYCLES});\n    }}", 1)
        needle = "    bulk::observe(state);"
        body = body.replace(needle, "    RSK_USB_EPOCH.store(state.bus_epoch.current(), "
            "core::sync::atomic::Ordering::Relaxed);\n" + needle)
        usb.write_text(body)
        env = os.environ | {"RSK_TZ_NO_TOUCH": "1", "LED_KIND": "none", "FLASH_SIZE": "4M",
                            "CARGO_BUILD_JOBS": "2"}
        subprocess.run(["bash", "scripts/build.sh"], cwd=tree, env=env, check=True)
        probe(tree, args.emulator.resolve(), args.base_port, revoked=True)
        needle = "if state.observer.observe_hal(Revocation::Reset)"
        assert body.count(needle) == 1
        usb.write_text(body.replace(needle, "if false && state.observer.observe_hal(Revocation::Reset)"))
        subprocess.run(["bash", "scripts/build.sh"], cwd=tree, env=env, check=True)
        probe(tree, args.emulator.resolve(), args.base_port, revoked=False)
    print("PASS: a post-snapshot HAL reset revokes auth; removing its fallback retains PIN authority.", flush=True)


if __name__ == "__main__":
    main()
