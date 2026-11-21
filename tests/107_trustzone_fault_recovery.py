#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Fence an authorized fault image, then cold boot its store without an ICC reset."""

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/emu"))
import image_assurance as laboratory

FAULT_ADDRESS = 0x50110000


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tests" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emulator", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--hostile-image", type=Path, required=True)
    parser.add_argument("--ns-image", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    args.work.mkdir(parents=True)
    sessions = module("sessions", "96_trustzone_sessions.py")
    isolation = module("isolation", "97_trustzone_isolation.py")
    marker = isolation.load_probe(args.ns_image, "write")
    target = isolation.load_target(args.ns_image)
    store = args.work / "store.bin"
    dev = laboratory.Device(args.emulator.resolve(), args.hostile_image.resolve(), store,
                            args.work, "authorized-fault")
    piv = None
    try:
        piv = sessions.Ccid(dev.ccid_port, dev.inspect_port)
        piv.authorize()
        assert piv.raw_apdu(0x20, 0, 0x80)[1] == 0x9000
        assert dev.inspect(f"read {marker:x} 4") == "01000000"
        assert dev.inspect(f"read {target:x} 4") == "00000000"
        dev.inspect(f"plant {target:x} {FAULT_ADDRESS.to_bytes(4, 'little').hex()}")
        deadline = time.monotonic() + 60
        while True:
            state = laboratory.fields(dev.inspect("status"))
            if state["dead"] == "true":
                break
            assert time.monotonic() < deadline, "authorized image did not reach fatal cleanup"
            time.sleep(0.01)
        assert state["fatal_fenced"] == "true", "authorized fault left USB/DPRAM live"
        assert dev.inspect(f"read {marker:x} 4") == "01000000"
        isolation.check_fault(dev.log_path.read_text(), FAULT_ADDRESS, "write", 0x8200, False)
        message = bytes.fromhex("6f0400000000a100000000200080")
        piv.sock.sendall(b"\0" + len(message).to_bytes(4, "big") + message)
        assert piv.sock.recv(4) == b"", "fatal image accepted another CCID request"
    finally:
        if piv is not None:
            piv.sock.close()
        dev.close()
    fido, ccid, inspection = (laboratory.port() for _ in range(3))
    with (args.work / "cold-boot.log").open("w") as log:
        process = subprocess.Popen([str(args.emulator.resolve()), "--image", str(args.image.resolve()),
            "--store", str(store), "--seed", laboratory.SEED, "--fido-port", str(fido),
            "--ccid-port", str(ccid), "--inspect-port", str(inspection)], stdout=log, stderr=log)
        fresh = None
        try:
            sessions.crypto.wait_ready(inspection)
            fresh = sessions.Ccid(ccid, inspection, activate=False)
            fresh.assert_auth_cleared()
            fresh.authorize()
            assert fresh.raw_apdu(0x20, 0, 0x80)[1] == 0x9000
            scratch = laboratory.scratch_code(args.image)
            assert scratch is not None, "current image has no scratch code"
            start, expected = scratch
            assert isolation.inspect(inspection, f"read {start:x} {len(expected)}") == "ok " + expected.hex()
        finally:
            if fresh is not None:
                fresh.sock.close()
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    report = {"authorized_before_fault": True, "fatal_fenced": True, "CCID_refused_after_fault": True,
              "cold_boot_PIN_refused_before_SELECT": True, "PIN_and_management_revoked_after_SELECT": True,
              "new_authorization_succeeded": True, "scratch_load_bytes_restored": len(expected)}
    (args.work / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS: authorized fatal cleanup, CCID refusal and cold-boot recovery without ICC reset.", flush=True)


if __name__ == "__main__":
    main()
