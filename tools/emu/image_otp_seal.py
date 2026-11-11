#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Exercise boot sealing in an actual ELF; only owned emulator files are fused."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import time

import image_assurance as harness

RESCUE = bytes.fromhex("a0583fc19b7e4f21")
LOCK_ROW = 0xFF5
LATCH = 0x3D3D3D
RAW_MASK = 0xFFFFFF
MIGRATION_CUT_TIMEOUT_S = 300


class Boot(harness.Device):
    """CCID-only so recovery mode is observable without waiting for FIDO."""
    def __init__(self, binary, image, store, directory, label, cut=None, rom=None):
        self.fido_port, self.ccid_port, self.inspect_port = (harness.port() for _ in range(3))
        self.log_path = directory / f"{label}.log"
        self.log = self.log_path.open("w")
        self.image, self.card, self.hid = image, None, None
        command = [
            str(binary), "--image", str(image), "--store", str(store), "--seed", harness.SEED,
            "--fido-port", str(self.fido_port), "--ccid-port", str(self.ccid_port),
            "--inspect-port", str(self.inspect_port),
        ]
        if rom:
            command.extend(["--rom", str(rom)])
        self.process = subprocess.Popen(command, stdout=self.log, stderr=self.log)
        try:
            if cut is not None:
                deadline = time.monotonic() + 30
                while True:
                    try:
                        self.inspect(f"cut-program {cut}")
                        break
                    except OSError:
                        assert time.monotonic() < deadline, "inspection listener absent"
                        time.sleep(0.005)
                self.wait_for_migration_cut()
            self.wait_ready(power_ups=2 if cut is not None else 1)
            os.environ[harness.emu.ENV_CCID_ADDR] = f"127.0.0.1:{self.ccid_port}"
            self.card = harness.emu.EmuCard()
            self.card.connect()
        except BaseException:
            self.close()
            raise

    def wait_for_migration_cut(self):
        # An armed program cut single-steps the emulator throughout migration.
        deadline = time.monotonic() + MIGRATION_CUT_TIMEOUT_S
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"emulator exited before the migration cut; see {self.log_path}")
            state = harness.fields(self.inspect("status"))
            assert state["dead"] == "false", f"emulator faulted before the migration cut: {state}"
            if state["last_cut"] != "none":
                return
            assert state["ready"] == "false", "USB configured before the migration cut"
            time.sleep(0.05)
        raise TimeoutError(f"migration cut did not fire; see {self.log_path}")

    def seal_status(self):
        self.select(RESCUE)
        data = self.apdu(bytes.fromhex("801e090000"))
        assert len(data) == 4 and data[0] == 1, data.hex()
        return data[1], int.from_bytes(data[2:], "big")


@contextlib.contextmanager
def boot(*args, **kwargs):
    device = Boot(*args, **kwargs)
    try:
        yield device
    finally:
        device.close()


def otp_path(store):
    return Path(str(store) + ".otp")


def rows(store):
    return list(struct.unpack("<4096I", otp_path(store).read_bytes()))


def save_rows(store, values):
    otp_path(store).write_bytes(struct.pack("<4096I", *values))


def encode(word):
    for bit, mask in enumerate((0xAD5B, 0x366D, 0xC78E, 0x07F0, 0xF800, 0x1FFFFF), 16):
        word |= ((word & mask).bit_count() & 1) << bit
    return word


def provision(store, lock=0, count=64):
    values = rows(store)
    payload = []
    for base, key in ((0xE80, bytes(range(1, 33))), (0xE90, bytes(range(33, 65)))):
        payload.extend((base + i, encode(int.from_bytes(key[i * 2:i * 2 + 2], "little")))
                       for i in range(16))
    payload += [(row + 0x20, raw ^ RAW_MASK) for row, raw in payload]
    for row, raw in payload[:count]:
        values[row] = raw
    values[LOCK_ROW] = lock
    save_rows(store, values)


def clone(source, dest):
    shutil.copyfile(source, dest)
    shutil.copyfile(otp_path(source), otp_path(dest))


def run(args):
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    binary, image = args.binary.resolve(), args.image.resolve()
    options = {"rom": args.rom.resolve() if args.rom else None}
    report = {
        "image_sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
        "emulator_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "rom_sha256": hashlib.sha256(args.rom.read_bytes()).hexdigest() if args.rom else None,
        "cases": [],
    }
    seed = out / "seed.flash"
    with boot(binary, image, seed, out, "blank", **options) as dev:
        assert dev.seal_status() == (1, 0xFFFF)
        harness.put_oath(dev)
        assert harness.calculate(dev) == harness.expected_oath(harness.KEY)
    assert rows(seed)[LOCK_ROW] == 0
    for lock in (0, 0x003C3C, 0x010000, 0x3C3C3C, 0x3D3C3C, 0x3D3D3C):
        label = f"provisioned-{lock:06x}"
        store = out / f"{label}.flash"
        source = out / "provisioned-000000.flash" if lock == 0x3D3D3C else seed
        clone(source, store)
        provision(store, lock)
        with boot(binary, image, store, out, label, **options) as dev:
            expected = 10 if lock == 0x3D3D3C else 2
            assert dev.seal_status() == (expected, 0), dev.seal_status()
            assert harness.calculate(dev) == harness.expected_oath(harness.KEY), "migration lost secret"
            state = harness.fields(dev.inspect("status"))
            if expected == 10:
                assert state["programmed_bytes"] == "0", "closed partial latch repeated the scrub"
        assert rows(store)[LOCK_ROW] == (lock if expected == 10 else LATCH)
        before = otp_path(store).read_bytes()
        with boot(binary, image, store, out, label + "-repeat", **options) as dev:
            assert dev.seal_status() == (expected, 0)
            assert harness.calculate(dev) == harness.expected_oath(harness.KEY)
        assert otp_path(store).read_bytes() == before, "sealed boot changed fuses"
        report["cases"].append({"case": label, "state": state, "passed": True})
        (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    store = out / "closed-latch-pre-otp-replay.flash"
    clone(seed, store)
    provision(store, 0x3D3D3C)
    with boot(binary, image, store, out, "closed-latch-pre-otp-replay", **options) as dev:
        assert dev.seal_status() == (10, 0xFFFE)
        assert dev.apdu(bytes.fromhex("801e080000")) == bytes([2, 0])
    assert rows(store)[LOCK_ROW] == 0x3D3D3C, "replayed storage must not authorize latch completion"
    report["cases"].append({"case": "closed-latch-pre-otp-replay-refused", "passed": True})
    store = out / "secure-only-torn-lock.flash"
    clone(seed, store)
    provision(store, 0x010100)
    before = store.read_bytes()[0x280000:]
    with boot(binary, image, store, out, "secure-only-torn-lock", **options) as dev:
        assert dev.seal_status() == (11, 0xFFFE)
        assert dev.apdu(bytes.fromhex("801e080000")) == bytes([2, 0])
    assert rows(store)[LOCK_ROW] == 0x010100
    assert store.read_bytes()[0x280000:] == before, "incomplete access lock migrated storage"
    report["cases"].append({"case": "secure-only-torn-lock", "passed": True})
    for count in (1, 16, 31, 32, 48, 63):
        label = f"torn-provisioning-{count}"
        store = out / f"{label}.flash"
        clone(seed, store)
        provision(store, count=count)
        before = store.read_bytes()[0x280000:]
        with boot(binary, image, store, out, label, **options) as dev:
            assert dev.seal_status()[0] == 5
            dev.select(RESCUE)
            assert dev.apdu(bytes.fromhex("801e080000")) == bytes([2, 0])
        assert rows(store)[LOCK_ROW] == 0
        assert store.read_bytes()[0x280000:] == before, "torn root migrated storage"
        report["cases"].append({"case": label, "passed": True})
    for cut in (0, 1, 255, 256, 4096):
        label = f"migration-cut-{cut}"
        store = out / f"{label}.flash"
        clone(seed, store)
        provision(store)
        with boot(binary, image, store, out, label, cut=cut, **options) as dev:
            state = harness.fields(dev.inspect("status"))
            assert int(state["power_ups"]) > 1 and state["last_cut"] != "none", state
            assert dev.seal_status() == (2, 0), dev.seal_status()
            assert harness.calculate(dev) == harness.expected_oath(harness.KEY)
        assert rows(store)[LOCK_ROW] == LATCH
        report["cases"].append({"case": label, "state": state, "passed": True})
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--rom", type=Path)
    run(parser.parse_args())
