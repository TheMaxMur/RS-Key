#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Exercise firmware ELF stack, residue, upgrade and interrupted NOR writes.

This runner owns every process, flash file and TCP endpoint it uses. It talks
only to tests/emu.py's socket clients, never to a connected security key.
"""

import argparse
import contextlib
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
import emu  # noqa: E402

emu.install()
from ctaphid import ctaphid_init, decode, enc, send_cbor  # noqa: E402
import image_operations  # noqa: E402

OATH = bytes.fromhex("a0000005272101")
OPENPGP = bytes.fromhex("d27600012401")
NAME = b"image-assurance"
KEY = bytes.fromhex("5a3c96e1d27b48f0a5c3691e2db7840f5e3ca197")
NEW_KEY = bytes.fromhex("0123456789abcdeffedcba987654321001234567")
RP = "image-assurance.invalid"
CDH = hashlib.sha256(b"image-assurance").digest()
PW3 = b"87654321"
SEED = "1234567890abcdef" * 4
# Interrupt entry can vary the sampled maximum by a few hundred bytes.
STACK_JITTER = 1024


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def fields(reply):
    return dict(item.split("=", 1) for item in reply.split() if "=" in item)


class Device:
    def __init__(self, binary, image, store, directory, label):
        self.fido_port, self.ccid_port, self.inspect_port = port(), port(), port()
        self.log_path = directory / f"{label}.log"
        self.log = self.log_path.open("w")
        args = [str(binary), "--store", str(store), "--seed", SEED,
                "--fido-port", str(self.fido_port), "--ccid-port", str(self.ccid_port)]
        if image:
            args += ["--image", str(image), "--inspect-port", str(self.inspect_port)]
        self.process = subprocess.Popen(args, stdout=self.log, stderr=self.log)
        self.image = image
        self.card = None
        self.hid = None
        try:
            self.wait_ready()
            os.environ[emu.ENV_ADDR] = f"127.0.0.1:{self.fido_port}"
            os.environ[emu.ENV_CCID_ADDR] = f"127.0.0.1:{self.ccid_port}"
            self.card = emu.EmuCard()
            self.card.connect()
            self.hid = emu.EmuHid()
            self.hid.open_path()
            self.cid = ctaphid_init(self.hid)
        except BaseException:
            self.close()
            raise

    def inspect(self, command):
        with socket.create_connection(("127.0.0.1", self.inspect_port), timeout=30) as sock:
            sock.sendall(command.encode() + b"\n")
            reply = sock.makefile("r").readline().rstrip()
        if not reply.startswith("ok "):
            raise AssertionError(f"inspection {command.split()[0]}: {reply}")
        return reply[3:]

    def wait_ready(self, power_ups=1):
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"emulator exited; see {self.log_path}")
            if self.image:
                try:
                    state = fields(self.inspect("status"))
                    if state["ready"] == "true" and int(state["power_ups"]) >= power_ups:
                        return state
                    if state["dead"] == "true":
                        raise RuntimeError(f"image faulted; see {self.log_path}")
                except OSError:
                    pass
            elif "device ready" in self.log_path.read_text():
                return None
            time.sleep(0.02)
        raise TimeoutError(f"emulator not ready; see {self.log_path}")

    def close(self):
        if self.hid:
            self.hid.close()
        if self.card and self.card.sock:
            self.card.sock.close()
        self.process.kill()
        self.process.wait()
        self.log.close()

    def apdu(self, command, expected=0x9000):
        body, hi, lo = self.card.transmit(command)
        body = bytes(body)
        while hi == 0x61:
            more, hi, lo = self.card.transmit([0, 0xC0, 0, 0, lo])
            body += bytes(more)
        sw = (hi << 8) | lo
        assert sw == expected, f"APDU {bytes(command[:4]).hex()}: {sw:04x}, expected {expected:04x}"
        return body

    def select(self, aid):
        return self.apdu(bytes([0, 0xA4, 4, 0, len(aid)]) + aid)

    def power_cycle(self):
        with socket.create_connection(("127.0.0.1", self.ccid_port), timeout=180) as sock:
            sock.sendall(bytes([emu.OP_REPLUG]) + bytes(4))
            emu._recv_frame(sock)
        self.hid.close()
        self.hid = emu.EmuHid()
        self.hid.open_path()
        self.cid = ctaphid_init(self.hid)
        self.card.sock.close()
        self.card = emu.EmuCard()
        self.card.connect()

    def ctap(self, command, body=None, expected=0):
        answer = send_cbor(self.hid, self.cid, bytes([command]) + (enc(body) if body is not None else b""))
        assert answer[0] == expected, f"CTAP {command}: status {answer[0]:02x}, expected {expected:02x}"
        return decode(answer[1:]) if len(answer) > 1 else None

    def measured(self, label, operation, report):
        self.inspect("begin")
        try:
            result = operation()
        finally:
            measurement = fields(self.inspect("end"))
            report[label] = {k: int(v) for k, v in measurement.items()}
        for core in range(2):
            assert int(measurement[f"core{core}_min"]) >= int(measurement[f"core{core}_low"]), label
        return result


@contextlib.contextmanager
def device(*args):
    item = Device(*args)
    try:
        yield item
    finally:
        item.close()


def tlv(tag, value):
    return bytes([tag, len(value)]) + value


def put_oath(dev, key=KEY):
    dev.select(OATH)
    body = tlv(0x71, NAME) + tlv(0x73, bytes([0x21, 6]) + key)
    dev.apdu(bytes([0, 1, 0, 0, len(body)]) + body)


def calculate(dev):
    dev.select(OATH)
    body = tlv(0x71, NAME) + tlv(0x74, (1).to_bytes(8, "big"))
    return dev.apdu(bytes([0, 0xA2, 0, 1, len(body)]) + body)


def expected_oath(key):
    digest = hmac.new(key, (1).to_bytes(8, "big"), "sha1").digest()
    offset = digest[-1] & 15
    truncated = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return bytes([0x76, 5, 6]) + (truncated % 10**6).to_bytes(4, "big")


def create_credential(dev, alg=-7):
    answer = dev.ctap(1, {1: CDH, 2: {"id": RP}, 3: {"id": b"user", "name": "image"},
                          4: [{"alg": alg, "type": "public-key"}], 7: {"rk": True}})
    auth = answer[2]
    size = int.from_bytes(auth[53:55], "big")
    cred, public = auth[55:55 + size], decode(auth[55 + size:])
    assert public[3] == alg
    return cred, public


def assertion(dev, cred, public):
    response = dev.ctap(2, {1: RP, 2: CDH, 3: [{"id": cred, "type": "public-key"}]})
    image_operations.verify_fido(public, response[2] + CDH, response[3])
    return response


def transcript(dev):
    put_oath(dev)
    otp = calculate(dev)
    assert otp == expected_oath(KEY)
    dev.select(OPENPGP)
    before = dev.apdu(bytes.fromhex("00ca00c400"))
    dev.apdu(bytes.fromhex("0020008106393939393939"), 0x6982)
    after_wrong = dev.apdu(bytes.fromhex("00ca00c400"))
    dev.apdu(bytes.fromhex("0020008106313233343536"))
    after_right = dev.apdu(bytes.fromhex("00ca00c400"))
    dev.apdu(bytes.fromhex("00fe0000"), 0x6D00)
    return {"oath": otp.hex(), "pin_before": before.hex(),
            "pin_wrong": after_wrong.hex(), "pin_correct": after_right.hex()}


def assert_no_residue(dev):
    for pattern in (KEY[:16], bytes(b ^ 0x36 for b in KEY[:16]), bytes(b ^ 0x5C for b in KEY[:16])):
        scan = fields(dev.inspect(f"scan {pattern.hex()}"))
        assert int(scan["count"]) == 0, f"secret residue remains at {scan['addresses']}"


def residue(dev):
    # Allow the post-response worker sweep to complete before inspecting SRAM.
    time.sleep(0.05)
    assert_no_residue(dev)
    planted = KEY[:16]
    # SRAM9 is outside the firmware linker RAM, without touching live frames.
    address = "20081000"
    dev.inspect(f"plant {address} {planted.hex()}")
    try:
        try:
            assert_no_residue(dev)
        except AssertionError as error:
            assert str(error) == f"secret residue remains at {address}", error
        else:
            raise AssertionError("planted OATH key did not fail the residue check")
    finally:
        dev.inspect(f"plant {address} {'00' * len(planted)}")
    assert_no_residue(dev)


def copy_store(source, destination):
    shutil.copyfile(source, destination)
    shutil.copyfile(Path(str(source) + ".otp"), Path(str(destination) + ".otp"))


def upgrade(args, work, report):
    store = work / "release.flash"
    with device(args.emulator, args.release_image, store, work, "release") as old:
        put_oath(old)
        cred, public = create_credential(old)
        old.select(OPENPGP)
        body = b"12345678" + PW3
        old.apdu(bytes([0, 0x24, 0, 0x83, len(body)]) + body)
        assert calculate(old) == expected_oath(KEY)
    upgraded = work / "upgrade.flash"
    copy_store(store, upgraded)
    with device(args.emulator, args.image, upgraded, work, "upgrade") as new:
        assert calculate(new) == expected_oath(KEY), "upgrade lost the OATH credential"
        assertion(new, cred, public)
        new.select(OPENPGP)
        new.apdu(bytes([0, 0x20, 0, 0x83, len(PW3)]) + PW3)
    report["upgrade"] = "OATH key, resident FIDO signing key and changed OpenPGP PIN survived"
    if args.incompatible_image:
        broken = work / "incompatible.flash"
        copy_store(store, broken)
        with device(args.emulator, args.incompatible_image, broken, work, "incompatible") as bad:
            try:
                calculate(bad)
            except AssertionError as error:
                assert "APDU 00a20001: 6984" in str(error), f"wrong falsification failure: {error}"
                report["upgrade_falsification"] = str(error)
            else:
                raise AssertionError("incompatible image still reads the old OATH credential")


def cuts(args, work, report):
    original = work / "cuts-base.flash"
    with device(args.emulator, args.image, original, work, "cuts-base") as dev:
        put_oath(dev)
        assert calculate(dev) == expected_oath(KEY)
    control = work / "cuts-control.flash"
    copy_store(original, control)
    with device(args.emulator, args.image, control, work, "cuts-control") as dev:
        before = int(fields(dev.inspect("status"))["programmed_bytes"])
        put_oath(dev, NEW_KEY)
        assert calculate(dev) == expected_oath(NEW_KEY), "successful replacement control failed"
        total = int(fields(dev.inspect("status"))["programmed_bytes"]) - before
        assert total > 0 and total % 256 == 0, "expected complete ROM page programs"
        dev.inspect("cut-cycles 0")
        interrupted = False
        try:
            dev.select(OATH)
        except (emu.CardConnectionException, OSError):
            interrupted = True
        assert interrupted, "the post-acknowledgment cut did not interrupt its request"
        state = dev.wait_ready(power_ups=2)
        assert state["last_cut"] != "none", "post-acknowledgment power cut never fired"
        dev.card.sock.close()
        dev.card = emu.EmuCard()
        dev.card.connect()
        assert calculate(dev) == expected_oath(NEW_KEY), "acknowledged replacement was lost at power cut"
        report["acknowledged_cut"] = {"acknowledged": True, "result": expected_oath(NEW_KEY).hex(),
                                      "cut": dev.inspect("status")}
    with device(args.emulator, args.image, control, work, "reopen-acknowledged-store") as fresh:
        assert calculate(fresh) == expected_oath(NEW_KEY), "acknowledged replacement was not persisted"
    byte_points = sorted({0, 1, 7, 63, 128, 256, total} | {
        base + within for base in range(0, total, 256) for within in (0, 1, 255)
    })
    outcomes = []
    snapshots = {}
    committed_cut = None
    for mode, points in (("program", byte_points),
                         ("program-cycles", [0, 1, 1000, 30000]),
                         ("cycles", [0, 1, 1000, 10000, 100000])):
        for point in points:
            store = work / f"cut-{mode}-{point}.flash"
            copy_store(original, store)
            with device(args.emulator, args.image, store, work, f"cut-{mode}-{point}") as dev:
                dev.select(OATH)
                dev.inspect(f"cut-{mode} {point}")
                body = tlv(0x71, NAME) + tlv(0x73, bytes([0x21, 6]) + NEW_KEY)
                acknowledged = False
                try:
                    dev.apdu(bytes([0, 1, 0, 0, len(body)]) + body)
                    acknowledged = True
                except (emu.CardConnectionException, OSError):
                    pass
                state = dev.wait_ready(power_ups=2)
                assert state["last_cut"] != "none", "fault injection never fired"
                dev.card.sock.close()
                dev.card = emu.EmuCard()
                dev.card.connect()
                answer = calculate(dev)
                assert answer in (expected_oath(KEY), expected_oath(NEW_KEY)), "torn credential accepted"
                if acknowledged:
                    assert answer == expected_oath(NEW_KEY), "acknowledged replacement was lost"
                if mode == "program" and point == total:
                    committed_cut = (store, answer)
                cut = dev.inspect("status")
                outcomes.append({"mode": mode, "point": point, "result": answer.hex(),
                                 "acknowledged": acknowledged, "cut": cut})
                detail = fields(cut)
                if mode in ("program", "program-cycles"):
                    assert detail["flash"].startswith("program"), "cut missed the page program"
                    at = int(detail["address"], 0)
                    page = Path(str(store) + ".cut").read_bytes()[at:at + 256]
                    snapshots[(mode, point)] = (at, page, int(detail["bytes"].split("/")[0]))
            reopened = work / f"reload-{mode}-{point}.flash"
            shutil.copyfile(Path(str(store) + ".cut"), reopened)
            shutil.copyfile(Path(str(store) + ".otp"), Path(str(reopened) + ".otp"))
            with device(args.emulator, args.image, reopened, work, f"reload-{mode}-{point}") as fresh:
                assert calculate(fresh) == answer, "persisted torn flash recovered differently"
    before_at, before, _ = snapshots[("program", 0)]
    after_at, after, _ = snapshots[("program", 256)]
    assert before_at == after_at and before != after, "cut control did not change its flash page"
    for (mode, point), (at, page, count) in snapshots.items():
        if mode == "program" and point > 256:
            continue
        assert at == before_at, "fault runs targeted different array operations"
        assert page == after[:count] + before[count:], f"{mode} {point}: flash is not the reported torn prefix"
    store, answer = committed_cut
    with device(args.emulator, args.image, store, work, "reopen-recovered-store") as fresh:
        assert calculate(fresh) == answer, "the recovered --store file did not persist its state"
    report["power_cuts"] = outcomes
    report["replacement_programmed_bytes"] = total


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emulator", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True, help="partitioned current no-touch ELF")
    parser.add_argument("--release-image", type=Path, help="partitioned v0.4.11 no-touch ELF")
    parser.add_argument("--incompatible-image", type=Path, help="scratch ELF with OATH FID base changed")
    parser.add_argument("--stack-regression", type=Path, help="scratch ELF with increased ML-DSA stack use")
    parser.add_argument("--work", type=Path, required=True, help="new directory for logs and emulated flash")
    parser.add_argument("--only", choices=["basic", "stack", "operations", "upgrade", "cuts", "all"], default="all")
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=False)
    for name in ("emulator", "image", "release_image", "incompatible_image", "stack_regression"):
        value = getattr(args, name)
        if value:
            setattr(args, name, value.resolve(strict=True))
    report = {"emulator": hashlib.sha256(args.emulator.read_bytes()).hexdigest(),
              "images": {name: hashlib.sha256(getattr(args, name).read_bytes()).hexdigest()
                         for name in ("image", "release_image", "incompatible_image", "stack_regression")
                         if getattr(args, name)}}
    if args.stack_regression:
        assert report["images"]["image"] != report["images"]["stack_regression"], "stack mutant ELF is identical to baseline"
    try:
        if args.only in ("all", "operations"):
            for label, elf in (("native_operations", None), ("image_operations", args.image)):
                report[label] = {}
                with device(args.emulator, elf, args.work / f"{label}.store", args.work, label) as dev:
                    image_operations.run(dev, report[label])
        if args.only in ("all", "basic"):
            with device(args.emulator, None, args.work / "native.store", args.work, "native") as native:
                expected = transcript(native)
            with device(args.emulator, args.image, args.work / "basic.flash", args.work, "basic") as image:
                observed = transcript(image)
                assert observed == expected, f"native/image mismatch: {expected} != {observed}"
                report["differential"] = observed
                image.measured("oath_calculate", lambda: calculate(image), report)
                residue(image)
                report["residue"] = "known OATH key and HMAC pads absent; SRAM planted leak found and cleared"
        if args.only in ("all", "stack"):
            for label, elf in (("stack", args.image), ("stack_regression", args.stack_regression)):
                if not elf:
                    continue
                with device(args.emulator, elf, args.work / f"{label}.flash", args.work, label) as image:
                    cred, public = image.measured(f"{label}_create_mldsa87", lambda: create_credential(image, -50), report)
                    image.measured(f"{label}_sign_mldsa87", lambda: assertion(image, cred, public), report)
            if args.stack_regression:
                baseline = max(report[f"stack_{op}_mldsa87"]["core0_used"] for op in ("create", "sign"))
                mutated = max(report[f"stack_regression_{op}_mldsa87"]["core0_used"] for op in ("create", "sign"))
                assert mutated > baseline + STACK_JITTER, f"stack mutation did not exceed the baseline envelope: {baseline} -> {mutated}"
                report["stack_falsification"] = {"baseline": baseline, "mutated": mutated}
        if args.only in ("all", "upgrade"):
            if not args.release_image:
                parser.error("--release-image is required for the upgrade scenario")
            upgrade(args, args.work, report)
        if args.only in ("all", "cuts"):
            cuts(args, args.work, report)
    finally:
        (args.work / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"IMAGE ASSURANCE PASSED; report: {args.work / 'report.json'}")


if __name__ == "__main__":
    main()
