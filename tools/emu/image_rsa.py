# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Generated RSA keys: both core stacks and factor residue in the actual SRAM."""

import subprocess
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from image_operations import CDH, DI_SHA256, MESSAGE, apdu, tlv, value

SRAM_BASE = 0x20000000
SRAM_LEN = 520 * 1024
CONTROL_ADDRESS = 0x20081000
COUNTERS = {"JOBS": 4, "C1_TRIES": 4, "C0_TRIES": 4, "BUSY": 1, "JOB_PENDING": 1}
WIND_DOWN_TIMEOUT = 30
CORE1_IDLE_ENVELOPE = 1024


def read(dev, address, length):
    blob = bytes.fromhex(dev.inspect(f"read {address:x} {length}"))
    assert len(blob) == length, "truncated SRAM inspection"
    return blob


def counters(dev):
    output = subprocess.check_output(["arm-none-eabi-nm", "--defined-only", "--print-size",
                                      "--format=posix", str(dev.image)], text=True)
    result = {}
    for name, size in COUNTERS.items():
        matches = [line.split() for line in output.splitlines()
                   if "5core1" in line and f"{len(name)}{name}" in line.split()[0]]
        assert len(matches) == 1, f"ELF has no unique core1::{name}"
        _, kind, address, length = matches[0]
        assert kind.lower() in ("b", "d") and int(length, 16) == size, name
        result[name] = int.from_bytes(read(dev, int(address, 16), size), "little")
    return result


def factors(blob, modulus):
    length = modulus.bit_length() // 16
    hits = []
    for offset in range(len(blob) - length + 1):
        window = blob[offset:offset + length]
        for order, lsb in (("big", window[-1]), ("little", window[0])):
            if lsb & 1:
                candidate = int.from_bytes(window, order)
                if 1 < candidate < modulus and modulus % candidate == 0:
                    hits.append((SRAM_BASE + offset, order))
    return hits


def clean(dev, modulus):
    time.sleep(0.05)
    hits = factors(read(dev, SRAM_BASE, SRAM_LEN), modulus)
    assert not hits, f"RSA factor residue remains at {hits}"
    return {"rsa_factor_matches": len(hits)}


def control(dev, key):
    numbers = key.private_numbers()
    prime = numbers.p.to_bytes(key.key_size // 16, "big")
    dev.inspect(f"plant {CONTROL_ADDRESS:x} {prime.hex()}")
    try:
        try:
            clean(dev, numbers.public_numbers.n)
        except AssertionError as error:
            assert str(error) == f"RSA factor residue remains at {[(CONTROL_ADDRESS, 'big')]}", error
        else:
            raise AssertionError("planted RSA factor escaped the SRAM residue assertion")
    finally:
        dev.inspect(f"plant {CONTROL_ADDRESS:x} {'00' * len(prime)}")
    clean(dev, numbers.public_numbers.n)


def public_key(answer):
    inner = value(answer, 0x7F49)
    assert inner[:2] == b"\x81\x82", "missing RSA modulus"
    length = int.from_bytes(inner[2:4], "big")
    modulus = int.from_bytes(inner[4:4 + length], "big")
    exponent = int.from_bytes(value(inner[4 + length:], 0x82), "big")
    assert modulus.bit_length() == 2048 and exponent == 65537
    return rsa.RSAPublicNumbers(exponent, modulus).public_key()


def generate(ops, label, command):
    dev = ops.dev
    before = counters(dev) if dev.image else None
    after = None

    def operation():
        nonlocal after
        key = public_key(dev.apdu(command))
        if dev.image:
            after = counters(dev)
            row = ops.report[label]
            row["core1_busy_at_reply"] = bool(after["BUSY"])
            assert after["JOB_PENDING"] == 0, "RSA reply left a posted job"
            # The last candidate finishes in the background; measure its tail too.
            deadline = time.monotonic() + WIND_DOWN_TIMEOUT
            while after["BUSY"]:
                assert time.monotonic() < deadline, "core1 did not wind down"
                time.sleep(0.05)
                after = counters(dev)
        return key

    key = ops.run(label, operation)
    if dev.image:
        row = ops.report[label]
        row["core1"] = {name: after[name] - before[name] for name in ("JOBS", "C1_TRIES", "C0_TRIES")}
        assert row["core1"]["JOBS"] > 0 and row["core1"]["C1_TRIES"] > 0, "core1 did not search"
        assert after["BUSY"] == 0 and after["JOB_PENDING"] == 0, "core1 did not wind down"
        assert row["stack"]["core1_used"] > CORE1_IDLE_ENVELOPE, "core1 stack stayed at idle depth"
        row["residue"] = clean(dev, key.public_numbers().n)
    return key


def piv(ops):
    dev = ops.dev
    dev.apdu(apdu(0x20, 0, 0x80, b"123456\xff\xff"))
    key = generate(ops, "piv_generate_rsa", apdu(0x47, 0, 0x9C, tlv(0xAC, tlv(0x80, b"\x07"))))

    def sign():
        digest = DI_SHA256 + CDH
        block = b"\x00\x01" + b"\xff" * (256 - 3 - len(digest)) + b"\x00" + digest
        answer = dev.apdu(apdu(0x87, 7, 0x9C, tlv(0x7C, tlv(0x82, b"") + tlv(0x81, block))))
        key.verify(value(value(answer, 0x7C), 0x82), MESSAGE, padding.PKCS1v15(), hashes.SHA256())

    ops.run("piv_generated_rsa_sign", sign)
    if dev.image:
        ops.report["piv_generated_rsa_sign"]["residue"] = clean(dev, key.public_numbers().n)



def openpgp(ops, control_key):
    dev = ops.dev
    dev.apdu(apdu(0x20, 0, 0x83, b"12345678"))
    key = generate(ops, "openpgp_generate_rsa", bytes.fromhex("00478000000002b6000000"))
    dev.apdu(apdu(0x20, 0, 0x81, b"123456"))

    def sign_openpgp():
        signature = dev.apdu(apdu(0x2A, 0x9E, 0x9A, DI_SHA256 + CDH))
        key.verify(signature, MESSAGE, padding.PKCS1v15(), hashes.SHA256())

    ops.run("openpgp_generated_rsa_sign", sign_openpgp)
    if dev.image:
        ops.report["openpgp_generated_rsa_sign"]["residue"] = clean(dev, key.public_numbers().n)
        control(dev, control_key)
        ops.report["rsa_factor_control"] = "planted factor refused and cleared"
