# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Versioned synthetic PIV histories; no device access in this module."""

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import random

SCHEMA = 1
LENGTHS = (1, 2, 3, 4, 5, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65,
           127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025,
           2033, 2048, 2049, 3000, 3045, 3046)
OBJECTS = tuple(bytes((0x5F, 0, 0x70 + index)) for index in range(8))
SLOTS = (0x9A, 0x9C, 0x9D, 0x9E)


class Kind(str, Enum):
    PUT = "put"
    DELETE_OBJECT = "delete_object"
    EC = "ec"
    RSA = "rsa"
    DELETE_KEY = "delete_key"
    PIN = "pin"
    RETRY = "retry"
    SELECT = "select"
    REBOOT = "reboot"


@dataclass(frozen=True)
class Operation:
    id: int
    kind: Kind
    argument: int = 0
    length: int = 0

    def encode(self):
        return asdict(self)


@dataclass(frozen=True)
class Failure:
    phase: str
    instruction: int
    status: int
    cause: tuple = ()

    @property
    def target(self):
        return self.phase == "reset" and self.instruction == 0xFB and self.status == 0x6581


def generate(seed, steps, rsa=False):
    if not 0 <= seed < 2**64 or not 1 <= steps <= 10000:
        raise ValueError("seed must be u64 and steps must be 1..10000")
    rng = random.Random(seed)
    kinds = ([Kind.PUT] * 8 + [Kind.DELETE_OBJECT, Kind.EC, Kind.DELETE_KEY,
                              Kind.PIN, Kind.RETRY, Kind.SELECT, Kind.REBOOT])
    operations = []
    for index in range(steps):
        kind = rng.choice(kinds)
        argument = rng.randrange(len(OBJECTS)) if kind in (Kind.PUT, Kind.DELETE_OBJECT) else 0
        if kind in (Kind.EC, Kind.DELETE_KEY):
            argument = rng.choice(SLOTS)
        if kind == Kind.PIN:
            argument = rng.randrange(1, 1000000)
        length = rng.choice(LENGTHS) if kind == Kind.PUT else 0
        operations.append(Operation(index + 1, kind, argument, length))
    if rsa:
        operations.insert(steps // 2, Operation(steps + 1, Kind.RSA))
    return operations


def payload(seed, operation):
    domain = f"RS-Key public PIV history v{SCHEMA}:{seed}:{operation.id}".encode()
    return hashlib.shake_256(domain).digest(operation.length)


def manifest(seed, operations, identity):
    return {"schema": SCHEMA, "seed": seed, "baseline": "blank-emulator-store",
            "replay": "APDU history; cryptographic randomness is backend dependent",
            "identity": identity, "operations": [item.encode() for item in operations]}


def decode(document):
    if document.get("schema") != SCHEMA or document.get("baseline") != "blank-emulator-store":
        raise ValueError("unsupported history schema or baseline")
    seed = document["seed"]
    if type(seed) is not int or not 0 <= seed < 2**64:
        raise ValueError("invalid seed")
    operations = []
    ids = set()
    for row in document["operations"]:
        if set(row) != {"id", "kind", "argument", "length"}:
            raise ValueError("invalid operation fields")
        item = Operation(row["id"], Kind(row["kind"]), row["argument"], row["length"])
        if any(type(value) is not int for value in (item.id, item.argument, item.length)):
            raise ValueError("operation numbers must be integers")
        if item.id <= 0 or item.id in ids:
            raise ValueError("operation IDs must be unique and positive")
        ids.add(item.id)
        if item.kind in (Kind.PUT, Kind.DELETE_OBJECT):
            if not 0 <= item.argument < len(OBJECTS):
                raise ValueError("unknown pooled object")
        elif item.kind in (Kind.EC, Kind.DELETE_KEY):
            if item.argument not in SLOTS:
                raise ValueError("unknown key slot")
        elif item.kind == Kind.PIN:
            if not 1 <= item.argument < 1000000:
                raise ValueError("invalid public test PIN index")
        elif item.argument != 0:
            raise ValueError("unexpected operation argument")
        if item.kind == Kind.PUT:
            if item.length not in LENGTHS:
                raise ValueError("unsupported object length")
        elif item.length != 0:
            raise ValueError("unexpected operation length")
        operations.append(item)
    if len(operations) > 10001:
        raise ValueError("history too long")
    return seed, operations


def minimize(operations, target, execute):
    """Every execution starts from the baseline; retain the same refusal only."""
    if not target.target:
        raise ValueError("only an admitted RESET 6581 can be minimized")
    remaining = list(operations)
    granularity = 2
    while remaining:
        width = max(1, (len(remaining) + granularity - 1) // granularity)
        reduced = False
        for start in range(0, len(remaining), width):
            candidate = remaining[:start] + remaining[start + width:]
            if execute(candidate) == target:
                remaining = candidate
                granularity = max(2, granularity - 1)
                reduced = True
                break
        if not reduced:
            if width == 1:
                break
            granularity = min(len(remaining), granularity * 2)
    return remaining
