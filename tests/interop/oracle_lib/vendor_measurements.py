# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Measurement selectors have explicit build gates and device-timer response shapes."""
from itertools import product

from . import codec

FEATURES = {0x12: "core1-stats", 0x13: "keygen-bench", 0x14: "bench", 0x15: "bench"}
BENCH_ITERATIONS, BENCH_SAMPLES, OTP_READ_REPETITIONS = 400, 32, 100


def vectors():
    for p1, p2, size in product((0, 1, 255), (0, 255), (0, 1, 32)):
        yield 0x12, p1, p2, size
    for p1, p2, size in product((0, 1, 2, 255), (0, 255), (0, 1, 31, 32, 33, 63, 64, 65, 127, 128, 255, 256, 257)):
        yield 0x13, p1, p2, size
    for p1, p2, size in product((0, 1, 2, 3, 4, 255), (0, 1, 31, 32, 33, 255), (0, 1, 16)):
        yield 0x14, p1, p2, size
    for p1, size in product((0, 1, 2, 3, 255), (0, 1, 7, 8, 9, 63, 64, 65, 255)):
        yield 0x15, p1, 0, size


def expected(ins, p1, size):
    if ins == 0x13:
        return 0x6700 if not size or size % 32 or size > 256 else 0x9000 if p1 in (0, 1) else 0x6a86
    if ins == 0x14:
        return 0x9000 if p1 <= 3 else 0x6a86
    if ins == 0x15:
        return 0x6700 if p1 == 0 and not 8 <= size <= 64 else 0x9000 if p1 <= 2 else 0x6a86
    return 0x9000


def run(session):
    for enabled, (ins, p1, p2, size) in product((False, True), vectors()):
        with session.case(f"rsk.measurement.selector.{ins:02x}.feature-{enabled}.P1-{p1}.P2-{p2}.length-{size}", ("V13", "G03", "G04", "G13", "G14"),
                effects=("config_change",) if enabled and ins == 0x15 and p1 in (1, 2) else (),
                parameters={"build_feature": FEATURES[ins], "feature_declared": enabled, "selector": p1, "warmup": p2, "body_length": size}):
            session.require(session.profile == "rsk", "measurement command map requires RS-Key", "excluded_by_profile")
            session.require((FEATURES[ins] in session.options.features) == enabled, "scenario needs its explicitly declared measurement/shipping profile", "excluded_by_profile")
            session.select("vendor")
            before = session.card_value(session.apdu(codec.apdu(2)))
            stopped = False
            try:
                result = session.apdu(codec.apdu(ins, p1, p2, session.fixture("measurement.pattern", size)))
                status = expected(ins, p1, size) if enabled else 0x6d00
                stopped = enabled and ins == 0x15 and p1 == 1 and result.status == 0x9000
                session.check("measurement build gate and selector/length precedence are explicit", result.status, status)
                if status == 0x9000:
                    body = session.card_value(result)
                    if ins == 0x12:
                        session.check("core1 statistics contain the complete fixed block", len(body), 32)
                    elif ins == 0x13:
                        session.check("keygen bench declares the actual operation divisor", body, BENCH_ITERATIONS.to_bytes(4, "little"))
                    elif ins == 0x14:
                        session.check("latency summary has exactly its selector's response layout", len(body), 24 if p1 == 3 else 20)
                        n, cold, minimum, median, mad = (int.from_bytes(body[at:at + 4], "little") for at in range(0, 20, 4))
                        session.check("warmup removes samples without underflow", n, max(0, BENCH_SAMPLES - p2))
                        session.check("device timer minimum does not exceed its median", minimum <= median)
                        if not n:
                            session.check("empty warm range collapses onto the cold observation", (minimum, median, mad), (cold, cold, 0))
                        if p1 == 3:
                            session.check("batched OTP selector supplies its own divisor", int.from_bytes(body[20:], "little"), OTP_READ_REPETITIONS)
                        session.observe("device_timer_summary_us", {"n": n, "cold": cold, "minimum": minimum, "median": median, "mad": mad}, "presence")
                    elif p1 == 0:
                        session.check("residue probe has all three unsigned counters", len(body), 12)
                        matches, nonzero, scanned = (int.from_bytes(body[at:at + 4], "little") for at in (0, 4, 8))
                        session.check("residue observations fit the scanned region", matches <= scanned and nonzero <= scanned)
                    else:
                        session.check("sweep control acknowledges without exposing stack bytes", body, b"")
                else:
                    session.check("measurement refusal exposes no timer or stack bytes", result.data[:-2], b"")
                session.check("measurement requests cannot change the persistent vendor counter", session.card_value(session.apdu(codec.apdu(2))), before)
            finally:
                if stopped and not session.broken:
                    session.trace.phase = "cleanup"
                    session.card_value(session.apdu(codec.apdu(0x15, 2)))
                    session.observe("sweep_recovery", "restart acknowledged after the declared measurement-build stop; prior pause state is not exported")
