# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Host waiting is evidence of an interval, never a device-side timestamp."""
import time


def wait(session, seconds):
    session._gate()
    session.require(session.options.timeout > seconds + 0.25, "increase --timeout to include this explicit waiting interval")
    start = session.trace.now()
    session.trace.emit("interaction", action="wait", stage="started", duration_ns=int(seconds * 1e9), source="host_monotonic")
    end = time.monotonic() + seconds
    while True:
        remaining = end - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(remaining, 0.1))
    finish = session.trace.now()
    session.trace.emit("interaction", action="wait", stage="completed", interval_start_ns=start, interval_end_ns=finish,
                       requested_duration_ns=int(seconds * 1e9), observed_duration_ns=finish - start, source="host_monotonic")
