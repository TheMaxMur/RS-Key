#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Keep physical-key getInfo below one second on an otherwise idle device.

The image emulator does not model XIP-cache misses; its wall clock cannot
measure this regression. Select the physical key with RSK_TEST_SERIAL.
Only INIT and getInfo are sent; no PIN, configuration or credential writes.
"""
import os
import statistics
import time

from ctaphid import decode, find, hid, read, send_cbor, write

MAX_GETINFO_S = 1.0
GETINFO_SAMPLES = 3


def main():
    info = find()
    assert info is not None, "no selected FIDO key"
    device = hid.device()
    device.open_path(info["path"])
    durations = []
    try:
        nonce = os.urandom(8)
        write(device, b"\xff" * 4 + b"\x86\x00\x08" + nonce)
        reply = read(device)
        assert len(reply) == 64 and reply[:7] == b"\xff" * 4 + b"\x86\x00\x11"
        assert reply[7:15] == nonce, "INIT nonce mismatch"
        cid = reply[15:19]
        for sample in range(GETINFO_SAMPLES):
            started = time.monotonic()
            reply = send_cbor(device, cid, b"\x04")
            elapsed = time.monotonic() - started
            assert reply and reply[0] == 0, "getInfo failed"
            assert "FIDO_2_1" in decode(reply[1:])[1], "unexpected getInfo response"
            durations.append(elapsed)
            print(f"getInfo {sample + 1}: {elapsed * 1000:.3f} ms", flush=True)
    finally:
        device.close()
    median = statistics.median(durations)
    assert max(durations) < MAX_GETINFO_S, (
        f"getInfo took {max(durations):.3f}s (median {median:.3f}s); "
        f"idle physical-key budget is {MAX_GETINFO_S:.3f}s"
    )
    print(f"PASS: getInfo median {median * 1000:.3f} ms, all samples below 1s")


if __name__ == "__main__":
    main()
