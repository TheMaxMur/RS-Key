#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Record a seam trace from a live `tools/emu` — the phase-4 recorder.

Drives one scripted CCID session against the emulator's card socket and writes
`formal/traces/seams-session.jsonl`: one wire-level event per line, in the
vocabulary `scripts/trace_map.py` maps onto `RSKeyAppletSeams` actions. The
mapped trace is then CHECKED against the model by TLC (`TraceSeams.cfg`): every
recorded session must be a behavior the model admits, and a divergence is a
deadlock at the exact step.

This script needs a LIVE emulator and is therefore not a gate row — run it only
to regenerate the committed trace:

    cargo run --manifest-path tools/emu/Cargo.toml --target <host>   # shell 1
    python3 formal/record-seam-trace.py                              # shell 2
    python3 scripts/trace_map.py --write                             # re-map
    ./formal/run-tlc.sh TraceSeams.cfg                               # re-check

The session deliberately speaks ONLY the mapped vocabulary (SELECT, VERIFY,
card reset, power cycle): an INS outside it would force the mapper to choose
between erroring and silently stuttering, and silent is how a checker stops
checking. The store is the emulator's fresh in-memory default, so the default
references (PIV PIN 123456, PW1 123456, PW3 12345678) hold and the retry
budgets are full.
"""

import json
import pathlib
import socket
import sys

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE / "traces" / "seams-session.jsonl"

ADDR = ("127.0.0.1", 7800)
OP_CCID = 0x00
OP_REPLUG = 0x03
CCID_POWER_ON = 0x62
CCID_POWER_OFF = 0x63
CCID_XFR_BLOCK = 0x6F
CCID_HEADER = 10
CCID_STATUS_MASK = 0xC0
CCID_STATUS_TIMEEXT = 0x80

AIDS = {
    "piv": bytes([0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00]),
    "pgp": bytes([0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]),
    "oath": bytes([0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01]),
}

# The default references of a fresh store, in each applet's wire form.
PIV_PIN_OK = b"123456\xff\xff"
PIV_PIN_BAD = b"000000\xff\xff"
PGP_PW1_OK = b"123456"
PGP_PW3_BAD = b"00000000"


class Card:
    """The same CCID framing `tests/emu.py`'s shim speaks, standalone."""

    def __init__(self):
        self.sock = socket.create_connection(ADDR, timeout=30)
        self.seq = 0

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            part = self.sock.recv(n - len(buf))
            if not part:
                raise OSError("the emulator closed the card socket")
            buf += part
        return buf

    def _recv_frame(self):
        return self._recv_exact(int.from_bytes(self._recv_exact(4), "big"))

    def _exchange(self, msg_type, payload=b""):
        self.seq = (self.seq + 1) & 0xFF
        header = bytes([msg_type]) + len(payload).to_bytes(4, "little") + bytes(
            [0x00, self.seq, 0x00, 0x00, 0x00]
        )
        self.sock.sendall(
            bytes([OP_CCID])
            + (CCID_HEADER + len(payload)).to_bytes(4, "big")
            + header
            + payload
        )
        while True:
            resp = self._recv_frame()
            if len(resp) < CCID_HEADER:
                raise OSError(f"short CCID response: {resp.hex()}")
            if resp[6] != self.seq:
                raise OSError(f"bSeq {resp[6]} answering {self.seq}")
            if resp[7] & CCID_STATUS_MASK == CCID_STATUS_TIMEEXT:
                continue
            dw = int.from_bytes(resp[1:5], "little")
            return resp[CCID_HEADER : CCID_HEADER + dw]

    def power_on(self):
        self._exchange(CCID_POWER_ON)

    def power_off(self):
        self._exchange(CCID_POWER_OFF)

    def apdu(self, cla, ins, p1, p2, data=b""):
        req = bytes([cla, ins, p1, p2, len(data)]) + data if data else bytes(
            [cla, ins, p1, p2]
        )
        resp = self._exchange(CCID_XFR_BLOCK, req)
        if len(resp) < 2:
            raise OSError(f"response shorter than a status word: {resp.hex()}")
        return (resp[-2] << 8) | resp[-1]

    def replug(self):
        """The emulator's power cycle — CCID has no message for it."""
        self.sock.sendall(bytes([OP_REPLUG]) + (0).to_bytes(4, "big"))
        self._recv_frame()


def main():
    events = []

    def ev(**kw):
        events.append(kw)

    card = Card()
    card.power_on()

    def select(app):
        sw = card.apdu(0x00, 0xA4, 0x04, 0x00, AIDS[app])
        ev(ev="select", app=app, sw=f"{sw:04X}")

    def verify(app, p2, ref, secret):
        sw = card.apdu(0x00, 0x20, 0x00, p2, secret)
        ev(ev="verify", app=app, ref=ref, sw=f"{sw:04X}")

    # The session: selections across all three applets (fresh and repeated, so
    # both SelectOther and Reselect appear), a failed and a successful PIV
    # VERIFY, a successful PW1 and a failed PW3, then the two events that end a
    # session from outside any applet.
    select("piv")
    verify("piv", 0x80, "pivPin", PIV_PIN_BAD)
    verify("piv", 0x80, "pivPin", PIV_PIN_OK)
    select("oath")
    select("piv")
    select("piv")  # a re-SELECT of the current AID: the model's Reselect
    select("pgp")
    verify("pgp", 0x81, "pw1", PGP_PW1_OK)
    verify("pgp", 0x83, "pw3", PGP_PW3_BAD)

    # SCardDisconnect(RESET) — power the slot off and on: Dispatcher::reset_card.
    card.power_off()
    card.power_on()
    ev(ev="card_reset")

    select("piv")

    # The replug: everything in this module's state dies with the power.
    card.replug()
    ev(ev="power_cycle")
    card.power_on()

    select("pgp")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")
    print(f"recorded {len(events)} events -> {OUT.relative_to(HERE.parent)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
